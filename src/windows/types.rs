// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::{
    ClassKind, FallibleIterator, MemberFunctionType, PointerAttributes, PointerMode, PointerType,
    PrimitiveKind, ProcedureType, Result, TypeData, TypeFinder, TypeIndex, TypeInformation,
};
use symbolic_common::{Language, Name};
use symbolic_demangle::{Demangle, DemangleFormat, DemangleOptions};

pub(super) struct TypeDumper<'a> {
    finder: TypeFinder<'a>,
}

pub enum FuncName {
    // The undecorated name even in case of failure
    // (there is a bug somewhere else but the name should be undecorated)
    Undecorated(String),
    // The name hasn't been undecorated because the language is unknown
    Unknown((String, u32)),
}

impl FuncName {
    pub fn get_unknown(name: String) -> Self {
        if name.is_empty() {
            return FuncName::Unknown((name, 0));
        }

        let (first, sub) = name.split_at(1);

        if sub.find(|c: char| c == ':' || c == '(').is_some() {
            return FuncName::Unknown((name, 0));
        }

        if first != "_" && first != "@" {
            return FuncName::Unknown((name, 0));
        }

        let parts: Vec<_> = sub.rsplitn(2, '@').collect();
        if parts.len() <= 1 {
            let name = if first == "_" { sub.to_string() } else { name };
            return FuncName::Unknown((name, 0));
        }

        if let Ok(stack_param_size) = parts[0].parse::<u32>() {
            let sps = if first == "@" {
                if stack_param_size > 8 {
                    stack_param_size - 8
                } else {
                    0
                }
            } else {
                stack_param_size
            };
            return FuncName::Unknown((parts[1].to_string(), sps));
        }

        let name = if first == "_" { sub.to_string() } else { name };

        FuncName::Unknown((name, 0))
    }
}

impl<'a> TypeDumper<'a> {
    /// Collect all the Type and their TypeIndex to be able to search for a TypeIndex
    pub fn new<'b>(type_info: &'a TypeInformation<'b>) -> Result<Self> {
        let mut finder = type_info.finder();
        let mut types = type_info.iter();

        // Populate finder
        finder.update(&types);
        while let Some(_) = types.next()? {
            finder.update(&types);
        }

        Ok(Self { finder })
    }

    /// Dump a ProcedureType at the given TypeIndex
    /// If the TypeIndex is 0 then try to use demanglers to have the correct name
    pub fn dump_function(&self, name: &str, index: TypeIndex) -> Result<FuncName> {
        if name.is_empty() {
            Ok(FuncName::Undecorated("<name omitted>".to_string()))
        } else if index == TypeIndex(0) {
            Ok(Self::demangle(name))
        } else {
            let typ = self.finder.find(index)?;
            let typ = typ.parse()?;
            match typ {
                TypeData::MemberFunction(t) => {
                    let (ztatic, ret, args) = self.dump_method_parts(t)?;
                    let ztatic = if ztatic { "static " } else { "" };
                    Ok(FuncName::Undecorated(format!(
                        "{}{}{}({})",
                        ztatic,
                        Self::fix_return(ret),
                        name,
                        args
                    )))
                }
                TypeData::Procedure(t) => {
                    let (ret, args) = self.dump_procedure_parts(t)?;
                    Ok(FuncName::Undecorated(format!(
                        "{}{}({})",
                        Self::fix_return(ret),
                        name,
                        args
                    )))
                }
                _ => {
                    error!("Function {} hasn't a function type", name);
                    Ok(FuncName::Undecorated(name.to_string()))
                }
            }
        }
    }

    #[inline(always)]
    fn fix_return(mut name: String) -> String {
        if !name.is_empty() {
            name.push(' ');
        }
        name
    }

    fn demangle(ident: &str) -> FuncName {
        // If the name is not mangled maybe we can guess stacksize in using it.
        // So the boolean flag in the returned value is here for that (true == known language)
        // For information:
        //  - msvc-demangler has no problem with symbols containing ".llvm."

        let lang = Name::new(ident).detect_language();
        if lang == Language::Unknown {
            return FuncName::get_unknown(ident.to_string());
        }

        let name = Name::with_language(ident, lang);
        match name.demangle(DemangleOptions {
            format: DemangleFormat::Full,
            with_arguments: true,
        }) {
            Some(demangled) => FuncName::Undecorated(demangled),
            None => {
                warn!("Didn't manage to demangle {}", ident);
                FuncName::Undecorated(ident.to_string())
            }
        }
    }

    fn dump_procedure_parts(&self, typ: ProcedureType) -> Result<(String, String)> {
        let ret_typ = if let Some(ret_typ) = typ.return_type {
            let attrs = typ.attributes;
            if attrs.is_constructor() || attrs.cxx_return_udt() {
                "".to_string()
            } else {
                self.dump_index(ret_typ)?
            }
        } else {
            "".to_string()
        };
        let args_typ = self.dump_index(typ.argument_list)?;

        Ok((ret_typ, args_typ))
    }

    fn check_this_type(&self, this: TypeIndex, class: TypeIndex) -> Result<bool> {
        let this = self.finder.find(this)?;
        let this = this.parse()?;
        Ok(if let TypeData::Pointer(this) = this {
            this.underlying_type == class
        } else {
            false
        })
    }

    fn dump_method_parts(&self, typ: MemberFunctionType) -> Result<(bool, String, String)> {
        let attrs = typ.attributes;
        let ret_typ = if attrs.is_constructor() || attrs.cxx_return_udt() {
            "".to_string()
        } else {
            self.dump_index(typ.return_type)?
        };
        let args_typ = self.dump_index(typ.argument_list)?;
        // Note: "this" isn't dumped but there are some cases in rust code where
        // a first argument shouldn't be "this" but in fact it is:
        // https://hg.mozilla.org/releases/mozilla-release/annotate/7ece03f6971968eede29275477502309bbe399da/toolkit/components/bitsdownload/src/bits_interface/task/service_task.rs#l217
        // So we dump "this" when the underlying type (modulo pointer) is different from the class type

        let ztatic = typ.this_pointer_type.is_none();
        let args_typ = if !ztatic {
            let this_typ = typ.this_pointer_type.unwrap();
            if !self.check_this_type(this_typ, typ.class_type)? {
                let this_typ = self.dump_index(this_typ)?;
                if args_typ.is_empty() {
                    this_typ
                } else {
                    format!("{}, {}", this_typ, args_typ)
                }
            } else {
                args_typ
            }
        } else {
            args_typ
        };

        Ok((ztatic, ret_typ, args_typ))
    }

    fn dump_attributes(attrs: Vec<PointerAttributes>) -> String {
        attrs
            .iter()
            .fold(String::new(), |mut buf, attr| {
                if attr.is_const() {
                    buf.push_str(" const ");
                }
                match attr.pointer_mode() {
                    PointerMode::Pointer => buf.push('*'),
                    PointerMode::LValueReference => buf.push('&'),
                    PointerMode::Member => buf.push_str("::*"),
                    PointerMode::MemberFunction => buf.push_str("::"),
                    PointerMode::RValueReference => buf.push_str("&&"),
                }
                buf
            })
            .trim_start()
            .to_string()
    }

    fn dump_ptr(&self, ptr: PointerType) -> Result<String> {
        let mut attributes = Vec::new();
        attributes.push(ptr.attributes);
        let mut ptr = ptr;
        loop {
            let typ = self.finder.find(ptr.underlying_type)?;
            let typ = typ.parse()?;
            match typ {
                TypeData::Pointer(t) => {
                    attributes.push(t.attributes);
                    ptr = t;
                }
                TypeData::MemberFunction(t) => {
                    let (_, ret, args) = self.dump_method_parts(t)?;
                    let attrs = Self::dump_attributes(attributes);
                    return Ok(format!("{}({})({})", Self::fix_return(ret), attrs, args));
                }
                TypeData::Procedure(t) => {
                    let (ret, args) = self.dump_procedure_parts(t)?;
                    let attrs = Self::dump_attributes(attributes);
                    return Ok(format!("{}({})({})", Self::fix_return(ret), attrs, args));
                }
                _ => {
                    let typ = self.dump_data(typ)?;
                    let attrs = Self::dump_attributes(attributes);
                    let c = typ.chars().last().unwrap();
                    return Ok(if c == '*' || c == '&' {
                        format!("{}{}", typ, attrs)
                    } else {
                        format!("{} {}", typ, attrs)
                    });
                }
            }
        }
    }

    fn dump_index(&self, index: TypeIndex) -> Result<String> {
        let typ = self.finder.find(index)?;
        let typ = typ.parse()?;

        self.dump_data(typ)
    }

    fn dump_data(&self, typ: TypeData) -> Result<String> {
        let typ = match typ {
            TypeData::Primitive(t) => {
                // TODO: check that these names are what we want to see
                let name = match t.kind {
                    PrimitiveKind::NoType => "<NoType>",
                    PrimitiveKind::Void => "void",
                    PrimitiveKind::Char => "signed char",
                    PrimitiveKind::UChar => "unsigned char",
                    PrimitiveKind::RChar => "char",
                    PrimitiveKind::WChar => "wchar_t",
                    PrimitiveKind::RChar16 => "char16_t",
                    PrimitiveKind::RChar32 => "char32_t",
                    PrimitiveKind::I8 => "signed char",
                    PrimitiveKind::U8 => "unsigned char",
                    PrimitiveKind::I16 => "short",
                    PrimitiveKind::U16 => "unsigned short",
                    PrimitiveKind::I32 => "int",
                    PrimitiveKind::U32 => "unsigned int",
                    PrimitiveKind::I64 => "long long",
                    PrimitiveKind::U64 => "unsigned long long",
                    PrimitiveKind::I128 => "int128_t",
                    PrimitiveKind::U128 => "uint128_t",
                    PrimitiveKind::F16 => "float16_t",
                    PrimitiveKind::F32 => "float",
                    PrimitiveKind::F32PP => "float",
                    PrimitiveKind::F48 => "float48_t",
                    PrimitiveKind::F64 => "double",
                    PrimitiveKind::F80 => "long double",
                    PrimitiveKind::F128 => "long double",
                    PrimitiveKind::Complex32 => "complex<float>",
                    PrimitiveKind::Complex64 => "complex<double>",
                    PrimitiveKind::Complex80 => "complex<long double>",
                    PrimitiveKind::Complex128 => "complex<long double>",
                    PrimitiveKind::Bool8 => "bool",
                    PrimitiveKind::Bool16 => "bool16_t",
                    PrimitiveKind::Bool32 => "bool32_t",
                    PrimitiveKind::Bool64 => "bool64_t",
                    PrimitiveKind::HRESULT => "HRESULT",
                };

                if t.indirection.is_some() {
                    format!("{} *", name)
                } else {
                    name.to_string()
                }
            }
            TypeData::Class(t) => {
                // TODO: should we really print this ?
                let name = match t.kind {
                    ClassKind::Class => "class",
                    ClassKind::Interface => "interface",
                    ClassKind::Struct => "struct",
                };
                format!("{} {}", name, t.name)
            }
            TypeData::MemberFunction(t) => {
                let (_, ret, args) = self.dump_method_parts(t)?;
                format!("{}()({})", Self::fix_return(ret), args)
            }
            TypeData::Procedure(t) => {
                let (ret, args) = self.dump_procedure_parts(t)?;
                format!("{}()({})", Self::fix_return(ret), args)
            }
            TypeData::ArgumentList(t) => {
                let mut buf = String::new();
                if let Some((last, args)) = t.arguments.split_last() {
                    for index in args.iter() {
                        let typ = self.dump_index(*index)?;
                        buf.push_str(&typ);
                        buf.push_str(", ");
                    }
                    let typ = self.dump_index(*last)?;
                    buf.push_str(&typ);
                }
                buf
            }
            TypeData::Pointer(t) => self.dump_ptr(t)?,
            TypeData::Array(t) => {
                let elmt_typ = self.dump_index(t.element_type)?;
                let dims = "[]".repeat(t.dimensions.len());
                format!("{}{}", elmt_typ, dims)
            }
            TypeData::Union(t) => format!("union {}", t.name),
            TypeData::Enumeration(t) => format!("enum {}", t.name),
            TypeData::Enumerate(t) => format!("enum class {}", t.name),
            TypeData::Modifier(t) => {
                let underlying_typ = self.dump_index(t.underlying_type)?;
                if t.constant {
                    format!("const {}", underlying_typ)
                } else {
                    underlying_typ
                }
            }
            _ => format!("unhandled type /* {:?} */", typ),
        };

        Ok(typ)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_funcname_sps() {
        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("_foo@123".to_string()) {
            assert_eq!(name, "foo");
            assert_eq!(sps, 123);
        }

        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("@foo@123".to_string()) {
            assert_eq!(name, "foo");
            assert_eq!(sps, 115);
        }

        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("@foo@3".to_string()) {
            assert_eq!(name, "foo");
            assert_eq!(sps, 0);
        }
    }

    #[test]
    fn test_funcname() {
        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("_foo@123()".to_string()) {
            assert_eq!(name, "_foo@123()");
            assert_eq!(sps, 0);
        }

        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("_foo@".to_string()) {
            assert_eq!(name, "foo@");
            assert_eq!(sps, 0);
        }

        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("_foo".to_string()) {
            assert_eq!(name, "foo");
            assert_eq!(sps, 0);
        }

        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("_foo@bar".to_string()) {
            assert_eq!(name, "foo@bar");
            assert_eq!(sps, 0);
        }

        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("foobar".to_string()) {
            assert_eq!(name, "foobar");
            assert_eq!(sps, 0);
        }

        if let FuncName::Unknown((name, sps)) = FuncName::get_unknown("@foobar".to_string()) {
            assert_eq!(name, "@foobar");
            assert_eq!(sps, 0);
        }
    }
}
