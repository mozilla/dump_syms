// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use bitflags::bitflags;
use hashbrown::HashMap;
use log::{error, warn};
use pdb::{
    ArgumentList, ArrayType, ClassKind, ClassType, FallibleIterator, FunctionAttributes,
    MemberFunctionType, ModifierType, PointerMode, PointerType, PrimitiveKind, PrimitiveType,
    ProcedureType, RawString, Result, TypeData, TypeFinder, TypeIndex, TypeInformation, UnionType,
    Variant,
};
use symbolic::common::{Language, Name, NameMangling};
use symbolic::demangle::{Demangle, DemangleOptions};

use crate::common;

type FwdRefSize<'a> = HashMap<RawString<'a>, u32>;

#[derive(Eq, PartialEq)]
enum ThisKind {
    This,
    ConstThis,
    NotThis,
}

impl ThisKind {
    fn new(is_this: bool, is_const: bool) -> Self {
        if is_this {
            if is_const {
                Self::ConstThis
            } else {
                Self::This
            }
        } else {
            Self::NotThis
        }
    }
}

#[derive(Debug)]
struct PtrAttributes {
    is_pointer_const: bool,
    is_pointee_const: bool,
    mode: PointerMode,
}

bitflags! {
    pub(super) struct DumperFlags: u32 {
        const NO_FUNCTION_RETURN = 0b1;
        const SPACE_AFTER_COMMA = 0b10;
        const SPACE_BEFORE_POINTER = 0b100;
        const NAME_ONLY = 0b1000;
    }
}

impl Default for DumperFlags {
    fn default() -> Self {
        Self::NO_FUNCTION_RETURN | Self::SPACE_AFTER_COMMA | Self::NAME_ONLY
    }
}

pub(super) struct TypeDumper<'a> {
    finder: TypeFinder<'a>,
    fwd: FwdRefSize<'a>,
    ptr_size: u32,
    flags: DumperFlags,
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
        // https://docs.microsoft.com/en-us/cpp/build/reference/decorated-names?view=vs-2019
        // __cdecl Leading underscore (_)
        // __stdcall Leading underscore (_) and a trailing at sign (@) followed by the number of bytes in the parameter list in decimal
        // __fastcall Leading and trailing at signs (@) followed by a decimal number representing the number of bytes in the parameter list

        if name.is_empty() {
            return FuncName::Unknown((name, 0));
        }

        let (first, sub) = name.split_at(1);

        if (first != "_" && first != "@") || sub.find(|c: char| c == ':' || c == '(').is_some() {
            return FuncName::Unknown((name, 0));
        }

        let parts: Vec<_> = sub.rsplitn(2, '@').collect();
        if parts.len() <= 1 {
            let name = if first == "_" { sub.to_string() } else { name };
            return FuncName::Unknown((name, 0));
        }

        if let Ok(stack_param_size) = parts[0].parse::<u32>() {
            let sps = if first == "@" {
                // __fastcall: the two first args are put in ECX and EDX
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
    pub fn new<'b>(
        type_info: &'a TypeInformation<'b>,
        ptr_size: u32,
        flags: DumperFlags,
    ) -> Result<Self> {
        let mut types = type_info.iter();
        let mut finder = type_info.finder();

        // Some struct are incomplete so they've no size but they're forward references
        // So create a map containing names defining the struct (when they aren't fwd ref) and their size.
        // Once we'll need to compute a size for a fwd ref, we just use this map.
        let mut fwd = FwdRefSize::default();

        while let Some(typ) = types.next()? {
            finder.update(&types);
            if let Ok(typ) = typ.parse() {
                match typ {
                    TypeData::Class(t) => {
                        if !t.properties.forward_reference() {
                            let name = t.unique_name.unwrap_or(t.name);
                            fwd.insert(name, t.size.into());
                        }
                    }
                    TypeData::Union(t) => {
                        if !t.properties.forward_reference() {
                            let name = t.unique_name.unwrap_or(t.name);
                            fwd.insert(name, t.size);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(Self {
            finder,
            fwd,
            ptr_size,
            flags,
        })
    }

    fn find(&self, index: TypeIndex) -> Result<TypeData> {
        let typ = self.finder.find(index).unwrap();
        typ.parse()
    }

    fn get_class_size(&self, typ: &ClassType) -> u32 {
        if typ.properties.forward_reference() {
            let name = typ.unique_name.unwrap_or(typ.name);

            // The name can not be in self.fwd because the type can be a forward reference to itself !!
            // (it's possible with an empty struct)
            *self.fwd.get(&name).unwrap_or(&typ.size.into())
        } else {
            typ.size.into()
        }
    }

    fn get_union_size(&self, typ: &UnionType) -> u32 {
        if typ.properties.forward_reference() {
            let name = typ.unique_name.unwrap_or(typ.name);
            *self.fwd.get(&name).unwrap_or(&typ.size)
        } else {
            typ.size
        }
    }

    pub fn get_type_size(&self, index: TypeIndex) -> u32 {
        let typ = self.find(index);
        typ.ok().map_or(0, |typ| self.get_data_size(&typ))
    }

    fn get_data_size(&self, typ: &TypeData) -> u32 {
        match typ {
            TypeData::Primitive(t) => {
                if t.indirection.is_some() {
                    return self.ptr_size;
                }
                match t.kind {
                    PrimitiveKind::NoType | PrimitiveKind::Void => 0,
                    PrimitiveKind::Char
                    | PrimitiveKind::UChar
                    | PrimitiveKind::RChar
                    | PrimitiveKind::I8
                    | PrimitiveKind::U8
                    | PrimitiveKind::Bool8 => 1,
                    PrimitiveKind::WChar
                    | PrimitiveKind::RChar16
                    | PrimitiveKind::Short
                    | PrimitiveKind::UShort
                    | PrimitiveKind::I16
                    | PrimitiveKind::U16
                    | PrimitiveKind::F16
                    | PrimitiveKind::Bool16 => 2,
                    PrimitiveKind::RChar32
                    | PrimitiveKind::Long
                    | PrimitiveKind::ULong
                    | PrimitiveKind::I32
                    | PrimitiveKind::U32
                    | PrimitiveKind::F32
                    | PrimitiveKind::F32PP
                    | PrimitiveKind::Bool32
                    | PrimitiveKind::HRESULT => 4,
                    PrimitiveKind::I64
                    | PrimitiveKind::U64
                    | PrimitiveKind::Quad
                    | PrimitiveKind::UQuad
                    | PrimitiveKind::F64
                    | PrimitiveKind::Complex32
                    | PrimitiveKind::Bool64 => 8,
                    PrimitiveKind::I128
                    | PrimitiveKind::U128
                    | PrimitiveKind::Octa
                    | PrimitiveKind::UOcta
                    | PrimitiveKind::F128
                    | PrimitiveKind::Complex64 => 16,
                    PrimitiveKind::F48 => 6,
                    PrimitiveKind::F80 => 10,
                    PrimitiveKind::Complex80 => 20,
                    PrimitiveKind::Complex128 => 32,
                    _ => {
                        panic!("Unsupported primitive type {:?}", t.kind);
                    }
                }
            }
            TypeData::Class(t) => self.get_class_size(t),
            TypeData::MemberFunction(_) => self.ptr_size,
            TypeData::Procedure(_) => self.ptr_size,
            TypeData::Pointer(t) => t.attributes.size().into(),
            TypeData::Array(t) => *t.dimensions.last().unwrap(),
            TypeData::Union(t) => self.get_union_size(t),
            TypeData::Enumeration(t) => self.get_type_size(t.underlying_type),
            TypeData::Enumerate(t) => match t.value {
                Variant::I8(_) | Variant::U8(_) => 1,
                Variant::I16(_) | Variant::U16(_) => 2,
                Variant::I32(_) | Variant::U32(_) => 4,
                Variant::I64(_) | Variant::U64(_) => 8,
            },
            TypeData::Modifier(t) => self.get_type_size(t.underlying_type),
            _ => 0,
        }
    }

    /// Dump a ProcedureType at the given TypeIndex
    /// If the TypeIndex is 0 then try to use demanglers to have the correct name
    pub fn dump_function(&self, name: &str, index: TypeIndex) -> Result<FuncName> {
        if name.is_empty() {
            Ok(FuncName::Undecorated("<name omitted>".to_string()))
        } else if index == TypeIndex(0) {
            Ok(Self::demangle(name))
        } else {
            let typ = self.find(index)?;
            match typ {
                TypeData::MemberFunction(t) => {
                    let (ztatic, const_meth, ret, args) = self.dump_method_parts(
                        t,
                        self.flags.intersects(DumperFlags::NO_FUNCTION_RETURN),
                    )?;
                    let ztatic = if ztatic { "static " } else { "" };
                    let konst = if const_meth { " const" } else { "" };
                    Ok(FuncName::Undecorated(format!(
                        "{}{}{}({}){}",
                        ztatic,
                        Self::fix_return(ret),
                        name,
                        args,
                        konst,
                    )))
                }
                TypeData::Procedure(t) => {
                    let (ret, args) = self.dump_procedure_parts(
                        t,
                        self.flags.intersects(DumperFlags::NO_FUNCTION_RETURN),
                    )?;
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

    #[inline(always)]
    fn fix_mangled_name(name: String) -> String {
        name.replace("__cdecl", "")
            .replace("public: ", "")
            .replace("protected: ", "")
            .replace("private: ", "")
            .replace("(void)", "")
            .replace("  ", " ")
    }

    pub fn demangle(ident: &str) -> FuncName {
        // If the name is not mangled maybe we can guess stacksize in using it.
        // So the boolean flag in the returned value is here for that (true == known language)
        // For information:
        //  - msvc-demangler has no problem with symbols containing ".llvm."
        let lang = Name::new(ident, NameMangling::Mangled, Language::Unknown).detect_language();
        if lang == Language::Unknown {
            return FuncName::get_unknown(ident.to_string());
        }

        let name = Name::new(ident, NameMangling::Mangled, lang);
        let name = common::fix_symbol_name(&name);

        match name.demangle(DemangleOptions::complete()) {
            Some(demangled) => {
                if demangled == ident {
                    // Maybe the langage detection was finally wrong
                    FuncName::get_unknown(demangled)
                } else {
                    let demangled = Self::fix_mangled_name(demangled);
                    FuncName::Undecorated(demangled)
                }
            }
            None => {
                warn!("Didn't manage to demangle {}", ident);
                FuncName::Undecorated(ident.to_string())
            }
        }
    }

    fn get_return_type(
        &self,
        typ: Option<TypeIndex>,
        attrs: FunctionAttributes,
        no_return: bool,
    ) -> String {
        typ.filter(|_| !no_return && !attrs.is_constructor())
            .and_then(|r| self.dump_index(r).ok())
            .map_or_else(|| "".to_string(), |r| r)
    }

    fn dump_procedure_parts(
        &self,
        typ: ProcedureType,
        no_return: bool,
    ) -> Result<(String, String)> {
        let ret_typ = self.get_return_type(typ.return_type, typ.attributes, no_return);
        let args_typ = self.dump_index(typ.argument_list)?;

        Ok((ret_typ, args_typ))
    }

    fn check_this_type(&self, this: TypeIndex, class: TypeIndex) -> Result<ThisKind> {
        let this = self.find(this)?;

        let is_this = match this {
            TypeData::Pointer(ptr) => {
                if ptr.underlying_type == class {
                    ThisKind::This
                } else {
                    let underlying_typ = self.find(ptr.underlying_type)?;
                    if let TypeData::Modifier(modifier) = underlying_typ {
                        ThisKind::new(modifier.underlying_type == class, modifier.constant)
                    } else {
                        ThisKind::NotThis
                    }
                }
            }
            TypeData::Modifier(modifier) => {
                let underlying_typ = self.find(modifier.underlying_type)?;
                if let TypeData::Pointer(ptr) = underlying_typ {
                    ThisKind::new(ptr.underlying_type == class, modifier.constant)
                } else {
                    ThisKind::NotThis
                }
            }
            _ => ThisKind::NotThis,
        };
        Ok(is_this)
    }

    fn dump_method_parts(
        &self,
        typ: MemberFunctionType,
        no_return: bool,
    ) -> Result<(bool, bool, String, String)> {
        let ret_typ = self.get_return_type(Some(typ.return_type), typ.attributes, no_return);
        let args_typ = self.dump_index(typ.argument_list)?;
        // Note: "this" isn't dumped but there are some cases in rust code where
        // a first argument shouldn't be "this" but in fact it is:
        // https://hg.mozilla.org/releases/mozilla-release/annotate/7ece03f6971968eede29275477502309bbe399da/toolkit/components/bitsdownload/src/bits_interface/task/service_task.rs#l217
        // So we dump "this" when the underlying type (modulo pointer) is different from the class type

        let ztatic = typ.this_pointer_type.is_none();
        let (args_typ, const_meth) = if !ztatic {
            let this_typ = typ.this_pointer_type.unwrap();
            let this_kind = self.check_this_type(this_typ, typ.class_type)?;
            if this_kind == ThisKind::NotThis {
                let this_typ = self.dump_index(this_typ)?;
                if args_typ.is_empty() {
                    (this_typ, false)
                } else {
                    (format!("{}, {}", this_typ, args_typ), false)
                }
            } else {
                (args_typ, this_kind == ThisKind::ConstThis)
            }
        } else {
            (args_typ, false)
        };

        Ok((ztatic, const_meth, ret_typ, args_typ))
    }

    fn dump_attributes(&self, attrs: Vec<PtrAttributes>) -> String {
        attrs
            .iter()
            .rev()
            .fold(String::new(), |mut buf, attr| {
                if attr.is_pointee_const {
                    if self.flags.intersects(DumperFlags::SPACE_BEFORE_POINTER) {
                        buf.push_str(" const ");
                    } else {
                        buf.push_str(" const");
                    }
                }
                match attr.mode {
                    PointerMode::Pointer => buf.push('*'),
                    PointerMode::LValueReference => buf.push('&'),
                    PointerMode::Member => buf.push_str("::*"),
                    PointerMode::MemberFunction => buf.push_str("::*"),
                    PointerMode::RValueReference => buf.push_str("&&"),
                }
                if attr.is_pointer_const {
                    if self.flags.intersects(DumperFlags::SPACE_BEFORE_POINTER) {
                        buf.push_str(" const ");
                    } else {
                        buf.push_str(" const");
                    }
                }
                buf
            })
            .trim()
            .to_string()
    }

    fn dump_member_ptr(
        &self,
        fun: MemberFunctionType,
        attributes: Vec<PtrAttributes>,
    ) -> Result<String> {
        let class = self.dump_index(fun.class_type)?;
        let (_, _, ret, args) = self.dump_method_parts(fun, false)?;
        let attrs = self.dump_attributes(attributes);
        Ok(format!(
            "{}({}{})({})",
            Self::fix_return(ret),
            class,
            attrs,
            args
        ))
    }

    fn dump_proc_ptr(&self, fun: ProcedureType, attributes: Vec<PtrAttributes>) -> Result<String> {
        let (ret, args) = self.dump_procedure_parts(fun, false)?;
        let attrs = self.dump_attributes(attributes);
        Ok(format!("{}({})({})", Self::fix_return(ret), attrs, args))
    }

    fn dump_other_ptr(&self, typ: TypeData, attributes: Vec<PtrAttributes>) -> Result<String> {
        let typ = self.dump_data(typ)?;
        let attrs = self.dump_attributes(attributes);
        let c = typ.chars().last().unwrap();
        let space = if !attrs.starts_with('c')
            && (c == '*' || c == '&' || !self.flags.intersects(DumperFlags::SPACE_BEFORE_POINTER))
        {
            ""
        } else {
            " "
        };

        Ok(format!("{}{}{}", typ, space, attrs))
    }

    fn dump_ptr_helper(&self, attributes: Vec<PtrAttributes>, typ: TypeData) -> Result<String> {
        match typ {
            TypeData::MemberFunction(t) => self.dump_member_ptr(t, attributes),
            TypeData::Procedure(t) => self.dump_proc_ptr(t, attributes),
            _ => self.dump_other_ptr(typ, attributes),
        }
    }

    fn dump_ptr(&self, ptr: PointerType, is_const: bool) -> Result<String> {
        let mut attributes = Vec::new();
        attributes.push(PtrAttributes {
            is_pointer_const: ptr.attributes.is_const() || is_const,
            is_pointee_const: false,
            mode: ptr.attributes.pointer_mode(),
        });
        let mut ptr = ptr;
        loop {
            let typ = self.find(ptr.underlying_type)?;
            match typ {
                TypeData::Pointer(t) => {
                    attributes.push(PtrAttributes {
                        is_pointer_const: t.attributes.is_const(),
                        is_pointee_const: false,
                        mode: t.attributes.pointer_mode(),
                    });
                    ptr = t;
                }
                TypeData::Modifier(t) => {
                    // the vec cannot be empty since we push something in just before the loop
                    attributes.last_mut().unwrap().is_pointee_const = t.constant;
                    let typ = self.find(t.underlying_type)?;
                    if let TypeData::Pointer(t) = typ {
                        attributes.push(PtrAttributes {
                            is_pointer_const: t.attributes.is_const(),
                            is_pointee_const: false,
                            mode: t.attributes.pointer_mode(),
                        });
                        ptr = t;
                    } else {
                        return self.dump_ptr_helper(attributes, typ);
                    }
                }
                _ => {
                    return self.dump_ptr_helper(attributes, typ);
                }
            }
        }
    }

    fn get_array_info(&self, array: ArrayType) -> Result<(Vec<u32>, TypeData)> {
        // For an array int[12][34] it'll be represented as "int[34] *".
        // For any reason the 12 is lost...
        // The internal representation is: Pointer{ base: Array{ base: int, dim: 34 * sizeof(int)} }
        let mut base = array;
        let mut dims = Vec::new();
        dims.push(base.dimensions[0]);

        loop {
            let typ = self.find(base.element_type)?;
            match typ {
                TypeData::Array(a) => {
                    dims.push(a.dimensions[0]);
                    base = a;
                }
                _ => {
                    return Ok((dims, typ));
                }
            }
        }
    }

    fn dump_array(&self, array: ArrayType) -> Result<String> {
        let (dimensions, base) = self.get_array_info(array)?;
        let base_size = self.get_data_size(&base);
        let mut size = base_size;
        let mut dims = dimensions
            .iter()
            .rev()
            .map(|dim| {
                let s = if size != 0 {
                    format!("[{}]", dim / size)
                } else {
                    // The base size can be zero: struct A{}; void foo(A x[10])
                    // No way to get the array dimension in such a case
                    "[]".to_string()
                };
                size = *dim;
                s
            })
            .collect::<Vec<String>>();
        dims.reverse();
        let base_typ = self.dump_data(base)?;
        Ok(format!("{}{}", base_typ, dims.join("")))
    }

    fn dump_modifier(&self, modifier: ModifierType) -> Result<String> {
        let typ = self.find(modifier.underlying_type)?;
        match typ {
            TypeData::Pointer(ptr) => self.dump_ptr(ptr, modifier.constant),
            TypeData::Primitive(prim) => Ok(self.dump_primitive(prim, modifier.constant)),
            _ => {
                let underlying_typ = self.dump_data(typ)?;
                Ok(if modifier.constant {
                    format!("const {}", underlying_typ)
                } else {
                    underlying_typ
                })
            }
        }
    }

    fn dump_class(&self, class: ClassType) -> String {
        if self.flags.intersects(DumperFlags::NAME_ONLY) {
            class.name.to_string().into()
        } else {
            let name = match class.kind {
                ClassKind::Class => "class",
                ClassKind::Interface => "interface",
                ClassKind::Struct => "struct",
            };
            format!("{} {}", name, class.name)
        }
    }

    fn dump_arg_list(&self, list: ArgumentList) -> Result<String> {
        let mut buf = String::new();
        let comma = if self.flags.intersects(DumperFlags::SPACE_AFTER_COMMA) {
            ", "
        } else {
            ","
        };
        if let Some((last, args)) = list.arguments.split_last() {
            for index in args.iter() {
                let typ = self.dump_index(*index)?;
                buf.push_str(&typ);
                buf.push_str(comma);
            }
            let typ = self.dump_index(*last)?;
            buf.push_str(&typ);
        }
        Ok(buf)
    }

    fn dump_primitive(&self, prim: PrimitiveType, is_const: bool) -> String {
        // TODO: check that these names are what we want to see
        let name = match prim.kind {
            PrimitiveKind::NoType => "<NoType>",
            PrimitiveKind::Void => "void",
            PrimitiveKind::Char => "signed char",
            PrimitiveKind::UChar => "unsigned char",
            PrimitiveKind::RChar => "char",
            PrimitiveKind::WChar => "wchar_t",
            PrimitiveKind::RChar16 => "char16_t",
            PrimitiveKind::RChar32 => "char32_t",
            PrimitiveKind::I8 => "int8_t",
            PrimitiveKind::U8 => "uint8_t",
            PrimitiveKind::Short => "short",
            PrimitiveKind::UShort => "unsigned short",
            PrimitiveKind::I16 => "int16_t",
            PrimitiveKind::U16 => "uint16_t",
            PrimitiveKind::Long => "long",
            PrimitiveKind::ULong => "unsigned long",
            PrimitiveKind::I32 => "int",
            PrimitiveKind::U32 => "unsigned int",
            PrimitiveKind::Quad => "long long",
            PrimitiveKind::UQuad => "unsigned long long",
            PrimitiveKind::I64 => "int64_t",
            PrimitiveKind::U64 => "uint64_t",
            PrimitiveKind::I128 | PrimitiveKind::Octa => "int128_t",
            PrimitiveKind::U128 | PrimitiveKind::UOcta => "uint128_t",
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
            _ => {
                panic!("Unsupported primitive type {:?}", prim.kind);
            }
        };

        if prim.indirection.is_some() {
            if self.flags.intersects(DumperFlags::SPACE_BEFORE_POINTER) {
                if is_const {
                    format!("{} const *", name)
                } else {
                    format!("{} *", name)
                }
            } else if is_const {
                format!("{} const*", name)
            } else {
                format!("{}*", name)
            }
        } else if is_const {
            format!("const {}", name)
        } else {
            name.to_string()
        }
    }

    fn dump_named(&self, base: &str, name: RawString) -> String {
        if self.flags.intersects(DumperFlags::NAME_ONLY) {
            name.to_string().into()
        } else {
            format!("{} {}", base, name)
        }
    }

    fn dump_index(&self, index: TypeIndex) -> Result<String> {
        let typ = self.find(index)?;
        self.dump_data(typ)
    }

    fn dump_data(&self, typ: TypeData) -> Result<String> {
        let typ = match typ {
            TypeData::Primitive(t) => self.dump_primitive(t, false),
            TypeData::Class(t) => self.dump_class(t),
            TypeData::MemberFunction(t) => {
                let (_, _, ret, args) = self
                    .dump_method_parts(t, self.flags.intersects(DumperFlags::NO_FUNCTION_RETURN))?;
                format!("{}()({})", Self::fix_return(ret), args)
            }
            TypeData::Procedure(t) => {
                let (ret, args) = self.dump_procedure_parts(
                    t,
                    self.flags.intersects(DumperFlags::NO_FUNCTION_RETURN),
                )?;
                format!("{}()({})", Self::fix_return(ret), args)
            }
            TypeData::ArgumentList(t) => self.dump_arg_list(t)?,
            TypeData::Pointer(t) => self.dump_ptr(t, false)?,
            TypeData::Array(t) => self.dump_array(t)?,
            TypeData::Union(t) => self.dump_named("union", t.name),
            TypeData::Enumeration(t) => self.dump_named("enum", t.name),
            TypeData::Enumerate(t) => self.dump_named("enum class", t.name),
            TypeData::Modifier(t) => self.dump_modifier(t)?,
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
