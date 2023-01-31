// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::ops::Bound::{Excluded, Included};
use symbolic::debuginfo::Object;

use crate::line::Lines;

const PDB_MAGIC: u64 = 7381245236781214029;

#[derive(Clone, Debug, Default)]
pub struct Symbol {
    pub name: String,
    pub is_public: bool,
    pub is_multiple: bool,
    pub is_synthetic: bool,
    pub rva: u32,
    pub len: u32,
    pub parameter_size: u32,
    pub source: Lines,
}

pub type Symbols = BTreeMap<u32, Symbol>;

pub trait ContainsSymbol {
    fn is_inside_symbol(&self, rva: u32) -> bool;
}

impl ContainsSymbol for Symbols {
    fn is_inside_symbol(&self, rva: u32) -> bool {
        let last = self.range((Included(0), Excluded(rva))).next_back();
        last.map_or(false, |last| rva < (last.1.rva + last.1.len))
    }
}

impl Display for Symbol {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if self.is_public {
            writeln!(
                f,
                "PUBLIC {}{:x} {:x} {}",
                if self.is_multiple { "m " } else { "" },
                self.rva,
                self.parameter_size,
                self.name,
            )?;
        } else {
            writeln!(
                f,
                "FUNC {}{:x} {:x} {:x} {}",
                if self.is_multiple { "m " } else { "" },
                self.rva,
                self.len,
                self.parameter_size,
                self.name,
            )?;

            write!(f, "{}", self.source)?;
        }

        Ok(())
    }
}

impl Symbol {
    pub(super) fn remap_lines(&mut self, file_remapping: Option<&[u32]>) {
        if let Some(file_remapping) = file_remapping {
            for line in self.source.lines.iter_mut() {
                line.file_id = file_remapping[line.file_id as usize];
            }
        }
    }

    pub(super) fn remap_inlines(
        &mut self,
        file_remapping: Option<&[u32]>,
        inline_origin_remapping: &[u32],
    ) {
        let inlines = std::mem::take(&mut self.source.inlines);
        self.source.inlines = inlines
            .into_iter()
            .map(|(mut inline_site, address_ranges)| {
                if let Some(file_remapping) = file_remapping {
                    inline_site.call_file_id = file_remapping[inline_site.call_file_id as usize];
                }
                inline_site.inline_origin_id =
                    inline_origin_remapping[inline_site.inline_origin_id as usize];
                (inline_site, address_ranges)
            })
            .collect();
    }
}

pub(super) fn add_executable_section_symbols(
    mut syms: Symbols,
    name: &str,
    object: &Object,
) -> Symbols {
    let object = goblin::Object::parse(object.data());
    match object {
        Ok(goblin::Object::Elf(elf)) => {
            for header in elf.section_headers {
                if header.is_executable() {
                    let name = if name.is_empty() { "unknown" } else { name };
                    let section_name = elf.shdr_strtab.get_at(header.sh_name).unwrap_or("unknown");
                    let symbol_name = format!("<{section_name} ELF section in {name}>");
                    let rva = header.sh_addr as u32;
                    syms.entry(rva).or_insert(Symbol {
                        name: symbol_name,
                        is_public: true,
                        is_multiple: false,
                        is_synthetic: true,
                        rva,
                        len: 0,
                        parameter_size: 0,
                        source: Lines::new(),
                    });
                }
            }
        }
        Ok(goblin::Object::PE(_)) | Ok(goblin::Object::Unknown(PDB_MAGIC)) => {
            syms = append_dummy_symbol_pe_pdb(syms, name);
        }
        _ => (),
    }
    syms
}

fn append_dummy_symbol_pe_pdb(mut syms: Symbols, name: &str) -> Symbols {
    let (rva, len) = if let Some((_, last_sym)) = syms.iter().next_back() {
        (last_sym.rva, last_sym.len)
    } else {
        return syms;
    };

    let rva = if len == 0 { rva + 1 } else { rva + len };

    let name = if name.is_empty() {
        String::from("<unknown>")
    } else {
        format!("<unknown in {name}>")
    };

    syms.entry(rva).or_insert(Symbol {
        name,
        is_public: true,
        is_multiple: false,
        is_synthetic: true,
        rva,
        len: 0,
        parameter_size: 0,
        source: Lines::new(),
    });

    syms
}

// Get separated debugging information into .gnu_debugdata section.
// See https://sourceware.org/gdb/onlinedocs/gdb/MiniDebugInfo.html.
pub(super) fn get_compressed_minidebuginfo(object: &Object) -> Option<Vec<u8>> {
    let data = object.data();
    let object = goblin::Object::parse(data);
    if let Ok(goblin::Object::Elf(elf)) = object {
        for header in elf.section_headers {
            if let Some(section_name) = elf.shdr_strtab.get_at(header.sh_name) {
                if section_name == ".gnu_debugdata" {
                    let (start, length) = (header.sh_offset as usize, header.sh_size as usize);
                    let mut buf: &[u8] = &data[start..(start + length)];
                    let mut out: Vec<u8> = Vec::new();
                    lzma_rs::xz_decompress(&mut buf, &mut out).ok()?;
                    return Some(out);
                }
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
pub struct ParsedWinFuncName {
    pub name: String,
    pub param_size: Option<u32>,
}

impl ParsedWinFuncName {
    pub fn name_only(name: String) -> Self {
        Self {
            name,
            param_size: None,
        }
    }

    pub fn parse_unknown(name: &str) -> Self {
        if name.contains(|c| c == ':' || c == '(') {
            Self::name_only(name.to_string())
        } else {
            Self::parse_c_decorated(name)
        }
    }

    /// Call this if c_decorated_name does not contain ':' or '('.
    pub fn parse_c_decorated(c_decorated_name: &str) -> Self {
        // https://docs.microsoft.com/en-us/cpp/build/reference/decorated-names?view=vs-2019
        // __cdecl Leading underscore (_)
        // __stdcall Leading underscore (_) and a trailing at sign (@) followed by the number of bytes in the parameter list in decimal
        // __fastcall Leading and trailing at signs (@) followed by a decimal number representing the number of bytes in the parameter list
        // __vectorcall Two trailing at signs (@@) followed by a decimal number of bytes in the parameter list
        // > In a 64-bit environment, C or extern "C" functions are only decorated when using the __vectorcall calling convention."

        // Parse __vectorcall.
        if let Some((name, param_size)) = c_decorated_name.rsplit_once("@@") {
            if let Ok(param_size) = param_size.parse::<u32>() {
                return Self {
                    name: name.to_string(),
                    param_size: Some(param_size),
                };
            }
        }

        // Parse the other three.
        if !c_decorated_name.is_empty() {
            if let ("@" | "_", rest) = c_decorated_name.split_at(1) {
                if let Some((name, param_size)) = rest.rsplit_once('@') {
                    if let Ok(param_size) = param_size.parse::<u32>() {
                        // __stdcall or __fastcall
                        return Self {
                            name: name.to_string(),
                            param_size: Some(param_size),
                        };
                    }
                }
                if &c_decorated_name[0..1] == "_" {
                    // __cdecl
                    return Self::name_only(rest.to_string());
                }
            }
        }

        Self::name_only(c_decorated_name.to_string())
    }
}

fn is_constant_string(name: &str) -> bool {
    name.starts_with("??_C")
}

fn is_constant_number(name: &str) -> bool {
    if let Some(name) = name.strip_prefix("__") {
        name.starts_with("real@") || name.starts_with("xmm@") || name.starts_with("ymm@")
    } else {
        false
    }
}

pub fn should_skip_symbol(name: &str) -> bool {
    is_constant_string(name) || is_constant_number(name)
}
