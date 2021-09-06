// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::ops::Bound::{Excluded, Included};
use symbolic::debuginfo::Object;

use crate::line::Lines;

#[derive(Clone, Debug, Default)]
pub(super) struct ElfSymbol {
    pub name: String,
    pub is_public: bool,
    pub is_multiple: bool,
    pub is_synthetic: bool,
    pub rva: u32,
    pub len: u32,
    pub parameter_size: u32,
    pub source: Lines,
}

pub(super) type ElfSymbols = BTreeMap<u32, ElfSymbol>;

pub trait ContainsSymbol {
    fn is_inside_symbol(&self, rva: u32) -> bool;
}

impl ContainsSymbol for ElfSymbols {
    fn is_inside_symbol(&self, rva: u32) -> bool {
        let last = self.range((Included(0), Excluded(rva))).next_back();
        last.map_or(false, |last| rva < (last.1.rva + last.1.len))
    }
}

impl Display for ElfSymbol {
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

impl ElfSymbol {
    pub(super) fn fix_lines(&mut self, remapping: Option<&Vec<u32>>) {
        if let Some(remapping) = remapping {
            for line in self.source.lines.iter_mut() {
                line.file_id = remapping[line.file_id as usize];
            }
        }
    }
}

pub(super) fn add_executable_section_symbols(
    mut syms: ElfSymbols,
    name: &str,
    object: &Object,
) -> ElfSymbols {
    let object = goblin::Object::parse(object.data());
    if let Ok(goblin::Object::Elf(elf)) = object {
        for header in elf.section_headers {
            if header.is_executable() {
                let name = if name.is_empty() { "unknown" } else { name };
                let section_name = elf.shdr_strtab.get_at(header.sh_name).unwrap_or("unknown");
                let symbol_name = format!("<{} ELF section in {}>", section_name, name);
                let rva = header.sh_addr as u32;
                syms.entry(rva).or_insert(ElfSymbol {
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

    syms
}
