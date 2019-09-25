// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::{
    AddressMap, FrameTable, PdbInternalRva, PdbInternalSectionOffset, ProcedureSymbol,
    PublicSymbol, Result, TypeIndex,
};
use std::io::Write;

use super::line::Lines;
use super::source::SourceLineCollector;
use super::types::{FuncName, TypeDumper};

pub(super) struct BlockInfo {
    pub rva: u32,
    pub offset: PdbInternalSectionOffset,
    pub len: u32,
}

#[derive(Debug)]
pub(super) struct SelectedSymbol {
    pub name: String,
    pub type_index: TypeIndex,
    pub is_public: bool,
    pub is_multiple: bool,
    pub offset: PdbInternalSectionOffset,
    pub len: u32,
    pub source: Lines,
}

impl SelectedSymbol {
    fn split_address(&self, address_map: &AddressMap) -> Vec<(u32, u32)> {
        let start = self.offset.to_internal_rva(&address_map).unwrap();
        let end = PdbInternalRva(start.0 + self.len);
        let mut ranges = Vec::new();

        for rg in address_map.rva_ranges(start..end) {
            if rg.start != rg.end {
                ranges.push((rg.start.0, rg.end.0 - rg.start.0));
            }
        }
        ranges
    }

    fn get_und(&self, dumper: &TypeDumper) -> FuncName {
        if let Ok(und) = dumper.dump_function(&self.name, self.type_index) {
            und
        } else {
            // Shouldn't happen
            FuncName::get_unknown(self.name.clone())
        }
    }

    fn get_stack_param_size(&self, _address_map: &AddressMap, _frame_table: &FrameTable) -> u32 {
        // TODO: check if this value is the correct one
        // For now (legacy) return 0
        /*if frame_table.is_empty() {
            return 0;
        }

        let internal_rva = self.offset.to_internal_rva(&address_map).unwrap();
        if let Ok(frame) = frame_table.iter_at_rva(internal_rva).next() {
            if let Some(frame) =  frame {
                return frame.params_size;
            }
        }*/
        0
    }

    fn get_multiple(&self) -> &'static str {
        if self.is_multiple {
            "m "
        } else {
            ""
        }
    }

    pub(super) fn update_private(
        &mut self,
        function: ProcedureSymbol,
        block_info: BlockInfo,
        line_collector: &SourceLineCollector,
    ) -> Result<()> {
        self.is_multiple = true;

        // TODO: this is legacy code
        // this is probably useless.
        let fun_name = function.name.to_string().into_owned();
        if fun_name < self.name {
            self.name = fun_name;
            self.type_index = function.type_index;
            self.offset = block_info.offset;
            self.len = block_info.len;
            self.source = line_collector.collect_source_lines(block_info.offset, block_info.len)?;
        }

        Ok(())
    }

    pub(super) fn update_public(&mut self, symbol: PublicSymbol) {
        if self.is_public {
            self.is_multiple = true;
            let sym_name = symbol.name.to_string().into_owned();
            if sym_name < self.name {
                self.name = sym_name;
                self.offset = symbol.offset;
            }
        }
    }

    pub(super) fn dump<W: Write>(
        &mut self,
        address_map: &AddressMap,
        frame_table: &FrameTable,
        dumper: &TypeDumper,
        rva: u32,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let name = self.get_und(dumper);
        let (name, stack_param_size) = match name {
            FuncName::Undecorated(name) => {
                (name, self.get_stack_param_size(address_map, frame_table))
            }
            FuncName::Unknown((name, sps)) => (name, sps),
        };
        if self.is_public {
            writeln!(writer, "PUBLIC {}{:x} {}", self.get_multiple(), rva, name)
        } else {
            for (rva, len) in self.split_address(address_map) {
                writeln!(
                    writer,
                    "FUNC {}{:x} {:x} {} {}",
                    self.get_multiple(),
                    rva,
                    len,
                    stack_param_size,
                    name
                )?;
            }
            self.source.dump(self.len, &address_map, writer)
        }
    }
}
