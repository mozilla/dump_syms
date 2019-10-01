// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::{
    AddressMap, FrameTable, PdbInternalRva, PdbInternalSectionOffset, ProcedureSymbol,
    PublicSymbol, RegisterRelativeSymbol, Result, TypeIndex,
};
use std::collections::{btree_map, BTreeMap};
use std::io::Write;

use super::line::Lines;
use super::pdb::RvaLabels;
use super::source::SourceLineCollector;
use super::types::{FuncName, TypeDumper};

pub(super) struct BlockInfo {
    pub rva: u32,
    pub offset: PdbInternalSectionOffset,
    pub len: u32,
}

#[derive(Debug)]
struct EBPInfo {
    type_index: TypeIndex,
    offset: u32,
}

#[derive(Debug)]
struct SelectedSymbol {
    name: String,
    type_index: TypeIndex,
    is_public: bool,
    is_multiple: bool,
    offset: PdbInternalSectionOffset,
    len: u32,
    parameter_size: u32,
    source: Lines,
    ebp: Vec<EBPInfo>,
}

impl SelectedSymbol {
    fn split_address(&self, address_map: &AddressMap) -> Vec<(u32, u32)> {
        let start = self.offset.to_internal_rva(&address_map).unwrap();
        let end = PdbInternalRva(start.0 + self.len);
        address_map
            .rva_ranges(start..end)
            .filter_map(|r| {
                if r.start != r.end {
                    Some((r.start.0, r.end.0 - r.start.0))
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_und(&self, dumper: &TypeDumper) -> FuncName {
        dumper
            .dump_function(&self.name, self.type_index)
            .unwrap_or_else(|_| FuncName::get_unknown(self.name.clone()))
    }

    fn get_stack_param_size(
        &mut self,
        dumper: &TypeDumper,
        _address_map: &AddressMap,
        _frame_table: &FrameTable,
    ) -> u32 {
        // TODO: check if this value is the correct one
        // For now (legacy) return 0
        /*if frame_table.is_empty() {
            return 0;
        }

        let internal_rva = self.offset.to_internal_rva(&address_map).unwrap();
        let mut frames = frame_table.iter_at_rva(internal_rva);
        if let Ok(frame) = frames.next() {
            if let Some(frame) =  frame {
                return frame.params_size;
            }
        }*/

        if self.ebp.is_empty() {
            return self.parameter_size;
        }

        let (min_start, max_end) = self.ebp.drain(..).fold((std::u32::MAX, 0), |acc, i| {
            (
                acc.0.min(i.offset),
                acc.1.max(i.offset + dumper.get_type_size(i.type_index, 4)),
            )
        });

        let min_start = min_start.max(4);
        let sps = if min_start < max_end {
            // round max_end to next multiple of 4 (if not)
            let max_end = (max_end + 3) & !3;
            max_end - min_start
        } else {
            0
        };

        self.parameter_size = sps;

        sps
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
        } else {
            // The public name may contain parameter_size info so get it
            let fun_name = symbol.name.to_string().into_owned();
            if let FuncName::Unknown((name, sps)) = FuncName::get_unknown(fun_name.clone()) {
                if name == self.name || fun_name == self.name {
                    self.name = name;
                    self.parameter_size = sps;
                }
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
            FuncName::Undecorated(name) => (
                name,
                self.get_stack_param_size(dumper, address_map, frame_table),
            ),
            FuncName::Unknown((name, sps)) => (name, sps),
        };
        if self.is_public {
            writeln!(
                writer,
                "PUBLIC {}{:x} {:x} {}",
                self.get_multiple(),
                rva,
                stack_param_size,
                name
            )
        } else {
            for (rva, len) in self.split_address(address_map) {
                writeln!(
                    writer,
                    "FUNC {}{:x} {:x} {:x} {}",
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

#[derive(Default)]
pub(super) struct RvaSymbols {
    map: BTreeMap<u32, SelectedSymbol>,
    rva: u32,
    symbol: Option<SelectedSymbol>,
}

impl RvaSymbols {
    pub(super) fn add_procedure_symbol(
        &mut self,
        line_collector: &SourceLineCollector,
        function: ProcedureSymbol,
        block_info: BlockInfo,
    ) -> Result<()> {
        // Since several symbols may have the same rva (because they've the same disassembly code)
        // we need to "select" the a symbol for a rva.
        // Anyway it could lead to strange backtraces.

        let fun_name = function.name.to_string().into_owned();
        if let Some(selected) = self.map.get_mut(&block_info.rva) {
            selected.update_private(function, block_info, line_collector)?;
        } else {
            let source = line_collector.collect_source_lines(block_info.offset, block_info.len)?;
            self.rva = block_info.rva;
            self.symbol = Some(SelectedSymbol {
                name: fun_name,
                type_index: function.type_index,
                is_public: false,
                is_multiple: false,
                offset: block_info.offset,
                len: block_info.len,
                parameter_size: 0,
                source,
                ebp: Vec::new(),
            });
        }

        Ok(())
    }

    pub(super) fn add_public_symbol(
        &mut self,
        symbol: PublicSymbol,
        rva_labels: &RvaLabels,
        address_map: &AddressMap,
    ) {
        let rva = match symbol.offset.to_rva(address_map) {
            Some(rva) => rva,
            _ => return,
        };

        if symbol.code || symbol.function || rva_labels.contains(&rva.0) {
            match self.map.entry(rva.0) {
                btree_map::Entry::Occupied(selected) => {
                    let selected = selected.into_mut();
                    selected.update_public(symbol);
                }
                btree_map::Entry::Vacant(e) => {
                    let sym_name = symbol.name.to_string().into_owned();
                    let offset = symbol.offset;
                    e.insert(SelectedSymbol {
                        name: sym_name,
                        type_index: TypeIndex(0),
                        is_public: true,
                        is_multiple: false,
                        offset,
                        len: 0,
                        parameter_size: 0,
                        source: Lines::new(),
                        ebp: Vec::new(),
                    });
                }
            }
        }
    }

    pub(super) fn add_ebp(&mut self, ebp: RegisterRelativeSymbol) {
        if let Some(symbol) = self.symbol.as_mut() {
            symbol.ebp.push(EBPInfo {
                type_index: ebp.type_index,
                offset: ebp.offset as u32,
            });
        }
    }

    pub(super) fn close_procedure(&mut self) {
        if let Some(symbol) = self.symbol.take() {
            self.map.insert(self.rva, symbol);
        }
    }

    pub(super) fn dump<W: Write>(
        &mut self,
        address_map: &AddressMap,
        frame_table: &FrameTable,
        dumper: &TypeDumper,
        writer: &mut W,
    ) -> std::io::Result<()> {
        for (rva, sym) in self.map.iter_mut() {
            sym.dump(&address_map, frame_table, dumper, *rva, writer)?;
        }
        Ok(())
    }
}
