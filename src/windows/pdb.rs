// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use failure::Fail;
use pdb::{
    AddressMap, BlockSymbol, DebugInformation, FallibleIterator, FrameTable, MachineType,
    ModuleInfo, PDBInformation, ProcedureSymbol, PublicSymbol, Result, Source, SymbolData,
    SymbolTable, TypeIndex, PDB,
};
use std::collections::{btree_map, BTreeMap, HashSet};
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Write};
use symbolic_debuginfo::{pdb::PdbObject, pe::PeObject, Object};
use symbolic_minidump::cfi::AsciiCfiWriter;
use uuid::Uuid;

use super::line::Lines;
use super::source::{SourceFiles, SourceLineCollector};
use super::symbol::{BlockInfo, SelectedSymbol};
use super::types::TypeDumper;
use crate::common;

type RvaSymbols = BTreeMap<u32, SelectedSymbol>;
type RvaLabels = HashSet<u32>;

#[derive(Clone, Copy, Debug, PartialEq)]
enum CPU {
    X86,
    X86_64,
    Unknown,
}

impl Display for CPU {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CPU::X86 => "x86",
                CPU::X86_64 => "x86_64",
                CPU::Unknown => "unknown",
            }
        )
    }
}

pub(crate) struct PDBInfo<'s> {
    cpu: CPU,
    debug_id: String,
    pe_name: String,
    pdb_name: String,
    source_files: SourceFiles<'s>,
    rva_symbols: RvaSymbols,
    address_map: AddressMap<'s>,
}

impl PDBInfo<'_> {
    fn get_cpu(dbi: &DebugInformation) -> CPU {
        if let Ok(mt) = dbi.machine_type() {
            match mt {
                // Currently breakpad code only uses these machine types
                // but we've more possibilities:
                // https://docs.rs/pdb/0.5.0/pdb/enum.MachineType.html
                MachineType::X86 => CPU::X86,
                MachineType::Amd64 | MachineType::Ia64 => CPU::X86_64,
                _ => CPU::Unknown,
            }
        } else {
            CPU::Unknown
        }
    }

    fn get_debug_id(dbi: &DebugInformation, pi: PDBInformation) -> String {
        // Here the guid is treated like a 128-bit uuid (PDB >=7.0)
        let mut buf = Uuid::encode_buffer();
        let guid = pi.guid.to_simple().encode_upper(&mut buf);
        let age = if let Some(age) = dbi.age() {
            age
        } else {
            pi.age
        };
        format!("{}{:x}", guid, age)
    }

    fn add_public_symbol(
        &self,
        symbol: PublicSymbol,
        rva_labels: &RvaLabels,
        rva_symbols: &mut RvaSymbols,
    ) {
        let rva = match symbol.offset.to_rva(&self.address_map) {
            Some(rva) => rva,
            _ => return,
        };

        if symbol.code || symbol.function || rva_labels.contains(&rva.0) {
            match rva_symbols.entry(rva.0) {
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
                        source: Lines::new(),
                    });
                }
            }
        }
    }

    fn collect_public_symbols(
        &self,
        globals: SymbolTable,
        rva_labels: RvaLabels,
        rva_symbols: &mut RvaSymbols,
    ) -> Result<()> {
        let mut symbols = globals.iter();
        while let Some(symbol) = symbols.next()? {
            let symbol = match symbol.parse() {
                Ok(s) => s,
                _ => return Ok(()),
            };

            if let SymbolData::Public(symbol) = symbol {
                self.add_public_symbol(symbol, &rva_labels, rva_symbols);
            }
        }

        Ok(())
    }

    fn add_function_symbol(
        &self,
        line_collector: &SourceLineCollector,
        function: ProcedureSymbol,
        block_info: BlockInfo,
        rva_symbols: &mut RvaSymbols,
    ) -> Result<()> {
        // Since several symbols may have the same rva (because they've the same disassembly code)
        // we need to "select" the a symbol for a rva.
        // Anyway it could lead to strange backtraces.

        let fun_name = function.name.to_string().into_owned();
        match rva_symbols.entry(block_info.rva) {
            btree_map::Entry::Occupied(selected) => {
                selected
                    .into_mut()
                    .update_private(function, block_info, line_collector)?;
            }
            btree_map::Entry::Vacant(e) => {
                let source =
                    line_collector.collect_source_lines(block_info.offset, block_info.len)?;
                e.insert(SelectedSymbol {
                    name: fun_name,
                    type_index: function.type_index,
                    is_public: false,
                    is_multiple: false,
                    offset: block_info.offset,
                    len: block_info.len,
                    source,
                });
            }
        }
        Ok(())
    }

    fn add_block(
        &self,
        module_info: &ModuleInfo,
        line_collector: &SourceLineCollector,
        block: BlockSymbol,
        rva_symbols: &mut RvaSymbols,
    ) -> Result<()> {
        // When building with PGO, the compiler can split functions into
        // "hot" and "cold" blocks, and move the "cold" blocks out to separate
        // pages, so the function can be noncontiguous. To find these blocks,
        // we have to iterate over all the compilands, and then find blocks
        // that are children of them. We can then find the lexical parents
        // of those blocks and print out an extra FUNC line for blocks
        // that are not contained in their parent functions.

        let parent = match module_info.symbols_at(block.parent)?.next()? {
            Some(p) => p,
            _ => return Ok(()),
        };

        let parent = match parent.parse() {
            Ok(p) => p,
            _ => return Ok(()),
        };

        let parent = match parent {
            SymbolData::Procedure(p) => p,
            _ => return Ok(()),
        };

        let block_rva = match block.offset.to_rva(&self.address_map) {
            Some(rva) => rva,
            _ => return Ok(()),
        };

        let parent_rva = match parent.offset.to_rva(&self.address_map) {
            Some(rva) => rva,
            _ => return Ok(()),
        };

        if block_rva < parent_rva || block_rva > parent_rva + parent.len {
            // So the block is outside of its parent procedure
            self.add_function_symbol(
                &line_collector,
                parent,
                BlockInfo {
                    rva: block_rva.0,
                    offset: block.offset,
                    len: block.len,
                },
                rva_symbols,
            )?;
        }

        Ok(())
    }

    fn handle_symbol(
        &self,
        symbol: SymbolData,
        line_collector: &SourceLineCollector,
        module_info: &ModuleInfo,
        rva_labels: &mut RvaLabels,
        rva_symbols: &mut RvaSymbols,
    ) -> Result<()> {
        match symbol {
            SymbolData::Procedure(procedure) => {
                let rva = match procedure.offset.to_rva(&self.address_map) {
                    Some(rva) => rva,
                    _ => return Ok(()),
                };

                self.add_function_symbol(
                    line_collector,
                    procedure,
                    BlockInfo {
                        rva: rva.0,
                        offset: procedure.offset,
                        len: procedure.len,
                    },
                    rva_symbols,
                )?;
            }
            SymbolData::Label(label) => {
                if let Some(rva) = label.offset.to_rva(&self.address_map) {
                    rva_labels.insert(rva.0);
                }
            }
            SymbolData::Block(block) => {
                self.add_block(&module_info, line_collector, block, rva_symbols)?;
            }
            /*S_ATTR_REGREL => {
                // Could be useful to compute the stack size
                // We should get a symbol here and put in a vec in the last SelectedSymbol
            },*/
            _ => {}
        }

        Ok(())
    }

    fn collect_functions<'a, S: 'a + Source<'a>>(
        &self,
        pdb: &mut PDB<'a, S>,
        dbi: &DebugInformation,
        rva_symbols: &mut RvaSymbols,
    ) -> Result<RvaLabels> {
        let mut modules = dbi.modules()?;

        // Some public symbols corresponds to a label (most of the time they come from inline assembly)
        // So need to get such symbols because they've some code.
        let mut rva_labels = RvaLabels::default();

        // We get all the procedures and the labels
        // Labels correspond to some labelled code we can map with some public symbols (assembly)
        while let Some(module) = modules.next()? {
            let module_info = match pdb.module_info(&module)? {
                Some(info) => info,
                _ => continue,
            };

            let line_collector = SourceLineCollector::new(
                &self.address_map,
                &self.source_files,
                module_info.line_program()?,
            )?;

            let mut symbols = module_info.symbols()?;
            while let Some(symbol) = symbols.next()? {
                let symbol = match symbol.parse() {
                    Ok(s) => s,
                    _ => continue,
                };

                self.handle_symbol(
                    symbol,
                    &line_collector,
                    &module_info,
                    &mut rva_labels,
                    rva_symbols,
                )?;
            }
        }

        Ok(rva_labels)
    }

    fn dump_all<W: Write>(
        &mut self,
        type_dumper: TypeDumper,
        pdb: Option<PdbObject>,
        pe: Option<PeObject>,
        frame_table: &FrameTable,
        mut writer: W,
    ) -> common::Result<()> {
        writeln!(
            writer,
            "MODULE windows {} {} {}",
            self.cpu, self.debug_id, self.pdb_name
        )?;

        if let Some(pe) = pe.as_ref() {
            let code_id = pe.code_id().unwrap().as_str().to_uppercase();
            writeln!(writer, "INFO CODE_ID {} {}", code_id, self.pe_name)?;
        }

        self.source_files.dump(&mut writer)?;

        for (rva, sym) in self.rva_symbols.iter_mut() {
            sym.dump(
                &self.address_map,
                frame_table,
                &type_dumper,
                *rva,
                &mut writer,
            )?;
        }

        let mut cfi_writer = AsciiCfiWriter::new(writer);
        if self.cpu == CPU::X86_64 {
            if let Some(pe) = pe {
                cfi_writer
                    .process(&Object::Pe(pe))
                    .map_err(|e| e.compat())?;
            }
        } else if let Some(pdb) = pdb {
            cfi_writer
                .process(&Object::Pdb(pdb))
                .map_err(|e| e.compat())?;
        }

        Ok(())
    }

    pub fn dump<W: Write>(
        buf: &[u8],
        pdb_name: String,
        pe_name: String,
        pe: Option<PeObject>,
        writer: W,
    ) -> common::Result<()> {
        let cursor = Cursor::new(buf);
        let mut pdb = PDB::open(cursor)?;
        let pi = pdb.pdb_information()?;
        let dbi = pdb.debug_information()?;
        let frame_table = pdb.frame_table()?;

        let cpu = Self::get_cpu(&dbi);
        let debug_id = Self::get_debug_id(&dbi, pi);

        let source_files = SourceFiles::new(&mut pdb)?;

        let mut module = PDBInfo {
            cpu,
            debug_id,
            pe_name,
            pdb_name,
            source_files,
            rva_symbols: RvaSymbols::new(),
            address_map: pdb.address_map()?,
        };

        let mut rva_symbols = RvaSymbols::default();
        let rva_labels = module.collect_functions(&mut pdb, &dbi, &mut rva_symbols)?;

        let globals = pdb.global_symbols()?;
        module.collect_public_symbols(globals, rva_labels, &mut rva_symbols)?;

        std::mem::replace(&mut module.rva_symbols, rva_symbols);

        let type_info = pdb.type_information()?;

        // Demangler or dumper (for type info we've for private symbols)
        let type_dumper = TypeDumper::new(&type_info)?;

        // For stack unwinding info
        let pdb_object = if cpu == CPU::X86_64 {
            // Frame data are in the PE
            None
        } else {
            Some(PdbObject::parse(&buf).unwrap())
        };

        module.dump_all(type_dumper, pdb_object, pe, &frame_table, writer)
    }
}

#[cfg(test)]
mod tests {

    /*use std::path::PathBuf;

    use super::*;

    fn get_output(file_name: &str) -> Vec<u8> {
        let path = PathBuf::from("./tests");
        let path = path.join(file_name);

        let pe_buf = crate::utils::read_file(&path);
        let (pe, pdb_buf, pdb_name) = crate::windows::utils::get_pe_pdb_buf(path, &pe_buf).unwrap();
        let mut output = Vec::new();
        let cursor = Cursor::new(&mut output);
        PDBInfo::dump(&pdb_buf, pdb_name, file_name.to_string(), Some(pe), cursor);

        output
    }

    #[test]
    fn test_basic32() {
        let output = get_output("basic32.dll");
    }*/
}
