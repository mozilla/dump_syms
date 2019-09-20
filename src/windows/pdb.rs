// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::{
    AddressMap, BlockSymbol, DebugInformation, FallibleIterator, FrameTable, LineProgram,
    MachineType, ModuleInfo, PDBInformation, PdbInternalRva, PdbInternalSectionOffset,
    ProcedureSymbol, PublicSymbol, Result, Source, StringRef, StringTable, SymbolData, TypeIndex,
    PDB,
};
use std::collections::{btree_map, hash_map, BTreeMap, HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Write};
use symbolic_debuginfo::{pdb::PdbObject, pe::PeObject, Object};
use symbolic_minidump::cfi::AsciiCfiWriter;
use uuid::Uuid;

use super::line::Lines;
use super::types::{FuncName, TypeDumper};
use crate::common;

type RvaSymbols = BTreeMap<u32, SelectedSymbol>;
type RvaLabels = HashSet<u32>;

struct BlockInfo {
    rva: u32,
    offset: PdbInternalSectionOffset,
    len: u32,
}

#[derive(Debug)]
pub struct FileInfo {
    name: String,
    id: u32,
}

impl Display for FileInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "FILE {} {}", self.id, self.name)
    }
}

#[derive(Debug)]
struct SelectedSymbol {
    name: String,
    type_index: TypeIndex,
    is_public: bool,
    is_multiple: bool,
    offset: PdbInternalSectionOffset,
    len: u32,
    source: Lines,
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

    fn dump<W: Write>(
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

pub struct PDBInfo {
    cpu: &'static str,
    debug_id: String,
    pe_name: String,
    pdb_name: String,
    all_files: Vec<FileInfo>,
    rva_symbols: RvaSymbols,
}

impl PDBInfo {
    fn get_cpu(dbi: &DebugInformation) -> &'static str {
        if let Ok(mt) = dbi.machine_type() {
            match mt {
                // Currently breakpad code only uses these machine types
                // but we've more possibilities:
                // https://docs.rs/pdb/0.5.0/pdb/enum.MachineType.html
                MachineType::X86 => "x86",
                MachineType::Amd64 | MachineType::Ia64 => "x86_64",
                _ => "unknown",
            }
        } else {
            "unknown"
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

    fn name_to_string(str_ref: StringRef, string_table: &StringTable) -> Result<String> {
        Ok(str_ref.to_string_lossy(&string_table)?.into_owned())
    }

    fn collect_source(
        &mut self,
        file_ids: &mut HashMap<u32, u32>,
        line_program: LineProgram,
        string_table: &StringTable,
        last_id: u32,
    ) -> Result<u32> {
        let mut files = line_program.files();
        let mut last_id = last_id;
        while let Some(file) = files.next()? {
            // string_ref is an u32 corresponding to the offset in the string table
            let string_ref = file.name.0;
            match file_ids.entry(string_ref) {
                hash_map::Entry::Occupied(_) => {}
                hash_map::Entry::Vacant(e) => {
                    e.insert(last_id);
                    let name = Self::name_to_string(file.name, string_table)?;
                    self.all_files.push(FileInfo { name, id: last_id });

                    // if we put this increment just after the match, then we get exactly the same id
                    // as in the original breakpad
                    last_id += 1;
                }
            }
        }
        Ok(last_id)
    }

    fn collect_source_files<'a, S: 'a + Source<'a>>(
        &mut self,
        pdb: &mut PDB<'a, S>,
        dbi: &DebugInformation,
    ) -> Result<HashMap<u32, u32>> {
        let mut modules = dbi.modules()?;
        let string_table = pdb.string_table()?;
        let mut file_ids = HashMap::new();
        let mut last_id: u32 = 1;

        // Get all source files and generate an unique id for each one.
        // According to the docs: https://docs.rs/pdb/0.5.0/pdb/struct.PDB.html#method.string_table
        // the table contains deduplicated strings so each source file must have an unique StringRef.
        while let Some(module) = modules.next()? {
            if let Some(info) = pdb.module_info(&module)? {
                last_id = self.collect_source(
                    &mut file_ids,
                    info.line_program()?,
                    &string_table,
                    last_id,
                )?;
            }
        }

        Ok(file_ids)
    }

    fn collect_source_lines(
        address_map: &AddressMap,
        line_program: &LineProgram,
        offset: PdbInternalSectionOffset,
        file_ids: &HashMap<u32, u32>,
    ) -> Result<Lines> {
        // lines_at_offset is pretty slow (linear)
        let mut lines = line_program.lines_at_offset(offset);

        let mut source_lines = Lines::new();

        // Get the first element just to have file_index, file_id
        // which are likely the same for all lines
        let (mut last_file_index, mut last_file_id) = if let Some(line) = lines.next()? {
            let rva = line.offset.to_internal_rva(address_map).unwrap();
            let file = line_program.get_file_info(line.file_index)?;
            let file_id = *file_ids.get(&file.name.0).unwrap();

            source_lines.add_line(rva.0, line.line_start, file_id);
            (line.file_index.0, file_id)
        } else {
            return Ok(source_lines);
        };

        while let Some(line) = lines.next()? {
            let rva = line.offset.to_internal_rva(address_map).unwrap();

            // The file_id is very likely always the same
            let file_id = if line.file_index.0 == last_file_index {
                last_file_id
            } else {
                last_file_index = line.file_index.0;
                let file = line_program.get_file_info(line.file_index)?;
                last_file_id = *file_ids.get(&file.name.0).unwrap();
                last_file_id
            };
            source_lines.add_line(rva.0, line.line_start, file_id);
        }

        Ok(source_lines)
    }

    fn add_public_symbol(
        &mut self,
        symbol: PublicSymbol,
        address_map: &AddressMap,
        rva_labels: &RvaLabels,
    ) {
        if let Some(rva) = symbol.offset.to_rva(address_map) {
            if symbol.code || symbol.function || rva_labels.contains(&rva.0) {
                match self.rva_symbols.entry(rva.0) {
                    btree_map::Entry::Occupied(selected) => {
                        let selected = selected.into_mut();
                        if selected.is_public {
                            let sym_name = symbol.name.to_string().into_owned();
                            selected.is_multiple = true;
                            if sym_name < selected.name {
                                selected.name = sym_name;
                                selected.offset = symbol.offset;
                            }
                        }
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
    }

    fn collect_public_symbols<'a, S: 'a + Source<'a>>(
        &mut self,
        pdb: &mut PDB<'a, S>,
        address_map: &AddressMap,
        rva_labels: RvaLabels,
    ) -> Result<()> {
        let globals = pdb.global_symbols()?;
        let mut symbols = globals.iter();
        while let Some(symbol) = symbols.next()? {
            if let Ok(symbol) = symbol.parse() {
                if let SymbolData::Public(symbol) = symbol {
                    self.add_public_symbol(symbol, &address_map, &rva_labels);
                }
            }
        }

        Ok(())
    }

    fn add_function_symbol(
        &mut self,
        address_map: &AddressMap,
        line_program: &LineProgram,
        file_ids: &HashMap<u32, u32>,
        function: ProcedureSymbol,
        block_info: BlockInfo,
    ) -> Result<()> {
        // Since several symbols may have the same rva (because they've the same disassembly code)
        // we need to "select" the a symbol for a rva.
        // Anyway it could lead to strange backtraces.

        let fun_name = function.name.to_string().into_owned();
        match self.rva_symbols.entry(block_info.rva) {
            btree_map::Entry::Occupied(selected) => {
                let selected = selected.into_mut();
                selected.is_multiple = true;

                // TODO: this is legacy code
                // this is probably useless.
                if fun_name < selected.name {
                    selected.name = fun_name;
                    selected.type_index = function.type_index;
                    selected.offset = block_info.offset;
                    selected.len = block_info.len;
                    selected.source = Self::collect_source_lines(
                        &address_map,
                        &line_program,
                        block_info.offset,
                        &file_ids,
                    )?;
                }
            }
            btree_map::Entry::Vacant(e) => {
                let source = Self::collect_source_lines(
                    &address_map,
                    &line_program,
                    block_info.offset,
                    &file_ids,
                )?;
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
        &mut self,
        module_info: &ModuleInfo,
        address_map: &AddressMap,
        line_program: &LineProgram,
        file_ids: &HashMap<u32, u32>,
        block: BlockSymbol,
    ) -> Result<()> {
        // When building with PGO, the compiler can split functions into
        // "hot" and "cold" blocks, and move the "cold" blocks out to separate
        // pages, so the function can be noncontiguous. To find these blocks,
        // we have to iterate over all the compilands, and then find blocks
        // that are children of them. We can then find the lexical parents
        // of those blocks and print out an extra FUNC line for blocks
        // that are not contained in their parent functions.

        if let Some(parent) = module_info.symbols_at(block.parent)?.next()? {
            if let Ok(parent) = parent.parse() {
                if let SymbolData::Procedure(parent) = parent {
                    if let Some(block_rva) = block.offset.to_rva(&address_map) {
                        if let Some(parent_rva) = parent.offset.to_rva(&address_map) {
                            if block_rva < parent_rva || block_rva > parent_rva + parent.len {
                                // So the block is outside of its parent procedure
                                self.add_function_symbol(
                                    &address_map,
                                    &line_program,
                                    &file_ids,
                                    parent,
                                    BlockInfo {
                                        rva: block_rva.0,
                                        offset: block.offset,
                                        len: block.len,
                                    },
                                )?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_symbol(
        &mut self,
        symbol: SymbolData,
        address_map: &AddressMap,
        line_program: &LineProgram,
        module_info: &ModuleInfo,
        file_ids: &HashMap<u32, u32>,
        rva_labels: &mut RvaLabels,
    ) -> Result<()> {
        match symbol {
            SymbolData::Procedure(procedure) => {
                if let Some(rva) = procedure.offset.to_rva(&address_map) {
                    self.add_function_symbol(
                        &address_map,
                        &line_program,
                        &file_ids,
                        procedure,
                        BlockInfo {
                            rva: rva.0,
                            offset: procedure.offset,
                            len: procedure.len,
                        },
                    )?;
                }
            }
            SymbolData::Label(label) => {
                if let Some(rva) = label.offset.to_rva(&address_map) {
                    rva_labels.insert(rva.0);
                }
            }
            SymbolData::Block(block) => {
                self.add_block(&module_info, &address_map, &line_program, &file_ids, block)?;
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
        &mut self,
        pdb: &mut PDB<'a, S>,
        dbi: &DebugInformation,
        file_ids: HashMap<u32, u32>,
        address_map: &AddressMap,
    ) -> Result<()> {
        let mut modules = dbi.modules()?;

        // Some public symbols corresponds to a label (most of the time they come from inline assembly)
        // So need to get such symbols because they've some code.
        let mut rva_labels = RvaLabels::new();

        // We get all the procedures and the labels
        // Labels correspond to some labelled code we can map with some public symbols (assembly)
        while let Some(module) = modules.next()? {
            if let Some(module_info) = pdb.module_info(&module)? {
                let mut symbols = module_info.symbols()?;
                let line_program = module_info.line_program()?;
                while let Some(symbol) = symbols.next()? {
                    if let Ok(symbol) = symbol.parse() {
                        self.handle_symbol(
                            symbol,
                            &address_map,
                            &line_program,
                            &module_info,
                            &file_ids,
                            &mut rva_labels,
                        )?;
                    }
                }
            }
        }

        self.collect_public_symbols(pdb, &address_map, rva_labels)
    }

    fn dump_all<W: Write>(
        &mut self,
        type_dumper: TypeDumper,
        pdb: Option<PdbObject>,
        pe: Option<PeObject>,
        address_map: &AddressMap,
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

        for file_info in self.all_files.iter() {
            writeln!(writer, "{}", file_info)?;
        }

        for (rva, sym) in self.rva_symbols.iter_mut() {
            sym.dump(address_map, frame_table, &type_dumper, *rva, &mut writer)?;
        }

        let mut cfi_writer = AsciiCfiWriter::new(writer);
        if self.cpu == "x86_64" {
            if let Some(pe) = pe {
                cfi_writer.process(&Object::Pe(pe))?;
            }
        } else if let Some(pdb) = pdb {
            cfi_writer.process(&Object::Pdb(pdb))?;
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
        let address_map = pdb.address_map()?;
        let frame_table = pdb.frame_table()?;

        let cpu = Self::get_cpu(&dbi);
        let debug_id = Self::get_debug_id(&dbi, pi);

        let mut module = PDBInfo {
            cpu,
            debug_id,
            pe_name,
            pdb_name,
            all_files: Vec::new(),
            rva_symbols: RvaSymbols::new(),
        };

        let file_ids = module.collect_source_files(&mut pdb, &dbi)?;
        module.collect_functions(&mut pdb, &dbi, file_ids, &address_map)?;

        let type_info = pdb.type_information()?;

        // Demangler or dumper (for type info we've for private symbols)
        let type_dumper = TypeDumper::new(&type_info)?;

        // For stack unwinding info
        let pdb_object = if cpu == "x86_64" {
            // Frame data are in the PE
            None
        } else {
            Some(PdbObject::parse(&buf).unwrap())
        };

        module.dump_all(
            type_dumper,
            pdb_object,
            pe,
            &address_map,
            &frame_table,
            writer,
        )
    }
}
