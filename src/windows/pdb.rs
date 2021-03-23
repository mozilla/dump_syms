// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use failure::Fail;
use hashbrown::HashSet;
use pdb::{
    AddressMap, BlockSymbol, DebugInformation, FallibleIterator, MachineType, ModuleInfo,
    PDBInformation, ProcedureSymbol, PublicSymbol, Register, RegisterRelativeSymbol, Result,
    SeparatedCodeSymbol, Source, SymbolData, SymbolTable, PDB,
};
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Write};
use std::sync::Arc;
use symbolic::common::Arch;
use symbolic::debuginfo::{pdb::PdbObject, pe::PeObject, Object};
use symbolic::minidump::cfi::AsciiCfiWriter;
use uuid::Uuid;

use super::source::{SourceFiles, SourceLineCollector};
use super::symbol::{BlockInfo, PDBSymbols, RvaSymbols, SelectedSymbol};
use super::types::{DumperFlags, TypeDumper};
use super::utils::get_pe_debug_id;
use crate::common::{self, Dumpable, Mergeable};
use crate::mapping::PathMappings;

#[derive(Clone, Copy, Debug, PartialEq)]
enum CPU {
    X86,
    X86_64,
    Unknown,
}

impl CPU {
    fn get_ptr_size(self) -> u32 {
        match self {
            Self::X86 => 4,
            _ => 8,
        }
    }
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

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[derive(Debug)]
pub(super) struct PDBSections {
    sections: Option<Vec<bool>>,
}

impl PDBSections {
    fn new<'a, S: 'a + Source<'a>>(pdb: &mut PDB<'a, S>) -> Self {
        PDBSections {
            sections: pdb.sections().ok().and_then(|s| s).map(|sections| {
                sections
                    .iter()
                    .map(|section| Self::has_code(section.characteristics))
                    .collect()
            }),
        }
    }

    pub(super) fn is_code(&self, section: u16) -> bool {
        let section = (section - 1) as usize;
        self.sections
            .as_ref()
            .map_or(false, |v| *v.get(section).unwrap_or(&false))
    }

    pub(super) fn has_code(characteristics: u32) -> bool {
        characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0
    }

    pub(super) fn len(&self) -> usize {
        self.sections.as_ref().map_or(0, |s| s.len())
    }
}

#[derive(Debug)]
pub(super) struct PDBContributions {
    contributions: Option<Vec<HashSet<u32>>>,
}

// Some executable sections may contain symbols which are not executable (e.g. string constants)
// So here we collect all the symbols which are in an exec section and which aren't exec
impl PDBContributions {
    fn new(dbi: &DebugInformation, pdb_sections: &PDBSections) -> Self {
        PDBContributions {
            contributions: dbi
                .section_contributions()
                .ok()
                .and_then(|mut contributions| {
                    let mut contribs: Vec<HashSet<u32>> =
                        vec![HashSet::default(); pdb_sections.len()];
                    loop {
                        if let Ok(c) = contributions.next() {
                            if let Some(contribution) = c {
                                if pdb_sections.is_code(contribution.offset.section)
                                    && !PDBSections::has_code(contribution.characteristics)
                                {
                                    let section = (contribution.offset.section - 1) as usize;
                                    contribs[section].insert(contribution.offset.offset);
                                }
                            } else {
                                break;
                            }
                        } else {
                            return None;
                        }
                    }
                    if contribs.is_empty() {
                        None
                    } else {
                        Some(contribs)
                    }
                }),
        }
    }

    pub(super) fn is_code(&self, section: u16, offset: u32) -> bool {
        let section = (section - 1) as usize;
        self.contributions.as_ref().map_or(true, |v| {
            v.get(section).map_or(true, |o| !o.contains(&offset))
        })
    }
}

struct PDBData<'s> {
    address_map: AddressMap<'s>,
}

struct Collector {
    cpu: CPU,
    symbols: RvaSymbols,
    pdb_sections: PDBSections,
    pdb_contributions: PDBContributions,
}

impl Collector {
    fn add_public_symbol(&mut self, symbol: PublicSymbol, address_map: &AddressMap) {
        self.symbols.add_public_symbol(
            symbol,
            &self.pdb_sections,
            &self.pdb_contributions,
            address_map,
        )
    }

    fn add_procedure_symbol(
        &mut self,
        symbol: ProcedureSymbol,
        info: BlockInfo,
        lines: &SourceLineCollector,
    ) {
        self.symbols.add_procedure_symbol(lines, symbol, info);
    }

    fn add_symbol(&mut self, symbol: SelectedSymbol, info: BlockInfo) {
        self.symbols.add_symbol(symbol, info);
    }

    fn add_reg_rel(&mut self, symbol: RegisterRelativeSymbol) {
        // TODO: check that's the correct way to know if we've a parameter here
        // 22 comes from https://github.com/microsoft/microsoft-pdb/blob/master/include/cvconst.h#L436
        if self.cpu == CPU::X86 && symbol.register == Register(22 /* EBP */) && symbol.offset > 0 {
            self.symbols.add_ebp(symbol);
        }
    }

    fn close_procedure(&mut self) {
        self.symbols.close_procedure();
    }

    fn get_symbol_at(&self, rva: u32) -> Option<&SelectedSymbol> {
        self.symbols.get_symbol_at(rva)
    }
}

pub(crate) struct PDBInfo {
    symbols: PDBSymbols,
    files: Vec<String>,
    cpu: CPU,
    debug_id: String,
    pdb_name: String,
    pe_name: String,
    code_id: Option<String>,
    stack: String,
}

impl Display for PDBInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "MODULE windows {} {} {}",
            self.cpu, self.debug_id, self.pdb_name
        )?;

        if let Some(code_id) = self.code_id.as_ref() {
            writeln!(f, "INFO CODE_ID {} {}", code_id, self.pe_name)?;
        }

        for (n, file_name) in self.files.iter().enumerate() {
            writeln!(f, "FILE {} {}", n, file_name)?;
        }

        for (_, sym) in self.symbols.iter() {
            write!(f, "{}", sym)?;
        }

        write!(f, "{}", self.stack)?;

        Ok(())
    }
}

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
    let age = dbi.age().unwrap_or(pi.age);
    format!("{}{:x}", guid, age)
}

fn get_stack_info(pdb_buf: Option<&[u8]>, pe: Option<PeObject>) -> String {
    let mut found_unwind_info = false;
    let mut buf = Vec::new();
    let writer = Cursor::new(&mut buf);

    let mut cfi_writer = AsciiCfiWriter::new(writer);
    if let Some(pe) = pe {
        if pe.has_unwind_info() {
            cfi_writer
                .process(&Object::Pe(pe))
                .map_err(|e| e.compat())
                .unwrap();
            found_unwind_info = true;
        }
    }

    if !found_unwind_info {
        if let Some(pdb_buf) = pdb_buf {
            if let Ok(pdb) = PdbObject::parse(&pdb_buf) {
                if pdb.has_unwind_info() {
                    cfi_writer
                        .process(&Object::Pdb(pdb))
                        .map_err(|e| e.compat())
                        .unwrap();
                }
            }
        }
    }

    String::from_utf8(buf).unwrap()
}

impl<'s> PDBData<'s> {
    fn collect_public_symbols(
        &self,
        globals: SymbolTable,
        collector: &mut Collector,
    ) -> Result<()> {
        let mut symbols = globals.iter();
        while let Some(symbol) = symbols.next()? {
            let symbol = match symbol.parse() {
                Ok(s) => s,
                _ => return Ok(()),
            };

            if let SymbolData::Public(symbol) = symbol {
                collector.add_public_symbol(symbol, &self.address_map);
            }
        }

        Ok(())
    }

    fn add_block(
        &self,
        module_info: &ModuleInfo,
        block: BlockSymbol,
        collector: &mut Collector,
        lines: &SourceLineCollector,
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
            collector.add_procedure_symbol(
                parent,
                BlockInfo {
                    rva: block_rva.0,
                    offset: block.offset,
                    len: block.len,
                },
                lines,
            );
        }

        Ok(())
    }

    fn add_sepcode(
        &self,
        block: SeparatedCodeSymbol,
        collector: &mut Collector,
        lines: &SourceLineCollector,
    ) {
        // We can see some sepcode syms in ntdll.dll
        // As far as I understand, they're pieces of code moved at compilation time.
        // According to some functions signatures these piece of code can be just
        // exception filter and exception handling
        let block_rva = match block.offset.to_rva(&self.address_map) {
            Some(rva) => rva,
            _ => return,
        };

        let parent_rva = match block.parent_offset.to_rva(&self.address_map) {
            Some(rva) => rva,
            _ => return,
        };

        if let Some(parent) = collector.get_symbol_at(parent_rva.0) {
            if block_rva < parent_rva || block_rva > parent_rva + parent.len {
                // So the block is outside of its parent procedure
                let source = lines.collect_source_lines(block.offset, block.len);
                let sym = SelectedSymbol {
                    name: parent.name.clone(),
                    type_index: parent.type_index,
                    is_public: parent.is_public,
                    is_multiple: false,
                    offset: block.offset,
                    sym_offset: parent.sym_offset,
                    len: block.len,
                    parameter_size: parent.parameter_size,
                    source,
                    ebp: parent.ebp.clone(),
                    id: parent.id,
                };
                collector.add_symbol(
                    sym,
                    BlockInfo {
                        rva: block_rva.0,
                        offset: block.offset,
                        len: block.len,
                    },
                );
            }
        }
    }

    fn handle_symbol(
        &self,
        symbol: SymbolData,
        collector: &mut Collector,
        lines: &SourceLineCollector,
        module_info: &ModuleInfo,
    ) -> Result<()> {
        match symbol {
            SymbolData::Procedure(procedure) => {
                let rva = match procedure.offset.to_rva(&self.address_map) {
                    Some(rva) => rva,
                    _ => return Ok(()),
                };

                collector.add_procedure_symbol(
                    procedure,
                    BlockInfo {
                        rva: rva.0,
                        offset: procedure.offset,
                        len: procedure.len,
                    },
                    lines,
                );
            }
            SymbolData::Block(block) => {
                self.add_block(&module_info, block, collector, lines)?;
            }
            SymbolData::SeparatedCode(block) => {
                self.add_sepcode(block, collector, lines);
            }
            SymbolData::RegisterRelative(regrel) => {
                collector.add_reg_rel(regrel);
            }
            SymbolData::ScopeEnd => {
                collector.close_procedure();
            }
            _ => {}
        }

        Ok(())
    }

    fn collect_functions<'a, S: 'a + Source<'a>>(
        &self,
        pdb: &mut PDB<'a, S>,
        dbi: &DebugInformation,
        collector: &mut Collector,
        source_files: &SourceFiles<'s>,
    ) -> Result<()> {
        let mut modules = dbi.modules()?;

        // We get all the procedures and the labels
        // Labels correspond to some labelled code we can map with some public symbols (assembly)
        while let Some(module) = modules.next()? {
            let module_info = match pdb.module_info(&module)? {
                Some(info) => info,
                _ => continue,
            };

            let lines = SourceLineCollector::new(
                &self.address_map,
                &source_files,
                module_info.line_program()?,
            )?;

            let mut symbols = module_info.symbols()?;
            while let Some(symbol) = symbols.next()? {
                let symbol = match symbol.parse() {
                    Ok(s) => s,
                    _ => continue,
                };

                self.handle_symbol(symbol, collector, &lines, &module_info)?;
            }
        }

        Ok(())
    }
}

impl PDBInfo {
    pub fn new(
        buf: &[u8],
        pdb_name: &str,
        pe_name: &str,
        pe: Option<PeObject>,
        mapping: Option<Arc<PathMappings>>,
    ) -> Result<Self> {
        let cursor = Cursor::new(buf);
        let mut pdb = PDB::open(cursor)?;
        let dbi = pdb.debug_information()?;
        let pi = pdb.pdb_information()?;
        let frame_table = pdb.frame_table()?;
        let globals = pdb.global_symbols()?;
        let pdb_sections = PDBSections::new(&mut pdb);
        let pdb_contributions = PDBContributions::new(&dbi, &pdb_sections);

        let cpu = get_cpu(&dbi);
        let debug_id = get_debug_id(&dbi, pi);
        let source_files = SourceFiles::new(&mut pdb, mapping)?;

        let pdb_data = PDBData {
            address_map: pdb.address_map()?,
        };

        let mut collector = Collector {
            cpu,
            symbols: RvaSymbols::default(),
            pdb_sections,
            pdb_contributions,
        };

        pdb_data.collect_functions(&mut pdb, &dbi, &mut collector, &source_files)?;
        pdb_data.collect_public_symbols(globals, &mut collector)?;

        let type_info = pdb.type_information()?;
        // Demangler or dumper (for type info we've for private symbols)
        let type_dumper = TypeDumper::new(&type_info, cpu.get_ptr_size(), DumperFlags::default())?;

        let code_id = if let Some(pe) = pe.as_ref() {
            Some(pe.code_id().unwrap().as_str().to_uppercase())
        } else {
            None
        };

        let stack = get_stack_info(Some(&buf), pe);
        let symbols =
            collector
                .symbols
                .mv_to_pdb_symbols(type_dumper, &pdb_data.address_map, frame_table);
        let symbols = crate::windows::symbol::append_dummy_symbol(symbols, pe_name);

        Ok(PDBInfo {
            symbols,
            files: source_files.get_mapping(),
            cpu,
            debug_id,
            pdb_name: String::from(pdb_name),
            pe_name: String::from(pe_name),
            code_id,
            stack,
        })
    }

    pub fn set_pe(&mut self, pe_name: String, pe: PeObject, pdb_buf: &[u8]) -> bool {
        if get_pe_debug_id(Some(&pe)).unwrap() == self.debug_id {
            self.code_id = Some(pe.code_id().unwrap().as_str().to_uppercase());
            self.pe_name = pe_name;
            if self.stack.is_empty() {
                self.stack = get_stack_info(Some(pdb_buf), Some(pe));
            }
            true
        } else {
            false
        }
    }
}

impl Dumpable for PDBInfo {
    fn dump<W: Write>(&self, mut writer: W) -> common::Result<()> {
        write!(writer, "{}", self)?;
        Ok(())
    }

    fn get_debug_id(&self) -> &str {
        &self.debug_id
    }

    fn get_name(&self) -> &str {
        &self.pdb_name
    }
}

impl Mergeable for PDBInfo {
    fn merge(_left: PDBInfo, _right: PDBInfo) -> common::Result<PDBInfo> {
        Err("PDB merge not implemented".into())
    }
}

pub(crate) struct PEInfo {
    symbols: PDBSymbols,
    cpu: CPU,
    debug_id: String,
    pdb_name: String,
    pe_name: String,
    code_id: Option<String>,
    stack: String,
}

impl Display for PEInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "MODULE windows {} {} {}",
            self.cpu, self.debug_id, self.pdb_name
        )?;

        if let Some(code_id) = self.code_id.as_ref() {
            writeln!(f, "INFO CODE_ID {} {}", code_id, self.pe_name)?;
        }

        for (_, sym) in self.symbols.iter() {
            write!(f, "{}", sym)?;
        }

        write!(f, "{}", self.stack)?;

        Ok(())
    }
}

impl PEInfo {
    pub fn new(pe_name: &str, pe: PeObject) -> Result<Self> {
        let cpu = match pe.arch() {
            Arch::X86 => CPU::X86,
            Arch::X86Unknown => CPU::X86,
            Arch::Amd64 => CPU::X86_64,
            Arch::Amd64h => CPU::X86_64,
            Arch::Amd64Unknown => CPU::X86_64,
            _ => CPU::Unknown,
        };
        let pdb_name = pe.debug_file_name().unwrap_or_default().to_string();
        let pdb_name = PEInfo::file_name_only(&pdb_name).to_string();

        let debug_id = get_pe_debug_id(Some(&pe)).unwrap();
        let code_id = Some(pe.code_id().unwrap().as_str().to_uppercase());
        let symbols = crate::windows::symbol::symbolic_to_pdb_symbols(
            pe.symbols(),
            pe.exception_data(),
            pe_name,
        );
        let symbols = crate::windows::symbol::append_dummy_symbol(symbols, pe_name);
        let stack = get_stack_info(None, Some(pe));

        Ok(PEInfo {
            symbols,
            cpu,
            debug_id,
            pdb_name,
            pe_name: String::from(pe_name),
            code_id,
            stack,
        })
    }

    fn file_name_only(pdb_name: &str) -> &str {
        let index = pdb_name.rfind('\\').map_or(0, |i| i + 1);
        &pdb_name[index..pdb_name.len()]
    }
}

impl Dumpable for PEInfo {
    fn dump<W: Write>(&self, mut writer: W) -> common::Result<()> {
        write!(writer, "{}", self)?;
        Ok(())
    }

    fn get_debug_id(&self) -> &str {
        &self.debug_id
    }

    fn get_name(&self) -> &str {
        if self.pdb_name.is_empty() {
            return &self.pe_name;
        }

        &self.pdb_name
    }
}

impl Mergeable for PEInfo {
    fn merge(_left: PEInfo, _right: PEInfo) -> common::Result<PEInfo> {
        Err("PE merge not implemented".into())
    }
}

#[cfg(test)]
mod tests {

    use bitflags::bitflags;
    use fxhash::{FxHashMap, FxHashSet};
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use symbolic::debuginfo::breakpad::{
        BreakpadError, BreakpadFileMap, BreakpadFuncRecord, BreakpadLineRecord, BreakpadObject,
    };

    use super::*;

    bitflags! {
        struct TestFlags: u32 {
            const ALL = 0;
            const NO_MULTIPLICITY = 0b1;
            const NO_FILE_LINE = 0b10;
            const NO_FUNCS_LENGTH = 0b100;
        }
    }

    #[derive(Debug, PartialEq)]
    struct StackWin {
        typ: u32,
        rva: u32,
        code_size: u32,
        prolog_size: u32,
        epilog_size: u32,
        params_size: u32,
        regs_size: u32,
        locals_size: u32,
        max_stack_size: u32,
        extra: String,
    }

    const MS: &str = "https://msdl.microsoft.com/download/symbols";

    fn dl_from_server(url: &str) -> Vec<u8> {
        let mut response = reqwest::blocking::get(url).expect("GET request");
        let mut buf = Vec::new();
        response.copy_to(&mut buf).expect("Data from server");
        buf
    }

    fn get_data_from_server(url: &str) -> (Vec<u8>, &str) {
        let toks: Vec<_> = url.rsplitn(4, '/').collect();
        let name = toks[2];
        let pe_buf = dl_from_server(url);
        let pe_buf = crate::utils::read_cabinet(pe_buf, PathBuf::from(name)).unwrap();
        let (pe, pdb_buf, pdb_name) = crate::windows::utils::get_pe_pdb_buf(
            &PathBuf::from("."),
            &pe_buf,
            crate::cache::get_sym_servers(Some(&format!("SRV*~/symcache*{}", MS))).as_ref(),
        )
        .unwrap();

        let mut output = Vec::new();
        let cursor = Cursor::new(&mut output);
        let pdb = PDBInfo::new(&pdb_buf, &pdb_name, name, Some(pe), None).unwrap();
        pdb.dump(cursor).unwrap();

        let toks: Vec<_> = name.rsplitn(2, '.').collect();

        (output, toks[1])
    }

    fn get_new_bp(file_name: &str, mapping: Option<Arc<PathMappings>>) -> Vec<u8> {
        let path = PathBuf::from("./test_data/windows");
        let mut path = path.join(file_name);

        if !path.exists() {
            path.set_extension("exe");
        }

        let pe_buf = crate::utils::read_file(&path);
        let (pe, pdb_buf, pdb_name) = crate::windows::utils::get_pe_pdb_buf(
            &path,
            &pe_buf,
            crate::cache::get_sym_servers(Some(&format!("SRV*~/symcache*{}", MS))).as_ref(),
        )
        .unwrap_or_else(|| (PeObject::parse(&pe_buf).unwrap(), vec![], "".to_string()));

        let mut output = Vec::new();
        let cursor = Cursor::new(&mut output);

        if pdb_buf.is_empty() {
            let pe = PEInfo::new(file_name, pe).unwrap();
            pe.dump(cursor).unwrap();
        } else {
            let pdb = PDBInfo::new(&pdb_buf, &pdb_name, file_name, Some(pe), mapping).unwrap();
            pdb.dump(cursor).unwrap();
        }

        output
    }

    fn get_data(file_name: &str) -> Vec<u8> {
        let path = PathBuf::from("./test_data/windows");
        let mut path = path.join(file_name);
        for ext in &["sym", "old.sym"] {
            path.set_extension(ext);
            if path.exists() {
                break;
            }
        }

        let mut file = File::open(&path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    fn clean_old_lines(func: &BreakpadFuncRecord) -> Vec<BreakpadLineRecord> {
        let mut res: Vec<BreakpadLineRecord> = Vec::new();
        func.lines().for_each(|l| {
            let line = l.unwrap();
            if line.line >= 0x00f0_0000 {
                res.last_mut().unwrap().size += line.size
            } else {
                res.push(line);
            }
        });

        res
    }

    fn check_headers(new: &BreakpadObject, old: &BreakpadObject) {
        assert_eq!(new.code_id(), old.code_id(), "Bad code id");
        assert_eq!(new.debug_id(), old.debug_id(), "Bad debug id");
        assert_eq!(new.arch(), old.arch(), "Bad arch");
        assert_eq!(new.name(), old.name(), "Bad name");
        assert_eq!(new.kind(), old.kind(), "Bad kind");
    }

    fn check_func_len(
        func_new: &[std::result::Result<BreakpadFuncRecord<'_>, BreakpadError>],
        func_old: &[std::result::Result<BreakpadFuncRecord<'_>, BreakpadError>],
    ) {
        if func_new.len() != func_old.len() {
            // Try to find the diff in the addresses
            let mut old_addresses = FxHashMap::default();
            let mut old_keys = FxHashSet::default();
            for addr in func_old.iter().map(|f| f.as_ref().unwrap().address) {
                *old_addresses.entry(addr).or_insert(0) += 1;
                old_keys.insert(addr);
            }
            let mut new_addresses = FxHashMap::default();
            let mut new_keys = FxHashSet::default();
            for addr in func_new.iter().map(|f| f.as_ref().unwrap().address) {
                *new_addresses.entry(addr).or_insert(0) += 1;
                new_keys.insert(addr);
            }
            let diff: Vec<_> = old_keys.symmetric_difference(&new_keys).collect();
            for addr in diff.iter() {
                old_addresses.remove(addr);
                new_addresses.remove(addr);
            }

            let mut diff_value = Vec::new();
            for (addr, value) in old_addresses.iter() {
                let new_value = new_addresses.get(addr).unwrap();
                if new_value != value {
                    diff_value.push((addr, new_value, value));
                }
            }

            let diff: Vec<_> = diff.iter().map(|x| format!("0x{:x}", x)).collect();
            let values: Vec<_> = diff_value
                .iter()
                .map(|(a, n, o)| format!("At 0x{:x}: new {}, old: {}", a, n, o))
                .collect();
            panic!(
                "Not the same number of FUNC (new: {}, old: {}):\n - Diff keys: {:?}\n - Diff values: {:?}",
                func_new.len(),
                func_old.len(),
                diff,
                values,
            );
        }
    }

    fn check_func(
        pos: usize,
        new: &BreakpadFuncRecord,
        old: &BreakpadFuncRecord,
        file_map_new: &BreakpadFileMap,
        file_map_old: &BreakpadFileMap,
        flags: TestFlags,
    ) {
        assert_eq!(
            new.address,
            old.address,
            "Not the same address for FUNC at position {}",
            pos + 1
        );
        if !flags.intersects(TestFlags::NO_MULTIPLICITY) {
            assert_eq!(
                new.multiple, old.multiple,
                "Not the same multiplicity for FUNC at rva {:x}",
                new.address
            );
        }
        assert_eq!(
            new.size, old.size,
            "Not the same size for FUNC at rva {:x}",
            new.address
        );
        assert_eq!(
            new.parameter_size, old.parameter_size,
            "Not the same parameter size for FUNC at rva {:x}",
            new.address
        );

        if new.name.contains("test_array(") {
            assert_eq!(new.name, "test_array(char*, int[34]*, std::basic_string<char,std::char_traits<char>,std::allocator<char> >[34][56]*, double*[34][56][78]*)");
        }

        if new.name.contains("test_array_empty_struct(") {
            assert_eq!(
                new.name,
                "test_array_empty_struct(Empty*, Empty[]*, Empty[][]*, Empty[][][]*)"
            );
        }

        if new
            .name
            .contains("RefCountMap<unsigned short *>::Increment")
        {
            assert_eq!(
                new.name,
                "long RefCountMap<unsigned short *>::Increment(unsigned short *)"
            );
        }

        // TODO: find a way to compare function names

        let line_old = clean_old_lines(&old);
        let line_new = new.lines();

        assert_eq!(
            line_new.clone().count(),
            line_old.len(),
            "Not the same number of lines for FUNC at rva {:x}",
            new.address
        );
        for (i, (line_n, line_o)) in line_new.zip(line_old.iter()).enumerate() {
            let line_n = line_n.unwrap();

            assert_eq!(
                line_n.address,
                line_o.address,
                "Not the same address for line at position {} in FUNC at rva {:x}",
                i + 1,
                new.address
            );

            if flags.intersects(TestFlags::NO_FILE_LINE) {
                continue;
            }

            if i < line_old.len() - 1 {
                // Sometimes the last line is different
                // For a line, DIA seems to compute the length using the address of next line minus address of the line
                // But it appears that in assembly files we may have several symbols for the same offset
                // and so the length may be incorrect.
                assert_eq!(
                    line_n.size,
                    line_o.size,
                    "Not the same size for line at position {} in FUNC at rva {:x}",
                    i + 1,
                    new.address
                );
            }

            assert_eq!(
                line_n.line,
                line_o.line,
                "Not the same line number for line at position {} in FUNC at rva {:x}",
                i + 1,
                new.address
            );

            assert_eq!(
                file_map_new.get(&line_n.file_id),
                file_map_old.get(&line_o.file_id),
                "Not the same file for line at position {} in FUNC at rva {:x}",
                i + 1,
                new.address
            );
        }
    }

    fn test_file(name: &str, flags: TestFlags) {
        let (out, name) = if name.starts_with("https://") {
            get_data_from_server(name)
        } else {
            let dll = name.to_string() + ".dll";
            (get_new_bp(&dll, None), name)
        };
        let new = BreakpadObject::parse(&out).unwrap();

        let out = get_data(name);
        let old = BreakpadObject::parse(&out).unwrap();

        check_headers(&new, &old);

        let file_map_old = old.file_map();
        let file_map_new = new.file_map();
        let files_old: Vec<_> = file_map_old.values().collect();
        let files_new: Vec<_> = file_map_new.values().collect();

        assert_eq!(files_new, files_old, "Not the same files");

        let mut func_old: Vec<_> = old.func_records().collect();
        let mut func_new: Vec<_> = new.func_records().collect();
        func_old.sort_by_key(|f| f.as_ref().unwrap().address);
        func_new.sort_by_key(|f| f.as_ref().unwrap().address);

        if !flags.intersects(TestFlags::NO_FUNCS_LENGTH) {
            check_func_len(&func_new, &func_old);
        }

        for (i, (func_n, func_o)) in func_new.iter().zip(func_old.iter()).enumerate() {
            let func_n = func_n.as_ref().unwrap();
            let func_o = func_o.as_ref().unwrap();

            check_func(i, func_n, func_o, &file_map_new, &file_map_old, flags);
        }

        let public_old = old.public_records();
        // Remove public constants
        let public_old = public_old.filter(|x| {
            let x = x.as_ref().unwrap();
            !x.name.contains("::FNODOBFM::`string'")
        });

        let public_new = new.public_records();

        assert_eq!(
            public_new.clone().count(),
            public_old.clone().count(),
            "Not the same number of PUBLIC"
        );

        for (i, (public_n, public_o)) in public_new.zip(public_old).enumerate() {
            let public_n = public_n.unwrap();
            let public_o = public_o.unwrap();

            assert_eq!(
                public_n.address,
                public_o.address,
                "Not the same address for PUBLIC at position {} ({})",
                i + 1,
                public_n.name
            );
            if !flags.intersects(TestFlags::NO_MULTIPLICITY) {
                assert_eq!(
                    public_n.multiple, public_o.multiple,
                    "Not the same multiplicity for PUBLIC at rva {:x}",
                    public_n.address
                );
            }
            assert_eq!(
                public_n.parameter_size, public_o.parameter_size,
                "Not the same parameter size for PUBLIC at rva {:x}",
                public_n.address
            );
            /*assert_eq!(
                public_n.name, public_o.name,
                "Not the same name for PUBLIC at rva {:x}",
                public_n.address
            );*/
        }
    }

    #[test]
    fn test_basic32() {
        test_file("basic32", TestFlags::ALL);
    }

    #[test]
    fn test_basic32_min() {
        test_file("basic32-min", TestFlags::ALL);
    }

    #[test]
    fn test_basic64() {
        test_file("basic64", TestFlags::ALL);
    }

    #[test]
    fn test_basic_opt32() {
        test_file("basic-opt32", TestFlags::ALL);
    }

    #[test]
    fn test_basic_opt64() {
        test_file("basic-opt64", TestFlags::ALL);
    }

    #[test]
    fn test_dump_syms_regtest64() {
        test_file("dump_syms_regtest64", TestFlags::ALL);
    }

    #[test]
    fn test_mozwer() {
        test_file("mozwer", TestFlags::ALL);
    }

    #[test]
    fn test_ntdll() {
        test_file(
            &format!("{}/ntdll.dll/5D6AA5581AD000/ntdll.dll", MS),
            TestFlags::NO_MULTIPLICITY,
        );
    }

    #[test]
    fn test_oleaut32() {
        test_file(
            &format!("{}/oleaut32.dll/BCDE805BC4000/oleaut32.dll", MS),
            TestFlags::NO_MULTIPLICITY,
        );
    }

    #[test]
    fn test_win_mapping() {
        let mapping = PathMappings::new(
            &Some(vec!["rev=abcdef"]),
            &Some(vec![r"d:\\agent\\_work\\3\\s\\src\\(.*)"]),
            &Some(vec!["https://source/{rev}/{1}"]),
            &None,
        )
        .unwrap();
        let dll = "basic32.dll";
        let output = get_new_bp(dll, mapping.map(Arc::new));
        let bp = BreakpadObject::parse(&output).unwrap();

        let map = bp.file_map();
        let files: Vec<_> = map.values().collect();

        assert_eq!(
            files[6].replace('\\', "/"),
            "https://source/abcdef/externalapis/windows/10/sdk/inc/winbase.h"
        );
        assert_eq!(
            files[7].replace('\\', "/"),
            "https://source/abcdef/externalapis/windows/10/sdk/inc/winerror.h"
        );
        assert_eq!(
            files[files.len() - 1].replace('\\', "/"),
            "https://source/abcdef/vctools/crt/vcruntime/src/string/i386/memcmp.c"
        );
    }
}
