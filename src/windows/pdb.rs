// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use failure::Fail;
use pdb::{
    AddressMap, BlockSymbol, DebugInformation, FallibleIterator, MachineType, ModuleInfo,
    PDBInformation, ProcedureSymbol, PublicSymbol, Register, RegisterRelativeSymbol, Result,
    Source, SymbolData, SymbolTable, PDB,
};
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Write};
use symbolic_debuginfo::{pdb::PdbObject, pe::PeObject, Object};
use symbolic_minidump::cfi::AsciiCfiWriter;
use uuid::Uuid;

use super::source::{SourceFiles, SourceLineCollector};
use super::symbol::{BlockInfo, PDBSymbols, RvaSymbols};
use super::types::{DumperFlags, TypeDumper};
use super::utils::get_pe_debug_id;
use crate::common;

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

const IMAGE_SCN_CNT_CODE: u32 = 0x00_000_020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20_000_000;

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
                    .map(|section| {
                        section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0
                    })
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
}

struct PDBData<'s> {
    address_map: AddressMap<'s>,
}

struct Collector {
    cpu: CPU,
    symbols: RvaSymbols,
    pdb_sections: PDBSections,
}

impl Collector {
    fn add_public_symbol(&mut self, symbol: PublicSymbol, address_map: &AddressMap) {
        self.symbols
            .add_public_symbol(symbol, &self.pdb_sections, address_map)
    }

    fn add_procedure_symbol(
        &mut self,
        symbol: ProcedureSymbol,
        info: BlockInfo,
        lines: &SourceLineCollector,
    ) -> Result<()> {
        self.symbols.add_procedure_symbol(lines, symbol, info)
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
}

pub(crate) struct PDBInfo {
    symbols: PDBSymbols,
    files: Vec<String>,
    cpu: CPU,
    debug_id: String,
    pdb_name: String,
    pe_name: String,
    code_id: Option<String>,
    stack: Option<String>,
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

        if let Some(stack) = self.stack.as_ref() {
            write!(f, "{}", stack)?;
        }

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

fn get_stack_info(pdb_buf: &[u8], pe: Option<PeObject>, cpu: CPU) -> String {
    let mut buf = Vec::new();
    let writer = Cursor::new(&mut buf);

    let mut cfi_writer = AsciiCfiWriter::new(writer);
    if cpu == CPU::X86_64 {
        if let Some(pe) = pe {
            cfi_writer
                .process(&Object::Pe(pe))
                .map_err(|e| e.compat())
                .unwrap();
        }
    } else if let Ok(pdb) = PdbObject::parse(&pdb_buf) {
        cfi_writer
            .process(&Object::Pdb(pdb))
            .map_err(|e| e.compat())
            .unwrap();
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
            )?;
        }

        Ok(())
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
                )?;
            }
            SymbolData::Block(block) => {
                self.add_block(&module_info, block, collector, lines)?;
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
        pdb_name: String,
        pe_name: String,
        pe: Option<PeObject>,
        with_stack: bool,
    ) -> Result<Self> {
        let cursor = Cursor::new(buf);
        let mut pdb = PDB::open(cursor)?;
        let dbi = pdb.debug_information()?;
        let pi = pdb.pdb_information()?;
        let frame_table = pdb.frame_table()?;
        let globals = pdb.global_symbols()?;
        let pdb_sections = PDBSections::new(&mut pdb);

        let cpu = get_cpu(&dbi);
        let debug_id = get_debug_id(&dbi, pi);
        let source_files = SourceFiles::new(&mut pdb)?;

        let pdb_data = PDBData {
            address_map: pdb.address_map()?,
        };

        let mut collector = Collector {
            cpu,
            symbols: RvaSymbols::default(),
            pdb_sections,
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

        let stack = if with_stack {
            Some(get_stack_info(buf, pe, cpu))
        } else {
            None
        };

        Ok(PDBInfo {
            symbols: collector.symbols.mv_to_pdb_symbols(
                type_dumper,
                &pdb_data.address_map,
                frame_table,
            ),
            files: source_files.get_mapping(),
            cpu,
            debug_id,
            pdb_name,
            pe_name,
            code_id,
            stack,
        })
    }

    pub fn dump<W: Write>(&self, mut writer: W) -> common::Result<()> {
        write!(writer, "{}", self)?;
        Ok(())
    }

    pub fn debug_id(&self) -> &str {
        &self.debug_id
    }

    pub fn pdb_name(&self) -> &str {
        &self.pdb_name
    }
}

#[cfg(test)]
mod tests {

    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use symbolic_debuginfo::breakpad::{
        BreakpadFileMap, BreakpadFuncRecord, BreakpadLineRecord, BreakpadObject,
    };

    use super::*;

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

    fn get_new_bp(file_name: &str) -> Vec<u8> {
        let path = PathBuf::from("./test_data");
        let mut path = path.join(file_name);

        if !path.exists() {
            path.set_extension("exe");
        }

        let pe_buf = crate::utils::read_file(&path);
        let (pe, pdb_buf, pdb_name) =
            crate::windows::utils::get_pe_pdb_buf(path, &pe_buf, None).unwrap();
        let mut output = Vec::new();
        let cursor = Cursor::new(&mut output);
        let pdb = PDBInfo::new(&pdb_buf, pdb_name, file_name.to_string(), Some(pe), false).unwrap();
        pdb.dump(cursor).unwrap();

        output
    }

    fn get_data(file_name: &str) -> Vec<u8> {
        let path = PathBuf::from("./test_data");
        let path = path.join(file_name);

        let mut file = File::open(&path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    fn clean_old_lines(func: &BreakpadFuncRecord) -> Vec<BreakpadLineRecord> {
        let mut res: Vec<BreakpadLineRecord> = Vec::new();
        func.lines().for_each(|l| {
            let line = l.unwrap();
            if line.line >= 0xf00_000 {
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

    fn check_func(
        pos: usize,
        new: BreakpadFuncRecord,
        old: BreakpadFuncRecord,
        file_map_new: &BreakpadFileMap,
        file_map_old: &BreakpadFileMap,
    ) {
        assert_eq!(
            new.address,
            old.address,
            "Not the same address for FUNC at position {}",
            pos + 1
        );
        assert_eq!(
            new.multiple, old.multiple,
            "Not the same multiplicity for FUNC at rva {:x}",
            new.address
        );
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

    fn test_file(name: &str) {
        let dll = name.to_string() + ".dll";
        let out = get_new_bp(&dll);
        let new = BreakpadObject::parse(&out).unwrap();

        let sym = name.to_string() + ".old.sym";
        let out = get_data(&sym);
        let old = BreakpadObject::parse(&out).unwrap();

        check_headers(&new, &old);

        let file_map_old = old.file_map();
        let file_map_new = new.file_map();
        let files_old: Vec<_> = file_map_old.values().collect();
        let files_new: Vec<_> = file_map_new.values().collect();

        assert_eq!(files_new, files_old, "Not the same files");

        let func_old = old.func_records();
        let func_new = new.func_records();

        assert_eq!(
            func_new.clone().count(),
            func_old.clone().count(),
            "Not the same number of FUNC"
        );

        for (i, (func_n, func_o)) in func_new.zip(func_old).enumerate() {
            let func_n = func_n.unwrap();
            let func_o = func_o.unwrap();

            check_func(i, func_n, func_o, &file_map_new, &file_map_old);
        }

        let public_old = old.public_records();
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
            assert_eq!(
                public_n.multiple, public_o.multiple,
                "Not the same multiplicity for PUBLIC at rva {:x}",
                public_n.address
            );
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
        test_file("basic32");
    }

    #[test]
    fn test_basic32_min() {
        test_file("basic32-min");
    }

    #[test]
    fn test_basic64() {
        test_file("basic64");
    }

    #[test]
    fn test_basic_opt32() {
        test_file("basic-opt32");
    }

    #[test]
    fn test_basic_opt64() {
        test_file("basic-opt64");
    }

    #[test]
    fn test_dump_syms_regtest64() {
        test_file("dump_syms_regtest64");
    }
}
