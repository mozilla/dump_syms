// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use failure::Fail;
use hashbrown::HashMap;
use log::{error, warn};
use std::collections::btree_map;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Write};
use symbolic_debuginfo::{
    dwarf::DwarfFunctionIteratorOption, Function, LineInfo, Object, ObjectDebugSession,
};

use symbolic_common::{Language, Name};
use symbolic_demangle::{Demangle, DemangleFormat, DemangleOptions};
use symbolic_minidump::cfi::AsciiCfiWriter;

use super::source::SourceFiles;
use super::symbol::{ElfSymbol, ElfSymbols};

use crate::common::{self, Dumpable, LineFinalizer};
use crate::line::Lines;

#[derive(Debug, Default)]
pub struct ElfInfo {
    symbols: ElfSymbols,
    files: Vec<String>,
    file_name: String,
    cpu: &'static str,
    debug_id: String,
    code_id: Option<String>,
    stack: Option<String>,
}

impl Display for ElfInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "MODULE Linux {} {} {}",
            self.cpu, self.debug_id, self.file_name
        )?;

        if let Some(code_id) = self.code_id.as_ref() {
            writeln!(f, "INFO CODE_ID {}", code_id)?;
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

// What we have.
// Each function has an address, a size, a list of lines and a list of inlinees (which are functions)
// - address: the address where the function start: first_range.begin
// - size: last_range.end - first_range.begin
// - lines: each range is mapped to a set of lines, for any reason a range can be mapped with a line which is out of range
//   when the line address is an inlinee address, line info gives us the "calling" location

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
struct ElfLineInfo {
    file_id: u32,
    line: u32,
}

#[derive(Debug, Default)]
struct Inlinee {
    location: ElfLineInfo,
    start: u64,
    end: u64,
}

impl Display for Inlinee {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "location: {:?}", self.location)?;
        writeln!(f, "start: 0x{:x}", self.start)?;
        writeln!(f, "end: 0x{:x}", self.end)
    }
}

#[derive(Debug)]
struct InlineeManager {
    /// All the inlinees
    inlinees: Vec<Inlinee>,

    /// Map addresses we've in an inlinee with inlinee position in inlinees vec
    /// So for a given address we're able to find the corresponding inlinee
    addresses: HashMap<u64, usize>,
}

impl Default for InlineeManager {
    fn default() -> Self {
        Self {
            inlinees: Vec::with_capacity(16),
            addresses: HashMap::default(),
        }
    }
}

impl InlineeManager {
    /// Add to this manager inlinees we have in function
    /// It returns true if some inlinees contain address such as addr < inlinee_start_addr
    fn add_inlinees(&mut self, fun: &Function, source: &mut SourceFiles) -> bool {
        let mut has_lower_address = false;
        for inlinee in fun.inlinees.iter() {
            let has_hla = self.add_inlinee(inlinee, source);
            has_lower_address |= has_hla;
        }

        has_lower_address
    }

    /// Add to this manager an inlinee
    /// It returns true if some inlinees contain address such as addr < inlinee_start_addr
    fn add_inlinee(&mut self, fun: &Function, source: &mut SourceFiles) -> bool {
        let inlinee_pos = self.inlinees.len();
        let has_oor = self.collect_inlinee_data(fun.address, inlinee_pos, fun, source);

        self.inlinees.push(Inlinee {
            location: ElfLineInfo::default(),
            start: fun.address,
            end: fun.address + fun.size,
        });

        has_oor
    }

    fn collect_inlinee_data(
        &mut self,
        base_address: u64,
        inlinee_pos: usize,
        fun: &Function,
        source: &mut SourceFiles,
    ) -> bool {
        let mut has_lower_address = false;
        self.addresses.insert(fun.address, inlinee_pos);
        for line in fun.lines.iter() {
            self.addresses.insert(line.address, inlinee_pos);
            has_lower_address |= line.address < base_address;
        }

        for inlinee in fun.inlinees.iter() {
            let has_oor = self.collect_inlinee_data(base_address, inlinee_pos, inlinee, source);
            has_lower_address |= has_oor;
        }

        has_lower_address
    }

    /// Get the line info for the given address
    fn get_line_info(&mut self, address: u64, line: u32, file_id: u32) -> ElfLineInfo {
        let info = ElfLineInfo { file_id, line };
        if let Some(inlinee_pos) = self.addresses.get(&address) {
            let inlinee = &mut self.inlinees[*inlinee_pos];
            if inlinee.start == address {
                // (line,file) correspond to the location where the inliner inlines the inlinee
                // So for the next addresses we'll have in this inlinee we'll be able to return this location
                inlinee.location = info.clone();
                info
            } else {
                // returns the location corresponding to the location of the inlinement
                inlinee.location.clone()
            }
        } else {
            // the line doesn't belong to an inlinee
            info
        }
    }

    /// Set the location where the inlinees are inlined in the inliner
    /// We use this function when some addresses in an inlinee are before the function start
    fn set_line_info(&mut self, line: &LineInfo, compilation_dir: &[u8], source: &mut SourceFiles) {
        if let Some(inlinee_pos) = self.addresses.get(&line.address) {
            let inlinee = &mut self.inlinees[*inlinee_pos];
            if inlinee.start == line.address {
                let file_id = source.get_id(compilation_dir, &line.file);
                inlinee.location = ElfLineInfo {
                    file_id,
                    line: line.line as u32,
                };
            }
        }
    }
}

#[derive(Debug, Default)]
struct Collector {
    syms: ElfSymbols,
}

impl Collector {
    #[allow(dead_code)]
    fn debug_function(fun: &Function, level: String) {
        println!("{}Name: {}", level, fun.name.as_str());
        println!("{}Address: 0x{:x}", level, fun.address);
        println!("{}Size: 0x{:x}", level, fun.size);
        for line in fun.lines.iter() {
            println!("{}Line: {:?}", level, line);
        }
        println!("{}Inlinees:", level);
        for f in fun.inlinees.iter() {
            Self::debug_function(&f, "  ".to_string() + &level);
        }
    }

    fn demangle(name: &Name) -> String {
        if let Language::C = name.language() {
            return name.as_str().to_string();
        }

        match name.demangle(DemangleOptions {
            format: DemangleFormat::Full,
            with_arguments: true,
        }) {
            Some(demangled) => demangled,
            None => {
                let aname = name.as_str();
                warn!("Didn't manage to demangle {:?}", name);
                aname.to_string()
            }
        }
    }

    fn demangle_str(name: &str) -> String {
        let lang = Name::new(name).detect_language();
        if lang == Language::Unknown {
            return name.to_string();
        }

        let name = Name::with_language(name, lang);
        match name.demangle(DemangleOptions {
            format: DemangleFormat::Full,
            with_arguments: true,
        }) {
            Some(demangled) => demangled,
            None => {
                warn!("Didn't manage to demangle {}", name);
                name.to_string()
            }
        }
    }

    fn collect_function(&mut self, fun: &Function, source: &mut SourceFiles) {
        if fun.address == 0 {
            return;
        }

        let mut inlinee_manager = InlineeManager::default();
        let has_lower_address = inlinee_manager.add_inlinees(fun, source);

        if has_lower_address {
            // some addresses belong to an inlinee but they're before the inlinee call
            // so we need to set the calling info (file, line) before
            for line in fun.lines.iter() {
                inlinee_manager.set_line_info(&line, fun.compilation_dir, source);
            }
        }

        let mut lines = Lines::new();
        let mut last = None;

        for line in fun.lines.iter() {
            if line.line == 0 {
                // It's probably better to skip it to avoid to have some links in crash-stats pointing to line 0 in a file
                continue;
            }

            let file_id = source.get_id(fun.compilation_dir, &line.file);
            let line_info = inlinee_manager.get_line_info(line.address, line.line as u32, file_id);

            if last.as_ref().map_or(true, |prev| *prev != line_info) {
                lines.add_line(
                    line.address as u32,
                    line_info.line as u32,
                    source.get_true_id(line_info.file_id),
                );
                last = Some(line_info);
            }
        }

        // compute line length
        lines.finalize(fun.address as u32, fun.size as u32, &());

        self.syms.insert(
            fun.address as u32,
            ElfSymbol {
                name: Self::demangle(&fun.name),
                is_public: false,
                is_multiple: false,
                rva: fun.address as u32,
                len: fun.size as u32,
                parameter_size: 0,
                source: lines,
            },
        );
    }

    fn collect_functions(&mut self, o: &Object, source: &mut SourceFiles) -> common::Result<()> {
        let ds = o.debug_session().map_err(|e| e.compat())?;
        let ds = if let ObjectDebugSession::Dwarf(ds) = ds {
            ds
        } else {
            unreachable!();
        };

        let functions_iter = ds.functions_option(DwarfFunctionIteratorOption {
            collapse_lines: false,
        });

        for fun in functions_iter {
            match fun {
                Ok(fun) => {
                    self.collect_function(&fun, source);
                }
                Err(e) => {
                    error!("{:?}", e);
                }
            }
        }

        Ok(())
    }

    fn collect_publics(&mut self, o: &Object) {
        for sym in o.symbols() {
            match self.syms.entry(sym.address as u32) {
                btree_map::Entry::Occupied(_) => {}
                btree_map::Entry::Vacant(e) => {
                    let sym_name = sym.name.map_or_else(
                        || "<name omitted>".to_string(),
                        |n| Self::demangle_str(&n.to_owned()),
                    );
                    e.insert(ElfSymbol {
                        name: sym_name,
                        is_public: true,
                        is_multiple: false,
                        rva: sym.address as u32,
                        len: sym.size as u32,
                        parameter_size: 0,
                        source: Lines::default(),
                    });
                }
            }
        }
    }

    fn get_stack_info(o: &Object) -> String {
        let mut buf = Vec::new();
        let writer = Cursor::new(&mut buf);

        let mut cfi_writer = AsciiCfiWriter::new(writer);
        if let Err(e) = cfi_writer.process(o) {
            error!("{}", e);
        }

        String::from_utf8(buf).unwrap()
    }
}

impl ElfInfo {
    pub fn new(buf: &[u8], file_name: String, with_stack: bool) -> common::Result<Self> {
        let o = Object::parse(&buf).map_err(|e| e.compat())?;
        let mut collector = Collector::default();
        let mut source = SourceFiles::default();
        let debug_id = format!("{}", o.debug_id().breakpad());
        let code_id = o.code_id().map(|c| c.as_str().to_string().to_uppercase());
        let cpu = o.arch().name();

        collector.collect_functions(&o, &mut source)?;
        collector.collect_publics(&o);

        let stack = if with_stack {
            Some(Collector::get_stack_info(&o))
        } else {
            None
        };

        Ok(Self {
            symbols: collector.syms,
            files: source.get_mapping(),
            file_name,
            cpu,
            debug_id,
            code_id,
            stack,
        })
    }
}

impl Dumpable for ElfInfo {
    fn dump<W: Write>(&self, mut writer: W) -> common::Result<()> {
        write!(writer, "{}", self)?;
        Ok(())
    }

    fn get_debug_id(&self) -> &str {
        &self.debug_id
    }

    fn get_name(&self) -> &str {
        &self.file_name
    }
}
