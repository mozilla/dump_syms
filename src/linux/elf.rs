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
use std::sync::Arc;
use symbolic_common::{Language, Name, NameMangling};
use symbolic_debuginfo::{Function, Object, ObjectDebugSession};
use symbolic_demangle::{Demangle, DemangleOptions};
use symbolic_minidump::cfi::AsciiCfiWriter;

use super::source::{SourceFiles, SourceMap};
use super::symbol::{ElfSymbol, ElfSymbols};
use crate::common::{self, Dumpable, LineFinalizer, Mergeable};
use crate::line::Lines;
use crate::mapping::PathMappings;

#[derive(Debug, PartialEq)]
pub enum Type {
    Stripped,
    DebugInfo,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Platform {
    Linux,
    Mac,
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let p = match self {
            Self::Linux => "Linux",
            Self::Mac => "Mac",
        };
        write!(f, "{}", p)
    }
}

#[derive(Debug)]
pub struct ElfInfo {
    symbols: ElfSymbols,
    files: SourceMap,
    file_name: String,
    cpu: &'static str,
    debug_id: String,
    code_id: Option<String>,
    stack: String,
    bin_type: Type,
    platform: Platform,
}

impl Display for ElfInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "MODULE {} {} {} {}",
            self.platform, self.cpu, self.debug_id, self.file_name
        )?;

        if let Some(code_id) = self.code_id.as_ref() {
            writeln!(f, "INFO CODE_ID {}", code_id)?;
        }

        for (n, file_name) in self.files.get_mapping().iter().enumerate() {
            writeln!(f, "FILE {} {}", n, file_name)?;
        }

        for (_, sym) in self.symbols.iter() {
            write!(f, "{}", sym)?;
        }

        write!(f, "{}", self.stack)?;

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
    fn add_inlinees(&mut self, fun: &Function, source: &mut SourceFiles) {
        for inlinee in fun.inlinees.iter() {
            self.add_inlinee(inlinee, source);
        }
    }

    /// Add to this manager an inlinee
    fn add_inlinee(&mut self, fun: &Function, source: &mut SourceFiles) {
        let inlinee_pos = self.inlinees.len();
        self.collect_inlinee_data(fun.address, inlinee_pos, fun, source);

        self.inlinees.push(Inlinee {
            location: ElfLineInfo::default(),
            start: fun.address,
            end: fun.address + fun.size,
        });
    }

    fn collect_inlinee_data(
        &mut self,
        base_address: u64,
        inlinee_pos: usize,
        fun: &Function,
        source: &mut SourceFiles,
    ) {
        self.addresses.insert(fun.address, inlinee_pos);
        for line in fun.lines.iter() {
            self.addresses.insert(line.address, inlinee_pos);
        }

        for inlinee in fun.inlinees.iter() {
            self.collect_inlinee_data(base_address, inlinee_pos, inlinee, source);
        }
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
}

#[derive(Debug, Default)]
pub struct Collector {
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
        println!();
    }

    fn demangle(name: &Name) -> String {
        let name = common::fix_symbol_name(name);
        if let Language::C = name.language() {
            return name.as_str().to_string();
        }

        match name.demangle(DemangleOptions::complete()) {
            Some(demangled) => demangled,
            None => {
                let aname = name.as_str();
                warn!("Didn't manage to demangle {:?}", name);
                aname.to_string()
            }
        }
    }

    fn demangle_str(name: &str) -> String {
        let lang = Name::new(name, NameMangling::Mangled, Language::Unknown).detect_language();
        if lang == Language::Unknown {
            return name.to_string();
        }

        let name = Name::new(name, NameMangling::Mangled, lang);
        let name = common::fix_symbol_name(&name);

        match name.demangle(DemangleOptions::complete()) {
            Some(demangled) => demangled,
            None => {
                warn!("Didn't manage to demangle {}", name);
                name.to_string()
            }
        }
    }

    pub fn collect_function(&mut self, fun: &Function, source: &mut SourceFiles) {
        if fun.address == 0 {
            return;
        }

        let mut inlinee_manager = InlineeManager::default();
        inlinee_manager.add_inlinees(fun, source);

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

    pub fn collect_functions(
        &mut self,
        o: &Object,
        source: &mut SourceFiles,
    ) -> common::Result<()> {
        let ds = o.debug_session().map_err(|e| e.compat())?;
        let ds = if let ObjectDebugSession::Dwarf(ds) = ds {
            ds
        } else {
            unreachable!();
        };

        for fun in ds.functions() {
            match fun {
                Ok(fun) => {
                    self.collect_function(&fun, source);
                }
                Err(e) => {
                    error!("Function collection: {:?}", e);
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
            error!("CFI: {:?}", e);
        }

        String::from_utf8(buf).unwrap()
    }
}

impl ElfInfo {
    pub(crate) fn new(
        buf: &[u8],
        file_name: &str,
        platform: Platform,
        mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        let o = Object::parse(&buf).map_err(|e| e.compat())?;
        Self::from_object(&o, file_name, platform, mapping)
    }

    pub fn from_object(
        o: &Object,
        file_name: &str,
        platform: Platform,
        mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        let mut collector = Collector::default();
        let mut source = SourceFiles::new(mapping);
        let debug_id = format!("{}", o.debug_id().breakpad());
        let code_id = o.code_id().map(|c| c.as_str().to_string().to_uppercase());
        let cpu = o.arch().name();
        let bin_type = if o.has_debug_info() {
            Type::DebugInfo
        } else {
            Type::Stripped
        };

        collector.collect_functions(&o, &mut source)?;
        collector.collect_publics(&o);

        let stack = Collector::get_stack_info(&o);

        Ok(Self {
            symbols: collector.syms,
            files: source.get_mapping(),
            file_name: String::from(file_name),
            cpu,
            debug_id,
            code_id,
            stack,
            bin_type,
            platform,
        })
    }
}

impl Mergeable for ElfInfo {
    fn merge(left: ElfInfo, right: ElfInfo) -> common::Result<ElfInfo> {
        if left.debug_id != right.debug_id {
            return Err(format!(
                "The files don't have the same debug id: {} and {}",
                left.debug_id, right.debug_id
            )
            .into());
        }

        // Just to avoid to iterate on the bigger
        let (mut left, mut right) = if left.symbols.len() > right.symbols.len() {
            (left, right)
        } else {
            (right, left)
        };

        // merge the CFIs
        if left.stack.is_empty() {
            std::mem::swap(&mut left.stack, &mut right.stack);
        } else if !right.stack.is_empty() {
            if *left.stack.as_bytes().last().unwrap() != b'\n' {
                left.stack.push('\n');
            }
            left.stack.push_str(&right.stack);
        }

        // If the two files contains some FUNC they may have differents FILE number associated with
        // So merge them and get an array to remap files from 'right' with the new correct id
        let remapping = left.files.merge(&mut right.files);

        for (addr, sym) in right.symbols.iter_mut() {
            if sym.is_public {
                // No line info so just put the sym in the map

                // Check that the symbol isn't inside another one (it happens sometimes IRL)
                let last = left.symbols.range(0..*addr).next_back();
                if let Some(last) = last {
                    if *addr < last.1.rva + last.1.len {
                        continue;
                    }
                }

                match left.symbols.entry(*addr) {
                    btree_map::Entry::Occupied(mut e) => {
                        // we already have one so just discard this one
                        e.get_mut().is_multiple = true;
                    }
                    btree_map::Entry::Vacant(e) => {
                        e.insert(sym.clone());
                    }
                }
                continue;
            }

            // Deal with a FUNC
            match left.symbols.entry(*addr) {
                btree_map::Entry::Occupied(mut e) => {
                    let a_sym = e.get_mut();
                    if a_sym.is_public {
                        // FUNC is more interesting than the PUBLIC
                        // so just keep the FUNC
                        sym.fix_lines(remapping.as_ref());
                        std::mem::swap(a_sym, sym);
                    }
                    a_sym.is_multiple = true;
                }
                btree_map::Entry::Vacant(e) => {
                    sym.fix_lines(remapping.as_ref());
                    e.insert(sym.clone());
                }
            }
        }

        if left.code_id.is_none() && right.code_id.is_some() {
            left.code_id = right.code_id;
        }

        if right.bin_type == Type::Stripped {
            left.file_name = right.file_name;
        }

        Ok(left)
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
