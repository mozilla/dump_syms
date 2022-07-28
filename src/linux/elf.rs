// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use log::{error, warn};
use std::collections::btree_map;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::sync::Arc;
use symbolic::cfi::AsciiCfiWriter;
use symbolic::common::{Language, Name, NameMangling};
use symbolic::debuginfo::{Function, Object, ObjectDebugSession};
use symbolic::demangle::Demangle;

use super::source::{SourceFiles, SourceMap};
use super::symbol::{ContainsSymbol, ElfSymbol, ElfSymbols, ParsedWinFuncName};
use crate::common::{self, demangle_options, Dumpable, LineFinalizer, Mergeable};
use crate::inline_origins::{merge_inline_origins, InlineOrigins};
use crate::line::{InlineAddressRange, InlineSite, Lines};
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
    Win,
}

impl Platform {
    pub fn is_target(&self) -> bool {
        match self {
            Platform::Linux => cfg!(target_os = "linux"),
            Platform::Mac => cfg!(target_os = "macos"),
            Platform::Win => cfg!(target_os = "windows"),
        }
    }

    pub fn is_absolute_path(&self, path: &str) -> bool {
        match self {
            Platform::Linux | Platform::Mac => path.starts_with('/'),
            Platform::Win => {
                // Detect "C:\..." and "C:/...".
                let first_fragment = match path.find(&['/', '\\']) {
                    Some(first_fragment_len) => &path[..first_fragment_len],
                    None => path,
                };
                first_fragment.ends_with(':')
            }
        }
    }

    pub fn join_paths(&self, left: &str, right: &str) -> String {
        match self {
            Platform::Linux | Platform::Mac => {
                let left = left.trim_end_matches('/');
                let right = right.trim_start_matches('/');
                format!("{}/{}", left, right)
            }
            Platform::Win => {
                let left = left.trim_end_matches('\\');
                let right = right.trim_start_matches('\\');
                format!("{}\\{}", left, right)
            }
        }
    }
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let p = match self {
            Self::Linux => "Linux",
            Self::Mac => "Mac",
            Self::Win => "windows",
        };
        write!(f, "{}", p)
    }
}

#[derive(Debug)]
pub struct ElfInfo {
    symbols: ElfSymbols,
    files: SourceMap,
    inline_origins: Vec<String>,
    file_name: String,
    cpu: &'static str,
    debug_id: String,
    code_id: Option<String>,
    pe_name: Option<String>,
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
            let pe_name = self.pe_name.as_deref().unwrap_or_default();
            let line = format!("INFO CODE_ID {} {}", code_id, pe_name);
            writeln!(f, "{}", line.trim())?;
        }

        for (n, file_name) in self.files.get_mapping().iter().enumerate() {
            writeln!(f, "FILE {} {}", n, file_name)?;
        }

        for (n, function_name) in self.inline_origins.iter().enumerate() {
            writeln!(f, "INLINE_ORIGIN {} {}", n, function_name)?;
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

#[derive(Debug)]
pub struct Collector {
    platform: Platform,
    collect_inlines: bool,
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
            Self::debug_function(f, "  ".to_string() + &level);
        }
        println!();
    }

    fn demangle(name: &Name) -> String {
        let name = common::fix_symbol_name(name);
        if let Language::C = name.language() {
            return name.as_str().to_string();
        }

        match name.demangle(demangle_options()) {
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

        match name.demangle(demangle_options()) {
            Some(demangled) => demangled,
            None => {
                warn!("Didn't manage to demangle {}", name);
                name.to_string()
            }
        }
    }

    pub fn collect_function<'a>(
        &mut self,
        fun: &Function<'a>,
        source: &mut SourceFiles,
        inline_origins: &mut InlineOrigins<'a>,
    ) {
        if fun.address == 0 {
            return;
        }

        if let Some(sym) = self.syms.get_mut(&(fun.address as u32)) {
            if !sym.is_public {
                sym.is_multiple = true;
                return;
            }
        }

        let mut lines = Lines::new();

        if self.collect_inlines {
            Self::collect_function_with_inlines_recursive(
                fun,
                &mut lines,
                source,
                inline_origins,
                0,
            );
        } else {
            Self::collect_function_without_inlines(fun, &mut lines, source);
        }

        // compute line length
        lines.finalize(fun.address as u32, fun.size as u32, &());

        self.syms.insert(
            fun.address as u32,
            ElfSymbol {
                name: Self::demangle(&fun.name),
                is_public: false,
                is_multiple: false,
                is_synthetic: false,
                rva: fun.address as u32,
                len: fun.size as u32,
                parameter_size: 0,
                source: lines,
            },
        );
    }

    fn collect_function_without_inlines<'a>(
        fun: &Function<'a>,
        lines: &mut Lines,
        source: &mut SourceFiles,
    ) {
        let mut prev = None;
        for line in fun.lines.iter() {
            if line.line == 0 {
                // It's probably better to skip it to avoid to have some links in crash-stats pointing to line 0 in a file
                continue;
            }

            let file_id = source.get_id(fun.compilation_dir, &line.file);
            let line_info = (line.line, file_id);
            if prev.as_ref() != Some(&line_info) {
                lines.add_line(
                    line.address as u32,
                    line.line as u32,
                    source.get_true_id(file_id),
                );
                prev = Some(line_info);
            }
        }
    }

    /// Translate the information in `fun` into calls to `lines.add_line` and `lines.add_inline`.
    fn collect_function_with_inlines_recursive<'a>(
        fun: &Function<'a>,
        lines: &mut Lines,
        source: &mut SourceFiles,
        inline_origins: &mut InlineOrigins<'a>,
        call_depth: u32,
    ) {
        // This function converts between two representations of line information:
        // "Lines for both self-lines and for inlined calls" -> "Only self-lines"
        //
        // `fun` contains the debug info for our function, with some data for each instruction
        // that our function is made of, associated via the instruction's code address.
        // `fun.lines` contains line records, each of which covers a range of code addresses.
        // `fun.inlinees` contains inlinee records, each of which has its own set of line
        // records (at `inlinee.lines`) covering code addresses.
        //
        // We can divide the instructions in a function into two buckets:
        //  (1) Instructions which are part of an inlined function call, and
        //  (2) instructions which are *not* part of an inlined function call.
        //
        // Our incoming line records cover both (1) and (2) types of instructions.
        // We want to call `lines.add_line` *only for type (2)*.
        //
        // So we need to know which address ranges are covered by inline calls, so that we
        // can filter out those address ranges and skip calling `lines.add_line` for them.

        // First we gather the address ranges covered by inlined calls.
        // We also recurse into the inlinees, while we're at it.
        // The order of calls to `add_line` and `add_inline` is irrelevant; `Lines` will sort
        // everything by address once the entire outer function has been processed.
        let mut inline_ranges = Vec::new();
        for inlinee in &fun.inlinees {
            if inlinee.lines.is_empty() {
                continue;
            }

            let inline_origin_id = inline_origins.get_id(&inlinee.name);

            for line in &inlinee.lines {
                let start = line.address;
                let end = line.address + line.size.unwrap_or(1);
                inline_ranges.push((start..end, inline_origin_id));
            }

            // Recurse.
            Self::collect_function_with_inlines_recursive(
                inlinee,
                lines,
                source,
                inline_origins,
                call_depth + 1,
            );
        }

        // Sort the inline ranges.
        inline_ranges.sort_unstable_by_key(|(range, _origin)| range.start);

        // Walk two iterators. We assume that fun.lines is already sorted by address.
        let mut line_iter = fun.lines.iter();
        let mut inline_iter = inline_ranges.into_iter();
        let mut next_line = line_iter.next();
        let mut next_inline = inline_iter.next();

        let mut prev_line_info = None;

        // Iterate over the line records.
        while let Some(line) = next_line.take() {
            let line_range_start = line.address;
            let line_range_end = line.address + line.size.unwrap_or(1);
            let file_id = source.get_id(fun.compilation_dir, &line.file);
            let file_id = source.get_true_id(file_id);
            let line_no = line.line as u32;

            // The incoming line record can be a "self line", or a "call line", or even a mixture.
            //
            // Examples:
            //
            //  a) Just self line:
            //      Line:      |==============|
            //      Inlines:    (none)
            //
            //      Effect: add_line()
            //
            //  b) Just call line:
            //      Line:      |==============|
            //      Inlines:   |--------------|
            //
            //      Effect: add_inline()
            //
            //  c) Just call line, for multiple inlined calls:
            //      Line:      |==========================|
            //      Inlines:   |----------||--------------|
            //
            //      Effect: add_inline(), add_inline()
            //
            //  d) Call line and trailing self line:
            //      Line:      |==================|
            //      Inlines:   |-----------|
            //
            //      Effect: add_inline(), add_line()
            //
            //  e) Leading self line and also call line:
            //      Line:      |==================|
            //      Inlines:          |-----------|
            //
            //      Effect: add_line(), add_inline()
            //
            //  f) Interleaving
            //      Line:      |======================================|
            //      Inlines:          |-----------|    |-------|
            //
            //      Effect: add_line(), add_inline(), add_line(), add_inline(), add_line()
            //
            //  g) Bad debug info
            //      Line:      |=======|
            //      Inlines:   |-------------|
            //
            //      Effect: add_inline()

            let mut current_address = line_range_start;
            while current_address < line_range_end {
                // Emit a line at current_address if current_address is not covered by an inlined call.
                if next_inline.is_none() || next_inline.as_ref().unwrap().0.start > current_address
                {
                    let line_info = (line_no, file_id);
                    if prev_line_info.as_ref() != Some(&line_info) {
                        lines.add_line(current_address as u32, line_no, file_id);
                        prev_line_info = Some(line_info);
                    }
                }

                // If there is an inlined call covered by this line record, turn this line into that
                // call's "call line" and emit an inline record.
                if next_inline.is_some() && next_inline.as_ref().unwrap().0.start < line_range_end {
                    let (inline_range, inline_origin_id) = next_inline.take().unwrap();

                    let call_line_number = line_no;
                    let call_file_id = file_id;

                    lines.add_inline(
                        InlineSite {
                            inline_origin_id,
                            call_depth,
                            call_line_number,
                            call_file_id,
                        },
                        InlineAddressRange {
                            rva: inline_range.start as u32,
                            len: (inline_range.end - inline_range.start) as u32,
                        },
                    );

                    // Advance current_address to the end of this inline range.
                    current_address = inline_range.end;
                    prev_line_info = None;
                    next_inline = inline_iter.next();
                } else {
                    // No further inline ranges are overlapping with this line record. Advance to the
                    // end of the line record.
                    current_address = line_range_end;
                }
            }

            // Advance the line iterator.
            next_line = line_iter.next();

            // Skip any lines that start before current_address.
            // Such lines can exist if the debug information is faulty, or if the compiler created
            // multiple identical small "call line" records instead of one combined record
            // covering the entire inline range. We can't have different "call lines" for a single
            // inline range anyway, so it's fine to skip these.
            while next_line.is_some() && next_line.as_ref().unwrap().address < current_address {
                next_line = line_iter.next();
            }
        }
    }

    pub fn collect_functions<'a>(
        &mut self,
        ds: &'a ObjectDebugSession,
        source: &mut SourceFiles,
        inline_origins: &mut InlineOrigins<'a>,
    ) -> common::Result<()> {
        for fun in ds.functions() {
            match fun {
                Ok(fun) => {
                    self.collect_function(&fun, source, inline_origins);
                }
                Err(e) => {
                    error!("Function collection: {:?}", e);
                }
            }
        }

        Ok(())
    }

    // This runs after collect_functions.
    fn collect_publics(&mut self, o: &Object) {
        for sym in o.symbols() {
            if self.syms.is_inside_symbol(sym.address as u32) {
                continue;
            }

            let parsed_win_name = if self.platform == Platform::Win {
                sym.name().map(ParsedWinFuncName::parse_unknown)
            } else {
                None
            };

            match self.syms.entry(sym.address as u32) {
                btree_map::Entry::Occupied(mut e) => {
                    let sym = e.get_mut();
                    if sym.is_public {
                        sym.is_multiple = true;
                    } else if let Some(parsed_win_name) = parsed_win_name {
                        // If we have both a symbol and a function at the same address, the function
                        // may not have parameters but the symbol's mangled name might.
                        if !sym.name.contains('(') && parsed_win_name.name.starts_with('?') {
                            // Get the name from the symbol.
                            sym.name = Self::demangle_str(&parsed_win_name.name);
                        }
                        if let Some(size) = parsed_win_name.param_size {
                            // Get the parameter size from the symbol.
                            sym.parameter_size = size;
                        }
                    }
                }
                btree_map::Entry::Vacant(e) => {
                    let sym_name = match (&parsed_win_name, sym.name) {
                        (Some(name), _) => Self::demangle_str(&name.name),
                        (None, Some(name)) => Self::demangle_str(&name),
                        _ => "<name omitted>".to_string(),
                    };
                    let parameter_size = parsed_win_name
                        .and_then(|n| n.param_size)
                        .unwrap_or_default();
                    e.insert(ElfSymbol {
                        name: sym_name,
                        is_public: true,
                        is_multiple: false,
                        is_synthetic: false,
                        rva: sym.address as u32,
                        len: sym.size as u32,
                        parameter_size,
                        source: Lines::default(),
                    });
                }
            }
        }
    }
}

fn get_stack_info(pdb: Option<&Object>, pe: Option<&Object>) -> String {
    let mut buf = Vec::new();
    let mut cfi_writer = AsciiCfiWriter::new(&mut buf);

    match (pdb, pe) {
        (_, Some(pe)) if pe.has_unwind_info() => {
            cfi_writer.process(pe).unwrap();
        }
        (Some(pdb), _) if pdb.has_unwind_info() => {
            cfi_writer.process(pdb).unwrap();
        }
        _ => {}
    }

    String::from_utf8(buf).unwrap()
}

impl ElfInfo {
    pub(crate) fn new(
        buf: &[u8],
        file_name: &str,
        platform: Platform,
        mapping: Option<Arc<PathMappings>>,
        collect_inlines: bool,
    ) -> common::Result<Self> {
        let o = Object::parse(buf)?;
        Self::from_object(
            &o,
            file_name,
            None,
            None,
            platform,
            mapping,
            collect_inlines,
        )
    }

    pub fn from_object(
        main_object: &Object,
        main_file_name: &str,
        pe_object: Option<&Object>,
        pe_file_name: Option<&str>,
        platform: Platform,
        mapping: Option<Arc<PathMappings>>,
        collect_inlines: bool,
    ) -> common::Result<Self> {
        let mut collector = Collector {
            platform,
            collect_inlines,
            syms: ElfSymbols::default(),
        };

        let ds = main_object.debug_session()?;
        let mut source = SourceFiles::new(mapping, platform);
        let mut inline_origins = InlineOrigins::default();
        let debug_id = format!("{}", main_object.debug_id().breakpad());
        let code_id = pe_object
            .and_then(|o| o.code_id())
            .or_else(|| main_object.code_id())
            .map(|c| c.as_str().to_string().to_uppercase());
        let cpu = main_object.arch().name();
        let bin_type = if main_object.has_debug_info() {
            Type::DebugInfo
        } else {
            Type::Stripped
        };

        collector.collect_functions(&ds, &mut source, &mut inline_origins)?;
        collector.collect_publics(main_object);

        let stack = get_stack_info(Some(main_object), pe_object);
        let symbols = crate::linux::symbol::add_executable_section_symbols(
            collector.syms,
            main_file_name,
            main_object,
        );

        let file_name = match (&main_object, &pe_file_name) {
            (Object::Elf(elf), _) => elf.name().unwrap_or(main_file_name),
            (Object::MachO(macho), _) => macho.name().unwrap_or(main_file_name),
            _ => main_file_name,
        };

        Ok(Self {
            symbols,
            files: source.get_mapping(),
            inline_origins: inline_origins.get_list(),
            file_name: Self::file_name_only(file_name).to_string(),
            pe_name: pe_file_name.map(ToOwned::to_owned),
            cpu,
            debug_id,
            code_id,
            stack,
            bin_type,
            platform,
        })
    }

    fn file_name_only(file_name: &str) -> &str {
        file_name.rsplit('/').next().unwrap_or(file_name)
    }
}

impl Mergeable for ElfInfo {
    fn merge(left: ElfInfo, right: ElfInfo) -> common::Result<ElfInfo> {
        anyhow::ensure!(
            left.debug_id == right.debug_id,
            "The files don't have the same debug id: {} and {}",
            left.debug_id,
            right.debug_id
        );

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
        let file_remapping = left.files.merge(&mut right.files);
        let inline_origin_remapping =
            merge_inline_origins(&mut left.inline_origins, right.inline_origins);

        for (addr, sym) in right.symbols.iter_mut() {
            if sym.is_public {
                // No line info so just put the sym in the map
                if left.symbols.is_inside_symbol(*addr) {
                    continue;
                }

                match left.symbols.entry(*addr) {
                    btree_map::Entry::Occupied(mut e) => {
                        if sym.is_synthetic {
                            // Do not replace an existing symbol with a synthetic one
                            continue;
                        }

                        if e.get().is_synthetic {
                            // Always replace a synthetic symbol
                            e.insert(sym.clone());
                        } else if e.get().name != sym.name {
                            // We already have one so just discard this one
                            e.get_mut().is_multiple = true;
                        }
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
                        sym.remap_lines(file_remapping.as_deref());
                        sym.remap_inlines(file_remapping.as_deref(), &inline_origin_remapping);
                        std::mem::swap(a_sym, sym);
                    }
                    a_sym.is_multiple = true;
                }
                btree_map::Entry::Vacant(e) => {
                    sym.remap_lines(file_remapping.as_deref());
                    sym.remap_inlines(file_remapping.as_deref(), &inline_origin_remapping);
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

    fn has_stack(&self) -> bool {
        !self.stack.is_empty()
    }
}
