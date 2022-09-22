// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use log::error;
use std::collections::btree_map;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::sync::Arc;
use symbolic::cfi::AsciiCfiWriter;
use symbolic::debuginfo::Object;

use super::source::{SourceFiles, SourceMap};
use super::symbol::{ContainsSymbol, Symbols};
use crate::collector::Collector;
use crate::common;
use crate::inline_origins::{merge_inline_origins, InlineOrigins};
use crate::mapping::PathMappings;
use crate::platform::Platform;

#[derive(Debug, PartialEq, Eq)]
pub enum Type {
    Stripped,
    DebugInfo,
}

#[derive(Debug)]
pub struct ObjectInfo {
    symbols: Symbols,
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

impl Display for ObjectInfo {
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
            let function_name = if function_name.is_empty() {
                "<name omitted>"
            } else {
                function_name
            };
            writeln!(f, "INLINE_ORIGIN {} {}", n, function_name)?;
        }

        for (_, sym) in self.symbols.iter() {
            write!(f, "{}", sym)?;
        }

        write!(f, "{}", self.stack)?;

        Ok(())
    }
}

fn get_stack_info(pdb: Option<&Object>, pe: Option<&Object>) -> String {
    let mut buf = Vec::new();
    let mut cfi_writer = AsciiCfiWriter::new(&mut buf);

    let result = match (pdb, pe) {
        (_, Some(pe)) if pe.has_unwind_info() => cfi_writer.process(pe),
        (Some(pdb), _) if pdb.has_unwind_info() => cfi_writer.process(pdb),
        _ => Ok(()),
    };

    if let Err(e) = result {
        error!("CFI: {:?}", e);
    }

    String::from_utf8(buf).unwrap()
}

impl ObjectInfo {
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
            syms: Symbols::default(),
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

        if let Object::Pe(pe) = &main_object {
            if let Some(exception_data) = pe.exception_data() {
                collector.collect_placeholder_functions(
                    exception_data,
                    pe_file_name.unwrap_or(main_file_name),
                );
            }
        }

        collector.collect_publics(main_object);

        let stack = get_stack_info(Some(main_object), pe_object);
        let symbols = match platform {
            Platform::Linux | Platform::Mac => super::symbol::add_executable_section_symbols(
                collector.syms,
                main_file_name,
                main_object,
            ),
            Platform::Win => super::symbol::append_dummy_symbol(
                collector.syms,
                pe_file_name.unwrap_or(main_file_name),
            ),
        };

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

    pub fn merge(left: ObjectInfo, right: ObjectInfo) -> common::Result<ObjectInfo> {
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

    pub fn dump<W: Write>(&self, mut writer: W) -> common::Result<()> {
        write!(writer, "{}", self)?;
        Ok(())
    }

    pub fn get_debug_id(&self) -> &str {
        &self.debug_id
    }

    pub fn get_name(&self) -> &str {
        &self.file_name
    }

    pub fn has_stack(&self) -> bool {
        !self.stack.is_empty()
    }
}
