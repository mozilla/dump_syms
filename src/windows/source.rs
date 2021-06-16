// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use hashbrown::{hash_map, HashMap};
use log::error;
use pdb::{
    AddressMap, FallibleIterator, FileIndex, LineInfo, LineProgram, PdbInternalSectionOffset,
    Result, Source, StringRef, StringTable, PDB,
};
use std::collections::BTreeMap;
use std::fs;
use std::ops::Bound::{Excluded, Included};
use std::path::PathBuf;
use std::sync::Arc;

use crate::line::Lines;
use crate::mapping::PathMappings;
use crate::utils;

type RefToIds = HashMap<StringRef, u32>;

pub(super) struct SourceLineCollector<'a, 's> {
    address_map: &'a AddressMap<'s>,
    source_files: &'a SourceFiles<'s>,
    lines: BTreeMap<(u16, u32), LineInfo>,
    line_program: LineProgram<'a>,
}

impl<'a, 's> SourceLineCollector<'a, 's> {
    pub(super) fn new(
        address_map: &'a AddressMap<'s>,
        source_files: &'a SourceFiles<'s>,
        line_program: LineProgram<'a>,
    ) -> Result<Self> {
        let mut source_lines = BTreeMap::default();
        let mut lines = line_program.lines();

        // Some symbols corresponding to assembly code don't necessarly start at the correct offset
        // in LineProgram (e.g. the executable code is at address 0xf00 and source starts at 0xee0).
        // And the same for symbol length.
        // So finally we get all the lines by internal offset
        // and just get the ones which are in corresponding range ([start, start+len[)
        while let Some(line) = lines.next()? {
            let offset = line.offset;
            source_lines.insert((offset.section, offset.offset), line);
        }

        Ok(Self {
            address_map,
            source_files,
            lines: source_lines,
            line_program,
        })
    }

    pub(super) fn collect_source_lines(&self, offset: PdbInternalSectionOffset, len: u32) -> Lines {
        let mut source_lines = Lines::new();
        if self.lines.is_empty() {
            return source_lines;
        }

        let start = (offset.section, offset.offset);
        let end = (offset.section, offset.offset + len);
        let mut last_file_index = FileIndex(std::u32::MAX);
        let mut last_file_id = 0;

        for (_, line) in self.lines.range((Included(&start), Excluded(&end))) {
            let rva = line.offset.to_internal_rva(self.address_map).unwrap();
            if last_file_index != line.file_index {
                let file = self.line_program.get_file_info(line.file_index).unwrap();
                last_file_index = line.file_index;
                last_file_id = self.source_files.get_id(file.name);
            }
            source_lines.add_line(rva.0, line.line_start, last_file_id);
        }

        source_lines
    }
}

#[derive(Debug)]
pub(super) struct SourceFiles<'a> {
    string_table: Option<StringTable<'a>>,
    ref_to_id: RefToIds,
    id_to_ref: Vec<StringRef>,
    mapping: Option<Arc<PathMappings>>,
}

impl<'a> SourceFiles<'a> {
    pub(super) fn new<S: 'a + Source<'a>>(
        pdb: &mut PDB<'a, S>,
        mapping: Option<Arc<PathMappings>>,
    ) -> Result<Self> {
        // The string table may be empty: not a problem
        let string_table = match pdb.string_table() {
            Ok(st) => st,
            _ => {
                return Ok(Self {
                    string_table: None,
                    ref_to_id: RefToIds::default(),
                    id_to_ref: Vec::new(),
                    mapping: None,
                })
            }
        };

        let dbi = pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        let mut ref_to_id = RefToIds::default();
        let mut id_to_ref = Vec::new();
        let mut id = 0;

        // Get all source files and generate an unique id for each one.
        // According to the docs: https://docs.rs/pdb/0.5.0/pdb/struct.PDB.html#method.string_table
        // the table contains deduplicated strings so each source file must have an unique StringRef.
        while let Some(module) = modules.next()? {
            let module_info = match pdb.module_info(&module)? {
                Some(info) => info,
                _ => continue,
            };

            let mut files = module_info.line_program()?.files();
            while let Some(file) = files.next()? {
                match ref_to_id.entry(file.name) {
                    hash_map::Entry::Occupied(_) => {}
                    hash_map::Entry::Vacant(e) => {
                        e.insert(id);
                        id_to_ref.push(file.name);
                        id += 1;
                    }
                }
            }
        }

        Ok(Self {
            string_table: Some(string_table),
            ref_to_id,
            id_to_ref,
            mapping,
        })
    }

    pub(super) fn get_id(&self, file_ref: StringRef) -> u32 {
        *self.ref_to_id.get(&file_ref).unwrap()
    }

    fn map(&self, file: String) -> String {
        let path = PathBuf::from(&file);

        let path = if cfg!(windows) {
            // No need to try to canonicalize a windows path on a unix OS
            if let Ok(path) = fs::canonicalize(&path) {
                path
            } else {
                utils::normalize_path(&path)
            }
        } else {
            utils::normalize_path(&path)
        };

        let new_path = if let Some(mapping) = self.mapping.as_ref() {
            match mapping.map(&path) {
                Ok(p) => p,
                Err(e) => {
                    error!("Mapping error: {}", e);
                    None
                }
            }
        } else {
            None
        };
        new_path.unwrap_or(file)
    }

    pub(super) fn get_mapping(&self) -> Vec<String> {
        if let Some(string_table) = self.string_table.as_ref() {
            self.id_to_ref
                .iter()
                .filter_map(|file_ref| string_table.get(*file_ref).ok())
                .map(|s| s.to_string().into_owned())
                .map(|s| self.map(s))
                .collect()
        } else {
            Vec::new()
        }
    }
}
