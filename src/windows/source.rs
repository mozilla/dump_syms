// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use fxhash::FxHashMap;
use pdb::{
    AddressMap, FallibleIterator, FileIndex, LineInfo, LineProgram, PdbInternalSectionOffset,
    Result, Source, StringRef, StringTable, PDB,
};
use std::collections::{hash_map, BTreeMap};
use std::io::Write;
use std::ops::Bound::{Excluded, Included};

use super::line::Lines;

type RefToIds = FxHashMap<StringRef, u32>;

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

    pub(super) fn has_lines(&self) -> bool {
        !self.lines.is_empty()
    }

    pub(super) fn collect_source_lines(
        &self,
        offset: PdbInternalSectionOffset,
        len: u32,
    ) -> Result<Lines> {
        let mut source_lines = Lines::new();
        if self.lines.is_empty() {
            return Ok(source_lines);
        }

        let start = (offset.section, offset.offset);
        let end = (offset.section, offset.offset + len);
        let mut last_file_index = FileIndex(std::u32::MAX);
        let mut last_file_id = 0;

        for (_, line) in self.lines.range((Included(&start), Excluded(&end))) {
            let rva = line.offset.to_internal_rva(&self.address_map).unwrap();
            if last_file_index != line.file_index {
                let file = self.line_program.get_file_info(line.file_index).unwrap();
                last_file_index = line.file_index;
                last_file_id = self.source_files.get_id(file.name);
            }
            source_lines.add_line(rva.0, line.line_start, last_file_id);
        }

        Ok(source_lines)
    }
}

#[derive(Debug)]
pub(super) struct SourceFiles<'a> {
    string_table: StringTable<'a>,
    ref_to_id: RefToIds,
    id_to_ref: Vec<StringRef>,
}

impl<'a> SourceFiles<'a> {
    pub(super) fn new<S: 'a + Source<'a>>(pdb: &mut PDB<'a, S>) -> Result<Self> {
        let string_table = pdb.string_table()?;
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
            string_table,
            ref_to_id,
            id_to_ref,
        })
    }

    pub(super) fn get_id(&self, file_ref: StringRef) -> u32 {
        *self.ref_to_id.get(&file_ref).unwrap()
    }

    pub(super) fn dump<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for (n, file_ref) in self.id_to_ref.iter().enumerate() {
            if let Ok(file_name) = self.string_table.get(*file_ref) {
                writeln!(writer, "FILE {} {}", n, file_name.to_string())?;
            } else {
                warn!(
                    "Impossible to get file (id={}) for string ref {}",
                    n, file_ref
                );
                writeln!(writer, "FILE {} <erroneous file name>", n)?;
            }
        }
        Ok(())
    }
}
