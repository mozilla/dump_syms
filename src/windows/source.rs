// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::{
    AddressMap, FallibleIterator, LineProgram, PdbInternalSectionOffset, Result, Source, StringRef,
    StringTable, PDB,
};
use std::collections::{hash_map, HashMap};
use std::io::Write;

use super::line::Lines;

pub(super) struct SourceLineCollector<'a, 's> {
    address_map: &'a AddressMap<'s>,
    source_files: &'a SourceFiles<'s>,
    line_program: LineProgram<'a>,
}

impl<'a, 's> SourceLineCollector<'a, 's> {
    pub(super) fn new(
        address_map: &'a AddressMap<'s>,
        source_files: &'a SourceFiles<'s>,
        line_program: LineProgram<'a>,
    ) -> Self {
        Self {
            address_map,
            source_files,
            line_program,
        }
    }

    pub(super) fn collect_source_lines(&self, offset: PdbInternalSectionOffset) -> Result<Lines> {
        // lines_at_offset is pretty slow (linear)
        let mut lines = self.line_program.lines_at_offset(offset);

        let mut source_lines = Lines::new();

        // Get the first element just to have file_index, file_id
        // which are likely the same for all lines
        let (mut last_file_index, mut last_file_id) = if let Some(line) = lines.next()? {
            let rva = line.offset.to_internal_rva(&self.address_map).unwrap();
            let file = self.line_program.get_file_info(line.file_index)?;
            let file_id = self.source_files.get_id(file.name);

            source_lines.add_line(rva.0, line.line_start, file_id);
            (line.file_index.0, file_id)
        } else {
            return Ok(source_lines);
        };

        while let Some(line) = lines.next()? {
            let rva = line.offset.to_internal_rva(&self.address_map).unwrap();

            // The file_id is very likely always the same
            let file_id = if line.file_index.0 == last_file_index {
                last_file_id
            } else {
                last_file_index = line.file_index.0;
                let file = self.line_program.get_file_info(line.file_index)?;
                last_file_id = self.source_files.get_id(file.name);
                last_file_id
            };
            source_lines.add_line(rva.0, line.line_start, file_id);
        }

        Ok(source_lines)
    }
}

#[derive(Debug)]
pub(super) struct SourceFiles<'a> {
    string_table: StringTable<'a>,
    ref_to_id: HashMap<StringRef, u32>,
    id_to_ref: Vec<StringRef>,
}

impl<'a> SourceFiles<'a> {
    pub(super) fn new<S: 'a + Source<'a>>(pdb: &mut PDB<'a, S>) -> Result<Self> {
        let string_table = pdb.string_table()?;
        let dbi = pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        let mut ref_to_id = HashMap::default();
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
                // string_ref is an u32 corresponding to the offset in the string table
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
