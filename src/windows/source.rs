// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::{AddressMap, FallibleIterator, LineProgram, PdbInternalSectionOffset, Result};

use super::line::Lines;
use super::pdb::FileIds;

pub(super) struct SourceLineCollector<'a, 's> {
    address_map: &'a AddressMap<'s>,
    file_ids: &'a FileIds,
    line_program: LineProgram<'a>,
}

impl<'a, 's> SourceLineCollector<'a, 's> {
    pub(super) fn new(
        address_map: &'a AddressMap<'s>,
        file_ids: &'a FileIds,
        line_program: LineProgram<'a>,
    ) -> Self {
        Self {
            address_map,
            file_ids,
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
            let file_id = *self.file_ids.get(&file.name.0).unwrap();

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
                last_file_id = *self.file_ids.get(&file.name.0).unwrap();
                last_file_id
            };
            source_lines.add_line(rva.0, line.line_start, file_id);
        }

        Ok(source_lines)
    }
}
