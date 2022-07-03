// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::common::LineFinalizer;
use crate::line::{Line, Lines};
use pdb::{AddressMap, PdbInternalRva};
use pdb_addr2line::pdb;

impl LineFinalizer<AddressMap<'_>> for Lines {
    fn finalize(&mut self, sym_rva: u32, sym_len: u32, address_map: &AddressMap) {
        self.compute_len(sym_rva, sym_len);

        // the rva is the internal rva (needed to compute the length)
        // So replace them (and eventually split lines) by the rva in the binary
        let mut to_insert = Vec::new();

        // Just to check that the lines are ordered according to their rva
        let mut is_sorted = true;
        let mut last_rva = 0;

        for (i, line) in self.lines.iter_mut().enumerate() {
            let start = PdbInternalRva(line.rva);
            let end = PdbInternalRva(line.rva + line.len);

            // new_line won't be empty if and only if the range has been splitted
            let mut new_line = Vec::new();

            for (j, rg) in address_map.rva_ranges(start..end).enumerate() {
                if j == 0 {
                    line.rva = rg.start.0;
                    line.len = rg.end - rg.start;
                    is_sorted = is_sorted && last_rva <= line.rva;
                    last_rva = line.rva;
                } else {
                    // The range has been splitted so need to insert the new mapping
                    new_line.push(Line {
                        rva: rg.start.0,
                        len: rg.end - rg.start,
                        num: line.num,
                        file_id: line.file_id,
                    });

                    is_sorted = is_sorted && last_rva <= rg.start.0;
                    last_rva = rg.start.0;
                }
            }

            if !new_line.is_empty() {
                to_insert.push((i + 1, new_line));
            }
        }

        if !to_insert.is_empty() {
            // Using extend_from_slice requires that the Line is cloneable
            // Probably a slow path here but should be pretty rare

            let mut new_lines = Vec::new();
            let mut last = 0;
            for (i, new_line) in to_insert.iter_mut() {
                new_lines.extend_from_slice(&self.lines[last..*i]);
                new_lines.append(new_line);
                last = *i;
            }

            if last < self.lines.len() {
                new_lines.extend_from_slice(&self.lines[last..]);
            }
            let _ = std::mem::replace(&mut self.lines, new_lines);
        }

        if !is_sorted {
            self.lines.sort_by_key(|x| x.rva);
        }
    }
}
