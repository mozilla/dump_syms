// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::{AddressMap, PdbInternalRva};
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug)]
pub struct Line {
    pub rva: u32,
    pub num: u32,
    pub len: u32,
    pub file_id: u32,
}

#[derive(Debug, Default)]
pub struct Lines {
    pub lines: Vec<Line>,
    pub is_sorted: bool,
}

impl Display for Lines {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for line in self.lines.iter() {
            writeln!(
                f,
                "{:x} {:x} {} {}",
                line.rva, line.len, line.num, line.file_id
            )?;
        }
        Ok(())
    }
}

impl Lines {
    fn compute_len(&mut self, sym_len: u32) {
        // The length (in the binary) of the line is not in the pdb but we can infer it:
        // RVA     LINE NUMBER
        // 0x0001  10  <= the size of line 10 is 0x000B - 0x0001
        // 0x000B  11
        // ...
        // 0x002A  15 <= the size of line 15 is sym length - (0x002A - 0x0001)

        if self.lines.is_empty() {
            return;
        }

        if !self.is_sorted {
            self.lines.sort_by_key(|x| x.rva);
        }

        let n_lines = self.lines.len();

        unsafe {
            let first_rva = if n_lines > 1 {
                // The 2 next lines are valid because n_lines > 1
                let next_rva = self.lines.get_unchecked(1).rva;
                let line = self.lines.get_unchecked_mut(0);

                let first_rva = line.rva;
                line.len = next_rva - first_rva;

                for i in 1..n_lines - 1 {
                    // Valid because i + 1 < n_lines - 1 + 1
                    let next_rva = self.lines.get_unchecked(i + 1).rva;
                    let line = self.lines.get_unchecked_mut(i);
                    line.len = next_rva - line.rva;
                }

                first_rva
            } else {
                // Valid because self.lines is not empty
                self.lines.get_unchecked(0).rva
            };

            // Valid because self.lines is not empty
            let last = self.lines.get_unchecked_mut(n_lines - 1);
            last.len = sym_len - (last.rva - first_rva);
        }
    }

    fn compute_rva(&mut self, address_map: &AddressMap) {
        // the rva is the internal rva (needed to compute the length)
        // So replace them (and eventually split lines) by the rva in the binary
        let mut to_insert = Vec::new();

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
                        num: line.num,
                        len: rg.end - rg.start,
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
            std::mem::replace(&mut self.lines, new_lines);
        }

        if !is_sorted {
            self.lines.sort_by_key(|x| x.rva);
        }
    }

    pub fn finalize(&mut self, sym_len: u32, address_map: &AddressMap) {
        self.compute_len(sym_len);
        self.compute_rva(address_map);
    }
}
