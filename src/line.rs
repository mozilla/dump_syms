// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Debug, Display, Formatter};

#[derive(Clone, Default)]
pub(crate) struct Line {
    // rva stands for relative virtual address
    pub(crate) rva: u32,
    // line length in the binary
    // this data isn't in the pdb so we need to infer it before dumping
    pub(crate) len: u32,
    // line number
    pub(crate) num: u32,
    // file identifier where this line is
    pub(crate) file_id: u32,
}

impl Debug for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Line {{ rva: {:x}, len: {:x}, line: {}, file_id: {} }}",
            self.rva, self.len, self.num, self.file_id
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct Lines {
    // The lines
    pub(crate) lines: Vec<Line>,
    // Each time we insert a new line we check
    // that its rva is greater than the previous one.
    // If is_sorted is false before finalizing data, we'll sort them.
    pub(crate) is_sorted: bool,
    pub(crate) last_rva: u32,
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
    pub(crate) fn new() -> Self {
        Self {
            lines: Vec::new(),
            is_sorted: true,
            last_rva: 0,
        }
    }

    pub(crate) fn add_line(&mut self, rva: u32, num: u32, file_id: u32) {
        self.lines.push(Line {
            rva,
            num,
            len: 0,
            file_id,
        });

        // There are no guarantee that the rva are sorted
        // So we check each time we push an element and we'll sort if it's required
        self.is_sorted = self.is_sorted && self.last_rva <= rva;
        self.last_rva = rva;
    }

    pub(crate) fn compute_len(&mut self, sym_rva: u32, sym_len: u32) {
        // The length (in the binary) of the line is not in the pdb but we can infer it:
        // RVA     LINE NUMBER
        // 0x0001  10  <= the size of line 10 is 0x000B - 0x0001
        // 0x000B  11
        // ...
        // 0x002A  15 <= the size of line 15 is sym length - (0x002A - 0x0001)

        if self.lines.is_empty() {
            return;
        }

        // If the rva aren't ordered we need to sort the lines
        if !self.is_sorted {
            self.lines.sort_by_key(|x| x.rva);
        }

        let lens: Vec<u32> = self.lines.windows(2).map(|w| w[1].rva - w[0].rva).collect();

        // Cannot fail since self.lines isn't empty
        let (last, lines) = self.lines.split_last_mut().unwrap();

        lines
            .iter_mut()
            .zip(lens.iter())
            .for_each(|(line, len)| line.len = *len);

        last.len = sym_len - (last.rva - sym_rva);
    }

    fn find_lines_for_range(&self, rva: u32, len: u32) -> Lines {
        Lines {
            lines: self
                .lines
                .iter()
                .filter_map(|line| {
                    if rva <= line.rva && line.rva + line.len <= rva + len {
                        Some(line.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            is_sorted: true,
            last_rva: 0,
        }
    }

    pub(crate) fn retain(&self, rva: u32, len: u32) -> Option<Lines> {
        // A symbol space can be split in several chunks
        // so we need to retain the lines which are in the different chunks
        if self.lines.is_empty() {
            return None;
        }
        if rva == self.lines.first().unwrap().rva {
            let last = self.lines.last().unwrap();
            if last.rva + last.len == rva + len {
                return None;
            }
        }

        Some(self.find_lines_for_range(rva, len))
    }
}
