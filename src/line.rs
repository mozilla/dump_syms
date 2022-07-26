// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Display, Formatter},
};

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

/// Represents an inlined function call.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct InlineSite {
    /// The identifier of the function name, as an index into InlineOrigins.
    pub(crate) inline_origin_id: u32,
    /// The call depth of this call. Calls from the outer function have
    /// depth 0, calls inside an inline function of depth N have depth N + 1.
    pub(crate) call_depth: u32,
    /// The line number of the call in the parent function.
    pub(crate) call_line_number: u32,
    /// The filename of the call in the parent function.
    pub(crate) call_file_id: u32,
}

impl Debug for InlineSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InlineSite {{ inline_origin_id: {}, call_depth: {}, call_line_number: {}, call_file_id: {} }}",
            self.inline_origin_id, self.call_depth, self.call_line_number, self.call_file_id
        )
    }
}

/// Represents a contiguous slice of instructions (i.e. an rva range)
/// for an inlined function call.
#[derive(Clone, Default)]
pub(crate) struct InlineAddressRange {
    /// rva stands for relative virtual address
    pub(crate) rva: u32,
    /// Length in bytes
    pub(crate) len: u32,
}

impl Debug for InlineAddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InlineAddressRange {{ rva: {:x}, len: {:x} }}",
            self.rva, self.len
        )
    }
}

/// Information about the instructions of a single function in the binary.
///
/// This information allows mapping an instruction address to information about the
/// source code which generated this instruction, specifically to the source
/// file and line number, and to the inline stack at each address (with file + line
/// at each level of inlining).
// TODO: Consider renaming this struct to FunctionDebugInfo
#[derive(Clone, Debug, Default)]
pub struct Lines {
    /// The line records.
    ///
    /// If inline information is available, then the line records carry the file/line
    /// at the inline "leaf", i.e. at the deepest level of the inline stack at that
    /// location.
    ///
    /// If no inline information is available, then the line records are about the
    /// outermost level (i.e. they describe locations in the outer function).
    pub(crate) lines: Vec<Line>,
    /// The inline records, if available.
    pub(crate) inlines: BTreeMap<InlineSite, Vec<InlineAddressRange>>,
    // Each time we insert a new line we check
    // that its rva is greater than the previous one.
    // If are_lines_sorted is false before finalizing data, we'll sort them.
    pub(crate) are_lines_sorted: bool,
    /// The rva of the most-recently-added line record, for sortedness detection.
    pub(crate) last_line_rva: u32,
}

fn write_inline_record(
    site: &InlineSite,
    ranges: &[InlineAddressRange],
    f: &mut Formatter<'_>,
) -> fmt::Result {
    // INLINE <inline_nest_level> <call_site_line> <call_site_file_id> <origin_id> [<address> <size>]+
    write!(
        f,
        "INLINE {} {} {} {}",
        site.call_depth, site.call_line_number, site.call_file_id, site.inline_origin_id,
    )?;
    for range in ranges {
        write!(f, " {:x} {:x}", range.rva, range.len)?;
    }
    writeln!(f)
}

fn write_line_record(line: &Line, f: &mut Formatter<'_>) -> fmt::Result {
    writeln!(
        f,
        "{:x} {:x} {} {}",
        line.rva, line.len, line.num, line.file_id
    )
}

impl Display for Lines {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // Write out all inline records first, and then all line records.

        // Sort the inlines by the first range's rva and by call depth.
        let mut inlines: Vec<(&_, &_)> = self.inlines.iter().collect();
        inlines.sort_by_key(|(site, ranges)| (ranges.first().unwrap().rva, site.call_depth));
        for (site, ranges) in inlines {
            write_inline_record(site, ranges, f)?;
        }

        // Write out the line records.
        for line in &self.lines {
            write_line_record(line, f)?;
        }
        Ok(())
    }
}

impl Lines {
    pub(crate) fn new() -> Self {
        Self {
            lines: Vec::new(),
            inlines: BTreeMap::new(),
            are_lines_sorted: true,
            last_line_rva: 0,
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
        self.are_lines_sorted = self.are_lines_sorted && self.last_line_rva <= rva;
        self.last_line_rva = rva;
    }

    pub(crate) fn add_inline(&mut self, site: InlineSite, address_range: InlineAddressRange) {
        self.inlines
            .entry(site)
            .or_insert_with(|| Vec::with_capacity(1))
            .push(address_range);
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

        assert!(
            self.are_lines_sorted,
            "Call ensure_order() before calling compute_len()"
        );

        let lens: Vec<u32> = self.lines.windows(2).map(|w| w[1].rva - w[0].rva).collect();

        // Cannot fail since self.lines isn't empty
        let (last, lines) = self.lines.split_last_mut().unwrap();

        lines
            .iter_mut()
            .zip(lens.iter())
            .for_each(|(line, len)| line.len = *len);

        last.len = sym_len - (last.rva - sym_rva);
    }

    /// Makes sure that `self.lines` and `self.inlines` are sorted.
    ///
    /// Must be called before invoking the `Display` implementation and
    /// before calling `compute_len`.
    pub(crate) fn ensure_order(&mut self) {
        if !self.are_lines_sorted {
            // Sort the lines.
            self.lines.sort_by_key(|x| x.rva);
            self.are_lines_sorted = true;
        }

        // Sort the address ranges of each inline site and merge adjacent ranges.
        for ranges in self.inlines.values_mut() {
            ranges.sort_by_key(|range| range.rva);
            ranges.dedup_by(|next, current| {
                if current.rva.checked_add(current.len) == Some(next.rva) {
                    current.len += next.len;
                    true
                } else {
                    false
                }
            })
        }
    }
}
