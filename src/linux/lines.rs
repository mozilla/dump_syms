// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::common::LineFinalizer;
use crate::line::Lines;

impl LineFinalizer<()> for Lines {
    fn finalize(&mut self, sym_rva: u32, sym_len: u32, _map: &()) {
        self.ensure_order();
        self.compute_len(sym_rva, sym_len);
    }
}
