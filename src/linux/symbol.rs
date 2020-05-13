// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use crate::line::Lines;

#[derive(Clone, Debug, Default)]
pub(super) struct ElfSymbol {
    pub name: String,
    pub is_public: bool,
    pub is_multiple: bool,
    pub rva: u32,
    pub len: u32,
    pub parameter_size: u32,
    pub source: Lines,
}

pub(super) type ElfSymbols = BTreeMap<u32, ElfSymbol>;

impl Display for ElfSymbol {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if self.is_public {
            writeln!(
                f,
                "PUBLIC {}{:x} {:x} {}",
                if self.is_multiple { "m " } else { "" },
                self.rva,
                self.parameter_size,
                self.name,
            )?;
        } else {
            writeln!(
                f,
                "FUNC {}{:x} {:x} {:x} {}",
                if self.is_multiple { "m " } else { "" },
                self.rva,
                self.len,
                self.parameter_size,
                self.name,
            )?;

            write!(f, "{}", self.source)?;
        }

        Ok(())
    }
}
