// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::error;
use std::io::Write;
use std::result;

type Error = Box<dyn error::Error + std::marker::Send + std::marker::Sync>;
pub type Result<T> = result::Result<T, Error>;

pub(crate) enum FileType {
    Pdb,
    Pe,
    Elf,
    Unknown,
}

impl FileType {
    pub(crate) fn from_buf(buf: &[u8]) -> Self {
        if buf.starts_with(b"Microsoft C/C++") {
            Self::Pdb
        } else if buf.starts_with(b"\x4d\x5a") {
            Self::Pe
        } else if buf.starts_with(b"\x7fELF") {
            Self::Elf
        } else {
            Self::Unknown
        }
    }
}

pub(crate) trait Dumpable {
    fn dump<W: Write>(&self, writer: W) -> Result<()>;
    fn get_name(&self) -> &str;
    fn get_debug_id(&self) -> &str;
}

pub(crate) trait LineFinalizer<M> {
    fn finalize(&mut self, sym_rva: u32, sym_len: u32, map: &M);
}
