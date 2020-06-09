// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use goblin::{self, Hint};
use std::convert::TryInto;
use std::env::consts::ARCH;
use std::error;
use std::io::Write;
use std::result;
use symbolic_common::Arch;

type Error = Box<dyn error::Error + std::marker::Send + std::marker::Sync>;
pub type Result<T> = result::Result<T, Error>;

pub(crate) enum FileType {
    Pdb,
    Pe,
    Elf,
    Macho,
    Unknown,
}

impl FileType {
    pub(crate) fn from_buf(buf: &[u8]) -> Self {
        if buf.starts_with(b"Microsoft C/C++") {
            Self::Pdb
        } else if buf.len() >= 16 {
            let start: &[u8; 16] = &buf[0..16].try_into().unwrap();
            if let Ok(hint) = goblin::peek_bytes(start) {
                match hint {
                    Hint::Elf(_) => Self::Elf,
                    Hint::Mach(_) | Hint::MachFat(_) => Self::Macho,
                    Hint::PE => Self::Pe,
                    _ => Self::Unknown,
                }
            } else {
                Self::Unknown
            }
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

pub(crate) trait Mergeable {
    fn merge(left: Self, right: Self) -> Result<Self>
    where
        Self: Sized;
}

pub(crate) trait LineFinalizer<M> {
    fn finalize(&mut self, sym_rva: u32, sym_len: u32, map: &M);
}

pub(crate) fn get_compile_time_arch() -> &'static str {
    use Arch::*;

    match ARCH {
        "x86" => X86,
        "x86_64" => Amd64,
        "arm" => Arm,
        "aarch64" => Arm64,
        "mips" => Mips,
        "mips64" => Mips64,
        "powerpc" => Ppc,
        "powerpc64" => Ppc64,
        _ => Unknown,
    }
    .name()
}
