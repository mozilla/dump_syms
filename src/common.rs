// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use regex::Regex;
use std::env::consts::ARCH;
use std::result;
use symbolic::common::{Arch, Name};
use symbolic::debuginfo::{peek, FileFormat};
use symbolic::demangle::DemangleOptions;

pub type Result<T> = result::Result<T, anyhow::Error>;

pub fn demangle_options() -> DemangleOptions {
    DemangleOptions::complete().return_type(false)
}

pub enum FileType {
    Pdb,
    Pe,
    Elf,
    Macho,
    Unknown,
}

impl FileType {
    pub fn from_buf(buf: &[u8]) -> Self {
        match peek(buf, true /* check for fat binary */) {
            FileFormat::Pdb => Self::Pdb,
            FileFormat::Pe => Self::Pe,
            FileFormat::Elf => Self::Elf,
            FileFormat::MachO => Self::Macho,
            _ => Self::Unknown,
        }
    }
}

impl std::str::FromStr for FileType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.to_lowercase();
        Ok(match s.as_str() {
            "pdb" => Self::Pdb,
            "elf" => Self::Elf,
            "macho" => Self::Macho,
            _ => Self::Unknown,
        })
    }
}

pub(crate) trait LineFinalizer<M> {
    fn finalize(&mut self, sym_rva: u32, sym_len: u32, map: &M);
}

pub fn get_compile_time_arch() -> &'static str {
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

pub(crate) fn normalize_anonymous_namespace(text: &str) -> String {
    let fixed = text.replace("`anonymous namespace'", "(anonymous namespace)");
    String::from(&fixed)
}

pub(crate) fn fix_symbol_name<'a>(name: &'a Name<'a>) -> Name<'a> {
    lazy_static::lazy_static! {
        static ref LLVM_NNN: Regex = Regex::new(r"\.llvm\.[0-9]+$").unwrap();
    }
    let fixed = LLVM_NNN.replace(name.as_str(), "");
    let fixed = normalize_anonymous_namespace(&fixed);

    Name::new(fixed, name.mangling(), name.language())
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbolic::common::{Language, NameMangling};

    #[test]
    fn test_fix_symbol_name() {
        let name = Name::new("hello", NameMangling::Mangled, Language::Unknown);
        assert_eq!(name, fix_symbol_name(&name));

        let name = Name::new(
            "hello.llvm.1234567890",
            NameMangling::Mangled,
            Language::Unknown,
        );
        assert_eq!(
            Name::new("hello", NameMangling::Mangled, Language::Unknown),
            fix_symbol_name(&name)
        );
    }

    #[test]
    fn test_normalize_anonymous_namespace() {
        let name = "(anonymous namespace)";
        assert_eq!("(anonymous namespace)", normalize_anonymous_namespace(name));

        let name = "`anonymous namespace'";
        assert_eq!("(anonymous namespace)", normalize_anonymous_namespace(name));
    }
}
