// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use once_cell::sync::Lazy;
use regex::Regex;
use std::env::consts::ARCH;
use std::result;
use symbolic::common::{Arch, Name};
use symbolic::demangle::DemangleOptions;

pub type Result<T> = result::Result<T, anyhow::Error>;

pub fn demangle_options() -> DemangleOptions {
    DemangleOptions::complete().return_type(false)
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
    static COMPILER_NNN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"((\.(cold|constprop|llvm|localalias|lto_priv|isra|part|str)(\.[0-9]+)?)|( ?\[clone[^\]]*\] ?))+$",
        )
        .unwrap()
    });
    let fixed = COMPILER_NNN.replace(name.as_str(), "");
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

        let test_names = [
            "hello.llvm.1234567890",
            "hello.str.158.llvm.1786438672924483777",
            "hello [clone .constprop.0] [clone .isra.0] [clone .cold]",
            "hello.localalias",
            "hello.constprop.0.isra.0",
        ];

        for test_name in test_names {
            let test_name = Name::new(test_name, NameMangling::Mangled, Language::Unknown);
            assert_eq!(name, fix_symbol_name(&test_name));
        }

        // Check that we don't strip labels we don't know about
        let test_name = Name::new(
            "hello [clone foo][bar]",
            NameMangling::Mangled,
            Language::Unknown,
        );
        assert_eq!("hello [clone foo][bar]", fix_symbol_name(&test_name));
    }

    #[test]
    fn test_normalize_anonymous_namespace() {
        let name = "(anonymous namespace)";
        assert_eq!("(anonymous namespace)", normalize_anonymous_namespace(name));

        let name = "`anonymous namespace'";
        assert_eq!("(anonymous namespace)", normalize_anonymous_namespace(name));
    }
}
