// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{Display, Formatter};
use std::io::Write;
use std::sync::Arc;
use symbolic::common::Arch;
use symbolic::debuginfo::Archive;

use crate::common::{self, Dumpable, Mergeable};
use crate::linux::elf::{ElfInfo, Platform};
use crate::mapping::PathMappings;

#[derive(Debug)]
pub struct MachoInfo {
    elf: ElfInfo,
}

impl Display for MachoInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.elf)
    }
}

impl MachoInfo {
    pub fn new(
        buf: &[u8],
        file_name: &str,
        arch: Arch,
        mapping: Option<Arc<PathMappings>>,
        collect_inlines: bool,
    ) -> common::Result<Self> {
        // Fat files may contain several objects for different architectures
        // So if there is only one object, then we don't care about the arch (as argument)
        // and if several then we use arch (by default it's compile-time arch).
        let archive = Archive::parse(buf)?;
        let object = if archive.object_count() == 1 {
            archive.object_by_index(0).unwrap()
        } else {
            archive
                .objects()
                .filter_map(|o| o.ok())
                .find(|o| o.arch() == arch)
        };

        if let Some(object) = object {
            Ok(Self {
                elf: ElfInfo::from_object(
                    &object,
                    file_name,
                    Platform::Mac,
                    mapping,
                    collect_inlines,
                )?,
            })
        } else {
            anyhow::bail!(
                "Cannot find a valid object for architecture {} in file {}",
                arch.name(),
                file_name
            );
        }
    }

    /// Print on screen the cpu arch for the different objects present in the fat file
    pub fn print_architectures(buf: &[u8], file_name: String) -> common::Result<()> {
        let archive = Archive::parse(buf)?;
        let archs = archive
            .objects()
            .map(|o| o.unwrap().arch().name())
            .collect::<Vec<_>>();
        println!(
            "{} contains the following architecture{}:",
            file_name,
            if archs.len() == 1 { "" } else { "s" }
        );
        println!("{}", archs.join(", "));

        Ok(())
    }
}

impl Mergeable for MachoInfo {
    fn merge(left: MachoInfo, right: MachoInfo) -> common::Result<MachoInfo> {
        Ok(MachoInfo {
            elf: ElfInfo::merge(left.elf, right.elf)?,
        })
    }
}

impl Dumpable for MachoInfo {
    fn dump<W: Write>(&self, mut writer: W) -> common::Result<()> {
        write!(writer, "{}", self.elf)?;
        Ok(())
    }

    fn get_debug_id(&self) -> &str {
        self.elf.get_debug_id()
    }

    fn get_name(&self) -> &str {
        self.elf.get_name()
    }

    fn has_stack(&self) -> bool {
        self.elf.has_stack()
    }
}
