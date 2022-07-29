// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use symbolic::common::Arch;
use symbolic::debuginfo::Archive;

use crate::common;
use crate::mapping::PathMappings;
use crate::object_info::ObjectInfo;
use crate::platform::Platform;

impl ObjectInfo {
    pub fn from_macho(
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
            ObjectInfo::from_object(
                &object,
                file_name,
                None,
                None,
                Platform::Mac,
                mapping,
                collect_inlines,
            )
        } else {
            anyhow::bail!(
                "Cannot find a valid object for architecture {} in file {}",
                arch.name(),
                file_name
            );
        }
    }
}

/// Print on screen the cpu arch for the different objects present in the fat file
pub fn print_macho_architectures(buf: &[u8], file_name: String) -> common::Result<()> {
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
