// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use symbolic::debuginfo::Object;

use crate::common;
use crate::mapping::PathMappings;
use crate::object_info::ObjectInfo;
use crate::platform::Platform;

impl ObjectInfo {
    pub fn from_elf(
        buf: &[u8],
        file_name: &str,
        platform: Platform,
        mapping: Option<Arc<PathMappings>>,
        collect_inlines: bool,
    ) -> common::Result<Self> {
        let o = Object::parse(buf)?;
        Self::from_object(
            &o,
            file_name,
            None,
            None,
            platform,
            mapping,
            collect_inlines,
        )
    }
}
