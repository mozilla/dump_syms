// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Mac,
    Win,
}

impl Platform {
    pub fn is_target(&self) -> bool {
        match self {
            Platform::Linux => cfg!(target_os = "linux"),
            Platform::Mac => cfg!(target_os = "macos"),
            Platform::Win => cfg!(target_os = "windows"),
        }
    }

    pub fn is_absolute_path(&self, path: &str) -> bool {
        match self {
            Platform::Linux | Platform::Mac => path.starts_with('/'),
            Platform::Win => {
                // Detect "C:\..." and "C:/...".
                let first_fragment = match path.find(&['/', '\\']) {
                    Some(first_fragment_len) => &path[..first_fragment_len],
                    None => path,
                };
                first_fragment.ends_with(':')
            }
        }
    }

    pub fn join_paths(&self, left: &str, right: &str) -> String {
        match self {
            Platform::Linux | Platform::Mac => {
                let left = left.trim_end_matches('/');
                let right = right.trim_start_matches('/');
                format!("{}/{}", left, right)
            }
            Platform::Win => {
                let left = left.trim_end_matches('\\');
                let right = right.trim_start_matches('\\');
                format!("{}\\{}", left, right)
            }
        }
    }
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let p = match self {
            Self::Linux => "Linux",
            Self::Mac => "Mac",
            Self::Win => "windows",
        };
        write!(f, "{}", p)
    }
}
