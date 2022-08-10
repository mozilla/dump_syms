// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq)]
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
                // Detect "/...", "\...", "C:\..." and "C:/...".
                let first_fragment = match path.find(&['/', '\\']) {
                    Some(first_fragment_len) => &path[..first_fragment_len],
                    None => path,
                };
                first_fragment.is_empty() || first_fragment.ends_with(':')
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
                // We need to support both Linux-style paths and Windows-style paths.
                // That's because Platform::Win is used for all PDB files, even for
                // PDB files for build that were (cross-)compiled on a Linux machine;
                // those contain Linux paths.
                let left = left.trim_end_matches(&['/', '\\']);
                let right = right.trim_start_matches(&['/', '\\']);

                // If `left` happens to be an absolute Linux-style path, use `/` as
                // the separator. This covers the PDB-on-Linux case we care about; all
                // the paths in such a PDB appear to be absolute paths.
                if left.starts_with('/') {
                    format!("{}/{}", left, right)
                } else {
                    format!("{}\\{}", left, right)
                }
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

#[cfg(test)]
mod test {
    use crate::platform::Platform;

    #[test]
    fn test_linux() {
        assert!(Platform::Linux.is_absolute_path("/home/test/filename"));
        assert!(!Platform::Linux.is_absolute_path("test/filename"));
        assert!(!Platform::Linux.is_absolute_path("../test/filename"));

        assert_eq!(
            &Platform::Linux.join_paths("/home/test/", "filename"),
            "/home/test/filename"
        );
        assert_eq!(
            &Platform::Linux.join_paths("/home/test", "filename"),
            "/home/test/filename"
        );
        assert_eq!(
            &Platform::Linux.join_paths("/home/test/", "test2/filename"),
            "/home/test/test2/filename"
        );
        assert_eq!(
            &Platform::Linux.join_paths("/home/test/", "/test2/filename"),
            "/home/test/test2/filename"
        );
        assert_eq!(
            &Platform::Linux.join_paths("/home/test", "/test2/filename"),
            "/home/test/test2/filename"
        );
    }

    #[test]
    fn test_win() {
        assert!(Platform::Win.is_absolute_path("/home/test/filename"));
        assert!(Platform::Win.is_absolute_path(r"D:\Users\test\filename"));
        assert!(Platform::Win.is_absolute_path(r"\\netshare\test\filename"));
        assert!(Platform::Win.is_absolute_path(r"E:/Users/test/filename"));
        assert!(!Platform::Win.is_absolute_path("../test/filename"));
        assert!(!Platform::Win.is_absolute_path("test/filename"));
        assert!(!Platform::Win.is_absolute_path(r"..\test\filename"));
        assert!(!Platform::Win.is_absolute_path(r"test\filename"));

        assert_eq!(
            &Platform::Win.join_paths(r"C:\Users\test\", "filename"),
            r"C:\Users\test\filename"
        );
        assert_eq!(
            &Platform::Win.join_paths(r"C:\Users\test", r"filename"),
            r"C:\Users\test\filename"
        );
        assert_eq!(
            &Platform::Win.join_paths(r"C:\Users\test", r"test2\filename"),
            r"C:\Users\test\test2\filename"
        );
        assert_eq!(
            &Platform::Win.join_paths(r"C:\Users\test", r"\test2\filename"),
            r"C:\Users\test\test2\filename"
        );
        assert_eq!(
            &Platform::Win.join_paths(r"C:\Users\test", r"\test2\filename"),
            r"C:\Users\test\test2\filename"
        );

        // Make sure that if the left side is an absolute Linux path, / is used as the separator.
        // This is needed to recover the correct paths from PDB files for Windows builds that
        // were compiled on a Linux machine; those PDB files contain Linux paths.
        assert_eq!(
            &Platform::Win.join_paths("/home/test/", "filename"),
            "/home/test/filename"
        );
        assert_eq!(
            &Platform::Win.join_paths("/home/test", "filename"),
            "/home/test/filename"
        );
        assert_eq!(
            &Platform::Win.join_paths("/home/test/", "test2/filename"),
            "/home/test/test2/filename"
        );
        assert_eq!(
            &Platform::Win.join_paths("/home/test/", "/test2/filename"),
            "/home/test/test2/filename"
        );
        assert_eq!(
            &Platform::Win.join_paths("/home/test", "/test2/filename"),
            "/home/test/test2/filename"
        );
    }
}
