// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn read_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let mut file = File::open(&path).unwrap_or_else(|_| {
        panic!(
            "Unable to open the file {}",
            path.as_ref().to_str().unwrap()
        )
    });
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap_or_else(|_| {
        panic!(
            "Unable to read the file {}",
            path.as_ref().to_str().unwrap()
        )
    });

    buf
}
