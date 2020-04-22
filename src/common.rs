// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::error;
use std::io::Write;
use std::result;

type Error = Box<dyn error::Error>;
pub type Result<T> = result::Result<T, Error>;

pub(crate) trait Dumpable {
    fn dump<W: Write>(&self, writer: W) -> Result<()>;
    fn get_name(&self) -> &str;
    fn get_debug_id(&self) -> &str;
}
