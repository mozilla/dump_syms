// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::result;

#[derive(Debug)]
pub enum DumpSymError {
    PdbError(Error),
    IOError(&'static str),
}

pub type Result<T> = result::Result<T, DumpSymError>;

impl From<Error> for DumpSymError {
    fn from(e: Error) -> Self {
        DumpSymError::PdbError(e)
    }
}

impl Display for DumpSymError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        match *self {
            DumpSymError::IOError(s) => write!(f, "{}", s),
            _ => Debug::fmt(self, f),
        }
    }
}
