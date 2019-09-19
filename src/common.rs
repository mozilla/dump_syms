// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use pdb::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::result;
use symbolic_minidump::cfi;

#[derive(Debug)]
pub enum DumpSymError {
    PdbError(Error),
    Message(&'static str),
    IOError(io::Error),
    CfiError(cfi::CfiError),
}

pub type Result<T> = result::Result<T, DumpSymError>;

impl From<Error> for DumpSymError {
    fn from(e: Error) -> Self {
        DumpSymError::PdbError(e)
    }
}

impl From<io::Error> for DumpSymError {
    fn from(e: io::Error) -> Self {
        DumpSymError::IOError(e)
    }
}

impl From<cfi::CfiError> for DumpSymError {
    fn from(e: cfi::CfiError) -> Self {
        DumpSymError::CfiError(e)
    }
}

impl Display for DumpSymError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        match *self {
            DumpSymError::Message(s) => writeln!(f, "{}", s),
            _ => Debug::fmt(self, f),
        }
    }
}
