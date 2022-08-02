# dump_syms

[![Task Status](https://community-tc.services.mozilla.com/api/github/v1/repository/mozilla/dump_syms/main/badge.svg)](https://community-tc.services.mozilla.com/api/github/v1/repository/mozilla/dump_syms/main/latest)
[![codecov](https://codecov.io/gh/calixteman/dump_syms/branch/master/graph/badge.svg)](https://codecov.io/gh/calixteman/dump_syms)

dump_syms is a command-line utility for parsing the debugging information the
compiler provides (whether as DWARF or STABS sections in an ELF file or as
stand-alone PDB files) and writing that information back out in the Breakpad
symbol file format.


# Usage

Use dump_syms:

    dump_syms [FLAGS] [OPTIONS] <filenames>...
    
for help:

    dump_syms --help


# Development

To build:

    cargo build
    
To run tests:

    cargo test
