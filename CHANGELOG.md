# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!-- next-header -->
## [Unreleased] - ReleaseDate

## [1.0.1] - 2022-05-25

### Fixes
* Fixed dumping when HTTP support is disabled.

## [1.0.0] - 2022-05-24

First public release on crates.io. Functional parity with Breakpad dump_syms
tools for Linux, Windows and macOS including changes in the Mozilla fork.
Much faster and providing significantly better output than the original.

Several long-standing issues with the original dump_syms logic were also fixed
including unwinding directives for certain opcodes, compact unwinding info
support on macOS, surfacing of public symbols, normalization of namespaces
across different architectures, removal of compiler-generated suffixes and
better handling of Windows types.

The crate can be used to build a stand-alone executable or as a library to
provide symbol-file generation in other tools.

<!-- next-url -->
[Unreleased]: https://github.com/mozilla/dump_syms/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/mozilla/dump_syms/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mozilla/dump_syms/compare/cab687047df228587473fbc9a33e2ff2fd2d8c2e...v1.0.0
