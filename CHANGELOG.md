# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!-- next-header -->
## [Unreleased] - ReleaseDate

## [2.0.1] - 2022-10-20

### Added

- Several labels added by compilers are stripped from the symbols

### Changed

- Use the last version of the cpp_demangle crate for better results

### Fixed

- Function names are properly demangled even when inlined
- Emit an <unknown> symbol when an inline function doesn't have a name (this
  can happen with debug information that has been split with tools like dwz),
  this avoids emitting INLINE_ORIGIN directives without a name

## [2.0.0] - 2022-08-18

Major release, adds support for inlined functions in symbol files and fixes a
large number of issues.

### Added
- Emit information about inlined functions using INLINE and INLINE_ORIGIN
  directives when the `--inlines` option is specified.

### Changed
- Use the same logic to handle Windows PE/PDB and ELF files, resulting in
  better consistency across platforms
- Dummy symbols for executable sections are now generated for all architectures
- `static` is not emitted anymore in front of method names

### Fixes
- Linux absolute paths in Windows PDB files are handled correctly
- Names that were accidentally demangled twice are now handled properly
- Parameter size is now detected correctly on Windows
- Symbols matching multiple addresses are now properly marked on ELF
- The best symbol is always used when present in separate files, even when it
  doesn't appear in the first file
- Using symbol stores now works correctly on Linux and macOS too

## [1.0.1] - 2022-05-25

### Fixes

- Fixed dumping when HTTP support is disabled.

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
[Unreleased]: https://github.com/mozilla/dump_syms/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/mozilla/dump_syms/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/mozilla/dump_syms/compare/v1.0.1...v2.0.0
[1.0.1]: https://github.com/mozilla/dump_syms/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mozilla/dump_syms/compare/cab687047df228587473fbc9a33e2ff2fd2d8c2e...v1.0.0
