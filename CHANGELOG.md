# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!-- next-header -->

## [Unreleased] - ReleaseDate

## [2.3.6] - 2026-01-19

- Fixed an issue when generating symbols for AArch64 binaries
- Removed duplicate dependencies and yanked crates

## [2.3.5] - 2025-06-18

- Updated the symbolic crates as well as most of the other dependencies.

## [2.3.4] - 2024-09-06

### Changed

- Updated the symbolic crates and update the dependency on a yanked crate

## [2.3.3] - 2024-06-04

### Fixed

- Fixed an issue in the automation machinery that prevented a proper release
  to happen automatically on GitHub.

## [2.3.2] - 2024-06-04

### Changed

- Updated all the crate dependencies, removing some very old ones and importing
  a number of fixes along the way. One notable change is that PDB files with
  a debug filename held by an array larger than the string itself now work
  correctly instead of failing without output.

## [2.3.1] - 2024-03-11

### Fixed

- Fixes a build issue when newer versions of the dependencies are used

## [2.3.0] - 2024-03-06

### Added

- The `--extra-info` option can be used to add additional information via
  `INFO` lines at the beginning of the output file
- The `--no-generator` option can be used to prevent dump_syms from emitting
  the `INFO GENERATOR` line thus restoring the traditional Breakpad-based
  dump_syms behavior

### Changed

- Paths in MinGW executables are never canonicalized, they will be printed out
  exactly like they appear in the debug information

## [2.2.2] - 2023-09-13

### Changed

- Update the goblin crate to match the one used by symbolic and the bitflags
  crate to the next major version. This restores the ability to build the tool.

## [2.2.1] - 2023-03-13

### Changed

- Use the last version of the symbolic crates and update several other
  dependencies

## [2.2.0] - 2023-02-03

### Added

- dump_syms now supports dumping DWARF debug information in Windows PE files

### Changed

- Use the last version of symbolic (11) and various other crates

### Fixed

- Avoid underflows when infering the length of the last line in a function
- Do not emit `INLINE_ORIGIN` directives where the name is made entirely of
  whitespace, these are replaced with a `<name omitted>` symbol

## [2.1.1] - 2022-11-29

### Changed

- Use the last version of the symbolic crates and update to clap 4

### Fixed

- `INLINE_ORIGIN` names could contain line-breaks if the debuginfo contained
  them. These caused parsing the .sym file to fail so they're now stripped
  before emitting them.

## [2.1.0] - 2022-11-18

### Added

- The program version is now included in the .sym file under a `INFO GENERATOR`
  line. This line can be used to identify which version of dump_syms was used
  to produce a .sym file and will be ignored by most legacy tools.

### Changed

- Use the last version of the symbolic, goblin and cpp_demangle crates for
  improved output and better compatibility

## [2.0.2] - 2022-10-20

Minor release with only the changes of the previous release, but this time in
the right repository.

## [2.0.1] - 2022-10-20

### Added

- Several labels added by compilers are stripped from the symbols

### Changed

- Use the last version of the cpp_demangle crate for better results

### Fixed

- Function names are properly demangled even when inlined
- Emit a `<name omitted>` symbol when an inline function doesn't have a name
  (this can happen with debug information that has been split with tools like
  dwz), this avoids emitting `INLINE_ORIGIN` directives without a name

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
[Unreleased]: https://github.com/mozilla/dump_syms/compare/v2.3.6...HEAD
[2.3.6]: https://github.com/mozilla/dump_syms/compare/v2.3.5...v2.3.6
[2.3.5]: https://github.com/mozilla/dump_syms/compare/v2.3.4...v2.3.5
[2.3.4]: https://github.com/mozilla/dump_syms/compare/v2.3.3...v2.3.4
[2.3.3]: https://github.com/mozilla/dump_syms/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/mozilla/dump_syms/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/mozilla/dump_syms/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/mozilla/dump_syms/compare/v2.2.2...v2.3.0
[2.2.2]: https://github.com/mozilla/dump_syms/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/mozilla/dump_syms/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/mozilla/dump_syms/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/mozilla/dump_syms/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/mozilla/dump_syms/compare/v2.0.2...v2.1.0
[2.0.2]: https://github.com/mozilla/dump_syms/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/mozilla/dump_syms/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/mozilla/dump_syms/compare/v1.0.1...v2.0.0
[1.0.1]: https://github.com/mozilla/dump_syms/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mozilla/dump_syms/compare/cab687047df228587473fbc9a33e2ff2fd2d8c2e...v1.0.0
