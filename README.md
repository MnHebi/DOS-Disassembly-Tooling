# DOS Disassembly Tooling (DDT)

A small, read-only, cross-platform toolkit for examining 16-bit DOS executables. One Python source tree runs on Linux x86-64 and Windows x86-64. It is deliberately not a full disassembler: the goal is reliable, machine-readable inspection, address mapping and binary comparison that work offline, with no Ghidra, emulator or network dependency.

## Supported inputs

- DOS MZ executables: header, relocation table and overlay are validated; NE, LE, LX and PE binaries are rejected rather than treated as DOS MZ payloads.
- Headerless COM images, selected explicitly with `--format com`.
- Arbitrary files and directories for hashing and byte-level comparison.

## Implemented now

- Strict DOS MZ header, relocation and overlay inventory (never executes the binary)
- Explicit headerless COM recognition and offset layout
- File-offset mapping for **module-relative** segment:offset coordinates, kept distinct from unknown runtime segments
- File and directory SHA-256 manifests
- Binary file and directory comparison with exact differing spans, bounded hexadecimal previews and exact run counts
- Printable-string extraction with exact original file offsets
- Versioned JSON output and a nonzero exit code on invalid input
- Native Linux and Windows packaging workflow using native runners

## Planned (not yet implemented)

- Read-only export from an existing Ghidra project, with bounded dependency slicing
- Segmented code navigation (writers, readers, callers) that reports unresolved edges instead of guessing
- Optional capture intake and evidence indexing with hashes and provenance

## Installation and usage

```sh
python -m pip install -e .
ddt inspect GAME.EXE --json
ddt inspect GAME.COM --format com --json
ddt address GAME.EXE --segment 0x1234 --offset 0x100 --json
ddt diff before/ after/ --json
ddt manifest before/ --json
ddt strings GAME.EXE --json
python -m pytest -q
```

See [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the design and roadmap.

## Distribution builds

GitHub Actions `.github/workflows/build.yml` runs the tests and produces PyInstaller `onedir` artifacts on Ubuntu and Windows using native runners. A Windows executable must be built **on a Windows runner**; no Windows binary is included in this source tree. Local build commands are documented in the blueprint.

## Safety and limits

The tools never modify original files, do not infer runtime behavior from static layout, and never claim that an MZ load-module offset is an observed runtime segment:offset address. COM files are headerless and must be requested explicitly. The per-file processing limit is 64 MiB. No proprietary binaries or save files are included.
