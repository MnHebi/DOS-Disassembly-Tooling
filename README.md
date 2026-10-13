# DOS Disassembly Tooling (DDT)

A small, read-only, cross-platform toolkit for examining 16-bit DOS executables. One Python source tree runs on Linux x86-64 and Windows x86-64. It is deliberately not a full disassembler: the goal is reliable, machine-readable inspection, address mapping and binary comparison that work offline, with no Ghidra, emulator or network dependency.

## Supported inputs

- DOS MZ executables: header, relocation table and overlay are validated; NE, LE, LX and PE binaries are rejected rather than treated as DOS MZ payloads.
- Headerless COM images, selected explicitly with `--format com`.
- Other containers (NE/LE/LX/PE stubs, embedded COFF, common packers) are only **identified** by `ddt identify`; they are not loaded or analyzed.
- Arbitrary files and directories for hashing and byte-level comparison.

## Implemented now

- Strict DOS MZ header, relocation and overlay inventory (never executes the binary)
- Explicit headerless COM recognition and offset layout
- File-offset mapping for **module-relative** segment:offset coordinates, kept distinct from unknown runtime segments
- File and directory SHA-256 manifests
- Binary file and directory comparison with exact differing spans, bounded hexadecimal previews and exact run counts
- Printable-string extraction with exact original file offsets
- Read-only export of one analyzed function from an existing Ghidra project (optional; Ghidra is not needed for any other command)
- Offline direct caller/callee navigation over an exported function (no Ghidra required)
- Read-only identification of DOS containers, embedded signatures and packaging markers
- Versioned JSON output and a nonzero exit code on invalid input
- Native Linux and Windows packaging workflow using native runners

## Planned (not yet implemented)

- Recursive call graphs and writers/readers/slice queries (only direct callers and callees exist today)
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
ddt identify PROGRAM.EXE --json
ddt ghidra export --project ./proj --program GAME.EXE --function 1000:0000 --out func.json --json
ddt code callers --export func.json --json
ddt code callees --export func.json --json
python -m pytest -q
```

See [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the design and roadmap.

## Ghidra integration (optional)

`ddt ghidra export` runs Ghidra's headless analyzer in process mode against an **existing, saved** project to describe one already-analyzed function. It uses `-process -readOnly -noanalysis` and a bundled GhidraScript (`ddt/ghidra_scripts/ExportFunction.java`); it never imports, re-analyzes, overwrites, or commits to the project, and never modifies the original executable. The command is optional and self-contained: without it, DDT has no Ghidra dependency.

Point it at a Ghidra install with `--ghidra <dir>` (or the `GHIDRA_HOME` environment variable); `--java-home` selects a JDK if one is not already configured. Select the project with `--project <dir-or-.gpr>`, the program with `--program <name>`, and the function by its Ghidra entry address (`--function 1000:0000`). The versioned JSON record (`ddt.ghidra-function.v1`) reports program identity, language and image base, segmented memory blocks with import source mapping, the function's body ranges and instructions, and direct incoming/outgoing references with resolved/computed/unknown marked explicitly.

Limitations: instruction bytes are read from the loaded program image and may differ from original file bytes where a loader applied relocations; original file offsets are included only where Ghidra recorded an import source mapping, and otherwise reported as unknown. Incoming references are reported for the function entry only, computed or indirect control transfers are listed as unresolved rather than resolved, and nothing outside the selected function is exported.

## Function navigation (offline)

`ddt code callers --export func.json` and `ddt code callees --export func.json` answer direct relationship questions from an existing export, with no Ghidra run and no re-reading of the executable. Callers reports call references that target the function entry, separating direct, computed/indirect, and externally resolved ones; callees does the same for outgoing calls, plus unresolved (indirect) calls. Both output a compact versioned record (`ddt.code-callers.v2` / `ddt.code-callees.v1`).

These are deliberately bounded: a single exported function does not describe the whole program, incoming references cover the entry point only, caller function names are unavailable, indirect or aliased calls may be unresolved, and the export's own limits may truncate reference collections (the response reports truncation, marking it unknown for older exports). Direct call targets are referenced destination addresses, not necessarily verified function entry points.

## Format identification (identification-only)

`ddt identify PROGRAM.EXE` reports what a file structurally is, without loading, unpacking, relocating or executing anything. It reuses the validated MZ parser for the outer container (header size, declared length, appended region) and adds:

- **Recognized and unsupported**: secondary `NE`/`LE`/`LX`/`PE` headers reached through the MZ `e_lfanew` pointer, reported with their file offset and container relationship (`supported: false`). A header is `identified` only when documented structural fields validate (NE segment table, LE/LX CPU/OS header, PE Windows COFF optional header and section table); a bare or inconsistent signature is a `candidate` or `unknown` and does not make `ddt inspect` reject the MZ. LE/LX are not assumed to be any particular DOS extender.
- **Candidates**: `LZEXE` (`LZ09`/`LZ91` at the fixed 32-byte-header signature offset) and `UPX` (marker at file offset 85). A matching marker is a `candidate`, never proof of packing.
- **Embedded i386 COFF**: reported as a `candidate` only when a bounds-validated i386 COFF file header, section table and section raw-data extents are present at the start of the file or at the MZ declared-image end; the loader identity stays `unknown` (it is not claimed to be DJGPP).
- **Appended data**: bytes past the MZ declared image are reported as a region with `purpose: unknown` unless a recognized structure begins exactly there; appended bytes are never equated with code.

Each finding carries a `classification` of `identified`, `candidate` or `unknown`, plus the exact basis. Not yet recognized: `PKLITE` and `EXEPACK` (no reliably anchored, independently verifiable signature), and DJGPP/GO32 identity beyond a candidate `go32stub` marker. `ddt inspect` and `ddt address` keep their existing MZ/COM behavior.

## Distribution builds

GitHub Actions `.github/workflows/build.yml` runs the tests and produces PyInstaller `onedir` artifacts on Ubuntu and Windows using native runners. A Windows executable must be built **on a Windows runner**; no Windows binary is included in this source tree. Local build commands are documented in the blueprint.

## Safety and limits

The tools never modify original files, do not infer runtime behavior from static layout, and never claim that an MZ load-module offset is an observed runtime segment:offset address. COM files are headerless and must be requested explicitly. The per-file processing limit is 64 MiB. No proprietary binaries or save files are included.
