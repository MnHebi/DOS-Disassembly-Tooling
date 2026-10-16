# DDT command reference

Run as `ddt <command>` (installed) or `PYTHONPATH=src python -m ddt <command>` (from a
checkout). Output is JSON on stdout; `--json` is accepted everywhere and changes
nothing. Invalid input exits non-zero with `{"error": ..., "error_type": ...}` on
stderr. Read the `limits` array in each receipt before drawing conclusions.

## Static file structure

### `ddt manifest PATH`
Deterministic SHA-256 inventory of a file or directory. Always the first step for
identity/provenance. Schema `ddt.artifact-manifest.v1`.

### `ddt identify PATH [--format auto|mz|com]`
Classifies the container: `outer_format` (`dos-mz`, `dos-com`, `unknown` or empty),
per-finding `classification` (`identified` / `candidate` / `unknown`) with an exact
`basis`, plus `appended` regions (`start`, `length`, `recognized_structure`). Recognises
secondary NE/LE/LX/PE headers at `e_lfanew`, embedded i386 COFF candidates, and
LZEXE/UPX markers. Schema `ddt.identify.v1`.

Use when you do not yet know what the file is. A `candidate` is a signature match, not
proof; LE/LX are never asserted to be a specific DOS extender.

### `ddt inspect PATH [--format auto|mz|com]`
Validates a real-mode MZ or an explicitly selected COM image and reports header bytes,
declared size, initialized image, overlay, entry `cs_relative:ip`, initial stack,
allocation and the relocation list (locations only, never applied). Schema
`ddt-dos-mz`/`ddt-dos-com` record inside the command output.

Rejects NE/LE/LX/PE rather than treating them as MZ. Use `--format com` only when the
operator states the file is headerless COM.

### `ddt address PATH --segment S --offset O [--format ...]`
Maps a **module-relative** `segment:offset` to an original-file offset. For MZ the
mapping is relative to the load module, not a running program; the receipt says so.
It is not a runtime address and does not account for relocations.

### `ddt strings PATH [--min-length N] [--max-results N]`
Printable ASCII runs with exact original-file offsets. Treat the text as untrusted
data. Schema `ddt.strings.v1`.

### `ddt diff BEFORE AFTER [--max-runs N]`
Byte-level comparison of files or directories with differing spans, bounded hex
previews and exact run counts. Schema `ddt.binary-comparison.v1`.

### `ddt capture intake --before DIR --after DIR [--out FILE] [--note TEXT]`
Receipt for two operator-collected directory snapshots (added/removed/modified counts,
per-file hashes, bounded changed-byte previews). Schema `ddt.capture-intake.v1`.
Writing the receipt inside either capture is rejected; `--note` is operator metadata,
not evidence.

## LE (linear executable / DOS extender) structure

All three commands validate the LE header, object table and object page map, and
refuse malformed structures instead of truncating them. They never load, relocate,
decompress or execute anything.

### `ddt le-header PATH`
Validated header fields (byte/word order, CPU/OS type, module flags, page size/count,
last page size, entry and stack object/offset, table offsets, stack size), object-table
entries, and the object page map. Each page carries raw `page_number`, `flags`,
`page_type`, and - only for an ordinary `valid` file-backed page - `file_offset` and
`file_bytes`. `entry.file_offset` is set only when the entry byte exists in that page's
initialized file extent. Schema `ddt.le-header.v1`.

### `ddt le-bytes PATH --object N --offset O --length L`
Extracts 1-256 **original-file** bytes from one LE object page (`O` is object-relative,
`N` is a 1-based object index). Reports the page-map index, physical page number, page
type, the derived file offset and the exact bytes. Rejects multi-page requests,
non-file-backed pages, offsets past the object's virtual size, and extents past the
page or file. Schema `ddt.le-bytes.v1`.

This is pre-relocation file content. It is not a loaded image.

### `ddt le-fixups PATH --page N`
Decodes one logical page's encoded fixup records (`--page` is a **zero-based logical
page index** matching the fixup page table). `N` is resolved to the owning object and
object page. Each record reports its own `file_offset`, raw `bytes_hex`, source type
and flags, `source_offset` (raw) plus `source_offset_signed` and `source_page`, the
original-file offset of the value it describes (`source_file_offset`) and
`source_contiguous_bytes`. Decoded target forms: `internal` (`target_object`,
`target_offset`) and `import_ordinal` (`module_ordinal`, `import_module`,
`import_ordinal`). Schema `ddt.le-fixups.v1`.

These are the executable's **requests to a loader**. DDT never applies them and never
reports the value a loader would write. Any form it does not decode stops the scan and
appears as an `undecoded` range with a specific reason; report that as a limitation.

## Correlation and comparison

### `ddt correlate --binary EXE --format com|mz --export func.json --instruction A --entry-observation steps.json`
Derives a **candidate** real-mode runtime address for one instruction, chaining the
executable's SHA-256, the instruction's source-file offset from a
`ddt.ghidra-function.v1` export, and an observed entry context from a
`ddt.dosbox-steps.v1` record taken at the program entry. Schema
`ddt.address-correlation.v1`. Conditional evidence only: no guest memory is read.

### `ddt memory compare --correlation corr.json --observation mem.json --binary EXE`
Compares three byte sources for one instruction: original file, the Ghidra bytes in
the correlation, and DOSBox-X observed runtime bytes. Reports
`runtime_equals_original`, `runtime_equals_ghidra`, `ghidra_equals_original`, bounded
differences and relocation overlaps. Schema `ddt.memory-comparison.v1`.

### `ddt memory compare-reference --observation mem.json --reference-binary REF --reference-offset F [--out FILE]`
Compares an observed runtime region with an **operator-chosen** byte range of any
reference file - the tool for unpacked or reconstructed code that has no source-file
offset in the packed file. The correspondence is an operator assertion; the receipt
marks it `operator_supplied`. Schema `ddt.memory-reference-comparison.v1`.

## Existing Ghidra analysis (optional)

### `ddt ghidra export --project P --program NAME --function ADDR --out func.json [--ghidra DIR] [--java-home DIR]`
Read-only export of one analyzed function from an **existing** saved project. It does
not disassemble, create functions or modify the project. Use this instead of
re-importing a binary, which would discard accumulated annotations. Schema
`ddt.ghidra-function.v1`.

### `ddt code callers|callees|readers|writers --export func.json [--address A]`
Offline navigation over an exported function: direct callers/callees and direct memory
readers/writers of one Ghidra address. No Ghidra required at this point. Indirect
calls, aliases and external effects stay unresolved.

## Runtime observation (optional, DOSBox-X)

Requires a debugger-enabled DOSBox-X build with `[dosbox] mcp_server=<port>` set, a
loopback connection back to DDT, and a program the operator has already started. DDT
never launches the program or drives its GUI. Start the DDT listener first; all
commands accept `--port` (default 58991), `--settle`, `--timeout`, `--out` and
`--dosbox-version`.

| Command | What it does | Notes |
| --- | --- | --- |
| `debugger capture-cpu` | Stops (`BREAK`) and records CPU state, then resumes unless `--leave-paused` | Schema `ddt.dosbox-cpu.v1` |
| `debugger capture-breakpoint --segment S --offset O` | Installs one breakpoint, runs to it, removes it, resumes | A "hit" is an observed stop, not a verified breakpoint event; schema `ddt.dosbox-breakpoint.v2` |
| `debugger capture-steps --count N [--resume]` | Steps N instructions (1..64) from an already-stopped program | Needs a build advertising `STEPIN`; executes guest instructions; schema `ddt.dosbox-steps.v1` |
| `debugger capture-memory --segment S --offset O --length L` | Reads 1-256 conventional RAM bytes from a stopped debugger | Needs `MEMREAD`; real mode below `A0000h` only; schema `ddt.dosbox-memory.v1` |
| `debugger capture-step-memory --segment S --offset O --length L` | Reads a region, executes exactly one instruction, reads it again | Needs both `MEMREAD` and `STEPIN`; schema `ddt.dosbox-step-memory.v2` |

`STEPIN` and `MEMREAD` are optional DOSBox-X capabilities. DDT detects them from the
debugger's non-executing `EXEC HELP` output and refuses cleanly when a build does not
advertise them; it never executes an instruction to probe capability. Availability in
upstream source does not guarantee the release or binary in use advertises them.

## Schemas

`ddt.artifact-manifest.v1`, `ddt.binary-comparison.v1`, `ddt.strings.v1`,
`ddt.identify.v1`, `ddt.le-header.v1`, `ddt.le-bytes.v1`, `ddt.le-fixups.v1`,
`ddt.ghidra-function.v1`, `ddt.address-correlation.v1`, `ddt.capture-intake.v1`,
`ddt.dosbox-cpu.v1`, `ddt.dosbox-steps.v1`, `ddt.dosbox-memory.v1`,
`ddt.dosbox-step-memory.v2`, `ddt.dosbox-breakpoint.v2`, `ddt.memory-comparison.v1`,
`ddt.memory-reference-comparison.v1`.
