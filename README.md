# DOS Disassembly Tooling (DDT)

A small, read-only, cross-platform toolkit for examining 16-bit DOS executables. One Python source tree runs on Linux x86-64 and Windows x86-64. It is deliberately not a full disassembler: the goal is reliable, machine-readable inspection, address mapping and binary comparison that work offline, with no Ghidra, emulator or network dependency.

## Supported inputs

- DOS MZ executables: header, relocation table and overlay are validated; NE, LE, LX and PE binaries are rejected rather than treated as DOS MZ payloads.
- Headerless COM images, selected explicitly with `--format com`.
- Other containers (NE/LE/LX/PE stubs, embedded COFF, common packers) are only **identified** by `ddt identify`; `LE` can additionally be structurally inspected and its file-backed pages extracted with `ddt le-header`/`ddt le-bytes`, and none of them are loaded or executed.
- Arbitrary files and directories for hashing and byte-level comparison.

## Implemented now

- Strict DOS MZ header, relocation and overlay inventory (never executes the binary)
- Explicit headerless COM recognition and offset layout
- File-offset mapping for **module-relative** segment:offset coordinates, kept distinct from unknown runtime segments
- File and directory SHA-256 manifests
- Binary file and directory comparison with exact differing spans, bounded hexadecimal previews and exact run counts
- Printable-string extraction with exact original file offsets
- Static/runtime address correlation from original file offsets and an observed entry context
- Read-only export of one analyzed function from an existing Ghidra project (optional; Ghidra is not needed for any other command)
- Offline navigation over an exported function: direct callers/callees and memory readers/writers (no Ghidra required)
- Read-only identification of DOS containers, embedded signatures and packaging markers
- Read-only LE (linear executable) header, object-table, page-map and fixup-record inspection, plus bounded original-file byte extraction from one validated LE page
- Read-only runtime capture intake: compare an operator's before/after artifact snapshots
- Optional DOSBox-X debugger CPU-state capture (needs a debugger-enabled DOSBox-X build)
- Optional DOSBox-X execution-breakpoint capture at an explicit runtime address
- Optional DOSBox-X single-instruction stepping (only on builds advertising `STEPIN`)
- Optional DOSBox-X bounded conventional-RAM observation (only on builds advertising `MEMREAD`)
- Optional DOSBox-X single-instruction memory-change observation (needs both `MEMREAD` and `STEPIN`)
- Offline comparison of observed runtime bytes with original and Ghidra instruction bytes
- Versioned JSON output and a nonzero exit code on invalid input
- Native Linux and Windows packaging workflow using native runners

## Planned (not yet implemented)

- Recursive call graphs and writers/readers/slice queries (only direct callers and callees exist today)
- Searchable evidence indexing across many captures (single before/after intake exists today)

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
ddt le-header PROGRAM.EXE --json
ddt le-bytes PROGRAM.EXE --object 1 --offset 0x88 --length 16 --json
ddt le-fixups PROGRAM.EXE --page 0 --json
ddt capture intake --before ./capture-before --after ./capture-after --json
ddt correlate --binary PROGRAM.EXE --format mz --export func.json --instruction 1000:000c --entry-observation steps.json --json
ddt debugger capture-cpu --port 58991 --out cpu.json --json
ddt debugger capture-breakpoint --port 58991 --segment 0x0813 --offset 0x0103 --out bp.json --json
ddt debugger capture-steps --port 58991 --count 2 --out steps.json --json
ddt debugger capture-memory --port 58991 --segment 0x0813 --offset 0x0103 --length 3 --out memory.json --json
ddt debugger capture-step-memory --port 58991 --segment 0x0813 --offset 0x0200 --length 16 --out step-memory.json --json
ddt memory compare --correlation correlation.json --observation memory.json --binary PROGRAM.COM --json
ddt memory compare-reference --observation memory.json --reference-binary ORIG.EXE --reference-offset 64 --json
ddt ghidra export --project ./proj --program GAME.EXE --function 1000:0000 --out func.json --json
ddt code callers --export func.json --json
ddt code callees --export func.json --json
ddt code readers --export func.json --address 1000:1234 --json
ddt code writers --export func.json --address 1000:1234 --json
python -m pytest -q
```

See [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the design and roadmap.

## Agent Skill (optional)

`skills/ddt-dos-reverse-engineering/` is a portable [Agent Skill](https://developers.openai.com/codex/skills) that teaches an AI coding agent to select and interpret DDT's existing commands: container identification, COM/MZ and LE structure, fixup and relocation reading, original-file offset mapping, bounded byte extraction, artifact comparison, and the optional runtime and Ghidra evidence paths. It is **instructions only** — no new analysis code, no dependencies, and no MCP requirement; everything it describes runs through the ordinary `ddt` CLI, and it may use the MCP tools below when a client already has that server connected.

The skill is optional and purely additive: DDT, its packaging and its test suite work exactly the same without it. Install it by copying or symlinking the folder into a location your agent scans (Codex reads repository, user, admin and bundled locations, and follows symlinked skill folders):

```sh
mkdir -p .agents/skills && cp -r skills/ddt-dos-reverse-engineering .agents/skills/   # repo-scoped
mkdir -p "$HOME/.agents/skills" && cp -r skills/ddt-dos-reverse-engineering "$HOME/.agents/skills/"   # user-scoped
```

Codex discovers new skills automatically; restart it if the skill does not appear. Other Agent Skills-compatible clients read `SKILL.md` from their own skill directory, so point them at the same folder. The skill's `SKILL.md` is the entry point; `references/commands.md` and `references/evidence.md` are loaded only when a task needs them.

## MCP server (optional)

```sh
python -m pip install "dos-disassembly-tooling[mcp]"
ddt-mcp --root /path/to/authorized/analysis
```

The `mcp` extra adds `ddt-mcp`, a local **stdio** MCP server that exposes a bounded read-only subset of DDT through the official Model Context Protocol Python SDK (`mcp>=2.3,<3`, currently verified against 2.3.0). It is not a second implementation: every tool calls the same Python function the CLI calls and returns the same versioned JSON receipt, including its `limits` and unknown fields. It never executes the analyzed program, never drives DOSBox-X or Ghidra, exposes no shell and no write operation, and adds no HTTP listener, daemon or state. The server is launched by an MCP client and terminates with that session; protocol messages use stdout and diagnostics use stderr only.

| Tool | DDT operation |
| --- | --- |
| `ddt_manifest` | Hash one file (`ddt.artifact-manifest.v1`) |
| `ddt_identify` | Identify the container (`ddt.identify.v1`) |
| `ddt_inspect` | Inspect a COM/MZ image |
| `ddt_le_header` | Inspect an LE header, object table and page map (`ddt.le-header.v1`) |
| `ddt_le_bytes` | Extract bounded LE original-file bytes (`ddt.le-bytes.v1`) |
| `ddt_le_fixups` | Inspect one logical LE page's fixups (`ddt.le-fixups.v1`) |

**Authorized root.** `--root` is required and must be an existing directory. Every requested path is resolved (including symlinks) and must stay inside that directory; paths outside it, missing files, directories and non-files are refused, and a refusal never causes the server to look elsewhere. This is an **application-level** restriction, not an operating-system sandbox: it assumes the client process could otherwise read the filesystem, and does not confine the process itself.

**Response size.** A receipt larger than 256 KiB is returned as an explicit size-limit error naming the limit and the actual size, with a suggestion to narrow the request. DDT never truncates a receipt and presents it as complete.

Client configuration (Codex reads `[mcp_servers.<name>]` stdio tables from `config.toml`; `command`, `args` and `cwd` are the documented keys):

```toml
[mcp_servers.ddt]
command = "ddt-mcp"
args = ["--root", "/path/to/authorized/analysis"]
```

The same server can be registered from the CLI: `codex mcp add ddt -- ddt-mcp --root /path/to/authorized/analysis`. Installing DDT without the extra changes nothing: the SDK is imported lazily, `ddt-mcp` exits with an installation hint, and the frozen PyInstaller builds still contain only the core.

## Ghidra integration (optional)

`ddt ghidra export` runs Ghidra's headless analyzer in process mode against an **existing, saved** project to describe one already-analyzed function. It uses `-process -readOnly -noanalysis` and a bundled GhidraScript (`ddt/ghidra_scripts/ExportFunction.java`); it never imports, re-analyzes, overwrites, or commits to the project, and never modifies the original executable. The command is optional and self-contained: without it, DDT has no Ghidra dependency.

Point it at a Ghidra install with `--ghidra <dir>` (or the `GHIDRA_HOME` environment variable); `--java-home` selects a JDK if one is not already configured. Select the project with `--project <dir-or-.gpr>`, the program with `--program <name>`, and the function by its Ghidra entry address (`--function 1000:0000`). The versioned JSON record (`ddt.ghidra-function.v1`) reports program identity, language and image base, segmented memory blocks with import source mapping, the function's body ranges and instructions, and direct incoming/outgoing references with resolved/computed/unknown marked explicitly.

Limitations: instruction bytes are read from the loaded program image and may differ from original file bytes where a loader applied relocations; original file offsets are included only where Ghidra recorded an import source mapping, and otherwise reported as unknown. Incoming references are reported for the function entry only, computed or indirect control transfers are listed as unresolved rather than resolved, and nothing outside the selected function is exported.

## Function navigation (offline)

`ddt code callers --export func.json` and `ddt code callees --export func.json` answer direct relationship questions from an existing export, with no Ghidra run and no re-reading of the executable. Callers reports call references that target the function entry, separating direct, computed/indirect, and externally resolved ones; callees does the same for outgoing calls, plus unresolved (indirect) calls. Both output a compact versioned record (`ddt.code-callers.v2` / `ddt.code-callees.v1`).

These are deliberately bounded: a single exported function does not describe the whole program, incoming references cover the entry point only, caller function names are unavailable, indirect or aliased calls may be unresolved, and the export's own limits may truncate reference collections (the response reports truncation, marking it unknown for older exports). Direct call targets are referenced destination addresses, not necessarily verified function entry points.

`ddt code readers --export func.json --address 1000:1234` and `ddt code writers --export func.json --address 1000:1234` report the instructions in that exported function whose Ghidra references are classified as reading or writing the given **Ghidra address** (`ddt.code-readers.v1` / `ddt.code-writers.v1`). Calls, jumps and other control flow are excluded, direct and computed/indirect matches are listed separately, and address-space identity is preserved (the address text must match exactly, so different spaces or destinations never collide). Results are Ghidra's static reference classification — analysis evidence, not proof of an executed access. For exports predating the read/write flags, references are classified only by exact Ghidra reference-type names and anything else is counted as unclassified rather than guessed. These queries cover one exported function: other functions, indirect/unresolved accesses, pointer writes, interprocedural effects and segment aliases are out of scope, so an empty result means "no matching direct reference in this export", not "nothing in the program touches this address".

## Format identification (identification-only)

`ddt identify PROGRAM.EXE` reports what a file structurally is, without loading, unpacking, relocating or executing anything. It reuses the validated MZ parser for the outer container (header size, declared length, appended region) and adds:

- **Recognized and unsupported**: secondary `NE`/`LE`/`LX`/`PE` headers reached through the MZ `e_lfanew` pointer, reported with their file offset and container relationship (`supported: false`). A header is `identified` only when documented structural fields validate (NE segment table, LE/LX CPU/OS header, PE Windows COFF optional header and section table); a bare or inconsistent signature is a `candidate` or `unknown` and does not make `ddt inspect` reject the MZ. LE/LX are not assumed to be any particular DOS extender.
- **Candidates**: `LZEXE` (`LZ09`/`LZ91` at the fixed 32-byte-header signature offset) and `UPX` (marker at file offset 85). A matching marker is a `candidate`, never proof of packing.
- **Embedded i386 COFF**: reported as a `candidate` only when a bounds-validated i386 COFF file header, section table and section raw-data extents are present at the start of the file or at the MZ declared-image end; the loader identity stays `unknown` (it is not claimed to be DJGPP).
- **Appended data**: bytes past the MZ declared image are reported as a region with `purpose: unknown` unless a recognized structure begins exactly there; appended bytes are never equated with code.

Each finding carries a `classification` of `identified`, `candidate` or `unknown`, plus the exact basis. Not yet recognized: `PKLITE` and `EXEPACK` (no reliably anchored, independently verifiable signature), and DJGPP/GO32 identity beyond a candidate `go32stub` marker. `ddt inspect` and `ddt address` keep their existing MZ/COM behavior.

## LE (linear executable) inspection

`ddt le-header PROGRAM.EXE` validates and reports the LE container an MZ-hosted DOS-extender program carries at its `e_lfanew` offset, as `ddt.le-header.v1`. It reports the validated header fields (byte/word order, CPU and OS type, module version and flags, page size and count, last page size, entry and stack object numbers and offsets, stack size), the object table, and the object page map. Each page entry carries the raw `page_number` and `flags`, a `page_type` name, and — **only for an ordinary file-backed (`PAGE_VALID`) page** — its `file_offset` and the `file_bytes` that page actually occupies in the file. A file offset is reported for the entry point only when the entry byte really exists inside that page's initialized file extent. Every table is bounds-checked against the file, and inconsistent or out-of-range values are rejected rather than truncated.

The page-map flag byte is not decoration. LE distinguishes `valid`, `iterated`, `invalid`, `zeroed`, `range`, `compressed` and `m3-packed` pages (`bld/watcom/h/exeflat.h`); for anything but `valid`, the entry's 24-bit value is *not* a file page number — an iterated or range page indexes the iterated-data map instead. Those pages therefore keep their raw number and flags but get `file_offset: null` and `file_bytes: null`, and are never offered as executable bytes. Likewise a byte in an object's uninitialized tail (past the mapped pages, or past the `last_page_size` bytes of a short final page) yields `file_offset: null` with `mapped_to_file: false`: that is a valid virtual address without a file image, which is reported distinctly from a structurally invalid object or page map (those raise an error).

`ddt le-bytes PROGRAM.EXE --object 1 --offset 0x88 --length 16` extracts those original-file bytes directly, as `ddt.le-bytes.v1`: the source path/size/SHA-256, the 1-based object, the object-relative offset and request length, the page-map index, physical page number and flags, the derived original-file offset, and the exact bytes in hex. The request is bounded to 1–256 bytes, must lie entirely inside one `PAGE_VALID` page's initialized file extent, and must fit in the file; a multi-page request, an uninitialized or non-file-backed page, an out-of-range object/offset, or a malformed extent is rejected with a specific error rather than silently combined or zero-filled. This is **original-file byte extraction** — no relocation, decompression, protected-mode loading or runtime observation — and nothing is ever written back into the executable.

Keep the four address kinds distinct: an **object-relative offset** is an index into one LE object; a **physical page number** selects a page in the file's data-page area; the derived **original-file offset** is `data_pages_offset + (page-1) * page_size + (offset mod page_size)`; and a **runtime address** is a protected-mode selector plus offset that DDT cannot observe at all. None of the first three implies the fourth.

`ddt le-fixups PROGRAM.EXE --page 0` reports one logical page's **encoded fixup records** as `ddt.le-fixups.v1`. The fixup page table has one entry per module page plus a final sentinel, and its values bound each page's records inside the fixup record table; `--page` is a **zero-based logical page index** in that table, which is resolved to the owning object and object-page (the physical page number, page type, file extent and `page_size` are reported alongside). Each decoded record keeps its file offset, raw bytes, source type and flags, source offset, and the **original-file offset of the value it describes** (`source_file_offset`), plus the target object and target offset for the internal-reference form. It reports a page that has no records as such, and it never advances past a record form it does not decode: the remaining range is reported as an undecoded extent instead.

A source offset is **signed**. A negative value (for example the raw `0xFFFF` that means `-1`) says the fixup's bytes *begin in the preceding logical page*, which is how an LE image records a relocation that straddles a page boundary — in the fixture, page 2 names the value at its last byte while page 3 names the same value at offset `-1`, and both resolve to the same original-file byte. DDT reports the raw unsigned `source_offset`, the `source_offset_signed` reading, the `source_page` the byte falls in, and `source_file_offset` mapped **through that page's own file extent and its object's declared virtual extent** — never by subtracting one from the selected page's offset, because adjacent logical pages need not be adjacent in the file. `source_contiguous_bytes` (capped at 8, wider than any LE fixup source field) reports how many consecutive file-backed bytes actually follow *within the same object and its virtual extent*, so a consumer can tell whether reading a multi-byte value from `source_file_offset` is safe. A source byte outside its object, in a page with no file image, or followed by a page belonging to another object gets no established offset or only the bytes that really are present — physically adjacent pages of different objects are never counted as contiguous.

Two things `le-fixups` deliberately does **not** do. It does not apply fixups, so it never claims what a loader would write — the records are the executable's *requests* to a loader, and `source_file_offset` locates the value, not the relocated value. And a record's own `file_offset` is not the file offset of the value it describes. `ddt le-bytes` is unchanged and still returns the raw, unrelocated original-file bytes.

Two record forms are decoded, both verified record-for-record against OpenWatcom's own `wdump`: **internal references** and **import-by-ordinal** references. An import record reports its `module_ordinal`, the `import_module` name resolved from the header's import module name table (length-prefixed entries, bounds-checked), and its `import_ordinal`. It deliberately reports no symbol name and no address: the imported symbol's name lives in the *other* module, and the address a loader assigns is not in this file at all.

Every other form whose flags change what the bytes mean stops decoding at that record and reports the remaining range as an `undecoded` extent with a specific reason, rather than quietly reporting it as an ordinary relocation: the `import-name` and `internal-via-entry` target types; the `alias-source` (`0x10`) and list (`0x20`) source flags; and the `additive-value` (`0x04`), `internal-chain` (`0x08`), `32-bit-additive` (`0x20`) and — for internal references only — `8-bit-ordinal` (`0x80`) target flags, whose names come from OpenWatcom's `bld/watcom/h/exeflat.h`. Flag bits that are reserved or whose meaning is not established are left untouched rather than restricted. The declared fixup-section size is reported but not used for bounds.

This is structural only: nothing is loaded, relocated, decompressed or executed, and no runtime `segment:offset` address is ever derived from a file offset. The header layout and the page-map encoding (a 24-bit big-endian page number plus one flag byte per entry) were checked against OpenWatcom's `wdump` and GNU `file` for one genuine, reproducible fixture: an OpenWatcom v2 `wcl386`/`wlink system dos4g` hello-world with a `0x220`-byte MZ stub, an `LE` header (CPU 2, OS 1), a `0x1000` page size over five pages (last page `0x414`), and entry `object 1:0x88` resolving to original file offset `2616`, where `EB 12` begins.

Only `LE` is inspected here. `LX` headers are still only *identified* by `ddt identify` (no verified LX fixture yet), and the LE/LX OS type field is not treated as identification of a specific DOS extender. `ddt inspect` and `ddt address` continue to reject NE/LE/LX as real-mode DOS MZ targets, and no protected-mode runtime debugging exists.

## Runtime capture intake

`ddt capture intake --before DIR --after DIR` compares two directories the operator collected around one action, reusing DDT's manifest and byte-comparison primitives. It is read-only: it never modifies, copies or renames anything in either capture, and it reports added/removed/unchanged/modified counts, per-file lengths and SHA-256 hashes, exact relative paths, and bounded changed-byte previews with full run counts. The receipt (`ddt.capture-intake.v1`) can be written outside the captures with `--out`; writing it inside either capture is rejected. A `--note` is recorded as user-supplied metadata, not as verified fact.

Intended workflow: (1) prepare an isolated DOS application environment and pick one action to investigate; (2) have the operator take a BEFORE snapshot using the application's normal controls; (3) perform the single action; (4) take an AFTER snapshot; (5) run `ddt capture intake`; (6) keep the original artifacts and the receipt.

A receipt states what DDT read and what differs — it does not prove which application, executable or runtime session produced the captures, and it does not attribute any difference to the action. DDT does not drive the emulator or simulate input.

## Static/runtime address correlation

`ddt correlate --binary PROGRAM.EXE --format mz --export func.json --instruction 1000:000c --entry-observation steps.json` derives a **candidate** real-mode runtime address for one instruction in a Ghidra export (`ddt.address-correlation.v1`), chaining three pieces of evidence: the original executable bytes (the export's `executable_sha256` must equal the binary's SHA-256), the instruction's original source-file offset from the `ddt.ghidra-function.v1` export, and an observed entry context from a `ddt.dosbox-steps.v1` record made at the program entry (`DEBUGBOX`). For COM it requires the observed entry IP to be `0100` and maps file offset `F` to runtime `entryCS:0100+F`; for MZ it requires the observed IP to equal the header's entry IP, derives `load_segment = entryCS − header_entry_CS`, `module_offset = F − header_bytes`, and reports the canonical `segment:offset` for the resulting physical address, rejecting any value that would need wrap/A20 assumptions. The selected instruction's full extent (offset + length, cross-checked against its reported bytes) must lie inside the initialized image — not in the MZ header, appended overlay, or past the end of the file — and the executable is read exactly once.

The result is **conditional**, never verified execution: no guest memory is read, so byte equality at the derived address is not observed, and Ghidra's address space is never equated with the guest's `segment:offset` space. It is not applicable to overlays, protected-mode extenders, uninitialized storage without a file offset, or self-modified/decompressed code, and the canonical `segment:offset` is one representation, not necessarily the alias the running program uses. Both paths are verified end-to-end against real Ghidra exports and live DOSBox-X entry observations; note that a headerless COM imported as a raw binary has no function entry point, so the Ghidra **project** must first disassemble the fixture and create the function (DDT's exporter stays read-only and reproduces no analysis).

## DOSBox-X debugger capture (optional)

`ddt debugger capture-cpu --port 58991 --out cpu.json` listens on `127.0.0.1`, accepts the single connection that DOSBox-X makes when its `[dosbox] mcp_server=<port>` setting is enabled, and drives the documented line protocol (`REQ`/`BEGIN`/`END`): `PING`, `BREAK`, one `EV` register read, one `CPU` status read, then `RUN` to leave the emulator running. It writes a compact `ddt.dosbox-cpu.v1` observation containing the raw protocol exchanges and the parsed registers. Start the DDT command first so the listener exists before DOSBox-X connects; DDT does not launch or drive the emulator and exposes no other debugger command.

This needs a DOSBox-X built with the internal debugger **and** SDL_net (`./configure --enable-debug --enable-sdl2`, with SDL2_net installed). The standard distributions, including the common Flatpak build, ship with the debugger disabled; keep that installation and build a separate debugger-enabled DOSBox-X (for example inside a container). Instruction-level checks (break, registers, memory) require launching DOSBox-X from a terminal, because the text debugger initialises only with a TTY.

Captured values are DOSBox-X runtime observations, not Ghidra addresses, module offsets or original file offsets, and DDT never translates between them. The DOSBox-X build identity is not obtainable over the protocol, so pass `--dosbox-version` to record one. The debugger's `MEMDUMPBIN` memory dump was independently verified to work, but it is not exposed by DDT yet because its output is written into the emulated DOS drive rather than a DDT-controlled location.

`ddt debugger capture-breakpoint --segment 0x0813 --offset 0x0103` installs one real-mode execution breakpoint at an explicit runtime `segment:offset` (no automatic translation from any other address space), confirms it through `BPLIST`, resumes, and reports `ddt.dosbox-breakpoint.v2`. DOSBox-X exposes **no asynchronous breakpoint-hit event** — the control channel only has `PING`, `BREAK` and `EXEC`, and its event sender is never called. So DDT distinguishes an *observation* from a *verified hit*: `target_ip_observed_stable` is true when CS:IP stays on the requested address across several differently spaced register queries after resuming (without issuing another `BREAK`), while `breakpoint_hit_verified` and `stop_reason` stay `null` because the protocol cannot prove a stop (a tight self-loop at the target could look identical). Cleanup also distinguishes a `BPDEL` acknowledgement from an *independently verified* absence in a final `BPLIST` (`delete_acknowledged`/`final_list_verified`/`removal_verified`), and only the address-verified breakpoint DDT installed is deleted — unrelated user breakpoints are preserved and `BPDEL *` is never used. `run_acknowledged` records that `RUN` was accepted, `paused_state` stays `unknown`, and `--leave-paused` keeps the emulator stopped. (v2 replaces v1's `hit_confirmed`/`resumed`/`paused_at_capture` fields.)

*Unresolved breakpoint hypothesis* (recorded during a packed-MZ investigation, not a confirmed root cause): a breakpoint installed at the instruction where the debugger is already stopped did not intercept control returning to that address. Two candidate explanations are that `RUN`'s initial breakpoint-inhibition applies to the current instruction, and that non-heavy-debugger DOSBox-X builds may use `CC` software breakpoints which an in-place unpacker can overwrite while decompressing over itself. DDT implements no breakpoint workaround for either.

`ddt debugger capture-steps --count 2` steps an already-stopped program one guest instruction at a time and reports `ddt.dosbox-steps.v1` with the initial/last register state, each step's observed register differences, and the raw debugger responses. **`STEPIN` is an optional DOSBox-X capability**, and the existing `capture-cpu`/`capture-breakpoint` commands do not require it. It is implemented in upstream DOSBox-X source (documented in upstream `README.debugger`), but that establishes availability in the source tree only: an official tagged release or a prebuilt binary may predate it, so the build actually in use still has to be checked. DDT checks support from the debugger's non-executing `EXEC HELP` output and refuses with a clear message when a build does not advertise `STEPIN` — it never executes an instruction to discover capability. The program must already be stopped at the intended instruction (start it with `DEBUGBOX`, or break in first); DDT never issues `BREAK` to establish a starting point. Stepping *changes guest execution state*, and DDT leaves the debugger stopped afterwards unless `--resume` is given (whose `RUN` acknowledgement is recorded but is not proof that execution resumed). A step may be a jump, call or interrupt, so CS:IP can move non-sequentially and an `INT` may enter a handler; register values are runtime observations, never Ghidra addresses or file offsets.

`ddt debugger capture-memory --segment 0x0813 --offset 0x0103 --length 3` reads 1–256 bytes of **actual guest RAM** from an already-stopped debugger and reports `ddt.dosbox-memory.v1` (address, requested length, exact hex bytes, initial/final CS:IP, and the raw `MEMREAD` response). **`MEMREAD` is an optional DOSBox-X capability** with the same availability caveat as `STEPIN`: it is implemented in upstream DOSBox-X source, but a given release or prebuilt binary must advertise it before DDT will use it. Support is detected from the non-executing `EXEC HELP` output; an unreadable byte fails the whole request rather than becoming a fabricated zero. Only real-mode conventional RAM below `A0000h` is read, in a single bounded request, and DDT never issues `BREAK`/`RUN`/`STEPIN` or writes memory.

`ddt memory compare --correlation correlation.json --observation memory.json --binary PROGRAM.COM` compares three byte sources for one instruction: the **original executable**, **Ghidra's recorded memory bytes** (from the correlation's instruction), and the **DOSBox-X observed runtime bytes**. It requires the binary's SHA-256 to match the correlation, the observation to cover exactly the correlation's derived address and length (segment aliases are rejected, not treated as equivalent), and valid hex of the expected length; for MZ it also reports any relocation word overlapping the instruction extent. The result (`ddt.memory-comparison.v1`) reports `runtime_equals_original`, `runtime_equals_ghidra` and `ghidra_equals_original`, a bounded list of differing byte positions, and explicit uncertainty — **evidence, never an inferred cause** (relocations, loader activity or runtime modification can all explain a difference).

`ddt memory compare-reference --observation memory.json --reference-binary ORIG.EXE --reference-offset 64` is the offline companion for cases where no static correlation can exist — code produced by **unpacking** has no source-file offset in the packed file. The comparison length comes from the observation (1–256 bytes) and `--reference-offset` is an **operator-supplied original-file byte offset**, not a runtime address and not a mapping DDT derives. The receipt validates the observation rigorously (schema, `read_success`/`cs_ip_unchanged` strictly true, equal initial/final CS:IP, request/response address and length agreement, byte count and hex), computes the reference file's SHA-256 from the bytes actually read, requires the whole extent to fit, and never modifies either input (`ddt.memory-reference-comparison.v1`, with bounded per-byte differences carrying both relative and reference-file offsets).

Its provenance is three-way by construction: **verified** — whether the two supplied byte sequences are equal or different; **operator assertion** — that those ranges are *intended* to correspond; **not established** — executable identity, load history, that the observed region executed as those instructions, unpacking causality, or any source-file mapping into the packed executable. A relocation-induced difference is reported literally and never "corrected" by nudging the offset.

`ddt debugger capture-step-memory --segment 0x0813 --offset 0x0200 --length 16` reads a bounded RAM region, executes **exactly one** DOS instruction, reads the identical region again and reports `ddt.dosbox-step-memory.v2`: the before/after bytes, each changed byte (`relative_offset`, `address`, `before`, `after`), the register differences, the synchronous STEPIN response and the raw exchanges. It needs a debugger-enabled build advertising **both** `MEMREAD` and `STEPIN` (both optional DOSBox-X capabilities) and a debugger already stopped at the intended instruction — start the program with `DEBUGBOX`; DDT never launches the program, sets breakpoints or resumes execution. `--segment`/`--offset`/`--length` are the **region to observe**, an explicit runtime address rather than an instruction address: supply it from the observed registers (for a `DS`-relative instruction, use the observed `DS`), because DDT does not assume the region belongs to `CS`, `DS` or `SS`. Everything happens on one connection as a fixed sequence (capability check → registers → read → registers → one `STEPIN` → registers → read → registers).

The record states what is actually established and no more: `resume_requested` is `false` (no `RUN`/resume was issued), `stepin_acknowledged` records that `STEPIN` returned an acknowledged response, and `paused_state` stays `unknown` because the protocol has no stopped-state query — a stable CS:IP is a consistency observation, not proof that the debugger is internally stopped.

The evidence rules are explicit in the record: a changed byte shows the observed RAM differed between the two reads, **not** that the stepped instruction was the only possible cause; zero changed bytes means no difference was seen *inside the selected region*, not that the instruction wrote nothing elsewhere; register observations cover only the registers DDT reads; and a stable CS:IP across the reads is a consistency check, not proof of the debugger's internal state. A failed read after the step is reported as *uncertain* — the guest instruction may already have executed, and DDT never retries, undoes or resumes it.

## Distribution builds

GitHub Actions `.github/workflows/build.yml` runs the tests and produces PyInstaller `onedir` artifacts on Ubuntu and Windows using native runners. A Windows executable must be built **on a Windows runner**; no Windows binary is included in this source tree. Local build commands are documented in the blueprint.

## Safety and limits

The tools never modify original files, do not infer runtime behavior from static layout, and never claim that an MZ load-module offset is an observed runtime segment:offset address. COM files are headerless and must be requested explicitly. The per-file processing limit is 64 MiB. No proprietary binaries or save files are included.

**Read-only guarantees versus runtime effects.** DDT never modifies original executables, and never writes to saved Ghidra analysis projects — inspection, identification, diff/manifest and comparison commands are read-only, as are `MEMREAD`/`capture-memory` (they observe guest RAM without writing anything). DDT never writes guest memory, guest-drive files or host files through the debugger.

Guest **execution** is a separate matter, and execution control is per command:

- `capture-memory` and `capture-step-memory`: issue neither `RUN` nor `BREAK` (they require the debugger to be stopped already, and `capture-step-memory` executes exactly one instruction via `STEPIN`).
- `capture-steps`: issues no `RUN` unless `--resume` is given; `STEPIN` executes guest instructions, so stepping changes guest runtime state.
- `capture-cpu`: issues `BREAK` to stop the guest, then `RUN` to resume it (or leaves it stopped with `--leave-paused`).
- `capture-breakpoint`: installs one breakpoint, issues `RUN` to reach it, deletes its own breakpoint and resumes unless `--leave-paused` is given — letting the guest run is itself a change to guest runtime state, and its "hit" is an observed stop, not a verified breakpoint event.

`STEPIN`/`capture-steps`/`capture-step-memory` are therefore the deliberate exceptions to DDT's read-only stance: they **execute guest instructions and change guest runtime state**, while memory reads remain pure observations.

## Project direction: DOS format support

DDT's long-term goal is to explain **executable structures and the runtime evidence that can be tied back to them** across several DOS formats and execution environments. Support is added incrementally, and only for formats backed by real, independently verified fixtures — never from a specification alone.

**Supported today**

- Headerless **COM**: inspection, explicit original-file offsets, runtime address correlation (verified end-to-end).
- Conventional real-mode DOS **MZ**: header/relocation/overlay inspection, source-offset mapping, runtime correlation (verified end-to-end).
- **Runtime observation** (optional, debugger-enabled DOSBox-X builds): bounded conventional-RAM reads, single-instruction stepping, one-instruction memory-change observation, and single-breakpoint capture — within the supported real-mode debugger environment.
- **LE** (linear executable) DOS-extender containers: layout validation, object-table and page-map parsing with `ddt le-header`, bounded original-file page extraction with `ddt le-bytes`, and encoded fixup-record inspection with `ddt le-fixups` — one genuine OpenWatcom/DOS-4GW fixture, no loading, relocation or execution.
- **Other containers** (NE, LX, PE, embedded COFF, packer markers): conservative **identification only**; DDT never claims to load or analyze them.

**Planned investigation areas** — explicitly *not* implemented:

- Packed COM/MZ executables (packer identity, stub entry, unpacking handoff).
- Overlay-based DOS programs.
- **LX** containers, other DOS extenders, and protected-mode execution — including any runtime observation of extended memory, which the real-mode debugger interface cannot reach.
- Any further format, when a real example justifies the work.

Each format advances through the same incremental stages — **identification → structural parsing → byte extraction → address mapping → runtime correlation** — and not every format needs every stage immediately. Nothing in the list above is implemented until a command exists and has been verified against a genuine fixture.

**Architecture principle.** Keep the evidence-processing core (hashing, manifests, bounded byte comparison, memory/correlation records) format-independent wherever that is genuinely possible, and let format-specific code supply only the structure and mapping facts needed to interpret a file. Never assume that bytes in a packed or compressed executable map directly to the instructions produced after decompression: a runtime instruction may correspond to the original program while having **no direct source-file offset in the packed file**. No plugin architecture is introduced before real implementations justify it.
