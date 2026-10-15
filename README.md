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
- Static/runtime address correlation from original file offsets and an observed entry context
- Read-only export of one analyzed function from an existing Ghidra project (optional; Ghidra is not needed for any other command)
- Offline navigation over an exported function: direct callers/callees and memory readers/writers (no Ghidra required)
- Read-only identification of DOS containers, embedded signatures and packaging markers
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

`ddt debugger capture-steps --count 2` steps an already-stopped program one guest instruction at a time and reports `ddt.dosbox-steps.v1` with the initial/last register state, each step's observed register differences, and the raw debugger responses. **`STEPIN` is an optional DOSBox-X capability**: upstream DOSBox-X 2026.10.01 does not include it, and the existing `capture-cpu`/`capture-breakpoint` commands do not require it. DDT checks support from the debugger's non-executing `EXEC HELP` output and refuses with a clear message when a build does not advertise `STEPIN` — it never executes an instruction to discover capability. The program must already be stopped at the intended instruction (start it with `DEBUGBOX`, or break in first); DDT never issues `BREAK` to establish a starting point. Stepping *changes guest execution state*, and DDT leaves the debugger stopped afterwards unless `--resume` is given (whose `RUN` acknowledgement is recorded but is not proof that execution resumed). A step may be a jump, call or interrupt, so CS:IP can move non-sequentially and an `INT` may enter a handler; register values are runtime observations, never Ghidra addresses or file offsets. The experimental emulator patch that adds `STEPIN` is separate from DDT and is not upstream (see the accompanying patch/PR draft).

`ddt debugger capture-memory --segment 0x0813 --offset 0x0103 --length 3` reads 1–256 bytes of **actual guest RAM** from an already-stopped debugger and reports `ddt.dosbox-memory.v1` (address, requested length, exact hex bytes, initial/final CS:IP, and the raw `MEMREAD` response). **`MEMREAD` is an optional, experimental DOSBox-X capability** — upstream DOSBox-X 2026.10.01 does not include it (the local patch is not upstream, unlike the STEPIN contribution). Support is detected from the non-executing `EXEC HELP` output; an unreadable byte fails the whole request rather than becoming a fabricated zero. Only real-mode conventional RAM below `A0000h` is read, in a single bounded request, and DDT never issues `BREAK`/`RUN`/`STEPIN` or writes memory.

`ddt memory compare --correlation correlation.json --observation memory.json --binary PROGRAM.COM` compares three byte sources for one instruction: the **original executable**, **Ghidra's recorded memory bytes** (from the correlation's instruction), and the **DOSBox-X observed runtime bytes**. It requires the binary's SHA-256 to match the correlation, the observation to cover exactly the correlation's derived address and length (segment aliases are rejected, not treated as equivalent), and valid hex of the expected length; for MZ it also reports any relocation word overlapping the instruction extent. The result (`ddt.memory-comparison.v1`) reports `runtime_equals_original`, `runtime_equals_ghidra` and `ghidra_equals_original`, a bounded list of differing byte positions, and explicit uncertainty — **evidence, never an inferred cause** (relocations, loader activity or runtime modification can all explain a difference).

`ddt memory compare-reference --observation memory.json --reference-binary ORIG.EXE --reference-offset 64` is the offline companion for cases where no static correlation can exist — code produced by **unpacking** has no source-file offset in the packed file. The comparison length comes from the observation (1–256 bytes) and `--reference-offset` is an **operator-supplied original-file byte offset**, not a runtime address and not a mapping DDT derives. The receipt validates the observation rigorously (schema, `read_success`/`cs_ip_unchanged` strictly true, equal initial/final CS:IP, request/response address and length agreement, byte count and hex), computes the reference file's SHA-256 from the bytes actually read, requires the whole extent to fit, and never modifies either input (`ddt.memory-reference-comparison.v1`, with bounded per-byte differences carrying both relative and reference-file offsets).

Its provenance is three-way by construction: **verified** — whether the two supplied byte sequences are equal or different; **operator assertion** — that those ranges are *intended* to correspond; **not established** — executable identity, load history, that the observed region executed as those instructions, unpacking causality, or any source-file mapping into the packed executable. A relocation-induced difference is reported literally and never "corrected" by nudging the offset.

`ddt debugger capture-step-memory --segment 0x0813 --offset 0x0200 --length 16` reads a bounded RAM region, executes **exactly one** DOS instruction, reads the identical region again and reports `ddt.dosbox-step-memory.v2`: the before/after bytes, each changed byte (`relative_offset`, `address`, `before`, `after`), the register differences, the synchronous STEPIN response and the raw exchanges. It needs a debugger-enabled build advertising **both** `MEMREAD` and `STEPIN` (the two experimental capabilities) and a debugger already stopped at the intended instruction — start the program with `DEBUGBOX`; DDT never launches the program, sets breakpoints or resumes execution. `--segment`/`--offset`/`--length` are the **region to observe**, an explicit runtime address rather than an instruction address: supply it from the observed registers (for a `DS`-relative instruction, use the observed `DS`), because DDT does not assume the region belongs to `CS`, `DS` or `SS`. Everything happens on one connection as a fixed sequence (capability check → registers → read → registers → one `STEPIN` → registers → read → registers).

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
- **Other containers** (NE/LE/LX/PE, embedded COFF, packer markers): conservative **identification only**; DDT never claims to load or analyze them.

**Planned investigation areas** — explicitly *not* implemented:

- Packed COM/MZ executables (packer identity, stub entry, unpacking handoff).
- Overlay-based DOS programs.
- DOS extenders and protected-mode executables, and the LE/LX containers they use.
- Any further format, when a real example justifies the work.

Each format advances through the same incremental stages — **identification → structural parsing → byte extraction → address mapping → runtime correlation** — and not every format needs every stage immediately. Nothing in the list above is implemented until a command exists and has been verified against a genuine fixture.

**Architecture principle.** Keep the evidence-processing core (hashing, manifests, bounded byte comparison, memory/correlation records) format-independent wherever that is genuinely possible, and let format-specific code supply only the structure and mapping facts needed to interpret a file. Never assume that bytes in a packed or compressed executable map directly to the instructions produced after decompression: a runtime instruction may correspond to the original program while having **no direct source-file offset in the packed file**. No plugin architecture is introduced before real implementations justify it.
