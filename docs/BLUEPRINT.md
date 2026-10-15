# DOS Disassembly Tooling (DDT)

**Project:** Standalone, cross-platform toolkit for reverse engineering 16-bit DOS programs.  
**Platforms:** Linux x86-64 and Windows x86-64 as first-class builds.  
**Design:** Ghidra-compatible, offline-first, read-only by default; reuse proven techniques from the CEO reconstruction project, but include no CEO-specific logic or files.  
**Status:** Generic design and bootstrap source. **No source has yet been copied out of CEO.** Direct access to the CEO source checkout is unavailable from this environment; the harvest must be performed by an agent with local access to that checkout. Do not confuse the bootstrap with a fully featured disassembler.

## 1. The product, not another agent framework

DDT should answer practical reverse-engineering questions with a short command and auditable output:

- What exactly is this DOS executable (MZ, COM, not a DOS binary)? How is it laid out, relocated, and mapped to original file offsets?
- Which instruction(s) read or write an address or data field, and which call paths are known to reach them?
- What changed between two binary artifacts or whole captured directories, and which changes are unrelated to the suspected behavior?
- What evidence supports the result, which binary/analysis state produced it, and what remains unknown?
- Can I reuse existing Ghidra analyses and original-program captures without repeatedly regenerating them?

The core remains a Python command-line application with a versioned JSON interface. Ghidra and DOSBox-X are optional integrations, *not* dependencies for basic inspection or binary comparison. No Node.js, REA, always-on MCP server, database server, custom emulator, or mandatory GUI.

### Out of scope in the first two releases

Source-level decompilation of an entire program; DOS game simulation; automatic game GUI manipulation; patching originals; invented symbolic meaning for state fields; automatic discovery of all indirect calls; unpacking every DOS packer; protected-mode DOS extenders and their runtime; loading, relocating or executing NE/LX/PE images or an LE load module (only the validated LE header, object table and page map are parsed); full 8086 emulation; use of CEO data files as generic test fixtures.

## 2. Architecture

```text
                       original binary / data / captures (immutable)
                                       |
                             ddt core (Python)
                   +-------------------+------------------+
                   |                   |                  |
           MZ/COM inventory     address mapping      byte/dir diff
                   |                   |                  |
                   +-------------------+------------------+
                                       |
                              provenance-backed JSON
                                       |
          +----------------------------+---------------------------+
          |                            |                           |
  optional Ghidra export       optional evidence index     optional capture intake
  via an existing project       (derived/read-only)         (human operates game)
          |                            |                           |
  resolved xrefs/CFG/SSA       query known facts by         hash + validate
  bounded dependency slice    address/artifact SHA         original outputs
```

**Layer boundary:** Core code has no imports from Ghidra, project paths, or game plugins. Ghidra export scripts run in Ghidra and return a documented JSON format; DDT consumes those exports. Existing analyst names and annotations in a saved Ghidra project must remain reusable. No silent creation of a fresh database that discards accumulated analysis.

### Proposed CLI (only `inspect`, `address`, `diff`, `manifest`, `version` are implemented in the starter)

```text
ddt inspect target.exe --json
ddt inspect target.com --format com --json
ddt address target.exe --segment 0x1234 --offset 0x00A0 --json
ddt diff ./pre ./post --json
ddt manifest ./fixtures --json

# Planned only, after harvest and provider audit:
ddt ghidra export --project <path> --binary <name> --out analysis.json
ddt code writers --export analysis.json --address 0x12340 --json
ddt code callers --export analysis.json --procedure 0x12340 --depth 2 --json
ddt code slice --export analysis.json --at 0x12340 --direction backward --json
ddt evidence find --address 0x12340 --index evidence.json --json
ddt capture intake --before ./captureA --after ./captureB --receipt receipt.json --json
```

Do not promise that the future `writers` search is exhaustive: computed pointers, indirect calls, segment aliases, and dynamic code can remain undiscovered.

## 3. Scavenging plan: CEO source audit, then selective port

**Source checkout:** `MnHebi/Total-Recompilation` / the user's working CEO checkout. GitHub app access could not read the repository, so all entries below are *audit candidates*, not assertions that the current code is portable. The extracting agent must inspect current files, ownership and imports before copying. Prefer small function-level ports rather than dragging in modules or their dependency graphs.

| CEO candidate (inspect exact current file) | Potentially portable value | Required genericization | Do not copy |
|---|---|---|---|
| `replacement/src/ceo_state/compare.py` | ByteRun comparison, retained offsets, missing/changed artifacts | Arbitrary paths/files, bounded diff output, no save-family assumptions | CI/CE/CJ layouts, scenario-specific assertions |
| `replacement/src/ceo_state/loader.py`, `model.py` | Immutable snapshots, read-only bytes, provenance | Generic directory/artifact snapshot; no fixed SAV convention | CEO save-slot profiles and family catalog |
| `analysis/scripts/structured_analysis.py` | Binary inventory, offsets, bulk repeatable analysis | Accept explicit original binary/load profile; split only reusable functions | CEO-specific address constants |
| `analysis/scripts/phase17-1-cartography.py` | Instruction boundary/call-target census, unresolved-edge tracking | Export target-neutral function/edge records; keep confidence and search bounds | Hardcoded CEO tables/identifiers |
| `analysis/state/state-memory-map.json`, `analysis/state/cj-alias-dataflow.json` | Examples of useful evidence shape, alias/segment discipline | Design reference for schemas; not source-of-truth code | Recovered CEO semantics or state data |
| `analysis/scripts/phase18_3_packet.py`, `phase18_4_packet.py`, `phase18_5_packet.py` | Deterministic receipts, hashing, manifest construction | Generic manifest generator; use a single implementation | Historical phase gates and packet naming |
| `replacement/src/ceo_resources/text.py` | Possibly reusable CP437 decoding and raw/decoded separation | Small pure encoding helper, only if no stdlib equivalent suffices | CEO message-bank layouts |
| Existing DOSBox-X launch and capture scripts | Session preflight, artifact intake, watcher/logging | Configurable executable/working directory/capture paths | GUI scripts tied to CEO menus/save slots |
| Independently reconstructed SSA/proof tools from `analysis/` | Optional bounded slicing and unresolved-dependency reporting | Only extract if a reproducible generic interface exists | Solvers and proof pipelines coupled to CEO milestone semantics |

**Explicitly exclude:** `ceo_state.transitions`, `ceo_scenario`, scenario parsers, save profile names, gameplay semantics, original assets, licensed binaries, captured saves, raw decompilation listings, frozen milestone packets, `.opencode/agents/`, and project-specific evidence acceptance bureaucracy. Transfer reusable algorithms and the *principle* of independent verification; do not transplant the CEO project's lifecycle.

### Mandatory extraction discipline

1. Inventory exact current CEO source paths, imports, license/ownership and tests; record file hashes and last known validation status. **No changes to CEO.**
2. For each candidate, mark `reusable verbatim`, `extract function`, `adapt`, `reference-only`, or `reject`, with reason.
3. Port one narrow implementation into DDT; retain an origin comment or `docs/PROVENANCE.md` entry identifying CEO path/hash and changes. Never import CEO modules from DDT at runtime.
4. Make test fixtures synthetically, or use explicitly redistributable independent samples. No CEO IP or accepted fixtures in public releases.
5. Write focused tests before declaring the generic port equivalent; compare original and port outputs on **authorized, locally retained** regression inputs, without shipping those inputs.
6. Do not copy entire historical tests or multi-agent acceptance processes merely to preserve test totals.
7. Stage porting and verification in the new DDT tree only. Do not patch original binaries or the CEO checkout.

## 4. DOS correctness contract

### MZ format

Validate `MZ`/`ZM`, DOS header length (`e_cparhdr * 16`), relocation table bounds (`e_lfarlc`, `e_crlc`), declared file size (`e_cp`, `e_cblp`), module size, and potential overlay. Report the segment-relative relocation entries and their original-image locations. Detect known `NE`, `LE`, `LX`, `PE` new executable signatures when the `e_lfanew` field points to one; reject rather than treating them as DOS MZ payloads.

Do not confuse (a) original file offset, (b) offset within loaded MZ module, (c) Ghidra image-base-dependent address, or (d) runtime segmented `CS:IP` / `DS:offset`. Relocation modifies loaded words, not immutable original file bytes. DOS loader choices, wraparound, overlays, and uninitialized memory must remain explicit. Relative MZ module address mapping is deterministic; actual runtime segment mappings require observed or caller-provided segment context. File offsets for addresses in BSS, gaps, PSP, or overlays must not be fabricated.

### COM format

COM is *headerless*; it must be selected explicitly (`--format com`). Load file bytes at offset `0x100` within a single DOS segment for nominal layout, while PSP content and actual runtime segment value remain unknown without a runtime observation. Limit initialized COM content to 65,280 bytes.

### Ghidra export

Prefer extraction from the user's existing saved project, not reimport. For each supported function/edge export, keep provider identity, project/binary hash, language/context, source image map, literal instruction bytes, defined function-body ranges (which can be non-contiguous), direct vs computed references, recovered variables/defs, and any truncated/unresolved information. Decompiler P-code is an observation, not proof of runtime meaning. Only build optional one-function backward slicing after a real use case validates it is useful.

## 5. Build and supported platforms

**Shared source:** Python 3.12+ portable stdlib core; `pyproject.toml` for source/wheel install. Dependency-free core features should work equally on Linux and Windows. Optional extra packages only for features that need them.

**Binary distributions:** Use PyInstaller **on native OS runners** (Linux generates a Linux executable, Windows generates an `.exe`). Ship an onedir distribution (easier to debug and distribute dependent files) inside a platform-specific ZIP. Do not assume cross-compiling Windows executables from Linux works. Ship core functionality without bundling Ghidra, Java, DOSBox-X, copyrighted games, or unrelated runtime engines.

**Continuous integration:** matrix of Ubuntu x86-64 and Windows x86-64. On both: install, lint if configured, run the *same* synthetic-fixture unit tests, smoke-test command help/inspection/diff, package wheel, freeze native executable, run its smoke test, upload platform artifact. Release names:

```text
DDT-<version>-linux-x86_64.zip
DDT-<version>-windows-x86_64.zip
DDT-<version>-py3-none-any.whl
```

The starter source archive includes a GitHub Actions workflow using both OS runners. It has **not** produced a Windows executable in this environment; verify that in CI before calling the binary release ready.

### Local developer commands

Linux:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
python -m PyInstaller --clean --noconfirm --onedir --name ddt packaging/launcher.py
./dist/ddt/ddt --version
```

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python -m pytest -q
python -m PyInstaller --clean --noconfirm --onedir --name ddt packaging/launcher.py
.\dist\ddt\ddt.exe --version
```

The shared interface must use `pathlib` and `subprocess` argument arrays, not shell-dependent paths/quoting. Ghidra integration later resolves `analyzeHeadless` (`.bat` versus POSIX script) without global environment modifications. No full OS VM required for standard tests; emulator tests optional, opt-in, and machine-specific.

## 6. Proposed incremental milestones

**M0: Baseline and portable bootstrap.** Establish independent DDT project, source package, cross-platform CI, synthetic MZ/COM/address/diff tests and end-to-end CLI smoke. The accompanying starter zip provides an initial M0 implementation. No CEO source copied yet.

**M1: Harvest and prove portability.** In the actual CEO checkout, audit the candidate table, port the first broadly useful and independently testable algorithm (likely ByteRun comparison or address mapping), and record provenance. Reject code whose extraction adds more dependencies than value. Ensure all generic tests run on both OS targets.

**M2: Ghidra export from existing projects.** Produce a minimal read-only export for one defined function and its references. Verify segmented/file coordinates and source hashes against an independent parser/known fixture. Avoid replacing the Ghidra project, mutating names, or shipping Ghidra.

**M3: Static code navigator.** Build a compact index and bounded `writers`, `readers`, `callers`, `dossier` queries. Require explicit `unknown` for unresolved indirect references and aliases; no exhaustive claims from direct xrefs.

**M4: Human-driven runtime capture intake.** Generic prepare/receipt/intake of two directory snapshots. Agent launches the environment and requests clearly specified *human* game actions; does not automate fragile UI. Original filesystem evidence remains immutable.

**M5: Evidence-cache / optional slicing / selective trace.** Add only when actual use cases justify them. No mandatory graph database or MCP. P-code slicing should first try existing CEO SSA code and test whether extracting it is cheaper than a small new script.

Every milestone uses focused tests during implementation; execute platform test suites on CI once a change is stable. Do not rerun old CEO milestones or restore their review pipeline.

## 7. What constitutes success

- One source tree builds and runs natively on both Windows and Linux, with equivalent canonical JSON for the same fixture.
- Basic inspection, segmented address mapping, and file/directory diffs work with **no Ghidra or emulator installed**.
- Ghidra export (once implemented) preserves the user's saved project analysis and original byte provenance.
- Changed or malformed input fails conservatively rather than returning credible-looking wrong offsets.
- Indexed answers are short, source-addressable, and admit unresolved edges and coverage limits.
- Ported CEO functionality has independently demonstrated equivalence on locally authorized tests; source ownership is recorded.
- Agent work decreases through fewer navigation/polling calls and reduced repeated parsing. Measure calls/tokens on the same tasks, not artifact count.

## 8. Handoff prompt for Codex / DeepSeek in the actual source checkout

> Establish a new standalone repository **DOS Disassembly Tooling (DDT)** supporting native Linux x86-64 and Windows x86-64 builds. Read `DOS_Disassembly_Tooling_Blueprint.md` and the starter source archive, then inventory the current CEO project (`MnHebi/Total-Recompilation` or my local checkout) **read-only**. CEO is a *source of proven reusable algorithms*, not an application dependency. Do not install REA or rewrite any CEO code/evidence. For each candidate in the blueprint's scavenging table, cite the exact source path, APIs, dependencies, SHA-256, verdict (`verbatim`/`extract`/`adapt`/`reference-only`/`reject`), and why it is or isn't generic. Reuse only narrow algorithms with a measurable benefit; start with the existing ByteRun comparison or another low-coupling primitive. Write generic interfaces and synthetic fixtures, preserve binary provenance and segment:offset semantics, avoid importing CEO names/formats/gameplay, and record ports in `docs/PROVENANCE.md`. Keep DDT's Python core independent of Ghidra/DOSBox-X; plan read-only Ghidra export from an **existing** project as a later adapter. Configure **real Linux and Windows native build jobs**, run focused tests, and verify executable smoke tests on both platforms in CI. Avoid model-driven polling and speculative refactoring; minimize tool calls. Report direct verification separately from inherited claims. Stop after a bounded M1 port and a migration audit; do not expand the feature set without a concrete use case.

## 9. Source references

- Original acceleration concept: `CEO_RE_acceleration_blueprint.md` (design input only).
- CEO project: `MnHebi/Total-Recompilation` (not available to this session's GitHub connector).
- REA's DOS-MZ/Ghidra guide (feature reference, not implementation dependency): https://github.com/morluto/rea/blob/main/docs/ghidra-dos.md
- Ghidra scripting: https://github.com/NationalSecurityAgency/ghidra
- DOSBox-X: https://github.com/joncampbell123/dosbox-x
