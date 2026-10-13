# DOS Disassembly Tooling (DDT)

Cross-platform, read-only foundations for reverse engineering 16-bit DOS applications. Linux and Windows use one Python source tree. **This bootstrap is not a full disassembler or a source port of CEO.** Ghidra and emulator adapters are planned and must be scavenged/adapted only after auditing the actual CEO checkout.

## Implemented now

- Strict DOS MZ header/relocation/overlay inventory (no execution)
- Explicit headerless COM recognition and offset layout
- File-offset mapping for **module-relative** segment:offset coordinates, distinct from unknown runtime segments
- File/directory SHA-256 manifests
- Binary file/directory comparison with exact differing spans, bounded hexadecimal previews and exact run counts
- Versioned JSON output and nonzero error exit
- Native Linux and Windows packaging workflow using native runners

## Installation and usage

```sh
python -m pip install -e .
ddt inspect GAME.EXE --json
ddt inspect GAME.COM --format com --json
ddt address GAME.EXE --segment 0x1234 --offset 0x100 --json
ddt diff before/ after/ --json
ddt manifest before/ --json
python -m pytest -q
```

See [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the full extraction and roadmap, including the original CEO components proposed for **read-only audit** and later portable adaptation.

## Distribution builds

GitHub Actions `.github/workflows/build.yml` executes tests and produces PyInstaller `onedir` artifacts separately on Ubuntu and Windows. A Windows executable must be built **on a Windows runner**; no Windows binary is included in this source archive. Local commands are in the blueprint.

## Safety and limits

The tools do not change original files, infer recovered gameplay semantics, or claim that an MZ load module offset is an observed runtime segment address. COM files are headerless and must be requested explicitly. The initial per-file processing limit is 64 MiB. No genuine proprietary game binaries or save files are included.

## Scavenge safely from the CEO checkout

The starter contains **no imported CEO source** because that private checkout is not available to this session. On a machine that has it, begin with this non-mutating source inventory:

```sh
python migration/audit_ceo.py /absolute/path/to/CEO > ceo-source-audit.json
```

Follow [the bounded migration prompt](docs/MIGRATION_PROMPT.md) and [source provenance ledger](docs/PROVENANCE.md). Only migrate algorithms after inspecting their dependencies and proving generic correctness.
