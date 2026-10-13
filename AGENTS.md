# AGENTS.md — DOS Disassembly Tooling (DDT)

Instructions for coding agents working in this repository, including DeepSeek. These rules apply to the entire project unless a more specific `AGENTS.md` explicitly overrides them.

## Mission and scope

Build a **small, reliable, cross-platform toolkit for examining 16-bit DOS software**. One source tree must work on Linux x86-64 and Windows x86-64. Keep the core usable without Ghidra, DOSBox-X, network access, or an AI agent.

The current code is a **bootstrap**, not a complete disassembler. Check `README.md`, `docs/BLUEPRINT.md`, and the actual implementation before claiming a feature exists. Treat CEO as a possible source of reusable algorithms, never as a runtime dependency.

## Engineering principles (in priority order)

1. **Correctness and evidence first.** Never invent a binary fact, address, runtime behavior, test result, or platform verification.
2. **YAGNI.** Implement only what the current task requires. Do not build speculative extensibility, generic engines, new layers, or convenience features for imagined future use.
3. **Prefer the simplest working solution.** Reuse an existing function before adding another. Prefer a clear one-liner for genuinely trivial operations; use readable explicit code for parsing, validation, state, and error handling. Fewer lines are not a substitute for clarity.
4. **Avoid new dependencies.** Prefer the standard library and existing tools. Add a dependency only for a demonstrated need that cannot reasonably be met by the current stack.
5. **Make small, local changes.** No unrelated refactors, renames, API churn, formatting sweeps, or wholesale rewrites. Do not modify files merely because they could be improved.
6. **Don't duplicate infrastructure.** No REA, mandatory MCP server, database/service, custom emulator, new agent framework, or general-purpose P-code engine without an explicitly approved use case.
7. **Preserve compatibility.** Keep CLI behavior and versioned JSON contracts stable unless a task deliberately changes them; document intentional breaking changes.

When two implementations are equally correct, choose the one with fewer moving parts and lower maintenance cost.

## Work procedure

1. Read the request and inspect only the relevant project paths. Determine what is already implemented before proposing additions.
2. State the smallest intended change and any genuine blocker. Do not turn a narrow task into a roadmap.
3. Edit only the necessary files. Prefer extending existing modules and tests over creating new ones.
4. Run **focused checks** for affected behavior. Once the change is stable, run the required broader checks **once**, not after every minor edit. Re-run only checks invalidated by subsequent changes.
5. Report what changed, what was actually verified, what remains unverified, and any concrete blocker. Keep the report short.

Do not report planned tests as executed tests. A Linux run does **not** establish Windows compatibility; Windows support requires a Windows build and smoke test (and vice versa). CI configuration is not proof CI passed.

## Token, tool, and time efficiency

- Use targeted file reads and searches; avoid dumping large directories or repeatedly rereading unchanged sources.
- Batch related inspections when doing so doesn't hide failures or increase risk.
- Prefer one blocking command, process watcher, callback, or script to **model-driven polling**. Do not repeatedly call tools just to ask whether a build, emulator run, or test has finished.
- Use the agent harness's supported sleep/wait mechanism when available. Do not assume a `/sleep` command exists or invent configuration keys; otherwise use ordinary blocking execution or a small watcher.
- Avoid unnecessary agents, repeated independent reviews, elaborate status reports, and broad test matrices for a small change. Follow mandatory review checks when explicitly required by the task.
- Don't optimize for the fastest runtime if that increases tool calls or model usage without improving correctness.

## DOS analysis rules

- **Inputs are read-only by default.** Never patch executables, source evidence, fixtures, or captured outputs unless explicitly authorized. Mutation tests use isolated copies.
- Keep original file offsets, MZ module-relative offsets, load-image addresses, Ghidra addresses, and runtime `segment:offset` addresses distinct. Never silently equate them.
- Preserve relocation locations, overlay boundaries, unmapped regions, instruction bytes, and unknown data. Reject invalid or ambiguous mappings rather than guessing.
- COM files are headerless and must be identified explicitly. Do not mistake NE/LE/LX/PE binaries for ordinary DOS MZ targets.
- A disassembler's interpretation, P-code, direct xref, or pattern match is **evidence for investigation**, not proof of runtime meaning. Unresolved indirect calls, aliases, and external effects stay unresolved.
- Prefer extracting data from an **existing saved Ghidra project** when appropriate; do not discard accumulated annotations by reimporting a binary without reason. Ghidra and DOSBox-X remain optional adapters.
- Favor compact machine-readable results containing exact provenance, coverage, and uncertainty over verbose narratives or unsupported confidence labels.

## Reusing work from CEO

- Treat the CEO checkout as **read-only** unless the user separately authorizes CEO modifications. Never restart its historical milestones as part of DDT work.
- Audit source and imports before copying. Prefer one isolated algorithm over a subsystem. Generalize names and interfaces; remove game-specific assumptions.
- Record origin path/function, source hash, adaptation, equivalence check, and redistribution/licensing assessment in `docs/PROVENANCE.md`.
- Use synthetic or independently redistributable fixtures in DDT. Do not copy CEO executables, assets, proprietary save files, disassembly dumps, or private acceptance packets into this repository or releases.
- If the proposed port is more complicated than a fresh minimal implementation, explain the tradeoff and choose the simpler verified route.

## Cross-platform changes

- Use `pathlib`, explicit encodings, and `subprocess` argument lists; avoid shell-specific assumptions and platform-dependent path separators.
- Keep the same public commands and JSON semantics on Linux and Windows. Isolate genuine OS differences in small adapters.
- Build platform-native distributions **on their respective OS runners**. Do not claim cross-compilation or support based on an untested build workflow.
- Don't add Ghidra, Java, DOSBox-X, or proprietary application files to the core distribution.

## Tests and evidence

- Test the behavior being changed, especially malformed inputs, bounds, non-mutation, and address provenance when relevant.
- Use independently derived expected values (literal byte fixtures, a small independent reference, or original observations). Don't validate a parser solely against its own generated output.
- Favor a small synthetic fixture over full game sessions for ordinary unit tests. Emulator and GUI checks are opt-in unless the task specifically requires them.
- Never weaken or remove a failing assertion just to get green tests. Report genuine limitations and failures.
- Do not add a test harness, fixture generator, or abstraction whose maintenance costs exceed its value to the requested change.

## Git and commit messages

- Commit only changes within the requested scope and only when the task authorizes committing. Do not stage unrelated work or overwrite uncommitted user changes. Never force-push or rewrite history unless explicitly instructed.
- **Commit subjects describe what the commit does, not which files it touches.** Use one short imperative sentence, ideally no more than 72 characters.
- **No file-by-file commentary in commit messages.** A subject is normally enough. Add a body only when essential to explain a non-obvious reason, compatibility impact, or migration requirement; keep it brief and about behavior, not a file inventory.
- Avoid marketing language, progress logs, detailed test narration, and generic messages such as `Update files`, `Improve code`, or `Various fixes`.

Good:

```text
Validate relocation table bounds
Add read-only Ghidra function export
Preserve COM load offsets in address reports
Reuse byte-run comparison for directory diffs
```

Bad:

```text
Update format.py, cli.py, and test_format.py
Implement MZ parsing: changed header reader, added helpers, edited docs...
Enhance the overall reverse engineering architecture
```

## Definition of done

A task is finished when the **requested behavior** exists, focused validation supports it, source inputs remain protected, and limitations are stated plainly. Do not expand scope merely to make the change look more substantial. Favor a small completed improvement over an unfinished grand design.
