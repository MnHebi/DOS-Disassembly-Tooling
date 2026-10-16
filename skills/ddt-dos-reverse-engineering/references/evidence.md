# Interpreting DDT evidence

Every DDT receipt separates **what was measured** from **what it means**. Read the
`limits`, `checks`, `verified` and `not_established` fields literally, and carry the
input's SHA-256 into any conclusion.

## Four address kinds

| Kind | Produced by | Means |
| --- | --- | --- |
| Original-file offset | `strings`, `diff`, `le-*`, `ghidra export` | A byte position in the file you hashed |
| Module-relative `seg:off` | `inspect`, `address` | An offset inside the MZ load module, or a COM image offset - still not runtime |
| Ghidra address | `ghidra export`, `code *` | An address in the analyzer's address space for that program |
| Runtime `segment:offset` | `debugger *`, `correlate` | A real-mode address; observed only if a capture reported it, otherwise derived |

Never convert one into another silently. `ddt address` maps module-relative to file
offset and says so; `ddt correlate` derives a *candidate* runtime address and requires
the observed entry context from a real capture.

## COM and MZ

- A COM file is headerless; only select `--format com` when the operator says so. Its
  runtime segment and PSP are not observed.
- MZ relocation entries are reported as locations; DDT never applies them. A byte in
  the file is pre-relocation content.
- An appended region is not automatically an overlay of code; `identify` reports it as
  a region with an unknown purpose unless a recognised structure begins there.
- When the MZ declared image ends and trailing bytes follow, do not assume those bytes
  are loaded.

## LE containers (DOS extenders)

Keep these distinct, because they are routinely conflated:

- **Object-relative offset** - an index into one object's virtual extent.
- **Logical page index** - the module's page sequence, used by `le-fixups --page` and
  the fixup page table.
- **Physical file page number** - which page in the file's data-page area stores the
  content; a page's `file_bytes` may be shorter than the page size for the final page.
- **Original-file offset** - `data_pages_offset + (page - 1) * page_size + (offset mod
  page_size)`, reported as `file_offset` / `source_file_offset`.
- **Runtime address** - a protected-mode selector plus offset. DDT cannot observe it;
  it never equates it with any file offset.

Only an ordinary `valid`, file-backed page yields bytes. `iterated`, `invalid`,
`zeroed`, `range`, `compressed` and `m3-packed` pages keep their raw page number and
flags with no file offset, because their contents are not a direct file image.

### Fixup records

A fixup record is the executable's **request to a loader**. It is not a change that
was observed, and DDT never computes the value a loader would write.

- The record's own `file_offset` locates the *record*; `source_file_offset` locates the
  bytes the loader would modify. Do not confuse them.
- `source_offset` is signed; a negative value begins in the preceding logical page.
  `source_contiguous_bytes` says how many consecutive file-backed bytes really follow
  it inside the same object, so a multi-byte read from `source_file_offset` is only
  safe up to that count.
- `internal` records name a target object and target offset. `import_ordinal` records
  name a module (resolved from the import module name table) and an ordinal; the
  imported **symbol name lives in the other module** and the loader decides its
  address. Report the ordinal, not a guessed name or address.
- Decoded today: internal references and import-by-ordinal. Everything else - the
  `import-name` and `internal-via-entry` target types, the `alias-source` and list
  source flags, and the `additive-value`, `internal-chain`, `32-bit-additive` and
  (for internal references) `8-bit-ordinal` target flags - stops the scan and is
  reported as an `undecoded` range with a reason. Say so explicitly; do not estimate
  how long such a record is or what it contains.
- The declared fixup-section size is reported but not used for bounds; the fixup page
  table's final entry bounds the record table.

## Packed executables

Three identities must stay separate: the **original unpacked** program, the **packed
file**, and the **runtime image**. A runtime instruction may match the original
program while having no source-file offset in the packed file at all.

- Do not assign compressed-file offsets to decompressed instructions.
- Signature matches (UPX, LZEXE, ...) are candidates, never proof of the packer or of
  the decompressed layout.
- `memory compare-reference` is the right tool when an operator supplies the intended
  correspondence between an observed region and a reference file range. The receipt
  records that correspondence as `operator_supplied`; it does not establish executable
  identity, load history, or that unpacking caused a difference.

## Runtime captures

- A capture reports only what was read, at the address it names, at that moment.
  A stable `CS:IP` is a consistency observation, not proof that the debugger is
  internally paused.
- `capture-steps` and `capture-step-memory` **execute guest instructions**, which
  changes guest state. `capture-cpu` and `capture-breakpoint` issue `BREAK`/`RUN`.
  `capture-memory` and `capture-step-memory` issue neither `RUN` nor `BREAK`.
- `MEMREAD` reads ordinary real-mode conventional RAM below `A0000h` only. Protected-mode
  application memory, selectors and extended memory are **not** reachable through it;
  do not assume a 32-bit DOS-extender image can be observed this way.
- A breakpoint "hit" is an observed stop at an address, not a verified breakpoint event.
- Receipts record the session they came from. Two receipts are not proof of one
  session, and byte equality is not proof of load history.

## Ghidra

Prefer exporting one function from an existing saved project. Re-importing a binary
discards accumulated annotations and is not DDT's job. A disassembler's
interpretation, xref, or pattern match is evidence for investigation, never proof of
runtime meaning; indirect calls, aliases and external effects stay unresolved.

## What a result proves, and what it does not

| Result | Proves | Does not prove |
| --- | --- | --- |
| Matching SHA-256 | The bytes you analyzed are those bytes | The file is the program that ran |
| `identify` `identified` | A documented structure validated | The image loads, unpacks or runs |
| `address` / `correlate` output | A derivation from stated premises | Observed runtime behaviour |
| `le-bytes` bytes | Original-file content at that offset | The loaded or relocated image |
| `le-fixups` record | The loader request encoded in the file | That the loader applied it, or to what |
| `memory compare*` equality | The compared sequences are equal | Identity, causality, or a source-file mapping |

## Boundaries to state in conclusions

DDT is not a disassembler, not a loader, not an emulator, and not a debugger. It
inspects structure, maps offsets, extracts bounded bytes and records observations that
other tools produced. When a question needs protection-mode execution, a general
unpacker, or whole-program analysis, say that DDT does not answer it and stop - do not
extrapolate from static bytes.
