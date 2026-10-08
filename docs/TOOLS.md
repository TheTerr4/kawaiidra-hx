# Tools and commands

Locations accepted everywhere: `0x1805d0760`, `1805d0760`, `FUN_1805d0760` (any symbol), `va:0x...`,
`rva:0x5d0760`, `off:6094176` / `off:0x5CFD60` (**file** offset; decimal unless `0x`).
`project` = workspace name, path to a `.gpr`, or a folder containing one. `program` may be omitted when the project holds
exactly one program.

## MCP tools (`khx mcp`)

| Group | Tool | Purpose |
|---|---|---|
| Session | `session_status` | config, open projects/programs, jobs |
| | `list_projects`, `list_programs` | what exists |
| | `import_binary` | import + analyze as a background job (returns after `wait_seconds` with a job id if still running) |
| | `job_status`, `cancel_job` | follow or stop a job |
| Inspect | `program_info`, `memory_map`, `resolve` | summary, sections, address/offset description |
| | `decompile` (offset/limit paging), `disassemble` | code |
| | `xrefs_to`, `xrefs_from`, `callers`, `callees` | graph |
| | `find_strings`, `scan_instructions`, `find_symbols`, `find_bytes` | search (`scan_instructions` is whole-program, ~15 s on a 12 MB DLL) |
| | `read_bytes`, `pointer_table`, `data_at`, `rtti_classes` | data |
| | `query` | many commands in one call (see below) |
| Annotate | `rename`, `set_comment`, `save_program` | write mode; persisted only on save |
| PE / patch (no Ghidra) | `pe_identify`, `pe_sections`, `pe_imports`, `pe_exports` | identity (sha256, timestamp, entry point, patch id), headers, import/export tables |
| | `offset_to_va`, `va_to_offset` | header math for any PE on disk |
| | `patch_show`, `patch_verify`, `patch_apply`, `patch_make`, `patch_diff`, `branch_encode` | JSON patch files (memory, union, number, signature, group); `patch_apply` writes a copy |
| Signatures | `sig_make` (Ghidra), `sig_check` (no Ghidra) | synthesize version-independent `signature` entries for a binary's patch sites; resolve a signature file in any number of binaries |
| Inspect (no Ghidra) | `triage` | a first look at any binary: identity, sections and entropy, exports, imports by class, debug info, embedded URLs/paths/versions; non-PE files described too |
| Builds | `match_functions` (Ghidra) | match the functions of two analysed builds; the counterpart of an address, or a listing; fingerprints cached by file hash |
| | `match_carry_names` (Ghidra, write) | carry hand-set function names to the matching functions of another build (dry run by default; `clear=true` undoes); persist with `save_program` |
| | `port_patches` (Ghidra for the source) | carry a build's patches to another build's file: signature, window ladder, string anchor, optional function matching; nothing guessed |
| Annotate | `list_patch_sites`, `annotate_patch_sites` (Ghidra) | patch-file offsets -> VA -> function; label + bookmark + tagged comments at each site (dry run by default, `clear` undoes) |
| | `imports_resolve` (Ghidra) | name `Ordinal_N` imports from the export tables of the libraries shipped with the module (dry run by default, `restore` undoes) |

Large results are saved under `workspace/results/` and truncated inline with the file path.

## Query command language (`query` tool / `khx query -c ...`)

```
decomp <addr>   dis <addr> [n]   disf <addr>   func <addr>   xrefs <addr>   xfrom <addr>
callers <addr>  callees <addr>   str <text>    scan <text>   sym <text>     find <hex pattern>
bytes <addr> <n>   vt <addr> [n]   data <addr>   rtti [text]   info   sections   resolve <addr>
```
Output of each command is framed by `=========== <command> ===========`. `#` lines are ignored.

## CLI (`khx`)

```
khx doctor [--jvm]
khx pe sections|off2va|va2off|identify|exports|imports FILE ...
khx patch show JSON
khx patch verify FILE patches.json [--entry NAME]... [--ignore-identity]
khx patch apply  FILE patches.json -o OUT [--entry NAME]... [--set NAME=VALUE]... [--overwrite]
khx patch revert FILE patches.json -o OUT [--entry NAME]...
khx patch make FILE --name N --edit va:0x1805D0760=B863000000C3 [--game ABC --dll target.dll --pe-id ID] [-o entry.json | --append-to patches.json]
khx patch diff ORIGINAL MODIFIED --name N [--gap N --pad N] [-o entry.json | --append-to patches.json]
khx patch merge TARGET.json SOURCE.json [--replace]
khx patch branch --at 0x1805D091B --to 0x1805D0990 --op jmp|call|jnz|... [--short | --near]
khx sig make PROJECT PROGRAM PATCHFILE... [--binary FILE] [--only TEXT] [--max-bytes 48] [--min-fixed 12] [--no-usage] [-o OUT.json | --append-to FILE]
khx sig check SIGFILE.json FILE...                               # no JVM: unique / ambiguous / not found per binary
khx triage FILE...                                               # no JVM
khx imports show FILE [--libs DIR]... [--skip-regex RX]          # no JVM: what each ordinal import would be named
khx imports resolve PROJECT PROGRAM [--libs DIR]... [--skip-regex RX] [--binary FILE] [--restore] [--dry-run] [--no-save]
khx sites list|annotate|clear PROJECT PROGRAM [PATCHFILE...] [--only TEXT] [--binary FILE] [--force] [--dry-run] [--no-save]
khx match PROJECT SOURCE TARGET [--at ADDR]... [--list --limit N --only TEXT --named-only] [--json F] [--no-strings] [--refresh]
khx match PROJECT SOURCE TARGET --apply [--dry-run] [--no-rename] [--force] [--min-score 0.7] [--min-margin 0.05] [--no-save]   # names -> target; --clear undoes
khx port PROJECT SOURCE TARGET_FILE PATCHFILE... [-o OUT.json] [--allow-partial] [--no-ladder] [--min-agree 3] [--min-side 0] [--min-string 8] [--anchors --target-program NAME]
khx import FILE [-p PROJECT] [--name NAME|auto --game ABC] [--no-analyze] [--overwrite]      # progress on stderr, Ctrl-C cancels
khx projects | khx programs [PROJECT]
khx query PROJECT PROGRAM -c "decomp 0x..." -c "xrefs 0x..."  |  -f cmds.txt  |  < cmds.txt
khx commands | khx mcp
khx corpus list | verify | fetch NAME --yes
```

## Patch files

JSON list of entries. Offsets are FILE offsets. Types: `memory` (toggle `dataDisabled`/`dataEnabled`), `union` (pick one option;
`--set "Mode=Fast"`), `number` (`--set "Rate=120"`, little-endian, range-checked), `signature` (byte pattern with `??`/`XX` wildcards,
`usage` = 0-based n-th match, `offset` into the match), `group` (UI only). Metadata header objects (no `name`) are preserved, and so are
unknown keys. A patch file named `{gameCode}-{TimeDateStamp:x}_{EntryRVA:x}.json` (or entries with `peIdentifier`) is only applied to that
build: `verify`/`apply` fail with `WRONG_BUILD` otherwise (`--ignore-identity` to override). Unselected unions/numbers are skipped, never
guessed. `apply`/`revert` always write a copy and abort before writing on any mismatch or overlap.

### Signatures

`khx sig make` turns the `memory` patches (and `union` windows) of a patch file into `signature` entries that survive a rebuild: it grows
an instruction window around each site until the masked pattern is unique in the file, then shrinks what is not needed. Only
position-dependent operand bytes are wildcarded (relative branch displacements, RIP-relative/absolute/IAT references from Ghidra's
operand masks, and every byte covered by a base relocation); opcodes, register choices, struct offsets and small constants stay fixed.
A signature must keep at least `--min-fixed` informative bytes (a wrong silent match is worse than no match) and is verified to resolve to
exactly the site it was made from. Sites with no unique window are reported, never guessed; an ambiguous one is pinned by its n-th
occurrence (`usage`) with a caution unless `--no-usage`. Sites inside incremental-link `jmp` thunk tables have no distinguishing bytes:
sign the function body behind the thunk instead.

### Matching functions between two builds (`khx match`)

SOURCE and TARGET are programs of an analysed project (`--target-project` if the target lives elsewhere), e.g. two releases of one DLL. Each is fingerprinted once (strings, imports by name or ordinal,
large constants, an instruction skeleton, ordered callees, an instruction stream; RTTI vtables from `<Class>::vftable` labels) and cached under `<workspace>/cache` by the sha256 of the original file, so
later runs need no Ghidra work for fingerprinting. The functions are then matched in stages: seeds from rare shared features (accepted only when mutual best by a clear margin), unique strings, RTTI
vtable slots, call-graph propagation, and an order-aware alignment between the anchors found so far (similarity of size, constants, strings, imports, skeleton and callee agreement; a pair with an equally good
rival is reported as unmatched, never guessed). `--at ADDR` prints the counterpart of the function holding an address with its evidence, or the candidates between its neighbours' counterparts.
Across different ISAs the similarity bar is lower and a result is a hint.

`--apply` carries the names you gave functions by hand (Ghidra source *User defined*) from the source program into the target as a tagged plate comment (`[khx-match:Name] ...`) and a `khx-match` bookmark, and renames the
target function when it still has its default `FUN_` name (`--force` for others, `--no-rename` for comments only). Strong evidence (unique strings, rare features, RTTI slots) always counts; an alignment match needs
`--min-score` and `--min-margin`. `--dry-run` shows the plan; `--clear` removes the tags and gives the old names back. Re-running is idempotent.

### Porting patches between builds (`khx port`)

`khx port PROJECT SOURCE TARGET_FILE PATCHFILE...` takes patch files written for the analysed SOURCE build and produces the patch entries for the build in TARGET_FILE, which needs no Ghidra project. Tiers, in order:
the signature made in the source (`khx sig`); windows leaning other ways around the site (each unique in both builds, `--min-agree` of them agreeing); the NUL-delimited string a data patch edits; and with `--anchors` the function
holding the site matched between the builds (`--target-program` names the analysed target) with the patched instruction mapped inside it. The edit is re-applied to the *target's own bytes* (operands copied from the original
instruction are re-derived), a jump edit is refused on a jump that goes the other way, a multi-site entry is emitted only if every site was found, and the emitted entries are verified against the target.

### Patch sites and import ordinals

`khx sites annotate` turns the file offsets of patch files into knowledge in the Ghidra listing: for each site a `patch_<entry>` label, a `khx-patch` bookmark and a tagged end-of-line comment with the entry, the bytes
and the state they are in (original, patched, a union option), and a plate comment on the function that holds it. A site is annotated only when the program's bytes are what the patch file expects (`--force` to override);
functions are never renamed (a label on an entry point would rename it, so those sites get the bookmark and comment only); re-running is idempotent and `clear` removes everything it wrote.

`khx imports resolve` names `Ordinal_N` imports from the export tables of the libraries shipped with the module (`--libs`, next to the module, next to the imported file). Ghidra already does this when the library is in
the same folder at import time; this is for the case where it was not. `--skip-regex` leaves hashed export names alone. Ghidra keeps the original imported name, so `--restore` puts `Ordinal_N` back.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | (required for Ghidra features) | Ghidra install |
| `KHX_WORKSPACE` | `<repo>/workspace` | projects, results, logs |
| `KHX_DEFAULT_PROJECT` | `default` | used when `project` is omitted |
| `KHX_MAX_INLINE_CHARS` | 20000 | larger output is saved to a file |
| `KHX_DECOMPILE_TIMEOUT` | 120 | seconds per decompile |
| `KHX_REF_CONFIG` | `tests/reference.local.json` | tests only: JSON naming private reference binaries and a Ghidra project (see `tests/reference.example.json`); tests marked `reference` skip without it |

Nothing tracked in the repository depends on one machine: `tests/test_portability.py` fails on drive-letter paths, user names, home folders and OS-specific interpreter paths in any file git would commit.
Where Ghidra and your binaries live is an argument or one of the variables above.
