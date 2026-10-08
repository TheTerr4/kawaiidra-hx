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

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | (required for Ghidra features) | Ghidra install |
| `KHX_WORKSPACE` | `<repo>/workspace` | projects, results, logs |
| `KHX_DEFAULT_PROJECT` | `default` | used when `project` is omitted |
| `KHX_MAX_INLINE_CHARS` | 20000 | larger output is saved to a file |
| `KHX_DECOMPILE_TIMEOUT` | 120 | seconds per decompile |
