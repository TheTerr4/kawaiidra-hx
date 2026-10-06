# kawaiidra-hx

A PyGhidra-based reverse-engineering workbench for Windows PE binaries (DLL/EXE) with an **MCP server** for Claude Code,
a **CLI**, and a **patch toolkit** for file-offset hex patches (JSON patch entries). It is the successor to
kawaiidra-mcp's useful ideas, rebuilt on lessons from porting a game DLL's hex patches from its 2019 build to
its 2026 build (see [docs/LESSONS.md](docs/LESSONS.md)).

What it fixes compared with a subprocess-per-call design: one long-lived JVM (queries are milliseconds), imports and
analysis as background jobs with live progress (no 300 s kill), read-only by default, large output offloaded to files,
and the primitives patch work needs (`off:` file offsets, operand scan, pointer tables, patch verify/apply).

## Requirements

* JDK 21+ on `PATH` (or `JAVA_HOME`)
* Ghidra 12.1.x, with `GHIDRA_INSTALL_DIR` pointing at it (PyGhidra must match: 3.1.0 for 12.1.x)
* [uv](https://docs.astral.sh/uv/) and Python >= 3.10 (verified on 3.14.8)

## Setup

```bash
uv sync
uv run khx doctor --jvm        # checks Java, Ghidra, PyGhidra, JPype, workspace, and starts the JVM once
```

## Use

```bash
# patch work needs no Ghidra
uv run khx pe off2va target.dll 6094176
uv run khx patch verify target.dll entry.json
uv run khx patch apply  target.dll entry.json -o target_patched.dll

# analysis
uv run khx import binaries/target.dll -p mytarget          # minutes for big DLLs; progress on stderr
uv run khx query mytarget target.dll -c "info" -c "str config" -c "decomp 0x1805d0760"
```

Claude Code: the repo's `.mcp.json` registers the server by calling the venv's Python directly (`GHIDRA_INSTALL_DIR` is
taken from your environment).
Tools and the command language are listed in [docs/TOOLS.md](docs/TOOLS.md).

## Layout

```
src/kawaiidra_hx/
  core/       session (one JVM, projects, programs), resolver, background jobs
  queries/    decomp, disassembly, xrefs, strings, scan, symbols, bytes, pointer tables, RTTI
  commands.py text command language shared by the CLI and the MCP `query` tool
  annotate.py rename / comment (write mode)
  pe/         PE header math (no Ghidra)          patch/   verify, apply, make, branch encoding (no Ghidra)
  corpus.py   safe test-binary handling           mcp_server.py   MCP layer       cli.py   `khx`
tests/        unit tests + golden tests replaying the original Q.java session
docs/         LESSONS.md, TOOLS.md
corpus/       manifest.json (pinned downloads) ; downloads/ and user-supplied/ are git-ignored
```

## Tests

```bash
uv run pytest                      # everything available on this machine
uv run pytest -m "not ghidra"      # JVM-free, instant
uv run pytest -m "ghidra and not slow"
```
Tests marked `reference` need private reference DLLs and a Ghidra project. They read them in place from the paths in
`tests/reference.local.json` (git-ignored; start from `tests/reference.example.json`) and skip when it is absent.
Tests that need real third-party binaries use `corpus/` and skip when it is empty.

## Safety

Binaries are analyzed statically and never executed. Programs open read-only. `patch apply` writes a copy and refuses to
touch the source. The test corpus is only what you copy into `corpus/user-supplied/` yourself or what a pinned,
checksum-verified manifest entry downloads after an explicit `--yes`. Nothing is read from system locations automatically.

## License

MIT. Portions derive from kawaiidra-mcp (MIT), see [NOTICE](NOTICE).
