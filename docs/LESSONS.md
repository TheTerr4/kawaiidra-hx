# Lessons learned (why kawaiidra-hx is built the way it is)

This project started after porting a game DLL's hex patches from its 2019 build (32-bit, "the old DLL") to its
2026 build (x64, "the new DLL"). Kawaiidra MCP could not carry the whole job; a hand-run headless Ghidra project with a small
Java query script (`Q.java`) did. Everything below is something we hit, measured or decided.

## What went wrong with the Kawaiidra-style setup

| Symptom | Cause | What kawaiidra-hx does instead |
|---|---|---|
| Most tools failed on Ghidra 12.1.4; `run_script` and address tools broke | Kawaiidra embeds 83 f-string scripts tagged `# @runtime Jython`; Ghidra 12.1.4 ships no Jython (only `Features/PyGhidra`). Only the 14 operations routed through its JPype bridge (`bridge/backend.py`) can work. (We did not re-run every fallback script; with no Jython they cannot run.) | No inline scripts at all. Queries are plain Python on Ghidra's Java API through PyGhidra. |
| DLL import "timed out" after 300 s | Import ran as a blocking `analyzeHeadless` subprocess with a 300 s kill, from inside an `async` handler. Analysis of the 12.6 MB x64 DLL alone is ~250 s (331 s end to end when the machine was busy). | Import + analysis is a background **job** with live progress and cancel; no timeout kill. |
| `get_binary_info` hung for 30 minutes | Blocking calls in async handlers, and a Ghidra project can be open in only one process (the bridge held it while subprocess fallbacks tried to open it). Not proven, but consistent. | One long-lived JVM owns every project; lock errors name the lock file instead of hanging. |
| Tracked `scripts/*.py` showed up modified in `git status` | Per-call scripts were written into the shared scripts directory (`write_ghidra_script`). | Nothing is generated on disk. |
| Tools resolved only function entry points | Lookup used `getFunctionAt` | One resolver: hex VA, symbol, `rva:`, `off:` (file offset); queries accept any address (mid-function, data). |
| Missing exactly what we needed | no operand scan, no pointer-table dump, no string+xrefs, no file-offset conversion, no patch checks | `scan`, `vt`, `str`, `resolve off:`, `patch_verify` / `patch_apply`. |
| Huge decompiles flooded the context | inline output | Anything over `KHX_MAX_INLINE_CHARS` is saved to `workspace/results/` and truncated inline. |

The part that worked: batching many commands in one run (`Q.java` took a command file). That is now the `query`
tool and `khx query`.

## Measurements (the new DLL: x64, 12.6 MB, 37,281 functions, Windows 11)

| Operation | Time |
|---|---|
| Start JVM (PyGhidra) | ~2.4 s |
| Open an existing project + read-only program | ~1.5 s |
| Decompile one function (warm) | ~0.3 s |
| `scan` over all 2.06 M instructions (pure Python/JPype) | ~13 s (153k instr/s), so no Java accelerator was needed |
| Defined-data walk (155k items) | 0.8 s |
| Import | ~15 s |
| Auto-analysis | ~250-330 s |
| Old way: `analyzeHeadless` process per query | ~10-15 s each |

## Ghidra / PyGhidra / JPype gotchas

* **PyGhidra pins `JPype1==1.5.2`, which has no Python 3.14 wheels.** `pyghidra 3.1.0` + JPype 1.7.1 on Python 3.14.8 works
  (verified: project open, decompile, import, analysis, write+save). `pyproject.toml` uses a uv `override-dependencies`.
  The pyghidra version must match the Ghidra install (3.1.0 for 12.1.x).
* **Start the JVM on the main thread, before any event loop.** Calling `pyghidra.start()` from `asyncio.to_thread` hangs
  inside `jpype.startJVM` on Windows (reproduced; no output after "starting Ghidra"). Calls from worker threads *after*
  startup are fine. The MCP server therefore warms up the JVM in `run()` before `mcp.run()`.
* **stdout belongs to the MCP protocol.** PyGhidra silences Java output only while starting. `mcp_server._isolate_stdout`
  dups the real stdout for the SDK, points fd 1 *and* (Windows) the OS `STD_OUTPUT_HANDLE` at stderr before the JVM
  starts, so JVM/log4j/native output cannot corrupt the stream.
* **pytest + JVM:** run with `-p no:faulthandler`. The JVM raises benign access violations (null checks, safepoints)
  that faulthandler reports as "Windows fatal exception". PyGhidra's own test config does the same.
* **JPype copies Python buffers.** `Memory.getBytes(addr, bytearray)` leaves the bytearray untouched (we got a row of
  zeros from a function that starts `40 53 48 83 ec 40`). Pass `JArray(JByte)(n)`.
* **Python implementations of `TaskMonitor` must override the interface's *default* methods too.** Otherwise Ghidra
  calling `increment()` / `checkCancelled()` / `clearCancelled()` raises
  `WrongMethodTypeException: cannot convert MethodHandle()void to (Object)Object`.
* **`TaskMonitorAdapter` shows no analysis progress** (message stayed `None`). A custom monitor gets real messages
  ("Disassembled 1788 K", "x86 Constant Reference Analyzer 5750/40627").
* **Ghidra stores file bytes with the program**, so `Memory.getAddressSourceInfo(addr).getFileOffset()` and
  `Memory.locateAddressesForFileOffset(off)` convert file offsets <-> addresses without the original file. Our pure
  Python PE math and Ghidra agree on both builds of the DLL (tests/test_crosscheck.py).
* **Opening read-only:** `DomainFile.getReadOnlyDomainObject(consumer, DEFAULT_VERSION, monitor)` opens an immutable
  program; PyGhidra's `program_context` opens for update, so we use our own handle code.
* **Decompiler state leaks across calls.** In one session the same function came out as `undefined4 param_2` or
  `undefined8 param_2` depending on what had been decompiled before it (a fresh JVM per command file, as Q.java did,
  gave the first form). `flushCache()` and a new `DecompInterface` did not reliably reset it. Treat parameter *sizes*
  in decompiler output as a hint; verify with the disassembly. The golden tests compare decompiles modulo `undefinedN`.

## Patch-work gotchas (from the port)

* Patch JSON `offset` is a **file offset**, not an address. `VA = image_base + RVA`, `RVA = section_rva + (offset -
  section_raw_ptr)`; the delta differs per section and per DLL (.text is +0xA00 in the new DLL, +0xC00 in the old one).
  We once used +0x400 by mistake; mismatched `dataDisabled` bytes exposed it. Always verify `dataDisabled` against the file
  (`khx patch verify`).
* Short-jump displacement bytes are **signed**: `75 8D` is a backward jump of -115, not +141.
  Target = address + instruction length + signed displacement (`patch/asm.py`).
* Same-length, in-place edits only. When an `xor al,al` is shared by several paths (merged by the compiler), flip the
  jump that selects it instead of the shared instruction.
* Never patch in place: `patch apply` writes a copy, aborts before writing if any expected byte differs, and refuses to
  overlap or overwrite without `--overwrite`.

## Reverse-engineering method that worked

1. Anchor on strings and RTTI names (a feature-flag string, a game-state class name, a save-data key) and follow xrefs.
2. Find the single choke point (here the per-mode stage-limit function with ~25 callers) and patch it instead of its callers.
3. Diff old vs new structure: the 2019 DLL's patch bytes told us what to look for in the 2026 build.
4. Verify before writing: original bytes, jump-target arithmetic, call-graph evidence.
5. State what is verified and what is not (nothing here was tested in the game).

## Safety decisions

* Programs open **read-only**; write tools need an explicit write open and persist only on `save`.
* The corpus never auto-discovers files and never touches system locations; the user copies test binaries in. Downloads
  need a pinned https URL + size + vendor-published SHA-256 and an explicit `--yes`. Nothing is executed.

## Corpus downloads: what we hit

* **TLS:** Python's default context uses the Windows certificate store, which rejected `www.sqlite.org` with
  "certificate has expired" (a stale root chosen during path building) while curl and the Mozilla bundle validated it
  (Let's Encrypt, valid to 2026-10-30). The fix is to verify against the `certifi` bundle, not to turn verification off.
* **Different vendors, different digests:** PuTTY publishes SHA-256 (`sha256sums`), sqlite.org publishes SHA3-256 and the
  exact byte size in a machine-readable `PRODUCT` line on its download page. The manifest supports both; for zip downloads we
  also record our own SHA-256 of the extracted DLL (`member_sha256`) so later `corpus verify` runs check the file we keep.
* **Pin version-specific URLs** (`/putty/0.85/...`, `/2026/sqlite-dll-...-3530400.zip`), not `latest`, or the pinned digest
  breaks on the next release.
* **Authenticode is only a bonus:** PuTTY's exe is signed (`Valid`, CN=Simon Tatham); SQLite's DLLs are `NotSigned`, so
  their integrity rests on the vendor digest + HTTPS. `$args` is not populated under `powershell -Command`; pass the path
  through an environment variable.
* Imports of the three corpus binaries (1.7-3.3 MB) took ~100 s of analysis each; our PE offset math and Ghidra's agreed
  on all of them.
