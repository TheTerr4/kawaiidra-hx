# Test corpus

Real third-party binaries used to prove kawaiidra-hx works beyond the private reference DLLs. Handled as untrusted input:
**static analysis only, nothing here is ever executed.**

* `user-supplied/`: files **you** copy in by hand (for example a Windows DLL you chose). The tooling never reads,
  copies or modifies anything outside this repository on its own. Git-ignored.
* `downloads/`: files fetched by `khx corpus fetch NAME --yes` from a `manifest.json` entry. Git-ignored.
* `manifest.json`: one entry per allowed download, pinning an `https` URL, the exact `size` and the `sha256` the
  vendor publishes (record where in `source`). `fetch` refuses to run without `--yes`, deletes anything whose size or
  hash differs, and extracts only the named zip member (path traversal is rejected).

Checklist before adding an entry: official vendor site over HTTPS; a checksum or signature published by the vendor
(not just one you computed); small file; license allows analysis; then run `khx corpus verify` (hashes, PE headers and,
on Windows, the Authenticode status of the copy in this folder).

```bash
uv run khx corpus list
uv run khx corpus verify
uv run khx corpus fetch <name> --yes     # only after reading the url / size / sha256 it prints
```

## Current manifest (fetched with approval on 2026-10-06)

| name | file | what it adds | integrity |
|---|---|---|---|
| `sqlite-3.53.4-x64` | `sqlite3-3.53.4-x64.dll` | x64 DLL with a real export table | vendor SHA3-256 of the zip + our SHA-256 of the DLL (unsigned) |
| `sqlite-3.53.4-x86` | `sqlite3-3.53.4-x86.dll` | 32-bit DLL (like the old reference build) | same |
| `putty-0.85-w64` | `putty-0.85-w64.exe` | x64 EXE, big Win32 import surface | vendor SHA-256; Authenticode `Valid` (Simon Tatham) |
| `putty-0.85-w32` | (not fetched) | 32-bit EXE | vendor SHA-256 |
