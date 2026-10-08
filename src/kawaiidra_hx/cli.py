"""``khx`` command line.

JVM-free commands (``pe``, ``patch``, ``doctor``) start instantly; anything touching Ghidra starts the JVM lazily.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .util import parse_hex, parse_int

# --- helpers ----------------------------------------------------------------------------------


def _num(text: str) -> int:
    return parse_int(text)


def _read_commands(args: argparse.Namespace) -> list[str]:
    lines: list[str] = []
    if args.command:
        lines += args.command
    if args.file:
        lines += Path(args.file).read_text(encoding="utf-8").splitlines()
    if not lines and not sys.stdin.isatty():
        lines += sys.stdin.read().splitlines()
    return lines


# --- pe ---------------------------------------------------------------------------------------


def cmd_pe_sections(args: argparse.Namespace) -> int:
    from .pe import format_sections, parse_pe

    print(format_sections(parse_pe(args.file)))
    return 0


def cmd_pe_off2va(args: argparse.Namespace) -> int:
    from .pe import NotMappedError, parse_pe

    pe = parse_pe(args.file)
    rc = 0
    for raw in args.offset:
        try:
            print(pe.describe_offset(_num(raw)))
        except NotMappedError as e:
            print(f"{raw}: {e}")
            rc = 1
    return rc


def cmd_pe_va2off(args: argparse.Namespace) -> int:
    from .pe import NotMappedError, parse_pe

    pe = parse_pe(args.file)
    rc = 0
    for raw in args.va:
        try:
            va = parse_hex(raw)
            off = pe.va_to_offset(va)
            s = pe.section_for_offset(off)
            print(f"VA 0x{va:X} -> file 0x{off:X} ({off}) ({s.name if s else 'headers'})")
        except Exception as e:
            print(f"{raw}: {e}")
            rc = 1
    return rc


def cmd_pe_identify(args: argparse.Namespace) -> int:
    from .pe import PEImage

    ident = PEImage(args.file).identity
    print(f"file        {ident.path}")
    print(f"size        {ident.size}")
    print(f"sha256      {ident.sha256}")
    print(f"machine     {ident.machine} ({'PE32+' if ident.is_64bit else 'PE32'} {'DLL' if ident.is_dll else 'EXE'})")
    print(f"image base  0x{ident.image_base:X}")
    print(f"timestamp   0x{ident.timestamp:x} ({ident.build_time} UTC)")
    print(f"entry RVA   0x{ident.entry_rva:x}")
    for code in args.game or []:
        print(f"patch id    {ident.pe_identifier(code)}")
    if not args.game:
        print(f"patch id    <GAMECODE>-{ident.timestamp:x}_{ident.entry_rva:x}   (patch file name stem; give --game CODE)")
    return 0


def cmd_pe_exports(args: argparse.Namespace) -> int:
    from .pe import PEImage

    ex = PEImage(args.file).exports
    if ex is None:
        print("(no export directory)")
        return 0
    print(f"module {ex.module_name}  ordinal base {ex.ordinal_base}  {len(ex.exports)} export(s)")
    for e in ex.exports:
        print(f"  #{e.ordinal:<4} 0x{e.rva:08X}  {e.name or '<ordinal only>'}" + (f"  -> {e.forwarder}" if e.forwarder else ""))
    return 0


def cmd_pe_imports(args: argparse.Namespace) -> int:
    from .pe import PEImage

    libs = PEImage(args.file).imports
    want = [d.lower() for d in args.dll or []]
    for lib in libs:
        if want and not any(w in lib.dll.lower() for w in want):
            continue
        extra = f", {lib.by_ordinal} by ordinal" if lib.by_ordinal else ""
        print(f"{lib.dll}{' (delay-load)' if lib.delay else ''}  {len(lib.symbols)} import(s){extra}")
        if args.dll or args.all:
            for sym in lib.symbols:
                print(f"    0x{sym.iat_rva:08X}  {sym.label}")
    return 0


# --- patch ------------------------------------------------------------------------------------


def _expected_id(pf, args: argparse.Namespace) -> Optional[str]:
    return None if getattr(args, "ignore_identity", False) else pf.pe_identifier


def _parse_sets(items: Optional[list[str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        name, sep, value = item.rpartition("=")
        if not sep or not name:
            raise SystemExit(f"--set expects NAME=VALUE (union option name or number), got {item!r}")
        out[name] = value
    return out


def cmd_patch_show(args: argparse.Namespace) -> int:
    from .patch import describe_entries, load_patchfile

    print(describe_entries(load_patchfile(args.json)))
    return 0


def cmd_patch_verify(args: argparse.Namespace) -> int:
    from .patch import load_patchfile, select_entries, verify

    pf = load_patchfile(args.json)
    report = verify(args.file, select_entries(pf.entries, args.entry), expected_id=_expected_id(pf, args))
    print(report.format())
    return 0 if report.ok else 1


def cmd_patch_apply(args: argparse.Namespace) -> int:
    from .patch import apply, load_patchfile, select_entries

    pf = load_patchfile(args.json)
    rep = apply(
        args.file, args.output, select_entries(pf.entries, args.entry), overwrite=args.overwrite,
        selections=_parse_sets(args.set), mode="revert" if getattr(args, "revert", False) else "apply",
        expected_id=_expected_id(pf, args),
    )  # fmt: skip
    print(rep.format())
    return 0


def cmd_patch_revert(args: argparse.Namespace) -> int:
    args.revert = True
    args.set = None
    return cmd_patch_apply(args)


def cmd_patch_make(args: argparse.Namespace) -> int:
    from .patch import make_entry

    edits = []
    for e in args.edit:
        loc, sep, hexbytes = e.partition("=")
        if not sep:
            raise SystemExit(f"--edit expects LOCATION=HEX (e.g. va:0x1805D0760=B863000000C3), got {e!r}")
        edits.append((loc, hexbytes))
    entry = make_entry(
        args.file, edits, name=args.name, description=args.description, game_code=args.game, dll_name=args.dll,
        pe_identifier=args.pe_id, caution=args.caution or "",
    )  # fmt: skip
    return _emit_entry(entry, args)


def cmd_patch_diff(args: argparse.Namespace) -> int:
    from .patch import diff_entry

    entry = diff_entry(
        args.original, args.modified, name=args.name, description=args.description, game_code=args.game,
        dll_name=args.dll, gap=args.gap, pad=args.pad, pe_identifier=args.pe_id,
    )  # fmt: skip
    return _emit_entry(entry, args)


def _emit_entry(entry, args: argparse.Namespace) -> int:
    from .patch import PatchFile, dump_entries, load_patchfile, merge_entries

    if getattr(args, "append_to", None):
        target = Path(args.append_to)
        pf = load_patchfile(target) if target.exists() else PatchFile(entries=[])
        _pf, log = merge_entries(pf, [entry], replace=args.replace)
        target.write_text(pf.dumps(), encoding="utf-8")
        print(f"{log[0]} in {target}")
        return 0
    text = dump_entries([entry])
    if args.output:
        out = Path(args.output)
        if out.exists() and not args.overwrite:
            raise SystemExit(f"{out} exists; use --append-to {out} to add the entry, or --overwrite to replace the file")
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text, end="")
    return 0


def cmd_patch_merge(args: argparse.Namespace) -> int:
    from .patch import load_patchfile, merge_entries

    target = load_patchfile(args.target)
    source = load_patchfile(args.source)
    _pf, log = merge_entries(target, source.entries, replace=args.replace)
    Path(args.target).write_text(target.dumps(), encoding="utf-8")
    print("\n".join(log))
    return 0


def cmd_patch_branch(args: argparse.Namespace) -> int:
    from .patch import asm

    src, dst = parse_hex(args.at), parse_hex(args.to)
    op = args.op.lower()
    data = asm.branch(op, src, dst, short=args.short, near=args.near)
    print(f"{op} 0x{src:X} -> 0x{dst:X}: {data.hex().upper()}")
    return 0


# --- ghidra-backed ----------------------------------------------------------------------------


def cmd_import(args: argparse.Namespace) -> int:
    from .core import get_session
    from .core.jobs import get_jobs, import_program

    session = get_session()
    session.ensure_started()  # start the JVM on the main thread
    name = args.name
    if name == "auto":  # program named by build id, e.g. ABC-12345678_1000.dll (modules that all share one file name)
        from .pe import PEImage

        name = PEImage(args.file).identity.pe_identifier(args.game) + Path(args.file).suffix
        print(f"program name: {name}", file=sys.stderr)
    jobs = get_jobs()
    job = jobs.submit(
        "import",
        Path(args.file).name,
        lambda j: import_program(
            session, args.file, args.project, analyze=not args.no_analyze, name=name, overwrite=args.overwrite, job=j
        ),
    )
    last = ""
    try:
        while not job.finished_ok:
            time.sleep(1.0)
            line = job.status_line()
            if int(job.elapsed) % args.progress_every == 0 and line != last:
                print(line, file=sys.stderr, flush=True)
                last = line
    except KeyboardInterrupt:
        print("\ncancelling...", file=sys.stderr)
        job.cancel()
        jobs.wait(job, timeout=60)
    print(job.status_line(), file=sys.stderr)
    if job.state == "failed":
        print(f"error: {job.error}", file=sys.stderr)
        return 2
    for k, v in (job.result or {}).items():
        if v not in ("", None):
            print(f"{k}: {v}")
    return 0 if job.state == "done" else 130


def cmd_projects(args: argparse.Namespace) -> int:
    from .core import get_session, list_projects

    s = get_session()
    found = list_projects(s.settings)
    print(f"workspace: {s.settings.workspace}")
    if not found:
        print("(no projects yet; `khx import FILE` creates one)")
    for ref in found:
        print(f"  {ref.name}    {ref.gpr}")
    return 0


def cmd_programs(args: argparse.Namespace) -> int:
    from .core import get_session

    proj = get_session().open_project(args.project)
    print(f"project {proj.ref.name} ({proj.ref.gpr})")
    for path, ctype in proj.program_files():
        print(f"  {path}    [{ctype}]")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    from . import commands
    from .core import get_session

    lines = _read_commands(args)
    if not lines:
        print("no commands given (use -c 'decomp 0x...', -f FILE or pipe lines on stdin)", file=sys.stderr)
        return 2
    session = get_session()
    handle = session.program(args.project, args.program)
    text = commands.run_script(handle, lines, session.settings)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text)
    return 0


def cmd_commands(args: argparse.Namespace) -> int:
    from . import commands

    print(commands.help_text())
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import run

    run()
    return 0


# --- corpus -----------------------------------------------------------------------------------


def cmd_corpus_list(args: argparse.Namespace) -> int:
    from . import corpus

    entries = corpus.load_manifest()
    print(f"corpus root: {corpus.CORPUS_ROOT}")
    if not entries:
        print("manifest.json has no entries yet")
    for e in entries:
        have = (corpus.CORPUS_ROOT / "downloads" / e.file).exists()
        print(f"  [{'present' if have else 'missing':<7}] {e.name}  {e.file}  {e.size / 1e6:.2f} MB")
    supplied = corpus.CORPUS_ROOT / "user-supplied"
    files = [p.name for p in supplied.iterdir() if p.is_file() and not p.name.startswith(".")] if supplied.is_dir() else []
    print(f"user-supplied: {', '.join(files) if files else '(none: copy test binaries into ' + str(supplied) + ' yourself)'}")
    return 0


def cmd_corpus_verify(args: argparse.Namespace) -> int:
    from . import corpus

    reports = corpus.verify_all(check_signature=not args.no_signature)
    if not reports:
        print("corpus is empty")
        return 0
    for r in reports:
        print(r.format())
    return 1 if any(r.problems for r in reports) else 0


def cmd_corpus_fetch(args: argparse.Namespace) -> int:
    from . import corpus

    entries = {e.name: e for e in corpus.load_manifest()}
    if args.name not in entries:
        raise SystemExit(f"unknown corpus entry {args.name!r}; available: {', '.join(entries) or 'none'}")
    entry = entries[args.name]
    print(corpus.describe_entry(entry))
    path = corpus.fetch(entry, confirm=args.yes)
    expected, algo = corpus.pinned_digest(entry)
    rep = corpus.verify_file(path, expected, algo=algo)
    print(rep.format())
    if entry.member and not entry.member_sha256:
        print(f"note: record this in manifest.json as member_sha256 for future verification: {rep.sha256}")
    return 1 if rep.problems else 0


# --- doctor -----------------------------------------------------------------------------------


def _java_version() -> Optional[str]:
    java = shutil.which("java")
    home = os.environ.get("JAVA_HOME")
    if not java and home:
        cand = Path(home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        java = str(cand) if cand.exists() else None
    if not java:
        return None
    try:
        out = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=20)
        return (out.stderr or out.stdout).splitlines()[0]
    except Exception:
        return None


def cmd_doctor(args: argparse.Namespace) -> int:
    from .config import ConfigError, load_settings

    rows: list[tuple[str, str, str]] = []

    def add(status: str, name: str, detail: str) -> None:
        rows.append((status, name, detail))

    add("ok", "kawaiidra-hx", __version__)
    add("ok", "python", sys.version.split()[0])
    jv = _java_version()
    add("ok" if jv else "FAIL", "java", jv or "not found (need JDK 21+ on PATH or JAVA_HOME)")

    settings = load_settings()
    try:
        ghidra = settings.require_ghidra()
        props = (ghidra / "Ghidra" / "application.properties").read_text(encoding="utf-8", errors="replace")
        ver = next((ln.split("=", 1)[1].strip() for ln in props.splitlines() if ln.startswith("application.version=")), "?")
        add("ok", "ghidra", f"{ghidra} (version {ver})")
    except ConfigError as e:
        ghidra, ver = None, "?"
        add("FAIL", "ghidra", str(e))

    try:
        from importlib import metadata

        pg = metadata.version("pyghidra")
        add("ok", "pyghidra", pg)
    except Exception:
        add("FAIL", "pyghidra", "not installed (uv sync)")
    try:
        import jpype

        add("ok", "jpype", f"{jpype.__version__} (pyghidra pins 1.5.2; newer is needed for Python 3.14 and works)")
    except Exception:
        add("FAIL", "jpype", "not installed (uv sync)")
    try:
        from importlib import metadata

        add("ok", "mcp sdk", metadata.version("mcp"))
    except Exception:
        add("WARN", "mcp sdk", "not installed (only needed for `khx mcp`)")

    try:
        settings.workspace.mkdir(parents=True, exist_ok=True)
        probe = settings.workspace / ".write-test"
        probe.write_text("x")
        probe.unlink()
        add("ok", "workspace", str(settings.workspace))
    except Exception as e:
        add("FAIL", "workspace", f"{settings.workspace}: {e}")

    if args.jvm and ghidra:
        t0 = time.time()
        try:
            from .core import get_session

            get_session().ensure_started()
            add("ok", "jvm", f"Ghidra started in {time.time() - t0:.1f}s")
        except Exception as e:
            add("FAIL", "jvm", f"{type(e).__name__}: {e}")

    width = max(len(n) for _s, n, _d in rows)
    for status, name, detail in rows:
        print(f"[{status:<4}] {name:<{width}}  {detail}")
    return 1 if any(s == "FAIL" for s, _n, _d in rows) else 0


# --- parser -----------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="khx", description="kawaiidra-hx: PyGhidra RE workbench (PE-first, patch-oriented)")
    ap.add_argument("--version", action="version", version=f"khx {__version__}")
    ap.add_argument("--workspace", help="override KHX_WORKSPACE")
    ap.add_argument("--ghidra", help="override GHIDRA_INSTALL_DIR")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("doctor", help="check Java, Ghidra, PyGhidra, JPype and the workspace")
    p.add_argument("--jvm", action="store_true", help="also start the JVM")
    p.set_defaults(func=cmd_doctor)

    # pe
    pe = sub.add_parser("pe", help="PE header tools (no JVM)").add_subparsers(dest="pe_cmd", required=True)
    p = pe.add_parser("sections", help="show headers and section table")
    p.add_argument("file")
    p.set_defaults(func=cmd_pe_sections)
    p = pe.add_parser("off2va", help="file offset(s) -> virtual address")
    p.add_argument("file")
    p.add_argument("offset", nargs="+")
    p.set_defaults(func=cmd_pe_off2va)
    p = pe.add_parser("va2off", help="virtual address(es) -> file offset")
    p.add_argument("file")
    p.add_argument("va", nargs="+")
    p.set_defaults(func=cmd_pe_va2off)
    p = pe.add_parser("identify", help="build identity: sha256, timestamp, entry point, patch id")
    p.add_argument("file")
    p.add_argument("--game", action="append", help="game code(s) to print a patch id for, e.g. ABC (repeatable)")
    p.set_defaults(func=cmd_pe_identify)
    p = pe.add_parser("exports", help="export table")
    p.add_argument("file")
    p.set_defaults(func=cmd_pe_exports)
    p = pe.add_parser("imports", help="imports grouped by library (--dll NAME lists that library's symbols)")
    p.add_argument("file")
    p.add_argument("--dll", action="append", help="only libraries whose name contains this (repeatable); lists their symbols")
    p.add_argument("--all", action="store_true", help="list every symbol")
    p.set_defaults(func=cmd_pe_imports)

    # patch
    pt = sub.add_parser("patch", help="JSON file-offset patch tools (no JVM)").add_subparsers(dest="patch_cmd", required=True)
    p = pt.add_parser("show", help="list the entries of a patch file")
    p.add_argument("json")
    p.set_defaults(func=cmd_patch_show)
    p = pt.add_parser("verify", help="check that a binary contains the bytes a patch file expects (and is the build it names)")
    p.add_argument("file")
    p.add_argument("json")
    p.add_argument("--entry", action="append", help="entry name or 1-based index (repeatable); default all")
    p.add_argument("--ignore-identity", action="store_true", help="do not require the PE identifier in the patch file name/entries to match")
    p.set_defaults(func=cmd_patch_verify)
    p = pt.add_parser("apply", help="write a patched COPY of the binary (never modifies the source)")
    p.add_argument("file")
    p.add_argument("json")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--entry", action="append")
    p.add_argument("--set", action="append", metavar="NAME=VALUE", help='choose a union option / number value, e.g. --set "Mode=Fast"')
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--ignore-identity", action="store_true")
    p.set_defaults(func=cmd_patch_apply)
    p = pt.add_parser("revert", help="write a COPY with memory/signature patches reverted to their original bytes")
    p.add_argument("file")
    p.add_argument("json")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--entry", action="append")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--ignore-identity", action="store_true")
    p.set_defaults(func=cmd_patch_revert)

    def entry_output_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--description", default="")
        p.add_argument("--caution")
        p.add_argument("--game", help="gameCode to record, e.g. ABC")
        p.add_argument("--dll", help="dllName to record, e.g. target.dll")
        p.add_argument("--pe-id", help="peIdentifier to record, e.g. ABC-12345678_1000 (see `khx pe identify`)")
        p.add_argument("-o", "--output", help="write the entry as a new JSON file (refuses to overwrite without --overwrite)")
        p.add_argument("--overwrite", action="store_true")
        p.add_argument("--append-to", metavar="JSON", help="add the entry to this patch file (created if missing)")
        p.add_argument("--replace", action="store_true", help="with --append-to: replace an entry of the same name")

    p = pt.add_parser("make", help="build a patch entry, reading the original bytes from the binary")
    p.add_argument("file")
    p.add_argument("--name", required=True)
    p.add_argument("--edit", action="append", required=True, metavar="LOC=HEX", help="e.g. va:0x1805D0760=B863000000C3 or off:0x5CFD60=9090")
    entry_output_args(p)
    p.set_defaults(func=cmd_patch_make)
    p = pt.add_parser("diff", help="turn the byte differences between two same-size binaries into a patch entry")
    p.add_argument("original")
    p.add_argument("modified")
    p.add_argument("--name", required=True)
    p.add_argument("--gap", type=int, default=0, help="merge differing runs closer than this many bytes")
    p.add_argument("--pad", type=int, default=0, help="widen every patch by this many context bytes each side")
    entry_output_args(p)
    p.set_defaults(func=cmd_patch_diff)
    p = pt.add_parser("merge", help="add the entries of one patch file to another")
    p.add_argument("target")
    p.add_argument("source")
    p.add_argument("--replace", action="store_true")
    p.set_defaults(func=cmd_patch_merge)
    p = pt.add_parser("branch", help="encode a jump/call from one address to another")
    p.add_argument("--at", required=True, help="address of the branch instruction")
    p.add_argument("--to", required=True, help="target address")
    p.add_argument("--op", default="jmp", help="jmp, call, or a conditional such as jnz/jbe")
    p.add_argument("--short", action="store_true", help="jmp: use the 2-byte rel8 form")
    p.add_argument("--near", action="store_true", help="conditional: use the 6-byte 0F 8x rel32 form")
    p.set_defaults(func=cmd_patch_branch)

    # ghidra
    p = sub.add_parser("import", help="import (and analyze) a binary into a project; progress on stderr")
    p.add_argument("file")
    p.add_argument("-p", "--project", help="project name, .gpr path or folder (default: workspace 'default')")
    p.add_argument("--name", help="program name inside the project (default: file name; `auto` = <GAME>-<TimeDateStamp>_<EntryRVA> + extension)")
    p.add_argument("--game", default="PE", help="game code for --name auto (e.g. ABC)")
    p.add_argument("--no-analyze", action="store_true")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--progress-every", type=int, default=10, help="seconds between progress lines")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("projects", help="list workspace projects")
    p.set_defaults(func=cmd_projects)
    p = sub.add_parser("programs", help="list programs in a project")
    p.add_argument("project", nargs="?")
    p.set_defaults(func=cmd_programs)

    p = sub.add_parser("query", help="run query commands against a program (read-only)", description="Run `khx commands` for the language.")
    p.add_argument("project")
    p.add_argument("program")
    p.add_argument("-c", "--command", action="append", help="one command line (repeatable)")
    p.add_argument("-f", "--file", help="file with one command per line")
    p.add_argument("-o", "--output", help="write results to a file")
    p.set_defaults(func=cmd_query)
    p = sub.add_parser("commands", help="show the query command language")
    p.set_defaults(func=cmd_commands)

    # corpus
    co = sub.add_parser("corpus", help="test-binary corpus (downloads need --yes)").add_subparsers(dest="corpus_cmd", required=True)
    p = co.add_parser("list", help="manifest entries and user-supplied files")
    p.set_defaults(func=cmd_corpus_list)
    p = co.add_parser("verify", help="re-hash everything on disk, check PE headers and (Windows) Authenticode signatures")
    p.add_argument("--no-signature", action="store_true")
    p.set_defaults(func=cmd_corpus_verify)
    p = co.add_parser("fetch", help="download one manifest entry (pinned URL/size/sha256); needs --yes")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true", help="I have read the url/size/hash above and approve this download")
    p.set_defaults(func=cmd_corpus_fetch)

    p = sub.add_parser("mcp", help="run the MCP server on stdio")
    p.set_defaults(func=cmd_mcp)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    if args.workspace:
        os.environ["KHX_WORKSPACE"] = args.workspace
    if args.ghidra:
        os.environ["GHIDRA_INSTALL_DIR"] = args.ghidra

    from .core.errors import KhxError
    from .config import ConfigError
    from .patch import PatchFormatError, PatchMismatchError
    from .pe import PEError

    try:
        return int(args.func(args) or 0)
    except (KhxError, ConfigError, PatchFormatError, PatchMismatchError, PEError, FileExistsError, FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
