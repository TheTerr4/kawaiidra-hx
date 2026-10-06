"""MCP server (stdio). A thin layer over the core/queries/patch modules.

Design rules (each fixes a Kawaiidra hiccup):
  * blocking Ghidra work runs in worker threads, never on the event loop;
  * long work (import + analysis) is a *job*: ``import_binary`` returns a job id, ``job_status`` polls it;
  * big results are written to a file and truncated inline (see ``outputs.emit``);
  * programs open read-only unless a write tool is used; write tools only persist on ``save``;
  * stdout belongs to the protocol: JVM/native output is redirected to stderr before Ghidra starts.
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import sys
from typing import Any, Callable, Optional

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import annotate, commands
from .core import KhxError, ProgramHandle, get_session, list_projects
from .core.jobs import get_jobs, import_program
from .outputs import emit, slice_lines
from .queries import code, data, search
from .util import parse_hex, parse_int

log = logging.getLogger("khx.mcp")

INSTRUCTIONS = """\
kawaiidra-hx: Ghidra-backed reverse engineering for Windows PE binaries, plus patch tooling.

Workflow: list_projects -> (import_binary if the binary is not in a project; it runs as a job, poll job_status)
-> explore with `query` (batch many commands in ONE call: decomp/disf/xrefs/str/scan/...) or the single-purpose tools.
Locations accept 0x1805d0760, FUN_1805d0760, rva:0x5d0760 and off:0x5CFD60 (FILE offset, as used by patch JSON).
Patch work needs no Ghidra: pe_sections / offset_to_va / va_to_offset / patch_verify / patch_apply (writes a COPY,
never the original). Programs are read-only unless you call a write tool (rename, set_comment) and then save_program.
Decompiler output can vary slightly (undefined4 vs undefined8) with the order functions were decompiled in a session.
"""

mcp = FastMCP("kawaiidra-hx", instructions=INSTRUCTIONS)

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
FILEWRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)


# --- helpers ----------------------------------------------------------------------------------


def _handle(project: Optional[str], program: Optional[str], write: bool = False) -> ProgramHandle:
    proj = get_session().open_project(project)
    if not program:
        progs = [p for p, t in proj.program_files() if t == "Program"]
        if len(progs) != 1:
            raise KhxError(f"'program' is required; programs in project {proj.ref.name}: {', '.join(progs) or 'none'}")
        program = progs[0]
    return proj.open_program(program, write=write)


async def _run(label: str, fn: Callable[[], str]) -> str:
    """Run blocking work in a thread and keep the result inline-sized."""
    text = await asyncio.to_thread(fn)
    return emit(text, get_session().settings, label)


# --- session / projects / jobs ----------------------------------------------------------------


@mcp.tool(annotations=READ)
async def session_status() -> str:
    """Show configuration, open projects/programs and background jobs."""

    def work() -> str:
        s = get_session()
        st = s.settings
        lines = [
            f"ghidra      {st.ghidra_dir}",
            f"workspace   {st.workspace}",
            f"jvm started {s._started}",
        ]
        for key, p in s._projects.items():
            lines.append(f"open project {p.ref.name} ({p.ref.gpr})")
            for path, h in p.programs.items():
                lines.append(f"    {path} [{'rw' if h.writable else 'ro'}]{' *unsaved*' if h.has_unsaved_changes else ''}")
        for j in get_jobs().list():
            lines.append(j.status_line())
        return "\n".join(lines)

    return await asyncio.to_thread(work)


@mcp.tool(name="list_projects", annotations=READ)
async def list_projects_tool() -> str:
    """List Ghidra projects in the workspace (name and path)."""
    s = get_session()
    found = list_projects(s.settings)
    if not found:
        return f"No projects in {s.settings.projects_dir}. Use import_binary to create one."
    return "\n".join(f"{r.name}    {r.gpr}" for r in found)


@mcp.tool(annotations=READ)
async def list_programs(project: Optional[str] = None) -> str:
    """List programs (imported binaries) in a project. `project` may be a workspace name, a .gpr path or a project folder."""

    def work() -> str:
        proj = get_session().open_project(project)
        return f"project {proj.ref.name}\n" + "\n".join(f"  {p}  [{t}]" for p, t in proj.program_files())

    return await asyncio.to_thread(work)


@mcp.tool(annotations=FILEWRITE)
async def import_binary(
    file_path: str,
    project: Optional[str] = None,
    name: Optional[str] = None,
    analyze: bool = True,
    overwrite: bool = False,
    wait_seconds: int = 20,
) -> str:
    """Import a binary into a project (created if missing) and run Ghidra auto-analysis as a background job.

    The binary is only read. Analysis of a large x64 DLL takes minutes: this returns after `wait_seconds` with a
    job id if it is still running; poll with job_status.
    """
    s = get_session()
    await asyncio.to_thread(s.ensure_started)
    jobs = get_jobs()
    job = jobs.submit(
        "import",
        os.path.basename(file_path),
        lambda j: import_program(s, file_path, project, analyze=analyze, name=name, overwrite=overwrite, job=j),
    )
    await asyncio.to_thread(jobs.wait, job, wait_seconds)
    return _job_text(job)


def _job_text(job: Any) -> str:
    lines = [job.status_line()]
    if job.state == "done" and job.result:
        lines += [f"  {k}: {v}" for k, v in job.result.items() if v not in ("", None)]
    elif not job.finished_ok:
        lines.append("  still running: call job_status again to follow progress")
    if job.history:
        lines.append("  recent: " + " || ".join(list(job.history)[-3:]))
    return "\n".join(lines)


@mcp.tool(annotations=READ)
async def job_status(job_id: Optional[str] = None, wait_seconds: int = 0) -> str:
    """Status of a background job (or all jobs). Optionally wait up to `wait_seconds` for it to finish."""
    jobs = get_jobs()
    if job_id is None:
        listing = jobs.list()
        return "\n".join(j.status_line() for j in listing) if listing else "no jobs"
    job = jobs.get(job_id)
    if wait_seconds:
        await asyncio.to_thread(jobs.wait, job, min(wait_seconds, 300))
    return _job_text(job)


@mcp.tool(annotations=WRITE)
async def cancel_job(job_id: str) -> str:
    """Request cancellation of a running job (analysis stops at the next checkpoint)."""
    job = get_jobs().get(job_id)
    job.cancel()
    return f"cancel requested for {job.id}: {job.status_line()}"


# --- program queries --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
async def program_info(project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Format, language, image base, function count, hashes and open mode of a program."""
    return await _run("info", lambda: data.info(_handle(project, program)))


@mcp.tool(annotations=READ)
async def memory_map(project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Memory blocks (sections) with permissions and the file offset each starts at."""
    return await _run("sections", lambda: data.sections(_handle(project, program)))


@mcp.tool(annotations=READ)
async def resolve(location: str, project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Describe a location: address, block, containing function, FILE offset and RVA.

    `location`: 0x1805d0760 | FUN_1805d0760 | rva:0x5d0760 | off:6094176 (file offset). Use this to convert between
    the addresses Ghidra shows and the file offsets patch JSON uses.
    """
    return await _run("resolve", lambda: data.resolve(_handle(project, program), location))


@mcp.tool(annotations=READ)
async def decompile(
    location: str,
    project: Optional[str] = None,
    program: Optional[str] = None,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
) -> str:
    """Decompile the function containing `location`. `offset`/`limit` page by lines (0-based)."""

    def work() -> str:
        h = _handle(project, program)
        text = code.decomp(h, location, timeout=get_session().settings.decompile_timeout)
        return slice_lines(text, offset, limit)

    return await _run(f"decomp-{location}", work)


@mcp.tool(annotations=READ)
async def disassemble(
    location: str,
    project: Optional[str] = None,
    program: Optional[str] = None,
    count: int = 40,
    whole_function: bool = False,
) -> str:
    """Disassemble `count` instructions from `location`, or the whole containing function."""

    def work() -> str:
        h = _handle(project, program)
        return code.disf(h, location) if whole_function else code.dis(h, location, count)

    return await _run(f"dis-{location}", work)


@mcp.tool(annotations=READ)
async def xrefs_to(location: str, project: Optional[str] = None, program: Optional[str] = None, limit: int = 500) -> str:
    """References TO an address (works on any address, including data and mid-function)."""
    return await _run("xrefs", lambda: code.xrefs(_handle(project, program), location, limit))


@mcp.tool(annotations=READ)
async def xrefs_from(location: str, project: Optional[str] = None, program: Optional[str] = None) -> str:
    """References FROM an address."""
    return await _run("xrefs-from", lambda: code.xrefs_from(_handle(project, program), location))


@mcp.tool(annotations=READ)
async def callers(location: str, project: Optional[str] = None, program: Optional[str] = None, limit: int = 500) -> str:
    """Call sites of the function containing `location`."""
    return await _run("callers", lambda: code.callers(_handle(project, program), location, limit))


@mcp.tool(annotations=READ)
async def callees(location: str, project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Functions called directly by the function containing `location`."""
    return await _run("callees", lambda: code.callees(_handle(project, program), location))


@mcp.tool(annotations=READ)
async def find_strings(text: str, project: Optional[str] = None, program: Optional[str] = None, limit: int = 200) -> str:
    """Defined strings containing `text` (case-insensitive), each with cross-references."""
    return await _run("strings", lambda: search.strings(_handle(project, program), text, limit))


@mcp.tool(annotations=READ)
async def scan_instructions(text: str, project: Optional[str] = None, program: Optional[str] = None, limit: int = 400) -> str:
    """Instructions whose text contains `text` (immediates/displacements such as `0x6c0`, `[rax + 0x6c]`). Slow: ~15 s on a 12 MB DLL."""
    return await _run("scan", lambda: search.scan(_handle(project, program), text, limit))


@mcp.tool(annotations=READ)
async def find_symbols(text: str, project: Optional[str] = None, program: Optional[str] = None, limit: int = 300) -> str:
    """Symbols whose name contains `text`."""
    return await _run("symbols", lambda: search.symbols(_handle(project, program), text, limit))


@mcp.tool(annotations=READ)
async def find_bytes(pattern: str, project: Optional[str] = None, program: Optional[str] = None, limit: int = 50) -> str:
    """Find a byte pattern, e.g. `B8 63 00 00 00 C3` or with wildcards `48 8B ?? 10`. Reports file offsets too."""
    return await _run("find-bytes", lambda: search.search_bytes(_handle(project, program), pattern, limit))


@mcp.tool(annotations=READ)
async def read_bytes(location: str, count: int, project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Raw bytes at an address."""
    return await _run("bytes", lambda: data.read_bytes(_handle(project, program), location, count))


@mcp.tool(annotations=READ)
async def pointer_table(location: str, count: int = 40, project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Dump `count` pointers and the function each targets (vtables, jump tables)."""
    return await _run("ptrs", lambda: data.pointer_table(_handle(project, program), location, count))


@mcp.tool(annotations=READ)
async def data_at(location: str, project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Defined data at an address: type, value, label and cross-references."""
    return await _run("data", lambda: data.data_at(_handle(project, program), location))


@mcp.tool(annotations=READ)
async def rtti_classes(text: str = "", project: Optional[str] = None, program: Optional[str] = None) -> str:
    """C++ classes recovered from RTTI, optionally filtered by `text`."""
    return await _run("rtti", lambda: search.rtti(_handle(project, program), text))


@mcp.tool(annotations=READ)
async def query(commands_text: str, project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Run several query commands in ONE call (cheapest way to explore). One command per line, e.g.:

    decomp 0x1805d0760 / disf 0x1805d08c0 / xrefs 0x180b9c4d4 / str config / scan 0x6c0 / find B8 63 00 00 00 C3 /
    bytes 0x1805d0760 16 / vt 0x180958a88 4 / rtti Manager / resolve off:6094176 / sections / info.
    Results are framed by `=========== <command> ===========`.
    """

    def work() -> str:
        s = get_session()
        return commands.run_script(_handle(project, program), commands_text.splitlines(), s.settings)

    return await _run("query", work)


# --- annotations (write) ----------------------------------------------------------------------


@mcp.tool(annotations=WRITE)
async def rename(location: str, new_name: str, project: Optional[str] = None, program: Optional[str] = None, save: bool = False) -> str:
    """Rename the function/label at `location` (opens the program read-write). Persisted only when `save` is true or save_program is called."""

    def work() -> str:
        h = _handle(project, program, write=True)
        msg = annotate.rename(h, location, new_name)
        if save:
            h.save()
            msg += " (saved)"
        return msg

    return await asyncio.to_thread(work)


@mcp.tool(annotations=WRITE)
async def set_comment(
    location: str,
    text: str,
    kind: str = "eol",
    project: Optional[str] = None,
    program: Optional[str] = None,
    save: bool = False,
) -> str:
    """Set a comment (kind: eol, pre, post, plate, repeatable) at `location`."""

    def work() -> str:
        h = _handle(project, program, write=True)
        msg = annotate.set_comment(h, location, text, kind)
        if save:
            h.save()
            msg += " (saved)"
        return msg

    return await asyncio.to_thread(work)


@mcp.tool(annotations=WRITE)
async def save_program(project: Optional[str] = None, program: Optional[str] = None) -> str:
    """Save pending renames/comments of a program opened read-write."""

    def work() -> str:
        h = _handle(project, program)
        if not h.writable:
            return f"{h.name} is open read-only: nothing to save"
        h.save()
        return f"{h.name} saved"

    return await asyncio.to_thread(work)


# --- PE + patch tools (no Ghidra needed) ------------------------------------------------------


@mcp.tool(annotations=READ)
async def pe_sections(file_path: str) -> str:
    """PE headers and section table of a file on disk (no Ghidra needed). Shows the VA-minus-offset delta per section."""
    from .pe import format_sections, parse_pe

    return format_sections(parse_pe(file_path))


@mcp.tool(annotations=READ)
async def offset_to_va(file_path: str, offsets: list[str]) -> str:
    """Convert FILE offsets (decimal or 0x hex) to virtual addresses for a PE file."""
    from .pe import NotMappedError, parse_pe

    pe = parse_pe(file_path)
    out = []
    for raw in offsets:
        try:
            out.append(pe.describe_offset(parse_int(raw)))
        except (NotMappedError, ValueError) as e:
            out.append(f"{raw}: {e}")
    return "\n".join(out)


@mcp.tool(annotations=READ)
async def va_to_offset(file_path: str, addresses: list[str]) -> str:
    """Convert virtual addresses to FILE offsets for a PE file."""
    from .pe import NotMappedError, parse_pe

    pe = parse_pe(file_path)
    out = []
    for raw in addresses:
        try:
            va = parse_hex(raw)
            off = pe.va_to_offset(va)
            out.append(f"VA 0x{va:X} -> file 0x{off:X} ({off})")
        except (NotMappedError, ValueError) as e:
            out.append(f"{raw}: {e}")
    return "\n".join(out)


@mcp.tool(annotations=READ)
async def patch_verify(file_path: str, patch_file: str, entries: Optional[list[str]] = None) -> str:
    """Check a binary against a patch JSON (file-offset entries): each patch must contain its expected original bytes
    (state ORIGINAL) or already be applied. Reports the VA of each patch. Read-only."""
    from .patch import load_entries, select_entries, verify

    return verify(file_path, select_entries(load_entries(patch_file), entries)).format()


@mcp.tool(annotations=FILEWRITE)
async def patch_apply(
    file_path: str,
    patch_file: str,
    output_path: str,
    entries: Optional[list[str]] = None,
    overwrite: bool = False,
) -> str:
    """Write a patched COPY of `file_path` to `output_path` (the source is never modified; aborts before writing if any
    expected original bytes are missing)."""
    from .patch import apply, load_entries, select_entries

    return apply(file_path, output_path, select_entries(load_entries(patch_file), entries), overwrite=overwrite).format()


@mcp.tool(annotations=READ)
async def patch_make(
    file_path: str,
    name: str,
    edits: list[str],
    description: str = "",
    game_code: Optional[str] = None,
    dll_name: Optional[str] = None,
) -> str:
    """Build a patch JSON entry. `edits` are `LOCATION=HEX` strings, e.g. `va:0x1805D0760=B863000000C3` or
    `off:0x5CFD60=9090`; the original bytes are read from the file, so dataDisabled is always exact. Returns JSON text."""
    from .patch import dump_entries, make_entry

    parsed = []
    for e in edits:
        loc, sep, hx = e.partition("=")
        if not sep:
            raise KhxError(f"edit {e!r} must look like LOCATION=HEX")
        parsed.append((loc, hx))
    return dump_entries([make_entry(file_path, parsed, name=name, description=description, game_code=game_code, dll_name=dll_name)])


@mcp.tool(annotations=READ)
async def branch_encode(at: str, to: str, op: str = "jmp", short: bool = False) -> str:
    """Encode a branch at address `at` to `to`: jmp (EB rel8 with short=true, else E9 rel32), call (E8), or a conditional
    short jump such as jnz/jbe. Handles the signed displacement for you."""
    from .patch import asm

    src, dst = parse_hex(at), parse_hex(to)
    op_l = op.lower()
    if op_l == "jmp":
        enc = asm.jmp_short(src, dst) if short else asm.jmp_near(src, dst)
    elif op_l == "call":
        enc = bytes([0xE8]) + ((dst - (src + 5)) & 0xFFFFFFFF).to_bytes(4, "little")
    else:
        enc = asm.jcc_short(op_l, src, dst)
    return f"{op_l} 0x{src:X} -> 0x{dst:X}: {enc.hex().upper()}"


# --- entry point ------------------------------------------------------------------------------


def _isolate_stdout() -> None:
    """Make fd 1 (and, on Windows, the OS stdout handle) point at stderr so JVM/native output cannot corrupt the
    protocol; hand the MCP SDK a private duplicate of the original stdout."""
    sys.stdout.flush()
    proto_fd = os.dup(1)
    os.dup2(2, 1)
    if os.name == "nt":
        import ctypes
        import msvcrt

        ctypes.windll.kernel32.SetStdHandle(-11, msvcrt.get_osfhandle(2))  # STD_OUTPUT_HANDLE
    sys.stdout = io.TextIOWrapper(os.fdopen(proto_fd, "wb"), encoding="utf-8", write_through=True)


def _warm_up_jvm() -> None:
    """Start Ghidra's JVM now, on the main thread, before the event loop exists.

    Starting it lazily from a worker thread (asyncio.to_thread) deadlocks inside ``jpype.startJVM`` on Windows while
    the asyncio loop is running (reproduced: no output after "starting Ghidra"). Later calls from worker threads are
    fine. If Ghidra is not configured the server still starts: PE/patch tools work without it.
    """
    from .config import ConfigError

    try:
        get_session().ensure_started()
    except ConfigError as e:
        log.warning("Ghidra not available (%s); only the PE/patch tools will work", e)
    except Exception:  # noqa: BLE001
        log.exception("could not start Ghidra; only the PE/patch tools will work")


def run() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    _isolate_stdout()
    _warm_up_jvm()
    mcp.run()


if __name__ == "__main__":
    run()
