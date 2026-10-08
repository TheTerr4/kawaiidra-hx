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
from pathlib import Path
from typing import Any, Callable, Optional

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import annotate, commands
from .core import KhxError, ProgramHandle, get_session, list_projects
from .core.jobs import get_jobs, import_program
from .outputs import emit, slice_lines
from .pe import PEImage
from .queries import code, data, search
from .util import parse_hex, parse_int

log = logging.getLogger("khx.mcp")

INSTRUCTIONS = """\
kawaiidra-hx: Ghidra-backed reverse engineering for Windows PE binaries, plus patch tooling.

Workflow: list_projects -> (import_binary if the binary is not in a project; it runs as a job, poll job_status)
-> explore with `query` (batch many commands in ONE call: decomp/disf/xrefs/str/scan/...) or the single-purpose tools.
Locations accept 0x1805d0760, FUN_1805d0760, rva:0x5d0760 and off:0x5CFD60 (FILE offset, as used by patch JSON).
Patch work needs no Ghidra: pe_identify / pe_sections / pe_imports / pe_exports / offset_to_va / va_to_offset / patch_show /
patch_verify / patch_apply / patch_diff (apply writes a COPY, never the original). Programs are read-only unless you call a write tool (rename, set_comment) and then save_program.
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
async def pe_identify(file_path: str, game_codes: Optional[list[str]] = None) -> str:
    """Build identity of a PE file: sha256, machine, linker timestamp, entry point and the build/patch identifier
    (`{gameCode}-{TimeDateStamp:x}_{EntryRVA:x}`, e.g. ABC-12345678_1000) for each game code given. No Ghidra needed."""
    from .pe import PEImage

    ident = PEImage(file_path).identity
    lines = [
        f"file {ident.path}", f"size {ident.size}", f"sha256 {ident.sha256}",
        f"machine {ident.machine} ({'PE32+' if ident.is_64bit else 'PE32'} {'DLL' if ident.is_dll else 'EXE'})",
        f"image base 0x{ident.image_base:X}", f"timestamp 0x{ident.timestamp:x} ({ident.build_time} UTC)",
        f"entry RVA 0x{ident.entry_rva:x}",
    ]  # fmt: skip
    lines += [f"patch id {ident.pe_identifier(c)}" for c in game_codes or []]
    return "\n".join(lines)


@mcp.tool(annotations=READ)
async def pe_exports(file_path: str) -> str:
    """Export table of a PE file (ordinal, RVA, name, forwarder). No Ghidra needed."""
    from .pe import PEImage

    ex = PEImage(file_path).exports
    if ex is None:
        return "(no export directory)"
    rows = [f"module {ex.module_name}  ordinal base {ex.ordinal_base}  {len(ex.exports)} export(s)"]
    rows += [f"#{e.ordinal} 0x{e.rva:08X} {e.name or '<ordinal only>'}" + (f" -> {e.forwarder}" if e.forwarder else "") for e in ex.exports]
    return "\n".join(rows)


@mcp.tool(annotations=READ)
async def pe_imports(file_path: str, dll: Optional[str] = None) -> str:
    """Imports of a PE file grouped by library; pass `dll` (substring) to list that library's symbols with IAT RVAs
    (ordinal imports show as #N). No Ghidra needed."""
    from .pe import PEImage

    out: list[str] = []
    for lib in PEImage(file_path).imports:
        if dll and dll.lower() not in lib.dll.lower():
            continue
        extra = f", {lib.by_ordinal} by ordinal" if lib.by_ordinal else ""
        out.append(f"{lib.dll}{' (delay-load)' if lib.delay else ''}  {len(lib.symbols)} import(s){extra}")
        if dll:
            out += [f"    0x{sy.iat_rva:08X}  {sy.label}" for sy in lib.symbols]
    return "\n".join(out) or "(no matching imports)"


@mcp.tool(annotations=READ)
async def patch_show(patch_file: str) -> str:
    """List the entries of a patch JSON (type, name, offsets/options). Understands memory, union, number, signature and
    group entries and the metadata header."""
    from .patch import describe_entries, load_patchfile

    return describe_entries(load_patchfile(patch_file))


@mcp.tool(annotations=READ)
async def patch_verify(
    file_path: str, patch_file: str, entries: Optional[list[str]] = None, ignore_identity: bool = False
) -> str:
    """Check a binary against a patch JSON (file-offset entries). memory: ORIGINAL or APPLIED; union: which option the
    file currently holds; number: current value vs range; signature: resolved offset + match count. Also checks that the
    binary is the build the patch file names (PE identifier from its file name / `peIdentifier`) unless ignore_identity.
    Reports the VA of each patch. Read-only."""
    from .patch import load_patchfile, select_entries, verify

    pf = load_patchfile(patch_file)
    expected = None if ignore_identity else pf.pe_identifier
    return verify(file_path, select_entries(pf.entries, entries), expected_id=expected).format()


@mcp.tool(annotations=FILEWRITE)
async def patch_apply(
    file_path: str,
    patch_file: str,
    output_path: str,
    entries: Optional[list[str]] = None,
    overwrite: bool = False,
    set_values: Optional[list[str]] = None,
    revert: bool = False,
    ignore_identity: bool = False,
) -> str:
    """Write a patched COPY of `file_path` to `output_path` (the source is never modified; aborts before writing if any
    expected original bytes are missing or the build differs). `set_values` choose union options / number values as
    `NAME=VALUE` (unselected unions/numbers are skipped); `revert=true` restores the original bytes of memory/signature patches."""
    from .patch import apply, load_patchfile, select_entries

    sel: dict[str, str] = {}
    for item in set_values or []:
        name, sep, value = item.rpartition("=")
        if not sep or not name:
            raise KhxError(f"set_values item {item!r} must look like NAME=VALUE")
        sel[name] = value
    pf = load_patchfile(patch_file)
    rep = apply(
        file_path, output_path, select_entries(pf.entries, entries), overwrite=overwrite, selections=sel,
        mode="revert" if revert else "apply", expected_id=None if ignore_identity else pf.pe_identifier,
    )  # fmt: skip
    return rep.format()


@mcp.tool(annotations=READ)
async def patch_make(
    file_path: str,
    name: str,
    edits: list[str],
    description: str = "",
    game_code: Optional[str] = None,
    dll_name: Optional[str] = None,
    pe_identifier: Optional[str] = None,
    caution: str = "",
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
    entry = make_entry(
        file_path, parsed, name=name, description=description, game_code=game_code, dll_name=dll_name,
        pe_identifier=pe_identifier, caution=caution,
    )  # fmt: skip
    return dump_entries([entry])


@mcp.tool(annotations=READ)
async def patch_diff(
    original_path: str,
    modified_path: str,
    name: str,
    game_code: Optional[str] = None,
    dll_name: Optional[str] = None,
    gap: int = 0,
    pad: int = 0,
) -> str:
    """Turn the byte differences between two same-size binaries into a `memory` patch entry (JSON text): dataDisabled from
    the original, dataEnabled from the modified file. `gap` merges runs closer than that many bytes; `pad` adds context bytes."""
    from .patch import diff_entry, dump_entries

    return dump_entries([diff_entry(original_path, modified_path, name=name, game_code=game_code, dll_name=dll_name, gap=gap, pad=pad)])


@mcp.tool(annotations=READ)
async def branch_encode(at: str, to: str, op: str = "jmp", short: bool = False, near: bool = False) -> str:
    """Encode a branch at address `at` to `to`: jmp (EB rel8 with short=true, else E9 rel32), call (E8 rel32), or a conditional
    jump such as jnz/jbe (2-byte short form; near=true gives 0F 8x rel32). Handles the signed displacement for you."""
    from .patch import asm

    src, dst = parse_hex(at), parse_hex(to)
    op_l = op.lower()
    enc = asm.branch(op_l, src, dst, short=short, near=near)
    return f"{op_l} 0x{src:X} -> 0x{dst:X}: {enc.hex().upper()}"


@mcp.tool(annotations=READ)
async def sig_make(
    patch_files: list[str],
    project: Optional[str] = None,
    program: Optional[str] = None,
    binary: Optional[str] = None,
    only: Optional[str] = None,
    max_bytes: int = 48,
    min_fixed: int = 12,
    allow_usage: bool = True,
    include_json: bool = False,
) -> str:
    """Synthesize version-independent `signature` patch entries for the memory patches of `patch_files` (patch JSON(s) for this
    exact binary): the smallest masked byte pattern around each site that is unique in the file, with position-dependent operands
    (relative branches, RIP-relative/absolute addresses, relocations) wildcarded, verified to resolve back to the exact site.
    `binary` is the file the program was imported from (default: the path Ghidra recorded). Returns the per-site report;
    include_json=true appends the patch file JSON. Read-only (writes nothing)."""
    from . import sigs

    def work() -> str:
        h = _handle(project, program)
        rep = sigs.make_signatures(h, patch_files, binary=binary, only=only, max_bytes=max_bytes, min_fixed=min_fixed, allow_usage=allow_usage)
        text = rep.format()
        if include_json and rep.patchfile is not None:
            text += "\n\n" + rep.patchfile.dumps()
        return text

    return await _run("sig_make", work)


@mcp.tool(annotations=READ)
async def sig_check(patch_file: str, files: list[str]) -> str:
    """Resolve every `signature` entry of a patch JSON in each binary and report where it lands (unique / ambiguous /
    not found, file offset and VA). The test a signature patch has to survive when the binary is rebuilt. No Ghidra needed."""
    from . import sigs
    from .patch import load_patchfile

    return sigs.check_signatures(load_patchfile(patch_file), files).format()


def _target_handle(project: Optional[str], target_project: Optional[str], program: str, write: bool = False):
    return get_session().program(target_project or project, program, write=write)


@mcp.tool(annotations=READ)
async def match_functions(
    source: str,
    target: str,
    project: Optional[str] = None,
    target_project: Optional[str] = None,
    addresses: Optional[list[str]] = None,
    only: Optional[str] = None,
    named_only: bool = False,
    limit: int = 40,
    no_strings: bool = False,
    refresh: bool = False,
) -> str:
    """Match the functions of two analysed builds of a binary (`source` = the one you know, `target` = the new one; both programs in
    `project`, or `target_project`) through unique strings, imports, constants, RTTI vtable slots, the call graph and the order the
    functions sit in the image. Pass `addresses` (any address inside a source function) to get each one's counterpart with the evidence
    (method, similarity, margin) or, when there is none, the candidates between its neighbours' counterparts. Without addresses it
    summarises and lists matches (`only` filters by source name, `named_only` skips unnamed functions). Fingerprints are cached by file
    hash, so only the first call per binary is slow. Read-only."""
    from .match import run

    def work() -> str:
        a = _handle(project, source)
        b = _target_handle(project, target_project, target)
        res = run.compare(a, b, refresh=refresh, kinds=("imports", "consts") if no_strings else None)
        out = [run.summary(res)]
        if addresses:
            out.append(run.counterparts(res, [parse_hex(x) for x in addresses]))
        else:
            out.append(run.listing(res, limit=limit, only=only, named_only=named_only))
        return chr(10).join(out)

    return await _run("match_functions", work)


@mcp.tool(annotations=WRITE)
async def match_carry_names(
    source: str,
    target: str,
    project: Optional[str] = None,
    target_project: Optional[str] = None,
    dry_run: bool = True,
    rename: bool = True,
    force: bool = False,
    clear: bool = False,
    min_score: float = 0.7,
    min_margin: float = 0.05,
) -> str:
    """Carry the names you gave functions in the `source` program to their counterparts in the `target` program: a tagged plate comment and a
    `khx-match` bookmark on each, and a rename when the target function still has its default FUN_ name (`force` renames others too; `rename=false`
    leaves names alone). `dry_run` (the default) only reports. `clear=true` undoes an earlier run (removes the tags, gives the old names back).
    Strong evidence (unique strings, rare features, RTTI slots) always counts; an alignment match needs `min_score` and `min_margin`.
    Writes need save_program afterwards."""
    from .match import run, transfer

    def work() -> str:
        a = _handle(project, source)
        b = _target_handle(project, target_project, target, write=not dry_run or clear)
        if clear:
            return str(transfer.clear_program(b))
        res = run.compare(a, b)
        carries = transfer.plan(res.matched, transfer.source_names(a), min_score=min_score, min_margin=min_margin)
        rep = transfer.apply_carries(b, carries, source_label=a.name, rename=rename, force=force, dry_run=dry_run)
        return run.summary(res) + chr(10) + f"{len(carries)} named function(s) have a match strong enough to carry" + chr(10) + rep.format()

    return await _run("match_carry_names", work)


@mcp.tool(annotations=READ)
async def port_patches(
    source: str,
    target_file: str,
    patch_files: list[str],
    project: Optional[str] = None,
    source_binary: Optional[str] = None,
    only: Optional[str] = None,
    allow_partial: bool = False,
    anchors: bool = False,
    target_program: Optional[str] = None,
    target_project: Optional[str] = None,
    include_json: bool = False,
) -> str:
    """Carry the patches of an analysed build (`source`, with `patch_files` written for it) to another build's file (`target_file`): per site the
    signature made in the source, windows leaning other ways around it, the string a data patch edits, and with `anchors=true` (both builds analysed;
    `target_program` names the target in the project) the function holding the site matched between the builds. Nothing is guessed: a site is ported
    only when the evidence is unique, a multi-site entry only when every site was found (`allow_partial` to emit the rest, flagged), and the result is
    verified against the target. The target needs no Ghidra without `anchors`. Returns the report; `include_json=true` appends the patch file JSON."""
    from . import sigs
    from .match.anchors import AnchorContext
    from .match.store import FingerprintStore
    from .pe import PEImage
    from .port import port_build

    def work() -> str:
        h = _handle(project, source)
        img = PEImage(target_file)
        made = sigs.make_signatures(h, patch_files, binary=source_binary, only=only)
        code = made.build_id.split("-", 1)[0]
        to_id = img.identity.pe_identifier(code)
        if made.build_id == to_id:
            raise KhxError(f"source and target are the same build ({to_id})")
        ctx = None
        if anchors:
            if not target_program:
                raise KhxError("anchors=true needs target_program: the target as imported in the project")
            store = FingerprintStore()
            dst = _target_handle(project, target_project, target_program)
            a, b = store.index(h, source_binary), store.index(dst, target_file)
            ctx = AnchorContext(a, b, PEImage(sigs.original_bytes(h, source_binary)), img, cache=store.dir / f"align_{a.build_id}_{b.build_id}.pkl")
        rep = port_build(made, img, to_id, game_code=code, allow_partial=allow_partial, anchors=ctx)
        text = rep.format()
        if include_json and rep.patchfile is not None:
            text += chr(10) * 2 + rep.patchfile.dumps()
        return text

    return await _run("port_patches", work)


@mcp.tool(annotations=READ)
async def triage(file_path: str, game_code: str = "PE") -> str:
    """A first look at any binary, from the file alone (no Ghidra): identity and build id, DLL/EXE and export count, sections with flags and
    entropy (W+X and packed-looking ones flagged), data directories, relocations, exports, imports grouped by class (system / C++ runtime /
    must ship with the program, ordinal-only imports flagged), PDB path, and embedded URLs, build paths, version and copyright strings.
    A file that is not a PE image is described by its first bytes and entropy."""
    from . import triage as _triage

    return _triage.triage(file_path, game_code=game_code)


@mcp.tool(annotations=WRITE)
async def imports_resolve(
    project: Optional[str] = None,
    program: Optional[str] = None,
    libs: Optional[list[str]] = None,
    binary: Optional[str] = None,
    skip_regex: Optional[str] = None,
    dry_run: bool = True,
    restore: bool = False,
) -> str:
    """Name the imports-by-ordinal of a program (`Ordinal_12`) from the export tables of the libraries shipped with the module: looked up in `libs`
    (folders), next to `binary` and next to the file the program was imported from. `skip_regex` leaves exports with matching names alone (hashed
    names). `dry_run` (the default) only reports; `restore=true` puts the `Ordinal_N` names back. Ghidra already resolves them if the library was in
    the same folder at import time. Writes need save_program afterwards."""
    from . import annotate, imports as _imports, sigs

    def work() -> str:
        h = _handle(project, program, write=not dry_run)
        image = PEImage(sigs.original_bytes(h, binary))
        found = _imports.resolve_ordinals(image, _imports.default_dirs(h, binary, [Path(d) for d in libs or []]), skip_regex=skip_regex)
        text = _imports.format_resolution(found)
        mapping = _imports.external_renames(found)
        if dry_run or not mapping:
            return text
        counts = annotate.rename_externals(h, mapping, restore=restore)
        return text + chr(10) + ("restored " if restore else "renamed ") + ", ".join(f"{v} {k}" for k, v in counts.items())

    return await _run("imports_resolve", work)


@mcp.tool(annotations=READ)
async def list_patch_sites(
    patch_files: list[str],
    project: Optional[str] = None,
    program: Optional[str] = None,
    only: Optional[str] = None,
    binary: Optional[str] = None,
    game_code: Optional[str] = None,
) -> str:
    """The patch sites of patch JSON(s) for this program: file offset -> virtual address -> function, and whether the bytes in the program are the
    original, the patched form, a union option, or neither (wrong build). Signature entries are resolved against `binary` (default: the file the
    program was imported from). Read-only."""
    from . import sites as _sites

    def work() -> str:
        h = _handle(project, program)
        build_id, found, notes = _sites.build_context(h, patch_files, binary=binary, only=only, game_code=game_code)
        return f"build {build_id}" + chr(10) + _sites.format_sites(_sites.resolve_sites(h, found), notes)

    return await _run("list_patch_sites", work)


@mcp.tool(annotations=WRITE)
async def annotate_patch_sites(
    patch_files: list[str],
    project: Optional[str] = None,
    program: Optional[str] = None,
    only: Optional[str] = None,
    binary: Optional[str] = None,
    game_code: Optional[str] = None,
    force: bool = False,
    dry_run: bool = True,
    clear: bool = False,
) -> str:
    """Put the patch sites into the program: a `patch_*` label, a `khx-patch` bookmark and a tagged comment at each site, and a plate comment on the
    function that holds it. A site is annotated only if its bytes match what the patch file expects (`force` overrides); functions are never renamed;
    re-running is idempotent. `dry_run` (the default) only reports; `clear=true` removes everything this tool wrote. Writes need save_program afterwards."""
    from . import sites as _sites

    def work() -> str:
        h = _handle(project, program, write=not dry_run or clear)
        if clear:
            counts = _sites.clear_program(h)
            return "removed " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in counts.items())
        return _sites.annotate_program(h, patch_files, binary=binary, only=only, force=force, dry_run=dry_run, game_code=game_code).format()

    return await _run("annotate_patch_sites", work)


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
