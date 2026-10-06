"""Text command language shared by the CLI (``khx query``) and the MCP ``query`` tool.

One command per line, same spirit as the Q.java helper used in the original patch port. Several commands can be
batched in one call, which is the cheapest way to explore (one round trip, one program lock).

    decomp <addr>            decompile the function containing addr
    dis <addr> [n]           disassemble n instructions (default 40) from addr
    disf <addr>              disassemble the whole function containing addr
    func <addr>              function bounds
    xrefs <addr>             references to addr
    xfrom <addr>             references from addr
    callers <addr>           call sites of the function containing addr
    callees <addr>           functions called by the function containing addr
    str <text>               defined strings containing text, with xrefs
    scan <text>              instructions whose text contains text (immediates, displacements)
    sym <text>               symbols whose name contains text
    find <hex pattern>       byte pattern search, e.g. "B8 63 ?? 00 00 00 C3"
    bytes <addr> <n>         raw bytes
    vt <addr> [n]            pointer table dump (vtables, jump tables)
    data <addr>              defined data at addr
    rtti [text]              C++ classes recovered from RTTI
    info | sections          program summary / memory blocks
    resolve <addr>           block, function, file offset and rva for an address

<addr> is a hex VA (0x1805d0760), a symbol (FUN_1805d0760), or va:/rva:/off: forms (off: is a FILE offset).
Lines starting with # are ignored.
"""

from __future__ import annotations

from typing import Callable

from .config import Settings
from .core.errors import KhxError
from .core.session import ProgramHandle
from .queries import code, data, search

Handler = Callable[[ProgramHandle, list[str], Settings], str]


def _need(args: list[str], n: int, usage: str) -> None:
    if len(args) < n:
        raise KhxError(f"usage: {usage}")


def _int(text: str, usage: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise KhxError(f"usage: {usage} (bad number {text!r})") from None


def _rest(args: list[str]) -> str:
    return " ".join(args)


COMMANDS: dict[str, tuple[str, Handler]] = {
    "decomp": ("decomp <addr>", lambda h, a, s: (_need(a, 1, "decomp <addr>"), code.decomp(h, a[0], timeout=s.decompile_timeout))[1]),
    "dis": ("dis <addr> [n]", lambda h, a, s: (_need(a, 1, "dis <addr> [n]"), code.dis(h, a[0], _int(a[1], "dis <addr> [n]") if len(a) > 1 else 40))[1]),
    "disf": ("disf <addr>", lambda h, a, s: (_need(a, 1, "disf <addr>"), code.disf(h, a[0]))[1]),
    "func": ("func <addr>", lambda h, a, s: (_need(a, 1, "func <addr>"), code.func(h, a[0]))[1]),
    "xrefs": ("xrefs <addr>", lambda h, a, s: (_need(a, 1, "xrefs <addr>"), code.xrefs(h, a[0]))[1]),
    "xfrom": ("xfrom <addr>", lambda h, a, s: (_need(a, 1, "xfrom <addr>"), code.xrefs_from(h, a[0]))[1]),
    "callers": ("callers <addr>", lambda h, a, s: (_need(a, 1, "callers <addr>"), code.callers(h, a[0]))[1]),
    "callees": ("callees <addr>", lambda h, a, s: (_need(a, 1, "callees <addr>"), code.callees(h, a[0]))[1]),
    "str": ("str <text>", lambda h, a, s: search.strings(h, _rest(a))),
    "scan": ("scan <text>", lambda h, a, s: (_need(a, 1, "scan <text>"), search.scan(h, _rest(a)))[1]),
    "sym": ("sym <text>", lambda h, a, s: (_need(a, 1, "sym <text>"), search.symbols(h, _rest(a)))[1]),
    "find": ("find <hex pattern>", lambda h, a, s: (_need(a, 1, "find <hex pattern>"), search.search_bytes(h, _rest(a)))[1]),
    "bytes": ("bytes <addr> <n>", lambda h, a, s: (_need(a, 2, "bytes <addr> <n>"), data.read_bytes(h, a[0], _int(a[1], "bytes <addr> <n>")))[1]),
    "vt": ("vt <addr> [n]", lambda h, a, s: (_need(a, 1, "vt <addr> [n]"), data.pointer_table(h, a[0], _int(a[1], "vt <addr> [n]") if len(a) > 1 else 40))[1]),
    "data": ("data <addr>", lambda h, a, s: (_need(a, 1, "data <addr>"), data.data_at(h, a[0]))[1]),
    "rtti": ("rtti [text]", lambda h, a, s: search.rtti(h, _rest(a))),
    "info": ("info", lambda h, a, s: data.info(h)),
    "sections": ("sections", lambda h, a, s: data.sections(h)),
    "resolve": ("resolve <addr>", lambda h, a, s: (_need(a, 1, "resolve <addr>"), data.resolve(h, a[0]))[1]),
}
ALIASES = {"strings": "str", "disasm": "dis", "decompile": "decomp", "xref": "xrefs", "blocks": "sections"}


def help_text() -> str:
    return __doc__ or ""


def run_command(h: ProgramHandle, line: str, settings: Settings) -> str:
    """Run one command line; returns its output text (raises :class:`KhxError` for usage/lookup errors)."""
    parts = line.strip().split()
    if not parts:
        return ""
    name = ALIASES.get(parts[0].lower(), parts[0].lower())
    if name not in COMMANDS:
        raise KhxError(f"unknown command {parts[0]!r}; commands: {', '.join(sorted(COMMANDS))}")
    return COMMANDS[name][1](h, parts[1:], settings)


def run_script(h: ProgramHandle, lines: list[str], settings: Settings) -> str:
    """Run several command lines; each result is framed like the Q.java output (``=========== line ===========``)."""
    blocks: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            result = run_command(h, line, settings)
        except KhxError as e:
            result = f"ERR {e}"
        except Exception as e:  # Java exceptions etc.: keep the batch going
            result = f"ERR {type(e).__name__}: {e}"
        blocks.append(f"\n=========== {line} ===========\n{result}")
    return "\n".join(blocks).lstrip("\n") if blocks else ""
