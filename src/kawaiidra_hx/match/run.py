"""Glue for ``khx match`` / ``khx port --anchors`` and their MCP tools: fingerprint two analysed programs (cached), align their functions
(cached), and answer questions about the result. Used by the CLI and the MCP server; the algorithms live in the sibling modules."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Union

from ..core.errors import KhxError
from ..core.session import ProgramHandle
from ..pe import PEImage
from ..queries.fingerprint import FuncFP
from ..sigs import original_bytes
from .anchors import AnchorContext
from .funcmatch import FMatch
from .store import FingerprintStore


@dataclass
class MatchResult:
    source: ProgramHandle
    target: ProgramHandle
    ctx: AnchorContext
    source_label: str
    target_label: str

    @property
    def matched(self) -> dict[int, FMatch]:
        return self.ctx.matched

    @property
    def cross_isa(self) -> bool:
        return self.ctx.cross_isa


def compare(
    source: ProgramHandle,
    target: ProgramHandle,
    *,
    source_binary: Union[str, Path, None] = None,
    target_binary: Union[str, Path, None] = None,
    refresh: bool = False,
    kinds: Optional[tuple[str, ...]] = None,
    log: Optional[Callable[[str], None]] = None,
    store: Optional[FingerprintStore] = None,
) -> MatchResult:
    """Align the functions of two analysed programs. Fingerprints are cached by file hash, the alignment by the pair."""
    store = store or FingerprintStore(refresh=refresh, log=log)
    img_a = PEImage(original_bytes(source, source_binary))
    img_b = PEImage(original_bytes(target, target_binary))
    A = store.index(source, source_binary)
    B = store.index(target, target_binary)
    cache = store.dir / f"align_{A.build_id}_{B.build_id}.pkl"
    if refresh and cache.exists():
        cache.unlink()
    ctx = AnchorContext(A, B, img_a, img_b, cache=cache, kinds=kinds, log=(lambda m: log(f"align: {m}")) if log else None)
    return MatchResult(source, target, ctx, source.name, target.name)


def _name(fp: Optional[FuncFP]) -> str:
    return fp.name if fp is not None else "?"


def summary(res: MatchResult) -> str:
    m = res.matched
    by = Counter(x.method for x in m.values())
    total = len(res.ctx.A.funcs)
    kinds = ", ".join(f"{n} {k}" for k, n in sorted(by.items(), key=lambda kv: -kv[1]))
    isa = "different ISAs: lower similarity bar" if res.cross_isa else "same ISA"
    return (f"match {res.source_label} -> {res.target_label}: {len(m)} of {total} functions matched ({100 * len(m) / total:.0f}%)"
            f" [{kinds or 'none'}]; {isa}")


def format_pair(res: MatchResult, a: int) -> str:
    fa = res.ctx.A.funcs[a]
    m = res.matched.get(a)
    if m is None:
        near = res.ctx.candidates(a, 3)
        hint = ("; candidates between the counterparts of its neighbours: " + ", ".join(f"0x{e:X} {_name(res.ctx.B.funcs.get(e))} ({s:.2f})" for e, s in near)) if near else ""
        return f"0x{a:X} {fa.name}: no counterpart{hint}"
    fb = res.ctx.B.funcs.get(m.b)
    return f"0x{a:X} {fa.name} -> 0x{m.b:X} {_name(fb)}   {m.method}, similarity {m.score:.2f}" + (f", margin {m.margin:.2f}" if m.margin else "")


def counterparts(res: MatchResult, addresses: list[int]) -> str:
    """For each address (any address inside a function of the source), the function that holds it and its counterpart."""
    out = []
    for va in addresses:
        fa = res.ctx.A.containing(va)
        out.append(f"0x{va:X}: not inside a function of {res.source_label}" if fa is None else format_pair(res, fa.entry))
    return "\n".join(out)


def listing(res: MatchResult, *, limit: int = 40, only: Optional[str] = None, named_only: bool = False) -> str:
    rows = []
    for a, m in sorted(res.matched.items()):
        fa = res.ctx.A.funcs[a]
        if named_only and fa.name.startswith(("FUN_", "thunk_FUN_")):
            continue
        if only and only.casefold() not in fa.name.casefold():
            continue
        rows.append(format_pair(res, a))
    shown = rows[:limit] if limit else rows
    more = f"\n... {len(rows) - len(shown)} more (--limit 0 for all, --json FILE to export)" if len(shown) < len(rows) else ""
    return "\n".join(shown) + more if shown else "(no matches to list)"


def dump_json(res: MatchResult, path: Union[str, Path]) -> int:
    rows = []
    for a, m in sorted(res.matched.items()):
        fa, fb = res.ctx.A.funcs[a], res.ctx.B.funcs.get(m.b)
        rows.append({"source": f"0x{a:X}", "source_name": fa.name, "target": f"0x{m.b:X}", "target_name": _name(fb),
                     "method": m.method, "similarity": round(m.score, 4), "margin": round(m.margin, 4)})  # fmt: skip
    Path(path).write_text(json.dumps({"source": res.source_label, "target": res.target_label, "matches": rows}, indent=1), encoding="utf-8")
    return len(rows)


def require_same_pair(res: MatchResult) -> None:
    if res.source.name == res.target.name and res.source.project is res.target.project:
        raise KhxError("source and target are the same program")
