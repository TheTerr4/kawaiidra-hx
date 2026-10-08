"""Carry what you learned about functions of one build to the matching functions of another: names, as tagged comments, bookmarks and (when safe) renames.

Given the function matches between a *source* program (the one you annotated) and a *target* program (the new build), :func:`plan` picks the
matches worth carrying and :func:`apply_carries` writes them into the target. Nothing is silent and everything can be undone:

* every touched function gets a plate-comment line ``[khx-match:<name>] <name> <- <source> 0x<addr> [<how>; similarity .., margin ..]`` and a
  bookmark of category ``khx-match``;
* a function is renamed only if it still has Ghidra's default name (``FUN_...``), or with ``force``; the name it had is written into the comment
  (``was=...``) so :func:`clear_program` gives it back;
* a function two sources claim keeps the first name; a refused name (duplicate, illegal) is reported, not retried;
* only names somebody set by hand (Ghidra source ``USER_DEFINED``) are carried; analysis names and imports exist in both builds already.

The evidence is the matcher's: matches from rare shared features, unique strings and RTTI vtable slots are strong; an ``align`` match must reach
``min_score`` and lead its rival by ``min_margin``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping

from .. import annotate
from ..core.resolve import parse_address
from ..core.session import ProgramHandle
from .funcmatch import FMatch

TAG = "[khx-match:"
BOOKMARK_CATEGORY = "khx-match"
STRONG_METHODS = frozenset({"seed", "string", "vtable", "given"})
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_$:~<>]*$")
_WAS = re.compile(r"\bwas=(\S+)(?: src=(\w+))?")  # ``was=<old name> src=<its Ghidra source type>``, written on the line of a function that was renamed


@dataclass(frozen=True)
class Carry:
    source: int  # function entry (VA) in the source program
    target: int  # ... and its counterpart in the target
    name: str
    method: str
    score: float
    margin: float


@dataclass
class ApplyReport:
    dry_run: bool = False
    functions: int = 0  # functions that got a comment
    renamed: int = 0
    already_named: int = 0
    skipped: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)  # dry run: one line per function

    def format(self) -> str:
        verb = "would annotate" if self.dry_run else "annotated"
        lines = [f"{verb} {self.functions} function(s): {self.renamed} {'to be ' if self.dry_run else ''}renamed, {self.already_named} already carried the name"]
        lines += [f"  {p}" for p in self.plan]
        lines += [f"  skipped: {s}" for s in self.skipped]
        if self.functions and not self.dry_run:
            lines.append("  (changes are in memory: save the program to keep them)")
        return "\n".join(lines)


def source_names(h: ProgramHandle) -> dict[int, str]:
    """``{function entry: name}`` of the functions somebody named by hand in this program (Ghidra source ``USER_DEFINED``)."""
    from ghidra.program.model.symbol import SourceType

    out: dict[int, str] = {}
    with h.lock:
        for fn in h.program.getFunctionManager().getFunctions(True):
            if fn.getSymbol().getSource() != SourceType.USER_DEFINED:
                continue
            name = str(fn.getName())
            if _NAME.match(name):
                out[int(fn.getEntryPoint().getOffset())] = name
    return out


def plan(matched: Mapping[int, FMatch], names: Mapping[int, str], *, min_score: float = 0.7, min_margin: float = 0.05) -> list[Carry]:
    """The matches whose source function has a hand-set name and whose evidence is strong enough, best evidence first."""
    out: list[Carry] = []
    for a, m in matched.items():
        name = names.get(a)
        if not name:
            continue
        if m.method not in STRONG_METHODS and (m.score < min_score or m.margin < min_margin):
            continue
        out.append(Carry(a, m.b, name, m.method, m.score, m.margin))
    return sorted(out, key=lambda c: (c.method not in STRONG_METHODS, -c.score, c.target))


def _recorded_suffix(h: ProgramHandle, where: str, tag: str) -> str:
    """The `` was=<name> src=<source>`` an earlier run recorded on the tagged plate-comment line of the function at ``where`` ("" if none)."""
    from ghidra.program.model.listing import CodeUnit

    text = h.program.getListing().getComment(CodeUnit.PLATE_COMMENT, parse_address(h, where))
    for line in str(text or "").split("\n"):
        if line.startswith(tag):
            m = _WAS.search(line)
            return f" was={m.group(1)}" + (f" src={m.group(2)}" if m.group(2) else "") if m else ""
    return ""


def apply_carries(
    h: ProgramHandle,
    carries: list[Carry],
    *,
    source_label: str = "source",
    rename: bool = True,
    force: bool = False,
    dry_run: bool = False,
) -> ApplyReport:
    """Annotate the target functions. Needs a write-mode handle unless ``dry_run``."""
    from ghidra.program.model.symbol import SourceType

    rep = ApplyReport(dry_run=dry_run)
    named: dict[int, str] = {}  # target function -> the name a carry gave it in this run (the first claim wins)
    with h.lock:
        fm = h.program.getFunctionManager()
        for c in carries:
            where = f"0x{c.target:X}"
            fn = fm.getFunctionAt(parse_address(h, where))
            if fn is None:
                rep.skipped.append(f"{c.name} @ {where}: no function starts there in this program")
                continue
            how = c.method if c.method in STRONG_METHODS else f"{c.method} similarity {c.score:.2f}, margin {c.margin:.2f}"
            note = f"{c.name} <- {source_label} 0x{c.source:X} [{how}]"
            keep_was = was = was_src = ""
            if rename:
                current = str(fn.getName())
                if current == c.name:
                    rep.already_named += 1
                    keep_was = _recorded_suffix(h, where, f"{TAG}{c.name}]")  # a re-run must not forget the name the function had before ours
                elif c.target in named:
                    rep.skipped.append(f"{c.name} @ {where}: the function was already named {named[c.target]} in this run")
                elif fn.getSymbol().getSource() != SourceType.DEFAULT and not force:
                    rep.skipped.append(f"{c.name} @ {where}: the function is already named {current} (use --force to rename it)")
                else:
                    was, was_src = current, str(fn.getSymbol().getSource())
                    named[c.target] = c.name
            rep.functions += 1
            rep.renamed += bool(was)
            if dry_run:
                rep.plan.append(f"{where}  {c.name}  ({how})" + (f"  (rename from {was})" if was else ""))
                continue
            if was:
                try:
                    with h.transaction(f"name {c.name}"):
                        fn.setName(c.name, SourceType.USER_DEFINED)
                except Exception as e:  # a duplicate name in the namespace, a name Ghidra refuses
                    rep.renamed -= 1
                    rep.skipped.append(f"{c.name} @ {where}: Ghidra refused the name ({e})")
                    was = ""
            annotate.set_tagged_comment(h, where, f"{TAG}{c.name}]", note + (f" was={was} src={was_src}" if was else keep_was), "plate", snap_to_unit=False)
            annotate.add_bookmark(h, where, BOOKMARK_CATEGORY, f"{c.name}: {c.method}", snap_to_unit=False)
    return rep


def clear_program(h: ProgramHandle) -> dict[str, int]:
    """Remove every ``[khx-match:...]`` comment line and ``khx-match`` bookmark; give back the names the functions had (when they still carry ours)."""
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType

    counts = {"names_restored": 0, "names_kept": 0}
    todo: list[tuple[object, str, str, str]] = []
    with h.lock:
        listing = h.program.getListing()
        for addr in list(listing.getCommentAddressIterator(CodeUnit.PLATE_COMMENT, h.program.getMemory(), True)):
            for line in str(listing.getComment(CodeUnit.PLATE_COMMENT, addr)).split("\n"):
                m = _WAS.search(line) if line.startswith(TAG) else None
                if m:
                    todo.append((addr, line[len(TAG) : line.index("]")], m.group(1), m.group(2) or "USER_DEFINED"))
        fm = h.program.getFunctionManager()
        with h.transaction("restore names"):
            for addr, ident, was, src in todo:
                fn = fm.getFunctionAt(addr)
                if fn is None or str(fn.getName()) != ident:
                    counts["names_kept"] += 1  # renamed again by somebody since: not ours to undo
                    continue
                if src == "DEFAULT":
                    fn.setName(None, SourceType.DEFAULT)  # back to FUN_<address>
                else:
                    try:
                        fn.setName(was, SourceType.valueOf(src))  # with the kind of name it was (an analysis or imported name stays one)
                    except Exception:
                        fn.setName(was, SourceType.USER_DEFINED)
                counts["names_restored"] += 1
    counts.update(annotate.clear_tagged(h, TAG, bookmark_category=BOOKMARK_CATEGORY))
    return counts
