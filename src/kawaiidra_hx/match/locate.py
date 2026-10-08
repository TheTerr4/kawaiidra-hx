"""Locate a patch site inside a function that was matched between two builds, instruction by instruction.

Signature windows need a stretch of *bytes* that stays unique and unchanged; recompiled code changes struct offsets, immediates and
register choices all over a function while its instruction sequence barely moves. Given the matched functions, this module aligns their
instruction streams (:class:`~kawaiidra_hx.queries.fingerprint.CodeStream`: mnemonic + operand kinds, plus the *counterpart* of a callee and
the string or import an operand refers to) with difflib, and carries the patched instruction across the alignment.

It answers only when the evidence is there: the site's own instruction must be aligned (equal, or the same mnemonic inside a same-sized
replaced stretch), enough of its neighbours must be equal, and at least one of the equal neighbours must be distinctive (a call to a matched
function, a string or import, a large immediate) unless the two functions are almost identical as a whole, because repeated idioms (``pop edi / pop esi / xor al,al / ret``) align by position alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Optional

from ..queries.fingerprint import FuncFP, FuncIndex

WINDOW = 4  # instructions on each side of the site that are looked at
MIN_CONTEXT = 4  # of the (up to) 2 * WINDOW neighbours, this many must be aligned as equal
MAX_STREAM = 6000  # instructions; longer functions are not aligned (difflib is quadratic)
BIG_IMMEDIATE = 0x100
WHOLE_FUNCTION = 0.9  # a function whose instruction sequence is this identical in both builds needs no distinctive neighbour: position is the evidence


@dataclass
class SiteMap:
    ok: bool
    why: str = ""
    ia: int = -1  # index of the site's first instruction in the source stream
    ib: int = -1  # ... and of its counterpart in the target stream
    count: int = 1  # instructions the patch window covers
    context: int = 0  # neighbours (within WINDOW) aligned as equal at the same shift as the site
    left: int = 0  # ... of which before the site
    right: int = 0  # ... and after it
    distinctive: int = 0  # ... of which carry a matched callee, a string/import reference or a large immediate
    rel: int = 0  # byte offset of the site inside its first instruction
    b_rva: int = 0  # RVA of the counterpart instruction in the target
    notes: list[str] = field(default_factory=list)

    @property
    def evidence(self) -> str:
        return f"{self.context} aligned neighbours, {self.distinctive} distinctive"


def _callee_class(idx: FuncIndex, va: int) -> str:
    """What an unmatched callee looks like: size bucket and whether it touches strings, imports or large constants (stable across rebuilds)."""
    f = idx.funcs.get(va)
    if f is None:
        return "?"
    return f"~{f.n.bit_length()}{'s' if f.strings else ''}{'i' if f.imports else ''}{'c' if f.consts else ''}"


def _tokens(idx: FuncIndex, f: FuncFP, pairs: dict[int, int], side: str) -> list[str]:
    """Strict tokens: kind token + the callee + the string or import an operand refers to.

    A callee that has a counterpart (``pairs``: A entry -> B entry) is written as that counterpart, so a call must go to the matched function; a
    callee without one is written as its *class* (:func:`_callee_class`): a call to a 3-instruction thunk is not a call to a 400-instruction
    routine. On the B side a callee is written as itself only when it *is* some counterpart."""
    cs = f.code
    assert cs is not None
    base = idx.image_base
    known_b = set(pairs.values()) if side == "b" else None
    out: list[str] = []
    for k in range(len(cs)):
        t = idx.vocab[cs.t1[k]]
        c = cs.callee[k]
        if c:
            va = c + base
            if side == "a":
                b = pairs.get(va)
                t += f"@{b}" if b is not None else _callee_class(idx, va)
            else:
                t += f"@{va}" if known_b is not None and va in known_b else _callee_class(idx, va)
        if cs.ref[k]:
            t += f"${cs.ref[k]:x}"
        out.append(t)
    return out


def _distinctive(idx: FuncIndex, f: FuncFP, k: int, tok: str) -> bool:
    """A matched callee, a string or import, or a large immediate: something that is unlikely to appear twice by chance."""
    cs = f.code
    assert cs is not None
    if "@" in tok or "$" in tok:
        return True
    text = idx.vocab[cs.t2[k]]
    vals = text.split("|", 1)[1] if "|" in text else ""
    for v in vals.split(","):
        try:
            if v and BIG_IMMEDIATE <= abs(int(v, 16)) < 0xFFFF0000:  # (not a pointer-sized value, which moves with every build)
                return True
        except ValueError:
            pass
    return False


def map_site(
    A: FuncIndex,
    B: FuncIndex,
    fa: FuncFP,
    fb: FuncFP,
    matched: dict[int, int],
    site_rva: int,
    length: int,
    *,
    window: int = WINDOW,
    min_context: int = MIN_CONTEXT,
) -> SiteMap:
    """Carry the instruction(s) holding ``[site_rva, site_rva + length)`` of function ``fa`` (build A) to the matched function ``fb`` (build B).

    ``matched`` maps A function entries to B function entries (it supplies the callee counterparts)."""
    ca, cb = fa.code, fb.code
    if ca is None or cb is None or getattr(A, "version", 1) < 2 or getattr(B, "version", 1) < 2:
        return SiteMap(False, "no instruction streams for this build (re-extract fingerprints)")
    if len(ca) > MAX_STREAM or len(cb) > MAX_STREAM:
        return SiteMap(False, f"function too long to align ({len(ca)} / {len(cb)} instructions)")
    ia = ca.index_of(site_rva)
    if ia < 0:
        return SiteMap(False, "the site is not on an instruction of the source function")
    last = ca.index_of(site_rva + length - 1)
    if last < 0:
        last = ia
    rel = site_rva - ca.rva[ia]
    sa, sb = _tokens(A, fa, matched, "a"), _tokens(B, fb, matched, "b")
    sm = SequenceMatcher(None, sa, sb, autojunk=False)
    mapping: dict[int, int] = {}  # source index -> target index for the aligned-as-equal instructions
    loose: dict[int, int] = {}  # ... and for same-sized replaced stretches (candidate pairs, mnemonic checked below)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                mapping[i1 + k] = j1 + k
        elif tag == "replace" and i2 - i1 == j2 - j1:
            for k in range(i2 - i1):
                loose[i1 + k] = j1 + k
    res = SiteMap(False, ia=ia, rel=rel, count=last - ia + 1)
    # every instruction the window covers must have a counterpart of the same length (the edit is made of the source's bytes)
    ib0 = -1
    for k in range(ia, last + 1):
        jb = mapping.get(k)
        if jb is None:
            jb = loose.get(k)
            if jb is not None and sa[k].split(".")[0] != sb[jb].split(".")[0]:
                jb = None
        if jb is None:
            res.why = "the patched instruction has no counterpart in the target function (replaced or removed)"
            return res
        if ca.size[k] != cb.size[jb]:
            res.why = f"the patched instruction is encoded differently in the target ({ca.size[k]} vs {cb.size[jb]} bytes)"
            return res
        if ib0 < 0:
            ib0 = jb
        elif jb != ib0 + (k - ia):
            res.why = "the instructions of the patch window are not contiguous in the target"
            return res
    res.ib = ib0
    res.b_rva = cb.rva[ib0]
    delta = ib0 - ia
    left = right = dist = 0
    room_left = min(window, ia)
    room_right = min(window, len(ca) - 1 - last)
    for k in range(ia - room_left, last + room_right + 1):
        if ia <= k <= last or mapping.get(k) != k + delta:
            continue  # a neighbour counts only if it is aligned at the same shift as the site: the code around the site is the same code
        if k < ia:
            left += 1
        else:
            right += 1
        dist += _distinctive(A, fa, k, sa[k])
    for k in range(ia, last + 1):  # the site's own instruction counts as evidence when it is distinctive
        if k in mapping and _distinctive(A, fa, k, sa[k]):
            dist += 1
    res.context, res.distinctive, res.left, res.right = left + right, dist, left, right
    if left + right < min(min_context, room_left + room_right) or left < min(1, room_left) or right < min(1, room_right):
        res.why = f"only {left} instructions before and {right} after the site are aligned at its shift ({min_context} in all, one on each side needed)"
        return res
    if dist == 0 and sm.ratio() < WHOLE_FUNCTION:
        res.why = "nothing distinctive (no matched call, string, import or large immediate) next to the site: it would align by position alone"
        return res
    if dist == 0:
        res.notes.append(f"placed by the whole function: its instruction sequence is {sm.ratio():.0%} identical in both builds")
    # the same few instructions twice in the target function (a block that was duplicated): the alignment cannot say which copy is the site's,
    # unless the source has the same number of copies and the site is the same one of them
    lo, hi = max(0, ia - window), min(len(sa), last + window + 1)
    pat = sa[lo:hi]
    copies_a, copies_b = _occurrences(sa, pat), _occurrences(sb, pat)
    if len(copies_b) > 1:
        want = copies_b[copies_a.index(lo)] + (ia - lo) if len(copies_a) == len(copies_b) and lo in copies_a else -1
        if want != ib0:
            res.why = f"the instructions around the site occur {len(copies_b)} times in the target function ({len(copies_a)} in the source): which copy is the site's cannot be told"
            return res
    res.ok = True
    return res


def _occurrences(seq: list[str], pat: list[str]) -> list[int]:
    n = len(pat)
    return [i for i in range(len(seq) - n + 1) if seq[i : i + n] == pat] if n else []
