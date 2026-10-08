"""Signature synthesis: turn "these bytes at this file offset" into a ``signature`` entry that finds the same place in other
builds of the binary.

A good signature keeps the bytes that survive a rebuild (opcodes, register choices, struct offsets, small constants) and wildcards the
ones that do not (relative branch displacements, RIP-relative / absolute addresses, relocated pointers). Which bytes those are comes from
the caller: Ghidra's operand masks (``queries/sigmask.py``) and the PE base-relocation table. This module only does the search: grow the
window instruction by instruction around the patch site until the masked pattern is unique in the file, then shrink what is not needed.

Pure Python on bytes; no Ghidra. The caller supplies the instruction map as :class:`Insn` records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import islice
from typing import Iterable, Sequence

from .entries import Entry, SignatureSpec, format_masked
from .signature import count_matches, iter_matches, resolve_signature


@dataclass(frozen=True)
class Insn:
    """One decoded unit of the file: ``length`` bytes at file ``offset``; ``volatile`` lists byte indexes (0-based inside the
    instruction) that change between builds and must be wildcards."""

    offset: int
    length: int
    volatile: tuple[int, ...] = ()
    text: str = ""

    @property
    def end(self) -> int:
        return self.offset + self.length


def byte_units(data: bytes, start: int, end: int, volatile_offsets: Iterable[int] = ()) -> list[Insn]:
    """1-byte pseudo-instructions for data regions (strings, tables), with ``volatile_offsets`` (e.g. relocated pointers) wildcarded."""
    vol = set(volatile_offsets)
    start, end = max(0, start), min(len(data), end)
    return [Insn(o, 1, (0,) if o in vol else (), "db") for o in range(start, end)]


@dataclass
class SigCandidate:
    start: int  # file offset of the first signature byte
    end: int  # one past the last
    pattern: bytes
    mask: bytes  # 0xFF = fixed, 0x00 = wildcard
    matches: int  # occurrences in the file (1 = unique)
    insns: int
    text: str = ""
    site: tuple[int, int] = (0, 0)  # the patched window, file offsets
    notes: list[str] = field(default_factory=list)
    usage: int = 0  # which occurrence (0-based) is the site; only non-zero for ambiguous signatures
    ambiguous_of: int = 0  # total occurrences when the signature is not unique (usage disambiguates)
    weight: int = 0  # informative fixed bytes (padding and wildcards excluded); what ``min_fixed`` is measured in

    @property
    def length(self) -> int:
        return len(self.pattern)

    @property
    def fixed(self) -> int:
        return sum(1 for m in self.mask if m)

    @property
    def unique(self) -> bool:
        return self.matches == 1

    @property
    def usable(self) -> bool:
        """Unique, or ambiguous but pinned down by ``usage``."""
        return self.matches == 1 or self.ambiguous_of > 1

    @property
    def site_offset(self) -> int:
        """Offset of the patched window inside the signature (the entry's ``offset``)."""
        return self.site[0] - self.start


_DATA_PADDING = (0x00, 0xCC)


def unit_weight(data: bytes, ins: Insn) -> int:
    """How much an instruction contributes to a signature's information: its fixed bytes, except padding. Alignment filler (NOP/INT3
    in code, zero/CC runs in data) differs between builds and says nothing about *this* place, so it weighs 0 and context growth
    avoids it. Wildcarded bytes weigh 0 too."""
    if ins.text.startswith(("NOP", "INT3")):
        return 0
    vol = set(ins.volatile)
    data_unit = ins.text == "db"
    w = 0
    for i in range(ins.length):
        if i in vol:
            continue
        if data_unit and data[ins.offset + i] in _DATA_PADDING:
            continue
        w += 1
    return w


def _pattern(data: bytes, insns: Sequence[Insn]) -> tuple[bytes, bytes]:
    pat, mask = bytearray(), bytearray()
    for ins in insns:
        vol = set(ins.volatile)
        for i in range(ins.length):
            pat.append(data[ins.offset + i])
            mask.append(0x00 if i in vol else 0xFF)
    return bytes(pat), bytes(mask)


def _contiguous(insns: Sequence[Insn]) -> bool:
    return all(a.end == b.offset for a, b in zip(insns, insns[1:]))


def make_signature(
    data: bytes,
    insns: Sequence[Insn],
    site_start: int,
    site_end: int,
    *,
    max_bytes: int = 48,
    min_fixed: int = 12,
    escalate_to: int = 96,
    allow_usage: bool = True,
    shrink: bool = True,
) -> SigCandidate | None:
    """Smallest signature covering ``[site_start, site_end)`` that is unique in ``data``; None if the site is not inside ``insns``.

    ``insns`` must be sorted and contiguous around the site (``queries/sigmask.instruction_window`` guarantees that).

    * ``min_fixed`` (default 12): a signature that is unique only by a handful of bytes is likely to hit a *different* place in a
      rebuilt binary and the patcher would patch it silently; failing to match is the safe outcome, so context is added until at
      least this many bytes are fixed.
    * If no window of ``max_bytes`` is unique it is retried with ``escalate_to`` bytes; still ambiguous and ``allow_usage``: the
      candidate pins the site by ``usage`` (n-th occurrence) and says so in ``notes`` (fragile if occurrence order changes).
    * Otherwise the best attempt is returned with ``matches != 1`` so the caller can report it.
    """
    cand = _make_once(data, insns, site_start, site_end, max_bytes=max_bytes, min_fixed=min_fixed, shrink=shrink)
    if cand is not None and not cand.unique and escalate_to > max_bytes:
        bigger = _make_once(data, insns, site_start, site_end, max_bytes=escalate_to, min_fixed=min_fixed, shrink=shrink)
        if bigger is not None and (bigger.unique or bigger.matches < cand.matches or cand.matches == 0):
            cand = bigger
            if bigger.unique:
                cand.notes.append(f"needed {cand.length} bytes of context")
    if cand is not None and not cand.unique and allow_usage:
        hits = list(islice(iter_matches(data, cand.pattern, cand.mask), 17))
        if 1 < len(hits) <= 16 and cand.start in hits:
            cand.usage = hits.index(cand.start)
            cand.ambiguous_of = len(hits)
            cand.notes = [n for n in cand.notes if not n.startswith("not unique")]
            cand.notes.append(f"ambiguous: this is occurrence #{cand.usage} of {len(hits)}; applied with usage={cand.usage} (fragile if the order changes)")
    return cand


def _make_once(
    data: bytes,
    insns: Sequence[Insn],
    site_start: int,
    site_end: int,
    *,
    max_bytes: int,
    min_fixed: int,
    shrink: bool,
) -> SigCandidate | None:
    """Smallest unique signature covering ``[site_start, site_end)``; None if the site is not inside ``insns``.

    ``insns`` must be sorted and contiguous around the site (``queries/sigmask.instruction_window`` guarantees that). The result is
    unique (``matches == 1``) unless no window up to ``max_bytes`` could make it so, in which case the best (fewest matches) attempt
    is returned with ``matches > 1`` so the caller can report it. ``min_fixed`` keeps a signature from being unique only by luck.
    """
    if site_end <= site_start or not insns:
        return None
    if not _contiguous(insns):
        raise ValueError("instructions must be contiguous")
    cover = [i for i, ins in enumerate(insns) if ins.offset < site_end and ins.end > site_start]
    if not cover or insns[cover[0]].offset > site_start or insns[cover[-1]].end < site_end:
        return None  # the site is not fully inside the instruction map
    lo, hi = cover[0], cover[-1]  # inclusive indexes of the current window
    first, last = lo, hi

    weights = [unit_weight(data, ins) for ins in insns]

    def build(l: int, h: int) -> tuple[bytes, bytes, int]:
        pat, mask = _pattern(data, insns[l : h + 1])
        return pat, mask, count_matches(data, pat, mask, limit=2)

    def info(l: int, h: int) -> int:
        return sum(weights[l : h + 1])

    def size(l: int, h: int) -> int:
        return insns[h].end - insns[l].offset

    pat, mask, n = build(lo, hi)
    best = (n, lo, hi)
    grow_left = True
    while not (n == 1 and info(lo, hi) >= min_fixed):
        can_left, can_right = lo > 0, hi < len(insns) - 1
        if not (can_left or can_right):
            break
        if can_left and can_right and weights[lo - 1] != weights[hi + 1]:
            take_left = weights[lo - 1] > weights[hi + 1]  # grow toward the informative side, away from padding
        else:
            take_left = can_left and (grow_left or not can_right)
        grow_left = not grow_left
        nl, nh = (lo - 1, hi) if take_left else (lo, hi + 1)
        if size(nl, nh) > max_bytes:
            # the preferred side does not fit; try the other before giving up
            nl, nh = (lo, hi + 1) if take_left else (lo - 1, hi)
            if not (0 <= nl and nh < len(insns)) or size(nl, nh) > max_bytes:
                break
        lo, hi = nl, nh
        pat, mask, n = build(lo, hi)
        if n < best[0] or (n == best[0] and size(lo, hi) < size(best[1], best[2])):
            best = (n, lo, hi)
    if n != 1 and best[0] != n:
        lo, hi = best[1], best[2]
        pat, mask, n = build(lo, hi)

    if n == 1 and shrink:  # drop context that is not needed (never the instructions that hold the site)
        changed = True
        while changed:
            changed = False
            for side in ("left", "right"):
                nl, nh = (lo + 1, hi) if side == "left" else (lo, hi - 1)
                if (side == "left" and lo >= first) or (side == "right" and hi <= last) or nl > nh:
                    continue
                p2, m2, n2 = build(nl, nh)
                if n2 == 1 and info(nl, nh) >= min_fixed:
                    lo, hi, pat, mask, n, changed = nl, nh, p2, m2, n2, True

    cand = SigCandidate(
        start=insns[lo].offset, end=insns[hi].end, pattern=pat, mask=mask, matches=n, insns=hi - lo + 1,
        text=format_masked(pat, mask), site=(site_start, site_end), weight=info(lo, hi),
    )  # fmt: skip
    if n != 1:
        cand.notes.append(f"not unique: {'0' if n == 0 else '2+'} matches within {max_bytes} bytes of context")
    elif cand.weight < min_fixed:
        cand.notes.append(f"only {cand.weight} informative bytes (min {min_fixed})")
    return cand


def trim_replacement(disabled: bytes, enabled: bytes) -> tuple[int, str]:
    """``(offset into the patched window, replacement text)``: bytes equal to the original become ``??`` (a wildcard keeps the original
    there) and ``??`` at both ends are dropped, so the replacement touches only what really changes."""
    if len(disabled) != len(enabled) or not disabled:
        raise ValueError("disabled and enabled must be the same non-zero length")
    diff = [i for i, (a, b) in enumerate(zip(disabled, enabled)) if a != b]
    if not diff:
        raise ValueError("enabled bytes equal the original: nothing to patch")
    lo, hi = diff[0], diff[-1] + 1
    return lo, "".join(f"{enabled[i]:02X}" if disabled[i] != enabled[i] else "??" for i in range(lo, hi))


def signature_entry(
    cand: SigCandidate,
    disabled: bytes,
    enabled: bytes,
    *,
    name: str,
    description: str = "",
    game_code: str | None = None,
    dll_name: str | None = None,
    caution: str | None = None,
) -> Entry:
    """A ``signature`` entry that applies ``disabled -> enabled`` at the candidate's patched window."""
    rel, replacement = trim_replacement(disabled, enabled)
    spec = SignatureSpec(
        signature=cand.text, replacement=replacement, offset=cand.site_offset + rel, usage=cand.usage, dll_name=dll_name
    )
    return Entry(
        name=name, description=description, game_code=game_code, type="signature", caution=caution, signature=spec
    )  # fmt: skip


def verify_signature(
    data: bytes, entry: Entry, site_offset: int, disabled: bytes, enabled: bytes, *, allow_ambiguous: bool = False
) -> tuple[bool, str]:
    """Round trip: the entry must resolve to the patched window at file ``site_offset`` in ``data`` and write exactly the bytes
    of ``enabled`` that differ from ``disabled`` (the replacement is trimmed to those)."""
    assert entry.signature is not None
    res = resolve_signature(data, entry.signature)
    if res.state != "original" or res.offset is None or res.enabled is None:
        return False, f"signature resolves as {res.state} ({res.matches} matches)"
    if res.matches != 1 and not allow_ambiguous:
        return False, f"not unique ({res.matches} matches)"
    rel, _text = trim_replacement(disabled, enabled)
    if res.offset != site_offset + rel:
        return False, f"resolves to 0x{res.offset:X}, expected 0x{site_offset + rel:X}"
    want = enabled[rel : rel + len(res.enabled)]
    if res.enabled != want:
        return False, f"replacement would write {res.enabled.hex().upper()}, expected {want.hex().upper()}"
    return True, "ok"


def window_ladder(
    data: bytes,
    insns: Sequence[Insn],
    site_start: int,
    site_end: int,
    *,
    min_info: int = 12,
    max_bytes: int = 96,
    max_ext: int = 24,
) -> list[SigCandidate]:
    """Alternative windows around a site, all unique in ``data`` and carrying at least ``min_info`` informative bytes.

    One signature is the smallest unique window, so when *its* particular neighbours change in another build it stops matching even though
    a window leaning the other way would still hold. The ladder is the frontier of minimal windows: for every extent to the left, the
    smallest extent to the right that is informative enough and unique, and the other way round. Used by porting, which then requires
    every window that matches the target to agree on one location.
    """
    if site_end <= site_start or not insns or not _contiguous(insns):
        return []
    cover = [i for i, ins in enumerate(insns) if ins.offset < site_end and ins.end > site_start]
    if not cover or insns[cover[0]].offset > site_start or insns[cover[-1]].end < site_end:
        return []
    lo0, hi0 = cover[0], cover[-1]
    weights = [unit_weight(data, ins) for ins in insns]
    found: dict[tuple[int, int], SigCandidate] = {}

    def window_info(lo: int, hi: int) -> int:
        return sum(weights[lo : hi + 1])

    def try_window(lo: int, hi: int) -> bool:
        """True once the window is long enough (so growing it further cannot make it *more* minimal); records it when unique."""
        if insns[hi].end - insns[lo].offset > max_bytes:
            return True
        if window_info(lo, hi) < min_info:
            return False
        if (lo, hi) not in found:
            pat, mask = _pattern(data, insns[lo : hi + 1])
            if count_matches(data, pat, mask, limit=2) == 1:
                found[(lo, hi)] = SigCandidate(
                    start=insns[lo].offset, end=insns[hi].end, pattern=pat, mask=mask, matches=1, insns=hi - lo + 1,
                    text=format_masked(pat, mask), site=(site_start, site_end), weight=window_info(lo, hi),
                )  # fmt: skip
                return True
        else:
            return True
        return False

    for left in range(0, min(max_ext, lo0) + 1):  # for each left extent: the smallest right extent that works
        for right in range(0, min(max_ext, len(insns) - 1 - hi0) + 1):
            if try_window(lo0 - left, hi0 + right):
                break
    for right in range(0, min(max_ext, len(insns) - 1 - hi0) + 1):  # and for each right extent the smallest left extent
        for left in range(0, min(max_ext, lo0) + 1):
            if try_window(lo0 - left, hi0 + right):
                break
    return sorted(found.values(), key=lambda c: (c.length, c.start))
