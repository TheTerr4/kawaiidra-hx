"""Semantic anchors: find where a source build's patch sites went by *what the code is*, not by which bytes it consists of.

Two steps, both fed by the fingerprint caches (:mod:`kawaiidra_hx.queries.fingerprint`, :mod:`kawaiidra_hx.match.store`), so a build needs a
Ghidra analysis once and no more:

1. **Function alignment** (:mod:`kawaiidra_hx.match.align`): the function holding the site in build A is matched to a function of build B through
   strings, imports, constants, the call graph and the order functions sit in the image.
2. **Instruction alignment** (:mod:`kawaiidra_hx.match.locate`): inside the two functions, the instruction streams are aligned and the patched
   instruction is carried across.

:class:`AnchorContext` bundles both for one (A, B) pair and is what ``port_build`` consults when no signature or window of bytes holds.
"""

from __future__ import annotations

import bisect
import pickle
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Callable, Optional

from ..pe import PEImage
from ..queries.fingerprint import FuncIndex
from .align import Similarity, align_functions
from .funcmatch import FMatch
from .locate import SiteMap, map_site


@dataclass
class Anchor:
    """Where one source site went, with the evidence."""

    offset: Optional[int]  # file offset in the target of the first byte of the patch window (None when not found)
    why: str  # the reason when not found, else a one-line description of the evidence
    source_fn: int = 0  # entry (VA) of the function holding the site in the source
    target_fn: int = 0  # ... and of its counterpart in the target
    fn_score: float = 0.0
    fn_margin: float = 0.0
    site: Optional[SiteMap] = None


ALIGN_CACHE_VERSION = 4  # bump when the alignment algorithm or its thresholds change: cached results are then recomputed (4: RTTI vtable seeds)
BRACKET_BYTES = 0x20000  # candidates are looked for between neighbours whose counterparts are at most this far apart
BRACKET_TRIES = 12  # ... trying this many anchors on each side


class AnchorContext:
    """Function alignment + instruction alignment between two builds, for the sites of ``A`` that ``port_build`` could not place by bytes."""

    def __init__(
        self,
        A: FuncIndex,
        B: FuncIndex,
        img_a: PEImage,
        img_b: PEImage,
        *,
        matched: dict[int, FMatch] | None = None,
        cache: Path | None = None,
        kinds: tuple[str, ...] | None = None,
        log: Callable[[str], None] | None = None,
    ):
        for idx, name in ((A, "source"), (B, "target")):
            if getattr(idx, "version", 1) < 2:
                raise ValueError(f"the {name} fingerprints have no instruction streams; extract them again (`khx match --refresh`)")
        self.A, self.B, self.img_a, self.img_b = A, B, img_a, img_b
        self.kinds = kinds  # feature families the alignment may use (None: all; an evaluation withholds the strings)
        self.cross_isa = getattr(img_a.info, "machine", "") != getattr(img_b.info, "machine", "")  # x86 vs x64: function level only
        self.matched = matched if matched is not None else self._align(cache, log)
        self.pairs = {a: m.b for a, m in self.matched.items()}

    def _key(self) -> dict:
        """What a cached alignment was computed from (a different build, or the same build with vtables where there were none, is another input)."""
        return {"v": ALIGN_CACHE_VERSION, "a": (self.A.build_id, len(self.A.funcs), len(self.A.vtables or ())), "b": (self.B.build_id, len(self.B.funcs), len(self.B.vtables or ())), "kinds": self.kinds}

    def _align(self, cache: Path | None, log: Callable[[str], None] | None) -> dict[int, FMatch]:
        key = self._key()
        if cache is not None and cache.exists():
            try:
                blob = pickle.loads(cache.read_bytes())  # noqa: S301 - our own cache under workspace/
                if all(blob.get(k) == v for k, v in key.items()):
                    return blob["matched"]
            except Exception:
                pass
        matched = align_functions(self.A, self.B, cross_isa=self.cross_isa, log=log, **({} if self.kinds is None else {"kinds": self.kinds}))
        if cache is not None:
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(cache.suffix + ".tmp")
            tmp.write_bytes(pickle.dumps({**key, "matched": matched}, protocol=pickle.HIGHEST_PROTOCOL))
            tmp.replace(cache)
        return matched

    def candidates(self, entry: int, k: int = 5) -> list[tuple[int, float]]:
        """For a function of A without a counterpart: the functions of B in the stretch the counterparts of its neighbours bound, best first
        (``[(entry in B, similarity)]``). Evidence for a human to look at, never a match.

        The bracket is the nearest anchor on each side whose counterparts keep the order and lie within ``BRACKET_BYTES`` of each other (a neighbour
        that was matched into another translation unit is skipped); with only the anchor after the function, the stretch of B just before that
        anchor's counterpart, as long as the distance in A suggests."""
        pairs = sorted((a, m.b) for a, m in self.matched.items() if a != entry)
        keys = [a for a, _ in pairs]
        i = bisect.bisect_left(keys, entry)
        ratios = [self.B.funcs[b].n / self.A.funcs[a].n for a, b in pairs if self.A.funcs[a].n >= 10 and self.B.funcs[b].n >= 10]
        scale = float(median(ratios)) if len(ratios) >= 20 else 1.0
        lo = hi = None
        for left in reversed(pairs[max(0, i - BRACKET_TRIES) : i]):
            for right in pairs[i : i + BRACKET_TRIES]:
                if 0 < right[1] - left[1] <= BRACKET_BYTES:
                    lo, hi = left[1], right[1]
                    break
            if lo is not None:
                break
        if lo is None and i < len(pairs):  # no consistent pair: the stretch before the next anchor
            ra, rb = pairs[i]
            span = max(BRACKET_BYTES // 8, int(3 * (ra - entry) * max(scale, 1.0)))
            lo, hi = rb - span, rb
        if lo is None:
            return []
        fb_sorted = sorted(self.B.funcs)
        taken = {m.b for m in self.matched.values()}
        FB = [e for e in fb_sorted[bisect.bisect_right(fb_sorted, lo) : bisect.bisect_left(fb_sorted, hi)] if e not in taken and self.B.funcs[e].n >= 3]
        if not FB or len(FB) > 400:
            return []
        sim = Similarity(self.A, self.B, self.pairs, use_strings=True, scale=scale)
        return sorted(((eb, sim(entry, eb)) for eb in FB), key=lambda t: -t[1])[:k]

    def string_users(self, offset: int, length: int, min_len: int = 4) -> Anchor:
        """A data site inside a string literal of the source (a child name, a format string): which functions of the source use that string, and
        what they correspond to in the target. Never an offset (the edit is to data, the behaviour lives in the code that reads it), only a hint."""
        data = self.img_a.data
        lo, hi = offset, offset + max(length, 1)
        while lo > 0 and data[lo - 1] != 0:
            lo -= 1
        while hi < len(data) and data[hi] != 0:
            hi += 1
        raw = data[lo:hi]
        if len(raw) < min_len or not all(0x20 <= c < 0x7F for c in raw):
            return Anchor(None, "the site is not inside a string literal")
        text = raw.decode("ascii")
        users = sorted(self.A.inverted["strings"].get(text, ()))
        if not users:
            return Anchor(None, f"no function of the source refers to the string {text!r}")
        parts = []
        for e in users[:4]:
            m = self.matched.get(e)
            if m is not None:
                parts.append(f"0x{e:X} -> 0x{m.b:X}")
                continue
            near = self.candidates(e, 3)
            parts.append(f"0x{e:X} (no counterpart" + ("; candidates " + ", ".join(f"0x{c:X} ({s:.2f})" for c, s in near) if near else "") + ")")
        more = f", and {len(users) - 4} more" if len(users) > 4 else ""
        return Anchor(None, f"the string {text!r} is used by {', '.join(parts)}{more}: the data edit has to be redone where the target reads the behaviour")

    def locate(self, offset: int, length: int, *, min_margin: float = 0.0) -> Anchor:
        """Where the window ``[offset, offset + length)`` (file offsets of build A) is in build B."""
        try:
            va = self.img_a.info.offset_to_va(offset)
        except Exception:
            return Anchor(None, "the site is not inside a section of the source build")
        fa = self.A.containing(va)
        if fa is None:
            return Anchor(None, "the site is not inside a function of the source build")
        m = self.matched.get(fa.entry)
        if m is None:
            near = self.candidates(fa.entry, 3)
            hint = "; candidates between the counterparts of its neighbours: " + ", ".join(f"0x{e:X} ({s:.2f})" for e, s in near) if near else ""
            return Anchor(None, f"the function holding the site (0x{fa.entry:X}) has no counterpart in the target{hint}", source_fn=fa.entry)
        if m.margin < min_margin:
            return Anchor(None, f"the counterpart of 0x{fa.entry:X} (0x{m.b:X}) is ambiguous (margin {m.margin:.2f})", fa.entry, m.b, m.score, m.margin)
        if self.cross_isa:  # the instruction streams of two ISAs do not line up: name the function, leave the edit to a human with both decompilations
            return Anchor(None, f"cross-ISA hint: the function holding the site (0x{fa.entry:X}) corresponds to 0x{m.b:X} (similarity {m.score:.2f}, margin {m.margin:.2f}); the instructions of two different ISAs are not aligned, port the edit by hand", fa.entry, m.b, m.score, m.margin)
        fb = self.B.funcs[m.b]
        sm = map_site(self.A, self.B, fa, fb, self.pairs, va - self.A.image_base, length)
        if not sm.ok:
            return Anchor(None, f"function 0x{fa.entry:X} -> 0x{m.b:X}, but {sm.why}", fa.entry, m.b, m.score, m.margin, sm)
        va_b = self.B.image_base + sm.b_rva + sm.rel
        try:
            off_b = self.img_b.info.va_to_offset(va_b)
        except Exception:
            return Anchor(None, "the counterpart instruction is not backed by the target file", fa.entry, m.b, m.score, m.margin, sm)
        how = f"similarity {m.score:.2f}, margin {m.margin:.2f}" if m.method == "align" else m.method
        return Anchor(off_b, f"function 0x{fa.entry:X} -> 0x{m.b:X} ({how}), {sm.evidence}", fa.entry, m.b, m.score, m.margin, sm)
