"""Order-aware function alignment between two builds.

Functions of one translation unit sit next to each other in the image, in source order, and that order mostly survives rebuilds (less so
across a change of compiler or ISA). A function without any string, constant or import of its own is then not "somewhere in the build" but
*between the neighbours that do have an anchor*: BinDiff's "address sequence" step.

``align_functions`` seeds with :func:`~kawaiidra_hx.match.funcmatch.match_functions`, the unique string pairs and the virtual functions that occupy the
same slot of the same RTTI class in both builds (class names are in the binary: an anchor that needs no string of the function's own), keeps the seeds
that agree on one order (the longest increasing subsequence of target addresses), and aligns the functions between every two consecutive anchors with a Needleman-Wunsch pass over a similarity
made of size, constants, strings, imports, instruction skeleton and *callee agreement* (a call to a function already matched must go to its
counterpart). Matches feed the next round as more callee evidence. A pairing is accepted only above a similarity threshold and, where another
candidate is close, only with a margin: a near-duplicate function is reported as unmatched rather than guessed.
"""

from __future__ import annotations

import bisect
from statistics import median
from typing import Callable, Optional

from ..queries.fingerprint import FuncFP, FuncIndex
from ..queries.vtables import vtable_slot_pairs
from .funcmatch import FMatch, match_functions, pairs_by_unique_strings, skeleton_sim

VT_GATE = 0.3  # smallest size ratio (smaller / larger, after the ISA scale) of a pair taken from the same vtable slot
THRESHOLD = 0.55  # similarity (0..1) a pair needs
CROSS_THRESHOLD = 0.35  # ... when the two builds are of different ISAs (e.g. x86 vs x64)
SMALL = 8  # instructions; a function this small has little identity and needs a higher similarity
SMALL_EXTRA = 0.10
MIN_ALIGN = 3  # instructions; smaller functions are not aligned at all
MIN_MARGIN = 0.02  # another candidate at or above the threshold must be at least this far behind
EXACT_CELLS = 90_000  # gaps up to this many cells are solved exactly, bigger ones inside a diagonal band
BAND = 40
MAX_WIDTH = 300  # a band wider than this (the two runs differ hugely in length: no anchors there) is not worth aligning


def lis(pairs: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The longest subsequence of ``pairs`` (sorted by first element) whose second elements strictly increase."""
    tails: list[int] = []
    idx: list[int] = []
    prev = [-1] * len(pairs)
    for i, (_a, b) in enumerate(pairs):
        k = bisect.bisect_left(tails, b)
        if k == len(tails):
            tails.append(b)
            idx.append(i)
        else:
            tails[k] = b
            idx[k] = i
        prev[i] = idx[k - 1] if k else -1
    out: list[tuple[int, int]] = []
    i = idx[-1] if idx else -1
    while i != -1:
        out.append(pairs[i])
        i = prev[i]
    return out[::-1]


def _jaccard(a: frozenset, b: frozenset) -> Optional[float]:
    if not a and not b:
        return None
    return len(a & b) / len(a | b)


class Similarity:
    """Similarity of a function of A to a function of B, in 0..1, from whichever features both have."""

    def __init__(self, A: FuncIndex, B: FuncIndex, matched: dict[int, int], *, use_strings: bool = True, scale: float = 1.0):
        self.A, self.B, self.matched, self.use_strings, self.scale = A, B, matched, use_strings, scale
        self._skel: dict[tuple[int, int], float] = {}

    def need(self, ea: int, eb: int, thr: float) -> float:
        """The similarity this pair has to reach: tiny functions carry little identity."""
        return thr + (SMALL_EXTRA if min(self.A.funcs[ea].n, self.B.funcs[eb].n) < SMALL else 0.0)

    def __call__(self, ea: int, eb: int) -> float:
        fa, fb = self.A.funcs[ea], self.B.funcs[eb]
        na, nb = fa.n * self.scale, fb.n
        top = max(na, nb)
        parts = [(0.30, min(na, nb) / top if top else 0.0)]
        j = _jaccard(fa.consts, fb.consts)
        if j is not None:
            parts.append((0.25, j))
        if self.use_strings:
            j = _jaccard(fa.strings, fb.strings)
            if j is not None:
                parts.append((0.25, j))
        j = _jaccard(fa.imports, fb.imports)
        if j is not None:
            parts.append((0.15, j))
        if fa.calls or fb.calls:
            ca, cb = set(fa.calls), set(fb.calls)
            hit = sum(1 for c in ca if c in self.matched and self.matched[c] in cb)
            parts.append((0.30, hit / max(1, len(ca), len(cb))))
        num, den = sum(w * v for w, v in parts), sum(w for w, _ in parts)
        if fa.skeleton and fb.skeleton and fa.n > 6 and num / den >= THRESHOLD - 0.3:
            la, lb = len(fa.skeleton), len(fb.skeleton)
            if (num + 0.30 * 2 * min(la, lb) / (la + lb)) / (den + 0.30) < THRESHOLD - 0.2:
                return num / den  # even a perfect skeleton match could not lift this pair near the threshold: skip the quadratic comparison
            key = (ea, eb)
            sk = self._skel.get(key)
            if sk is None:
                sk = self._skel[key] = skeleton_sim(fa, fb)
            return (num + 0.30 * sk) / (den + 0.30)
        return num / den


def align_gap(
    FA: list[int], FB: list[int], sim: Callable[[int, int], float], need: Callable[[int, int], float], floor: float, min_margin: float = MIN_MARGIN
) -> list[tuple[int, int, float, float]]:
    """Needleman-Wunsch over two short runs of functions. Returns ``[(a, b, similarity, margin)]``.

    A pair is allowed when ``sim`` reaches ``need(a, b)``; unmatched functions cost nothing. A pair whose best rival (another B for the same A, or
    another A for the same B) is at or above ``floor`` is dropped unless it leads by ``min_margin``."""
    n, m = len(FA), len(FB)
    if n == 0 or m == 0:
        return []
    banded = n * m > EXACT_CELLS
    width = BAND + abs(n - m)
    if banded and width > MAX_WIDTH:
        return []
    S: list[dict[int, float]] = []
    for i, ea in enumerate(FA):
        lo, hi = (max(0, int(i * m / n) - width), min(m, int(i * m / n) + width + 1)) if banded else (0, m)
        row: dict[int, float] = {}
        for j in range(lo, hi):
            s = sim(ea, FB[j])
            if s > 0:
                row[j] = s
        S.append(row)
    col: dict[int, list[tuple[int, float]]] = {}
    for i, row in enumerate(S):
        for j, s in row.items():
            col.setdefault(j, []).append((i, s))

    D = [[0.0] * (m + 1) for _ in range(n + 1)]
    T = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        T[i][0] = 1
    for j in range(1, m + 1):
        T[0][j] = 2
    for i in range(1, n + 1):
        Di, Dp, Ti, row, ea = D[i], D[i - 1], T[i], S[i - 1], FA[i - 1]
        for j in range(1, m + 1):
            s = row.get(j - 1)
            g = s - need(ea, FB[j - 1]) if s is not None else -1.0
            d = Dp[j - 1] + g if g > 0 else -1e18
            u, l = Dp[j], Di[j - 1]
            best = max(d, u, l)
            Di[j] = best
            Ti[j] = 0 if (g > 0 and best == d) else (1 if best == u else 2)
    out: list[tuple[int, int, float, float]] = []
    i, j = n, m
    while i > 0 or j > 0:
        t = T[i][j]
        if i > 0 and j > 0 and t == 0:
            s = S[i - 1][j - 1]
            second = max([v for jj, v in S[i - 1].items() if jj != j - 1] + [v for ii, v in col.get(j - 1, ()) if ii != i - 1], default=0.0)
            if second < floor or s - second >= min_margin:
                out.append((FA[i - 1], FB[j - 1], s, s - second))
            i -= 1
            j -= 1
        elif t == 1 and i > 0:
            i -= 1
        else:
            j -= 1
    return out[::-1]


def _gaps(pairs: list[tuple[int, int]], *, multi: bool) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    """The stretches between consecutive anchors that are still to be aligned: ``[((a0, b0), (a1, b1))]``.

    Within one generation the anchors that keep one order (the longest increasing subsequence) cover almost everything. Across a change of ISA
    the code of a translation unit stays together while the units are laid out in another order, so with ``multi`` the anchors left over after the first chain are peeled into further chains, and every chain bounds
    the gaps between its own consecutive anchors."""
    chains: list[list[tuple[int, int]]] = []
    rest = pairs
    while len(rest) >= (3 if multi else 1) and len(chains) < (12 if multi else 1):
        chain = lis(rest)
        chains.append(chain)
        taken = set(chain)
        rest = [p for p in rest if p not in taken]
    chains = chains or [[]]  # no anchors at all: the whole image is one gap
    out: list[tuple[tuple[int, int], tuple[int, int]]] = []
    for k, chain in enumerate(chains):
        pts = [(-1, -1), *chain, (1 << 62, 1 << 62)] if k == 0 else chain
        out += list(zip(pts, pts[1:]))
    return out


def _vtable_seeds(A: FuncIndex, B: FuncIndex, seeds: dict[int, FMatch], scale: float) -> int:
    """Add the functions two builds share by ``(class, vtable slot)`` to ``seeds`` (RTTI names are in the binary, so they need no string of the function's own).

    A table whose slots were reordered pairs the wrong functions, and those are nearly always of very different size, so a pair is kept only when
    the two functions (after the ISA's size ratio) are at least ``VT_GATE`` alike. A function a stronger seed already matched keeps that match."""
    va, vb = getattr(A, "vtables", None), getattr(B, "vtables", None)
    if not va or not vb:
        return 0
    taken = {m.b for m in seeds.values()}
    added = 0
    for a, (b, _n, _tot) in sorted(vtable_slot_pairs(va, vb).items()):
        if a in seeds or b in taken or a not in A.funcs or b not in B.funcs:
            continue
        na, nb = A.funcs[a].n * scale, B.funcs[b].n
        if max(na, nb) <= 0 or min(na, nb) / max(na, nb) < VT_GATE:
            continue
        seeds[a] = FMatch(b, 3.0, "vtable")
        taken.add(b)
        added += 1
    return added


def align_functions(
    A: FuncIndex,
    B: FuncIndex,
    *,
    kinds: tuple[str, ...] = ("strings", "imports", "consts"),
    threshold: Optional[float] = None,
    min_margin: float = MIN_MARGIN,
    rounds: int = 3,
    seeds_extra: Optional[dict[int, int]] = None,
    cross_isa: Optional[bool] = None,
    use_vtables: bool = True,
    log: Optional[Callable[[str], None]] = None,
) -> dict[int, FMatch]:
    """``{entry in A: FMatch(entry in B, similarity, "align" | "seed" | "vtable" | ..., margin)}``.

    ``kinds`` are the feature families that may be used: leave ``"strings"`` out to measure the matcher on string-anchored pairs it never saw
    (strings are then ignored everywhere, the similarity included). ``cross_isa`` says the two builds are of different ISAs (default: guessed from
    the size ratio of the seeds); it selects the lower similarity threshold. ``seeds_extra`` are further known pairs (A entry -> B entry) to anchor
    on: an evaluation can pass 80% of the string-anchored pairs here and score the other 20%."""
    log = log or (lambda m: None)
    use_strings = "strings" in kinds
    seeds = match_functions(A, B, kinds=kinds)
    for a, b in (seeds_extra or {}).items():
        if a in A.funcs and b in B.funcs and b not in {m.b for m in seeds.values()}:
            seeds[a] = FMatch(b, 3.0, "given")
    if use_strings:  # unique string pairs the mutual-best rule left out (every unique string must agree on one pair)
        taken = {m.b for m in seeds.values()}
        for a, b in pairs_by_unique_strings(A, B, min_len=4).items():
            if a not in seeds and b not in taken and A.funcs[a].n >= MIN_ALIGN and B.funcs[b].n >= MIN_ALIGN:
                seeds[a] = FMatch(b, 3.0, "string")
                taken.add(b)
    log(f"seeds: {len(seeds)}")
    ratios = [B.funcs[m.b].n / A.funcs[a].n for a, m in seeds.items() if A.funcs[a].n >= 10 and B.funcs[m.b].n >= 10]
    scale = float(median(ratios)) if len(ratios) >= 20 else 1.0  # x64 code is typically ~1.4x the size of x86 code for the same source
    cross = cross_isa if cross_isa is not None else (scale > 1.15 or scale < 0.87)
    if use_vtables:
        added = _vtable_seeds(A, B, seeds, scale)
        if added:
            log(f"vtable seeds: +{added}")
    if threshold is None:  # across a change of ISA similarities run lower (skeletons, sizes, call counts differ), hence the lower bar
        threshold = CROSS_THRESHOLD if cross else THRESHOLD
    matched: dict[int, FMatch] = dict(seeds)
    fa_sorted, fb_sorted = sorted(A.funcs), sorted(B.funcs)
    for r in range(rounds):
        sim = Similarity(A, B, {a: m.b for a, m in matched.items()}, use_strings=use_strings, scale=scale)
        used_b = {m.b for m in matched.values()}
        added = 0
        pairs = sorted((a, m.b) for a, m in matched.items())
        multi = cross  # several chains only across an ISA change; within one generation the single longest chain covers nearly everything
        for (a0, b0), (a1, b1) in _gaps(pairs, multi=multi):
            FA = [e for e in fa_sorted[bisect.bisect_right(fa_sorted, a0) : bisect.bisect_left(fa_sorted, a1)] if e not in matched and A.funcs[e].n >= MIN_ALIGN]
            FB = [e for e in fb_sorted[bisect.bisect_right(fb_sorted, b0) : bisect.bisect_left(fb_sorted, b1)] if e not in used_b and B.funcs[e].n >= MIN_ALIGN]
            if multi and (len(FA) > 3 * len(FB) + 8 or len(FB) > 3 * len(FA) + 8):
                continue  # with several chains the anchors are sparse: runs that differ so much in length are not one stretch of code
            for a, b, s, margin in align_gap(FA, FB, sim, lambda x, y: sim.need(x, y, threshold), threshold, min_margin):
                matched[a] = FMatch(b, s, "align", margin)
                used_b.add(b)
                added += 1
        log(f"round {r + 1}: +{added} (total {len(matched)})")
        if not added:
            break
    return matched
