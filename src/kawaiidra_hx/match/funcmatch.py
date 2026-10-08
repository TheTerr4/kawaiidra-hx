"""Match functions between two builds of one program (best between adjacent builds: same ISA, compiler and code base).

Seeds come from rare shared features (string literals, imports by ``dll!#ordinal``, large constants) accepted only when the pair is the
mutual best by a clear margin; the match then spreads along the call graph (callees aligned in call order, a sole caller of a matched function) with
the same sanity checks. Nothing is accepted that the features and the instruction skeleton do not both support.

Feature/call-graph matching alone recovers little across a change of ISA or a rewrite; across such a gap it only seeds the order-aware
alignment (:mod:`kawaiidra_hx.match.align`), which is the matcher to use in general.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Callable, Optional

from ..queries.fingerprint import FuncFP, FuncIndex

BASE_WEIGHT = {"strings": 3.0, "imports": 1.4, "consts": 0.8}
MAX_DF = 8  # a feature shared by more functions than this (in either build) is not a distinguishing anchor
MIN_SIZE = 5  # instructions; tiny functions have no identity


@dataclass(frozen=True)
class FMatch:
    b: int  # entry address in the second build
    score: float
    method: str  # "seed" | "callee" | "caller" | "align" | "string" | "vtable" | "given" (see align.py)
    margin: float = 0.0  # how far the runner-up candidate was behind (align only)

    def __repr__(self) -> str:
        return f"FMatch(0x{self.b:X}, {self.score:.2f}, {self.method})"


def size_sim(a: FuncFP, b: FuncFP) -> float:
    return min(a.n, b.n) / max(a.n, b.n) if max(a.n, b.n) else 0.0


def skeleton_sim(a: FuncFP, b: FuncFP, cap: int = 4000) -> float:
    if not a.skeleton or not b.skeleton:
        return 0.0
    if len(a.skeleton) * len(b.skeleton) > cap * cap:
        a_s, b_s = a.skeleton[:cap], b.skeleton[:cap]
    else:
        a_s, b_s = a.skeleton, b.skeleton
    return SequenceMatcher(None, a_s, b_s, autojunk=False).ratio()


def feature_scores(a: FuncFP, A: FuncIndex, B: FuncIndex, kinds: tuple[str, ...] = ("strings", "imports", "consts")) -> dict[int, float]:
    """Candidate entries in B with the summed rarity weight of the features they share with ``a``."""
    scores: dict[int, float] = {}
    for kind in kinds:
        for f in getattr(a, kind):
            da, db = A.df(kind, f), B.df(kind, f)
            if not db or da > MAX_DF or db > MAX_DF:
                continue
            w = BASE_WEIGHT[kind] / math.sqrt(da * db)
            for e in B.inverted[kind].get(f, ()):
                scores[e] = scores.get(e, 0.0) + w
    return scores


def _token(fp: FuncFP) -> str:
    """Coarse identity of a callee used to align call lists: size bucket + whether it touches strings/imports."""
    return f"{fp.n.bit_length()}{'s' if fp.strings else ''}{'i' if fp.imports else ''}"


def _dedupe(seq: tuple[int, ...]) -> list[int]:
    return list(dict.fromkeys(seq))


def match_functions(
    A: FuncIndex,
    B: FuncIndex,
    *,
    kinds: tuple[str, ...] = ("strings", "imports", "consts"),
    seed_min: float = 1.5,
    margin: float = 1.5,
    accept_sim: float = 0.45,
    rounds: int = 12,
    log: Optional[Callable[[str], None]] = None,
) -> dict[int, FMatch]:
    """``{entry in A: FMatch(entry in B, ...)}``. ``kinds`` selects the feature families used for seeding (evaluation drops ``strings``)."""
    log = log or (lambda m: None)
    matched: dict[int, FMatch] = {}
    taken: set[int] = set()

    # ---- seeds: mutual best by rare features, with a margin over the runner-up ------------------------
    best_a: dict[int, tuple[int, float, float]] = {}
    cands_b: dict[int, dict[int, float]] = {}
    for ea, fa in A.funcs.items():
        if fa.n < MIN_SIZE:
            continue
        sc = feature_scores(fa, A, B, kinds)
        if not sc:
            continue
        ranked = sorted(sc.items(), key=lambda kv: -kv[1])
        top = ranked[0]
        second = ranked[1][1] if len(ranked) > 1 else 0.0
        best_a[ea] = (top[0], top[1], second)
        for eb, s in ranked[:6]:
            cands_b.setdefault(eb, {})[ea] = s
    for ea, (eb, s, second) in best_a.items():
        if s < seed_min:
            continue
        if second > 0 and s < second * margin:
            continue
        # mutual: ea must also be the best candidate of eb among the functions that list eb
        mine = cands_b.get(eb, {})
        if mine and max(mine.items(), key=lambda kv: kv[1])[0] != ea:
            continue
        fa, fb = A.funcs[ea], B.funcs[eb]
        if size_sim(fa, fb) < 0.3 or eb in taken:
            continue
        sk = skeleton_sim(fa, fb)
        if sk < 0.2 and fa.n > 12:
            continue
        matched[ea] = FMatch(eb, s + sk, "seed")
        taken.add(eb)
    log(f"seeds: {len(matched)}")

    # ---- propagation along the call graph ------------------------------------------------------------------
    for r in range(rounds):
        proposals: dict[int, dict[int, int]] = {}
        for ea, m in list(matched.items()):
            fa, fb = A.funcs[ea], B.funcs[m.b]
            ca, cb = _dedupe(fa.calls), _dedupe(fb.calls)
            ca = [x for x in ca if x in A.funcs]
            cb = [y for y in cb if y in B.funcs]
            if ca and cb:
                if len(ca) == len(cb):
                    pairs = list(zip(ca, cb))
                else:
                    ta, tb = [_token(A.funcs[x]) for x in ca], [_token(B.funcs[y]) for y in cb]
                    pairs = []
                    for tag, i1, i2, j1, j2 in SequenceMatcher(None, ta, tb, autojunk=False).get_opcodes():
                        if tag == "equal":
                            pairs += [(ca[i1 + k], cb[j1 + k]) for k in range(i2 - i1)]
                for x, y in pairs:
                    proposals.setdefault(x, {})[y] = proposals.setdefault(x, {}).get(y, 0) + 1
            ra, rb = [x for x in A.callers.get(ea, ()) if x != ea], [y for y in B.callers.get(m.b, ()) if y != m.b]
            if len(ra) == 1 and len(rb) == 1:
                proposals.setdefault(ra[0], {})[rb[0]] = proposals.setdefault(ra[0], {}).get(rb[0], 0) + 1
        added = 0
        for x, votes in proposals.items():
            if x in matched or A.funcs[x].n < MIN_SIZE:
                continue
            ranked = sorted(votes.items(), key=lambda kv: -kv[1])
            y, v = ranked[0]
            if len(ranked) > 1 and ranked[1][1] == v:
                continue  # tie
            if y in taken:
                continue
            fa, fb = A.funcs[x], B.funcs[y]
            if size_sim(fa, fb) < accept_sim:
                continue
            sk = skeleton_sim(fa, fb)
            if sk < accept_sim and fa.n > 8:
                continue
            matched[x] = FMatch(y, v + sk, "callee")
            taken.add(y)
            added += 1
        log(f"round {r + 1}: +{added} (total {len(matched)})")
        if not added:
            break
    return matched


def pairs_by_unique_strings(A: FuncIndex, B: FuncIndex, min_len: int = 6) -> dict[int, int]:
    """Pairs of functions that reference the same *unique* string in both builds (every shared unique string must agree).

    Used as ground truth in evaluations: the strings are excluded from the matcher's features and the pair must still be found."""
    votes: dict[int, dict[int, int]] = {}
    for s, ea in A.inverted["strings"].items():
        eb = B.inverted["strings"].get(s, ())
        if len(s) >= min_len and len(ea) == 1 and len(eb) == 1:
            votes.setdefault(ea[0], {})[eb[0]] = votes.setdefault(ea[0], {}).get(eb[0], 0) + 1
    return {a: next(iter(v)) for a, v in votes.items() if len(v) == 1}


def evaluate(match: dict[int, FMatch], truth: dict[int, int]) -> dict[str, float | int]:
    right = sum(1 for a, b in truth.items() if a in match and match[a].b == b)
    wrong = sum(1 for a, b in truth.items() if a in match and match[a].b != b)
    return {
        "truth": len(truth), "right": right, "wrong": wrong, "missed": len(truth) - right - wrong,
        "recall": right / len(truth) if truth else 0.0, "precision": right / (right + wrong) if right + wrong else 0.0,
    }  # fmt: skip
