"""Byte-pattern search with wildcards, mirroring the reference patcher's pattern scan.

The patcher scans the whole module data one byte at a time (so overlapping matches count) and takes the ``usage``-th
(0-based) hit. Offline (this project) the data is the file; at run time it is the loaded image. A signature that is
unique in the file is the portable case; ``usage`` exists for the rest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from .entries import SignatureSpec


def compile_pattern(pattern: bytes, mask: bytes) -> re.Pattern[bytes]:
    """Regex that matches ``pattern`` where ``mask`` is 0xFF and anything where it is 0, as a zero-width lookahead
    (so ``finditer`` yields overlapping positions)."""
    if len(pattern) != len(mask) or not pattern:
        raise ValueError("pattern and mask must be the same non-zero length")
    parts: list[bytes] = []
    i = 0
    while i < len(pattern):
        if not mask[i]:
            j = i
            while j < len(pattern) and not mask[j]:
                j += 1
            parts.append(b".{%d}" % (j - i))
            i = j
        else:
            j = i
            while j < len(pattern) and mask[j]:
                j += 1
            parts.append(re.escape(pattern[i:j]))
            i = j
    return re.compile(b"(?=" + b"".join(parts) + b")", re.DOTALL)


def _anchor(pattern: bytes, mask: bytes) -> tuple[int, int] | None:
    """``(start, length)`` of the longest run of fixed bytes (what ``bytes.find`` can jump to), or None."""
    best: tuple[int, int] | None = None
    i = 0
    while i < len(pattern):
        if mask[i]:
            j = i
            while j < len(pattern) and mask[j]:
                j += 1
            if best is None or j - i > best[1]:
                best = (i, j - i)
            i = j
        else:
            i += 1
    return best


def _full_regex(pattern: bytes, mask: bytes) -> re.Pattern[bytes]:
    """Anchored-at-``match(pos)`` regex of the whole pattern (no lookahead)."""
    return re.compile(compile_pattern(pattern, mask).pattern[len(b"(?="):-1], re.DOTALL)


def iter_matches(data: bytes, pattern: bytes, mask: bytes, start: int = 0) -> Iterator[int]:
    """Every offset (ascending, overlapping allowed) at which the masked pattern matches.

    Jumps between occurrences of the pattern's longest fixed run with ``bytes.find`` and verifies the whole pattern there
    (fast on 12 MB DLLs); patterns without a run of 3+ fixed bytes fall back to a lookahead regex scan.
    """
    anchor = _anchor(pattern, mask)
    if anchor is None or anchor[1] < 3:
        for m in compile_pattern(pattern, mask).finditer(data, start):
            yield m.start()
        return
    a_start, a_len = anchor
    needle = pattern[a_start : a_start + a_len]
    rx = _full_regex(pattern, mask)
    pos = start + a_start
    while True:
        idx = data.find(needle, pos)
        if idx < 0:
            return
        p = idx - a_start
        if p >= start and rx.match(data, p):
            yield p
        pos = idx + 1


def count_matches(data: bytes, pattern: bytes, mask: bytes, limit: int | None = None) -> int:
    """Number of matches, stopping early once ``limit`` is reached (uniqueness checks only need 0 / 1 / 2+)."""
    n = 0
    for _ in iter_matches(data, pattern, mask):
        n += 1
        if limit is not None and n >= limit:
            break
    return n


def find_nth(data: bytes, pattern: bytes, mask: bytes, usage: int = 0) -> tuple[int | None, int]:
    """``(offset of the usage-th match or None, total match count)``. The count scans the whole buffer."""
    hits = list(iter_matches(data, pattern, mask))
    return (hits[usage] if usage < len(hits) else None), len(hits)


@dataclass(frozen=True)
class SignatureResolution:
    """Where a ``signature`` entry lands in a given binary."""

    state: str  # "original" | "applied" | "not_found" | "no_such_usage"
    matches: int  # matches of the original (unpatched) signature
    patched_matches: int  # matches of the signature with the replacement overlaid
    match_offset: int | None  # file offset of the matched signature start
    offset: int | None  # file offset of the replacement window (match + spec.offset)
    disabled: bytes | None  # bytes in the window as in the unpatched file
    enabled: bytes | None  # bytes after the replacement

    @property
    def ok(self) -> bool:
        return self.state in ("original", "applied")


def overlay_signature(spec: SignatureSpec) -> tuple[bytes, bytes]:
    """The signature as it reads *after* the replacement was applied (replacement bytes become fixed bytes)."""
    pat, mask = (bytearray(x) for x in spec.pattern)
    rbytes, rmask = spec.replace
    for i, (b, m) in enumerate(zip(rbytes, rmask)):
        if m:
            pat[spec.offset + i] = b
            mask[spec.offset + i] = 0xFF
    return bytes(pat), bytes(mask)


def resolve_signature(data: bytes, spec: SignatureSpec) -> SignatureResolution:
    """Apply the signature-patch rules to ``data``."""
    pat, mask = spec.pattern
    hit, n = find_nth(data, pat, mask, spec.usage)
    rbytes, rmask = spec.replace
    if hit is not None:
        start = hit + spec.offset
        actual = data[start : start + len(rbytes)]
        enabled = bytes(a if not m else b for a, b, m in zip(actual, rbytes, rmask))
        return SignatureResolution("original", n, 0, hit, start, actual, enabled)
    opat, omask = overlay_signature(spec)
    ohit, on = find_nth(data, opat, omask, spec.usage)
    if ohit is not None:
        start = ohit + spec.offset
        actual = data[start : start + len(rbytes)]
        # the original bytes are only known where the signature fixes them (wildcard positions are unrecoverable)
        disabled = bytes(
            actual[i] if not mask[spec.offset + i] else pat[spec.offset + i] for i in range(len(rbytes))
        )
        return SignatureResolution("applied", n, on, ohit, start, disabled, actual)
    return SignatureResolution("no_such_usage" if n else "not_found", n, on, None, None, None, None)
