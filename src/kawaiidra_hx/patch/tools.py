"""Whole-file helpers around patch entries: diff two binaries into an entry, merge entries into a patch file."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Union

from .entries import Entry, Patch, PatchFile, PatchFormatError


def diff_runs(a: bytes, b: bytes, *, gap: int = 0) -> list[tuple[int, int]]:
    """``[(start, end)]`` byte ranges where ``a`` and ``b`` differ; ranges closer than ``gap`` bytes are merged."""
    if len(a) != len(b):
        raise PatchFormatError(f"files differ in size ({len(a)} vs {len(b)} bytes); only same-size in-place edits can be turned into patches")
    runs: list[list[int]] = []
    i, n = 0, len(a)
    # skip identical stretches quickly (files are megabytes): compare in blocks, then refine
    block = 1 << 16
    while i < n:
        if a[i : i + block] == b[i : i + block]:
            i += block
            continue
        j = i
        stop = min(i + block, n)
        while j < stop:
            if a[j] != b[j]:
                if runs and j - runs[-1][1] <= gap:
                    runs[-1][1] = j + 1
                else:
                    runs.append([j, j + 1])
            j += 1
        i = stop
    return [(s, e) for s, e in runs]


def diff_entry(
    original: Union[str, Path, bytes],
    modified: Union[str, Path, bytes],
    *,
    name: str,
    description: str = "",
    game_code: str | None = None,
    dll_name: str | None = None,
    gap: int = 0,
    pad: int = 0,
    pe_identifier: str | None = None,
) -> Entry:
    """Build a ``memory`` entry from two same-size binaries: ``dataDisabled`` from ``original``, ``dataEnabled`` from ``modified``.

    ``gap`` merges runs closer than that many bytes into one patch; ``pad`` widens every patch by that many context bytes on
    each side (handy so a verify still fails on a different build when a patch is a single byte).
    """
    a = original if isinstance(original, (bytes, bytearray)) else Path(original).read_bytes()
    b = modified if isinstance(modified, (bytes, bytearray)) else Path(modified).read_bytes()
    a, b = bytes(a), bytes(b)
    runs = diff_runs(a, b, gap=gap)
    if not runs:
        raise PatchFormatError("the two files are identical")
    padded: list[list[int]] = []
    for s, e in runs:
        s2, e2 = max(0, s - pad), min(len(a), e + pad)
        if padded and s2 <= padded[-1][1]:  # padding made two runs touch/overlap: one patch (apply rejects overlaps)
            padded[-1][1] = max(padded[-1][1], e2)
        else:
            padded.append([s2, e2])
    patches = [Patch(offset=s2, dll_name=dll_name, disabled=a[s2:e2], enabled=b[s2:e2]) for s2, e2 in padded]
    return Entry(name=name, description=description, game_code=game_code, type="memory", patches=patches, pe_identifier=pe_identifier)


def merge_entries(base: PatchFile, new: Iterable[Entry], *, replace: bool = False) -> tuple[PatchFile, list[str]]:
    """Add ``new`` entries to ``base`` (in place). A name clash raises unless ``replace`` is set (then the old entry is swapped).

    Returns ``(base, log_lines)``.
    """
    log: list[str] = []
    for e in new:
        idx = next((i for i, x in enumerate(base.entries) if x.name == e.name), None)
        if idx is None:
            base.entries.append(e)
            log.append(f"added {e.name!r}")
        elif replace:
            base.entries[idx] = e
            log.append(f"replaced {e.name!r}")
        else:
            raise PatchFormatError(f"entry {e.name!r} already exists in the patch file (use replace / --replace to overwrite it)")
    return base, log


def describe_entries(pf: PatchFile) -> str:
    """One line per entry: index, type, name, and what it touches."""
    lines = []
    if pf.headers:
        h = pf.headers[0]
        lines.append("header: " + ", ".join(f"{k}={v}" for k, v in h.items()))
    ident = pf.pe_identifier
    if ident:
        lines.append(f"pe identifier: {ident}")
    for i, e in enumerate(pf.entries, 1):
        if e.type == "memory":
            what = f"{len(e.patches)} patch(es) @ " + ", ".join(f"0x{p.offset:X}" for p in e.patches[:4]) + (" ..." if len(e.patches) > 4 else "")
        elif e.type == "union":
            what = f"{len(e.options)} options @ 0x{e.options[0].offset:X}: " + " | ".join(o.name for o in e.options) if e.options else "no options"
        elif e.type == "number" and e.number:
            what = f"{e.number.size}-byte value {e.number.min}..{e.number.max} @ 0x{e.number.offset:X}"
        elif e.type == "signature" and e.signature:
            what = f"signature {len(e.signature.pattern[0])} bytes, usage {e.signature.usage}, offset {e.signature.offset}"
        else:
            what = ""
        lines.append(f"{i:3d}. [{e.type}] {e.name}" + (f"  - {what}" if what else ""))
    return "\n".join(lines)
