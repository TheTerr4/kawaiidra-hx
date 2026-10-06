"""verify / apply / make for file-offset patches. Never modifies the source binary."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Union

from ..pe import NotMappedError, PEInfo, parse_pe
from .entries import Entry, Patch, PatchFormatError


class PatchMismatchError(RuntimeError):
    """The file does not contain the bytes the patch expects (wrong DLL version, or overlapping edit)."""


@dataclass
class PatchCheck:
    entry: str
    patch: Patch
    actual: bytes
    state: str  # "original" | "applied" | "mismatch" | "out_of_range"
    va: int | None = None
    section: str | None = None

    @property
    def ok(self) -> bool:
        return self.state in ("original", "applied")

    def format(self) -> str:
        p = self.patch
        loc = f"file 0x{p.offset:X}"
        if self.va is not None:
            loc += f" -> VA 0x{self.va:X} ({self.section})"
        line = f"[{self.state.upper():<12}] {self.entry}: {loc} len={p.length}"
        if self.state == "mismatch":
            line += f"\n    expected {p.disabled.hex().upper()} (or patched {p.enabled.hex().upper()})"
            line += f"\n    found    {self.actual.hex().upper()}"
        elif self.state == "out_of_range":
            line += " (offset past end of file)"
        return line


@dataclass
class VerifyReport:
    checks: list[PatchCheck] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # unsupported entry types
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def format(self) -> str:
        lines = [c.format() for c in self.checks]
        lines += [f"[SKIPPED     ] {n} (unsupported entry type)" for n in self.skipped]
        lines += [f"note: {n}" for n in self.notes]
        n_ok = sum(c.ok for c in self.checks)
        lines.append(f"{n_ok}/{len(self.checks)} patches OK" + ("" if self.ok else "  -- MISMATCH, do not apply"))
        return "\n".join(lines)


def _read(source: Union[str, Path, bytes]) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    return Path(source).read_bytes()


def _pe_or_none(data: bytes) -> PEInfo | None:
    try:
        return parse_pe(data)
    except Exception:
        return None


def _locate(pe: PEInfo | None, offset: int) -> tuple[int | None, str | None]:
    if pe is None:
        return None, None
    try:
        va = pe.offset_to_va(offset)
    except NotMappedError:
        return None, None
    s = pe.section_for_offset(offset)
    return va, (s.name if s else "headers")


def verify(source: Union[str, Path, bytes], entries: Iterable[Entry]) -> VerifyReport:
    """Check every patch's bytes against the file. Read-only."""
    data = _read(source)
    pe = _pe_or_none(data)
    report = VerifyReport()
    claimed: list[tuple[int, int, str]] = []
    for entry in entries:
        if not entry.supported:
            report.skipped.append(f"{entry.name} (type={entry.type})")
            continue
        for p in entry.patches:
            end = p.offset + p.length
            va, sec = _locate(pe, p.offset)
            if end > len(data) or p.offset < 0:
                report.checks.append(PatchCheck(entry.name, p, b"", "out_of_range", va, sec))
                continue
            actual = data[p.offset : end]
            if actual == p.disabled:
                state = "original"
            elif actual == p.enabled:
                state = "applied"
            else:
                state = "mismatch"
            report.checks.append(PatchCheck(entry.name, p, actual, state, va, sec))
            for (o, e, who) in claimed:
                if p.offset < e and o < end:
                    report.notes.append(f"{entry.name!r} overlaps {who!r} at file 0x{max(o, p.offset):X}")
            claimed.append((p.offset, end, entry.name))
    return report


@dataclass
class ApplyReport:
    src: str
    dst: str
    applied: list[str]
    already_applied: list[str]
    bytes_changed: int
    sha256_before: str
    sha256_after: str

    def format(self) -> str:
        lines = [
            f"wrote {self.dst}",
            f"  patches applied: {len(self.applied)}" + (f" (+{len(self.already_applied)} already applied)" if self.already_applied else ""),
            f"  bytes changed vs source: {self.bytes_changed}",
            f"  sha256 source : {self.sha256_before}",
            f"  sha256 patched: {self.sha256_after}",
        ]
        return "\n".join(lines)


def apply(
    src: Union[str, Path],
    dst: Union[str, Path],
    entries: Iterable[Entry],
    *,
    overwrite: bool = False,
) -> ApplyReport:
    """Copy ``src`` to ``dst`` with the given entries applied. ``src`` is only ever read.

    Aborts before writing anything if any patch's expected original bytes are not found.
    """
    src_p, dst_p = Path(src).resolve(), Path(dst).resolve()
    if src_p == dst_p or (dst_p.exists() and os.path.samefile(src_p, dst_p)):
        raise PatchMismatchError("refusing to patch in place: destination must differ from the source file")
    if dst_p.exists() and not overwrite:
        raise FileExistsError(f"{dst_p} exists (pass overwrite=True / --overwrite to replace it)")

    entries = list(entries)
    data = bytearray(src_p.read_bytes())
    report = verify(bytes(data), entries)
    if not report.ok:
        raise PatchMismatchError("refusing to apply:\n" + report.format())
    overlaps = [n for n in report.notes if "overlaps" in n]
    if overlaps:
        raise PatchMismatchError("refusing to apply overlapping patches:\n  " + "\n  ".join(overlaps))

    applied: list[str] = []
    already: list[str] = []
    for c in report.checks:
        if c.state == "applied":
            already.append(c.entry)
            continue
        data[c.patch.offset : c.patch.offset + c.patch.length] = c.patch.enabled
        applied.append(c.entry)

    original = src_p.read_bytes()
    changed = sum(1 for a, b in zip(original, data) if a != b)
    dst_p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dst_p.parent), prefix=dst_p.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, dst_p)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return ApplyReport(
        src=str(src_p),
        dst=str(dst_p),
        applied=applied,
        already_applied=already,
        bytes_changed=changed,
        sha256_before=hashlib.sha256(original).hexdigest(),
        sha256_after=hashlib.sha256(bytes(data)).hexdigest(),
    )


def make_entry(
    src: Union[str, Path],
    edits: list[tuple[str, str]],
    *,
    name: str,
    description: str = "",
    game_code: str | None = None,
    dll_name: str | None = None,
) -> Entry:
    """Build an entry from ``(location, new_hex)`` edits, reading the original bytes from ``src``.

    ``location`` is ``off:0x5CFD60`` (file offset), ``va:0x1805D0760`` or ``rva:0x5D0760``; a bare number is a
    file offset. The original bytes are read from the file so ``dataDisabled`` is always exact.
    """
    data = Path(src).read_bytes()
    pe = parse_pe(data)
    patches: list[Patch] = []
    for loc, new_hex in edits:
        kind, _, num = loc.partition(":") if ":" in loc else ("off", "", loc)
        value = int(num, 0)
        if kind == "va":
            offset = pe.va_to_offset(value)
        elif kind == "rva":
            offset = pe.rva_to_offset(value)
        elif kind == "off":
            offset = value
        else:
            raise PatchFormatError(f"unknown location kind {kind!r} (use off:, va:, rva:)")
        new = bytes.fromhex(new_hex.replace(" ", ""))
        if offset + len(new) > len(data):
            raise PatchFormatError(f"{loc}: edit runs past the end of the file")
        patches.append(Patch(offset=offset, dll_name=dll_name, disabled=data[offset : offset + len(new)], enabled=new))
    return Entry(name=name, description=description, game_code=game_code, type="memory", patches=patches)
