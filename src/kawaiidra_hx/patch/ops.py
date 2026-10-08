"""verify / apply / revert / make for file-offset patches. Never modifies the source binary.

Semantics follow the reference patcher: offsets are FILE offsets; ``memory`` toggles between
``dataDisabled`` and ``dataEnabled``; ``union`` writes one option's ``data``; ``number`` writes a little-endian integer;
``signature`` locates its own offset by byte pattern (see :mod:`kawaiidra_hx.patch.signature`).
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Optional, Union

from ..pe import NotMappedError, PEInfo, parse_pe
from .entries import Entry, NumberSpec, Patch, PatchFormatError, UnionOption
from .signature import SignatureResolution, resolve_signature


class PatchMismatchError(RuntimeError):
    """The file does not contain the bytes the patch expects (wrong DLL version, or overlapping edit)."""


# --- checks ---------------------------------------------------------------------------------------


class _Located:
    """Mixin: checks carry ``va``/``section`` (set by ``verify``) and format their location the same way."""

    va: int | None
    section: str | None

    def _loc(self, offset: int) -> str:
        loc = f"file 0x{offset:X}"
        if self.va is not None:
            loc += f" -> VA 0x{self.va:X} ({self.section})"
        return loc


@dataclass
class PatchCheck(_Located):
    """A ``memory`` patch against the file."""

    entry: str = ""
    patch: Patch | None = None
    actual: bytes = b""
    state: str = "mismatch"  # "original" | "applied" | "mismatch" | "out_of_range"
    va: int | None = None
    section: str | None = None

    @property
    def ok(self) -> bool:
        return self.state in ("original", "applied")

    def format(self) -> str:
        p = self.patch
        assert p is not None
        line = f"[{self.state.upper():<12}] {self.entry}: {self._loc(p.offset)} len={p.length}"
        if self.state == "mismatch":
            line += f"\n    expected {p.disabled.hex().upper()} (or patched {p.enabled.hex().upper()})"
            line += f"\n    found    {self.actual.hex().upper()}"
        elif self.state == "out_of_range":
            line += " (offset past end of file)"
        return line


@dataclass
class UnionCheck(_Located):
    """A ``union`` entry: which option's bytes does the file currently hold?"""

    entry: str = ""
    offset: int = 0
    length: int = 0
    actual: bytes = b""
    active: list[str] = field(default_factory=list)  # names of every option equal to the file bytes
    options: list[str] = field(default_factory=list)
    state: str = "unmatched"  # "matches" | "unmatched" | "out_of_range"
    va: int | None = None
    section: str | None = None

    @property
    def ok(self) -> bool:
        return self.state == "matches"

    def format(self) -> str:
        head = f"[{self.state.upper():<12}] {self.entry}: {self._loc(self.offset)} len={self.length}"
        if self.state == "matches":
            return head + "  = " + " | ".join(repr(n) for n in self.active)
        if self.state == "out_of_range":
            return head + " (offset past end of file)"
        return head + f"\n    found {self.actual.hex().upper()}, matches none of: {', '.join(self.options)}"


@dataclass
class NumberCheck(_Located):
    """A ``number`` entry: the current little-endian value and whether it is inside [min, max]."""

    entry: str = ""
    spec: NumberSpec | None = None
    value: int | None = None
    state: str = "value"  # "value" | "bad_value" | "out_of_range"
    va: int | None = None
    section: str | None = None

    @property
    def ok(self) -> bool:
        return self.state == "value"

    def format(self) -> str:
        s = self.spec
        assert s is not None
        head = f"[{self.state.upper():<12}] {self.entry}: {self._loc(s.offset)} size={s.size}"
        if self.state == "out_of_range":
            return head + " (offset past end of file)"
        extra = "" if self.state == "value" else "  OUTSIDE the allowed range"
        return head + f" value={self.value} (allowed {s.min}..{s.max}){extra}"


@dataclass
class SignatureCheck(_Located):
    """A ``signature`` entry resolved against the file."""

    entry: str = ""
    resolution: SignatureResolution | None = None
    usage: int = 0
    va: int | None = None
    section: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.resolution and self.resolution.ok)

    @property
    def state(self) -> str:
        return self.resolution.state if self.resolution else "not_found"

    def format(self) -> str:
        r = self.resolution
        assert r is not None
        head = f"[{r.state.upper():<12}] {self.entry}: signature"
        if r.offset is not None:
            head += f" -> {self._loc(r.offset)} len={len(r.enabled or b'')} ({r.matches} match{'es' if r.matches != 1 else ''}, using #{self.usage})"
        elif r.state == "no_such_usage":
            head += f" matches {r.matches}x but patch uses match #{self.usage}"
        else:
            head += " not found in this file"
        return head


@dataclass
class IdentityCheck:
    """The patch file / entry names a PE identifier; does this binary have it?"""

    entry: str
    expected: str
    actual: str

    @property
    def ok(self) -> bool:
        return self.expected == self.actual

    @property
    def state(self) -> str:
        return "identity" if self.ok else "wrong_build"

    def format(self) -> str:
        if self.ok:
            return f"[IDENTITY    ] {self.entry}: build {self.actual}"
        return f"[WRONG_BUILD ] {self.entry}: patches are for {self.expected} but this binary is {self.actual}"


Check = Union[PatchCheck, UnionCheck, NumberCheck, SignatureCheck, IdentityCheck]


@dataclass
class VerifyReport:
    checks: list[Check] = field(default_factory=list)
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
        lines.append(f"{n_ok}/{len(self.checks)} checks OK" + ("" if self.ok else "  -- MISMATCH, do not apply"))
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


def _identity_code(identifier: str) -> str:
    return identifier.split("-", 1)[0]


def verify(
    source: Union[str, Path, bytes],
    entries: Iterable[Entry],
    *,
    expected_id: Optional[str] = None,
) -> VerifyReport:
    """Check every patch against the file. Read-only.

    ``expected_id`` is the PE identifier (``ABC-12345678_1000``) the patch file is for (e.g. from its file name); entries
    carrying their own ``peIdentifier`` are checked too. A binary with a different identifier fails the report.
    """
    data = _read(source)
    pe = _pe_or_none(data)
    report = VerifyReport()
    claimed: list[tuple[int, int, str]] = []
    seen_ids: set[str] = set()

    def claim(entry: str, offset: int, end: int) -> None:
        for (o, e, who) in claimed:
            if offset < e and o < end:
                report.notes.append(f"{entry!r} overlaps {who!r} at file 0x{max(o, offset):X}")
        claimed.append((offset, end, entry))

    def check_identity(entry: Entry | None, ident: str | None) -> None:
        if not ident or ident in seen_ids or pe is None:
            return
        seen_ids.add(ident)
        actual = pe.pe_identifier(_identity_code(ident))
        report.checks.append(IdentityCheck(entry.name if entry else "(patch file)", ident, actual))

    check_identity(None, expected_id)
    for entry in entries:
        if not entry.supported:
            report.skipped.append(f"{entry.name} (type={entry.type})")
            continue
        check_identity(entry, entry.pe_identifier)
        if entry.type == "memory":
            for p in entry.patches:
                end = p.offset + p.length
                va, sec = _locate(pe, p.offset)
                if end > len(data) or p.offset < 0:
                    report.checks.append(PatchCheck(entry.name, p, b"", "out_of_range", va, sec))
                    continue
                actual = data[p.offset : end]
                state = "original" if actual == p.disabled else "applied" if actual == p.enabled else "mismatch"
                report.checks.append(PatchCheck(entry.name, p, actual, state, va, sec))
                claim(entry.name, p.offset, end)
        elif entry.type == "union" and entry.options:
            o0 = entry.options[0]
            lo = min(o.offset for o in entry.options)
            hi = max(o.offset + o.length for o in entry.options)
            va, sec = _locate(pe, lo)
            names = [o.name for o in entry.options]
            if hi > len(data) or lo < 0:
                report.checks.append(UnionCheck(entry.name, lo, hi - lo, b"", [], names, "out_of_range", va, sec))
                continue
            active = [o.name for o in entry.options if data[o.offset : o.offset + o.length] == o.data]
            actual = data[o0.offset : o0.offset + o0.length]
            report.checks.append(
                UnionCheck(entry.name, lo, hi - lo, actual, active, names, "matches" if active else "unmatched", va, sec)
            )
            claim(entry.name, lo, hi)
        elif entry.type == "number" and entry.number is not None:
            n = entry.number
            va, sec = _locate(pe, n.offset)
            if n.offset < 0 or n.offset + n.size > len(data):
                report.checks.append(NumberCheck(entry.name, n, None, "out_of_range", va, sec))
                continue
            value = int.from_bytes(data[n.offset : n.offset + n.size], "little", signed=n.min < 0)
            report.checks.append(NumberCheck(entry.name, n, value, "value" if n.min <= value <= n.max else "bad_value", va, sec))
            claim(entry.name, n.offset, n.offset + n.size)
        elif entry.type == "signature" and entry.signature is not None:
            res = resolve_signature(data, entry.signature)
            va, sec = _locate(pe, res.offset) if res.offset is not None else (None, None)
            report.checks.append(SignatureCheck(entry.name, res, entry.signature.usage, va, sec))
            if res.ok and res.offset is not None and res.enabled is not None:
                claim(entry.name, res.offset, res.offset + len(res.enabled))
                if res.matches > 1:
                    report.notes.append(
                        f"{entry.name!r}: signature matches {res.matches}x in this file (patch uses #{entry.signature.usage}); "
                        "not unique, so it may land elsewhere on another build"
                    )
        # group entries carry no bytes
    return report


# --- apply / revert -------------------------------------------------------------------------------


@dataclass
class Write:
    entry: str
    offset: int
    old: bytes  # bytes in the source
    new: bytes
    already: bool = False  # the source already holds ``new``

    @property
    def length(self) -> int:
        return len(self.new)


@dataclass
class ApplyReport:
    src: str
    dst: str
    applied: list[str]
    already_applied: list[str]
    bytes_changed: int
    sha256_before: str
    sha256_after: str
    skipped: list[str] = field(default_factory=list)  # entries that needed a selection (union/number) or are unsupported
    mode: str = "apply"

    def format(self) -> str:
        done = "reverted" if self.mode == "revert" else "applied"
        lines = [
            f"wrote {self.dst}",
            f"  patches {done}: {len(self.applied)}" + (f" (+{len(self.already_applied)} already {done})" if self.already_applied else ""),
            f"  bytes changed vs source: {self.bytes_changed}",
            f"  sha256 source : {self.sha256_before}",
            f"  sha256 patched: {self.sha256_after}",
        ]
        lines += [f"  skipped: {s}" for s in self.skipped]
        return "\n".join(lines)


def _find_option(entry: Entry, wanted: str) -> UnionOption:
    exact = [o for o in entry.options if o.name == wanted]
    if exact:
        return exact[0]
    folded = [o for o in entry.options if o.name.casefold() == wanted.casefold()]
    if len(folded) == 1:
        return folded[0]
    if wanted.isdigit() and 1 <= int(wanted) <= len(entry.options):
        return entry.options[int(wanted) - 1]
    raise PatchFormatError(f"{entry.name!r} has no option {wanted!r}; options: {[o.name for o in entry.options]}")


def plan_writes(
    data: bytes,
    entries: Iterable[Entry],
    selections: Mapping[str, str] | None = None,
    *,
    mode: str = "apply",
) -> tuple[list[Write], list[str]]:
    """Turn entries into byte writes against ``data``. Returns ``(writes, skipped_notes)``.

    ``selections`` maps an entry name to the union option name (or number value) to write; unions/numbers without a
    selection are skipped. ``mode="revert"`` restores ``dataDisabled`` (memory/signature only).
    """
    selections = dict(selections or {})
    writes: list[Write] = []
    skipped: list[str] = []
    for entry in entries:
        if not entry.supported:
            skipped.append(f"{entry.name} (unsupported type {entry.type})")
        elif entry.type == "memory":
            for p in entry.patches:
                actual = data[p.offset : p.offset + p.length]
                want = p.disabled if mode == "revert" else p.enabled
                writes.append(Write(entry.name, p.offset, actual, want, already=actual == want))
        elif entry.type == "signature" and entry.signature is not None:
            res = resolve_signature(data, entry.signature)
            if not res.ok or res.offset is None or res.enabled is None or res.disabled is None:
                raise PatchMismatchError(f"{entry.name!r}: signature {res.state} ({res.matches} matches)")
            actual = data[res.offset : res.offset + len(res.enabled)]
            want = res.disabled if mode == "revert" else res.enabled
            writes.append(Write(entry.name, res.offset, actual, want, already=actual == want))
        elif entry.type == "union":
            if mode == "revert":
                skipped.append(f"{entry.name} (union: no defined original to revert to)")
            elif entry.name in selections and entry.options:
                opt = _find_option(entry, selections[entry.name])
                actual = data[opt.offset : opt.offset + opt.length]
                writes.append(Write(entry.name, opt.offset, actual, opt.data, already=actual == opt.data))
            else:
                skipped.append(f"{entry.name} (union: choose with --set \"{entry.name}=<option>\")")
        elif entry.type == "number" and entry.number is not None:
            n = entry.number
            if mode == "revert":
                skipped.append(f"{entry.name} (number: no defined original to revert to)")
            elif entry.name in selections:
                try:
                    value = int(str(selections[entry.name]), 0)
                except ValueError:
                    raise PatchFormatError(f"{entry.name!r}: {selections[entry.name]!r} is not an integer") from None
                if not n.min <= value <= n.max:
                    raise PatchFormatError(f"{entry.name!r}: {value} is outside the allowed range {n.min}..{n.max}")
                new = value.to_bytes(n.size, "little", signed=value < 0)
                actual = data[n.offset : n.offset + n.size]
                writes.append(Write(entry.name, n.offset, actual, new, already=actual == new))
            else:
                skipped.append(f"{entry.name} (number {n.min}..{n.max}: set with --set \"{entry.name}=<value>\")")
        # group entries: nothing to write
    return writes, skipped


def apply(
    src: Union[str, Path],
    dst: Union[str, Path],
    entries: Iterable[Entry],
    *,
    overwrite: bool = False,
    selections: Mapping[str, str] | None = None,
    mode: str = "apply",
    expected_id: Optional[str] = None,
) -> ApplyReport:
    """Copy ``src`` to ``dst`` with the given entries applied (or reverted). ``src`` is only ever read.

    Aborts before writing anything if any patch's expected original bytes are not found, a union/number/signature
    does not resolve, patches overlap, or the binary's PE identifier differs from the one the patches are for.
    """
    if mode not in ("apply", "revert"):
        raise ValueError("mode must be 'apply' or 'revert'")
    src_p, dst_p = Path(src).resolve(), Path(dst).resolve()
    if src_p == dst_p or (dst_p.exists() and os.path.samefile(src_p, dst_p)):
        raise PatchMismatchError("refusing to patch in place: destination must differ from the source file")
    if dst_p.exists() and not overwrite:
        raise FileExistsError(f"{dst_p} exists (pass overwrite=True / --overwrite to replace it)")

    entries = list(entries)
    original = src_p.read_bytes()
    data = bytearray(original)

    sel = dict(selections or {})
    unknown = sorted(set(sel) - {e.name for e in entries})
    if unknown:  # a typo or an entry excluded by --entry would otherwise be silently ignored
        raise PatchFormatError(f"selection for entr{'y' if len(unknown) == 1 else 'ies'} not being applied: {', '.join(map(repr, unknown))}")
    # unselected unions/numbers are skipped, so only verify what we will write
    to_check = [e for e in entries if e.type not in ("union", "number") or e.name in sel]
    report = verify(bytes(data), to_check, expected_id=expected_id)
    if not report.ok:
        raise PatchMismatchError("refusing to apply:\n" + report.format())
    overlaps = [n for n in report.notes if "overlaps" in n]
    if overlaps:
        raise PatchMismatchError("refusing to apply overlapping patches:\n  " + "\n  ".join(overlaps))

    writes, skipped = plan_writes(bytes(data), entries, sel, mode=mode)
    applied: list[str] = []
    already: list[str] = []
    for w in writes:
        if w.already:
            already.append(w.entry)
            continue
        data[w.offset : w.offset + w.length] = w.new
        applied.append(w.entry)

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
        skipped=skipped,
        mode=mode,
    )


# --- make -----------------------------------------------------------------------------------------


def make_entry(
    src: Union[str, Path],
    edits: list[tuple[str, str]],
    *,
    name: str,
    description: str = "",
    game_code: str | None = None,
    dll_name: str | None = None,
    pe_identifier: str | None = None,
    caution: str = "",
) -> Entry:
    """Build an entry from ``(location, new_hex)`` edits, reading the original bytes from ``src``.

    ``location`` is ``off:0x5CFD60`` (file offset), ``va:0x1805D0760`` or ``rva:0x5D0760``; a bare number is a
    file offset. The original bytes are read from the file so ``dataDisabled`` is always exact.
    """
    from ..util import parse_hex, parse_int

    data = Path(src).read_bytes()
    pe = parse_pe(data)
    patches: list[Patch] = []
    for loc, new_hex in edits:
        kind, _, num = loc.partition(":") if ":" in loc else ("off", "", loc)
        kind = kind.strip().lower()
        try:
            if kind == "va":
                offset = pe.va_to_offset(parse_hex(num))
            elif kind == "rva":
                offset = pe.rva_to_offset(parse_hex(num))
            elif kind in ("off", "file"):
                offset = parse_int(num)
            else:
                raise PatchFormatError(f"unknown location kind {kind!r} (use off:, va:, rva:)")
        except (ValueError, NotMappedError) as e:
            raise PatchFormatError(f"{loc}: {e}") from e
        new = bytes.fromhex(new_hex.replace(" ", ""))
        if offset + len(new) > len(data):
            raise PatchFormatError(f"{loc}: edit runs past the end of the file")
        patches.append(Patch(offset=offset, dll_name=dll_name, disabled=data[offset : offset + len(new)], enabled=new))
    return Entry(
        name=name, description=description, game_code=game_code, type="memory", patches=patches,
        caution=caution or None, pe_identifier=pe_identifier,
    )  # fmt: skip
