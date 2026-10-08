"""``khx sig``: turn the patches you know for one build into version-independent ``signature`` entries, and test them on other builds.

``make`` takes a patch file of a binary, finds each ``memory`` patch site (and the window a ``union`` covers) in the binary's Ghidra
analysis, builds the smallest unique masked pattern around it (:mod:`kawaiidra_hx.patch.sigmake`, operand masks from
:mod:`kawaiidra_hx.queries.sigmask`) and emits ``signature`` entries. Each one is verified to resolve back to exactly the site it
was made from. ``check`` resolves a signature file against any number of binaries and says where each signature lands (unique,
ambiguous, not found), which is what a signature patch has to survive when the binary is rebuilt.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

from .core.errors import KhxError
from .core.session import ProgramHandle
from .patch import Entry, Patch, PatchFile, load_patchfile, resolve_signature
from .patch.sigmake import SigCandidate, make_signature, signature_entry, verify_signature
from .pe import PEImage
from .queries.sigmask import data_window, instruction_window


@dataclass
class SigRow:
    entry: str  # source entry name
    index: int
    total: int
    offset: int  # file offset of the patched window
    length: int
    kind: str  # code | data
    cand: Optional[SigCandidate] = None
    out: Optional[Entry] = None
    ok: bool = False
    why: str = ""
    src: Optional[Patch] = None  # the source patch (full window: bytes before/after) this signature was made from
    win: list = field(default_factory=list)  # the instruction map the signature was made from (for window ladders)
    src_entry: Optional[Entry] = None
    options: list = field(default_factory=list)  # the UnionOptions when the row is a union window (``src`` is then the window with a representative option applied)

    @property
    def label(self) -> str:
        return self.entry + (f" ({self.index}/{self.total})" if self.total > 1 else "")

    def line(self) -> str:
        c = self.cand
        if c is None:
            return f"  FAIL  {self.label:<46} @0x{self.offset:X}  {self.why}"
        tag = "ok  " if self.ok else "FAIL"
        extra = "" if not c.notes else "   [" + "; ".join(c.notes) + "]"
        return f"  {tag}  {self.label:<46} @0x{self.offset:X} {self.kind}  {c.length:3d} bytes ({c.fixed} fixed, {c.insns} insn)  {c.text[:72]}{'...' if len(c.text) > 72 else ''}{extra}" + ("" if self.ok else f"   <<< {self.why}")


@dataclass
class MakeReport:
    build_id: str
    rows: list[SigRow] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    patchfile: Optional[PatchFile] = None
    data: bytes = b""  # the source binary's file bytes

    @property
    def made(self) -> int:
        return sum(r.ok for r in self.rows)

    def format(self) -> str:
        lines = [f"signatures for {self.build_id}: {self.made}/{len(self.rows)} sites"]
        lines += [r.line() for r in self.rows]
        lines += [f"  skipped: {s}" for s in self.skipped]
        return "\n".join(lines)


def program_build_id(h: ProgramHandle, game_code: str = "PE") -> str:
    """``{code}-{TimeDateStamp:x}_{EntryRVA:x}`` of the program's original file (read from the bytes Ghidra stored)."""
    return original_image(h).identity.pe_identifier(game_code)


def original_image(h: ProgramHandle, binary: Union[str, Path, None] = None) -> PEImage:
    return PEImage(original_bytes(h, binary))


def original_bytes(h: ProgramHandle, binary: Union[str, Path, None] = None) -> bytes:
    """The original file's bytes. ``binary`` if given, else the path Ghidra recorded at import time; either way the sha256 must be the
    program's own, so a signature is never made from a different build than the one that was analysed."""
    want = str(h.program.getExecutableSHA256() or "").lower()
    cands: list[Path] = [Path(binary)] if binary else []
    try:
        raw = str(h.program.getExecutablePath() or "")
        cands.append(Path(raw[1:] if re.match(r"^/[A-Za-z]:", raw) else raw))
    except Exception:
        pass
    for p in cands:
        if p.is_file():
            data = p.read_bytes()
            if not want or hashlib.sha256(data).hexdigest() == want:
                return data
            if binary:
                raise KhxError(f"{p} is not the file {h.name} was imported from (sha256 differs)")
    raise KhxError(f"cannot find the original bytes of {h.name}: pass --binary FILE (the file it was imported from)")


def union_window(data: bytes, e: Entry) -> Optional[Patch]:
    """A ``union`` as one patch window: the bytes its options cover, with the first option that changes anything applied (the representative edit)."""
    if not e.options:
        return None
    lo = min(o.offset for o in e.options)
    hi = max(o.offset + o.length for o in e.options)
    if hi > len(data):
        return None
    orig = data[lo:hi]
    for o in e.options:
        enabled = bytearray(orig)
        enabled[o.offset - lo : o.offset - lo + o.length] = o.data
        if bytes(enabled) != orig:
            return Patch(offset=lo, dll_name=o.dll_name or "", disabled=orig, enabled=bytes(enabled))
    return None


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_") or "x"


def _group_id(name: str) -> str:
    return "g_" + _slug(name)


def make_signatures(
    h: ProgramHandle,
    patch_files: Union[PatchFile, str, Path, Iterable[Union[PatchFile, str, Path]]],
    *,
    binary: Union[str, Path, None] = None,
    only: str | None = None,
    max_bytes: int = 48,
    min_fixed: int = 12,
    allow_usage: bool = True,
    game_code: str | None = None,
) -> MakeReport:
    """Signature entries for the memory patches (and union windows) of ``patch_files`` in the analysed program ``h``."""
    if isinstance(patch_files, (PatchFile, str, Path)):
        patch_files = [patch_files]
    files = [pf if isinstance(pf, PatchFile) else load_patchfile(pf) for pf in patch_files]
    data = original_bytes(h, binary)
    image = PEImage(data)
    code = game_code or next((pf.game_code for pf in files if pf.game_code), None) or "PE"
    build_id = image.identity.pe_identifier(code)
    own = build_id.split("-", 1)[1]
    reloc = image.relocated_offsets()
    rep = MakeReport(build_id, data=data)
    out_entries: list[Entry] = []
    seen: set[tuple[str, int]] = set()
    for pf in files:
        for e in pf.entries:
            if only and only.casefold() not in e.name.casefold():
                continue
            if e.pe_identifier and e.pe_identifier.split("-", 1)[-1] != own:
                rep.skipped.append(f"{e.name}: entry is for {e.pe_identifier}")
                continue
            if e.type == "group":
                continue
            if e.type not in ("memory", "union"):
                rep.skipped.append(f"{e.name}: {e.type} entries have no single byte site to sign")
                continue
            union = e.type == "union"  # located like a memory patch, but a signature entry cannot hold options (`khx patch port` carries them)
            if union:
                window = union_window(data, e)
                if window is None:
                    rep.skipped.append(f"{e.name}: union options do not change anything in this binary (or fall outside the file)")
                    continue
            sites = [(1, window)] if union else list(enumerate(e.patches, 1))
            members: list[Entry] = []
            for k, p in sites:
                if (e.name, p.offset) in seen:
                    continue
                seen.add((e.name, p.offset))
                site = (p.offset, p.offset + p.length)
                win = instruction_window(h, site[0], site[1], extra_volatile=reloc)
                kind = "code"
                if win is None:
                    win = data_window(data, site[0], site[1], extra_volatile=reloc)
                    kind = "data"
                row = SigRow(e.name, k, len(sites), p.offset, p.length, kind, src=p, src_entry=e, win=win, options=list(e.options) if union else [])
                rep.rows.append(row)
                row.cand = make_signature(data, win, site[0], site[1], max_bytes=max_bytes, min_fixed=min_fixed, allow_usage=allow_usage)
                if row.cand is None:
                    row.why = "site is not inside the disassembled/instruction window"
                    continue
                if not row.cand.usable:
                    row.why = row.cand.notes[0] if row.cand.notes else "no unique window"
                    continue
                if p.disabled == p.enabled:
                    row.why = "dataEnabled equals dataDisabled"
                    continue
                caution = None
                if row.cand.ambiguous_of > 1:
                    caution = f"Ambiguous signature: uses occurrence #{row.cand.usage} of {row.cand.ambiguous_of}; verify after every update"
                row.out = signature_entry(
                    row.cand, p.disabled, p.enabled, name=row.label,
                    description=e.description or "", game_code=e.game_code or code, dll_name=p.dll_name, caution=caution,
                )  # fmt: skip
                ok, why = verify_signature(data, row.out, p.offset, p.disabled, p.enabled, allow_ambiguous=row.cand.ambiguous_of > 1)
                row.ok, row.why = ok, ("" if ok else why)
                if ok and not union:
                    members.append(row.out)
            if len(e.patches) > 1 and members:
                gid = _group_id(e.name)
                out_entries.append(
                    Entry(name=e.name, description=f"{len(e.patches)} signature entries (toggle them together). " + (e.description or ""), game_code=e.game_code or code, type="group", id=gid)
                )
                for m in members:
                    m.group = gid
            out_entries += members
    header = {"gameCode": code, "version": f"signatures made from {build_id}", "source": "khx sig make"}
    rep.patchfile = PatchFile(entries=out_entries, headers=[header])
    return rep


# --- check ----------------------------------------------------------------------------------------


@dataclass
class CheckRow:
    entry: str
    binary: str
    state: str  # unique | applied (already patched) | ambiguous | not_found | no_such_usage
    matches: int
    offset: Optional[int] = None
    va: Optional[int] = None

    def line(self) -> str:
        where = f"0x{self.offset:X} (VA 0x{self.va:X})" if self.offset is not None and self.va is not None else "-"
        return f"  {self.entry:<44} {self.binary:<28} {self.state:<13} {self.matches:>3}x  {where}"


@dataclass
class CheckReport:
    rows: list[CheckRow] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.rows:
            out[r.state] = out.get(r.state, 0) + 1
        return out

    @property
    def ok(self) -> bool:
        return bool(self.rows) and all(r.state in ("unique", "applied") for r in self.rows)

    def format(self) -> str:
        lines = [f"  {'signature':<44} {'binary':<28} {'result':<13} {'n':>4}  lands at"]
        lines += [r.line() for r in self.rows]
        lines += [f"note: {n}" for n in self.notes]
        lines.append("summary: " + ", ".join(f"{v} {k}" for k, v in sorted(self.summary().items())))
        return "\n".join(lines)


def check_signatures(pf: PatchFile, binaries: Iterable[Union[str, Path]]) -> CheckReport:
    """Resolve every ``signature`` entry of ``pf`` in each binary."""
    rep = CheckReport()
    sigs = [e for e in pf.entries if e.type == "signature" and e.signature]
    if not sigs:
        rep.notes.append("no signature entries in the file")
    for path in binaries:
        p = Path(path)
        if not p.is_file():
            rep.notes.append(f"{p}: not a readable file; skipped")
            continue
        img = PEImage(p)
        for e in sigs:
            res = resolve_signature(img.data, e.signature)  # type: ignore[arg-type]
            if res.state == "no_such_usage":
                state, n = "no_such_usage", res.matches
            elif res.state == "applied":  # the file already holds the patched bytes: count the patched pattern
                state, n = "applied", res.patched_matches
            else:
                n = res.matches
                state = "unique" if n == 1 else "ambiguous" if n > 1 else "not_found"
            row = CheckRow(e.name, p.name, state, n)
            if res.offset is not None:
                row.offset = res.offset
                try:
                    row.va = img.info.offset_to_va(res.offset)
                except Exception:
                    row.va = None
            rep.rows.append(row)
    return rep
