"""Patch sites in Ghidra: turn the file offsets of a patch file into labels, bookmarks and comments on the program.

A patch file is a list of places where somebody already worked out what the code does ("Force option X", "Skip the check"). Pushing those file
offsets into the Ghidra database makes that knowledge visible in the listing and searchable (Bookmarks window, category ``khx-patch``), so a
fresh build can be oriented around known behaviour in seconds.

Safety: a site is only annotated when the bytes in the program match what the patch file expects (original, applied, or one union option).
Functions are never renamed. Everything is tagged (``[khx-patch:...]`` comment lines, ``patch_*`` labels, ``khx-patch`` bookmarks) so it can be
re-run (idempotent) and removed with :func:`clear_program`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

from . import annotate
from .core.errors import AddressError, KhxError
from .core.resolve import parse_address
from .core.session import ProgramHandle
from .patch import Entry, PatchFile, load_patchfile, resolve_signature
from .pe import parse_pe
from .queries.code import _fn_label, _function_containing
from .queries.data import fetch_bytes

TAG = "[khx-patch:"
BOOKMARK_CATEGORY = "khx-patch"
LABEL_PREFIX = "patch_"


def slugify(name: str, limit: int = 56) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")
    return (s or "patch")[:limit].rstrip("_")


@dataclass
class Site:
    entry: str
    kind: str  # memory | union | number | signature
    offset: int  # file offset
    length: int
    variants: dict[str, bytes] = field(default_factory=dict)  # state name -> expected bytes ("original"/"applied" or union option)
    index: int = 1  # which patch of the entry (1-based)
    total: int = 1
    build_id: str = ""
    source: str = ""  # the patch file's name
    number: tuple[int, int, int] | None = None  # (size, min, max)

    @property
    def slug(self) -> str:
        return slugify(self.entry) + (f"_{self.index}" if self.total > 1 else "")

    @property
    def tag(self) -> str:
        return f"{TAG}{self.slug}]"

    @property
    def label(self) -> str:
        return LABEL_PREFIX + self.slug


def _cut(b: bytes, limit: int = 32) -> str:
    h = b.hex().upper()
    return h if len(h) <= limit else h[:limit] + ".."


def sites_from_entry(e: Entry, *, build_id: str, source: str, file_bytes: bytes | None = None) -> tuple[list[Site], list[str]]:
    notes: list[str] = []
    out: list[Site] = []
    if e.type == "memory":
        for i, p in enumerate(e.patches, 1):
            out.append(Site(e.name, "memory", p.offset, p.length, {"original": p.disabled, "applied": p.enabled}, i, len(e.patches), build_id, source))
    elif e.type == "union" and e.options:
        lo = min(o.offset for o in e.options)
        hi = max(o.offset + o.length for o in e.options)
        out.append(Site(e.name, "union", lo, hi - lo, {o.name: o.data for o in e.options}, 1, 1, build_id, source))
    elif e.type == "number" and e.number:
        n = e.number
        out.append(Site(e.name, "number", n.offset, n.size, {}, 1, 1, build_id, source, number=(n.size, n.min, n.max)))
    elif e.type == "signature" and e.signature:
        if file_bytes is None:
            notes.append(f"{e.name}: signature entry skipped (needs the file bytes to resolve; pass the binary the program was imported from)")
        else:
            res = resolve_signature(file_bytes, e.signature)
            if res.ok and res.offset is not None and res.disabled is not None and res.enabled is not None:
                out.append(Site(e.name, "signature", res.offset, len(res.enabled), {"original": res.disabled, "applied": res.enabled}, 1, 1, build_id, source))
            else:
                notes.append(f"{e.name}: signature did not resolve ({res.state})")
    return out, notes


def collect_sites(
    files: Iterable[tuple[str, PatchFile]], build_id: str, file_bytes: bytes | None = None, only: str | None = None
) -> tuple[list[Site], list[str]]:
    sites: list[Site] = []
    notes: list[str] = []
    seen: set[tuple[str, int]] = set()
    own = build_id.split("-", 1)[-1]
    for source, pf in files:
        for e in pf.entries:
            if only and only.casefold() not in e.name.casefold():
                continue
            if e.pe_identifier and e.pe_identifier.split("-", 1)[-1] != own:
                notes.append(f"{e.name}: entry is for {e.pe_identifier}, not {build_id}; skipped")
                continue
            ss, nn = sites_from_entry(e, build_id=build_id, source=source, file_bytes=file_bytes)
            notes += nn
            for s in ss:
                if (s.entry, s.offset) in seen:
                    continue
                seen.add((s.entry, s.offset))
                sites.append(s)
    return sites, notes


# --- program side ---------------------------------------------------------------------------------


def program_build_id(h: ProgramHandle, game_code: str = "PE") -> str:
    """The build id of a Ghidra program, read from the PE headers Ghidra maps at the image base."""
    with h.lock:
        mem = h.program.getMemory()
        base = h.program.getImageBase()
        block = mem.getBlock(base)
        if block is None:
            raise KhxError(f"{h.name}: no memory block at the image base {base}; cannot read the PE headers")
        data = fetch_bytes(h, base, min(int(block.getSize()), 0x1000))
    try:
        return parse_pe(data).pe_identifier(game_code)
    except Exception as e:
        raise KhxError(f"{h.name}: PE headers at {base} could not be parsed ({e})") from e


@dataclass
class ProgramSite:
    site: Site
    address: Optional[str] = None  # Ghidra address text
    va: Optional[int] = None
    function: Optional[str] = None
    state: str = "unmapped"  # original | applied | <union option> | value=N | mismatch | unmapped
    actual: bytes = b""

    @property
    def ok(self) -> bool:
        return self.state not in ("mismatch", "unmapped")


def _state(site: Site, actual: bytes) -> str:
    if site.kind == "number" and site.number:
        size, lo, hi = site.number
        v = int.from_bytes(actual[:size], "little", signed=lo < 0)
        return f"value={v}" if lo <= v <= hi else "mismatch"
    names = [n for n, data in site.variants.items() if actual[: len(data)] == data and len(actual) >= len(data)]
    return " | ".join(names) if names else "mismatch"


def resolve_sites(h: ProgramHandle, sites: list[Site]) -> list[ProgramSite]:
    out: list[ProgramSite] = []
    with h.lock:
        for s in sites:
            ps = ProgramSite(s)
            try:
                addr = parse_address(h, f"off:{s.offset}")
            except AddressError:
                out.append(ps)
                continue
            ps.address = str(addr)
            ps.va = int(addr.getOffset())
            ps.actual = fetch_bytes(h, addr, s.length)
            ps.state = _state(s, ps.actual) if len(ps.actual) == s.length else "mismatch"
            fn = _function_containing(h, addr)
            ps.function = _fn_label(fn) if fn is not None else None
            out.append(ps)
    return out


def _describe(ps: ProgramSite) -> str:
    s = ps.site
    if s.kind in ("memory", "signature"):
        return f"{_cut(s.variants['original'])} -> {_cut(s.variants['applied'])}"
    if s.kind == "union":
        return "options: " + " | ".join(s.variants)
    if s.number:
        return f"{s.number[0]}-byte value {s.number[1]}..{s.number[2]}"
    return ""


def format_sites(rows: list[ProgramSite], notes: list[str] | None = None) -> str:
    lines = [f"{'VA':<14}{'file off':<10}{'state':<22}{'entry':<44}function"]
    for ps in sorted(rows, key=lambda r: r.site.offset):
        s = ps.site
        va = f"0x{ps.va:X}" if ps.va is not None else "-"
        label = s.entry + (f" #{s.index}/{s.total}" if s.total > 1 else "")
        lines.append(f"{va:<14}0x{s.offset:<8X}{ps.state[:20]:<22}{label[:42]:<44}{ps.function or '-'}  [{_describe(ps)}]")
    ok = sum(r.ok for r in rows)
    lines.append("")
    lines.append(f"{len(rows)} site(s): {ok} consistent with the program, {len(rows) - ok} mismatched/unmapped")
    lines += [f"note: {n}" for n in notes or []]
    return "\n".join(lines)


@dataclass
class SitesReport:
    build_id: str
    sites: int = 0
    annotated: int = 0
    skipped: list[str] = field(default_factory=list)
    functions: int = 0
    labels: int = 0
    labels_skipped: int = 0  # sites on function entries: no label (it would rename the function)
    dry_run: bool = False

    def format(self) -> str:
        verb = "would annotate" if self.dry_run else "annotated"
        lines = [f"{verb} {self.annotated}/{self.sites} patch site(s) of {self.build_id} in {self.functions} function(s)"]
        if not self.dry_run:
            lines.append(f"  labels: {self.labels} created, {self.labels_skipped} skipped on function entries (bookmark + comment still set)")
        lines += [f"  skipped: {s}" for s in self.skipped]
        if not self.dry_run and self.annotated:
            lines.append("  (changes are in memory: save the program to keep them)")
        return "\n".join(lines)


def _file_bytes(h: ProgramHandle, binary: Union[str, Path, None]) -> bytes | None:
    from .sigs import original_bytes

    try:
        return original_bytes(h, binary)
    except KhxError:
        return None


def build_context(
    h: ProgramHandle,
    patch_files: Union[PatchFile, str, Path, Iterable[Union[PatchFile, str, Path]]],
    *,
    binary: Union[str, Path, None] = None,
    only: str | None = None,
    game_code: str | None = None,
):
    if isinstance(patch_files, (PatchFile, str, Path)):
        patch_files = [patch_files]
    files = [(getattr(pf, "path", None) and Path(pf.path).name or "patch file", pf) if isinstance(pf, PatchFile) else (Path(pf).name, load_patchfile(pf)) for pf in patch_files]
    if not files:
        raise KhxError("no patch files given")
    code = game_code or next((pf.game_code for _, pf in files if pf.game_code), None) or "PE"
    build_id = program_build_id(h, code)
    sites, notes = collect_sites(files, build_id, _file_bytes(h, binary), only)
    return build_id, sites, notes


def annotate_program(
    h: ProgramHandle,
    patch_files,
    *,
    binary: Union[str, Path, None] = None,
    only: str | None = None,
    force: bool = False,
    dry_run: bool = False,
    game_code: str | None = None,
) -> SitesReport:
    """Label/bookmark/comment every patch site. Needs a write-mode handle unless ``dry_run``."""
    build_id, sites, notes = build_context(h, patch_files, binary=binary, only=only, game_code=game_code)
    rows = resolve_sites(h, sites)
    rep = SitesReport(build_id=build_id, sites=len(rows), dry_run=dry_run, skipped=list(notes))
    per_function: dict[str, list[str]] = {}
    for ps in rows:
        s = ps.site
        if ps.state == "unmapped":
            rep.skipped.append(f"{s.entry} @ file 0x{s.offset:X}: not backed by this program's memory")
            continue
        if ps.state == "mismatch" and not force:
            rep.skipped.append(f"{s.entry} @ 0x{ps.va:X}: bytes {_cut(ps.actual)} match neither the original nor the patched form (wrong build? use --force)")
            continue
        rep.annotated += 1
        assert ps.address is not None
        if ps.function:
            per_function.setdefault(ps.function, []).append(s.entry)
        if dry_run:
            continue
        where = f"va:0x{ps.va:X}"
        note = f"{s.entry}" + (f" #{s.index}/{s.total}" if s.total > 1 else "")
        made = annotate.add_label(h, where, s.label)
        if " skipped " in made:
            rep.labels_skipped += 1
        else:
            rep.labels += 1
        annotate.add_bookmark(h, where, BOOKMARK_CATEGORY, f"{note}: {_describe(ps)} (now {ps.state})")
        annotate.set_tagged_comment(h, where, s.tag, f"{note}: {_describe(ps)} [{build_id}, {s.source}] now={ps.state}", "eol")
    rep.functions = len(per_function)
    if not dry_run:
        for fn_label, names in per_function.items():
            entry_addr = fn_label.split("@", 1)[1]
            uniq = sorted(set(names))
            annotate.set_tagged_comment(h, f"0x{entry_addr}", f"{TAG}fn]", f"patch site(s) in this function: {', '.join(uniq)}", "plate", snap_to_unit=False)
    return rep


def clear_program(h: ProgramHandle) -> dict[str, int]:
    return annotate.clear_tagged(h, TAG, bookmark_category=BOOKMARK_CATEGORY, label_prefix=LABEL_PREFIX)
