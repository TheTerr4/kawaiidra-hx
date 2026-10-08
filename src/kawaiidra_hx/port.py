"""``khx port``: carry a binary's known patches over to another build of it (typically the next update) by signature.

For every memory patch site of build A: take its signature (made in Ghidra from A, see :mod:`kawaiidra_hx.sigs`), look for it in the
bytes of build B, and rebuild the whole patch window from B's own bytes: ``dataDisabled`` is what B contains there, ``dataEnabled`` is the
same window with A's edits applied at the positions A changed. Nothing is guessed:

* a site counts as ported only if its signature is unique in B (or, for signatures that were ambiguous in A, matches as often as it did);
* a multi-site entry is emitted only if *every* site was found (half-applying a patch can break the program);
* everything else is listed with the reason. B needs no Ghidra project at all, *unless* the semantic-anchor tier is switched on (``anchors=``, see
  :mod:`kawaiidra_hx.match.anchors`): then a site no signature, window or string holds is looked for by matching the function around it between the
  builds and mapping the instruction inside it, which needs both builds analysed once (fingerprints are cached).

The tiers, in order: the signature made in A; windows leaning other ways around the same site (each unique in both builds, enough of them agreeing);
the string a data patch edits; the semantic anchors. Signatures first and function matching last because a silent wrong match is worse than a clear
"not found": signatures hold between adjacent builds (same compiler, moved offsets), and the order-aware alignment makes function matching good enough
within a generation to serve as the last tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .match.anchors import AnchorContext
from .patch import Entry, Patch, PatchFile, UnionOption, count_matches, iter_matches, resolve_signature, verify
from .patch.sigmake import window_ladder
from .pe import PEImage
from .sigs import MakeReport, SigRow


@dataclass
class PortedSite:
    row: SigRow
    status: str  # ported | ambiguous | not_found | failed
    why: str = ""
    patch: Optional[Patch] = None  # the patch for B
    how: str = ""  # signature | window ladder (k windows agree) | string anchor | anchor
    options: list = field(default_factory=list)  # union rows: the options rebuilt for B
    option_notes: list[str] = field(default_factory=list)  # union rows: notes about the carried options

    @property
    def ok(self) -> bool:
        return self.status == "ported"


@dataclass
class PortedEntry:
    name: str
    sites: list[PortedSite] = field(default_factory=list)
    entry: Optional[Entry] = None

    @property
    def status(self) -> str:
        n_ok = sum(s.ok for s in self.sites)
        return "ported" if n_ok == len(self.sites) and self.sites else ("partial" if n_ok else "failed")


@dataclass
class PortReport:
    from_id: str
    to_id: str
    entries: list[PortedEntry] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    patchfile: Optional[PatchFile] = None
    verified: bool = False

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {"ported": 0, "partial": 0, "failed": 0}
        for e in self.entries:
            out[e.status] += 1
        return out

    def format(self) -> str:
        c = self.counts()
        lines = [
            f"port {self.from_id} -> {self.to_id}: {c['ported']} entries ported, {c['partial']} partial (not emitted), {c['failed']} not found",
        ]
        for e in self.entries:
            icon = {"ported": "ok     ", "partial": "PARTIAL", "failed": "FAILED "}[e.status]
            lines.append(f"  {icon} {e.name}")
            for s in e.sites:
                if s.ok and s.patch is not None:
                    lines.append(f"            #{s.row.index}/{s.row.total} -> file 0x{s.patch.offset:X}  {s.patch.disabled.hex().upper()[:24]} -> {s.patch.enabled.hex().upper()[:24]}  via {s.how}")
                    if s.options:
                        lines.append(f"            union window of {s.patch.length} bytes, {len(s.options)} of {len(s.row.options)} options carried: " + ", ".join(o.name for o in s.options))
                    lines += [f"              note: {n}" for n in s.option_notes]
                else:
                    lines.append(f"            #{s.row.index}/{s.row.total} {s.status}: {s.why}")
        lines += [f"  skipped: {s}" for s in self.skipped]
        if self.patchfile is not None:
            n = len(self.patchfile.entries)
            unions = sum(e.type == "union" for e in self.patchfile.entries)
            kinds = f" ({n - unions} memory, {unions} union)" if unions else " (memory)"
            lines.append(f"emitted {n} entr{'y' if n == 1 else 'ies'}{kinds}; verify against the target: {'OK' if self.verified else 'FAILED'}")
        return "\n".join(lines)


def branch_direction(buf: bytes) -> int | None:
    """+1 / -1 when ``buf`` starts with a relative jump (jcc/jmp, short or near) that goes forward / backward, else ``None``."""
    if len(buf) >= 2 and (0x70 <= buf[0] <= 0x7F or buf[0] == 0xEB):
        return -1 if buf[1] >= 0x80 else 1
    if len(buf) >= 6 and buf[0] == 0x0F and 0x80 <= buf[1] <= 0x8F:
        return -1 if buf[5] >= 0x80 else 1
    if len(buf) >= 5 and buf[0] == 0xE9:
        return -1 if buf[4] >= 0x80 else 1
    return None


def _edit_start(src: Patch) -> int:
    return next((i for i, (d, e) in enumerate(zip(src.disabled, src.enabled)) if d != e), 0)


COPY_MIN = 3  # bytes; a shorter run that also occurs in the original window is chance, not a copied operand


def carry_copies(disabled: bytes, enabled: bytes, target: bytes) -> bytes:
    """The enabled bytes for ``target`` (the target build's bytes at the patch window) given the source's ``disabled`` -> ``enabled``.

    A byte the edit leaves alone comes from the target. A byte the edit writes comes from the source's ``enabled`` *unless* it is a copy of
    bytes of the original window shown at another position (a rewritten instruction that keeps the original operand: ``mov eax,[ebx+0xa78]`` ->
    ``mov [ebx+0xa78],eax``): that operand is a build-specific value (a struct offset), so it is taken from the target's own bytes.
    Runs shorter than ``COPY_MIN`` or without two distinct byte values are not treated as copies."""
    n = len(enabled)
    out = bytearray(t if e == d else e for d, e, t in zip(disabled, enabled, target))
    i = 0
    while i < n and n <= 256:  # (tables and long strings are data: nothing is "re-encoded" there)
        if enabled[i] == disabled[i]:
            i += 1
            continue
        best_k, best_j = 0, -1
        for j in range(n):
            if j == i:
                continue
            k = 0
            while i + k < n and j + k < n and enabled[i + k] == disabled[j + k] and enabled[i + k] != disabled[i + k]:
                k += 1
            if k > best_k:
                best_k, best_j = k, j
        if best_k >= COPY_MIN and len(set(enabled[i : i + best_k])) >= 2:
            out[i : i + best_k] = target[best_j : best_j + best_k]
            i += best_k
        else:
            i += 1
    return bytes(out)


def _build_patch(row: SigRow, b: bytes, site_b: int, how: str, a_data: bytes = b"") -> PortedSite:
    src = row.src
    assert src is not None
    end = site_b + src.length
    if site_b < 0 or end > len(b):
        return PortedSite(row, "failed", "window falls outside the target file")
    dis = b[site_b:end]
    # An edit on a jump must land on a jump that goes the same way: turning the loop-closing `jnz` of another idiom into `jmp` hangs the program.
    # Windows are often just the opcode byte (`75` -> `EB`), so the displacement is read from the files, past the window.
    p = _edit_start(src)
    sd = branch_direction(a_data[src.offset + p : src.offset + p + 6]) if a_data else branch_direction(src.disabled[p:])
    td = branch_direction(b[site_b + p : site_b + p + 6])
    if sd is not None and td is not None and sd != td:
        return PortedSite(row, "failed", f"the edited jump goes {'forward' if sd > 0 else 'backward'} in the source and {'forward' if td > 0 else 'backward'} at 0x{site_b:X} in the target")
    en = carry_copies(src.disabled, src.enabled, dis)
    if en == dis:
        return PortedSite(row, "failed", "the edit would not change the target's bytes")
    return PortedSite(row, "ported", patch=Patch(offset=site_b, dll_name=src.dll_name, disabled=dis, enabled=en), how=how)


def string_anchor(a_data: bytes, src: Patch, min_run: int = 8) -> tuple[bytes, int] | None:
    """The NUL-delimited printable string around a data patch: ``(NUL + string + NUL, offset of the patch inside it)``.

    String literals are what many data patches edit (a menu label, a format string, a file name with one letter changed). The neighbouring
    strings change from build to build, so any window that reaches into them breaks, while the string itself, bounded by its terminators, survives
    and is unique. ``None`` when the site is not inside one plain ASCII string of at least ``min_run`` characters.
    """
    d, off = src.disabled, src.offset
    end = off + len(d)
    core_lo = off + (len(d) - len(d.lstrip(b"\0")))  # the site may carry the terminators itself (`\0NAME: %s\0`)
    core_hi = end - (len(d) - len(d.rstrip(b"\0")))
    if core_hi <= core_lo or b"\0" in a_data[core_lo:core_hi]:
        return None
    lo, hi = core_lo, core_hi
    while lo > 0 and a_data[lo - 1] != 0:
        lo -= 1
    while hi < len(a_data) and a_data[hi] != 0:
        hi += 1
    if lo == 0 or hi >= len(a_data) or hi - lo < min_run or not all(0x20 <= c < 0x7F for c in a_data[lo:hi]):
        return None
    return a_data[lo - 1 : hi + 1], off - (lo - 1)


def _port_row(row: SigRow, b: bytes, a_data: bytes, *, min_info: int = 12, use_ladder: bool = True, min_agree: int = 3, min_side: int = 0, min_string: int = 8, anchors: Optional[AnchorContext] = None) -> PortedSite:
    assert row.out is not None and row.out.signature is not None and row.cand is not None and row.src is not None
    spec, cand, src = row.out.signature, row.cand, row.src

    # 1. the signature made in the source build
    res = resolve_signature(b, spec)
    if res.state not in ("not_found", "no_such_usage") and res.match_offset is not None:
        if cand.ambiguous_of > 1:
            if res.matches == cand.ambiguous_of:
                return _build_patch(row, b, res.match_offset + cand.site_offset, "signature (ambiguous in the source, same count)", a_data)
            return PortedSite(row, "ambiguous", f"signature was ambiguous in the source ({cand.ambiguous_of} occurrences, usage {spec.usage}) and now has {res.matches}")
        if res.matches == 1:
            return _build_patch(row, b, res.match_offset + cand.site_offset, "signature", a_data)
        first_why = f"signature matches {res.matches} places in the target"
    else:
        first_why = "signature does not occur in the target"

    # 2. windows leaning other ways around the same site: each must be unique in BOTH builds, and all that match must agree
    failed: Optional[PortedSite] = None
    if use_ladder and row.win:
        hits: dict[int, int] = {}
        two_sided: dict[int, int] = {}  # per location: the most informative bytes an agreeing window holds on its *poorer* side of the site
        for c in window_ladder(a_data, row.win, src.offset, src.offset + src.length, min_info=min_info):
            if count_matches(b, c.pattern, c.mask, limit=2) == 1:
                m = next(iter_matches(b, c.pattern, c.mask))
                at = m + c.site_offset
                hits[at] = hits.get(at, 0) + 1
                left = sum(1 for x in c.mask[: c.site_offset] if x)
                right = sum(1 for x in c.mask[c.site_offset + src.length :] if x)
                two_sided[at] = max(two_sided.get(at, 0), min(left, right))
        if len(hits) == 1:
            (site_b, k), = hits.items()
            if k < min_agree:  # a ladder backed by only one or two windows is weak evidence
                failed = PortedSite(row, "not_found", f"{first_why}; one window around the site finds it at 0x{site_b:X}, but {k} < {min_agree} windows agree (--min-agree)")
            elif two_sided[site_b] < min_side:  # nested windows that all lean the same way are one piece of evidence, not k: the code on the other side may be unrelated
                failed = PortedSite(row, "not_found", f"{first_why}; the windows that find it at 0x{site_b:X} all lean on one side of the site (no window has {min_side}+ informative bytes on both sides; --min-side)")
            else:
                return _build_patch(row, b, site_b, f"window ladder ({k} windows agree)", a_data)
        elif len(hits) > 1:
            where = ", ".join(f"0x{x:X} ({n}x)" for x, n in sorted(hits.items()))
            failed = PortedSite(row, "ambiguous", f"windows around the site disagree about where it is in the target: {where}")
    if failed is None:
        failed = PortedSite(row, "ambiguous" if "places" in first_why else "not_found", first_why + (" (and no other window around the site is unique in both builds)" if use_ladder else ""))

    # 3. data sites inside a string literal: the whole string, bounded by its terminators, when it is unique in both builds
    if min_string and row.kind == "data":
        found = string_anchor(a_data, src, min_string)
        if found is not None:
            pat, rel = found
            if a_data.count(pat) == 1 and b.count(pat) == 1:
                text = pat.strip(b"\0").decode("ascii")[:24]
                return _build_patch(row, b, b.find(pat) + rel, f"string anchor ({text!r})", a_data)

    # 4. semantic anchors: the function holding the site is matched between the builds, then the instruction inside it
    if anchors is not None and row.kind == "code":
        return _by_anchor(row, b, a_data, anchors, failed)
    if anchors is not None and row.kind == "data":  # (data is only ever hinted at: the code that reads it is where the target has to be looked at)
        hint = anchors.string_users(src.offset, src.length).why
        if hint.startswith("the string"):
            return PortedSite(failed.row, failed.status, f"{failed.why}; anchor: {hint}")
    return failed


def _by_anchor(row: SigRow, b: bytes, a_data: bytes, anchors: AnchorContext, failed: PortedSite) -> PortedSite:
    """The semantic-anchor tier: the site ported through the function and instruction alignment, else ``failed`` with the anchors' reason added."""
    src = row.src
    assert src is not None
    found_at = anchors.locate(src.offset, src.length)
    if found_at.offset is not None:
        return _build_patch(row, b, found_at.offset, f"anchor ({found_at.why})", a_data)
    return PortedSite(failed.row, failed.status, f"{failed.why}; anchor: {found_at.why}")


def carry_options(site: PortedSite, row: SigRow, b: bytes) -> PortedSite:
    """Rebuild a union's options for the target window the signature found (``site.patch``): the option that leaves the build alone gets the
    target's own bytes, every other option its edits applied over the target's bytes (never over the source's)."""
    src, at = row.src, site.patch.offset
    assert src is not None
    tgt = b[at : at + src.length]
    carried: list[UnionOption] = []
    for o in row.options:
        rel = o.offset - src.offset
        original = src.disabled[rel : rel + o.length]
        if o.data == original:
            data = tgt[rel : rel + o.length]
        else:
            full = bytearray(tgt)
            for i, byte in enumerate(o.data):
                if byte != original[i]:
                    full[rel + i] = byte
            data = bytes(full[rel : rel + o.length])
        carried.append(UnionOption(name=o.name, offset=at + rel, data=data, dll_name=o.dll_name))
    site.options = carried
    if any(c.data != tgt[c.offset - at : c.offset - at + len(c.data)] for c in carried):
        site.option_notes.append("option bytes were rebuilt from the target's own; check them against the target before use")
    else:
        site.status, site.why = "failed", "no option that changes anything could be carried"
    return site


def port_build(
    made: MakeReport,
    target: PEImage | bytes,
    to_id: str,
    *,
    game_code: str = "PE",
    min_info: int = 12,
    use_ladder: bool = True,
    min_agree: int = 3,
    min_side: int = 0,
    min_string: int = 8,
    allow_partial: bool = False,
    anchors: Optional[AnchorContext] = None,
) -> PortReport:
    """Port the signatures in ``made`` (a :class:`~kawaiidra_hx.sigs.MakeReport` for build A) onto ``target`` (build B's file)."""
    b = target.data if isinstance(target, PEImage) else bytes(target)
    rep = PortReport(from_id=made.build_id, to_id=to_id, skipped=list(made.skipped))
    by_entry: dict[str, PortedEntry] = {}
    for row in made.rows:
        pe = by_entry.setdefault(row.entry, PortedEntry(row.entry))
        if not row.ok or row.out is None:
            site = PortedSite(row, "failed", f"no signature could be made in the source build: {row.why}")
            # the anchors do not need a signature: a site whose bytes are not unique in the source can still be placed by what the code around it is
            if anchors is not None and row.kind == "code" and row.src is not None:
                site = _by_anchor(row, b, made.data, anchors, site)
                if site.ok and row.options:
                    site = carry_options(site, row, b)
            pe.sites.append(site)
            continue
        site = _port_row(row, b, made.data, min_info=min_info, use_ladder=use_ladder, min_agree=min_agree, min_side=min_side, min_string=min_string, anchors=anchors)
        if site.ok and row.options:
            site = carry_options(site, row, b)
        pe.sites.append(site)
    out_entries: list[Entry] = []
    for name, pe in by_entry.items():
        rep.entries.append(pe)
        if pe.status == "failed" or (pe.status == "partial" and not allow_partial):
            continue
        src = pe.sites[0].row.src_entry
        assert src is not None
        got = [s.patch for s in pe.sites if s.patch is not None]
        caution = src.caution
        if pe.status == "partial":  # only with allow_partial: say so, so nobody mistakes it for the whole patch
            warn = f"PARTIAL PORT: {len(got)} of {len(pe.sites)} sites were found in this build; the rest are missing"
            caution = f"{warn}. {caution}" if caution else warn
        if src.type == "union":
            notes = [n for s_ in pe.sites for n in s_.option_notes]
            if notes:
                caution = "Options not checked or not carried: " + "; ".join(notes) + (". " + caution if caution else "")
            pe.entry = Entry(
                name=name, description=src.description, game_code=src.game_code or game_code, type="union",
                options=[o for s_ in pe.sites for o in s_.options], caution=caution, pe_identifier=to_id,
            )  # fmt: skip
        else:
            pe.entry = Entry(
                name=name, description=src.description, game_code=src.game_code or game_code, type="memory",
                patches=got, caution=caution, pe_identifier=to_id,
            )  # fmt: skip
        out_entries.append(pe.entry)
    rep.patchfile = PatchFile(
        entries=out_entries,
        headers=[{"gameCode": game_code, "version": f"ported from {made.build_id}", "source": "khx port (signature carry-over; verify before use)"}],
    )
    rep.verified = verify(b, out_entries, expected_id=to_id).ok
    return rep
