"""`khx port`: carry a build's patches to another build by signature. Synthetic builds; Ghidra is needed for the source build only."""

from __future__ import annotations

import json
import os

import pytest

from kawaiidra_hx import port as portmod
from kawaiidra_hx import sigs
from kawaiidra_hx.patch import Patch, UnionOption, format_masked, verify
from kawaiidra_hx.patch.sigmake import SigCandidate, signature_entry
from kawaiidra_hx.pe import PEImage
from kawaiidra_hx.port import string_anchor

from .synth import FUNC, JZ, PE_ID, doc_two_sites, tiny_body, union_doc, write_pe


def _import_source(tmp_path, doc: list[dict]):
    """Tiny build A imported into Ghidra (analysed), its patch file written as ``doc``; yields the `MakeReport`, then closes the project."""
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR not set")
    from kawaiidra_hx.core import get_session
    from kawaiidra_hx.core.jobs import import_program

    patches = tmp_path / "patches.json"
    patches.write_text(json.dumps(doc))
    dll = write_pe(tmp_path / "a.dll", 0x1000, tiny_body())
    session = get_session()
    proj = str(tmp_path / "proj")
    import_program(session, dll, proj, analyze=True)
    h = session.program(proj, "a.dll")
    made = sigs.make_signatures(h, patches, binary=dll, min_fixed=10)
    yield made
    session.close_project(proj, discard=True)


@pytest.fixture()
def source_project(tmp_path):
    """Tiny build A imported into Ghidra with two patch sites of one entry (a `jz` and the `xor eax,eax`)."""
    xor_off = FUNC.index(bytes.fromhex("31C0"))
    for made in _import_source(tmp_path, doc_two_sites(PE_ID, 0x600 + JZ, 0x600 + xor_off)):
        yield made, tmp_path, xor_off


@pytest.fixture()
def union_project(tmp_path):
    """Tiny build A with one union entry over the `jz` (two options: the original and a forced jump)."""
    for made in _import_source(tmp_path, union_doc(PE_ID, 0x600 + JZ, {"Slow (Default)": "7407", "Fast": "EB07"})):
        yield made, tmp_path


# --- pure logic ----------------------------------------------------------------------------------------------------------------


def test_union_options_carry_to_the_target_window_over_the_targets_own_bytes():
    sd = bytes.fromhex("1122334455667788")
    src = Patch(0x10, "x.dll", sd, bytes.fromhex("1122334455667744"))
    opts = [UnionOption("Default", 0x10, sd, "x.dll"), UnionOption("Fast", 0x10, bytes.fromhex("1122334455667744"), "x.dll")]
    row = sigs.SigRow("Mode", 1, 1, 0x10, 8, "code", src=src, options=opts)
    target = bytearray(0x40)
    target[0x20:0x28] = bytes.fromhex("AA22334455667799")  # the first and last byte differ in the target
    site = portmod.PortedSite(row, "ported", patch=Patch(0x20, "x.dll", bytes(target[0x20:0x28]), bytes(8)))
    out = portmod.carry_options(site, row, bytes(target))
    by = {o.name: o for o in out.options}
    assert out.ok and set(by) == {"Default", "Fast"} and by["Default"].offset == 0x20
    assert by["Default"].data == bytes(target[0x20:0x28])  # the option that leaves the build alone is the target's own bytes
    assert by["Fast"].data == bytes.fromhex("AA22334455667744")  # only its edit (88 -> 44) lands; the target's AA byte is kept, not the source's 11
    assert any("check them against the target" in n for n in out.option_notes)


def test_a_union_whose_options_change_nothing_is_not_ported():
    sd = bytes.fromhex("1122334455667788")
    src = Patch(0x10, "x.dll", sd, sd)
    row = sigs.SigRow("Mode", 1, 1, 0x10, 8, "code", src=src, options=[UnionOption("Only", 0x10, sd, "x.dll")])
    target = bytes(0x40)
    site = portmod.PortedSite(row, "ported", patch=Patch(0x20, "x.dll", sd, sd))
    out = portmod.carry_options(site, row, target)
    assert not out.ok and "no option that changes anything" in out.why


def test_a_rewritten_instruction_keeps_the_targets_own_operand_not_the_sources():
    # `mov eax,[ebx+0x2c4]; lea ecx,[eax+1]; cmp ecx,3 ...` -> `mov eax,1; mov [ebx+0x2c4],eax; nop ...`: the struct offset is copied from the original
    disabled = bytes.fromhex("8b83c40200008d480183f90356577f52")
    enabled = bytes.fromhex("b8010000008983c402000090565790" "90")
    target = bytes.fromhex("8b83a80300008d480183f90456577f52")  # the next build: offset 0x3a8, limit 4
    assert portmod.carry_copies(disabled, enabled, target) == bytes.fromhex("b8010000008983a803000090565790" "90")
    # the naive rule would have written the source's offset into the target
    assert bytes(e if e != d else t for d, e, t in zip(disabled, enabled, target)) == bytes.fromhex("b8010000008983c402000090565790" "90")


def test_short_or_featureless_runs_are_not_mistaken_for_copied_operands():
    # two bytes that also occur in the original window are chance
    assert portmod.carry_copies(bytes.fromhex("01020304"), bytes.fromhex("03049999"), bytes.fromhex("aabbccdd")) == bytes.fromhex("03049999")
    # three equal bytes carry no operand
    assert portmod.carry_copies(bytes.fromhex("112233000000" "44"), bytes.fromhex("000000" "99999999"), bytes.fromhex("aabbccddeeff" "00")) == bytes.fromhex("000000" "99999999")
    # an edit with nothing copied is the plain rule: unchanged bytes from the target, written bytes from the source
    assert portmod.carry_copies(bytes.fromhex("7673"), bytes.fromhex("eb73"), bytes.fromhex("7573")) == bytes.fromhex("eb73")
    # a long window is data (tables, strings): operands are not re-derived there
    d = bytes(i % 251 for i in range(300))
    e = d[:10] + d[100:105] + d[15:]
    assert portmod.carry_copies(d, e, b"\xff" * 300)[10:15] == d[100:105]
    assert portmod.carry_copies(d[:200], e[:200], b"\xff" * 200)[10:15] == b"\xff" * 5  # ... while the same edit in a 200-byte window is


def test_branch_direction_decodes_short_near_and_unconditional_jumps():
    d = portmod.branch_direction
    assert d(bytes.fromhex("750D")) == 1 and d(bytes.fromhex("75EE")) == -1 and d(bytes.fromhex("EB00")) == 1
    assert d(bytes.fromhex("0F8584000000")) == 1 and d(bytes.fromhex("0F85F0FFFFFF")) == -1 and d(bytes.fromhex("E9F0FFFFFF")) == -1
    assert d(bytes.fromhex("31C0")) is None and d(b"\x75") is None and d(bytes.fromhex("0F85")) is None and d(b"") is None


def test_an_edit_on_a_jump_is_not_carried_to_a_jump_that_goes_the_other_way():
    # `jnz +0x0d` -> `jmp` (skip a block) can match, through an identical tail, the loop-closing `jnz -0x12` of another idiom in the next build;
    # patching that one would hang the program
    src = Patch(offset=0x10, dll_name="x.dll", disabled=bytes.fromhex("750D"), enabled=bytes.fromhex("EB0D"))
    row = sigs.SigRow("E", 1, 1, 0x10, 2, "code", src=src)
    fwd = portmod._build_patch(row, b"\x00" * 4 + bytes.fromhex("7507"), 4, "signature")
    assert fwd.ok and fwd.patch.disabled == bytes.fromhex("7507") and fwd.patch.enabled == bytes.fromhex("EB07")
    back = portmod._build_patch(row, b"\x00" * 4 + bytes.fromhex("75EE"), 4, "signature")
    assert back.status == "failed" and back.patch is None and "forward in the source and backward" in back.why
    near = Patch(offset=0x20, dll_name="x.dll", disabled=bytes.fromhex("0F8584000000"), enabled=bytes.fromhex("90E984000000"))
    nrow = sigs.SigRow("N", 1, 1, 0x20, 6, "code", src=near)
    assert portmod._build_patch(nrow, bytes.fromhex("0F8512000000"), 0, "signature").ok
    assert portmod._build_patch(nrow, bytes.fromhex("0F85F0FFFFFF"), 0, "signature").status == "failed"
    # windows are often just the opcode byte (`75` -> `EB`): the displacement lies past the window and is read from the files
    one = Patch(offset=4, dll_name="x.dll", disabled=b"\x75", enabled=b"\xEB")
    orow = sigs.SigRow("O", 1, 1, 4, 1, "code", src=one)
    a_file = b"\x00" * 4 + bytes.fromhex("750D") + b"\x00" * 8
    assert portmod._build_patch(orow, b"\x00" * 4 + bytes.fromhex("750A") + b"\x00" * 8, 4, "signature", a_file).ok
    loop = portmod._build_patch(orow, b"\x00" * 4 + bytes.fromhex("75EE") + b"\x00" * 8, 4, "signature", a_file)
    assert loop.status == "failed" and "backward at 0x4" in loop.why
    # an edit that is not on a jump has no direction to compare
    nop = Patch(offset=0x30, dll_name="x.dll", disabled=bytes.fromhex("E810000000"), enabled=bytes.fromhex("9090909090"))
    assert portmod._build_patch(sigs.SigRow("C", 1, 1, 0x30, 5, "code", src=nop), bytes.fromhex("E8F0FFFFFF"), 0, "signature").ok


def _data_row(a: bytes, off: int, disabled: bytes, enabled: bytes) -> "sigs.SigRow":
    """A source data site with a (neighbour-based) signature, as `sig make` would have produced it."""
    lo, hi = off - 6, off + len(disabled) + 6
    cand = SigCandidate(start=lo, end=hi, pattern=a[lo:hi], mask=b"\xff" * (hi - lo), matches=1, insns=hi - lo, site=(off, off + len(disabled)))
    cand.text = format_masked(cand.pattern, cand.mask)
    out = signature_entry(cand, disabled, enabled, name="Hide text", game_code="ABC")
    return sigs.SigRow("Hide text", 1, 1, off, len(disabled), "data", cand=cand, out=out, ok=True, src=Patch(offset=off, dll_name="x.dll", disabled=disabled, enabled=enabled))


def test_string_anchor_extracts_the_nul_delimited_string_around_a_data_site():
    a = b"\x00" * 4 + b"\x00PREVIOUS ITEM\x00MENU LABEL\x00texture_mask\x00%0*d\x00" + b"\x01\x02\x03\x04\x05\x06\x07\x08\x09" + b"\x00" * 4
    label = a.index(b"MENU LABEL")
    assert string_anchor(a, Patch(label, "x.dll", b"MENU LABEL", b"\x00" * 10)) == (b"\x00MENU LABEL\x00", 1)
    # the site may carry the terminators (`\0NAME: %s\0`), or be a single letter inside the string
    assert string_anchor(a, Patch(label - 1, "x.dll", b"\x00MENU LABEL\x00", b"\x00" * 12)) == (b"\x00MENU LABEL\x00", 0)
    tm = a.index(b"texture_mask") + 7
    assert string_anchor(a, Patch(tm, "x.dll", b"a", b"b")) == (b"\x00texture_mask\x00", 8)
    # too short, a table, or a site spanning two strings are not anchored
    assert string_anchor(a, Patch(a.index(b"%0*d"), "x.dll", b"%0*d", b"\x00" * 4)) is None
    t = a.index(b"\x01\x02")
    assert string_anchor(a, Patch(t, "x.dll", b"\x01\x02", b"\x00\x00")) is None
    assert string_anchor(a, Patch(label, "x.dll", b"MENU LABEL\x00textu", b"\x00" * 16)) is None
    assert string_anchor(a, Patch(label, "x.dll", b"MENU LABEL", b"\x00" * 10), min_run=11) is None


def test_data_site_in_a_string_literal_is_found_by_the_string_when_its_neighbours_changed():
    a = b"\x00" * 16 + b"PREVIOUS ITEM\x00MENU LABEL\x00NEXT ITEM HERE\x00" + b"\x00" * 16
    row = _data_row(a, a.index(b"MENU LABEL"), b"MENU LABEL", b"\x00" * 10)
    b = b"\x00" * 16 + b"A TOTALLY DIFFERENT NEIGHBOUR\x00MENU LABEL\x00ANOTHER ONE\x00" + b"\x00" * 16
    site = portmod._port_row(row, b, a, use_ladder=False)
    assert site.ok and site.how.startswith("string anchor") and "MENU LABEL" in site.how
    assert site.patch.offset == b.index(b"MENU LABEL") and site.patch.disabled == b"MENU LABEL" and site.patch.enabled == b"\x00" * 10
    # not unique in the target -> not found, never a guess; switched off -> not found
    twice = b + b"OTHER\x00MENU LABEL\x00"
    assert portmod._port_row(row, twice, a, use_ladder=False).status == "not_found"
    assert portmod._port_row(row, b, a, use_ladder=False, min_string=0).status == "not_found"
    # a code site never uses it
    code = _data_row(a, a.index(b"MENU LABEL"), b"MENU LABEL", b"\x00" * 10)
    code.kind = "code"
    assert portmod._port_row(code, b, a, use_ladder=False).status == "not_found"


# --- synthetic builds through Ghidra (source only) -----------------------------------------------------------------------------


@pytest.mark.ghidra
def test_union_ported_to_a_shifted_build_keeps_its_options_and_verifies(union_project):
    made, tmp = union_project
    (row,) = made.rows
    assert row.ok and len(row.options) == 2 and row.kind == "code", made.format()
    assert not any(e.type == "union" for e in made.patchfile.entries)  # a signature entry cannot hold options
    img = PEImage(write_pe(tmp / "u.dll", 0x1800, tiny_body(prefix=b"\x90" * 8, call_disp=0x28)))
    rep = portmod.port_build(made, img, "ABC-5c5c0000_1800")
    assert rep.counts() == {"ported": 1, "partial": 0, "failed": 0}, rep.format()
    e = rep.patchfile.entries[0]
    assert e.type == "union" and e.name == "Mode" and [o.name for o in e.options] == ["Slow (Default)", "Fast"]
    assert [o.offset for o in e.options] == [0x600 + 8 + JZ] * 2
    assert [o.data.hex() for o in e.options] == ["7407", "eb07"]  # default = the target's own bytes; Fast = the source's edit
    assert rep.verified and verify(img.data, rep.patchfile.entries, expected_id="ABC-5c5c0000_1800").ok
    assert "union window of 2 bytes, 2 of 2 options carried" in rep.format()


@pytest.mark.ghidra
def test_port_adjacent_build_moved_code_changed_call(source_project):
    made, tmp, xor_off = source_project
    assert made.made == 2, made.format()
    img = PEImage(write_pe(tmp / "b.dll", 0x1100, tiny_body(prefix=b"\x90" * 8, call_disp=0x28)))  # code moved by 8 bytes, call displacement changed
    rep = portmod.port_build(made, img, "ABC-5c5c0000_1100")
    assert rep.counts() == {"ported": 1, "partial": 0, "failed": 0}, rep.format()
    e = rep.patchfile.entries[0]
    assert e.pe_identifier == "ABC-5c5c0000_1100" and e.name == "Two Sites" and e.description == "d"
    assert [p.offset for p in e.patches] == [0x600 + 8 + JZ, 0x600 + 8 + xor_off]
    # the window is rebuilt from B's own bytes, with only A's edits applied
    assert e.patches[0].disabled == bytes.fromhex("7407") and e.patches[0].enabled == bytes.fromhex("EB07")
    assert e.patches[1].disabled == bytes.fromhex("31C0") and e.patches[1].enabled == bytes.fromhex("B001")
    assert rep.verified and verify(img.data, rep.patchfile.entries, expected_id="ABC-5c5c0000_1100").ok
    assert all(s.how for en in rep.entries for s in en.sites)
    assert "1 entries ported" in rep.format() and "via" in rep.format()


@pytest.mark.ghidra
def test_the_anchor_tier_places_what_no_signature_holds_and_says_why_when_it_cannot(source_project):
    from kawaiidra_hx.match.anchors import Anchor

    made, tmp, xor_off = source_project
    img = PEImage(write_pe(tmp / "c.dll", 0x1100, b"\x90" * 0x80))  # nothing of the source survives: no signature, no window
    jz_src = 0x600 + JZ

    class Fake:  # (the real AnchorContext needs two analysed builds: tests/test_align.py covers it with synthetic indexes)
        def locate(self, offset, length):
            return Anchor(0x640, "function 0x1 -> 0x2, 7 aligned neighbours") if offset == jz_src else Anchor(None, "the function has no counterpart")

    plain = portmod.port_build(made, img, "ABC-5c5c0000_1100")
    assert plain.counts()["ported"] == 0 and "anchor" not in plain.entries[0].sites[0].why
    rep = portmod.port_build(made, img, "ABC-5c5c0000_1100", anchors=Fake(), allow_partial=True)
    placed, lost = rep.entries[0].sites
    assert placed.ok and placed.how.startswith("anchor (function 0x1 -> 0x2") and placed.patch.offset == 0x640
    assert placed.patch.disabled == b"\x90\x90" and placed.patch.enabled == bytes.fromhex("EB90")  # A's edit on B's own bytes
    assert not lost.ok and lost.why.endswith("anchor: the function has no counterpart") and rep.entries[0].status == "partial"


@pytest.mark.ghidra
def test_primary_signature_broken_but_a_window_leaning_the_other_way_still_matches(source_project):
    made, tmp, xor_off = source_project
    row = made.rows[0]  # the `jz` site
    primary = row.cand
    # change one fixed byte of the primary signature that lies to the LEFT of the site (an instruction before it was rebuilt)
    left = [i for i in range(primary.site_offset) if primary.mask[i]]
    assert left, "expected left context in the primary signature"
    b = bytearray(tiny_body())
    b[primary.start - 0x600 + left[0]] ^= 0xFF  # file offsets are body offsets + 0x600
    img = PEImage(write_pe(tmp / "b2.dll", 0x1200, bytes(b)))
    only_primary = portmod.port_build(made, img, "ABC-5c5c0000_1200", use_ladder=False)
    with_ladder = portmod.port_build(made, img, "ABC-5c5c0000_1200")
    assert only_primary.entries[0].sites[0].status == "not_found"  # the single signature no longer matches
    site = with_ladder.entries[0].sites[0]
    assert site.status == "ported" and site.how.startswith("window ladder") and site.patch.offset == 0x600 + JZ
    # the site whose primary context was intact keeps using the plain signature or a ladder, never a wrong place
    assert all(s.patch is None or s.patch.offset in (0x600 + JZ, 0x600 + xor_off) for s in with_ladder.entries[0].sites)
    # a ladder result needs min_agree agreeing windows: with a bar above what exists the site is reported, not ported
    k = int(site.how.split("(")[1].split()[0])
    strict = portmod.port_build(made, img, "ABC-5c5c0000_1200", min_agree=k + 1).entries[0].sites[0]
    assert strict.status == "not_found" and f"{k} < {k + 1} windows agree" in strict.why and strict.patch is None
    # ... and at least one agreeing window must hold informative bytes on both sides of the site, or the k windows are one piece of evidence
    lopsided = portmod.port_build(made, img, "ABC-5c5c0000_1200", min_side=999).entries[0].sites[0]
    assert lopsided.status == "not_found" and "lean on one side" in lopsided.why and lopsided.patch is None


@pytest.mark.ghidra
def test_not_found_ambiguous_and_partial_are_never_emitted_as_complete(source_project):
    made, tmp, xor_off = source_project
    # the function is gone in B: nothing is ported, nothing emitted, and the reasons are listed
    gone = PEImage(write_pe(tmp / "gone.dll", 0x1300, b"\x90" * 0x80))
    rep = portmod.port_build(made, gone, "ABC-5c5c0000_1300")
    assert rep.counts()["failed"] == 1 and rep.patchfile.entries == []
    assert all(s.status == "not_found" for s in rep.entries[0].sites) and "not found" in rep.format()

    # B contains the function twice: the signature is no longer unique -> ambiguous, not a guess
    body = tiny_body()
    twice = PEImage(write_pe(tmp / "twice.dll", 0x1400, body[:0x40] + tiny_body(call_disp=0x30)))
    amb = portmod.port_build(made, twice, "ABC-5c5c0000_1400", use_ladder=False)
    assert amb.counts()["ported"] == 0 and any(s.status == "ambiguous" for s in amb.entries[0].sites)
    assert amb.patchfile.entries == []

    # one of the two sites changed in B: partial; not emitted by default, emitted with a loud caution on request
    part_body = bytearray(tiny_body())
    part_body[xor_off : xor_off + 2] = bytes.fromhex("33C0")  # xor eax,eax encoded the other way: the second site's context changed
    img = PEImage(write_pe(tmp / "part.dll", 0x1500, bytes(part_body)))
    p1 = portmod.port_build(made, img, "ABC-5c5c0000_1500")
    status = p1.entries[0].status
    if status == "partial":  # the expected outcome: the jz site is found, the changed xor site is not
        assert p1.patchfile.entries == []
        p2 = portmod.port_build(made, img, "ABC-5c5c0000_1500", allow_partial=True)
        assert p2.patchfile.entries and "PARTIAL PORT: 1 of 2" in (p2.patchfile.entries[0].caution or "")
        assert len(p2.patchfile.entries[0].patches) == 1
    elif status == "failed":  # the jz window happened to include the changed bytes too
        assert p1.patchfile.entries == []
    else:
        pytest.fail("a changed site must never port cleanly: " + p1.format())
