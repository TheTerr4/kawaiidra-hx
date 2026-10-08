"""The full JSON patch format: header, memory, union, number, signature, group; verify/apply/revert/diff/merge."""

from __future__ import annotations

import json

import pytest

from kawaiidra_hx.patch import (
    PatchFormatError,
    PatchMismatchError,
    apply,
    asm,
    describe_entries,
    diff_entry,
    dump_entries,
    find_nth,
    iter_matches,
    load_patchfile,
    merge_entries,
    parse_masked,
    patchfile_from_data,
    plan_writes,
    verify,
)

from .conftest import build_pe

BODY = bytes.fromhex("40534883EC40") + bytes.fromhex("7673") + bytes.fromhex("758D") + b"\x90" * 4 + bytes.fromhex("E811223344") + b"\x3C\x00\x00\x00" + b"\x11" * 8
# file offsets: 0x600 prologue, 0x606 jbe, 0x608 jnz, 0x60A..0x60D nops, 0x60E call rel32 (E8 11223344), 0x613 u32 = 60, 0x617.. 8x 0x11


@pytest.fixture()
def pe_bytes() -> bytes:
    return build_pe(body=BODY)


def spec_file() -> list[dict]:
    return [
        {"gameCode": "ABC", "version": "2026-01-01", "lastUpdated": "now", "source": "test"},
        {"name": "Group", "description": "", "gameCode": "ABC", "type": "group", "id": "g1"},
        {
            "name": "Toggle", "description": "d", "caution": "careful", "gameCode": "ABC", "type": "memory", "group": "g1",
            "patches": [{"offset": 0x600, "dllName": "x.dll", "dataDisabled": "40534883EC40", "dataEnabled": "B863000000C3"}],
        },
        {
            "name": "Mode", "description": "", "gameCode": "ABC", "type": "union",
            "patches": [
                {"name": "Slow (Default)", "patch": {"offset": 0x606, "dllName": "x.dll", "data": "7673"}},
                {"name": "Fast", "patch": {"offset": 0x606, "dllName": "x.dll", "data": "EB73"}},
            ],
        },
        {
            "name": "Rate", "description": "", "gameCode": "ABC", "type": "number",
            "patch": {"offset": 0x613, "dllName": "x.dll", "size": 4, "min": 30, "max": 240},
        },
        {
            "name": "Sig", "description": "", "gameCode": "ABC", "type": "signature", "dllName": "x.dll",
            "signature": "7673 758D", "replacement": "EB?? 9090",
        },
        {"name": "Future", "type": "hologram", "whatever": [1, 2]},
    ]


def test_header_is_preserved_and_loading_no_longer_fails():
    pf = patchfile_from_data(spec_file())
    assert pf.headers == [spec_file()[0]] and pf.game_code == "ABC" and pf.version == "2026-01-01"
    assert [e.type for e in pf.entries] == ["group", "memory", "union", "number", "signature", "hologram"]
    assert json.loads(pf.dumps()) == spec_file()  # lossless, including caution/group/unknown entry


def test_pe_identifier_from_filename_and_entries(tmp_path):
    p = tmp_path / "ABC-12345678_1000.json"
    p.write_text(json.dumps(spec_file()))
    assert load_patchfile(p).pe_identifier == "ABC-12345678_1000"
    q = tmp_path / "ABC-12345678_1000.extra.json"
    q.write_text(json.dumps(spec_file()))
    assert load_patchfile(q).pe_identifier == "ABC-12345678_1000"
    r = tmp_path / "mine.json"
    r.write_text(json.dumps([{"name": "a", "peIdentifier": "ABC-1_2", "patches": [{"offset": 0, "dataDisabled": "00", "dataEnabled": "01"}]}]))
    assert load_patchfile(r).pe_identifier == "ABC-1_2"
    assert load_patchfile(tmp_path / "mine.json").entries[0].pe_identifier == "ABC-1_2"


def test_union_options_may_differ_in_length_like_real_files():
    pf = patchfile_from_data(
        [{"name": "Score", "type": "union", "patches": [
            {"name": "A", "patch": {"offset": 5, "dllName": "d", "data": "AABB"}},
            {"name": "B", "patch": {"offset": 5, "dllName": "d", "data": "AA"}},
        ]}]
    )
    assert [o.length for o in pf.entries[0].options] == [2, 1]


def test_bad_inputs_raise():
    with pytest.raises(PatchFormatError):
        patchfile_from_data([{"name": "n", "type": "number", "patch": {"offset": 0, "size": 3, "min": 0, "max": 1}}])
    with pytest.raises(PatchFormatError):
        patchfile_from_data([{"name": "n", "type": "signature", "signature": "AA", "replacement": "AABB"}])
    with pytest.raises(PatchFormatError):
        parse_masked("A?")  # half wildcard
    with pytest.raises(PatchFormatError):
        parse_masked("ABC")  # odd length
    with pytest.raises(PatchFormatError):
        patchfile_from_data("nope")


def test_signature_matching_is_overlapping_and_nth():
    data = b"\x00AAAA\x00"
    pat, mask = parse_masked("4141")
    assert list(iter_matches(data, pat, mask)) == [1, 2, 3]  # overlapping, like a naive byte-by-byte search
    assert find_nth(data, pat, mask, 1) == (2, 3)
    assert find_nth(data, pat, mask, 5) == (None, 3)
    pat, mask = parse_masked("41 ?? 41")
    assert list(iter_matches(data, pat, mask)) == [1, 2]
    assert parse_masked("41xx41") == (b"\x41\x00\x41", b"\xff\x00\xff")  # XX is a wildcard too


def test_verify_all_types(pe_bytes):
    pf = patchfile_from_data(spec_file())
    r = verify(pe_bytes, pf.entries)
    assert r.ok, r.format()
    kinds = {c.entry: c for c in r.checks}
    assert kinds["Toggle"].state == "original"
    assert kinds["Mode"].active == ["Slow (Default)"]
    assert kinds["Rate"].value == 60 and kinds["Rate"].state == "value"
    assert kinds["Sig"].state == "original" and kinds["Sig"].resolution.offset == 0x606 and kinds["Sig"].va == 0x180001006
    assert any("Future" in s for s in r.skipped)  # unknown type reported, not silently ignored
    assert "Slow (Default)" in r.format()


def test_verify_detects_union_mismatch_bad_number_and_missing_signature(pe_bytes):
    pf = patchfile_from_data(spec_file())
    b = bytearray(pe_bytes)
    b[0x606] = 0x99  # no union option nor signature matches any more
    b[0x613] = 0xFF
    b[0x614] = 0xFF  # 65535 > 240
    r = verify(bytes(b), pf.entries)
    by = {c.entry: c for c in r.checks}
    assert by["Mode"].state == "unmatched" and "matches none of" in by["Mode"].format()
    assert by["Rate"].state == "bad_value" and "OUTSIDE" in by["Rate"].format()
    assert by["Sig"].state == "not_found"
    assert not r.ok


def test_signature_applied_state_and_ambiguity_note(pe_bytes):
    ent = patchfile_from_data(
        [{"name": "S", "type": "signature", "signature": "7673 758D", "replacement": "EB?? 9090"}]
    ).entries
    out = bytearray(pe_bytes)
    out[0x606:0x60A] = bytes.fromhex("EB739090")  # as if applied (wildcard in replacement keeps the 73)
    r = verify(bytes(out), ent)
    assert r.checks[0].state == "applied" and r.ok
    dup = bytes(pe_bytes) + bytes.fromhex("7673758D")  # second copy appended: ambiguous
    r = verify(dup, ent)
    assert r.checks[0].state == "original" and any("not unique" in n for n in r.notes)


def test_wrong_build_identity_fails(pe_bytes):
    ent = patchfile_from_data(spec_file()).entries
    good = f"ABC-5c5c0000_{0:x}"  # build_pe: timestamp 0x5C5C0000, entry rva 0
    assert verify(pe_bytes, ent, expected_id=good).ok
    r = verify(pe_bytes, ent, expected_id="ABC-12345678_1000")
    assert not r.ok and r.checks[0].state == "wrong_build" and "WRONG_BUILD" in r.format()


def test_plan_writes_selection(pe_bytes):
    ent = patchfile_from_data(spec_file()).entries
    writes, skipped = plan_writes(pe_bytes, ent)  # no selections
    assert {w.entry for w in writes} == {"Toggle", "Sig"}
    assert any("Mode" in s for s in skipped) and any("Rate" in s for s in skipped) and any("Future" in s for s in skipped)
    writes, _ = plan_writes(pe_bytes, ent, {"Mode": "fast", "Rate": "120"})  # option names are case-insensitive
    by = {w.entry: w for w in writes}
    assert by["Mode"].new == bytes.fromhex("EB73") and by["Rate"].new == (120).to_bytes(4, "little")
    with pytest.raises(PatchFormatError, match="outside the allowed range"):
        plan_writes(pe_bytes, ent, {"Rate": "999"})
    with pytest.raises(PatchFormatError, match="no option"):
        plan_writes(pe_bytes, ent, {"Mode": "ludicrous"})


def test_apply_with_selections_then_revert(pe_bytes, tmp_path):
    src = tmp_path / "x.dll"
    src.write_bytes(pe_bytes)
    ent = [e for e in patchfile_from_data(spec_file()).entries if e.name in ("Toggle", "Mode", "Rate")]
    out = tmp_path / "o.dll"
    rep = apply(src, out, ent, selections={"Mode": "Fast", "Rate": "120"})
    data = out.read_bytes()
    assert data[0x600:0x606] == bytes.fromhex("B863000000C3")
    assert data[0x606:0x608] == bytes.fromhex("EB73")
    assert int.from_bytes(data[0x613:0x617], "little") == 120
    assert rep.bytes_changed == 6 + 1 + 1 and not rep.skipped

    # a union/number without a selection is skipped, not guessed
    out2 = tmp_path / "o2.dll"
    rep2 = apply(src, out2, ent)
    assert out2.read_bytes()[0x606:0x608] == bytes.fromhex("7673") and len(rep2.skipped) == 2

    # revert restores the memory entry; unions/numbers have no defined original
    back = tmp_path / "back.dll"
    rep3 = apply(out, back, ent, mode="revert")
    assert back.read_bytes()[0x600:0x606] == bytes.fromhex("40534883EC40")
    assert "reverted" in rep3.format() and len(rep3.skipped) == 2


def test_apply_rejects_selection_for_an_entry_that_is_not_applied(pe_bytes, tmp_path):
    src = tmp_path / "x.dll"
    src.write_bytes(pe_bytes)
    ent = [e for e in patchfile_from_data(spec_file()).entries if e.name == "Toggle"]
    with pytest.raises(PatchFormatError, match="Mode"):
        apply(src, tmp_path / "o.dll", ent, selections={"Mode": "Fast"})


def test_apply_refuses_wrong_build_and_unmatched_union(pe_bytes, tmp_path):
    src = tmp_path / "x.dll"
    src.write_bytes(pe_bytes)
    ent = patchfile_from_data(spec_file()).entries
    with pytest.raises(PatchMismatchError, match="WRONG_BUILD"):
        apply(src, tmp_path / "a.dll", ent, expected_id="ABC-1_2")
    b = bytearray(pe_bytes)
    b[0x606] = 0x99
    src2 = tmp_path / "y.dll"
    src2.write_bytes(bytes(b))
    only_union = [e for e in ent if e.name == "Mode"]
    with pytest.raises(PatchMismatchError, match="matches none of"):
        apply(src2, tmp_path / "b.dll", only_union, selections={"Mode": "Fast"})
    assert not (tmp_path / "b.dll").exists()


def test_apply_signature_entry(pe_bytes, tmp_path):
    src = tmp_path / "x.dll"
    src.write_bytes(pe_bytes)
    ent = [e for e in patchfile_from_data(spec_file()).entries if e.name == "Sig"]
    out = tmp_path / "o.dll"
    apply(src, out, ent)
    assert out.read_bytes()[0x606:0x60A] == bytes.fromhex("EB739090")  # EB??, 9090 with the 73 kept
    again = tmp_path / "o2.dll"
    rep = apply(out, again, ent)  # already applied -> found through the overlaid signature
    assert rep.applied == [] and rep.already_applied == ["Sig"]
    back = tmp_path / "o3.dll"
    apply(out, back, ent, mode="revert")
    assert back.read_bytes() == pe_bytes  # the signature fixed every original byte, so revert is exact


def test_diff_entry_and_merge(pe_bytes, tmp_path):
    mod = bytearray(pe_bytes)
    mod[0x600:0x606] = bytes.fromhex("B863000000C3")
    mod[0x608] = 0x90  # not adjacent to the first run
    mod[0x60A] = 0x00
    e = diff_entry(pe_bytes, bytes(mod), name="D", game_code="ABC", dll_name="x.dll")
    assert [(p.offset, p.disabled.hex().upper(), p.enabled.hex().upper()) for p in e.patches] == [
        (0x600, "40534883EC40", "B863000000C3"),
        (0x608, "75", "90"),
        (0x60A, "90", "00"),  # 0x609 is untouched, so this is its own run
    ]
    merged = diff_entry(pe_bytes, bytes(mod), name="D", gap=2)  # 0x608 and 0x60A are 1 byte apart; 0x606 is 2 apart from 0x608
    assert len(merged.patches) == 1 and merged.patches[0].offset == 0x600 and merged.patches[0].length == 0x0B
    padded = diff_entry(pe_bytes, bytes(mod), name="D", pad=1)  # padding makes the first two runs overlap -> merged
    assert [(p.offset, p.length) for p in padded.patches] == [(0x5FF, 0xD)]  # all three padded runs touch -> one patch
    assert verify(pe_bytes, [padded]).ok
    assert verify(pe_bytes, [e]).ok and all(c.state == "applied" for c in verify(bytes(mod), [e]).checks)
    with pytest.raises(PatchFormatError, match="identical"):
        diff_entry(pe_bytes, pe_bytes, name="x")
    with pytest.raises(PatchFormatError, match="size"):
        diff_entry(pe_bytes, pe_bytes + b"\0", name="x")

    pf = patchfile_from_data(spec_file())
    _pf, log = merge_entries(pf, [e])
    assert log == ["added 'D'"] and pf.entries[-1].name == "D"
    with pytest.raises(PatchFormatError, match="already exists"):
        merge_entries(pf, [e])
    _pf, log = merge_entries(pf, [e], replace=True)
    assert log == ["replaced 'D'"]


def test_describe_entries_lists_everything():
    text = describe_entries(patchfile_from_data(spec_file()))
    for needle in ("header:", "[group] Group", "[memory] Toggle", "[union] Mode", "Fast", "[number] Rate", "[signature] Sig", "[hologram] Future"):
        assert needle in text


def test_dump_entries_roundtrip_of_new_types():
    ents = patchfile_from_data(spec_file()).entries
    again = patchfile_from_data(json.loads(dump_entries(ents))).entries
    assert [e.to_dict() for e in again] == [e.to_dict() for e in ents]


def test_branch_encoders():
    assert asm.call_near(0x1000, 0x1005) == bytes.fromhex("E800000000")
    assert asm.jcc_near("jnz", 0x1000, 0x1006) == bytes.fromhex("0F8500000000")
    assert asm.branch("jmp", 0x1000, 0x1005) == asm.jmp_near(0x1000, 0x1005)
    assert asm.branch("jmp", 0x1000, 0x1002, short=True) == bytes.fromhex("EB00")
    assert asm.branch("jnz", 0x1000, 0x1002) == bytes.fromhex("7500")  # conditionals default to the 2-byte form
    assert asm.branch("jnz", 0x1000, 0x1006, near=True) == bytes.fromhex("0F8500000000")
    with pytest.raises(ValueError):
        asm.branch("call", 0, 0, short=True)
    with pytest.raises(ValueError):
        asm.call_near(0, 1 << 33)
