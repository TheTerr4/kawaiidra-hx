from __future__ import annotations

import hashlib

import pytest

from kawaiidra_hx.patch import (
    PatchFormatError,
    PatchMismatchError,
    apply,
    dump_entries,
    entries_from_data,
    load_entries,
    make_entry,
    select_entries,
    verify,
)
from kawaiidra_hx.patch import asm


def _entries():
    return entries_from_data(
        [
            {
                "name": "Main",
                "type": "memory",
                "patches": [{"offset": 0x600, "dllName": "x.dll", "dataDisabled": "40534883EC40", "dataEnabled": "B863000000C3"}],
            },
            {
                "name": "Safe",
                "type": "memory",
                "patches": [
                    {"offset": 0x606, "dllName": "x.dll", "dataDisabled": "7673", "dataEnabled": "EB73"},
                    {"offset": 0x608, "dllName": "x.dll", "dataDisabled": "758D", "dataEnabled": "9090"},
                ],
            },
            {"name": "Choice", "type": "mystery", "patches": []},  # unknown type: kept verbatim, skipped
        ]
    )


def test_entry_parsing_and_roundtrip():
    entries = _entries()
    assert [e.name for e in entries] == ["Main", "Safe", "Choice"]
    assert entries[0].patches[0].enabled == bytes.fromhex("B863000000C3")
    assert not entries[2].supported
    again = entries_from_data(__import__("json").loads(dump_entries(entries)))
    assert [e.to_dict() for e in again] == [e.to_dict() for e in entries]


def test_length_mismatch_rejected():
    with pytest.raises(PatchFormatError):
        entries_from_data([{"name": "x", "patches": [{"offset": 0, "dataDisabled": "00", "dataEnabled": "0000"}]}])


def test_select_by_name_and_index():
    entries = _entries()
    assert [e.name for e in select_entries(entries, ["Safe"])] == ["Safe"]
    assert [e.name for e in select_entries(entries, ["1", "2"])] == ["Main", "Safe"]
    with pytest.raises(PatchFormatError):
        select_entries(entries, ["nope"])


def test_verify_original_applied_and_mismatch(tiny_pe):
    entries = _entries()
    report = verify(tiny_pe, entries)
    assert report.ok and all(c.state == "original" for c in report.checks)
    assert report.skipped and "Choice" in report.skipped[0]
    assert report.checks[0].va == 0x180001000  # offset 0x600 -> .text RVA 0x1000

    patched = bytearray(tiny_pe)
    patched[0x600:0x606] = bytes.fromhex("B863000000C3")
    assert verify(bytes(patched), entries).checks[0].state == "applied"

    wrong = bytearray(tiny_pe)
    wrong[0x600] = 0x41
    r = verify(bytes(wrong), entries)
    assert not r.ok and r.checks[0].state == "mismatch"
    assert "found    41534883EC40" in r.format()


def test_verify_out_of_range(tiny_pe):
    bad = entries_from_data([{"name": "far", "patches": [{"offset": 10**9, "dataDisabled": "00", "dataEnabled": "01"}]}])
    assert verify(tiny_pe, bad).checks[0].state == "out_of_range"


def test_apply_writes_copy_and_never_touches_source(tiny_pe, tmp_path):
    src = tmp_path / "orig.dll"
    src.write_bytes(tiny_pe)
    dst = tmp_path / "out" / "orig_patched.dll"
    rep = apply(src, dst, _entries())
    assert src.read_bytes() == tiny_pe
    out = dst.read_bytes()
    assert out[0x600:0x606] == bytes.fromhex("B863000000C3")
    assert out[0x606:0x60A] == bytes.fromhex("EB739090")
    assert rep.bytes_changed == 6 + 1 + 2
    assert rep.sha256_after == hashlib.sha256(out).hexdigest()
    assert rep.sha256_before == hashlib.sha256(tiny_pe).hexdigest()
    assert len(rep.applied) == 3 and not rep.already_applied


def test_apply_refuses_in_place_existing_and_mismatch(tiny_pe, tmp_path):
    src = tmp_path / "orig.dll"
    src.write_bytes(tiny_pe)
    with pytest.raises(PatchMismatchError):
        apply(src, src, _entries())
    dst = tmp_path / "p.dll"
    dst.write_bytes(b"x")
    with pytest.raises(FileExistsError):
        apply(src, dst, _entries())
    apply(src, dst, _entries(), overwrite=True)

    other = tmp_path / "other.dll"
    broken = bytearray(tiny_pe)
    broken[0x601] ^= 0xFF
    other.write_bytes(bytes(broken))
    with pytest.raises(PatchMismatchError):
        apply(other, tmp_path / "never.dll", _entries())
    assert not (tmp_path / "never.dll").exists()  # aborted before writing anything


def test_apply_is_idempotent_on_already_applied(tiny_pe, tmp_path):
    src = tmp_path / "orig.dll"
    src.write_bytes(tiny_pe)
    first = tmp_path / "a.dll"
    apply(src, first, _entries())
    second = tmp_path / "b.dll"
    rep = apply(first, second, _entries())
    assert rep.applied == [] and len(rep.already_applied) == 3
    assert second.read_bytes() == first.read_bytes()


def test_overlapping_patches_rejected(tiny_pe, tmp_path):
    src = tmp_path / "orig.dll"
    src.write_bytes(tiny_pe)
    entries = entries_from_data(
        [
            {"name": "a", "patches": [{"offset": 0x600, "dataDisabled": "4053", "dataEnabled": "9090"}]},
            {"name": "b", "patches": [{"offset": 0x601, "dataDisabled": "5348", "dataEnabled": "9090"}]},
        ]
    )
    with pytest.raises(PatchMismatchError, match="overlap"):
        apply(src, tmp_path / "o.dll", entries)


def test_make_entry_reads_original_bytes_and_accepts_va(tiny_pe, tmp_path):
    src = tmp_path / "orig.dll"
    src.write_bytes(tiny_pe)
    e = make_entry(
        src,
        [("va:0x180001000", "B863000000C3"), ("off:0x606", "EB73")],
        name="Main",
        game_code="ABC",
        dll_name="target.dll",
    )
    assert e.patches[0].offset == 0x600 and e.patches[0].disabled == bytes.fromhex("40534883EC40")
    assert e.patches[1].offset == 0x606 and e.patches[1].disabled == bytes.fromhex("7673")
    d = e.to_dict()
    assert d["gameCode"] == "ABC" and d["patches"][0]["dataDisabled"] == "40534883EC40"
    assert verify(tiny_pe, [e]).ok


def test_asm_branch_math():
    # `jbe +0x73` at 0x1805D091B (2 bytes) -> 0x1805D0990, and `jmp short` to the same target is EB73
    assert asm.rel_target(0x1805D091B, 2, 0x73) == 0x1805D0990
    assert asm.jmp_short(0x1805D091B, 0x1805D0990) == bytes.fromhex("EB73")
    # `jnz 8D` is a *backward* jump: 0x8D is -115 as a signed byte
    assert asm.signed8(0x8D) == -115 and asm.signed8(0x73) == 0x73
    back = asm.rel_target(0x1805D098E, 2, asm.signed8(0x8D))
    assert back == 0x1805D098E + 2 - 115 == 0x1805D091D  # lands right after the `jbe` at ...91B
    assert asm.jcc_short("jnz", 0x1805D098E, back) == bytes.fromhex("758D")
    assert asm.rel8_for(0x100, 0x100 + 2 - 128) == -128
    with pytest.raises(ValueError):
        asm.rel8_for(0x100, 0x100 + 2 + 200)
    assert asm.jmp_near(0x1000, 0x1005) == bytes.fromhex("E900000000")
    assert asm.mov_eax_imm_ret(99) == bytes.fromhex("B863000000C3")
    assert asm.nops(2) == bytes.fromhex("9090")


@pytest.mark.reference
def test_reference_entry_file_verifies_and_applies_byte_identical(ref_new, ref_new_patched, ref_patch_json, tmp_path):
    entries = load_entries(ref_patch_json)
    assert len(entries) == 4
    r = verify(ref_new, entries)
    assert r.ok and all(c.state == "original" for c in r.checks)
    assert [c.va for c in r.checks] == [0x1805D0760, 0x1805D091B, 0x1805D098E, 0x180292C6C, 0x1803B6A86]

    assert all(c.state == "applied" for c in verify(ref_new_patched, entries).checks)

    out = tmp_path / "new_patched.dll"
    rep = apply(ref_new, out, entries)
    assert rep.bytes_changed == 16
    assert out.read_bytes() == ref_new_patched.read_bytes()
