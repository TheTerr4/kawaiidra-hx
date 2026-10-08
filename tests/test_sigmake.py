"""Signature synthesis: the pure algorithm (synthetic data) and the Ghidra operand-mask rules (tiny synthetic PE)."""

from __future__ import annotations

import os

import pytest

from kawaiidra_hx.patch import SignatureSpec, load_patchfile, parse_masked, patchfile_from_data, resolve_signature, verify
from kawaiidra_hx.patch.sigmake import (
    Insn,
    byte_units,
    make_signature,
    signature_entry,
    trim_replacement,
    verify_signature,
)
from kawaiidra_hx.patch.signature import count_matches, iter_matches

from .conftest import build_pe


def units(data: bytes, lengths: list[int], volatile: dict[int, tuple[int, ...]] | None = None, base: int = 0) -> list[Insn]:
    """Split ``data`` into instructions of the given lengths; ``volatile`` maps instruction index -> wildcard byte indexes."""
    out, off = [], base
    for i, n in enumerate(lengths):
        out.append(Insn(off, n, (volatile or {}).get(i, ()), f"i{i}"))
        off += n
    assert off - base == len(data), (off - base, len(data))
    return out


# a little "binary": the same idiom appears in three places, only one with distinguishing context
IDIOM = bytes.fromhex("8B4308" "85C0" "7405")  # mov eax,[rbx+8]; test eax,eax; jz +5  (3 instructions)
FILLER = bytes.fromhex("90" * 16)


def build_binary() -> tuple[bytes, list[int]]:
    parts = [
        FILLER, bytes.fromhex("B801000000"), IDIOM, bytes.fromhex("E800112233"), FILLER,  # A: context mov eax,1 ... call
        bytes.fromhex("B802000000"), IDIOM, bytes.fromhex("C3"), FILLER,  # B
        bytes.fromhex("B803000000"), IDIOM, bytes.fromhex("C2"), FILLER,  # C
    ]  # fmt: skip
    data = b"".join(parts)
    starts = []
    for needle in (bytes.fromhex("B801000000"), bytes.fromhex("B802000000"), bytes.fromhex("B803000000")):
        starts.append(data.index(needle))
    return data, starts


def insn_map(data: bytes) -> list[Insn]:
    """Instruction boundaries for build_binary(): fillers are 1-byte nops, the rest as written above."""
    out: list[Insn] = []
    i = 0
    known = [  # (needle, [lengths of the instructions in it])
        (bytes.fromhex("B801000000"), [5]), (bytes.fromhex("B802000000"), [5]), (bytes.fromhex("B803000000"), [5]),
        (IDIOM, [3, 2, 2]), (bytes.fromhex("E800112233"), [5]), (bytes.fromhex("C3"), [1]), (bytes.fromhex("C2"), [1]),
    ]  # fmt: skip
    while i < len(data):
        for needle, lens in known:
            if data.startswith(needle, i) and (needle != bytes.fromhex("C3") or data[i - 1 : i] != b"\x90" or True):
                if needle in (bytes.fromhex("C3"), bytes.fromhex("C2")) and i < 16:
                    continue
                for n in lens:
                    out.append(Insn(i, n, (), "x"))
                    i += n
                break
        else:
            out.append(Insn(i, 1, (), "nop"))
            i += 1
    return out


def test_grows_until_unique_and_enforces_min_fixed():
    data, starts = build_binary()
    insns = insn_map(data)
    assert count_matches(data, *parse_masked("8B430885C07405")) == 3  # the idiom alone is ambiguous
    site = (starts[1] + 5 + 5, starts[1] + 5 + 7)  # the `jz +5` of copy B (2 bytes)
    sig = make_signature(data, insns, *site, min_fixed=6, escalate_to=0, allow_usage=False)
    assert sig is not None and sig.unique and sig.fixed >= 6
    assert sig.start <= site[0] and sig.end >= site[1]
    # the bare idiom matches 3 places, so some context that tells copy B apart (its `mov eax,2` before or its `ret` after) is inside
    assert sig.length > len(IDIOM) and sig.start <= starts[1] + 10
    assert count_matches(data, sig.pattern, sig.mask) == 1


def test_volatile_bytes_become_wildcards_and_do_not_break_matching():
    data = bytes.fromhex("90909090" "E8AABBCCDD" "85C0" "7405" "9090909090")
    other = data.replace(bytes.fromhex("AABBCCDD"), bytes.fromhex("11223344"))  # same code, rebuilt: call displacement moved
    insns = units(data, [1, 1, 1, 1, 5, 2, 2, 5], {4: (1, 2, 3, 4)}) if False else None
    insns = [Insn(0, 1), Insn(1, 1), Insn(2, 1), Insn(3, 1), Insn(4, 5, (1, 2, 3, 4), "call"), Insn(9, 2, (), "test"), Insn(11, 2, (1,), "jz"), Insn(13, 5)]
    # data is only used for the pattern bytes; 5 trailing nops are not instructions in the map
    sig = make_signature(data, insns, 9, 11, min_fixed=3, escalate_to=0, allow_usage=False)
    assert sig is not None and sig.unique
    assert "????????" in sig.text.replace(" ", "")
    # the rebuilt binary has a different call displacement and still matches the wildcarded signature
    assert count_matches(other, sig.pattern, sig.mask) == 1
    assert count_matches(data, sig.pattern, sig.mask) == 1


def test_shrink_drops_context_that_is_not_needed():
    data = bytes.fromhex("11223344556677889900AABBCCDDEEFF") + bytes.fromhex("01") * 40
    insns = [Insn(i, 1) for i in range(16)]
    sig = make_signature(data, insns, 8, 9, min_fixed=2, escalate_to=0, allow_usage=False)
    assert sig is not None and sig.unique and sig.length == 2  # the byte plus one neighbour is already unique


def test_escalation_then_usage_fallback():
    block = bytes.fromhex("AABBCCDD" * 6)  # 24 repeating bytes: no window of 8 is unique
    data = bytes.fromhex("EE") * 4 + block + bytes.fromhex("EE") * 4 + block + bytes.fromhex("FF") * 4
    insns = [Insn(i, 1) for i in range(len(data))]
    site_start = 4 + len(block) + 4 + 8  # inside the second block
    none = make_signature(data, insns, site_start, site_start + 1, max_bytes=8, min_fixed=2, escalate_to=0, allow_usage=False)
    assert none is not None and not none.unique
    big = make_signature(data, insns, site_start, site_start + 1, max_bytes=8, min_fixed=2, escalate_to=64, allow_usage=False)
    assert big is not None and big.unique and any("needed" in n for n in big.notes)

    amb = [Insn(i, 1) for i in range(4, 4 + 2 * len(block) + 4)]  # an instruction map too small to disambiguate by context
    sig = make_signature(data, amb, site_start, site_start + 1, max_bytes=8, min_fixed=2, escalate_to=0, allow_usage=True)
    assert sig is not None and not sig.unique and sig.ambiguous_of > 1 and sig.usable
    assert sig.usage >= 1 and any("ambiguous" in n for n in sig.notes)


def test_site_outside_the_map_is_not_signable():
    data = bytes(range(64))
    assert make_signature(data, [Insn(10, 4), Insn(14, 4)], 0, 2) is None
    assert make_signature(data, [Insn(10, 4), Insn(14, 4)], 12, 20) is None  # runs past the end of the map
    assert make_signature(data, [], 0, 1) is None
    with pytest.raises(ValueError):
        make_signature(data, [Insn(0, 4), Insn(8, 4)], 0, 2)  # gap between instructions


def test_trim_replacement_keeps_unchanged_bytes_as_wildcards():
    assert trim_replacement(bytes.fromhex("0F10060F114760"), bytes.fromhex("C7476001000000")) == (0, "C7476001000000")
    assert trim_replacement(bytes.fromhex("7673"), bytes.fromhex("EB73")) == (0, "EB")
    assert trim_replacement(bytes.fromhex("758D"), bytes.fromhex("908D")) == (0, "90")
    assert trim_replacement(bytes.fromhex("AA11BB"), bytes.fromhex("AA22BB")) == (1, "22")
    assert trim_replacement(bytes.fromhex("0011223344"), bytes.fromhex("0099223388")) == (1, "99????88")
    with pytest.raises(ValueError):
        trim_replacement(b"\x00", b"\x00")


def test_signature_entry_round_trips_through_patcher_semantics():
    data, starts = build_binary()
    insns = insn_map(data)
    site = (starts[1] + 10, starts[1] + 12)
    disabled, enabled = data[site[0] : site[1]], bytes.fromhex("EB05")
    sig = make_signature(data, insns, *site, min_fixed=6, escalate_to=0, allow_usage=False)
    entry = signature_entry(sig, disabled, enabled, name="B patch", game_code="ABC", dll_name="x.dll")
    assert entry.type == "signature" and entry.signature.replacement == "EB"  # only the opcode changes
    ok, why = verify_signature(data, entry, site[0], disabled, enabled)
    assert ok, why
    # applying it through the normal patch engine changes exactly that byte
    res = resolve_signature(data, entry.signature)
    assert res.offset == site[0] and res.enabled == b"\xEB"
    # and it survives a JSON round trip as a plain signature entry
    again = patchfile_from_data([entry.to_dict()]).entries[0]
    assert again.signature == entry.signature and "peIdentifier" not in entry.to_dict()
    assert verify(data, [again]).ok
    # a different binary where the context differs does not match (safe failure rather than a wrong patch)
    b_copy = bytes.fromhex("B802000000") + IDIOM + bytes.fromhex("C3")
    broken = data.replace(b_copy, bytes.fromhex("B902000000") + IDIOM + bytes.fromhex("C4"))  # the context of copy B changed
    assert resolve_signature(broken, entry.signature).state in ("not_found", "no_such_usage")


def test_byte_units_for_data_sites():
    data = bytes(range(32))
    us = byte_units(data, 4, 12, volatile_offsets={6, 7})
    assert [u.offset for u in us] == list(range(4, 12)) and [u.volatile for u in us][2:4] == [(0,), (0,)]
    assert byte_units(data, -5, 3)[0].offset == 0 and byte_units(data, 30, 99)[-1].offset == 31
    sig = make_signature(data, byte_units(data, 0, 32), 10, 11, min_fixed=3, escalate_to=0)
    assert sig is not None and sig.unique and sig.fixed >= 3


def test_iter_matches_fast_path_equals_lookahead_scan():
    import random

    random.seed(7)
    data = bytes(random.choice(b"\x00\x01\x02\x03") for _ in range(5000))
    from kawaiidra_hx.patch.signature import compile_pattern

    for text in ("01 02 03", "00 ?? 02 02", "?? ?? 03 03 01", "02 00 00 00 ?? 01", "03"):
        p, m = parse_masked(text)
        assert list(iter_matches(data, p, m)) == [x.start() for x in compile_pattern(p, m).finditer(data)], text


# --- Ghidra: operand-mask rules on a tiny PE ------------------------------------------------------

CODE = (
    bytes.fromhex("488D0DF90F0000")  # 0x180001000 lea rcx,[rip+0xFF9]   -> 0x180002000 (.data)
    + bytes.fromhex("E814000000")  # 0x180001007 call 0x180001020
    + bytes.fromhex("7402")  # 0x18000100C jz 0x180001010
    + bytes.fromhex("31C0")  # 0x18000100E xor eax,eax
    + bytes.fromhex("83F806")  # 0x180001010 cmp eax,6
    + bytes.fromhex("C3")  # 0x180001013 ret
    + b"\xCC" * 12
    + bytes.fromhex("C3")  # 0x180001020 callee
)


@pytest.mark.ghidra
def test_operand_masks_wildcard_only_position_dependent_bytes(tmp_path):
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR not set")
    from kawaiidra_hx.core import get_session
    from kawaiidra_hx.core.jobs import import_program
    from kawaiidra_hx.queries.sigmask import data_window, format_window, instruction_window

    dll = tmp_path / "t.dll"
    dll.write_bytes(build_pe(entry_rva=0x1000, body=CODE))
    proj = str(tmp_path / "proj")
    session = get_session()
    import_program(session, dll, proj, analyze=True)
    try:
        h = session.program(proj, "t.dll")
        win = instruction_window(h, 0x600, 0x607, before=0, after=6)
        assert win is not None
        by_text = {u.text.split(" ")[0]: u for u in win}
        assert by_text["LEA"].volatile == (3, 4, 5, 6)  # RIP-relative disp32 (data reference)
        assert by_text["CALL"].volatile == (1, 2, 3, 4)  # rel32 call displacement
        assert by_text["JZ"].volatile == (1,)  # rel8 jump displacement
        assert by_text["XOR"].volatile == () and by_text["CMP"].volatile == ()  # scalar immediate 6 stays fixed
        assert win[0].offset == 0x600 and all(a.end == b.offset for a, b in zip(win, win[1:]))

        data = dll.read_bytes()
        text = format_window(win, data, (0x600, 0x607))
        assert "48 8D 0D ?? ?? ?? ??" in text and "E8 ?? ?? ?? ??" in text and "83 F8 06" in text

        # extra volatile bytes (relocations) are merged in
        win2 = instruction_window(h, 0x600, 0x607, before=0, after=6, extra_volatile={0x60E, 0x60F})
        xor = next(u for u in win2 if u.text.startswith("XOR"))
        assert xor.volatile == (0, 1)

        # a site that is not code has no instruction window; data windows work from the bytes alone
        assert instruction_window(h, 0xA00, 0xA02) is None
        assert len(data_window(data, 0xA00, 0xA02, radius=4)) == 10
    finally:
        session.close_project(proj, discard=True)


def test_padding_bytes_do_not_count_and_growth_avoids_them():
    """A string followed by zero padding: the padding differs between builds, so the signature must use the string's own context."""
    pad = b"\x00" * 12
    data = b"\x11" * 6 + b"A_path/texture_mask" + pad + b"\x22" * 6 + b"B_path/texture_mask" + pad + b"\x33" * 6
    site = data.index(b"A_path/") + len(b"A_path/texture_m")  # the 'a' of "mask"
    sig = make_signature(data, byte_units(data, 0, len(data)), site, site + 1, min_fixed=12, escalate_to=0, allow_usage=False)
    assert sig is not None and sig.unique
    assert b"\x00" not in sig.pattern and sig.weight >= 12  # no padding inside, and 12 real bytes of context
    assert b"A_path/" in sig.pattern or sig.pattern.startswith(b"/texture") or b"A_p" in sig.pattern
    # code: alignment filler weighs nothing too
    from kawaiidra_hx.patch.sigmake import unit_weight

    assert unit_weight(b"\xCC", Insn(0, 1, (), "INT3")) == 0 and unit_weight(b"\x0F\x1F\x00", Insn(0, 3, (), "NOP dword ptr [RAX]")) == 0
    assert unit_weight(b"\x83\xF8\x06", Insn(0, 3, (), "CMP EAX,0x6")) == 3
    assert unit_weight(b"\xE8\x00\x00\x00\x00", Insn(0, 5, (1, 2, 3, 4), "CALL x")) == 1  # wildcarded displacement carries nothing
    assert unit_weight(b"\x00", Insn(0, 1, (), "db")) == 0 and unit_weight(b"\x41", Insn(0, 1, (), "db")) == 1
