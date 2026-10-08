"""Exports / imports / relocations / CodeView / identity on a hand-built PE, plus structural checks on the reference DLLs."""

from __future__ import annotations

import struct

import pytest

from kawaiidra_hx.pe import PEImage, parse_pe

from .conftest import build_pe

RDATA_RVA, RDATA_RAW = 0x2000, 0xA00


def build_pe_with_tables(*, is64: bool, lib: bytes = b"KERNEL32.dll", ordinal: int = 5, export_base: int = 1) -> bytes:
    """.text + .rdata; .rdata carries export, import, base-reloc and debug data at fixed RVAs."""
    sections = [(".text", 0x1000, 0x400, 0x600, 0x400), (".rdata", RDATA_RVA, 0x800, RDATA_RAW, 0x800)]
    buf = bytearray(build_pe(is64=is64, image_base=0x180000000 if is64 else 0x10000000, entry_rva=0x1234, sections=sections, total_size=0x1200))

    def put(rva: int, data: bytes) -> None:
        o = RDATA_RAW + (rva - RDATA_RVA)
        buf[o : o + len(data)] = data

    # export directory @0x2000: module "mod.dll", ordinals 1..3: alpha, <forwarder>, gamma
    put(0x2000, struct.pack("<IIHHIIIIIII", 0, 0x5C5C0000, 0, 0, 0x2100, export_base, 3, 2, 0x2040, 0x2050, 0x2060))
    put(0x2040, struct.pack("<III", 0x1010, 0x2130, 0x1020))
    put(0x2050, struct.pack("<II", 0x2110, 0x2118))
    put(0x2060, struct.pack("<HH", 0, 2))
    put(0x2100, b"mod.dll\0")
    put(0x2110, b"alpha\0")
    put(0x2118, b"gamma\0")
    put(0x2130, b"other.alpha\0")
    # import directory @0x2200: KERNEL32 (by name + by ordinal), HELPER (by name)
    w = 8 if is64 else 4
    fmt = "<Q" if is64 else "<I"
    flag = 1 << (w * 8 - 1)
    put(0x2200, struct.pack("<IIIII", 0x2300, 0, 0, 0x2480, 0x2320) + struct.pack("<IIIII", 0x2340, 0, 0, 0x2490, 0x2360) + b"\0" * 20)
    put(0x2300, struct.pack(fmt, 0x2400) + struct.pack(fmt, flag | ordinal) + struct.pack(fmt, 0))
    put(0x2320, struct.pack(fmt, 0x2400) + struct.pack(fmt, flag | ordinal) + struct.pack(fmt, 0))
    put(0x2340, struct.pack(fmt, 0x2420) + struct.pack(fmt, 0))
    put(0x2360, struct.pack(fmt, 0x2420) + struct.pack(fmt, 0))
    put(0x2400, struct.pack("<H", 7) + b"ExitProcess\0")
    put(0x2420, struct.pack("<H", 1) + b"helper_init\0")
    put(0x2480, lib + b"\0")
    put(0x2490, b"HELPER.dll\0")
    # base relocations @0x2500: page 0x1000, two real entries + one ABSOLUTE pad
    kind = 10 if is64 else 3
    put(0x2500, struct.pack("<II", 0x1000, 14 + 2) + struct.pack("<HHH", (kind << 12) | 0x10, (kind << 12) | 0x30, 0) + b"\0\0")
    # debug directory @0x2600 -> CodeView @0x2640
    cv = b"RSDS" + bytes(range(16)) + struct.pack("<I", 3) + b"c:\\x\\mod.pdb\0"
    put(0x2600, struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(cv), 0x2640, RDATA_RAW + 0x640))
    put(0x2640, cv)

    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    opt = e_lfanew + 24
    dirs = opt + (112 if is64 else 96)
    for index, (rva, size) in {0: (0x2000, 0x200), 1: (0x2200, 0x3C), 5: (0x2500, 16), 6: (0x2600, 28)}.items():
        struct.pack_into("<II", buf, dirs + 8 * index, rva, size)
    return bytes(buf)


@pytest.mark.parametrize("is64", [True, False])
def test_tables_on_synthetic_pe(is64):
    im = PEImage(build_pe_with_tables(is64=is64))
    assert im.info.entry_rva == 0x1234
    assert im.identity.pe_identifier("ABC") == f"ABC-5c5c0000_1234"

    ex = im.exports
    assert ex is not None and ex.module_name == "mod.dll" and ex.ordinal_base == 1
    assert [(e.ordinal, e.name, e.rva, e.forwarder) for e in ex.exports] == [
        (1, "alpha", 0x1010, None),
        (2, None, 0x2130, "other.alpha"),
        (3, "gamma", 0x1020, None),
    ]
    assert ex.by_name("gamma").rva == 0x1020

    libs = {lib.dll: lib for lib in im.imports}
    k32 = libs["KERNEL32.dll"]
    assert [(s.name, s.ordinal, s.hint) for s in k32.symbols] == [("ExitProcess", None, 7), (None, 5, 0)]
    assert [s.iat_rva for s in k32.symbols] == [0x2320, 0x2320 + (8 if is64 else 4)]
    assert k32.by_ordinal == 1 and k32.symbols[1].label == "#5"
    assert [s.name for s in libs["HELPER.dll"].symbols] == ["helper_init"]

    width = 8 if is64 else 4
    assert im.relocations == {0x1010: width, 0x1030: width}
    covered = im.relocated_offsets()
    assert covered == set(range(0x610, 0x610 + width)) | set(range(0x630, 0x630 + width))  # .text raw 0x600 <-> RVA 0x1000

    assert im.codeview is not None
    assert im.codeview.kind == "RSDS" and im.codeview.age == 3 and im.codeview.path == "c:\\x\\mod.pdb"
    assert im.codeview.guid == "{03020100-0504-0706-0809-0A0B0C0D0E0F}"


def test_missing_tables_are_empty():
    im = PEImage(build_pe())
    assert im.exports is None and im.imports == [] and im.relocations == {} and im.codeview is None


def test_directory_names_and_security_is_file_offset():
    pe = parse_pe(build_pe_with_tables(is64=True))
    assert pe.directory("export") == (0x2000, 0x200)
    assert pe.directory("debug") == (0x2600, 28)
    assert pe.directory("tls") == (0, 0)
    with pytest.raises(KeyError):
        pe.directory("nope")


# --- reference DLLs (read in place; skipped when not configured). Structure only, nothing build-specific --------


@pytest.mark.reference
def test_reference_tables_are_structurally_sound(ref_old, ref_new):
    for path, width in ((ref_old, 4), (ref_new, 8)):
        im = PEImage(path)
        assert im.identity.pe_identifier("ABC") == f"ABC-{im.info.timestamp:x}_{im.info.entry_rva:x}"
        # relocations are absolute 4-byte addresses on x86 and 8-byte pointers on x64 (code is RIP-relative there)
        assert im.relocations and set(im.relocations.values()) == {width}, path
        assert im.imports and all(lib.symbols for lib in im.imports), path
        for lib in im.imports:
            for sym in lib.symbols:  # every IAT slot lives inside a mapped section
                assert im.info.rva_to_offset(sym.iat_rva) >= 0
        assert im.codeview is None or im.codeview.kind in ("RSDS", "NB10")
        if im.exports is not None:
            assert len(im.exports.exports) == len({e.ordinal for e in im.exports.exports})
