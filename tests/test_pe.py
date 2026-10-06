from __future__ import annotations

import pytest

from kawaiidra_hx.pe import NotMappedError, PEError, format_sections, parse_pe

from .conftest import build_pe


def test_parse_synthetic_pe64(tiny_pe):
    pe = parse_pe(tiny_pe)
    assert pe.is_64bit and pe.is_dll
    assert pe.machine == "x64"
    assert pe.image_base == 0x180000000
    assert [s.name for s in pe.sections] == [".text", ".data"]
    assert pe.section_by_name(".text").delta == 0x1000 - 0x600


def test_parse_synthetic_pe32():
    pe = parse_pe(build_pe(is64=False, image_base=0x10000000))
    assert not pe.is_64bit and pe.machine == "x86" and pe.image_base == 0x10000000


def test_offset_va_roundtrip(tiny_pe):
    pe = parse_pe(tiny_pe)
    assert pe.offset_to_rva(0x600) == 0x1000
    assert pe.offset_to_va(0x610) == 0x180001010
    assert pe.va_to_offset(0x180001010) == 0x610
    # header bytes map identically
    assert pe.offset_to_rva(0x100) == 0x100


def test_not_mapped_cases(tiny_pe):
    pe = parse_pe(tiny_pe)
    with pytest.raises(NotMappedError):
        pe.offset_to_rva(0x2000)  # past every section's raw data
    with pytest.raises(NotMappedError):
        pe.va_to_offset(0x100)  # below image base
    # .data is 0x1000 in memory but only 0x200 in the file: RVA 0x2800 is zero-filled, no file offset
    with pytest.raises(NotMappedError):
        pe.rva_to_offset(0x2800)


def test_rejects_non_pe():
    with pytest.raises(PEError):
        parse_pe(b"not a pe at all" * 10)
    with pytest.raises(PEError):
        parse_pe(b"MZ" + b"\0" * 0x80)


def test_format_sections_lists_every_section(tiny_pe):
    text = format_sections(parse_pe(tiny_pe))
    assert ".text" in text and ".data" in text and "image_base=0x180000000" in text


@pytest.mark.reference
def test_reference_new_known_patch_addresses(ref_new):
    pe = parse_pe(ref_new)
    assert pe.image_base == 0x180000000 and pe.is_64bit
    # offsets from the reference patch entry file and the VAs we verified in Ghidra during the port
    assert pe.offset_to_va(6094176) == 0x1805D0760  # FUN_1805d0760 (stage limit)
    assert pe.offset_to_va(6094619) == 0x1805D091B
    assert pe.offset_to_va(6094734) == 0x1805D098E
    assert pe.offset_to_va(2695788) == 0x180292C6C
    assert pe.offset_to_va(3891334) == 0x1803B6A86
    assert pe.section_by_name(".text").delta == 0xA00
    assert pe.va_to_offset(0x1805D0760) == 6094176


@pytest.mark.reference
def test_reference_old_text_delta(ref_old):
    pe = parse_pe(ref_old)
    assert pe.image_base == 0x10000000 and not pe.is_64bit
    assert pe.section_by_name(".text").delta == 0xC00
