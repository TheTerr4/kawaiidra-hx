"""x86/x64 branch arithmetic for hand-written patches.

Short/near jumps encode a signed displacement from the *end* of the instruction:
    target = address_of_instruction + instruction_length + displacement
"""

from __future__ import annotations

JCC_SHORT = {
    "jo": 0x70, "jno": 0x71, "jb": 0x72, "jnb": 0x73, "jz": 0x74, "je": 0x74, "jnz": 0x75, "jne": 0x75,
    "jbe": 0x76, "ja": 0x77, "js": 0x78, "jns": 0x79, "jp": 0x7A, "jnp": 0x7B, "jl": 0x7C, "jge": 0x7D,
    "jle": 0x7E, "jg": 0x7F,
}  # fmt: skip


def signed8(byte: int) -> int:
    """Interpret an encoded rel8 byte as signed: 0x73 -> +115, 0x8D -> -115."""
    return byte - 256 if byte >= 0x80 else byte


def rel_target(address: int, length: int, displacement: int) -> int:
    """Where a branch at ``address`` (``length`` bytes long) lands for a given *signed* displacement.

    Remember bytes >= 0x80 are negative (backward jumps): use :func:`signed8` on an encoded rel8.
    """
    return address + length + displacement


def rel8_for(address: int, target: int, length: int = 2) -> int:
    """Signed 8-bit displacement for a short branch at ``address`` to reach ``target``."""
    disp = target - (address + length)
    if not -128 <= disp <= 127:
        raise ValueError(f"target 0x{target:X} is {disp} bytes from 0x{address:X}: out of rel8 range")
    return disp


def jmp_short(address: int, target: int) -> bytes:
    """``EB rel8``"""
    return bytes([0xEB, rel8_for(address, target) & 0xFF])


def jcc_short(mnemonic: str, address: int, target: int) -> bytes:
    """``7x rel8`` for a conditional short jump."""
    try:
        op = JCC_SHORT[mnemonic.lower()]
    except KeyError:
        raise ValueError(f"unknown conditional jump {mnemonic!r}") from None
    return bytes([op, rel8_for(address, target) & 0xFF])


def jmp_near(address: int, target: int) -> bytes:
    """``E9 rel32``"""
    disp = target - (address + 5)
    return bytes([0xE9]) + (disp & 0xFFFFFFFF).to_bytes(4, "little")


def nops(n: int) -> bytes:
    """``n`` single-byte NOPs (``90``). Plain 0x90 fill is always valid, if not the prettiest."""
    return b"\x90" * n


def mov_eax_imm_ret(value: int) -> bytes:
    """``mov eax, imm32; ret`` (6 bytes): force a function to return a constant (x86 and x64)."""
    return bytes([0xB8]) + (value & 0xFFFFFFFF).to_bytes(4, "little") + b"\xC3"
