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


def call_near(address: int, target: int) -> bytes:
    """``E8 rel32``"""
    disp = target - (address + 5)
    if not -(1 << 31) <= disp < (1 << 31):
        raise ValueError(f"target 0x{target:X} is out of rel32 range from 0x{address:X}")
    return bytes([0xE8]) + (disp & 0xFFFFFFFF).to_bytes(4, "little")


def jcc_near(mnemonic: str, address: int, target: int) -> bytes:
    """``0F 8x rel32`` for a conditional near jump (6 bytes)."""
    try:
        op = JCC_SHORT[mnemonic.lower()] + 0x10
    except KeyError:
        raise ValueError(f"unknown conditional jump {mnemonic!r}") from None
    disp = target - (address + 6)
    if not -(1 << 31) <= disp < (1 << 31):
        raise ValueError(f"target 0x{target:X} is out of rel32 range from 0x{address:X}")
    return bytes([0x0F, op]) + (disp & 0xFFFFFFFF).to_bytes(4, "little")


def branch(op: str, address: int, target: int, *, short: bool = False, near: bool = False) -> bytes:
    """Encode ``jmp``/``call``/``jcc`` from ``address`` to ``target`` (the one place CLI and MCP share).

    ``jmp`` is the 5-byte near form unless ``short``; ``call`` is always near; conditionals are the 2-byte short form
    unless ``near`` (``0F 8x rel32``), because in-place patches usually keep the original instruction length.
    """
    op = op.lower()
    if op == "jmp":
        return jmp_short(address, target) if short else jmp_near(address, target)
    if op == "call":
        if short:
            raise ValueError("call has no short form")
        return call_near(address, target)
    return jcc_near(op, address, target) if near else jcc_short(op, address, target)


def nops(n: int) -> bytes:
    """``n`` single-byte NOPs (``90``). Plain 0x90 fill is always valid, if not the prettiest."""
    return b"\x90" * n


def mov_eax_imm_ret(value: int) -> bytes:
    """``mov eax, imm32; ret`` (6 bytes): force a function to return a constant (x86 and x64)."""
    return bytes([0xB8]) + (value & 0xFFFFFFFF).to_bytes(4, "little") + b"\xC3"
