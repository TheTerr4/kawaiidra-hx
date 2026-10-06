"""Turn user text into Ghidra addresses (and back to file offsets).

Accepted forms (``parse_address``):

    0x1805d0760 | 1805d0760     virtual address, hex (a bare token needs >= 5 hex digits, else it is tried as a symbol)
    FUN_1805d0760 | name        symbol / function name
    va:0x...                    explicit virtual address
    rva:0x5d0760                offset from the image base
    off:6094176 | off:0x5CFD60  *file offset* (what JSON patch files use)

Numbers after ``off:``/``rva:``/``va:`` are decimal unless written with ``0x`` (or containing a-f).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from .errors import AddressError
from .session import ProgramHandle

_PREFIXED = re.compile(r"^(va|rva|off|file)\s*[:=]\s*(\S+)$", re.IGNORECASE)
_HEXLIKE = re.compile(r"^(0x)?[0-9a-fA-F]+$")


def _number(text: str) -> int:
    t = text.strip().replace("_", "")
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if t.isdigit():
            return int(t, 10)
        return int(t, 16)
    except ValueError:
        raise AddressError(f"{text!r} is not a number") from None


def _addr(program: Any, value: int) -> Any:
    space = program.getAddressFactory().getDefaultAddressSpace()
    try:
        return space.getAddress(value)
    except Exception as e:
        raise AddressError(f"0x{value:X} is out of range for this program's address space: {e}") from None


def file_offset(program: Any, address: Any) -> Optional[int]:
    """File offset backing ``address`` (None when the bytes are not file-backed)."""
    info = program.getMemory().getAddressSourceInfo(address)
    if info is None:
        return None
    off = int(info.getFileOffset())
    return off if off >= 0 else None


def parse_address(h: ProgramHandle, text: str, *, must_be_mapped: bool = True) -> Any:
    """Resolve ``text`` to a Ghidra ``Address`` in ``h.program``."""
    prog = h.program
    t = text.strip()
    if not t:
        raise AddressError("empty address")

    m = _PREFIXED.match(t)
    addr: Any = None
    if m:
        kind, num = m.group(1).lower(), _number(m.group(2))
        if kind == "va":
            addr = _addr(prog, num)
        elif kind == "rva":
            addr = prog.getImageBase().add(num)
        else:  # off / file
            hits = list(prog.getMemory().locateAddressesForFileOffset(num))
            if not hits:
                raise AddressError(f"file offset 0x{num:X} is not mapped to any address in {h.name}")
            addr = hits[0]
    elif _HEXLIKE.match(t) and (t.lower().startswith("0x") or len(t) >= 5):
        addr = _addr(prog, int(t, 16))
    else:
        symbols = list(prog.getSymbolTable().getGlobalSymbols(t))
        addrs = sorted({str(s.getAddress()) for s in symbols})
        if len(addrs) == 1:
            addr = symbols[0].getAddress()
        elif len(addrs) > 1:
            raise AddressError(f"symbol {t!r} is ambiguous: {', '.join(addrs[:8])}")
        elif _HEXLIKE.match(t):
            addr = _addr(prog, int(t, 16))
        else:
            raise AddressError(f"{t!r} is not an address or a known symbol in {h.name}")

    if must_be_mapped and not prog.getMemory().contains(addr):
        raise AddressError(f"{addr} is not inside {h.name}'s memory (image base {prog.getImageBase()})")
    return addr


@dataclass
class Location:
    address: str
    function: Optional[str]
    function_entry: Optional[str]
    block: Optional[str]
    file_offset: Optional[int]
    rva: int
    symbol: Optional[str]

    def format(self) -> str:
        lines = [f"address      0x{int(self.address, 16):X}   (rva 0x{self.rva:X})"]
        if self.block:
            lines.append(f"block        {self.block}")
        if self.file_offset is not None:
            lines.append(f"file offset  0x{self.file_offset:X} ({self.file_offset})")
        else:
            lines.append("file offset  (not file-backed)")
        if self.function:
            lines.append(f"function     {self.function} @ 0x{int(self.function_entry, 16):X}")
        if self.symbol:
            lines.append(f"symbol       {self.symbol}")
        return "\n".join(lines)


def describe(h: ProgramHandle, address: Any) -> Location:
    prog = h.program
    fn = prog.getFunctionManager().getFunctionContaining(address)
    block = prog.getMemory().getBlock(address)
    sym = prog.getSymbolTable().getPrimarySymbol(address)
    return Location(
        address=str(address),
        function=str(fn.getName()) if fn is not None else None,
        function_entry=str(fn.getEntryPoint()) if fn is not None else None,
        block=str(block.getName()) if block is not None else None,
        file_offset=file_offset(prog, address),
        rva=int(address.subtract(prog.getImageBase())),
        symbol=str(sym.getName(True)) if sym is not None else None,
    )
