"""Instruction map for signature synthesis: which bytes of each instruction move when the binary is rebuilt?

For every instruction Ghidra knows the bit ranges of each operand (``InstructionPrototype.getOperandValueMask``) and the references the
operand carries. An operand is *position dependent* when it is a control-flow operand (relative jump/call displacement) or a memory
reference to an address in the image (RIP-relative / absolute / IAT slot). Its bytes are wildcards in a signature. Everything else
(opcode, ModRM register bits, struct displacements, stack offsets, scalar immediates) stays fixed: it survives a rebuild of the same code.

Extra volatile bytes (the PE base-relocation table: absolute pointers on x86, DIR64 on x64) are merged in by the caller.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from ..core.resolve import file_offset, parse_address
from ..core.session import ProgramHandle
from ..patch.sigmake import Insn, byte_units


def operand_is_position_dependent(ins: Any, i: int) -> bool:
    ref_type = ins.getOperandRefType(i)
    if ref_type is not None and ref_type.isFlow():
        return True
    for ref in ins.getOperandReferences(i):
        if ref.isMemoryReference() and not ref.isStackReference():
            return True
        if ref.isExternalReference():
            return True
    return False


def volatile_bytes(ins: Any) -> tuple[int, ...]:
    """Indexes (inside the instruction) of the bytes that are wholly covered by a position-dependent operand."""
    length = int(ins.getLength())
    out: set[int] = set()
    proto = ins.getPrototype()
    for i in range(int(ins.getNumOperands())):
        if not operand_is_position_dependent(ins, i):
            continue
        mask = proto.getOperandValueMask(i)
        if mask is None:
            continue
        for k, mb in enumerate(mask.getBytes()):
            if k < length and (int(mb) & 0xFF) == 0xFF:
                out.add(k)
    return tuple(sorted(out))


def _insn(prog: Any, ins: Any, extra: set[int]) -> Optional[Insn]:
    off = file_offset(prog, ins.getAddress())
    if off is None:
        return None
    vol = set(volatile_bytes(ins))
    for k in range(int(ins.getLength())):
        if off + k in extra:
            vol.add(k)
    return Insn(off, int(ins.getLength()), tuple(sorted(vol)), str(ins))


def _adjacent(a: Any, b: Any) -> bool:
    """``a`` ends exactly where ``b`` starts (no gap, no data between them)."""
    return a.getMaxAddress().next() is not None and a.getMaxAddress().next().equals(b.getMinAddress())


def instruction_window(
    h: ProgramHandle,
    site_start: int,
    site_end: int,
    *,
    before: int = 24,
    after: int = 24,
    extra_volatile: Iterable[int] = (),
) -> Optional[list[Insn]]:
    """Contiguous instructions around the file range ``[site_start, site_end)``: those covering it plus up to ``before`` / ``after``
    more on either side. None when the site is not code (no instruction at its first byte). Never crosses a gap or non-code bytes."""
    extra = set(extra_volatile)
    with h.lock:
        prog = h.program
        addr = parse_address(h, f"off:{site_start}")
        first = prog.getListing().getInstructionContaining(addr)
        if first is None:
            return None
        window: list[Any] = [first]
        cur = first
        for _ in range(before):
            prev = cur.getPrevious()
            if prev is None or not _adjacent(prev, cur):
                break
            window.insert(0, prev)
            cur = prev
        cur = first
        extra_after = after
        covered = False
        while True:
            off = file_offset(prog, cur.getAddress())
            if off is not None and off + int(cur.getLength()) >= site_end:
                covered = True
            if covered:
                if extra_after <= 0:
                    break
                extra_after -= 1
            nxt = cur.getNext()
            if nxt is None or not _adjacent(cur, nxt):
                break
            window.append(nxt)
            cur = nxt
        out: list[Insn] = []
        for ins in window:
            unit = _insn(prog, ins, extra)
            if unit is None:
                if not out:
                    continue
                break  # a non-file-backed instruction ends the contiguous run
            if out and out[-1].end != unit.offset:
                break
            out.append(unit)
        return out or None


def data_window(data: bytes, site_start: int, site_end: int, *, radius: int = 48, extra_volatile: Iterable[int] = ()) -> list[Insn]:
    """1-byte units around a data patch (strings, tables); relocated pointers are the only wildcards."""
    return byte_units(data, site_start - radius, site_end + radius, extra_volatile)


def format_window(insns: list[Insn], data: bytes, site: tuple[int, int] | None = None) -> str:
    """Debug view: ``file-offset  bytes (wildcards as ??)  text``."""
    lines = []
    for ins in insns:
        raw = " ".join("??" if k in ins.volatile else f"{data[ins.offset + k]:02X}" for k in range(ins.length))
        mark = "*" if site and ins.offset < site[1] and ins.end > site[0] else " "
        lines.append(f"{mark} 0x{ins.offset:X}  {raw:<26} {ins.text}")
    return "\n".join(lines)
