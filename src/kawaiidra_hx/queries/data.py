"""Data queries: raw bytes, pointer tables, defined data, program/section info, address resolution."""

from __future__ import annotations

from ..core.resolve import describe, file_offset, parse_address
from ..core.session import ProgramHandle
from .code import _fn_label, _function_containing


def read_bytes(h: ProgramHandle, where: str, count: int) -> str:
    from jpype import JArray, JByte

    with h.lock:
        addr = parse_address(h, where)
        # must be a real Java byte[]: JPype copies Python bytearrays instead of filling them in place
        buf = JArray(JByte)(count)
        n = int(h.program.getMemory().getBytes(addr, buf))
        return " ".join(f"{b & 0xFF:02x}" for b in buf[:n]) + (" " if n else "")


def fetch_bytes(h: ProgramHandle, addr, count: int) -> bytes:
    """Raw bytes at a Ghidra ``Address`` (shorter than ``count`` if memory ends). Caller holds ``h.lock``."""
    from jpype import JArray, JByte

    buf = JArray(JByte)(count)  # a real Java byte[]: JPype copies Python bytearrays instead of filling them
    n = int(h.program.getMemory().getBytes(addr, buf))
    return bytes(b & 0xFF for b in buf[:n])


def pointer_table(h: ProgramHandle, where: str, count: int = 40) -> str:
    """Dump ``count`` pointers starting at an address and the function each one points to (vtables, jump tables)."""
    with h.lock:
        prog = h.program
        start = parse_address(h, where)
        mem = prog.getMemory()
        size = int(prog.getDefaultPointerSize())
        space = prog.getAddressFactory().getDefaultAddressSpace()
        lines = []
        for k in range(count):
            pa = start.add(size * k)
            v = int(mem.getLong(pa)) if size == 8 else int(mem.getInt(pa)) & 0xFFFFFFFF
            v &= (1 << (8 * size)) - 1
            if v >= 1 << 63:
                v -= 1 << 64
            target = space.getAddress(v)
            fn = prog.getFunctionManager().getFunctionAt(target)
            lines.append(f"{pa} -> {target} {fn.getName() if fn is not None else ''}".rstrip())
        return "\n".join(lines)


def data_at(h: ProgramHandle, where: str) -> str:
    with h.lock:
        addr = parse_address(h, where)
        listing = h.program.getListing()
        d = listing.getDataContaining(addr)
        if d is None or not d.isDefined():
            return f"{addr}: no defined data (undefined or code)"
        sym = h.program.getSymbolTable().getPrimarySymbol(d.getAddress())
        lines = [
            f"{d.getAddress()}  {d.getDataType().getName()}  length={d.getLength()}",
            f"  value  : {d.getDefaultValueRepresentation()}",
        ]
        if sym is not None:
            lines.append(f"  label  : {sym.getName(True)}")
        refs = [str(r.getFromAddress()) for r in h.program.getReferenceManager().getReferencesTo(d.getAddress())]
        if refs:
            lines.append(f"  xrefs  : {', '.join(refs[:12])}{' ...' if len(refs) > 12 else ''} ({len(refs)})")
        return "\n".join(lines)


def sections(h: ProgramHandle) -> str:
    with h.lock:
        prog = h.program
        lines = [f"{'block':<12}{'start':>18}{'end':>18}{'size':>12}  perms  file offset"]
        for b in prog.getMemory().getBlocks():
            perms = ("R" if b.isRead() else "-") + ("W" if b.isWrite() else "-") + ("X" if b.isExecute() else "-")
            off = file_offset(prog, b.getStart()) if b.isInitialized() else None
            lines.append(
                f"{str(b.getName()):<12}{str(b.getStart()):>18}{str(b.getEnd()):>18}{int(b.getSize()):>#12x}  {perms}    "
                + (f"0x{off:X}" if off is not None else "-")
            )
        return "\n".join(lines)


def info(h: ProgramHandle) -> str:
    with h.lock:
        p = h.program
        from ghidra.program.util import GhidraProgramUtilities

        funcs = int(p.getFunctionManager().getFunctionCount())
        lines = [
            f"name        {p.getName()}",
            f"format      {p.getExecutableFormat()}",
            f"language    {p.getLanguageID()}  compiler {p.getCompilerSpec().getCompilerSpecID()}",
            f"image base  {p.getImageBase()}  pointer size {p.getDefaultPointerSize()}",
            f"functions   {funcs}",
            f"analyzed    {bool(GhidraProgramUtilities.isAnalyzed(p))}",
            f"source      {p.getExecutablePath()}",
            f"md5         {p.getExecutableMD5()}",
            f"sha256      {p.getExecutableSHA256()}",
            f"open mode   {'read-write' if h.writable else 'read-only'}",
        ]
        return "\n".join(lines)


def resolve(h: ProgramHandle, where: str) -> str:
    """Describe an address / symbol / file offset: block, function, file offset, rva."""
    with h.lock:
        addr = parse_address(h, where)
        return describe(h, addr).format()
