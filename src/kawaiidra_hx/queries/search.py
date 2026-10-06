"""Search queries: strings (+xrefs), instruction-text scan, symbols, byte patterns, RTTI classes."""

from __future__ import annotations

import re
from typing import Any, Optional

from ..core.resolve import file_offset
from ..core.session import ProgramHandle
from .code import _fn_label, _function_containing


def strings(h: ProgramHandle, needle: str, limit: int = 1000) -> str:
    """Defined strings containing ``needle`` (case-insensitive), each with its cross-references."""
    needle_l = needle.strip().lower()
    with h.lock:
        out: list[str] = []
        shown = 0
        for d in h.program.getListing().getDefinedData(True):
            if not d.hasStringValue():
                continue
            v = d.getValue()
            if v is None:
                continue
            s = str(v)
            if needle_l and needle_l not in s.lower():
                continue
            out.append(f'{d.getAddress()} "{s}"')
            for ref in h.program.getReferenceManager().getReferencesTo(d.getAddress()):
                fn = _function_containing(h, ref.getFromAddress())
                out.append(f"    xref {ref.getFromAddress()} in {_fn_label(fn)}")
            shown += 1
            if shown >= limit:
                out.append(f"... (limit {limit} strings reached)")
                break
        return "\n".join(out) if out else "(no matching strings)"


def scan(h: ProgramHandle, needle: str, limit: int = 400) -> str:
    """Instructions whose text contains ``needle`` (case-insensitive), e.g. ``0x6c0`` or ``cmp dword ptr [rax + 0x6c]``.

    Finds immediates and displacements that cross-references cannot. ~13 s for a 2M-instruction program.
    """
    needle_l = needle.strip().lower()
    with h.lock:
        out: list[str] = []
        for ins in h.program.getListing().getInstructions(True):
            text = str(ins)
            if needle_l in text.lower():
                fn = _function_containing(h, ins.getAddress())
                out.append(f"{ins.getAddress()}  {text}   [{_fn_label(fn)}]")
                if len(out) >= limit:
                    out.append(f"... (limit {limit} hits reached)")
                    break
        return "\n".join(out) if out else "(no matching instructions)"


def symbols(h: ProgramHandle, needle: str, limit: int = 3000) -> str:
    needle_l = needle.strip().lower()
    with h.lock:
        out: list[str] = []
        for s in h.program.getSymbolTable().getAllSymbols(True):
            name = str(s.getName(True))
            if needle_l in name.lower():
                out.append(f"{s.getAddress()} {s.getSymbolType()} {name}")
                if len(out) >= limit:
                    out.append(f"... (limit {limit} symbols reached)")
                    break
        return "\n".join(out) if out else "(no matching symbols)"


def parse_byte_pattern(pattern: str) -> tuple[bytes, bytes]:
    """``"B8 63 ?? 00"`` -> (bytes, mask) where mask byte 0xFF means "must match"."""
    toks = pattern.replace(",", " ").split()
    if len(toks) == 1 and re.fullmatch(r"(?:[0-9a-fA-F]{2}|\?\?)+", toks[0]):
        toks = re.findall(r"[0-9a-fA-F]{2}|\?\?", toks[0])
    vals, mask = bytearray(), bytearray()
    for t in toks:
        if t in ("??", "?", "**"):
            vals.append(0)
            mask.append(0)
        elif re.fullmatch(r"[0-9a-fA-F]{2}", t):
            vals.append(int(t, 16))
            mask.append(0xFF)
        else:
            raise ValueError(f"bad byte token {t!r} (use hex pairs and ?? wildcards)")
    if not vals:
        raise ValueError("empty byte pattern")
    return bytes(vals), bytes(mask)


def search_bytes(h: ProgramHandle, pattern: str, limit: int = 50) -> str:
    """Find a byte pattern (hex pairs, ``??`` wildcards) in initialized memory."""
    from ghidra.util.task import TaskMonitor

    data, mask = parse_byte_pattern(pattern)
    with h.lock:
        mem = h.program.getMemory()
        addr: Optional[Any] = mem.getMinAddress()
        out: list[str] = []
        while addr is not None and len(out) < limit:
            addr = mem.findBytes(addr, data, mask, True, TaskMonitor.DUMMY)
            if addr is None:
                break
            fn = _function_containing(h, addr)
            off = file_offset(h.program, addr)
            off_s = f"file 0x{off:X}" if off is not None else "no file offset"
            out.append(f"{addr}  {off_s}  [{_fn_label(fn)}]")
            addr = addr.next()
        if len(out) >= limit:
            out.append(f"... (limit {limit} matches reached)")
        return "\n".join(out) if out else "(pattern not found)"


def rtti(h: ProgramHandle, needle: str = "", limit: int = 1000) -> str:
    """C++ classes recovered from RTTI (``<Class>::RTTI_Type_Descriptor`` symbols)."""
    needle_l = needle.strip().lower()
    suffix = "::RTTI_Type_Descriptor"
    with h.lock:
        rows: list[tuple[str, str]] = []
        for s in h.program.getSymbolTable().getSymbolIterator("*RTTI_Type_Descriptor", True):
            name = str(s.getName(True))
            if not name.endswith(suffix):
                continue
            cls = name[: -len(suffix)]
            if needle_l and needle_l not in cls.lower():
                continue
            rows.append((cls, str(s.getAddress())))
        rows.sort()
        out = [f"{addr}  {cls}" for cls, addr in rows[:limit]]
        if len(rows) > limit:
            out.append(f"... (limit {limit} of {len(rows)} classes reached)")
        return "\n".join(out) if out else "(no RTTI classes found)"
