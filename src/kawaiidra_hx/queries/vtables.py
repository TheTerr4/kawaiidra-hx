"""RTTI vtables of a Ghidra program: for every C++ class the virtual-function table(s) and the functions in their slots.

Ghidra's RTTI analyzer labels each vtable ``<Class>::vftable`` (the class is the namespace). The class name is part of the binary, so it is the same in
every build of the program, and a virtual function keeps its slot as long as the class keeps its layout: ``(class, slot)`` is an identity for a function
that needs neither a string nor a constant of its own. Absolute addresses never enter the result except as the keys of the program they came from.
"""

from __future__ import annotations

from typing import Mapping

from ..core.session import ProgramHandle

MAX_SLOTS = 512  # a vtable longer than this is a misread (it ran into the next table)

VTable = tuple[int, tuple[int, ...]]  # (virtual address of slot 0, entry address of the function in every slot)


def extract_vtables(h: ProgramHandle) -> dict[str, list[VTable]]:
    """``{class name (namespace path): [(vftable address, slot function entries), ...]}``; the tables of one class are in address order.

    A table ends at the first slot that is not the entry point of a function, or at the next label that is not a default pointer name (the
    ``vftable_meta_ptr`` in front of the following table). The program must be analysed."""
    out: dict[str, list[VTable]] = {}
    with h.lock:
        prog = h.program
        symtab, fm, mem = prog.getSymbolTable(), prog.getFunctionManager(), prog.getMemory()
        space = prog.getAddressFactory().getDefaultAddressSpace()
        ptr = int(prog.getDefaultPointerSize())
        for sym in symtab.getSymbolIterator("vftable", True):
            ns = sym.getParentNamespace()
            if ns is None or ns.isGlobal():
                continue
            start = sym.getAddress()
            slots: list[int] = []
            for i in range(MAX_SLOTS):
                cur = start.add(i * ptr)
                if i and any(not str(s.getName()).startswith(("PTR_", "DAT_")) for s in symtab.getSymbols(cur)):
                    break
                try:
                    raw = mem.getLong(cur) if ptr == 8 else (mem.getInt(cur) & 0xFFFFFFFF)
                except Exception:  # not backed by file bytes
                    break
                target = space.getAddress(raw)
                fn = fm.getFunctionContaining(target)
                if fn is None or not fn.getEntryPoint().equals(target):
                    break
                slots.append(int(target.getOffset()))
            out.setdefault(str(ns.getName(True)), []).append((int(start.getOffset()), tuple(slots)))
    for tables in out.values():
        tables.sort()
    return out


def vtable_slot_pairs(A: Mapping[str, list[VTable]], B: Mapping[str, list[VTable]]) -> dict[int, tuple[int, int, int]]:
    """Pair the functions of two builds by ``(class, vtable, slot)``.

    Only classes that have the same number of tables in both builds, and tables with the same number of slots, are paired (a table that grew or
    shrank has moved its slots). A function that sits in several tables must be paired with the same counterpart by a clear majority of them.
    Returns ``{function in A: (function in B, votes for it, votes cast)}``."""
    votes: dict[int, dict[int, int]] = {}
    for cls, tables_a in A.items():
        tables_b = B.get(cls)
        if not tables_b or len(tables_a) != len(tables_b):
            continue
        for (_, slots_a), (_, slots_b) in zip(tables_a, tables_b):
            if len(slots_a) != len(slots_b):
                continue
            for x, y in zip(slots_a, slots_b):
                v = votes.setdefault(x, {})
                v[y] = v.get(y, 0) + 1
    out: dict[int, tuple[int, int, int]] = {}
    for a, v in votes.items():
        ranked = sorted(v.items(), key=lambda kv: -kv[1])
        b, n = ranked[0]
        rest = sum(k for _, k in ranked[1:])
        if not rest or n > 2 * rest:
            out[a] = (b, n, n + rest)
    return out
