"""Code queries: decompile, disassemble, function bounds, callers/callees, cross-references.

Output formats intentionally match the Q.java helper used during the original patch port, so earlier results can be
diffed against these (golden tests).
"""

from __future__ import annotations

from typing import Any, Optional

from ..core.resolve import parse_address
from ..core.session import ProgramHandle


def _fn_label(fn: Optional[Any]) -> str:
    return "?" if fn is None else f"{fn.getName()}@{fn.getEntryPoint()}"


def _function_containing(h: ProgramHandle, address: Any) -> Optional[Any]:
    return h.program.getFunctionManager().getFunctionContaining(address)


def _instruction_line(ins: Any) -> str:
    raw = "".join(f"{b & 0xFF:02x} " for b in ins.getBytes())
    return f"{ins.getAddress()}  {raw:<24} {ins}"


def decomp(h: ProgramHandle, where: str, *, timeout: int = 120) -> str:
    from ghidra.util.task import TaskMonitor

    with h.lock:
        addr = parse_address(h, where)
        fn = _function_containing(h, addr)
        if fn is None:
            return "no function"
        head = f"// {fn.getName()} @ {fn.getEntryPoint()} size {fn.getBody().getNumAddresses()}"
        res = h.decompiler().decompileFunction(fn, timeout, TaskMonitor.DUMMY)
        if res.decompileCompleted():
            return head + "\n" + str(res.getDecompiledFunction().getC())
        return head + "\ndecompile failed: " + str(res.getErrorMessage())


def dis(h: ProgramHandle, where: str, count: int = 40) -> str:
    """``count`` instructions starting at an address (does not stop at function ends)."""
    with h.lock:
        addr = parse_address(h, where)
        listing = h.program.getListing()
        ins = listing.getInstructionAt(addr) or listing.getInstructionContaining(addr)
        out = []
        k = 0
        while ins is not None and k < count:
            out.append(_instruction_line(ins))
            ins = ins.getNext()
            k += 1
        return "\n".join(out) if out else "no instruction"


def disf(h: ProgramHandle, where: str) -> str:
    """Whole-function disassembly."""
    with h.lock:
        addr = parse_address(h, where)
        fn = _function_containing(h, addr)
        if fn is None:
            return "no function"
        lines = [f"// {fn.getName()} @ {fn.getEntryPoint()}"]
        for ins in h.program.getListing().getInstructions(fn.getBody(), True):
            lines.append(_instruction_line(ins))
        return "\n".join(lines)


def func(h: ProgramHandle, where: str) -> str:
    with h.lock:
        fn = _function_containing(h, parse_address(h, where))
        if fn is None:
            return "none"
        body = fn.getBody()
        return f"{fn.getName()} {body.getMinAddress()} - {body.getMaxAddress()}"


def xrefs(h: ProgramHandle, where: str, limit: int = 5000) -> str:
    """References *to* an address."""
    with h.lock:
        addr = parse_address(h, where)
        lines = []
        for ref in h.program.getReferenceManager().getReferencesTo(addr):
            fn = _function_containing(h, ref.getFromAddress())
            lines.append(f"{ref.getFromAddress()} {ref.getReferenceType()} in {_fn_label(fn)}")
            if len(lines) >= limit:
                lines.append(f"... (limit {limit} reached)")
                break
        return "\n".join(lines) if lines else "(no references)"


def xrefs_from(h: ProgramHandle, where: str) -> str:
    """References *from* an address (one instruction/data item)."""
    with h.lock:
        addr = parse_address(h, where)
        lines = []
        for ref in h.program.getReferenceManager().getReferencesFrom(addr):
            to = ref.getToAddress()
            fn = _function_containing(h, to)
            lines.append(f"{addr} -> {to} {ref.getReferenceType()} ({_fn_label(fn)})")
        return "\n".join(lines) if lines else "(no references)"


def callers(h: ProgramHandle, where: str, limit: int = 5000) -> str:
    """Call sites of the function containing an address."""
    with h.lock:
        fn = _function_containing(h, parse_address(h, where))
        if fn is None:
            return "none"
        lines = []
        for ref in h.program.getReferenceManager().getReferencesTo(fn.getEntryPoint()):
            caller = _function_containing(h, ref.getFromAddress())
            lines.append(f"{ref.getFromAddress()} {ref.getReferenceType()} in {_fn_label(caller)}")
            if len(lines) >= limit:
                lines.append(f"... (limit {limit} reached)")
                break
        return "\n".join(lines) if lines else "(no callers)"


def callees(h: ProgramHandle, where: str) -> str:
    """Functions called directly by the function containing an address."""
    from ghidra.util.task import TaskMonitor

    with h.lock:
        fn = _function_containing(h, parse_address(h, where))
        if fn is None:
            return "none"
        called = sorted(fn.getCalledFunctions(TaskMonitor.DUMMY), key=lambda f: int(f.getEntryPoint().getOffset()))
        lines = [f"{fn.getName()} @ {fn.getEntryPoint()} calls {len(called)} function(s):"]
        lines += [f"  {f.getName()} @ {f.getEntryPoint()}" for f in called]
        return "\n".join(lines)
