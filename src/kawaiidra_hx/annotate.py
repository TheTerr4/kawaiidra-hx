"""Write operations (rename, comment). Require a program opened with write access; nothing persists until ``save``."""

from __future__ import annotations

from .core.errors import KhxError
from .core.resolve import parse_address
from .core.session import ProgramHandle

COMMENT_KINDS = {"eol": "EOL_COMMENT", "pre": "PRE_COMMENT", "post": "POST_COMMENT", "plate": "PLATE_COMMENT", "repeatable": "REPEATABLE_COMMENT"}


def rename(h: ProgramHandle, where: str, new_name: str) -> str:
    """Rename the function at/containing ``where``; if there is no function, create/rename a label at the address."""
    from ghidra.program.model.symbol import SourceType

    if not new_name or any(c.isspace() for c in new_name):
        raise KhxError("new name must be non-empty and contain no whitespace")
    with h.lock:
        addr = parse_address(h, where)
        with h.transaction(f"rename {where} -> {new_name}"):
            fn = h.program.getFunctionManager().getFunctionContaining(addr)
            if fn is not None and fn.getEntryPoint().equals(addr):
                old = str(fn.getName())
                fn.setName(new_name, SourceType.USER_DEFINED)
                return f"function {old} @ {addr} renamed to {new_name}"
            symtab = h.program.getSymbolTable()
            sym = symtab.getPrimarySymbol(addr)
            if sym is not None:
                old = str(sym.getName())
                sym.setName(new_name, SourceType.USER_DEFINED)
                return f"symbol {old} @ {addr} renamed to {new_name}"
            symtab.createLabel(addr, new_name, SourceType.USER_DEFINED)
            return f"label {new_name} created @ {addr}"


def set_comment(h: ProgramHandle, where: str, text: str, kind: str = "eol") -> str:
    from ghidra.program.model.listing import CodeUnit

    key = COMMENT_KINDS.get(kind.lower())
    if key is None:
        raise KhxError(f"comment kind must be one of {', '.join(COMMENT_KINDS)}")
    with h.lock:
        addr = parse_address(h, where)
        with h.transaction(f"comment @ {where}"):
            h.program.getListing().setComment(addr, getattr(CodeUnit, key), text)
        return f"{kind} comment set @ {addr}"
