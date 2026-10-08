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


def _code_unit_start(h: ProgramHandle, addr):
    """Start of the code unit containing ``addr`` (comments and labels belong on unit starts); ``addr`` itself if none."""
    cu = h.program.getListing().getCodeUnitContaining(addr)
    return cu.getMinAddress() if cu is not None else addr


def add_label(h: ProgramHandle, where: str, name: str, *, snap_to_unit: bool = True, allow_function_entry: bool = False) -> str:
    """Create label ``name`` at ``where`` (idempotent: an existing label of that name at the address is left alone).

    A label on a function's entry point makes Ghidra *rename the function* (it becomes the primary symbol), so that is refused
    unless ``allow_function_entry``; the return text then starts with ``label ... skipped``.
    """
    from ghidra.program.model.symbol import SourceType

    if not name or any(c.isspace() for c in name):
        raise KhxError("label must be non-empty and contain no whitespace")
    with h.lock:
        addr = parse_address(h, where)
        if snap_to_unit:
            addr = _code_unit_start(h, addr)
        if not allow_function_entry:
            fn = h.program.getFunctionManager().getFunctionAt(addr)
            if fn is not None:
                return f"label {name} skipped @ {addr}: function entry (a label here would rename {fn.getName()})"
        symtab = h.program.getSymbolTable()
        if any(str(s.getName()) == name for s in symtab.getSymbols(addr)):
            return f"label {name} already at {addr}"
        with h.transaction(f"label {name}"):
            symtab.createLabel(addr, name, SourceType.USER_DEFINED)
        return f"label {name} created @ {addr}"


def add_bookmark(h: ProgramHandle, where: str, category: str, comment: str, *, snap_to_unit: bool = True) -> str:
    """Set a Note bookmark. Ghidra keeps one bookmark per (address, type, category), so a second call at the same address
    appends its text (`` | ``-joined) unless that text is already there: re-running never duplicates."""
    from ghidra.program.model.listing import BookmarkType

    with h.lock:
        addr = parse_address(h, where)
        if snap_to_unit:
            addr = _code_unit_start(h, addr)
        bm = h.program.getBookmarkManager()
        old = bm.getBookmark(addr, BookmarkType.NOTE, category)
        parts = str(old.getComment()).split(" | ") if old is not None and old.getComment() else []
        if comment in parts:
            return f"bookmark [{category}] @ {addr} (already set)"
        with h.transaction(f"bookmark {category}"):
            bm.setBookmark(addr, BookmarkType.NOTE, category, " | ".join(parts + [comment]))
        return f"bookmark [{category}] @ {addr}"


def set_tagged_comment(h: ProgramHandle, where: str, tag: str, text: str, kind: str = "eol", *, snap_to_unit: bool = True) -> str:
    """Upsert one comment line ``"<tag> <text>"``: a previous line starting with the same ``tag`` is replaced, other lines
    (yours, other tags) are kept. Re-running an annotation therefore never duplicates or clobbers anything."""
    from ghidra.program.model.listing import CodeUnit

    key = COMMENT_KINDS.get(kind.lower())
    if key is None:
        raise KhxError(f"comment kind must be one of {', '.join(COMMENT_KINDS)}")
    with h.lock:
        addr = parse_address(h, where)
        if snap_to_unit:
            addr = _code_unit_start(h, addr)
        ctype = getattr(CodeUnit, key)
        listing = h.program.getListing()
        existing = listing.getComment(ctype, addr)
        lines = [ln for ln in (str(existing).split("\n") if existing else []) if not ln.startswith(tag)]
        lines.append(f"{tag} {text}")
        with h.transaction(f"comment {tag} @ {where}"):
            listing.setComment(addr, ctype, "\n".join(lines))
        return f"{kind} comment {tag} @ {addr}"


def clear_tagged(h: ProgramHandle, tag_prefix: str, *, bookmark_category: str | None = None, label_prefix: str | None = None) -> dict[str, int]:
    """Undo tagged annotations: delete comment lines starting with ``tag_prefix``, bookmarks of ``bookmark_category``
    and labels whose name starts with ``label_prefix``. Returns counts."""
    from ghidra.program.model.listing import CodeUnit
    from ghidra.util.task import TaskMonitor

    counts = {"comment_lines": 0, "bookmarks": 0, "labels": 0}
    with h.lock, h.transaction(f"clear {tag_prefix}"):
        listing = h.program.getListing()
        for key in COMMENT_KINDS.values():
            ctype = getattr(CodeUnit, key)
            for addr in list(listing.getCommentAddressIterator(ctype, h.program.getMemory(), True)):
                existing = listing.getComment(ctype, addr)
                if not existing or tag_prefix not in str(existing):
                    continue
                lines = str(existing).split("\n")
                keep = [ln for ln in lines if not ln.startswith(tag_prefix)]
                if len(keep) != len(lines):
                    counts["comment_lines"] += len(lines) - len(keep)
                    listing.setComment(addr, ctype, "\n".join(keep) if keep else None)
        if bookmark_category:
            bm = h.program.getBookmarkManager()
            before = int(bm.getBookmarkCount())
            bm.removeBookmarks("Note", bookmark_category, TaskMonitor.DUMMY)
            counts["bookmarks"] = before - int(bm.getBookmarkCount())
        if label_prefix:
            from ghidra.program.model.symbol import SourceType, SymbolType

            for sym in list(h.program.getSymbolTable().getSymbolIterator(label_prefix + "*", True)):
                if not str(sym.getName()).startswith(label_prefix):
                    continue
                if sym.getSymbolType() == SymbolType.FUNCTION:
                    # never delete a function; give back its default name (older runs labelled function entries)
                    fn = h.program.getFunctionManager().getFunctionAt(sym.getAddress())
                    if fn is not None:
                        fn.setName(None, SourceType.DEFAULT)  # back to FUN_<address>
                        counts["functions_renamed_back"] = counts.get("functions_renamed_back", 0) + 1
                elif sym.delete():
                    counts["labels"] += 1
    return counts


def rename_externals(h: ProgramHandle, renames: dict[tuple[str, str], str], *, restore: bool = False) -> dict[str, int]:
    """Rename imported (external) locations. ``renames`` maps ``(LIBRARY.DLL upper-case, imported name such as "Ordinal_12")`` to the
    name to show. Ghidra keeps the original imported name, so ``restore=True`` puts ``Ordinal_N`` back for the same keys.
    Returns counts: ``renamed``, ``already``, ``unmatched`` (keys with no import in the program)."""
    from ghidra.program.model.symbol import SourceType

    counts = {"renamed": 0, "already": 0, "unmatched": 0}
    seen: set[tuple[str, str]] = set()
    with h.lock, h.transaction("restore imports" if restore else "resolve imports"):
        em = h.program.getExternalManager()
        for lib in list(em.getExternalLibraryNames()):
            for loc in list(em.getExternalLocations(lib)):
                label = str(loc.getLabel())
                orig = loc.getOriginalImportedName()
                imported = str(orig) if orig else label  # the name the import table used ("Ordinal_12" / "init_module")
                key = (str(lib).upper(), imported)
                if key not in renames:
                    continue
                seen.add(key)
                want = imported if restore else renames[key]
                if label == want:
                    counts["already"] += 1
                    continue
                loc.setName(loc.getParentNameSpace(), want, SourceType.USER_DEFINED)
                counts["renamed"] += 1
    counts["unmatched"] = len(set(renames) - seen)
    return counts
