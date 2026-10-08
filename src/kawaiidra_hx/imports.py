"""Resolve imports-by-ordinal from the libraries shipped next to a module.

A module that imports a library by ordinal (names stripped) shows ``Ordinal_12`` in Ghidra; the library's export table says which export each ordinal
is. Some libraries export readable names, others hashed or generated ones; ``skip_regex`` leaves the latter alone (they are stable per library
generation, so applying them is still useful for comparing builds: leave it unset to apply everything). Works on the PE import table (no Ghidra) and
renames external locations in a Ghidra program, reversibly (Ghidra keeps the original imported name).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .pe import PEImage


@dataclass
class ResolvedLibrary:
    dll: str
    found_at: Optional[str] = None
    ordinal_imports: int = 0
    resolved: dict[int, str] = field(default_factory=dict)  # ordinal -> export name
    skipped: int = 0  # exports whose name matched ``skip_regex``
    unresolved: list[int] = field(default_factory=list)


def find_library(name: str, dirs: Iterable[Path]) -> Optional[Path]:
    for d in dirs:
        p = Path(d)
        if p.is_file():
            p = p.parent
        cand = p / name
        if cand.is_file():
            return cand
        for f in p.iterdir() if p.is_dir() else ():
            if f.is_file() and f.name.lower() == name.lower():
                return f
    return None


def resolve_ordinals(image: PEImage, dirs: Iterable[Path], *, skip_regex: str | None = None) -> list[ResolvedLibrary]:
    """For every library the module imports by ordinal: which export each ordinal is, from the library file found in ``dirs``."""
    dirs = list(dirs)
    skip = re.compile(skip_regex) if skip_regex else None
    out: list[ResolvedLibrary] = []
    for lib in image.imports:
        ords = sorted({s.ordinal for s in lib.symbols if s.name is None and s.ordinal is not None})
        if not ords:
            continue
        r = ResolvedLibrary(lib.dll, ordinal_imports=len(ords))
        path = find_library(lib.dll, dirs)
        if path is not None:
            r.found_at = str(path)
            try:
                ex = PEImage(path).exports
            except Exception:
                ex = None
            names = {e.ordinal: e.name for e in (ex.exports if ex else []) if e.name}
            for o in ords:
                n = names.get(o)
                if n is None:
                    r.unresolved.append(o)
                elif skip is not None and skip.search(n):
                    r.skipped += 1
                else:
                    r.resolved[o] = n
        else:
            r.unresolved = list(ords)
        out.append(r)
    return out


def external_renames(libs: list[ResolvedLibrary]) -> dict[tuple[str, str], str]:
    """The ``annotate.rename_externals`` mapping (``(LIB.DLL, "Ordinal_N") -> name``)."""
    return {(r.dll.upper(), f"Ordinal_{o}"): n for r in libs for o, n in r.resolved.items()}


def format_resolution(libs: list[ResolvedLibrary]) -> str:
    if not libs:
        return "(no library is imported by ordinal)"
    lines = []
    for r in libs:
        where = r.found_at or "NOT FOUND in the given folders"
        lines.append(f"{r.dll:<26} {r.ordinal_imports:>3} by ordinal: {len(r.resolved)} resolved, {r.skipped} skipped by name pattern, {len(r.unresolved)} unresolved   [{where}]")
        sample = list(r.resolved.items())[:4]
        if sample:
            lines.append("    e.g. " + ", ".join(f"#{o}={n}" for o, n in sample))
    return "\n".join(lines)


def default_dirs(h, binary: "str | Path | None" = None, extra: Iterable[Path] = ()) -> list[Path]:
    """Folders to look for sibling libraries in: ``extra``, the folder of ``binary``, and the folder Ghidra recorded for the program's source file."""
    dirs = [Path(d) for d in extra]
    if binary:
        dirs.append(Path(binary).parent)
    try:
        raw = str(h.program.getExecutablePath() or "")
        dirs.append(Path(raw[1:] if re.match(r"^/[A-Za-z]:", raw) else raw).parent)
    except Exception:
        pass
    return [d for d in dirs if d.is_dir()]
