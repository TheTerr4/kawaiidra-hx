"""PE data-directory readers that work on the raw file bytes (pure Python, no Ghidra).

``parse_pe`` only needs the first 64 KiB; these functions take the *whole* file (``bytes``) plus the ``PEInfo`` from
``parse_pe`` and decode exports, imports (regular and delay-load), base relocations and the CodeView/PDB record.
They are defensive: a malformed table yields what could be read plus nothing worse than a ``PEError`` for impossible input.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Iterator

from .parser import NotMappedError, PEError, PEInfo, Section

_MAX_STR = 1024
_MAX_ITEMS = 1_000_000


def _cstr(data: bytes, off: int, limit: int = _MAX_STR) -> str:
    end = data.find(b"\0", off, off + limit)
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("latin-1")


def _off(pe: PEInfo, rva: int) -> int | None:
    try:
        return pe.rva_to_offset(rva)
    except NotMappedError:
        return None


# --- exports --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Export:
    ordinal: int
    name: str | None
    rva: int
    forwarder: str | None = None


@dataclass(frozen=True)
class ExportTable:
    module_name: str  # the name inside the export directory (often differs from the file name)
    timestamp: int
    ordinal_base: int
    exports: tuple[Export, ...]

    def by_name(self, name: str) -> Export | None:
        return next((e for e in self.exports if e.name == name), None)


def read_exports(data: bytes, pe: PEInfo) -> ExportTable | None:
    rva, size = pe.directory("export")
    if not rva:
        return None
    base = _off(pe, rva)
    if base is None or base + 40 > len(data):
        raise PEError("export directory is outside the file")
    _chars, ts, _maj, _min, name_rva, ord_base, n_funcs, n_names, funcs_rva, names_rva, ords_rva = struct.unpack_from(
        "<IIHHIIIIIII", data, base
    )
    n_funcs, n_names = min(n_funcs, _MAX_ITEMS), min(n_names, _MAX_ITEMS)
    name_off = _off(pe, name_rva)
    module = _cstr(data, name_off) if name_off is not None else ""
    funcs_off, names_off, ords_off = _off(pe, funcs_rva), _off(pe, names_rva), _off(pe, ords_rva)
    names_by_index: dict[int, str] = {}
    if n_names and names_off is not None and ords_off is not None:
        for i in range(n_names):
            (nrva,) = struct.unpack_from("<I", data, names_off + 4 * i)
            (idx,) = struct.unpack_from("<H", data, ords_off + 2 * i)
            o = _off(pe, nrva)
            if o is not None:
                names_by_index[idx] = _cstr(data, o)
    out: list[Export] = []
    if funcs_off is not None:
        for i in range(n_funcs):
            (frva,) = struct.unpack_from("<I", data, funcs_off + 4 * i)
            if frva == 0:
                continue
            forwarder = None
            if rva <= frva < rva + size:  # points back into the export directory: a forwarder string
                fo = _off(pe, frva)
                forwarder = _cstr(data, fo) if fo is not None else None
            out.append(Export(ordinal=ord_base + i, name=names_by_index.get(i), rva=frva, forwarder=forwarder))
    return ExportTable(module_name=module, timestamp=ts, ordinal_base=ord_base, exports=tuple(out))


# --- imports --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ImportedSymbol:
    name: str | None  # None when imported by ordinal
    ordinal: int | None
    hint: int
    iat_rva: int  # where the loader writes the resolved address

    @property
    def label(self) -> str:
        return self.name if self.name is not None else f"#{self.ordinal}"


@dataclass(frozen=True)
class ImportedLibrary:
    dll: str
    symbols: tuple[ImportedSymbol, ...]
    delay: bool = False

    @property
    def by_ordinal(self) -> int:
        return sum(1 for s in self.symbols if s.name is None)


def _read_thunks(data: bytes, pe: PEInfo, thunk_rva: int, iat_rva: int) -> list[ImportedSymbol]:
    width = 8 if pe.is_64bit else 4
    flag = 1 << (width * 8 - 1)
    off = _off(pe, thunk_rva)
    out: list[ImportedSymbol] = []
    if off is None:
        return out
    fmt = "<Q" if width == 8 else "<I"
    for i in range(_MAX_ITEMS):
        if off + width * (i + 1) > len(data):
            break
        (v,) = struct.unpack_from(fmt, data, off + width * i)
        if v == 0:
            break
        iat = iat_rva + width * i
        if v & flag:
            out.append(ImportedSymbol(name=None, ordinal=v & 0xFFFF, hint=0, iat_rva=iat))
        else:
            o = _off(pe, v & 0x7FFFFFFF)
            if o is None or o + 2 > len(data):
                out.append(ImportedSymbol(name="<bad name rva>", ordinal=None, hint=0, iat_rva=iat))
                continue
            (hint,) = struct.unpack_from("<H", data, o)
            out.append(ImportedSymbol(name=_cstr(data, o + 2), ordinal=None, hint=hint, iat_rva=iat))
    return out


def read_imports(data: bytes, pe: PEInfo) -> list[ImportedLibrary]:
    """Regular imports followed by delay-load imports (``delay=True``)."""
    libs: list[ImportedLibrary] = []
    rva, _size = pe.directory("import")
    base = _off(pe, rva) if rva else None
    if base is not None:
        for i in range(_MAX_ITEMS):
            o = base + 20 * i
            if o + 20 > len(data):
                break
            oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, o)
            if not (oft or name_rva or ft):
                break
            n_off = _off(pe, name_rva)
            dll = _cstr(data, n_off) if n_off is not None else "<bad name>"
            libs.append(ImportedLibrary(dll=dll, symbols=tuple(_read_thunks(data, pe, oft or ft, ft))))
    drva, _dsize = pe.directory("delay_import")
    dbase = _off(pe, drva) if drva else None
    if dbase is not None:
        for i in range(_MAX_ITEMS):
            o = dbase + 32 * i
            if o + 32 > len(data):
                break
            attrs, name_rva, _hmod, iat_rva, int_rva, _bound, _unload, _ts = struct.unpack_from("<IIIIIIII", data, o)
            if not (name_rva or int_rva):
                break
            if not attrs & 1:  # pre-VC7 descriptors hold VAs, not RVAs; not worth guessing
                continue
            n_off = _off(pe, name_rva)
            dll = _cstr(data, n_off) if n_off is not None else "<bad name>"
            libs.append(ImportedLibrary(dll=dll, symbols=tuple(_read_thunks(data, pe, int_rva, iat_rva)), delay=True))
    return libs


# --- base relocations -----------------------------------------------------------------------------

REL_ABSOLUTE, REL_HIGH, REL_LOW, REL_HIGHLOW, REL_DIR64 = 0, 1, 2, 3, 10
_REL_WIDTH = {REL_HIGH: 2, REL_LOW: 2, REL_HIGHLOW: 4, REL_DIR64: 8}


def read_relocations(data: bytes, pe: PEInfo) -> dict[int, int]:
    """``{rva: width_in_bytes}`` of every position-dependent field the loader patches when the image moves.

    On x86 these are absolute addresses (HIGHLOW) and must be wildcarded in a version-independent signature;
    x64 images carry few (DIR64 pointers) because code is RIP-relative.
    """
    rva, size = pe.directory("basereloc")
    off = _off(pe, rva) if rva else None
    out: dict[int, int] = {}
    if off is None:
        return out
    end = min(off + size, len(data))
    while off + 8 <= end:
        page, block = struct.unpack_from("<II", data, off)
        if block < 8:
            break
        for j in range((block - 8) // 2):
            if off + 8 + 2 * j + 2 > len(data):
                break
            (entry,) = struct.unpack_from("<H", data, off + 8 + 2 * j)
            kind = entry >> 12
            if kind == REL_ABSOLUTE:
                continue
            width = _REL_WIDTH.get(kind)
            if width:
                out[page + (entry & 0xFFF)] = width
        off += block
    return out


def relocated_offsets(data: bytes, pe: PEInfo) -> set[int]:
    """File offsets of every byte covered by a base relocation (file-backed ones only)."""
    covered: set[int] = set()
    for rva, width in read_relocations(data, pe).items():
        o = _off(pe, rva)
        if o is not None:
            covered.update(range(o, o + width))
    return covered


# --- debug / PDB ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class CodeView:
    kind: str  # "RSDS" (PDB 7.0) or "NB10"
    guid: str
    age: int
    path: str


def read_codeview(data: bytes, pe: PEInfo) -> CodeView | None:
    rva, size = pe.directory("debug")
    base = _off(pe, rva) if rva else None
    if base is None:
        return None
    for i in range(size // 28):
        o = base + 28 * i
        if o + 28 > len(data):
            break
        _chars, _ts, _maj, _min, dtype, dsize, _araw, praw = struct.unpack_from("<IIHHIIII", data, o)
        if dtype != 2 or not praw or praw + 24 > len(data):  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        sig = data[praw : praw + 4]
        if sig == b"RSDS":
            g = data[praw + 4 : praw + 20]
            (age,) = struct.unpack_from("<I", data, praw + 20)
            guid = "{%08X-%04X-%04X-%s-%s}" % (
                struct.unpack_from("<I", g, 0)[0], struct.unpack_from("<H", g, 4)[0], struct.unpack_from("<H", g, 6)[0],
                g[8:10].hex().upper(), g[10:16].hex().upper(),
            )  # fmt: skip
            return CodeView("RSDS", guid, age, _cstr(data, praw + 24))
        if sig == b"NB10":
            return CodeView("NB10", "", struct.unpack_from("<I", data, praw + 12)[0], _cstr(data, praw + 16))
    return None


# --- sections -------------------------------------------------------------------------------------


def section_entropy(data: bytes, section: Section) -> float:
    """Shannon entropy (bits/byte, 0..8) of a section's raw bytes; > ~7.2 usually means packed/encrypted."""
    raw = data[section.raw_pointer : section.raw_end]
    if not raw:
        return 0.0
    counts = [0] * 256
    for b in raw:
        counts[b] += 1
    n = len(raw)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def iter_symbols(libs: list[ImportedLibrary]) -> Iterator[tuple[str, ImportedSymbol]]:
    for lib in libs:
        for s in lib.symbols:
            yield lib.dll, s
