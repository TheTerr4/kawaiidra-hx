"""Minimal PE header reader (pure Python, no Ghidra/JVM needed).

JSON patch files address bytes by *file offset*, while Ghidra shows *virtual
addresses*. This module does that conversion straight from the section table:

    RVA = section.virtual_address + (file_offset - section.raw_pointer)
    VA  = image_base + RVA

The mapping differs per section and per build (e.g. one DLL's .text is +0xA00 while an older build of the same DLL
has +0xC00), so it must always come from the real headers of the exact file being patched.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C0: "arm", 0x1C4: "armnt"}
_PE32 = 0x10B
_PE32_PLUS = 0x20B

# Index in the optional header's data-directory table.
DIRECTORY_NAMES = (
    "export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
    "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr", "reserved",
)  # fmt: skip


class PEError(ValueError):
    """The data is not a PE image we can parse."""


class NotMappedError(ValueError):
    """The offset/address is not backed by anything in the image."""


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int  # RVA
    virtual_size: int
    raw_pointer: int
    raw_size: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        """Bytes the loader maps in memory for this section."""
        return self.virtual_size or self.raw_size

    @property
    def rva_end(self) -> int:
        return self.virtual_address + self.mapped_size

    @property
    def raw_end(self) -> int:
        return self.raw_pointer + self.raw_size

    @property
    def delta(self) -> int:
        """VA - file offset (before adding the image base)."""
        return self.virtual_address - self.raw_pointer

    @property
    def flags(self) -> str:
        c = self.characteristics
        return ("R" if c & 0x40000000 else "-") + ("W" if c & 0x80000000 else "-") + ("X" if c & 0x20000000 else "-")


@dataclass(frozen=True)
class PEInfo:
    path: str
    machine: str
    is_64bit: bool
    is_dll: bool
    image_base: int
    size_of_image: int
    size_of_headers: int
    timestamp: int
    sections: tuple[Section, ...] = field(default_factory=tuple)
    entry_rva: int = 0  # AddressOfEntryPoint
    dll_characteristics: int = 0
    directories: tuple[tuple[int, int], ...] = ()  # (rva, size) per DIRECTORY_NAMES entry; ``security`` is a FILE offset

    # --- identity ----------------------------------------------------------------------------

    def pe_identifier(self, game_code: str) -> str:
        """Build identifier ``{code}-{TimeDateStamp:x}_{AddressOfEntryPoint:x}`` (lowercase hex), e.g. ``ABC-12345678_1000``."""
        return f"{game_code}-{self.timestamp:x}_{self.entry_rva:x}"

    def directory(self, name: str) -> tuple[int, int]:
        """``(rva, size)`` of a data directory by name; ``(0, 0)`` when absent."""
        try:
            i = DIRECTORY_NAMES.index(name)
        except ValueError:
            raise KeyError(name) from None
        return self.directories[i] if i < len(self.directories) else (0, 0)

    # --- conversions -------------------------------------------------------------------------

    def section_by_name(self, name: str) -> Section:
        for s in self.sections:
            if s.name == name:
                return s
        raise KeyError(name)

    def section_for_offset(self, offset: int) -> Section | None:
        for s in self.sections:
            if s.raw_size and s.raw_pointer <= offset < s.raw_end:
                return s
        return None

    def section_for_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.virtual_address <= rva < s.rva_end:
                return s
        return None

    def offset_to_rva(self, offset: int) -> int:
        if 0 <= offset < self.size_of_headers:
            return offset
        s = self.section_for_offset(offset)
        if s is None:
            raise NotMappedError(f"file offset 0x{offset:X} is not inside any section's raw data")
        return s.virtual_address + (offset - s.raw_pointer)

    def offset_to_va(self, offset: int) -> int:
        return self.image_base + self.offset_to_rva(offset)

    def rva_to_offset(self, rva: int) -> int:
        if 0 <= rva < self.size_of_headers:
            return rva
        s = self.section_for_rva(rva)
        if s is None:
            raise NotMappedError(f"RVA 0x{rva:X} is not inside any section")
        rel = rva - s.virtual_address
        if rel >= s.raw_size:
            raise NotMappedError(
                f"RVA 0x{rva:X} is in {s.name} but past its file-backed bytes (zero-filled at load time)"
            )
        return s.raw_pointer + rel

    def va_to_offset(self, va: int) -> int:
        if va < self.image_base:
            raise NotMappedError(f"VA 0x{va:X} is below the image base 0x{self.image_base:X}")
        return self.rva_to_offset(va - self.image_base)

    def describe_offset(self, offset: int) -> str:
        va = self.offset_to_va(offset)
        s = self.section_for_offset(offset)
        where = s.name if s else "headers"
        return f"file 0x{offset:X} -> VA 0x{va:X} ({where})"


# --- parsing ---------------------------------------------------------------------------------


def parse_pe(source: Union[str, Path, bytes, bytearray]) -> PEInfo:
    """Parse the headers of a PE file (path) or of an in-memory image (bytes)."""
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source[:0x10000])
        label = "<bytes>"
    else:
        label = str(source)
        with open(source, "rb") as f:
            data = f.read(0x10000)

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError(f"{label}: missing MZ header")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise PEError(f"{label}: missing PE signature")

    coff = e_lfanew + 4
    machine, nsections, timestamp, _symptr, _nsyms, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    opt = coff + 20
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic == _PE32:
        (image_base,) = struct.unpack_from("<I", data, opt + 28)
        is64 = False
    elif magic == _PE32_PLUS:
        (image_base,) = struct.unpack_from("<Q", data, opt + 24)
        is64 = True
    else:
        raise PEError(f"{label}: unknown optional-header magic 0x{magic:X}")
    size_of_image, size_of_headers = struct.unpack_from("<II", data, opt + 56)
    (entry_rva,) = struct.unpack_from("<I", data, opt + 16)
    (dll_chars,) = struct.unpack_from("<H", data, opt + 70)
    dir_count_at = opt + (108 if is64 else 92)
    (n_dirs,) = struct.unpack_from("<I", data, dir_count_at)
    n_dirs = min(n_dirs, 16, max(0, (opt_size - (dir_count_at + 4 - opt)) // 8))
    directories = tuple(struct.unpack_from("<II", data, dir_count_at + 4 + 8 * i) for i in range(n_dirs))

    table = opt + opt_size
    if table + nsections * 40 > len(data):
        raise PEError(f"{label}: section table runs past the first 64 KiB")
    sections = []
    for i in range(nsections):
        raw_name, vsize, va, rsize, rptr, _r, _l, _nr, _nl, chars = struct.unpack_from("<8sIIIIIIHHI", data, table + 40 * i)
        sections.append(
            Section(
                name=raw_name.rstrip(b"\0").decode("latin-1"),
                virtual_address=va,
                virtual_size=vsize,
                raw_pointer=rptr,
                raw_size=rsize,
                characteristics=chars,
            )
        )
    return PEInfo(
        path=label,
        machine=MACHINES.get(machine, f"0x{machine:X}"),
        is_64bit=is64,
        is_dll=bool(characteristics & 0x2000),
        image_base=image_base,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        timestamp=timestamp,
        sections=tuple(sections),
        entry_rva=entry_rva,
        dll_characteristics=dll_chars,
        directories=directories,
    )


def format_sections(pe: PEInfo) -> str:
    """Human-readable header summary (used by the CLI and MCP tools)."""
    lines = [
        f"{pe.path}",
        f"  machine={pe.machine} {'PE32+' if pe.is_64bit else 'PE32'} {'DLL' if pe.is_dll else 'EXE'}"
        f" image_base=0x{pe.image_base:X} size_of_image=0x{pe.size_of_image:X} headers=0x{pe.size_of_headers:X}",
        f"  {'section':<10}{'RVA':>10}{'vsize':>10}{'raw_ptr':>10}{'raw_size':>10}  flags  VA-offset",
    ]
    for s in pe.sections:
        lines.append(
            f"  {s.name:<10}{s.virtual_address:>#10x}{s.virtual_size:>#10x}{s.raw_pointer:>#10x}"
            f"{s.raw_size:>#10x}  {s.flags}    +0x{s.delta & 0xFFFFFFFF:X}"
        )
    return "\n".join(lines)
