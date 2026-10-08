"""A whole PE file in memory: header info plus lazily decoded tables and an identity record."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path
from typing import Union

from . import tables
from .parser import PEInfo, parse_pe


@dataclass(frozen=True)
class PEIdentity:
    """Everything that says *which build* a binary is."""

    path: str
    size: int
    sha256: str
    machine: str
    is_64bit: bool
    is_dll: bool
    image_base: int
    timestamp: int
    entry_rva: int

    @property
    def build_time(self) -> str:
        """The linker timestamp as UTC ISO text (may be fake for reproducible builds)."""
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def pe_identifier(self, game_code: str) -> str:
        return f"{game_code}-{self.timestamp:x}_{self.entry_rva:x}"


class PEImage:
    """Read-only view of a PE file. Reads the whole file once; decodes tables on first use."""

    def __init__(self, source: Union[str, Path, bytes, bytearray]):
        if isinstance(source, (bytes, bytearray)):
            self.path = "<bytes>"
            self.data = bytes(source)
        else:
            self.path = str(source)
            self.data = Path(source).read_bytes()
        self.info: PEInfo = parse_pe(self.data)

    @cached_property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @cached_property
    def identity(self) -> PEIdentity:
        i = self.info
        return PEIdentity(
            path=self.path, size=len(self.data), sha256=self.sha256, machine=i.machine, is_64bit=i.is_64bit,
            is_dll=i.is_dll, image_base=i.image_base, timestamp=i.timestamp, entry_rva=i.entry_rva,
        )  # fmt: skip

    @cached_property
    def exports(self) -> tables.ExportTable | None:
        return tables.read_exports(self.data, self.info)

    @cached_property
    def imports(self) -> list[tables.ImportedLibrary]:
        return tables.read_imports(self.data, self.info)

    @cached_property
    def relocations(self) -> dict[int, int]:
        return tables.read_relocations(self.data, self.info)

    @cached_property
    def codeview(self) -> tables.CodeView | None:
        return tables.read_codeview(self.data, self.info)

    def relocated_offsets(self) -> set[int]:
        return tables.relocated_offsets(self.data, self.info)

    def entropy(self, section_name: str) -> float:
        return tables.section_entropy(self.data, self.info.section_by_name(section_name))
