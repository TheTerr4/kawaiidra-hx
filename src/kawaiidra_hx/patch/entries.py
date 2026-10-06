"""Patch entries in a JSON patch-entry format (named entries of file-offset based hex edits).

Only ``"type": "memory"`` entries are understood (a list of {offset, dllName, dataDisabled, dataEnabled}).
Other entry types ("union", "number", ...) are kept verbatim and flagged ``supported = False`` so a verify
or apply run reports them as skipped instead of silently ignoring them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union


class PatchFormatError(ValueError):
    """The JSON is not a patch list we can read."""


@dataclass(frozen=True)
class Patch:
    offset: int
    dll_name: str | None
    disabled: bytes  # original bytes (what the file contains before patching)
    enabled: bytes  # patched bytes

    def __post_init__(self) -> None:
        if len(self.disabled) != len(self.enabled):
            raise PatchFormatError(
                f"patch at offset {self.offset}: dataDisabled and dataEnabled differ in length "
                f"({len(self.disabled)} vs {len(self.enabled)}); only same-length in-place edits are supported"
            )
        if not self.disabled:
            raise PatchFormatError(f"patch at offset {self.offset}: empty data")

    @property
    def length(self) -> int:
        return len(self.disabled)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"offset": self.offset}
        if self.dll_name is not None:
            d["dllName"] = self.dll_name
        d["dataDisabled"] = self.disabled.hex().upper()
        d["dataEnabled"] = self.enabled.hex().upper()
        return d


@dataclass
class Entry:
    name: str
    description: str = ""
    game_code: str | None = None
    type: str = "memory"
    patches: list[Patch] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def supported(self) -> bool:
        return self.type == "memory"

    def to_dict(self) -> dict[str, Any]:
        if not self.supported:
            return dict(self.raw)
        d: dict[str, Any] = {"name": self.name}
        if self.description:
            d["description"] = self.description
        if self.game_code is not None:
            d["gameCode"] = self.game_code
        d["type"] = self.type
        d["patches"] = [p.to_dict() for p in self.patches]
        return d


def _hex(value: Any, where: str) -> bytes:
    if not isinstance(value, str):
        raise PatchFormatError(f"{where}: expected a hex string, got {type(value).__name__}")
    s = value.replace(" ", "")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise PatchFormatError(f"{where}: bad hex string {value!r}") from e


def entries_from_data(data: Any) -> list[Entry]:
    if isinstance(data, dict):  # tolerate a single entry
        data = [data]
    if not isinstance(data, list):
        raise PatchFormatError("patch file must be a JSON list of entries")
    out: list[Entry] = []
    for i, raw in enumerate(data):
        if not isinstance(raw, dict) or "name" not in raw:
            raise PatchFormatError(f"entry #{i} has no name")
        etype = raw.get("type", "memory")
        entry = Entry(
            name=raw["name"],
            description=raw.get("description", ""),
            game_code=raw.get("gameCode"),
            type=etype,
            raw=raw,
        )
        if etype == "memory":
            for j, p in enumerate(raw.get("patches", [])):
                where = f"entry {raw['name']!r} patch #{j}"
                if "offset" not in p:
                    raise PatchFormatError(f"{where}: missing offset")
                entry.patches.append(
                    Patch(
                        offset=int(p["offset"]),
                        dll_name=p.get("dllName"),
                        disabled=_hex(p.get("dataDisabled"), where + " dataDisabled"),
                        enabled=_hex(p.get("dataEnabled"), where + " dataEnabled"),
                    )
                )
        out.append(entry)
    return out


def load_entries(source: Union[str, Path]) -> list[Entry]:
    """Load entries from a JSON file path."""
    try:
        data = json.loads(Path(source).read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as e:
        raise PatchFormatError(f"{source}: invalid JSON: {e}") from e
    return entries_from_data(data)


def dump_entries(entries: list[Entry], *, indent: int = 4) -> str:
    return json.dumps([e.to_dict() for e in entries], indent=indent) + "\n"


def select_entries(entries: list[Entry], names: list[str] | None) -> list[Entry]:
    """Pick entries by exact name (or 1-based index). ``None``/empty selects all."""
    if not names:
        return list(entries)
    chosen: list[Entry] = []
    for n in names:
        if n.isdigit() and 1 <= int(n) <= len(entries):
            chosen.append(entries[int(n) - 1])
            continue
        match = [e for e in entries if e.name == n]
        if not match:
            raise PatchFormatError(f"no entry named {n!r}; available: {[e.name for e in entries]}")
        chosen.extend(match)
    return chosen
