"""Patch files in a JSON ``patches`` format (named entries of file-offset based hex edits).

A patch file is a JSON list. Objects *without* a ``name`` are metadata headers (``{"gameCode", "version", "lastUpdated",
"source"}``) and are kept verbatim. Every other object is an entry with one of these types:

    memory     ``patches: [{offset, dllName, dataDisabled, dataEnabled}]``     (a toggle)
    union      ``patches: [{name, patch: {offset, dllName, data}}]``          (pick one option; all share offset/length)
    number     ``patch: {offset, dllName, size, min, max}``                   (little-endian integer in a range)
    signature  ``signature, replacement, dllName, offset, usage``              (found by byte pattern with ``??`` wildcards)
    group      ``id, name, description``                                       (UI grouping only, no bytes)

Entries of an unknown ``type`` are kept verbatim and flagged ``supported = False`` so verify/apply report them as
skipped instead of silently ignoring them. Unknown keys on supported entries survive a load/dump round trip.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

KNOWN_TYPES = ("memory", "union", "number", "signature", "group")
_PEID_FILE = re.compile(r"^([A-Za-z0-9]{3})-([0-9a-f]+)_([0-9a-f]+)(?:\.[^.]*)*\.json$")


class PatchFormatError(ValueError):
    """The JSON is not a patch list we can read."""


@dataclass(frozen=True)
class Patch:
    """One in-place edit of a ``memory`` entry."""

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


@dataclass(frozen=True)
class UnionOption:
    """One choice of a ``union`` entry (the spec wants one shared offset/length; a few real files differ in length)."""

    name: str
    offset: int
    data: bytes
    dll_name: str | None = None

    @property
    def length(self) -> int:
        return len(self.data)

    def to_dict(self) -> dict[str, Any]:
        p: dict[str, Any] = {"offset": self.offset}
        if self.dll_name is not None:
            p["dllName"] = self.dll_name
        p["data"] = self.data.hex().upper()
        return {"name": self.name, "patch": p}


@dataclass(frozen=True)
class NumberSpec:
    """The ``patch`` object of a ``number`` entry."""

    offset: int
    size: int
    min: int
    max: int
    dll_name: str | None = None

    def __post_init__(self) -> None:
        if self.size not in (1, 2, 4, 8):
            raise PatchFormatError(f"number patch at offset {self.offset}: size must be 1, 2, 4 or 8 (got {self.size})")
        if self.min > self.max:
            raise PatchFormatError(f"number patch at offset {self.offset}: min {self.min} > max {self.max}")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"offset": self.offset}
        if self.dll_name is not None:
            d["dllName"] = self.dll_name
        d.update({"size": self.size, "min": self.min, "max": self.max})
        return d


@dataclass(frozen=True)
class SignatureSpec:
    """A ``signature`` entry's search: ``signature`` is hex pairs with ``??``/``XX`` wildcards (spaces ignored),
    ``replacement`` is applied at ``match + offset`` (its wildcards keep the original byte), ``usage`` is the 0-based
    n-th match (positions are scanned one byte at a time, so overlapping matches count)."""

    signature: str
    replacement: str
    offset: int = 0
    usage: int = 0
    dll_name: str | None = None

    def __post_init__(self) -> None:
        sig, rep = parse_masked(self.signature), parse_masked(self.replacement)
        if self.offset < 0 or self.usage < 0:
            raise PatchFormatError("signature patch: offset and usage must be >= 0")
        if self.offset + len(rep[0]) > len(sig[0]):
            raise PatchFormatError(
                f"signature patch: offset {self.offset} + replacement ({len(rep[0])} bytes) exceeds the signature ({len(sig[0])} bytes)"
            )

    @property
    def pattern(self) -> tuple[bytes, bytes]:
        """``(bytes, mask)``; mask byte 0xFF = must match, 0x00 = wildcard."""
        return parse_masked(self.signature)

    @property
    def replace(self) -> tuple[bytes, bytes]:
        return parse_masked(self.replacement)


def parse_masked(text: str) -> tuple[bytes, bytes]:
    """Parse signature syntax: hex pairs, ``??`` or ``XX`` for a wildcard byte, spaces ignored."""
    s = "".join(str(text).split())
    if not s or len(s) % 2:
        raise PatchFormatError(f"bad signature {text!r}: needs a non-empty, even number of hex digits")
    vals, mask = bytearray(), bytearray()
    for i in range(0, len(s), 2):
        pair = s[i : i + 2]
        if pair in ("??", "xx", "XX", "Xx", "xX"):
            vals.append(0)
            mask.append(0)
        elif "?" in pair or "x" in pair.lower():
            raise PatchFormatError(f"bad signature {text!r}: half-wildcard {pair!r} (wildcards are whole bytes: ?? or XX)")
        else:
            try:
                vals.append(int(pair, 16))
            except ValueError:
                raise PatchFormatError(f"bad signature {text!r}: {pair!r} is not hex") from None
            mask.append(0xFF)
    return bytes(vals), bytes(mask)


def format_masked(data: bytes, mask: bytes) -> str:
    """Inverse of :func:`parse_masked` (uppercase hex, ``??`` for wildcards)."""
    return "".join(f"{b:02X}" if m else "??" for b, m in zip(data, mask))


@dataclass
class Entry:
    name: str
    description: str = ""
    game_code: str | None = None
    type: str = "memory"
    patches: list[Patch] = field(default_factory=list)  # memory entries
    raw: dict[str, Any] = field(default_factory=dict)
    caution: str | None = None  # None = key absent ("" is kept as an explicit empty caution)
    pe_identifier: str | None = None
    group: str | None = None
    id: str | None = None  # group entries
    options: list[UnionOption] = field(default_factory=list)  # union entries
    number: NumberSpec | None = None  # number entries
    signature: SignatureSpec | None = None  # signature entries

    @property
    def supported(self) -> bool:
        return self.type in KNOWN_TYPES

    def to_dict(self) -> dict[str, Any]:
        if not self.supported:
            return dict(self.raw)
        d: dict[str, Any] = {}
        d["name"] = self.name
        d["description"] = self.description  # the spec: "Required, but can be blank"
        if self.caution is not None:
            d["caution"] = self.caution
        if self.game_code is not None:
            d["gameCode"] = self.game_code
        d["type"] = self.type
        if self.pe_identifier is not None:
            d["peIdentifier"] = self.pe_identifier
        if self.group is not None:
            d["group"] = self.group
        if self.id is not None:
            d["id"] = self.id
        if self.type == "memory":
            d["patches"] = [p.to_dict() for p in self.patches]
        elif self.type == "union":
            d["patches"] = [o.to_dict() for o in self.options]
        elif self.type == "number" and self.number is not None:
            d["patch"] = self.number.to_dict()
        elif self.type == "signature" and self.signature is not None:
            s = self.signature
            if s.dll_name is not None:
                d["dllName"] = s.dll_name
            d["signature"] = s.signature
            d["replacement"] = s.replacement
            if s.offset:
                d["offset"] = s.offset
            if s.usage:
                d["usage"] = s.usage
        # unknown keys of supported entries survive (placed after the known ones)
        for k, v in self.raw.items():
            d.setdefault(k, v)
        return d


@dataclass
class PatchFile:
    """A loaded patch file: metadata headers + entries (+ where it came from)."""

    entries: list[Entry]
    headers: list[dict[str, Any]] = field(default_factory=list)
    path: str | None = None

    @property
    def pe_identifier(self) -> str | None:
        """From the file name (``ABC-12345678_1000.json``) or a uniform ``peIdentifier`` on all entries."""
        if self.path:
            m = _PEID_FILE.match(Path(self.path).name)
            if m:
                return f"{m.group(1)}-{m.group(2)}_{m.group(3)}"
        ids = {e.pe_identifier for e in self.entries if e.pe_identifier}
        return next(iter(ids)) if len(ids) == 1 else None

    @property
    def game_code(self) -> str | None:
        for h in self.headers:
            if h.get("gameCode"):
                return str(h["gameCode"])
        codes = {e.game_code for e in self.entries if e.game_code}
        return next(iter(codes)) if len(codes) == 1 else None

    @property
    def version(self) -> str | None:
        for h in self.headers:
            if h.get("version"):
                return str(h["version"])
        return None

    def to_data(self) -> list[dict[str, Any]]:
        return [dict(h) for h in self.headers] + [e.to_dict() for e in self.entries]

    def dumps(self, *, indent: int = 4) -> str:
        return json.dumps(self.to_data(), indent=indent) + "\n"


# --- parsing --------------------------------------------------------------------------------------


def _hex(value: Any, where: str) -> bytes:
    if not isinstance(value, str):
        raise PatchFormatError(f"{where}: expected a hex string, got {type(value).__name__}")
    s = value.replace(" ", "")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise PatchFormatError(f"{where}: bad hex string {value!r}") from e


def _int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise PatchFormatError(f"{where}: expected an integer, got {type(value).__name__}")
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except ValueError:
        raise PatchFormatError(f"{where}: {value!r} is not an integer") from None


_KNOWN_KEYS = {
    "memory": {"name", "description", "caution", "gameCode", "type", "peIdentifier", "group", "patches"},
    "union": {"name", "description", "caution", "gameCode", "type", "peIdentifier", "group", "patches"},
    "number": {"name", "description", "caution", "gameCode", "type", "peIdentifier", "group", "patch"},
    "signature": {
        "name", "description", "caution", "gameCode", "type", "peIdentifier", "group",
        "signature", "replacement", "dllName", "offset", "usage",
    },
    "group": {"name", "description", "caution", "gameCode", "type", "peIdentifier", "group", "id"},
}  # fmt: skip


def _entry_from_raw(raw: dict[str, Any], index: int) -> Entry:
    name = raw["name"]
    etype = raw.get("type", "memory")
    entry = Entry(
        name=name,
        description=raw.get("description", ""),
        game_code=raw.get("gameCode"),
        type=etype,
        caution=raw.get("caution"),
        pe_identifier=raw.get("peIdentifier"),
        group=raw.get("group"),
        id=raw.get("id") if etype == "group" else None,
    )
    if etype not in KNOWN_TYPES:
        entry.raw = raw
        return entry
    entry.raw = {k: v for k, v in raw.items() if k not in _KNOWN_KEYS[etype]}
    if etype == "group":
        entry.raw.pop("id", None)
    where = f"entry {name!r}"
    if etype == "memory":
        for j, p in enumerate(raw.get("patches", [])):
            w = f"{where} patch #{j}"
            if "offset" not in p:
                raise PatchFormatError(f"{w}: missing offset")
            entry.patches.append(
                Patch(
                    offset=_int(p["offset"], w + " offset"),
                    dll_name=p.get("dllName"),
                    disabled=_hex(p.get("dataDisabled"), w + " dataDisabled"),
                    enabled=_hex(p.get("dataEnabled"), w + " dataEnabled"),
                )
            )
    elif etype == "union":
        for j, o in enumerate(raw.get("patches", [])):
            w = f"{where} option #{j}"
            inner = o.get("patch") if isinstance(o, dict) else None
            if not isinstance(inner, dict) or "name" not in o or "offset" not in inner:
                raise PatchFormatError(f"{w}: expected {{name, patch: {{offset, dllName, data}}}}")
            entry.options.append(
                UnionOption(
                    name=str(o["name"]),
                    offset=_int(inner["offset"], w + " offset"),
                    data=_hex(inner.get("data"), w + " data"),
                    dll_name=inner.get("dllName"),
                )
            )
        # The format asks for one offset/length per union, but real files break it (options of different lengths), and
        # the patcher just copies each option's own bytes, so options are verified/applied at their own offset and length.
        if any(o.length == 0 for o in entry.options):
            raise PatchFormatError(f"{where}: union option with empty data")
    elif etype == "number":
        p = raw.get("patch")
        if not isinstance(p, dict) or not {"offset", "size", "min", "max"} <= p.keys():
            raise PatchFormatError(f"{where}: number entry needs patch {{offset, dllName, size, min, max}}")
        entry.number = NumberSpec(
            offset=_int(p["offset"], where + " offset"),
            size=_int(p["size"], where + " size"),
            min=_int(p["min"], where + " min"),
            max=_int(p["max"], where + " max"),
            dll_name=p.get("dllName"),
        )
    elif etype == "signature":
        if "signature" not in raw or "replacement" not in raw:
            raise PatchFormatError(f"{where}: signature entry needs signature and replacement")
        entry.signature = SignatureSpec(
            signature=str(raw["signature"]),
            replacement=str(raw["replacement"]),
            offset=_int(raw.get("offset", 0), where + " offset"),
            usage=_int(raw.get("usage", 0), where + " usage"),
            dll_name=raw.get("dllName"),
        )
    return entry


def patchfile_from_data(data: Any, *, path: str | None = None) -> PatchFile:
    if isinstance(data, dict):  # tolerate a single entry
        data = [data]
    if not isinstance(data, list):
        raise PatchFormatError("patch file must be a JSON list of entries")
    headers: list[dict[str, Any]] = []
    entries: list[Entry] = []
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            raise PatchFormatError(f"item #{i} is not a JSON object")
        if "name" not in raw:
            headers.append(raw)  # metadata header (version / lastUpdated / source)
            continue
        entries.append(_entry_from_raw(raw, i))
    return PatchFile(entries=entries, headers=headers, path=path)


def load_patchfile(source: Union[str, Path]) -> PatchFile:
    """Load a patch JSON file with its metadata headers."""
    try:
        data = json.loads(Path(source).read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as e:
        raise PatchFormatError(f"{source}: invalid JSON: {e}") from e
    return patchfile_from_data(data, path=str(source))


def entries_from_data(data: Any) -> list[Entry]:
    return patchfile_from_data(data).entries


def load_entries(source: Union[str, Path]) -> list[Entry]:
    """Load the entries of a JSON file path (metadata headers are skipped; use :func:`load_patchfile` to keep them)."""
    return load_patchfile(source).entries


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
