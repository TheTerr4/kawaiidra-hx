"""Small shared helpers."""

from __future__ import annotations


def parse_int(text: str) -> int:
    """File offsets: ``0x5CFD60`` is hex, ``6094176`` is decimal (as in patch JSON), ``5CFD60`` (letters) is hex."""
    t = text.strip().replace("_", "")
    if t.lower().startswith("0x"):
        return int(t, 16)
    if t.isdigit():
        return int(t, 10)
    return int(t, 16)


def parse_hex(text: str) -> int:
    """Virtual addresses are always hex, with or without ``0x``."""
    t = text.strip().replace("_", "")
    return int(t[2:] if t.lower().startswith("0x") else t, 16)
