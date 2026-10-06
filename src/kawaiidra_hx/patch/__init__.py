"""Patch toolkit: JSON file-offset patches. Works without Ghidra."""

from .entries import Entry, Patch, PatchFormatError, dump_entries, entries_from_data, load_entries, select_entries
from .ops import ApplyReport, PatchMismatchError, VerifyReport, apply, make_entry, verify

__all__ = [
    "ApplyReport",
    "Entry",
    "Patch",
    "PatchFormatError",
    "PatchMismatchError",
    "VerifyReport",
    "apply",
    "dump_entries",
    "entries_from_data",
    "load_entries",
    "make_entry",
    "select_entries",
    "verify",
]
