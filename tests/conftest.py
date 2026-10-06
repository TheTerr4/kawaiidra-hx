"""Shared fixtures.

Tests marked ``reference`` need the maintainer's private reference files: an old 32-bit build and a new x64 build of
the same DLL, a patched copy of the new build, its patch entry file, and a Ghidra project holding both builds. They are
read *in place* (never copied) from the paths in ``tests/reference.local.json`` (git-ignored; copy
``tests/reference.example.json``) or the file named by ``KHX_REF_CONFIG``, and the tests skip when it is absent.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest

REF_CONFIG = Path(os.environ.get("KHX_REF_CONFIG") or Path(__file__).with_name("reference.local.json"))
REF: dict[str, str] = json.loads(REF_CONFIG.read_text(encoding="utf-8")) if REF_CONFIG.is_file() else {}
REF_DIR = Path(REF["dir"]) if REF.get("dir") else None
REF_PROJECT_DIR = Path(REF["project_dir"]) if REF.get("project_dir") else None
REF_PROJECT_NAME = REF.get("project_name", "proj")
REF_OLD_DLL = REF.get("old_dll", "")
REF_NEW_DLL = REF.get("new_dll", "")


def need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"{path} not found")
    return path


def ref_file(key: str) -> Path:
    """File ``key`` of the reference config, inside its ``dir``; skips when not configured or absent."""
    if REF_DIR is None or not REF.get(key):
        pytest.skip(f"reference '{key}' not configured (see tests/reference.example.json)")
    return need(REF_DIR / REF[key])


def ref_gpr() -> Path | None:
    return REF_PROJECT_DIR / f"{REF_PROJECT_NAME}.gpr" if REF_PROJECT_DIR else None


@pytest.fixture(scope="session")
def ref_old() -> Path:
    return ref_file("old_dll")


@pytest.fixture(scope="session")
def ref_new() -> Path:
    return ref_file("new_dll")


@pytest.fixture(scope="session")
def ref_new_patched() -> Path:
    return ref_file("patched_dll")


@pytest.fixture(scope="session")
def ref_patch_json() -> Path:
    return ref_file("patch_json")


def build_pe(
    *,
    is64: bool = True,
    image_base: int = 0x180000000,
    entry_rva: int = 0,
    sections: list[tuple[str, int, int, int, int]] | None = None,
    body: bytes = b"",
    total_size: int = 0x1000,
) -> bytes:
    """Hand-build a tiny PE image. ``sections``: (name, rva, vsize, raw_ptr, raw_size)."""
    sections = sections or [(".text", 0x1000, 0x400, 0x600, 0x400), (".data", 0x2000, 0x1000, 0xA00, 0x200)]
    e_lfanew = 0x80
    opt_size = 0xF0 if is64 else 0xE0
    buf = bytearray(max(total_size, 0xC00))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    machine = 0x8664 if is64 else 0x14C
    struct.pack_into("<HHIIIHH", buf, e_lfanew + 4, machine, len(sections), 0x5C5C0000, 0, 0, opt_size, 0x2022)
    opt = e_lfanew + 24
    struct.pack_into("<H", buf, opt, 0x20B if is64 else 0x10B)
    if is64:
        struct.pack_into("<Q", buf, opt + 24, image_base)
    else:
        struct.pack_into("<I", buf, opt + 28, image_base)
    struct.pack_into("<I", buf, opt + 16, entry_rva)  # AddressOfEntryPoint
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)  # SectionAlignment, FileAlignment (Ghidra needs them)
    struct.pack_into("<II", buf, opt + 56, 0x4000, 0x600)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<H", buf, opt + 68, 3)  # Subsystem: console
    struct.pack_into("<I", buf, opt + (108 if is64 else 92), 16)  # NumberOfRvaAndSizes
    table = opt + opt_size
    for i, (name, rva, vsize, rptr, rsize) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI", buf, table + 40 * i, name.encode(), vsize, rva, rsize, rptr, 0, 0, 0, 0, 0x60000020
        )
    buf[0x600 : 0x600 + len(body)] = body
    return bytes(buf)


@pytest.fixture()
def tiny_pe() -> bytes:
    body = bytes.fromhex("40534883EC40") + bytes.fromhex("7673") + bytes.fromhex("758D") + b"\x90" * 16
    return build_pe(body=body)
