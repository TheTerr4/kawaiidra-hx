"""``khx triage FILE``: a JVM-free first look at any binary.

Answers, from the file alone: what is it (identity, DLL or EXE, how many exports), how is it laid out (sections with flags and entropy, data
directories, relocations), what does it link against (system libraries, C/C++ runtimes, everything else, with the ones imported by ordinal only
flagged: their names were stripped), whether it carries debug info, a signature block or text that says where it came from (URLs, build paths,
version and copyright strings). A file that is not a PE image is described by its first bytes and entropy instead of failing.
"""

from __future__ import annotations

import math
import re
from collections import OrderedDict
from pathlib import Path
from typing import Union

from .pe import PEImage
from .pe.parser import DIRECTORY_NAMES
from .pe.tables import section_entropy

_SYSTEM = frozenset(
    "kernel32 kernelbase user32 gdi32 advapi32 shell32 ole32 oleaut32 ws2_32 wsock32 msvcrt ntdll comctl32 comdlg32 winmm version shlwapi crypt32 bcrypt "
    "secur32 iphlpapi wininet winhttp d3d9 d3d11 d3d12 dxgi opengl32 glu32 imm32 setupapi psapi dbghelp rpcrt4 ucrtbase win32u uxtheme dwmapi netapi32 "
    "userenv wtsapi32 powrprof mmdevapi avrt dsound dinput8 xinput1_4 xinput9_1_0 hid shcore combase cfgmgr32 normaliz wldap32 mswsock".split()
)
_RUNTIME = re.compile(r"^(?:api-ms-win-|ext-ms-win-|msvcp|vcruntime|concrt|vcomp|mfc|ucrtbase)", re.IGNORECASE)

_MARKERS = (
    ("url", re.compile(rb"https?://[\x21-\x7e]{6,120}"), 6),
    ("build path", re.compile(rb"(?<![A-Za-z0-9])[A-Za-z]:\\[\x20-\x7e]{6,120}\.(?:cpp|c|cc|h|hpp|pdb|obj|lib)"), 6),
    ("version", re.compile(rb"(?i)\bversion[ :=_-]{0,3}\d+(?:\.\d+){1,3}"), 5),
    ("copyright", re.compile(rb"(?i)copyright[ \x28c\x29]{0,6}[\x20-\x7e]{4,80}"), 3),
)


def classify_library(dll: str) -> str:
    stem = dll.lower().removesuffix(".dll")
    if stem in _SYSTEM:
        return "system"
    if _RUNTIME.match(stem):
        return "C/C++ runtime"
    return "other (ships with the program?)"


def find_markers(data: bytes) -> "OrderedDict[str, list[tuple[int, str]]]":
    out: "OrderedDict[str, list[tuple[int, str]]]" = OrderedDict()
    for name, rx, limit in _MARKERS:
        seen: set[str] = set()
        hits: list[tuple[int, str]] = []
        for m in rx.finditer(data):
            text = m.group(0).decode("latin-1", errors="replace")
            if text in seen:
                continue
            seen.add(text)
            hits.append((m.start(), text))
            if len(hits) >= limit:
                break
        if hits:
            out[name] = hits
    return out


def _kind(im: PEImage) -> str:
    n = len(im.exports.exports) if im.exports else 0
    if im.info.is_dll:
        return f"DLL, {n} exports" if n else "DLL without exports"
    return "EXE" + (f", {n} exports" if n else "")


def _entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = [0] * 256
    for b in raw:
        counts[b] += 1
    n = len(raw)
    return max(0.0, -sum((c / n) * math.log2(c / n) for c in counts if c))


def triage_non_pe(path: Union[str, Path], reason: str) -> str:
    """What can be said about a file that is not a PE image."""
    data = Path(path).read_bytes()
    head = data[:32]
    ent = _entropy(data[:65536])
    lines = [
        f"== triage: {Path(path).name} ==", f"NOT A PE IMAGE ({reason})", f"size        {len(data)} bytes",
        f"first bytes {head.hex()}  ascii {''.join(chr(c) if 32 <= c < 127 else '.' for c in head)}", f"entropy     {ent:.2f} bits/byte (first 64 KiB)",
    ]  # fmt: skip
    if head[:1] == b"\x30" and head[1:2] in (b"\x80", b"\x81", b"\x82", b"\x83", b"\x84"):
        kind = "DER/ASN.1 structure"
        if b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03" in data[:64]:
            kind += ": PKCS#7/CMS EnvelopedData (1.2.840.113549.1.7.3), i.e. an ENCRYPTED container"
        elif b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" in data[:64]:
            kind += ": PKCS#7/CMS SignedData"
        lines.append(f"looks like  {kind}")
    elif data[:4] == b"\x7fELF":
        lines.append("looks like  an ELF executable")
    elif data[:2] == b"PK":
        lines.append("looks like  a zip archive")
    elif ent > 7.5:
        lines.append("looks like  high-entropy data: encrypted or compressed")
    return "\n".join(lines)


def triage(path: Union[str, Path], *, game_code: str = "PE", max_exports: int = 40) -> str:
    try:
        im = PEImage(path)
    except Exception as e:
        return triage_non_pe(path, str(e))
    pe = im.info
    ident = im.identity
    out: list[str] = [
        f"== triage: {Path(path).name} ==",
        f"kind        {_kind(im)}",
        f"size        {ident.size} bytes   sha256 {ident.sha256}",
        f"machine     {ident.machine} ({'PE32+' if ident.is_64bit else 'PE32'})   image base 0x{ident.image_base:X}   entry RVA 0x{ident.entry_rva:x}",
        f"built       {ident.build_time} UTC (linker timestamp; may be fake in reproducible builds)",
        f"build id    {ident.pe_identifier(game_code)}",
    ]
    sec_off, sec_size = pe.directory("security")
    if sec_size:
        out.append(f"authenticode signature block: {sec_size} bytes at file 0x{sec_off:X} (stale after any edit)")

    out.append("")
    out.append("sections:")
    out.append(f"  {'name':<10}{'rva':>10}{'vsize':>10}{'raw':>10}{'rsize':>10}  flags  entropy")
    for s in pe.sections:
        ent = section_entropy(im.data, s) if s.raw_size else 0.0
        warn = "  <-- W+X" if s.flags == "RWX" else (("  <-- high entropy (compressed resources?)" if s.name.lower() == ".rsrc" else "  <-- high entropy (packed/encrypted?)") if ent > 7.2 else "")
        out.append(f"  {s.name:<10}{s.virtual_address:>#10x}{s.virtual_size:>#10x}{s.raw_pointer:>#10x}{s.raw_size:>#10x}  {s.flags}    {ent:5.2f}{warn}")
    dirs = [f"{n}={rva:#x}+{size:#x}" for n, (rva, size) in zip(DIRECTORY_NAMES, pe.directories) if rva or size]
    out.append("  directories: " + ", ".join(dirs))
    if not pe.dll_characteristics & 0x40:
        out.append("  no DYNAMIC_BASE: loads at its preferred address (relocations matter only if that is taken)")
    if im.relocations:
        kinds = sorted(set(im.relocations.values()))
        what = "absolute addresses in code: wildcard them in signatures" if not pe.is_64bit else "pointers in data only (code is RIP-relative)"
        out.append(f"  {len(im.relocations)} base relocations ({'/'.join(f'{k * 8}-bit' for k in kinds)}): {what}")

    ex = im.exports
    if ex:
        out.append("")
        out.append(f"exports (module name {ex.module_name!r}, {len(ex.exports)}):")
        for e in ex.exports[:max_exports]:
            out.append(f"  #{e.ordinal:<4} 0x{e.rva:08X}  {e.name or '<ordinal only>'}" + (f"  -> {e.forwarder}" if e.forwarder else ""))
        if len(ex.exports) > max_exports:
            out.append(f"  ... {len(ex.exports) - max_exports} more")

    out.append("")
    out.append("imports (library, count, class):")
    others: list[str] = []
    for lib in im.imports:
        cls = classify_library(lib.dll)
        ordn = f", {lib.by_ordinal} by ordinal ONLY (names stripped)" if lib.by_ordinal else ""
        out.append(f"  {lib.dll:<28}{len(lib.symbols):>4}  {cls}{ordn}{' (delay-load)' if lib.delay else ''}")
        if cls.startswith("other"):
            others.append(lib.dll)
    if others:
        out.append(f"  not part of Windows or the C/C++ runtimes, so they must ship with the program: {', '.join(others)}")

    if im.codeview:
        cv = im.codeview
        out.append("")
        out.append(f"debug: {cv.kind} {cv.guid} age {cv.age}")
        out.append(f"  {cv.path}")
    found = find_markers(im.data)
    if found:
        out.append("")
        out.append("markers:")
        for name, hits in found.items():
            for off, text in hits:
                out.append(f"  {name:<12} @0x{off:X}  {text}")
    return "\n".join(out)
