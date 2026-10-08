"""Tiny synthetic PE builds shared by the signature / port tests: one function plus a callee, with knobs to move and rewire the code."""

from __future__ import annotations

from pathlib import Path

from .conftest import build_pe

# sub rsp,0x28 | lea rcx,[rip+0xFF5] | call +0x30 | test eax,eax | jz +7 (lands on the xor, so every instruction is reachable) | mov eax,1 | jmp +2 | xor eax,eax | add rsp,0x28 | ret
FUNC = bytes.fromhex("4883EC28" "488D0DF50F0000" "E830000000" "85C0" "7407" "B801000000" "EB02" "31C0" "4883C428" "C3")
JZ = 4 + 7 + 5 + 2  # offset of `jz +5` inside FUNC
CALLEE = bytes.fromhex("31C0C3")
PE_ID = "ABC-5c5c0000_1000"  # build_pe: TimeDateStamp 0x5C5C0000, entry RVA from the call


def tiny_body(prefix: bytes = b"", call_disp: int = 0x30) -> bytes:
    func = FUNC.replace(bytes.fromhex("E830000000"), b"\xE8" + call_disp.to_bytes(4, "little"))
    body = prefix + func
    return body + b"\xCC" * (0x40 - len(body)) + CALLEE


def write_pe(path: Path, entry_rva: int, body: bytes) -> Path:
    path.write_bytes(build_pe(entry_rva=entry_rva, body=body))
    return path


def patch_doc(pe_id: str, offset: int, name: str = "Force It") -> list[dict]:
    return [
        {"gameCode": "ABC", "version": "t"},
        {
            "name": name, "description": "makes it so", "gameCode": "ABC", "type": "memory", "peIdentifier": pe_id,
            "patches": [{"offset": offset, "dllName": "x.dll", "dataDisabled": "7407", "dataEnabled": "EB07"}],
        },
    ]


def doc_two_sites(pe_id: str, off1: int, off2: int) -> list[dict]:
    return [
        {"gameCode": "ABC", "version": "t"},
        {
            "name": "Two Sites", "description": "d", "gameCode": "ABC", "type": "memory", "peIdentifier": pe_id,
            "patches": [
                {"offset": off1, "dllName": "x.dll", "dataDisabled": "7407", "dataEnabled": "EB07"},
                {"offset": off2, "dllName": "x.dll", "dataDisabled": "31C0", "dataEnabled": "B001"},
            ],
        },
    ]


def union_doc(pe_id: str, off: int, options: dict[str, str]) -> list[dict]:
    return [
        {"gameCode": "ABC", "version": "t"},
        {
            "name": "Mode", "description": "d", "gameCode": "ABC", "type": "union", "peIdentifier": pe_id,
            "patches": [{"name": n, "patch": {"offset": off, "dllName": "x.dll", "data": d}} for n, d in options.items()],
        },
    ]  # fmt: skip
