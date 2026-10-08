"""End-to-end: spawn the MCP server over stdio and call tools like a real client would.

Checks stdout hygiene too: if JVM/native output leaked onto the protocol stream the client would fail to parse it.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

from .conftest import REF_NEW_DLL, REF_PROJECT_NAME, ref_gpr

mcp_client = pytest.importorskip("mcp.client.stdio")
from mcp import ClientSession, StdioServerParameters  # noqa: E402


def _params(env_extra: dict[str, str] | None = None) -> StdioServerParameters:
    env = dict(os.environ)
    env.update(env_extra or {})
    return StdioServerParameters(command=sys.executable, args=["-m", "kawaiidra_hx.mcp_server"], env=env)


async def _with_session(fn, env_extra=None):
    async with mcp_client.stdio_client(_params(env_extra)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await fn(session)


def _text(result) -> str:
    assert not result.isError, result.content
    return "\n".join(c.text for c in result.content if getattr(c, "type", "") == "text")


def test_lists_expected_tools():
    async def go(session):
        tools = await session.list_tools()
        return {t.name for t in tools.tools}

    names = asyncio.run(_with_session(go))
    for expected in (
        "list_projects", "import_binary", "job_status", "program_info", "resolve", "decompile", "disassemble",
        "xrefs_to", "callers", "find_strings", "scan_instructions", "find_bytes", "query", "rename", "save_program",
        "pe_sections", "offset_to_va", "patch_verify", "patch_apply", "patch_make", "branch_encode",
        "pe_identify", "pe_imports", "pe_exports", "patch_show", "patch_diff",
    ):  # fmt: skip
        assert expected in names, expected


@pytest.mark.reference
def test_patch_tools_need_no_ghidra(ref_new, ref_new_patched, ref_patch_json):
    async def go(session):
        sections = _text(await session.call_tool("pe_sections", {"file_path": str(ref_new)}))
        off = _text(await session.call_tool("offset_to_va", {"file_path": str(ref_new), "offsets": ["6094176"]}))
        va = _text(await session.call_tool("va_to_offset", {"file_path": str(ref_new), "addresses": ["0x1805D0760"]}))
        ver = _text(await session.call_tool("patch_verify", {"file_path": str(ref_new), "patch_file": str(ref_patch_json)}))
        br = _text(await session.call_tool("branch_encode", {"at": "0x1805D091B", "to": "0x1805D0990", "op": "jmp", "short": True}))
        ident = _text(await session.call_tool("pe_identify", {"file_path": str(ref_new), "game_codes": ["ABC"]}))
        exports = _text(await session.call_tool("pe_exports", {"file_path": str(ref_new)}))
        imports = _text(await session.call_tool("pe_imports", {"file_path": str(ref_new)}))
        shown = _text(await session.call_tool("patch_show", {"patch_file": str(ref_patch_json)}))
        diff = _text(await session.call_tool("patch_diff", {"original_path": str(ref_new), "modified_path": str(ref_new_patched), "name": "all"}))
        return sections, off, va, ver, br, ident, exports, imports, shown, diff

    sections, off, va, ver, br, ident, exports, imports, shown, diff = asyncio.run(_with_session(go))
    assert ".text" in sections and "0x180000000" in sections
    assert "VA 0x1805D0760" in off
    assert "file 0x5CFD60" in va
    assert "5/5 checks OK" in ver
    assert "EB73" in br
    assert "patch id ABC-" in ident and "x64" in ident
    assert exports.startswith(("module ", "(no export directory)"))
    assert "import(s)" in imports
    assert "[memory]" in shown
    assert '"dataEnabled"' in diff and '"dataDisabled"' in diff


@pytest.mark.ghidra
@pytest.mark.reference
def test_ghidra_tools_over_stdio():
    gpr = ref_gpr()
    if gpr is None or not gpr.exists() or not REF_NEW_DLL or not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("reference project or GHIDRA_INSTALL_DIR missing")
    args = {"project": str(gpr), "program": REF_NEW_DLL}

    async def go(session):
        info = _text(await session.call_tool("program_info", args))
        res = _text(await session.call_tool("resolve", {**args, "location": "off:6094176"}))
        dec = _text(await session.call_tool("decompile", {**args, "location": "0x1805d0760"}))
        q = _text(await session.call_tool("query", {**args, "commands_text": "func 0x1805d0760\nbytes 0x1805d0760 6\nbogus"}))
        big = _text(await session.call_tool("scan_instructions", {**args, "text": "mov", "limit": 400}))
        status = _text(await session.call_tool("session_status", {}))
        return info, res, dec, q, big, status

    info, res, dec, q, big, status = asyncio.run(_with_session(go, {"KHX_MAX_INLINE_CHARS": "3000"}))
    assert REF_NEW_DLL in info and "x86:LE:64" in info and "read-only" in info
    assert "FUN_1805d0760" in res and "0x5CFD60" in res
    assert "FUN_1805d0760" in dec and "switch" in dec
    assert "FUN_1805d0760 1805d0760 - 1805d0889" in q and "40 53 48 83 ec 40" in q and "ERR unknown command" in q
    assert "[full output saved to" in big  # oversized output is offloaded, not inlined
    assert f"open project {REF_PROJECT_NAME}" in status and f"{REF_NEW_DLL} [ro]" in status
