"""Golden parity: replay every command file from the original Q.java session (run with
``analyzeHeadless -process ... -postScript Q.java``) against the new in-process queries and diff the results.

Reads the reference Ghidra project (``project_dir`` in the reference config, see conftest) in place (read-only).
Skipped when the project or Ghidra is unavailable.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from kawaiidra_hx import commands
from kawaiidra_hx.core import get_session

from .conftest import REF_NEW_DLL, REF_OLD_DLL, REF_PROJECT_DIR, ref_gpr

pytestmark = [pytest.mark.ghidra, pytest.mark.reference]

_HEADER = re.compile(r"^=========== (.*) ===========$", re.MULTILINE)


def parse_blocks(out_text: str) -> list[tuple[str, str]]:
    """Split a Q.java output file into ``[(command line, body)]``."""
    out: list[tuple[str, str]] = []
    matches = list(_HEADER.finditer(out_text))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(out_text)
        out.append((m.group(1).strip(), out_text[m.end() : end]))
    return out


# Messages the new queries print where Q.java printed nothing, and the notice appended when a cap is hit.
_PLACEHOLDERS = {
    "no instruction",
    "(no matching strings)",
    "(no matching symbols)",
    "(no matching instructions)",
    "(no references)",
    "(no callers)",
    "(pattern not found)",
}
_LIMIT_NOTICE = re.compile(r"^\.\.\. \(limit \d+ .*reached\)$")
_SYMBOL = re.compile(r"(?:FUN|DAT|PTR|LAB|thunk_FUN)_[0-9a-f]{6,}")


def norm(text: str, command: str = "") -> str:
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").strip().split("\n")]
    lines = [ln for ln in lines if not _LIMIT_NOTICE.match(ln)]
    if len(lines) == 1 and lines[0] in _PLACEHOLDERS:
        return ""
    out = "\n".join(lines).strip()
    if command.startswith("decomp"):
        # Ghidra's decompiler keeps cross-function state inside a session, so the same function can come out with
        # different parameter sizes (`undefined4` vs `undefined8`) or different call argument lists depending on what
        # was decompiled before it (Q.java ran a fresh JVM per command file). Compare what is stable: the header line
        # and the set of functions/data the code refers to.
        header = out.split("\n", 1)[0]
        return header + "\nrefs: " + " ".join(sorted(set(_SYMBOL.findall(out))))
    return out


def golden_files() -> list[str]:
    if REF_PROJECT_DIR is None or not REF_PROJECT_DIR.is_dir():
        return []
    names = [p.stem for p in REF_PROJECT_DIR.glob("*.txt") if (REF_PROJECT_DIR / f"{p.stem}.out").exists()]
    return sorted(names, key=lambda n: (re.sub(r"\d+", "", n), int(re.sub(r"\D", "", n) or 0), n))


def _guess_programs(lines: list[str]) -> list[str]:
    """Old-build addresses are 0x10xxxxxx, new-build 0x18xxxxxxx; commands without addresses try new, then old."""
    for ln in lines:
        m = re.search(r"\b0x([0-9a-f]{8,9})\b", ln, re.IGNORECASE)
        if m:
            return [REF_OLD_DLL] if len(m.group(1)) == 8 and m.group(1).startswith("10") else [REF_NEW_DLL]
    return [REF_NEW_DLL, REF_OLD_DLL]


@pytest.fixture(scope="module")
def session():
    gpr = ref_gpr()
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR not set")
    if gpr is None or not gpr.exists():
        pytest.skip(f"reference Ghidra project not found ({gpr or 'not configured'})")
    s = get_session()
    yield s
    s.close_project(str(gpr), discard=True)  # release Ghidra's project lock for other processes (e.g. the MCP test)


def _run_against(session, program: str, blocks: list[tuple[str, str]]) -> list[str]:
    h = session.program(str(ref_gpr()), program)
    problems = []
    for line, expected in blocks:
        try:
            got = commands.run_command(h, line, session.settings)
        except Exception as e:
            got = f"ERR {e}"
        if norm(got, line) != norm(expected, line):
            exp, act = norm(expected, line).split("\n"), norm(got, line).split("\n")
            first = next((i for i, (a, b) in enumerate(zip(exp, act)) if a != b), min(len(exp), len(act)))
            problems.append(
                f"[{program}] {line!r}: first difference at line {first + 1} "
                f"(expected {len(exp)} lines, got {len(act)})\n    expected: {exp[first] if first < len(exp) else '<end>'}\n"
                f"    got     : {act[first] if first < len(act) else '<end>'}"
            )
    return problems


def _golden_params():
    params = []
    for name in golden_files():
        txt = (REF_PROJECT_DIR / f"{name}.txt").read_text(encoding="utf-8")
        slow = any(ln.strip().startswith("scan") for ln in txt.splitlines())
        params.append(pytest.param(name, marks=pytest.mark.slow) if slow else name)
    return params


@pytest.mark.parametrize("name", _golden_params())
def test_matches_qjava_output(session, name):
    txt = (REF_PROJECT_DIR / f"{name}.txt").read_text(encoding="utf-8")
    blocks = parse_blocks((REF_PROJECT_DIR / f"{name}.out").read_text(encoding="utf-8", errors="replace"))
    cmd_lines = [ln for ln in txt.splitlines() if ln.strip() and not ln.startswith("#")]
    if not blocks:
        pytest.skip("empty golden output")
    attempts = {}
    for program in _guess_programs(cmd_lines):
        problems = _run_against(session, program, blocks)
        if not problems:
            return
        attempts[program] = problems
    pytest.fail("\n".join(f"--- {p}\n" + "\n".join(v) for p, v in attempts.items()))
