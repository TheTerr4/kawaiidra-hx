"""Two independent implementations of file offset <-> address must agree: our PE-header math (pure Python) and
Ghidra's FileBytes mapping. Runs on the reference DLLs (see conftest) and on any binary present in the corpus."""

from __future__ import annotations

import os

import pytest

from kawaiidra_hx import corpus
from kawaiidra_hx.core import get_session
from kawaiidra_hx.core.jobs import import_program
from kawaiidra_hx.core.resolve import file_offset
from kawaiidra_hx.pe import parse_pe

from .conftest import REF, ref_file, ref_gpr

pytestmark = pytest.mark.ghidra


@pytest.fixture(scope="module")
def session():
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR not set")
    return get_session()


def sample_offsets(pe):
    offs = []
    for s in pe.sections:
        if s.raw_size:
            offs += [s.raw_pointer, s.raw_pointer + 1, s.raw_pointer + s.raw_size // 2, s.raw_end - 1]
    return offs


def agree(pe, h):
    mem = h.program.getMemory()
    checked = 0
    for off in sample_offsets(pe):
        va = pe.offset_to_va(off)
        hits = [int(a.getOffset()) for a in mem.locateAddressesForFileOffset(off)]
        if not hits:
            continue  # Ghidra does not map every raw byte (e.g. padding past VirtualSize)
        assert va in hits, f"offset 0x{off:X}: PE math says 0x{va:X}, Ghidra says {[hex(x) for x in hits]}"
        addr = h.program.getAddressFactory().getDefaultAddressSpace().getAddress(va)
        assert file_offset(h.program, addr) == off
        checked += 1
    assert checked >= len(pe.sections), "too few offsets were comparable"


@pytest.mark.reference
@pytest.mark.parametrize("key", ["old_dll", "new_dll"])
def test_reference_pe_math_matches_ghidra(session, key):
    src = ref_file(key)
    gpr = ref_gpr()
    if gpr is None or not gpr.exists():
        pytest.skip("reference Ghidra project not found")
    try:
        agree(parse_pe(src), session.program(str(gpr), REF[key]))
    finally:
        session.close_project(str(gpr), discard=True)  # release the project lock for other processes


@pytest.mark.corpus
@pytest.mark.parametrize("path", corpus.corpus_files() or [None], ids=lambda p: getattr(p, "name", "no-corpus"))
def test_corpus_binary_import_and_crosscheck(session, tmp_path, path):
    if path is None:
        pytest.skip("corpus is empty (see `khx corpus list`)")
    proj = str(tmp_path / "proj")
    res = import_program(session, path, proj, analyze=True)
    try:
        assert res["functions"] > 0
        pe = parse_pe(path)
        agree(pe, session.program(proj, path.name))
    finally:
        session.close_project(proj, discard=True)
