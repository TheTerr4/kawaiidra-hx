"""`khx match` on real programs: the x86 and x64 builds of the pinned SQLite corpus DLL are one source tree built twice, so function names are ground truth.

Slow (two full Ghidra analyses, a few minutes); skipped without GHIDRA_INSTALL_DIR and the corpus downloads.
"""

from __future__ import annotations

import os
import re
from collections import Counter

import pytest

from kawaiidra_hx import corpus, sigs
from kawaiidra_hx.match import run, transfer
from kawaiidra_hx.match.store import FingerprintStore

pytestmark = [pytest.mark.ghidra, pytest.mark.corpus, pytest.mark.slow]

_DEFAULT = ("FUN_", "thunk_FUN_", "LAB_", "?")


def _file(name: str):
    return next((p for p in corpus.corpus_files() if p.name == name), None)


@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    x86, x64 = _file("sqlite3-3.53.4-x86.dll"), _file("sqlite3-3.53.4-x64.dll")
    if x86 is None or x64 is None or not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("needs both SQLite DLLs in the corpus (khx corpus fetch sqlite-3.53.4-x86|x64 --yes) and GHIDRA_INSTALL_DIR")
    from kawaiidra_hx.core import get_session
    from kawaiidra_hx.core.jobs import import_program

    tmp = tmp_path_factory.mktemp("match")
    session = get_session()
    proj = str(tmp / "proj")
    import_program(session, x86, proj, analyze=True)
    import_program(session, x64, proj, analyze=True)
    a, b = session.program(proj, x86.name, write=True), session.program(proj, x64.name, write=True)
    store = FingerprintStore(tmp / "cache")
    res = run.compare(a, b, store=store)
    yield res, store, x86, x64
    session.close_project(proj, discard=True)


def _real(name: str) -> bool:
    return not name.startswith(_DEFAULT)


def _norm(name: str) -> str:
    return re.sub(r"@\d+$", "", name).lstrip("_")  # x86 name decoration: leading underscores, stdcall @N


def test_functions_match_across_a_change_of_isa_and_the_names_agree(pair):
    res, _store, _x86, _x64 = pair
    assert res.cross_isa and len(res.matched) > 0.3 * len(res.ctx.A.funcs)
    named = [(res.ctx.A.funcs[a].name, res.ctx.B.funcs[m.b].name, m.method) for a, m in res.matched.items()]
    named = [(x, y, how) for x, y, how in named if _real(x) and _real(y)]
    right = [t for t in named if _norm(t[0]) == _norm(t[1])]
    assert len(named) >= 150 and len(right) / len(named) >= 0.80, f"{len(right)}/{len(named)} named matches agree"
    by = Counter(how for _x, _y, how in named)
    assert by["align"] and by["callee"]  # the order-aware stage and the call-graph stage both contributed
    text = run.summary(res)
    assert "functions matched" in text and "different ISAs" in text


def test_counterparts_and_listing_report_a_matched_function_and_say_so_for_an_unmatched_one(pair):
    res, *_ = pair
    a = next(a for a, m in res.matched.items() if m.method == "seed")
    out = run.counterparts(res, [a + 1])  # any address inside the function finds it
    assert f"0x{a:X}" in out and "->" in out and "seed" in out
    unmatched = next(e for e in res.ctx.A.funcs if e not in res.matched and res.ctx.A.funcs[e].n >= 20)
    assert "no counterpart" in run.counterparts(res, [unmatched])
    assert "not inside a function" in run.counterparts(res, [0x10])
    assert run.listing(res, limit=3).count(chr(10)) >= 2


def test_names_carry_to_the_matching_functions_and_clear_gives_the_old_names_back(pair):
    from kawaiidra_hx import annotate
    from kawaiidra_hx.core.resolve import parse_address

    res, *_ = pair
    a, b = res.source, res.target

    def fn_at(h, va):
        return h.program.getFunctionManager().getFunctionAt(parse_address(h, f"0x{va:X}"))

    # pick strongly matched functions that are unnamed on both sides, name two of them in the source by hand
    picks = [(x, m.b) for x, m in sorted(res.matched.items())
             if m.method in transfer.STRONG_METHODS and str(fn_at(a, x).getName()).startswith("FUN_") and str(fn_at(b, m.b).getName()).startswith("FUN_")][:2]  # fmt: skip
    assert len(picks) == 2
    for i, (x, _y) in enumerate(picks):
        annotate.rename(a, f"0x{x:X}", f"KhxCarryTest{i}")
    carries = [c for c in transfer.plan(res.matched, transfer.source_names(a)) if c.name.startswith("KhxCarryTest")]
    assert sorted(c.target for c in carries) == sorted(y for _x, y in picks)

    dry = transfer.apply_carries(b, carries, source_label="x86", dry_run=True)
    assert dry.dry_run and dry.functions == 2 and dry.renamed == 2 and str(fn_at(b, picks[0][1]).getName()).startswith("FUN_")  # nothing written

    rep = transfer.apply_carries(b, carries, source_label="x86")
    assert rep.functions == 2 and rep.renamed == 2 and not rep.skipped, rep.format()
    for i, (_x, y) in enumerate(picks):
        assert str(fn_at(b, y).getName()) == f"KhxCarryTest{i}"
    from ghidra.program.model.listing import CodeUnit

    plate = str(b.program.getListing().getComment(CodeUnit.PLATE_COMMENT, fn_at(b, picks[0][1]).getEntryPoint()))
    assert plate.startswith("[khx-match:KhxCarryTest0]") and "<- x86" in plate and "was=FUN_" in plate and "src=DEFAULT" in plate

    again = transfer.apply_carries(b, carries, source_label="x86")  # idempotent: the same names, no duplicate lines
    assert again.already_named == 2 and again.renamed == 0
    assert str(b.program.getListing().getComment(CodeUnit.PLATE_COMMENT, fn_at(b, picks[0][1]).getEntryPoint())).count("[khx-match:") == 1

    # a function that already has a real name is not renamed without --force
    other = transfer.apply_carries(b, [transfer.Carry(carries[0].source, picks[1][1], "Other", "seed", 1.0, 0.0)], source_label="x86")
    assert other.renamed == 0 and any("already named" in s for s in other.skipped)

    counts = transfer.clear_program(b)
    assert counts["names_restored"] == 2
    for _x, y in picks:
        assert str(fn_at(b, y).getName()).startswith("FUN_")
    assert not str(b.program.getListing().getComment(CodeUnit.PLATE_COMMENT, fn_at(b, picks[0][1]).getEntryPoint()) or "").startswith("[khx-match")
    from ghidra.program.model.symbol import SourceType

    with a.transaction("undo the hand names"):  # (the source is a shared module-scope program: leave it as it was)
        for x, _y in picks:
            fn_at(a, x).setName(None, SourceType.DEFAULT)


def test_the_anchor_tier_across_isas_hints_at_the_function_and_never_places_the_edit(pair, tmp_path):
    from kawaiidra_hx.patch import make_entry, patchfile_from_data
    from kawaiidra_hx.pe import PEImage
    from kawaiidra_hx.port import port_build

    res, store, x86, x64 = pair
    entry = make_entry(x86, [("va:0x1003a370", "B800000000C3")], name="Open16", game_code="ABC", dll_name="sqlite3.dll")
    made = sigs.make_signatures(res.source, patchfile_from_data([entry.to_dict()]), binary=x86)
    assert made.made == 1, made.format()
    rep = port_build(made, PEImage(x64), "ABC-6a63bdf5_110e", anchors=res.ctx, use_ladder=False)
    site = rep.entries[0].sites[0]
    assert not site.ok  # the bytes differ between the ISAs and the instruction streams do not line up: never a guessed offset
    assert "cross-ISA hint" in site.why or "no counterpart" in site.why
    assert rep.patchfile.entries == [] and rep.counts()["ported"] == 0
