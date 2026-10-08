"""``khx sig``: check states on a hand-built PE (JVM-free) and make -> verify -> apply on a real corpus DLL (Ghidra, slow)."""

from __future__ import annotations

import os

import pytest

from kawaiidra_hx import corpus, sigs
from kawaiidra_hx.patch import apply, entries_from_data, patchfile_from_data, verify

from .conftest import build_pe

BODY = bytes.fromhex("40534883EC40") + bytes.fromhex("7673") + bytes.fromhex("758D") + b"\x90" * 4


def _sig_file(signature: str, replacement: str, **extra) -> object:
    return patchfile_from_data([{"name": "S", "type": "signature", "signature": signature, "replacement": replacement, "dllName": "x.dll", **extra}])


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_check_reports_unique_ambiguous_not_found_and_applied(tmp_path):
    pe = build_pe(body=BODY)
    plain = _write(tmp_path, "plain.dll", pe)
    twice = _write(tmp_path, "twice.dll", pe + bytes.fromhex("7673758D"))  # the pattern appears a second time
    other = _write(tmp_path, "other.dll", build_pe(body=b"\x90" * 16))
    patched = bytearray(pe)
    patched[0x606:0x60A] = bytes.fromhex("EB739090")
    done = _write(tmp_path, "done.dll", bytes(patched))

    rep = sigs.check_signatures(_sig_file("7673 758D", "EB?? 9090"), [plain, twice, other, done])
    states = {r.binary: (r.state, r.matches) for r in rep.rows}
    assert states["plain.dll"] == ("unique", 1)
    assert states["twice.dll"] == ("ambiguous", 2)
    assert states["other.dll"] == ("not_found", 0)
    assert states["done.dll"] == ("applied", 1)
    assert not rep.ok and rep.summary() == {"unique": 1, "ambiguous": 1, "not_found": 1, "applied": 1}
    assert rep.rows[0].offset == 0x606 - 0 and rep.rows[0].va == 0x180001000 + 6  # the replacement window, as file offset and VA
    assert "ambiguous" in rep.format() and "summary:" in rep.format()


def test_check_usage_picks_the_nth_match_and_flags_a_missing_one(tmp_path):
    twice = _write(tmp_path, "twice.dll", build_pe(body=BODY) + bytes.fromhex("7673758D"))
    ok = sigs.check_signatures(_sig_file("7673 758D", "EB?? 9090", usage=1), [twice])
    assert ok.rows[0].state == "ambiguous" and ok.rows[0].offset is not None  # still ambiguous, but it resolves to the 2nd hit
    bad = sigs.check_signatures(_sig_file("7673 758D", "EB?? 9090", usage=5), [twice])
    assert bad.rows[0].state == "no_such_usage"


def test_check_notes_missing_files_and_empty_patch_files(tmp_path):
    rep = sigs.check_signatures(patchfile_from_data([{"name": "M", "type": "memory", "patches": [{"offset": 0, "dataDisabled": "00", "dataEnabled": "01"}]}]), [tmp_path / "nope.dll"])
    assert not rep.ok and any("no signature entries" in n for n in rep.notes) and any("not a readable file" in n for n in rep.notes)


def test_union_window_covers_all_options_and_picks_a_changing_one():
    entry = entries_from_data(
        [{"name": "U", "type": "union", "patches": [
            {"name": "A", "patch": {"offset": 0x606, "dllName": "x.dll", "data": "7673"}},   # equals the file: changes nothing
            {"name": "B", "patch": {"offset": 0x606, "dllName": "x.dll", "data": "EB73"}},
        ]}]
    )[0]
    win = sigs.union_window(build_pe(body=BODY), entry)
    assert win is not None and win.offset == 0x606 and win.disabled == bytes.fromhex("7673") and win.enabled == bytes.fromhex("EB73")
    assert sigs.union_window(b"\0" * 8, entry) is None  # options fall outside the file


# --- Ghidra: synthesise signatures for a real DLL (the pinned corpus build), then prove they do what the memory patch does --------


def _sqlite_x86():
    for p in corpus.corpus_files():
        if p.name == "sqlite3-3.53.4-x86.dll":
            return p
    return None


@pytest.mark.ghidra
@pytest.mark.corpus
@pytest.mark.slow
def test_make_signatures_apply_exactly_like_the_memory_patch(tmp_path):
    from kawaiidra_hx.core import get_session
    from kawaiidra_hx.core.jobs import import_program
    from kawaiidra_hx.patch import make_entry

    src = _sqlite_x86()
    if src is None or not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("needs the x86 SQLite DLL in the corpus (khx corpus fetch sqlite-3.53.4-x86 --yes) and GHIDRA_INSTALL_DIR")
    session = get_session()
    proj = str(tmp_path / "proj")
    import_program(session, src, proj, analyze=True)
    try:
        h = session.program(proj, src.name)
        # real function bodies (the first instructions behind the incremental-link jump thunks)
        entry = make_entry(src, [("va:0x1003a370", "B800000000C3")], name="Open16", game_code="ABC", dll_name="sqlite3.dll")
        two = make_entry(src, [("va:0x1003a350", "9090")], name="Open", game_code="ABC", dll_name="sqlite3.dll")
        rep = sigs.make_signatures(h, patchfile_from_data([entry.to_dict(), two.to_dict()]), binary=src)
        assert rep.made == 2 and all(r.ok and r.kind == "code" for r in rep.rows), rep.format()
        assert rep.build_id.startswith("ABC-")
        out_entries = rep.patchfile.entries
        assert [e.type for e in out_entries] == ["signature", "signature"]

        # the signature entries find exactly the offsets of the memory patches ...
        check = sigs.check_signatures(rep.patchfile, [src])
        assert check.ok and {r.entry: r.offset for r in check.rows} == {"Open16": entry.patches[0].offset, "Open": two.patches[0].offset}

        # ... and applying them gives the same bytes as applying the memory patches
        via_memory = tmp_path / "memory.dll"
        via_signature = tmp_path / "signature.dll"
        apply(src, via_memory, [entry, two])
        apply(src, via_signature, out_entries)
        assert via_memory.read_bytes() == via_signature.read_bytes()
        assert all(c.state == "applied" for c in verify(via_signature, out_entries).checks)
    finally:
        session.close_project(proj, discard=True)
