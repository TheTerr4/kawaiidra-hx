"""triage, import-ordinal resolution and patch-site annotation: synthetic PEs; the Ghidra parts import a tiny program."""

from __future__ import annotations

import json
import os

import pytest

from kawaiidra_hx import annotate, imports, sites, triage
from kawaiidra_hx.patch import patchfile_from_data
from kawaiidra_hx.pe import PEImage

from .synth import FUNC, JZ, PE_ID, doc_two_sites, tiny_body, write_pe
from .test_pe_tables import build_pe_with_tables

BS = chr(92)


# --- triage ---------------------------------------------------------------------------------------------------------------------


def test_triage_describes_identity_sections_exports_imports_and_debug_info(tmp_path):
    f = tmp_path / "t.dll"
    f.write_bytes(build_pe_with_tables(is64=True))
    text = triage.triage(f, game_code="ABC")
    assert "kind        DLL, 3 exports" in text and "build id    ABC-5c5c0000_1234" in text
    assert "x64 (PE32+)" in text and ".rdata" in text and ".text" in text
    assert "exports (module name 'mod.dll', 3)" in text and "-> other.alpha" in text
    assert "KERNEL32.dll" in text and "system" in text and "1 by ordinal ONLY" in text
    assert "HELPER.dll" in text and "other (ships with the program?)" in text and "must ship with the program: HELPER.dll" in text
    assert "debug: RSDS" in text and "mod.pdb" in text
    assert "base relocations" in text and "pointers in data only" in text


def test_triage_markers_find_urls_and_windows_build_paths_but_not_url_fragments(tmp_path):
    f = tmp_path / "m.dll"
    path = b"C:" + BS.encode() + b"build" + BS.encode() + b"src" + BS.encode() + b"main.cpp"
    f.write_bytes(build_pe_with_tables(is64=False) + b"\0see https://example.org/docs/page\0" + path + b"\0Version 1.2.3\0Copyright (c) Somebody 2026\0")
    found = triage.find_markers(f.read_bytes())
    assert [t for _o, t in found["url"]] == ["https://example.org/docs/page"]
    assert [t for _o, t in found["build path"]] == [path.decode()]  # a fragment of the URL must not look like a drive path
    assert found["version"][0][1] == "Version 1.2.3" and found["copyright"][0][1].startswith("Copyright (c) Somebody")
    assert "markers:" in triage.triage(f)


def test_triage_classifies_libraries():
    c = triage.classify_library
    assert c("KERNEL32.dll") == "system" and c("api-ms-win-crt-heap-l1-1-0.dll") == "C/C++ runtime" and c("VCRUNTIME140.dll") == "C/C++ runtime"
    assert c("plugin.dll").startswith("other")


def test_triage_describes_a_file_that_is_not_a_pe(tmp_path):
    cms = tmp_path / "blob.bin"
    cms.write_bytes(bytes.fromhex("30820100" "06092a864886f70d010703") + bytes(range(64)))
    text = triage.triage(cms)
    assert "NOT A PE IMAGE" in text and "EnvelopedData" in text and "ENCRYPTED container" in text
    noise = tmp_path / "noise.bin"
    noise.write_bytes(bytes((i * 167 + (i >> 3)) % 256 for i in range(70000)))
    assert "high-entropy" in triage.triage(noise)
    elf = tmp_path / "prog"
    elf.write_bytes(b"\x7fELF" + b"\0" * 60)
    assert "ELF" in triage.triage(elf)


def test_section_entropy_of_constant_data_is_zero_not_negative_zero(tmp_path):
    f = tmp_path / "z.dll"
    f.write_bytes(build_pe_with_tables(is64=True))
    assert "-0.00" not in triage.triage(f)


# --- import ordinals ------------------------------------------------------------------------------------------------------------


def _ordinal_pair(tmp_path):
    """A module importing ordinal 9 of plugin.dll, and (in another folder: next to the module Ghidra's loader would resolve the ordinal itself)
    a plugin.dll whose export table numbers its functions 7, 8, 9."""
    (tmp_path / "app").mkdir()
    (tmp_path / "libs").mkdir()
    mod = tmp_path / "app" / "module.dll"
    mod.write_bytes(build_pe_with_tables(is64=True, lib=b"plugin.dll", ordinal=9))
    (tmp_path / "libs" / "plugin.dll").write_bytes(build_pe_with_tables(is64=True, export_base=7))
    return mod


def test_ordinals_are_resolved_from_the_export_table_of_the_library_next_to_the_module(tmp_path):
    mod = _ordinal_pair(tmp_path)
    (lib,) = imports.resolve_ordinals(PEImage(mod), [tmp_path / "libs"])
    assert lib.dll == "plugin.dll" and lib.ordinal_imports == 1 and lib.resolved == {9: "gamma"} and not lib.unresolved
    assert imports.external_renames([lib]) == {("PLUGIN.DLL", "Ordinal_9"): "gamma"}
    assert "1 resolved" in imports.format_resolution([lib]) and "#9=gamma" in imports.format_resolution([lib])
    # a name pattern leaves matching exports alone; a library that is not there leaves the ordinal unresolved
    (skipped,) = imports.resolve_ordinals(PEImage(mod), [tmp_path / "libs"], skip_regex="^gam")
    assert skipped.resolved == {} and skipped.skipped == 1
    (missing,) = imports.resolve_ordinals(PEImage(mod), [tmp_path / "nowhere"])
    assert missing.unresolved == [9] and missing.found_at is None and "NOT FOUND" in imports.format_resolution([missing])


@pytest.mark.ghidra
def test_externals_are_renamed_from_the_resolved_ordinals_and_restored(tmp_path):
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR not set")
    from kawaiidra_hx.core import get_session
    from kawaiidra_hx.core.jobs import import_program

    mod = _ordinal_pair(tmp_path)
    session = get_session()
    proj = str(tmp_path / "proj")
    import_program(session, mod, proj, analyze=True)
    try:
        h = session.program(proj, "module.dll", write=True)

        def labels():
            em = h.program.getExternalManager()
            return {str(loc.getLabel()) for lib in em.getExternalLibraryNames() for loc in em.getExternalLocations(lib)}

        assert "Ordinal_9" in labels()
        libs = imports.resolve_ordinals(PEImage(mod), imports.default_dirs(h, None, [tmp_path / "libs"]))
        mapping = imports.external_renames(libs)
        assert mapping == {("PLUGIN.DLL", "Ordinal_9"): "gamma"}
        counts = annotate.rename_externals(h, mapping)
        assert counts == {"renamed": 1, "already": 0, "unmatched": 0} and "gamma" in labels() and "Ordinal_9" not in labels()
        assert annotate.rename_externals(h, mapping)["already"] == 1  # idempotent
        back = annotate.rename_externals(h, mapping, restore=True)
        assert back["renamed"] == 1 and "Ordinal_9" in labels() and "gamma" not in labels()
        assert annotate.rename_externals(h, {("PLUGIN.DLL", "Ordinal_77"): "x"})["unmatched"] == 1
    finally:
        session.close_project(proj, discard=True)


# --- patch sites in Ghidra ------------------------------------------------------------------------------------------------------


@pytest.fixture()
def site_program(tmp_path):
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR not set")
    from kawaiidra_hx.core import get_session
    from kawaiidra_hx.core.jobs import import_program

    xor_off = FUNC.index(bytes.fromhex("31C0"))
    patches = tmp_path / "patches.json"
    patches.write_text(json.dumps(doc_two_sites(PE_ID, 0x600 + JZ, 0x600 + xor_off)))
    dll = write_pe(tmp_path / "a.dll", 0x1000, tiny_body())
    session = get_session()
    proj = str(tmp_path / "proj")
    import_program(session, dll, proj, analyze=True)
    h = session.program(proj, "a.dll", write=True)
    yield h, patches, dll, tmp_path
    session.close_project(proj, discard=True)


@pytest.mark.ghidra
def test_patch_sites_become_labels_bookmarks_and_comments_and_clear_removes_them(site_program):
    from ghidra.program.model.listing import CodeUnit

    h, patches, dll, _tmp = site_program
    build_id, found, notes = sites.build_context(h, patches)
    assert build_id == PE_ID and [s.offset for s in found] == [0x600 + JZ, 0x600 + FUNC.index(bytes.fromhex("31C0"))] and not notes
    rows = sites.resolve_sites(h, found)
    assert [r.state for r in rows] == ["original", "original"] and all(r.function for r in rows)
    text = sites.format_sites(rows, notes)
    assert "2 site(s): 2 consistent" in text and "Two Sites #1/2" in text

    dry = sites.annotate_program(h, patches, dry_run=True)
    assert dry.dry_run and dry.annotated == 2 and "would annotate 2/2" in dry.format()
    assert not list(h.program.getBookmarkManager().getBookmarksIterator())  # nothing written

    rep = sites.annotate_program(h, patches)
    assert rep.annotated == 2 and rep.functions == 1 and rep.labels == 2, rep.format()
    syms = {str(s.getName()) for s in h.program.getSymbolTable().getAllSymbols(True)}
    assert {"patch_two_sites_1", "patch_two_sites_2"} <= syms
    addr = rows[0].address
    eol = str(h.program.getListing().getComment(CodeUnit.EOL_COMMENT, h.program.getAddressFactory().getAddress(addr)))
    assert eol.startswith("[khx-patch:two_sites_1]") and "Two Sites #1/2" in eol and "now=original" in eol
    cats = {str(b.getCategory()) for b in h.program.getBookmarkManager().getBookmarksIterator()}
    assert cats == {"khx-patch"}

    again = sites.annotate_program(h, patches)  # idempotent: no duplicate comment lines, labels, bookmarks
    assert again.annotated == 2
    assert eol == str(h.program.getListing().getComment(CodeUnit.EOL_COMMENT, h.program.getAddressFactory().getAddress(addr)))
    assert sum(1 for _ in h.program.getBookmarkManager().getBookmarksIterator()) == 2

    counts = sites.clear_program(h)
    assert counts["bookmarks"] == 2 and counts["labels"] == 2 and counts["comment_lines"] >= 3
    assert not list(h.program.getBookmarkManager().getBookmarksIterator())
    assert "patch_two_sites_1" not in {str(s.getName()) for s in h.program.getSymbolTable().getAllSymbols(True)}


@pytest.mark.ghidra
def test_a_site_whose_bytes_do_not_match_is_skipped_unless_forced(site_program):
    h, _patches, dll, tmp = site_program
    wrong = patchfile_from_data(
        [{"name": "Wrong", "type": "memory", "gameCode": "ABC", "patches": [{"offset": 0x600 + JZ, "dllName": "x.dll", "dataDisabled": "FFFF", "dataEnabled": "9090"}]}]
    )
    rep = sites.annotate_program(h, wrong, dry_run=True)
    assert rep.annotated == 0 and any("match neither the original nor the patched form" in s for s in rep.skipped)
    forced = sites.annotate_program(h, wrong, force=True, dry_run=True)
    assert forced.annotated == 1
    # an entry for another build is skipped with the reason
    other = patchfile_from_data(
        [{"name": "Elsewhere", "type": "memory", "gameCode": "ABC", "peIdentifier": "ABC-00000001_1", "patches": [{"offset": 0x600, "dataDisabled": "48", "dataEnabled": "90"}]}]
    )
    _bid, found, notes = sites.build_context(h, other)
    assert found == [] and any("is for ABC-00000001_1" in n for n in notes)
