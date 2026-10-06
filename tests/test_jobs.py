"""Import + analysis as a background job, and the write path, on a tiny synthetic PE (fast, no real binary needed)."""

from __future__ import annotations

import os

import pytest

from kawaiidra_hx import annotate, commands
from kawaiidra_hx.core import KhxError, ReadOnlyError, get_session
from kawaiidra_hx.core.jobs import get_jobs, import_program

from .conftest import build_pe

pytestmark = pytest.mark.ghidra

CODE = bytes.fromhex("B863000000C3") + b"\xCC" * 10  # mov eax,99 ; ret ; padding
ENTRY_VA = "0x180001000"


@pytest.fixture(scope="module")
def session():
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR not set")
    return get_session()


@pytest.fixture()
def tiny_dll(tmp_path):
    p = tmp_path / "tiny.dll"
    p.write_bytes(build_pe(entry_rva=0x1000, body=CODE))
    return p


def test_import_job_reports_progress_and_program_is_queryable(session, tiny_dll, tmp_path):
    proj = str(tmp_path / "proj")
    jobs = get_jobs()
    job = jobs.submit("import", "tiny.dll", lambda j: import_program(session, tiny_dll, proj, job=j))
    jobs.wait(job, timeout=240)
    try:
        assert job.state == "done", job.error
        assert job.result["analyzed"] is True and job.result["functions"] >= 1
        assert job.history, "the job monitor should have captured progress messages"
        assert {"import", "analyze"} <= {line.split("] ")[1].split(":")[0] for line in job.history} or job.phase == "done"

        h = session.program(proj, "tiny.dll")
        assert not h.writable
        assert "MOV EAX,0x63" in commands.run_command(h, f"disf {ENTRY_VA}", session.settings)
        assert "99" in commands.run_command(h, f"decomp {ENTRY_VA}", session.settings)
        # Ghidra remembers the file bytes: file offset <-> address works without the original file
        res = commands.run_command(h, f"resolve {ENTRY_VA}", session.settings)
        assert "file offset  0x600" in res and ".text" in res
        assert "0x180001000" in commands.run_command(h, "resolve off:0x600", session.settings)

        # importing the same name again must not silently clobber the program
        with pytest.raises(KhxError, match="already exists"):
            import_program(session, tiny_dll, proj)
    finally:
        session.close_project(proj, discard=True)


def test_read_only_by_default_and_write_roundtrip(session, tiny_dll, tmp_path):
    proj = str(tmp_path / "proj_rw")
    import_program(session, tiny_dll, proj, analyze=True)
    try:
        ro = session.program(proj, "tiny.dll")
        with pytest.raises(ReadOnlyError):
            annotate.rename(ro, ENTRY_VA, "my_func")

        rw = session.program(proj, "tiny.dll", write=True)  # upgrades the handle
        assert rw.writable
        assert "renamed to my_func" in annotate.rename(rw, ENTRY_VA, "my_func")
        assert "comment set" in annotate.set_comment(rw, ENTRY_VA, "returns 99", "plate")
        assert rw.has_unsaved_changes
        with pytest.raises(KhxError, match="unsaved changes"):
            rw.close()
        rw.save()
        assert not rw.has_unsaved_changes
        session.close_project(proj)

        again = session.program(proj, "tiny.dll")  # fresh read-only open sees the saved rename
        assert "my_func" in commands.run_command(again, f"resolve {ENTRY_VA}", session.settings)
    finally:
        session.close_project(proj, discard=True)


def test_import_overwrite_replaces_program(session, tiny_dll, tmp_path):
    proj = str(tmp_path / "proj_ow")
    try:
        import_program(session, tiny_dll, proj, analyze=False)
        res = import_program(session, tiny_dll, proj, analyze=True, overwrite=True)
        assert res["analyzed"] is True
    finally:
        session.close_project(proj, discard=True)
