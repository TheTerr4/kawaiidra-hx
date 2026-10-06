"""JVM-free unit tests for config, output offloading, project references and the command parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from kawaiidra_hx import commands
from kawaiidra_hx.config import ConfigError, load_settings
from kawaiidra_hx.core import KhxError, ProjectNotFoundError, resolve_project
from kawaiidra_hx.outputs import emit, slice_lines
from kawaiidra_hx.queries.search import parse_byte_pattern
from kawaiidra_hx.util import parse_hex, parse_int


def settings(tmp_path: Path, **extra):
    env = {"KHX_WORKSPACE": str(tmp_path / "ws"), "GHIDRA_INSTALL_DIR": str(tmp_path / "nope")}
    env.update(extra)
    return load_settings(env)


def test_settings_defaults_and_overrides(tmp_path):
    s = settings(tmp_path, KHX_MAX_INLINE_CHARS="123", KHX_DECOMPILE_TIMEOUT="7", KHX_DEFAULT_PROJECT="p")
    assert s.max_inline_chars == 123 and s.decompile_timeout == 7 and s.default_project == "p"
    assert s.projects_dir == tmp_path / "ws" / "projects"
    with pytest.raises(ConfigError):
        s.require_ghidra()  # bogus directory is rejected with a clear message
    assert load_settings({"KHX_WORKSPACE": str(tmp_path)}).ghidra_dir is None


def test_emit_inline_when_small_and_offloaded_when_large(tmp_path):
    s = settings(tmp_path, KHX_MAX_INLINE_CHARS="200")
    assert emit("short", s) == "short"
    big = "\n".join(f"line {i:04d} " + "x" * 20 for i in range(100))
    out = emit(big, s, "my label/with:odd chars")
    assert "truncated" in out and "[full output saved to" in out
    saved = Path(out.rsplit("saved to ", 1)[1].rstrip("]"))
    assert saved.read_text(encoding="utf-8") == big
    assert saved.parent == s.results_dir and "my_label_with_odd_chars" in saved.name
    assert len(out) < len(big)


def test_slice_lines():
    text = "\n".join(str(i) for i in range(10))
    assert slice_lines(text) == text
    assert slice_lines(text, 2, 3) == "[lines 2-5 of 10]\n2\n3\n4"
    assert slice_lines(text, offset=8).endswith("8\n9")


def test_resolve_project_forms(tmp_path):
    s = settings(tmp_path)
    # bare name that does not exist yet -> clear error naming the expected path
    with pytest.raises(ProjectNotFoundError, match="not found"):
        resolve_project("missing", s)
    ref = resolve_project("fresh", s, create=True)
    assert ref.location == s.projects_dir / "fresh" and ref.name == "fresh" and not ref.exists()

    # a folder with exactly one .gpr (an existing analyzeHeadless project)
    folder = tmp_path / "ext"
    folder.mkdir()
    (folder / "proj.gpr").write_text("")
    assert resolve_project(str(folder), s).name == "proj"
    assert resolve_project(str(folder / "proj.gpr"), s).location == folder
    # ambiguous folder
    (folder / "other.gpr").write_text("")
    with pytest.raises(KhxError, match="several projects"):
        resolve_project(str(folder), s)
    # empty folder, not creating
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ProjectNotFoundError):
        resolve_project(str(empty), s)


def test_number_parsing():
    assert parse_int("6094176") == 6094176 and parse_int("0x5CFD60") == 6094176 and parse_int("5CFD60") == 6094176
    assert parse_hex("0x1805D0760") == parse_hex("1805d0760") == 0x1805D0760


def test_byte_pattern_parsing():
    assert parse_byte_pattern("B8 63 ?? 00") == (bytes([0xB8, 0x63, 0, 0]), bytes([0xFF, 0xFF, 0, 0xFF]))
    assert parse_byte_pattern("B863") == (bytes([0xB8, 0x63]), bytes([0xFF, 0xFF]))
    with pytest.raises(ValueError):
        parse_byte_pattern("ZZ")
    with pytest.raises(ValueError):
        parse_byte_pattern("")


def test_command_parser_errors_do_not_need_a_program(tmp_path):
    s = settings(tmp_path)
    with pytest.raises(KhxError, match="unknown command"):
        commands.run_command(None, "nonsense 1", s)
    with pytest.raises(KhxError, match="usage: decomp"):
        commands.run_command(None, "decomp", s)
    with pytest.raises(KhxError, match="usage: bytes"):
        commands.run_command(None, "bytes 0x1000", s)
    # a batch keeps going after errors and frames each block like Q.java
    out = commands.run_script(None, ["# comment", "", "nonsense", "decomp"], s)
    assert out.count("===========") == 4 and "ERR unknown command" in out and "ERR usage: decomp" in out


def test_every_command_is_documented():
    doc = commands.help_text()
    for name in commands.COMMANDS:
        assert name in doc, f"{name} missing from the command help"
