"""Nothing tracked in the repo may depend on one machine: no drive letters, user names or home folders, no OS-specific interpreter paths.

Where Ghidra, the binaries and the workspace live is configuration (arguments and ``KHX_*`` / ``GHIDRA_INSTALL_DIR`` environment variables, see
docs/TOOLS.md), so this workbench runs on anyone's system. The check covers the files git would commit (tracked and untracked-but-not-ignored); outside a
git checkout it walks the tree. The personal markers are derived at run time from whoever runs the test (user name, home folder), so nobody's name
is written into the repository: a contributor's own paths are what the test catches.
Strings that are *data from binaries* (a PDB path such as ``C:/work/proj/...`` found inside a DLL) are exempt: their line says ``pdb``.
"""

from __future__ import annotations

import getpass
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "workspace", "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build", "node_modules", "downloads", "user-supplied"}
SKIP_FILES = {"uv.lock", "reference.local.json"}  # (registry URLs and hashes; the git-ignored per-machine test config)
TEXT_SUFFIXES = {".py", ".md", ".json", ".toml", ".txt", ".cfg", ".ini", ".yml", ".yaml", ""}

# a drive-letter path (`D:\x`, `d:/x`); `https://` is not one because the letter is not at a word boundary
DRIVE_PATH = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/]")
# an interpreter path of one OS inside the venv
VENV_PATH = re.compile(r"\.venv[\\/]+(Scripts|bin)")  # (several separators: JSON writes one backslash as two)
# a user folder of any OS
HOME_FOLDER = re.compile(r"[\\/]Users[\\/][^\\/\s]|[\\/]home[\\/][a-z]")


def personal_markers() -> list[re.Pattern[str]]:
    """The current user's name and home folder, as patterns (names shorter than 4 characters are too likely to be ordinary words)."""
    out = []
    names = {getpass.getuser(), Path.home().name}
    for n in names:
        if len(n) >= 4:
            out.append(re.compile(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])", re.IGNORECASE))
    home = str(Path.home())
    out.append(re.compile(re.escape(home).replace(re.escape("\\"), "[\\\\/]"), re.IGNORECASE))
    return out


def candidate_files() -> list[Path]:
    try:
        names = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.splitlines()
        files = [ROOT / n for n in names if n]
    except (OSError, subprocess.CalledProcessError):
        files = [p for p in sorted(ROOT.rglob("*")) if p.is_file()]
    out = []
    for p in files:
        rel = p.relative_to(ROOT)
        if not p.is_file() or SKIP_DIRS & set(rel.parts) or p.name in SKIP_FILES:
            continue
        if p.suffix.lower() in TEXT_SUFFIXES and p.stat().st_size < 2_000_000:
            out.append(p)
    return out


def offending_lines(patterns: list[re.Pattern[str]], *, allow_pdb: bool) -> list[str]:
    hits = []
    for p in candidate_files():
        if p.name == Path(__file__).name:
            continue
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue  # a binary file with a text-like name
        for n, line in enumerate(lines, 1):
            if any(rx.search(line) for rx in patterns) and not (allow_pdb and "pdb" in line.lower()):
                hits.append(f"{p.relative_to(ROOT).as_posix()}:{n}: {line.strip()[:140]}")
    return hits


def test_no_drive_letter_paths_in_tracked_files():
    assert offending_lines([DRIVE_PATH], allow_pdb=True) == []


def test_no_user_names_or_home_folders_in_tracked_files():
    assert offending_lines([HOME_FOLDER, *personal_markers()], allow_pdb=False) == []


def test_no_os_specific_venv_interpreter_paths_in_tracked_files():
    assert offending_lines([VENV_PATH], allow_pdb=False) == []


def test_the_checks_themselves_catch_what_they_are_for(tmp_path, monkeypatch):
    bs = chr(92)
    assert DRIVE_PATH.search("open " + "D:" + bs + "data" + bs + "x.dll") and DRIVE_PATH.search("c:/tools/ghidra")
    assert not DRIVE_PATH.search("https://example.org/a") and not DRIVE_PATH.search("a:b")
    assert VENV_PATH.search(".venv" + bs + "Scripts" + bs + "python.exe") and VENV_PATH.search(".venv/bin/python") and not VENV_PATH.search(".venv/")
    assert HOME_FOLDER.search("/home/someone/x") and HOME_FOLDER.search(bs + "Users" + bs + "someone") and not HOME_FOLDER.search("/usr/home_dir")
    monkeypatch.setattr(getpass, "getuser", lambda: "sampleuser")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "sampleuser"))
    marks = personal_markers()
    assert any(m.search("owned by SampleUser") for m in marks) and not any(m.search("sampleusers are many") for m in marks)
    assert any(m.search(str(tmp_path / "sampleuser" / "proj")) for m in marks)


def test_machine_settings_come_from_the_environment_only(monkeypatch):
    """The configuration points are environment variables with neutral defaults: unset means 'not configured', never somebody's folder."""
    from kawaiidra_hx.config import load_settings

    for name in ("GHIDRA_INSTALL_DIR", "KHX_WORKSPACE", "KHX_DEFAULT_PROJECT"):
        monkeypatch.delenv(name, raising=False)
    s = load_settings()
    assert s.ghidra_dir is None and s.workspace.name == "workspace" and s.default_project == "default"
    monkeypatch.setenv("KHX_DEFAULT_PROJECT", "mine")
    assert load_settings().default_project == "mine"
