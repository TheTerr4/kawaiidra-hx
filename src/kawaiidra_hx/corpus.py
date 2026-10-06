"""Test corpus: binaries to exercise kawaiidra-hx on, handled conservatively.

Rules (they exist because binaries from the internet are untrusted input):
  * static analysis only: nothing in the corpus is ever executed;
  * ``corpus/user-supplied/`` holds files the *user* copied there themselves; nothing on the machine is auto-discovered;
  * ``corpus/downloads/`` holds files fetched via a manifest entry that pins an https URL, the exact size and a
    SHA-256 taken from the vendor's published checksum; a mismatch deletes the download;
  * every fetch needs an explicit ``confirm=True`` (CLI ``--yes``) given by a human after reading what it will fetch.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from .core.errors import KhxError
from .pe import PEError, parse_pe

CORPUS_ROOT = Path(__file__).resolve().parents[2] / "corpus"
MAX_DOWNLOAD_SLACK = 1024  # bytes tolerated over the pinned size before aborting


class CorpusError(KhxError):
    pass


@dataclass
class CorpusEntry:
    name: str
    url: str
    size: int
    sha256: str  # vendor-published digest of the downloaded file (archive or binary); see ``algo``
    file: str  # final file name under downloads/
    member: Optional[str] = None  # when url is a zip: the member to extract as `file`
    member_sha256: Optional[str] = None  # our own SHA-256 of the extracted member, recorded after the first verified fetch
    algo: str = "sha256"  # vendors differ: PuTTY publishes SHA-256, sqlite.org publishes SHA3-256
    license: str = ""
    source: str = ""  # where the checksum was published
    notes: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def load_manifest(path: Optional[Path] = None) -> list[CorpusEntry]:
    path = path or (CORPUS_ROOT / "manifest.json")
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for e in data.get("entries", []):
        algo = "sha3_256" if "sha3_256" in e else "sha256"
        for key in ("name", "url", "size", algo, "file"):
            if key not in e:
                raise CorpusError(f"manifest entry {e.get('name', '?')!r} lacks required field {key!r}")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", e[algo]):
            raise CorpusError(f"manifest entry {e['name']!r}: {algo} must be 64 hex digits")
        out.append(
            CorpusEntry(
                name=e["name"], url=e["url"], size=int(e["size"]), sha256=e[algo].lower(), file=e["file"], algo=algo,
                member=e.get("member"), member_sha256=(e.get("member_sha256") or "").lower() or None,
                license=e.get("license", ""), source=e.get("source", ""), notes=e.get("notes", ""), raw=e,
            )
        )  # fmt: skip
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _ssl_context() -> Any:
    """Verifying TLS context from the certifi (Mozilla) bundle. The Windows store on this machine reports an expired
    certificate for sqlite.org (a stale root chosen during path building); certifi validates it. Verification is never
    disabled."""
    import ssl

    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # noqa: BLE001
        return ssl.create_default_context()


def _safe_name(name: str) -> str:
    if name != os.path.basename(name) or name in ("", ".", "..") or "/" in name or "\\" in name:
        raise CorpusError(f"unsafe file name {name!r}")
    return name


def describe_entry(entry: CorpusEntry) -> str:
    return (
        f"{entry.name}: {entry.file}\n"
        f"  url     {entry.url}\n"
        f"  size    {entry.size} bytes ({entry.size / 1e6:.2f} MB)\n"
        f"  sha256  {entry.sha256}\n"
        + (f"  member  {entry.member} (sha256 {entry.member_sha256})\n" if entry.member else "")
        + (f"  license {entry.license}\n" if entry.license else "")
        + (f"  checksum published at {entry.source}\n" if entry.source else "")
    )


def fetch(
    entry: CorpusEntry,
    *,
    confirm: bool = False,
    dest: Optional[Path] = None,
    allow_insecure_localhost: bool = False,
) -> Path:
    """Download one manifest entry into ``corpus/downloads`` after verifying it. Requires ``confirm=True``."""
    if not confirm:
        raise CorpusError("refusing to download without explicit confirmation (pass confirm=True / --yes).\n" + describe_entry(entry))
    url = urlparse(entry.url)
    local_ok = allow_insecure_localhost and url.scheme == "http" and url.hostname in ("127.0.0.1", "localhost")
    if url.scheme != "https" and not local_ok:
        raise CorpusError(f"{entry.name}: only https URLs are allowed (got {url.scheme}://)")
    out_dir = dest or (CORPUS_ROOT / "downloads")
    out_dir.mkdir(parents=True, exist_ok=True)
    final = out_dir / _safe_name(entry.file)

    fd, tmp_name = tempfile.mkstemp(dir=out_dir, prefix=".fetch-", suffix=".part")
    tmp = Path(tmp_name)
    try:
        hasher = hashlib.new(entry.algo)
        total = 0
        req = urllib.request.Request(entry.url, headers={"User-Agent": "kawaiidra-hx-corpus/0.1"})
        with os.fdopen(fd, "wb") as f, urllib.request.urlopen(req, timeout=60, context=_ssl_context()) as resp:  # noqa: S310 - scheme checked above
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > entry.size + MAX_DOWNLOAD_SLACK:
                    raise CorpusError(f"{entry.name}: download exceeds the pinned size ({entry.size}); aborting")
                hasher.update(chunk)
                f.write(chunk)
        if total != entry.size:
            raise CorpusError(f"{entry.name}: size {total} != pinned {entry.size}")
        if hasher.hexdigest() != entry.sha256:
            raise CorpusError(f"{entry.name}: {entry.algo} mismatch\n  expected {entry.sha256}\n  got      {hasher.hexdigest()}")

        if entry.member:
            extracted = _extract_member(tmp, entry, out_dir)
            tmp.unlink()
            tmp = extracted
        os.replace(tmp, final)
        tmp = None  # type: ignore[assignment]
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()
    return final


def _extract_member(archive: Path, entry: CorpusEntry, out_dir: Path) -> Path:
    member = entry.member or ""
    if member.startswith(("/", "\\")) or ".." in Path(member).parts or ":" in member:
        raise CorpusError(f"{entry.name}: unsafe zip member path {member!r}")
    with zipfile.ZipFile(archive) as z:
        try:
            info = z.getinfo(member)
        except KeyError:
            raise CorpusError(f"{entry.name}: {member!r} not found in the archive (members: {z.namelist()[:12]})") from None
        if info.file_size > max(entry.size * 50, 1 << 26):
            raise CorpusError(f"{entry.name}: member {member!r} is implausibly large when unpacked ({info.file_size})")
        fd, name = tempfile.mkstemp(dir=out_dir, prefix=".extract-", suffix=".part")
        out = Path(name)
        try:
            with os.fdopen(fd, "wb") as dst, z.open(info) as src:
                shutil.copyfileobj(src, dst)
            if entry.member_sha256 and sha256_file(out) != entry.member_sha256:
                raise CorpusError(f"{entry.name}: extracted {member!r} sha256 mismatch")
        except BaseException:
            out.unlink(missing_ok=True)
            raise
    return out


# --- verification of what is on disk -----------------------------------------------------------


@dataclass
class FileReport:
    path: Path
    size: int
    sha256: str
    pe: str
    signature: str
    problems: list[str] = field(default_factory=list)

    def format(self) -> str:
        flag = "OK  " if not self.problems else "FAIL"
        extra = "".join(f"\n      ! {p}" for p in self.problems)
        return f"[{flag}] {self.path.name}  {self.size} bytes  sha256={self.sha256[:16]}...  {self.pe}  signature: {self.signature}{extra}"


def authenticode_status(path: Path) -> str:
    """Windows only: ``Get-AuthenticodeSignature`` on a file already inside our corpus folder."""
    if os.name != "nt":
        return "n/a (not Windows)"
    ps = (
        "$s = Get-AuthenticodeSignature -LiteralPath $env:KHX_CORPUS_FILE; "
        "$subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }; "
        "'{0}|{1}' -f $s.Status, $subj"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=90, env={**os.environ, "KHX_CORPUS_FILE": str(path)},
        )  # fmt: skip
        status, _, subject = r.stdout.strip().partition("|")
        if not status:
            return "unknown"
        return f"{status} {subject[:90]}".strip()
    except Exception as e:  # noqa: BLE001
        return f"unknown ({type(e).__name__})"


def verify_file(path: Path, expected: Optional[str] = None, check_signature: bool = True, algo: str = "sha256") -> FileReport:
    """Hash ``path`` (always SHA-256 for display), compare with ``expected`` under ``algo`` if given, parse the PE header."""
    problems: list[str] = []
    digest = sha256_file(path)
    if expected:
        got = digest if algo == "sha256" else hashlib.new(algo, path.read_bytes()).hexdigest()
        if got != expected.lower():
            problems.append(f"{algo} differs from the pinned value ({expected})")
    try:
        pe = parse_pe(path)
        pe_text = f"{pe.machine} {'DLL' if pe.is_dll else 'EXE'} base=0x{pe.image_base:X}"
    except PEError as e:
        pe_text = "not a PE"
        problems.append(str(e))
    sig = authenticode_status(path) if check_signature else "skipped"
    return FileReport(path, path.stat().st_size, digest, pe_text, sig, problems)


def pinned_digest(entry: CorpusEntry) -> tuple[Optional[str], str]:
    """The digest to check the *installed* file against: the extracted member's SHA-256 for zip entries (the archive's
    vendor digest only applies to the archive, which is not kept), else the vendor digest."""
    if entry.member:
        return entry.member_sha256, "sha256"
    return entry.sha256, entry.algo


def verify_all(root: Optional[Path] = None, check_signature: bool = True) -> list[FileReport]:
    root = root or CORPUS_ROOT
    manifest = {e.file: e for e in load_manifest(root / "manifest.json")}
    reports: list[FileReport] = []
    downloads = root / "downloads"
    if downloads.is_dir():
        for p in sorted(downloads.iterdir()):
            if p.is_file() and not p.name.startswith("."):
                e = manifest.get(p.name)
                if e is None:
                    rep = verify_file(p, None, check_signature)
                    rep.problems.append("not listed in manifest.json")
                else:
                    expected, algo = pinned_digest(e)
                    rep = verify_file(p, expected, check_signature, algo)
                reports.append(rep)
    supplied = root / "user-supplied"
    if supplied.is_dir():
        reports += [verify_file(p, None, check_signature) for p in sorted(supplied.iterdir()) if p.is_file() and not p.name.startswith(".")]
    return reports


def corpus_files(root: Optional[Path] = None) -> list[Path]:
    """Binaries present on disk (downloads + user-supplied), for tests that want 'any real binary'."""
    root = root or CORPUS_ROOT
    out: list[Path] = []
    for sub in ("downloads", "user-supplied"):
        d = root / sub
        if d.is_dir():
            out += [p for p in sorted(d.iterdir()) if p.is_file() and p.suffix.lower() in (".dll", ".exe", ".sys")]
    return out
