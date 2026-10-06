"""Corpus safety rails, tested against a local HTTP server (no internet involved)."""

from __future__ import annotations

import hashlib
import http.server
import json
import threading
import zipfile
from functools import partial
from pathlib import Path

import pytest

from kawaiidra_hx import corpus

from .conftest import build_pe


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture()
def server(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *a, **k: None  # type: ignore[attr-defined]
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield root, f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def entry(url, data, file="tool.dll", **kw) -> corpus.CorpusEntry:
    return corpus.CorpusEntry(name="t", url=url, size=len(data), sha256=sha(data), file=file, **kw)


def test_fetch_requires_confirmation(server, tmp_path):
    root, base = server
    data = build_pe()
    (root / "tool.dll").write_bytes(data)
    with pytest.raises(corpus.CorpusError, match="explicit confirmation"):
        corpus.fetch(entry(f"{base}/tool.dll", data), dest=tmp_path / "dl", allow_insecure_localhost=True)
    assert not (tmp_path / "dl").exists() or not any((tmp_path / "dl").iterdir())


def test_only_https_unless_localhost_opt_in(tmp_path):
    e = entry("http://example.com/tool.dll", b"x" * 10)
    with pytest.raises(corpus.CorpusError, match="only https"):
        corpus.fetch(e, confirm=True, dest=tmp_path)
    e2 = entry("ftp://example.com/tool.dll", b"x" * 10)
    with pytest.raises(corpus.CorpusError, match="only https"):
        corpus.fetch(e2, confirm=True, dest=tmp_path, allow_insecure_localhost=True)


def test_good_download_is_verified_and_installed(server, tmp_path):
    root, base = server
    data = build_pe()
    (root / "tool.dll").write_bytes(data)
    out = corpus.fetch(entry(f"{base}/tool.dll", data), confirm=True, dest=tmp_path / "dl", allow_insecure_localhost=True)
    assert out.read_bytes() == data and out.name == "tool.dll"
    assert not list((tmp_path / "dl").glob(".fetch-*")), "temp files must be cleaned up"
    rep = corpus.verify_file(out, sha(data), check_signature=False)
    assert not rep.problems and "x64 DLL" in rep.pe


def test_sha3_vendor_digest_supported(server, tmp_path):
    root, base = server
    data = build_pe()
    (root / "tool.dll").write_bytes(data)
    e = entry(f"{base}/tool.dll", data)
    e.algo, e.sha256 = "sha3_256", hashlib.sha3_256(data).hexdigest()
    out = corpus.fetch(e, confirm=True, dest=tmp_path / "dl", allow_insecure_localhost=True)
    assert out.read_bytes() == data
    assert not corpus.verify_file(out, e.sha256, check_signature=False, algo="sha3_256").problems
    assert corpus.verify_file(out, "0" * 64, check_signature=False, algo="sha3_256").problems
    e.sha256 = "0" * 64
    with pytest.raises(corpus.CorpusError, match="sha3_256 mismatch"):
        corpus.fetch(e, confirm=True, dest=tmp_path / "dl2", allow_insecure_localhost=True)


def test_manifest_loads_sha3_entries_and_pins_member_digest(tmp_path):
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps({"entries": [{
        "name": "z", "url": "https://x/z.zip", "size": 10, "sha3_256": "B" * 64, "file": "z.dll", "member": "z.dll",
        "member_sha256": "c" * 64,
    }]}))
    e = corpus.load_manifest(p)[0]
    assert e.algo == "sha3_256" and e.sha256 == "b" * 64
    assert corpus.pinned_digest(e) == ("c" * 64, "sha256")  # installed member is checked against OUR sha256, not the zip's SHA3
    e.member_sha256 = None
    assert corpus.pinned_digest(e) == (None, "sha256")


def test_hash_mismatch_deletes_download(server, tmp_path):
    root, base = server
    data = build_pe()
    (root / "tool.dll").write_bytes(data)
    e = entry(f"{base}/tool.dll", data)
    e.sha256 = "0" * 64
    with pytest.raises(corpus.CorpusError, match="sha256 mismatch"):
        corpus.fetch(e, confirm=True, dest=tmp_path / "dl", allow_insecure_localhost=True)
    assert not (tmp_path / "dl" / "tool.dll").exists()
    assert not list((tmp_path / "dl").glob(".fetch-*"))


def test_oversize_and_wrong_size_rejected(server, tmp_path):
    root, base = server
    big = b"A" * 5000
    (root / "big.bin").write_bytes(big)
    small_pin = entry(f"{base}/big.bin", b"A" * 100, file="big.bin")
    small_pin.sha256 = sha(big)
    with pytest.raises(corpus.CorpusError, match="exceeds the pinned size"):
        corpus.fetch(small_pin, confirm=True, dest=tmp_path / "dl", allow_insecure_localhost=True)

    short = entry(f"{base}/big.bin", b"A" * 5000 + b"B" * 10, file="big.bin")  # pinned larger than served
    with pytest.raises(corpus.CorpusError, match="size"):
        corpus.fetch(short, confirm=True, dest=tmp_path / "dl", allow_insecure_localhost=True)


def test_zip_member_extraction_and_traversal_guard(server, tmp_path):
    root, base = server
    dll = build_pe()
    zpath = root / "pkg.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("bin/tool.dll", dll)
        z.writestr("../evil.dll", b"nope")
    zdata = zpath.read_bytes()
    good = entry(f"{base}/pkg.zip", zdata, member="bin/tool.dll", member_sha256=sha(dll))
    out = corpus.fetch(good, confirm=True, dest=tmp_path / "dl", allow_insecure_localhost=True)
    assert out.read_bytes() == dll

    bad_member = entry(f"{base}/pkg.zip", zdata, member="../evil.dll")
    with pytest.raises(corpus.CorpusError, match="unsafe zip member"):
        corpus.fetch(bad_member, confirm=True, dest=tmp_path / "dl2", allow_insecure_localhost=True)

    wrong_hash = entry(f"{base}/pkg.zip", zdata, member="bin/tool.dll", member_sha256="1" * 64)
    with pytest.raises(corpus.CorpusError, match="extracted .* sha256 mismatch"):
        corpus.fetch(wrong_hash, confirm=True, dest=tmp_path / "dl3", allow_insecure_localhost=True)
    assert not list((tmp_path / "dl3").glob("tool.dll"))


def test_unsafe_target_file_name_rejected(server, tmp_path):
    root, base = server
    (root / "x.bin").write_bytes(b"abc")
    e = entry(f"{base}/x.bin", b"abc", file="../escape.dll")
    with pytest.raises(corpus.CorpusError, match="unsafe file name"):
        corpus.fetch(e, confirm=True, dest=tmp_path / "dl", allow_insecure_localhost=True)


def test_manifest_validation(tmp_path):
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps({"entries": [{"name": "a", "url": "https://x/y", "size": 1, "sha256": "zz", "file": "a.dll"}]}))
    with pytest.raises(corpus.CorpusError, match="64 hex"):
        corpus.load_manifest(p)
    p.write_text(json.dumps({"entries": [{"name": "a", "url": "https://x/y"}]}))
    with pytest.raises(corpus.CorpusError, match="lacks required field"):
        corpus.load_manifest(p)
    p.write_text(json.dumps({"entries": [{"name": "a", "url": "https://x/y", "size": 3, "sha256": "A" * 64, "file": "a.dll"}]}))
    assert corpus.load_manifest(p)[0].sha256 == "a" * 64
    assert corpus.load_manifest(tmp_path / "missing.json") == []


def test_verify_all_flags_unlisted_downloads_and_non_pe(tmp_path):
    root = tmp_path / "corpus"
    (root / "downloads").mkdir(parents=True)
    (root / "user-supplied").mkdir()
    (root / "downloads" / "mystery.dll").write_bytes(build_pe())
    (root / "user-supplied" / "notes.txt").write_text("hello")
    (root / "user-supplied" / "mine.dll").write_bytes(build_pe(is64=False, image_base=0x10000000))
    reports = {r.path.name: r for r in corpus.verify_all(root, check_signature=False)}
    assert "not listed in manifest.json" in reports["mystery.dll"].problems
    assert reports["notes.txt"].problems and reports["notes.txt"].pe == "not a PE"
    assert not reports["mine.dll"].problems and "x86 DLL" in reports["mine.dll"].pe
    assert [p.name for p in corpus.corpus_files(root)] == ["mystery.dll", "mine.dll"]
