"""Function fingerprints + matching between builds: synthetic indexes for the algorithm, a tiny PE through Ghidra for the extraction."""

from __future__ import annotations

import os

import pytest

from kawaiidra_hx.pe import PEImage
from kawaiidra_hx.queries.fingerprint import FuncFP, FuncIndex, iat_map
from kawaiidra_hx.match.funcmatch import evaluate, match_functions, pairs_by_unique_strings, size_sim, skeleton_sim

from .conftest import build_pe
from .test_pe_tables import build_pe_with_tables


def fp(entry, n=20, strings=(), imports=(), consts=(), skeleton=None, calls=()):
    return FuncFP(
        entry=entry, size=n * 4, n=n, strings=frozenset(strings), imports=frozenset(imports), consts=frozenset(consts),
        skeleton=tuple(skeleton) if skeleton is not None else tuple(f"OP{i % 7}" for i in range(n)), calls=tuple(calls), name=f"f{entry:x}",
    )  # fmt: skip


def index(*funcs):
    return FuncIndex(funcs={f.entry: f for f in funcs})


def two_builds():
    """f1 (unique string) calls f2 and f3; f3 calls f4 (unique constant); f5 is a decoy with the same size as f2 but a different skeleton."""
    sk2 = ["CALL", "TEST", "JZ", "CMP", "JNZ", "XOR", "CALL"] * 3
    A = index(
        fp(0x1000, 30, strings=["alpha-string"], calls=[0x2000, 0x3000]),
        fp(0x2000, 21, skeleton=sk2),
        fp(0x3000, 40, calls=[0x4000]),
        fp(0x4000, 25, consts=[0x12345]),
        fp(0x5000, 21, skeleton=["JMP"] * 21),
    )
    B = index(
        fp(0x9000, 31, strings=["alpha-string"], calls=[0x9100, 0x9200]),
        fp(0x9100, 22, skeleton=sk2 + ["NOP"]),
        fp(0x9200, 41, calls=[0x9300]),
        fp(0x9300, 24, consts=[0x12345]),
        fp(0x9400, 22, skeleton=["JMP"] * 22),
    )
    return A, B


def test_seed_by_unique_string_then_propagate_through_calls():
    A, B = two_builds()
    m = match_functions(A, B)
    assert m[0x1000].b == 0x9000 and m[0x1000].method == "seed"
    assert m[0x2000].b == 0x9100 and m[0x2000].method == "callee"  # aligned by call order, skeleton agrees
    assert m[0x3000].b == 0x9200 and m[0x4000].b == 0x9300
    assert 0x5000 not in m  # the decoy is nobody's callee and shares no feature
    truth = {0x1000: 0x9000, 0x2000: 0x9100, 0x3000: 0x9200, 0x4000: 0x9300}
    assert evaluate(m, truth) == {"truth": 4, "right": 4, "wrong": 0, "missed": 0, "recall": 1.0, "precision": 1.0}


def test_one_shared_constant_alone_is_not_enough_unless_the_threshold_is_lowered():
    A, B = two_builds()
    assert match_functions(A, B, kinds=("consts",)) == {}  # strings held out, a single constant weighs 0.8 < seed_min
    m = match_functions(A, B, kinds=("consts",), seed_min=0.5)
    assert m[0x4000].b == 0x9300 and m[0x4000].method == "seed"
    assert m[0x3000].b == 0x9200 and m[0x3000].method == "callee"  # reached through the sole-caller rule
    assert 0x1000 in m and m[0x1000].b == 0x9000  # ... and so on up the call chain


def test_nothing_is_matched_on_weak_or_ambiguous_evidence():
    A = index(fp(0x1000, 30, strings=["common"]), fp(0x2000, 30, strings=["common"]))
    B = index(fp(0x9000, 30, strings=["common"]), fp(0x9100, 30, strings=["common"]))
    assert match_functions(A, B) == {}  # the string is shared by two functions on each side: no unique anchor
    # same unique string, wildly different size and skeleton: rejected as a coincidence
    A2 = index(fp(0x1000, 10, strings=["only-here"], skeleton=["CALL"] * 10))
    B2 = index(fp(0x9000, 400, strings=["only-here"], skeleton=["JMP"] * 400))
    assert match_functions(A2, B2) == {}
    assert size_sim(A2.funcs[0x1000], B2.funcs[0x9000]) < 0.05 and skeleton_sim(A2.funcs[0x1000], B2.funcs[0x9000]) == 0.0


def test_unique_string_pairs_are_the_ground_truth_helper():
    A, B = two_builds()
    assert pairs_by_unique_strings(A, B, min_len=5) == {0x1000: 0x9000}
    A2 = index(fp(0x1000, strings=["abcdef"]), fp(0x2000, strings=["abcdef", "uvwxyz"]))
    B2 = index(fp(0x9000, strings=["abcdef"]))
    assert pairs_by_unique_strings(A2, B2) == {}  # "abcdef" is not unique in A


def test_index_helpers():
    A, _ = two_builds()
    assert A.df("strings", "alpha-string") == 1 and A.df("consts", 0x99) == 0
    assert A.callers[0x2000] == [0x1000] and A.callers[0x4000] == [0x3000]
    assert A.containing(0x1010).entry == 0x1000 and A.containing(0x9999999) is None
    assert A.containing(0x0FFF) is None and A.containing(0x1000 + 30 * 4 - 1).entry == 0x1000 and A.containing(0x1000 + 30 * 4) is None
    # a fragmented body (an out-of-line chunk elsewhere) is found through its ranges, not through entry + size
    frag = FuncFP(entry=0x7000, size=20, n=5, ranges=((0x7000, 0x7007), (0x8000, 0x800F)))
    idx = FuncIndex(funcs={0x7000: frag, 0x7100: fp(0x7100, 4)})
    assert idx.containing(0x8008).entry == 0x7000 and idx.containing(0x7008) is None and idx.containing(0x7100).entry == 0x7100


def test_iat_map_uses_names_and_ordinals():
    img = PEImage(build_pe_with_tables(is64=True))
    m = iat_map(img)
    base = img.info.image_base
    assert m[base + 0x2320] == "kernel32.dll!ExitProcess" and m[base + 0x2328] == "kernel32.dll!#5" and m[base + 0x2360] == "helper.dll!helper_init"


@pytest.mark.ghidra
def test_extract_fingerprints_from_a_tiny_program(tmp_path):
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR not set")
    from kawaiidra_hx.core import get_session
    from kawaiidra_hx.core.jobs import import_program
    from kawaiidra_hx.queries.fingerprint import extract_fingerprints

    code = bytes.fromhex("B845230100" "E806000000" "C3") + b"\xCC" * 5 + bytes.fromhex("31C0C3")  # mov eax,0x12345 | call +6 | ret | pad | xor eax,eax; ret
    dll = tmp_path / "t.dll"
    dll.write_bytes(build_pe(entry_rva=0x1000, body=code))
    proj = str(tmp_path / "proj")
    session = get_session()
    import_program(session, dll, proj, analyze=True)
    try:
        h = session.program(proj, "t.dll")
        idx = extract_fingerprints(h, {}, build_id="t")
        main = idx.funcs[0x180001000]
        assert main.n == 3 and 0x12345 in main.consts and main.calls == (0x180001010,)
        assert main.file_off == 0x600 and main.strings == frozenset() and idx.funcs[0x180001010].n == 2
        assert idx.containing(0x180001004).entry == 0x180001000 and main.ranges and main.ranges[0][0] == 0x180001000
        # the instruction stream: RVAs, lengths, tokens (kinds / kinds + scalar values), the direct callee as an RVA
        assert idx.version == 2 and idx.image_base == 0x180000000
        cs = main.code
        assert list(cs.rva) == [0x1000, 0x1005, 0x100A] and list(cs.size) == [5, 5, 1] and list(cs.callee) == [0, 0x1010, 0]
        assert [idx.vocab[t] for t in cs.t1] == ["MOV.RI", "CALL.C", "RET."] and [idx.vocab[t] for t in cs.t2][0] == "MOV.RI|12345"
        assert cs.index_of(0x1006) == 1 and cs.index_of(0x100B) == -1 and cs.index_of(0x0FFF) == -1
        assert [idx.vocab[t] for t in idx.funcs[0x180001010].code.t1] == ["XOR.RR", "RET."]
    finally:
        session.close_project(proj, discard=True)
