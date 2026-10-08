"""Order-aware function alignment, instruction-stream site mapping and the anchors that join them: synthetic indexes, no Ghidra."""

from __future__ import annotations

from kawaiidra_hx.queries.fingerprint import CodeStream, FuncFP, FuncIndex
from kawaiidra_hx.match.align import align_functions, align_gap, lis, Similarity
from kawaiidra_hx.match.anchors import AnchorContext
from kawaiidra_hx.match.funcmatch import FMatch
from kawaiidra_hx.match.locate import map_site

SK = tuple(f"OP{i % 7}" for i in range(60))


def fp(entry, n=20, strings=(), imports=(), consts=(), calls=(), skeleton=None, code=None):
    return FuncFP(
        entry=entry, size=n * 4, n=n, strings=frozenset(strings), imports=frozenset(imports), consts=frozenset(consts),
        skeleton=tuple(skeleton) if skeleton is not None else SK[:n], calls=tuple(calls), name=f"f{entry:x}", code=code,
    )  # fmt: skip


def index(*funcs, base=0, vocab=None):
    return FuncIndex(funcs={f.entry: f for f in funcs}, image_base=base, vocab=vocab if vocab is not None else [], version=2)  # (the vocabulary list is shared on purpose)


def test_lis_keeps_the_longest_increasing_run():
    assert lis([(1, 10), (2, 30), (3, 20), (4, 40), (5, 50)]) == [(1, 10), (3, 20), (4, 40), (5, 50)] or lis([(1, 10), (2, 30), (3, 20), (4, 40), (5, 50)]) == [(1, 10), (2, 30), (4, 40), (5, 50)]
    assert len(lis([(1, 10), (2, 30), (3, 20), (4, 40), (5, 50)])) == 4
    assert lis([]) == [] and lis([(1, 5)]) == [(1, 5)]
    assert len(lis([(1, 9), (2, 8), (3, 7)])) == 1  # strictly increasing: equal or falling values never chain


def two_builds():
    """Five functions in a row; only the first and last carry a string. The middle ones are told apart by size, constants and order."""
    A = index(
        fp(0x1000, 30, strings=["s-one"]), fp(0x1100, 12, consts=[0x111]), fp(0x1200, 50, consts=[0x222]),
        fp(0x1300, 25, calls=[0x1100]), fp(0x1400, 40, strings=["s-two"]),
    )  # fmt: skip
    B = index(
        fp(0x9000, 31, strings=["s-one"]), fp(0x9100, 12, consts=[0x111]), fp(0x9200, 52, consts=[0x222]),
        fp(0x9250, 7),  # a function that did not exist before, between the two
        fp(0x9300, 26, calls=[0x9100]), fp(0x9400, 41, strings=["s-two"]),
    )  # fmt: skip
    return A, B


def test_functions_between_two_anchored_neighbours_are_found_by_order_and_similarity():
    A, B = two_builds()
    m = align_functions(A, B)
    assert {a: x.b for a, x in m.items()} == {0x1000: 0x9000, 0x1100: 0x9100, 0x1200: 0x9200, 0x1300: 0x9300, 0x1400: 0x9400}
    assert m[0x1200].method == "align" and m[0x1000].method in ("seed", "string")
    assert 0x9250 not in {x.b for x in m.values()}  # the new function stays unmatched


def test_strings_are_not_used_anywhere_when_they_are_held_out():
    A, B = two_builds()
    with_strings = align_functions(A, B)
    without = align_functions(A, B, kinds=("imports", "consts"))
    assert without[0x1000].method == "align" and without[0x1400].method == "align"  # no string seed: order and similarity alone
    assert {a: x.b for a, x in without.items()} == {a: x.b for a, x in with_strings.items()}
    # the similarity must not read the strings either: two functions that differ only in their strings look identical to it
    X = index(fp(0x1000, 30, strings=["only-in-a"]))
    Y = index(fp(0x9000, 30, strings=["different"]))
    assert Similarity(X, Y, {}, use_strings=False)(0x1000, 0x9000) > Similarity(X, Y, {}, use_strings=True)(0x1000, 0x9000)


def test_a_pair_with_an_equally_good_rival_is_not_guessed():
    A = index(fp(0x1000, 30), fp(0x1100, 30))
    B = index(fp(0x9000, 30), fp(0x9100, 30))  # indistinguishable: nothing but order tells them apart
    sim = Similarity(A, B, {})
    got = align_gap([0x1000, 0x1100], [0x9000, 0x9100], sim, lambda a, b: sim.need(a, b, 0.55), 0.55)
    assert got == []
    got = align_gap([0x1000, 0x1100], [0x9000, 0x9100], sim, lambda a, b: sim.need(a, b, 0.55), 0.55, min_margin=0.0)
    assert [(a, b) for a, b, _s, _m in got] == [(0x1000, 0x9000), (0x1100, 0x9100)]  # with the margin off, order decides


def test_callees_must_agree_with_what_is_already_matched():
    A = index(fp(0x1000, 20, calls=[0x1500]), fp(0x1500, 20))
    B = index(fp(0x9000, 20, calls=[0x9500]), fp(0x9100, 20, calls=[0x9600]), fp(0x9500, 20), fp(0x9600, 20))
    sim = Similarity(A, B, {0x1500: 0x9500})
    assert sim(0x1000, 0x9000) > sim(0x1000, 0x9100)  # the one that calls the counterpart of my callee


# ---- instruction streams -------------------------------------------------------------------------------------------------------


def stream_of(vocab, items, base_rva):
    """``items``: (kind, size[, callee rva[, ref crc[, scalars]]])."""
    cs = CodeStream()
    rva = base_rva
    for it in items:
        kind, size = it[0], it[1]
        callee = it[2] if len(it) > 2 else 0
        ref = it[3] if len(it) > 3 else 0
        scal = it[4] if len(it) > 4 else ""
        for text in (kind, kind + "|" + scal):
            if text not in vocab:
                vocab.append(text)
        cs.rva.append(rva)
        cs.size.append(size)
        cs.t1.append(vocab.index(kind))
        cs.t2.append(vocab.index(kind + "|" + scal))
        cs.callee.append(callee)
        cs.ref.append(ref)
        rva += size
    return cs


BASE = 0x1000

SOURCE = [
    ("PUSH.R", 1), ("CALL.C", 5, 0x500), ("TEST.RR", 2), ("JZ.C+", 2), ("MOV.RM", 6, 0, 0, "1064"),
    ("CMP.RI", 3, 0, 0, "4"), ("JG.C+", 2), ("XOR.RR", 2), ("CALL.C", 5, 0x600), ("MOV.MR", 6, 0, 0xABC), ("RET.", 1),
]  # fmt: skip


def pair(src_items, dst_items, matched_callees=((0x500, 0x1500), (0x600, 0x1600))):
    va, vb = [], []
    a = index(base=BASE, vocab=va)
    b = index(base=BASE, vocab=vb)
    ca = stream_of(va, src_items, 0x100)
    cb = stream_of(vb, dst_items, 0x200)
    fa = fp(BASE + 0x100, len(src_items), code=ca)
    fb = fp(BASE + 0x200, len(dst_items), code=cb)
    a.funcs[fa.entry], b.funcs[fb.entry] = fa, fb
    pairs = {BASE + x: BASE + y for x, y in matched_callees}
    return a, b, fa, fb, pairs


def rva_of(items, k, base=0x100):
    return base + sum(it[1] for it in items[:k])


def test_a_site_is_carried_to_the_instruction_with_the_same_neighbours_even_when_operands_change():
    # same code, other struct offset / immediate and a re-encoded displacement-free instruction between: tokens ignore the operand values
    dst = [it if it[0] != "MOV.RM" else ("MOV.RM", 6, 0, 0, "a78") for it in SOURCE]
    dst = [("NOP.", 1)] + dst  # everything moves by one instruction and one byte
    A, B, fa, fb, pairs = pair(SOURCE, dst)
    k = 7  # XOR.RR, the instruction a patch would edit
    sm = map_site(A, B, fa, fb, pairs, rva_of(SOURCE, k), 2)
    assert sm.ok, sm.why
    assert sm.ia == k and sm.ib == k + 1 and sm.b_rva == 0x200 + 1 + sum(it[1] for it in SOURCE[:k]) and sm.rel == 0
    assert sm.left >= 1 and sm.right >= 1 and sm.distinctive >= 1


def test_a_site_inside_a_window_is_mapped_from_its_first_instruction_and_offset():
    A, B, fa, fb, pairs = pair(SOURCE, SOURCE)
    k = 4  # a 6-byte instruction; the patch starts 2 bytes into it and covers the next instruction too
    sm = map_site(A, B, fa, fb, pairs, rva_of(SOURCE, k) + 2, 6)
    assert sm.ok and sm.ia == 4 and sm.count == 2 and sm.rel == 2 and sm.ib == 4


def test_an_instruction_without_a_counterpart_or_encoded_differently_is_refused():
    dst = [it for it in SOURCE if it[0] != "XOR.RR"]  # the patched instruction is gone
    A, B, fa, fb, pairs = pair(SOURCE, dst)
    assert "no counterpart" in map_site(A, B, fa, fb, pairs, rva_of(SOURCE, 7), 2).why
    dst = [("XOR.RR", 3) if it[0] == "XOR.RR" else it for it in SOURCE]  # same instruction, longer encoding
    A, B, fa, fb, pairs = pair(SOURCE, dst)
    assert "encoded differently" in map_site(A, B, fa, fb, pairs, rva_of(SOURCE, 7), 2).why


def test_neighbours_must_be_aligned_at_the_sites_own_shift():
    # a run of identical calls: the difflib alignment can pair the site with a call elsewhere in the run; neighbours at another shift do not count
    src = [("CMP.RI", 3), ("JNZ.C+", 2), ("CALL.C", 5, 0x700), ("MOV.RR", 2), ("CALL.C", 5, 0x700), ("CALL.C", 5, 0x700), ("MOV.RM", 6), ("RET.", 1)]
    dst = [("CMP.RI", 3), ("JNZ.C+", 2), ("MOV.RR", 2), ("CALL.C", 5, 0x700), ("MOV.RR", 2), ("CALL.C", 5, 0x700), ("CALL.C", 5, 0x700), ("MOV.RM", 6), ("RET.", 1)]
    A, B, fa, fb, pairs = pair(src, dst, matched_callees=())
    sm = map_site(A, B, fa, fb, pairs, rva_of(src, 2), 5)
    assert sm.ok is False or sm.ib == 3  # either refused or placed on the call that follows the inserted MOV, never on a later one


def test_a_block_duplicated_in_the_target_function_is_not_guessed():
    X = [("PUSH.R", 1), ("MOV.RR", 2), ("MOV.RI", 5, 0, 0, "4"), ("CALL.C", 5, 0x500), ("TEST.RR", 2), ("JNZ.C+", 2), ("MOV.RR", 2)]
    src = X + [("RET.", 1)]
    dst = X + [("RET.", 1)] + X + [("RET.", 1)]
    A, B, fa, fb, pairs = pair(src, dst, matched_callees=((0x500, 0x500),))
    sm = map_site(A, B, fa, fb, pairs, rva_of(src, 2), 5)
    assert not sm.ok and "which copy is the site's cannot be told" in sm.why and "2 times in the target" in sm.why
    # the same number of copies on both sides: the site is the same one of them
    src2 = X + [("NOP.", 1)] + X + [("RET.", 1)]
    dst2 = X + [("NOP.", 1), ("NOP.", 1)] + X + [("RET.", 1)]
    A, B, fa, fb, pairs = pair(src2, dst2, matched_callees=((0x500, 0x500),))
    k = len(X) + 1 + 2  # the MOV.RI of the second copy
    sm = map_site(A, B, fa, fb, pairs, rva_of(src2, k), 5)
    assert sm.ok, sm.why
    assert sm.ib == len(X) + 2 + 2


def test_a_site_among_unremarkable_instructions_is_not_placed_by_position_alone():
    plain = [("MOV.RR", 2), ("ADD.RI", 3), ("MOV.RR", 2), ("SHL.RI", 3), ("MOV.RR", 2), ("AND.RI", 3), ("MOV.RR", 2), ("OR.RI", 3), ("RET.", 1)]
    longer = plain[:-1] + [("XOR.RR", 2), ("NEG.R", 2), ("NOT.R", 2), ("INC.R", 1), ("RET.", 1)]  # the target grew: no longer the same function as a whole
    A, B, fa, fb, pairs = pair(plain, longer, matched_callees=())
    sm = map_site(A, B, fa, fb, pairs, rva_of(plain, 4), 2)
    assert not sm.ok and "distinctive" in sm.why
    # a function that is the same instruction sequence in both builds needs no distinctive neighbour: position is the evidence
    A, B, fa, fb, pairs = pair(plain, plain, matched_callees=())
    sm = map_site(A, B, fa, fb, pairs, rva_of(plain, 4), 2)
    assert sm.ok and sm.ib == 4 and any("whole function" in n for n in sm.notes)


def test_version_one_fingerprints_are_refused_with_a_hint():
    A, B, fa, fb, pairs = pair(SOURCE, SOURCE)
    A.version = 1
    assert "re-extract" in map_site(A, B, fa, fb, pairs, rva_of(SOURCE, 7), 2).why


class _Info:
    def __init__(self, base, delta):
        self.image_base, self.delta = base, delta

    def offset_to_va(self, off):
        return off + self.delta

    def va_to_offset(self, va):
        return va - self.delta


class _Img:
    def __init__(self, delta):
        self.info = _Info(BASE, delta)


def test_anchor_context_turns_a_file_offset_of_a_into_a_file_offset_of_b():
    dst = [("NOP.", 1)] + SOURCE
    A, B, fa, fb, pairs = pair(SOURCE, dst)
    matched = {fa.entry: FMatch(fb.entry, 0.9, "align", 0.2)}
    ctx = AnchorContext(A, B, _Img(0x400000 - 0x600), _Img(0x400000 - 0x500), matched=matched)
    ctx.pairs = pairs | ctx.pairs
    site_va = BASE + rva_of(SOURCE, 7)
    got = ctx.locate(site_va - (0x400000 - 0x600), 2)  # file offset in A
    assert got.offset is not None, got.why
    assert got.offset + (0x400000 - 0x500) == BASE + 0x200 + 1 + sum(it[1] for it in SOURCE[:7]) and got.source_fn == fa.entry and got.target_fn == fb.entry
    # not inside any function / no counterpart / ambiguous counterpart: a reason, never a guess
    assert "not inside a function" in ctx.locate(0, 2).why
    other = AnchorContext(A, B, _Img(0x400000 - 0x600), _Img(0x400000 - 0x500), matched={})
    assert "no counterpart" in other.locate(site_va - (0x400000 - 0x600), 2).why
    assert "ambiguous" in ctx.locate(site_va - (0x400000 - 0x600), 2, min_margin=0.5).why


def test_anchor_context_needs_fingerprints_with_streams():
    old = FuncIndex(funcs={})
    import pytest

    with pytest.raises(ValueError, match="instruction streams"):
        AnchorContext(old, old, _Img(0), _Img(0), matched={})


def test_a_data_site_in_a_string_names_the_functions_that_read_it_and_their_counterparts():
    class Img:  # a "file" holding the string; the stub maps offsets 1:1
        def __init__(self, data):
            self.data = data
            self.info = _Info(BASE, 0)

    data = b"\x00" * 0x40 + b"\x00alpha_02\x00beta_new\x00" + b"\x00" * 0x40 + b"\x00\x01\x02ab\x00"
    at = data.index(b"alpha_02")
    A = index(fp(0x1000, 20, strings=["alpha_02", "beta_new"]), fp(0x1100, 20, strings=["alpha_02"]), fp(0x1200, 20, consts=[0x999]), fp(0x1300, 20))
    B = index(fp(0x9000, 20), fp(0x9100, 20), fp(0x9150, 21, consts=[0x999]), fp(0x9300, 20))
    matched = {0x1000: FMatch(0x9000, 0.9, "align"), 0x1300: FMatch(0x9300, 0.9, "align")}
    ctx = AnchorContext(A, B, Img(data), Img(b""), matched=matched)
    got = ctx.string_users(at + 1, 1)  # the patch edits the second character
    assert got.offset is None and "'alpha_02'" in got.why
    assert "0x1000 -> 0x9000" in got.why and "0x1100 (no counterpart" in got.why  # a matched user and an unmatched one with its candidates
    assert "0x9100" in got.why or "0x9150" in got.why
    assert "not inside a string literal" in ctx.string_users(len(data) - 4, 1).why  # binary bytes
    assert "'beta_new' is used by 0x1000 -> 0x9000" in ctx.string_users(data.index(b"beta_new") + 1, 1).why


# ---- RTTI vtable seeds -----------------------------------------------------------------------------------------------------------


def test_vtable_slots_pair_the_functions_of_a_class_across_builds():
    from kawaiidra_hx.queries.vtables import vtable_slot_pairs

    A = {"CNode": [(0x5000, (0x1000, 0x1100, 0x1200))], "CRemoved": [(0x5100, (0x1300,))], "CGrew": [(0x5200, (0x1400, 0x1500))]}
    B = {"CNode": [(0x7000, (0x9000, 0x9100, 0x9200))], "CNew": [(0x7100, (0x9300,))], "CGrew": [(0x7200, (0x9400, 0x9500, 0x9600))]}
    got = {a: b for a, (b, _n, _tot) in vtable_slot_pairs(A, B).items()}
    # a table that changed length moved its slots (CGrew), a class in one build only has nothing to pair with
    assert got == {0x1000: 0x9000, 0x1100: 0x9100, 0x1200: 0x9200}


def test_a_function_in_several_tables_needs_a_clear_majority():
    A = {f"C{i}": [(0x5000 + i, (0x1000, 0x1100 + i))] for i in range(4)}
    B = {f"C{i}": [(0x7000 + i, (0x9000 if i < 3 else 0x9777, 0x9100 + i))] for i in range(4)}
    assert vtable_pairs_of(A, B)[0x1000] == (0x9000, 3, 4)  # three of four tables agree
    B["C2"] = [(0x7002, (0x9888, 0x9102))]
    assert 0x1000 not in vtable_pairs_of(A, B)  # two against two (and two singles): no majority, no pair


def vtable_pairs_of(A, B):
    from kawaiidra_hx.queries.vtables import vtable_slot_pairs

    return vtable_slot_pairs(A, B)


def test_vtable_seeds_anchor_look_alike_functions_and_are_gated_by_size():
    A = index(fp(0x1000, 30), fp(0x1100, 30), fp(0x1200, 30), fp(0x1300, 30))
    B = index(fp(0x9000, 30), fp(0x9100, 30), fp(0x9200, 30), fp(0x9300, 400))  # the last slot holds a function 13 times as big: a reordered table
    A.vtables = {"CNode": [(0x5000, (0x1000, 0x1100, 0x1200, 0x1300))]}
    B.vtables = {"CNode": [(0x7000, (0x9000, 0x9100, 0x9200, 0x9300))]}
    assert align_functions(A, B, kinds=("imports", "consts"), use_vtables=False) == {}  # indistinguishable by features: nothing is guessed
    m = align_functions(A, B, kinds=("imports", "consts"))
    assert {a: (x.b, x.method) for a, x in m.items()} == {0x1000: (0x9000, "vtable"), 0x1100: (0x9100, "vtable"), 0x1200: (0x9200, "vtable")}
    # a stronger seed keeps its function: a unique string beats the table
    A2 = index(fp(0x1000, 30, strings=["only-one"]), fp(0x1100, 30))
    B2 = index(fp(0x9000, 30), fp(0x9100, 30, strings=["only-one"]))
    A2.vtables, B2.vtables = {"C": [(0x5000, (0x1000, 0x1100))]}, {"C": [(0x7000, (0x9000, 0x9100))]}
    assert align_functions(A2, B2)[0x1000].b == 0x9100


def test_the_alignment_cache_notices_that_vtables_arrived(tmp_path):
    A = index(fp(0x1000, 30), fp(0x1100, 30))
    B = index(fp(0x9000, 30), fp(0x9100, 30))
    A.build_id, B.build_id = "ABC-a_1", "ABC-b_1"
    cache = tmp_path / "align.pkl"
    assert AnchorContext(A, B, _Img(0), _Img(0), cache=cache).matched == {}
    A.vtables, B.vtables = {"C": [(0x5000, (0x1000, 0x1100))]}, {"C": [(0x7000, (0x9000, 0x9100))]}
    assert len(AnchorContext(A, B, _Img(0), _Img(0), cache=cache).matched) == 2  # computed again, not read from the vtable-less cache
