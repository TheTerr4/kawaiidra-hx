"""Per-function fingerprints from a Ghidra program: the raw material for matching functions between two builds of a binary.

Features chosen because they survive a rebuild of the same code: the string literals a function references, the *imports* it calls (as
``dll!name`` or ``dll!#ordinal``, taken from the PE import table so ordinal-only imports are as good as named ones), large scalar
constants, a skeleton of instruction mnemonics, and the ordered list of direct callees. Absolute addresses never enter a fingerprint.
"""

from __future__ import annotations

import bisect
import time
import zlib
from array import array
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from ..core.resolve import file_offset
from ..core.session import ProgramHandle

# mnemonics that differ with calling convention / frame layout between rebuilds and carry little meaning
_SKIP = frozenset({"PUSH", "POP", "NOP", "INT3", "RET", "RETN", "LEAVE", "SUB", "ADD", "MOV", "LEA", "XCHG"})
MIN_STRING = 4
MIN_CONST = 0x100
FP_VERSION = 2  # 2: FuncFP.code (instruction streams), FuncIndex.vocab / image_base; version-1 pickles lack them


@dataclass
class CodeStream:
    """The instructions of one function in address order, as parallel compact arrays (see :func:`extract_fingerprints`).

    ``t1`` is the token of an instruction's mnemonic and operand *kinds* (``CMP.RI``, ``MOV.RM``, ``JNZ.C+``), ``t2`` the same with the scalar values
    (immediates, struct displacements) appended; both are ids into :attr:`FuncIndex.vocab`. ``callee`` is the RVA of a direct callee (0 = none) and
    ``ref`` a crc32 of the string literal or import an operand refers to (0 = none): the things that stay the same when code is recompiled around them.
    """

    rva: array = field(default_factory=lambda: array("I"))
    size: bytearray = field(default_factory=bytearray)
    t1: array = field(default_factory=lambda: array("I"))
    t2: array = field(default_factory=lambda: array("I"))
    callee: array = field(default_factory=lambda: array("I"))
    ref: array = field(default_factory=lambda: array("I"))

    def __len__(self) -> int:
        return len(self.rva)

    def index_of(self, rva: int) -> int:
        """Index of the instruction that contains ``rva`` (-1 when it falls between instructions or outside the function)."""
        i = bisect.bisect_right(self.rva, rva) - 1
        return i if i >= 0 and rva < self.rva[i] + self.size[i] else -1


@dataclass
class FuncFP:
    entry: int  # virtual address
    size: int  # bytes
    n: int  # instruction count
    strings: frozenset[str] = frozenset()
    imports: frozenset[str] = frozenset()
    consts: frozenset[int] = frozenset()
    skeleton: tuple[str, ...] = ()
    calls: tuple[int, ...] = ()  # direct callee entry addresses in call order (thunks resolved)
    file_off: Optional[int] = None
    name: str = ""
    ranges: tuple[tuple[int, int], ...] = ()  # (min, max) address ranges of the body (Ghidra bodies can be fragmented)
    code: Optional[CodeStream] = None  # instruction stream (absent in version-1 caches)

    @property
    def end_hint(self) -> int:
        return self.entry + self.size


@dataclass
class FuncIndex:
    """All function fingerprints of one build + inverted feature indexes (built lazily)."""

    funcs: dict[int, FuncFP] = field(default_factory=dict)
    build_id: str = ""
    image_base: int = 0  # code streams hold RVAs
    vocab: list[str] = field(default_factory=list)  # token id -> text, for the code streams (only meaningful when version >= 2)
    version: int = 1  # an old pickle has no such attribute and reads this default; extraction stores FP_VERSION
    vtables: Optional[dict[str, list[tuple[int, tuple[int, ...]]]]] = None  # RTTI vtables (queries/vtables.py), attached by the caller that loads them; None = not loaded

    def __post_init__(self) -> None:
        self._inv: dict[str, dict[Any, list[int]]] | None = None
        self._callers: dict[int, list[int]] | None = None
        self._starts: list[int] | None = None
        self._spans: list[tuple[int, int]] | None = None

    @property
    def inverted(self) -> dict[str, dict[Any, list[int]]]:
        if self._inv is None:
            inv: dict[str, dict[Any, list[int]]] = {"strings": {}, "imports": {}, "consts": {}}
            for e, f in self.funcs.items():
                for kind in inv:
                    for x in getattr(f, kind):
                        inv[kind].setdefault(x, []).append(e)
            self._inv = inv
        return self._inv

    def df(self, kind: str, feature: Any) -> int:
        return len(self.inverted[kind].get(feature, ()))

    @property
    def callers(self) -> dict[int, list[int]]:
        if self._callers is None:
            out: dict[int, list[int]] = {}
            for e, f in self.funcs.items():
                for c in dict.fromkeys(f.calls):
                    out.setdefault(c, []).append(e)
            self._callers = out
        return self._callers

    def _build_spans(self) -> None:
        spans: list[tuple[int, int, int]] = []
        for e, f in self.funcs.items():
            for lo, hi in (f.ranges or ((e, e + max(f.size, 1) - 1),)):
                spans.append((lo, hi, e))
        spans.sort()
        self._starts = [x[0] for x in spans]
        self._spans = [(x[1], x[2]) for x in spans]

    def containing(self, address: int) -> Optional[FuncFP]:
        """The function whose body holds ``address`` (binary search over the stored address ranges)."""
        if self._starts is None:
            self._build_spans()
        assert self._starts is not None and self._spans is not None
        i = bisect.bisect_right(self._starts, address) - 1
        if i >= 0:
            hi, entry = self._spans[i]
            if address <= hi:
                return self.funcs[entry]
        return None


def extract_fingerprints(
    h: ProgramHandle,
    imports_by_va: Mapping[int, str],
    *,
    build_id: str = "",
    log: Any = None,
    code: bool = True,
) -> FuncIndex:
    """Fingerprint every function. ``imports_by_va`` maps an IAT slot's virtual address to ``"dll!name"`` / ``"dll!#ordinal"``
    (from :func:`iat_map`); the program must be analysed. With ``code`` (default) every function also gets its :class:`CodeStream`."""
    from ghidra.program.model.lang import OperandType as OT  # JVM must be running

    t0 = time.time()
    with h.lock:
        prog = h.program
        fm, listing, refman = prog.getFunctionManager(), prog.getListing(), prog.getReferenceManager()
        base = int(prog.getImageBase().getOffset())

        fstr: dict[int, set[str]] = {}
        strcrc: dict[int, int] = {}  # string address -> crc32 of its text (for the per-instruction ``ref``)
        for d in listing.getDefinedData(True):
            if not d.hasStringValue():
                continue
            v = d.getValue()
            if v is None:
                continue
            text = str(v)
            if len(text) < MIN_STRING:
                continue
            strcrc[int(d.getAddress().getOffset())] = zlib.crc32(text.encode("utf-8", "replace"))
            for ref in refman.getReferencesTo(d.getAddress()):
                fn = fm.getFunctionContaining(ref.getFromAddress())
                if fn is not None:
                    fstr.setdefault(int(fn.getEntryPoint().getOffset()), set()).add(text)
        if log:
            log(f"strings: {len(fstr)} functions reference one ({time.time() - t0:.1f}s)")

        out = FuncIndex(build_id=build_id, image_base=base, version=FP_VERSION)
        vocab: dict[str, int] = {}

        def tok(text: str) -> int:
            i = vocab.get(text)
            if i is None:
                i = vocab[text] = len(vocab)
            return i

        for fn in fm.getFunctions(True):
            entry = int(fn.getEntryPoint().getOffset())
            mn: list[str] = []
            consts: set[int] = set()
            imps: set[str] = set()
            calls: list[int] = []
            stream = CodeStream() if code else None
            n = 0
            for ins in listing.getInstructions(fn.getBody(), True):
                n += 1
                m = str(ins.getMnemonicString())
                if m not in _SKIP:
                    mn.append(m)
                nops = int(ins.getNumOperands())
                kinds: list[str] = []
                scalars: list[int] = []
                ref_crc = 0
                for i in range(nops):
                    sc = ins.getScalar(i)
                    if sc is not None:
                        v = int(sc.getUnsignedValue())
                        if MIN_CONST <= v <= 0xFFFFFFF0 and not _is_address_like(v, prog):
                            consts.add(v)
                    for r in ins.getOperandReferences(i):
                        if r.isMemoryReference() and not r.isStackReference():
                            to = int(r.getToAddress().getOffset())
                            tag = imports_by_va.get(to)
                            if tag:
                                imps.add(tag)
                                ref_crc = ref_crc or zlib.crc32(tag.encode())
                            elif to in strcrc:
                                ref_crc = ref_crc or strcrc[to]
                    if stream is not None:
                        t = int(ins.getOperandType(i))
                        k = "C" if OT.isCodeReference(t) else "M" if OT.isDynamic(t) else "A" if OT.isAddress(t) else "I" if OT.isScalar(t) else "R" if OT.isRegister(t) else "X"
                        kinds.append(k)
                        if k in ("M", "I"):
                            scalars += [int(o.getSignedValue()) for o in ins.getOpObjects(i) if hasattr(o, "getSignedValue")]
                callee = 0
                if ins.getFlowType().isCall():
                    for r in ins.getReferencesFrom():
                        if r.getReferenceType().isCall() and not r.isExternalReference():
                            tgt = fm.getFunctionAt(r.getToAddress())
                            if tgt is None:
                                continue
                            if tgt.isThunk():
                                inner = tgt.getThunkedFunction(True)
                                if inner is not None:
                                    tgt = inner
                            callee_va = int(tgt.getEntryPoint().getOffset())
                            calls.append(callee_va)
                            callee = callee_va - base if callee_va >= base else 0  # external functions live in a space of their own
                if stream is not None:
                    direction = ""
                    if ins.getFlowType().isJump():  # which way a jump goes is part of what it is (a loop-closing `jnz` is not a skip-ahead `jnz`)
                        flows = ins.getFlows()
                        if flows is not None and len(flows) == 1:
                            direction = "+" if int(flows[0].getOffset()) > int(ins.getAddress().getOffset()) else "-"
                    t1 = f"{m}.{''.join(kinds)}{direction}"
                    stream.rva.append(int(ins.getAddress().getOffset()) - base)
                    stream.size.append(int(ins.getLength()))
                    stream.t1.append(tok(t1))
                    stream.t2.append(tok(t1 + "|" + ",".join(f"{v:x}" for v in scalars)))
                    stream.callee.append(callee)
                    stream.ref.append(ref_crc)
            out.funcs[entry] = FuncFP(
                entry=entry, size=int(fn.getBody().getNumAddresses()), n=n, strings=frozenset(fstr.get(entry, ())),
                imports=frozenset(imps), consts=frozenset(consts), skeleton=tuple(mn), calls=tuple(calls),
                file_off=file_offset(prog, fn.getEntryPoint()), name=str(fn.getName()),
                ranges=tuple((int(r.getMinAddress().getOffset()), int(r.getMaxAddress().getOffset())) for r in fn.getBody().getAddressRanges()),
                code=stream,
            )  # fmt: skip
        out.vocab = [t for t, _ in sorted(vocab.items(), key=lambda kv: kv[1])]
    if log:
        log(f"{len(out.funcs)} functions fingerprinted ({time.time() - t0:.1f}s)")
    return out


def _is_address_like(v: int, prog: Any) -> bool:
    """Constants that are really addresses inside the image (they move between builds)."""
    base = int(prog.getImageBase().getOffset())
    return base <= v < base + 0x4000000


def iat_map(image: Any) -> dict[int, str]:
    """``{IAT slot VA: "dll!name" | "dll!#ordinal"}`` from a :class:`~kawaiidra_hx.pe.PEImage` import table (delay-loads included)."""
    base = image.info.image_base
    out: dict[int, str] = {}
    for lib in image.imports:
        dll = lib.dll.lower()
        for s in lib.symbols:
            out[base + s.iat_rva] = f"{dll}!{s.name}" if s.name else f"{dll}!#{s.ordinal}"
    return out
