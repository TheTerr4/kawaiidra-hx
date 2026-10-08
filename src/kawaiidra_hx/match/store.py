"""Cache of per-function fingerprints and RTTI vtables, keyed by the sha256 of the program's original file.

Extracting fingerprints walks every function of an analysed program (tens of seconds for a big binary); the result is plain data, so it is
pickled under ``<workspace>/cache`` and later runs need no Ghidra at all for a binary that was fingerprinted once. A cache entry is used only
if its format version is current, so a stale one is re-extracted rather than misread. The vtables have a cache of their own (under a second
to extract, but Ghidra is needed for it).
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Callable, Optional, Union

from ..core.session import ProgramHandle
from ..pe import PEImage
from ..queries.fingerprint import FP_VERSION, FuncIndex, extract_fingerprints, iat_map
from ..queries.vtables import extract_vtables

VT_CACHE_VERSION = 1


def _save(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))
    tmp.replace(path)


def _load(path: Path):
    try:
        return pickle.loads(path.read_bytes())  # noqa: S301 - our own cache under workspace/
    except Exception:
        return None


class FingerprintStore:
    """``index(h)``: the program's :class:`FuncIndex` (with ``.vtables`` attached), from the cache when it is current."""

    def __init__(self, cache_dir: Union[str, Path, None] = None, *, refresh: bool = False, log: Optional[Callable[[str], None]] = None):
        if cache_dir is None:
            from ..core import get_session

            cache_dir = get_session().settings.workspace / "cache"
        self.dir = Path(cache_dir)
        self.refresh = refresh
        self.log = log
        self._mem: dict[str, FuncIndex] = {}

    def index(self, h: ProgramHandle, binary: Union[str, Path, None] = None) -> FuncIndex:
        from ..sigs import original_bytes  # (the sha256-checked original file; ``binary`` overrides the recorded path)

        data = original_bytes(h, binary)
        image = PEImage(data)
        key = image.sha256[:20]
        if key in self._mem:
            return self._mem[key]
        label = f"{h.name}"
        say = (lambda m: self.log(f"{label}: {m}")) if self.log else None
        path = self.dir / f"fp_{key}.pkl"
        idx = None if self.refresh or not path.exists() else _load(path)
        if idx is not None and getattr(idx, "version", 1) < FP_VERSION:
            idx = None
        if idx is None:
            idx = extract_fingerprints(h, iat_map(image), build_id=key, log=say)
            _save(path, idx)  # (before the vtables are attached: they have a cache of their own)
        idx.vtables = self._vtables(h, key, say)
        self._mem[key] = idx
        return idx

    def _vtables(self, h: ProgramHandle, key: str, say) -> dict:
        path = self.dir / f"vt_{key}.pkl"
        if path.exists() and not self.refresh:
            blob = _load(path)
            if isinstance(blob, dict) and blob.get("v") == VT_CACHE_VERSION:
                return blob["tables"]
        tables = extract_vtables(h)
        _save(path, {"v": VT_CACHE_VERSION, "tables": tables})
        if say:
            say(f"{sum(len(v) for v in tables.values())} RTTI vtables of {len(tables)} classes")
        return tables
