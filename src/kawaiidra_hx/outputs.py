"""Keep tool output small: oversized text is saved to a file and truncated inline.

Every query tool funnels its text through :func:`emit`, so a 4,000-line decompile or a 400-hit scan never floods
the caller's context. The full text is always recoverable from the saved file path.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from .config import Settings


def _slug(label: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("_")
    return (s or "out")[:60]


def slice_lines(text: str, offset: int | None = None, limit: int | None = None) -> str:
    """Line-based pagination (``offset`` is 0-based). A header notes the window when slicing."""
    if offset is None and limit is None:
        return text
    lines = text.split("\n")
    start = max(offset or 0, 0)
    end = start + limit if limit is not None else len(lines)
    window = "\n".join(lines[start:end])
    return f"[lines {start}-{min(end, len(lines))} of {len(lines)}]\n{window}"


def emit(text: str, settings: Settings, label: str = "out") -> str:
    """Return ``text`` or, when it exceeds ``settings.max_inline_chars``, a head + a pointer to the saved file."""
    limit = settings.max_inline_chars
    if len(text) <= limit:
        return text
    settings.results_dir.mkdir(parents=True, exist_ok=True)
    path = settings.results_dir / f"{time.strftime('%Y%m%d-%H%M%S')}-{_slug(label)}.txt"
    path.write_text(text, encoding="utf-8")
    head = text[:limit]
    # cut at a line boundary so the head doesn't end mid-line
    cut = head.rfind("\n")
    if cut > limit // 2:
        head = head[:cut]
    total_lines = text.count("\n") + 1
    return (
        f"{head}\n"
        f"... [truncated: showing {head.count(chr(10)) + 1} of {total_lines} lines, {len(text)} chars]\n"
        f"[full output saved to {path}]"
    )
