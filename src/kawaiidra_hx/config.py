"""Settings, read from environment variables with sensible defaults.

    GHIDRA_INSTALL_DIR     Ghidra install (required for anything that starts the JVM)
    KHX_WORKSPACE          where projects, results and logs live (default: <repo>/workspace)
    KHX_DEFAULT_PROJECT    project used when a tool call omits one (default: "default")
    KHX_MAX_INLINE_CHARS   larger tool output is saved to a file and truncated inline (default 20000)
    KHX_DECOMPILE_TIMEOUT  seconds per decompile (default 120)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional


class ConfigError(RuntimeError):
    pass


def _default_workspace() -> Path:
    # Running from a source checkout: keep data next to the repo. Installed: use the home directory.
    root = Path(__file__).resolve().parents[2]
    if (root / "pyproject.toml").exists():
        return root / "workspace"
    return Path.home() / ".kawaiidra-hx" / "workspace"


@dataclass(frozen=True)
class Settings:
    ghidra_dir: Optional[Path]
    workspace: Path
    default_project: str
    max_inline_chars: int
    decompile_timeout: int

    @property
    def projects_dir(self) -> Path:
        return self.workspace / "projects"

    @property
    def results_dir(self) -> Path:
        return self.workspace / "results"

    @property
    def log_dir(self) -> Path:
        return self.workspace / "logs"

    def require_ghidra(self) -> Path:
        if self.ghidra_dir is None:
            raise ConfigError("GHIDRA_INSTALL_DIR is not set. Point it at your Ghidra install, e.g. C:\\ghidra_12.1.4_PUBLIC")
        if not (self.ghidra_dir / "Ghidra" / "application.properties").exists():
            raise ConfigError(f"GHIDRA_INSTALL_DIR={self.ghidra_dir} does not look like a Ghidra install (no Ghidra/application.properties)")
        return self.ghidra_dir


def load_settings(env: Optional[Mapping[str, str]] = None) -> Settings:
    env = os.environ if env is None else env
    ghidra = env.get("GHIDRA_INSTALL_DIR")
    return Settings(
        ghidra_dir=Path(ghidra) if ghidra else None,
        workspace=Path(env.get("KHX_WORKSPACE") or _default_workspace()),
        default_project=env.get("KHX_DEFAULT_PROJECT", "default"),
        max_inline_chars=int(env.get("KHX_MAX_INLINE_CHARS", "20000")),
        decompile_timeout=int(env.get("KHX_DECOMPILE_TIMEOUT", "120")),
    )
