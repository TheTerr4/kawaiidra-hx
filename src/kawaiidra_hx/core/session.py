"""One long-lived Ghidra session per process.

* The JVM starts once, lazily (``pyghidra.start``), so ``khx pe``/``khx patch`` stay instant.
* Projects and programs stay open between calls, so a decompile is milliseconds instead of a 10 s
  ``analyzeHeadless`` process start.
* Programs open **read-only** (immutable domain objects) unless a tool explicitly asks for write access,
  so exploring never modifies a project.
* A Ghidra project can be open in only one process at a time; a held lock is reported with the lock file
  path instead of hanging.
"""

from __future__ import annotations

import atexit
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ..config import Settings, load_settings
from .errors import KhxError, ProgramNotFoundError, ProjectLockedError, ProjectNotFoundError, ReadOnlyError

log = logging.getLogger("khx.session")


# --- project references ---------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectRef:
    location: Path  # directory that contains <name>.gpr
    name: str

    @property
    def gpr(self) -> Path:
        return self.location / f"{self.name}.gpr"

    @property
    def key(self) -> str:
        return str(self.gpr.resolve()).lower()

    def exists(self) -> bool:
        return self.gpr.exists()

    def __str__(self) -> str:
        return str(self.gpr)


def list_projects(settings: Settings) -> list[ProjectRef]:
    """Projects under the workspace (<workspace>/projects/<name>/<name>.gpr)."""
    out = []
    if settings.projects_dir.is_dir():
        for d in sorted(settings.projects_dir.iterdir()):
            if (d / f"{d.name}.gpr").exists():
                out.append(ProjectRef(d, d.name))
    return out


def resolve_project(ref: Optional[str], settings: Settings, *, create: bool = False) -> ProjectRef:
    """Turn a user-supplied project reference into a :class:`ProjectRef`.

    Accepted forms: a bare name (a workspace project), a path to a ``.gpr`` file, or a directory that
    contains exactly one ``.gpr`` (such as an existing ``analyzeHeadless`` project folder).
    """
    ref = ref or settings.default_project
    p = Path(ref)
    if p.suffix.lower() == ".gpr":
        out = ProjectRef(p.parent, p.stem)
    elif p.is_dir():
        gprs = sorted(p.glob("*.gpr"))
        if len(gprs) == 1:
            out = ProjectRef(p, gprs[0].stem)
        elif len(gprs) > 1:
            raise KhxError(f"{p} contains several projects ({', '.join(g.stem for g in gprs)}); pass the .gpr file path")
        elif create:
            out = ProjectRef(p, p.name)
        else:
            raise ProjectNotFoundError(f"no .gpr project file in {p}")
    elif p.is_absolute() or len(p.parts) > 1:
        # a path that does not exist yet
        if not create:
            raise ProjectNotFoundError(f"project path {p} does not exist")
        out = ProjectRef(p, p.name)
    else:
        out = ProjectRef(settings.projects_dir / ref, ref)

    if not out.exists() and not create:
        known = ", ".join(r.name for r in list_projects(settings)) or "none"
        raise ProjectNotFoundError(f"project {ref!r} not found at {out.gpr} (workspace projects: {known})")
    return out


def _lock_files(ref: ProjectRef) -> list[Path]:
    return [p for p in (ref.location / f"{ref.name}.lock", ref.location / f"{ref.name}.lock~") if p.exists()]


def java_message(exc: BaseException) -> str:
    """Best-effort readable message for a Java exception surfaced through JPype."""
    msg = str(exc)
    return msg if msg else type(exc).__name__


# --- program handle -------------------------------------------------------------------------


class ProgramHandle:
    """An open Ghidra program plus the per-program lock and decompiler.

    Ghidra programs and ``DecompInterface`` are not safe for concurrent use, so every query takes
    ``handle.lock`` (re-entrant) for its duration.
    """

    def __init__(self, project: "ProjectHandle", path: str, program: Any, consumer: Any, writable: bool):
        self.project = project
        self.path = path
        self.program = program
        self._consumer = consumer
        self.writable = writable
        self.lock = threading.RLock()
        self._decompiler: Any = None
        self._closed = False

    @property
    def name(self) -> str:
        return str(self.program.getName())

    # --- decompiler --------------------------------------------------------------------------

    def decompiler(self) -> Any:
        if self._decompiler is None:
            from ghidra.app.decompiler import DecompInterface

            di = DecompInterface()
            di.openProgram(self.program)
            self._decompiler = di
        return self._decompiler

    # --- writing -----------------------------------------------------------------------------

    def require_writable(self) -> None:
        if not self.writable:
            raise ReadOnlyError(
                f"{self.name} is open read-only. Re-open it with write access (khx --write / write=True) "
                "to rename, comment or retype; changes are only kept after save."
            )

    def transaction(self, description: str):
        """Context manager wrapping program edits in a Ghidra transaction (requires write access)."""
        self.require_writable()
        import pyghidra

        return pyghidra.transaction(self.program, description)

    @property
    def has_unsaved_changes(self) -> bool:
        return bool(self.writable and self.program.isChanged())

    def save(self, description: str = "kawaiidra-hx") -> None:
        self.require_writable()
        from ghidra.util.task import TaskMonitor

        with self.lock:
            self.program.save(description, TaskMonitor.DUMMY)

    # --- lifecycle ---------------------------------------------------------------------------

    def close(self, *, discard: bool = False) -> None:
        with self.lock:
            if self._closed:
                return
            if self.has_unsaved_changes and not discard:
                raise KhxError(f"{self.name} has unsaved changes; save first or close with discard=True")
            if self._decompiler is not None:
                try:
                    self._decompiler.dispose()
                except Exception:  # pragma: no cover - best effort
                    pass
                self._decompiler = None
            self.program.release(self._consumer)
            self._closed = True


# --- project handle -------------------------------------------------------------------------


class ProjectHandle:
    def __init__(self, ref: ProjectRef, project: Any):
        self.ref = ref
        self.project = project
        self.programs: dict[str, ProgramHandle] = {}
        self.lock = threading.RLock()

    # --- enumeration -------------------------------------------------------------------------

    def program_files(self) -> list[tuple[str, str]]:
        """``[(project_path, content_type)]`` for every file in the project."""
        out: list[tuple[str, str]] = []

        def walk(folder: Any) -> None:
            for f in folder.getFiles():
                out.append((str(f.getPathname()), str(f.getContentType())))
            for sub in folder.getFolders():
                walk(sub)

        walk(self.project.getProjectData().getRootFolder())
        return sorted(out)

    def _find_file(self, name: str) -> tuple[str, Any]:
        data = self.project.getProjectData()
        if name.startswith("/"):
            df = data.getFile(name)
            if df is None:
                raise ProgramNotFoundError(f"{name} not found in project {self.ref.name}")
            return name, df
        files = self.program_files()
        wanted = name.lower()
        exact = [p for p, _t in files if p.rsplit("/", 1)[-1].lower() == wanted]
        if not exact:
            avail = ", ".join(p for p, t in files if t == "Program") or "none"
            raise ProgramNotFoundError(f"program {name!r} not found in project {self.ref.name} (programs: {avail})")
        if len(exact) > 1:
            raise ProgramNotFoundError(f"{name!r} is ambiguous in project {self.ref.name}: {', '.join(exact)}")
        return exact[0], data.getFile(exact[0])

    # --- programs ----------------------------------------------------------------------------

    def open_program(self, name: str, *, write: bool = False) -> ProgramHandle:
        from java.lang import Object
        from ghidra.framework.model import DomainFile
        from ghidra.util.task import TaskMonitor

        with self.lock:
            path, df = self._find_file(name)
            cached = self.programs.get(path)
            if cached is not None:
                if not write or cached.writable:
                    return cached
                cached.close()  # upgrade read-only -> writable
                del self.programs[path]
            consumer = Object()
            if write:
                prog = df.getDomainObject(consumer, True, False, TaskMonitor.DUMMY)
            else:
                prog = df.getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY)
            handle = ProgramHandle(self, path, prog, consumer, writable=write)
            self.programs[path] = handle
            log.info("opened %s (%s)", path, "rw" if write else "ro")
            return handle

    def close_program(self, name: str, *, discard: bool = False) -> bool:
        with self.lock:
            path, _df = self._find_file(name)
            h = self.programs.pop(path, None)
            if h is None:
                return False
            h.close(discard=discard)
            return True

    def close(self, *, discard: bool = False) -> None:
        with self.lock:
            for path in list(self.programs):
                self.programs.pop(path).close(discard=discard)
            self.project.close()


# --- session --------------------------------------------------------------------------------


class Session:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or load_settings()
        self._lock = threading.RLock()
        self._projects: dict[str, ProjectHandle] = {}
        self._started = False

    # --- JVM ---------------------------------------------------------------------------------

    def ensure_started(self) -> None:
        with self._lock:
            if self._started:
                return
            import pyghidra

            if not pyghidra.started():
                ghidra = self.settings.require_ghidra()
                log.info("starting Ghidra from %s", ghidra)
                pyghidra.start(install_dir=ghidra)
            self._started = True
            atexit.register(self.close_all)

    # --- projects ----------------------------------------------------------------------------

    def open_project(self, ref: Optional[str] = None, *, create: bool = False) -> ProjectHandle:
        pref = resolve_project(ref, self.settings, create=create)
        with self._lock:
            h = self._projects.get(pref.key)
            if h is not None:
                return h
            self.ensure_started()
            import pyghidra

            if create and not pref.exists():
                pref.location.mkdir(parents=True, exist_ok=True)
            try:
                project = pyghidra.open_project(str(pref.location), pref.name, create=create)
            except Exception as e:  # Java LockException, FileNotFoundError, ...
                locks = _lock_files(pref)
                text = java_message(e)
                if locks or "lock" in text.lower():
                    where = ", ".join(str(p) for p in locks) or str(pref.location)
                    raise ProjectLockedError(
                        f"project {pref.name} is locked by another process (Ghidra GUI, headless run or another khx). "
                        f"Close it, or if no such process is running delete the stale lock file(s): {where}"
                    ) from e
                raise KhxError(f"could not open project {pref.name} at {pref.location}: {text}") from e
            h = ProjectHandle(pref, project)
            self._projects[pref.key] = h
            return h

    def program(self, project: Optional[str], name: str, *, write: bool = False) -> ProgramHandle:
        return self.open_project(project).open_program(name, write=write)

    def close_project(self, ref: Optional[str] = None, *, discard: bool = False) -> bool:
        """Close an open project (releases Ghidra's lock on it). Returns False if it was not open."""
        pref = resolve_project(ref, self.settings)
        with self._lock:
            h = self._projects.pop(pref.key, None)
            if h is None:
                return False
            h.close(discard=discard)
            return True

    def close_all(self, *, discard: bool = True) -> None:
        with self._lock:
            for key in list(self._projects):
                try:
                    self._projects.pop(key).close(discard=discard)
                except Exception as e:  # pragma: no cover - shutdown best effort
                    log.warning("error closing project: %s", e)


_session: Optional[Session] = None
_session_lock = threading.Lock()


def get_session() -> Session:
    """Process-wide session (the JVM can only be started once per process)."""
    global _session
    with _session_lock:
        if _session is None:
            _session = Session()
        return _session
