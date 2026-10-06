"""Background jobs (import + analysis) with live progress, cancellation and no hard timeout.

Kawaiidra ran ``analyzeHeadless`` as a blocking subprocess with a 300 s kill; a 12 MB x64 DLL needs ~250 s of
analysis alone, so imports died. Here the work runs in a worker thread inside the long-lived JVM and the caller
polls ``Job`` for the current phase/message instead of waiting on a timeout.
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Optional

from .errors import KhxError
from .session import ProgramHandle, Session

log = logging.getLogger("khx.jobs")


@dataclass
class Job:
    id: str
    kind: str
    label: str
    state: str = "queued"  # queued | running | done | failed | cancelled
    phase: str = ""
    message: str = ""
    progress: int = 0
    maximum: int = 0
    created: float = field(default_factory=time.time)
    started: Optional[float] = None
    finished: Optional[float] = None
    result: Any = None
    error: Optional[str] = None
    cancel_requested: bool = False
    history: Deque[str] = field(default_factory=lambda: deque(maxlen=40))
    _monitor: Any = field(default=None, repr=False)

    @property
    def finished_ok(self) -> bool:
        return self.state in ("done", "failed", "cancelled")

    @property
    def elapsed(self) -> float:
        if self.started is None:
            return 0.0
        return (self.finished or time.time()) - self.started

    def set_message(self, msg: str) -> None:
        if msg and msg != self.message:
            self.message = msg
            self.history.append(f"[{self.elapsed:6.1f}s] {self.phase}: {msg}")

    def cancel(self) -> None:
        self.cancel_requested = True
        mon = self._monitor
        if mon is not None:
            try:
                mon.cancel()
            except Exception:  # pragma: no cover
                pass

    def status_line(self) -> str:
        bits = [f"job {self.id} {self.kind} {self.label!r}: {self.state}"]
        if self.phase:
            bits.append(f"phase={self.phase}")
        if self.message:
            bits.append(f"'{self.message}'")
        if self.maximum > 0:
            bits.append(f"{self.progress}/{self.maximum}")
        bits.append(f"{self.elapsed:.0f}s")
        if self.error:
            bits.append(f"error: {self.error}")
        return " | ".join(bits)


# --- Java TaskMonitor implemented in Python ---------------------------------------------------

_monitor_cls: Any = None


def _monitor_class() -> Any:
    """Build (once, after the JVM is up) a ``ghidra.util.task.TaskMonitor`` that feeds a :class:`Job`."""
    global _monitor_cls
    if _monitor_cls is not None:
        return _monitor_cls
    from jpype import JImplements, JOverride

    @JImplements("ghidra.util.task.TaskMonitor")
    class JobMonitor:
        def __init__(self, job: Job):
            self.job = job
            self._cancelled = False
            self._cancel_enabled = True
            self._indeterminate = False
            self._max = 0
            self._progress = 0
            self._message = ""
            self._listeners: list[Any] = []

        @JOverride
        def isCancelled(self):
            return self._cancelled

        @JOverride
        def setShowProgressValue(self, show):
            pass

        @JOverride
        def setMessage(self, message):
            self._message = str(message) if message is not None else ""
            self.job.set_message(self._message)

        @JOverride
        def getMessage(self):
            return self._message

        @JOverride
        def setProgress(self, value):
            self._progress = int(value)
            self.job.progress = self._progress

        @JOverride
        def initialize(self, *args):
            self._max = int(args[0])
            self._progress = 0
            self.job.maximum, self.job.progress = self._max, 0
            if len(args) > 1 and args[1] is not None:
                self.setMessage(args[1])

        @JOverride
        def setMaximum(self, maximum):
            self._max = int(maximum)
            self.job.maximum = self._max

        @JOverride
        def getMaximum(self):
            return self._max

        @JOverride
        def incrementProgress(self, *args):
            self._progress += int(args[0]) if args else 1
            self.job.progress = self._progress

        @JOverride
        def getProgress(self):
            return self._progress

        @JOverride
        def cancel(self):
            self._cancelled = True
            for lst in list(self._listeners):
                try:
                    lst.cancelled()
                except Exception:  # pragma: no cover
                    pass

        @JOverride
        def addCancelledListener(self, listener):
            self._listeners.append(listener)

        @JOverride
        def removeCancelledListener(self, listener):
            if listener in self._listeners:
                self._listeners.remove(listener)

        @JOverride
        def setCancelEnabled(self, enable):
            self._cancel_enabled = bool(enable)

        @JOverride
        def isCancelEnabled(self):
            return self._cancel_enabled

        @JOverride
        def clearCanceled(self):
            self._cancelled = False

        @JOverride
        def checkCanceled(self):
            if self._cancelled:
                from ghidra.util.exception import CancelledException

                raise CancelledException()

        # TaskMonitor's *default* methods must be overridden too: JPype cannot invoke an interface default method
        # on a Python proxy ("WrongMethodTypeException: cannot convert MethodHandle()void to (Object)Object").
        @JOverride
        def checkCancelled(self):
            self.checkCanceled()

        @JOverride
        def clearCancelled(self):
            self._cancelled = False

        @JOverride
        def increment(self, *args):
            self.incrementProgress(*args)

        @JOverride
        def setIndeterminate(self, indeterminate):
            self._indeterminate = bool(indeterminate)

        @JOverride
        def isIndeterminate(self):
            return self._indeterminate

    _monitor_cls = JobMonitor
    return _monitor_cls


def new_monitor(job: Job) -> Any:
    """A fresh monitor bound to ``job`` (one per phase: ``pyghidra.analyze`` cancels its monitor when done)."""
    mon = _monitor_class()(job)
    job._monitor = mon
    if job.cancel_requested:
        mon.cancel()
    return mon


# --- job manager ------------------------------------------------------------------------------


class JobManager:
    def __init__(self, workers: int = 2):
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="khx-job")
        self._jobs: dict[str, Job] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def submit(self, kind: str, label: str, fn: Callable[[Job], Any]) -> Job:
        with self._lock:
            job = Job(id=f"j{next(self._ids)}", kind=kind, label=label)
            self._jobs[job.id] = job

        def runner() -> None:
            job.state, job.started = "running", time.time()
            try:
                job.result = fn(job)
                job.state = "cancelled" if job.cancel_requested else "done"
            except BaseException as e:  # noqa: BLE001 - report everything to the caller
                job.state = "cancelled" if job.cancel_requested else "failed"
                job.error = f"{type(e).__name__}: {e}"
                log.exception("job %s failed", job.id)
            finally:
                job.finished = time.time()

        self._pool.submit(runner)
        return job

    def get(self, job_id: str) -> Job:
        try:
            return self._jobs[job_id]
        except KeyError:
            raise KhxError(f"no such job {job_id!r} (jobs: {', '.join(self._jobs) or 'none'})") from None

    def list(self) -> list[Job]:
        return list(self._jobs.values())

    def wait(self, job: Job, timeout: Optional[float] = None, poll: float = 0.25) -> Job:
        end = None if timeout is None else time.time() + timeout
        while not job.finished_ok:
            if end is not None and time.time() >= end:
                break
            time.sleep(poll)
        return job


_manager: Optional[JobManager] = None
_manager_lock = threading.Lock()


def get_jobs() -> JobManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = JobManager()
        return _manager


# --- the import + analyze work ----------------------------------------------------------------


def import_program(
    session: Session,
    binary: str | Path,
    project: Optional[str] = None,
    *,
    analyze: bool = True,
    name: Optional[str] = None,
    overwrite: bool = False,
    job: Optional[Job] = None,
) -> dict[str, Any]:
    """Import ``binary`` into a project (created if missing), optionally run auto-analysis, and save.

    The source file is only read. Runs synchronously; wrap in :meth:`JobManager.submit` for background use.
    """
    job = job or Job(id="inline", kind="import", label=str(binary))
    src = Path(binary).resolve()
    if not src.is_file():
        raise KhxError(f"{src} is not a file")
    program_name = name or src.name

    session.ensure_started()
    import pyghidra
    from java.io import File

    job.phase = "open project"
    proj = session.open_project(project, create=True)
    existing = [p for p, t in proj.program_files() if t == "Program" and p.rsplit("/", 1)[-1].lower() == program_name.lower()]
    if existing and not overwrite:
        raise KhxError(f"{program_name} already exists in project {proj.ref.name}; pass overwrite=True to replace it")
    for path in existing:
        proj.close_program(path, discard=True)
        proj.project.getProjectData().getFile(path).delete()

    job.phase = "import"
    mon = new_monitor(job)
    loader = (
        pyghidra.program_loader()
        .project(proj.project)
        .source(File(str(src)))
        .name(program_name)
        .projectFolderPath("/")
        .monitor(mon)
    )
    with loader.load() as results:
        results.save(mon)
    imported_path = "/" + program_name
    if job.cancel_requested:
        return {"program": program_name, "analyzed": False, "note": "cancelled during import"}

    analyzed = False
    log_text = ""
    if analyze:
        job.phase = "analyze"
        amon = new_monitor(job)
        with pyghidra.program_context(proj.project, imported_path) as prog:
            log_text = str(pyghidra.analyze(prog, amon))
            if not job.cancel_requested:
                from ghidra.util.task import TaskMonitor

                prog.save("Analyzed by kawaiidra-hx", TaskMonitor.DUMMY)
                analyzed = True
    job.phase = "done"
    handle: ProgramHandle = proj.open_program(program_name)
    functions = int(handle.program.getFunctionManager().getFunctionCount())
    return {
        "project": proj.ref.name,
        "program": program_name,
        "analyzed": analyzed,
        "functions": functions,
        "analysis_log_tail": log_text[-1500:],
        "note": "analysis cancelled; import kept (re-run import with overwrite to analyze)" if analyze and not analyzed else "",
    }
