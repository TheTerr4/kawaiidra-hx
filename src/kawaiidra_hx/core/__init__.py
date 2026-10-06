"""Core Ghidra layer: session, projects, programs, address resolution, background jobs."""

from .errors import (
    AddressError,
    KhxError,
    ProgramNotFoundError,
    ProjectLockedError,
    ProjectNotFoundError,
    ReadOnlyError,
)
from .session import ProgramHandle, ProjectHandle, ProjectRef, Session, get_session, list_projects, resolve_project

__all__ = [
    "AddressError",
    "KhxError",
    "ProgramHandle",
    "ProgramNotFoundError",
    "ProjectHandle",
    "ProjectLockedError",
    "ProjectNotFoundError",
    "ProjectRef",
    "ReadOnlyError",
    "Session",
    "get_session",
    "list_projects",
    "resolve_project",
]
