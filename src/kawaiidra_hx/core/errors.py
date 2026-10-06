"""Exceptions raised by the core layer. All derive from :class:`KhxError` so callers can show a clean message."""


class KhxError(Exception):
    """Base class: the message is meant to be shown to the user as is."""


class ProjectNotFoundError(KhxError):
    pass


class ProjectLockedError(KhxError):
    pass


class ProgramNotFoundError(KhxError):
    pass


class AddressError(KhxError):
    """The text could not be resolved to an address in the program."""


class ReadOnlyError(KhxError):
    pass
