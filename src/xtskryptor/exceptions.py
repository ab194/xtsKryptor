"""Project-specific exceptions."""

from __future__ import annotations


class XtsKryptorError(Exception):
    """Base class for expected xtskryptor failures."""


class ArchiveFormatError(XtsKryptorError):
    """Raised when an encrypted archive cannot be parsed."""


class AuthenticationError(XtsKryptorError):
    """Raised when archive authentication fails."""
