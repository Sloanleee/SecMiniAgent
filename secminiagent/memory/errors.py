"""Typed failures defined by the M0 memory contract."""


class MemoryError(RuntimeError):
    """Base class for memory-subsystem failures."""


class MemoryAccessDenied(MemoryError):
    """The caller cannot access a memory in the requested scope."""


class MemoryValidationError(MemoryError, ValueError):
    """A memory value object or request violates a frozen invariant."""


class MemoryPolicyDenied(MemoryError):
    """Policy explicitly denied persistence or disclosure."""


class MemoryConfirmationRequired(MemoryError):
    """An operation requires explicit user confirmation."""


class MemoryNotFound(MemoryError):
    """No accessible live memory exists for the supplied identifier."""


class MemoryIntegrityError(MemoryError):
    """Authenticated content or bound metadata failed integrity checks."""


class MemoryDependencyUnavailable(MemoryError):
    """A required local detector, key protector, or storage dependency failed."""


class MemoryDeletionIncomplete(MemoryError):
    """Authoritative access is denied, but derived cleanup still needs retry."""


class MemorySchemaUnsupported(MemoryError):
    """The database schema cannot be opened by the active runtime."""


class MemoryMigrationRequired(MemoryError):
    """The database requires an explicit schema migration."""


class MemoryMigrationFailed(MemoryError):
    """A migration step failed without exposing record content."""


class MemoryMigrationIncomplete(MemoryError):
    """A recoverable migration has not reached a terminal phase."""


class MemoryMigrationConflict(MemoryError):
    """Another writer or a changed source snapshot invalidated migration."""


class MemoryStateIntegrityError(MemoryIntegrityError):
    """Authenticated mutable state failed verification."""


class MemoryLifecycleConflict(MemoryError):
    """A Thread/Run transition or concurrent lifecycle mutation was rejected."""
