from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.esedb.table import LongValueChunk


class Error(Exception):
    pass


class InvalidDatabase(Error):
    pass


class KeyNotFoundError(Error):
    pass


class NoNeighbourPageError(Error):
    pass


class LongValueError(Error):
    """Raised when a long value cannot be assembled from its chunks without ambiguity.

    The exception carries the chunk evidence that was collected while reading the value, so callers
    can point to the exact page and chunk that failed validation.

    Attributes:
        message: A description of the inconsistency.
        key: The long value lookup key, if available.
        declared_size: The total value size declared by the long value header, if available.
        chunk: The chunk that triggered the error, if applicable.
        evidence: All chunk evidence collected up to and including the failure.
    """

    def __init__(
        self,
        message: str,
        *,
        key: bytes | None = None,
        declared_size: int | None = None,
        chunk: LongValueChunk | None = None,
        evidence: list[LongValueChunk] | None = None,
    ) -> None:
        super().__init__(message)

        self.message = message
        self.key = key
        self.declared_size = declared_size
        self.chunk = chunk
        self.evidence = evidence or []

    def __str__(self) -> str:
        context = []
        if self.key is not None:
            context.append(f"key={self.key.hex()}")
        if self.declared_size is not None:
            context.append(f"declared_size={self.declared_size}")
        if self.chunk is not None:
            context.append(f"chunk={self.chunk}")

        return f"{self.message} ({', '.join(context)})" if context else self.message
