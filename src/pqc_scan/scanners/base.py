"""The interface every scanner implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from pqc_scan.models import ErrorKind, Observation, ScanConfig


class ScanTargetError(Exception):
    """A single target could not be scanned.

    The engine turns this into a :class:`~pqc_scan.models.ScanError`; the rest
    of the run continues. The message must never contain secret material.
    """

    def __init__(self, kind: ErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


class Scanner(ABC):
    """Base class for scanners.

    A scanner looks at one target (a ``host:port`` or a root path) and reports
    what it saw as :class:`~pqc_scan.models.Observation` objects. It does not
    classify risk and does not know about report formats.
    """

    name: ClassVar[str]

    @abstractmethod
    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        """Scan one target.

        Raise :class:`ScanTargetError` for expected, target-level failures
        (unreachable host, unreadable path, ...). Network scanners must honour
        ``config.timeout`` on every socket operation.
        """
