"""The interface every scanner implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from pqc_scan.models import ErrorKind, FileCoverage, Observation, ScanConfig


class ScanTargetError(Exception):
    """A single target could not be scanned.

    The engine turns this into a :class:`~pqc_scan.models.ScanError`; the rest
    of the run continues. The message must never contain secret material.
    """

    def __init__(self, kind: ErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class FileAudit:
    scanner: str
    target: str
    inspected: int = 0
    oversized: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)

    def summary(self) -> FileCoverage:
        return FileCoverage(
            scanner=self.scanner,
            target=self.target,
            inspected=self.inspected,
            oversized=self.oversized,
            unreadable=self.unreadable,
            unparsed=self.unparsed,
        )


class Scanner(ABC):
    """Base class for scanners.

    A scanner looks at one target (a ``host:port`` or a root path) and reports
    what it saw as :class:`~pqc_scan.models.Observation` objects. It does not
    classify risk and does not know about report formats.
    """

    name: ClassVar[str]

    def scan_with_coverage(
        self, target: str, config: ScanConfig
    ) -> tuple[list[Observation], FileCoverage | None]:
        return self.scan(target, config), None

    @abstractmethod
    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        """Scan one target.

        Raise :class:`ScanTargetError` for expected, target-level failures
        (unreachable host, unreadable path, ...). Network scanners must honour
        ``config.timeout`` on every socket operation.
        """


class FileTreeScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        return self.scan_with_coverage(target, config)[0]

    def scan_with_coverage(
        self, target: str, config: ScanConfig
    ) -> tuple[list[Observation], FileCoverage]:
        audit = FileAudit(self.name, target)
        found = self.scan_tree(target, config, audit)
        return found, audit.summary()

    @abstractmethod
    def scan_tree(self, target: str, config: ScanConfig, audit: FileAudit) -> list[Observation]:
        """Inspect a local file tree and record its coverage."""
