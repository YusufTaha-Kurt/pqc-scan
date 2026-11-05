"""Report formats. Reporters only read a :class:`~pqc_scan.models.ScanResult`."""

from __future__ import annotations

from enum import StrEnum

from pqc_scan.models import ScanResult
from pqc_scan.reporters import console, json_report


class ReportFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"
    HTML = "html"
    CBOM = "cbom"


IMPLEMENTED_FORMATS: frozenset[ReportFormat] = frozenset({ReportFormat.CONSOLE, ReportFormat.JSON})


class UnsupportedFormatError(ValueError):
    """The format exists in the CLI but is not implemented yet."""


def render(result: ScanResult, fmt: ReportFormat) -> str:
    """Render ``result`` as text in the given format."""
    if fmt is ReportFormat.CONSOLE:
        return console.render(result)
    if fmt is ReportFormat.JSON:
        return json_report.render(result)
    raise UnsupportedFormatError(f"the '{fmt.value}' format is not implemented yet")


__all__ = ["IMPLEMENTED_FORMATS", "ReportFormat", "UnsupportedFormatError", "render"]
