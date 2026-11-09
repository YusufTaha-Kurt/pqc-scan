"""Report formats. Reporters only read a :class:`~pqc_scan.models.ScanResult`."""

from __future__ import annotations

import importlib.util
from enum import StrEnum

from pqc_scan.models import ScanResult
from pqc_scan.reporters import console, json_report


class ReportFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"
    HTML = "html"
    CBOM = "cbom"
    SARIF = "sarif"


class UnsupportedFormatError(ValueError):
    """The format needs an optional dependency that is not installed."""


_OPTIONAL: dict[ReportFormat, str] = {
    ReportFormat.HTML: "jinja2",
    ReportFormat.CBOM: "cyclonedx",
}


def missing_dependency(fmt: ReportFormat) -> str | None:
    """An error message if ``fmt`` cannot be produced in this installation."""
    module = _OPTIONAL.get(fmt)
    if module is None or importlib.util.find_spec(module) is not None:
        return None
    return f"the '{fmt.value}' format needs extra packages: pip install 'pqc-scan[report]'"


def render(result: ScanResult, fmt: ReportFormat) -> str:
    """Render ``result`` as text in the given format."""
    problem = missing_dependency(fmt)
    if problem:
        raise UnsupportedFormatError(problem)
    if fmt is ReportFormat.CONSOLE:
        return console.render(result)
    if fmt is ReportFormat.JSON:
        return json_report.render(result)
    if fmt is ReportFormat.HTML:
        from pqc_scan.reporters import html_report

        return html_report.render(result)
    if fmt is ReportFormat.SARIF:
        from pqc_scan.reporters import sarif

        return sarif.render(result)
    from pqc_scan.reporters import cbom

    return cbom.render(result)


__all__ = ["ReportFormat", "UnsupportedFormatError", "missing_dependency", "render"]
