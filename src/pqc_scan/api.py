"""Stable Python API for embedding pqc-scan in other tools.

Everything defined here, and re-exported from :mod:`pqc_scan`, follows
semantic versioning. Other modules are internal and may change between minor
releases.

Example::

    import pqc_scan

    result = pqc_scan.scan(paths=["./my-repo"], tls=["example.com:443"])
    html = pqc_scan.render_report(result, "html", lang="tr")
    if pqc_scan.exceeds(result, "VULNERABLE"):
        ...

Only scan systems you own or have written permission to test.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from pqc_scan.engine import ProgressCallback, ScanJob, run_scan
from pqc_scan.i18n import language, tr
from pqc_scan.models import RiskClass, ScanConfig, ScanResult
from pqc_scan.reporters import ReportFormat, render
from pqc_scan.scanners.code import CodeScanner
from pqc_scan.scanners.files import FilesScanner
from pqc_scan.scanners.ssh import SSHScanner
from pqc_scan.scanners.tls import TLSScanner

#: Report languages. Machine-readable formats (JSON, CBOM, SARIF ids) never change.
LANGUAGES = ("en", "tr")


@dataclass(frozen=True)
class Targets:
    """Targets grouped by scanner type."""

    tls: tuple[str, ...] = ()
    ssh: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.tls or self.ssh or self.paths)


def parse_targets(lines: Iterable[str]) -> Targets:
    """Sort target lines into TLS endpoints, SSH servers and local paths.

    ``tls://host:port`` (or ``https://``) and ``ssh://host:port`` name
    endpoints, ``path:DIR`` or ``file:DIR`` a local directory or file, and a
    bare ``host[:port]`` is a TLS endpoint. Blank lines and ``#`` comments are
    ignored.
    """
    tls: list[str] = []
    ssh: list[str] = []
    paths: list[str] = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        scheme, sep, rest = line.partition("://")
        if sep and scheme.lower() == "ssh":
            ssh.append(rest)
        elif sep and scheme.lower() in ("tls", "https"):
            tls.append(rest)
        elif line.startswith(("path:", "file:")):
            paths.append(line.split(":", 1)[1])
        else:
            tls.append(line)
    return Targets(tuple(tls), tuple(ssh), tuple(paths))


def build_jobs(
    *,
    tls: Iterable[str] = (),
    ssh: Iterable[str] = (),
    paths: Iterable[str] = (),
    files: bool = True,
    code: bool = True,
) -> list[ScanJob]:
    """One job per scanner and target, duplicates removed, order preserved.

    Each path is scanned for key/certificate files (``files``) and for
    cryptography in source code (``code``).
    """
    jobs = [ScanJob(TLSScanner(), target) for target in dict.fromkeys(tls)]
    jobs += [ScanJob(SSHScanner(), target) for target in dict.fromkeys(ssh)]
    for path in dict.fromkeys(paths):
        if files:
            jobs.append(ScanJob(FilesScanner(), path))
        if code:
            jobs.append(ScanJob(CodeScanner(), path))
    return jobs


def scan(
    *,
    tls: Iterable[str] = (),
    ssh: Iterable[str] = (),
    paths: Iterable[str] = (),
    config: ScanConfig | None = None,
    files: bool = True,
    code: bool = True,
    on_progress: ProgressCallback | None = None,
) -> ScanResult:
    """Scan endpoints and local paths and return one classified result.

    A target that fails is recorded in ``ScanResult.errors``; it never raises.
    ``on_progress`` is called after each job (see
    :data:`pqc_scan.engine.ProgressCallback`).

    :raises ValueError: if no target is given.
    """
    jobs = build_jobs(tls=tls, ssh=ssh, paths=paths, files=files, code=code)
    if not jobs:
        raise ValueError("no targets given")
    return run_scan(jobs, config or ScanConfig(), on_job_done=on_progress)


def _language(lang: str) -> str:
    if lang not in LANGUAGES:
        raise ValueError(f"unsupported language {lang!r}; use one of {', '.join(LANGUAGES)}")
    return lang


def localize(text: str, lang: str = "en") -> str:
    """Translate a reason, recommendation or report label (unknown text is returned as is)."""
    token = language.set(_language(lang))
    try:
        return tr(text)
    finally:
        language.reset(token)


def render_report(
    result: ScanResult, fmt: ReportFormat | str = ReportFormat.JSON, *, lang: str = "en"
) -> str:
    """Render ``result`` in a report format and language.

    The language applies to this call only, so it is safe in threads.

    :raises ValueError: for an unknown format or language.
    :raises pqc_scan.UnsupportedFormatError: if ``html`` or ``cbom`` is
        requested without the ``[report]`` extra.
    """
    report_format = ReportFormat(fmt)
    token = language.set(_language(lang))
    try:
        return render(result, report_format)
    finally:
        language.reset(token)


def write_report(
    result: ScanResult,
    path: str | Path,
    fmt: ReportFormat | str = ReportFormat.JSON,
    *,
    lang: str = "en",
) -> Path:
    """Render ``result`` and write it to ``path`` as UTF-8. Returns the path."""
    target = Path(path)
    target.write_text(render_report(result, fmt, lang=lang), encoding="utf-8")
    return target


def exceeds(result: ScanResult, threshold: RiskClass | str) -> bool:
    """True if any finding is at least as severe as ``threshold`` (like ``--fail-on``)."""
    limit = RiskClass(str(threshold).upper())
    worst = result.worst_risk()
    return worst is not None and worst.at_least(limit)


def all_failed(result: ScanResult) -> bool:
    """True if every job of the scan failed (exit code 3 on the command line)."""
    jobs = result.job_count or 0
    return jobs > 0 and len(result.errors) >= jobs


__all__ = [
    "LANGUAGES",
    "ProgressCallback",
    "Targets",
    "all_failed",
    "build_jobs",
    "exceeds",
    "localize",
    "parse_targets",
    "render_report",
    "scan",
    "write_report",
]
