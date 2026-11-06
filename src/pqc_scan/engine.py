"""Run scanners over targets, classify what they saw and build a ScanResult."""

from __future__ import annotations

import socket
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime

from pqc_scan import __version__, mosca
from pqc_scan.classify import Classifier, default_classifier
from pqc_scan.models import (
    Asset,
    ErrorKind,
    Finding,
    Observation,
    ScanConfig,
    ScanError,
    ScanResult,
)
from pqc_scan.scanners.base import Scanner, ScanTargetError

_MAX_ERROR_MESSAGE = 300


@dataclass(frozen=True)
class ScanJob:
    """One scanner applied to one target."""

    scanner: Scanner
    target: str


def _now() -> datetime:
    return datetime.now(UTC)


def _error_for(job: ScanJob, exc: Exception) -> ScanError:
    """Convert any exception raised while scanning a target into a ScanError."""
    kind: ErrorKind
    if isinstance(exc, ScanTargetError):
        kind, message = exc.kind, exc.message
    elif isinstance(exc, TimeoutError):
        kind, message = ErrorKind.TIMEOUT, "timed out"
    elif isinstance(exc, ConnectionRefusedError):
        kind, message = ErrorKind.CONNECTION_REFUSED, "connection refused"
    elif isinstance(exc, socket.gaierror):
        kind, message = ErrorKind.DNS, "could not resolve host"
    elif isinstance(exc, PermissionError):
        kind, message = ErrorKind.PERMISSION, "permission denied"
    else:
        # Unexpected failure. Keep the message short; scanners must not put
        # secret material in exceptions, but truncate as a second safeguard.
        kind, message = ErrorKind.INTERNAL, f"{type(exc).__name__}: {exc}"
    if len(message) > _MAX_ERROR_MESSAGE:
        message = message[: _MAX_ERROR_MESSAGE - 1] + "…"
    return ScanError(target=job.target, scanner=job.scanner.name, kind=kind, message=message)


def _run_job(job: ScanJob, config: ScanConfig) -> list[Observation] | ScanError:
    try:
        return job.scanner.scan(job.target, config)
    except Exception as exc:  # one target must never abort the run
        return _error_for(job, exc)


def _classify(observation: Observation, classifier: Classifier, config: ScanConfig) -> Finding:
    result = classifier.classify(observation.algorithm)
    return Finding(
        **dict(observation),
        id=observation.fingerprint(),
        risk=result.risk,
        algorithm_id=result.algorithm_id,
        reason=result.reason,
        recommendation=result.recommendation,
        mosca=mosca.score(result.risk, mosca.inputs_for(observation.asset, config)),
    )


def _sort_key(finding: Finding) -> tuple[int, str, str, str]:
    return (-finding.risk.severity, finding.asset.id, finding.usage, finding.algorithm.raw_name)


def run_scan(
    jobs: Sequence[ScanJob],
    config: ScanConfig,
    classifier: Classifier | None = None,
    clock: Callable[[], datetime] = _now,
) -> ScanResult:
    """Run every job with bounded concurrency and return the combined result.

    A failing job is recorded in ``ScanResult.errors`` and never stops the
    others. Findings are de-duplicated by id and sorted worst first.
    """
    classifier = classifier or default_classifier()
    started_at = clock()

    with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
        outcomes = list(pool.map(lambda job: _run_job(job, config), jobs))

    findings: dict[str, Finding] = {}
    assets: dict[str, Asset] = {}
    errors: list[ScanError] = []
    for outcome in outcomes:
        if isinstance(outcome, ScanError):
            errors.append(outcome)
            continue
        for observation in outcome:
            finding = _classify(observation, classifier, config)
            findings.setdefault(finding.id, finding)
            assets.setdefault(observation.asset.id, observation.asset)

    return ScanResult(
        tool_version=__version__,
        started_at=started_at,
        finished_at=clock(),
        scanners=list(dict.fromkeys(job.scanner.name for job in jobs)),
        config=config,
        assets=sorted(assets.values(), key=lambda a: a.id),
        findings=sorted(findings.values(), key=_sort_key),
        errors=sorted(errors, key=lambda e: (e.scanner, e.target)),
    )
