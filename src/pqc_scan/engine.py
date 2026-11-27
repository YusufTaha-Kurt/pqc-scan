"""Run scanners over targets, classify what they saw and build a ScanResult."""

from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime

from pqc_scan import __version__, mosca
from pqc_scan.classify import Classifier, default_classifier
from pqc_scan.models import (
    Asset,
    ErrorKind,
    FileCoverage,
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


#: Called after each job as ``(done, total, job, error)``; ``error`` is None on success.
#: It runs on a worker thread, and an exception raised by it is ignored.
ProgressCallback = Callable[[int, int, ScanJob, ScanError | None], None]


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


def _run_job(
    job: ScanJob, config: ScanConfig
) -> tuple[list[Observation], FileCoverage | None] | ScanError:
    try:
        return job.scanner.scan_with_coverage(job.target, config)
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
    on_job_done: ProgressCallback | None = None,
) -> ScanResult:
    """Run every job with bounded concurrency and return the combined result.

    A failing job is recorded in ``ScanResult.errors`` and never stops the
    others. Findings are de-duplicated by id and sorted worst first.
    ``on_job_done`` reports progress (see :data:`ProgressCallback`).
    """
    classifier = classifier or default_classifier()
    started_at = clock()
    total = len(jobs)
    done = 0
    lock = threading.Lock()

    def work(job: ScanJob) -> tuple[list[Observation], FileCoverage | None] | ScanError:
        nonlocal done
        outcome = _run_job(job, config)
        if on_job_done is not None:
            with lock:
                done += 1
                count = done
            error = outcome if isinstance(outcome, ScanError) else None
            # A progress hook must never break the scan.
            with contextlib.suppress(Exception):
                on_job_done(count, total, job, error)
        return outcome

    with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
        outcomes = list(pool.map(work, jobs))

    findings: dict[str, Finding] = {}
    assets: dict[str, Asset] = {}
    errors: list[ScanError] = []
    coverage = []
    for outcome in outcomes:
        if isinstance(outcome, ScanError):
            errors.append(outcome)
            continue
        observations, audit = outcome
        if audit is not None:
            coverage.append(audit)
        for observation in observations:
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
        job_count=len(jobs),
        file_coverage=coverage,
        errors=sorted(errors, key=lambda e: (e.scanner, e.target)),
    )
