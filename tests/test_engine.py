import socket
import threading
import time
from datetime import UTC, datetime

import pytest

from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import (
    Algorithm,
    Asset,
    AssetKind,
    ErrorKind,
    MoscaInputs,
    Observation,
    Primitive,
    RiskClass,
    ScanConfig,
)
from pqc_scan.scanners.base import Scanner, ScanTargetError


def obs(target: str, raw: str, primitive: Primitive, key_size: int | None = None) -> Observation:
    return Observation(
        asset=Asset(id=f"fake://{target}", kind=AssetKind.SOURCE_FILE, location=target),
        algorithm=Algorithm(raw_name=raw, primitive=primitive, key_size=key_size),
        usage="fake.test",
        scanner="fake",
    )


class FakeScanner(Scanner):
    """Returns canned observations per target, or raises the canned exception."""

    name = "fake"

    def __init__(self, results: dict[str, list[Observation] | Exception]) -> None:
        self.results = results

    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        result = self.results[target]
        if isinstance(result, Exception):
            raise result
        return result


def jobs(scanner: Scanner, *targets: str) -> list[ScanJob]:
    return [ScanJob(scanner, t) for t in targets]


def test_findings_are_classified_and_sorted_worst_first() -> None:
    scanner = FakeScanner(
        {
            "a": [
                obs("a", "ML-KEM-768", Primitive.KEM),
                obs("a", "RSA", Primitive.SIGNATURE, 1024),
            ],
            "b": [obs("b", "AES-128", Primitive.BLOCK_CIPHER), obs("b", "Mystery", Primitive.HASH)],
        }
    )
    result = run_scan(jobs(scanner, "a", "b"), ScanConfig())
    assert [f.risk for f in result.findings] == [
        RiskClass.BROKEN,
        RiskClass.WEAKENED,
        RiskClass.UNKNOWN,
        RiskClass.PQ_SAFE,
    ]
    rsa = result.findings[0]
    assert rsa.algorithm_id == "rsa"
    assert rsa.id == obs("a", "RSA", Primitive.SIGNATURE, 1024).fingerprint()
    assert rsa.recommendation
    assert [a.id for a in result.assets] == ["fake://a", "fake://b"]
    assert result.scanners == ["fake"]
    assert result.errors == []


def test_duplicate_observations_are_merged() -> None:
    o = obs("a", "RSA", Primitive.SIGNATURE, 2048)
    result = run_scan(jobs(FakeScanner({"a": [o, o]}), "a"), ScanConfig())
    assert len(result.findings) == 1


@pytest.mark.parametrize(
    ("exc", "kind"),
    [
        (ScanTargetError(ErrorKind.INVALID_TARGET, "bad target"), ErrorKind.INVALID_TARGET),
        (TimeoutError(), ErrorKind.TIMEOUT),
        (ConnectionRefusedError(), ErrorKind.CONNECTION_REFUSED),
        (socket.gaierror(), ErrorKind.DNS),
        (PermissionError(), ErrorKind.PERMISSION),
        (RuntimeError("boom"), ErrorKind.INTERNAL),
    ],
)
def test_failing_target_does_not_stop_the_run(exc: Exception, kind: ErrorKind) -> None:
    scanner = FakeScanner({"bad": exc, "good": [obs("good", "RSA", Primitive.SIGNATURE, 2048)]})
    result = run_scan(jobs(scanner, "bad", "good"), ScanConfig())
    assert len(result.findings) == 1
    assert len(result.errors) == 1
    error = result.errors[0]
    assert (error.target, error.scanner, error.kind) == ("bad", "fake", kind)


def test_long_internal_error_messages_are_truncated() -> None:
    scanner = FakeScanner({"bad": ValueError("x" * 5000)})
    message = run_scan(jobs(scanner, "bad"), ScanConfig()).errors[0].message
    assert len(message) <= 300
    assert message.startswith("ValueError: ")


def test_concurrency_limit_is_respected() -> None:
    lock = threading.Lock()
    state = {"active": 0, "peak": 0}

    class SlowScanner(Scanner):
        name = "slow"

        def scan(self, target: str, config: ScanConfig) -> list[Observation]:
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            time.sleep(0.02)
            with lock:
                state["active"] -= 1
            return []

    run_scan(jobs(SlowScanner(), *[str(i) for i in range(12)]), ScanConfig(concurrency=3))
    assert 1 <= state["peak"] <= 3


def test_mosca_scores_only_for_at_risk_classes() -> None:
    scanner = FakeScanner(
        {"a": [obs("a", "RSA", Primitive.SIGNATURE, 2048), obs("a", "ML-KEM", Primitive.KEM)]}
    )
    config = ScanConfig(mosca=MoscaInputs(x=10, y=5, z=12))
    by_risk = {f.risk: f for f in run_scan(jobs(scanner, "a"), config).findings}
    vulnerable = by_risk[RiskClass.VULNERABLE].mosca
    assert vulnerable is not None
    assert vulnerable.at_risk
    assert by_risk[RiskClass.PQ_SAFE].mosca is None


def test_no_mosca_without_inputs() -> None:
    scanner = FakeScanner({"a": [obs("a", "RSA", Primitive.SIGNATURE, 2048)]})
    assert run_scan(jobs(scanner, "a"), ScanConfig()).findings[0].mosca is None


def test_timestamps_come_from_clock() -> None:
    times = iter([datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 2, tzinfo=UTC)])
    result = run_scan([], ScanConfig(), clock=lambda: next(times))
    assert result.started_at.day == 1
    assert result.finished_at.day == 2
    assert result.findings == []
