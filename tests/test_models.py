from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pqc_scan.models import (
    Algorithm,
    Asset,
    AssetKind,
    Evidence,
    Finding,
    MoscaScore,
    Observation,
    Primitive,
    RiskClass,
    ScanConfig,
    ScanResult,
)


def _observation(**overrides: object) -> Observation:
    data: dict[str, object] = {
        "asset": Asset(
            id="tls://example.test:443", kind=AssetKind.TLS_ENDPOINT, location="example.test:443"
        ),
        "algorithm": Algorithm(raw_name="RSA", primitive=Primitive.SIGNATURE, key_size=2048),
        "usage": "tls.certificate.public_key",
        "scanner": "tls",
    }
    data.update(overrides)
    return Observation.model_validate(data)


def test_risk_class_order() -> None:
    ordered = sorted(RiskClass, key=lambda c: c.severity, reverse=True)
    assert ordered == [
        RiskClass.BROKEN,
        RiskClass.VULNERABLE,
        RiskClass.WEAKENED,
        RiskClass.UNKNOWN,
        RiskClass.HYBRID,
        RiskClass.PQ_SAFE,
    ]


def test_risk_class_at_least_and_worst() -> None:
    assert RiskClass.BROKEN.at_least(RiskClass.VULNERABLE)
    assert RiskClass.VULNERABLE.at_least(RiskClass.VULNERABLE)
    assert not RiskClass.HYBRID.at_least(RiskClass.WEAKENED)
    assert RiskClass.worst([RiskClass.PQ_SAFE, RiskClass.WEAKENED]) is RiskClass.WEAKENED
    assert RiskClass.worst([]) is None


def test_models_are_frozen_and_strict() -> None:
    obs = _observation()
    with pytest.raises(ValidationError):
        obs.usage = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Algorithm(raw_name="RSA", primitive=Primitive.SIGNATURE, colour="red")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        Algorithm(raw_name="RSA", primitive=Primitive.SIGNATURE, key_size=0)


def test_fingerprint_is_deterministic_and_sensitive() -> None:
    a = _observation()
    assert a.fingerprint() == _observation().fingerprint()
    assert len(a.fingerprint()) == 16
    b = _observation(evidence=Evidence(line=3))
    assert a.fingerprint() != b.fingerprint()


def test_mosca_score() -> None:
    assert MoscaScore(x=25, y=5, z=15).margin == 15
    assert MoscaScore(x=25, y=5, z=15).at_risk
    assert not MoscaScore(x=2, y=3, z=10).at_risk
    dumped = MoscaScore(x=1, y=1, z=1).model_dump()
    assert dumped["at_risk"] is True
    assert dumped["margin"] == 1


def test_scan_config_defaults_are_conservative() -> None:
    config = ScanConfig()
    assert config.timeout == 5.0
    assert config.concurrency == 10
    assert not config.follow_symlinks
    assert ".git" in config.exclude
    with pytest.raises(ValidationError):
        ScanConfig(timeout=0)
    with pytest.raises(ValidationError):
        ScanConfig(concurrency=0)


def test_scan_result_summary_and_json_round_trip() -> None:
    obs = _observation()
    finding = Finding(
        **dict(obs),
        id=obs.fingerprint(),
        risk=RiskClass.VULNERABLE,
        algorithm_id="rsa",
        reason="test",
    )
    now = datetime.now(UTC)
    result = ScanResult(
        tool_version="0",
        started_at=now,
        finished_at=now,
        scanners=["tls"],
        config=ScanConfig(),
        assets=[obs.asset],
        findings=[finding],
    )
    summary = result.summary()
    assert summary[RiskClass.VULNERABLE] == 1
    assert summary[RiskClass.BROKEN] == 0
    assert result.worst_risk() is RiskClass.VULNERABLE
    assert ScanResult.model_validate_json(result.model_dump_json()) == result


def test_empty_result_has_no_worst_risk() -> None:
    now = datetime.now(UTC)
    result = ScanResult(
        tool_version="0", started_at=now, finished_at=now, scanners=[], config=ScanConfig()
    )
    assert result.worst_risk() is None
