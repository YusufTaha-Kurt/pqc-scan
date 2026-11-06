"""Helpers shared by reporters."""

from __future__ import annotations

from dataclasses import dataclass

from pqc_scan.models import Algorithm, RiskClass, ScanResult


@dataclass(frozen=True)
class Recommendation:
    """One migration advice and what it applies to."""

    text: str
    risk: RiskClass  # worst risk among the affected findings
    algorithms: tuple[str, ...]
    count: int


def describe_algorithm(algorithm: Algorithm) -> str:
    """Short display form, e.g. ``RSA 2048-bit`` or ``EC secp256r1``."""
    if algorithm.curve:
        return f"{algorithm.raw_name} {algorithm.curve}"
    if algorithm.key_size:
        return f"{algorithm.raw_name} {algorithm.key_size}-bit"
    return algorithm.raw_name


def recommendations(result: ScanResult) -> list[Recommendation]:
    """Distinct recommendations for findings that need action (UNKNOWN or worse)."""
    grouped: dict[str, list[tuple[RiskClass, str]]] = {}
    for finding in result.findings:
        if finding.recommendation and finding.risk.at_least(RiskClass.UNKNOWN):
            grouped.setdefault(finding.recommendation, []).append(
                (finding.risk, describe_algorithm(finding.algorithm))
            )
    found = [
        Recommendation(
            text=text,
            risk=RiskClass.worst([risk for risk, _ in items]) or RiskClass.UNKNOWN,
            algorithms=tuple(sorted({name for _, name in items})),
            count=len(items),
        )
        for text, items in grouped.items()
    ]
    return sorted(found, key=lambda r: (-r.risk.severity, -r.count, r.text))
