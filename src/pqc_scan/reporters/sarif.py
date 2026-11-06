"""SARIF 2.1.0 output for code-scanning dashboards (e.g. GitHub code scanning).

Only actionable findings are emitted (``UNKNOWN`` or worse); quantum-safe and
hybrid algorithms are not alerts. One rule per algorithm, one result per
finding. File-based findings point to the file and line; endpoint findings
(TLS/SSH) carry a logical location only, because SARIF consumers expect
source files.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Final
from urllib.parse import unquote, urlparse

from pqc_scan import __version__
from pqc_scan.models import Finding, RiskClass, ScanResult
from pqc_scan.reporters.common import describe_algorithm

SCHEMA: Final = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS: Final = {
    RiskClass.BROKEN: "error",
    RiskClass.VULNERABLE: "warning",
    RiskClass.WEAKENED: "warning",
    RiskClass.UNKNOWN: "note",
}
# GitHub sorts alerts by this 0-10 score.
_SECURITY_SEVERITY: Final = {
    RiskClass.BROKEN: "8.0",
    RiskClass.VULNERABLE: "6.0",
    RiskClass.WEAKENED: "4.0",
    RiskClass.UNKNOWN: "2.0",
}


def _rule_id(finding: Finding) -> str:
    name = finding.algorithm_id or finding.algorithm.raw_name
    return f"pqc/{finding.risk.value.lower()}/{name}"


def _artifact_uri(finding: Finding, base: Path) -> str | None:
    """Path of a file asset relative to ``base`` (falls back to the scan location)."""
    parsed = urlparse(finding.asset.id)
    if parsed.scheme != "file":
        return None
    path = Path(unquote(parsed.path))
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return finding.asset.location


def _fingerprint(finding: Finding) -> str:
    a = finding.algorithm
    key = "\x1f".join(
        map(
            str,
            (
                finding.scanner,
                finding.asset.location,
                finding.usage,
                a.raw_name,
                a.key_size,
                a.curve,
            ),
        )
    )
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def build(result: ScanResult, base: Path | None = None) -> dict[str, Any]:
    base = (base or Path.cwd()).resolve()
    findings = [f for f in result.findings if f.risk.at_least(RiskClass.UNKNOWN)]
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id not in rules:
            text = finding.recommendation or "Review this algorithm."
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.algorithm_id or finding.algorithm.raw_name,
                "shortDescription": {"text": f"{finding.risk.value}: {finding.algorithm.raw_name}"},
                "fullDescription": {"text": finding.reason},
                "help": {"text": text, "markdown": text},
                "defaultConfiguration": {"level": _LEVELS[finding.risk]},
                "properties": {
                    "tags": ["security", "cryptography", "post-quantum", finding.risk.value],
                    "security-severity": _SECURITY_SEVERITY[finding.risk],
                },
            }
        message = (
            f"{describe_algorithm(finding.algorithm)} ({finding.usage}) is {finding.risk.value}: "
            f"{finding.reason}"
        )
        uri = _artifact_uri(finding, base)
        if uri is not None:
            physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
            if finding.evidence.line:
                physical["region"] = {"startLine": finding.evidence.line}
            location: dict[str, Any] = {"physicalLocation": physical}
        else:
            location = {"logicalLocations": [{"name": finding.asset.location, "kind": "resource"}]}
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVELS[finding.risk],
                "message": {"text": message},
                "locations": [location],
                "partialFingerprints": {"pqcScan/v1": _fingerprint(finding)},
                "properties": {"risk": finding.risk.value, "evidence": finding.evidence.detail},
            }
        )
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pqc-scan",
                        "version": result.tool_version or __version__,
                        "informationUri": "https://github.com/YusufTaha-Kurt/pqc-scan",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "startTimeUtc": result.started_at.isoformat().replace("+00:00", "Z"),
                        "endTimeUtc": result.finished_at.isoformat().replace("+00:00", "Z"),
                    }
                ],
            }
        ],
    }


def render(result: ScanResult) -> str:
    return json.dumps(build(result), indent=2) + "\n"
