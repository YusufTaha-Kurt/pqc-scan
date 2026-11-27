from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from pqc_scan.cli import ExitCode, app
from pqc_scan.diff import diff, render_console
from pqc_scan.i18n import language
from pqc_scan.models import (
    Algorithm,
    Asset,
    AssetKind,
    ErrorKind,
    FileCoverage,
    Finding,
    Primitive,
    RiskClass,
    ScanError,
    ScanResult,
)
from test_reporters import sample_result

runner = CliRunner(env={"COLUMNS": "200"})


def moved(result: ScanResult) -> ScanResult:
    """The same findings, as if checked out elsewhere and shifted by 3 lines."""
    findings = []
    for f in result.findings:
        asset = Asset(
            id="file:///elsewhere/" + f.asset.location, kind=f.asset.kind, location=f.asset.location
        )
        line = (f.evidence.line or 0) + 3 or None
        findings.append(
            f.model_copy(
                update={"asset": asset, "evidence": f.evidence.model_copy(update={"line": line})}
            )
        )
    return result.model_copy(update={"findings": findings})


def test_no_change_after_move() -> None:
    base = sample_result()
    result = diff(base, moved(base))
    assert result.new == [] and result.resolved == []
    assert result.unchanged == len(base.findings)
    assert result.worst_new_risk() is None


def test_new_and_resolved() -> None:
    base = sample_result()
    head = base.model_copy(update={"findings": base.findings[1:]})  # first finding fixed
    result = diff(head, base)
    assert [f.id for f in result.new] == [base.findings[0].id]
    assert result.worst_new_risk() == base.findings[0].risk
    reverse = diff(base, head)
    assert [f.id for f in reverse.resolved] == [base.findings[0].id]
    text = render_console(result)
    assert "1 new · 0 resolved" in text and "New findings" in text


def _write(tmp_path: Path, name: str, result: ScanResult) -> str:
    path = tmp_path / name
    path.write_text(result.model_dump_json())
    return str(path)


def test_diff_cli(tmp_path: Path) -> None:
    base = sample_result()
    head = base.model_copy(update={"findings": base.findings[1:]})
    old, new = _write(tmp_path, "old.json", head), _write(tmp_path, "new.json", base)

    result = runner.invoke(app, ["diff", old, new, "--fail-on", "BROKEN"])
    assert result.exit_code == ExitCode.FAIL_ON
    assert "Worst new risk: BROKEN" in result.output

    result = runner.invoke(app, ["diff", new, old, "-f", "json", "--fail-on", "BROKEN"])
    assert result.exit_code == ExitCode.OK
    data: dict[str, Any] = json.loads(result.stdout)
    assert data["new"] == [] and len(data["resolved"]) == 1

    out = tmp_path / "diff.txt"
    assert runner.invoke(app, ["diff", old, new, "-o", str(out)]).exit_code == ExitCode.OK
    assert "1 new" in out.read_text()


def test_diff_cli_errors(tmp_path: Path) -> None:
    good = _write(tmp_path, "a.json", sample_result())
    assert runner.invoke(app, ["diff", good, good, "-f", "html"]).exit_code == ExitCode.USAGE
    assert (
        runner.invoke(app, ["diff", good, str(tmp_path / "missing.json")]).exit_code
        == ExitCode.USAGE
    )
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert runner.invoke(app, ["diff", good, str(bad)]).exit_code == ExitCode.USAGE
    assert (
        runner.invoke(app, ["diff", good, good, "-o", "/nonexistent/x.txt"]).exit_code
        == ExitCode.USAGE
    )


def test_kind_does_not_matter_for_matching() -> None:
    base = sample_result()
    f = base.findings[0]
    other = f.model_copy(
        update={"asset": Asset(id="x", kind=AssetKind.SOURCE_FILE, location=f.asset.location)}
    )
    assert diff(base, base.model_copy(update={"findings": [other, *base.findings[1:]]})).new == []


def test_failed_tls_endpoint_is_unverified() -> None:
    from pqc_scan.models import ErrorKind, ScanError

    base = sample_result()
    item = base.findings[0]
    a = item.asset.model_copy(update={"location": "example.test:443"})
    finding = item.model_copy(update={"asset": a, "scanner": "tls"})
    base = base.model_copy(update={"findings": [finding]})
    error = ScanError(
        scanner="tls", target="https://example.test", kind=ErrorKind.TIMEOUT, message="timed out"
    )
    result = diff(base, base.model_copy(update={"findings": [], "errors": [error]}))
    assert result.unverified == [finding] and not result.resolved


# --- unverified resolutions (pqc_scan.diff._not_verified) -------------------


def _finding(scanner: str, location: str, asset_id: str | None = None) -> Finding:
    asset = Asset(
        id=asset_id or f"{scanner}://{location}", kind=AssetKind.SOURCE_FILE, location=location
    )
    return Finding(
        asset=asset,
        algorithm=Algorithm(raw_name="RSA", primitive=Primitive.SIGNATURE),
        usage=f"{scanner}.test",
        scanner=scanner,
        id=f"{scanner}-{location}",
        risk=RiskClass.VULNERABLE,
        reason="r",
    )


def _head(errors: list[ScanError], coverage: list[FileCoverage] | None = None) -> ScanResult:
    base = sample_result()
    return base.model_copy(
        update={"findings": [], "errors": errors, "file_coverage": coverage or []}
    )


def _base(*findings: Finding) -> ScanResult:
    return sample_result().model_copy(update={"findings": list(findings)})


def test_failed_ssh_endpoint_is_unverified() -> None:
    finding = _finding("ssh", "srv.test:22")
    head = _head([ScanError(target="srv.test", scanner="ssh", kind=ErrorKind.TIMEOUT, message="t")])
    assert [f.id for f in diff(_base(finding), head).unverified] == [finding.id]


def test_unparsable_error_target_is_ignored() -> None:
    finding = _finding("tls", "srv.test:443")
    error = ScanError(target="srv.test:notaport", scanner="tls", kind=ErrorKind.DNS, message="x")
    result = diff(_base(finding), _head([error]))
    assert [f.id for f in result.resolved] == [finding.id]


def test_failed_code_job_without_coverage_is_unverified() -> None:
    finding = _finding("code", "app.py", "file:///repo/app.py")
    error = ScanError(target="/repo", scanner="code", kind=ErrorKind.PERMISSION, message="p")
    assert diff(_base(finding), _head([error])).unverified


def test_failed_code_job_with_covering_job_is_resolved() -> None:
    root = Path("/repo").absolute()
    finding = _finding("code", "app.py", (root / "app.py").as_uri())
    error = ScanError(target="/other", scanner="code", kind=ErrorKind.PERMISSION, message="p")
    coverage = FileCoverage(scanner="code", target=str(root), inspected=1)
    result = diff(_base(finding), _head([error], [coverage]))
    assert [f.id for f in result.resolved] == [finding.id] and not result.unverified


def test_other_scanner_error_matches_by_location() -> None:
    finding = _finding("custom", "thing")
    error = ScanError(target="thing", scanner="custom", kind=ErrorKind.INTERNAL, message="x")
    assert diff(_base(finding), _head([error])).unverified
    other = ScanError(target="thing", scanner="tls", kind=ErrorKind.INTERNAL, message="x")
    assert not diff(_base(finding), _head([other])).unverified


@pytest.mark.parametrize("skipped", ["app.py", "src", "."])
def test_skipped_files_are_unverified(skipped: str) -> None:
    finding = _finding("code", "src/app.py" if skipped == "src" else "app.py")
    coverage = FileCoverage(scanner="code", target="/repo", oversized=[skipped])
    assert diff(_base(finding), _head([], [coverage])).unverified


def test_console_in_turkish_with_unverified() -> None:
    finding = _finding("ssh", "srv.test:22")
    head = _head([ScanError(target="srv.test", scanner="ssh", kind=ErrorKind.TIMEOUT, message="t")])
    token = language.set("tr")
    try:
        text = render_console(diff(_base(finding), head))
    finally:
        language.reset(token)
    assert "0 yeni · 0 giderilen" in text
