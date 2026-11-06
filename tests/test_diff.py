from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from pqc_scan.cli import ExitCode, app
from pqc_scan.diff import diff, render_console
from pqc_scan.models import Asset, AssetKind, ScanResult
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
