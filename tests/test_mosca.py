from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from pqc_scan import mosca
from pqc_scan.cli import ExitCode, app
from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import (
    Asset,
    AssetKind,
    MoscaInputs,
    MoscaRule,
    RiskClass,
    ScanConfig,
    ScanResult,
)
from test_reporters import SampleScanner

runner = CliRunner(env={"COLUMNS": "200"})


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "mosca.yaml"
    path.write_text(text)
    return path


def test_resolve_without_file() -> None:
    assert mosca.resolve((None, None, None), None) == (None, ())
    assert mosca.resolve((1, 2, 3), None) == (MoscaInputs(x=1, y=2, z=3), ())


def test_resolve_file_defaults_and_rules(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "default: {x: 5, y: 2, z: 15}\n"
        "assets:\n"
        "  - match: 'certs/*'\n"
        "    x: 20\n"
        "  - match: 'tls://*.bank.example:*'\n"
        "    x: 25\n"
        "    y: 4\n",
    )
    default, rules = mosca.resolve((None, None, 10), path)  # --mosca-z 10 overrides the file
    assert default == MoscaInputs(x=5, y=2, z=10)
    assert rules == (
        MoscaRule(match="certs/*", x=20, y=2, z=10),
        MoscaRule(match="tls://*.bank.example:*", x=25, y=4, z=10),
    )


def test_rule_without_z_is_an_error(tmp_path: Path) -> None:
    path = write(tmp_path, "assets:\n  - match: '*'\n    x: 1\n    y: 1\n")
    with pytest.raises(mosca.MoscaFileError, match="must be known"):
        mosca.resolve((None, None, None), path)


@pytest.mark.parametrize("text", ["default: {x: -1}", "unknown: 1", "assets: [{x: 1}]", "{bad"])
def test_invalid_files(tmp_path: Path, text: str) -> None:
    with pytest.raises(mosca.MoscaFileError):
        mosca.resolve((None, None, None), write(tmp_path, text))


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(mosca.MoscaFileError):
        mosca.resolve((None, None, None), tmp_path / "nope.yaml")


def test_inputs_for_first_match_wins() -> None:
    config = ScanConfig(
        mosca=MoscaInputs(x=1, y=1, z=10),
        mosca_rules=(
            MoscaRule(match="certs/*", x=30, y=5, z=10),
            MoscaRule(match="*", x=2, y=2, z=10),
        ),
    )
    cert = Asset(id="file:///r/certs/a.pem", kind=AssetKind.CERTIFICATE, location="certs/a.pem")
    other = Asset(id="file:///r/x.py", kind=AssetKind.SOURCE_FILE, location="x.py")
    assert mosca.inputs_for(cert, config) == MoscaInputs(x=30, y=5, z=10)
    assert mosca.inputs_for(other, config) == MoscaInputs(x=2, y=2, z=10)
    assert mosca.inputs_for(other, ScanConfig(mosca=MoscaInputs(x=1, y=1, z=1))) == MoscaInputs(
        x=1, y=1, z=1
    )


def test_engine_uses_per_asset_values() -> None:
    config = ScanConfig(mosca_rules=(MoscaRule(match="certs/legacy.pem", x=30, y=5, z=10),))
    result = run_scan([ScanJob(SampleScanner(), "repo")], config)
    scored = {f.asset.location: f.mosca for f in result.findings if f.mosca is not None}
    assert set(scored) == {"certs/legacy.pem"}
    assert scored["certs/legacy.pem"].margin == 25  # type: ignore[union-attr]
    unscored = [f for f in result.findings if f.asset.location != "certs/legacy.pem"]
    assert all(f.mosca is None for f in unscored)
    assert any(f.risk == RiskClass.VULNERABLE for f in unscored)


def test_cli_mosca_file(tmp_path: Path, keys: dict[str, Any]) -> None:
    from conftest import cert_pem, make_cert

    (tmp_path / "web.pem").write_bytes(cert_pem(make_cert(keys["p256"])))
    path = write(tmp_path, "default: {x: 1, y: 1}\nassets:\n  - match: 'web.pem'\n    x: 40\n")
    result = runner.invoke(
        app,
        [
            "scan",
            "files",
            str(tmp_path),
            "-f",
            "json",
            "--mosca-file",
            str(path),
            "--mosca-z",
            "12",
        ],
    )
    assert result.exit_code == ExitCode.OK, result.output
    report = ScanResult.model_validate_json(result.stdout)
    margins = {f.mosca.margin for f in report.findings if f.mosca}
    assert margins == {29.0}


def test_cli_bad_mosca_file(tmp_path: Path) -> None:
    path = write(tmp_path, "assets: [{match: '*'}]")
    result = runner.invoke(app, ["scan", "files", str(tmp_path), "--mosca-file", str(path)])
    assert result.exit_code == ExitCode.USAGE
    assert "must be known" in " ".join(result.output.replace("│", " ").split())
