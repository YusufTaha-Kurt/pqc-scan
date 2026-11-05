from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from conftest import CryptoTree, cert_pem, make_cert
from pqc_scan import __version__
from pqc_scan.cli import AUTHORIZATION_WARNING, ExitCode, app
from pqc_scan.models import RiskClass, ScanResult

# Wide terminal so that paths are not folded in console output.
runner = CliRunner(env={"COLUMNS": "200"})


def invoke(*args: str) -> Any:
    return runner.invoke(app, list(args))


def flat(text: str) -> str:
    return " ".join(text.replace("│", " ").split())


@pytest.fixture
def safe_dir(tmp_path: Path) -> Path:
    """A directory with nothing worse than a SHA-256 hash... and no keys at all."""
    (tmp_path / "readme.txt").write_text("hello\n")
    return tmp_path


@pytest.fixture
def ec_dir(tmp_path: Path, keys: dict[str, Any]) -> Path:
    """A single P-256 certificate: worst risk is VULNERABLE."""
    (tmp_path / "ec.pem").write_bytes(cert_pem(make_cert(keys["p256"])))
    return tmp_path


# --- basics -----------------------------------------------------------------


def test_version() -> None:
    result = invoke("--version")
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.mark.parametrize("command", [[], ["scan"], ["scan", "files"]])
def test_help_contains_authorization_warning(command: list[str]) -> None:
    result = invoke(*command, "--help")
    assert result.exit_code == 0
    assert "written permission" in flat(result.output)
    assert "written permission" in AUTHORIZATION_WARNING


def test_python_dash_m() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "pqc_scan", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert __version__ in completed.stdout


# --- scan files ---------------------------------------------------------------


def test_scan_files_console(crypto_tree: CryptoTree) -> None:
    result = invoke("scan", "files", str(crypto_tree.root))
    assert result.exit_code == ExitCode.OK
    assert "Worst risk: BROKEN" in result.output
    assert "certs/rsa1024.pem" in result.output


def test_scan_files_json_to_stdout(ec_dir: Path) -> None:
    result = invoke("scan", "files", str(ec_dir), "--format", "json")
    assert result.exit_code == ExitCode.OK
    report = ScanResult.model_validate_json(result.stdout)
    assert report.scanners == ["files"]
    assert report.worst_risk() == RiskClass.VULNERABLE


def test_scan_files_json_to_file(ec_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    out = tmp_path_factory.mktemp("out") / "report.json"
    result = invoke("scan", "files", str(ec_dir), "-f", "json", "-o", str(out))
    assert result.exit_code == ExitCode.OK
    assert result.stdout == ""
    assert "Report written to" in result.stderr
    assert json.loads(out.read_text())["findings"]


def test_console_report_to_file_has_no_colours(ec_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.txt"
    assert invoke("scan", "files", str(ec_dir), "-o", str(out)).exit_code == ExitCode.OK
    text = out.read_text()
    assert "Worst risk: VULNERABLE" in text
    assert "\x1b[" not in text


@pytest.mark.parametrize(
    ("threshold", "code"),
    [
        ("VULNERABLE", ExitCode.FAIL_ON),
        ("vulnerable", ExitCode.FAIL_ON),
        ("WEAKENED", ExitCode.FAIL_ON),
        ("BROKEN", ExitCode.OK),
    ],
)
def test_fail_on(ec_dir: Path, threshold: str, code: ExitCode) -> None:
    result = invoke("scan", "files", str(ec_dir), "--fail-on", threshold)
    assert result.exit_code == code


def test_fail_on_without_findings(safe_dir: Path) -> None:
    result = invoke("scan", "files", str(safe_dir), "--fail-on", "PQ_SAFE")
    assert result.exit_code == ExitCode.OK
    assert "No cryptography found." in result.output


def test_all_targets_failed() -> None:
    result = invoke("scan", "files", "/nonexistent/a", "/nonexistent/b")
    assert result.exit_code == ExitCode.ALL_TARGETS_FAILED
    assert "path does not exist" in result.output  # the report is still printed


def test_some_targets_failed(ec_dir: Path) -> None:
    result = invoke("scan", "files", str(ec_dir), "/nonexistent/a")
    assert result.exit_code == ExitCode.OK
    assert "invalid_target" in result.output


def test_targets_file(
    ec_dir: Path, safe_dir: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    targets = tmp_path_factory.mktemp("t") / "targets.txt"
    targets.write_text(f"# local paths\n{ec_dir}\n\n{safe_dir}  # no keys here\n{ec_dir}\n")
    result = invoke("scan", "files", "--targets", str(targets), "-f", "json")
    assert result.exit_code == ExitCode.OK
    report = ScanResult.model_validate_json(result.stdout)
    assert len(report.assets) == 1


def test_exclude_option(crypto_tree: CryptoTree) -> None:
    result = invoke(
        "scan", "files", str(crypto_tree.root), "-f", "json", "-e", "certs", "-e", "ssh"
    )
    report = ScanResult.model_validate_json(result.stdout)
    locations = {a.location for a in report.assets}
    assert locations
    assert not any(loc.startswith(("certs/", "ssh/", "node_modules/")) for loc in locations)


def test_mosca_scores(ec_dir: Path) -> None:
    result = invoke(
        "scan", "files", str(ec_dir), "-f", "json",
        "--mosca-x", "10", "--mosca-y", "5", "--mosca-z", "12",
    )  # fmt: skip
    report = ScanResult.model_validate_json(result.stdout)
    scored = [f.mosca for f in report.findings if f.risk == RiskClass.VULNERABLE]
    assert scored
    assert all(m is not None and m.at_risk for m in scored)
    # A report with scores can be rendered again later.
    assert ScanResult.model_validate_json(result.stdout) == report


# --- usage errors ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["scan", "files"], "no targets given"),
        (["scan", "files", ".", "--mosca-x", "1"], "must be given together"),
        (["scan", "files", ".", "--format", "html"], "not implemented yet"),
        (["scan", "files", ".", "--format", "cbom"], "not implemented yet"),
        (["scan", "files", ".", "--targets", "/nonexistent/targets.txt"], "cannot read"),
        (["scan", "files", ".", "--fail-on", "SCARY"], "SCARY"),
        (["scan", "files", ".", "--concurrency", "0"], "concurrency"),
    ],
)
def test_usage_errors(args: list[str], message: str) -> None:
    result = invoke(*args)
    assert result.exit_code == ExitCode.USAGE
    assert message in flat(result.output)


def test_unwritable_out(ec_dir: Path) -> None:
    result = invoke("scan", "files", str(ec_dir), "-f", "json", "-o", "/nonexistent/dir/r.json")
    assert result.exit_code == ExitCode.USAGE
    assert "cannot write" in flat(result.output)


# --- report -------------------------------------------------------------------


@pytest.fixture
def saved_report(ec_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("saved") / "report.json"
    assert invoke("scan", "files", str(ec_dir), "-f", "json", "-o", str(out)).exit_code == 0
    return out


def test_report_renders_saved_json(saved_report: Path) -> None:
    result = invoke("report", str(saved_report))
    assert result.exit_code == ExitCode.OK
    assert "Worst risk: VULNERABLE" in result.output


def test_report_json_round_trip(saved_report: Path) -> None:
    result = invoke("report", str(saved_report), "-f", "json")
    assert ScanResult.model_validate_json(result.stdout) == ScanResult.model_validate_json(
        saved_report.read_text()
    )


def test_report_fail_on(saved_report: Path) -> None:
    assert invoke("report", str(saved_report), "--fail-on", "VULNERABLE").exit_code == 1


@pytest.mark.parametrize("content", ["not json", '{"findings": []}'])
def test_report_rejects_invalid_files(tmp_path: Path, content: str) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    result = invoke("report", str(bad))
    assert result.exit_code == ExitCode.USAGE
    assert "not a pqc-scan JSON report" in flat(result.output)


def test_report_missing_file() -> None:
    result = invoke("report", "/nonexistent/report.json")
    assert result.exit_code == ExitCode.USAGE
    assert "cannot read" in flat(result.output)
