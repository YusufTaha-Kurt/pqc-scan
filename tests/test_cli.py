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


@pytest.mark.parametrize(
    "command",
    [
        [],
        ["scan"],
        ["scan", "files"],
        ["scan", "tls"],
        ["scan", "code"],
        ["scan", "ssh"],
        ["scan", "all"],
    ],
)
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


# --- scan tls -------------------------------------------------------------------


def test_scan_tls_json(local_server: Any, tmp_path: Path, keys: dict[str, Any]) -> None:
    import ssl

    from conftest import ssl_handler, ssl_server_context

    context = ssl_server_context(tmp_path, keys["rsa2048"], minimum=ssl.TLSVersion.TLSv1_2)
    server = local_server(ssl_handler(context))
    result = invoke("scan", "tls", f"127.0.0.1:{server.port}", "-f", "json", "--timeout", "1")
    assert result.exit_code == ExitCode.OK
    report = ScanResult.model_validate_json(result.stdout)
    assert report.scanners == ["tls"]
    assert any(f.usage == "tls.protocol" for f in report.findings)
    assert report.config.timeout == 1.0


def test_scan_tls_unreachable_exit_code() -> None:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    result = invoke("scan", "tls", f"127.0.0.1:{port}", "--timeout", "0.5")
    assert result.exit_code == ExitCode.ALL_TARGETS_FAILED
    assert "connection_refused" in result.output


# --- scan code ------------------------------------------------------------------


def test_scan_code_fail_on() -> None:
    fixtures = str(Path(__file__).parent / "fixtures" / "code")
    result = invoke("scan", "code", fixtures, "-f", "json", "--fail-on", "BROKEN")
    assert result.exit_code == ExitCode.FAIL_ON
    report = ScanResult.model_validate_json(result.stdout)
    assert report.scanners == ["code"]
    assert {f.asset.location for f in report.findings} >= {"Sample.java", "sample.go"}


# --- scan ssh / scan all ---------------------------------------------------------


def test_scan_ssh(local_server: Any) -> None:
    from test_scanner_ssh import ssh_handler

    server = local_server(ssh_handler())
    result = invoke("scan", "ssh", f"127.0.0.1:{server.port}", "-f", "json", "--timeout", "1")
    assert result.exit_code == ExitCode.OK
    report = ScanResult.model_validate_json(result.stdout)
    assert report.worst_risk() == RiskClass.BROKEN  # ssh-rsa host key


def test_split_all_targets() -> None:
    from pqc_scan.cli import split_all_targets

    lines = ["ssh://git.example:2222", "tls://a.example", "https://b.example", "c.example:8443",
             "path:./repo", "file:/srv/certs"]  # fmt: skip
    assert split_all_targets(lines) == (
        ["a.example", "b.example", "c.example:8443"],
        ["git.example:2222"],
        ["./repo", "/srv/certs"],
    )


def test_scan_all_combines_scanners(
    local_server: Any, crypto_tree: CryptoTree, tmp_path_factory: pytest.TempPathFactory
) -> None:
    from test_scanner_ssh import ssh_handler

    ssh = local_server(ssh_handler())
    code_dir = str(Path(__file__).parent / "fixtures" / "code")
    targets = tmp_path_factory.mktemp("all") / "targets.txt"
    targets.write_text(f"ssh://127.0.0.1:{ssh.port}\npath:{code_dir}\n")
    result = invoke(
        "scan", "all", "--targets", str(targets), "--path", str(crypto_tree.root),
        "-f", "json", "--timeout", "1",
    )  # fmt: skip
    assert result.exit_code == ExitCode.OK
    report = ScanResult.model_validate_json(result.stdout)
    assert report.scanners == ["ssh", "files", "code"]
    assert {f.scanner for f in report.findings} == {"ssh", "files", "code"}


def test_scan_all_without_targets() -> None:
    result = invoke("scan", "all")
    assert result.exit_code == ExitCode.USAGE
    assert "no targets given" in flat(result.output)


@pytest.mark.parametrize("fmt", ["html", "cbom"])
def test_report_formats_to_file(ec_dir: Path, tmp_path: Path, fmt: str) -> None:
    out = tmp_path / f"report.{fmt}"
    result = invoke("scan", "files", str(ec_dir), "-f", fmt, "-o", str(out))
    assert result.exit_code == ExitCode.OK
    text = out.read_text()
    assert ("<!doctype html>" in text) if fmt == "html" else ('"specVersion": "1.6"' in text)


def test_missing_report_extra_is_a_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import pqc_scan.cli as cli

    monkeypatch.setattr(cli, "missing_dependency", lambda fmt: "needs extra packages")
    result = invoke("scan", "files", ".", "--format", "html")
    assert result.exit_code == ExitCode.USAGE
    assert "needs extra packages" in flat(result.output)
