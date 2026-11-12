"""Run the GitHub Action's script against a throw-away git repository."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "github-action.sh"

requires_posix = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None or shutil.which("git") is None,
    reason="the shell test harness requires a POSIX environment",
)


def git(cwd: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603 - fixed arguments
        ["git", *args],  # noqa: S607
        cwd=cwd,
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
        },
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """origin with a clean `main`; the working copy adds MD5 on a feature branch."""
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    git(tmp_path, "init", "--bare", "-b", "main", str(origin))
    git(tmp_path, "clone", str(origin), str(work))
    (work / "app.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    git(work, "add", ".")
    git(work, "commit", "-m", "base")
    git(work, "push", "origin", "HEAD:main")
    git(work, "checkout", "-b", "feature")
    (work / "legacy.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    git(work, "add", ".")
    git(work, "commit", "-m", "add md5")
    return work


def run_action(repo: Path, **env: str) -> subprocess.CompletedProcess[str]:
    runner_temp = repo.parent / "runner"
    runner_temp.mkdir(exist_ok=True)
    full_env = {
        **os.environ,
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_STEP_SUMMARY": str(runner_temp / "summary.md"),
        "GITHUB_OUTPUT": str(runner_temp / "output.txt"),
        "PQC_OUTPUT_DIR": str(repo / "pqc-scan-report"),
        **env,
    }
    return subprocess.run(  # noqa: S603 - fixed script
        ["bash", str(SCRIPT)],  # noqa: S607
        cwd=repo,
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
    )


@requires_posix
def test_push_event_fails_on_broken(repo: Path) -> None:
    result = run_action(repo, PQC_FAIL_ON="BROKEN", GITHUB_EVENT_NAME="push")
    assert result.returncode == 1, result.stderr
    report_dir = repo / "pqc-scan-report"
    assert (report_dir / "pqc-scan-report.html").read_text().startswith("<!doctype html>")
    data = json.loads((report_dir / "pqc-scan.json").read_text())
    assert {f["asset"]["location"] for f in data["findings"]} == {"legacy.py"}
    outputs = (repo.parent / "runner" / "output.txt").read_text()
    assert "worst-risk=BROKEN" in outputs
    sarif = json.loads((report_dir / "pqc-scan.sarif").read_text())
    assert (
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]
        == "legacy.py"
    )
    assert "## pqc-scan" in (repo.parent / "runner" / "summary.md").read_text()


@requires_posix
def test_pull_request_only_new_findings(repo: Path) -> None:
    env = {"PQC_FAIL_ON": "BROKEN", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_BASE_REF": "main"}
    result = run_action(repo, **env)
    assert result.returncode == 1, result.stderr  # md5 is new in this branch
    diff = json.loads((repo / "pqc-scan-report" / "pqc-scan-diff.json").read_text())
    assert [f["asset"]["location"] for f in diff["new"]] == ["legacy.py"]
    assert "Changes compared with `main`" in (repo.parent / "runner" / "summary.md").read_text()

    # Once main has the same code, the PR introduces nothing new.
    git(repo, "push", "origin", "HEAD:main")
    assert run_action(repo, **env).returncode == 0


@requires_posix
def test_no_fail_on_and_cbom(repo: Path) -> None:
    result = run_action(repo, PQC_FAIL_ON="", PQC_FORMAT="cbom")
    assert result.returncode == 0, result.stderr
    assert (repo / "pqc-scan-report" / "pqc-scan-report.cdx.json").exists()


@requires_posix
def test_bad_format(repo: Path) -> None:
    assert run_action(repo, PQC_FORMAT="pdf").returncode == 2


def test_action_metadata_passes_inputs_through_env() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    scan = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    assert "${{" not in scan["run"]  # inputs are never interpolated into the shell
    assert set(action["inputs"]) >= {"path", "tls", "ssh", "fail-on", "only-new", "format"}


def test_action_script_uses_unix_line_endings() -> None:
    assert b"\r\n" not in SCRIPT.read_bytes()
