"""Tests for the public Python API (pqc_scan.api, re-exported from pqc_scan)."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

import pqc_scan
from pqc_scan import RiskClass, ScanConfig, ScanError
from pqc_scan.engine import ScanJob

FIXTURES = Path(__file__).parent / "fixtures" / "code"
REFUSED = "127.0.0.1:1"  # local port that refuses connections; never the internet


def test_top_level_exports() -> None:
    for name in pqc_scan.__all__:
        assert hasattr(pqc_scan, name), name
    assert pqc_scan.__version__ == "0.4.0"


def test_parse_targets() -> None:
    targets = pqc_scan.parse_targets(
        [
            "tls://a.test:443",
            "https://b.test:8443",
            "SSH://c.test:22",
            "path:./repo",
            "file:./keys",
            "d.test",
            "",
            "   # a comment",
            "e.test:443  # trailing comment",
        ]
    )
    assert targets.tls == ("a.test:443", "b.test:8443", "d.test", "e.test:443")
    assert targets.ssh == ("c.test:22",)
    assert targets.paths == ("./repo", "./keys")
    assert targets
    assert not pqc_scan.parse_targets(["# nothing"])


def test_build_jobs_deduplicates_and_honours_switches() -> None:
    jobs = pqc_scan.build_jobs(tls=["a:443", "a:443"], ssh=["b:22"], paths=["p", "p"])
    assert [(j.scanner.name, j.target) for j in jobs] == [
        ("tls", "a:443"),
        ("ssh", "b:22"),
        ("files", "p"),
        ("code", "p"),
    ]
    only_code = pqc_scan.build_jobs(paths=["p"], files=False)
    assert [j.scanner.name for j in only_code] == ["code"]


def test_scan_paths_finds_and_classifies() -> None:
    result = pqc_scan.scan(paths=[str(FIXTURES / "sample_crypto.py")])
    assert result.findings
    assert set(result.scanners) == {"files", "code"}
    assert pqc_scan.exceeds(result, "VULNERABLE")
    assert pqc_scan.exceeds(result, RiskClass.PQ_SAFE)
    assert not pqc_scan.all_failed(result)


def test_scan_without_targets_raises() -> None:
    with pytest.raises(ValueError, match="no targets"):
        pqc_scan.scan()


def test_failed_targets_are_errors_not_exceptions() -> None:
    result = pqc_scan.scan(tls=[REFUSED], paths=["/does/not/exist"], config=ScanConfig(timeout=1))
    assert result.findings == []
    assert {e.scanner for e in result.errors} == {"tls", "files", "code"}
    assert pqc_scan.all_failed(result)
    assert not pqc_scan.exceeds(result, "PQ_SAFE")


def test_progress_callback_reports_every_job() -> None:
    seen: list[tuple[int, int, str, bool]] = []
    lock = threading.Lock()

    def progress(done: int, total: int, job: ScanJob, error: ScanError | None) -> None:
        with lock:
            seen.append((done, total, job.scanner.name, error is None))

    pqc_scan.scan(
        tls=[REFUSED],
        paths=[str(FIXTURES / "sample.go")],
        config=ScanConfig(timeout=1),
        on_progress=progress,
    )
    assert sorted(d for d, *_ in seen) == [1, 2, 3]
    assert {t for _, t, *_ in seen} == {3}
    assert ("tls", False) in {(name, ok) for *_, name, ok in seen}


def test_failing_progress_callback_does_not_break_the_scan() -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("hook failed")

    result = pqc_scan.scan(paths=[str(FIXTURES / "sample.go")], on_progress=boom)
    assert result.findings and not result.errors


def test_render_report_language_is_per_call_and_thread_safe() -> None:
    result = pqc_scan.scan(paths=[str(FIXTURES / "sample_crypto.py")])
    out: dict[str, str] = {}

    def worker() -> None:
        out["tr"] = pqc_scan.render_report(result, "console", lang="tr")

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    assert "Bulgular" in out["tr"]
    english = pqc_scan.render_report(result, pqc_scan.ReportFormat.CONSOLE)
    assert "Findings" in english and "Bulgular" not in english


def test_render_report_json_round_trips() -> None:
    result = pqc_scan.scan(paths=[str(FIXTURES / "sample.go")])
    text = pqc_scan.render_report(result)
    assert pqc_scan.ScanResult.model_validate_json(text) == result
    assert json.loads(pqc_scan.render_report(result, "sarif"))["version"] == "2.1.0"


def test_render_report_rejects_unknown_format_and_language() -> None:
    result = pqc_scan.scan(paths=[str(FIXTURES / "sample.go")])
    with pytest.raises(ValueError):
        pqc_scan.render_report(result, "pdf")
    with pytest.raises(ValueError, match="unsupported language"):
        pqc_scan.render_report(result, lang="de")


def test_write_report(tmp_path: Path) -> None:
    result = pqc_scan.scan(paths=[str(FIXTURES / "sample.go")])
    path = pqc_scan.write_report(result, tmp_path / "r.json")
    assert json.loads(path.read_text(encoding="utf-8"))["tool_version"] == "0.4.0"


def test_localize() -> None:
    reason = "RSA is broken by Shor's algorithm at every key size"
    assert pqc_scan.localize(reason) == reason
    assert pqc_scan.localize(reason, "tr") != reason
    assert pqc_scan.localize("not in the catalog", "tr") == "not in the catalog"
