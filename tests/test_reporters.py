from __future__ import annotations

import io
import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from rich.console import Console

from conftest import CryptoTree
from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import (
    Algorithm,
    Asset,
    AssetKind,
    ErrorKind,
    Evidence,
    MoscaInputs,
    Observation,
    Primitive,
    ScanConfig,
    ScanResult,
)
from pqc_scan.reporters import ReportFormat, UnsupportedFormatError, console, json_report, render
from pqc_scan.scanners.base import Scanner, ScanTargetError
from pqc_scan.scanners.files import FilesScanner

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS = Path(__file__).parent / "snapshots"
SCHEMA_FILE = ROOT / "docs" / "schema" / "scan-result.schema.json"
UPDATE = os.environ.get("PQC_UPDATE_SNAPSHOTS") == "1"


def check_snapshot(path: Path, actual: str) -> None:
    """Compare with a committed file; ``PQC_UPDATE_SNAPSHOTS=1`` rewrites it."""
    if UPDATE or not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8")
    assert actual == path.read_text(encoding="utf-8"), (
        f"{path.name} is out of date; rerun with PQC_UPDATE_SNAPSHOTS=1 and review the diff"
    )


def fixed_clock() -> Iterator[datetime]:
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    yield start
    yield start + timedelta(seconds=1.5)


def observation(
    location: str,
    kind: AssetKind,
    usage: str,
    raw: str,
    primitive: Primitive,
    *,
    key_size: int | None = None,
    curve: str | None = None,
    line: int | None = None,
) -> Observation:
    return Observation(
        asset=Asset(id=f"file:///repo/{location}", kind=kind, location=location),
        algorithm=Algorithm(raw_name=raw, primitive=primitive, key_size=key_size, curve=curve),
        usage=usage,
        scanner="sample",
        evidence=Evidence(line=line, detail="sample"),
    )


class SampleScanner(Scanner):
    name = "sample"

    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        if target == "unreachable":
            raise ScanTargetError(ErrorKind.INVALID_TARGET, "path does not exist")
        cert = AssetKind.CERTIFICATE
        return [
            observation(
                "certs/legacy.pem",
                cert,
                "file.certificate.public_key",
                "RSA",
                Primitive.SIGNATURE,
                key_size=1024,
                line=1,
            ),
            observation(
                "certs/legacy.pem",
                cert,
                "file.certificate.signature_hash",
                "sha1",
                Primitive.HASH,
                line=1,
            ),
            observation(
                "certs/web.pem",
                cert,
                "file.certificate.public_key",
                "EC",
                Primitive.SIGNATURE,
                key_size=256,
                curve="secp256r1",
            ),
            observation(
                "keys/[bold]odd[/bold].key",
                AssetKind.PRIVATE_KEY,
                "file.private_key",
                "encrypted private key",
                Primitive.SIGNATURE,
            ),
            observation(
                "keys/pq.pem",
                AssetKind.PUBLIC_KEY,
                "file.public_key",
                "ML-KEM-768",
                Primitive.KEM,
            ),
        ]


def sample_result(config: ScanConfig | None = None) -> ScanResult:
    clock = fixed_clock()
    scanner = SampleScanner()
    result = run_scan(
        [ScanJob(scanner, "repo"), ScanJob(scanner, "unreachable")],
        config or ScanConfig(),
        clock=lambda: next(clock),
    )
    # Pin the version so snapshots do not change on every release.
    return result.model_copy(update={"tool_version": "0.0.0"})


def empty_result() -> ScanResult:
    clock = fixed_clock()
    return run_scan([], ScanConfig(), clock=lambda: next(clock))


# --- console ---------------------------------------------------------------


def test_console_snapshot() -> None:
    check_snapshot(SNAPSHOTS / "console.txt", console.render(sample_result()))


def test_console_snapshot_with_mosca() -> None:
    result = sample_result(ScanConfig(mosca=MoscaInputs(x=10, y=5, z=12)))
    check_snapshot(SNAPSHOTS / "console-mosca.txt", console.render(result))


def test_console_empty_result() -> None:
    text = console.render(empty_result())
    assert "0 findings on 0 assets" in text
    assert "No cryptography found." in text
    assert "Reason" not in text  # no findings table
    assert "Errors" not in text


def test_console_does_not_interpret_markup_in_data() -> None:
    text = console.render(sample_result(), width=200)
    assert "keys/[bold]odd[/bold].key" in text


def test_console_colours_follow_the_console() -> None:
    buffer = io.StringIO()
    coloured = Console(file=buffer, width=120, force_terminal=True, color_system="standard")
    console.print_report(sample_result(), coloured)
    assert "\x1b[" in buffer.getvalue()
    assert "\x1b[" not in console.render(sample_result())


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        (Algorithm(raw_name="RSA", primitive=Primitive.SIGNATURE, key_size=2048), "RSA 2048-bit"),
        (
            Algorithm(
                raw_name="EC", primitive=Primitive.SIGNATURE, key_size=256, curve="secp256r1"
            ),
            "EC secp256r1",
        ),
        (Algorithm(raw_name="Ed25519", primitive=Primitive.SIGNATURE), "Ed25519"),
    ],
)
def test_describe_algorithm(algorithm: Algorithm, expected: str) -> None:
    assert console.describe_algorithm(algorithm) == expected


# --- json ------------------------------------------------------------------


def test_json_round_trip() -> None:
    result = sample_result()
    text = json_report.render(result)
    assert text.endswith("\n")
    assert ScanResult.model_validate_json(text) == result


def test_json_is_deterministic() -> None:
    assert json_report.render(sample_result()) == json_report.render(sample_result())


def test_json_snapshot() -> None:
    check_snapshot(SNAPSHOTS / "report.json", json_report.render(sample_result()))


def test_committed_schema_is_up_to_date() -> None:
    check_snapshot(SCHEMA_FILE, json_report.json_schema_text())


def test_report_validates_against_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    document = json.loads(json_report.render(sample_result()))
    jsonschema.validate(document, json_report.json_schema())


# --- dispatch ----------------------------------------------------------------


def test_render_dispatch() -> None:
    result = sample_result()
    assert render(result, ReportFormat.JSON) == json_report.render(result)
    assert render(result, ReportFormat.CONSOLE) == console.render(result)


@pytest.mark.parametrize("fmt", [ReportFormat.HTML, ReportFormat.CBOM])
def test_unimplemented_formats(fmt: ReportFormat) -> None:
    with pytest.raises(UnsupportedFormatError, match=fmt.value):
        render(sample_result(), fmt)


# --- T-135 for reporters -----------------------------------------------------


def test_reports_never_contain_private_key_material(crypto_tree: CryptoTree) -> None:
    result = run_scan([ScanJob(FilesScanner(), str(crypto_tree.root))], ScanConfig())
    output = "".join(render(result, fmt) for fmt in (ReportFormat.CONSOLE, ReportFormat.JSON))
    leaked = [line for line in crypto_tree.secret_lines if line.decode() in output]
    assert leaked == []
    assert "BEGIN" not in output
