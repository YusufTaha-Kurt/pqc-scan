"""Command-line interface for pqc-scan.

Exit codes (decision D-8):

* ``0`` success
* ``1`` a finding reached the ``--fail-on`` threshold
* ``2`` usage error (bad option, unreadable targets file, unsupported format)
* ``3`` every target failed to scan
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from enum import IntEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console

from pqc_scan import __version__
from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import DEFAULT_EXCLUDES, MoscaInputs, RiskClass, ScanConfig, ScanResult
from pqc_scan.reporters import IMPLEMENTED_FORMATS, ReportFormat, console, render
from pqc_scan.scanners.base import Scanner
from pqc_scan.scanners.code import CodeScanner
from pqc_scan.scanners.files import FilesScanner
from pqc_scan.scanners.ssh import SSHScanner
from pqc_scan.scanners.tls import TLSScanner

AUTHORIZATION_WARNING = (
    "Only scan systems you own or have written permission to test. "
    "pqc-scan performs passive discovery: it reads handshake metadata, "
    "never logs in, and never attempts exploitation."
)


class ExitCode(IntEnum):
    OK = 0
    FAIL_ON = 1
    USAGE = 2
    ALL_TARGETS_FAILED = 3


app = typer.Typer(
    name="pqc-scan",
    help=(
        "Find quantum-vulnerable cryptography in endpoints and code, "
        f"and plan your post-quantum migration.\n\n{AUTHORIZATION_WARNING}"
    ),
    no_args_is_help=True,
    add_completion=False,
)
scan_app = typer.Typer(
    help=f"Scan targets and report what cryptography they use.\n\n{AUTHORIZATION_WARNING}",
    no_args_is_help=True,
)
app.add_typer(scan_app, name="scan")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"pqc-scan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """pqc-scan root command."""


# --- shared options -----------------------------------------------------------

FormatOption = Annotated[
    ReportFormat,
    typer.Option("--format", "-f", case_sensitive=False, help="Report format."),
]
OutOption = Annotated[
    Path | None,
    typer.Option("--out", "-o", dir_okay=False, help="Write the report here instead of stdout."),
]
FailOnOption = Annotated[
    RiskClass | None,
    typer.Option(
        "--fail-on",
        case_sensitive=False,
        help="Exit with code 1 if any finding is at least this severe (for CI).",
    ),
]
TargetsOption = Annotated[
    Path | None,
    typer.Option(
        "--targets",
        "-t",
        dir_okay=False,
        help="File with one target per line ('#' starts a comment).",
    ),
]
ConcurrencyOption = Annotated[
    int, typer.Option("--concurrency", min=1, max=256, help="Targets scanned in parallel.")
]
MoscaXOption = Annotated[
    float | None,
    typer.Option("--mosca-x", min=0, help="Years the data must stay confidential."),
]
MoscaYOption = Annotated[
    float | None, typer.Option("--mosca-y", min=0, help="Years needed to migrate.")
]
MoscaZOption = Annotated[
    float | None,
    typer.Option(
        "--mosca-z",
        min=0,
        help="Years until a cryptographically relevant quantum computer (your estimate).",
    ),
]


_DEFAULTS = ScanConfig()

PathsArgument = Annotated[
    list[str] | None,
    typer.Argument(help="Directories or files to scan.", show_default=False),
]
ExcludeOption = Annotated[
    list[str] | None,
    typer.Option(
        "--exclude",
        "-e",
        help="Skip files and directories matching this glob (repeatable). "
        "Added to the defaults (.git, node_modules, .venv, ...).",
    ),
]
MaxFileSizeOption = Annotated[
    int, typer.Option("--max-file-size", min=1, help="Skip files larger than this (bytes).")
]
FollowSymlinksOption = Annotated[
    bool, typer.Option("--follow-symlinks", help="Follow symbolic links.")
]
TimeoutOption = Annotated[
    float, typer.Option("--timeout", min=0.1, help="Seconds per network operation.")
]


# --- helpers ------------------------------------------------------------------


def _read_targets_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise typer.BadParameter(f"cannot read {path}: {exc}", param_hint="--targets") from exc
    targets = []
    for line in text.splitlines():
        target = line.split("#", 1)[0].strip()
        if target:
            targets.append(target)
    return targets


def collect_targets(arguments: Sequence[str] | None, targets_file: Path | None) -> list[str]:
    """Targets from the command line and ``--targets``, de-duplicated in order."""
    targets = list(arguments or [])
    if targets_file is not None:
        targets += _read_targets_file(targets_file)
    if not targets:
        raise typer.BadParameter("no targets given (pass them as arguments or with --targets)")
    return list(dict.fromkeys(targets))


def mosca_inputs(x: float | None, y: float | None, z: float | None) -> MoscaInputs | None:
    """All three Mosca values, or none of them (decision D-7)."""
    given = [value is not None for value in (x, y, z)]
    if not any(given):
        return None
    if not all(given):
        raise typer.BadParameter(
            "--mosca-x, --mosca-y and --mosca-z must be given together", param_hint="--mosca-*"
        )
    assert x is not None and y is not None and z is not None  # noqa: S101 - narrowing only
    return MoscaInputs(x=x, y=y, z=z)


def _check_format(fmt: ReportFormat) -> None:
    """Fail before scanning if the format cannot be produced."""
    if fmt not in IMPLEMENTED_FORMATS:
        raise typer.BadParameter(f"'{fmt.value}' is not implemented yet", param_hint="--format")


def emit(result: ScanResult, fmt: ReportFormat, out: Path | None) -> None:
    """Print the report to stdout or write it to ``out``."""
    if out is None and fmt is ReportFormat.CONSOLE:
        console.print_report(result, Console())
        return
    text = render(result, fmt)
    if out is None:
        sys.stdout.write(text)
        return
    try:
        out.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(f"cannot write {out}: {exc}", param_hint="--out") from exc
    typer.echo(f"Report written to {out}", err=True)


def exit_code(result: ScanResult, job_count: int, fail_on: RiskClass | None) -> ExitCode:
    """Map a finished scan to an exit code (D-8)."""
    if job_count and len(result.errors) >= job_count:
        return ExitCode.ALL_TARGETS_FAILED
    worst = result.worst_risk()
    if fail_on is not None and worst is not None and worst.at_least(fail_on):
        return ExitCode.FAIL_ON
    return ExitCode.OK


def _run(
    scanner: Scanner,
    targets: list[str],
    config: ScanConfig,
    fmt: ReportFormat,
    out: Path | None,
    fail_on: RiskClass | None,
) -> None:
    _run_jobs([ScanJob(scanner, target) for target in targets], config, fmt, out, fail_on)


def _run_jobs(
    jobs: list[ScanJob],
    config: ScanConfig,
    fmt: ReportFormat,
    out: Path | None,
    fail_on: RiskClass | None,
) -> None:
    result = run_scan(jobs, config)
    emit(result, fmt, out)
    raise typer.Exit(exit_code(result, len(jobs), fail_on))


def split_all_targets(lines: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Sort ``--targets`` lines of ``scan all`` into (tls, ssh, paths).

    ``tls://host:port`` and ``ssh://host:port`` name endpoints, ``path:DIR``
    or ``file:DIR`` a local directory; a bare ``host[:port]`` is a TLS endpoint.
    """
    tls, ssh, paths = [], [], []
    for line in lines:
        scheme, sep, rest = line.partition("://")
        if sep and scheme.lower() == "ssh":
            ssh.append(rest)
        elif sep and scheme.lower() in ("tls", "https"):
            tls.append(rest)
        elif line.startswith(("path:", "file:")):
            paths.append(line.split(":", 1)[1])
        else:
            tls.append(line)
    return tls, ssh, paths


# --- commands -----------------------------------------------------------------


def _local_config(
    concurrency: int,
    follow_symlinks: bool,
    max_file_size: int,
    exclude: list[str] | None,
    mosca: MoscaInputs | None,
) -> ScanConfig:
    return ScanConfig(
        concurrency=concurrency,
        follow_symlinks=follow_symlinks,
        max_file_size=max_file_size,
        exclude=(*DEFAULT_EXCLUDES, *(exclude or [])),
        mosca=mosca,
    )


@scan_app.command("files", epilog=AUTHORIZATION_WARNING)
def scan_files(
    paths: PathsArgument = None,
    targets_file: TargetsOption = None,
    fmt: FormatOption = ReportFormat.CONSOLE,
    out: OutOption = None,
    fail_on: FailOnOption = None,
    exclude: ExcludeOption = None,
    max_file_size: MaxFileSizeOption = _DEFAULTS.max_file_size,
    follow_symlinks: FollowSymlinksOption = False,
    concurrency: ConcurrencyOption = _DEFAULTS.concurrency,
    mosca_x: MoscaXOption = None,
    mosca_y: MoscaYOption = None,
    mosca_z: MoscaZOption = None,
) -> None:
    """Find certificates and keys (PEM, DER, OpenSSH) in local files."""
    _check_format(fmt)
    targets = collect_targets(paths, targets_file)
    mosca = mosca_inputs(mosca_x, mosca_y, mosca_z)
    config = _local_config(concurrency, follow_symlinks, max_file_size, exclude, mosca)
    _run(FilesScanner(), targets, config, fmt, out, fail_on)


@scan_app.command("code", epilog=AUTHORIZATION_WARNING)
def scan_code(
    paths: PathsArgument = None,
    targets_file: TargetsOption = None,
    fmt: FormatOption = ReportFormat.CONSOLE,
    out: OutOption = None,
    fail_on: FailOnOption = None,
    exclude: ExcludeOption = None,
    max_file_size: MaxFileSizeOption = _DEFAULTS.max_file_size,
    follow_symlinks: FollowSymlinksOption = False,
    concurrency: ConcurrencyOption = _DEFAULTS.concurrency,
    mosca_x: MoscaXOption = None,
    mosca_y: MoscaYOption = None,
    mosca_z: MoscaZOption = None,
) -> None:
    """Find cryptography API usage in source code (Python, Java/Kotlin,
    JavaScript/TypeScript, Go). Reports file, line and API name only.
    """
    _check_format(fmt)
    targets = collect_targets(paths, targets_file)
    mosca = mosca_inputs(mosca_x, mosca_y, mosca_z)
    config = _local_config(concurrency, follow_symlinks, max_file_size, exclude, mosca)
    _run(CodeScanner(), targets, config, fmt, out, fail_on)


@scan_app.command("tls", epilog=AUTHORIZATION_WARNING)
def scan_tls(
    hosts: Annotated[
        list[str] | None,
        typer.Argument(
            help="Endpoints as host, host:port or [IPv6]:port (default port 443).",
            show_default=False,
        ),
    ] = None,
    targets_file: TargetsOption = None,
    fmt: FormatOption = ReportFormat.CONSOLE,
    out: OutOption = None,
    fail_on: FailOnOption = None,
    timeout: TimeoutOption = _DEFAULTS.timeout,
    concurrency: ConcurrencyOption = _DEFAULTS.concurrency,
    mosca_x: MoscaXOption = None,
    mosca_y: MoscaYOption = None,
    mosca_z: MoscaZOption = None,
) -> None:
    """Probe TLS endpoints: versions, cipher suites, key-exchange groups
    (including hybrid post-quantum groups) and certificates.

    Each endpoint receives a few dozen short connections. No handshake is
    completed except one to read a TLS 1.3 certificate; no data is sent.
    """
    _check_format(fmt)
    targets = collect_targets(hosts, targets_file)
    config = ScanConfig(
        timeout=timeout,
        concurrency=concurrency,
        mosca=mosca_inputs(mosca_x, mosca_y, mosca_z),
    )
    _run(TLSScanner(), targets, config, fmt, out, fail_on)


@scan_app.command("ssh", epilog=AUTHORIZATION_WARNING)
def scan_ssh(
    hosts: Annotated[
        list[str] | None,
        typer.Argument(
            help="Servers as host, host:port or [IPv6]:port (default port 22).",
            show_default=False,
        ),
    ] = None,
    targets_file: TargetsOption = None,
    fmt: FormatOption = ReportFormat.CONSOLE,
    out: OutOption = None,
    fail_on: FailOnOption = None,
    timeout: TimeoutOption = _DEFAULTS.timeout,
    concurrency: ConcurrencyOption = _DEFAULTS.concurrency,
    mosca_x: MoscaXOption = None,
    mosca_y: MoscaYOption = None,
    mosca_z: MoscaZOption = None,
) -> None:
    """Read the algorithms an SSH server offers (key exchange, host keys,
    ciphers, MACs). One connection per server; no login is attempted.
    """
    _check_format(fmt)
    targets = collect_targets(hosts, targets_file)
    config = ScanConfig(
        timeout=timeout, concurrency=concurrency, mosca=mosca_inputs(mosca_x, mosca_y, mosca_z)
    )
    _run(SSHScanner(), targets, config, fmt, out, fail_on)


@scan_app.command("all", epilog=AUTHORIZATION_WARNING)
def scan_all(
    targets_file: Annotated[
        Path | None,
        typer.Option(
            "--targets",
            "-t",
            dir_okay=False,
            help="File with one target per line: tls://host:port, ssh://host:port, "
            "path:DIR, or a bare host:port (TLS).",
        ),
    ] = None,
    tls_hosts: Annotated[
        list[str] | None, typer.Option("--tls", help="TLS endpoint (repeatable).")
    ] = None,
    ssh_hosts: Annotated[
        list[str] | None, typer.Option("--ssh", help="SSH server (repeatable).")
    ] = None,
    paths: Annotated[
        list[str] | None,
        typer.Option("--path", "-p", help="Directory scanned for files and code (repeatable)."),
    ] = None,
    fmt: FormatOption = ReportFormat.CONSOLE,
    out: OutOption = None,
    fail_on: FailOnOption = None,
    timeout: TimeoutOption = _DEFAULTS.timeout,
    concurrency: ConcurrencyOption = _DEFAULTS.concurrency,
    exclude: ExcludeOption = None,
    max_file_size: MaxFileSizeOption = _DEFAULTS.max_file_size,
    follow_symlinks: FollowSymlinksOption = False,
    mosca_x: MoscaXOption = None,
    mosca_y: MoscaYOption = None,
    mosca_z: MoscaZOption = None,
) -> None:
    """Run every scanner in one go and produce a single report:
    TLS and SSH endpoints, plus files and source code under --path.
    """
    _check_format(fmt)
    tls, ssh, local = list(tls_hosts or []), list(ssh_hosts or []), list(paths or [])
    if targets_file is not None:
        more_tls, more_ssh, more_paths = split_all_targets(_read_targets_file(targets_file))
        tls, ssh, local = tls + more_tls, ssh + more_ssh, local + more_paths
    if not (tls or ssh or local):
        raise typer.BadParameter("no targets given (use --tls, --ssh, --path or --targets)")
    config = ScanConfig(
        timeout=timeout,
        concurrency=concurrency,
        follow_symlinks=follow_symlinks,
        max_file_size=max_file_size,
        exclude=(*DEFAULT_EXCLUDES, *(exclude or [])),
        mosca=mosca_inputs(mosca_x, mosca_y, mosca_z),
    )
    jobs = [ScanJob(TLSScanner(), t) for t in dict.fromkeys(tls)]
    jobs += [ScanJob(SSHScanner(), t) for t in dict.fromkeys(ssh)]
    for path in dict.fromkeys(local):
        jobs += [ScanJob(FilesScanner(), path), ScanJob(CodeScanner(), path)]
    _run_jobs(jobs, config, fmt, out, fail_on)


@app.command("report")
def report(
    result_file: Annotated[
        Path,
        typer.Argument(dir_okay=False, help="A JSON report produced with --format json."),
    ],
    fmt: FormatOption = ReportFormat.CONSOLE,
    out: OutOption = None,
    fail_on: FailOnOption = None,
) -> None:
    """Render a saved JSON report in another format."""
    _check_format(fmt)
    try:
        result = ScanResult.model_validate_json(result_file.read_bytes())
    except OSError as exc:
        raise typer.BadParameter(f"cannot read {result_file}: {exc}") from exc
    except ValidationError as exc:
        message = f"{result_file} is not a pqc-scan JSON report ({exc.error_count()} errors)"
        raise typer.BadParameter(message) from exc
    emit(result, fmt, out)
    raise typer.Exit(exit_code(result, 0, fail_on))
