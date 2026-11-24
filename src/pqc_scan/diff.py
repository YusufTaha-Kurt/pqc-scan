"""Compare two scan results: what is new, what was resolved.

Used in CI (e.g. the GitHub Action) to flag cryptography *introduced* by a
change. Findings are matched on what they describe — scanner, location,
usage and algorithm — not on line numbers or absolute paths, so moving code
around or checking out into another directory does not create noise.
"""

from __future__ import annotations

import io
from pathlib import Path

from pydantic import BaseModel, ConfigDict
from rich.console import Console, Group, RenderableType
from rich.text import Text

from pqc_scan.i18n import language, tr
from pqc_scan.models import Finding, RiskClass, ScanResult
from pqc_scan.reporters.console import findings_table, risk_text
from pqc_scan.scanners.base import ScanTargetError
from pqc_scan.scanners.tls import display_endpoint, parse_target

FindingKey = tuple[str, str, str, str, str, int | None, str | None]


class DiffResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    new: list[Finding]
    resolved: list[Finding]
    unverified: list[Finding] = []
    unchanged: int

    def worst_new_risk(self) -> RiskClass | None:
        return RiskClass.worst([f.risk for f in self.new])


def finding_key(finding: Finding) -> FindingKey:
    a = finding.algorithm
    return (
        finding.scanner,
        finding.asset.location,
        finding.usage,
        a.raw_name,
        a.primitive.value,
        a.key_size,
        a.curve,
    )


def _not_verified(finding: Finding, head: ScanResult) -> bool:
    location = finding.asset.location
    for error in head.errors:
        if error.scanner != finding.scanner:
            continue
        if error.scanner in {"tls", "ssh"}:
            try:
                host, port = parse_target(error.target, 443 if error.scanner == "tls" else 22)
            except ScanTargetError:
                continue
            if display_endpoint(host, port).lower() == location.lower():
                return True
        elif error.scanner in {"code", "files"}:
            # Absolute checkout paths can change between base and head.
            # Without a successful job covering the old file, resolution is uncertain.
            if not any(
                c.scanner == finding.scanner
                and (Path(c.target).absolute() / location).as_uri()
                == finding.asset.id.split("#")[0]
                for c in head.file_coverage
            ):
                return True
        elif error.target == location:
            return True
    for coverage in head.file_coverage:
        if coverage.scanner == finding.scanner:
            for skipped in (*coverage.oversized, *coverage.unparsed, *coverage.unreadable):
                if skipped == "." or location == skipped or location.startswith(skipped + "/"):
                    return True
    return False


def diff(base: ScanResult, head: ScanResult) -> DiffResult:
    base_keys = {finding_key(f) for f in base.findings}
    head_keys = {finding_key(f) for f in head.findings}
    new = [f for f in head.findings if finding_key(f) not in base_keys]
    resolved = [f for f in base.findings if finding_key(f) not in head_keys]
    # One entry per key (the same algorithm on two lines of one file counts once).
    new = list({finding_key(f): f for f in new}.values())
    resolved = list({finding_key(f): f for f in resolved}.values())
    unverified = [f for f in resolved if _not_verified(f, head)]
    missing_ids = {f.id for f in unverified}
    return DiffResult(
        new=new,
        resolved=[f for f in resolved if f.id not in missing_ids],
        unverified=unverified,
        unchanged=len(base_keys & head_keys),
    )


def render_console(result: DiffResult, width: int | None = None) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, width=width or 120, color_system=None, force_terminal=False)
    console.print(build(result))
    return buffer.getvalue()


def build(result: DiffResult) -> RenderableType:
    header = Text(
        f"{len(result.new)} new · {len(result.resolved)} resolved · {result.unchanged} unchanged",
        style="bold",
    )
    if language.get() == "tr":
        header = Text(
            f"{len(result.new)} yeni · {len(result.resolved)} giderilen · "
            f"{result.unchanged} değişmeyen",
            style="bold",
        )
    parts: list[RenderableType] = [header, Text()]
    if result.new:
        table = findings_table(result.new)
        table.title = tr("New findings")
        parts += [table, Text()]
    if result.resolved:
        table = findings_table(result.resolved)
        table.title = tr("Resolved findings")
        parts += [table, Text()]
    if result.unverified:
        table = findings_table(result.unverified)
        table.title = tr("Could not verify")
        parts += [table, Text()]
    worst = result.worst_new_risk()
    verdict = Text(tr("Worst new risk: "), style="bold")
    verdict.append_text(risk_text(worst) if worst else Text(tr("none")))
    parts.append(verdict)
    return Group(*parts)
