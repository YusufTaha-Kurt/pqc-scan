"""Compare two scan results: what is new, what was resolved.

Used in CI (e.g. the GitHub Action) to flag cryptography *introduced* by a
change. Findings are matched on what they describe — scanner, location,
usage and algorithm — not on line numbers or absolute paths, so moving code
around or checking out into another directory does not create noise.
"""

from __future__ import annotations

import io

from pydantic import BaseModel, ConfigDict
from rich.console import Console, Group, RenderableType
from rich.text import Text

from pqc_scan.models import Finding, RiskClass, ScanResult
from pqc_scan.reporters.console import findings_table, risk_text

FindingKey = tuple[str, str, str, str, str, int | None, str | None]


class DiffResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    new: list[Finding]
    resolved: list[Finding]
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


def diff(base: ScanResult, head: ScanResult) -> DiffResult:
    base_keys = {finding_key(f) for f in base.findings}
    head_keys = {finding_key(f) for f in head.findings}
    new = [f for f in head.findings if finding_key(f) not in base_keys]
    resolved = [f for f in base.findings if finding_key(f) not in head_keys]
    # One entry per key (the same algorithm on two lines of one file counts once).
    new = list({finding_key(f): f for f in new}.values())
    resolved = list({finding_key(f): f for f in resolved}.values())
    return DiffResult(new=new, resolved=resolved, unchanged=len(base_keys & head_keys))


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
    parts: list[RenderableType] = [header, Text()]
    if result.new:
        table = findings_table(result.new)
        table.title = "New findings"
        parts += [table, Text()]
    if result.resolved:
        table = findings_table(result.resolved)
        table.title = "Resolved findings"
        parts += [table, Text()]
    worst = result.worst_new_risk()
    verdict = Text("Worst new risk: ", style="bold")
    verdict.append_text(risk_text(worst) if worst else Text("none"))
    parts.append(verdict)
    return Group(*parts)
