"""Human-readable terminal report built with ``rich``.

All values that come from scanned data (paths, algorithm names, messages) are
wrapped in :class:`rich.text.Text` so that they are never interpreted as rich
markup.
"""

from __future__ import annotations

import io
from typing import Final

from rich.console import Console, Group, RenderableType
from rich.table import Table
from rich.text import Text

from pqc_scan.i18n import language, tr
from pqc_scan.models import Finding, RiskClass, ScanError, ScanResult
from pqc_scan.reporters.common import Recommendation, describe_algorithm, recommendations

RISK_STYLES: Final[dict[RiskClass, str]] = {
    RiskClass.BROKEN: "bold red",
    RiskClass.VULNERABLE: "red",
    RiskClass.WEAKENED: "yellow",
    RiskClass.UNKNOWN: "magenta",
    RiskClass.HYBRID: "cyan",
    RiskClass.PQ_SAFE: "green",
}

RISK_MEANINGS: Final[dict[RiskClass, str]] = {
    RiskClass.BROKEN: "Weak today, even without a quantum computer",
    RiskClass.VULNERABLE: "Broken by a quantum computer (Shor)",
    RiskClass.WEAKENED: "Security margin reduced by a quantum computer (Grover)",
    RiskClass.UNKNOWN: "Not in the rule set; review manually",
    RiskClass.HYBRID: "Classical + post-quantum combined",
    RiskClass.PQ_SAFE: "Considered quantum-resistant",
}


def risk_text(risk: RiskClass) -> Text:
    return Text(risk.value, style=RISK_STYLES[risk])


def _location(finding: Finding) -> str:
    line = finding.evidence.line
    return f"{finding.asset.location}:{line}" if line else finding.asset.location


def _header(result: ScanResult) -> Text:
    seconds = (result.finished_at - result.started_at).total_seconds()
    findings = len(result.findings)
    assets = len(result.assets)
    text = Text()
    text.append(f"pqc-scan {result.tool_version}", style="bold")
    if language.get() == "tr":
        text.append(
            f" · tarayıcılar: {', '.join(result.scanners) or '-'}"
            f" · {assets} varlıkta {findings} bulgu · {seconds:.1f} sn"
        )
        return text
    text.append(f" · scanners: {', '.join(result.scanners) or '-'}")
    text.append(f" · {findings} finding{'s' if findings != 1 else ''}")
    text.append(f" on {assets} asset{'s' if assets != 1 else ''}")
    text.append(f" · {seconds:.1f}s")
    return text


def _summary(result: ScanResult) -> Table:
    table = Table(title=tr("Summary"), title_justify="left", show_edge=False)
    table.add_column(tr("Risk"))
    table.add_column(tr("Findings"), justify="right")
    table.add_column(tr("Meaning"))
    for risk, count in result.summary().items():
        table.add_row(risk_text(risk), str(count), tr(RISK_MEANINGS[risk]))
    return table


def findings_table(findings: list[Finding]) -> Table:
    with_mosca = any(f.mosca is not None for f in findings)
    table = Table(title=tr("Findings"), title_justify="left", show_edge=False)
    table.add_column(tr("Risk"), no_wrap=True)
    table.add_column(tr("Location"), overflow="fold", ratio=2)
    table.add_column(tr("Usage"), no_wrap=True)
    table.add_column(tr("Algorithm"), overflow="fold", ratio=1)
    if with_mosca:
        table.add_column(tr("Mosca"), no_wrap=True)
    table.add_column(tr("Reason"), ratio=3)
    for finding in findings:
        row: list[RenderableType] = [
            risk_text(finding.risk),
            Text(_location(finding)),
            Text(finding.usage),
            Text(describe_algorithm(finding.algorithm)),
        ]
        if with_mosca:
            mosca = finding.mosca
            if mosca is None:
                row.append(Text("-"))
            else:
                label = "at risk" if mosca.at_risk else "ok"
                row.append(Text(f"{tr(label)} ({mosca.margin:+.1f}y)"))
        row.append(Text(tr(finding.reason)))
        table.add_row(*row)
    return table


def _recommendations(items: list[Recommendation]) -> Table:
    table = Table(title=tr("Recommendations"), title_justify="left", show_edge=False)
    table.add_column(tr("Risk"), no_wrap=True)
    table.add_column(tr("What to do"), ratio=3)
    table.add_column(tr("Applies to"), ratio=2, overflow="fold")
    for item in items:
        applies = (
            f"{', '.join(item.algorithms)} ({item.count} finding{'s' if item.count != 1 else ''})"
        )
        if language.get() == "tr":
            applies = f"{', '.join(item.algorithms)} ({item.count} bulgu)"
        table.add_row(risk_text(item.risk), Text(tr(item.text)), Text(applies))
    return table


def _errors(errors: list[ScanError]) -> Table:
    table = Table(title=tr("Errors"), title_justify="left", show_edge=False, title_style="bold red")
    table.add_column(tr("Scanner"))
    table.add_column(tr("Target"), overflow="fold")
    table.add_column(tr("Kind"))
    table.add_column(tr("Message"))
    for error in errors:
        table.add_row(
            Text(error.scanner), Text(error.target), Text(error.kind.value), Text(tr(error.message))
        )
    return table


def _verdict(result: ScanResult) -> Text:
    worst = result.worst_risk()
    if worst is None:
        if result.errors:
            return Text(
                tr("No cryptography found; some targets failed. See errors above."), style="bold"
            )
        return Text(tr("No cryptography found."), style="bold")
    text = Text(tr("Worst risk: "), style="bold")
    text.append_text(risk_text(worst))
    return text


def build(result: ScanResult) -> RenderableType:
    """The full report as a single renderable."""
    parts: list[RenderableType] = [_header(result), Text(), _summary(result), Text()]
    if result.file_coverage:
        coverage = Table(title=tr("File coverage"), title_justify="left")
        for column in ("Scanner", "Target", "Inspected", "Oversized", "Unreadable", "Unparsed"):
            coverage.add_column(tr(column))
        for job in result.file_coverage:
            coverage.add_row(
                Text(job.scanner),
                Text(job.target),
                str(job.inspected),
                str(len(job.oversized)),
                str(len(job.unreadable)),
                str(len(job.unparsed)),
            )
        parts += [coverage, Text()]
    if result.findings:
        parts += [findings_table(result.findings), Text()]
    advice = recommendations(result)
    if advice:
        parts += [_recommendations(advice), Text()]
    if result.errors:
        parts += [_errors(result.errors), Text()]
    parts.append(_verdict(result))
    return Group(*parts)


def print_report(result: ScanResult, console: Console) -> None:
    """Print the report to ``console`` (colours follow the console's settings)."""
    console.print(build(result))


def render(result: ScanResult, width: int = 120) -> str:
    """The report as plain text without colours, e.g. for ``--out report.txt``."""
    buffer = io.StringIO()
    console = Console(
        file=buffer, width=width, color_system=None, force_terminal=False, legacy_windows=False
    )
    print_report(result, console)
    return buffer.getvalue()
