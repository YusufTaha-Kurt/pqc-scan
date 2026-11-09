"""Self-contained HTML report (one file, no external assets).

Rendered from ``templates/report.html.j2`` with Jinja2 autoescaping, so
scanned data can never inject markup. Needs the optional ``[report]`` extra.
"""

from __future__ import annotations

from importlib import resources

import jinja2

from pqc_scan.models import RiskClass, ScanResult
from pqc_scan.reporters.common import describe_algorithm, recommendations
from pqc_scan.reporters.console import RISK_MEANINGS


def render(result: ScanResult) -> str:
    template_text = (
        resources.files("pqc_scan").joinpath("templates/report.html.j2").read_text("utf-8")
    )
    environment = jinja2.Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    template = environment.from_string(template_text)
    return template.render(
        result=result,
        risks=list(RiskClass),
        summary=result.summary(),
        meanings=RISK_MEANINGS,
        worst=result.worst_risk(),
        advice=recommendations(result),
        with_mosca=any(f.mosca is not None for f in result.findings),
        duration=(result.finished_at - result.started_at).total_seconds(),
        describe=describe_algorithm,
    )
