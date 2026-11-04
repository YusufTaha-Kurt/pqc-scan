"""Mosca's inequality: data is at risk when x + y > z.

x: years the data must stay confidential, y: years needed to migrate,
z: years until a cryptographically relevant quantum computer exists.
All three come from the user; pqc-scan never assumes a quantum timeline.
"""

from __future__ import annotations

from typing import Final

from pqc_scan.models import MoscaInputs, MoscaScore, RiskClass

#: Risk classes for which a migration-urgency score is meaningful.
SCORED_CLASSES: Final = frozenset(
    {RiskClass.BROKEN, RiskClass.VULNERABLE, RiskClass.WEAKENED, RiskClass.UNKNOWN}
)


def score(risk: RiskClass, inputs: MoscaInputs | None) -> MoscaScore | None:
    """Return the Mosca score for a finding, or None if not applicable."""
    if inputs is None or risk not in SCORED_CLASSES:
        return None
    return MoscaScore(x=inputs.x, y=inputs.y, z=inputs.z)
