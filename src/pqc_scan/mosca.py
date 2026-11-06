"""Mosca's inequality: data is at risk when x + y > z.

x: years the data must stay confidential, y: years needed to migrate,
z: years until a cryptographically relevant quantum computer exists.
All three come from the user; pqc-scan never assumes a quantum timeline.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from pqc_scan.models import Asset, MoscaInputs, MoscaRule, MoscaScore, RiskClass, ScanConfig

#: Risk classes for which a migration-urgency score is meaningful.
SCORED_CLASSES: Final = frozenset(
    {RiskClass.BROKEN, RiskClass.VULNERABLE, RiskClass.WEAKENED, RiskClass.UNKNOWN}
)


def score(risk: RiskClass, inputs: MoscaInputs | None) -> MoscaScore | None:
    """Return the Mosca score for a finding, or None if not applicable."""
    if inputs is None or risk not in SCORED_CLASSES:
        return None
    return MoscaScore(x=inputs.x, y=inputs.y, z=inputs.z)


def inputs_for(asset: Asset, config: ScanConfig) -> MoscaInputs | None:
    """Mosca values for one asset: the first matching rule, else the global values."""
    for rule in config.mosca_rules:
        if fnmatchcase(asset.id, rule.match) or fnmatchcase(asset.location, rule.match):
            return MoscaInputs(x=rule.x, y=rule.y, z=rule.z)
    return config.mosca


# --- mapping file ---------------------------------------------------------------


class MoscaFileError(ValueError):
    """The Mosca mapping file is unreadable or invalid."""


class _Partial(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    x: float | None = Field(default=None, ge=0)
    y: float | None = Field(default=None, ge=0)
    z: float | None = Field(default=None, ge=0)


class _PartialRule(_Partial):
    match: str = Field(min_length=1)


class _MoscaFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    default: _Partial = _Partial()
    assets: list[_PartialRule] = []


def resolve(
    cli: tuple[float | None, float | None, float | None], path: Path | None
) -> tuple[MoscaInputs | None, tuple[MoscaRule, ...]]:
    """Combine ``--mosca-x/-y/-z`` with an optional mapping file.

    Command-line values override the file's ``default``. Each rule's missing
    values are filled from those defaults; a rule that still lacks a value is
    an error (no value is ever assumed — decision D-7).
    """
    data = _MoscaFile()
    if path is not None:
        try:
            raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            data = _MoscaFile.model_validate(raw)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise MoscaFileError(f"invalid Mosca file {path}: {exc}") from exc
    x, y, z = (
        c if c is not None else d
        for c, d in zip(cli, (data.default.x, data.default.y, data.default.z), strict=True)
    )
    default = None
    if x is not None and y is not None and z is not None:
        default = MoscaInputs(x=x, y=y, z=z)
    rules = []
    for rule in data.assets:
        values = (
            rule.x if rule.x is not None else x,
            rule.y if rule.y is not None else y,
            rule.z if rule.z is not None else z,
        )
        if None in values:
            raise MoscaFileError(
                f"rule {rule.match!r}: x, y and z must be known (set them or a default)"
            )
        rx, ry, rz = values
        assert rx is not None and ry is not None and rz is not None  # noqa: S101 - narrowing
        rules.append(MoscaRule(match=rule.match, x=rx, y=ry, z=rz))
    return default, tuple(rules)
