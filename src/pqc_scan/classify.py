"""Map observed algorithms to risk classes.

All classification knowledge lives in ``rules/algorithms.yaml``. This module
only loads, validates and evaluates that file.

Evaluation for one algorithm:

1. Normalise the observed name and look it up in the alias index.
2. If no entry matches, the result is ``UNKNOWN``.
3. Otherwise collect every rule of the entry whose ``when`` conditions all hold.
   If at least one matches, the **worst** matching rule wins. If none match,
   the entry's ``default`` applies.
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from pqc_scan.models import Algorithm, Primitive, RiskClass

_NON_ALNUM = re.compile(r"[^0-9a-z]+")


class RuleSetError(ValueError):
    """The rule file is missing, malformed or inconsistent."""


def normalize_name(name: str) -> str:
    """Case-fold and drop separators: ``SHA-256`` and ``sha_256`` both become ``sha256``."""
    return _NON_ALNUM.sub("", name.casefold())


# --- rule file schema ---------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Condition(_Strict):
    """All given conditions must hold for a rule to match."""

    key_size_lt: int | None = Field(default=None, gt=0)
    key_size_unknown: bool | None = None
    primitive: list[Primitive] | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if self.key_size_lt is None and self.key_size_unknown is None and self.primitive is None:
            raise ValueError("a rule's 'when' needs at least one condition")
        return self

    def matches(self, algorithm: Algorithm) -> bool:
        if self.key_size_lt is not None and (
            algorithm.key_size is None or algorithm.key_size >= self.key_size_lt
        ):
            return False
        if self.key_size_unknown is not None and (
            (algorithm.key_size is None) != self.key_size_unknown
        ):
            return False
        return self.primitive is None or algorithm.primitive in self.primitive


class Rule(_Strict):
    when: Condition
    risk: RiskClass
    reason: str = Field(min_length=1)


class AlgorithmEntry(_Strict):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1, description="Display name")
    aliases: list[str] = Field(min_length=1)
    primitives: list[Primitive] = Field(min_length=1)
    default: RiskClass
    reason: str = Field(min_length=1)
    recommendation: str | None = None
    rules: list[Rule] = []


class RuleSet(_Strict):
    schema_version: int
    algorithms: list[AlgorithmEntry]

    @model_validator(mode="after")
    def _check_schema_version(self) -> Self:
        if self.schema_version != 1:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        return self


# --- classification -----------------------------------------------------


class Classification(_Strict):
    risk: RiskClass
    algorithm_id: str | None
    reason: str
    recommendation: str | None = None


class Classifier:
    """Evaluates a validated :class:`RuleSet`."""

    def __init__(self, ruleset: RuleSet) -> None:
        self.ruleset = ruleset
        self._index: dict[str, AlgorithmEntry] = {}
        seen_ids: set[str] = set()
        for entry in ruleset.algorithms:
            if entry.id in seen_ids:
                raise RuleSetError(f"duplicate algorithm id: {entry.id}")
            seen_ids.add(entry.id)
            for alias in [entry.id, *entry.aliases]:
                key = normalize_name(alias)
                if not key:
                    raise RuleSetError(f"{entry.id}: alias {alias!r} is empty after normalisation")
                other = self._index.get(key)
                if other is not None and other.id != entry.id:
                    raise RuleSetError(
                        f"alias {alias!r} of {entry.id!r} collides with {other.id!r}"
                    )
                self._index[key] = entry

    @classmethod
    def from_file(cls, path: Path) -> Classifier:
        return cls(load_ruleset(path))

    def lookup(self, raw_name: str) -> AlgorithmEntry | None:
        return self._index.get(normalize_name(raw_name))

    def classify(self, algorithm: Algorithm) -> Classification:
        entry = self.lookup(algorithm.raw_name)
        if entry is None:
            return Classification(
                risk=RiskClass.UNKNOWN,
                algorithm_id=None,
                reason=f"'{algorithm.raw_name}' is not in the rule set; review manually",
            )

        matched = [rule for rule in entry.rules if rule.when.matches(algorithm)]
        if matched:
            worst = max(matched, key=lambda rule: rule.risk.severity)
            risk, reason = worst.risk, worst.reason
        else:
            risk, reason = entry.default, entry.reason

        return Classification(
            risk=risk,
            algorithm_id=entry.id,
            reason=reason,
            recommendation=entry.recommendation,
        )


def _parse(text: str, source: str) -> RuleSet:
    try:
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleSetError(f"{source}: invalid YAML: {exc}") from exc
    try:
        return RuleSet.model_validate(data)
    except ValidationError as exc:
        raise RuleSetError(f"{source}: invalid rule set:\n{exc}") from exc


def load_ruleset(path: Path | None = None) -> RuleSet:
    """Load a rule file, or the one shipped with the package when ``path`` is None."""
    if path is None:
        resource = resources.files("pqc_scan").joinpath("rules/algorithms.yaml")
        return _parse(resource.read_text(encoding="utf-8"), "rules/algorithms.yaml")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleSetError(f"cannot read rule file {path}: {exc}") from exc
    return _parse(text, str(path))


@lru_cache(maxsize=1)
def default_classifier() -> Classifier:
    """Classifier for the packaged rule set, loaded once per process."""
    return Classifier(load_ruleset())


def classify(algorithm: Algorithm) -> Classification:
    """Classify with the packaged rule set."""
    return default_classifier().classify(algorithm)
