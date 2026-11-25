"""Localize human-readable reports while preserving machine identifiers."""

import json
from contextvars import ContextVar
from functools import lru_cache
from importlib.resources import files

language: ContextVar[str] = ContextVar("language", default="en")


@lru_cache(maxsize=1)
def _catalog() -> dict[str, str]:
    catalog: dict[str, str] = json.loads(
        files("pqc_scan").joinpath("rules/tr.json").read_text("utf8")
    )
    return catalog


def tr(message: str) -> str:
    if language.get() != "tr":
        return message
    suffix = " is not in the rule set; review manually"
    if message.endswith(suffix):
        return message.removesuffix(suffix) + " kural kümesinde yok, elle inceleyin."
    return _catalog().get(message, message)
