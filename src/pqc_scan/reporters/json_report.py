"""Machine-readable JSON report.

The document is the serialised :class:`~pqc_scan.models.ScanResult`. Its JSON
Schema is published in ``docs/schema/scan-result.schema.json``.
"""

from __future__ import annotations

import json
from typing import Any

from pqc_scan.models import ScanResult


def render(result: ScanResult) -> str:
    """The scan result as indented JSON, ending with a newline."""
    return result.model_dump_json(indent=2) + "\n"


def json_schema() -> dict[str, Any]:
    """JSON Schema describing the output of :func:`render`."""
    schema = ScanResult.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://github.com/YusufTaha-Kurt/pqc-scan/docs/schema/scan-result.schema.json"
    return schema


def json_schema_text() -> str:
    """The schema as stable, pretty-printed JSON text."""
    return json.dumps(json_schema(), indent=2, sort_keys=True) + "\n"
