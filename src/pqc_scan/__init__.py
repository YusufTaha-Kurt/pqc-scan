"""pqc-scan: find quantum-vulnerable cryptography and plan the post-quantum migration.

The names below are the public Python API (see :mod:`pqc_scan.api`).
"""

# Defined before the imports below: pqc_scan.engine reads it.
__version__ = "0.4.0"

from pqc_scan.api import (
    LANGUAGES,
    ProgressCallback,
    Targets,
    all_failed,
    build_jobs,
    exceeds,
    localize,
    parse_targets,
    render_report,
    scan,
    write_report,
)
from pqc_scan.models import (
    Asset,
    AssetKind,
    Finding,
    MoscaInputs,
    MoscaRule,
    RiskClass,
    ScanConfig,
    ScanError,
    ScanResult,
)
from pqc_scan.reporters import ReportFormat, UnsupportedFormatError

__all__ = [
    "LANGUAGES",
    "Asset",
    "AssetKind",
    "Finding",
    "MoscaInputs",
    "MoscaRule",
    "ProgressCallback",
    "ReportFormat",
    "RiskClass",
    "ScanConfig",
    "ScanError",
    "ScanResult",
    "Targets",
    "UnsupportedFormatError",
    "__version__",
    "all_failed",
    "build_jobs",
    "exceeds",
    "localize",
    "parse_targets",
    "render_report",
    "scan",
    "write_report",
]
