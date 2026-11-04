"""Core data models shared by scanners, the engine, classification and reporters."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, computed_field

SCHEMA_VERSION: Final = "1"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --- enums --------------------------------------------------------------


class RiskClass(StrEnum):
    """Quantum risk of an algorithm, from most to least severe."""

    BROKEN = "BROKEN"
    VULNERABLE = "VULNERABLE"
    WEAKENED = "WEAKENED"
    UNKNOWN = "UNKNOWN"
    HYBRID = "HYBRID"
    PQ_SAFE = "PQ_SAFE"

    @property
    def severity(self) -> int:
        """Higher means worse. Used for sorting, ``--fail-on`` and worst-wins rules."""
        return _SEVERITY[self]

    def at_least(self, other: RiskClass) -> bool:
        """Return True if this class is as severe as ``other`` or worse."""
        return self.severity >= other.severity

    @staticmethod
    def worst(classes: list[RiskClass]) -> RiskClass | None:
        """Return the most severe class, or None for an empty list."""
        return max(classes, key=lambda c: c.severity, default=None)


_SEVERITY: Final[dict[RiskClass, int]] = {
    RiskClass.BROKEN: 5,
    RiskClass.VULNERABLE: 4,
    RiskClass.WEAKENED: 3,
    RiskClass.UNKNOWN: 2,
    RiskClass.HYBRID: 1,
    RiskClass.PQ_SAFE: 0,
}


class Primitive(StrEnum):
    """What an algorithm is used for. Classification can depend on it."""

    KEY_EXCHANGE = "key_exchange"
    KEM = "kem"
    SIGNATURE = "signature"
    PUBLIC_KEY_ENCRYPTION = "public_key_encryption"
    BLOCK_CIPHER = "block_cipher"
    STREAM_CIPHER = "stream_cipher"
    AEAD = "aead"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    PROTOCOL = "protocol"


class AssetKind(StrEnum):
    TLS_ENDPOINT = "tls_endpoint"
    SSH_ENDPOINT = "ssh_endpoint"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"
    SOURCE_FILE = "source_file"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ErrorKind(StrEnum):
    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    DNS = "dns"
    PARSE = "parse"
    PERMISSION = "permission"
    INVALID_TARGET = "invalid_target"
    INTERNAL = "internal"


# --- observations and findings ----------------------------------------


class Algorithm(_Model):
    """An algorithm exactly as a scanner observed it."""

    raw_name: str = Field(min_length=1)
    primitive: Primitive
    key_size: int | None = Field(default=None, gt=0, description="Bits")
    curve: str | None = None


class Asset(_Model):
    """Something that uses cryptography: an endpoint, a file, a source file."""

    id: str = Field(
        min_length=1,
        description="Stable URI-like id, e.g. tls://host:443 or file:///abs/path",
    )
    kind: AssetKind
    location: str = Field(description="Human readable location (host:port or path)")


class Evidence(_Model):
    """Where an observation came from. Must never contain secret material."""

    line: int | None = Field(default=None, ge=1)
    detail: str = ""


class Observation(_Model):
    """What a scanner saw, before classification."""

    asset: Asset
    algorithm: Algorithm
    usage: str = Field(
        min_length=1,
        description="Dotted context, e.g. tls.key_exchange or file.certificate.signature",
    )
    scanner: str = Field(min_length=1)
    evidence: Evidence = Evidence()
    confidence: Confidence = Confidence.HIGH

    def fingerprint(self) -> str:
        """Deterministic id, stable across runs for the same observation."""
        parts = (
            self.asset.id,
            self.usage,
            self.algorithm.raw_name,
            self.algorithm.primitive.value,
            str(self.algorithm.key_size),
            str(self.algorithm.curve),
            str(self.evidence.line),
            self.evidence.detail,
        )
        digest = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
        return digest[:16]


class MoscaScore(_Model):
    """Mosca's inequality: data is at risk when x + y > z (all in years)."""

    x: float = Field(ge=0, description="Years the data must stay confidential")
    y: float = Field(ge=0, description="Years needed to migrate")
    z: float = Field(ge=0, description="Years until a cryptographically relevant QC")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def margin(self) -> float:
        return self.x + self.y - self.z

    @computed_field  # type: ignore[prop-decorator]
    @property
    def at_risk(self) -> bool:
        return self.margin > 0


class Finding(Observation):
    """A classified observation."""

    id: str
    risk: RiskClass
    algorithm_id: str | None = Field(
        default=None, description="Canonical id from algorithms.yaml; None if unknown"
    )
    reason: str
    recommendation: str | None = None
    mosca: MoscaScore | None = None


class ScanError(_Model):
    """A target that could not be scanned. Never aborts the whole run."""

    target: str
    scanner: str
    kind: ErrorKind
    message: str


# --- configuration and result -----------------------------------------

DEFAULT_EXCLUDES: Final = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    "dist",
    "build",
)


class MoscaInputs(_Model):
    x: float = Field(ge=0)
    y: float = Field(ge=0)
    z: float = Field(ge=0)


class ScanConfig(_Model):
    """Options shared by all scanners. Defaults are deliberately conservative."""

    timeout: float = Field(default=5.0, gt=0, description="Seconds per network operation")
    concurrency: int = Field(default=10, ge=1, le=256)
    follow_symlinks: bool = False
    max_file_size: int = Field(default=1024 * 1024, gt=0, description="Bytes")
    exclude: tuple[str, ...] = DEFAULT_EXCLUDES
    mosca: MoscaInputs | None = None


class ScanResult(_Model):
    """Everything a run produced. The only input reporters receive."""

    schema_version: str = SCHEMA_VERSION
    tool_version: str
    started_at: datetime
    finished_at: datetime
    scanners: list[str]
    config: ScanConfig
    assets: list[Asset] = []
    findings: list[Finding] = []
    errors: list[ScanError] = []

    def summary(self) -> dict[RiskClass, int]:
        """Number of findings per risk class, including zero counts."""
        counts = dict.fromkeys(RiskClass, 0)
        for finding in self.findings:
            counts[finding.risk] += 1
        return counts

    def worst_risk(self) -> RiskClass | None:
        return RiskClass.worst([f.risk for f in self.findings])
