"""Schema, loader and value transforms for ``rules/code_rules.yaml``.

The rule file says which source-code API uses which algorithm. This module
turns the strings found in code (``"SHA256withRSA"``, ``"aes-128-cbc"``,
``"P-256"``) into :class:`~pqc_scan.models.Algorithm` objects. Risk is still
decided only by ``algorithms.yaml``.
"""

from __future__ import annotations

import re
from enum import StrEnum
from functools import lru_cache
from importlib import resources
from typing import Any, Final, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from pqc_scan.classify import normalize_name
from pqc_scan.models import Algorithm, Primitive


class CodeRuleError(ValueError):
    """The code rule file is malformed."""


class Transform(StrEnum):
    NONE = "none"
    JCA_SIGNATURE = "jca_signature"
    JCA_CIPHER = "jca_cipher"
    OPENSSL_CIPHER = "openssl_cipher"
    JWT = "jwt"
    HMAC = "hmac"
    TLS_VERSION = "tls_version"
    WEBCRYPTO = "webcrypto"


class Language(StrEnum):
    PYTHON = "python"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    GO = "go"


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ArgSpec(_Strict):
    """Where an argument is: by keyword, or by position (-1 = keyword only)."""

    keyword: str | None = None
    position: int = -1


class _RuleBase(_Strict):
    algorithm: str | None = None
    primitive: Primitive
    usage: str = Field(pattern=r"^[a-z_]+$")
    transform: Transform = Transform.NONE
    ignore: tuple[str, ...] = ()


class PythonCallRule(_RuleBase):
    call: str
    algorithm_arg: ArgSpec | None = None
    key_size: ArgSpec | None = None
    curve: ArgSpec | None = None

    @model_validator(mode="after")
    def _has_algorithm(self) -> Self:
        if (self.algorithm is None) == (self.algorithm_arg is None):
            raise ValueError(f"{self.call}: give exactly one of 'algorithm' and 'algorithm_arg'")
        return self


class PythonAttributeRule(_RuleBase):
    name: str


class Follow(StrEnum):
    LINES = "lines"
    STATEMENT = "statement"


class PatternRule(_RuleBase):
    id: str
    languages: tuple[Language, ...] = Field(min_length=1)
    regex: str
    api: str
    algorithm_prefix: str = ""
    key_size_after: str | None = None
    curve_after: str | None = None
    follow: Follow = Follow.LINES

    @model_validator(mode="after")
    def _check(self) -> Self:
        try:
            compiled = re.compile(self.regex)
            for extra in (self.key_size_after, self.curve_after):
                if extra:
                    re.compile(extra)
        except re.error as exc:
            raise ValueError(f"{self.id}: invalid regex: {exc}") from exc
        if self.algorithm is None and "algorithm" not in compiled.groupindex:
            raise ValueError(f"{self.id}: needs 'algorithm' or an (?P<algorithm>...) group")
        return self

    @property
    def compiled(self) -> re.Pattern[str]:
        return _compile(self.regex)


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


class CodeRules(_Strict):
    schema_version: int
    python_calls: tuple[PythonCallRule, ...]
    python_attributes: tuple[PythonAttributeRule, ...]
    patterns: tuple[PatternRule, ...]

    @model_validator(mode="after")
    def _check_version(self) -> Self:
        if self.schema_version != 1:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        return self


def parse_rules(text: str, source: str = "code_rules.yaml") -> CodeRules:
    try:
        data: Any = yaml.safe_load(text)
        return CodeRules.model_validate(data)
    except (yaml.YAMLError, ValidationError) as exc:
        raise CodeRuleError(f"{source}: {exc}") from exc


@lru_cache(maxsize=1)
def default_rules() -> CodeRules:
    """The rule file shipped with the package, loaded once."""
    text = resources.files("pqc_scan").joinpath("rules/code_rules.yaml").read_text("utf-8")
    return parse_rules(text)


# --- curves -------------------------------------------------------------------

_CURVE_SIZES: Final = {
    "secp192r1": 192,
    "secp224r1": 224,
    "secp256r1": 256,
    "secp384r1": 384,
    "secp521r1": 521,
    "secp256k1": 256,
    "brainpoolP256r1": 256,
    "brainpoolP384r1": 384,
    "brainpoolP512r1": 512,
}
_CURVE_ALIASES: Final = {
    **{normalize_name(name): name for name in _CURVE_SIZES},
    "p192": "secp192r1",
    "prime192v1": "secp192r1",
    "p224": "secp224r1",
    "p256": "secp256r1",
    "prime256v1": "secp256r1",
    "nistp256": "secp256r1",
    "p384": "secp384r1",
    "nistp384": "secp384r1",
    "p521": "secp521r1",
    "nistp521": "secp521r1",
}


def normalize_curve(text: str) -> tuple[str, int] | None:
    """``P-256``, ``prime256v1``, ``SECP256R1``… → (``secp256r1``, 256)."""
    name = _CURVE_ALIASES.get(normalize_name(text))
    return (name, _CURVE_SIZES[name]) if name else None


# --- transforms -----------------------------------------------------------------

_CURVE_ALGORITHMS: Final = frozenset({"ec", "ecdsa", "ecdh", "ecdhe"})
_KEY_EXCHANGE_NAMES: Final = frozenset(
    {"dh", "diffiehellman", "dhe", "ecdh", "ecdhe", "x25519", "x448", "xdh"}
)
_CIPHER_MODES: Final = frozenset(
    {"cbc", "ecb", "gcm", "ctr", "cfb", "cfb1", "cfb8", "ofb", "ccm", "xts", "ocb", "wrap"}
)
_JWT_HASH: Final = {"256": "SHA256", "384": "SHA384", "512": "SHA512"}


def _primitive_for(name: str, default: Primitive) -> Primitive:
    key = normalize_name(name)
    if key in _KEY_EXCHANGE_NAMES:
        return Primitive.KEY_EXCHANGE
    if key.startswith("mlkem") or key.startswith("kyber"):
        return Primitive.KEM
    return default


def _jca_signature(value: str) -> list[tuple[str, Primitive]]:
    """``SHA256withECDSA`` → ECDSA + SHA256; ``Ed25519`` → Ed25519."""
    parts = re.split(r"with", value, maxsplit=1, flags=re.IGNORECASE)
    if len(parts) != 2:
        return [(value, Primitive.SIGNATURE)]
    digest, signer = parts[0], parts[1].split("/")[0]
    if normalize_name(signer) in ("rsaandmgf1", "rsassapss"):
        signer = "RSA-PSS"
    found = [(signer, Primitive.SIGNATURE)]
    if digest and digest.upper() != "NONE":
        found.append((digest, Primitive.HASH))
    return found


def _jca_cipher(value: str, default: Primitive) -> list[tuple[str, Primitive]]:
    """``AES/ECB/PKCS5Padding`` → AES + ECB. A bare ``AES`` defaults to ECB in Java."""
    parts = value.split("/")
    algorithm = parts[0]
    key = normalize_name(algorithm)
    if key.startswith("rsa") or key.startswith("ec"):
        return [(algorithm, Primitive.PUBLIC_KEY_ENCRYPTION)]
    found = [(algorithm, Primitive.AEAD if "GCM" in value.upper() else default)]
    block_cipher = key.startswith(("aes", "des", "blowfish", "rc2", "idea", "seed", "camellia"))
    mode = parts[1].upper() if len(parts) > 1 else ("ECB" if block_cipher else "")
    if mode == "ECB" and block_cipher:
        found.append(("ECB", Primitive.BLOCK_CIPHER))
    return found


def _openssl_cipher(value: str, default: Primitive) -> list[tuple[str, Primitive]]:
    """``aes-128-cbc`` → AES-128; ``*-ecb`` also reports ECB."""
    pieces = value.lower().split("-")
    mode = pieces[-1] if len(pieces) > 1 and pieces[-1] in _CIPHER_MODES else ""
    name = "-".join(pieces[:-1]) if mode else value
    found = [(name, Primitive.AEAD if mode in ("gcm", "ccm") else default)]
    if mode == "ecb":
        found.append(("ECB", Primitive.BLOCK_CIPHER))
    return found


def _jwt(value: str) -> list[tuple[str, Primitive]]:
    """JOSE algorithm names (RFC 7518): ``RS256`` → RSA + SHA256, ``HS256`` → HMAC-SHA256."""
    if value == "none":
        return [("NULL", Primitive.SIGNATURE)]
    if value == "EdDSA":
        return [("Ed25519", Primitive.SIGNATURE)]
    family, bits = value[:2], value[2:]
    digest = _JWT_HASH.get(bits)
    if digest is None:
        return [(value, Primitive.SIGNATURE)]
    if family == "HS":
        return [(f"HMAC-{digest}", Primitive.MAC)]
    signer = {"RS": "RSA", "PS": "RSA-PSS", "ES": "ECDSA"}.get(family, value)
    return [(signer, Primitive.SIGNATURE), (digest, Primitive.HASH)]


def _tls_version(value: str) -> list[tuple[str, Primitive]]:
    """``TLSv1_method`` / ``TLS10`` / ``SSL30`` → protocol names used by algorithms.yaml."""
    text = value.removesuffix("_method").replace("_", ".")
    go_names = {"SSL30": "SSLv3", "TLS10": "TLSv1.0", "TLS11": "TLSv1.1"}
    return [(go_names.get(text, text), Primitive.PROTOCOL)]


def _webcrypto(value: str, default: Primitive) -> list[tuple[str, Primitive]]:
    if value.upper().startswith("AES-"):
        return [("AES", Primitive.AEAD if value.upper() == "AES-GCM" else Primitive.BLOCK_CIPHER)]
    if normalize_name(value) == "rsaoaep":
        return [(value, Primitive.PUBLIC_KEY_ENCRYPTION)]
    return [(value, _primitive_for(value, default))]


def expand(transform: Transform, value: str, primitive: Primitive) -> list[tuple[str, Primitive]]:
    """Turn an algorithm string from source code into ``(name, primitive)`` pairs.

    The first pair is the main algorithm (it receives key size and curve).
    """
    if transform is Transform.JCA_SIGNATURE:
        return _jca_signature(value)
    if transform is Transform.JCA_CIPHER:
        return _jca_cipher(value, primitive)
    if transform is Transform.OPENSSL_CIPHER:
        return _openssl_cipher(value, primitive)
    if transform is Transform.JWT:
        return _jwt(value)
    if transform is Transform.HMAC:
        return [(f"HMAC-{value.upper().replace('-', '')}", Primitive.MAC)]
    if transform is Transform.TLS_VERSION:
        return _tls_version(value)
    if transform is Transform.WEBCRYPTO:
        return _webcrypto(value, primitive)
    return [(value, _primitive_for(value, primitive))]


def build_algorithms(
    rule: _RuleBase,
    value: str,
    key_size: int | None = None,
    curve: str | None = None,
) -> list[Algorithm]:
    """Algorithms for one match; key size / curve go to the main algorithm only."""
    if value in rule.ignore:
        return []
    found: list[Algorithm] = []
    for index, (name, primitive) in enumerate(expand(rule.transform, value, rule.primitive)):
        if not name:
            continue
        if index == 0:
            # A curve only means something for elliptic-curve algorithms.
            uses_curve = normalize_name(name) in _CURVE_ALGORITHMS
            curve_info = normalize_curve(curve) if curve and uses_curve else None
            size = curve_info[1] if curve_info and key_size is None else key_size
            found.append(
                Algorithm(
                    raw_name=name,
                    primitive=primitive,
                    key_size=size if size and size > 0 else None,
                    curve=curve_info[0] if curve_info else None,
                )
            )
        else:
            found.append(Algorithm(raw_name=name, primitive=primitive))
    return found
