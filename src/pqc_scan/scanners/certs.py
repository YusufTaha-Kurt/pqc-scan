"""Shared X.509 and key parsing for scanners that see certificates.

Maps ``cryptography`` key objects and OIDs to :class:`~pqc_scan.models.Algorithm`
and turns a certificate into ``(usage, algorithm, confidence)`` triples. Used
by the ``files`` and ``tls`` scanners.
"""

from __future__ import annotations

import importlib
import struct
import warnings
from collections.abc import Callable
from typing import Any, Final

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.utils import CryptographyDeprecationWarning

from pqc_scan.models import Algorithm, Confidence, Primitive

#: An observation before it is attached to an asset: (usage, algorithm, confidence).
Triple = tuple[str, Algorithm, Confidence]

# Anything a malformed or unsupported input can raise while we parse it.
PARSE_ERRORS: Final = (
    ValueError,
    TypeError,
    UnsupportedAlgorithm,
    IndexError,
    struct.error,
)

# --- key and OID → Algorithm ------------------------------------------------

_NIST = "2.16.840.1.101.3.4"

# Public key algorithm OIDs, used when ``cryptography`` cannot load the key.
_PUBLIC_KEY_OIDS: Final[dict[str, tuple[str, Primitive]]] = {
    "1.2.840.113549.1.1.1": ("RSA", Primitive.SIGNATURE),
    "1.2.840.113549.1.1.10": ("RSA-PSS", Primitive.SIGNATURE),
    "1.2.840.10045.2.1": ("EC", Primitive.SIGNATURE),
    "1.2.840.10040.4.1": ("DSA", Primitive.SIGNATURE),
    "1.3.101.110": ("X25519", Primitive.KEY_EXCHANGE),
    "1.3.101.111": ("X448", Primitive.KEY_EXCHANGE),
    "1.3.101.112": ("Ed25519", Primitive.SIGNATURE),
    "1.3.101.113": ("Ed448", Primitive.SIGNATURE),
    f"{_NIST}.3.17": ("ML-DSA-44", Primitive.SIGNATURE),
    f"{_NIST}.3.18": ("ML-DSA-65", Primitive.SIGNATURE),
    f"{_NIST}.3.19": ("ML-DSA-87", Primitive.SIGNATURE),
    f"{_NIST}.4.1": ("ML-KEM-512", Primitive.KEM),
    f"{_NIST}.4.2": ("ML-KEM-768", Primitive.KEM),
    f"{_NIST}.4.3": ("ML-KEM-1024", Primitive.KEM),
    **{f"{_NIST}.3.{n}": ("SLH-DSA", Primitive.SIGNATURE) for n in range(20, 32)},
}


def signer_name(oid: str) -> str | None:
    """Name of the public key algorithm behind a signature algorithm OID."""
    if oid == "1.2.840.113549.1.1.10":
        return "RSA-PSS"
    if oid.startswith("1.2.840.113549.1.1.") or oid == "1.3.14.3.2.29":
        return "RSA"
    if oid == "1.2.840.10045.4.1" or oid.startswith("1.2.840.10045.4.3."):
        return "ECDSA"
    if oid == "1.2.840.10040.4.3":
        return "DSA"
    if oid == "1.3.101.112":
        return "Ed25519"
    if oid == "1.3.101.113":
        return "Ed448"
    if oid.startswith(f"{_NIST}.3."):
        n = int(oid.rsplit(".", 1)[1])
        if 1 <= n <= 8:
            return "DSA"
        if 9 <= n <= 12:
            return "ECDSA"
        if 13 <= n <= 16:
            return "RSA"
        if n in (17, 18, 19):
            return _PUBLIC_KEY_OIDS[oid][0]
        if 20 <= n <= 31:
            return "SLH-DSA"
    return None


# (module, class name prefix, display name, primitive). Classes are looked
# up at import time so that a ``cryptography`` version without ML-DSA/ML-KEM,
# or one that has dropped DSA/DH, still works.
_KEY_TYPE_SPECS: Final = (
    ("rsa", "RSA", "RSA", Primitive.SIGNATURE),
    ("ec", "EllipticCurve", "EC", Primitive.SIGNATURE),
    ("dsa", "DSA", "DSA", Primitive.SIGNATURE),
    ("dh", "DH", "DH", Primitive.KEY_EXCHANGE),
    ("ed25519", "Ed25519", "Ed25519", Primitive.SIGNATURE),
    ("ed448", "Ed448", "Ed448", Primitive.SIGNATURE),
    ("x25519", "X25519", "X25519", Primitive.KEY_EXCHANGE),
    ("x448", "X448", "X448", Primitive.KEY_EXCHANGE),
    ("mldsa", "MLDSA44", "ML-DSA-44", Primitive.SIGNATURE),
    ("mldsa", "MLDSA65", "ML-DSA-65", Primitive.SIGNATURE),
    ("mldsa", "MLDSA87", "ML-DSA-87", Primitive.SIGNATURE),
    ("mlkem", "MLKEM512", "ML-KEM-512", Primitive.KEM),
    ("mlkem", "MLKEM768", "ML-KEM-768", Primitive.KEM),
    ("mlkem", "MLKEM1024", "ML-KEM-1024", Primitive.KEM),
)
_SIZED_KEYS: Final = frozenset({"RSA", "DSA", "DH"})


def _load_key_types() -> tuple[tuple[type[Any], str, Primitive], ...]:
    found: list[tuple[type[Any], str, Primitive]] = []
    with warnings.catch_warnings():
        # Touching DH/DSA classes emits deprecation warnings in newer versions.
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        for module_name, prefix, name, primitive in _KEY_TYPE_SPECS:
            try:
                module = importlib.import_module(
                    f"cryptography.hazmat.primitives.asymmetric.{module_name}"
                )
            except ImportError:  # pragma: no cover - depends on the installed version
                continue
            for suffix in ("PublicKey", "PrivateKey"):
                cls = getattr(module, f"{prefix}{suffix}", None)
                if isinstance(cls, type):
                    found.append((cls, name, primitive))
    return tuple(found)


_KEY_TYPES: Final = _load_key_types()


def key_algorithm(key: object) -> Algorithm | None:
    """Describe a ``cryptography`` key object; None if the type is not known."""
    for cls, name, primitive in _KEY_TYPES:
        if not isinstance(key, cls):
            continue
        if name == "EC":
            curve = key.curve
            return Algorithm(
                raw_name=name, primitive=primitive, key_size=curve.key_size, curve=curve.name
            )
        key_size = key.key_size if name in _SIZED_KEYS else None
        return Algorithm(raw_name=name, primitive=primitive, key_size=key_size)
    return None


def public_key_observation(
    key_loader: Callable[[], object], oid: str | None, usage: str
) -> Triple | None:
    """Describe a public key; fall back to its OID if it cannot be loaded."""
    try:
        algorithm = key_algorithm(key_loader())
    except PARSE_ERRORS:
        algorithm = None
    if algorithm is not None:
        return usage, algorithm, Confidence.HIGH
    if oid is None:
        return None
    name, primitive = _PUBLIC_KEY_OIDS.get(oid, (oid, Primitive.SIGNATURE))
    return usage, Algorithm(raw_name=name, primitive=primitive), Confidence.MEDIUM


def signature_observations(
    prefix: str,
    signature_oid: str,
    hash_name: str | None,
    signer_key: Algorithm | None,
) -> list[Triple]:
    """Signature algorithm (+ hash) of a certificate or CSR.

    ``signer_key`` is the subject key when the object is verifiably self-signed;
    only then do we know the signer's key size.
    """
    found: list[Triple] = []
    signer = signer_name(signature_oid)
    if signer is None:
        algorithm = Algorithm(raw_name=signature_oid, primitive=Primitive.SIGNATURE)
        found.append((f"{prefix}.signature", algorithm, Confidence.MEDIUM))
    else:
        algorithm = Algorithm(
            raw_name=signer,
            primitive=Primitive.SIGNATURE,
            key_size=signer_key.key_size if signer_key else None,
            curve=signer_key.curve if signer_key else None,
        )
        found.append((f"{prefix}.signature", algorithm, Confidence.HIGH))
    if hash_name:
        hash_algorithm = Algorithm(raw_name=hash_name, primitive=Primitive.HASH)
        found.append((f"{prefix}.signature_hash", hash_algorithm, Confidence.HIGH))
    return found


def _hash_name(obj: x509.Certificate | x509.CertificateSigningRequest) -> str | None:
    try:
        algorithm = obj.signature_hash_algorithm
    except PARSE_ERRORS:
        return None
    return algorithm.name if algorithm is not None else None


def certificate_observations(cert: x509.Certificate, prefix: str) -> list[Triple]:
    """Public key, signature and signature hash of a certificate.

    ``prefix`` is the usage prefix, e.g. ``file.certificate``. The signer's key
    size is only reported when the certificate verifiably signs itself.
    """
    found: list[Triple] = []
    oid = getattr(cert, "public_key_algorithm_oid", None)
    public = public_key_observation(
        cert.public_key,
        oid.dotted_string if oid is not None else None,
        f"{prefix}.public_key",
    )
    if public is not None:
        found.append(public)

    signer_key: Algorithm | None = None
    if public is not None and cert.issuer == cert.subject:
        try:
            cert.verify_directly_issued_by(cert)
            signer_key = public[1]
        except (*PARSE_ERRORS, InvalidSignature):
            signer_key = None
    found += signature_observations(
        prefix, cert.signature_algorithm_oid.dotted_string, _hash_name(cert), signer_key
    )
    return found


def csr_observations(csr: x509.CertificateSigningRequest, prefix: str) -> list[Triple]:
    """Public key, signature and signature hash of a certificate signing request."""
    found: list[Triple] = []
    public = public_key_observation(csr.public_key, None, f"{prefix}.public_key")
    if public is not None:
        found.append(public)
    try:
        signer_key = public[1] if public is not None and csr.is_signature_valid else None
    except PARSE_ERRORS:
        signer_key = None
    found += signature_observations(
        prefix, csr.signature_algorithm_oid.dotted_string, _hash_name(csr), signer_key
    )
    return found


def certificate_details(cert: x509.Certificate) -> dict[str, str]:
    """Public, non-secret metadata of a certificate (subject, issuer, validity)."""
    details: dict[str, str] = {}
    try:
        details["subject"] = cert.subject.rfc4514_string()
        details["issuer"] = cert.issuer.rfc4514_string()
    except PARSE_ERRORS:
        pass
    for key, attribute in (
        ("not_before", "not_valid_before_utc"),
        ("not_after", "not_valid_after_utc"),
    ):
        value = getattr(cert, attribute, None)
        if value is not None:
            details[key] = value.isoformat()
    details["serial"] = format(cert.serial_number, "x")
    return details
