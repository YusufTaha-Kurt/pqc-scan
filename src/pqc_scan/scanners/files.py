"""Find certificates and keys in a directory tree.

The scanner walks a directory (or looks at a single file) and reports the
algorithm and size of every certificate, CSR, public key and private key it
can recognise:

* PEM blocks anywhere in a file (one file may hold several),
* DER certificates and keys (``.der``, ``.cer``, ``.crt``),
* OpenSSH public keys (``*.pub``, ``authorized_keys``, ``known_hosts``),
* OpenSSH private keys, read from the unencrypted public part of the
  ``openssh-key-v1`` container only.

Security rules: private keys are never decrypted and no passphrase is ever
tried. Key material never leaves this module; observations only carry the
algorithm, its size and a position such as "PEM block 2".
"""

from __future__ import annotations

import base64
import binascii
import importlib
import itertools
import os
import re
import stat
import struct
import warnings
from collections.abc import Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Final

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.utils import CryptographyDeprecationWarning

from pqc_scan.models import (
    Algorithm,
    Asset,
    AssetKind,
    Confidence,
    ErrorKind,
    Evidence,
    Observation,
    Primitive,
    ScanConfig,
)
from pqc_scan.scanners.base import Scanner, ScanTargetError

# Anything a malformed or unsupported input can raise while we parse it.
_PARSE_ERRORS: Final = (
    ValueError,
    TypeError,
    UnsupportedAlgorithm,
    IndexError,
    struct.error,
)

_PEM_BLOCK: Final = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)
_PEM_MARKER: Final = b"-----BEGIN "
_DER_SUFFIXES: Final = frozenset({".der", ".cer", ".crt"})
_SSH_KEY_FILES: Final = frozenset(
    {"authorized_keys", "authorized_keys2", "known_hosts", "known_hosts2", "ssh_known_hosts"}
)
_OPENSSH_MAGIC: Final = b"openssh-key-v1\x00"
_ENCRYPTED_PRIVATE_KEY: Final = "encrypted private key"


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


def _signer_name(oid: str) -> str | None:
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


# --- OpenSSH wire format ----------------------------------------------------


class _SSHReader:
    """Minimal reader for the SSH wire format (RFC 4251 §5)."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def uint32(self) -> int:
        if self._pos + 4 > len(self._data):
            raise ValueError("truncated SSH data")
        (value,) = struct.unpack_from(">I", self._data, self._pos)
        self._pos += 4
        return int(value)

    def string(self) -> bytes:
        length = self.uint32()
        end = self._pos + length
        if end > len(self._data):
            raise ValueError("truncated SSH data")
        value = self._data[self._pos : end]
        self._pos = end
        return value

    def mpint_bits(self) -> int:
        return int.from_bytes(self.string(), "big").bit_length()


_SSH_CERT_SUFFIX: Final = "-cert-v01@openssh.com"
_SSH_EC_CURVES: Final = {
    "nistp256": ("secp256r1", 256),
    "nistp384": ("secp384r1", 384),
    "nistp521": ("secp521r1", 521),
}


def ssh_key_algorithm(blob: bytes) -> tuple[str, Algorithm, Confidence]:
    """Parse an SSH public key blob; return its type string, algorithm and confidence."""
    reader = _SSHReader(blob)
    key_type = reader.string().decode("ascii")
    base_type = key_type
    if base_type.endswith(_SSH_CERT_SUFFIX):
        base_type = base_type.removesuffix(_SSH_CERT_SUFFIX)
        reader.string()  # certificate nonce precedes the key fields

    signature = Primitive.SIGNATURE
    if base_type == "ssh-rsa":
        reader.string()  # e
        return (
            key_type,
            Algorithm(raw_name="RSA", primitive=signature, key_size=reader.mpint_bits()),
            Confidence.HIGH,
        )
    if base_type == "ssh-dss":
        return (
            key_type,
            Algorithm(raw_name="DSA", primitive=signature, key_size=reader.mpint_bits()),
            Confidence.HIGH,
        )
    match = re.fullmatch(r"(?:sk-)?ecdsa-sha2-(nistp\d+)(?:@openssh\.com)?", base_type)
    if match and match.group(1) in _SSH_EC_CURVES:
        curve, size = _SSH_EC_CURVES[match.group(1)]
        return (
            key_type,
            Algorithm(raw_name="EC", primitive=signature, key_size=size, curve=curve),
            Confidence.HIGH,
        )
    if base_type in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        return key_type, Algorithm(raw_name="Ed25519", primitive=signature), Confidence.HIGH
    if base_type == "ssh-ed448":
        return key_type, Algorithm(raw_name="Ed448", primitive=signature), Confidence.HIGH
    return key_type, Algorithm(raw_name=key_type, primitive=signature), Confidence.LOW


def _openssh_private_key(der: bytes) -> tuple[str, Algorithm, Confidence, bool]:
    """Read the public half of an ``openssh-key-v1`` private key without decrypting it."""
    if not der.startswith(_OPENSSH_MAGIC):
        raise ValueError("not an openssh-key-v1 container")
    reader = _SSHReader(der[len(_OPENSSH_MAGIC) :])
    cipher = reader.string()
    reader.string()  # kdf name
    reader.string()  # kdf options
    if reader.uint32() < 1:
        raise ValueError("no keys in container")
    key_type, algorithm, confidence = ssh_key_algorithm(reader.string())
    return key_type, algorithm, confidence, cipher != b"none"


# --- per-file parsing -------------------------------------------------------


@dataclass
class _Item:
    """One certificate or key found in a file."""

    kind: AssetKind
    anchor: str  # "block-2", "line-5", or "" for whole-file DER
    line: int | None
    detail: str
    observations: list[tuple[str, Algorithm, Confidence]] = field(default_factory=list)


def _public_key_observation(
    key_loader: Any, oid: str | None, usage: str
) -> tuple[str, Algorithm, Confidence] | None:
    try:
        algorithm = key_algorithm(key_loader())
    except _PARSE_ERRORS:
        algorithm = None
    if algorithm is not None:
        return usage, algorithm, Confidence.HIGH
    if oid is None:
        return None
    name, primitive = _PUBLIC_KEY_OIDS.get(oid, (oid, Primitive.SIGNATURE))
    return usage, Algorithm(raw_name=name, primitive=primitive), Confidence.MEDIUM


def _signature_observations(
    prefix: str,
    signature_oid: str,
    hash_name: str | None,
    signer_key: Algorithm | None,
) -> list[tuple[str, Algorithm, Confidence]]:
    """Signature algorithm (+ hash) of a certificate or CSR.

    ``signer_key`` is the subject key when the object is verifiably self-signed;
    only then do we know the signer's key size.
    """
    found: list[tuple[str, Algorithm, Confidence]] = []
    signer = _signer_name(signature_oid)
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
    except _PARSE_ERRORS:
        return None
    return algorithm.name if algorithm is not None else None


def _certificate_item(cert: x509.Certificate, anchor: str, line: int | None, detail: str) -> _Item:
    item = _Item(AssetKind.CERTIFICATE, anchor, line, detail)
    oid = getattr(cert, "public_key_algorithm_oid", None)
    public = _public_key_observation(
        cert.public_key,
        oid.dotted_string if oid is not None else None,
        "file.certificate.public_key",
    )
    if public is not None:
        item.observations.append(public)

    signer_key: Algorithm | None = None
    if public is not None and cert.issuer == cert.subject:
        try:
            cert.verify_directly_issued_by(cert)
            signer_key = public[1]
        except (*_PARSE_ERRORS, InvalidSignature):
            signer_key = None
    item.observations += _signature_observations(
        "file.certificate", cert.signature_algorithm_oid.dotted_string, _hash_name(cert), signer_key
    )
    return item


def _csr_item(
    csr: x509.CertificateSigningRequest, anchor: str, line: int | None, detail: str
) -> _Item:
    item = _Item(AssetKind.CERTIFICATE_REQUEST, anchor, line, detail)
    public = _public_key_observation(csr.public_key, None, "file.csr.public_key")
    if public is not None:
        item.observations.append(public)
    try:
        signer_key = public[1] if public is not None and csr.is_signature_valid else None
    except _PARSE_ERRORS:
        signer_key = None
    item.observations += _signature_observations(
        "file.csr", csr.signature_algorithm_oid.dotted_string, _hash_name(csr), signer_key
    )
    return item


def _key_item(
    kind: AssetKind, usage: str, key: object, anchor: str, line: int | None, detail: str
) -> _Item | None:
    algorithm = key_algorithm(key)
    if algorithm is None:
        return None
    return _Item(kind, anchor, line, detail, [(usage, algorithm, Confidence.HIGH)])


# PEM labels of legacy (PKCS#1 / SEC1) private keys → algorithm name, used
# when the key is encrypted and only the label tells us the type.
_LEGACY_PRIVATE_LABELS: Final = {
    "RSA PRIVATE KEY": "RSA",
    "EC PRIVATE KEY": "EC",
    "DSA PRIVATE KEY": "DSA",
}


def _pem_item(
    label: str, block: bytes, body: bytes, anchor: str, line: int, detail: str
) -> _Item | None:
    if label in ("CERTIFICATE", "X509 CERTIFICATE"):
        return _certificate_item(x509.load_pem_x509_certificate(block), anchor, line, detail)
    if label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
        return _csr_item(x509.load_pem_x509_csr(block), anchor, line, detail)
    if label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
        key = serialization.load_pem_public_key(block)
        return _key_item(AssetKind.PUBLIC_KEY, "file.public_key", key, anchor, line, detail)
    if label == "OPENSSH PRIVATE KEY":
        der = base64.b64decode(b"".join(body.split()), validate=True)
        _, algorithm, confidence, encrypted = _openssh_private_key(der)
        note = f"{detail}, OpenSSH format" + (", encrypted" if encrypted else "")
        return _Item(
            AssetKind.PRIVATE_KEY, anchor, line, note, [("file.private_key", algorithm, confidence)]
        )
    if label == "ENCRYPTED PRIVATE KEY":
        algorithm = Algorithm(raw_name=_ENCRYPTED_PRIVATE_KEY, primitive=Primitive.SIGNATURE)
        note = f"{detail}, encrypted PKCS#8; key type is not visible without the passphrase"
        return _Item(
            AssetKind.PRIVATE_KEY,
            anchor,
            line,
            note,
            [("file.private_key", algorithm, Confidence.LOW)],
        )
    if label == "PRIVATE KEY" or label in _LEGACY_PRIVATE_LABELS:
        if b"Proc-Type: 4,ENCRYPTED" in body:
            name = _LEGACY_PRIVATE_LABELS.get(label, _ENCRYPTED_PRIVATE_KEY)
            algorithm = Algorithm(raw_name=name, primitive=Primitive.SIGNATURE)
            note = f"{detail}, encrypted; key size is not visible without the passphrase"
            return _Item(
                AssetKind.PRIVATE_KEY,
                anchor,
                line,
                note,
                [("file.private_key", algorithm, Confidence.MEDIUM)],
            )
        private_key = serialization.load_pem_private_key(
            block, password=None, unsafe_skip_rsa_key_validation=True
        )
        return _key_item(
            AssetKind.PRIVATE_KEY, "file.private_key", private_key, anchor, line, detail
        )
    return None


def _pem_items(data: bytes) -> list[_Item]:
    items: list[_Item] = []
    for index, match in enumerate(_PEM_BLOCK.finditer(data), start=1):
        label = match.group(1).decode("ascii")
        line = data.count(b"\n", 0, match.start()) + 1
        detail = f"PEM block {index} ({label})"
        try:
            item = _pem_item(label, match.group(0), match.group(2), f"block-{index}", line, detail)
        except _PARSE_ERRORS:
            continue  # malformed or unsupported block: not our business
        if item is not None and item.observations:
            items.append(item)
    return items


def _der_items(data: bytes, suffix: str) -> list[_Item]:
    try:
        return [
            _certificate_item(x509.load_der_x509_certificate(data), "", None, "DER certificate")
        ]
    except _PARSE_ERRORS:
        pass
    if suffix != ".der":
        return []
    loaders = (
        (
            AssetKind.PUBLIC_KEY,
            "file.public_key",
            "DER public key",
            lambda: serialization.load_der_public_key(data),
        ),
        (
            AssetKind.PRIVATE_KEY,
            "file.private_key",
            "DER private key",
            lambda: serialization.load_der_private_key(
                data, password=None, unsafe_skip_rsa_key_validation=True
            ),
        ),
    )
    for kind, usage, detail, load in loaders:
        try:
            item = _key_item(kind, usage, load(), "", None, detail)
        except _PARSE_ERRORS:
            continue
        return [item] if item is not None else []
    return []


def _ssh_public_items(data: bytes) -> list[_Item]:
    """Keys in ``*.pub``, ``authorized_keys`` and ``known_hosts`` style files.

    Each line may have a prefix (options, host names, markers) and a trailing
    comment. A key is a ``<type> <base64>`` pair whose blob starts with that
    same type string.
    """
    items: list[_Item] = []
    text = data.decode("utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), start=1):
        tokens = line.split()
        if not tokens or tokens[0].startswith("#"):
            continue
        for key_type, encoded in itertools.pairwise(tokens):
            try:
                blob = base64.b64decode(encoded, validate=True)
                parsed_type, algorithm, confidence = ssh_key_algorithm(blob)
            except (*_PARSE_ERRORS, binascii.Error, UnicodeDecodeError):
                continue
            if parsed_type != key_type:
                continue
            detail = f"line {number}, SSH public key ({key_type})"
            usage_item = ("file.ssh_public_key", algorithm, confidence)
            items.append(
                _Item(AssetKind.PUBLIC_KEY, f"line-{number}", number, detail, [usage_item])
            )
            break
    return items


def parse_file(path: Path, data: bytes) -> list[_Item]:
    """Every certificate and key in one file's content."""
    if _PEM_MARKER in data:
        return _pem_items(data)
    name = path.name
    suffix = path.suffix.lower()
    if suffix in _DER_SUFFIXES:
        return _der_items(data, suffix)
    if suffix == ".pub" or name in _SSH_KEY_FILES:
        return _ssh_public_items(data)
    return []


# --- directory walk ---------------------------------------------------------


def _excluded(name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch(name, pattern) for pattern in patterns)


def iter_files(root: Path, config: ScanConfig) -> Iterator[Path]:
    """Regular files under ``root`` honouring excludes and the symlink policy.

    Children whose name matches an exclude pattern are pruned; ``root`` itself
    is always scanned. Symlinked directories are visited at most once.
    """
    if not root.is_dir():
        yield root
        return
    follow = config.follow_symlinks
    visited: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow):
        real = os.path.realpath(dirpath)
        if real in visited:
            dirnames[:] = []
            continue
        visited.add(real)
        dirnames[:] = sorted(d for d in dirnames if not _excluded(d, config.exclude))
        for name in sorted(filenames):
            path = Path(dirpath, name)
            if _excluded(name, config.exclude) or (not follow and path.is_symlink()):
                continue
            yield path


def _read_candidate(path: Path, max_size: int) -> bytes | None:
    """File content, or None for non-regular, oversized or unreadable files."""
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_size:
            return None
        with path.open("rb") as handle:
            data = handle.read(max_size + 1)
    except OSError:
        return None
    return data if len(data) <= max_size else None


class FilesScanner(Scanner):
    """Report certificates and keys stored in files."""

    name = "files"

    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        root = Path(target).expanduser()
        if not root.exists():
            raise ScanTargetError(ErrorKind.INVALID_TARGET, "path does not exist")
        if not (root.is_dir() or root.is_file()):
            raise ScanTargetError(ErrorKind.INVALID_TARGET, "not a file or directory")
        if not os.access(root, os.R_OK):
            raise ScanTargetError(ErrorKind.PERMISSION, "permission denied")
        base = root if root.is_dir() else root.parent

        observations: list[Observation] = []
        for path in iter_files(root, config):
            data = _read_candidate(path, config.max_file_size)
            if data is None:
                continue
            observations += self._observations(path, base, parse_file(path, data))
        return observations

    def _observations(self, path: Path, base: Path, items: list[_Item]) -> list[Observation]:
        uri = path.absolute().as_uri()
        location = path.relative_to(base).as_posix()
        result: list[Observation] = []
        for item in items:
            # Only disambiguate with an anchor when the file holds several items.
            asset_id = f"{uri}#{item.anchor}" if len(items) > 1 and item.anchor else uri
            asset = Asset(id=asset_id, kind=item.kind, location=location)
            evidence = Evidence(line=item.line, detail=item.detail)
            result += [
                Observation(
                    asset=asset,
                    algorithm=algorithm,
                    usage=usage,
                    scanner=self.name,
                    evidence=evidence,
                    confidence=confidence,
                )
                for usage, algorithm, confidence in item.observations
            ]
        return result
