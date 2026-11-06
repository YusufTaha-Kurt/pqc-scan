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
import itertools
import os
import re
import stat
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import serialization

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
from pqc_scan.scanners.certs import (
    PARSE_ERRORS,
    Triple,
    certificate_details,
    certificate_observations,
    csr_observations,
    key_algorithm,
)

_PEM_BLOCK: Final = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)
_PEM_MARKER: Final = b"-----BEGIN "
_DER_SUFFIXES: Final = frozenset({".der", ".cer", ".crt"})
_SSH_KEY_FILES: Final = frozenset(
    {"authorized_keys", "authorized_keys2", "known_hosts", "known_hosts2", "ssh_known_hosts"}
)
_OPENSSH_MAGIC: Final = b"openssh-key-v1\x00"
_ENCRYPTED_PRIVATE_KEY: Final = "encrypted private key"


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
    observations: list[Triple] = field(default_factory=list)
    details: dict[str, str] = field(default_factory=dict)


def _certificate_item(cert: x509.Certificate, anchor: str, line: int | None, detail: str) -> _Item:
    observations = certificate_observations(cert, "file.certificate")
    return _Item(
        AssetKind.CERTIFICATE, anchor, line, detail, observations, certificate_details(cert)
    )


def _csr_item(
    csr: x509.CertificateSigningRequest, anchor: str, line: int | None, detail: str
) -> _Item:
    observations = csr_observations(csr, "file.csr")
    return _Item(AssetKind.CERTIFICATE_REQUEST, anchor, line, detail, observations)


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
        except PARSE_ERRORS:
            continue  # malformed or unsupported block: not our business
        if item is not None and item.observations:
            items.append(item)
    return items


def _der_items(data: bytes, suffix: str) -> list[_Item]:
    try:
        return [
            _certificate_item(x509.load_der_x509_certificate(data), "", None, "DER certificate")
        ]
    except PARSE_ERRORS:
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
        except PARSE_ERRORS:
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
            except (*PARSE_ERRORS, binascii.Error, UnicodeDecodeError):
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


def read_candidate(path: Path, max_size: int) -> bytes | None:
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
            data = read_candidate(path, config.max_file_size)
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
            asset = Asset(id=asset_id, kind=item.kind, location=location, details=item.details)
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
