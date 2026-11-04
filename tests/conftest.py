"""Shared fixtures.

Keys and certificates are generated while the tests run and written to a
temporary directory. No private key is ever committed to the repository
(that would trip GitHub secret scanning, and it is bad practice anyway).
"""

from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import NameOID

PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
NO_ENCRYPTION = serialization.NoEncryption()
PASSPHRASE = b"correct horse battery staple"


def make_cert(
    key: Any,
    *,
    cn: str = "pqc-scan test",
    issuer_key: Any = None,
    issuer_cn: str | None = None,
    hash_algorithm: hashes.HashAlgorithm | None = None,
) -> x509.Certificate:
    """A certificate for ``key``; self-signed unless ``issuer_key`` is given."""
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    signer = issuer_key if issuer_key is not None else key
    needs_hash = (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, dsa.DSAPrivateKey)
    if hash_algorithm is None and isinstance(signer, needs_hash):
        hash_algorithm = hashes.SHA256()
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(signer, hash_algorithm)
    )


_SHA256_WITH_RSA = bytes.fromhex("06092a864886f70d01010b")
_SHA1_WITH_RSA = bytes.fromhex("06092a864886f70d010105")


def with_sha1_signature_oid(cert: x509.Certificate) -> x509.Certificate:
    """The same certificate, relabelled as sha1WithRSAEncryption.

    OpenSSL refuses to create SHA-1 signatures, so we patch the algorithm OID
    instead. The signature no longer verifies, which the scanner tolerates.
    """
    der = cert.public_bytes(DER)
    assert der.count(_SHA256_WITH_RSA) == 2  # tbsCertificate + outer signature
    return x509.load_der_x509_certificate(der.replace(_SHA256_WITH_RSA, _SHA1_WITH_RSA))


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(PEM)


def private_pem(
    key: Any, fmt: serialization.PrivateFormat, encryption: Any = NO_ENCRYPTION
) -> bytes:
    return bytes(key.private_bytes(PEM, fmt, encryption))


def openssh_public(key: Any, comment: str = "user@example") -> bytes:
    line = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    return bytes(line) + b" " + comment.encode()


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def encrypted_openssh_private(key: Any) -> bytes:
    """An ``openssh-key-v1`` container that looks passphrase-protected.

    ``cryptography`` needs the optional ``bcrypt`` module to encrypt OpenSSH
    keys, so we build the container by hand: the real public part, a bcrypt
    KDF header and random bytes in place of the encrypted private section.
    The scanner must report type and size without touching the secret part.
    """
    pem = private_pem(key, serialization.PrivateFormat.OpenSSH)
    body = b"".join(pem.splitlines()[1:-1])
    der = base64.b64decode(body)
    magic = b"openssh-key-v1\x00"
    pos = len(magic)
    fields = []
    for _ in range(3):  # cipher, kdf, kdf options
        (length,) = struct.unpack_from(">I", der, pos)
        fields.append(der[pos + 4 : pos + 4 + length])
        pos += 4 + length
    pos += 4  # number of keys
    (length,) = struct.unpack_from(">I", der, pos)
    public_blob = der[pos + 4 : pos + 4 + length]
    rebuilt = (
        magic
        + _ssh_string(b"aes256-ctr")
        + _ssh_string(b"bcrypt")
        + _ssh_string(_ssh_string(os.urandom(16)) + struct.pack(">I", 16))
        + struct.pack(">I", 1)
        + _ssh_string(public_blob)
        + _ssh_string(os.urandom(160))
    )
    encoded = base64.b64encode(rebuilt)
    lines = [encoded[i : i + 70] for i in range(0, len(encoded), 70)]
    return b"\n".join(
        [b"-----BEGIN OPENSSH PRIVATE KEY-----", *lines, b"-----END OPENSSH PRIVATE KEY-----", b""]
    )


def pem_body(pem: bytes) -> list[bytes]:
    """Base64 lines between the BEGIN/END markers (no headers)."""
    return [
        line
        for line in pem.splitlines()
        if line and not line.startswith(b"-----") and b":" not in line
    ]


@dataclass
class CryptoTree:
    """A directory full of generated certificates and keys."""

    root: Path
    outside: Path
    # Base64 lines of every private key written into ``root``.
    secret_lines: list[bytes] = field(default_factory=list)

    def write(self, relative: str, content: bytes, *, secret: bool = False) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        if secret:
            self.secret_lines += pem_body(content)
        return path


@pytest.fixture(scope="session")
def keys() -> dict[str, Any]:
    """Private keys reused across tests (RSA generation is slow)."""
    return {
        "rsa1024": rsa.generate_private_key(public_exponent=65537, key_size=1024),  # noqa: S505
        "rsa2048": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "rsa4096": rsa.generate_private_key(public_exponent=65537, key_size=4096),
        "p256": ec.generate_private_key(ec.SECP256R1()),
        "p384": ec.generate_private_key(ec.SECP384R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
        "dsa2048": dsa.generate_private_key(key_size=2048),
    }


@pytest.fixture(scope="session")
def crypto_tree(tmp_path_factory: pytest.TempPathFactory, keys: dict[str, Any]) -> CryptoTree:
    base = tmp_path_factory.mktemp("crypto")
    tree = CryptoTree(root=base / "repo", outside=base / "outside")
    tree.root.mkdir()
    tree.outside.mkdir()
    k = keys
    pkcs8 = serialization.PrivateFormat.PKCS8
    traditional = serialization.PrivateFormat.TraditionalOpenSSL
    openssh = serialization.PrivateFormat.OpenSSH
    encrypt = serialization.BestAvailableEncryption(PASSPHRASE)

    # Certificates
    tree.write("certs/rsa1024.pem", cert_pem(make_cert(k["rsa1024"])))
    tree.write("certs/rsa2048.der", make_cert(k["rsa2048"]).public_bytes(DER))
    tree.write(
        "certs/rsa2048-sha1.crt",
        cert_pem(with_sha1_signature_oid(make_cert(k["rsa2048"]))),
    )
    tree.write(
        "certs/p384.cer", make_cert(k["p384"], hash_algorithm=hashes.SHA384()).public_bytes(DER)
    )
    tree.write("certs/ed25519.pem", cert_pem(make_cert(k["ed25519"])))
    ca = make_cert(k["rsa4096"], cn="Test CA")
    leaf = make_cert(k["p256"], cn="leaf", issuer_key=k["rsa4096"], issuer_cn="Test CA")
    tree.write(
        "certs/chain.pem",
        b"leaf first, then the CA\n"
        + cert_pem(leaf)
        + cert_pem(ca)
        + b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n",
    )

    # CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr")]))
        .sign(k["p256"], hashes.SHA256())
    )
    tree.write("certs/request.csr", csr.public_bytes(PEM))

    # Public and private keys
    tree.write(
        "keys/rsa4096.pub.pem",
        k["rsa4096"]
        .public_key()
        .public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    )
    tree.write("keys/ec-p256.key", private_pem(k["p256"], pkcs8), secret=True)
    tree.write("keys/dsa.key", private_pem(k["dsa2048"], traditional), secret=True)
    tree.write(
        "keys/rsa-legacy-enc.key", private_pem(k["rsa2048"], traditional, encrypt), secret=True
    )
    tree.write("keys/pkcs8-enc.key", private_pem(k["p384"], pkcs8, encrypt), secret=True)
    tree.write("keys/rsa.der", k["rsa1024"].private_bytes(DER, pkcs8, NO_ENCRYPTION))

    # OpenSSH
    tree.write("ssh/id_ed25519", private_pem(k["ed25519"], openssh), secret=True)
    tree.write("ssh/id_rsa", encrypted_openssh_private(k["rsa2048"]), secret=True)
    tree.write("ssh/id_ecdsa.pub", openssh_public(k["p384"]))
    tree.write(
        "ssh/authorized_keys",
        b"# comment line\n\n"
        + b'from="10.0.0.1",no-pty '
        + openssh_public(k["rsa4096"])
        + b"\n"
        + openssh_public(k["ed25519"])
        + b"\n"
        + b"ssh-rsa not-base64!! broken\n",
    )
    tree.write(
        "ssh/known_hosts",
        b"example.com,192.0.2.1 " + openssh_public(k["p256"], comment="") + b"\n",
    )

    # Noise that must be ignored
    tree.write("broken.pem", b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n")
    tree.write("garbage.der", b"\x00\x01 not der")
    tree.write("notes.txt", b"nothing to see here\n")
    tree.write("node_modules/dep/cert.pem", cert_pem(make_cert(k["rsa1024"])))

    # A symlink to a directory outside the tree
    (tree.outside / "outside.pem").write_bytes(cert_pem(make_cert(k["rsa1024"])))
    (tree.root / "linked").symlink_to(tree.outside, target_is_directory=True)
    return tree
