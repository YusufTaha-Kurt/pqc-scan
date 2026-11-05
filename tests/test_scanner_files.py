from __future__ import annotations

import base64
import logging
import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa

from conftest import CryptoTree, cert_pem, make_cert, openssh_public, private_pem
from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import (
    AssetKind,
    Confidence,
    ErrorKind,
    Observation,
    Primitive,
    RiskClass,
    ScanConfig,
)
from pqc_scan.scanners.base import ScanTargetError
from pqc_scan.scanners.certs import public_key_observation, signature_observations, signer_name
from pqc_scan.scanners.files import FilesScanner, iter_files, ssh_key_algorithm

CONFIG = ScanConfig()


def scan(target: Path, config: ScanConfig = CONFIG) -> list[Observation]:
    return FilesScanner().scan(str(target), config)


def by_location(observations: list[Observation], location: str) -> dict[str, Observation]:
    """Observations of one file keyed by usage (fails on duplicate usages)."""
    found = [o for o in observations if o.asset.location == location]
    keyed = {o.usage: o for o in found}
    assert len(keyed) == len(found), f"duplicate usages in {location}"
    return keyed


@pytest.fixture(scope="module")
def observations(crypto_tree: CryptoTree) -> list[Observation]:
    return scan(crypto_tree.root)


# --- certificates ----------------------------------------------------------


def test_self_signed_rsa1024_certificate(observations: list[Observation]) -> None:
    obs = by_location(observations, "certs/rsa1024.pem")
    assert set(obs) == {
        "file.certificate.public_key",
        "file.certificate.signature",
        "file.certificate.signature_hash",
    }
    key = obs["file.certificate.public_key"]
    assert key.asset.kind == AssetKind.CERTIFICATE
    assert (key.algorithm.raw_name, key.algorithm.key_size) == ("RSA", 1024)
    signature = obs["file.certificate.signature"].algorithm
    # Self-signed: the signer's key size is known.
    assert (signature.raw_name, signature.key_size) == ("RSA", 1024)
    assert obs["file.certificate.signature_hash"].algorithm.raw_name == "sha256"
    assert key.evidence.line == 1
    assert key.scanner == "files"


def test_der_certificate(observations: list[Observation]) -> None:
    obs = by_location(observations, "certs/rsa2048.der")
    key = obs["file.certificate.public_key"]
    assert (key.algorithm.raw_name, key.algorithm.key_size) == ("RSA", 2048)
    assert key.evidence.detail == "DER certificate"
    assert key.evidence.line is None


def test_sha1_signed_certificate(observations: list[Observation]) -> None:
    obs = by_location(observations, "certs/rsa2048-sha1.crt")
    assert obs["file.certificate.signature_hash"].algorithm.raw_name == "sha1"


def test_ec_certificate_with_cer_extension(observations: list[Observation]) -> None:
    obs = by_location(observations, "certs/p384.cer")
    key = obs["file.certificate.public_key"].algorithm
    assert (key.raw_name, key.key_size, key.curve) == ("EC", 384, "secp384r1")
    signature = obs["file.certificate.signature"].algorithm
    assert (signature.raw_name, signature.key_size) == ("ECDSA", 384)
    assert obs["file.certificate.signature_hash"].algorithm.raw_name == "sha384"


def test_ed25519_certificate_has_no_hash(observations: list[Observation]) -> None:
    obs = by_location(observations, "certs/ed25519.pem")
    assert obs["file.certificate.public_key"].algorithm.raw_name == "Ed25519"
    assert obs["file.certificate.signature"].algorithm.raw_name == "Ed25519"
    assert "file.certificate.signature_hash" not in obs


def test_chain_gets_one_asset_per_block(observations: list[Observation]) -> None:
    found = [o for o in observations if o.asset.location == "certs/chain.pem"]
    ids = {o.asset.id for o in found}
    assert {i.rsplit("#", 1)[1] for i in ids} == {"block-1", "block-2"}  # block 3 is broken

    leaf = [o for o in found if o.asset.id.endswith("#block-1")]
    leaf_key = next(o for o in leaf if o.usage == "file.certificate.public_key")
    assert (leaf_key.algorithm.raw_name, leaf_key.algorithm.key_size) == ("EC", 256)
    leaf_sig = next(o for o in leaf if o.usage == "file.certificate.signature")
    # Signed by the CA: the signer's key size is not knowable from the leaf alone.
    assert (leaf_sig.algorithm.raw_name, leaf_sig.algorithm.key_size) == ("RSA", None)
    assert leaf_key.evidence.line == 2
    assert leaf_key.evidence.detail == "PEM block 1 (CERTIFICATE)"

    ca_key = next(
        o for o in found if o.asset.id.endswith("#block-2") and o.usage.endswith("public_key")
    )
    assert ca_key.algorithm.key_size == 4096


def test_csr(observations: list[Observation]) -> None:
    obs = by_location(observations, "certs/request.csr")
    key = obs["file.csr.public_key"]
    assert key.asset.kind == AssetKind.CERTIFICATE_REQUEST
    assert (key.algorithm.raw_name, key.algorithm.curve) == ("EC", "secp256r1")
    assert obs["file.csr.signature"].algorithm.raw_name == "ECDSA"
    assert obs["file.csr.signature"].algorithm.key_size == 256
    assert obs["file.csr.signature_hash"].algorithm.raw_name == "sha256"


# --- keys ------------------------------------------------------------------


def test_public_key(observations: list[Observation]) -> None:
    obs = by_location(observations, "keys/rsa4096.pub.pem")["file.public_key"]
    assert obs.asset.kind == AssetKind.PUBLIC_KEY
    assert (obs.algorithm.raw_name, obs.algorithm.key_size) == ("RSA", 4096)


@pytest.mark.parametrize(
    ("location", "name", "size", "confidence"),
    [
        ("keys/ec-p256.key", "EC", 256, Confidence.HIGH),
        ("keys/dsa.key", "DSA", 2048, Confidence.HIGH),
        ("keys/rsa.der", "RSA", 1024, Confidence.HIGH),
        ("keys/rsa-legacy-enc.key", "RSA", None, Confidence.MEDIUM),
        ("keys/pkcs8-enc.key", "encrypted private key", None, Confidence.LOW),
        ("ssh/id_ed25519", "Ed25519", None, Confidence.HIGH),
        ("ssh/id_rsa", "RSA", 2048, Confidence.HIGH),
    ],
)
def test_private_keys(
    observations: list[Observation],
    location: str,
    name: str,
    size: int | None,
    confidence: Confidence,
) -> None:
    obs = by_location(observations, location)["file.private_key"]
    assert obs.asset.kind == AssetKind.PRIVATE_KEY
    assert (obs.algorithm.raw_name, obs.algorithm.key_size) == (name, size)
    assert obs.confidence == confidence


def test_encrypted_openssh_key_is_marked(observations: list[Observation]) -> None:
    obs = by_location(observations, "ssh/id_rsa")["file.private_key"]
    assert "encrypted" in obs.evidence.detail
    plain = by_location(observations, "ssh/id_ed25519")["file.private_key"]
    assert "encrypted" not in plain.evidence.detail


# --- OpenSSH public keys -----------------------------------------------------


def test_pub_file(observations: list[Observation]) -> None:
    obs = by_location(observations, "ssh/id_ecdsa.pub")["file.ssh_public_key"]
    assert (obs.algorithm.raw_name, obs.algorithm.key_size, obs.algorithm.curve) == (
        "EC",
        384,
        "secp384r1",
    )
    # A single key in the file: no anchor in the asset id.
    assert "#" not in obs.asset.id


def test_authorized_keys_with_options(observations: list[Observation]) -> None:
    found = [o for o in observations if o.asset.location == "ssh/authorized_keys"]
    assert [(o.evidence.line, o.algorithm.raw_name, o.algorithm.key_size) for o in found] == [
        (3, "RSA", 4096),
        (4, "Ed25519", None),
    ]
    assert found[0].asset.id.endswith("#line-3")


def test_known_hosts(observations: list[Observation]) -> None:
    obs = by_location(observations, "ssh/known_hosts")["file.ssh_public_key"]
    assert obs.algorithm.curve == "secp256r1"


@pytest.mark.filterwarnings("ignore:SSH DSA key support is deprecated")
def test_ssh_dsa_and_unknown_types() -> None:
    # SSH only allows 1024-bit DSA keys.
    line = openssh_public(dsa.generate_private_key(key_size=1024))  # noqa: S505
    blob = base64.b64decode(line.split()[1])
    key_type, algorithm, confidence = ssh_key_algorithm(blob)
    assert (key_type, algorithm.raw_name, algorithm.key_size) == ("ssh-dss", "DSA", 1024)
    assert confidence == Confidence.HIGH

    unknown = b"\x00\x00\x00\x0bssh-unknown"
    key_type, algorithm, confidence = ssh_key_algorithm(unknown)
    assert (algorithm.raw_name, confidence) == ("ssh-unknown", Confidence.LOW)


def test_ssh_certificate_type(keys: dict[str, Any]) -> None:
    def string(value: bytes) -> bytes:
        return len(value).to_bytes(4, "big") + value

    numbers = keys["rsa2048"].public_key().public_numbers()
    blob = (
        string(b"ssh-rsa-cert-v01@openssh.com")
        + string(b"nonce")
        + string(numbers.e.to_bytes(3, "big"))
        + string(b"\x00" + numbers.n.to_bytes(256, "big"))
    )
    key_type, algorithm, _ = ssh_key_algorithm(blob)
    assert key_type == "ssh-rsa-cert-v01@openssh.com"
    assert (algorithm.raw_name, algorithm.key_size) == ("RSA", 2048)


def test_truncated_ssh_blob_raises() -> None:
    with pytest.raises(ValueError, match="truncated"):
        ssh_key_algorithm(b"\x00\x00\x00\xffssh-rsa")


# --- post-quantum keys ---------------------------------------------------------


def test_ml_dsa_and_ml_kem_keys(tmp_path: Path) -> None:
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    mlkem = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mlkem")
    pkcs8 = serialization.PrivateFormat.PKCS8
    (tmp_path / "mldsa.key").write_bytes(private_pem(mldsa.MLDSA65PrivateKey.generate(), pkcs8))
    public = mlkem.MLKEM768PrivateKey.generate().public_key()
    (tmp_path / "mlkem.pem").write_bytes(
        public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    names = {o.asset.location: o.algorithm.raw_name for o in scan(tmp_path)}
    assert names == {"mldsa.key": "ML-DSA-65", "mlkem.pem": "ML-KEM-768"}


# --- walking -----------------------------------------------------------------


def test_noise_is_ignored(observations: list[Observation]) -> None:
    locations = {o.asset.location for o in observations}
    assert not locations & {"broken.pem", "garbage.der", "notes.txt"}


def test_default_excludes_prune_directories(observations: list[Observation]) -> None:
    assert not any(o.asset.location.startswith("node_modules/") for o in observations)


def test_custom_exclude_pattern(crypto_tree: CryptoTree) -> None:
    found = scan(crypto_tree.root, ScanConfig(exclude=("ssh", "*.der")))
    locations = {o.asset.location for o in found}
    assert not any(loc.startswith("ssh/") or loc.endswith(".der") for loc in locations)
    assert any(loc.startswith("node_modules/") for loc in locations)


def test_symlinks_not_followed_by_default(observations: list[Observation]) -> None:
    assert not any(o.asset.location.startswith("linked/") for o in observations)


def test_symlinks_followed_when_enabled(crypto_tree: CryptoTree) -> None:
    found = scan(crypto_tree.root, ScanConfig(follow_symlinks=True))
    assert any(o.asset.location == "linked/outside.pem" for o in found)


def test_symlink_loop_terminates(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "loop").symlink_to(tmp_path, target_is_directory=True)
    files = list(iter_files(tmp_path, ScanConfig(follow_symlinks=True)))
    assert files == []


def test_symlinked_file_skipped_by_default(tmp_path: Path, keys: dict[str, Any]) -> None:
    real = tmp_path / "real.pem"
    real.write_bytes(cert_pem(make_cert(keys["p256"])))
    (tmp_path / "alias.pem").symlink_to(real)
    assert {o.asset.location for o in scan(tmp_path)} == {"real.pem"}


def test_max_file_size(crypto_tree: CryptoTree) -> None:
    found = scan(crypto_tree.root, ScanConfig(max_file_size=100))
    assert found == []


def test_single_file_target(crypto_tree: CryptoTree) -> None:
    found = scan(crypto_tree.root / "certs" / "rsa1024.pem")
    assert {o.asset.location for o in found} == {"rsa1024.pem"}
    assert found[0].asset.id == (crypto_tree.root / "certs" / "rsa1024.pem").absolute().as_uri()


def test_missing_target() -> None:
    with pytest.raises(ScanTargetError) as info:
        scan(Path("/nonexistent/pqc-scan/path"))
    assert info.value.kind == ErrorKind.INVALID_TARGET


def test_fifo_is_skipped(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe.pem")
    assert scan(tmp_path) == []


def test_observations_are_deterministic(crypto_tree: CryptoTree) -> None:
    first = [o.fingerprint() for o in scan(crypto_tree.root)]
    second = [o.fingerprint() for o in scan(crypto_tree.root)]
    assert first == second


# --- end to end with the classifier ------------------------------------------


def test_classified_risks(crypto_tree: CryptoTree) -> None:
    result = run_scan([ScanJob(FilesScanner(), str(crypto_tree.root))], CONFIG)
    assert result.errors == []
    risk = {(f.asset.location, f.usage): f.risk for f in result.findings if "#" not in f.asset.id}
    assert risk[("certs/rsa1024.pem", "file.certificate.public_key")] == RiskClass.BROKEN
    assert risk[("certs/rsa1024.pem", "file.certificate.signature")] == RiskClass.BROKEN
    assert risk[("certs/rsa2048.der", "file.certificate.public_key")] == RiskClass.VULNERABLE
    assert risk[("certs/rsa2048-sha1.crt", "file.certificate.signature_hash")] == RiskClass.BROKEN
    assert risk[("certs/ed25519.pem", "file.certificate.public_key")] == RiskClass.VULNERABLE
    assert risk[("certs/rsa1024.pem", "file.certificate.signature_hash")] == RiskClass.PQ_SAFE
    assert risk[("keys/pkcs8-enc.key", "file.private_key")] == RiskClass.UNKNOWN


def test_missing_target_becomes_scan_error() -> None:
    result = run_scan([ScanJob(FilesScanner(), "/nonexistent/pqc-scan")], CONFIG)
    assert result.findings == []
    assert [e.kind for e in result.errors] == [ErrorKind.INVALID_TARGET]


# --- T-135: private key material never leaks ---------------------------------


def test_private_key_material_never_appears_in_output(
    crypto_tree: CryptoTree, caplog: pytest.LogCaptureFixture
) -> None:
    assert len(crypto_tree.secret_lines) > 20  # the fixture really wrote secrets
    with caplog.at_level(logging.DEBUG):
        result = run_scan([ScanJob(FilesScanner(), str(crypto_tree.root))], CONFIG)
    output = result.model_dump_json() + caplog.text
    leaked = [line for line in crypto_tree.secret_lines if line.decode() in output]
    assert leaked == []
    # The DER private key is binary; check its base64 form too.
    der = (crypto_tree.root / "keys" / "rsa.der").read_bytes()
    assert base64.b64encode(der)[:40].decode() not in output
    assert "BEGIN" not in output


# --- edge cases ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("oid", "name"),
    [
        ("1.2.840.113549.1.1.5", "RSA"),
        ("1.2.840.113549.1.1.10", "RSA-PSS"),
        ("1.3.14.3.2.29", "RSA"),
        ("1.2.840.10045.4.1", "ECDSA"),
        ("1.2.840.10045.4.3.2", "ECDSA"),
        ("1.2.840.10040.4.3", "DSA"),
        ("1.3.101.112", "Ed25519"),
        ("1.3.101.113", "Ed448"),
        ("2.16.840.1.101.3.4.3.2", "DSA"),
        ("2.16.840.1.101.3.4.3.10", "ECDSA"),
        ("2.16.840.1.101.3.4.3.14", "RSA"),
        ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
        ("2.16.840.1.101.3.4.3.20", "SLH-DSA"),
        ("2.16.840.1.101.3.4.3.99", None),
        ("1.2.3.4", None),
    ],
)
def test_signature_oids(oid: str, name: str | None) -> None:
    assert signer_name(oid) == name


def test_unknown_signature_oid_is_reported_raw() -> None:
    (obs,) = signature_observations("file.certificate", "1.2.3.4", None, None)
    assert obs[0] == "file.certificate.signature"
    assert obs[1].raw_name == "1.2.3.4"
    assert obs[2] == Confidence.MEDIUM


def test_unloadable_public_key_falls_back_to_oid() -> None:
    def unsupported() -> object:
        raise UnsupportedAlgorithm("not in this version")

    usage = "file.certificate.public_key"
    known = public_key_observation(unsupported, "2.16.840.1.101.3.4.4.2", usage)
    assert known is not None
    assert (known[1].raw_name, known[1].primitive, known[2]) == (
        "ML-KEM-768",
        Primitive.KEM,
        Confidence.MEDIUM,
    )
    unknown = public_key_observation(unsupported, "1.2.3.4", usage)
    assert unknown is not None
    assert unknown[1].raw_name == "1.2.3.4"
    assert public_key_observation(unsupported, None, usage) is None


def test_ml_dsa_certificate(tmp_path: Path) -> None:
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    (tmp_path / "pq.pem").write_bytes(cert_pem(make_cert(mldsa.MLDSA87PrivateKey.generate())))
    obs = by_location(scan(tmp_path), "pq.pem")
    assert obs["file.certificate.public_key"].algorithm.raw_name == "ML-DSA-87"
    assert obs["file.certificate.signature"].algorithm.raw_name == "ML-DSA-87"
    assert "file.certificate.signature_hash" not in obs


def _ssh_blob(*parts: bytes) -> bytes:
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


@pytest.mark.parametrize(
    ("blob", "name", "curve"),
    [
        (_ssh_blob(b"ssh-ed448", b"k" * 57), "Ed448", None),
        (_ssh_blob(b"sk-ssh-ed25519@openssh.com", b"k" * 32, b"ssh:"), "Ed25519", None),
        (
            _ssh_blob(b"sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256", b"Q", b"ssh:"),
            "EC",
            "secp256r1",
        ),
        (_ssh_blob(b"ecdsa-sha2-nistp999", b"nistp999", b"Q"), "ecdsa-sha2-nistp999", None),
    ],
)
def test_other_ssh_key_types(blob: bytes, name: str, curve: str | None) -> None:
    _, algorithm, _ = ssh_key_algorithm(blob)
    assert (algorithm.raw_name, algorithm.curve) == (name, curve)


def test_malformed_ssh_and_openssh_inputs_are_skipped(tmp_path: Path) -> None:
    rsa_blob = _ssh_blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + b"\xff" * 256)
    mismatched = b"ssh-ed25519 " + base64.b64encode(rsa_blob) + b"\n"
    (tmp_path / "mismatch.pub").write_bytes(mismatched)

    def openssh_pem(der: bytes) -> bytes:
        body = base64.b64encode(der)
        return (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + body
            + b"\n-----END OPENSSH PRIVATE KEY-----\n"
        )

    zero_keys = b"openssh-key-v1\x00" + _ssh_blob(b"none", b"none", b"") + b"\x00\x00\x00\x00"
    (tmp_path / "bad_magic").write_bytes(openssh_pem(b"not-openssh"))
    (tmp_path / "zero_keys").write_bytes(openssh_pem(zero_keys))
    (tmp_path / "unknown.pem").write_bytes(
        b"-----BEGIN PGP THING-----\nAAAA\n-----END PGP THING-----\n"
    )
    assert scan(tmp_path) == []


def test_fifo_target_is_invalid(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(ScanTargetError) as info:
        scan(tmp_path / "pipe")
    assert info.value.kind == ErrorKind.INVALID_TARGET
