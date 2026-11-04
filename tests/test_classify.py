from pathlib import Path

import pytest

from pqc_scan.classify import (
    Classifier,
    RuleSetError,
    classify,
    default_classifier,
    load_ruleset,
    normalize_name,
)
from pqc_scan.models import Algorithm, Primitive, RiskClass

P = Primitive


def risk(name: str, primitive: Primitive, key_size: int | None = None) -> RiskClass:
    return classify(Algorithm(raw_name=name, primitive=primitive, key_size=key_size)).risk


# --- examples from CLAUDE.md section 3 ---------------------------------


@pytest.mark.parametrize(
    ("name", "primitive", "key_size"),
    [
        ("RSA", P.SIGNATURE, 2048),
        ("RSA", P.SIGNATURE, 4096),
        ("ECDSA", P.SIGNATURE, 256),
        ("ECDH", P.KEY_EXCHANGE, 256),
        ("Ed25519", P.SIGNATURE, None),
        ("X25519", P.KEY_EXCHANGE, None),
        ("DH", P.KEY_EXCHANGE, 2048),
        ("DSA", P.SIGNATURE, 2048),
    ],
)
def test_vulnerable(name: str, primitive: Primitive, key_size: int | None) -> None:
    assert risk(name, primitive, key_size) is RiskClass.VULNERABLE


@pytest.mark.parametrize(
    ("name", "primitive", "key_size"),
    [
        ("AES-128", P.BLOCK_CIPHER, None),
        ("AES_128_GCM", P.AEAD, None),
        ("AES", P.BLOCK_CIPHER, 128),
        ("SHA-224", P.HASH, None),
    ],
)
def test_weakened(name: str, primitive: Primitive, key_size: int | None) -> None:
    assert risk(name, primitive, key_size) is RiskClass.WEAKENED


@pytest.mark.parametrize(
    "name",
    [
        "X25519MLKEM768",
        "mlkem768x25519-sha256",
        "SecP256r1MLKEM768",
        "sntrup761x25519-sha512@openssh.com",
    ],
)
def test_hybrid(name: str) -> None:
    assert risk(name, P.KEY_EXCHANGE) is RiskClass.HYBRID


@pytest.mark.parametrize(
    ("name", "primitive", "key_size"),
    [
        ("ML-KEM-768", P.KEM, None),
        ("ML-DSA-65", P.SIGNATURE, None),
        ("SLH-DSA", P.SIGNATURE, None),
        ("AES-256", P.BLOCK_CIPHER, None),
        ("AES", P.AEAD, 256),
        ("SHA-256", P.HASH, None),
        ("SHA-384", P.HASH, None),
        ("SHA512", P.HASH, None),
        ("SHA3-256", P.HASH, None),
        ("chacha20-poly1305@openssh.com", P.AEAD, None),
    ],
)
def test_pq_safe(name: str, primitive: Primitive, key_size: int | None) -> None:
    assert risk(name, primitive, key_size) is RiskClass.PQ_SAFE


@pytest.mark.parametrize(
    ("name", "primitive", "key_size"),
    [
        ("MD5", P.HASH, None),
        ("SHA-1", P.HASH, None),
        ("RC4", P.STREAM_CIPHER, None),
        ("3DES", P.BLOCK_CIPHER, None),
        ("DES-EDE3-CBC", P.BLOCK_CIPHER, None),
        ("TLSv1", P.PROTOCOL, None),
        ("TLS 1.1", P.PROTOCOL, None),
        ("SSLv3", P.PROTOCOL, None),
        ("RSA", P.SIGNATURE, 1024),
        ("ssh-rsa", P.SIGNATURE, None),
        ("ssh-dss", P.SIGNATURE, None),
        ("ECB", P.BLOCK_CIPHER, None),
    ],
)
def test_broken(name: str, primitive: Primitive, key_size: int | None) -> None:
    assert risk(name, primitive, key_size) is RiskClass.BROKEN


# --- rule semantics -----------------------------------------------------


@pytest.mark.parametrize(
    ("key_size", "expected"),
    [
        (1024, RiskClass.BROKEN),
        (2047, RiskClass.BROKEN),
        (2048, RiskClass.VULNERABLE),
        (None, RiskClass.VULNERABLE),
    ],
)
def test_rsa_key_size_boundary(key_size: int | None, expected: RiskClass) -> None:
    assert risk("rsaEncryption", P.PUBLIC_KEY_ENCRYPTION, key_size) is expected


def test_small_curves_are_broken() -> None:
    assert risk("secp192r1", P.KEY_EXCHANGE, 192) is RiskClass.BROKEN
    assert risk("P-224", P.KEY_EXCHANGE, 224) is RiskClass.VULNERABLE


def test_primitive_context_changes_classification() -> None:
    assert risk("SHA1", P.HASH) is RiskClass.BROKEN
    assert risk("hmac-sha1", P.MAC) is RiskClass.WEAKENED


def test_aes_without_key_size_is_unknown() -> None:
    result = classify(Algorithm(raw_name="AES", primitive=P.BLOCK_CIPHER))
    assert result.risk is RiskClass.UNKNOWN
    assert result.algorithm_id == "aes"
    assert "key size" in result.reason


def test_unknown_algorithm() -> None:
    result = classify(Algorithm(raw_name="FancyCipher9000", primitive=P.BLOCK_CIPHER))
    assert result.risk is RiskClass.UNKNOWN
    assert result.algorithm_id is None
    assert "FancyCipher9000" in result.reason


def test_classification_carries_reason_and_recommendation() -> None:
    result = classify(Algorithm(raw_name="RSA", primitive=P.SIGNATURE, key_size=1024))
    assert result.algorithm_id == "rsa"
    assert "2048" in result.reason
    assert result.recommendation is not None
    assert "ML-DSA" in result.recommendation


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("SHA-256", "sha256"),
        ("sha_256", "sha256"),
        ("TLS 1.3", "tls13"),
        ("aes128-gcm@openssh.com", "aes128gcmopensshcom"),
    ],
)
def test_normalize_name(raw: str, expected: str) -> None:
    assert normalize_name(raw) == expected


def test_lookup_is_spelling_insensitive() -> None:
    c = default_classifier()
    entry = c.lookup("Sha-256")
    assert entry is not None
    assert entry is c.lookup("SHA256")


# --- packaged rule file -------------------------------------------------


def test_packaged_ruleset_is_valid() -> None:
    ruleset = load_ruleset()
    assert ruleset.schema_version == 1
    assert len(ruleset.algorithms) > 40
    Classifier(ruleset)  # raises on duplicate ids or alias collisions


def test_every_entry_lists_its_rule_primitives() -> None:
    for entry in load_ruleset().algorithms:
        for rule in entry.rules:
            for primitive in rule.when.primitive or []:
                assert primitive in entry.primitives, entry.id


# --- invalid rule files -------------------------------------------------


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


ENTRY = """
  - id: {id}
    name: X
    aliases: [{alias}]
    primitives: [hash]
    default: BROKEN
    reason: r
"""


def test_custom_rule_file(tmp_path: Path) -> None:
    path = _write(tmp_path, "schema_version: 1\nalgorithms:" + ENTRY.format(id="x", alias="Foo"))
    c = Classifier.from_file(path)
    assert c.classify(Algorithm(raw_name="foo", primitive=P.HASH)).risk is RiskClass.BROKEN


def test_alias_collision_is_rejected(tmp_path: Path) -> None:
    text = (
        "schema_version: 1\nalgorithms:"
        + ENTRY.format(id="a", alias="SHA-1")
        + ENTRY.format(id="b", alias="sha1")
    )
    with pytest.raises(RuleSetError, match="collides"):
        Classifier.from_file(_write(tmp_path, text))


def test_duplicate_id_is_rejected(tmp_path: Path) -> None:
    text = (
        "schema_version: 1\nalgorithms:"
        + ENTRY.format(id="a", alias="x")
        + ENTRY.format(id="a", alias="y")
    )
    with pytest.raises(RuleSetError, match="duplicate"):
        Classifier.from_file(_write(tmp_path, text))


def test_empty_alias_is_rejected(tmp_path: Path) -> None:
    text = "schema_version: 1\nalgorithms:" + ENTRY.format(id="a", alias="'--'")
    with pytest.raises(RuleSetError, match="empty"):
        Classifier.from_file(_write(tmp_path, text))


@pytest.mark.parametrize(
    "text",
    [
        "schema_version: 1\nalgorithms: [ {",  # invalid YAML
        "schema_version: 2\nalgorithms: []",  # unsupported version
        "schema_version: 1\nalgorithms:"
        + ENTRY.format(id="a", alias="x").replace("BROKEN", "MAYBE"),  # unknown risk class
        "schema_version: 1\nalgorithms:"
        + ENTRY.format(id="a", alias="x")
        + "    rules:\n      - when: {}\n        risk: BROKEN\n        reason: r\n",  # empty when
    ],
)
def test_invalid_rule_files(tmp_path: Path, text: str) -> None:
    with pytest.raises(RuleSetError):
        load_ruleset(_write(tmp_path, text))


def test_missing_rule_file(tmp_path: Path) -> None:
    with pytest.raises(RuleSetError, match="cannot read"):
        load_ruleset(tmp_path / "missing.yaml")
