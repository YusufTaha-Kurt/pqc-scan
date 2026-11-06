from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import AssetKind, Confidence, ErrorKind, Primitive, RiskClass, ScanConfig
from pqc_scan.scanners.base import ScanTargetError
from pqc_scan.scanners.code import CodeScanner, pattern_hits, python_hits, strip_comments
from pqc_scan.scanners.code_rules import (
    CodeRuleError,
    Language,
    Transform,
    default_rules,
    expand,
    normalize_curve,
    parse_rules,
)

FIXTURES = Path(__file__).parent / "fixtures" / "code"
RULES = default_rules()


@pytest.fixture(scope="module")
def findings() -> dict[str, set[tuple[int, str, int | None, str | None, RiskClass]]]:
    result = run_scan([ScanJob(CodeScanner(), str(FIXTURES))], ScanConfig())
    assert result.errors == []
    table: dict[str, set[tuple[int, str, int | None, str | None, RiskClass]]] = {}
    for f in result.findings:
        assert f.asset.kind == AssetKind.SOURCE_FILE
        assert f.usage.startswith("code.")
        a = f.algorithm
        table.setdefault(f.asset.location, set()).add(
            (f.evidence.line or 0, a.raw_name, a.key_size, a.curve, f.risk)
        )
    return table


B, V, W, H, S, U = (
    RiskClass.BROKEN,
    RiskClass.VULNERABLE,
    RiskClass.WEAKENED,
    RiskClass.HYBRID,
    RiskClass.PQ_SAFE,
    RiskClass.UNKNOWN,
)


def test_python_findings(
    findings: dict[str, set[tuple[int, str, int | None, str | None, RiskClass]]],
) -> None:
    assert findings["sample_crypto.py"] == {
        (18, "RSA", 1024, None, B),
        (19, "RSA", None, None, V),  # key size is a variable
        (20, "EC", 384, "secp384r1", V),
        (21, "Ed25519", None, None, V),
        (22, "SHA1", None, None, B),
        (23, "ECB", None, None, B),
        (24, "MD5", None, None, B),  # `from hashlib import md5 as legacy_md5`
        (25, "sha224", None, None, W),
        (27, "HMAC-SHA1", None, None, W),
        (28, "HMAC-SHA256", None, None, S),
        (29, "TLSv1.0", None, None, B),
        (30, "TLSv1.1", None, None, B),
        (31, "RSA", 2048, None, V),  # pycryptodome
        (32, "ECB", None, None, B),  # AES.MODE_ECB
        (33, "3DES", None, None, B),
        (34, "HMAC-SHA256", None, None, S),  # JWT HS256
    }


def test_java_findings(
    findings: dict[str, set[tuple[int, str, int | None, str | None, RiskClass]]],
) -> None:
    assert findings["Sample.java"] == {
        (9, "RSA", 1024, None, B),  # size from kpg.initialize(1024) on the next line
        (11, "EC", None, None, V),
        (12, "EC", 256, "secp256r1", V),
        (13, "RSA", None, None, V),
        (13, "SHA1", None, None, B),
        (14, "AES", None, None, U),
        (14, "ECB", None, None, B),
        (15, "AES", None, None, U),  # GCM, but key size unknown
        (16, "DESede", None, None, B),
        (16, "ECB", None, None, B),  # a bare cipher name defaults to ECB in Java
        (17, "MD5", None, None, B),
        (18, "ECDH", None, None, V),
        (21, "AES", 128, None, W),
        (23, "TLSv1.1", None, None, B),
        (25, "ML-KEM-768", None, None, S),
    }


def test_javascript_findings(
    findings: dict[str, set[tuple[int, str, int | None, str | None, RiskClass]]],
) -> None:
    assert findings["sample.js"] == {
        (5, "rsa", 2048, None, V),
        (8, "ec", 384, "secp384r1", V),
        (9, "md5", None, None, B),
        (10, "HMAC-SHA1", None, None, W),
        (11, "aes-128", None, None, W),
        (11, "ECB", None, None, B),
        (12, "aes-256", None, None, S),
        (13, "ECDH", 256, "secp256r1", V),
        (14, "RSA", None, None, V),
        (14, "SHA256", None, None, S),
        (15, "RSA", 1024, None, B),
        (17, "TLSv1", None, None, B),
    }
    assert findings["sample.ts"] == {
        (2, "RSA-PSS", 3072, None, V),
        (7, "AES", 128, None, W),
        (8, "ECDSA", 256, "secp256r1", V),
    }


def test_go_findings(
    findings: dict[str, set[tuple[int, str, int | None, str | None, RiskClass]]],
) -> None:
    assert findings["sample.go"] == {
        (14, "RSA", 1024, None, B),
        (15, "ECDSA", 256, "secp256r1", V),
        (16, "MD5", None, None, B),
        (17, "X25519", None, None, V),
        (19, "TLSv1.0", None, None, B),
        (20, "X25519MLKEM768", None, None, H),
        (20, "ECDH", 256, "secp256r1", V),
    }


def test_broken_python_file_is_skipped(
    findings: dict[str, set[tuple[int, str, int | None, str | None, RiskClass]]],
) -> None:
    assert "broken_syntax.py" not in findings


def test_source_lines_never_appear_in_output() -> None:
    result = run_scan([ScanJob(CodeScanner(), str(FIXTURES))], ScanConfig())
    text = result.model_dump_json()
    for fragment in ("public_exponent=65537", "PKCS5Padding", "modulusLength", "rand.Reader"):
        assert fragment not in text
    details = {f.evidence.detail for f in result.findings}
    assert "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key" in details
    assert "Cipher.getInstance" in details


def test_non_literal_key_size_lowers_confidence() -> None:
    hits = python_hits(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(65537, BITS)\n",
        RULES,
    )
    assert [(h[2].raw_name, h[2].key_size, h[4]) for h in hits] == [
        ("RSA", None, Confidence.MEDIUM)
    ]


def test_local_variables_are_not_mistaken_for_apis() -> None:
    source = "import hmac\nalgo = pick()\nhmac.new(b'k', b'm', algo)\n"
    assert python_hits(source, RULES) == []


def test_cryptodome_namespace_and_import_forms() -> None:
    source = (
        "import Cryptodome.Hash.MD5\nimport hashlib as h\nCryptodome.Hash.MD5.new()\nh.sha1()\n"
    )
    assert [h[2].raw_name for h in python_hits(source, RULES)] == ["MD5", "SHA1"]


def test_strip_comments_keeps_strings_and_lines() -> None:
    source = "a = \"// not a comment\"; // gone\n/* multi\nline */ b = '/* kept */';\nc = `x`"
    stripped = strip_comments(source)
    assert "// not a comment" in stripped and "gone" not in stripped
    assert "multi" not in stripped and "/* kept */" in stripped
    assert stripped.count("\n") == source.count("\n")
    assert strip_comments('s = "esc\\"aped // still string"') == 's = "esc\\"aped // still string"'


def test_pattern_hits_language_filter() -> None:
    assert pattern_hits('MessageDigest.getInstance("MD5")', Language.GO, RULES) == []
    (hit,) = pattern_hits('MessageDigest.getInstance("MD5")', Language.JAVA, RULES)
    assert hit[2].raw_name == "MD5"


@pytest.mark.parametrize(
    ("transform", "value", "expected"),
    [
        (
            Transform.JCA_SIGNATURE,
            "SHA256withECDSA",
            [("ECDSA", Primitive.SIGNATURE), ("SHA256", Primitive.HASH)],
        ),
        (
            Transform.JCA_SIGNATURE,
            "SHA256withRSAandMGF1",
            [("RSA-PSS", Primitive.SIGNATURE), ("SHA256", Primitive.HASH)],
        ),
        (Transform.JCA_SIGNATURE, "NONEwithRSA", [("RSA", Primitive.SIGNATURE)]),
        (Transform.JCA_SIGNATURE, "Ed25519", [("Ed25519", Primitive.SIGNATURE)]),
        (Transform.JCA_CIPHER, "RSA/ECB/OAEPPadding", [("RSA", Primitive.PUBLIC_KEY_ENCRYPTION)]),
        (
            Transform.JCA_CIPHER,
            "ChaCha20-Poly1305",
            [("ChaCha20-Poly1305", Primitive.BLOCK_CIPHER)],
        ),
        (Transform.OPENSSL_CIPHER, "des-ede3-cbc", [("des-ede3", Primitive.BLOCK_CIPHER)]),
        (Transform.OPENSSL_CIPHER, "rc4", [("rc4", Primitive.BLOCK_CIPHER)]),
        (Transform.JWT, "ES384", [("ECDSA", Primitive.SIGNATURE), ("SHA384", Primitive.HASH)]),
        (Transform.JWT, "PS512", [("RSA-PSS", Primitive.SIGNATURE), ("SHA512", Primitive.HASH)]),
        (Transform.JWT, "EdDSA", [("Ed25519", Primitive.SIGNATURE)]),
        (Transform.JWT, "none", [("NULL", Primitive.SIGNATURE)]),
        (Transform.JWT, "XX999", [("XX999", Primitive.SIGNATURE)]),
        (Transform.HMAC, "sha-256", [("HMAC-SHA256", Primitive.MAC)]),
        (Transform.TLS_VERSION, "SSLv3_method", [("SSLv3", Primitive.PROTOCOL)]),
        (Transform.TLS_VERSION, "SSL30", [("SSLv3", Primitive.PROTOCOL)]),
        (Transform.WEBCRYPTO, "RSA-OAEP", [("RSA-OAEP", Primitive.PUBLIC_KEY_ENCRYPTION)]),
        (Transform.WEBCRYPTO, "X25519", [("X25519", Primitive.KEY_EXCHANGE)]),
        (Transform.NONE, "DiffieHellman", [("DiffieHellman", Primitive.KEY_EXCHANGE)]),
        (Transform.NONE, "Kyber768", [("Kyber768", Primitive.KEM)]),
    ],
)
def test_transforms(
    transform: Transform, value: str, expected: list[tuple[str, Primitive]]
) -> None:
    assert expand(transform, value, Primitive.BLOCK_CIPHER) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("P-256", ("secp256r1", 256)),
        ("prime256v1", ("secp256r1", 256)),
        ("SECP521R1", ("secp521r1", 521)),
        ("P224", ("secp224r1", 224)),
        ("curve-unknown", None),
    ],
)
def test_normalize_curve(text: str, expected: tuple[str, int] | None) -> None:
    assert normalize_curve(text) == expected


def test_every_rule_algorithm_is_known_to_the_classifier() -> None:
    from pqc_scan.classify import default_classifier

    classifier = default_classifier()
    fixed = [r.algorithm for r in (*RULES.python_calls, *RULES.python_attributes, *RULES.patterns)]
    for name in filter(None, fixed):
        assert classifier.lookup(name) is not None, name


@pytest.mark.parametrize(
    "text",
    [
        "schema_version: 2\npython_calls: []\npython_attributes: []\npatterns: []",
        "schema_version: 1\npython_calls: [{call: a.b, primitive: hash, usage: hash}]\n"
        "python_attributes: []\npatterns: []",
        "schema_version: 1\npython_calls: []\npython_attributes: []\n"
        "patterns: [{id: x, languages: [go], regex: '(', api: a, algorithm: MD5,"
        " primitive: hash, usage: hash}]",
        "schema_version: 1\npython_calls: []\npython_attributes: []\n"
        "patterns: [{id: x, languages: [go], regex: 'a', api: a, primitive: hash, usage: hash}]",
        "{not yaml",
    ],
)
def test_invalid_rule_files(text: str) -> None:
    with pytest.raises(CodeRuleError):
        parse_rules(text)


def test_single_file_target_and_missing_target(tmp_path: Path) -> None:
    target = tmp_path / "one.py"
    shutil.copy(FIXTURES / "sample_crypto.py", target)
    found = CodeScanner().scan(str(target), ScanConfig())
    assert {o.asset.location for o in found} == {"one.py"}
    with pytest.raises(ScanTargetError) as info:
        CodeScanner().scan(str(tmp_path / "missing"), ScanConfig())
    assert info.value.kind == ErrorKind.INVALID_TARGET


def test_non_source_files_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text('MessageDigest.getInstance("MD5")')
    (tmp_path / "big.py").write_text("import hashlib\nhashlib.md5()\n" + "#" * 2000)
    assert CodeScanner().scan(str(tmp_path), ScanConfig(max_file_size=100)) == []
