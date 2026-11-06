from __future__ import annotations

import socket
import ssl
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from conftest import make_cert, ssl_handler, ssl_server_context
from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import ErrorKind, Primitive, RiskClass, ScanConfig
from pqc_scan.scanners.base import ScanTargetError
from pqc_scan.scanners.tls import TLSScanner, fetch_certificates, parse_target
from pqc_scan.scanners.tls_names import (
    GROUPS,
    SSL3,
    SUITE_NAMES,
    TLS10,
    TLS12,
    TLS13,
    group_algorithm,
    group_label,
    suite_components,
    suite_name,
)
from pqc_scan.scanners.tls_probe import (
    HRR_RANDOM,
    ProbeError,
    TLSProber,
    build_client_hello,
    parse_response,
    parse_server_hello,
)

FAST = ScanConfig(timeout=1.0)

X25519MLKEM768 = 0x11EC
X25519 = 0x001D
SECP256R1 = 0x0017
ECDHE_RSA_AES256_GCM = 0xC030
DHE_RSA_AES128_CBC_SHA = 0x0033
RSA_3DES = 0x000A


# --- wire helpers used by the fake server ---------------------------------------


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u24(value: int) -> bytes:
    return struct.pack(">I", value)[1:]


def vec8(data: bytes) -> bytes:
    return bytes([len(data)]) + data


def vec16(data: bytes) -> bytes:
    return u16(len(data)) + data


def vec24(data: bytes) -> bytes:
    return u24(len(data)) + data


def record(content_type: int, payload: bytes, version: int = TLS12) -> bytes:
    return bytes([content_type]) + u16(version) + vec16(payload)


def handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + vec24(body)


def alert(description: int) -> bytes:
    return record(21, bytes([2, description]))


def extension(ext_type: int, data: bytes) -> bytes:
    return u16(ext_type) + vec16(data)


def server_hello(
    version: int, suite: int, *, extensions: bytes | None = None, random: bytes = b"\x11" * 32
) -> bytes:
    body = u16(version) + random + vec8(b"") + u16(suite) + b"\x00"
    if extensions is not None:
        body += vec16(extensions)
    return handshake(2, body)


@dataclass
class ClientHello:
    version: int
    suites: list[int]
    groups: list[int]
    supported_versions: list[int]
    server_name: str | None
    extensions: dict[int, bytes]


def parse_client_hello(data: bytes) -> ClientHello:
    assert data[0] == 22
    body = data[5 + 4 :]
    pos = 0

    def take(size: int) -> bytes:
        nonlocal pos
        chunk = body[pos : pos + size]
        pos += size
        return chunk

    version = int.from_bytes(take(2), "big")
    take(32)
    take(take(1)[0])
    suites_raw = take(int.from_bytes(take(2), "big"))
    take(take(1)[0])
    extensions: dict[int, bytes] = {}
    if pos < len(body):
        raw = take(int.from_bytes(take(2), "big"))
        i = 0
        while i < len(raw):
            ext_type = int.from_bytes(raw[i : i + 2], "big")
            length = int.from_bytes(raw[i + 2 : i + 4], "big")
            extensions[ext_type] = raw[i + 4 : i + 4 + length]
            i += 4 + length
    suites = [int.from_bytes(suites_raw[i : i + 2], "big") for i in range(0, len(suites_raw), 2)]
    groups_raw = extensions.get(10, b"\x00\x00")[2:]
    groups = [int.from_bytes(groups_raw[i : i + 2], "big") for i in range(0, len(groups_raw), 2)]
    versions_raw = extensions.get(43, b"\x00")[1:]
    supported = [
        int.from_bytes(versions_raw[i : i + 2], "big") for i in range(0, len(versions_raw), 2)
    ]
    server_name = None
    if 0 in extensions:
        server_name = extensions[0][5:].decode()
    return ClientHello(version, suites, groups, supported, server_name, extensions)


def read_record(conn: socket.socket) -> bytes:
    header = b""
    while len(header) < 5:
        chunk = conn.recv(5 - len(header))
        if not chunk:
            raise ConnectionError
        header += chunk
    length = int.from_bytes(header[3:5], "big")
    body = b""
    while len(body) < length:
        body += conn.recv(length - len(body))
    return header + body


@dataclass
class FakePolicy:
    """What the scripted server supports. Preference order = list order."""

    tls13_suites: list[int] = field(default_factory=lambda: [0x1302, 0x1301])
    tls13_groups: list[int] = field(default_factory=lambda: [X25519MLKEM768, X25519])
    tls12_suites: list[int] = field(
        default_factory=lambda: [ECDHE_RSA_AES256_GCM, DHE_RSA_AES128_CBC_SHA]
    )
    tls12_groups: list[int] = field(default_factory=lambda: [SECP256R1])
    legacy_versions: tuple[int, ...] = (TLS12,)
    dh_bits: int = 1024
    certificate: bytes = b""
    hello_records: list[ClientHello] = field(default_factory=list)


def fake_tls_handler(policy: FakePolicy) -> Any:
    """A scripted TLS server: answers exactly like the RFCs say, then hangs up."""

    def handle(conn: socket.socket) -> None:
        hello = parse_client_hello(read_record(conn))
        policy.hello_records.append(hello)
        if TLS13 in hello.supported_versions:
            suite = next((s for s in policy.tls13_suites if s in hello.suites), None)
            group = next((g for g in policy.tls13_groups if g in hello.groups), None)
            if suite is None or group is None:
                conn.sendall(alert(40))
                return
            exts = extension(43, u16(TLS13)) + extension(51, u16(group))
            conn.sendall(record(22, server_hello(TLS12, suite, extensions=exts, random=HRR_RANDOM)))
            return
        if hello.version not in policy.legacy_versions:
            conn.sendall(alert(70))  # protocol_version
            return
        suite = next((s for s in policy.tls12_suites if s in hello.suites), None)
        if suite is None:
            conn.sendall(alert(40))
            return
        messages = server_hello(hello.version, suite, extensions=b"")
        messages += handshake(11, vec24(vec24(policy.certificate)))
        if "_ECDHE_" in SUITE_NAMES[suite]:
            group = next((g for g in policy.tls12_groups if g in hello.groups), None)
            if group is None:
                conn.sendall(alert(40))
                return
            messages += handshake(12, b"\x03" + u16(group) + vec8(b"\x04" + b"\x00" * 64) + b"sig")
        elif "_DHE_" in SUITE_NAMES[suite]:
            prime = (1 << (policy.dh_bits - 1) | 1).to_bytes(policy.dh_bits // 8, "big")
            messages += handshake(12, vec16(prime) + vec16(b"\x02") + vec16(b"\x05" * 8))
        messages += handshake(14, b"")
        # Split across two records to exercise reassembly.
        half = len(messages) // 2
        conn.sendall(record(22, messages[:half]) + record(22, messages[half:]))

    return handle


@pytest.fixture
def certificate_der(keys: dict[str, Any]) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return make_cert(keys["rsa2048"], cn="fake.example").public_bytes(Encoding.DER)


@pytest.fixture
def fake_server(local_server: Any, certificate_der: bytes) -> Any:
    def start(policy: FakePolicy | None = None) -> tuple[Any, FakePolicy]:
        policy = policy or FakePolicy()
        policy.certificate = policy.certificate or certificate_der
        return local_server(fake_tls_handler(policy)), policy

    return start


# --- names ----------------------------------------------------------------------


def test_suite_components() -> None:
    parts = {c.role: c.algorithm for c in suite_components("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")}
    assert parts["key_exchange"].raw_name == "ECDHE"
    assert parts["authentication"].raw_name == "RSA"
    assert (parts["cipher"].raw_name, parts["cipher"].primitive) == (
        "AES_128_CBC",
        Primitive.BLOCK_CIPHER,
    )
    assert parts["mac"].raw_name == "HMAC-SHA1"

    aead = {c.role for c in suite_components("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384")}
    assert aead == {"key_exchange", "authentication", "cipher"}  # AEAD: no separate MAC

    (tls13,) = suite_components("TLS_CHACHA20_POLY1305_SHA256")
    assert (tls13.role, tls13.algorithm.raw_name) == ("cipher", "CHACHA20_POLY1305")

    rc4 = {c.role: c.algorithm for c in suite_components("TLS_RSA_WITH_RC4_128_MD5")}
    assert rc4["cipher"].primitive == Primitive.STREAM_CIPHER
    assert suite_components("TLS_FOO_BAR") == []
    assert suite_components("TLS_PSK_WITH_AES_128_CBC_SHA") == []


def test_every_known_suite_classifies() -> None:
    from pqc_scan.classify import classify

    for name in SUITE_NAMES.values():
        components = suite_components(name)
        assert components, name
        for component in components:
            assert classify(component.algorithm).risk != RiskClass.UNKNOWN, (name, component)


@pytest.mark.parametrize(
    ("code", "label", "risk"),
    [
        (0x11EC, "X25519MLKEM768", RiskClass.HYBRID),
        (0x0201, "ML-KEM-768", RiskClass.PQ_SAFE),
        (0x001D, "X25519", RiskClass.VULNERABLE),
        (0x0017, "secp256r1", RiskClass.VULNERABLE),
        (0x0013, "secp192r1", RiskClass.BROKEN),
        (0x0100, "ffdhe2048", RiskClass.VULNERABLE),
        (0xFAFA, "0xFAFA", RiskClass.UNKNOWN),
    ],
)
def test_groups(code: int, label: str, risk: RiskClass) -> None:
    from pqc_scan.classify import classify

    assert group_label(code) == label
    assert classify(group_algorithm(code)).risk == risk


def test_suite_name_fallback() -> None:
    assert suite_name(0x1301) == "TLS_AES_128_GCM_SHA256"
    assert suite_name(0xABCD) == "0xABCD"


# --- ClientHello / ServerHello encoding -----------------------------------------------


def test_tls13_client_hello() -> None:
    raw = build_client_hello(
        version=TLS13, suites=[0x1301], groups=[X25519MLKEM768], server_name="example.com"
    )
    hello = parse_client_hello(raw)
    assert hello.version == TLS12  # legacy_version is frozen at 1.2
    assert hello.supported_versions == [TLS13]
    assert hello.groups == [X25519MLKEM768]
    assert hello.extensions[51] == b"\x00\x00"  # empty key_share → HelloRetryRequest
    assert hello.server_name == "example.com"


def test_legacy_client_hellos() -> None:
    tls10 = parse_client_hello(
        build_client_hello(version=TLS10, suites=[RSA_3DES], groups=[SECP256R1], server_name=None)
    )
    assert tls10.version == TLS10
    assert 43 not in tls10.extensions and 0 not in tls10.extensions
    ssl3 = build_client_hello(version=SSL3, suites=[RSA_3DES], groups=[], server_name=None)
    assert ssl3[1:3] == u16(SSL3)
    assert parse_client_hello(ssl3).extensions == {}


def test_parse_hello_retry_request() -> None:
    exts = extension(43, u16(TLS13)) + extension(51, u16(X25519MLKEM768))
    hello = parse_server_hello(server_hello(TLS12, 0x1302, extensions=exts, random=HRR_RANDOM)[4:])
    assert (hello.version, hello.cipher_suite, hello.group, hello.retry) == (
        TLS13,
        0x1302,
        X25519MLKEM768,
        True,
    )


def test_parse_legacy_server_hello_without_extensions() -> None:
    hello = parse_server_hello(server_hello(TLS10, RSA_3DES)[4:])
    assert (hello.version, hello.cipher_suite, hello.group, hello.retry) == (
        TLS10,
        RSA_3DES,
        None,
        False,
    )


def test_parse_response_alert_and_partial_records() -> None:
    assert parse_response(alert(40)).alert == 40
    full = record(22, server_hello(TLS12, RSA_3DES))
    assert parse_response(full[:-3]).hello is None  # incomplete record is ignored
    assert parse_response(full).hello is not None
    with pytest.raises(ProbeError):
        parse_response(b"HTTP/1.1 400 Bad Request\r\n\r\n")


def test_truncated_server_hello_raises() -> None:
    with pytest.raises(ProbeError, match="truncated"):
        parse_server_hello(b"\x03\x03\x00")


# --- targets ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("example.com", ("example.com", 443)),
        ("example.com:8443", ("example.com", 8443)),
        ("https://example.com/path", ("example.com", 443)),
        ("[2001:db8::1]:444", ("2001:db8::1", 444)),
        ("[2001:db8::1]", ("2001:db8::1", 443)),
        ("2001:db8::1", ("2001:db8::1", 443)),
        ("192.0.2.1:25", ("192.0.2.1", 25)),
    ],
)
def test_parse_target(target: str, expected: tuple[str, int]) -> None:
    assert parse_target(target) == expected


@pytest.mark.parametrize("target", ["", ":443", "host:0", "host:99999", "host:abc", "[::1]x"])
def test_parse_target_rejects(target: str) -> None:
    with pytest.raises(ScanTargetError) as info:
        parse_target(target)
    assert info.value.kind == ErrorKind.INVALID_TARGET


# --- scripted server: hybrid groups and TLS 1.2 details --------------------------------


def test_fake_server_probe_report(fake_server: Any, certificate_der: bytes) -> None:
    server, policy = fake_server()
    report = TLSProber("127.0.0.1", server.port, 1.0, "fake.example").run()
    assert report.suites == {
        TLS13: [0x1302, 0x1301],
        TLS12: [ECDHE_RSA_AES256_GCM, DHE_RSA_AES128_CBC_SHA],
    }
    assert report.groups == {TLS13: [X25519MLKEM768, X25519], TLS12: [SECP256R1]}
    assert report.dh_bits == {TLS12: 1024}
    assert report.certificates == [certificate_der]
    assert not report.truncated
    # SNI in every hello (SSL 3.0 has no extensions at all).
    assert all(h.server_name == "fake.example" for h in policy.hello_records if h.version != SSL3)


def test_fake_server_findings(fake_server: Any) -> None:
    server, _ = fake_server()
    result = run_scan([ScanJob(TLSScanner(), f"127.0.0.1:{server.port}")], FAST)
    assert result.errors == []
    by_usage: dict[str, set[tuple[str, RiskClass]]] = {}
    for f in result.findings:
        by_usage.setdefault(f.usage, set()).add((f.algorithm.raw_name, f.risk))
    assert by_usage["tls.protocol"] == {
        ("TLSv1.3", RiskClass.PQ_SAFE),
        ("TLSv1.2", RiskClass.VULNERABLE),
    }
    groups = by_usage["tls.key_exchange_group"]
    assert ("X25519MLKEM768", RiskClass.HYBRID) in groups
    assert ("X25519", RiskClass.VULNERABLE) in groups
    assert ("DH", RiskClass.BROKEN) in by_usage["tls.dh_parameters"]  # 1024-bit DHE
    assert ("HMAC-SHA1", RiskClass.WEAKENED) in by_usage["tls.cipher_suite.mac"]
    assert ("RSA", RiskClass.VULNERABLE) in by_usage["tls.certificate.public_key"]

    endpoint = f"tls://127.0.0.1:{server.port}"
    assert {a.id for a in result.assets} == {endpoint, f"{endpoint}#cert-0"}
    cert_asset = next(a for a in result.assets if a.id.endswith("#cert-0"))
    assert cert_asset.details["subject"] == "CN=fake.example"
    hybrid = next(f for f in result.findings if f.algorithm.raw_name == "X25519MLKEM768")
    assert hybrid.evidence.detail == "TLSv1.3: X25519MLKEM768 (selected #1)"
    ciphers = {f.evidence.detail for f in result.findings if f.algorithm.raw_name == "AES_256_GCM"}
    assert ciphers == {
        "TLSv1.3: TLS_AES_256_GCM_SHA384",
        "TLSv1.2: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    }


def test_server_without_post_quantum_groups(fake_server: Any) -> None:
    server, _ = fake_server(FakePolicy(tls13_groups=[X25519, SECP256R1]))
    report = TLSProber("127.0.0.1", server.port, 1.0, None).run()
    assert report.groups[TLS13] == [X25519, SECP256R1]


def test_legacy_only_server(fake_server: Any) -> None:
    policy = FakePolicy(
        tls13_suites=[],
        tls12_suites=[RSA_3DES],
        legacy_versions=(TLS10,),
    )
    server, _ = fake_server(policy)
    report = TLSProber("127.0.0.1", server.port, 1.0, None).run()
    assert report.suites == {TLS10: [RSA_3DES]}
    assert TLS10 not in report.groups  # no ECDHE suite, no group probe
    assert report.certificates


def test_connection_budget(fake_server: Any) -> None:
    server, _ = fake_server()
    prober = TLSProber("127.0.0.1", server.port, 1.0, None, max_connections=3)
    report = prober.run()
    assert report.truncated
    assert prober.connections == 3


# --- real TLS server (Python ssl / OpenSSL) ---------------------------------------------


def test_real_tls_server(local_server: Any, tmp_path: Path, keys: dict[str, Any]) -> None:
    context = ssl_server_context(tmp_path, keys["p256"], minimum=ssl.TLSVersion.TLSv1_2)
    server = local_server(ssl_handler(context))
    result = run_scan([ScanJob(TLSScanner(), f"127.0.0.1:{server.port}")], FAST)
    assert result.errors == []
    protocols = {f.algorithm.raw_name for f in result.findings if f.usage == "tls.protocol"}
    assert protocols == {"TLSv1.3", "TLSv1.2"}
    groups = {f.algorithm.raw_name for f in result.findings if f.usage == "tls.key_exchange_group"}
    assert "X25519" in groups
    cert_key = next(f for f in result.findings if f.usage == "tls.certificate.public_key")
    assert (cert_key.algorithm.raw_name, cert_key.algorithm.curve) == ("EC", "secp256r1")


def test_tls13_only_server_certificate_via_ssl(
    local_server: Any, tmp_path: Path, keys: dict[str, Any]
) -> None:
    context = ssl_server_context(tmp_path, keys["ed25519"], minimum=ssl.TLSVersion.TLSv1_3)
    server = local_server(ssl_handler(context))
    result = run_scan([ScanJob(TLSScanner(), f"127.0.0.1:{server.port}")], FAST)
    protocols = {f.algorithm.raw_name for f in result.findings if f.usage == "tls.protocol"}
    assert protocols == {"TLSv1.3"}
    cert_key = next(f for f in result.findings if f.usage == "tls.certificate.public_key")
    assert cert_key.algorithm.raw_name == "Ed25519"


def test_fetch_certificates_failure_returns_empty(local_server: Any) -> None:
    server = local_server(lambda conn: conn.sendall(b"not tls"))
    assert fetch_certificates("127.0.0.1", server.port, 0.5, None) == []


# --- errors -----------------------------------------------------------------------------


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_connection_refused() -> None:
    result = run_scan([ScanJob(TLSScanner(), f"127.0.0.1:{unused_port()}")], FAST)
    assert [e.kind for e in result.errors] == [ErrorKind.CONNECTION_REFUSED]


def test_not_a_tls_server(local_server: Any) -> None:
    server = local_server(lambda conn: (conn.recv(1024), conn.sendall(b"HTTP/1.0 400 Bad\r\n\r\n")))
    result = run_scan([ScanJob(TLSScanner(), f"127.0.0.1:{server.port}")], FAST)
    assert [(e.kind, e.message) for e in result.errors] == [
        (ErrorKind.PARSE, "no TLS handshake response")
    ]


def test_silent_server_times_out(local_server: Any) -> None:
    import time

    server = local_server(lambda conn: time.sleep(0.5))
    result = run_scan([ScanJob(TLSScanner(), f"127.0.0.1:{server.port}")], ScanConfig(timeout=0.1))
    assert [e.kind for e in result.errors] == [ErrorKind.PARSE]


def test_invalid_target_error() -> None:
    result = run_scan([ScanJob(TLSScanner(), "host:99999")], FAST)
    assert [e.kind for e in result.errors] == [ErrorKind.INVALID_TARGET]


def test_group_table_has_unique_names_per_code() -> None:
    assert len(GROUPS) == len({(g.name, g.curve, g.key_size) for g in GROUPS.values()})
