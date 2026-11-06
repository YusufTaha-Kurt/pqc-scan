from __future__ import annotations

import socket
import struct
from typing import Any

import pytest

from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import ErrorKind, RiskClass, ScanConfig
from pqc_scan.scanners.ssh import (
    CLIENT_IDENTIFICATION,
    SSHProtocolError,
    SSHScanner,
    parse_kexinit,
)

FAST = ScanConfig(timeout=1.0)

MODERN = {
    "kex": "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,"
    "diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
    "host_keys": "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,ssh-rsa",
    "ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr",
    "macs": "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1",
}


def name_list(text: str) -> bytes:
    data = text.encode()
    return struct.pack(">I", len(data)) + data


def kexinit_payload(lists: dict[str, str]) -> bytes:
    fields = [
        lists["kex"],
        lists["host_keys"],
        lists["ciphers"],
        lists.get("ciphers_s2c", lists["ciphers"]),
        lists["macs"],
        lists["macs"],
        "none,zlib@openssh.com",
        "none,zlib@openssh.com",
        "",
        "",
    ]
    return bytes([20]) + b"\xaa" * 16 + b"".join(name_list(f) for f in fields) + b"\x00" + b"\0" * 4


def packet(payload: bytes) -> bytes:
    padding = 8 - ((len(payload) + 5) % 8)
    padding += 8 if padding < 4 else 0
    length = 1 + len(payload) + padding
    return struct.pack(">IB", length, padding) + payload + b"\0" * padding


def ssh_handler(
    identification: bytes = b"SSH-2.0-OpenSSH_9.9 Ubuntu",
    lists: dict[str, str] | None = None,
    *,
    preamble: bytes = b"Authorised users only\r\n",
    raw_packet: bytes | None = None,
    seen: list[bytes] | None = None,
) -> Any:
    def handle(conn: socket.socket) -> None:
        conn.sendall(preamble + identification + b"\r\n")
        if not identification.startswith((b"SSH-2.0", b"SSH-1.99")):
            return
        received = conn.recv(256)
        if seen is not None:
            seen.append(received)
        conn.sendall(
            raw_packet if raw_packet is not None else packet(kexinit_payload(lists or MODERN))
        )

    return handle


def scan(port: int, config: ScanConfig = FAST) -> Any:
    return run_scan([ScanJob(SSHScanner(), f"127.0.0.1:{port}")], config)


def test_modern_server(local_server: Any) -> None:
    seen: list[bytes] = []
    server = local_server(ssh_handler(seen=seen))
    result = scan(server.port)
    assert result.errors == []
    assert seen == [CLIENT_IDENTIFICATION]  # we only identify ourselves, nothing more

    by_usage: dict[str, list[tuple[str, RiskClass, str]]] = {}
    for f in sorted(result.findings, key=lambda f: f.evidence.detail):
        by_usage.setdefault(f.usage, []).append((f.algorithm.raw_name, f.risk, f.evidence.detail))

    assert by_usage["ssh.protocol"] == [("SSHv2", RiskClass.PQ_SAFE, "OpenSSH_9.9 Ubuntu")]
    kex = {name: risk for name, risk, _ in by_usage["ssh.key_exchange"]}
    assert kex == {
        "mlkem768x25519-sha256": RiskClass.HYBRID,
        "sntrup761x25519-sha512": RiskClass.HYBRID,
        "curve25519-sha256": RiskClass.VULNERABLE,
        "diffie-hellman-group14-sha256": RiskClass.VULNERABLE,
    }
    host_keys = {name: risk for name, risk, _ in by_usage["ssh.host_key"]}
    assert host_keys == {
        "ssh-ed25519": RiskClass.VULNERABLE,  # the -cert variant folds into it
        "rsa-sha2-512": RiskClass.VULNERABLE,
        "ssh-rsa": RiskClass.BROKEN,
    }
    ciphers = {name: risk for name, risk, _ in by_usage["ssh.cipher"]}
    assert ciphers["aes128-ctr"] == RiskClass.WEAKENED
    assert ciphers["aes256-gcm@openssh.com"] == RiskClass.PQ_SAFE
    macs = {name: risk for name, risk, _ in by_usage["ssh.mac"]}
    assert macs == {
        "umac-64-etm@openssh.com": RiskClass.WEAKENED,
        "hmac-sha2-256-etm@openssh.com": RiskClass.PQ_SAFE,
        "hmac-sha1": RiskClass.WEAKENED,
    }
    mlkem = next(f for f in result.findings if f.algorithm.raw_name == "mlkem768x25519-sha256")
    assert mlkem.evidence.detail == "server preference #1"
    assert {a.id for a in result.assets} == {f"ssh://127.0.0.1:{server.port}"}


def test_legacy_server(local_server: Any) -> None:
    lists = {
        "kex": "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
        "host_keys": "ssh-dss",
        "ciphers": "3des-cbc,arcfour,cast128-cbc",
        "ciphers_s2c": "aes128-cbc",
        "macs": "hmac-md5",
    }
    server = local_server(ssh_handler(b"SSH-1.99-OldSSH_3.0", lists, preamble=b""))
    result = scan(server.port)
    risks = {(f.usage, f.algorithm.raw_name): f.risk for f in result.findings}
    assert risks[("ssh.protocol", "SSHv1")] == RiskClass.BROKEN
    assert risks[("ssh.protocol", "SSHv2")] == RiskClass.PQ_SAFE
    assert risks[("ssh.key_exchange", "diffie-hellman-group1-sha1")] == RiskClass.BROKEN
    assert risks[("ssh.host_key", "ssh-dss")] == RiskClass.BROKEN
    assert risks[("ssh.cipher", "3des-cbc")] == RiskClass.BROKEN
    assert risks[("ssh.cipher", "aes128-cbc")] == RiskClass.WEAKENED  # server→client list
    assert risks[("ssh.mac", "hmac-md5")] == RiskClass.BROKEN


def test_ssh1_only_server(local_server: Any) -> None:
    server = local_server(ssh_handler(b"SSH-1.5-Ancient", preamble=b""))
    result = scan(server.port)
    assert [(f.algorithm.raw_name, f.risk) for f in result.findings] == [
        ("SSHv1", RiskClass.BROKEN)
    ]


@pytest.mark.parametrize(
    ("handler_kwargs", "message"),
    [
        ({"identification": b"HTTP/1.1 400 Bad Request", "preamble": b""}, "connection closed"),
        ({"raw_packet": struct.pack(">IB", 10**6, 4)}, "invalid packet length"),
        ({"raw_packet": packet(b"\x15" + b"\0" * 40)}, "not KEXINIT"),
        ({"raw_packet": packet(bytes([20]) + b"\0" * 16 + b"\0\0\0\xff")}, "truncated"),
        ({"raw_packet": struct.pack(">IB", 12, 12) + b"\0" * 12}, "invalid padding"),
    ],
)
def test_protocol_errors(local_server: Any, handler_kwargs: dict[str, Any], message: str) -> None:
    server = local_server(ssh_handler(**handler_kwargs))
    result = scan(server.port)
    assert len(result.errors) == 1
    assert result.errors[0].kind == ErrorKind.PARSE
    assert message in result.errors[0].message


def test_endless_banner_is_rejected(local_server: Any) -> None:
    def handle(conn: socket.socket) -> None:
        conn.sendall(b"x" * 10000)

    server = local_server(handle)
    result = scan(server.port)
    assert [e.message for e in result.errors] == ["no SSH identification string"]


def test_silent_server_times_out(local_server: Any) -> None:
    import time

    server = local_server(lambda conn: time.sleep(0.6))
    result = scan(server.port, ScanConfig(timeout=0.2))
    assert [e.kind for e in result.errors] == [ErrorKind.TIMEOUT]


def test_default_port_and_bad_target() -> None:
    result = run_scan([ScanJob(SSHScanner(), "host:abc")], FAST)
    assert [e.kind for e in result.errors] == [ErrorKind.INVALID_TARGET]


def test_parse_kexinit_direct() -> None:
    parsed = parse_kexinit(kexinit_payload(MODERN))
    assert parsed.kex[0] == "mlkem768x25519-sha256"
    assert parsed.macs_s2c == parsed.macs_c2s
    with pytest.raises(SSHProtocolError):
        parse_kexinit(b"")
