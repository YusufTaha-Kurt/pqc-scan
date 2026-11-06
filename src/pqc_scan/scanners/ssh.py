"""Report the algorithms an SSH server offers.

The server announces everything it supports in its first binary packet,
``SSH_MSG_KEXINIT`` (RFC 4253 §7.1), which is sent in clear text before any
key is agreed. The scanner connects, exchanges identification strings, reads
that one packet and closes the connection (decision D-5). It never starts a
key exchange and never authenticates.

Reported per ``host[:port]`` (default port 22): protocol version, key-exchange
methods (e.g. ``mlkem768x25519-sha256``), host-key algorithms, ciphers and MACs,
each in the server's order of preference.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass
from typing import Final

from pqc_scan import __version__
from pqc_scan.models import (
    Algorithm,
    Asset,
    AssetKind,
    ErrorKind,
    Evidence,
    Observation,
    Primitive,
    ScanConfig,
)
from pqc_scan.scanners.base import Scanner, ScanTargetError
from pqc_scan.scanners.tls import display_endpoint, parse_target

DEFAULT_PORT: Final = 22
SSH_MSG_KEXINIT: Final = 20
CLIENT_IDENTIFICATION: Final = f"SSH-2.0-pqc_scan_{__version__}\r\n".encode()

_MAX_BANNER_BYTES: Final = 8192
_MAX_PACKET: Final = 35000  # RFC 4253 §6.1
# Markers that appear in the KEX list but are not algorithms.
_PSEUDO_KEX: Final = frozenset(
    {
        "ext-info-s",
        "ext-info-c",
        "kex-strict-s-v00@openssh.com",
        "kex-strict-c-v00@openssh.com",
    }
)
_CERT_SUFFIX: Final = "-cert-v01@openssh.com"


class SSHProtocolError(Exception):
    """The server's answer is not a valid SSH identification or KEXINIT."""


@dataclass(frozen=True)
class KexInit:
    kex: list[str]
    host_keys: list[str]
    ciphers_c2s: list[str]
    ciphers_s2c: list[str]
    macs_c2s: list[str]
    macs_s2c: list[str]


def parse_kexinit(payload: bytes) -> KexInit:
    """Decode the name-lists of an SSH_MSG_KEXINIT payload."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise SSHProtocolError("first packet is not KEXINIT")
    pos = 1 + 16  # message type + cookie
    lists: list[list[str]] = []
    for _ in range(10):
        if pos + 4 > len(payload):
            raise SSHProtocolError("truncated KEXINIT")
        (length,) = struct.unpack_from(">I", payload, pos)
        pos += 4
        if pos + length > len(payload):
            raise SSHProtocolError("truncated KEXINIT")
        raw = payload[pos : pos + length].decode("ascii", errors="replace")
        lists.append([name for name in raw.split(",") if name])
        pos += length
    return KexInit(
        kex=lists[0],
        host_keys=lists[1],
        ciphers_c2s=lists[2],
        ciphers_s2c=lists[3],
        macs_c2s=lists[4],
        macs_s2c=lists[5],
    )


class _Connection:
    """Blocking reads with an overall deadline."""

    def __init__(self, sock: socket.socket, timeout: float) -> None:
        self.sock = sock
        self.buffer = b""
        self.deadline = time.monotonic() + 3 * timeout

    def _fill(self) -> None:
        if time.monotonic() > self.deadline:
            raise TimeoutError
        chunk = self.sock.recv(4096)
        if not chunk:
            raise SSHProtocolError("connection closed by server")
        self.buffer += chunk

    def read_identification(self) -> str:
        """The server's ``SSH-…`` line; other lines before it are allowed (RFC 4253 §4.2)."""
        while True:
            while b"\n" not in self.buffer:
                if len(self.buffer) > _MAX_BANNER_BYTES:
                    raise SSHProtocolError("no SSH identification string")
                self._fill()
            line, _, self.buffer = self.buffer.partition(b"\n")
            if line.startswith(b"SSH-"):
                return line.rstrip(b"\r").decode("ascii", errors="replace")
            if len(self.buffer) > _MAX_BANNER_BYTES:
                raise SSHProtocolError("no SSH identification string")

    def read_packet(self) -> bytes:
        while len(self.buffer) < 5:
            self._fill()
        (length,) = struct.unpack_from(">I", self.buffer)
        if not 5 <= length <= _MAX_PACKET:
            raise SSHProtocolError("invalid packet length")
        while len(self.buffer) < 4 + length:
            self._fill()
        padding = self.buffer[4]
        if padding >= length:
            raise SSHProtocolError("invalid padding length")
        return self.buffer[5 : 4 + length - padding]


@dataclass(frozen=True)
class SSHInfo:
    identification: str
    kexinit: KexInit | None  # None for an SSH-1-only server


def probe(host: str, port: int, timeout: float) -> SSHInfo:
    """Read the server identification and KEXINIT, then disconnect."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        conn = _Connection(sock, timeout)
        identification = conn.read_identification()
        version = identification.split("-", 2)[1] if identification.count("-") >= 2 else ""
        if version not in ("2.0", "1.99"):
            return SSHInfo(identification, None)
        sock.sendall(CLIENT_IDENTIFICATION)
        return SSHInfo(identification, parse_kexinit(conn.read_packet()))


def _software(identification: str) -> str:
    """The software part of an identification line, printable and short."""
    parts = identification.split("-", 2)
    text = parts[2] if len(parts) == 3 else identification
    clean = "".join(ch if ch.isprintable() else "?" for ch in text)
    return clean[:120]


def _host_key_name(name: str) -> str:
    return name.removesuffix(_CERT_SUFFIX)


class SSHScanner(Scanner):
    """Probe SSH servers for protocol version and offered algorithms."""

    name = "ssh"

    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        host, port = parse_target(target, DEFAULT_PORT)
        try:
            info = probe(host, port, config.timeout)
        except SSHProtocolError as exc:
            raise ScanTargetError(ErrorKind.PARSE, str(exc)) from exc
        return self._observations(display_endpoint(host, port), info)

    def _observations(self, location: str, info: SSHInfo) -> list[Observation]:
        asset = Asset(id=f"ssh://{location}", kind=AssetKind.SSH_ENDPOINT, location=location)
        found: list[Observation] = []

        def add(usage: str, name: str, primitive: Primitive, detail: str) -> None:
            found.append(
                Observation(
                    asset=asset,
                    algorithm=Algorithm(raw_name=name, primitive=primitive),
                    usage=usage,
                    scanner=self.name,
                    evidence=Evidence(detail=detail),
                )
            )

        version = info.identification.split("-", 2)[1] if "-" in info.identification else ""
        software = _software(info.identification)
        if version in ("1.99", "1.5", "1.3"):
            add("ssh.protocol", "SSHv1", Primitive.PROTOCOL, software)
        if version in ("2.0", "1.99"):
            add("ssh.protocol", "SSHv2", Primitive.PROTOCOL, software)

        kexinit = info.kexinit
        if kexinit is None:
            return found
        groups = (
            ("ssh.key_exchange", [k for k in kexinit.kex if k not in _PSEUDO_KEX],
             Primitive.KEY_EXCHANGE),
            ("ssh.host_key", list(dict.fromkeys(_host_key_name(k) for k in kexinit.host_keys)),
             Primitive.SIGNATURE),
            ("ssh.cipher", list(dict.fromkeys(kexinit.ciphers_c2s + kexinit.ciphers_s2c)),
             Primitive.BLOCK_CIPHER),
            ("ssh.mac", list(dict.fromkeys(kexinit.macs_c2s + kexinit.macs_s2c)),
             Primitive.MAC),
        )  # fmt: skip
        for usage, names, primitive in groups:
            for rank, name in enumerate(names, start=1):
                add(usage, name, primitive, f"server preference #{rank}")
        return found
