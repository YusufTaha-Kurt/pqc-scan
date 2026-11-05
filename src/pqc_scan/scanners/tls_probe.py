"""A minimal, passive TLS probe written in pure Python.

The probe sends hand-built ClientHello messages and reads only the server's
plaintext answer: ``ServerHello`` or ``HelloRetryRequest``, and for TLS ≤ 1.2
also ``Certificate`` and ``ServerKeyExchange``. It then closes the connection.
It never completes a handshake, never sends application data and needs no
cryptographic keys of its own.

How support is discovered (decisions D-2, D-11):

* **Versions** — one ClientHello per version; supported if the server answers
  with exactly that version.
* **Cipher suites and groups** — offer a list, note what the server picks,
  remove it and ask again until the server refuses. The order found is the
  order in which the server selected them.
* **TLS 1.3 groups** — the ClientHello carries an *empty* ``key_share`` list.
  RFC 8446 then obliges a server to answer with a HelloRetryRequest naming
  the group it wants, so no key shares (and no ML-KEM implementation) are
  needed on our side.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final

from pqc_scan.scanners.tls_names import (
    GROUPS,
    LEGACY_SUITES,
    SSL3,
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    TLS13_SUITES,
    is_dhe,
    is_ecdhe,
)

# Record and handshake types (RFC 8446 §5.1, §4)
_HANDSHAKE: Final = 22
_ALERT: Final = 21
_CLIENT_HELLO: Final = 1
SERVER_HELLO: Final = 2
CERTIFICATE: Final = 11
SERVER_KEY_EXCHANGE: Final = 12
SERVER_HELLO_DONE: Final = 14

# Extension types
_EXT_SERVER_NAME: Final = 0
_EXT_SUPPORTED_GROUPS: Final = 10
_EXT_EC_POINT_FORMATS: Final = 11
_EXT_SIGNATURE_ALGORITHMS: Final = 13
_EXT_EXTENDED_MASTER_SECRET: Final = 23
_EXT_SUPPORTED_VERSIONS: Final = 43
_EXT_PSK_KEY_EXCHANGE_MODES: Final = 45
_EXT_KEY_SHARE: Final = 51
_EXT_RENEGOTIATION_INFO: Final = 0xFF01

# ServerHello.random of a HelloRetryRequest (RFC 8446 §4.1.3)
HRR_RANDOM: Final = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

_SIGNATURE_SCHEMES: Final = (
    0x0403, 0x0503, 0x0603,  # ecdsa_secp{256,384,521}r1_sha{256,384,512}
    0x0807, 0x0808,  # ed25519, ed448
    0x0804, 0x0805, 0x0806,  # rsa_pss_rsae_sha{256,384,512}
    0x0809, 0x080A, 0x080B,  # rsa_pss_pss_sha{256,384,512}
    0x0401, 0x0501, 0x0601,  # rsa_pkcs1_sha{256,384,512}
    0x0904, 0x0905, 0x0906,  # mldsa{44,65,87}
    0x0201, 0x0203, 0x0202, 0x0402,  # SHA-1 and DSA based, for old servers
)  # fmt: skip

_MAX_RESPONSE: Final = 256 * 1024
_MAX_LOOP: Final = 64


class ProbeError(Exception):
    """The response is not a well-formed TLS answer."""


# --- encoding -----------------------------------------------------------------


def _u8(value: int) -> bytes:
    return struct.pack(">B", value)


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u24(value: int) -> bytes:
    return struct.pack(">I", value)[1:]


def _vec8(data: bytes) -> bytes:
    return _u8(len(data)) + data


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _extension(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _vec16(data)


def _codes(values: Iterable[int]) -> bytes:
    return b"".join(_u16(v) for v in values)


def build_client_hello(
    *,
    version: int,
    suites: Sequence[int],
    groups: Sequence[int],
    server_name: str | None,
) -> bytes:
    """A complete TLS record holding one ClientHello.

    For ``version == TLS13`` the hello uses ``supported_versions`` (offering
    only TLS 1.3) and an empty ``key_share``; otherwise ``legacy_version`` is
    the version being probed and no TLS 1.3 extensions are sent.
    """
    tls13 = version == TLS13
    extensions = b""
    if server_name:
        name = server_name.encode("idna")
        entry = _u8(0) + _vec16(name)  # host_name
        extensions += _extension(_EXT_SERVER_NAME, _vec16(entry))
    extensions += _extension(_EXT_SUPPORTED_GROUPS, _vec16(_codes(groups)))
    extensions += _extension(_EXT_EC_POINT_FORMATS, _vec8(b"\x00"))
    extensions += _extension(_EXT_SIGNATURE_ALGORITHMS, _vec16(_codes(_SIGNATURE_SCHEMES)))
    if tls13:
        extensions += _extension(_EXT_SUPPORTED_VERSIONS, _vec8(_u16(TLS13)))
        extensions += _extension(_EXT_PSK_KEY_EXCHANGE_MODES, _vec8(b"\x01"))
        extensions += _extension(_EXT_KEY_SHARE, _vec16(b""))  # empty → HelloRetryRequest
    else:
        extensions += _extension(_EXT_EXTENDED_MASTER_SECRET, b"")
        extensions += _extension(_EXT_RENEGOTIATION_INFO, b"\x00")

    body = (
        _u16(TLS12 if tls13 else version)
        + os.urandom(32)
        + _vec8(os.urandom(32) if tls13 else b"")
        + _vec16(_codes(suites))
        + _vec8(b"\x00")  # null compression
    )
    if version != SSL3:
        body += _vec16(extensions)
    handshake = _u8(_CLIENT_HELLO) + _u24(len(body)) + body
    record_version = SSL3 if version == SSL3 else TLS10
    return _u8(_HANDSHAKE) + _u16(record_version) + _vec16(handshake)


# --- decoding -----------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        end = self.pos + size
        if end > len(self.data):
            raise ProbeError("truncated TLS message")
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vec8(self) -> bytes:
        return self.take(self.u8())

    def vec16(self) -> bytes:
        return self.take(self.u16())

    def vec24(self) -> bytes:
        return self.take(self.u24())

    def done(self) -> bool:
        return self.pos >= len(self.data)


@dataclass(frozen=True)
class ServerHello:
    version: int  # negotiated version (supported_versions wins over legacy_version)
    cipher_suite: int
    group: int | None  # key_share group (HelloRetryRequest or TLS 1.3 ServerHello)
    retry: bool  # True for a HelloRetryRequest


def parse_server_hello(body: bytes) -> ServerHello:
    reader = _Reader(body)
    legacy_version = reader.u16()
    random = reader.take(32)
    reader.vec8()  # session id
    suite = reader.u16()
    reader.u8()  # compression
    version, group = legacy_version, None
    retry = random == HRR_RANDOM
    if not reader.done():
        extensions = _Reader(reader.vec16())
        while not extensions.done():
            ext_type = extensions.u16()
            data = _Reader(extensions.vec16())
            if ext_type == _EXT_SUPPORTED_VERSIONS:
                version = data.u16()
            elif ext_type == _EXT_KEY_SHARE:
                group = data.u16()
    return ServerHello(version=version, cipher_suite=suite, group=group, retry=retry)


def parse_certificates(body: bytes) -> list[bytes]:
    """DER certificates of a TLS ≤ 1.2 Certificate message."""
    entries = _Reader(_Reader(body).vec24())
    certificates = []
    while not entries.done():
        certificates.append(entries.vec24())
    return certificates


def parse_server_key_exchange(body: bytes, suite: int) -> tuple[int | None, int | None]:
    """(named group, DH prime bits) from a ServerKeyExchange."""
    reader = _Reader(body)
    if is_ecdhe(suite):
        if reader.u8() != 3:  # named_curve
            return None, None
        return reader.u16(), None
    if is_dhe(suite):
        prime = reader.vec16()
        return None, int.from_bytes(prime, "big").bit_length()
    return None, None


@dataclass
class Response:
    """Everything readable from one connection."""

    hello: ServerHello | None = None
    alert: int | None = None
    certificates: list[bytes] = field(default_factory=list)
    group: int | None = None  # TLS ≤ 1.2 ECDHE curve from ServerKeyExchange
    dh_bits: int | None = None
    messages: set[int] = field(default_factory=set)


def parse_response(data: bytes) -> Response:
    """Decode complete records in ``data``; a trailing partial record is ignored."""
    response = Response()
    stream = b""
    reader = _Reader(data)
    while len(data) - reader.pos >= 5:
        content_type = reader.u8()
        record_version = reader.u16()
        if content_type not in (20, 21, 22, 23) or record_version >> 8 != 3:
            raise ProbeError("not a TLS response")
        length = reader.u16()
        if len(data) - reader.pos < length:
            break
        fragment = reader.take(length)
        if content_type == _ALERT and len(fragment) >= 2:
            response.alert = fragment[1]
            break
        if content_type == _HANDSHAKE:
            stream += fragment  # change_cipher_spec (20) and encrypted data (23) are skipped

    messages = _Reader(stream)
    while len(stream) - messages.pos >= 4:
        msg_type = messages.u8()
        length = messages.u24()
        if len(stream) - messages.pos < length:
            break
        body = messages.take(length)
        response.messages.add(msg_type)
        if msg_type == SERVER_HELLO:
            response.hello = parse_server_hello(body)
        elif msg_type == CERTIFICATE:
            response.certificates = parse_certificates(body)
        elif msg_type == SERVER_KEY_EXCHANGE and response.hello is not None:
            response.group, response.dh_bits = parse_server_key_exchange(
                body, response.hello.cipher_suite
            )
    return response


# --- probing ------------------------------------------------------------------

LEGACY_VERSIONS: Final = (TLS12, TLS11, TLS10, SSL3)
_TLS13_GROUPS: Final = tuple(GROUPS)
_LEGACY_GROUPS: Final = tuple(code for code in GROUPS if code < 0x0200)


@dataclass
class TLSReport:
    """What a :class:`TLSProber` learned about one endpoint."""

    suites: dict[int, list[int]] = field(default_factory=dict)  # version → selected suites
    groups: dict[int, list[int]] = field(default_factory=dict)  # version → selected groups
    dh_bits: dict[int, int] = field(default_factory=dict)  # version → DHE prime size
    certificates: list[bytes] = field(default_factory=list)  # DER, leaf first
    truncated: bool = False  # the connection budget ran out


class _BudgetExhaustedError(Exception):
    """Internal: the connection budget for one endpoint is used up."""


class TLSProber:
    """Ask one endpoint what it supports, one short connection at a time."""

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        server_name: str | None,
        max_connections: int = 200,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.server_name = server_name
        self.max_connections = max_connections
        self.connections = 0
        self._reached = False

    # -- transport --

    def _connect(self) -> socket.socket | None:
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError:
            if not self._reached:
                raise  # unreachable target: let the engine report it
            return None  # the server stopped answering mid-scan
        self._reached = True
        return sock

    def exchange(self, hello: bytes, until: int = SERVER_HELLO) -> Response:
        """Send ``hello``; read until message ``until``, an alert or silence."""
        if self.connections >= self.max_connections:
            raise _BudgetExhaustedError
        self.connections += 1
        sock = self._connect()
        if sock is None:
            return Response()
        data = b""
        deadline = time.monotonic() + 2 * self.timeout
        with sock:
            try:
                sock.sendall(hello)
                while len(data) < _MAX_RESPONSE and time.monotonic() < deadline:
                    chunk = sock.recv(16384)
                    if not chunk:
                        break
                    data += chunk
                    response = parse_response(data)
                    if response.alert is not None or until in response.messages:
                        return response
                    if response.hello and response.hello.version == TLS13:
                        return response  # the rest is encrypted
            except (OSError, ProbeError):
                pass
        try:
            return parse_response(data)
        except ProbeError:
            return Response()

    def _hello(self, version: int, suites: Sequence[int], groups: Sequence[int]) -> bytes:
        return build_client_hello(
            version=version, suites=suites, groups=groups, server_name=self.server_name
        )

    # -- questions --

    def _all_suites(self, version: int) -> list[int]:
        return list(TLS13_SUITES if version == TLS13 else LEGACY_SUITES)

    def _all_groups(self, version: int) -> list[int]:
        return list(_TLS13_GROUPS if version == TLS13 else _LEGACY_GROUPS)

    def _accepted(self, response: Response, version: int) -> ServerHello | None:
        hello = response.hello
        if hello is None or hello.version != version:
            return None
        return hello

    def enumerate_suites(self, version: int) -> list[int]:
        offered = self._all_suites(version)
        selected: list[int] = []
        for _ in range(_MAX_LOOP):
            if not offered:
                break
            hello = self._accepted(
                self.exchange(self._hello(version, offered, self._all_groups(version))), version
            )
            if hello is None or hello.cipher_suite not in offered:
                break
            selected.append(hello.cipher_suite)
            offered.remove(hello.cipher_suite)
        return selected

    def enumerate_tls13_groups(self) -> list[int]:
        offered = self._all_groups(TLS13)
        selected: list[int] = []
        for _ in range(_MAX_LOOP):
            if not offered:
                break
            hello = self._accepted(
                self.exchange(self._hello(TLS13, list(TLS13_SUITES), offered)), TLS13
            )
            if hello is None or hello.group is None or hello.group not in offered:
                break
            selected.append(hello.group)
            offered.remove(hello.group)
        return selected

    def enumerate_legacy_groups(self, version: int, ecdhe_suites: list[int]) -> list[int]:
        offered = self._all_groups(version)
        selected: list[int] = []
        for _ in range(_MAX_LOOP):
            if not offered:
                break
            response = self.exchange(
                self._hello(version, ecdhe_suites, offered), until=SERVER_KEY_EXCHANGE
            )
            if self._accepted(response, version) is None or response.group not in offered:
                break
            assert response.group is not None  # noqa: S101 - narrowing only
            selected.append(response.group)
            offered.remove(response.group)
        return selected

    def legacy_details(self, version: int, suites: list[int]) -> Response:
        """One handshake up to ServerHelloDone: certificates and key exchange data."""
        return self.exchange(
            self._hello(version, suites, self._all_groups(version)), until=SERVER_HELLO_DONE
        )

    def run(self) -> TLSReport:
        report = TLSReport()
        try:
            self._run(report)
        except _BudgetExhaustedError:
            report.truncated = True
        return report

    def _run(self, report: TLSReport) -> None:
        for version in (TLS13, *LEGACY_VERSIONS):
            suites = self.enumerate_suites(version)
            if suites:
                report.suites[version] = suites

        if TLS13 in report.suites:
            report.groups[TLS13] = self.enumerate_tls13_groups()

        # Certificates and TLS ≤ 1.2 key exchange details are read once, at the
        # highest legacy version the server supports.
        legacy = next((v for v in LEGACY_VERSIONS if v in report.suites), None)
        if legacy is None:
            return
        suites = report.suites[legacy]
        report.certificates = self.legacy_details(legacy, suites).certificates
        ecdhe = [s for s in suites if is_ecdhe(s)]
        if ecdhe:
            report.groups[legacy] = self.enumerate_legacy_groups(legacy, ecdhe)
        dhe = [s for s in suites if is_dhe(s)]
        if dhe:
            bits = self.legacy_details(legacy, dhe).dh_bits
            if bits:
                report.dh_bits[legacy] = bits
