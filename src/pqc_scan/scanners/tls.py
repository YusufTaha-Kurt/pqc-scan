"""Report the cryptography a TLS endpoint offers.

For each ``host[:port]`` target the scanner reports:

* supported protocol versions (SSL 3.0 … TLS 1.3),
* the components of every accepted cipher suite, per version,
* supported key-exchange groups, including hybrid post-quantum groups,
* DHE parameter size,
* the certificate chain (public keys and signatures).

Discovery is done by :mod:`pqc_scan.scanners.tls_probe` (passive, no
completed handshake). The certificate of a TLS 1.3-only server is encrypted
on the wire, so it is fetched with one ordinary handshake through the
standard :mod:`ssl` module; no application data is sent.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections import defaultdict

from cryptography import x509

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
from pqc_scan.scanners.certs import PARSE_ERRORS, certificate_observations
from pqc_scan.scanners.tls_names import (
    VERSION_NAMES,
    group_algorithm,
    group_label,
    suite_components,
    suite_name,
)
from pqc_scan.scanners.tls_probe import TLSProber, TLSReport

DEFAULT_PORT = 443


def parse_target(target: str) -> tuple[str, int]:
    """Split ``host``, ``host:port``, ``[v6]:port`` or ``https://host/…``."""
    text = target.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    port_text = ""
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest:
            if not rest.startswith(":"):
                raise ScanTargetError(ErrorKind.INVALID_TARGET, "malformed IPv6 target")
            port_text = rest[1:]
    elif text.count(":") == 1:
        host, port_text = text.split(":")
    else:
        host = text  # a name, an IPv4 address or a bare IPv6 address
    if not host:
        raise ScanTargetError(ErrorKind.INVALID_TARGET, "missing host")
    if not port_text:
        return host, DEFAULT_PORT
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise ScanTargetError(ErrorKind.INVALID_TARGET, f"invalid port {port_text!r}")
    return host, int(port_text)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _display(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def fetch_certificates(
    host: str, port: int, timeout: float, server_name: str | None
) -> list[bytes]:
    """The server's certificate chain via one ordinary handshake (DER, leaf first).

    Verification is disabled on purpose: we want to *see* the certificate,
    including self-signed or expired ones. Returns an empty list on failure.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Inventory, not trust: we read the certificate and send no data.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=server_name) as tls,
        ):
            chain = getattr(tls, "get_unverified_chain", None)  # Python 3.13+
            if chain is not None:
                certificates = [bytes(c) for c in chain()]
                if certificates:
                    return certificates
            leaf = tls.getpeercert(binary_form=True)
            return [leaf] if leaf else []
    except (OSError, ssl.SSLError, ValueError):
        return []


class TLSScanner(Scanner):
    """Probe TLS endpoints for versions, cipher suites, groups and certificates."""

    name = "tls"

    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        host, port = parse_target(target)
        server_name = None if _is_ip(host) else host
        report = TLSProber(host, port, config.timeout, server_name).run()
        if not report.suites:
            raise ScanTargetError(ErrorKind.PARSE, "no TLS handshake response")
        certificates = report.certificates
        if not certificates:
            certificates = fetch_certificates(host, port, config.timeout, server_name)
        return self._observations(_display(host, port), report, certificates)

    def _observations(
        self, location: str, report: TLSReport, certificates: list[bytes]
    ) -> list[Observation]:
        endpoint = Asset(id=f"tls://{location}", kind=AssetKind.TLS_ENDPOINT, location=location)
        found: list[Observation] = []

        def add(
            asset: Asset,
            usage: str,
            algorithm: Algorithm,
            detail: str = "",
            confidence: Confidence = Confidence.HIGH,
        ) -> None:
            found.append(
                Observation(
                    asset=asset,
                    algorithm=algorithm,
                    usage=usage,
                    scanner=self.name,
                    evidence=Evidence(detail=detail),
                    confidence=confidence,
                )
            )

        for version, suites in report.suites.items():
            version_name = VERSION_NAMES[version]
            add(
                endpoint,
                "tls.protocol",
                Algorithm(raw_name=version_name, primitive=Primitive.PROTOCOL),
            )
            # One observation per distinct component; the detail lists the suites using it.
            users: dict[tuple[str, Algorithm], list[str]] = defaultdict(list)
            for code in suites:
                name = suite_name(code)
                for component in suite_components(name):
                    users[(component.role, component.algorithm)].append(name)
            for (role, algorithm), names in users.items():
                add(
                    endpoint,
                    f"tls.cipher_suite.{role}",
                    algorithm,
                    f"{version_name}: {', '.join(names)}",
                )

        for version, groups in report.groups.items():
            version_name = VERSION_NAMES[version]
            for rank, code in enumerate(groups, start=1):
                detail = f"{version_name}: {group_label(code)} (selected #{rank})"
                add(endpoint, "tls.key_exchange_group", group_algorithm(code), detail)

        for version, bits in report.dh_bits.items():
            algorithm = Algorithm(raw_name="DH", primitive=Primitive.KEY_EXCHANGE, key_size=bits)
            add(endpoint, "tls.dh_parameters", algorithm, VERSION_NAMES[version])

        for index, der in enumerate(certificates):
            try:
                cert = x509.load_der_x509_certificate(der)
            except PARSE_ERRORS:
                continue
            asset = Asset(
                id=f"tls://{location}#cert-{index}", kind=AssetKind.CERTIFICATE, location=location
            )
            detail = "leaf certificate" if index == 0 else f"chain certificate {index}"
            for usage, algorithm, confidence in certificate_observations(cert, "tls.certificate"):
                add(asset, usage, algorithm, detail, confidence)
        return found
