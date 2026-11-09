"""TLS code points and names: protocol versions, cipher suites, groups.

This module only maps wire values to names and splits cipher suite names into
their components. Whether a component is safe is decided by
``rules/algorithms.yaml``, never here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from pqc_scan.models import Algorithm, Primitive

# --- protocol versions ------------------------------------------------------

SSL3: Final = 0x0300
TLS10: Final = 0x0301
TLS11: Final = 0x0302
TLS12: Final = 0x0303
TLS13: Final = 0x0304

VERSION_NAMES: Final[dict[int, str]] = {
    SSL3: "SSLv3",
    TLS10: "TLSv1.0",
    TLS11: "TLSv1.1",
    TLS12: "TLSv1.2",
    TLS13: "TLSv1.3",
}

# --- cipher suites ----------------------------------------------------------

TLS13_SUITES: Final[dict[int, str]] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}

# Suites for SSL 3.0 … TLS 1.2. PSK and SRP suites are left out on purpose:
# they need a pre-shared secret and are not offered to anonymous clients.
LEGACY_SUITES: Final[dict[int, str]] = {
    # ECDHE + ECDSA
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    0xC0AF: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC05C: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xC05D: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xC072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    # ECDHE + RSA
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    # DHE + RSA
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x009A: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    # DHE + DSS
    0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    # Static ECDH
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    # RSA key transport
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM",
    0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
    0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    # Anonymous (no authentication at all)
    0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
}

SUITE_NAMES: Final[dict[int, str]] = {**TLS13_SUITES, **LEGACY_SUITES}


def suite_name(code: int) -> str:
    """IANA name of a cipher suite, or its hex code if unknown."""
    return SUITE_NAMES.get(code, f"0x{code:04X}")


# --- groups -----------------------------------------------------------------


@dataclass(frozen=True)
class Group:
    code: int
    name: str
    key_size: int | None = None
    curve: str | None = None


_GROUP_LIST: Final = (
    # Hybrid and pure post-quantum (draft-ietf-tls-ecdhe-mlkem, draft-connolly-tls-mlkem)
    Group(0x11EC, "X25519MLKEM768"),
    Group(0x11EB, "SecP256r1MLKEM768"),
    Group(0x11ED, "SecP384r1MLKEM1024"),
    Group(0x6399, "X25519Kyber768Draft00"),
    Group(0x0200, "ML-KEM-512"),
    Group(0x0201, "ML-KEM-768"),
    Group(0x0202, "ML-KEM-1024"),
    # Classical elliptic curves
    Group(0x001D, "X25519"),
    Group(0x001E, "X448"),
    Group(0x0017, "ECDH", 256, "secp256r1"),
    Group(0x0018, "ECDH", 384, "secp384r1"),
    Group(0x0019, "ECDH", 521, "secp521r1"),
    Group(0x0016, "ECDH", 256, "secp256k1"),
    Group(0x0015, "ECDH", 224, "secp224r1"),
    Group(0x0013, "ECDH", 192, "secp192r1"),
    Group(0x001A, "ECDH", 256, "brainpoolP256r1"),
    Group(0x001B, "ECDH", 384, "brainpoolP384r1"),
    Group(0x001C, "ECDH", 512, "brainpoolP512r1"),
    # Finite-field Diffie-Hellman (RFC 7919)
    Group(0x0100, "DH", 2048, None),
    Group(0x0101, "DH", 3072, None),
    Group(0x0102, "DH", 4096, None),
    Group(0x0103, "DH", 6144, None),
    Group(0x0104, "DH", 8192, None),
)

GROUPS: Final[dict[int, Group]] = {group.code: group for group in _GROUP_LIST}

_FFDHE_LABEL: Final = {0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
                       0x0103: "ffdhe6144", 0x0104: "ffdhe8192"}  # fmt: skip


def group_label(code: int) -> str:
    """Human-readable group name for evidence text."""
    group = GROUPS.get(code)
    if group is None:
        return f"0x{code:04X}"
    return group.curve or _FFDHE_LABEL.get(code) or group.name


def group_algorithm(code: int) -> Algorithm:
    """The key-exchange algorithm behind a group code."""
    group = GROUPS.get(code)
    if group is None:
        return Algorithm(raw_name=f"TLS group 0x{code:04X}", primitive=Primitive.KEY_EXCHANGE)
    return Algorithm(
        raw_name=group.name,
        primitive=Primitive.KEY_EXCHANGE,
        key_size=group.key_size,
        curve=group.curve,
    )


# --- cipher suite components --------------------------------------------------

_LEGACY_SUITE_RE: Final = re.compile(
    r"TLS_(?P<kx>[A-Za-z0-9_]+?)_WITH_(?P<cipher>[A-Z0-9_]+?)(?:_(?P<mac>SHA|SHA256|SHA384|MD5))?"
)
_TLS13_SUITE_RE: Final = re.compile(r"TLS_(?P<cipher>[A-Z0-9_]+)_(?P<hash>SHA256|SHA384)")

_KEX_NAMES: Final = {"ECDHE": "ECDHE", "DHE": "DHE", "ECDH": "ECDH", "DH": "DH", "RSA": "RSA"}
_AUTH_NAMES: Final = {"RSA": "RSA", "ECDSA": "ECDSA", "DSS": "DSA", "anon": "anon"}
_MAC_NAMES: Final = {"SHA": "HMAC-SHA1", "SHA256": "HMAC-SHA256", "SHA384": "HMAC-SHA384",
                     "MD5": "HMAC-MD5"}  # fmt: skip


@dataclass(frozen=True)
class SuiteComponent:
    """One part of a cipher suite, e.g. the key exchange."""

    role: str  # key_exchange | authentication | cipher | mac
    algorithm: Algorithm


def _cipher_algorithm(name: str) -> Algorithm:
    if name.startswith("RC4"):
        primitive = Primitive.STREAM_CIPHER
    elif any(mode in name for mode in ("GCM", "CCM", "POLY1305")):
        primitive = Primitive.AEAD
    else:
        primitive = Primitive.BLOCK_CIPHER
    return Algorithm(raw_name=name, primitive=primitive)


def suite_components(name: str) -> list[SuiteComponent]:
    """Split an IANA cipher suite name into its algorithms.

    ``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`` → key exchange ``ECDHE``,
    authentication ``RSA``, cipher ``AES_128_GCM`` (the trailing hash is the
    PRF of an AEAD suite and is not reported). CBC and stream suites also get
    their HMAC. TLS 1.3 suites only name the cipher. Unknown shapes give an
    empty list.
    """
    legacy = _LEGACY_SUITE_RE.fullmatch(name)
    if legacy:
        kx_parts = legacy["kx"].replace("_EXPORT", "").split("_")
        kex = _KEX_NAMES.get(kx_parts[0])
        auth = _AUTH_NAMES.get(kx_parts[1] if len(kx_parts) > 1 else kx_parts[0])
        if kex is None or auth is None:
            return []
        cipher = _cipher_algorithm(legacy["cipher"])
        parts = [
            SuiteComponent(
                "key_exchange", Algorithm(raw_name=kex, primitive=Primitive.KEY_EXCHANGE)
            ),
            SuiteComponent(
                "authentication", Algorithm(raw_name=auth, primitive=Primitive.SIGNATURE)
            ),
            SuiteComponent("cipher", cipher),
        ]
        mac = legacy["mac"]
        if mac and cipher.primitive is not Primitive.AEAD:
            mac_algorithm = Algorithm(raw_name=_MAC_NAMES[mac], primitive=Primitive.MAC)
            parts.append(SuiteComponent("mac", mac_algorithm))
        return parts
    modern = _TLS13_SUITE_RE.fullmatch(name)
    if modern:
        return [SuiteComponent("cipher", _cipher_algorithm(modern["cipher"]))]
    return []


def is_ecdhe(code: int) -> bool:
    return "_ECDHE_" in SUITE_NAMES.get(code, "")


def is_dhe(code: int) -> bool:
    return "_DHE_" in SUITE_NAMES.get(code, "")
