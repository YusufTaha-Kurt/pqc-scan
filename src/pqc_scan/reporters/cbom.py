"""CycloneDX 1.6 Cryptography Bill of Materials (CBOM).

Mapping of a :class:`~pqc_scan.models.ScanResult`:

* every distinct algorithm (canonical id + primitive + key size/curve) →
  ``cryptographic-asset`` component, ``assetType: algorithm``;
* every protocol version seen (TLS/SSH) → ``assetType: protocol``;
* certificates → ``assetType: certificate`` with references to their
  public-key and signature algorithms;
* key files → ``assetType: related-crypto-material`` (type, size, algorithm);
* source files → ``file`` components; TLS/SSH endpoints → services;
* each asset *depends on* the algorithms it uses.

pqc-scan's verdict is attached as properties (``pqc-scan:risk``,
``pqc-scan:reason``). ``nistQuantumSecurityLevel`` is 0 for algorithms a
quantum computer breaks. Needs the optional ``[report]`` extra.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Final

from cyclonedx.model import Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesType,
    RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialType,
)
from cyclonedx.model.service import Service
from cyclonedx.output.json import JsonV1Dot6

from pqc_scan.models import Asset, AssetKind, Finding, Primitive, RiskClass, ScanResult

_PRIMITIVES: Final = {
    Primitive.KEY_EXCHANGE: CryptoPrimitive.KEY_AGREE,
    Primitive.KEM: CryptoPrimitive.KEM,
    Primitive.SIGNATURE: CryptoPrimitive.SIGNATURE,
    Primitive.PUBLIC_KEY_ENCRYPTION: CryptoPrimitive.PKE,
    Primitive.BLOCK_CIPHER: CryptoPrimitive.BLOCK_CIPHER,
    Primitive.STREAM_CIPHER: CryptoPrimitive.STREAM_CIPHER,
    Primitive.AEAD: CryptoPrimitive.AE,
    Primitive.HASH: CryptoPrimitive.HASH,
    Primitive.MAC: CryptoPrimitive.MAC,
    Primitive.KDF: CryptoPrimitive.KDF,
}

# NIST PQC security categories (1 = AES-128 strength … 5 = AES-256 strength).
_NIST_LEVELS: Final = {
    "ml-kem": None,  # depends on the parameter set, see _PARAMETER_LEVELS
    "ml-dsa": None,
    "slh-dsa": 1,
    "aes-128": 1,
    "aes-192": 3,
    "aes-256": 5,
    "sha256": 2,
    "sha384": 4,
    "sha512": 5,
    "sha3": 2,
}
_PARAMETER_LEVELS: Final = {
    "mlkem512": 1,
    "mlkem768": 3,
    "mlkem1024": 5,
    "mldsa44": 2,
    "mldsa65": 3,
    "mldsa87": 5,
}
_SLUG: Final = re.compile(r"[^a-z0-9]+")


def _slug(*parts: object) -> str:
    return "-".join(_SLUG.sub("-", str(p).lower()).strip("-") for p in parts if p not in (None, ""))


def _quantum_level(finding: Finding) -> int | None:
    if finding.risk in (RiskClass.BROKEN, RiskClass.VULNERABLE):
        return 0
    key = re.sub(r"[^a-z0-9]", "", finding.algorithm.raw_name.lower())
    if key in _PARAMETER_LEVELS:
        return _PARAMETER_LEVELS[key]
    return _NIST_LEVELS.get(finding.algorithm_id or "")


def _properties(finding: Finding) -> list[Property]:
    found = [
        Property(name="pqc-scan:risk", value=finding.risk.value),
        Property(name="pqc-scan:reason", value=finding.reason),
    ]
    if finding.recommendation:
        found.append(Property(name="pqc-scan:recommendation", value=finding.recommendation))
    return found


def _algorithm_key(finding: Finding) -> str:
    a = finding.algorithm
    return _slug(finding.algorithm_id or a.raw_name, a.primitive.value, a.key_size, a.curve)


def _algorithm_component(finding: Finding, ref: str) -> Component:
    a = finding.algorithm
    if a.primitive is Primitive.PROTOCOL:
        protocol = (
            ProtocolPropertiesType.SSH
            if a.raw_name.upper().startswith("SSH")
            else (ProtocolPropertiesType.TLS)
        )
        version = re.sub(r"^(TLS|SSL|SSH)v?", "", a.raw_name, flags=re.IGNORECASE)
        crypto = CryptoProperties(
            asset_type=CryptoAssetType.PROTOCOL,
            protocol_properties=ProtocolProperties(type=protocol, version=version or None),
        )
    else:
        crypto = CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=AlgorithmProperties(
                primitive=_PRIMITIVES.get(a.primitive, CryptoPrimitive.OTHER),
                parameter_set_identifier=str(a.key_size) if a.key_size else None,
                curve=a.curve,
                nist_quantum_security_level=_quantum_level(finding),
            ),
        )
    name = a.raw_name if not a.key_size or a.curve else f"{a.raw_name}-{a.key_size}"
    return Component(
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        name=name if not a.curve else f"{a.raw_name} {a.curve}",
        bom_ref=ref,
        crypto_properties=crypto,
        properties=_properties(finding),
    )


def _timestamp(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _asset_component(
    asset: Asset, ref: str, findings: list[Finding], algorithm_refs: dict[str, BomRef]
) -> Component | Service:
    worst = RiskClass.worst([f.risk for f in findings])
    properties = [Property(name="pqc-scan:worst-risk", value=worst.value)] if worst else []
    properties.append(Property(name="pqc-scan:location", value=asset.location))

    def ref_for(suffix: str) -> BomRef | None:
        match = next((f for f in findings if f.usage.endswith(suffix)), None)
        return algorithm_refs[_algorithm_key(match)] if match else None

    if asset.kind in (AssetKind.TLS_ENDPOINT, AssetKind.SSH_ENDPOINT):
        return Service(
            name=asset.location,
            bom_ref=ref,
            endpoints=[XsUri(asset.id)],
            properties=properties,
        )
    if asset.kind in (AssetKind.CERTIFICATE, AssetKind.CERTIFICATE_REQUEST):
        crypto = CryptoProperties(
            asset_type=CryptoAssetType.CERTIFICATE,
            certificate_properties=CertificateProperties(
                subject_name=asset.details.get("subject"),
                issuer_name=asset.details.get("issuer"),
                not_valid_before=_timestamp(asset.details.get("not_before")),
                not_valid_after=_timestamp(asset.details.get("not_after")),
                signature_algorithm_ref=ref_for(".signature"),
                subject_public_key_ref=ref_for(".public_key"),
                certificate_format="X.509",
            ),
        )
        return Component(
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            name=asset.location,
            bom_ref=ref,
            crypto_properties=crypto,
            properties=properties,
        )
    if asset.kind in (AssetKind.PRIVATE_KEY, AssetKind.PUBLIC_KEY):
        key = findings[0] if findings else None
        material = (
            RelatedCryptoMaterialType.PRIVATE_KEY
            if asset.kind is AssetKind.PRIVATE_KEY
            else RelatedCryptoMaterialType.PUBLIC_KEY
        )
        crypto = CryptoProperties(
            asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
            related_crypto_material_properties=RelatedCryptoMaterialProperties(
                type=material,
                size=key.algorithm.key_size if key else None,
                algorithm_ref=algorithm_refs[_algorithm_key(key)] if key else None,
            ),
        )
        return Component(
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            name=asset.location,
            bom_ref=ref,
            crypto_properties=crypto,
            properties=properties,
        )
    return Component(
        type=ComponentType.FILE, name=asset.location, bom_ref=ref, properties=properties
    )


def build_bom(result: ScanResult) -> Bom:
    digest = hashlib.sha256(result.model_dump_json().encode()).hexdigest()
    bom = Bom(serial_number=uuid.UUID(digest[:32]))
    bom.metadata.timestamp = result.finished_at
    bom.metadata.tools.components.add(
        Component(type=ComponentType.APPLICATION, name="pqc-scan", version=result.tool_version)
    )

    algorithm_components: dict[str, Component] = {}
    for finding in result.findings:
        key = _algorithm_key(finding)
        if key not in algorithm_components:
            algorithm_components[key] = _algorithm_component(finding, f"crypto/{key}")
    algorithm_refs = {key: component.bom_ref for key, component in algorithm_components.items()}
    for component in algorithm_components.values():
        bom.components.add(component)

    by_asset: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        by_asset[finding.asset.id].append(finding)
    for index, asset in enumerate(result.assets):
        findings = by_asset.get(asset.id, [])
        node = _asset_component(asset, f"asset/{index}", findings, algorithm_refs)
        if isinstance(node, Service):
            bom.services.add(node)
        else:
            bom.components.add(node)
        depends = {_algorithm_key(f) for f in findings}
        bom.register_dependency(node, [algorithm_components[k] for k in sorted(depends)])
    return bom


def render(result: ScanResult) -> str:
    """The CBOM as CycloneDX 1.6 JSON."""
    return str(JsonV1Dot6(build_bom(result)).output_as_string(indent=2)) + "\n"
