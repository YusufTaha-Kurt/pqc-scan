"""Scan real OpenSSL >= 3.5 and OpenSSH >= 10 servers (hybrid post-quantum).

Skipped unless PQC_INTEROP_TLS=host:port points at a running server, e.g.
the container started by the CI job "interop" (see .github/workflows/ci.yml):

    docker run -d -p 8443:8443 -v "$PWD/certs:/certs:ro" -v "$PWD/tests/interop:/app:ro" \\
        python:3.13-slim-trixie python /app/tls_server.py /certs/cert.pem /certs/key.pem 8443
    PQC_INTEROP_TLS=127.0.0.1:8443 pytest tests/interop
"""

from __future__ import annotations

import os

import pytest

from pqc_scan.engine import ScanJob, run_scan
from pqc_scan.models import RiskClass, ScanConfig
from pqc_scan.scanners.tls import TLSScanner

TARGET = os.environ.get("PQC_INTEROP_TLS")


@pytest.mark.skipif(not TARGET, reason="set PQC_INTEROP_TLS=host:port to run")
def test_hybrid_group_detected_on_real_openssl() -> None:
    assert TARGET is not None
    result = run_scan([ScanJob(TLSScanner(), TARGET)], ScanConfig(timeout=5))
    assert result.errors == []
    groups = {
        f.algorithm.raw_name: (f.risk, f.evidence.detail)
        for f in result.findings
        if f.usage == "tls.key_exchange_group"
    }
    assert groups["X25519MLKEM768"][0] == RiskClass.HYBRID
    assert groups["X25519MLKEM768"][1].startswith("TLSv1.3")
    protocols = {f.algorithm.raw_name for f in result.findings if f.usage == "tls.protocol"}
    assert "TLSv1.3" in protocols
    assert any(f.usage == "tls.certificate.public_key" for f in result.findings)


SSH_TARGET = os.environ.get("PQC_INTEROP_SSH")


@pytest.mark.skipif(not SSH_TARGET, reason="set PQC_INTEROP_SSH=host:port to run")
def test_openssh_10_offers_mlkem_hybrid() -> None:
    from pqc_scan.scanners.ssh import SSHScanner

    assert SSH_TARGET is not None
    result = run_scan([ScanJob(SSHScanner(), SSH_TARGET)], ScanConfig(timeout=5))
    assert result.errors == []
    kex = {f.algorithm.raw_name: f.risk for f in result.findings if f.usage == "ssh.key_exchange"}
    assert kex["mlkem768x25519-sha256"] == RiskClass.HYBRID
    protocols = {f.algorithm.raw_name for f in result.findings if f.usage == "ssh.protocol"}
    assert protocols == {"SSHv2"}
    host_keys = {f.algorithm.raw_name for f in result.findings if f.usage == "ssh.host_key"}
    assert "ssh-ed25519" in host_keys
