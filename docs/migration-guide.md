# Post-quantum migration guide

pqc-scan tells you **where** quantum-vulnerable cryptography is. This guide
collects **what to change**, ordered by what usually matters first. Each
finding in a report also carries a one-line recommendation from
`rules/algorithms.yaml`.

> Always test configuration changes in staging first and keep a classical
> fallback during the transition: a hybrid key exchange still works with
> clients that do not support post-quantum algorithms.

## 1. Priorities

1. **Fix `BROKEN` first.** These are weak today, quantum or not: SSL 3.0,
   TLS 1.0/1.1, RC4, 3DES, export and anonymous cipher suites, MD5/SHA-1
   signatures, RSA/DSA/DH below 2048 bits, `ssh-rsa`/`ssh-dss` host keys.
2. **Key exchange before signatures.** Recorded traffic can be decrypted later
   ("harvest now, decrypt later"), so moving TLS and SSH key exchange to a
   hybrid ML-KEM group protects data *today*. Signatures only need to be safe
   when a quantum computer exists.
3. **Use Mosca's inequality to rank the rest** (`--mosca-x/-y/-z`): systems
   whose data must stay secret the longest go first.
4. **Symmetric crypto:** prefer AES-256 / ChaCha20-Poly1305 and SHA-384/512.

## 2. TLS (web servers, load balancers)

Goal: TLS 1.3 with the hybrid group `X25519MLKEM768` first, classical groups
as fallback; disable TLS ≤ 1.1.

**OpenSSL 3.5 or newer** knows `X25519MLKEM768` natively.

nginx (built against OpenSSL ≥ 3.5):

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;
```

Apache httpd (mod_ssl with OpenSSL ≥ 3.5):

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:secp256r1
```

Go (1.24 or newer): `X25519MLKEM768` is enabled by default when
`CurvePreferences` is left empty. If you set the list yourself, put it first:

```go
cfg := &tls.Config{
    MinVersion:       tls.VersionTLS12,
    CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
}
```

Verify with pqc-scan: `pqc-scan scan tls your.host` should list
`X25519MLKEM768` as `HYBRID`, selected first.

Certificates: post-quantum (ML-DSA) certificates are not yet accepted by
mainstream browsers. Keep RSA-2048+/ECDSA certificates for now, remove
SHA-1 and RSA-1024, and track your CA's ML-DSA plans.

## 3. SSH

OpenSSH 9.9 added `mlkem768x25519-sha256`; OpenSSH 10.0 makes it the default.
`sntrup761x25519-sha512` (hybrid, OpenSSH ≥ 9.0) is a good fallback.

`/etc/ssh/sshd_config`:

```
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
```

Remove `ssh-dss` and `ssh-rsa` host keys and any `diffie-hellman-group1-sha1`
or `-sha1` key exchange. Verify: `pqc-scan scan ssh your.host`.

## 4. Source code

| Found | Replace with |
| --- | --- |
| MD5 / SHA-1 for integrity or signatures | SHA-256 or better (SHA-384/512 preferred) |
| DES, 3DES, RC4, Blowfish, ECB mode | AES-256-GCM or ChaCha20-Poly1305 |
| RSA < 2048, DSA, DH < 2048 | at least RSA-3072 / X25519 now, then ML-KEM / ML-DSA |
| RSA/ECDH key exchange you control | hybrid X25519 + ML-KEM-768 |
| RSA/ECDSA signatures you control | plan ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) |
| JWT `none`, `HS*` with weak secrets | `ES256`/`EdDSA` now; follow JOSE ML-DSA work |
| TLS 1.0/1.1 pinned in code | let the library default (TLS 1.2+/1.3) |

Library support (check your exact version):

- **Python:** recent `cryptography` releases provide `mlkem` and `mldsa`
  modules (pqc-scan's tests use them).
- **Java:** JDK 24 added ML-KEM (`KeyPairGenerator.getInstance("ML-KEM")`,
  JEP 496) and ML-DSA (JEP 497).
- **Go:** `crypto/mlkem` (Go 1.24) and hybrid TLS by default.
- **OpenSSL:** 3.5 adds ML-KEM, ML-DSA and SLH-DSA.

## 5. Keys and certificates in repositories

Private keys do not belong in a repository at all, quantum or not: rotate any
key pqc-scan finds there, and move it to a secret store. For the rest, plan
rotation dates together with the algorithm change.

## 6. Keep it from coming back

Run pqc-scan in CI (see the GitHub Action in the README): `--fail-on BROKEN`
blocks weak crypto outright, and `pqc-scan diff` flags anything *new* in a
pull request.
