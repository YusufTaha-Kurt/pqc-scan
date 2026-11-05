# pqc-scan

**Find quantum-vulnerable cryptography in your endpoints and code, and plan
your post-quantum migration.**

> ⚠️ **Status: pre-alpha.** The project is being built in the open. The
> `files` and `tls` scanners and the `console`/`json` reports work today; the
> other scanners are in progress. See [`TASKS.md`](TASKS.md) for progress.

> ⚠️ **Authorised use only.** Only scan systems you own or have written
> permission to test. `pqc-scan` performs passive discovery: it reads handshake
> metadata, never logs in, never guesses passwords and never attempts
> exploitation.

## Why

A large enough quantum computer will break RSA, elliptic-curve cryptography and
Diffie–Hellman (Shor's algorithm), and weaken symmetric keys (Grover's
algorithm). Data recorded today can be decrypted later ("harvest now, decrypt
later"). Migrating to the NIST post-quantum standards — ML-KEM (FIPS 203),
ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) — starts with knowing where classical
cryptography is used.

`pqc-scan` builds that **cryptographic inventory**.

## What it scans

| Scanner | Input                 | Finds                                                                  |
| ------- | --------------------- | ---------------------------------------------------------------------- |
| `tls`   | `host:port`           | Protocol versions, cipher suites, key-exchange groups (incl. hybrid PQ such as `X25519MLKEM768`), certificate keys and signatures |
| `ssh`   | `host:port`           | Key-exchange and host-key algorithms (e.g. `mlkem768x25519-sha256`)    |
| `code`  | Local directory       | Crypto API usage in Python, Java (later JS/TS, Go)                     |
| `files` | Local directory       | PEM/DER certificates and keys, SSH public keys                         |

Private key **contents are never reported** — only path, type and size.

## Risk classes

| Class        | Meaning                                         | Examples                                  |
| ------------ | ----------------------------------------------- | ----------------------------------------- |
| `BROKEN`     | Weak even without a quantum computer            | MD5, SHA-1 signatures, RC4, 3DES, TLS 1.0, RSA < 2048 |
| `VULNERABLE` | Broken by Shor's algorithm                      | RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA |
| `WEAKENED`   | Security margin halved by Grover's algorithm    | AES-128                                   |
| `UNKNOWN`    | Not in the rule set; needs manual review        |                                           |
| `HYBRID`     | Classical and post-quantum combined             | X25519MLKEM768                            |
| `PQ_SAFE`    | Considered quantum resistant                    | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384 |

## Installation

```bash
pip install -e ".[dev]"      # development install (PyPI release planned for v0.2)
```

Optional extras: `[code]` (Semgrep), `[report]` (HTML and
CycloneDX CBOM), `[all]`.

## Usage

Available now:

```bash
pqc-scan scan files ./my-repo                          # table in the terminal
pqc-scan scan files ./my-repo -f json -o report.json   # machine-readable report
pqc-scan scan files ./my-repo --fail-on VULNERABLE     # CI gate: exit 1 if found
pqc-scan scan files --targets paths.txt --exclude "*.test.pem"
pqc-scan scan tls example.com mail.example.com:465     # TLS endpoints you are allowed to scan
pqc-scan report report.json                            # re-render a saved report
```

The TLS scanner needs no extra dependency: a small pure-Python probe asks the
server which versions, cipher suites and key-exchange groups it accepts —
including hybrid post-quantum groups such as `X25519MLKEM768` — and closes
the connection without completing the handshake.

Optional migration-urgency score ([Mosca's inequality](docs/architecture.md#7-mosca-priority-moscapy)).
You supply all three values; the tool never assumes a quantum timeline:

```bash
pqc-scan scan files ./my-repo --mosca-x 10 --mosca-y 5 --mosca-z 12
```

Planned for v0.1:

```bash
pqc-scan scan code ./my-repo --fail-on VULNERABLE
```

The JSON report follows [`docs/schema/scan-result.schema.json`](docs/schema/scan-result.schema.json).

Exit codes: `0` success · `1` `--fail-on` threshold reached · `2` usage error ·
`3` every target failed.

## Documentation

- [System definition](docs/architecture.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

[Apache-2.0](LICENSE)
