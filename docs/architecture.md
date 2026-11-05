# pqc-scan — System Definition (v0.1 draft)

> Status: **accepted for v0.1**. Items marked **[D-n]** refer to the decision
> log in [`TASKS.md`](../TASKS.md#kararlar). When a decision changes, update this
> document and `CLAUDE.md` together.

## 1. Purpose

`pqc-scan` is a passive, read-only command-line tool that builds a
**cryptographic inventory** of network endpoints and code repositories,
classifies every observed algorithm by its quantum risk, and reports the result
as console output, JSON, HTML, or a CycloneDX CBOM.

It answers three questions for every asset:

1. Which cryptographic algorithm is used, with which parameters?
2. How exposed is it to a cryptographically relevant quantum computer (CRQC)?
3. How urgent is migration (optional Mosca score)?

### Non-goals

Active attacks, exploitation, password guessing, authenticated scanning, and
binary analysis are out of scope. The tool never logs in and never reports the
contents of private key material.

## 2. High-level data flow

```
            ┌──────────────┐
 CLI args ─►│   cli.py     │  parse targets, options, build ScanConfig
            └──────┬───────┘
                   ▼
            ┌──────────────┐   per target, bounded concurrency, timeouts
            │  engine.py   │──────────────────────────────────────────┐
            └──────┬───────┘                                          │
                   ▼                                                  │
   ┌────────┬──────┴──┬─────────┐                                     │
   ▼        ▼         ▼         ▼                                     │
 tls.py   ssh.py   code.py   files.py   Scanner implementations       │
   │        │         │         │       (no knowledge of risk/report) │
   └────────┴────┬────┴─────────┘                                     │
                 ▼  Observation[]                    exceptions ──────┤
          ┌──────────────┐                                            ▼
          │ classify.py  │◄── rules/algorithms.yaml            ScanError[]
          └──────┬───────┘
                 ▼  Finding[]
          ┌──────────────┐
          │  mosca.py    │  optional, only when x/y/z are provided
          └──────┬───────┘
                 ▼
            ScanResult ──► reporters/{console,json_report,html_report,cbom}.py
```

Layering rules (from `CLAUDE.md` §6):

- Scanners know nothing about risk classes or report formats.
- `classify.py` is the only place that maps an algorithm to a risk class, and it
  reads its rules from `rules/algorithms.yaml`.
- Reporters consume only `ScanResult`.
- A failing target never aborts the run; it becomes a `ScanError`.

## 3. Data model (`models.py`)

All models are pydantic v2, frozen (`model_config = ConfigDict(frozen=True)`),
and serialisable to JSON without custom encoders.

### 3.1 `RiskClass`

`StrEnum`, ordered from most to least severe. The order is used for sorting,
for `--fail-on`, and for resolving multiple matching rules (worst wins).

| Order | Value        | Meaning                                              |
| ----- | ------------ | ---------------------------------------------------- |
| 1     | `BROKEN`     | Already weak classically (MD5, RC4, RSA < 2048, …)   |
| 2     | `VULNERABLE` | Breakable by Shor (RSA, ECDSA, ECDH, DH, DSA, …)     |
| 3     | `WEAKENED`   | Security margin halved by Grover (AES-128, …)        |
| 4     | `UNKNOWN`    | Not covered by the rule set — needs manual review **[D-3]** |
| 5     | `HYBRID`     | Classical + PQ combined (X25519MLKEM768, …)          |
| 6     | `PQ_SAFE`    | Considered quantum resistant (ML-KEM, ML-DSA, …)     |

### 3.2 `Primitive`

`StrEnum`: `key_exchange`, `kem`, `signature`, `public_key_encryption`,
`block_cipher`, `stream_cipher`, `aead`, `hash`, `mac`, `kdf`, `protocol`.

The primitive matters for classification: SHA-1 in a signature is `BROKEN`,
SHA-1 inside HMAC is not.

### 3.3 `Algorithm`

An algorithm exactly as a scanner observed it. Canonicalisation is
`classify`'s job, so this model carries no canonical name.

| Field        | Type          | Notes                                                    |
| ------------ | ------------- | -------------------------------------------------------- |
| `raw_name`   | `str`         | Exactly as observed (e.g. `rsa-sha2-512`, `AES_128_GCM`) |
| `primitive`  | `Primitive`   |                                                          |
| `key_size`   | `int \| None` | Bits, when meaningful                                    |
| `curve`      | `str \| None` | e.g. `secp256r1`, `Curve25519`                           |

### 3.4 `Asset`

| Field      | Type        | Notes                                                       |
| ---------- | ----------- | ----------------------------------------------------------- |
| `id`       | `str`       | Stable URI-like id, used for de-duplication and CBOM `bom-ref`: `tls://host:443`, `ssh://host:22`, `file:///abs/path`, `code:///abs/path` |
| `kind`     | `AssetKind` | `tls_endpoint`, `ssh_endpoint`, `certificate`, `certificate_request`, `private_key`, `public_key`, `source_file` |
| `location` | `str`       | Human readable (host:port or relative path)                 |

### 3.5 `Observation` (scanner output) **[D-1]**

What a scanner saw, before classification.

| Field        | Type                   | Notes                                                 |
| ------------ | ---------------------- | ----------------------------------------------------- |
| `asset`      | `Asset`                |                                                       |
| `algorithm`  | `Algorithm`            | Raw observation; one component per observation (composite names such as cipher suites are split by the scanner) |
| `usage`      | `str`                  | Dotted context, e.g. `tls.certificate.signature`, `tls.key_exchange`, `ssh.host_key`, `code.api_call` |
| `evidence`   | `Evidence`             | `line: int \| None`, `detail: str` — never secret material |
| `scanner`    | `str`                  | `tls`, `ssh`, `code`, `files`                         |
| `confidence` | `Confidence`           | `high` (protocol/file facts) · `medium`/`low` (code heuristics) |

### 3.6 `Finding`

`Observation` + classification:

| Field            | Type                 | Notes                                          |
| ---------------- | -------------------- | ---------------------------------------------- |
| *(all `Observation` fields)* |          |                                                |
| `id`             | `str`                | Deterministic hash of asset id + usage + algorithm + evidence, so diffs between runs are stable |
| `risk`           | `RiskClass`          |                                                |
| `algorithm_id`   | `str \| None`        | Canonical id from `algorithms.yaml`; `None` when unknown |
| `reason`         | `str`                | Which rule matched (e.g. `rsa: key_size < 2048`) |
| `recommendation` | `str \| None`        | From `algorithms.yaml` (e.g. "migrate to ML-DSA-65") |
| `mosca`          | `MoscaScore \| None` | Filled only when Mosca inputs are given        |

### 3.7 `ScanError`

| Field     | Type  | Notes                                                |
| --------- | ----- | ---------------------------------------------------- |
| `target`  | `str` |                                                      |
| `scanner` | `str` |                                                      |
| `kind`    | `str` | `timeout`, `connection_refused`, `dns`, `parse`, `permission`, `internal` |
| `message` | `str` |                                                      |

### 3.8 `ScanResult`

| Field            | Type               | Notes                                     |
| ---------------- | ------------------ | ----------------------------------------- |
| `schema_version` | `str`              | Starts at `"1"`; bump on breaking change  |
| `tool_version`   | `str`              |                                           |
| `started_at`     | `datetime` (UTC)   |                                           |
| `finished_at`    | `datetime` (UTC)   |                                           |
| `config`         | `ScanConfigSummary`| timeout, concurrency, scanners run, Mosca inputs |
| `assets`         | `list[Asset]`      | De-duplicated                             |
| `findings`       | `list[Finding]`    | Sorted by risk, then asset id             |
| `errors`         | `list[ScanError]`  |                                           |

Derived helpers (methods, not stored): `summary() -> dict[RiskClass, int]`,
`worst_risk() -> RiskClass | None`.

## 4. Scanner interface (`scanners/base.py`)

```python
class Scanner(ABC):
    name: ClassVar[str]

    @abstractmethod
    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        """Scan one target. Raise ScanTargetError on target-level failure."""
```

- One call = one target (one `host:port` or one root path). The engine handles
  fan-out, concurrency limits, and converts exceptions to `ScanError`.
- Network scanners must honour `config.timeout` on every socket operation.
- Concurrency model: a `ThreadPoolExecutor` with
  `max_workers=config.concurrency` **[D-4]**.

`ScanConfig` defaults (conservative, per `CLAUDE.md` §6):
`timeout=5.0` seconds, `concurrency=10`, `follow_symlinks=False`,
`max_file_size=1 MiB` (code/files), standard exclude list
(`.git`, `node_modules`, `.venv`, `venv`, `dist`, `build`, `__pycache__`).

## 5. Scanners

### 5.1 `files`

Walk a directory and parse:

- PEM blocks (certificate, public key, private key, CSR) — one file may contain several.
- DER files by extension (`.der`, `.cer`, `.crt`) with content sniffing.
- OpenSSH public keys (`*.pub`, `authorized_keys`, `known_hosts`).
- OpenSSH private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`): report type and
  size only; never decrypt, never emit content. Encrypted keys are reported
  with `key_size=None` and a note.

Output usages: `file.certificate.public_key`, `file.certificate.signature`,
`file.certificate.signature_hash`, `file.csr.public_key`, `file.csr.signature`,
`file.csr.signature_hash`, `file.private_key`, `file.public_key`,
`file.ssh_public_key`.

Details:

- Detection is by content (`-----BEGIN `) first, then by file name/extension.
- The signer's key size is only reported for certificates that verifiably sign
  themselves (and for CSRs); for CA-issued certificates it is unknown.
- Keys that the installed `cryptography` cannot load are named from their
  public-key OID (ML-DSA, ML-KEM, SLH-DSA OIDs are known) with
  `confidence: medium`; unknown OIDs are reported verbatim and classify as
  `UNKNOWN`.
- Encrypted PKCS#8 keys are reported as `encrypted private key` (`UNKNOWN`);
  legacy encrypted PEM keys take their type from the PEM label.
- A file with several items gets one asset per item: `file:///path#block-<n>`
  (PEM) or `file:///path#line-<n>` (SSH key lists).
- Unreadable, oversized, non-regular and malformed files are skipped silently;
  only a missing or unusable root path is a `ScanError`.

### 5.2 `tls`

Per `host:port`:

- Supported protocol versions (SSLv2 … TLS 1.3).
- Accepted cipher suites per version.
- Supported key-exchange groups, **including hybrid PQ groups**
  (`X25519MLKEM768`, `SecP256r1MLKEM768`, …).
- Leaf and chain certificates: public key type/size, signature algorithm.

Implementation note **[D-2]**: `sslyze` covers versions, cipher suites and
certificates, but its bundled OpenSSL (via `nassl`) is not expected to offer
ML-KEM hybrid groups. Detecting PQ groups therefore needs a small, dedicated
probe that sends a hand-built TLS 1.3 ClientHello advertising one group at a
time and reads the `ServerHello` / `HelloRetryRequest`. This probe never
completes the handshake.

### 5.3 `ssh`

Per `host:port`: connect, exchange identification strings, read the server's
`SSH_MSG_KEXINIT` (sent in clear text), parse its name-lists
(KEX, host key, ciphers, MACs), then close. No authentication is attempted.

Implementation note **[D-5]**: reading KEXINIT with a ~150-line raw-socket
parser is simpler and fully passive; `paramiko` would try to negotiate and fails
on servers that only offer algorithms it does not support (e.g.
`mlkem768x25519-sha256`).

### 5.4 `code`

- Semgrep rules in `rules/semgrep/` for Python and Java (v0.1), JS/TS and Go
  (v0.2). Each rule's metadata names the canonical algorithm and primitive so
  the scanner can build an `Observation` without interpreting messages.
- A Python-AST fallback for Python files when Semgrep is unavailable **[D-6]**.
- Detects: RSA/EC/DH/DSA key generation and usage, weak hashes (MD5, SHA-1),
  weak ciphers (DES, 3DES, RC4, ECB mode), hard-coded key sizes.
- Evidence contains file path and line number only (and at most the matched
  API name), never the line's literal content, to avoid leaking embedded keys.

## 6. Classification (`classify.py` + `rules/algorithms.yaml`)

### 6.1 Rule file schema

```yaml
schema_version: 1
algorithms:
  - id: rsa
    name: RSA
    aliases: [RSA, rsaEncryption, rsa-sha2-256, rsa-sha2-512]
    primitives: [signature, public_key_encryption]
    default: VULNERABLE
    reason: "RSA is broken by Shor's algorithm at every key size"
    recommendation: "Migrate signatures to ML-DSA; key transport to ML-KEM."
    rules:
      - when: { key_size_lt: 2048 }
        risk: BROKEN
        reason: "RSA key shorter than 2048 bits"

  - id: sha1
    name: SHA-1
    aliases: [SHA1, hmac-sha1]
    primitives: [hash, mac]
    default: BROKEN
    reason: "SHA-1 collisions are practical"
    rules:
      - when: { primitive: [mac] }
        risk: WEAKENED   # TODO: doğrula
        reason: "HMAC-SHA1 is not affected by SHA-1 collisions"
```

### 6.2 Algorithm

1. Normalise `raw_name` (case-fold, strip separators) and look it up in the
   alias index; composite names (`ecdhe-rsa-aes128-gcm-sha256`,
   `sha256WithRSAEncryption`) are split into components by protocol-specific
   decoders inside the scanner, not inside `classify`.
2. Evaluate every `rules` entry whose `when` conditions all hold. If at least
   one matches, the **worst** matching rule wins; otherwise `default` applies.
   (Rules override the default, so a rule may also *lower* the risk, e.g.
   SHA-1 → `BROKEN` by default, HMAC-SHA1 → `WEAKENED`.)
3. Name not in the rule set → `UNKNOWN`.

Supported conditions: `key_size_lt`, `key_size_unknown`, `primitive`. A rule
with an empty `when` is rejected.
4. The YAML is validated at load time with a pydantic model; an invalid rule
   file is a startup error, and a unit test loads the shipped file.

## 7. Mosca priority (`mosca.py`)

Mosca's inequality: if `x + y > z`, data is at risk.

- `x` — years the data must stay confidential (user input).
- `y` — years needed to migrate (user input).
- `z` — years until a CRQC exists (user input; **no built-in default**, the
  tool must not assert a quantum timeline) **[D-7]**.

`MoscaScore = {x, y, z, margin = (x + y) - z, at_risk = margin > 0}`.
Computed only for `BROKEN`, `VULNERABLE`, `WEAKENED` and `UNKNOWN`
findings. Inputs come from CLI flags (global) and, later, from a per-asset
mapping file.

## 8. CLI (`cli.py`) **[D-8]**

```
pqc-scan scan tls   TARGET... [--targets FILE]
pqc-scan scan ssh   TARGET... [--targets FILE]
pqc-scan scan code  PATH
pqc-scan scan files PATH
pqc-scan scan all   [--targets FILE] [--path PATH]
pqc-scan report     RESULT.json --format {console,json,html,cbom} --out FILE
```

Common options for `scan`:

| Option                     | Default   | Notes                                     |
| -------------------------- | --------- | ----------------------------------------- |
| `--format`                 | `console` | `console`, `json`, `html`, `cbom`         |
| `--out PATH`               | stdout    | Required for `html`                       |
| `--timeout SECONDS`        | `5`       |                                           |
| `--concurrency N`          | `10`      |                                           |
| `--fail-on CLASS`          | none      | Exit 1 if any finding is at least this severe |
| `--mosca-x/-y/-z YEARS`    | none      | All three needed to compute scores        |
| `--exclude GLOB`           | —         | Repeatable, for `code`/`files`            |

Exit codes: `0` success · `1` `--fail-on` threshold reached · `2` usage error
· `3` every target failed.

`--help` and the README carry the authorisation warning: scan only systems you
own or have written permission to test.

## 9. Reporters

| Reporter       | Output                                                     |
| -------------- | ---------------------------------------------------------- |
| `console`      | `rich` output: header, summary counts per risk class, findings table sorted worst first (location:line, usage, algorithm, optional Mosca column, reason), errors table, worst-risk verdict. Colours only on a terminal; scanned data is never interpreted as markup |
| `json_report`  | `ScanResult.model_dump_json(indent=2)`; JSON Schema committed as `docs/schema/scan-result.schema.json` (a test keeps it in sync) |
| `html_report`  | Single self-contained file rendered from `templates/report.html.j2` (no external assets) |
| `cbom`         | CycloneDX **1.6** BOM: each distinct algorithm → `cryptographic-asset` component (`assetType: algorithm`, `algorithmProperties`), each certificate → `assetType: certificate`; assets link to algorithms through `dependencies` |

`html_report` and `cbom` are v0.2 items; until then `reporters.render()` raises
`UnsupportedFormatError` for them (the CLI maps it to exit code 2).

Console and JSON output are covered by snapshot tests (`tests/snapshots/`);
run `PQC_UPDATE_SNAPSHOTS=1 pytest` after an intentional change and review
the diff.

## 10. Testing strategy

- No real internet targets, ever.
- Key and certificate fixtures are **generated at test time** in `conftest.py`
  with `cryptography` (session-scoped, `tmp_path_factory`). Committing private
  keys would trigger GitHub secret scanning / push protection. Static fixtures
  are acceptable only for public material and encrypted/garbage samples.
- TLS: a local `ssl`-based server on `127.0.0.1` with generated certificates.
  The PQ group probe is tested against recorded `ServerHello` bytes.
- SSH: a fake server socket that sends a canned banner + KEXINIT.
- Code: small sample files in `tests/fixtures/code/{python,java}`.
- Targets: `mypy --strict` clean, `ruff` clean, coverage ≥ 80 %.

## 11. Packaging

- `pyproject.toml` with hatchling, `src/` layout, entry point
  `pqc-scan = "pqc_scan.cli:app"`.
- `rules/**/*.yaml` and `templates/*.j2` shipped as package data and loaded via
  `importlib.resources`.
- Optional extras: `[tls]` (sslyze), `[code]` (semgrep), `[report]` (jinja2,
  cyclonedx-python-lib), `[dev]`, `[all]` **[D-6]**.
