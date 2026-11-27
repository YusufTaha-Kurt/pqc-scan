# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.4.0] — unreleased

### Added
- Stable Python API for embedding pqc-scan in other tools: `pqc_scan.scan()`,
  `parse_targets()`, `build_jobs()`, `render_report(..., lang=)`,
  `write_report()`, `localize()`, `exceeds()` and `all_failed()`, with the
  result models re-exported from `pqc_scan` (`pqc_scan.api`).
- Progress callback for scans (`on_progress` / `run_scan(on_job_done=...)`).

### Fixed
- The report language can now be chosen per call; it no longer depends on a
  context variable that is lost on worker threads.

### Changed
- The CLI uses the same target parsing and job building as the API.

## [0.3.0] — 2026-11-25

First PyPI release. [Version 0.3.0](https://pypi.org/project/pqc-readiness-scanner/0.3.0/)

- Preserve failed scan status in CI while retaining the report artifacts.
- Distinguish findings that could not be verified from resolved findings.
- Record local file coverage, honor relative exclude paths and isolate Python import aliases by scope.
- Support endpoint-only Action runs and Turkish CLI, report and Action output.

### Scanners
- `files`: PEM (multi-block), DER, CSRs, public/private keys, OpenSSH public
  and private keys (never decrypted), ML-DSA/ML-KEM keys.
- `tls`: pure-Python ClientHello probe — protocol versions SSL 3.0–TLS 1.3,
  accepted cipher suites, key-exchange groups including hybrid
  `X25519MLKEM768`, DHE size, certificate chain. No sslyze (decision D-11).
- `ssh`: reads the server's KEXINIT in clear text — key exchange (incl.
  `mlkem768x25519-sha256`), host keys, ciphers, MACs. No login.
- `code`: Python (AST with import resolution), Java/Kotlin,
  JavaScript/TypeScript, Go, C# and Rust (pattern rules). No Semgrep
  (decision D-12).

### Reports and CLI
- Formats: console, JSON (with a published JSON Schema), self-contained HTML,
  CycloneDX 1.6 CBOM with certificate subject/issuer/validity (validated
  against the official schema), SARIF 2.1.0 for code-scanning dashboards.
- Recommendations per finding; `docs/migration-guide.md`.
- Commands: `scan files|code|tls|ssh|all`, `report`, `diff`.
- `--fail-on` and exit codes 0/1/2/3; Mosca's inequality with
  `--mosca-x/-y/-z` and per-asset `--mosca-file`.

### Integrations
- GitHub Action (`action.yml`) that fails pull requests only on new findings
  and can upload SARIF to GitHub code scanning.
- CI interop job against real OpenSSL 3.5 and OpenSSH 10 servers; the TLS
  probe detects `X25519MLKEM768` on a stock OpenSSL 3.5 server.
- Docker image (non-root) and a release workflow publishing to PyPI (trusted
  publishing) and ghcr.io.

### Classification
- All judgement-call classifications were reviewed and approved
  (decision D-13); see `docs/teknik-ozet.md` §8.

### Documentation
- Learn notebooks: Grover, Shor, BB84 (pure Python, tested).
- Turkish usage guide, technical summary and quantum glossary.
