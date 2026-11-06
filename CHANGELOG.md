# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-11-06

First public release. It covers the whole v0.1–v0.3 roadmap.

### Scanners
- `files`: PEM (multi-block), DER, CSRs, public/private keys, OpenSSH public
  and private keys (never decrypted), ML-DSA/ML-KEM keys.
- `tls`: pure-Python ClientHello probe — protocol versions SSL 3.0–TLS 1.3,
  accepted cipher suites, key-exchange groups including hybrid
  `X25519MLKEM768`, DHE size, certificate chain. No sslyze (decision D-11).
- `ssh`: reads the server's KEXINIT in clear text — key exchange (incl.
  `mlkem768x25519-sha256`), host keys, ciphers, MACs. No login.
- `code`: Python (AST with import resolution), Java/Kotlin,
  JavaScript/TypeScript and Go (pattern rules). No Semgrep (decision D-12).

### Reports and CLI
- Formats: console, JSON (with a published JSON Schema), self-contained HTML,
  CycloneDX 1.6 CBOM (validated against the official schema).
- Recommendations per finding; `docs/migration-guide.md`.
- Commands: `scan files|code|tls|ssh|all`, `report`, `diff`.
- `--fail-on` and exit codes 0/1/2/3; Mosca's inequality with
  `--mosca-x/-y/-z` and per-asset `--mosca-file`.

### Integrations
- GitHub Action (`action.yml`) that fails pull requests only on new findings.
- Docker image (non-root) and a release workflow publishing to PyPI (trusted
  publishing) and ghcr.io.

### Documentation
- Learn notebooks: Grover, Shor, BB84 (pure Python, tested).
- Turkish usage guide, technical summary and quantum glossary.
