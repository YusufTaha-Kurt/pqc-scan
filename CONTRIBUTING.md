# Contributing

Thanks for your interest in `pqc-scan`!

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Quality checks

All of these must pass before a pull request is merged (CI runs them too):

```bash
ruff check . && ruff format --check .
mypy src
pytest -q --cov=pqc_scan
```

## Ground rules

- **Language:** code, comments, commit messages and documentation are in English.
- **Typing:** type hints are required; `mypy --strict` must pass.
- **Tests:** every new module ships with unit tests; coverage stays at or above 80 %.
- **Commits:** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
- **Branches:** one feature per branch and pull request (e.g. `feat/tls-scanner`),
  targeting `master`. Keep pull requests small.
- **Dependencies:** explain why in the pull request description before adding one.

## Architecture rules

See [`docs/architecture.md`](docs/architecture.md). In short:

- Scanners implement `Scanner` and return `list[Observation]`; they know nothing
  about risk classes or report formats.
- Source-code API rules live in `src/pqc_scan/rules/code_rules.yaml` (add a
  fixture line under `tests/fixtures/code/` for every new rule).
- Risk classification lives only in `src/pqc_scan/rules/algorithms.yaml` and
  `classify.py`. If you are unsure how to classify an algorithm, add it with a
  `# TODO: doğrula` ("verify") comment — the marker is kept as-is so it stays
  greppable — and mention it in the pull request.
- Reporters consume only `ScanResult`.

## Security and ethics

- Scanning is passive: no login, no exploitation, no password guessing.
- Never write private key material to reports, logs or error messages.
- Tests never contact real internet hosts. Keys and certificates used in tests
  are generated at test time — never commit private keys.
