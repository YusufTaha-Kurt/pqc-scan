# Example reports

Produced by scanning a small sample project (two certificates, an SSH public
key and the sample source files from `tests/fixtures/code/`) with

```bash
docker run --rm -v "$PWD:/scan:ro" pqc-scan scan all --path example-repo --format <format>
```

| File | Format |
| --- | --- |
| [`report.txt`](report.txt) | `console` (what you see in the terminal) |
| [`report.json`](report.json) | `json` — follows [`docs/schema/scan-result.schema.json`](../docs/schema/scan-result.schema.json) |
| [`report.html`](report.html) | `html` — download and open in a browser |
| [`report.cdx.json`](report.cdx.json) | `cbom` — CycloneDX 1.6 |

The sample project contains no private keys; no report ever contains key
material or source lines.
