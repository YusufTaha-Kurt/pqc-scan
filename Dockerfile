# pqc-scan container image.
#   docker build -t pqc-scan .
#   docker run --rm pqc-scan scan tls example.com
#   docker run --rm -v "$PWD:/scan:ro" pqc-scan scan all --path /scan
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="pqc-scan" \
      org.opencontainers.image.description="Find quantum-vulnerable cryptography in endpoints and code" \
      org.opencontainers.image.source="https://github.com/YusufTaha-Kurt/pqc-scan" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[report]" && rm /tmp/*.whl \
    && useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /scan
ENTRYPOINT ["pqc-scan"]
CMD ["--help"]
