# ÆTHERYA decision service.
#
# Two stages so the runtime image does not carry build tooling. The semantic
# model is baked in at build time: `require_warm_semantic_model` means the
# advisory layer declines to run on a cold model, and downloading ~90MB on first
# boot would either delay readiness or leave the layer silently inactive.

FROM python:3.11-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY src/ ./src/

# The provider SDKs are here because the same image runs the gateway, which
# cannot reach an upstream without them — installed, it answers; absent, every
# completion is a 502 that reads like a network fault. They are optional extras
# for a library consumer and mandatory for this image.
RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir ".[redis,llm,anthropic]"

# Pre-download the sentence-transformers model into the image.
ENV HF_HOME=/opt/models
RUN python -c "from aetherya.constitution import warmup_semantic_model; warmup_semantic_model()"


FROM python:3.11-slim AS runtime

# Never run the decision boundary as root.
RUN useradd --create-home --uid 10001 aetherya

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder --chown=aetherya:aetherya /opt/models /opt/models

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/opt/models

WORKDIR /app
COPY --chown=aetherya:aetherya config/ ./config/
COPY --chown=aetherya:aetherya examples/ ./examples/

# The audit trail is a chained JSONL file; it must outlive the container.
# docker-compose mounts a volume here.
RUN mkdir -p /app/audit && chown aetherya:aetherya /app/audit
VOLUME ["/app/audit"]

USER aetherya
EXPOSE 8080

# `degraded` and `policy_fingerprint_match` are the fields that matter: a replica
# serving with the advisory layer inactive, or under an unintended policy, should
# not receive traffic.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import json,urllib.request;\
d=json.load(urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=4));\
raise SystemExit(0 if d.get('ok') and not d.get('degraded') and d.get('policy_fingerprint_match') else 1)"

# --require-semantic-ready: fail startup rather than serve in a degraded state.
CMD ["aetherya-api", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--policy-path", "config/policy.yaml", \
     "--audit-path", "audit/decisions.jsonl", \
     "--require-semantic-ready"]
