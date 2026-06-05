# Multi-stage build for email-triage.
# Works with both Podman and Docker:
#   podman build -t email-triage -f Containerfile .
#   docker build -t email-triage -f Containerfile .

# ---------------------------------------------------------------------------
# Stage 1: Builder — install dependencies and build the package
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies (for cryptography wheel if needed).
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# 2026-05-14 — layer-cache discipline. Dependency-metadata files and
# all heavy ``pip install`` layers MUST run before the source COPY
# so source-only edits don't bust the cache for the lockfile pulls.
# Pre-fix this stage had ``COPY src/`` before the pip layers, so
# every code change re-pulled ~500-700 MB. Operator's bandwidth alert
# flagged ~13 GB on the deploy host in a 2-hour window after 12 same-
# day deploys. After fix, source-only edits pay only the small
# ``pip install . --no-deps`` layer at the end.
#
# 2026-05-17 — torch + sentence-transformers + the HuggingFace
# all-MiniLM-L6-v2 model are NO LONGER baked into the image. Pre-fix
# those three items added ~600 MB compressed (~2 GiB uncompressed) to
# the runtime stage, which pushed the air-gap release tarball over
# GitHub Releases' 2 GiB asset cap. Post-fix the runtime container
# is ~250 MB. The embedding stack downloads lazily on first admin
# setup via the in-app ``embedding_bits`` installer (hash-verified
# against ``scripts/embedding-bits-manifest.json`` shipped in the
# image). Sideload path covers air-gap installs. Customer-facing
# disclosure lives in README + docs/install.md.

# 1. Dependency metadata first — these layers are cached across
#    source edits.
COPY pyproject.toml .
COPY requirements.lock .

# 2. Install pinned deps from the lockfile (audit Framework B
#    "Dependency pinning"). Heavy layer; cached unless lockfile
#    changes. NOTE: requirements.lock excludes torch +
#    sentence-transformers post-#180 — those land at first-admin-
#    setup via the lazy installer, written into /app/data/runtime-
#    deps/site-packages on the operator's persistent volume.
RUN pip install --no-cache-dir --prefix=/install \
    -r requirements.lock

# 2b. v0.1.2 single-file encryption: SQLCipher encryption-at-rest binding.
# ``sqlcipher3-binary`` ships prebuilt wheels (CPython 3.11+) but is
# Linux-ONLY (no Windows wheels), so it lives here in the container build
# rather than the cross-platform ``requirements.lock``. The pyproject
# ``encryption`` extra pins the same range (sqlcipher3-binary>=0.5.4,<0.6).
# Without this layer the encryption boot-contract fail-closes with a
# RuntimeError when ``EMAIL_TRIAGE_DB_ENCRYPTION=true`` /
# ``persistence.encryption_enabled`` is set (db/_engine.py
# enforce_db_encryption_boot_contract, §164.312(a)(2)(iv) — never a silent
# plaintext fallback). Own cached layer: only re-pulls if the pin changes.
RUN pip install --no-cache-dir --prefix=/install \
    "sqlcipher3-binary>=0.5.4,<0.6"

# 3. Strip ``__pycache__`` directories from the installed packages.
#    pip auto-compiles every .py to .pyc on install (cuts first-
#    import latency by ~10%). The compiled bytecode roughly doubles
#    the disk footprint of /install — fine if the container is going
#    to be used for a long time, but bloats the image for negligible
#    runtime benefit (Python re-compiles on-demand at import time,
#    one-time ~50ms-per-module cost spread across boot). Net: drop
#    ~150-200 MB from the runtime image. Belt-and-braces ``find``
#    walk — covers .pyc files outside __pycache__ directories too.
RUN find /install -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true && \
    find /install -type f -name "*.pyc" -delete 2>/dev/null || true

# 4. Source LAST. Edits to anything under src/ invalidate only this
#    layer + the next thin ``pip install . --no-deps`` step.
COPY src/ src/

# 5. Install the package itself with --no-deps so pyproject's
#    ranges don't override the lock. The extras are still resolved
#    against the lock since extras add imports, not new constraints
#    — pip-tools bakes them into the pyproject reference. This
#    layer is cheap (re-runs on every source edit but downloads
#    nothing new — pip resolves locally from the wheels installed
#    in step 2).
RUN pip install --no-cache-dir --no-deps --prefix=/install \
    ".[keyfile,imap,office365,openai]"

# ---------------------------------------------------------------------------
# Stage 2: Runtime — minimal image with only what's needed
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# The canonical authorship + description for this image lives on
# the OCI labels declared in .github/workflows/release.yml's
# metadata-action (`org.opencontainers.image.{title,description,
# authors,source,licenses}`). Those are what GHCR + cosign + any
# OCI-spec-aware tool surface. The two LABEL lines below are the
# legacy single-name fields that `docker inspect` still reads
# back via the top-level `Config.Labels.maintainer` / `description`
# keys — kept here so a customer running `docker inspect` against
# the v0.1.0 image sees attribution to the LLC rather than the
# operator-internal name that historically lived here (scrubbed at
# publish time via publish-fresh-start.py SCRUB_RE, but cleaner to
# carry the public-facing value as the canonical source).
LABEL maintainer="Unlimited Data Works LLC <https://github.com/Unlimited-Data-Works-LLC>"
LABEL description="Privacy-first, HIPAA-aware email classification and reply drafting; local LLM via Ollama"

WORKDIR /app

# Copy installed packages from builder.
COPY --from=builder /install /usr/local

# 2026-05-17 — runtime-deps directory layout. The lazy
# embedding installer writes torch + sentence-transformers + the
# embedding model into the data volume (not into the image layer).
# HF_HOME points at the same volume so the model cache survives
# container restarts. The directory itself is created with the
# triage-user mode bits a few steps below, alongside the other
# mounted volumes.
ENV HF_HOME=/app/data/runtime-deps/hf-cache
ENV EMBEDDING_BITS_RUNTIME_DEPS=/app/data/runtime-deps

# Copy application source and project metadata.
COPY pyproject.toml .
COPY src/ src/

# Embedding-bits manifest — ships in the image so the installer
# verifies downloads (auto + sideload) against pinned hashes without
# trusting the operator's environment.
COPY scripts/embedding-bits-manifest.json /app/scripts/embedding-bits-manifest.json

# Bake the build-time commit SHA into the image. ``COMMIT`` carries the
# git ``export-subst`` placeholder ``$Format:%H$`` (.gitattributes), so
# ``git archive HEAD`` substitutes the real 40-char SHA at archive time —
# EVERY archive-based build bakes the right value, both ``scripts/deploy.sh``
# (which also overwrites COMMIT with ``git rev-parse HEAD``) and any manual
# ``git archive HEAD | podman build``. The /health endpoint reads this file
# via ``_resolve_version()`` (which treats an unsubstituted literal as dev).
COPY COMMIT /app/VERSION

# Re-install in editable-like mode so the entry point works.
# Since dependencies are already present, this is fast.
RUN pip install --no-cache-dir --no-deps -e .

# Create non-root user for security.
RUN groupadd -r triage && useradd -r -g triage -d /app triage

# Data directory for SQLite, token cache, and summary queue.
# This should be mounted as a volume.
RUN mkdir -p /app/data && chown triage:triage /app/data
VOLUME /app/data

# Config directory — mount your email-triage.yaml here.
RUN mkdir -p /app/config && chown triage:triage /app/config
VOLUME /app/config

# Switch to non-root user.
USER triage

# Expose the web UI / webhook receiver port.
EXPOSE 8080

# Health check — hit the dedicated /health endpoint (unauthenticated
# by design, returns JSON liveness + shallow readiness).  Replaces the
# earlier /login probe, which conflated the auth surface with liveness
# (audit finding — NERC CIP-007-R4).
# Try HTTPS first (TLS-enabled listener), fall back to HTTP. Accepts
# both 200 (healthy) and 503 (degraded -- app is still serving, just
# reporting at least one degraded subsystem; container itself is
# alive). Anything else, including connection failure on both schemes,
# is unhealthy. PR 5 / C1 changed /health to return 503 on degraded;
# the prior HEALTHCHECK that required exactly 200 would have flagged
# the container unhealthy on legitimate degraded states. Uses
# CMD-exec form (JSON array) so newlines in the python source survive.
HEALTHCHECK --interval=30s --timeout=15s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import httpx\nr=None\ntry:\n  r=httpx.get('https://localhost:8080/health',verify=False,timeout=12)\nexcept Exception:\n  try:\n    r=httpx.get('http://localhost:8080/health',timeout=12)\n  except Exception:\n    pass\nexit(0 if r is not None and r.status_code in (200,503) else 1)"]

# Default: start the web UI server.
# Override with any email-triage subcommand:
#   podman run email-triage run --query "is:unread" --limit 5
ENTRYPOINT ["email-triage"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
