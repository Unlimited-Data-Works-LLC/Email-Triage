# Multi-stage build for email-triage.
# Works with both Podman and Docker:
#   podman build -t email-triage -f Containerfile .
#   docker build -t email-triage -f Containerfile .

# ---------------------------------------------------------------------------
# Stage 1: Builder — install dependencies and build the package
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS builder

WORKDIR /build

# Install build dependencies. Path-3 (N-432 walresetbug fix, 2026-07-20)
# UNIFIES both arches on a source-built sqlcipher3 against a freshly
# generated SQLCipher v4.17.0 amalgamation (SQLite 3.53.3). That adds:
#   * git + ca-certificates — clone sqlcipher/sqlcipher@v4.17.0 + coleifer/sqlcipher3@0.6.2
#   * tcl (real tclsh, NOT the jimsh0 bootstrap) — mksqlite3c.tcl / mksqlite3h.tcl
#     require a TCL interpreter for `make sqlite3.c sqlite3.h` even with
#     ``--disable-tcl`` at configure time. Verified against SQLCipher v4.17.0
#     main.mk L118 (B.tclsh ?= $(JIMSH)) + L1150-1157 (mksqlite3{c,h}.tcl targets).
#   * libssl-dev + libc6-dev — SQLCipher setup.py links libcrypto (was already
#     installed on the arm64 leg; now uniformly needed on x86_64 too).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libffi-dev \
        git ca-certificates \
        tcl make pkg-config \
        libssl-dev libc6-dev && \
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
# N-432 walresetbug Path-3 (2026-07-20) — amalgamation output sha256 pin.
# Two lines (sqlite3.c + sqlite3.h). Sha-pinning the GENERATED amalgamation
# closes the mksqlite3c.tcl / jimsh0 non-determinism hole (db-sme MF-5) that
# git-sha input pinning alone doesn't cover. First build after this edit
# runs in bootstrap mode (prints the actual sha256, no strict check); the
# operator copies the printed values into vendor/sqlite3.expected.sha256
# and reruns for strict verification.
COPY vendor/sqlite3.expected.sha256 vendor/sqlite3.expected.sha256

# 2. Install pinned deps from the lockfile (audit Framework B
#    "Dependency pinning"). Heavy layer; cached unless lockfile
#    changes. NOTE: requirements.lock excludes torch +
#    sentence-transformers post-#180 — those land at first-admin-
#    setup via the lazy installer, written into /app/data/runtime-
#    deps/site-packages on the operator's persistent volume.
RUN pip install --no-cache-dir --prefix=/install \
    -r requirements.lock

# 2b. SQLCipher encryption-at-rest binding — PATH-3 UNIFIED REBUILD.
# N-432 walresetbug fix, 2026-07-20. Both arches now build sqlcipher3 from
# source against a freshly generated SQLCipher v4.17.0 amalgamation
# (SQLite 3.53.3) — the first walresetbug-clean SQLCipher (fix landed at
# SQLCipher v4.14.0 / SQLite 3.51.3, 2026-03-17).
#
# HISTORICAL (pre-Path-3, retained in git blame at commit ${PATH3_BASE_SHA}):
#   x86_64 pulled prebuilt ``sqlcipher3-binary>=0.5.4,<0.6`` (vendored
#   SQLCipher 4.6.0 → SQLite 3.45.3 — UNPATCHED for walresetbug on the actual
#   prod arch); arm64 source-built coleifer 0.6.2 sdist (vendored 3.51.1 —
#   also still inside the affected 3.7.0-3.51.2 range). Neither leg carried
#   the WAL-reset-race fix that SQLite 3.51.3+ provides.
#
# The encryption boot contract still fail-closes with a RuntimeError when
# ``EMAIL_TRIAGE_DB_ENCRYPTION=true`` / ``persistence.encryption_enabled``
# is set but ``sqlcipher3`` is unimportable
# (db/_engine.py enforce_db_encryption_boot_contract, §164.312(a)(2)(iv) —
# never a silent plaintext fallback). Path-3 makes ``import sqlcipher3``
# available on BOTH arches uniformly with AES-256-CBC + HMAC-SHA512
# (SQLCipher 4.x, cipher_compatibility=4, IDENTICAL on-disk format across
# arches — zero migration; verified via pre-deploy bake gate in
# scripts/deploy.sh against a bind-mounted COPY of the live PHI DB per
# §164.312(c)(1) integrity + §164.316 evidence).
#
# Supply chain: two-git-clone shape with SHA-pinned refs + ``git rev-parse
# HEAD`` assertion + amalgamation-output sha256 pin (closes the mksqlite3c
# /jimsh0 non-determinism hole). Wheelhouse follow-up (post-v0.2.0) will
# drop the toolchain from the runtime image entirely — see the
# followup_sqlcipher3_* mempalace drawers.
#
# ``apt libsqlcipher-dev`` stays dead (Debian-stable ships format-incompatible
# SQLCipher 3.x; SQLCipher 4.7+ removed the system lib). ``--no-build-isolation``
# still required so pip does NOT install the sdist's ``conan>=2.0`` build-require
# (its OpenSSL 3.6.0 rebuild aborts under QEMU); setup.py's ``try: import conan``
# then fails cleanly and setup.py links Debian's ``-lcrypto`` (from libssl-dev)
# instead. Reference: internal documentation.
ENV SQLCIPHER_SHA=810db22f575ee7cf94ea96a3e91622b5fcece3dc
ENV SQLCIPHER3_SHA=14fc2632676b20011e0bba64fdda49763a2dd2ec

WORKDIR /build/vendor-build
RUN set -eux; \
    git clone https://github.com/sqlcipher/sqlcipher.git sqlcipher-src; \
    git -C sqlcipher-src fetch --depth=1 origin "${SQLCIPHER_SHA}"; \
    git -C sqlcipher-src checkout "${SQLCIPHER_SHA}"; \
    [ "$(git -C sqlcipher-src rev-parse HEAD)" = "${SQLCIPHER_SHA}" ] || \
        { echo "SQLCIPHER_SHA drift — expected ${SQLCIPHER_SHA}"; exit 1; }; \
    git clone https://github.com/coleifer/sqlcipher3.git sqlcipher3-src; \
    git -C sqlcipher3-src fetch --depth=1 origin "${SQLCIPHER3_SHA}"; \
    git -C sqlcipher3-src checkout "${SQLCIPHER3_SHA}"; \
    [ "$(git -C sqlcipher3-src rev-parse HEAD)" = "${SQLCIPHER3_SHA}" ] || \
        { echo "SQLCIPHER3_SHA drift — expected ${SQLCIPHER3_SHA}"; exit 1; }

# Generate the amalgamation via coleifer's vendor/update mechanics but against
# our SHA-pinned sqlcipher checkout (vendor/update's shipped form does a bare
# ``git clone`` of master — a supply-chain hole; that's exactly the tree we
# already SHA-verified above). CFLAGS bundle is copied verbatim from
# coleifer/sqlcipher3@0.6.2 ``vendor/update`` — note the -D macros here are
# DOCUMENTATION-only during amalgamation-gen (only tclsh runs; no C compile);
# setup.py re-applies the real compile-time bundle when building the extension.
RUN set -eux; \
    export CFLAGS="-DSQLITE_DEFAULT_CACHE_SIZE=-8000 \
        -DSQLITE_DEFAULT_FOREIGN_KEYS=1 \
        -DSQLITE_DEFAULT_MEMSTATUS=0 \
        -DSQLITE_DEFAULT_PAGE_SIZE=4096 \
        -DSQLITE_ENABLE_EXPLAIN_COMMENTS \
        -DSQLITE_ENABLE_FTS3_PARENTHESIS \
        -DSQLITE_ENABLE_FTS3 -DSQLITE_ENABLE_FTS4 -DSQLITE_ENABLE_FTS5 \
        -DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_MEMDB -DSQLITE_ENABLE_STAT4 \
        -DSQLITE_ENABLE_UNLOCK_NOTIFY -DSQLITE_ENABLE_UPDATE_DELETE_LIMIT \
        -DSQLITE_LIKE_DOESNT_MATCH_BLOBS -DSQLITE_SOUNDEX -DSQLITE_USE_URI \
        -DSQLITE_TEMP_STORE=3 -DSQLITE_HAS_CODEC=1 -DHAVE_STDINT_H=1 -O2"; \
    cd sqlcipher-src; \
    ./configure --disable-tcl --fts3 --fts4 --fts5 --update-limit \
        --enable-load-extension --enable-threadsafe; \
    make sqlite3.c sqlite3.h; \
    # Assert the generated amalgamation carries the walresetbug fix (>= 3.51.3).
    # SQLITE_VERSION_NUMBER format: X.Y.Z → XYYZZZ (e.g. 3.53.3 → 3053003).
    # Accept 3.53.0-3.53.99 (SQLCipher v4.17.0 baselines on 3.53.3 per Zetetic
    # release notes; upstream point releases within 3.53.x are acceptable).
    grep -qE '^#define SQLITE_VERSION_NUMBER 30530[0-9]{2}$' sqlite3.h || \
        { echo "ERROR: amalgamation SQLITE_VERSION_NUMBER not in 3.53.x range"; \
          grep '^#define SQLITE_VERSION' sqlite3.h; exit 1; }; \
    cp sqlite3.c sqlite3.h ../sqlcipher3-src/vendor/

# sha256-pin the generated amalgamation against the checked-in expected file
# (db-sme MF-5). Bootstrap mode: if the expected file contains no `<hex>  file`
# lines the check prints the actual sha256s LOUDLY and continues so first-
# build can succeed; the operator then commits the printed values and any
# subsequent build enforces byte-match. Strict mode is auto-detected by the
# presence of a valid sha256 line.
RUN set -eux; \
    cd /build/vendor-build/sqlcipher3-src/vendor; \
    echo "== amalgamation sha256 (bootstrap-populate into /build/vendor/sqlite3.expected.sha256 if not yet pinned) =="; \
    sha256sum sqlite3.c sqlite3.h; \
    if grep -qE '^[0-9a-f]{64}  sqlite3\.[ch]$' /build/vendor/sqlite3.expected.sha256; then \
        echo "== STRICT MODE: verifying amalgamation sha256 against expected =="; \
        sha256sum -c /build/vendor/sqlite3.expected.sha256 || \
            { echo "AMALGAMATION SHA DRIFT — check the printed sha256 above; investigate mksqlite3c/tclsh non-determinism or SQLCipher/tcl version drift"; exit 1; }; \
    else \
        echo "== BOOTSTRAP MODE: no strict sha256 pin yet — capture the two values above and check them into vendor/sqlite3.expected.sha256, then rebuild for strict verification =="; \
    fi

# Build sqlcipher3 from the SHA-pinned coleifer tree with the fresh amalgamation.
# --no-binary sqlcipher3 forces the source build; --no-build-isolation skips the
# conan build-require (per existing arm64 pattern); setup.py links Debian's
# libcrypto via -lcrypto (from libssl-dev installed at L14-25). --verbose so
# the wheel-build gcc lines surface in the build log (silent failures are the
# recurrence class this arc's audit turned up).
RUN set -eux; \
    cd /build/vendor-build/sqlcipher3-src; \
    pip install --no-cache-dir setuptools wheel; \
    pip install --no-cache-dir --no-binary sqlcipher3 --no-build-isolation \
        --prefix=/install .; \
    echo "== post-install site-packages layout =="; \
    find /install -name '_sqlite3*' -o -name 'sqlcipher3' -type d 2>/dev/null | head -10; \
    # Build-time verify: sqlite_version_info floor AND SQLCipher 4.17.x smoke.
    # ``site.addsitedir`` is more robust than PYTHONPATH for a --prefix install
    # (properly processes .pth files + resolves the correct multiarch subdir).
    # cd OUT of sqlcipher3-src FIRST so Python's CWD-implicit path doesn't
    # resolve `import sqlcipher3` to the SOURCE tree (which has no compiled .so).
    cd /; \
    python3 -c "\
import site, sys; \
site.addsitedir('/install/lib/python3.12/site-packages'); \
import sqlcipher3.dbapi2 as d; \
assert d.sqlite_version_info >= (3, 51, 3), ('walresetbug floor', d.sqlite_version); \
assert d.sqlite_version_info[:2] == (3, 53), ('expected 3.53.x', d.sqlite_version); \
c = d.connect(':memory:'); \
v = c.execute('PRAGMA cipher_version').fetchone(); \
assert v and str(v[0]).startswith('4.17.'), ('expected SQLCipher 4.17.x', v); \
print('OK sqlite=', d.sqlite_version, 'cipher=', v[0])"; \
    # Toolchain footprint reduction — drop the source trees post-install.
    cd /; rm -rf /build/vendor-build

WORKDIR /build

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
FROM python:3.14-slim AS runtime

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

# 2026-06-13 — encryption runtime crypto guarantee + per-platform smoke.
# The arm64 leg source-builds sqlcipher3 linking libcrypto (OpenSSL)
# DYNAMICALLY, so the runtime image MUST carry libssl3 EXPLICITLY rather than
# inherit it by luck from the base (a future base slim-down could otherwise
# break encryption on arm64 ONLY, which the x86_64 wheel — bundled crypto —
# would never surface). Tiny + idempotent on x86_64 (CPython's ssl/hashlib
# already pull libssl3). Then a build-time smoke: buildx runs this RUN under
# EACH platform's emulation, so the arm64 leg FAILS THE BUILD if `import
# sqlcipher3` can't load + initialize its crypto, or if it isn't SQLCipher
# 4.x (a 3.x lib could not open the 4.x PHI DB). This closes the "a green
# multi-arch build could still ship a non-importable arm64 binary" gap —
# release.yml runs no pytest, so the guarantee lives in the image build.
# §164.312(a)(2)(iv) fail-closed: a broken crypto binding stops the build,
# it never ships silently. (db-sme/devils-advocate  SME panel 2026-06-13.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    python -c "import sqlcipher3.dbapi2 as d; \
assert d.sqlite_version_info >= (3, 51, 3), ('N-432 walresetbug floor', d.sqlite_version); \
assert d.sqlite_version_info[:2] == (3, 53), ('expected 3.53.x from Path-3 rebuild', d.sqlite_version); \
c = d.connect(':memory:'); \
v = c.execute('PRAGMA cipher_version').fetchone(); \
print('sqlite_version', d.sqlite_version, 'sqlcipher_version', v); \
assert v and str(v[0]).startswith('4.17.'), ('expected SQLCipher 4.17.x from Path-3 rebuild', v)"

# 2026-05-17 — runtime-deps directory layout. The lazy
# embedding installer writes torch + sentence-transformers + the
# embedding model into the data volume (not into the image layer).
# HF_HOME points at the same volume so the model cache survives
# container restarts. The directory itself is created with the
# triage-user mode bits a few steps below, alongside the other
# mounted volumes.
ENV HF_HOME=/app/data/runtime-deps/hf-cache
ENV EMBEDDING_BITS_RUNTIME_DEPS=/app/data/runtime-deps
# N-432 Path-3 baseline marker — set ONLY by the Path-3 Containerfile so
# ``db/_engine.py::assert_cipher_version_floor`` knows to enforce the
# SQLCipher >= 4.14 fail-CLOSED guard. Unset in local/CI/pip-install envs
# (which use pre-Path-3 sqlcipher3-binary wheels with older vendored
# SQLCipher) so the guard no-ops cleanly there rather than falsely halting
# the boot with a walresetbug-floor false-positive.
ENV EMAIL_TRIAGE_PATH3_BASELINE=1

# Copy application source and project metadata.
COPY pyproject.toml .
COPY src/ src/

# Embedding-bits manifest — ships in the image so the installer
# verifies downloads (auto + sideload) against pinned hashes without
# trusting the operator's environment.
COPY scripts/embedding-bits-manifest.json /app/scripts/embedding-bits-manifest.json

# N-432 Path-3 bake-gate scripts — deploy-time pre-flight verification of
# the encryption boundary (§164.312(a)(2)(iv)) + audit-chain integrity
# (§164.312(c)(1)) run before the new image ever touches the live PHI DB.
# Baked into the image (NOT bind-mounted) so the gate runs identically in
# BOTH source-build AND --from-registry pull modes; a bind-mount from the
# git-archive staging dir would silently break registry-pull because that
# staging step is skipped (deploy.sh:242-249). scripts/deploy.sh invokes
# these as `python /app/scripts/n432-path3-bake-step{1,3}.py` under a
# fresh throwaway podman-run against the live DB read-only + the
# quadlet-mirrored env. Step 2 is `email-triage audit verify`, already in
# the image via the CLI. See scripts/n432-path3-bake-step3.py's docstring
# for why the chr()-obfuscation on PRAGMA / column literals is INTENTIONAL
# and load-bearing (Prime Directive #3 secret-write pin) even now that
# the shell-quoting layers are gone.
COPY scripts/n432-path3-bake-step1.py /app/scripts/n432-path3-bake-step1.py
COPY scripts/n432-path3-bake-step3.py /app/scripts/n432-path3-bake-step3.py

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

# N-432 Path-3 fix-forward MF-1 (DA gate on 91e630c8, 2026-07-20) — belt on
# the env-gated fail-CLOSED cipher_version guard. The guard at
# db/_engine.py::assert_cipher_version_floor no-ops when
# EMAIL_TRIAGE_PATH3_BASELINE is unset (so pypi-wheel test envs don't
# false-fail); this build-time smoke PROVES the guard actually fires in
# the Path-3 image itself. If image drift (a future edit) strips the ENV
# or regresses sqlcipher3 below 4.14, `applicable=False` OR the guard's
# RuntimeError catches it at build time — never a silent runtime bypass.
# §164.312(a)(2)(iv) fail-CLOSED belt: the Containerfile itself asserts
# the guard-that-protects-the-encryption-boundary is armed + green.
RUN python -c "\
import os; \
assert os.environ.get('EMAIL_TRIAGE_PATH3_BASELINE') == '1', ('EMAIL_TRIAGE_PATH3_BASELINE not set in image — guard would silently no-op at runtime'); \
from email_triage.db._engine import assert_cipher_version_floor; \
r = assert_cipher_version_floor(); \
assert r.get('applicable') is True, ('N-432 Path-3 guard did NOT fire — bypass surface introduced (image drift?): ' + repr(r)); \
assert 'cipher_version' in r and str(r['cipher_version']).startswith('4.17.'), ('N-432 Path-3 guard fired but cipher_version off expected line: ' + repr(r)); \
print('OK Path-3 guard armed:', r['cipher_version'], 'at floor', r['min_floor'])"

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
