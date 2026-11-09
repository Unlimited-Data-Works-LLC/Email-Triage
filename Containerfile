# Multi-stage build for email-triage.
# Works with both Podman and Docker:
#   podman build -t email-triage -f Containerfile .
#   docker build -t email-triage -f Containerfile .

# ---------------------------------------------------------------------------
# Stage 1: Builder — install dependencies and build the package
# ---------------------------------------------------------------------------
# Punch 650: both FROMs name python:3.14-slim by the digest of its OCI INDEX (the
# multi-platform list), so every build of a commit gets the same bytes and the
# amd64 deploy build and the arm64 CI build each resolve their own entry. Never
# a single platform's manifest digest: that breaks the other architecture.
# tests/test_punch650_base_images_are_digest_pinned_pin.py holds every FROM to it.
# Bump path (both FROMs together, one digest):
#   1. Read the index digest of the tag:
#        skopeo inspect --raw docker://docker.io/library/python:3.14-slim | sha256sum
#      or the registry's `Docker-Content-Digest` header on a HEAD of
#      /v2/library/python/manifests/3.14-slim sent with
#      `Accept: application/vnd.oci.image.index.v1+json`.
#   2. Confirm it is an index carrying amd64 AND arm64 (with podman alone, on a
#      build host that has no skopeo):
#        podman manifest inspect docker.io/library/python@sha256:<digest>
#      -> "mediaType": "application/vnd.oci.image.index.v1+json".
#   3. Run scripts/regen-lock.sh on a Linux podman host: it resolves on the first
#      FROM below and records it as `base=` in every lock, which
#      tests/test_n545_lock_describes_the_image_ssot_pin.py P4 compares.
#   4. Deploy (scripts/deploy.sh), so the running image is built from it.
FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966 AS builder

WORKDIR /build

# Install build dependencies. Path-3 (N-432 walresetbug fix, 2026-07-20)
# UNIFIES both arches on a source-built sqlcipher3 against a freshly
# generated SQLCipher v4.20.0 amalgamation (SQLite 3.54.1). That adds:
#   * git + ca-certificates — clone sqlcipher/sqlcipher + coleifer/sqlcipher3 at the tags in source-built.pins
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
# punch 775: the build toolchain for the sqlcipher3 source build (2b), hash-pinned. Read by the 2b RUN.
COPY requirements-build.txt .
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
RUN pip install --no-cache-dir --require-hashes --prefix=/install \
    -r requirements.lock

# 2b. SQLCipher encryption-at-rest binding — PATH-3 UNIFIED REBUILD.
# N-432 walresetbug fix, 2026-07-20. Both arches now build sqlcipher3 from
# source against a freshly generated SQLCipher v4.20.0 amalgamation
# (SQLite 3.54.1; v4.19.0 / 3.53.4 until punch 731, v4.17.0 / 3.53.3 until punch 631) — walresetbug-clean (fix landed at
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
# ``persistence.encryption_enabled`` (the ONE store since punch 547)
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
# punch 538 / cve-arc  (2026-09-29) — the SHAs, versions and tags below come
# from ``source-built.pins``, which this build READS. There is deliberately no
# ARG, no ENV and no literal copy of any declared value anywhere in this file:
# a second copy is a place the declaration can be true while the build is not,
# and cve-arc silences advisories on the declaration's word.
# COPYed HERE — after the heavy ``pip install -r requirements.lock`` layer above
# — so editing the declaration does not invalidate the lock layer's cache.
COPY source-built.pins source-built.pins
COPY scripts/source_built.py scripts/source_built.py

WORKDIR /build/vendor-build
# ``shell`` is WRITTEN TO A FILE and then sourced, never ``eval "$(...)"``:
# under ``set -e`` a failing command substitution inside eval is NOT fatal (eval
# just runs the empty string and succeeds), so a malformed declaration would
# fall through to unset variables. Redirecting makes the parser's non-zero exit
# abort the layer. ``set -u`` then makes any variable the declaration no longer
# supplies a fatal error at the point of use, rather than an empty default.
RUN set -eux; \
    python3 /build/scripts/source_built.py shell /build/source-built.pins \
        > /build/source-built.env; \
    . /build/source-built.env; \
    git clone https://github.com/sqlcipher/sqlcipher.git sqlcipher-src; \
    git -C sqlcipher-src fetch --depth=1 origin "${SB_SQLCIPHER_SHA}"; \
    git -C sqlcipher-src checkout "${SB_SQLCIPHER_SHA}"; \
    [ "$(git -C sqlcipher-src rev-parse HEAD)" = "${SB_SQLCIPHER_SHA}" ] || \
        { echo "sqlcipher sha drift — expected ${SB_SQLCIPHER_SHA}"; exit 1; }; \
    git -C sqlcipher-src fetch --depth=1 origin \
        "refs/tags/${SB_SQLCIPHER_TAG}:refs/tags/${SB_SQLCIPHER_TAG}"; \
    [ "$(git -C sqlcipher-src rev-parse "refs/tags/${SB_SQLCIPHER_TAG}^{commit}")" \
        = "${SB_SQLCIPHER_SHA}" ] || \
        { echo "sqlcipher tag ${SB_SQLCIPHER_TAG} does not peel to ${SB_SQLCIPHER_SHA}"; \
          exit 1; }; \
    git clone https://github.com/coleifer/sqlcipher3.git sqlcipher3-src; \
    git -C sqlcipher3-src fetch --depth=1 origin "${SB_SQLCIPHER3_SHA}"; \
    git -C sqlcipher3-src checkout "${SB_SQLCIPHER3_SHA}"; \
    [ "$(git -C sqlcipher3-src rev-parse HEAD)" = "${SB_SQLCIPHER3_SHA}" ] || \
        { echo "sqlcipher3 sha drift — expected ${SB_SQLCIPHER3_SHA}"; exit 1; }; \
    git -C sqlcipher3-src fetch --depth=1 origin \
        "refs/tags/${SB_SQLCIPHER3_TAG}:refs/tags/${SB_SQLCIPHER3_TAG}"; \
    [ "$(git -C sqlcipher3-src rev-parse "refs/tags/${SB_SQLCIPHER3_TAG}^{commit}")" \
        = "${SB_SQLCIPHER3_SHA}" ] || \
        { echo "sqlcipher3 tag ${SB_SQLCIPHER3_TAG} does not peel to ${SB_SQLCIPHER3_SHA}"; \
          exit 1; }

# Generate the amalgamation via coleifer's vendor/update mechanics but against
# our SHA-pinned sqlcipher checkout (vendor/update's shipped form does a bare
# ``git clone`` of master — a supply-chain hole; that's exactly the tree we
# already SHA-verified above). CFLAGS bundle is copied verbatim from
# coleifer/sqlcipher3@0.6.2 ``vendor/update`` (unchanged in 0.6.3, 0.6.4 and 0.6.5) — the -D macros here are
# DOCUMENTATION-only during amalgamation-gen (only tclsh runs; no C compile);
# setup.py re-applies the real compile-time bundle when building the extension.
RUN set -eux; \
    python3 /build/scripts/source_built.py shell /build/source-built.pins \
        > /build/source-built.env; \
    . /build/source-built.env; \
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
    # The generated amalgamation's SQLite version must be EXACTLY the declared
    # one (punch 538). This replaces a `30530[0-9]{2}` RANGE check, which
    # accepted any 3.53.x: a range is fine as a walresetbug floor but wrong as
    # the binding behind a declared version, because cve-arc will silence
    # advisories against the exact string in source-built.pins and a point
    # release that is not running must not be covered by it. The floor assert
    # (>= 3.51.3) stays below, in the install smoke, where it belongs — it is a
    # separate SSOT with a separate reason to exist.
    sqlite_hdr="$(awk '$1=="#define" && $2=="SQLITE_VERSION" { v=$3; gsub(/"/,"",v); print v; exit }' sqlite3.h)"; \
    [ "$sqlite_hdr" = "${SB_SQLITE_VERSION}" ] || \
        { echo "ERROR: generated amalgamation is SQLITE_VERSION ${sqlite_hdr}, declared ${SB_SQLITE_VERSION}"; \
          grep '^#define SQLITE_VERSION' sqlite3.h; exit 1; }; \
    cp sqlite3.c sqlite3.h ../sqlcipher3-src/vendor/

# sha256-pin the generated amalgamation against the checked-in expected file
# (db-sme MF-5). FAIL-CLOSED on every non-strict outcome (N-616, punch 634,
# round 2): the pin file must yield one strict `<sha256>  sqlite3.c` line and
# one for `sqlite3.h`, and `sha256sum -c` must pass, or the build stops. An
# ABSENT or EMPTY pin file prints the two computed lines ready to pin and then
# ALWAYS exits 1 (no build-arg escape: any builder could pass one), so a
# bootstrap image can never finish building. Before punch 634 an unparseable pin
# fell through to a BOOTSTRAP MODE that checked nothing; a CRLF copy from a
# core.autocrlf=true `git archive` did exactly that on deploys from 2026-07-20.
# The match is deliberately NOT CR-tolerant: a stray CR stops the build.
# On the strict branch ONLY, and in THIS RUN (so a cached layer means the same
# check ran on the same inputs), it writes the marker: the two `sha256sum -c`
# OK lines plus the sha256 of the pin file. The runtime stage COPYs it
# --from=builder and asserts it against the pin file it ships. `pin`, `amalg`
# and `marker` are this step's only inputs, so
# tests/test_arch_encryption_build_pin.py runs this exact body under dash.
RUN set -eux; \
    pin=/build/vendor/sqlite3.expected.sha256; \
    amalg=/build/vendor-build/sqlcipher3-src/vendor; \
    marker=/build/.amalg-sha256-verified; \
    cd "$amalg"; \
    echo "== amalgamation sha256 =="; \
    sha256sum sqlite3.c sqlite3.h; \
    if [ ! -s "$pin" ]; then \
        echo "ERROR: $pin is absent or empty. Pin these two lines (LF), commit, rebuild:"; \
        sha256sum sqlite3.c sqlite3.h; \
        exit 1; \
    fi; \
    strict=0; \
    for x in c h; do \
        if grep -qE "^[0-9a-f]{64}  sqlite3\.$x\$" "$pin"; then strict=$((strict + 1)); fi; \
    done; \
    if [ "$strict" -lt 2 ]; then \
        echo "ERROR: $pin is non-empty but yields $strict strict lines (CRLF?); it needs one '<sha256>  sqlite3.c' and one '<sha256>  sqlite3.h' line. Computed, ready to pin:"; \
        sha256sum sqlite3.c sqlite3.h; \
        exit 1; \
    fi; \
    echo "== STRICT MODE: verifying amalgamation sha256 against expected =="; \
    if ! sha256sum -c "$pin" > "$marker.tmp"; then \
        cat "$marker.tmp"; \
        echo "AMALGAMATION SHA DRIFT — check the printed sha256 above; investigate mksqlite3c/tclsh non-determinism or SQLCipher/tcl version drift"; \
        exit 1; \
    fi; \
    cat "$marker.tmp"; \
    echo "pin-sha256 $(sha256sum < "$pin" | cut -d' ' -f1)" >> "$marker.tmp"; \
    mv "$marker.tmp" "$marker"

# Build sqlcipher3 from the SHA-pinned coleifer tree with the fresh amalgamation.
# --no-binary sqlcipher3 forces the source build; --no-build-isolation skips the
# conan build-require (per existing arm64 pattern); setup.py links Debian's
# libcrypto via -lcrypto (from libssl-dev installed at L14-25). --verbose so
# the wheel-build gcc lines surface in the build log (silent failures are the
# recurrence class this arc's audit turned up).
RUN set -eux; \
    cd /build/vendor-build/sqlcipher3-src; \
    pip install --no-cache-dir --require-hashes --only-binary :all: --no-deps \
        -r /build/requirements-build.txt; \
    pip install --no-cache-dir --no-deps --no-binary sqlcipher3 --no-build-isolation \
        --prefix=/install .; \
    echo "== post-install site-packages layout =="; \
    find /install -name '_sqlite3*' -o -name 'sqlcipher3' -type d 2>/dev/null | head -10; \
    # Build-time verify. Two checks, two SSOTs, deliberately not merged:
    #   * the N-432 walresetbug FLOOR (>= 3.51.3) — a lower bound with its own
    #     reason to exist (the WAL-reset race), which survives any future
    #     version bump;
    #   * ``source_built.py verify`` — EXACT equality against source-built.pins
    #     for the installed sqlcipher3, the SQLCipher cipher_version and the
    #     compiled-in sqlite_version. This replaces the old ``[:2] == (3, 53)``
    #     and ``startswith('4.17.')`` RANGE asserts, which would accept a point
    #     release the declaration does not name.
    # ``site.addsitedir`` is more robust than PYTHONPATH for a --prefix install
    # (properly processes .pth files + resolves the correct multiarch subdir).
    # cd OUT of sqlcipher3-src FIRST so Python's CWD-implicit path doesn't
    # resolve `import sqlcipher3` to the SOURCE tree (which has no compiled .so).
    cd /; \
    # The --prefix install's site-packages, DERIVED from the interpreter that
    # ran the install (platlib: sqlcipher3 is a C extension), never a literal
    # python3.X path that goes stale on the next base-image bump. The `test -d`
    # fails the build if the derived dir is not where pip put sqlcipher3.
    SP="$(python3 -c "import sysconfig; print(sysconfig.get_path('platlib', vars={'base': '/install', 'platbase': '/install'}))")"; \
    echo "== derived --prefix site-packages: $SP =="; \
    test -d "$SP/sqlcipher3"; \
    python3 -c "\
import site, sys; \
site.addsitedir('$SP'); \
import sqlcipher3.dbapi2 as d; \
assert d.sqlite_version_info >= (3, 51, 3), ('walresetbug floor', d.sqlite_version); \
print('OK walresetbug floor sqlite=', d.sqlite_version)"; \
    python3 /build/scripts/source_built.py verify /build/source-built.pins \
        --site-dir "$SP"; \
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
    ".[keyfile,imap,office365]"

# ---------------------------------------------------------------------------
# Stage 2: Runtime — minimal image with only what's needed
# ---------------------------------------------------------------------------
FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966 AS runtime

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

# build.sha — the commit this image was built from, readable WITHOUT entering the
# container (`podman inspect`, no `podman exec`).
#
# WHY: cve-arc's container-drift check answers "is this deployment current" by
# comparing a deployed image's build.sha against the repo checkout's HEAD
# (cve-arc 6c841c9). That subsumes a package-version comparison — if the build is
# current every locked version in it is current too — and it catches what no
# dependency scan can: a code-only fix that moved no dependency at all. It is
# also a weaker touch on this container: image metadata only, nothing entered,
# nothing executed inside.
#
# cve-arc verified 2026-08-05 that this image carried NO sha in any label (only
# description / io.buildah.version / maintainer; the sole sha in its env is the
# base image's PYTHON_SHA256) and asked for exactly this label. Independently
# confirmed here the same day: `org.opencontainers.image.revision` on the running
# container is EMPTY, so nothing could be read from it.
#
# DEFAULT IS EMPTY ON PURPOSE. An unset ARG must NOT bake a plausible-looking
# wrong value: "unknown" or "dev" would be a value that can never equal a commit
# SHA, i.e. a permanent false mismatch indistinguishable from real drift.
#
# CORRECTION (db-sme review 2026-08-05): this comment previously said a consumer
# sees an ABSENT label. It does not. This LABEL is UNCONDITIONAL, so an empty ARG
# still emits the key `build.sha` with the value "" — PRESENT-but-empty, never
# missing. A consumer testing `if "build.sha" in labels:` takes the present
# branch and compares "" against HEAD.
#
# THE CONTRACT IS THEREFORE: **empty string IS the unknown sentinel — treat
# FALSY, not MISSING, as unknown.** Stated to cve-arc in HANDOVER.md, since its
# reader lives in another repo (editing it is Tier-3).
#
# Same value as /app/VERSION (below) and the `version` field on /health/detail —
# one source, so the image, the app, and the monitor cannot disagree about which
# build this is.
ARG BUILD_SHA=""
LABEL build.sha="${BUILD_SHA}"

WORKDIR /app

# Copy installed packages from builder.
COPY --from=builder /install /usr/local
# N-616 / punch 634: the STRICT amalgamation marker comes ONLY from the builder
# RUN that wrote it (never a separate RUN, never the build context), and the pin
# file comes from the context, so the final-stage assert below can compare them.
COPY --from=builder /build/.amalg-sha256-verified /app/.amalg-sha256-verified

# N-553 (punch 555): the base image's pip (25.0.1 at filing) carries 6 OSV
# advisories, all fixed in 26.2.0, and the admin Install runs
# `sys.executable -m pip install` in THIS image. N-621 (2026-10-20): the floor
# became a hash pin. pip 26.2.1 vendors certifi 2026.06.17, inside
# GHSA-6q48-6c7w-9gw2; 26.2.2 vendors 2026.10.19. requirements-pip.txt carries
# both sha256 hashes, so pip refuses any other bytes. After the builder COPY so
# nothing later in the stage can put an older pip back.
COPY requirements-pip.txt /tmp/requirements-pip.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
        --require-hashes --only-binary :all: -r /tmp/requirements-pip.txt \
    && rm /tmp/requirements-pip.txt

# punch 538 / cve-arc  — the declaration and its parser ship in the RUNTIME
# image too, because the proof cve-arc relies on is about the image that runs,
# not the builder that made it. COPYed before the RUN below, which reads them.
COPY source-built.pins /app/source-built.pins
COPY scripts/source_built.py /app/scripts/source_built.py
# Punch 656: the SPKI deny-list check, COPYed before the RUN that follows the N-621 step.
COPY scripts/check_distrusted_spki.py /app/scripts/check_distrusted_spki.py
# N-616 / punch 634: the pin file this image ships, which the final-stage assert
# compares with the pin sha recorded in the builder's marker.
COPY vendor/sqlite3.expected.sha256 /app/vendor/sqlite3.expected.sha256

# 2026-06-13 — encryption runtime crypto guarantee + per-platform smoke.
# The `apt-get -y upgrade` first applies the distro's security fixes the
# pinned base predates (2026-11-04: apt 3.0.3 -> 3.0.4, CVE-2026-109518 /
# DSA-6607-1, while the newest python:3.14-slim still shipped 3.0.3). The
# BUILD_SHA label above busts the cache, so it runs on every deploy; the
# ca-certificates distrust step below runs after it, as G3 requires. The
# upgrade makes the package set a function of the build date, so the same RUN
# writes the as-built set to /app/.dpkg-manifest (N-658; db-sme S3): the
# locks' `base=` names the base, not what this image ships. `upgrade` keeps
# back a package whose new version needs a new dependency and still exits 0,
# so the build fails unless apt and libapt-pkg7.0 reached the DSA-6607-1 fix
# (3.0.4). Drop those two checks with the upgrade when the base ships >= 3.0.4.
#
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
#
# punch 538 (2026-09-29): the version half of that smoke is now
# ``source_built.py verify`` against the declaration, on the SHIPPING image
# rather than on the builder's ``/install`` tree — this is the run whose
# success is what cve-arc's silencing rule actually rests on. The walresetbug
# floor stays as a separate, independently-reasoned lower bound.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confold upgrade && apt-get install -y --no-install-recommends libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apt)" ge 3.0.4 && \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libapt-pkg7.0)" ge 3.0.4 && \
    dpkg-query -W > /app/.dpkg-manifest && \
    python -c "import sqlcipher3.dbapi2 as d; \
assert d.sqlite_version_info >= (3, 51, 3), ('N-432 walresetbug floor', d.sqlite_version); \
print('sqlite_version', d.sqlite_version)" && \
    python /app/scripts/source_built.py verify /app/source-built.pins \
        > /app/.path3-verified

# N-621 / panel J (J1 + DA-1): the system CA store trusted two roots that anchor the
# compromised eMudhra keys: emSign ECC Root CA - G3, and AAA Certificate Services
# (mozilla/Comodo_AAA_Services_root.crt), which issued a Sectigo cross-sign for each
# compromised intermediate under the same key. ca-certificates 20250419 enables both
# in /etc/ca-certificates.conf, and Python's default verify path is that bundle: the
# IMAP probe, SMTP STARTTLS and pip's truststore all read it, and Python checks no
# revocation. GHSA-6q48-6c7w-9gw2 names G3 only (certifi never carried AAA); the
# incident's own Debian mitigation disables both. certifi 2026.10.19 kept C1, C3 and
# G1, and USERTrust RSA stays, so this disables exactly the two roots in D and rebuilds
# the bundle, matching by the SHA-256 of each certificate's DER, never by file name.
# J-F1: the base image is not digest-pinned, so a root may already be gone upstream;
# the step then skips it. It asserts the parser sees a full bundle, and that each root
# is in the bundle exactly when its conf entry is enabled, so a wrong fingerprint fails
# the build instead of skipping. It ALWAYS fails the build unless both roots are absent
# afterwards and the bundle is still full.
#
# Punch 654 (panel J DA): this step runs AFTER the runtime stage's last apt step (the
# libssl3 install above), so no later package step or dpkg trigger can re-enable a root
# after the check; the pin fails any runtime RUN after it that names apt, dpkg or
# ca-certificates. Punch 655 (db-sme M1): a conf entry counts as enabled only while
# /usr/share/ca-certificates still ships its file, so a stale enabled line for a .crt that
# upstream removed (Debian #764296) no longer fails the build; a wrong fingerprint still
# does. Punch 653 (hipaa + DA): the absent-after check also reads every file in
# /etc/ssl/certs (the CApath hash links OpenSSL reads besides the bundle), so a rebuild
# that leaves a link behind fails the build. Punch 652: the pin parses this body as Docker
# joins it (continuations concatenated, no newline) and checks its AST, not its text.
# Panel L db D3(a): `python -I -S` (isolated, no `site`), so no .pth file in the
# site-packages the builder COPY filled can run before the body (a .pth that calls
# os._exit(0) would turn the step green unrun); the body imports only the stdlib.
# Panel L DA-5: httpx and requests verify against certifi's cacert.pem, not this store,
# so the absent-after check also reads the one certifi bundle under /usr/local, found by
# path because `-S` puts no site-packages on sys.path.
RUN python -I -S -c "import base64, glob, hashlib, os, re, subprocess; \
D = {'86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b': 'mozilla/emSign_ECC_Root_CA_-_G3.crt', 'd7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4': 'mozilla/Comodo_AAA_Services_root.crt'}; \
B = '/etc/ssl/certs/ca-certificates.crt'; C = '/etc/ca-certificates.conf'; S = '/usr/share/ca-certificates/'; \
fps = lambda p: [hashlib.sha256(base64.b64decode(''.join(b.split()))).hexdigest() for b in re.findall('-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', open(p, errors='replace').read(), re.S)]; \
pre = fps(B); \
assert len(pre) > 100, ('N-621: the bundle parser saw too few roots, so the distrust check would be blind', len(pre)); \
lines = open(C).read().splitlines(); \
on = lambda f: lines.count(D[f]) == 1 and os.path.isfile(S + D[f]); \
assert all((f in pre) == on(f) for f in D), ('N-621: a distrusted root must be in the bundle exactly when ' + C + ' holds one enabled entry for it and ' + S + ' ships its file', [(D[f], f in pre, lines.count(D[f]), os.path.isfile(S + D[f])) for f in D]); \
bad = [D[f] for f in D if f in pre]; \
bad and open(C, 'w').write(chr(10).join('!' + x if x in bad else x for x in lines) + chr(10)); \
bad and subprocess.run(['update-ca-certificates', '--fresh'], check=True); \
[print('N-621:', D[f], 'already absent upstream') for f in D if f not in pre]; \
after = fps(B); \
capath = [h for p in sorted(glob.glob('/etc/ssl/certs/*')) if os.path.isfile(p) for h in fps(p)]; \
K = glob.glob('/usr/local/lib/python3*/site-packages/certifi/cacert.pem'); \
assert len(K) == 1, ('N-621: expected exactly one certifi bundle under /usr/local', K); \
certifi = fps(K[0]); \
assert len(certifi) > 100, ('N-621: the certifi bundle parser saw too few roots', len(certifi)); \
assert not [f for f in D if f in after or f in capath or f in certifi], ('N-621: a distrusted root is still in ' + B + ', a CApath file in /etc/ssl/certs or ' + K[0], [D[f] for f in D if f in after or f in capath or f in certifi]); \
assert len(after) > 100, ('N-621: the system bundle is nearly empty', len(after)); \
print('N-621: emSign ECC Root CA - G3 and AAA Certificate Services absent from', B, 'from', len(capath), 'CApath certificates and from', K[0], '-', len(after), 'system roots,', len(certifi), 'certifi roots')"

# Punch 656 (panel J DA M-DA3): the step above distrusts two ROOTS by their DER hash; a key
# compromise is not bounded by roots, so this reads EVERY certificate the image bundles (the
# CApath and everything under /usr/local/lib: certifi and any vendored cacert.pem) and fails
# the build if one carries the SPKI of a compromised eMudhra key, whoever issued it. It is
# read-only, so it runs last, after the step that leaves the trust store in its final state
# (punch 654). It fails closed on an unparsable block and on a blind scan (fewer than 100
# certificates). The deny-list is src/email_triage/_distrusted_spki.py (one copy, shared with the
# run-time check in email_triage.tls); the script loads it from the package the builder COPY
# above installed into site-packages. The Python 3.14 note is in scripts/check_distrusted_spki.py.
RUN python -I -S /app/scripts/check_distrusted_spki.py

# 2026-05-17 — runtime-deps directory layout. The lazy
# embedding installer writes torch + sentence-transformers + the
# embedding model into the data volume (not into the image layer).
# HF_HOME points at the same volume so the model cache survives
# container restarts. The directory itself is created with the
# triage-user mode bits a few steps below, alongside the other
# mounted volumes.
ENV HF_HOME=/app/data/runtime-deps/hf-cache
# Punch 547: no ENV for the runtime-deps prefix (it was -e-overridable and
# chose what is verified and added to sys.path; the path is now a code
# constant) and no ENV Path-3 marker (``-e EMAIL_TRIAGE_PATH3_BASELINE=0``
# disarmed a fail-closed guard). The Path-3 marker is /app/.path3-verified,
# written above as the OUTPUT of ``source_built.py verify`` — it exists only
# in an image whose declaration was proved.

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
COPY scripts/n432-path3-bake-step2a.py /app/scripts/n432-path3-bake-step2a.py
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
# the marker-gated fail-CLOSED cipher_version guard. The guard at
# db/_engine.py::assert_cipher_version_floor no-ops when the baked marker
# /app/.path3-verified is absent (so pypi-wheel test envs don't
# false-fail); this build-time smoke PROVES the marker exists and the guard
# actually fires in the Path-3 image itself. Punch 547: the gate used to be
# an env var, which a runtime -e could flip; the marker cannot be typed.
# §164.312(a)(2)(iv) fail-CLOSED belt: the Containerfile itself asserts
# the guard-that-protects-the-encryption-boundary is armed + green.
RUN python -c "\
import os; \
assert os.path.isfile('/app/.path3-verified'), ('Path-3 marker /app/.path3-verified missing — guard would silently no-op at runtime'); \
from email_triage.db._engine import assert_cipher_version_floor; \
r = assert_cipher_version_floor(); \
assert r.get('applicable') is True, ('N-432 Path-3 guard did NOT fire — bypass surface introduced (image drift?): ' + repr(r)); \
assert 'cipher_version' in r and str(r['cipher_version']).startswith('4.20.'), ('N-432 Path-3 guard fired but cipher_version off expected line: ' + repr(r)); \
print('OK Path-3 guard armed:', r['cipher_version'], 'at floor', r['min_floor'])"

# N-616 / punch 634 (DA P3): no image without the STRICT amalgamation marker can
# exist, whatever the deploy path (a skipped bake, --from-registry, a manual
# build). The marker came --from=builder; the pin file came from the build
# context. Both must agree: two `sha256sum -c` OK lines, and a pin sha equal to
# the sha256 of the pin file this image ships.
RUN set -eu; \
    m=/app/.amalg-sha256-verified; \
    p=/app/vendor/sqlite3.expected.sha256; \
    [ -s "$m" ] || { echo "ERROR: $m missing: the amalgamation sha256 check did not pass STRICT"; exit 1; }; \
    [ "$(grep -cE '^sqlite3\.[ch]: OK$' "$m")" = 2 ] || { echo "ERROR: $m lacks the two sha256sum -c OK lines:"; cat "$m"; exit 1; }; \
    want="pin-sha256 $(sha256sum < "$p" | cut -d' ' -f1)"; \
    grep -qxF "$want" "$m" || { echo "ERROR: $m was produced for a different pin file than $p:"; cat "$m"; echo "shipped: $want"; exit 1; }; \
    echo "OK amalgamation marker: $(tr '\n' ' ' < "$m")"

# Punch 556 / N-559: the shipped SQLCipher honours the read-only opener.
# CI runs the runtime half of tests/test_n559_encrypted_readonly_opener_pin.py
# on the PyPI sqlcipher3 wheel (upstream's own build of SQLCipher 4.19.0); this
# image ships its source-built 4.20, so prove it here: a write through
# _make_encrypted_conn(read_only=True) must be refused. The probe turns the
# second layer (PRAGMA query_only) OFF first, so only mode=ro can refuse it:
# with query_only on, a mode=rwc regression would still refuse the write and
# pass (measured). The probe path holds '#' and '%' so the URI quoting is
# exercised too.
RUN printf '%s\n' \
      'import os, tempfile' \
      'from email_triage.db import _engine as e' \
      'p = os.path.join(tempfile.mkdtemp(), "n559 #ro%probe.db")' \
      'k = "n559-build-time-mode-ro-probe-0123456789abcdef"' \
      'w = e._make_encrypted_conn(p, k)' \
      'w.execute("CREATE TABLE t (a)")' \
      'w.commit()' \
      'r = e._make_encrypted_conn(p, k, read_only=True)' \
      'assert r.execute("SELECT count(*) FROM t").fetchone()[0] == 0' \
      'r.execute("PRAGMA query_only = OFF")' \
      'try:' \
      '    r.execute("INSERT INTO t VALUES (1)")' \
      'except Exception as x:' \
      '    assert "readonly" in str(x), x' \
      'else:' \
      '    raise SystemExit("N-559: mode=ro NOT honoured by this SQLCipher build")' \
      'print("OK N-559 mode=ro honoured, cipher", r.execute("PRAGMA cipher_version").fetchone()[0])' \
      > /tmp/n559_ro_probe.py \
 && python /tmp/n559_ro_probe.py \
 && rm -f /tmp/n559_ro_probe.py

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
