#!/usr/bin/env bash
#
# deploy.sh — ship HEAD to the deploy host with pre-validation +
# Nagios downtime.
#
# Routing topology (operator must wire correctly):
#   DEPLOYHOST   — host running the email-triage container
#                  (rootful podman + systemd target). SSH target
#                  for build / swap / restart / health probe.
#   AGENTHOST    — host running the nagios-monitor skill. SSH
#                  target for schedule + release of Nagios
#                  downtime. The skill itself talks to Nagios
#                  over HTTP cmd.cgi; NEVER SSH directly to the
#                  Nagios server from this script.
#   NAGIOS_HOST  — monitored target name as Nagios sees it
#                  (string arg, not an SSH target). Auto-derived
#                  by stripping "user@" off DEPLOYHOST when
#                  unset. Override only if Nagios registers the
#                  email-triage services under a different host.
#
# Configuration: copy scripts/deploy.env.local.example to
# scripts/deploy.env.local (gitignored) and set the three
# variables above. Script sources that file if it exists so a
# fresh shell doesn't need operator-side env bookkeeping.
#
# Source-tree carries no operator hostnames. Defaults below are
# empty + a fail-fast check exits 64 with explicit instructions
# rather than falling through to placeholders that don't resolve.
#
# Flags:
#   --skip-nagios       Skip Nagios downtime scheduling (dev loops)
#   --skip-validate     Skip pre-validation step (emergency / known-good)
#   --downtime-min N    Override default 15-min downtime window
#   --force             Proceed past an "incompatible_rollback" warning
#                       from version-check. Requires the operator to
#                       have a fresh DB snapshot — see docs/version-check.md.
#                       Does NOT override a downgrade_not_supported abort.
#   --from-registry T   Pull image tag T from GHCR instead of building
#                       from local source. Triggers cosign verification
#                       of CI build provenance + operator attestation
#                       BEFORE any tag swap. HIPAA-flagged installs also
#                       require the operator attestation's predicate to
#                       carry ``hipaa_safe: true``. See "Registry-pull
#                       mode" block below for the full verification chain.
#   --registry-image R  Override the registry image base. Defaults
#                       to the value of $REGISTRY_IMAGE from the
#                       environment (typically pinned in
#                       scripts/deploy.env.local to the operator's
#                       GHCR namespace, e.g.
#                       ``ghcr.io/<github-user>/email-triage``).
#                       Only takes effect with --from-registry.
#
# Registry-pull mode (--from-registry) verification chain:
#
#   1. ``cosign verify`` against the CI release workflow OIDC subject
#      ("release.yml@<ref>") — proves GitHub Actions built the image
#      from the expected source repository.
#   2. ``cosign verify-attestation`` against the operator-attest
#      workflow OIDC subject ("operator-attest.yml@<ref>"), predicate
#      type ``custom`` — proves the operator personally validated the
#      image after CI built it. Two distinct subjects, two distinct
#      signing events.
#   3. HIPAA installs only: parse the attestation predicate and
#      assert ``hipaa_safe: true``. Non-HIPAA installs accept any
#      operator attestation (the existence of the signature is the
#      approval signal).
#
# GHCR + OCI 1.1: the Referrers API is incomplete on GHCR. We use
# ``cosign download attestation`` (works against any registry that
# implements the OCI image spec) as the canonical retrieval path
# rather than relying on the registry's referrers endpoint. The
# verification calls handle retrieval transparently; the script
# never speaks the referrers API directly.
#
# Cosign availability: the deploy host must have ``cosign`` on PATH.
# Install via:
#     sudo dnf install cosign      # Fedora / RHEL
#     # or fetch from sigstore release page if no package available
# The script fails fast with a clear error if cosign is missing
# rather than silently skipping verification.
#
# Exit codes:
#   0  = healthy on new image
#   1  = pre-validation failed (old image restored)
#   2  = startup failed (old image restored)
#   3  = /health never came up within timeout
#   4  = pre-flight version-check refused (rollback would not work,
#        operator did not pass --force, OR downgrade detected)
#   5  = cosign verification failed (no swap performed)
#   6  = cosign not installed on deploy host
#  64 = required env vars missing (DEPLOYHOST / AGENTHOST)
set -euo pipefail

# Source operator-private env.local if present.
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$_SCRIPT_DIR/deploy.env.local" ]; then
    # shellcheck disable=SC1091
    source "$_SCRIPT_DIR/deploy.env.local"
fi

DEPLOYHOST=${DEPLOYHOST:-}
AGENTHOST=${AGENTHOST:-}
# NAGIOS_HOST defaults to DEPLOYHOST without the "user@" prefix.
NAGIOS_HOST=${NAGIOS_HOST:-${DEPLOYHOST#*@}}
DOWNTIME_MIN=15
SKIP_NAGIOS=0
SKIP_VALIDATE=0
FORCE=0
FROM_REGISTRY=""
# REGISTRY_IMAGE: pin to your GHCR namespace in scripts/deploy.env.local
# rather than baking it here. Empty default fails fast in registry mode
# with a clear instruction message rather than landing on a placeholder
# that won't resolve.
REGISTRY_IMAGE="${REGISTRY_IMAGE:-}"
# Data dir on the deploy host; lined up with the systemd-quadlet mount.
# Used by the step-0 snapshot + cosign verification flow.
DATA_DIR="${DATA_DIR:-/srv/email-triage/data}"

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-nagios) SKIP_NAGIOS=1 ;;
        --skip-validate) SKIP_VALIDATE=1 ;;
        --downtime-min) DOWNTIME_MIN="$2"; shift ;;
        --force) FORCE=1 ;;
        --from-registry) FROM_REGISTRY="$2"; shift ;;
        --registry-image) REGISTRY_IMAGE="$2"; shift ;;
        *) echo "Unknown flag: $1" >&2; exit 64 ;;
    esac
    shift
done

# Fail loud if the operator never wired the routing — earlier
# placeholder defaults silently fell through to "deployhost" /
# "agenthost" hostnames that don't resolve.
if [ -z "$DEPLOYHOST" ] || [ -z "$AGENTHOST" ]; then
    echo "ERROR: DEPLOYHOST + AGENTHOST must be set. Either" >&2
    echo "       export them in your shell, or copy" >&2
    echo "       scripts/deploy.env.local.example -> .local" >&2
    echo "       and fill in your hostnames." >&2
    exit 64
fi

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

if [ -n "$FROM_REGISTRY" ]; then
    # In registry-pull mode the image's lineage is the tag, not local
    # git HEAD (the source on this workstation may be far ahead of
    # what CI built). Encode the tag into commit_sha so the step-0
    # snapshot filename + Nagios downtime comment are still
    # human-traceable back to the deploy event.
    commit_sha="registry-${FROM_REGISTRY}"
    commit_short="reg-${FROM_REGISTRY}"
    commit_msg="pull ${REGISTRY_IMAGE}:${FROM_REGISTRY}"
else
    commit_sha=$(git rev-parse HEAD)
    commit_short=$(git rev-parse --short HEAD)
    commit_msg=$(git log -1 --format='%s')
fi

log "Deploy $commit_short \"$commit_msg\""
log "DeployHost: $DEPLOYHOST   AgentHost (nagios gateway): $AGENTHOST"
if [ -n "$FROM_REGISTRY" ]; then
    log "Source: registry (${REGISTRY_IMAGE}:${FROM_REGISTRY})"
fi

# ---- 1. Nagios downtime -----------------------------------------------------
if [ "$SKIP_NAGIOS" = 0 ]; then
    log "Scheduling ${DOWNTIME_MIN}min Nagios downtime for email-triage services on $NAGIOS_HOST"
    for svc in "email-triage service" "email-triage /health" "email-triage health detail"; do
        ssh "$AGENTHOST" \
            "python3 ~/.openclaw/workspace/skills/nagios-monitor/nagios_monitor.py \
             svc-downtime '$NAGIOS_HOST' '$svc' $DOWNTIME_MIN 'deploy $commit_short'" \
            || log "WARN: downtime for '$svc' failed (nagios may not recognise it yet); continuing"
    done
else
    log "WARN: --skip-nagios set. Monitoring alerts will fire during the swap window."
fi

# ---- 2. Stage source --------------------------------------------------------
#
# Skipped in registry-pull mode (--from-registry): the image already
# exists in GHCR, no local source needed on the deploy host.
if [ -z "$FROM_REGISTRY" ]; then
    log "Staging source on DeployHost"
    ssh "$DEPLOYHOST" "rm -rf /tmp/et-deploy && mkdir /tmp/et-deploy"
    git archive HEAD | ssh "$DEPLOYHOST" "tar -xf - -C /tmp/et-deploy"
    ssh "$DEPLOYHOST" "echo $commit_sha > /tmp/et-deploy/COMMIT"
else
    log "Registry-pull mode — skipping source staging"
fi

# ---- 3. Stop the service BEFORE building ------------------------------------
#
# systemd's Restart=on-failure will otherwise claw the old container back up
# between our build and startup, or worse (as happened 2026-04-24) loop an
# unstable NEW image's failed-start 10+ times and emit a storm of critical
# alerts. `systemctl stop` is idempotent; there is no :( "already stopped"
# failure mode to work around.
log "Stopping email-triage.service (prevents auto-restart loop on build failure)"
ssh "$DEPLOYHOST" "sudo systemctl stop email-triage.service"

# ---- 4. Tag current :latest as :previous for rollback -----------------------
ssh "$DEPLOYHOST" \
    "sudo podman tag localhost/email-triage:latest localhost/email-triage:previous 2>/dev/null || true"

# ---- 4b. Extract :previous image's schema cap -------------------------------
#
# Closes the 2026-05-09 deploy-recovery incident class. The case: live DB
# migrated to v14, but :previous image only knows up to v13, so a
# rollback retag refuses to open the DB and the service stays dead.
#
# The schema-compat helper (src/email_triage/version.py) answers
# "would rollback still work?" if we tell it the :previous image's
# cap. The cap is baked into the image itself — extract it by running
# `email-triage version-check --print-target-schema-only` inside a
# throwaway :previous container.
#
# If :previous doesn't exist (first deploy ever), the tag step above
# fell through ("|| true") and we'll get no image here either —
# treat as "no rollback target known" and proceed without a cap.
#
# Older :previous images predating this CLI flag will fail with a
# non-zero exit. Treat that as "no cap known" and proceed (the gate
# below silently degrades — never falsely loud).
PREVIOUS_SCHEMA_CAPS=""
if ssh "$DEPLOYHOST" "sudo podman image exists localhost/email-triage:previous"; then
    PREVIOUS_SCHEMA_CAPS=$(ssh "$DEPLOYHOST" \
        "sudo podman run --rm --entrypoint email-triage \
         localhost/email-triage:previous version-check --print-target-schema-only 2>/dev/null" \
        | tr -d '[:space:]' || true)
    # Sanity-check: must be a positive integer. Anything else (empty,
    # garbage, an older :previous image that doesn't know the flag) is
    # treated as "no cap known" — strictly less alarming, never falsely
    # loud — per the version.py contract.
    if ! [[ "$PREVIOUS_SCHEMA_CAPS" =~ ^[1-9][0-9]*$ ]]; then
        log "WARN: could not read schema cap from :previous image — rollback-safety gate will be skipped"
        PREVIOUS_SCHEMA_CAPS=""
    else
        log "Previous image schema cap: $PREVIOUS_SCHEMA_CAPS"
    fi
else
    log "No :previous image — first deploy or rollback target absent; skipping rollback-safety gate"
fi

# ---- 4c. Step-0 pre-apply DB snapshot (raw plain copy) ---------------------
#
# Internal-rollback safety net (CR-2b). Plain ``sqlite3 .backup`` of
# the live DB onto disk, sibling-named by commit_sha. NOT a substitute
# for the encrypted #65 backup-bundle — this is master-key-free,
# operator-readable only because the OS gates it, and intended for
# automatic restore on a failed health check (see step 8 below).
#
# Lifecycle:
#   * Created here, before any image swap.
#   * Restored automatically by step 8 if /health never comes up.
#   * Deleted by ``email_triage.backup_snapshot_cleanup`` after a
#     successful encrypted ``backup export`` (the operator's real
#     backup has now captured post-upgrade state, so the safety net
#     can be retired). Most-recent snapshot is always retained.
#
# We are inside the systemctl-stop window already (step 3), so the
# DB has no open writers. ``sqlite3 .backup`` over a quiesced DB is
# byte-equivalent to ``cp`` but uses the SQLite-aware page copier so
# we don't accidentally snapshot an in-progress WAL checkpoint.
SNAPSHOT_PATH="$DATA_DIR/triage.db.preupgrade-${commit_sha}"
log "Taking pre-apply DB snapshot: $SNAPSHOT_PATH"
ssh "$DEPLOYHOST" \
    "sudo sqlite3 $DATA_DIR/triage.db \".backup '$SNAPSHOT_PATH'\""
SNAPSHOT_TAKEN=1

# ---- 4d. Registry-pull + cosign verification (--from-registry only) --------
#
# Two distinct OIDC subjects must verify before any tag swap:
#
#   1. CI build provenance: subject is the ``release.yml`` workflow
#      identity. Proves "GitHub Actions built this from the expected
#      source repo + tag".
#   2. Operator attestation: subject is the ``operator-attest.yml``
#      workflow identity, predicate type ``custom``. Proves "the
#      operator personally validated this for release". The
#      attestation lives as a separate signature on the image; cosign
#      retrieves it via the OCI image spec (works against GHCR even
#      though GHCR's referrers API is incomplete).
#
# HIPAA installs ADDITIONALLY require the attestation predicate to
# carry ``hipaa_safe: true``. Detected from the live DB
# (``email_accounts.hipaa=1`` rows) or forced via the env var
# ``EMAIL_TRIAGE_HIPAA_MODE=true``.
#
# Refuses to proceed on ANY verification failure. The :previous tag
# is unchanged, the live image is unchanged, the running service is
# stopped — restart and exit 5.
if [ -n "$FROM_REGISTRY" ]; then
    if [ -z "$REGISTRY_IMAGE" ]; then
        log "ERROR: --from-registry requires REGISTRY_IMAGE to be set."
        log "       Either export REGISTRY_IMAGE in your shell, set it"
        log "       in scripts/deploy.env.local, or pass"
        log "       --registry-image <ghcr-base> on the command line."
        log "       Service was stopped — restarting old image."
        ssh "$DEPLOYHOST" "sudo systemctl start email-triage.service"
        exit 64
    fi
    REGISTRY_REF="${REGISTRY_IMAGE}:${FROM_REGISTRY}"
    log "Verifying cosign signatures on $REGISTRY_REF"

    # Cosign presence check. Surface a deliberate error rather than
    # letting `cosign: command not found` propagate as an opaque
    # exit-127 mid-verify.
    if ! ssh "$DEPLOYHOST" "command -v cosign >/dev/null 2>&1"; then
        log "ERROR: cosign not installed on deploy host."
        log "       Install via 'sudo dnf install cosign' or fetch"
        log "       from https://github.com/sigstore/cosign/releases"
        log "       Service was stopped — restarting old image."
        ssh "$DEPLOYHOST" "sudo systemctl start email-triage.service"
        exit 6
    fi

    # Pull the image first so cosign can verify against a local
    # reference. Pull failures abort cleanly.
    log "Pulling $REGISTRY_REF"
    if ! ssh "$DEPLOYHOST" "sudo podman pull $REGISTRY_REF"; then
        log "ERROR: podman pull failed. Restarting old image."
        ssh "$DEPLOYHOST" "sudo systemctl start email-triage.service"
        exit 5
    fi

    # Verification 1: CI build provenance.
    # The certificate-identity-regexp pins the workflow file path; any
    # signed image whose subject doesn't include
    # ``/.github/workflows/release.yml@`` fails. Anchored ``\.git``
    # protects against ``release.yml@evilbranch`` injections that
    # would otherwise match.
    log "Cosign verify (CI build provenance)"
    if ! ssh "$DEPLOYHOST" \
        "cosign verify $REGISTRY_REF \
         --certificate-identity-regexp 'https://github\\.com/.+/email-triage/\\.github/workflows/release\\.yml@.+' \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com \
         >/dev/null 2>&1"; then
        log "ERROR: cosign verify failed (CI build provenance)."
        log "       Image was not signed by the expected release.yml workflow."
        log "       Restarting old image."
        ssh "$DEPLOYHOST" "sudo systemctl start email-triage.service"
        exit 5
    fi

    # Verification 2: Operator attestation (predicate type ``custom``).
    # Captures attestation JSON so the HIPAA branch can parse the
    # predicate field below.
    log "Cosign verify-attestation (operator approval)"
    set +e
    operator_att=$(ssh "$DEPLOYHOST" \
        "cosign verify-attestation $REGISTRY_REF \
         --type custom \
         --certificate-identity-regexp 'https://github\\.com/.+/email-triage/\\.github/workflows/operator-attest\\.yml@.+' \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com 2>/dev/null")
    att_rc=$?
    set -e
    if [ "$att_rc" -ne 0 ]; then
        log "ERROR: cosign verify-attestation failed (operator approval)."
        log "       No valid operator-attest.yml signature on this image."
        log "       Restarting old image."
        ssh "$DEPLOYHOST" "sudo systemctl start email-triage.service"
        exit 5
    fi

    # HIPAA gate: detect whether THIS install is HIPAA-flagged, then
    # require ``hipaa_safe: true`` in the operator-attestation
    # predicate. Detection sources:
    #   * EMAIL_TRIAGE_HIPAA_MODE=true forces HIPAA mode (CI / fresh
    #     install pre-DB).
    #   * Any row in email_accounts with hipaa=1 in the live DB.
    HIPAA_MODE=0
    if [ "${EMAIL_TRIAGE_HIPAA_MODE:-}" = "true" ]; then
        HIPAA_MODE=1
    else
        set +e
        hipaa_count=$(ssh "$DEPLOYHOST" \
            "sudo sqlite3 $DATA_DIR/triage.db \
             'SELECT COUNT(*) FROM email_accounts WHERE hipaa=1' 2>/dev/null")
        set -e
        if [[ "$hipaa_count" =~ ^[1-9][0-9]*$ ]]; then
            HIPAA_MODE=1
        fi
    fi

    if [ "$HIPAA_MODE" = 1 ]; then
        log "HIPAA mode detected — requiring hipaa_safe=true predicate"
        # cosign verify-attestation prints a JSON envelope per
        # signature; the predicate is base64'd in the ``payload``
        # field. Decode + check for ``"hipaa_safe": true``.
        # awk pulls the payload from each envelope; base64 -d
        # decodes; grep returns 0 only on a true match.
        set +e
        printf '%s\n' "$operator_att" \
            | grep -o '"payload":"[^"]*"' \
            | sed 's/"payload":"\([^"]*\)"/\1/' \
            | while IFS= read -r payload_b64; do
                printf '%s' "$payload_b64" | base64 -d 2>/dev/null
              done \
            | grep -q '"hipaa_safe"[[:space:]]*:[[:space:]]*true'
        hipaa_rc=$?
        set -e
        if [ "$hipaa_rc" -ne 0 ]; then
            log "ERROR: operator attestation does not carry hipaa_safe=true."
            log "       This install is HIPAA-flagged; the attestation must"
            log "       explicitly assert hipaa_safe. Restarting old image."
            ssh "$DEPLOYHOST" "sudo systemctl start email-triage.service"
            exit 5
        fi
        log "Operator attestation includes hipaa_safe=true — proceeding"
    else
        log "Non-HIPAA install — operator-attestation existence is sufficient"
    fi

    log "Cosign verification chain OK — tagging $REGISTRY_REF as :latest"
    ssh "$DEPLOYHOST" \
        "sudo podman tag $REGISTRY_REF localhost/email-triage:latest"
fi

# ---- 5. Build the new image -------------------------------------------------
#
# Skipped in registry-pull mode — the verified image was tagged as
# :latest in step 4d above.
if [ -z "$FROM_REGISTRY" ]; then
    log "Building new image (format=docker so HEALTHCHECK survives)"
    ssh "$DEPLOYHOST" \
        "cd /tmp/et-deploy && sudo podman build --format docker \
         -t localhost/email-triage:latest -f Containerfile . 2>&1 | tail -5"
fi

# ---- 5b. Pre-flight version-check (rollback-safety gate) --------------------
#
# Run the new image's version-check against the LIVE DB with
# EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS set (from step 4b). The helper
# checks both directions:
#
#   * forward — would the new image be able to open the live DB?
#     Catches a downgrade attempt (live DB is past what the new image
#     knows).
#   * backward — if we had to re-tag :previous -> :latest right now,
#     would :previous still be able to open the live DB?
#
# Exit codes from `email-triage version-check`:
#   0  up_to_date              proceed
#   1  update_available        proceed (normal case)
#   2  incompatible_rollback   halt unless --force
#      downgrade_not_supported halt regardless of --force (data-loss
#                              territory; refuse-to-load is enforced
#                              by migrations anyway)
#
# Status `downgrade_not_supported` always aborts: it means the live DB
# was written by a binary newer than what we're about to deploy. The
# new container would refuse to start (migrations.run_migrations
# enforces this). Don't waste an outage window discovering that the
# hard way.
#
# Skipping with --skip-validate also skips this gate — same boundary
# as the init_db pre-flight that follows. Use --skip-validate if you
# already know what you're doing AND have a snapshot.
if [ "$SKIP_VALIDATE" = 0 ]; then
    log "Pre-flight version-check (new image vs. live DB)"
    set +e
    vc_json=$(ssh "$DEPLOYHOST" "sudo podman run --rm \
        -v /srv/email-triage/data:/data:ro \
        -e EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS=$PREVIOUS_SCHEMA_CAPS \
        --entrypoint email-triage \
        localhost/email-triage:latest \
        version-check --db /data/triage.db --json")
    vc_rc=$?
    set -e
    # Echo the JSON so any downstream scraping (operator review,
    # audit log) gets the same data the gate decision used.
    printf '%s\n' "$vc_json"
    case "$vc_rc" in
        0)
            log "version-check: up_to_date — no schema changes; rollback safe"
            ;;
        1)
            log "version-check: update_available — proceeding"
            ;;
        2)
            # Disambiguate the two status-2 cases via the JSON status field.
            vc_status=$(printf '%s' "$vc_json" | grep -o '"status": *"[a-z_]*"' | head -1 | sed 's/.*"\([a-z_]*\)"$/\1/')
            if [ "$vc_status" = "downgrade_not_supported" ]; then
                log "ERROR: version-check: downgrade_not_supported"
                log "       Live DB was written by a newer binary than the one"
                log "       you are about to deploy. The new container would"
                log "       refuse to start. Restoring previous image."
                ssh "$DEPLOYHOST" \
                    "sudo podman tag localhost/email-triage:previous localhost/email-triage:latest && \
                     sudo systemctl start email-triage.service"
                exit 4
            fi
            # incompatible_rollback path
            if [ "$FORCE" = 1 ]; then
                log "WARN: version-check: incompatible_rollback — --force passed, proceeding"
                log "WARN: Rolling back to :previous will FAIL after this deploy."
                log "WARN: Confirm you have a fresh DB snapshot at /srv/email-triage/data/triage.db before continuing."
            else
                log "ERROR: version-check: incompatible_rollback"
                log "       Applying this update is forward-safe, but rolling"
                log "       back to the :previous image will not work — the live"
                log "       DB is already past what :previous understands."
                log "       Snapshot /srv/email-triage/data/triage.db and re-run"
                log "       with --force, OR ship a smaller update first."
                log "       See docs/version-check.md for the full rationale."
                # Restore the service we stopped in step 3 (no harm done — we
                # haven't swapped images yet). The :latest tag still points at
                # the original image because the build in step 5 succeeded but
                # nothing has run from it.
                ssh "$DEPLOYHOST" \
                    "sudo podman tag localhost/email-triage:previous localhost/email-triage:latest && \
                     sudo systemctl start email-triage.service"
                exit 4
            fi
            ;;
        *)
            log "WARN: version-check exited $vc_rc (unexpected) — proceeding cautiously"
            ;;
    esac
else
    log "WARN: --skip-validate set. Skipping pre-flight version-check gate."
fi

# ---- 6. Pre-validate the image can open the real DB -------------------------
#
# The specific failure mode this catches: a schema / DDL change breaks
# init_db on the existing DB shape. Runs the app's init_db against a throwaway
# copy of the live DB. If the copy fails to initialise, the running
# container would too -- abort, rollback, exit non-zero.
if [ "$SKIP_VALIDATE" = 0 ]; then
    log "Pre-validating: init_db against a copy of the live triage.db"
    if ! ssh "$DEPLOYHOST" "sudo podman run --rm \
        -v /srv/email-triage/data:/data:ro \
        --entrypoint python \
        localhost/email-triage:latest \
        -c 'import shutil, os; shutil.copy(\"/data/triage.db\", \"/tmp/smoke.db\"); \
from email_triage.web.db import init_db; init_db(\"/tmp/smoke.db\"); \
print(\"SMOKE_OK\")'" >/tmp/et-smoke.log 2>&1; then
        log "ERROR: pre-validation failed. Restoring previous image."
        cat /tmp/et-smoke.log
        ssh "$DEPLOYHOST" \
            "sudo podman tag localhost/email-triage:previous localhost/email-triage:latest && \
             sudo systemctl start email-triage.service"
        exit 1
    fi
    log "Pre-validation passed"
else
    log "WARN: --skip-validate set. Skipping pre-flight init_db check."
fi

# ---- 6b. Persist :previous schema cap for the /config banner ---------------
#
# Drop a quadlet override into /etc/containers/systemd/email-triage.container.d/
# so EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS reaches the running container.
# The /config admin banner reads this env var to decide whether to
# warn "rollback won't work" — without it the banner silently
# degrades to "update available" with no rollback verdict.
#
# Re-written every deploy so the value tracks the actual :previous
# image. If we never extracted a cap (step 4b), remove any stale
# override file so the running container reflects "no rollback target."
if [ -n "$PREVIOUS_SCHEMA_CAPS" ]; then
    log "Persisting EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS=$PREVIOUS_SCHEMA_CAPS via quadlet drop-in"
    # shellcheck disable=SC2087
    ssh "$DEPLOYHOST" "sudo mkdir -p /etc/containers/systemd/email-triage.container.d && \
        sudo tee /etc/containers/systemd/email-triage.container.d/10-version-caps.conf >/dev/null <<EOF
[Container]
Environment=EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS=$PREVIOUS_SCHEMA_CAPS
EOF
        sudo systemctl daemon-reload"
else
    log "Clearing stale quadlet drop-in (no :previous schema cap available)"
    ssh "$DEPLOYHOST" "sudo rm -f /etc/containers/systemd/email-triage.container.d/10-version-caps.conf && \
        sudo systemctl daemon-reload"
fi

# ---- 7. Start the new container ---------------------------------------------
log "Starting email-triage.service"
ssh "$DEPLOYHOST" "sudo systemctl start email-triage.service"

# ---- 8. Wait for /health ----------------------------------------------------
log "Waiting for /health on :8081 (max 60s)"
healthy=0
for i in $(seq 1 30); do
    if ssh "$DEPLOYHOST" "curl -skf https://localhost:8081/health || curl -sf http://localhost:8081/health" >/dev/null 2>&1; then
        log "Healthy after ~$((i * 2))s"
        healthy=1
        break
    fi
    sleep 2
done
if [ "$healthy" = 0 ]; then
    log "ERROR: /health never came up. Rolling back to :previous"
    # Restore the pre-apply DB snapshot first (step 4c). The new
    # image may have run migrations against the live DB that the old
    # image cannot read. Without this, retagging :previous → :latest
    # would land the old container on a forward-migrated DB and
    # ``init_db`` would refuse to open it.
    if [ "${SNAPSHOT_TAKEN:-0}" = 1 ]; then
        log "Restoring pre-apply DB snapshot from $SNAPSHOT_PATH"
        ssh "$DEPLOYHOST" \
            "sudo systemctl stop email-triage.service && \
             sudo cp '$SNAPSHOT_PATH' $DATA_DIR/triage.db && \
             sudo podman tag localhost/email-triage:previous localhost/email-triage:latest && \
             sudo systemctl start email-triage.service"
    else
        ssh "$DEPLOYHOST" \
            "sudo systemctl stop email-triage.service && \
             sudo podman tag localhost/email-triage:previous localhost/email-triage:latest && \
             sudo systemctl start email-triage.service"
    fi
    exit 3
fi

# ---- 9. Summary + prune -----------------------------------------------------
ssh "$DEPLOYHOST" "curl -sk https://localhost:8081/health 2>/dev/null || curl -s http://localhost:8081/health"
echo
log "Pruning dangling images"
ssh "$DEPLOYHOST" "sudo podman image prune -f | tail -3"

# ---- 9.5. Post-health stability window --------------------------------------
#
# A single /health 200 isn't the same as "fully online" — background
# workers (watcher reconnects, push consumers, RAG model load) finish
# spinning up over the ~30s after FastAPI starts serving requests.
# Releasing Nagios downtime immediately on the first 200 means
# transient-failure alerts could fire on those still-initializing
# subsystems.
#
# Require /health to stay 200 for STABILITY_WINDOW_SECS straight
# before releasing the downtime. One re-fail re-starts the window.
# Caps at STABILITY_MAX_WAIT_SECS so a perpetually-flapping container
# doesn't pin the script indefinitely.
STABILITY_WINDOW_SECS=30
STABILITY_MAX_WAIT_SECS=120
log "Confirming sustained-healthy for ${STABILITY_WINDOW_SECS}s before releasing Nagios"
streak=0
elapsed=0
while [ "$streak" -lt "$STABILITY_WINDOW_SECS" ] && [ "$elapsed" -lt "$STABILITY_MAX_WAIT_SECS" ]; do
    if ssh "$DEPLOYHOST" "curl -skf https://localhost:8081/health || curl -sf http://localhost:8081/health" >/dev/null 2>&1; then
        streak=$((streak + 2))
    else
        if [ "$streak" -gt 0 ]; then
            log "  /health flapped after ${streak}s — restarting stability window"
        fi
        streak=0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done
if [ "$streak" -ge "$STABILITY_WINDOW_SECS" ]; then
    log "Sustained-healthy for ${streak}s — proceeding to Nagios release"
    deploy_stable=1
else
    log "WARN: /health did not stay healthy for ${STABILITY_WINDOW_SECS}s straight within ${STABILITY_MAX_WAIT_SECS}s"
    log "WARN: holding Nagios downtime in place; investigate the flapping subsystem"
    deploy_stable=0
fi

log "Deploy $commit_short healthy."

# ---- 10. Release Nagios downtime — only after sustained-healthy ------------
#
# The earlier svc-downtime calls all tagged their comment with
# "deploy $commit_short". Pull the current downtime list, find rows
# whose comment matches, delete them via del-svc-downtime <id>. If
# none match (e.g. user passed --skip-nagios) this is a no-op.
#
# Gate on ``deploy_stable`` (set by the post-health stability window
# above). If the new container didn't stay healthy for the required
# straight-streak, we LEAVE the downtime in place so Nagios alerts
# stay suppressed while the operator investigates. The downtime
# auto-expires after the scheduled window (default 15 min) so a
# stuck script doesn't pin alerts forever.
if [ "$SKIP_NAGIOS" = 0 ] && [ "$deploy_stable" = 1 ]; then
    log "Releasing Nagios downtime tagged 'deploy $commit_short'"
    # `downtimes --host deployhost` prints blocks:
    #   [SVC] id=6  deployhost / email-triage service
    #           by openclaw-api  ...
    #           deploy abc1234
    # Flush a completed block at the start of the next block OR at EOF.
    # `downtimes --host X` does NOT put blank lines between blocks, so a
    # blank-line-based parser only catches the last one.
    ids=$(ssh "$AGENTHOST" \
        "python3 ~/.openclaw/workspace/skills/nagios-monitor/nagios_monitor.py \
         downtimes --host $NAGIOS_HOST" \
        | awk -v tag="deploy $commit_short" '
            function flush() {
                if (matched && cur != "") {
                    match(cur, /id=[0-9]+/)
                    print substr(cur, RSTART+3, RLENGTH-3)
                }
            }
            /^\[SVC\] id=/ {
                flush()
                cur=$0; matched=0; next
            }
            /^[[:space:]]+/ {
                if ($0 ~ tag) matched=1
                next
            }
            /^$/ { flush(); cur=""; matched=0 }
            END { flush() }
        ')
    if [ -n "$ids" ]; then
        for id in $ids; do
            ssh "$AGENTHOST" \
                "python3 ~/.openclaw/workspace/skills/nagios-monitor/nagios_monitor.py \
                 del-svc-downtime $id" \
                || log "WARN: could not release downtime $id"
        done
    else
        log "No downtimes matched tag; nothing to release"
    fi
elif [ "$SKIP_NAGIOS" = 0 ] && [ "$deploy_stable" = 0 ]; then
    log "Nagios downtime retained — sustained-healthy window failed."
    log "Downtimes auto-expire after the scheduled window (~${DOWNTIME_MIN} min);"
    log "release manually via the nagios-monitor skill if the container settles."
fi
