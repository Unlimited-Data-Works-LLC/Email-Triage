# Install & Setup

The v0.1.0+ container ships with a slim runtime image (~250 MB).
The heavy embedding stack (PyTorch CPU + sentence-transformers +
the `all-MiniLM-L6-v2` model, ~600 MB total) lazy-installs on
first admin setup. Most customers download those bits on first
run; air-gap installs ship them via a sideloaded tarball.

This page covers prerequisites, release verification, the pull
+ boot, and the four flavours of the embedding-stack install
flow.

## Prerequisites

- A Linux host with **Podman 5.0+** (or Docker 24+, with adjusted
  commands). Rocky Linux 10, RHEL 10, Ubuntu 24.04+, and Debian 12+
  are tested.
- **~8 GB RAM** for the application + the local LLM. More if you
  run multiple accounts or larger models.
- Disk allocation depends on where the install lands — see the
  **Disk allocation** table below. Most installs need ~10 GB
  comfortable; HIPAA installs with multi-year retention plan
  50+ GB on the persistent volume.
- A local **Ollama** install for the LLM (or an OpenAI-compatible
  endpoint on the same network). Cloud-LLM backends are optional
  and BAA-gated for HIPAA accounts.
- **cosign 2.0+** on the deploy host for image signature
  verification before pull. Strongly recommended; required for
  HIPAA installs.

## Disk allocation

Total host disk is the wrong frame — what matters is how much
space each mount point has independently. The most common install
failure is the persistent-volume bind sitting on a small partition:
pip dies mid-unpack during the embedding install with `Errno 28 No
space left on device`. Allocate per the table below.

| Location | Minimum | Why |
|---|---|---|
| Container image storage (podman/docker overlay layer) | ~3 GB | v0.1.0 image is ~250 MB but the engine keeps the active `:latest`, the rollback `:previous`, and any intermediate build layers. Plan for two generations + headroom. On RHEL-family systems this is typically `/var/lib/containers/storage`. |
| Persistent volume mounted at `/app/data` | **~5 GB minimum** | This is where the embedding stack installs (lazy on first admin setup): ~600 MB downloaded + ~1.5 GB unpacked = ~2.1 GB. Plus the embedding model cache (~90 MB; more if you switch models). Plus the SQLite DB which grows with mail volume, the sent-mail-index vectors (~3 KB per indexed sent message), and the audit hash chain (~1 KB per row, indefinite retention). For HIPAA installs with multi-year retention plan **50+ GB**. |
| `/app/config` | ~10 MB | YAML + TLS certs only. Usually a small bind mount; doesn't need its own LV. |
| Host `/tmp` available during install | ~1 GB | pip's wheel-unpack scratch space when the embedding install runs. Constrained-`/tmp` hosts can fail mid-install even with plenty of room on `/app/data`. |

If your container engine separates image-layer storage from the
persistent-volume bind, each path needs the headroom listed above
independently. Mounted-where matters more than total host capacity.

## Verify the release before pull

Email Triage container images are signed with cosign keyless OIDC
and (when destined for HIPAA installs) carry an operator-issued
in-toto attestation with a `hipaa_safe: true` predicate.

For all installs:

```bash
sudo cosign verify ghcr.io/unlimited-data-works-llc/email-triage:0.1.0 \
    --certificate-identity-regexp \
        'https://github.com/Unlimited-Data-Works-LLC/.+/release\.yml@.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

> **Tag form:** the registry publishes both `:0.1.0` and `:v0.1.0`
> pointing at the same digest, matching whichever form your tooling
> defaults to. Examples in this doc use the bare semver (`0.1.0`)
> matching standard docker-pull convention.

For **HIPAA installs**, additionally verify the operator
attestation:

```bash
sudo cosign verify-attestation ghcr.io/unlimited-data-works-llc/email-triage:0.1.0 \
    --type custom \
    --certificate-identity-regexp \
        'https://github.com/Unlimited-Data-Works-LLC/.+/operator-attest\.yml@.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.payload | @base64d | fromjson | .predicate | select(.hipaa_safe == true)'
```

The `jq` filter returns the attestation predicate body if and
only if `hipaa_safe: true` is asserted. Empty output means the
operator has NOT signed off on this build for HIPAA use; HIPAA
installs MUST NOT apply it.

## Pull + boot

```bash
sudo podman pull ghcr.io/unlimited-data-works-llc/email-triage:0.1.0
sudo podman tag  ghcr.io/unlimited-data-works-llc/email-triage:0.1.0 \
                 localhost/email-triage:latest
```

Boot the container with your usual systemd quadlet / compose /
direct-run setup. The slim image boots cleanly without the
embedding stack — basic mail-routing + classification work
immediately. The style-learning features that need vector
retrieval are disabled until the embedding install completes.

## First-time embedding setup (connected install)

1. Bring the container up the usual way (Podman / Docker / direct
   `email-triage serve`). The image boots cleanly without the
   embedding stack — classification works, but the style-learning
   features that need vector retrieval are disabled.

2. Navigate to **Config → AI Backends**. Between the "Currently
   running" card and the metrics table you'll see a new card:
   **"Local embedding backend — install"**. The status will be
   `not installed`.

3. Click **Install now (download from internet)**. The installer
   fetches each manifest-listed wheel + model file over HTTPS,
   verifies every SHA-256 against the manifest baked into the
   image, and pip-installs the wheels into the persistent volume
   at `/app/data/runtime-deps`.

4. Progress is shown inline (files done / total, MB done / total,
   current file). The page self-polls every 2 seconds while an
   install is in flight. Typical wall-clock time is 5–10 minutes
   on a home connection.

5. On completion the card shows `✓ Installed` with the timestamp,
   runtime path, and short manifest hash. The status will not
   change until you reinstall or re-verify.

6. **Restart the container** to wire up the embedding backend
   against the configured model. Until restart, the live backend
   reflects whatever was loaded at boot — the install is on disk
   but the FastAPI app's `state.embedding_backend` is not yet
   pointing at it.

> The installer always verifies file hashes against the pinned
> manifest. There is no `--force` or `--skip-hash` flag — a hash
> mismatch is a hard refusal. Re-running on a clean failed state
> uses the cached-hash fast-path (no re-download of already-good
> files).

## Air-gap install via sideload

For installs without outbound internet access, the bits are
downloaded on a CONNECTED machine, packaged into a tarball, and
sideloaded onto the target.

### On the connected machine

```bash
# Stages all files + verifies hashes + packages
./scripts/download-embedding-bits.sh \
    ./embedding-bits-v0.1.x.tar.zst

# Outputs:
#   ./embedding-bits-v0.1.x.tar.zst
#   ./embedding-bits-v0.1.x.tar.zst.sha256
```

Resumable — the script caches downloads under
`${EMBEDDING_BITS_STAGING:-~/.cache/email-triage-embedding-bits}`.
A second run skips already-good files.

### On the target machine

```bash
# Copy both files to the target. Verify the sidecar:
sha256sum -c embedding-bits-v0.1.x.tar.zst.sha256

# Extract into the sideload dir (default /app/data/runtime-deps/sideload):
mkdir -p /app/data/runtime-deps/sideload
zstd -d embedding-bits-v0.1.x.tar.zst -c \
    | tar -x -C /app/data/runtime-deps/sideload

# Trigger the installer via the admin UI:
#   Config → AI Backends → "Sideload pre-staged bits"
# OR via CLI:
email-triage embedding-bits sideload \
    --source-dir /app/data/runtime-deps/sideload
```

The sideload path runs the **same hash verification** as the auto-
install — operator-staged bytes are not trusted. A bit-corrupted
tarball or a tampered air-gap drop trips the same HashMismatch
refusal as a poisoned mirror.

Alternative end-to-end via `scripts/install-embedding-bits.sh`:

```bash
# Wraps verify + extract + sideload in one command:
./scripts/install-embedding-bits.sh extract embedding-bits-v0.1.x.tar.zst
./scripts/install-embedding-bits.sh sideload
```

## Re-verifying an existing install

If a backup restore or container migration leaves you uncertain
whether the on-disk embedding bits are still intact:

* **Admin UI:** Config → AI Backends → expand the `installed`
  card and click **Re-verify**. The installer re-hashes every
  staged file against the manifest, no re-download.
* **CLI:** `email-triage embedding-bits verify`. Exits 0 on
  match, 1 on mismatch, with the offending filename on stderr.

A mismatch surfaces in the install card as `failed`. Click
**Retry (auto-download)** to refetch the corrupted files (or
**Sideload pre-staged bits** for air-gap targets).

## Switching embedding models

The shipped manifest pins `all-MiniLM-L6-v2` (384-dim, ~80 MB).
To switch to a different sentence-transformers model:

1. Update `embedding.model_name` in `/app/config/email-triage.yaml`
   via **Config → AI Backends → Embedding backend (primary)**.
2. Restart the container so the new model loads at boot.
3. **Re-embed existing rows** so retrieval comparisons work:
   * The `sent_mail_index` rows from the old model are tagged
     with `embedding_model` of the old name. They're effectively
     stale until re-embedded against the new backend.
   * Click the per-account **Reindex embeddings** button (admin-
     only; visible on the AI Backends tab once the runtime is
     ready) to enqueue a `triage_jobs` row with `kind='embedding_
     reindex'`. The bulk runner drains it in batches of 100 and
     updates the rows in place.
   * Monitor progress on the Triage → Bulk runs page.

For switching to Ollama (remote embedder, e.g. `nomic-embed-text`):

1. Set `embedding.backend = ollama` + `embedding.ollama_url` to
   the LAN URL of your Ollama instance.
2. Restart. The local embedding stack stays installed but unused
   (the lazy install is one-time; switching backends doesn't
   reset it).
3. Reindex as above.

> The privacy gate rejects non-LAN embedding URLs at startup. See
> `docs/privacy-audit-runbook.md` for the local-only rationale.

## Command reference

```text
email-triage embedding-bits install              # auto-download
email-triage embedding-bits sideload \           # air-gap install
    --source-dir /path/to/staged
email-triage embedding-bits verify               # re-hash on disk
email-triage embedding-bits status               # print state row
```

All four subcommands are equivalent to the admin UI buttons —
same code path under the hood (`email_triage.embedding_bits`).

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Install card stuck in `downloading` for >30 minutes | Worker task crashed without writing a terminal state. Click **Cancel**, then **Retry**. The cancel flag is honoured at the next file boundary; cached files survive. |
| `HashMismatch` on every retry | Upstream manifest drift, mirror corruption, or the wrong manifest is baked into the image. Compare `install_state.manifest_sha256` against the value printed by `scripts/build-embedding-bits-manifest.py`. |
| `Install state says "installed" but the package does not import` | The runtime path isn't on `sys.path`. Restart the container so `email_triage.embedding_bits.add_runtime_to_sys_path()` runs at boot. |
| Style-data page shows "Style-learning features are paused" | The configured embedding backend can't load. Check **Config → AI Backends → Currently running** — the live backend line names the actual problem. |
| `Source dir does not exist` on sideload | The extract step didn't run or chose a different path. Default is `/app/data/runtime-deps/sideload`; override via the form field on the admin card. |
