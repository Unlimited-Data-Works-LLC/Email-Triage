# Install & Setup

This guide covers deploying the container, supplying its master key,
turning on encryption-at-rest, and the environment variables that
control startup — then the one-time embedding-stack setup.

The container ships a slim runtime image (~250 MB). The heavy embedding
stack (PyTorch CPU + sentence-transformers + the `all-MiniLM-L6-v2`
model, ~600 MB) lazy-installs on first admin setup — see
[Embedding stack setup](#first-time-embedding-setup-connected-install)
below.

## Deploy the container

The image runs under Podman or Docker. It needs two volumes and a
config path:

| Mount / env | Purpose |
|---|---|
| `/app/data` (volume) | SQLite database, MSAL token cache, the lazy-installed embedding runtime |
| `/app/config` (volume) | `email-triage.yaml` + optional TLS certs |
| `EMAIL_TRIAGE_CONFIG` | Path to the config inside the container (default `/app/config/email-triage.yaml`) |

Compose is the simplest path (`compose.yaml` ships in the repo):

```bash
# 1. Put your email-triage.yaml in ./config/
# 2. Create the master-key secret (see "Master key & secrets" below)
# 3. Start:
podman-compose up -d
podman-compose logs -f
```

Or a direct run:

```bash
podman run -d --name email-triage \
    -p 8080:8080 \
    -v ./data:/app/data \
    -v ./config:/app/config \
    --secret ET_MASTER_KEY \
    ghcr.io/unlimited-data-works-llc/email-triage:0.1.2
```

The container's built-in healthcheck reports readiness on `/health`.

## Master key & secrets

Every user-managed secret (IMAP passwords, OAuth tokens, API keys) is
stored Fernet-encrypted in the database. At boot the app needs exactly
one thing to open that store: the **master key**. How it's supplied is
the *bootstrap backend*, set by `secrets.backend` in `email-triage.yaml`:

| Backend | Where the key comes from |
|---|---|
| `auto` *(default)* | Container secret `/run/secrets/ET_MASTER_KEY` if present, else `env` with a loud startup warning |
| `container` | `/run/secrets/<master_key_name>` (Podman/Docker secret) |
| `keyfile` | A file on disk (headless servers) |
| `keyring` | OS credential store (desktop) |
| `external:<name>` | A plugin provider (Vault, KeePass, …) — see [secrets_external_providers.md](secrets_external_providers.md) |
| `env` | **Deprecated — dev/CI only.** Key sits in the process environment (visible via `/proc/<pid>/environ`). Rejected at boot in HIPAA mode. |

Create the container secret — its name must match `secrets.master_key_name`
(default `ET_MASTER_KEY`):

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" \
    | podman secret create ET_MASTER_KEY -
```

> **Back up the master key.** Losing it makes every stored credential —
> and, with encryption-at-rest on, the entire database — unrecoverable.
> `email-triage backup export` produces a separate `*.etbkkey` bundle;
> store it apart from the data bundle.

The deprecated `env` backend is allowed for local dev / CI only; set
`EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY=1` there to silence the deprecation
warning. **HIPAA mode rejects the `env` backend at boot unconditionally**
— the carve-out var does not bypass it. (Sunset: hard error in v0.2.0
non-HIPAA, removed in v0.3.0.)

## Encryption at rest (v0.1.2)

v0.1.2 can encrypt the single SQLite database file with **SQLCipher
(AES-256)**, keyed by an HKDF-SHA256 derivation of the master key — no
new key to manage. **New installs are encrypted by default** — the `init`
scaffold and the example configs set `encryption_enabled: true`. The setting
only *defaults* off as a dataclass fallback, so an existing plaintext install
keeps booting unchanged after an upgrade until you migrate it.

**Requirements:** the `encryption` extra (`sqlcipher3-binary`,
Linux/container only — already baked into the published image) and a
reachable master key.

**Control it** with either:
- YAML — `persistence: { encryption_enabled: true }`, or
- env — `EMAIL_TRIAGE_DB_ENCRYPTION=true` (overrides the YAML field).

**New install:** the database is created encrypted at first boot
(`init_db_encrypted`) — no migration step. Set `encryption_enabled: false`
to opt out.

**Existing plaintext install — one-time migration:**

```bash
# 1. Stop the service.
# 2. Migrate in place (derives the SQLCipher key from ET_MASTER_KEY;
#    leaves a *.plaintext.bak rollback alongside the DB):
email-triage db encrypt --db /app/data/triage.db --yes
# 3. Redeploy with encryption enabled (EMAIL_TRIAGE_DB_ENCRYPTION=true
#    or persistence.encryption_enabled: true).
```

The migration is reversible with `email-triage db decrypt`. Once the
cutover is confirmed healthy, **shred the plaintext rollback**
(`shred -u /app/data/triage.db.plaintext.bak`) — it is unencrypted data
at rest until you do.

> **Fail-closed in HIPAA mode.** Once encryption resolves ON, a missing
> `sqlcipher3` import or an unreachable master key raises a boot error —
> the app never silently falls back to plaintext.

On encrypted installs the backup bundle's SQLite snapshot is itself
SQLCipher-encrypted before the Fernet wrap, so the export never stages
plaintext data on disk.

## Startup environment variables

These override the matching `email-triage.yaml` fields at boot (env
wins). Set them in the container `environment:` block.

| Variable | Effect |
|---|---|
| `EMAIL_TRIAGE_CONFIG` | Path to `email-triage.yaml` inside the container |
| `EMAIL_TRIAGE_DB_ENCRYPTION` | `true`/`1` enables SQLCipher encryption-at-rest (overrides `persistence.encryption_enabled`) |
| `EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY` | `1` silences the `env`-backend deprecation warning (dev/CI only; no effect in HIPAA mode) |
| `EMAIL_TRIAGE_CSRF_ENFORCE` | `true` flips CSRF from soft-launch (count-only) to hard enforcement |
| `EMAIL_TRIAGE_AUDIT_STRICT` | `1` makes audit-write failures re-raise synchronously instead of fail-soft (debug aid) |
| `EMAIL_TRIAGE_WRITER_QUEUE_MAXSIZE` | Integer bound for the single-writer queue (backpressure tuning) |

HIPAA mode itself is a YAML setting (`logging.hipaa: true`), not an env
var. In HIPAA mode the `env` secrets backend is rejected, MFA is
enforced, and encryption is fail-closed.

## Disk allocation

| Location | Minimum | Why |
|---|---|---|
| Container image storage (podman/docker overlay layer) | ~3 GB | The image is ~250 MB but the engine keeps the active `:latest`, the rollback `:previous`, and any intermediate build layers. Plan for two generations + headroom. |
| Persistent volume mounted at `/app/data` | **~5 GB minimum** | This is where the embedding stack installs (lazy on first admin setup): ~600 MB downloaded + ~1.5 GB unpacked = ~2.1 GB. Plus the embedding model cache (~90 MB; more if you switch models). Plus the SQLite DB which grows with mail volume, the sent-mail-index vectors (~3 KB per indexed sent message), and the audit hash chain (~1 KB per row, indefinite retention). For HIPAA installs with multi-year retention plan **50+ GB**. |
| `/app/config` | ~10 MB | YAML + TLS certs only |
| Host `/tmp` available during install | ~1 GB | pip's wheel-unpack scratch space when the embedding install runs |

If your container engine separates image-layer storage from the persistent-volume bind (the typical RHEL-family layout: `/var/lib/containers/storage` + a dedicated bind for `/app/data`), each path needs the headroom listed above independently. The most common install failure is the persistent-volume bind sitting on a small partition: pip dies mid-unpack with `Errno 28 No space left on device`. Mounted-where matters more than total host capacity.

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
     ready) to enqueue a `triage_jobs` row with
     `kind='embedding_reindex'`. The bulk runner drains it in batches of 100 and
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
> `internal documentation` for the local-only rationale.

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
