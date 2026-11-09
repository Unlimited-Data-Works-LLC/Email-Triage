# Changelog

All notable changes to this project are documented here.

The release workflow extracts the section whose heading matches the tag being
built (`## vX.Y.Z`, stopping at the next `## `) and uses it as the GitHub
Release body. Keep the heading format stable — the daily health probe parses the
Release body for its version banner.

**Embedding runtime.** When a release changes
`scripts/embedding-bits-manifest.json`, its section MUST carry the line
`Embedding runtime update required: the app installs it by itself shortly after the upgraded release starts, using only the files and hashes this release ships; there is nothing to click (security fix: yes|no). For a security fix, embedding stays off until the install succeeds; if it fails, the admin is emailed and the app retries. With embedding.auto_update set to false, click [Update embedding runtime] on Config > AI Backends instead.`
with `yes`/`no` matching that release's `set_changes` entry, and name every
advisory those entries list (`tests/test_n569_manifest_set_history_pin.py` checks
all three).

With `embedding.auto_update` on (the default, operator decision 2026-10-25) the
app compares the installed runtime ONLY with the manifest shipped in the running
image (it never asks PyPI, PyTorch or Hugging Face what is newer), downloads only
the files and hashes that manifest names, through the hosts the one-click install
already uses, and emails the admin what it did. Set `embedding.auto_update: false`
to keep the click: set it before the upgraded release first starts (its first update
runs seconds after boot), because it is read at start only and an admin Save on a
release older than v0.2.0 removes it.

## v0.2.0

Encrypted by default, regulatory clocks, topic digests.

### Highlights

- v0.2.0 ships multilingual mailbox support — Turkish, Spanish, Chinese, and 100+ other languages selectable from a single Admin dropdown. One install, any customer language.
- v0.2.0 ships ARM64 support; the DGX Spark is now a supported one-box deployment target.

Embedding runtime update required: the app installs it by itself shortly after the upgraded release starts, using only the files and hashes this release ships; there is nothing to click (security fix: yes). For a security fix, embedding stays off until the install succeeds; if it fails, the admin is emailed and the app retries. With embedding.auto_update set to false, click [Update embedding runtime] on Config > AI Backends instead. Advisories: CVE-2026-68770 / GHSA-jhr6-gm9c-rqjv (sentence-transformers 6.1.0), CVE-2026-104851 / GHSA-27vj-qcqg-25rc (fsspec 2026.9.0), GHSA-8g5g-8vmr-9782 / CVE-2026-112403, CVE-2026-112395, CVE-2026-112397, CVE-2026-112400, CVE-2026-112404, CVE-2026-112895, CVE-2026-112896, CVE-2026-112897, CVE-2026-112899 (pillow 13.0.0), GHSA-v4x8-3wr5-3wq8 / CVE-2026-112940, GHSA-9vhv-jxww-xfm5 / CVE-2026-112913, GHSA-567q-5qvw-pf92 / CVE-2026-112907 (filelock 4.2.1), GHSA-xmj3-9gf7-h52w (setuptools 84.2.1).

- Encryption at rest BY DEFAULT for new installs: SQLCipher out of the box, every
  dedicated/backup/migration connection inheriting the key through the
  encryption-aware opener. A config-less boot assumes encrypted and REFUSES
  without a master key rather than silently falling back to plaintext.
- The embedding runtime updates itself: when a release moves the manifest past the
  installed runtime, the app stages the new set beside the old one, checks every
  file against the publisher hashes, swaps, and rolls back on any failure, with no
  click (`embedding.auto_update`, default on). A security change keeps the old
  runtime refused until the swap; a failed attempt is retried with backoff, and a
  failure that leaves embedding off or a security fix undone emails the admin
  every six hours until it is fixed. Each run is audited under the actor
  `system:embedding-auto-update`.
- The container base moves from `python:3.12-slim` to `python:3.14-slim`
  (digest-pinned, punch 732). Its Expat 2.9.0 closes CVE-2026-77214 (HIGH) and
  remediates CVE-2026-102633 (not affected on these 64-bit images).
  On the first start after the upgrade, the embedding runtime the 3.12 image
  installed cannot load under 3.14: the app refuses it (`interpreter_mismatch`),
  checks the old tree against its install record, and reinstalls the cp314 wheels
  by itself, with nothing to click. That is about 244 MB of downloads on x86_64
  (torch is 192 MB); files already on the volume are reused when their hashes
  match. Embedding is off until the install finishes. An old tree that no longer
  matches its record is left for an admin instead.
- HMAC-SHA256 audit hash chain across 8 sibling audit-event tables plus a
  per-request PHI-access log, reachable from a paginated `/compliance` review
  surface; the chain survives master-key rotation via KEK preservation.
- Automated encrypted database backup — supervised in-app snapshotter, `.etbk`
  bundles or raw DB, master-key or write-only X25519 (ECIES) modes, fail-closed
  restorability gate before any snapshot counts. Ships DISABLED by default.
- Regulatory clock awareness — propose-then-confirm deadline engine for
  clinical-trial safety mail, `/clocks` page, daily digest, escalation email with
  portable `.ics` and optional calendar write.
- Topic / Study Digest — Topic matching folded into the primary classify pass
  (no extra body read, model, or egress); per-Topic recurring digests and sender
  reinforcement; whole-window Re-Triage Preview.
- Live AI-backend model picker with capability-aware failover, and a multilingual
  embedding selector (default `intfloat/multilingual-e5-base`) with
  confirm-gated background reindex.
- Per-target webhook body templating (Slack, PagerDuty, Opsgenie, Discord,
  Teams) with a HIPAA force-lock through a shared fail-closed reshaper, HMAC over
  the rendered bytes, and a wizard preview that renders the exact bytes
  production POSTs.
- External integration API renamed `/api/openclaw` → `/api/v1`, 308 for legacy
  clients.
- Route-scoped API keys: a key can be limited to exact `METHOD /path` routes
  (`api_keys.scope`, migration v55; a key with no scope works as before). Scope
  refusals, role refusals and unknown-key attempts are written to `auth_events`,
  capped per source.
- `/health/runtime-deps` also lists what the image carries beyond its Python
  distributions: vendored libraries (from each package's SBOM, `vendor.txt` or
  directory listing) and the Debian packages, keyed by source package. A source
  it cannot read is reported as an error, never as an empty list. A read-only
  `health_ro` user can call it.
- The webhook wizard preview can show the last real event for a target. Only a
  SHA-256 identity of the target is stored, never its URL, and the event is
  shown only to a user who manages its mailbox.

Security and data-integrity fixes included in this release:

- Bumped `icalendar` to 7.3.0, clearing CVE-2026-55099.
- Fixed backup bundles that had silently omitted every MSAL token cache since
  2026-07-08, so a restore could leave mailbox connections unauthenticated.
- One settings store per security knob, with a missing row preserving the
  existing value rather than resetting it.
- Closed three privacy controls that passed while examining nothing, and stopped
  personal identifiers from reaching the published tree.
- Bumped `sqlcipher3` to 0.6.5, and the SQLCipher library the image builds
  from source from 4.17.0 to 4.20.0 (SQLite 3.53.3 to 3.54.1). SQLCipher
  4.19.0 fixes escaping of database aliases in `sqlcipher_export()` and
  rejects an invalid `hexkey` URI parameter. SQLCipher 4.20.0 moves to the
  SQLite 3.54.1 baseline and fixes a deferred error in `cipher_migrate`.
  `sqlcipher3` 0.6.3 fixed a
  reference release in the connection destructor that ran without holding
  the GIL. `sqlcipher3` 0.6.5 vendors SQLCipher 4.20.0 in its PyPI wheels,
  so the test suite now runs on the same SQLCipher as the image.
- Bumped `pyasn1` to 0.6.5, clearing CVE-2026-119194 through CVE-2026-119197
  (quadratic CPU use when decoding crafted ASN.1).
- Bumped `cryptography` to 50.0.2, whose wheels bundle OpenSSL 4.0.3. The
  50.0.1 wheels bundled OpenSSL 4.0.2, which is affected by CVE-2026-84783
  (use-after-free in the X.509 extension cache under concurrent use) and
  CVE-2026-84782 (DTLS retransmission). No code path in email-triage reaches
  either flaw; the bump closes them regardless.
- `GET /health/runtime-deps` now lists the libraries that installed wheels
  bundle, under two new keys, `bundled` and `bundled_error`. Each row is a
  non-PyPI component from a wheel's PEP 770 SBOM (for example the OpenSSL
  inside cryptography) or a library auditwheel grafted into a `.libs`
  directory, with the wheel that carries it. A `.libs` library's version is
  read from its bytes (a known version banner, else its SONAME); the file is
  never loaded. Name-based scanners such as pip-audit cannot see these
  libraries; a CVE monitor reading this key can.
- The notice that older mail may be un-triaged no longer clears itself. It used
  to disappear on the next successful poll, IDLE reconnect or Gmail recovery
  walk, none of which reach the skipped mail. It now stays until you dismiss it
  after reviewing the mailbox, or until an Office 365 recovery walk covers the
  whole mailbox. Notices already showing when you upgrade stay until dismissed.
  A dismiss that cannot be recorded in the audit log is refused, and the notice
  stays.
- The image applies Debian security updates when it is built (`apt` 3.0.4 for
  CVE-2026-109518) and records its installed packages in `/app/.dpkg-manifest`.
  The base image moves to the current python:3.14-slim (Python 3.14.10).
- The CLI commands that create users, grant roles, create or revoke API keys,
  or re-normalize stored addresses now load the audit-chain HMAC keys right
  after opening the database and refuse if they cannot. Before, `user create` and `apikey create` refused on an
  install with HIPAA mode off, and `audit reconcile` could drop its own audit
  event. The emergency revokes (`user disable --emergency`,
  `apikey delete --emergency`) warn and proceed instead, so a compromised
  credential is never left live.
- API-key events record who acted (`api_key_events.actor_email`, migration
  v54). A grant with no actor is refused; a revoke with no actor proceeds and
  writes an alarm row, so a key is never left live.
- `audit verify` reports known emergency-revoke gaps beside its `intact`
  verdict, and an unreadable chain is refused rather than reported.
- A WebAuthn sign-in whose signature counter is lower than the stored one (a
  cloned or replayed authenticator) is refused.
- The distrusted-certificate check now also covers a caller-supplied SSL
  context or CA path, `rediss://` Redis connections and a caller-supplied IMAP
  `ssl_context`.
- Client-supplied meeting-invite (iMIP) attendee addresses pass the same
  address check as other calendar addresses before they reach Gmail or
  Office 365.
- The ACME certificate renewer no longer echoes exception text, and the IMAP
  connection test runs on a worker thread with a bounded close.
- The container image installs its Python dependencies from a hash-locked
  requirements file.

Behaviour change at upgrade:

- The master key is now read with any trailing newline (CR or LF) removed, and
  every key derives from that one value. A database created by an earlier
  release while the master-key secret ended with a newline no longer opens:
  the service refuses with `EncryptedDbKeyRefused` before any migration runs,
  and the database file is left unchanged. In practice this is the deprecated
  `env` backend with `ET_MASTER_KEY` ending in a newline; the `container` and
  file backends already removed it. To check before upgrading, run this in the
  service's environment; it prints `True` or `False` and never the key:
  `python -c 'import os; print(os.environ["ET_MASTER_KEY"].endswith(("\n", "\r")))'`.
  If you set `secrets.master_key_name`, use that variable name instead of
  `ET_MASTER_KEY`.
  An install that prints `True` should stay on v0.1.2 and leave the secret as
  it is (removing the newline stops v0.1.2 opening the database too) until a
  later release adds the re-key command.

- In HIPAA mode, a CLI command that records an audit start row now refuses to
  run when the secrets bootstrap, the audit-key wiring or the database open
  fails (`CliAuditGateClosed`). Before, it warned and ran unaudited. The global
  `--allow-unaudited` flag runs it anyway; the two emergency revokes
  (`user disable --emergency`, `apikey delete --emergency`) proceed with
  `--emergency`.

- With no SMTP server configured, email sign-in codes are refused rather than
  issued, so an account with no registered passkey cannot sign in by email. A
  non-HIPAA development install can set `smtp.dev_console_otp: true` to print
  each code to the process's stderr; the flag is refused in HIPAA mode.

- An existing unencrypted database is no longer opened in encrypted mode when
  the config turns encryption on, explicitly (`encryption_enabled: true`) or by
  leaving it at its default: the service refuses to start and names both
  remedies. Stop the service and convert the database with
  `email-triage db encrypt`, or, on an install where disk-level encryption is
  the documented safeguard, set `persistence.encryption_enabled: false` to keep
  it unencrypted. In either mode, the service also refuses to start when the
  database file is shorter than one SQLite header while its `-wal` file holds
  data: any open would discard that data and start an empty database. Restore
  the database from a backup.

- On a mailbox marked as holding protected health information, only watches
  created by the mailbox owner now fire. With the system HIPAA flag on, that is
  every mailbox, so every enabled watch a delegate created stops firing at
  upgrade. The owner and the delegate see "Not firing" on the Watches page, and
  the admin alert counts these watches. It reverses by itself if the flag is
  turned off; the owner can recreate any watch they still want.
