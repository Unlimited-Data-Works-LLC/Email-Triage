# Security Policy

This is a single-operator homelab project that processes mail for the
operator's own accounts and (in HIPAA-mode deployments) on behalf of
medical researchers handling protected health information. Security
posture is shaped by those two audiences.

## Reporting a vulnerability

If you discover a vulnerability:

1. **Do not open a public GitHub issue.** The repo is public; a
   public issue would expose the unfixed flaw to anyone watching.
2. Report it privately through GitHub: open the repository's
   **Security** tab and click **Report a vulnerability** (GitHub's
   private vulnerability reporting). Your report and the ensuing
   discussion stay private to you and the maintainers until a fix
   is published.
3. Provide a description, reproduction steps, the affected commit
   sha, and (if applicable) suggested mitigation.
4. Expect a first-response acknowledgment within 5 working days.

Maintainer commits to:

- Triage and confirm within 7 working days.
- Ship a fix or mitigation within 30 days for HIGH/CRITICAL findings,
  90 days for MEDIUM/LOW.
- Credit the reporter in the release notes (or honour anonymity if
  preferred).

## Scope

In scope:

- Source under `src/email_triage/`.
- The container image as built by `Containerfile`.
- Documented configuration surfaces (`config/*.yaml`, environment
  variables described in [README.md](README.md), `/config` admin UI).
- Webhook + OAuth integration paths.

Out of scope:

- Test fixtures (`tests/`) — synthetic credentials only.
- Local-only debug output (`probe.json`, `dev-data/`).
- Behaviour against a misconfigured operator install (e.g. weak
  master key, public exposure without TLS) — those are deployment
  concerns, not code defects.

## Risk register (current)

This is a snapshot of accepted, mitigated, and tracked risks as of
the most recent compliance audit. Detailed findings live in the
local-only `internal compliance review`; the public summary is here.

| Risk | Status | Mitigation |
|---|---|---|
| LLM classifier sends mail content to external vendor (OpenAI / Gemini / API endpoint not on a BAA) | **Mitigated** | HIPAA accounts fail-closed unless a BAA acknowledgment is on file for the exact `(backend, host)` tuple in use. See `src/email_triage/classify/baa_gate.py` and the check on `/config`. |
| Outbound webhooks egress to public-internet hosts unintentionally | **Mitigated** | Deny-by-default; operator must set `webhooks_allow_external: true` to permit external URLs. Payloads are metadata-only + HMAC-signed regardless. |
| OAuth/API tokens written to logs as values | **Mitigated** | `tests/test_security_token_logging.py` greps every log call in `src/` against a list of token-bearing field names + raw-JWT pattern. CI runs the test on every push. |
| HIPAA §164.312(b) access-audit gap (generic PHI-touch reads not logged) | **Closed** | New `access_log` table + `AccessAuditMiddleware` records every authenticated request to a PHI-touch route prefix. Surfaced on `/compliance`. |
| External CDN load (PicoCSS) leaked Referer + IP + UA on every page hit | **Closed** | Vendored to `src/email_triage/web/static/pico.min.css`. No external CDNs remain. |
| Pip's own CVE in CI | **Waived** | `scripts/run-pip-audit.sh` carries the waiver inline with rationale; pip is build-time, not runtime, and has no impact on the deployed image. Revisit when pip ships a patch. |
| Master-key loss (encrypted DB unrecoverable) | **Tracked** | Off-host nightly backup pending; operator-level concern. Detailed plan in README "Backup & Disaster Recovery". |
| Master key rotation cadence undocumented (NIST SP 800-57) | **Closed** | Annual rotation policy + runbook in "Master key rotation policy" section below. Calendar reminder is operator-side. |
| Log tamper-evidence (post-hoc edit detectable) | **Closed** | Hash chain on `log_entries` (prev_hash + row_hash). Verified on every `/compliance` page load; first break id + reason surfaced. |
| Internal TLS termination (HIPAA §164.312(e)(1) defense-in-depth) | **Closed** | Three deploy postures: self-signed auto-bootstrap (zero-config), external ACME pipeline (point `tls.cert_dir` at acme.sh / lego / certbot output), Tailscale-issued LE (`email-triage tls fetch-tailscale`). Default off; opt in via `tls.enabled: true` after updating external monitors. Plumbing: `src/email_triage/tls.py` + `email-triage tls {bootstrap,fetch-tailscale}`. |
| Server-side session table | **Tracked** | Sessions are signed cookies today; rotation/revocation not instant. Planned per audit finding. |

## Threat model — short version

- **Trusted:** the operator (root on the container host), users with
  admin role on the web UI, a healthy local Ollama at the configured
  URL, the operator's own SMTP server.
- **Semi-trusted:** non-admin users on the web UI (own-account scope,
  cannot read other users' mail or modify global config).
- **Untrusted:** every email body received, every URL/webhook
  destination unless explicitly local, every classifier endpoint
  unless `is_local` is true, every OAuth response from external
  IdPs.

The single hardest invariant: **PHI does not egress this install
under any code path.** The audit + the BAA gate + the
webhooks_allow_external flag + the no-external-CDN posture are
the four layers that uphold it.

## Master key rotation policy

The Fernet master key encrypting `secrets_store` should be rotated
on a documented cadence per NIST SP 800-57 ("Recommendation for Key
Management"):

- **Cadence: annual.** Set a calendar reminder for the deployment's
  installation anniversary. The reminder lives outside the repo
  (operator's calendar of choice) — there is no in-app scheduler
  for this because rotation is an offline operation.
- **Mechanism:** `email-triage secrets rotate-master-key`.
  Re-encrypts every row in `secrets_store` against the new key in
  one transaction, then writes the new key into the bootstrap
  backend (Podman secret on the deploy host; OS keyring elsewhere).
- **Required: app offline during rotation.** Running processes hold
  the old Fernet instance in memory; in-flight reads after the DB
  flips but before the bootstrap updates would fail to decrypt.
  Stop the service first: `sudo systemctl stop email-triage.service`.
- **Rollback:** the old key is logged to a secure operator-only
  location during rotation. If the new key is lost before any new
  writes land, restoring the old key + restarting the app recovers
  the install.
- **Verification:** after rotation, restart the service and confirm
  one mail-fetch round-trip per provider type (IMAP, Gmail API,
  Office 365). Failure = something didn't get re-encrypted; restore
  from the off-host nightly backup pre-rotation snapshot.

Future work: a "dual-key read window" via
`cryptography.fernet.MultiFernet` would enable zero-downtime
rotation. Not justified for a single-node homelab where annual
brief downtime is fine; revisit if this project deploys to a
multi-tenant environment.

## Hardening checklist for new deployments

In rough operator order:

1. Generate a fresh master key (`email-triage secrets bootstrap`).
2. Configure the bootstrap secret backend (Podman secret on the deploy host,
   OS keyring on a laptop).
3. Set `hipaa: true` if the install will handle PHI.
4. Disable any classifier backend except local Ollama, OR
   acknowledge the BAA for the configured external vendor.
5. Set `webhooks: []` unless webhooks are intentionally needed; if
   needed, point them at internal hostnames only and leave
   `webhooks_allow_external: false`.
6. Deploy behind TLS (Tailscale Funnel for internet-exposed
   installs, internal CA for LAN-only).
7. Run `./scripts/install-git-hooks.sh` so future pushes are
   pip-audit-gated locally.

## Cross-references

- Compliance posture: README "HIPAA Mode" section.
- Backup / recovery: README "Backup & Disaster Recovery".
- Incident response: [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md).
- Local-only audit detail: `internal compliance review` (gitignored).

## Shared-host container co-tenancy (SELinux MCS)

When email-triage runs as a container on a host it shares with other
containers, SELinux type enforcement keeps every container away from host
files, but only the MCS level separates one `container_t` process from another,
and all of them may use `container_file_t` files. A data or config directory at
the shared level `s0` is readable and writable by every container on the host,
so a process that escapes another container with its SELinux context intact
could reach the database and the key beside it. The controls: the container is
pinned to one two-category MCS level through a host quadlet drop-in
(`SecurityLabelLevel=`); a persistent fcontext rule labels the data and config
directories `container_file_t` at that level; every deploy container that mounts
them runs at the same level; and the deploy refuses on an SELinux host when the
level is missing, malformed, or the unit runs unconfined. The isolation holds
only while SELinux is Enforcing. Detection of cross-container attempts depends
on AVC denials being audited and alerted on, which is host configuration. See
`internal documentation` ("Exit 9 and exit 10") for the operator side.
