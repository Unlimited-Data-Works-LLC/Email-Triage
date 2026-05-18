# Security Policy

Email Triage processes mail for the operator's accounts and, in HIPAA-mode deployments, mail on behalf of clinicians and researchers handling protected health information. Security posture is shaped by those two audiences.

## Reporting a vulnerability

If you discover a vulnerability:

1. **Do not open a public GitHub issue.** The repo is public; an issue would expose the unfixed flaw to anyone watching.
2. Email: `craigl@udataworks.com` with subject prefix `[security] email-triage`.
3. Provide: description, reproduction steps, affected commit SHA, suggested mitigation if you have one.
4. Expect a first-response acknowledgment within 5 working days.

Maintainer commits to:

- Triage and confirm within 7 working days.
- Ship a fix or mitigation within 30 days for HIGH/CRITICAL findings, 90 days for MEDIUM/LOW.
- Credit the reporter in the release notes (or honour anonymity if you prefer).

## Scope

In scope:

- Source under `src/email_triage/`.
- The container image as published to `ghcr.io/unlimited-data-works-llc/email-triage`.
- Documented configuration surfaces (`config/*.yaml` examples, environment variables described in [README.md](README.md), `/config` admin UI).
- Webhook + OAuth integration paths.

Out of scope:

- Test fixtures (`tests/`) — synthetic credentials only.
- Behaviour against a misconfigured operator install (weak master key, public exposure without TLS, etc.) — those are deployment concerns, not code defects.
- Issues that require physical access to the host or root-equivalent privileges.

## Risk register

Current snapshot. Each row carries one of: **Closed** (mitigation shipped + verified) / **Mitigated** (controlled, with caveats) / **Tracked** (known, future work) / **Waived** (accepted with rationale).

| Risk | Status | Mitigation |
|---|---|---|
| LLM classifier sends mail content to a cloud vendor without a BAA | **Mitigated** | HIPAA-flagged accounts only see BAA-certified backends in the admin dropdown. Operator records the BAA expiration date per backend; auto-disables on expiry. See `baa_gate.py`. |
| Outbound webhooks egress to public-internet hosts unintentionally | **Mitigated** | Deny-by-default. Operator opts in per setting. Payloads are metadata-only + HMAC-signed regardless. |
| OAuth/API tokens written to logs as values | **Closed** | Privacy-invariant tests pin no-token-in-logs across every refresh path (Gmail, O365, IMAP-XOAUTH2). CI runs them on every push. |
| HIPAA §164.312(b) access-audit gap (generic PHI-touch reads not logged) | **Closed** | `access_log` table + `AccessAuditMiddleware` records every authenticated request to a PHI-touch route prefix. Surfaced on `/compliance`. |
| External CDN load leaking Referer / IP / User-Agent | **Closed** | All static assets vendored under `src/email_triage/web/static/`. Zero external CDNs at runtime. |
| Master key loss (encrypted DB unrecoverable) | **Tracked** | Admin-driven on-demand backup-bundle export (`email-triage backup export`). Operator-side off-host storage is the operator's responsibility. |
| Master-key rotation cadence | **Closed** | Annual rotation policy + runbook below. Operator-side calendar reminder. |
| Log tamper-evidence | **Closed** | Hash chain on `log_entries` (`prev_hash` + `row_hash`). Verified on every `/compliance` page load; first break id + reason surfaced. |
| Internal TLS termination (HIPAA §164.312(e)(1) defense-in-depth) | **Closed** | Three deploy postures: self-signed auto-bootstrap, external ACME pipeline (point `tls.cert_dir` at acme.sh / lego / certbot output), Tailscale-issued LE. |
| Watcher per-message error data loss | **Closed** | Per-message retry queue with exponential backoff (30s / 2m / 10m / 1h / 6h / 24h, 6 attempts). Operator-visible at `/admin/retry-queue`. |
| Style-learning PHI exposure on HIPAA accounts | **Closed** | Describe-and-discard semantics: structured-output LLM call extracts non-PHI style descriptor; 3-layer PHI scrubber (closed-vocabulary schema + HIPAA-18 regex + optional NER); body never persisted. Per-contact descriptors use salted-hash recipient identity. |

## HIPAA scope statement

Email Triage is intended for operators who need to triage mail that may carry PHI under HIPAA. The application implements:

- §164.308 administrative safeguards (RBAC, audit-able admin actions, BAA tracking for cloud-LLM backends).
- §164.310 physical safeguards (none — defers to the operator's host).
- §164.312 technical safeguards:
  - (a)(1) access control via RBAC + per-account HIPAA flag.
  - (b) audit controls via the hash-chained `log_entries` table + `access_log` for PHI-touch routes.
  - (c)(1) integrity via per-row hash chain detection.
  - (d) person/entity authentication via WebAuthn (preferred) or hardware-key login.
  - (e)(1) transmission security via TLS at the application or proxy layer.

Operators retain responsibility for the broader compliance posture: physical security of the deploy host, network segmentation, off-host backup, BAA paperwork with their cloud vendors if cloud-LLM is enabled, workforce training, breach-notification procedures, etc.

The application does NOT make the install HIPAA-compliant. It implements the technical safeguards that fit at the application layer; the operator's deployment posture + their operational procedures determine compliance.

## Threat model

- **Trusted:** the operator (root on the container host), users with admin role on the web UI, a healthy local Ollama at the configured URL, the operator's own SMTP server.
- **Semi-trusted:** non-admin users on the web UI (own-account scope; cannot read other users' mail or modify global config).
- **Untrusted:** every email body received, every URL/webhook destination unless explicitly internal, every classifier endpoint unless `is_local` is true, every OAuth response from external IdPs.

The single hardest invariant: **PHI does not egress this install under any code path.** The audit trail, the BAA gate, the deny-by-default webhook posture, and the no-external-CDN posture are the four layers that uphold it.

## Master key rotation policy

The Fernet master key encrypting `secrets_store` should be rotated on a documented cadence per NIST SP 800-57 ("Recommendation for Key Management"):

- **Cadence:** annual. Operator-side calendar reminder; no in-app scheduler.
- **Mechanism:** `email-triage secrets rotate-master-key`. Re-encrypts every row in `secrets_store` against the new key in one transaction, then writes the new key into the bootstrap backend.
- **Required:** app offline during rotation. Stop the service first.
- **Verification:** after rotation, restart the service and confirm one mail-fetch round-trip per configured provider. Failure = something didn't get re-encrypted; restore from the most recent backup-bundle export.

## Hardening checklist for new deployments

In rough operator order:

1. Generate a fresh master key (`email-triage secrets bootstrap`).
2. Configure the bootstrap secret backend (Podman secret, OS keyring, or one of the pluggable backends).
3. Set `hipaa: true` at the install level OR on individual accounts as appropriate.
4. Use only local Ollama unless you have a BAA on file for the chosen cloud vendor (the admin dropdown enforces this; verify post-setup).
5. Set `webhooks: []` unless webhooks are intentionally needed; if needed, point them at internal hostnames + leave the external-allow flag off.
6. Deploy behind TLS (Tailscale Funnel for internet-exposed installs, internal CA for LAN-only).
7. Schedule the off-host backup-bundle export cadence outside this app (operator's calendar of choice).
