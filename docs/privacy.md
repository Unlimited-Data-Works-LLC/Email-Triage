# Privacy + Compliance Posture

What Email Triage does — and does not — do with the mail flowing through it. Written for operators evaluating whether the application fits a compliance posture (HIPAA, attorney-client, journalist source protection, etc.).

## Verdict line

**No mail content, message metadata, or PHI leaves your install unless you've explicitly opted-in to a cloud-LLM backend with a Business Associate Agreement on file.** Every classification, draft, embedding, and audit-trail row is computed locally and stored encrypted at rest on your hardware. The only outbound network calls are to mail providers you've configured (Gmail / Outlook / your IMAP server) and the LLM backend you've selected (default: local Ollama on the same host).

## What stays on your install

| Data class | Storage |
|---|---|
| Mail bodies, headers, attachments (in-memory only during triage) | Not persisted by default; admin can opt-in to `sent_mail_index` for RAG draft assistance |
| Classification decisions + reasoning | `triage_runs` table, SQLite, encrypted at rest via filesystem encryption (operator-managed) |
| Per-account credentials (IMAP password, OAuth refresh tokens) | `secrets_store` table, Fernet-encrypted with the install master key |
| Audit trail (every PHI-touch request, every admin action) | `log_entries` (hash-chained for tamper-evidence) + `access_log` + `auth_events` |
| Style-learning descriptors | `hipaa_style_descriptors` (closed-vocabulary, no free text); per-contact descriptors keyed by salted hash of recipient address |
| Configuration (routes, watches, categories) | `triage.db`, plain SQLite |

The database is a single file. Off-host backup is the operator's responsibility; the in-app `email-triage backup export` command produces an encrypted tarball for that purpose.

## What leaves the install

| Destination | What | When |
|---|---|---|
| Your IMAP / Gmail / O365 server | IMAP / REST API traffic to fetch + send mail | Continuously (IDLE or poll) |
| Local LLM backend (Ollama by default) | Classification prompts (sender + subject + body excerpt); on HIPAA accounts with style learning enabled, full body for the describe-and-discard distill | On each new message; per-account-configurable cadence for style learning |
| Cloud-LLM backend (off by default; OpenAI / Gemini / Azure OpenAI when explicitly added) | Same as above, but to the chosen vendor | Only when admin has added the backend AND the account has selected it |
| Webhook URLs (off by default) | Metadata-only payloads (no body), HMAC-signed | Only when a route fires a `notify` action AND the URL is explicitly allowed |
| Mail destination | Drafts created by `draft-reply` action AND `escalate` SMS via configured gateway | Per route configuration |
| Daily-health email | Operator-internal status digest (no PHI) | Configurable cadence; SMTP destination is operator-controlled |

**Zero telemetry.** No phone-home, no usage analytics, no error-reporting service, no feature-flag fetch, no anonymous beacon. The application phones nothing it doesn't have an operator-configured reason to phone.

## HIPAA mode

Two granularities, evaluated most-restrictively:

- **Install-wide**: `hipaa: true` in `email-triage.yaml`. Applies to every account.
- **Per-account**: each `email_accounts` row carries its own `hipaa` flag. Independent of install-wide.

When an account is HIPAA-flagged (either way), the application:

1. **Disables PHI-leaky surfaces by default.** Body previews in digests are redacted (`[redacted]`). Classifier-reason text is dropped from operator-visible UI. The `discover` flow returns descriptions instead of raw mail excerpts.
2. **Requires BAA-certified backend for any cloud-LLM call.** The admin-curated AI Backends list filters HIPAA accounts to backends marked `BAA certified=1 AND baa_expires_at > today`. On BAA expiry, the backend auto-disables for HIPAA accounts only (non-HIPAA accounts keep using it).
3. **Records every PHI-touch.** Every authenticated request to a PHI-touching route prefix (`/accounts/<id>/messages/...`, `/triage/...`, `/digests/...`, etc.) emits a row in `access_log` with actor, timestamp, request_id, outcome. The `/compliance` page surfaces the audit trail.
4. **Hash-chains every audit row.** `log_entries.prev_hash` + `log_entries.row_hash`. Any post-hoc edit breaks the chain; `/compliance` highlights the first break and the reason. Verified on every page load.
5. **Runs style learning under describe-and-discard semantics.** Details below.

The install does NOT make you HIPAA-compliant. It implements the technical safeguards that fit at the application layer (§164.312); your overall posture depends on physical security, network segmentation, workforce training, breach-notification procedures, and the BAA paperwork with any cloud vendors you've enabled.

## Describe-and-discard style learning (HIPAA-mode behavior)

For non-HIPAA accounts, style learning indexes message-reply pairs in the RAG store to inform draft-reply generation. That mechanism is **not** used for HIPAA accounts.

For HIPAA accounts, style learning runs in **describe-and-discard** mode:

1. The application reads recent sent messages **in memory only** (the bodies are never written to disk).
2. It calls the per-account-selected LLM backend with a structured-output prompt that asks for a closed-vocabulary style descriptor: tone, formality level, greeting style, sign-off style, sentence-length preference, vocabulary register, common phrases. **No free-text fields.** The prompt explicitly tells the model never to emit names, dates, MRNs, diagnoses, or any of the HIPAA 18 identifiers.
3. The LLM response passes through a **3-layer PHI scrubber**:
   - Layer 1: closed-vocabulary schema enforcement (anything outside the enum is dropped).
   - Layer 2: regex matcher for the HIPAA 18 identifiers — names with two patterns, addresses, ZIP, dates, phones, email addresses, SSN-shaped digits, MRN-shaped long-digit runs, alphanumeric IDs, URLs containing PII, IPv4 + IPv6, image filenames, medical terms.
   - Layer 3 (optional, when `presidio_analyzer` or `spacy` is installed): NER for `PERSON` / `LOCATION` / `DATE_TIME` / `MEDICAL_RECORD_NUMBER` / `US_SSN`. Scrubber reports `degraded=true` if these libraries aren't available, surfaced to the operator.
4. If any layer flags PHI, the descriptor is rejected entirely (not partially scrubbed). The account's style learning is paused (no retry — leaky LLM output won't get better) and an audit row records the rejection. The operator manually clears the pause via `/admin/retry-queue` after investigating.
5. On pass, only the scrubbed descriptor is persisted. The mail body is discarded.

**Per-contact descriptors** (M-7): the same machinery, but keyed by a salted hash of the recipient email address rather than plaintext. Salt is a 64-byte random value Fernet-encrypted in the secrets store, separate from the master key (so master-key rotation doesn't invalidate every recipient hash). Recipient plaintext never appears in any persisted row or any log line.

## Audit trail integrity

The hash chain on `log_entries` is the integrity primitive:

- Every row carries `prev_hash` (the hash of the previous row, or zero for the genesis) and `row_hash` (the hash of the row's own fields).
- The CLI `email-triage audit verify` walks the chain end-to-end and reports the first break (if any) with the broken row's id and reason.
- The `/compliance` admin page runs the verify on every page load (cheap; ~milliseconds for ~50k rows) and renders the same break info to the admin.
- Post-hoc edits to a row break its `row_hash`. Deletions break the chain at the deletion point. Inserts in the middle break the chain at the insertion point.

If you suspect tampering, run `email-triage audit verify` and follow the row-id of the first break to inspect the offending row + the rows immediately before and after.

## Retention

- **Captured edit pairs** (RAG store, non-HIPAA accounts only): stored permanently until the user deletes them from `/profile/style-data`. Operator can configure an age-out via `style_learning.captured_pair_retention_days` if needed.
- **Style descriptors**: overwritten on re-learn (no historical descriptors retained).
- **Per-contact descriptors**: GC'd after 90 days of no re-learn activity (a sibling daily-health sweep).
- **Audit rows** (`log_entries`): rotated by age (default 30 days) + max-count (default 50k) backstops. Configurable; rotation rewrites the hash chain to anchor to the new genesis row. PHI-touch rows in `access_log` carry their own retention setting (default same as `log_entries`).
- **Triage runs** (`triage_runs`): operator-configurable retention; default 90 days.
- **Login + admin events** (`auth_events`): operator-configurable; default 365 days.

## Reading order

- [README.md](../README.md) for the product overview.
- [docs/install.md](install.md) for deploy mechanics.
- This file for the privacy posture.
- [docs/hipaa-audit.md](hipaa-audit.md) for the most recent compliance audit findings.
- [SECURITY.md](../SECURITY.md) for vulnerability reporting + risk register.
