# HIPAA Compliance Audit — Findings Summary

**Date of most recent audit:** 2026-05-17
**Audit scope:** Source code at `src/email_triage/` + container build pipeline + admin surfaces
**Audit type:** Internal review (single-maintainer project)

## Verdict

**No open findings.** All HIPAA-relevant code paths surveyed are gated by privacy-invariant runtime tests + the audit hash chain. The latest weekly cycle audited:

- Digest body-preview HIPAA redaction (verified by `tests/test_privacy_invariants_digest.py`).
- OAuth refresh log scrub across Gmail, Office 365, and the shared `oauth_request` helper (`tests/test_privacy_invariants_oauth.py`).
- Style-learning describe-and-discard distill (`tests/test_privacy_invariants_distill_hipaa.py`).
- 3-layer PHI scrubber (`tests/test_privacy_invariants_phi_scrubber.py`).
- M-7 per-contact descriptor recipient-hash salting (`tests/test_privacy_invariants_m7_hipaa.py`).
- M-series cross-cutting invariants (`tests/test_privacy_invariants_m_series.py`).

Tests run in CI on every push; production deploys verify integrity post-restart.

## Scope of this audit

In scope:

- Every PHI-touch code path in `src/email_triage/`.
- The `log_entries` audit hash chain integrity primitive.
- The BAA gate (`baa_gate.py`) that enforces "no cloud-LLM call for HIPAA accounts unless a BAA is on file with the chosen vendor".
- The describe-and-discard semantics for HIPAA-account style learning.
- The salted-hash recipient identity for per-contact style descriptors.
- The PHI-scrubbing of logs (`_TOKEN_KEYS`, `_PHI_KEYS` in `triage_logging.py`).

Not in scope at this audit (deferred or operator-side):

- Physical security of the deploy host (§164.310, operator's responsibility).
- Workforce training, breach-notification procedures (§164.308(a)(6), operator's procedures).
- BAA paperwork with cloud vendors (operator's contracts; the application tracks the operator-recorded expiration date but doesn't read the contract content).
- Off-host backup posture (the application provides `email-triage backup export`; the off-host storage and retention is operator-controlled).
- Network segmentation, TLS termination at the proxy layer if not at the app.

## Closed findings

Findings closed prior to this audit cycle, with mitigation status. Each closed finding has a regression-pinning test that runs in CI.

| Finding | Status | Mitigation |
|---|---|---|
| External CDN load (PicoCSS via CDN) leaked Referer + IP + User-Agent on every page render | **Closed** | All static assets vendored to `src/email_triage/web/static/`. No external CDNs at runtime. Privacy-invariant test pins the absence of CDN URLs in production source. |
| HIPAA §164.312(b) access-audit gap (generic PHI-touch reads not logged) | **Closed** | New `access_log` table + `AccessAuditMiddleware` records every authenticated request to a PHI-touch route prefix. Surfaced on `/compliance`. |
| Log tamper-evidence (post-hoc edits undetectable) | **Closed** | Hash chain on `log_entries` (`prev_hash` + `row_hash`). Verified on every `/compliance` page load. First break id + reason surfaced. |
| OAuth tokens written to logs as values during refresh | **Closed** | `_TOKEN_KEYS` scrub in `triage_logging.py` filters 14 token-bearing field names from every log record. Test `tests/test_privacy_invariants_oauth.py` exercises every refresh path against synthetic token-shape responses and asserts zero token strings reach the log output. |
| Digest body-preview HIPAA redaction not regression-tested | **Closed** | Test `tests/test_privacy_invariants_digest.py` pins 7 invariant classes across 26 cases. Confirms `[redacted]` return for HIPAA accounts on every renderer (`render_grouped_list`, `render_plain_list`, `render_table_generic`, the dispatcher, and the legacy `_preview` helper). |
| Exception messages leaking provider response bodies | **Closed** | `GmailApiError.__init__` applies `_TOKEN_KEYS` defensive scrub before stringifying any dict body. Sibling pattern in `AzureOpenAIError`, `GeminiError`, `OpenAIError`. Test pins the invariant. |
| HIPAA-flagged actor != owner audit gate (operator can read HIPAA account they don't own without auditing) | **Closed** | The audit-emit gate is `actor_user_id is not None AND account.hipaa AND actor_user_id != account.user_id`. Owner-self-access remains first-party under §164.502(a). Documented in policy. |
| Style-learning indexing of HIPAA-flagged content | **Closed** | Two-track design: non-HIPAA accounts use the standard RAG store; HIPAA accounts use describe-and-discard (structured-output LLM call → 3-layer PHI scrubber → store only the scrubbed descriptor; the body is discarded after the call). M-7 per-contact descriptors use a salted hash of the recipient address; recipient plaintext never appears in storage or logs. |
| Per-message watcher errors silently lost | **Closed** | New retry queue with exponential backoff (30s / 2m / 10m / 1h / 6h / 24h, 6 attempts). UIDVALIDITY-aware re-fetch. Operator-visible at `/admin/retry-queue`. Daily-health email surfaces patterns when deads accumulate. |
| Master-key rotation cadence undocumented | **Closed** | Annual rotation policy + runbook in [SECURITY.md](../SECURITY.md). `email-triage secrets rotate-master-key` performs the transactional re-encryption. Calendar reminder is operator-side. |

## Audit methodology

For each PHI-touch code path:

1. Identify the data flow: where does the PHI enter, where does it transit, where does it land?
2. Verify a HIPAA-mode check (per-account flag OR install-wide flag) is evaluated before any persistence, logging, or external-call decision.
3. Verify a regression-pinning test exists in `tests/test_privacy_invariants_*.py` that would fail if the gate is bypassed.
4. Trace BAA gate enforcement for every external-call path (`baa_gate.py:is_safe_for_hipaa(backend, host)`).
5. Spot-check the audit-row emission for the path; verify it lands in `access_log` or `log_entries` with the right actor + outcome fields.

The audit produces a finding when any of (1)-(5) fails. Findings are filed in the punch list with a severity tag and a fix-by date.

## Audit chain verification

Customers can verify their own install's audit-chain integrity at any time:

```bash
sudo podman exec email-triage email-triage audit verify
```

The command walks `log_entries` end-to-end, recomputes the chain, and reports the first break (if any) with the row id + reason. Exit code 0 = clean; non-zero = break detected. Run after any maintenance event (DB restore, migration, manual edit) to confirm chain integrity.

The same check runs on every `/compliance` page load (under a second for typical row counts). The chain has run continuously since the install was first started — there is no "chain reset" event in the application's lifetime.

## Reverification cadence

- **Customer-side, per install:** monthly recommended. Triggers — any DB restore, any backup-bundle import, any post-incident review.
- **Maintainer-side, the application:** weekly audit cycle on the source-code side; bi-weekly on the test-coverage side. Findings from each cycle land in the punch list with severity + fix-by.
- **Independent third-party review:** the codebase has not been third-party audited as of this writing. Customers with regulatory obligations that require an independent audit should engage one + share findings; the maintainer commits to addressing valid findings within the same SLA as `SECURITY.md` describes.

## Customer-side audit checklist

For your own install, the recommended periodic review:

1. Confirm `email-triage audit verify` exits clean.
2. Inspect `/compliance` for any "audit chain break" warnings.
3. Confirm `/admin/ai-backends` shows no `BAA certified` row past its `baa_expires_at` date.
4. Confirm `/admin/retry-queue` is empty or all entries are `state='done'`.
5. Spot-check `/logs` (filtered by `level=ERROR` and last 30d) for any uninvestigated entries.
6. Confirm the most recent `email-triage backup export` is off-host within your retention SLA.

## Reading order

- [SECURITY.md](../SECURITY.md) for vulnerability reporting + the risk register.
- [docs/privacy.md](privacy.md) for the privacy posture details.
- This file for audit findings.
- [docs/install.md](install.md) for deploy + verify mechanics.
