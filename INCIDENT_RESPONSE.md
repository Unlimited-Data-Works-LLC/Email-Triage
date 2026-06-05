# Incident Response Runbook

Single-operator project; runbook is short by design. Follow the
steps in order; when in doubt, **err toward containment**.

## Severity bands

| Band | Examples | Response window |
|---|---|---|
| **CRITICAL** | PHI egress, master-key loss, RCE, pre-auth account takeover | Immediate (drop everything) |
| **HIGH** | Authenticated privilege escalation, credential leak, DoS of mail processing for medical-research deployment | Same calendar day |
| **MEDIUM** | Information disclosure (non-PHI), persistent XSS, missing audit gap | 7 days |
| **LOW** | Minor logging gap, deprecation, hygiene | 30 days |

## On detection

### 1. Triage (5 min)

- What is the suspected impact? (PHI / credentials / availability)
- Which deployment? (the deploy host production / dev laptop / medical-researcher tenant)
- What evidence — log lines, alert, user report, PR review hit?
- Assign the band above.

### 2. Contain (CRITICAL / HIGH within 30 min)

For PHI egress suspicion:

```
# Stop the mail-processing pipeline.
ssh user@deploy-host "sudo systemctl stop email-triage.service"

# Snapshot logs + DB before any state moves.
ssh user@deploy-host "sudo cp -a /srv/email-triage/data /srv/email-triage/data.snap.$(date +%Y%m%d-%H%M)"
ssh user@deploy-host "sudo journalctl -u email-triage.service --since '24 hours ago' \
  > /tmp/incident-journal-$(date +%Y%m%d-%H%M).log"
```

For credential compromise:

```
# Rotate any exposed credentials immediately, even before confirming impact.
ssh user@deploy-host "sudo podman exec email-triage email-triage secrets rotate <KEY_NAME>"

# Revoke any stale API keys.
ssh user@deploy-host "sudo podman exec email-triage email-triage apikey list"
ssh user@deploy-host "sudo podman exec email-triage email-triage apikey delete <ID>"
```

For RCE / pre-auth takeover suspicion:

```
# Take the service offline pending review.
ssh user@deploy-host "sudo systemctl stop email-triage.service"
# Block the public surface (Tailscale Funnel, reverse proxy) at the
# edge — do not assume local container stop is sufficient.
```

### 3. Investigate (timebox to 2h before escalation)

- Pull the last 24h of `log_entries` matching the affected feature.
- Pull the last 24h of `hipaa_access_events` if PHI was potentially
  involved.
- Check `git log --since='24 hours ago'` for recent changes.
- Check the latest CI runs for security/audit failures that were
  ignored: `gh run list --workflow=Security`.
- If the suspicion is an external vendor (Gemini/OpenAI returning
  PHI in error responses, etc.), capture sample requests + check
  the BAA acknowledgment state on `/config`.

### 4. Notify

- Operator: as soon as containment is in place. Severity + band +
  systems affected + immediate next step.
- Affected users (HIPAA only): per `45 CFR §164.404` breach
  notification, individuals must be notified within 60 days. For
  500+ affected, the HHS Secretary + media notification within 60
  days. Single-operator note: a HIPAA-flagged deployment is the
  trigger for either.
- HHS / regulators: only after the operator and (if applicable)
  the covered entity's compliance officer have been looped in.

### 5. Remediate

Standard remediation lanes:

- **Code defect:** patch on a feature branch, full CI green, push,
  deploy via `scripts/deploy-the deploy host.sh` (the monitoring system downtime + pre-validate
  is automated). Bump version in commit message body.
- **Configuration error:** correct on `/config`, log a
  configuration-change boundary event so the change is traceable.
- **Compromised secret:** rotate via `email-triage secrets rotate`,
  revoke any sessions issued under the old secret if applicable.
- **Compromised dependency:** `pip-audit` will catch on next push;
  upgrade or pin a safe version, add waiver to
  `scripts/run-pip-audit.sh` ONLY if the issue is unfixable
  upstream and the risk is acceptable.

### 6. Post-incident (within 7 days)

Write a one-page note in `docs/incidents/<YYYY-MM-DD>-<short-name>.md`
covering:

- Detection time, containment time, full timeline.
- Affected systems + users.
- Root cause.
- Mitigation deployed.
- Lessons + follow-ups (track as the backlog items if non-trivial).

These are local-only (gitignored under `docs/incidents/`); a
sanitised summary may be added to the SECURITY.md risk register if
the lesson generalises.

## Break-glass emergency access

Covers HIPAA §164.312(a)(2)(ii) *Emergency Access Procedure*
(Required implementation specification under the
Technical Safeguards standard for Access Control). Verbatim text:
*"Establish (and implement as needed) procedures for obtaining
necessary electronic protected health information during an
emergency."* Source: eCFR 45 CFR §164.312, retrieved 2026-05-23,
<https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312>.

Matches Bundle E5  (HIPAA audit H-03). The system has no
application-layer "break-glass" command. Emergency access is the
**host-shell + CLI** combination already required to install,
deploy, and recover the system. This section documents the
procedure so it is *invokable*, *audited*, and *reviewed* — not a
new capability, a documented use of existing capabilities.

### When to invoke

Use break-glass ONLY when standard access is unavailable AND a
time-critical action is required. Typical triggers:

| Trigger | Why standard access fails | Required action |
|---|---|---|
| Web auth broken (DB corruption, session-table corruption, `users` row deletion mishap) | The `/login` flow cannot authenticate any admin | Inspect DB state, create or restore an admin row, restart |
| Primary admin unavailable + acute need | OTP delivery to absent admin's mailbox cannot complete | Create an emergency admin via CLI |
| Master-key recovery from backup | The running container has no `master.key`; `DbSecrets` cannot decrypt | Restore key from off-host backup, restart |
| Suspected active breach, must contain immediately | Web UI may be the compromised surface | Stop service, snapshot, then investigate via CLI |
| Account locked out + no recovery path (lost OTP mailbox, lost API key) | OTP cannot be delivered; recovery requires DB edits | Reset session/API-key state via CLI |

Do **NOT** use break-glass for:
- Routine admin work that the web UI supports (use the UI).
- Convenience access when the operator is just impatient (use the UI).
- Bypassing audit — *every* break-glass invocation is logged.

### Who can invoke

**Anyone with `sudo` on the deployment host** can invoke break-glass.
This is intentionally identical to the install/deploy authority — the
system inherits the host's access-control model. Concretely:

- **Production deployment (the deploy host):** anyone with `sudo` on `the deploy host` —
  per the homelab chart, the `claude` account has `sudo` for
  container ops (NEVER for app data); the root account has full
  authority.
- **Medical-researcher single-tenant deployment:** the named
  installing-operator per the install-time agreement. The same
  individual is the de facto Security Officer per §164.308(a)(2).
- **Dev laptop:** the developer.

If your deployment has a *named* HIPAA Security Officer separate from
the host admin, the Security Officer MUST be notified **as soon as
practicable, and no later than 1 hour** after any break-glass
invocation. (Matches the §164.408 "without unreasonable delay"
shape; the 1-hour bound is a procedural ceiling, not a target.)
Use the contact in SECURITY.md.

### How to invoke (procedure)

Run on the **deployment host**, in a recorded shell session if at
all possible (`script -a /tmp/break-glass-$(date +%Y%m%d-%H%M).log`
is the simplest record):

**Step 1 — Pre-incident note (mandatory, ≤2 min).** Before running
any command, create a file at
`docs/incidents/<YYYY-MM-DD>-break-glass-<short-name>.md` with at
least:

```
date: <UTC timestamp>
operator: <your name>
reason: <one-line trigger from the table above>
expected_actions: <what you intend to do>
auth_context: <admin-on-call / Security-Officer-notified / sole-operator>
```

The pre-incident note exists to make the access *intentional* and
*auditable* even if the next steps fail. If you only have time for
one thing before invoking, this is it.

**Step 2 — Container exec.** Most CLI commands run inside the
container so they share its `DbSecrets`, master-key, and database:

```bash
sudo podman exec -it email-triage email-triage <subcommand>
```

The container's logging (`SQLiteLogHandler`, audit chain at )
records every command's invocation with operator-name from
`$USER` and a boundary event marking the break-glass session.

**Step 3 — Common recovery actions.**

Create an emergency admin (web auth broken / primary admin
unavailable):

```bash
sudo podman exec -it email-triage email-triage user create \
  --email <new-admin@example.com> --role admin
# CLI prints the one-time login link; deliver via your alternate channel
# (Signal, SMS, in-person). Token expires per AUTH_OTP_TTL_MINUTES.
```

Restore master key from off-host backup:

```bash
# Stop the service first to release any open DB handles.
sudo systemctl stop email-triage.service

# Restore the master key from your backup location.
sudo cp /path/to/backup/master.key /srv/email-triage/data/master.key
sudo chown 1000:1000 /srv/email-triage/data/master.key  # match container UID
sudo chmod 600 /srv/email-triage/data/master.key

# Restart and verify secrets decrypt.
sudo systemctl start email-triage.service
sudo podman exec email-triage email-triage secrets list  # confirm DbSecrets decrypts
```

Snapshot DB + logs before destructive action:

```bash
ts=$(date +%Y%m%d-%H%M)
sudo cp -a /srv/email-triage/data /srv/email-triage/data.break-glass.$ts
sudo journalctl -u email-triage.service --since '24 hours ago' \
  > /tmp/break-glass-journal-$ts.log
```

Reset a locked API key or stuck session (DB-direct; LAST RESORT):

```bash
# Identify the affected key/session.
sudo podman exec email-triage email-triage apikey list
sudo podman exec email-triage email-triage user list

# Delete and recreate as needed, OR for direct DB inspection:
sudo podman exec -it email-triage sqlite3 /data/triage.db
# Inside sqlite3: do the minimum necessary; every UPDATE/DELETE here
# is a break-glass action that the post-incident review must reconcile.
```

**Step 4 — Document outcome.** Append to the pre-incident note:

```
actions_taken: <list of commands run, in order>
end_state: <what is now true that wasn't before>
side_effects: <anything unexpected, errors, partial completions>
follow_ups: <follow-up tasks / the backlog items needed>
```

If the access touched PHI directly (e.g. you read `triage_runs`
rows, viewed log entries containing sender/subject in non-HIPAA
mode, or ran any query against a HIPAA-flagged account), also note
that explicitly in `actions_taken` — the `hipaa_access_events`
audit table cannot capture CLI access, so your note IS the audit
record for that read.

**Step 5 — Restore standard access.** As soon as the emergency is
contained: re-enable normal admin access (login link or OTP), close
any direct DB sessions, and confirm the web UI is reachable for
routine work. Break-glass is a temporary path, not a residency.

### How the access is audited

Break-glass access leaves audit footprints in three places, each
serving a different reviewer:

1. **`log_entries` table** (SQLiteLogHandler chain at ): every
   CLI command that invokes the application logger writes an entry
   with a tamper-evident hash chain. A break-glass session is
   visible as a sequence of `severity=info` entries from the
   `email_triage` CLI with `operator=<$USER>`. The hash chain
   makes after-the-fact tampering detectable; an inserted or
   deleted entry breaks the chain.
2. **`docs/incidents/<date>-break-glass-<name>.md`** (the pre/post
   note you wrote): the human-readable, intention-bearing record.
   This is the authoritative record of *why* the access happened
   and *what* the operator intended.
3. **Host journal** (`journalctl -u email-triage.service` +
   `sudo` audit log if `auditd` is configured): captures the
   container start/stop and the `sudo podman exec` invocations
   themselves. Use this to corroborate the timeline.

These three should AGREE. Any disagreement (e.g., journal shows a
CLI invocation but the incident note doesn't list it) is itself an
audit finding and goes into the post-incident review.

**Procedural mechanism vs automated mechanism:** the
`hipaa_access_events` table (per §164.312(b) audit controls for
PHI-view access) is populated only by web-UI handlers — that's the
**automated mechanism**. CLI access reading PHI-bearing rows is
covered by the **procedural mechanism** in this section: your
`actions_taken` field in the incident note IS the audit record per
§164.312(b) for that read. §164.312(b) explicitly names "hardware,
software, **and/or procedural mechanisms**" as acceptable forms of
audit control; a documented procedure that REQUIRES the operator
to write the action record IS a procedural mechanism. Auto-emit on
CLI reads (upgrading the procedural mechanism to automated) is
tracked as a Cycle 6+ enhancement, not a compliance gap.

### Post-incident review

Within **7 days** of any break-glass invocation:

1. **Reconcile the three audit sources** (incident note,
   `log_entries`, host journal). Any disagreement is logged.
2. **Convert follow-ups to the backlog items.** If the break-glass
   was needed because of a defect (e.g., the web auth broke for a
   reason that should be code-fixed), file the fix as a HIGH
   the backlog item — the fact that break-glass was *necessary* is
   itself a quality signal.
3. **Operator + Security Officer review.** For HIPAA-flagged
   deployments, the Security Officer reviews the incident note and
   countersigns by appending `reviewed_by: <name>; reviewed_at:
   <timestamp>` to the file. For sole-operator deployments, the
   operator's own review and post-mortem note suffices.
4. **Update this runbook** if the procedure was unclear or wrong
   at any step. Break-glass procedure that wasn't clear at 3 a.m.
   is broken procedure; fix it while the experience is fresh.
5. **Sanitised summary into SECURITY.md** if the lesson
   generalises (the incident notes themselves stay local-only,
   gitignored under `docs/incidents/`).

### Limits — what break-glass cannot do

- **Cannot recover a lost master key without a backup.** This is
  intentional (README "Backup & Disaster Recovery"). If both the
  master key and all backups are lost, secrets are unrecoverable;
  the DB rows protected by `DbSecrets` are permanently inaccessible
  ciphertext. Plan backups accordingly.
- **Cannot bypass the audit chain.** Hash-chained `log_entries` is
  tamper-evident; deliberate tampering is detectable at the next
  hash-chain verification. Break-glass is recorded; it is not
  cover.
- **Cannot grant a non-host-admin emergency access.** A user without
  `sudo` on the host cannot break-glass; their recourse is to
  reach a host admin via your alternate-channel directory in
  SECURITY.md. This is by design — emergency access is gated on
  pre-existing trust, not on a self-asserted emergency.
- **Cannot exfiltrate data off-host.** Per
  `project_no_external_data_flow`, the install boundary is
  internal-only by design (no enumerated outbound channel to
  external mail/storage/messaging services for break-glass use).
  Break-glass operates INSIDE that boundary; if recovery requires
  data to leave the host (e.g. for forensic analysis by a third
  party), that's a separate decision logged in the incident note
  and approved by the Security Officer — not a break-glass action.

## Scenarios — quick reference

### "Mail just stopped flowing"

1. `curl http://the deploy host.example.com:8080/health` — service up?
2. `gh run list --workflow=Security` — CI broken on a deploy?
3. `ssh the agent host "python3 <your monitoring tool> status --host the deploy host"`
   — what is the monitoring system saying?
4. If watchers are 0/2 connected: provider creds rotated? Check
   `secrets_store` table for null/empty IMAP/OAuth tokens.

### "A user says they got someone else's mail in their digest"

CRITICAL by default — single-tenant boundary breach.

1. **Containment**: `systemctl stop email-triage.service` immediately.
2. Pull the last `triage_runs` rows + the digest delivery log line
   (`mechanism=deliver_to_inbox` entries).
3. Verify the digest recipient resolution returned the right address —
   the recipient-mode logic should never cross accounts. If it did,
   patch + audit every digest sent in the affected window.
4. Notify affected users.

### "pip-audit reports a CVE"

1. Check `Fix Versions` column. If a fix exists, upgrade the dep,
   re-run audit, push.
2. If no fix yet:
   - Is the dep actually exposed at runtime? (build-time only is
     acceptable risk.)
   - Add waiver to `scripts/run-pip-audit.sh` with rationale +
     expected resolution date.
   - Subscribe to advisory updates; remove waiver when fix lands.

### "GitHub Actions secret leaked"

1. Rotate the secret in GitHub Actions settings immediately.
2. Force-rotate the underlying credential on the issuing system.
3. Audit recent CI runs for misuse (`gh run list`).

## Runbook ownership

Maintained by the project owner. Reviewed at every audit cadence
(see SECURITY.md). Last review: 2026-04-24.
