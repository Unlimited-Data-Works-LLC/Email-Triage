# Email Triage

Privacy-first, HIPAA-aware email classification and draft replies. Self-hosted, local LLM inference, no third-party cloud unless you explicitly opt-in under a Business Associate Agreement.

Built for operators whose inboxes carry data that shouldn't visit someone else's servers — clinicians, researchers, lawyers, anyone whose mail comes under compliance or privilege rules.

---

## What it does

- **Classifies incoming mail** into operator-defined categories (`notifications`, `system-alerts`, `meetings`, `to-respond`, custom categories, etc.) using a local LLM.
- **Drafts reply text** in the operator's own writing style. Style learning is opt-in per account and HIPAA-aware (describe-and-discard semantics — zero PHI persisted).
- **Routes classified mail** to folders, applies labels, fires watches with optional webhook escalation.
- **Calendar-aware meeting scheduling** — when a `meeting-request` lands, drafts a reply listing free windows from the operator's calendar.
- **Daily digest** of overnight activity, BAA-expiry banner, /health endpoint for Nagios polling, tamper-evident audit hash chain.

## Privacy posture

Operator-confirmed boundary, audited:

- **Mail data** stays in your install's SQLite database. Encrypted at rest via Fernet; the master key lives in a podman secret on your deploy host.
- **Outbound network** is restricted to: mail providers you configure (Gmail / Outlook / your IMAP server). No analytics, no telemetry by default, no CDN.
- **LLM inference** runs on Ollama on your hardware. Cloud-LLM backends (OpenAI / Gemini / Azure OpenAI) are off by default; HIPAA-flagged accounts only see BAA-certified backends in the admin dropdown.
- **HIPAA mode** per-account or install-wide. Audit hash chain (§164.312(b)). Describe-and-discard style learning means the LLM produces structured-output descriptors, not summaries — message bodies are read in memory and never persisted.

Full detail: [docs/privacy.md](docs/privacy.md) and [docs/hipaa-audit.md](docs/hipaa-audit.md).

## Quick start

```bash
# 1. Run the container (image is cosign-signed; verify before pulling)
sudo cosign verify ghcr.io/unlimited-data-works-llc/email-triage:0.1.0 \
    --certificate-identity-regexp 'https://github.com/Unlimited-Data-Works-LLC/.+/release\.yml@.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com

sudo podman pull ghcr.io/unlimited-data-works-llc/email-triage:0.1.0

# 2. Generate master key + bootstrap secret backend
sudo podman run --rm -it ghcr.io/unlimited-data-works-llc/email-triage:0.1.0 \
    secrets bootstrap

# 3. Start the service (systemd quadlet or podman directly)
sudo systemctl start email-triage
```

Step-by-step guide: [docs/install.md](docs/install.md).

## About the image size

The container image ships at ~250 MB. The optional in-process embedding stack — used for style learning and semantic search — is ~600 MB of model weights + CPU ML runtime. We split this out instead of baking it into the image because the all-in-one image is ~2 GB compressed (8× the size), which slows pulls, pushes, CI builds, and air-gap transfers without giving most operators any benefit (you'll choose your embedding backend on first setup anyway).

On first run, the admin UI prompts to either install the local embedding backend (~600 MB, hash-verified against a pinned manifest baked into the image), sideload pre-staged bits (for restricted-egress installs), or point at an existing Ollama instance instead. All paths are hash-checked. See [docs/install.md](docs/install.md) for both setup paths.

**Plan ~5 GB on the persistent volume** you bind to `/app/data`: the embedding install lands there (~2.1 GB unpacked), plus the SQLite DB grows with mail volume and the sent-mail-index vectors are persisted per indexed sent message. The most common install failure is mounting `/app/data` on a small partition — see `docs/install.md` § Disk allocation for the full breakdown (HIPAA installs with multi-year retention plan 50+ GB).

## Container distribution

Released container images are published to `ghcr.io/unlimited-data-works-llc/email-triage`. Tag scheme:

- `X.Y.Z` — pinned semver release (e.g. `0.1.0`). The same image is also tagged `vX.Y.Z` (e.g. `v0.1.0`) so commands that match the git tag form still resolve. Both forms point at the same digest.
- `X.Y`, `X` — semver aliases that move forward with each compatible release.
- `:stable` — alias for the most recent semver release.
- `:latest` — same as `:stable` at release time. Don't depend on it long-term in scripts.
- `:edge` — every push to `main`; for operators tracking development.

Every published image is cosign-signed (keyless OIDC). HIPAA installs additionally require an operator-issued in-toto attestation with a `hipaa_safe: true` predicate before applying an update — that's a second OIDC subject, separately approved by a human reviewer. The customer-side verification recipe is in [docs/install.md](docs/install.md) § Verifying a release.

## Email provider support

- **Gmail** — REST API (preferred) or IMAP. Native push via Pub/Sub or IDLE.
- **Outlook / Office 365** — Microsoft Graph REST API or IMAP (`outlook.office365.com`).
- **Generic IMAP** — any standards-compliant IMAP server (Dovecot, Cyrus, etc.) with IDLE for push or poll for fallback.

Multiple accounts per install. Each account gets its own routes, watch list, calendar wiring, optional HIPAA flag, optional cloud-LLM backend choice.

## License

[Apache-2.0](LICENSE).

## Security

Reports: see [SECURITY.md](SECURITY.md). Never open a public issue for a vulnerability.

## Reading order

If you're evaluating Email Triage:

1. This README for the product overview.
2. [docs/install.md](docs/install.md) for deploy mechanics + verify-release recipe.
3. [docs/privacy.md](docs/privacy.md) for the privacy + compliance posture.
4. [docs/hipaa-audit.md](docs/hipaa-audit.md) for the most recent audit findings.
5. [SECURITY.md](SECURITY.md) for vulnerability reporting + risk register.
