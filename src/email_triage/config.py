"""YAML configuration loading and validation.

Config is searched at:
    1. Explicit path argument
    2. ./email-triage.yaml
    3. ~/.config/email-triage/config.yaml

No secrets are stored in config — those go through the secrets provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Config data structures
# ---------------------------------------------------------------------------

#: Install-wide cap on mailboxes an operator can IDLE-watch per IMAP
#: account. One TCP/TLS connection per folder, and most IMAP servers
#: limit concurrent per-user connections — Dovecot's default
#: ``mail_max_userip_connections`` is 10, Gmail IMAP caps at 15,
#: Exchange typically 16. Default 5 leaves headroom for other clients
#: (phone, desktop mail app) on the same account. Override in YAML:
#: ``provider.imap.max_mailboxes_per_account: N``.
DEFAULT_MAX_MAILBOXES_PER_ACCOUNT = 5


@dataclass
class ProviderConfig:
    type: str = "gmail_api"
    gmail_api: dict[str, Any] = field(default_factory=dict)
    imap: dict[str, Any] = field(default_factory=dict)
    office365: dict[str, Any] = field(default_factory=dict)


@dataclass
class ClassifierConfig:
    backend: str = "ollama"
    model: str = "[local-llm-model]
    ollama_url: str = "http://localhost:11434"
    # Ollama: if True, classify() probes /api/ps and uses whatever
    # model is already resident in VRAM (falls back to ``model`` when
    # nothing is loaded). Prevents a "GPU full, configured model
    # can't load" 500 in homelab setups where a different model is
    # already warm — and sidesteps version drift ([local-llm-model] → [local-llm-model])
    # without requiring a config chase. Cached for 30 s per process.
    prefer_loaded: bool = True
    openai_base_url: str = ""
    openai_model: str = ""
    gemini_model: str = ""
    categories: dict[str, str] = field(default_factory=lambda: {
        "to-respond": "Emails that need a reply from you",
        "fyi": "Informational, no action needed",
        "newsletters": "Subscriptions and recurring content",
        "comments": "Mentions, comments, and notifications from tools",
        "notifications": "System alerts and automated messages",
        "invoices": "Bills, receipts, and payment-related emails",
        "action-required": "Tasks, requests, deadlines",
        "meetings": "Meeting invites, agenda, scheduling",
        "grant-related": "Grant applications, reviews, funding communications",
        "sponsor": "Sponsorship inquiries and communications",
    })


@dataclass
class RouteConfig:
    actions: list[str] = field(default_factory=list)


@dataclass
class EscalationConfig:
    """Legacy global escalation config — kept for YAML compat.

    Escalation is now per-user, per-category via the web UI profile page.
    This config is ignored at runtime.
    """
    enabled: bool = False
    categories: list[str] = field(default_factory=lambda: ["to-respond", "action-required"])


@dataclass
class SecretsConfig:
    """Configuration for the secrets subsystem.

    ``backend`` is the *bootstrap* store — the place the app reads the
    master encryption key from at startup.  All user-managed secrets
    (IMAP passwords, OAuth tokens, SMTP auth, etc.) live in an encrypted
    DB column, keyed by that master key.

    Use ``backend: "external:<name>"`` to delegate to a plugin-registered
    provider (KeePass, Vault, etc.) — see ``register_external_provider``
    in ``email_triage.secrets``.
    """
    backend: str = "env"
    keyfile_path: str = "~/.config/email-triage/key"
    master_key_name: str = "ET_MASTER_KEY"
    external: dict[str, Any] = field(default_factory=dict)


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"
    hipaa: bool = False
    file: str | None = None
    # Rotation knobs for the SQLite ``log_entries`` table. Default caps
    # work out to roughly a month of history OR 50k rows, whichever
    # trims first. Set very high values to effectively disable.
    retention_days: int = 30
    max_rows: int = 50000


@dataclass
class PersistenceConfig:
    db_path: str = "./data/triage.db"


@dataclass
class Rfc2136Config:
    """RFC-2136 dynamic-DNS-update settings for ACME DNS-01 challenge.

    Operator's authoritative DNS server runs an ``update-policy``
    grant scoped to a TSIG-named key. Key may write
    ``_acme-challenge.<hostname>`` TXT records only. Renewer
    publishes record, polls until visible, hands off to LE for
    validation, deletes record.

    Minimal-privilege: TSIG key cannot touch any other record.
    Compromise of ``acme_tsig_secret`` exposes only the
    ACME-challenge subdomain.
    """
    nameserver: str = ""  # IP of the dynamic-update target
    nameserver_port: int = 53
    tsig_key_name: str = ""
    tsig_algorithm: str = "hmac-sha256"
    tsig_secret_ref: str = "acme_tsig_secret"  # secrets-store key
    # CNAME-delegation pattern: cert subject and TSIG-scoped zone
    # may differ. Operator pre-creates
    # ``_acme-challenge.<cert-subject> CNAME
    # _acme-challenge.<update-zone>``. App publishes TXT under
    # ``update_zone``. Empty ``update_zone`` -> publish under
    # the cert subject zone.
    update_zone: str = ""

    # Public-resolver propagation gate. After the dynamic update
    # is visible on the configured authoritative server, the
    # renewer polls these public recursive resolvers before
    # signaling LE. Some authoritative-DNS topologies separate
    # the update target from the public-facing nameservers, so
    # propagation between them can lag. Match acme.sh: query
    # multiple independent resolvers, retry for a long window,
    # only consider the gate cleared when ALL configured
    # resolvers see the record.
    public_resolvers: list[str] = field(
        default_factory=lambda: ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    )
    public_propagation_timeout_secs: int = 1800  # 30 min
    public_propagation_interval_secs: int = 15

    # Split-horizon DNS fallback wait. Some networks (homelab
    # privacy resolvers, internal DNS that doesn't leak queries to
    # upstream, etc.) return local-view answers for the operator's
    # zones. The gate detects this via a root-server probe; on
    # detection it skips the public-DNS verification and waits
    # this many seconds for the local-primary -> public-secondary
    # sync (typical cron cadence is 5 min) before letting LE judge
    # directly. Default 10 min covers the common 5-min cron plus a
    # buffer for recursor cache refresh on LE side.
    public_propagation_split_horizon_wait_secs: int = 600


@dataclass
class AcmeConfig:
    """Built-in ACME (Let's Encrypt) automation.

    When ``enabled``, a background task running every
    ``check_interval_hours`` checks the on-disk cert expiry; if it's
    within ``renewal_threshold_days`` of NotAfter, the renewer issues
    a fresh order against the configured directory and writes the
    new fullchain + key atomically into ``TLSConfig.cert_dir``. The
    HTTPS listener picks up the new cert on next handshake via the
    mtime-watch reload (no process restart).

    Account key (Ed25519) is generated on first run and stored
    encrypted in the secrets store under ``acme_account_key``.
    """
    enabled: bool = False
    # Default to LE production. Tests + first-time bring-up should
    # override this to the staging URL to avoid burning the 5/week
    # rate limit while iterating:
    #   https://acme-staging-v02.api.letsencrypt.org/directory
    directory_url: str = "https://acme-v02.api.letsencrypt.org/directory"
    account_email: str = ""
    domains: list[str] = field(default_factory=list)
    challenge: str = "dns-01"  # "dns-01" | "http-01"
    renewal_threshold_days: int = 30
    check_interval_hours: int = 24
    dns_provider: str = "rfc2136"  # "rfc2136" | future: "cloudflare", "route53"
    rfc2136: Rfc2136Config = field(default_factory=Rfc2136Config)
    # Resilience knobs for the LE-side validation step. After our
    # public-resolver gate passes, the LE directory still queries
    # the record from its own recursive chain — negative caches and
    # delegation latency can make the first attempt fail. Match
    # acme.sh: pause briefly to let LE-side caches expire, then
    # retry the full order on ValidationError.
    pre_validation_grace_secs: int = 30
    validation_retries: int = 5
    validation_retry_delay_secs: int = 60
    # #77 -- retry-loop polish. ``validation_retry_backoff`` shapes the
    # delay sequence between retries:
    #   "fixed"       -> always validation_retry_delay_secs
    #   "exponential" -> 15s, 30s, 60s, 120s, 300s, ... capped at the
    #                    configured retry-delay value
    #   "fibonacci"   -> 15s, 30s, 45s, 75s, 120s, ... same cap
    # Default exponential -- right curve for negative-cache TTL: first
    # retry fast (caches sometimes just need a poke), later retries
    # longer (clear the full neg-cache TTL).
    validation_retry_backoff: str = "exponential"
    # CAA pre-flight (PR 4 / B2). Walk up the DNS labels for each cert
    # subject and check for CAA records. If a CAA exists that excludes
    # ``letsencrypt.org``, the order will silently fail at LE
    # validation. ``caa_enforce`` controls whether the renewer aborts
    # (True) or only warns (False, default = report-only first week
    # so operators see what would have happened before opting in).
    caa_enforce: bool = False


@dataclass
class TLSConfig:
    """Internal HTTPS termination for the FastAPI listener.

    Four deploy postures supported, in priority order at startup:

    1. **Built-in ACME automation** (``acme.enabled=true``). The app
       speaks ACME directly to the configured directory (default LE
       prod), publishes challenges via DNS-01 (RFC-2136 against the
       operator's BIND) or HTTP-01, writes cert + key atomically into
       ``cert_dir``, and renews automatically on a 24-hour timer.
       Zero ongoing operator overhead.
    2. **External ACME pipeline** (operator-side acme.sh / lego /
       certbot with DNS-01). Point ``cert_dir`` at the directory the
       external tool writes ``server.crt`` + ``server.key`` to. App
       hot-reloads on mtime change.
    3. **Tailscale-issued LE** (HTTPS feature). One-shot via
       ``email-triage tls fetch-tailscale --hostname <host>``;
       monthly cron refreshes. Useful when the install is Tailnet-only
       and the operator doesn't want to configure DNS-01.
    4. **Self-signed** (default + zero-config fallback).
       ``email-triage tls bootstrap`` generates a cert if ``cert_dir``
       is empty. Browser shows the usual warning. WebAuthn won't
       work cross-host with self-signed; use one of the above for
       any auth-surface work that needs hardware keys.

    ``cert_dir`` defaults to ``<data_dir>/certs/``. Override here
    when the external ACME tool writes elsewhere on the host.
    """
    cert_dir: str = ""  # empty = default: <data_dir>/certs
    # Default OFF so existing deployments don't flip to HTTPS-only on
    # upgrade and surprise an external Nagios check / monitor that
    # was hard-coded to HTTP. Operator opts in via YAML
    # ``tls: { enabled: true }``. See docs/deploy-deployhost.md for the
    # rollout sequence (update monitors first, then enable here).
    enabled: bool = False
    acme: AcmeConfig = field(default_factory=AcmeConfig)
    # PR 8 / D1 follow-up: CSRF enforcement gate. Default ON
    # (#82 — flipped 2026-05-10 after the soft-launch window proved
    # rejects stay flat at zero across normal traffic + the #133
    # oversize-body fix landed). Violations now return HTTP 403.
    # Operator can opt out by setting ``tls: { csrf_enforce: false }``
    # in YAML, or by exporting ``EMAIL_TRIAGE_CSRF_ENFORCE=0`` for a
    # one-shot debug session. Soft-launch logging is still wired —
    # ``app.state.csrf_rejects`` and the access_log audit row both
    # fire regardless of enforce mode (outcome flips between
    # ``csrf_rejected`` (403'd) and ``csrf_would_reject`` (logged
    # only)).
    csrf_enforce: bool = True

    # #82 item 4 — operator-defined CSRF exempt path prefixes. Adds
    # to the always-on set baked into ``web/csrf.py`` (``/health``,
    # ``/webhooks/``, ``/api/oauth/``, ``/login``). Useful when the
    # operator has a custom integration that legitimately can't
    # carry the token (third-party signed webhook, kiosk fetch,
    # etc.). Each entry is a path PREFIX — ``/api/foo`` exempts
    # ``/api/foo/bar`` and ``/api/foo`` itself.
    #
    # Empty by default; operators with no extra prefixes never need
    # to touch this field. Validated at YAML-load: each entry must
    # start with ``/`` (anything else is a no-op trap waiting to
    # bite). Round-trips through ``_write_config_yaml``.
    csrf_exempt_prefixes: list[str] = field(default_factory=list)

    # Operator-defined hostname suffixes that count as "local" for the
    # webhook-dispatch + classifier-BAA gates. A hostname is treated
    # as local when it ends with any of these suffixes (in addition
    # to localhost / 127.0.0.1 / RFC1918 IPs / `.local`, which are
    # always-on). Empty list = only the always-on set fires.
    #
    # The operator configures their internal homelab / VLAN suffix
    # here (e.g. `[".home.lan", ".internal.example"]`); the source
    # tree never embeds an operator-specific suffix. Tests use
    # synthetic suffixes via this field too.
    local_url_suffixes: list[str] = field(default_factory=list)


@dataclass
class PushConfig:
    listen_port: int = 8080
    public_url: str = ""
    # Gmail Pub/Sub push config. The topic is the fully-qualified
    # resource name (projects/<proj>/topics/<name>) used when calling
    # users.watch. The SA email is the identity Cloud Pub/Sub uses on
    # the push subscription — we require the inbound JWT's `email`
    # claim to match it. Audience defaults to public_url when blank.
    gmail_topic_name: str = ""
    gmail_subscription_sa_email: str = ""
    gmail_audience: str = ""
    # OpenClaw bearer-token API. Webhook emit + rate limit
    # share the push config block because they're operator-facing
    # surface, not a per-account knob.
    openclaw_webhook_enabled: bool = True
    openclaw_rate_limit_per_minute: int = 60
    # Cap on bulk-endpoint batch size. 0 = unlimited (callers know
    # what they're doing). Default 100 prevents runaway batches.
    bulk_max_batch_size: int = 100
    # Office 365 / Microsoft Graph: how far ahead of expiration the
    # renewer should refresh subscriptions. Graph subscriptions for
    # mail resources max out at ~3 days (4230 minutes); the renewer
    # ticks hourly and refreshes anything whose ``expiration_at``
    # falls within this window. Operators with reliable Graph
    # connectivity can leave the default; ones with shaky links
    # should shrink it (subscription dies if a renew round-trip
    # fails on the very last attempt before expiry).
    office365_subscription_renewal_window_hours: int = 24


@dataclass
class SmtpConfig:
    host: str = ""
    port: int = 587
    username: str = ""               # SMTP login user (often the from_addr)
    from_addr: str = ""              # Envelope sender
    from_name: str = ""              # Optional display name: "Name" <addr>
    use_tls: bool = True
    # Password is NOT here — it comes from the secrets store as SMTP_PASSWORD.


@dataclass
class HealthEmailConfig:
    """Admin-configurable daily health digest (#27).

    The digest is a push-signal for admins so "dead gateway / silent
    failure" surfaces without anyone opening the UI.  All toggles live
    under the ``health_email:`` YAML section.

    PHI stance: no message-level content ever.  When the system is in
    HIPAA mode the ``include_hipaa_events`` section is suppressed
    automatically (the operator already knows PHI flows through).

    Recipient field deprecation (CR-2c, 2026-05-16)
    -----------------------------------------------
    ``recipients`` here is being phased out in favour of
    :class:`AdminEmailConfig.recipients` (canonical name now that the
    same destination drives update-failed alerts and any future
    admin-targeted notification). On read, daily-health falls back to
    this field when ``admin_email.recipients`` is empty and logs a
    deprecation warning. Operator-edit path writes
    ``admin_email.recipients`` only. Plan: drop after a v0.x
    deprecation cycle (~3 months).
    """
    enabled: bool = False
    recipients: list[str] = field(default_factory=list)
    send_at: str = "07:15"  # HH:MM local time.
    include_health: bool = True
    include_watchers: bool = True
    include_triage: bool = True
    include_errors: bool = True
    include_hipaa_events: bool = True
    include_api_key_events: bool = True
    include_pubsub: bool = True
    # CR-2c — opt-in section that surfaces ``version_status`` in the
    # daily-health email body when an update is available or rollback
    # is dangerous. Operator can suppress without disabling the digest
    # itself.
    include_update_available: bool = True
    quiet_mode: bool = False
    # Error-rate threshold (percentage) above which the subject line is
    # escalated to "Attention".  0 = any ERROR flips the flag.
    error_rate_threshold_pct: int = 0


@dataclass
class AdminEmailConfig:
    """Single destination for admin-targeted notifications (CR-2c).

    The daily health digest used to own its own ``recipients`` list. As
    of the managed-deployment build the same destination handles:

    * daily health digest (#27 — :class:`HealthEmailConfig`)
    * update-failed alerts (CR-2d — fired by ``scripts/deploy.sh`` when
      a post-apply health check fails and a snapshot-restore rollback
      runs)
    * any future admin-targeted channel

    Keeping the destination in one place avoids the operator having to
    edit two recipient lists. ``HealthEmailConfig.recipients`` survives
    as a read-fallback shim for a deprecation cycle; new edits write
    here.

    ``release_check_url`` is the GitHub Releases API endpoint the
    daily-health "update available" section queries to pick up release
    notes. Operator-configurable so an install pointing at a fork or a
    private mirror can override. Empty / missing falls back to the
    public mirror default below.
    """
    recipients: list[str] = field(default_factory=list)
    release_check_url: str = (
        "https://api.github.com/repos/unlimited-data-works-llc/email-triage/releases/latest"
    )


@dataclass
class SummaryEmailConfig:
    """Decoration for the outbound summary / digest family of emails (#33).

    ``signature`` supports ``{category}`` placeholder substitution now;
    ``{account}`` / ``{date}`` are reserved for later.
    """
    signature: str = "Sent by your email-triage {category} Digest 🗞️"


@dataclass
class WebhookTarget:
    url: str = ""
    events: list[str] = field(default_factory=list)
    secret_key: str = ""  # key name in secrets store, NOT the actual secret


@dataclass
class GoogleOAuthConfig:
    """Install-level Google OAuth client credentials.

    Shared across all Gmail accounts on this install. Two pairs because
    Google's "Web application" and "Desktop" client types have
    incompatible redirect-URI rules; both are required if both auth
    paths are to be offered.
    """
    web_client_id: str = ""
    web_client_secret: str = ""
    desktop_client_id: str = ""
    desktop_client_secret: str = ""


@dataclass
class Office365OAuthConfig:
    """Install-level Microsoft Entra (Azure AD) app registration creds.

    Shared across all Office 365 accounts on this install. One Azure
    app registration per install — accounts pick personal-MSA vs
    org-tenant via the per-account ``is_personal_msa`` flag, which
    routes auth to ``"common"`` (personal) or to this ``tenant_id``
    (organisation). Mirrors :class:`GoogleOAuthConfig` for symmetry.

    Hydrated from the secrets store at startup (keys
    ``O365_OAUTH_TENANT_ID`` / ``O365_OAUTH_CLIENT_ID`` /
    ``O365_OAUTH_CLIENT_SECRET``); never YAML round-tripped. Operator
    edits via the admin ``/config`` page.
    """
    tenant_id: str = ""      # GUID, or "organizations" for multi-tenant
    client_id: str = ""
    client_secret: str = ""  # raw secret at runtime (encrypted at rest in secrets store)


@dataclass
class IngestionConfig:
    """Server-wide cadence for the unified push + poll ingestion loop.

    The ingestion model gives every account two independent knobs:

      * ``push_enabled`` — start real-time delivery for this provider
        (IMAP IDLE / Gmail Pub/Sub / Graph subscription).
      * ``poll_enabled`` — run a background poller on ``poll_interval_minutes``
        cadence regardless of push state. Acts as a safety net when push
        is on (catches dropped deliveries, socket drops, Pub/Sub retry
        exhaustion), and as primary ingestion when push is off.

    ``default_poll_interval_minutes`` is the server-wide default used
    when a freshly-created account doesn't carry an explicit value.
    Bounds (``POLL_MIN`` / ``POLL_MAX`` / ``POLL_STEP``) are class-level
    constants so the admin template, the save handler, and the DB
    back-compat shim all read from one place.

    The legacy B3 fields ``push_poll_interval_min`` and
    ``poll_poll_interval_min`` are retained for YAML round-trip so
    existing configs keep parsing; they no longer drive the loop.
    """
    # Unified cadence default — one interval per account, used for both
    # safety-net poll (when push is healthy) and primary poll (when push
    # is off). 60 min default, range 10–240, step 10.
    default_poll_interval_minutes: int = 60

    POLL_MIN: int = 10
    POLL_MAX: int = 240
    POLL_STEP: int = 10

    # ── Legacy B3 fields (deprecated — kept for YAML back-compat) ──
    push_poll_interval_min: int = 20
    poll_poll_interval_min: int = 10
    PUSH_MIN: int = 10
    PUSH_MAX: int = 60
    STEP: int = 5


@dataclass
class WebAuthnConfig:
    """Browser FIDO2 / WebAuthn settings for hardware-key login.

    ``rp_id`` is the Relying Party ID — the browser binds every
    registered credential to this string permanently. Changing it
    invalidates every registered hardware key (operator + every user
    must re-register). Pick a hostname (or registrable suffix) that
    matches the install's canonical URL.

    Spec rule: ``rp_id`` must equal the origin hostname OR be a
    registrable suffix of it. Origin ``https://auth.example.com``
    permits ``rp_id`` of ``auth.example.com`` OR
    ``example.com``, but NOT ``com`` alone (TLD).

    The cert SAN must contain ``rp_id``. With this work's built-in
    ACME automation issuing a cert for the same name, that
    constraint is satisfied automatically.
    """
    rp_id: str = ""        # e.g. "auth.example.com"
    rp_name: str = "Email Triage"
    origin: str = ""       # e.g. "https://auth.example.com"
    # Future: enforce userVerification=required for admin role
    # (PIN/biometric on touch). Punch-list #69.
    require_user_verification_for_admin: bool = False


@dataclass
class AuthConfig:
    """Authentication / session settings.

    HIPAA / NERC-CIP context (PR 8 / D1 follow-up):

    Session timeout is the §164.312(a)(2)(iii) "Automatic Logoff"
    addressable spec. NIST SP 800-66 references it without a
    specific number. Industry norms:

      EHR / clinical workstations: 10-15 min idle.
      VA / DOD healthcare:         10 min.
      HIPAA research / portal SaaS: 30 min.
      Bedside / shared:            shorter still.

    ``session_ttl_secs`` is the operator pick for non-HIPAA
    deployments; default 86400 (1 day). UI surfaces the canonical
    buckets: 15 min, 30 min, 1 h, 1 d, 1 w, 2 w.

    ``hipaa_session_ttl_secs`` is the cap applied in HIPAA mode
    REGARDLESS of the operator pick. Default 900 (15 min) -- the
    aggressive end of HIPAA-defensible. Hard ceiling 1800 (30 min)
    enforced in code; values above are clamped at request-validation
    time so a misconfigured YAML can't silently weaken the auth
    surface.

    Effective TTL per request:
        if HIPAA mode (system OR account):
            min(session_ttl_secs, hipaa_session_ttl_secs)
        else:
            session_ttl_secs
    """
    session_ttl_secs: int = 86400  # 1 day
    hipaa_session_ttl_secs: int = 900  # 15 min

    # #92 login-rate-limit knobs. Per-email + per-IP rolling-window
    # failure counters guarding the login surfaces (OTP, WebAuthn,
    # dev-keypair) against brute-force / credential-stuffing. Source
    # of truth is the auth_events table — the guard reads
    # ``COUNT(outcome='failure') WHERE ts >= now - window``. Set
    # ``*_max=0`` to disable the corresponding scope (operators on
    # private LANs may want this).
    #
    # HIPAA §164.312(a)(2)(i) "Unique User Identification" + the
    # standing brute-force-protection security posture.
    login_per_email_max: int = 10
    login_per_email_window_secs: int = 600        # 10 min
    login_per_ip_max: int = 30
    login_per_ip_window_secs: int = 600           # 10 min

    # Hard upper bound on hipaa_session_ttl_secs. NOT exposed as a
    # config field -- enforced in code so a hand-edited YAML can't
    # raise the HIPAA cap above what the project's standing rule
    # allows. Re-litigating this constant requires a code change +
    # PR review, which is the point.
    HIPAA_TTL_HARD_CEILING_SECS: int = 1800


@dataclass
class LLMMaintenanceWindow:
    """One operator-defined LLM maintenance window (#149 Bundle C).

    See ``email_triage.llm_maintenance.MaintenanceWindow`` — this
    dataclass mirrors the runtime shape so YAML round-trips cleanly
    through :func:`load_config`. Identical fields; the runtime
    builder converts to the frozen runtime dataclass at startup.
    """
    host: str = ""             # informational, used in log + banner copy
    cron: str = ""             # 5-field POSIX cron (UTC)
    duration_minutes: int = 0
    backend: str = ""          # which classifier backend (e.g. "ollama")


@dataclass
class RedisCacheConfig:
    """Optional Redis-backed classification cache (#151).

    Skip the LLM call when the same email subject+sender+body has
    already been classified by the same model. Big token savings on
    repetitive inbound mail (Iperius backups, monitor alerts, list
    mail). OFF by default — operator opts in by pasting a Redis URL
    into ``/admin/integrations``.

    The URL is the credential: stored in YAML directly, NOT through
    the secrets store. Operators are responsible for keeping the
    Redis instance on the audited LAN-host allowlist (per the
    project's "no external data flow" rule). The cached values
    carry classifier metadata — including the classifier's free-text
    ``reason`` — so on-prem-only is the deployment posture.

    The protocol is plain Redis 5+. A ``valkey`` server (Linux
    Foundation fork) speaks the identical wire protocol — operators
    can point this URL at either and the ``redis`` Python client
    works unchanged.

    HIPAA defence-in-depth (revised 2026-05-13): the cache is now
    ENABLED for HIPAA-flagged accounts too, but the stored value
    OMITS the classifier ``reason`` field (the only PHI-shape leak
    surface — category + confidence + model are non-PHI). Reason-
    stripping happens at store time, transparent to the caller.

    Two-level cache shape (2026-05-13 refactor):
      * Outer Redis key: SHA-256 of
        (account_id, sender_norm, classifier_model, prompt_version).
        Stored as a Redis HASH.
      * Inner HASH field: SHA-256 of (subject_norm, body_hash).
      * Inner value: same JSON {category, confidence, reason,
        classified_at, model} (reason omitted under HIPAA).

    On lookup the outer key carries every classification ever made
    for that (account, sender, model) triple. Branch 1: an exact
    inner-field match returns the cached classification and skips
    the LLM. Branch 2 (outer hit, inner miss): the field-set is
    summarised into a category-distribution hint that's threaded
    into the LLM call (same shape as a list-rule hint). The LLM
    runs but with prior history as a bias signal; result is stored
    back as a new inner field.
    """
    url: str = ""           # empty disables; e.g. "redis://your-lan-host:6379/0"
    ttl_secs: int = 30 * 24 * 3600  # 30 days
    # Per-sender inner-array cap. When an outer key's HASH grows
    # past this, the oldest entry (by classified_at timestamp) is
    # evicted before the new field is added. Bounds growth on
    # heavy-traffic senders. Operator-configurable on
    # /config?tab=ai_backends.
    inner_cap_per_sender: int = 250
    # Hint strategy for Branch 2 (outer hit, inner miss):
    #   "top_k_with_freq" — pass full category distribution
    #     ("12 notifications / 8 to-respond / 3 newsletters") to
    #     the LLM as a hint. Most info to LLM; LLM picks based on
    #     current email content + history. Default.
    #   "top_1_dominant" — pass top-1 only IF it's >= dominant
    #     threshold percent of the field-set; else no hint, LLM
    #     cold. Safer for senders with mixed-category history.
    hint_strategy: str = "top_k_with_freq"
    # When ``hint_strategy == "top_1_dominant"``: the percent
    # threshold the top-1 category must exceed for a hint to fire.
    # 70% works for "this sender is clearly X" senders;
    # operator-tunable for tighter / looser bias.
    dominant_threshold_pct: int = 70


@dataclass
class EmbeddingFallbackConfig:
    """Optional secondary embedding backend (#m4-fallback).

    Only consulted when the primary embedder raises (network blip,
    model still loading, container restart in-flight). Same shape as
    the primary block — must individually pass the local-only
    allowlist at construction time.
    """
    backend: str = ""               # "ollama" / "sentence_transformers" / ""
    model_name: str = ""
    ollama_url: str = ""            # blank inherits primary's URL


@dataclass
class EmbeddingConfig:
    """Configuration for the local embedding backend (M-4 / M-5).

    Used by ``engine/embedding_backend.py`` to construct the embedder
    that ``actions/sent_mail_index.py`` (M-4) and the draft-reply
    prompt builder (M-5) consume. Local-only by design: ``backend``
    must be in the allowlist (``"ollama"`` /
    ``"sentence_transformers"``) or the factory raises ``ValueError``.

    Leave the section out of YAML entirely to disable retrieval
    install-wide -- per-account RAG toggles still work as a UX
    surface, but ``_should_use_rag`` returns False at draft time
    (with a one-time INFO log) when no embedding backend is
    configured. Fail-closed by design.

    Optional ``fallback`` sub-section configures a second backend
    that runs when the primary raises. Used 2026-05-13 to chain a
    fast CPU embedder (``sentence_transformers``) in front of an
    overflowing-GPU Ollama instance as the safety net.
    """
    backend: str = ""               # "ollama" / "sentence_transformers" / ""
    model_name: str = ""            # e.g. "all-MiniLM-L6-v2"
    ollama_url: str = "http://localhost:11434"
    fallback: EmbeddingFallbackConfig = field(
        default_factory=EmbeddingFallbackConfig,
    )


@dataclass
class TriageConfig:
    provider: ProviderConfig = field(default_factory=ProviderConfig)
    classifier: ClassifierConfig = field(default_factory=ClassifierConfig)
    routes: dict[str, RouteConfig] = field(default_factory=dict)
    escalation: EscalationConfig = field(default_factory=EscalationConfig)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    smtp: SmtpConfig = field(default_factory=SmtpConfig)
    push: PushConfig = field(default_factory=PushConfig)
    webhooks: list[WebhookTarget] = field(default_factory=list)
    # #60 — outbound webhook URLs default to local-only. Operators
    # must set webhooks_allow_external: true in YAML to ship events
    # to public-internet hosts. Even when allowed, payloads remain
    # metadata-only + HMAC-signed; this flag is the deny-by-default
    # guard against operator misconfiguration.
    webhooks_allow_external: bool = False
    google_oauth: GoogleOAuthConfig = field(default_factory=GoogleOAuthConfig)
    office365_oauth: Office365OAuthConfig = field(default_factory=Office365OAuthConfig)
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    webauthn: WebAuthnConfig = field(default_factory=WebAuthnConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    health_email: HealthEmailConfig = field(default_factory=HealthEmailConfig)
    # CR-2c — canonical admin-notification destination. Daily health
    # digest, update-failed alerts, and future admin-targeted channels
    # all resolve recipients via :func:`resolve_admin_recipients` which
    # falls back to ``health_email.recipients`` for the deprecation
    # cycle.
    admin_email: AdminEmailConfig = field(default_factory=AdminEmailConfig)
    summary_email: SummaryEmailConfig = field(default_factory=SummaryEmailConfig)
    embedding: EmbeddingConfig = field(default_factory=EmbeddingConfig)
    # #151 — optional Redis-backed classification cache.
    # Default empty URL = OFF (no behaviour change). Operator opts in
    # via /admin/integrations.
    redis_cache: RedisCacheConfig = field(default_factory=RedisCacheConfig)
    # #149 Bundle C — operator-defined LLM maintenance windows.
    # Empty list = no scheduled maintenance windows configured;
    # every LLM-unreachable error follows the default circuit-breaker
    # path (Bundle B) without the "scheduled maintenance" log /
    # banner copy. See ``email_triage.llm_maintenance``.
    llm_maintenance_windows: list[LLMMaintenanceWindow] = field(
        default_factory=list,
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_provider(raw: dict[str, Any]) -> ProviderConfig:
    return ProviderConfig(
        type=raw.get("type", "gmail_api"),
        gmail_api=raw.get("gmail_api", {}),
        imap=raw.get("imap", {}),
        office365=raw.get("office365", {}),
    )


def _parse_classifier(raw: dict[str, Any]) -> ClassifierConfig:
    cfg = ClassifierConfig()
    cfg.backend = raw.get("backend", cfg.backend)
    cfg.model = raw.get("model", cfg.model)
    cfg.ollama_url = raw.get("ollama_url", cfg.ollama_url)
    cfg.prefer_loaded = bool(raw.get("prefer_loaded", cfg.prefer_loaded))
    cfg.openai_base_url = raw.get("openai_base_url", cfg.openai_base_url)
    cfg.openai_model = raw.get("openai_model", cfg.openai_model)
    cfg.gemini_model = raw.get("gemini_model", cfg.gemini_model)
    if "categories" in raw:
        cfg.categories = raw["categories"]
    return cfg


def _parse_routes(raw: dict[str, Any]) -> dict[str, RouteConfig]:
    routes: dict[str, RouteConfig] = {}
    for key, val in raw.items():
        if isinstance(val, list):
            routes[key] = RouteConfig(actions=val)
        elif isinstance(val, dict):
            routes[key] = RouteConfig(actions=val.get("actions", []))
    return routes


def _parse_escalation(raw: dict[str, Any]) -> EscalationConfig:
    return EscalationConfig(
        enabled=raw.get("enabled", False),
        categories=raw.get("categories", ["to-respond", "action-required"]),
    )


def _parse_resolver_list(raw: Any, *, default: list[str]) -> list[str]:
    """Accept list, comma-string, or None -> list of resolver IPs."""
    if raw is None or raw == "":
        return list(default)
    if isinstance(raw, str):
        items = [s.strip() for s in raw.split(",") if s.strip()]
        return items or list(default)
    if isinstance(raw, list):
        items = [str(s).strip() for s in raw if str(s).strip()]
        return items or list(default)
    return list(default)


def _parse_webhooks(raw: list[dict[str, Any]]) -> list[WebhookTarget]:
    targets = []
    for item in raw:
        targets.append(WebhookTarget(
            url=item.get("url", ""),
            events=item.get("events", []),
            secret_key=item.get("secret_key", ""),
        ))
    return targets


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised when configuration is invalid or not found."""


_SEARCH_PATHS = [
    Path("./email-triage.yaml"),
    Path("./config/email-triage.yaml"),       # Container mount convention
    Path.home() / ".config" / "email-triage" / "config.yaml",
]


def load_config(path: str | Path | None = None) -> TriageConfig:
    """Load and validate configuration from YAML.

    Search order:
        1. Explicit ``path`` argument
        2. ./email-triage.yaml
        3. ~/.config/email-triage/config.yaml
    """
    resolved: Path | None = None

    if path is not None:
        resolved = Path(path)
        if not resolved.exists():
            raise ConfigError(f"Config file not found: {resolved}")
    else:
        for candidate in _SEARCH_PATHS:
            if candidate.exists():
                resolved = candidate
                break

    if resolved is None:
        # No config file found — return defaults.
        return TriageConfig()

    with open(resolved) as f:
        raw = yaml.safe_load(f) or {}

    return _parse_raw(raw)


def _parse_raw(raw: dict[str, Any]) -> TriageConfig:
    cfg = TriageConfig()

    if "provider" in raw:
        cfg.provider = _parse_provider(raw["provider"])
    if "classifier" in raw:
        cfg.classifier = _parse_classifier(raw["classifier"])
    if "routes" in raw:
        cfg.routes = _parse_routes(raw["routes"])
    if "escalation" in raw:
        cfg.escalation = _parse_escalation(raw["escalation"])
    if "secrets" in raw:
        s = raw["secrets"]
        cfg.secrets = SecretsConfig(
            backend=s.get("backend", "env"),
            keyfile_path=s.get("keyfile_path", "~/.config/email-triage/key"),
            master_key_name=s.get("master_key_name", "ET_MASTER_KEY"),
            external=s.get("external", {}) or {},
        )
    if "logging" in raw:
        lg = raw["logging"]
        cfg.logging = LoggingConfig(
            level=lg.get("level", "INFO"),
            format=lg.get("format", "json"),
            hipaa=lg.get("hipaa", False),
            file=lg.get("file"),
            retention_days=int(lg.get("retention_days", 30)),
            max_rows=int(lg.get("max_rows", 50000)),
        )
    if "persistence" in raw:
        cfg.persistence = PersistenceConfig(
            db_path=raw["persistence"].get("db_path", "./data/triage.db"),
        )
    if "tls" in raw:
        t = raw["tls"] or {}
        acme_raw = t.get("acme") or {}
        rfc_raw = (acme_raw.get("rfc2136") or {}) if isinstance(acme_raw, dict) else {}
        rfc = Rfc2136Config(
            nameserver=str(rfc_raw.get("nameserver", "")),
            nameserver_port=int(rfc_raw.get("nameserver_port", 53)),
            tsig_key_name=str(rfc_raw.get("tsig_key_name", "")),
            tsig_algorithm=str(rfc_raw.get("tsig_algorithm", "hmac-sha256")),
            tsig_secret_ref=str(rfc_raw.get("tsig_secret_ref", "acme_tsig_secret")),
            update_zone=str(rfc_raw.get("update_zone", "")),
            public_resolvers=_parse_resolver_list(
                rfc_raw.get("public_resolvers"),
                default=["8.8.8.8", "1.1.1.1", "9.9.9.9"],
            ),
            public_propagation_timeout_secs=int(
                rfc_raw.get("public_propagation_timeout_secs", 1800)
            ),
            public_propagation_interval_secs=int(
                rfc_raw.get("public_propagation_interval_secs", 15)
            ),
            public_propagation_split_horizon_wait_secs=int(
                rfc_raw.get("public_propagation_split_horizon_wait_secs", 600)
            ),
        )
        domains_raw = acme_raw.get("domains", []) if isinstance(acme_raw, dict) else []
        if isinstance(domains_raw, str):
            domains_raw = [d.strip() for d in domains_raw.split(",") if d.strip()]
        acme = AcmeConfig(
            enabled=bool(acme_raw.get("enabled", False)) if isinstance(acme_raw, dict) else False,
            directory_url=str(acme_raw.get(
                "directory_url",
                "https://acme-v02.api.letsencrypt.org/directory",
            )) if isinstance(acme_raw, dict) else
                "https://acme-v02.api.letsencrypt.org/directory",
            account_email=str(acme_raw.get("account_email", "")) if isinstance(acme_raw, dict) else "",
            domains=list(domains_raw),
            challenge=str(acme_raw.get("challenge", "dns-01")) if isinstance(acme_raw, dict) else "dns-01",
            renewal_threshold_days=int(acme_raw.get("renewal_threshold_days", 30)) if isinstance(acme_raw, dict) else 30,
            check_interval_hours=int(acme_raw.get("check_interval_hours", 24)) if isinstance(acme_raw, dict) else 24,
            dns_provider=str(acme_raw.get("dns_provider", "rfc2136")) if isinstance(acme_raw, dict) else "rfc2136",
            rfc2136=rfc,
            pre_validation_grace_secs=int(
                acme_raw.get("pre_validation_grace_secs", 30)
            ) if isinstance(acme_raw, dict) else 30,
            validation_retries=int(
                acme_raw.get("validation_retries", 5)
            ) if isinstance(acme_raw, dict) else 5,
            validation_retry_delay_secs=int(
                acme_raw.get("validation_retry_delay_secs", 60)
            ) if isinstance(acme_raw, dict) else 60,
            validation_retry_backoff=str(
                acme_raw.get("validation_retry_backoff", "exponential")
            ) if isinstance(acme_raw, dict) else "exponential",
            caa_enforce=bool(
                acme_raw.get("caa_enforce", False)
            ) if isinstance(acme_raw, dict) else False,
        )
        local_suffixes_raw = t.get("local_url_suffixes", []) or []
        local_suffixes = [
            str(s).strip() for s in local_suffixes_raw if str(s).strip()
        ] if isinstance(local_suffixes_raw, list) else []
        # #82 item 4 — operator-defined CSRF exempt path prefixes.
        # Drop entries that don't start with '/' (operator-side typo
        # like ``api/foo``) so they don't silently match nothing —
        # the config validator surfaces the rejected entries instead.
        csrf_exempt_raw = t.get("csrf_exempt_prefixes", []) or []
        csrf_exempt = (
            [str(p).strip() for p in csrf_exempt_raw
             if str(p).strip().startswith("/")]
            if isinstance(csrf_exempt_raw, list) else []
        )
        cfg.tls = TLSConfig(
            cert_dir=str(t.get("cert_dir", "")),
            enabled=bool(t.get("enabled", False)),
            acme=acme,
            csrf_enforce=bool(t.get("csrf_enforce", True)),
            csrf_exempt_prefixes=csrf_exempt,
            local_url_suffixes=local_suffixes,
        )
    if "smtp" in raw:
        sm = raw["smtp"]
        cfg.smtp = SmtpConfig(
            host=sm.get("host", ""),
            port=sm.get("port", 587),
            username=sm.get("username", ""),
            from_addr=sm.get("from_addr", ""),
            from_name=sm.get("from_name", ""),
            use_tls=sm.get("use_tls", True),
        )
    if "push" in raw:
        p = raw["push"]
        cfg.push = PushConfig(
            listen_port=p.get("listen_port", 8080),
            public_url=p.get("public_url", ""),
            gmail_topic_name=p.get("gmail_topic_name", ""),
            gmail_subscription_sa_email=p.get("gmail_subscription_sa_email", ""),
            gmail_audience=p.get("gmail_audience", ""),
            openclaw_webhook_enabled=p.get("openclaw_webhook_enabled", True),
            openclaw_rate_limit_per_minute=p.get("openclaw_rate_limit_per_minute", 60),
            bulk_max_batch_size=p.get("bulk_max_batch_size", 100),
            office365_subscription_renewal_window_hours=int(
                p.get("office365_subscription_renewal_window_hours", 24)
            ),
        )
    if "webhooks" in raw:
        cfg.webhooks = _parse_webhooks(raw["webhooks"])

    if "ingestion" in raw:
        i = raw["ingestion"] or {}
        default_iv = int(i.get("default_poll_interval_minutes", 60))
        push_iv = int(i.get("push_poll_interval_min", 20))
        poll_iv = int(i.get("poll_poll_interval_min", 10))
        cfg.ingestion = IngestionConfig(
            default_poll_interval_minutes=default_iv,
            push_poll_interval_min=push_iv,
            poll_poll_interval_min=poll_iv,
        )



    if "health_email" in raw:
        h = raw["health_email"] or {}
        recips = h.get("recipients", []) or []
        if isinstance(recips, str):
            recips = [r.strip() for r in recips.split(",") if r.strip()]
        cfg.health_email = HealthEmailConfig(
            enabled=bool(h.get("enabled", False)),
            recipients=list(recips),
            send_at=str(h.get("send_at", "07:15")),
            include_health=bool(h.get("include_health", True)),
            include_watchers=bool(h.get("include_watchers", True)),
            include_triage=bool(h.get("include_triage", True)),
            include_errors=bool(h.get("include_errors", True)),
            include_hipaa_events=bool(h.get("include_hipaa_events", True)),
            include_api_key_events=bool(h.get("include_api_key_events", True)),
            include_pubsub=bool(h.get("include_pubsub", True)),
            include_update_available=bool(
                h.get("include_update_available", True),
            ),
            quiet_mode=bool(h.get("quiet_mode", False)),
            error_rate_threshold_pct=int(h.get("error_rate_threshold_pct", 0)),
        )

    # CR-2c — canonical admin-notification destination. Parsed
    # independently from ``health_email`` so an operator can migrate
    # incrementally. ``daily_health.resolve_admin_recipients`` reads
    # this first and falls back to ``health_email.recipients`` with a
    # deprecation warning when this list is empty.
    if "admin_email" in raw:
        a = raw["admin_email"] or {}
        a_recips = a.get("recipients", []) or []
        if isinstance(a_recips, str):
            a_recips = [r.strip() for r in a_recips.split(",") if r.strip()]
        cfg.admin_email = AdminEmailConfig(
            recipients=list(a_recips),
            release_check_url=str(
                a.get(
                    "release_check_url",
                    AdminEmailConfig().release_check_url,
                ) or AdminEmailConfig().release_check_url,
            ),
        )

    if "summary_email" in raw:
        s = raw["summary_email"] or {}
        cfg.summary_email = SummaryEmailConfig(
            signature=str(s.get(
                "signature",
                "Sent by your email-triage {category} Digest 🗞️",
            )),
        )

    if "embedding" in raw:
        e = raw["embedding"] or {}
        fb_raw = e.get("fallback") or {}
        fb = EmbeddingFallbackConfig(
            backend=str(
                fb_raw.get("backend", "") or "",
            ).strip().lower(),
            model_name=str(fb_raw.get("model_name", "") or "").strip(),
            ollama_url=str(fb_raw.get("ollama_url", "") or "").strip(),
        )
        cfg.embedding = EmbeddingConfig(
            backend=str(e.get("backend", "") or "").strip().lower(),
            model_name=str(e.get("model_name", "") or "").strip(),
            ollama_url=str(
                e.get("ollama_url", "") or "http://localhost:11434"
            ),
            fallback=fb,
        )

    # #151 — optional Redis-backed classification cache.
    # Default empty URL = OFF. Operator opts in via /admin/integrations.
    if "redis_cache" in raw:
        rc = raw["redis_cache"] or {}
        # Clamp via the cache module's helper so YAML + admin-form
        # paths share the same [3600, 7_776_000] window. Import is
        # lazy to keep ``email_triage.config`` independent of the
        # cache module's import order.
        from email_triage.cache.classification import clamp_ttl_secs
        # New 2026-05-13 cache tuning knobs. Defaults sane; YAML
        # round-trips when operator changes them via /config?tab=ai_backends.
        raw_cap = rc.get("inner_cap_per_sender", 250)
        try:
            cap_int = max(1, min(10000, int(raw_cap)))
        except (TypeError, ValueError):
            cap_int = 250
        raw_strategy = str(
            rc.get("hint_strategy", "top_k_with_freq") or "top_k_with_freq",
        ).strip().lower()
        if raw_strategy not in ("top_k_with_freq", "top_1_dominant"):
            raw_strategy = "top_k_with_freq"
        raw_thresh = rc.get("dominant_threshold_pct", 70)
        try:
            thresh_int = max(50, min(100, int(raw_thresh)))
        except (TypeError, ValueError):
            thresh_int = 70
        cfg.redis_cache = RedisCacheConfig(
            url=str(rc.get("url", "") or "").strip(),
            ttl_secs=clamp_ttl_secs(rc.get("ttl_secs")),
            inner_cap_per_sender=cap_int,
            hint_strategy=raw_strategy,
            dominant_threshold_pct=thresh_int,
        )

    # #149 Bundle C — LLM maintenance windows. List of dicts; bad
    # entries silently skipped here (the runtime parser logs WARNING
    # — kept the YAML loader strict-but-graceful so a typo in one
    # entry doesn't block startup with a hard ConfigError).
    raw_windows = raw.get("llm_maintenance_windows")
    if isinstance(raw_windows, list):
        out: list[LLMMaintenanceWindow] = []
        for item in raw_windows:
            if not isinstance(item, dict):
                continue
            try:
                w = LLMMaintenanceWindow(
                    host=str(item.get("host", "") or "").strip(),
                    cron=str(item.get("cron", "") or "").strip(),
                    duration_minutes=int(item.get("duration_minutes", 0) or 0),
                    backend=str(item.get("backend", "") or "").strip(),
                )
            except (TypeError, ValueError):
                continue
            if w.cron and w.backend and w.duration_minutes > 0:
                out.append(w)
        cfg.llm_maintenance_windows = out

    # Dev-mode was removed in v0.x (2026-05-16). The legacy ``_dev:``
    # YAML block is rejected outright with a migration hint pointing
    # at the supported replacements. No replacement YAML section
    # exists — auth shortcuts now live in /admin/dev-keys (per-user
    # keypair, TTL-bound, audit-logged) or /profile/hardware-keys
    # (WebAuthn); DEBUG logging is set via standard Python log config
    # or LOG_LEVEL.
    if "_dev" in raw:
        raise ConfigError(
            "dev-mode was removed in v0.x; auth shortcuts are "
            "configured via /admin/dev-keys (per-user keypair, "
            "TTL-bound, audit-logged) or /profile/hardware-keys "
            "(WebAuthn) — no replacement YAML section needed. "
            "Remove the `_dev:` block from your config."
        )

    if "webauthn" in raw:
        w = raw["webauthn"] or {}
        cfg.webauthn = WebAuthnConfig(
            rp_id=str(w.get("rp_id", "")),
            rp_name=str(w.get("rp_name", "Email Triage")),
            origin=str(w.get("origin", "")),
            require_user_verification_for_admin=bool(
                w.get("require_user_verification_for_admin", False)
            ),
        )

    if "auth" in raw:
        a = raw["auth"] or {}
        cfg.auth = AuthConfig(
            session_ttl_secs=int(a.get("session_ttl_secs", 86400)),
            # Clamp to the hard ceiling at LOAD time so a hand-edited
            # YAML can't silently raise the HIPAA cap.
            hipaa_session_ttl_secs=min(
                int(a.get("hipaa_session_ttl_secs", 900)),
                AuthConfig.HIPAA_TTL_HARD_CEILING_SECS,
            ),
            # #92 login rate-limit tunables. Clamped to sane ranges
            # at LOAD so a typo'd YAML can't silently disable the
            # guard (max < 0) or pin a 30-day window.
            login_per_email_max=max(
                0, int(a.get("login_per_email_max", 10)),
            ),
            login_per_email_window_secs=max(
                60, min(86400, int(a.get("login_per_email_window_secs", 600))),
            ),
            login_per_ip_max=max(
                0, int(a.get("login_per_ip_max", 30)),
            ),
            login_per_ip_window_secs=max(
                60, min(86400, int(a.get("login_per_ip_window_secs", 600))),
            ),
        )

    return cfg


def validate_config(config: TriageConfig) -> list[str]:
    """Return a list of validation warnings/errors. Empty = valid."""
    issues: list[str] = []

    valid_backends = {"ollama", "openai", "gemini"}
    if config.classifier.backend not in valid_backends:
        issues.append(
            f"Unknown classifier backend '{config.classifier.backend}'. "
            f"Expected one of: {', '.join(sorted(valid_backends))}"
        )

    valid_providers = {"gmail_api", "imap", "office365"}
    if config.provider.type not in valid_providers:
        issues.append(
            f"Unknown provider type '{config.provider.type}'. "
            f"Expected one of: {', '.join(sorted(valid_providers))}"
        )

    valid_secrets = {"keyring", "keyfile", "container", "env"}
    if config.secrets.backend not in valid_secrets:
        issues.append(
            f"Unknown secrets backend '{config.secrets.backend}'. "
            f"Expected one of: {', '.join(sorted(valid_secrets))}"
        )

    if not config.classifier.categories:
        issues.append("No classification categories defined.")

    for cat, route in config.routes.items():
        if cat not in config.classifier.categories and cat != "_default":
            issues.append(
                f"Route '{cat}' does not match any defined category."
            )

    return issues


def get_max_mailboxes_per_account(config: TriageConfig) -> int:
    """Read the per-account mailbox cap from the IMAP provider config.

    Kept as a plain dict lookup (not a dataclass field) to avoid breaking
    any caller that pokes ``config.provider.imap[...]`` directly.
    """
    try:
        raw = int(config.provider.imap.get(
            "max_mailboxes_per_account",
            DEFAULT_MAX_MAILBOXES_PER_ACCOUNT,
        ))
    except (TypeError, ValueError):
        return DEFAULT_MAX_MAILBOXES_PER_ACCOUNT
    # Bound defensively: 1 <= cap <= 20. Below 1 is pointless; above 20
    # exceeds every commercial IMAP server's per-user connection limit.
    return max(1, min(raw, 20))
