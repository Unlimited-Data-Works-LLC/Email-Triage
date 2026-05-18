"""Provider factory — build EmailProvider instances from DB account records.

Lifted from ``web/routers/ui.py`` (#138.1) so non-UI consumers
(``cli.py``, ``web/app.py``, ``web/triage_runner.py``,
``web/triage_runner_bulk.py``, ``web/o365_renewer.py``) don't have to
reach into the UI router for what is fundamentally a domain-level
concern.

Install-level singletons (``_install_google_oauth``,
``_install_ingestion_config``) live here too — populated at app
startup from ``web/app.py`` lifespan, read by helper functions
without threading the config object through every call site.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Install-level singletons (populated at app startup)
# ---------------------------------------------------------------------------

# Install-level Google OAuth creds, populated at app startup from the
# secrets store (see web/app.py lifespan). Module-level because the
# provider factory has many callers — request-bound, background-loop,
# CLI — and threading a config param through all of them is churn.
# The factory still accepts an explicit override for tests.
_install_google_oauth: object | None = None


def set_install_google_oauth(google_oauth) -> None:
    """Register the install-level GoogleOAuthConfig for factory use."""
    global _install_google_oauth
    _install_google_oauth = google_oauth


def _resolve_google_oauth(override=None):
    """Prefer explicit override, else fall back to install-level singleton."""
    return override if override is not None else _install_google_oauth


# Install-level Office 365 OAuth creds. Same shape + reason as the
# Google singleton above. Populated at startup from the secrets store
# via web/app.py lifespan; consumed by the office365 + office365_calendar
# factory branches + the per-account template's amber-chip check.
_install_office365_oauth: object | None = None


def set_install_office365_oauth(office365_oauth) -> None:
    """Register the install-level Office365OAuthConfig for factory use."""
    global _install_office365_oauth
    _install_office365_oauth = office365_oauth


def _resolve_office365_oauth(override=None):
    """Prefer explicit override, else fall back to install-level singleton."""
    return override if override is not None else _install_office365_oauth


# Install-level IngestionConfig, set at startup (B3). Same pattern as
# _install_google_oauth — read by helper functions without threading
# config through every call site.
_install_ingestion_config: object | None = None


def set_install_ingestion_config(ingestion) -> None:
    """Register the install-level IngestionConfig for helper use."""
    global _install_ingestion_config
    _install_ingestion_config = ingestion


def get_install_ingestion_config():
    """Read accessor for the install-level IngestionConfig."""
    return _install_ingestion_config


# ---------------------------------------------------------------------------
# Secret-key derivation
# ---------------------------------------------------------------------------

def secret_key_for_account(account_id: int, provider_type: str) -> str | None:
    """Return the secrets-store key name for an account's password/secret.

    Mirrors the ``ProviderTraits.secret_key_template`` data — kept here
    too so the factory can use it without crossing into the traits
    module (which itself imports nothing from the factory). The
    ``_secret_key_for_account`` helper in ``web/routers/ui.py`` re-
    exports this for backwards compat with existing call sites.
    """
    if provider_type == "imap":
        return f"ACCOUNT_{account_id}_IMAP_PASSWORD"
    if provider_type == "office365":
        return f"ACCOUNT_{account_id}_O365_SECRET"
    if provider_type == "gmail_api":
        return f"ACCOUNT_{account_id}_GMAIL_REFRESH_TOKEN"
    return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_provider(
    acct: dict,
    secrets,
    google_oauth=None,
    office365_oauth=None,
    *,
    mailbox_override: str | None = None,
):
    """Instantiate an EmailProvider from a DB account record + secrets.

    For ``gmail_api`` accounts, OAuth client credentials come from the
    install-level GoogleOAuthConfig (B1 — moved out of per-account
    config). Prefers the Web-app pair; falls back to Desktop when Web
    is unset.

    ``mailbox_override`` (IMAP only): pin the connection to a specific
    folder instead of the account's default. Used by the per-mailbox
    watcher so one account can have N concurrent IDLE connections, one
    per folder. Gmail/Office 365 don't need this — their APIs address
    folders per-request.
    """
    ptype = acct["provider_type"]
    cfg = acct["config"] or {}

    if ptype == "imap":
        from email_triage.providers.imap import ImapProvider
        from email_triage.web.db import _account_mailboxes
        sk = secret_key_for_account(acct["id"], ptype)
        password = secrets.get(sk) if sk else ""
        if mailbox_override:
            mb = mailbox_override
        else:
            # Prefer the first entry from the canonical ``mailboxes``
            # list; fall back to legacy ``mailbox`` via the helper.
            mb = _account_mailboxes(cfg)[0]
        return ImapProvider(
            host=cfg.get("host", "localhost"),
            port=cfg.get("port", 993),
            username=cfg.get("username", ""),
            password=password or "",
            use_ssl=cfg.get("use_ssl", True),
            mailbox=mb,
            # 2026-05-13 — pass the separate email_address field
            # (introduced commit 6d6e7b9) so create_draft +
            # send_email default the From header to the operator's
            # actual sending address rather than the IMAP LOGIN.
            email_address=cfg.get("email_address", ""),
            # 2026-05-13 — operator override for the Drafts folder
            # (account form field). Bypasses the SPECIAL-USE / name-
            # match probe when set. Empty → discovery path runs.
            drafts_folder=cfg.get("drafts_folder", ""),
        )
    if ptype == "gmail_api":
        from email_triage.providers.gmail_api import GmailApiProvider
        sk = secret_key_for_account(acct["id"], ptype)
        refresh_token = secrets.get(sk) if sk else ""
        go = _resolve_google_oauth(google_oauth)
        client_id = go.web_client_id if go else ""
        client_secret = go.web_client_secret if go else ""
        if not client_id and go:
            client_id = go.desktop_client_id
            client_secret = go.desktop_client_secret
        return GmailApiProvider(
            account=cfg.get("account", ""),
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token or "",
        )
    if ptype == "office365":
        from email_triage.providers.office365 import Office365Provider
        # Install-level OAuth client (Phase A/C of the 2026-05-10
        # per-account → install-level lift). Per-account is_personal_msa
        # flag routes tenant resolution to "common" (personal Microsoft
        # account) or the install's configured org tenant.
        install = _resolve_office365_oauth(office365_oauth)
        client_id = install.client_id if install else ""
        client_secret = install.client_secret if install else ""
        is_personal = bool(cfg.get("is_personal_msa", False))
        tenant_id = "common" if is_personal else (install.tenant_id if install else "")
        return Office365Provider(
            client_id=client_id,
            tenant_id=tenant_id or "common",
            client_secret=client_secret or "",
        )
    raise ValueError(f"Unknown provider type: {ptype}")
