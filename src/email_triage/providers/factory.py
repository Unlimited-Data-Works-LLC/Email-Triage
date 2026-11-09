"""Provider factory — build EmailProvider instances from DB account records.

Lifted from ``web/routers/ui.py`` so non-UI consumers
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

from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Per-account MSAL token-cache path — SSOT (run18 #1 / census )
# ---------------------------------------------------------------------------

def msal_cache_path_for_account(account_id: Any) -> Path:
    """SSOT for the per-account Office 365 MSAL token-cache file path.

    Returns ``./data/msal_cache_<account_id>.json`` — the on-disk file that
    persists per-account O365 OAuth access+refresh tokens in PLAINTEXT
    (; written by ``providers/office365.py:_save_cache`` at 0o600 but
    UNENCRYPTED, OUTSIDE the SQLCipher DB).

    EVERY create/write site AND the §164.310(d)(2)(i) media-disposal unlink in
    ``db/accounts.py:purge_account_local_state`` MUST derive the path from HERE
    so the writer and the purge can never disagree. A forked literal is exactly
    how the run18 #1 disposal gap arose: the cache was written per-account
    (``factory.py`` / ``web/routers/ui/_shared.py``) while the purge unlinked
    nothing, so the MORE-exposed plaintext token copy SURVIVED the account
    deletion chartered to erase it (and stayed redeemable — the install-level
    client_secret persists).

    The path is preserved EXACTLY (``./data/`` dir, ``msal_cache_<id>.json``
    name) — this only centralizes the literal, it does NOT move the file.
    """
    return Path(f"./data/msal_cache_{account_id}.json")


def msal_cache_path_for_cli(username: str) -> Path:
    """N-209 R23 (2026-07-02): SSOT for the CLI-scoped MSAL token-cache path.

    The CLI is single-account (per-install YAML config); there is no
    `account_id` at bootstrap, so `msal_cache_path_for_account` doesn't apply.
    Derive from the (sanitised) O365 username instead so a second CLI
    invocation on a different account gets its own cache file — no cross-
    account pool.

    **N-307 R30 (tranche  batch B DA fix-forward on N-209b)**: DA panel
    on `15ae272b` found the pre-fix derivation was
    prefix-truncate-then-collapse-on-empty, which BROKE the
    §164.310(d)(2)(i) cross-account collision-resistance property this
    SSOT was landed to close. Verified defect: two long O365 UPNs
    (`alice.smith.contractor.northeast.tenant-a.com` and
    `alice.smith.contractor.northeast.tenant-b.com`) collapsed to the
    same 40-char alnum prefix → SAME MSAL cache file → shared plaintext
    OAuth refresh-token pool across accounts.

    Fix:

    1. **sha256(username)[:16] SUFFIX for collision-resistance** — the
       derived stem is ``<safe_stem_prefix>_<hash16>``. Prefix stays
       for operator readability; the 16-hex-char (64-bit) hash suffix
       is the collision-resistant identity. Two full UPNs whose first
       40 alnum chars match now still get distinct paths.
    2. **Fail-CLOSED on empty/whitespace-only username** — raises
       ``ValueError`` rather than silently sharing a ``cli_default``
       bucket. Unconfigured CLI should not get an MSAL cache at all
       until it's configured.

    Returns ``./data/msal_cache_cli_<safe_stem>_<hash16>.json``.

    This exists as a dedicated SSOT sibling (rather than an f-string at
    the CLI callsite) so the ``test_no_forked_per_account_msal_cache_
    literal`` pin stays STRICT — every path derives from the ONE module.
    """
    import hashlib

    stripped = (username or "").strip()
    if not stripped:
        raise ValueError(
            "msal_cache_path_for_cli: username is empty/whitespace-only. "
            "Configure the CLI's O365 username before invoking MSAL "
            "auth — a shared 'cli_default' cache would be a "
            "§164.310(d)(2)(i) cross-account credential-pool defect."
        )
    safe_stem = "".join(c if c.isalnum() else "_" for c in stripped)[:40]
    hash16 = hashlib.sha256(stripped.encode("utf-8")).hexdigest()[:16]
    return Path(f"./data/msal_cache_cli_{safe_stem}_{hash16}.json")


def dispose_msal_cache_for_account(account_id: Any) -> bool:
    """N-236 R23 (2026-07-02): SSOT dispose actuator for the per-account
    MSAL cache. Deletes the plaintext OAuth refresh token from disk so a
    HIPAA account-deletion sweep closes §164.310(d)(2)(i) at-rest cleanup.

    Idempotent. Returns True if a file was deleted, False if absent.
    Raises OSError on a real unlink failure (perms/FS) — callers MUST
    treat that as fail-CLOSED (do not report account fully cleaned) per
    the pattern at `db/accounts.py:1252`.
    """
    p = msal_cache_path_for_account(account_id)
    existed = p.exists()
    p.unlink(missing_ok=True)
    return existed


def dispose_msal_cache_for_cli(username: str) -> bool:
    """N-236 R23 (2026-07-02): SSOT dispose actuator for the CLI-scoped
    MSAL cache. Complements `msal_cache_path_for_cli` — pre-N-236 the
    CLI cache path was READ-ONLY (writer exists, dispose absent), so a
    plaintext OAuth refresh_token survived any operator-triggered
    "clear my auth" flow (§164.310(d)(2)(i) surface per R23 backlog).

    Idempotent. Returns True if a file was deleted, False if absent.
    Raises OSError on a real unlink failure — callers MUST treat that
    as fail-CLOSED.

    N-356 R31 (2026-07-05 trust-repair fix-forward per PHASE2 tranche
     hipaa-sme + db-sme + the backlog  = TASK ): also unlink
    the pre-N-307 OLD-shape file `./data/msal_cache_cli_<username>.json`
    when it exists. Before N-307 (2026-07-03 tranche ) the CLI cache
    was named after the raw username with no hash suffix; N-307
    switched to `msal_cache_cli_<safe_stem>_<hash16>.json` to eliminate
    a cross-account collision class (§164.310(d)(2)(i)) but left the
    OLD-shape files orphaned on any install upgraded across N-307. An
    operator's "clear my auth" flow silently missed those files → a
    plaintext OAuth refresh_token could survive the dispose. Now both
    shapes clean up in one call. Return True if EITHER file was
    deleted (so callers get an accurate "yes I removed something"
    signal). OLD-shape unlink is best-effort per-file: an OSError on
    the OLD path is still fail-CLOSED (raises), matching the NEW-path
    contract.
    """
    # N-356: attempt OLD-shape cleanup FIRST (best-effort, one file).
    # Skip for blank usernames — the OLD shape used the raw username, so
    # a blank one would target the same `msal_cache_cli_.json` sentinel
    # that N-307's collision class was landed to close.
    old_existed = False
    _u = (username or "").strip()
    if _u:
        old = Path(f"./data/msal_cache_cli_{_u}.json")
        old_existed = old.exists()
        if old_existed:
            old.unlink(missing_ok=True)
    p = msal_cache_path_for_cli(username)
    new_existed = p.exists()
    p.unlink(missing_ok=True)
    return old_existed or new_existed


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


def _read_account_secret(secrets, sk, *, account_id, ptype) -> str:
    """Read a per-account credential, failing CLOSED and LEGIBLY on an
    unreadable secret store (A5 / SME finding DA-1).

    A blank ``sk`` (no secret configured) returns "" as before. But a
    secret that EXISTS and won't decrypt (corrupt row / install-wide
    master-key mismatch) used to surface as an opaque ``SecretsDecryptError``
    traceback out of this hot path — provider construction sits on the
    mailbox-poll loop. Log the true, account-scoped cause first, then
    re-raise: the build still fails closed (no provider with a blank
    credential), but the operator sees WHY in the watcher log.
    """
    if not sk:
        return ""
    from email_triage.secrets import SecretsDecryptError, read_secret
    try:
        return read_secret(secrets, sk) or ""
    except SecretsDecryptError:
        from email_triage.triage_logging import get_logger
        get_logger("providers.factory").error(
            "cannot build provider — stored credential unreadable (corrupt "
            "row / master-key mismatch); check the secrets master key",
            ptype=ptype, account_id=account_id,
        )
        raise


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


def hydrate_and_register_install_oauth(config, secrets, conn=None) -> None:
    """MIGRATE (one-shot, pre-B1) -> HYDRATE -> REGISTER the install-level Google
    + Office365 OAuth creds. **THE ONE place this full wiring lives.**

    ``build_provider`` reads the install OAuth creds from this factory's
    module-level singletons (not a threaded param), so a ``gmail_api``/
    ``office365`` account built BEFORE this runs gets an empty ``client_id`` ->
    ``GmailAuthError(400, "client_id not configured")``. The server boot calls
    this in its lifespan; **every CLI command that builds an account provider
    (via ``build_provider`` / ``_create_provider_from_account``) MUST call it
    too**, after secrets bootstrap.

    Three steps, matching what the boot did inline:
      1. ``conn`` given -> run the one-shot per-account -> install OAuth cred
         MIGRATIONS (pre-B1 installs kept creds per-account). WITHOUT this, a
         fresh / never-web-booted install (the portable-reuse target) or an
         un-migrated O365 account reads empty install keys in step 2 (N-130
         gap #3, DA MUST-FIX). ``conn=None`` (a unit test with pre-seeded
         secrets) skips the migration.
      2. Hydrate the 7 install OAuth keys from the secrets store into ``config``.
      3. Register google + office365 + ingestion with the factory singletons.

    (N-129/N-130: the CLI mine paths skipped the boot's setup -> live failures
    mining a Gmail account; sibling CLI-vs-boot divergences. Enforced by
    ``tests/test_cli_provider_oauth_register_pin.py``.)
    """
    from email_triage.secrets import read_secret
    from email_triage.web.oauth_secret_keys import (
        GOOGLE_OAUTH_WEB_CLIENT_ID, GOOGLE_OAUTH_WEB_CLIENT_SECRET,
        GOOGLE_OAUTH_DESKTOP_CLIENT_ID, GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET,
        O365_OAUTH_TENANT_ID, O365_OAUTH_CLIENT_ID, O365_OAUTH_CLIENT_SECRET,
        INSTALL_OAUTH_FIELDS,  # N-181 R20_5 hydrate+save SSOT tuple
    )

    # Step 1 — one-shot per-account -> install-level OAuth cred migrations
    # (pre-B1). Seeds the install keys the hydrate below reads. conn=None skips.
    if conn is not None:
        from email_triage.web.db import (
            migrate_oauth_creds_to_install_level,
            migrate_o365_creds_to_install_level,
        )
        from email_triage.triage_logging import get_logger
        _log = get_logger("providers.factory")
        # Punch 922: the secrets are stored INSIDE the migration, before any
        # scrub UPDATE (DbSecrets.set commits this same conn). A secrets.set
        # failure raises before anything is scrubbed, and the per-account
        # creds survive; the next boot fills only the slots still empty.
        gmail_migrated: list[str] = []

        def _store_gmail(pair: tuple[str, str]) -> None:
            cid, csec = pair
            # Per-slot fill (punch 922 hipaa-sme MUST-1): a run that stored
            # the ID and then failed on the SECRET must refill the SECRET on
            # the next boot. Fill the SECRET only when the stored ID is this
            # pair's ID, so a secret is never paired with another client.
            have_id = read_secret(secrets, GOOGLE_OAUTH_WEB_CLIENT_ID)
            if have_id and have_id != cid:
                return
            if not have_id:
                # Filling the ID: always write the SECRET too, so this ID is
                # never left paired with a secret from an outside write. SECRET
                # first: the ID is the retry guard, so a failure between the
                # two leaves the ID empty and the next boot rewrites both.
                secrets.set(GOOGLE_OAUTH_WEB_CLIENT_SECRET, csec)
                secrets.set(GOOGLE_OAUTH_WEB_CLIENT_ID, cid)
            elif not read_secret(secrets, GOOGLE_OAUTH_WEB_CLIENT_SECRET):
                secrets.set(GOOGLE_OAUTH_WEB_CLIENT_SECRET, csec)
            if not have_id:
                gmail_migrated.append(cid)

        def _store_o365(triple: tuple[str, str, str]) -> None:
            tid, cid, csec = triple
            if tid and not read_secret(secrets, O365_OAUTH_TENANT_ID):
                secrets.set(O365_OAUTH_TENANT_ID, tid)
            if cid and not read_secret(secrets, O365_OAUTH_CLIENT_ID):
                secrets.set(O365_OAUTH_CLIENT_ID, cid)
            if csec and not read_secret(secrets, O365_OAUTH_CLIENT_SECRET):
                secrets.set(O365_OAUTH_CLIENT_SECRET, csec)

        migrate_oauth_creds_to_install_level(conn, persist=_store_gmail)
        if gmail_migrated:  # logged only after the migration committed
            _log.warning(
                "Migrated per-account Gmail OAuth creds to install-level "
                "(Web-app slot). Verify at /config — retype in the Desktop "
                "slot if that's the flow you intended.",
            )
        o365_found = migrate_o365_creds_to_install_level(
            conn, secrets, persist=_store_o365,
        )
        if o365_found is not None:
            _log.warning(
                "Migrated per-account Office 365 OAuth creds to install-level. "
                "Verify at /config — if accounts had different Azure tenants, "
                "only one was kept and the others will need their probe rerun "
                "after editing the install tenant.",
            )

    # Step 2 — hydrate every install OAuth field via INSTALL_OAUTH_FIELDS SSOT
    # (N-181 R20_5): iterate the paired tuple instead of a hand-list. A new
    # OAuth key added to the tuple is auto-hydrated here; the exact-set pin
    # (test_install_oauth_fields_ssot_pin.py) fails-red if save.py doesn't
    # also route it through _secret_write — kills the N-130-recurrence shape.
    for key_const, section, attr, _form_field, _kind in INSTALL_OAUTH_FIELDS:
        # db-sme N-181 must-fix (a): hasattr guard — a typo in the tuple
        # would otherwise silently create a stray attribute on the sub-config
        # object instead of a loud AttributeError from the hand-list shape.
        sub = getattr(config, section)
        if not hasattr(sub, attr):
            raise AttributeError(
                f"INSTALL_OAUTH_FIELDS entry ({section}, {attr}) — "
                f"config.{section} has no attribute {attr!r} (SSOT tuple drift)"
            )
        setattr(sub, attr, read_secret(secrets, key_const) or "")
    set_install_google_oauth(config.google_oauth)
    set_install_office365_oauth(config.office365_oauth)
    set_install_ingestion_config(config.ingestion)


def get_install_ingestion_config():
    """Read accessor for the install-level IngestionConfig."""
    return _install_ingestion_config


# ---------------------------------------------------------------------------
# Secret-key derivation
# ---------------------------------------------------------------------------

def secret_key_for_account(account_id: int, provider_type: str) -> str | None:
    """Return the secrets-store key name for an account's password/secret.

    DELEGATES to the table-driven SSOT
    ``providers.traits.secret_key_for_account`` (the ``TRAITS`` registry's
    ``secret_key_template``). census run15 #7 converged the formerly-hardcoded
    copy that lived here onto it: a hardcoded fork is a CIDI hazard — add a new
    provider to ``TRAITS`` (the store/read side) but forget the factory's
    hardcoded branch, or change a key name in one and not the other, and the
    factory derives a DIFFERENT key from the store side → a secret saved under
    one key and read under another → fail-CLOSED credential loss for that
    provider class. One derivation now, in ``TRAITS``.

    Imported function-locally so the factory module stays importable without
    eagerly pulling the traits registry (traits imports nothing from the
    factory, so there is no cycle either direction; the lazy import is
    belt-and-suspenders for the factory's optional-dep import-tolerance
    discipline). The ``_secret_key_for_account`` helper in
    ``web/routers/ui/_shared.py`` also delegates to the same traits SSOT.
    """
    from email_triage.providers.traits import (
        secret_key_for_account as _traits_secret_key,
    )
    return _traits_secret_key(account_id, provider_type)


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
        from email_triage.db.accounts import account_email
        from email_triage.providers.imap import ImapProvider
        from email_triage.web.db import _account_mailboxes
        sk = secret_key_for_account(acct["id"], ptype)
        password = _read_account_secret(
            secrets, sk, account_id=acct["id"], ptype=ptype,
        )
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
            email_address=account_email(acct),
            # 2026-05-13 — operator override for the Drafts folder
            # (account form field). Bypasses the SPECIAL-USE / name-
            # match probe when set. Empty → discovery path runs.
            drafts_folder=cfg.get("drafts_folder", ""),
            cert_check=cfg.get("cert_check"),
            cert_enforce=cfg.get("cert_enforce"),
        )
    if ptype == "gmail_api":
        from email_triage.providers.gmail_api import GmailApiProvider
        sk = secret_key_for_account(acct["id"], ptype)
        refresh_token = _read_account_secret(
            secrets, sk, account_id=acct["id"], ptype=ptype,
        )
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
        #  — give every O365 account its OWN MSAL token-cache file.
        # The provider's default is a single shared ``msal_cache.json``;
        # with two O365 accounts the second account's silent-acquire
        # would pick up the first's cached tokens. Key the cache file by
        # account id, and pass the mailbox address so the provider
        # selects the right cached MSAL account by username.
        token_cache_path = str(msal_cache_path_for_account(acct["id"]))
        return Office365Provider(
            client_id=client_id,
            tenant_id=tenant_id or "common",
            client_secret=client_secret or "",
            token_cache_path=token_cache_path,
            username=cfg.get("account", ""),
        )
    raise ValueError(f"Unknown provider type: {ptype}")
