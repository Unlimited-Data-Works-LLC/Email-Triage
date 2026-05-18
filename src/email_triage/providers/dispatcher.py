"""ProviderDispatcher registry — functional-dispatch sibling of
:mod:`email_triage.providers.traits` (#138 phase 2).

``traits.py`` carries STATIC per-provider metadata (strings, flags,
template literals) — fields the call site reads. ``dispatcher.py``
carries CALLABLE per-provider behaviour — methods the call site
INVOKES. Both registries are keyed on the same ``provider_type``
string (``imap`` / ``gmail_api`` / ``office365``) and a new ptype
shows up in both places when added.

Why two registries instead of one fat dataclass:

* The data registry can be loaded eagerly at import time — it holds
  cheap strings + flags. The functional registry MUST lazy-import
  the heavy provider modules (``imap.py``, ``gmail_api.py``,
  ``office365.py`` each pull optional dependencies). Splitting
  preserves the lazy-import discipline that lets the package start
  up even when ``msal`` / ``aioimaplib`` / etc. aren't installed.
* The data registry is consumed in pure-Python contexts (templates,
  CLI flags, setting-key derivation). The functional registry is
  consumed in event-loop contexts (push wiring, poll dispatch,
  test connection). Mixing them forces every consumer through the
  heavier surface.

Migration target — the 5 functional-dispatch ``if ptype ==`` switch
sites that survived Bundle G:

* ``web/app.py`` push wiring (``WatcherManager.start``)
* ``web/app.py`` unified poll dispatch (``_run_unified_poll_tick``)
* ``web/db.py`` push_enabled inference from settings/state
* ``web/routers/ui.py`` ``_test_account_connection`` connection probe
* ``web/routers/ui.py`` post-create auto-start-watch flow

Single-branch ``if ptype == "imap"`` GUARDS (the cap check, the
mailbox-list bounce condition) are NOT migrated — they are not
multi-branch dispatch and don't pay the dispatcher tax.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

logger = logging.getLogger("email_triage.providers.dispatcher")


# ---------------------------------------------------------------------------
# Dataclass shape
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderDispatch:
    """Per-provider callable behaviour.

    All fields are callables (sync or async) — invoking them from a
    call site replaces the ``if ptype == ...:`` switch. Each callable
    is responsible for its own lazy imports of the heavy provider
    modules; the registry itself MUST NOT import them at module load.

    Fields:
        poll_once:
            ``async (app, acct) -> None``. Single-shot poll tick for
            this account. Implementations enqueue onto ``push_queue``
            (Gmail), call ``provider.poll_once`` per mailbox (IMAP),
            or no-op (O365 — Graph subscriptions not yet wired).

        start_push:
            ``async (manager, account_id, acct) -> str``. Arm the
            push delivery mechanism for this account; returns the
            human-readable status string the WatcherManager surfaces.
            IMAP delegates to ``manager._start_imap_push``; Gmail
            records intent in ``settings.watch:<id>``; O365 records
            "not yet implemented".

        infer_push_enabled:
            ``(conn, account_id, default) -> bool``. Read DB state
            (settings ``watch:<id>`` row for IMAP, ``gmail_watches``
            row for Gmail) and infer whether push is currently
            armed. Used by ``hydrate_account_config`` when
            ``push_enabled`` is missing from ``config_json``.

        test_connection:
            ``async (acct, secrets) -> tuple[bool, str]``. Run an
            in-place connection probe and return ``(ok, msg_html)``
            for the inline test-result fragment. IMAP opens an
            ``imaplib.IMAP4_SSL`` and lists INBOX; Gmail lists
            labels via ``GmailApiProvider``; O365 returns the
            "save first, run CLI" deferral message.

        post_create_start_watch:
            ``async (manager, request, acct, secrets) -> tuple[str, str]``.
            Returns ``(success_msg, error_msg)`` from the
            "Start watching for new mail" checkbox flow on the add-
            account form. IMAP runs a connection test then calls
            ``manager.start``; Gmail surfaces the poll-mode
            confirmation; O365 returns empty (device-code auth needed
            first).
    """

    ptype: str
    poll_once: Callable[..., Awaitable[None]]
    start_push: Callable[..., Awaitable[str]]
    infer_push_enabled: Callable[..., bool]
    test_connection: Callable[..., Awaitable[tuple[bool, str]]]
    post_create_start_watch: Callable[..., Awaitable[tuple[str, str]]]


# ---------------------------------------------------------------------------
# IMAP dispatch
# ---------------------------------------------------------------------------

async def _imap_poll_once(app, acct: dict) -> None:
    """Delegate to the existing ``_poll_once_imap`` in web/app.py.

    Imported lazily so the dispatcher module stays loadable in
    contexts where ``web.app`` isn't on the import path (CLI tests,
    pure-provider tests).
    """
    from email_triage.web.app import _poll_once_imap
    await _poll_once_imap(app, acct)


async def _imap_start_push(manager, account_id: int, acct: dict) -> str:
    """IMAP push — delegate to the existing ``_start_imap_push`` method.

    Stays as a method on ``WatcherManager`` because it touches manager-
    private state (``_tasks``, ``_mb_state``); the dispatcher just
    routes the ptype-keyed call.
    """
    return await manager._start_imap_push(account_id, acct)


def _imap_infer_push_enabled(conn, account_id: int, default: bool = True) -> bool:
    """Infer IMAP push_enabled from the legacy ``watch:<id>`` setting."""
    import json as _json
    import sqlite3
    from email_triage.web.settings_keys import watch as _watch_key

    try:
        row = conn.execute(
            "SELECT value_json FROM settings WHERE key = ?",
            (_watch_key(account_id),),
        ).fetchone()
    except sqlite3.Error:
        return default

    if row is None:
        # No setting — default depends on caller. Fresh accounts
        # should boot with the IDLE watcher armed.
        return default

    raw_val = row["value_json"] if isinstance(row, sqlite3.Row) else row[0]
    try:
        parsed = _json.loads(raw_val) if raw_val else {}
    except (TypeError, ValueError):
        parsed = {}
    return bool(
        parsed.get("enabled", False) if isinstance(parsed, dict) else False
    )


async def _imap_test_connection(acct: dict, secrets) -> tuple[bool, str]:
    """IMAP connection probe — opens IMAP4_SSL, logs in, selects mailbox."""
    import imaplib
    import socket
    import ssl as ssl_mod

    from email_triage.providers.factory import secret_key_for_account

    ptype = acct["provider_type"]
    cfg = acct["config"] or {}
    account_id = acct["id"]

    host = cfg.get("host", "")
    port = cfg.get("port", 993)
    username = cfg.get("username", "")
    use_ssl = cfg.get("use_ssl", True)
    sk = secret_key_for_account(account_id, ptype)
    password = secrets.get(sk) if sk else ""

    if not host or not username:
        return False, (
            '<small style="color:var(--pico-del-color);">'
            'Host and username required.</small>'
        )
    try:
        if use_ssl:
            ctx = ssl_mod.create_default_context()
            imap = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
        else:
            imap = imaplib.IMAP4(host, port)
        imap.login(username, password or "")
        mailbox = cfg.get("mailbox", "INBOX")
        status, data = imap.select(mailbox, readonly=True)
        count = data[0].decode() if data else "?"
        imap.logout()
        return True, (
            f'<small style="color:var(--pico-ins-color);">'
            f'Connected. {count} messages in {mailbox}.</small>'
        )
    except ssl_mod.SSLCertVerificationError as e:
        err_msg = str(e)
        if "Hostname mismatch" in err_msg:
            try:
                fqdn = socket.getfqdn(host)
                ip = socket.gethostbyname(host)
                try:
                    reverse_name = socket.gethostbyaddr(ip)[0]
                except Exception:
                    reverse_name = ""
                suggestion = reverse_name or fqdn
                if suggestion and suggestion != host:
                    return False, (
                        f'<small style="color:var(--pico-del-color);">'
                        f'SSL certificate hostname mismatch: the certificate is not valid for "<code>{host}</code>". '
                        f'Try using the fully qualified domain name: <code>{suggestion}</code>'
                        f'</small>'
                    )
            except Exception:
                pass
            return False, (
                f'<small style="color:var(--pico-del-color);">'
                f'SSL certificate hostname mismatch. The server certificate does not match "<code>{host}</code>". '
                f'Use the server\'s fully qualified domain name (e.g. <code>mail.example.com</code>).'
                f'</small>'
            )
        elif "CERTIFICATE_VERIFY_FAILED" in err_msg:
            return False, (
                f'<small style="color:var(--pico-del-color);">'
                f'SSL certificate verification failed for "<code>{host}</code>": {err_msg}. '
                f'If this is a self-signed certificate, uncheck "Use SSL" and use port 143, '
                f'or ensure the server\'s CA is trusted.'
                f'</small>'
            )
        return False, (
            f'<small style="color:var(--pico-del-color);">SSL error: {e}</small>'
        )
    except Exception as e:
        return False, (
            f'<small style="color:var(--pico-del-color);">Failed: {e}</small>'
        )


async def _imap_post_create_start_watch(
    manager, request, acct: dict, secrets,
) -> tuple[str, str]:
    """IMAP post-create auto-start: connection test + watcher start.

    Mirrors the original ``accounts_create`` IMAP branch shape:
    on test-success, call ``manager.start``; on test-failure, surface
    a stripped reason. Returns ``(success_msg, error_msg)``; exactly
    one is non-empty.

    Routes the connection probe through ``_test_account_connection``
    on ``web.routers.ui`` rather than calling ``_imap_test_connection``
    in this module directly — tests that monkey-patch the router-side
    name continue to apply through this dispatch path.
    """
    import re

    from email_triage.web.routers.ui import _test_account_connection

    ok, test_msg = await _test_account_connection(acct, secrets)
    if ok:
        try:
            start_msg = await manager.start(acct["id"])
            return (
                f"Account added and watcher started ({start_msg}).",
                "",
            )
        except Exception as e:
            return ("", f"Account added, but watcher failed to start: {e}.")
    else:
        # Strip HTML tags from the inline error for the banner.
        reason = re.sub(r"<[^>]+>", "", test_msg).strip()
        return (
            "",
            f"Account added, but connection test failed: {reason}. "
            f"Watcher not started.",
        )


# ---------------------------------------------------------------------------
# Gmail dispatch
# ---------------------------------------------------------------------------

async def _gmail_poll_once(app, acct: dict) -> None:
    """Delegate to the existing ``_poll_once_gmail`` in web/app.py."""
    from email_triage.web.app import _poll_once_gmail
    await _poll_once_gmail(app, acct)


async def _gmail_start_push(manager, account_id: int, acct: dict) -> str:
    """Gmail push — record intent only; the actual Pub/Sub
    subscription is managed via the Start-watch button on the
    account-edit form, not via the unified WatcherManager path.

    D2 (#145.7) consolidated the ``{"enabled": bool}`` shape behind
    ``set_bool_setting`` — use it here instead of the raw dict so the
    settings-cache (D2 #140.2) invalidates correctly.
    """
    from email_triage.web.db import set_bool_setting
    from email_triage.web.settings_keys import watch as _watch_key

    set_bool_setting(manager.app.state.db, _watch_key(account_id), True)
    return "Push: Gmail Pub/Sub (manage on edit form)"


def _gmail_infer_push_enabled(conn, account_id: int, default: bool = True) -> bool:
    """Infer Gmail push_enabled from the ``gmail_watches`` row."""
    import sqlite3

    try:
        row = conn.execute(
            "SELECT topic_name, expires_at FROM gmail_watches "
            "WHERE account_id = ?",
            (account_id,),
        ).fetchone()
    except sqlite3.Error:
        return default

    if row is None:
        return default
    topic = (row["topic_name"] or "").strip() if isinstance(
        row, sqlite3.Row,
    ) else (row[0] or "").strip()
    # Non-empty topic = push set up. Don't gate on expiry — the
    # renewer recovers expiry; what we want here is operator intent.
    return bool(topic)


async def _gmail_test_connection(acct: dict, secrets) -> tuple[bool, str]:
    """Gmail connection probe — list labels via the API client.

    Routes provider construction through ``_create_provider_from_account``
    in ``web.routers.ui`` (the historical entry point) rather than the
    factory module directly. Tests that patch the name on the router
    module continue to apply through this dispatch path.
    """
    from email_triage.providers.factory import secret_key_for_account
    from email_triage.web.routers.ui import _create_provider_from_account

    ptype = acct["provider_type"]
    account_id = acct["id"]

    sk = secret_key_for_account(account_id, ptype)
    has_token = bool(secrets.get(sk)) if sk else False
    if not has_token:
        return False, (
            '<small style="color:var(--pico-color-amber-500);">'
            'Not authenticated. Click <strong>Authenticate with Google</strong> in the edit form.'
            '</small>'
        )
    try:
        provider = _create_provider_from_account(acct, secrets)
        labels = await provider.list_labels()
        await provider.close()
        return True, (
            f'<small style="color:var(--pico-ins-color);">'
            f'Connected. {len(labels)} labels visible.</small>'
        )
    except Exception as e:
        return False, (
            f'<small style="color:var(--pico-del-color);">Failed: {e}</small>'
        )


async def _gmail_post_create_start_watch(
    manager, request, acct: dict, secrets,
) -> tuple[str, str]:
    """Gmail post-create message — explain poll-mode default."""
    return (
        "Account added. Gmail runs in poll mode by default — "
        "new mail is fetched on the install's cadence. Configure "
        "push on the Routes page if you want instant delivery.",
        "",
    )


# ---------------------------------------------------------------------------
# Office 365 dispatch
# ---------------------------------------------------------------------------

async def _o365_poll_once(app, acct: dict) -> None:
    """O365 poll — not yet wired. Returns silently; the caller's
    debug log entry preserves the visibility."""
    return None


async def _o365_start_push(manager, account_id: int, acct: dict) -> str:
    """O365 push — Graph subscriptions not yet wired."""
    return "Push: Office 365 (not yet implemented)"


def _o365_infer_push_enabled(conn, account_id: int, default: bool = True) -> bool:
    """O365 — no inference path yet; mirror legacy fallback."""
    return default


async def _o365_test_connection(acct: dict, secrets) -> tuple[bool, str]:
    """O365 — no inline probe; the operator runs the CLI for device-code."""
    return False, (
        '<small>Save first, then run '
        '<code>email-triage run --dry-run --limit 1</code> '
        'for device-code auth.</small>'
    )


async def _o365_post_create_start_watch(
    manager, request, acct: dict, secrets,
) -> tuple[str, str]:
    """O365 post-create — no automatic start; device-code auth needed."""
    return ("", "")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

DISPATCHERS: dict[str, ProviderDispatch] = {
    "imap": ProviderDispatch(
        ptype="imap",
        poll_once=_imap_poll_once,
        start_push=_imap_start_push,
        infer_push_enabled=_imap_infer_push_enabled,
        test_connection=_imap_test_connection,
        post_create_start_watch=_imap_post_create_start_watch,
    ),
    "gmail_api": ProviderDispatch(
        ptype="gmail_api",
        poll_once=_gmail_poll_once,
        start_push=_gmail_start_push,
        infer_push_enabled=_gmail_infer_push_enabled,
        test_connection=_gmail_test_connection,
        post_create_start_watch=_gmail_post_create_start_watch,
    ),
    "office365": ProviderDispatch(
        ptype="office365",
        poll_once=_o365_poll_once,
        start_push=_o365_start_push,
        infer_push_enabled=_o365_infer_push_enabled,
        test_connection=_o365_test_connection,
        post_create_start_watch=_o365_post_create_start_watch,
    ),
}


def get_dispatch(ptype: str) -> ProviderDispatch | None:
    """Look up dispatch by provider type. ``None`` for unknown types.

    Call sites that previously used ``if ptype == ...`` switches now
    do ``d = get_dispatch(ptype); await d.poll_once(...)`` and let the
    None-check surface the unknown-ptype log entry.
    """
    return DISPATCHERS.get(ptype)
