"""ProviderDispatcher registry — functional-dispatch sibling of
:mod:`email_triage.providers.traits`.

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
import html
from email_triage.web.error_html import error_chip
from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import get_logger  # N-196b R21_4
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from email_triage.db._helpers import row_get
from email_triage._dbapi_errors import DB_ERRORS

logger = get_logger("email_triage.providers.dispatcher")  # N-196b R21_4


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

        poll_implemented:
            ``bool``. True when ``poll_once`` genuinely ingests mail.
             — when this is False a caller MUST NOT count the
            account as a healthy polling account: the unified poll
            loop records a tick regardless of dispatch outcome, so a
            no-op stub would otherwise aggregate as "polling fine".
            Health/aggregation code reads this to surface an honest
            ``provider_unimplemented`` alert instead.
    """

    ptype: str
    poll_once: Callable[..., Awaitable[None]]
    start_push: Callable[..., Awaitable[str]]
    infer_push_enabled: Callable[..., bool]
    test_connection: Callable[..., Awaitable[tuple[bool, str]]]
    post_create_start_watch: Callable[..., Awaitable[tuple[str, str]]]
    poll_implemented: bool = True


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
    from email_triage.db._helpers import load_json_col
    from email_triage.web.settings_keys import watch as _watch_key

    try:
        row = conn.execute(
            "SELECT value_json FROM settings WHERE key = ?",
            (_watch_key(account_id),),
        ).fetchone()
    except DB_ERRORS:
        return default

    if row is None:
        # No setting — default depends on caller. Fresh accounts
        # should boot with the IDLE watcher armed.
        return default

    # N-16: row_get duck-types on keys() so a sqlcipher3 Row takes the
    # keyed branch — isinstance(row, sqlite3.Row) goes False for it.
    raw_val = row_get(row, "value_json", 0)
    # census  SSOT — corrupt value_json degrades to {} (→ enabled False).
    parsed = load_json_col(raw_val, default={})
    return bool(parsed.get("enabled", False))


def _imap_release(imap) -> None:
    """End a blocking ``imaplib`` probe session, best-effort: LOGOUT, and when the server
    is gone (or LOGOUT itself fails) close the socket directly. Never raises."""
    try:
        imap.logout()
    except Exception as exc:
        logger.debug("imap probe logout failed; closing the socket", error=fmt_exc(exc, with_class=True))
        try:
            imap.shutdown()
        except Exception as exc2:
            logger.debug("imap probe socket close failed", error=fmt_exc(exc2, with_class=True))


async def _imap_test_connection(acct: dict, secrets) -> tuple[bool, str]:
    """IMAP connection probe — opens IMAP4_SSL, logs in, selects mailbox. The
    connection itself runs on a worker thread (:func:`_imap_probe_blocking`)."""
    import asyncio

    from email_triage.providers.factory import secret_key_for_account

    ptype = acct["provider_type"]
    cfg = acct["config"] or {}
    account_id = acct["id"]

    host = cfg.get("host", "")
    port = cfg.get("port", 993)
    username = cfg.get("username", "")
    use_ssl = cfg.get("use_ssl", True)
    sk = secret_key_for_account(account_id, ptype)
    from email_triage.secrets import SecretsDecryptError, read_secret
    try:
        password = read_secret(secrets, sk) if sk else ""
    except SecretsDecryptError:
        # A5 — fail closed + legible: a stored password that won't decrypt
        # (master-key mismatch) is not a connection problem to retry.
        return False, (
            '<small style="color:var(--pico-del-color);">'
            'Stored password unreadable — secrets master-key mismatch. '
            'Check the secrets master key.</small>'
        )

    if not host or not username:
        return False, (
            '<small style="color:var(--pico-del-color);">'
            'Host and username required.</small>'
        )
    # Cycle P db P1-1: imaplib blocks on connect, TLS, LOGIN, SELECT and LOGOUT (and the
    # hostname-mismatch hint below does blocking DNS look-ups), so the whole probe runs on
    # a worker thread: a slow or stalled server never holds the event loop.
    return await asyncio.to_thread(
        _imap_probe_blocking, cfg, host, port, username, password, use_ssl)


def _imap_probe_blocking(cfg: dict, host: str, port: int, username: str,
                         password: str, use_ssl: bool) -> tuple[bool, str]:
    """The blocking body of :func:`_imap_test_connection`, run in a worker thread."""
    import socket
    import ssl as ssl_mod

    from email_triage.providers.imap_fetch_transport import imap_connect

    try:
        # The transport applies the account's certificate-check mode itself
        # (tls.tls_connect), so the probe tests the same policy as the fetch it
        # predicts, and shows the verdict when the check failed but the mode let
        # the connection through.
        from email_triage.tls import resolve_cert_policy
        imap = imap_connect(host, port, use_ssl=use_ssl,
                            cert_policy=resolve_cert_policy(cfg))
        # Punch 694: the session is released on a failed login or select too.
        try:
            imap.login(username, password or "")
            mailbox = cfg.get("mailbox", "INBOX")
            status, data = imap.select(mailbox, readonly=True)
            count = data[0].decode() if data else "?"
            verdict = getattr(imap, "_et_cert_verdict", None)
        finally:
            _imap_release(imap)
        note = ""
        if verdict == "failed":
            note = (
                f'<br><span style="color:var(--pico-del-color);">'
                f'Warning: the certificate of "<code>{html.escape(host)}</code>" did not '
                f'verify. Connected anyway because certificate enforcement is off; '
                f'the failure is in the log (tls_cert_check_failed).</span>'
            )
        elif verdict == "unchecked":
            note = (
                '<br><span style="color:var(--pico-muted-color);">'
                'Certificate check is off for this connection.</span>'
            )
        return True, (
            f'<small style="color:var(--pico-ins-color);">'
            f'Connected. {html.escape(str(count))} messages in {html.escape(str(mailbox))}.{note}</small>'
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
                        f'SSL certificate hostname mismatch: the certificate is not valid for "<code>{html.escape(host)}</code>". '
                        f'Try using the fully qualified domain name: <code>{html.escape(suggestion)}</code>'
                        f'</small>'
                    )
            except Exception as exc:
                logger.debug("imap probe hostname hint lookup failed", error=fmt_exc(exc, with_class=True))
            return False, (
                f'<small style="color:var(--pico-del-color);">'
                f'SSL certificate hostname mismatch. The server certificate does not match "<code>{html.escape(host)}</code>". '
                f'Use the server\'s fully qualified domain name (e.g. <code>mail.example.com</code>).'
                f'</small>'
            )
        elif "CERTIFICATE_VERIFY_FAILED" in err_msg:
            return False, (
                f'<small style="color:var(--pico-del-color);">'
                f'SSL certificate verification failed for "<code>{html.escape(host)}</code>": {html.escape(err_msg)}. '
                f'If this is a self-signed or private-CA certificate, add its CA to the '
                f'trust store, or set this account\'s certificate enforcement to off (the '
                f'check still runs and logs), or turn the certificate check off while '
                f'setting up.'
                f'</small>'
            )
        return False, (
            error_chip(e, prefix='SSL error: ')
        )
    except Exception as e:
        return False, (
            error_chip(e, prefix='Failed: ')
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
        # Strip HTML tags from the inline error for the banner —  SSOT.
        from email_triage.engine.html_text import strip_tags
        reason = strip_tags(test_msg)
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

    D2 consolidated the ``{"enabled": bool}`` shape behind
    ``set_bool_setting`` — use it here instead of the raw dict so the
    settings-cache (D2 .2) invalidates correctly.
    """
    from email_triage.web.db import set_bool_setting
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.settings_keys import watch as _watch_key

    #  — _gmail_start_push is an async def; route the settings
    # write off the event-loop thread.
    await db_call(
        set_bool_setting, manager.app.state.db, _watch_key(account_id), True,
    )
    return "Push: Gmail Pub/Sub (manage on edit form)"


def _gmail_infer_push_enabled(conn, account_id: int, default: bool = True) -> bool:
    """Infer Gmail push_enabled from the ``gmail_watches`` row."""
    try:
        row = conn.execute(
            "SELECT topic_name, expires_at FROM gmail_watches "
            "WHERE account_id = ?",
            (account_id,),
        ).fetchone()
    except DB_ERRORS:
        return default

    if row is None:
        return default
    # N-16: row_get duck-types on keys() (sqlcipher3 Row supported).
    topic = (row_get(row, "topic_name", 0) or "").strip()
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
    from email_triage.providers.render_probe import (
        USER_SCAN_PROBE_TIMEOUT_S, probe_session, render_probe,
    )
    from email_triage.web.routers.ui import _create_provider_from_account

    ptype = acct["provider_type"]
    account_id = acct["id"]

    sk = secret_key_for_account(account_id, ptype)
    from email_triage.secrets import SecretsDecryptError, read_secret
    try:
        has_token = bool(read_secret(secrets, sk)) if sk else False
    except SecretsDecryptError:
        # A5 — fail closed + legible (master-key mismatch, not "not authed").
        return False, (
            '<small style="color:var(--pico-del-color);">'
            'Stored token unreadable — secrets master-key mismatch. '
            'Check the secrets master key.</small>'
        )
    if not has_token:
        return False, (
            '<small style="color:var(--pico-color-amber-500);">'
            'Not authenticated. Click <strong>Authenticate with Google</strong> in the edit form.'
            '</small>'
        )
    try:
        provider = _create_provider_from_account(acct, secrets)
        async with probe_session(provider):
            # Punch 819: bounded like the discover scan, the other probe a user
            # started and is waiting on (the 3 s page-render bound would turn a
            # slow Gmail into a failed button).
            labels = await render_probe(
                provider, "list_labels", account_id=account_id,
                timeout_s=USER_SCAN_PROBE_TIMEOUT_S,
            )
        return True, (
            f'<small style="color:var(--pico-ins-color);">'
            f'Connected. {len(labels)} labels visible.</small>'
        )
    except Exception as e:
        return False, (
            error_chip(e, prefix='Failed: ')
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
    """O365 poll — delegate to ``_poll_once_office365`` in web/app.py.

     — was a ``return None`` stub; an O365 account added via the UI
    received zero triage while the dashboard still showed it polling.
    Now walks the Graph Inbox delta feed and triages every changed
    message, sharing the standard ``triage_single_message`` body with
    the O365 push consumer.
    """
    from email_triage.web.app import _poll_once_office365
    await _poll_once_office365(app, acct)


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
