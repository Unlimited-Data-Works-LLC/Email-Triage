"""Routes for the users concern.

Split out of the legacy `web/routers/ui.py`. Helpers
live in `_shared`; this file holds only the @router-decorated
handlers + handler-local helpers for this URL surface.
No behavior changes from pre-split — every handler body is
byte-for-byte identical.
"""
from __future__ import annotations

import asyncio
import email as email_mod
import email.policy
import email.utils
import json as json_mod
import os
import sqlite3
import time
from typing import Any
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_manage_account
from email_triage.web._audit import safe_audit_write
from email_triage.web import settings_keys as _S
from email_triage.web.app import get_config, get_db, get_secrets, get_templates
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    generate_otp,
    get_user_by_email,
    send_otp_email,
    set_session_cookie,
    store_otp,
    update_last_login,
    verify_otp,
)
from email_triage.db.audit import GrantRefused, record_user_creation, record_user_update  # punch 668, 674
from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import (  # N-337: audit-XFF SSOT
    audit_forwarded_for,
    request_meta,
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    RequireUser,
    admin_gate_response,
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._envbool import parse_bool
from email_triage._errfmt import fmt_exc
from email_triage._secret_keys import SMTP_PASSWORD_KEY  # N-231 R22 stored-secret-key SSOT

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.users")

router = APIRouter()


from . import _shared
# Snapshot every helper from _shared into this module's globals so
# handler bare-name references resolve. globals().update is used
# instead of `from _shared import *` because * skips underscore-
# prefixed names (which is most helpers).
globals().update({
    _n: _v for _n, _v in vars(_shared).items()
    if not _n.startswith('__')
})


def __getattr__(name):
    """Legacy install-singleton names + PEP-562 fallback to ``_shared``.

    Two roles folded into one module-level ``__getattr__`` (census
    wf_56d1585d 2026-07-09 D3 — SSOT self-shadowing fix; Python only
    honours the LAST ``__getattr__`` per module, so previously the
    install-singleton compat glue was dead code from an unnoticed second
    override):

    1. Route reads of legacy install-singleton names
       (``_install_google_oauth`` / ``_install_ingestion_config``) through
       the factory module. Code that did
       ``from email_triage.web.routers.ui import _install_ingestion_config``
       (test fixtures, future plugins) keeps working.
    2. Late-bound lookup on ``_shared`` — catches names added to
       ``_shared`` after this module's ``globals().update`` populated, plus
       names the package-level monkeypatch mirror writes onto ``_shared``
       after import.
    """
    if name == "_install_google_oauth":
        from email_triage.providers import factory as _f
        return _f._install_google_oauth
    if name == "_install_ingestion_config":
        from email_triage.providers import factory as _f
        return _f._install_ingestion_config
    if hasattr(_shared, name):
        return getattr(_shared, name)
    raise AttributeError(
        f'module {__name__!r} has no attribute {name!r}'
    )


#: Punch 595: shown on the sign-in page when a code cannot be delivered. The
#: page is end-user facing, so it names the cause and no admin path.
_OTP_NO_DELIVERY_ERROR = (
    "Sign-in codes can't be sent: outgoing email isn't set up on this "
    "server yet. You can still sign in with a passkey."
)


def _otp_delivery(config: Any) -> str:
    """How a login code reaches the user: ``"smtp"``, ``"console"`` or
    ``"refuse"`` (punch 595). Decided BEFORE a code is minted, so a refused
    request leaves no undeliverable code behind.

    ``"console"`` needs the explicit ``smtp.dev_console_otp`` flag AND a
    non-HIPAA process, checked here against the live flag (HIPAA mode can be
    switched on at runtime). Anything else with no SMTP host is refused.
    """
    from email_triage.triage_logging import is_hipaa_mode
    smtp = config.smtp
    if smtp.host:
        return "smtp"
    if getattr(smtp, "dev_console_otp", False) and not is_hipaa_mode():
        return "console"
    return "refuse"


def _reaches_hipaa_account(db: Any, user: dict) -> bool:
    """True when ``user`` can reach any HIPAA-flagged mailbox (owner or
    delegate: the manageable-set SSOT, judged by the 3-axis
    ``account_hipaa_effective`` SSOT, N-266). Gates the dev-console OTP
    channel (HIPAA risk 4)."""
    from email_triage.web.account_scope import manageable_accounts
    from email_triage.triage_logging import account_hipaa_effective
    return any(
        account_hipaa_effective(account=a) for a in manageable_accounts(db, user)
    )


def _console_otp_refused(db: Any, user: dict) -> bool:
    """Dev-console OTP gate (HIPAA risk 4, operator rulings 2026-11-07).

    The console is an admin-only dev channel ("users would never have a
    need"), and even an admin is refused when they can reach a HIPAA-flagged
    mailbox: a stderr code is an unauthenticated read of that PHI access."""
    from email_triage.web.dependencies import is_admin
    return (not is_admin(user)) or _reaches_hipaa_account(db, user)


def _print_dev_console_otp(email: str, code: str) -> None:
    """Write a login code to the process's stderr for a dev install.

    Deliberately NOT a logger: every ``email_triage.*`` logger propagates to
    the ``SQLiteLogHandler`` that writes ``log_entries`` (HMAC-chained,
    retained 6 years), and the old ``log.warning(... % code)`` put each code
    there in clear (punch 595). Only :func:`_otp_delivery` returning
    ``"console"`` reaches this.
    """
    import sys
    sys.stderr.write(
        f"[email-triage dev console] login code for {email}: {code}\n"
    )
    sys.stderr.flush()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    templates = get_templates(request)
    user = await db_call(get_current_user, request)  # 
    if user is not None:
        return RedirectResponse("/dashboard", status_code=303)
    return await _render(templates, request, "login.html", {"step": "email"})


@router.post("/login/email", response_class=HTMLResponse)
async def login_email(request: Request, email: str = Form(...)):
    """Step 1: user submits email, we generate and store OTP.

    Fail-closed on disabled users: the SMTP send is skipped so no code
    ever reaches the inbox of a disabled account. The response is the
    same ``step=verify`` screen everyone else sees — we don't reveal
    whether the account exists or is disabled.

     — login_guard runs BEFORE the user lookup so a probing
    attacker can't use the unknown-email path as an enumeration
    oracle. Lockout response is identical regardless of whether
    the email exists; the unknown-email branch ALSO writes a
    failure row so the per-email + per-IP counters fire on
    nonexistent-account spray.
    """
    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    # Punch 595: no way to deliver a code -> refuse before the lookup and
    # before a code is minted. The page is identical for every email, so it
    # says nothing about whether the account exists.
    delivery = _otp_delivery(config)
    if delivery == "refuse":
        get_logger("web.auth").warning(
            "OTP login refused: no SMTP host is configured. Set smtp.host, "
            "or smtp.dev_console_otp on a non-HIPAA dev install.",
        )
        return await _render(templates, request, "login.html", {
            "step": "email", "error": _OTP_NO_DELIVERY_ERROR,
        })

    #  lockout gate — runs first. A locked email or IP gets the
    # generic verify-step screen (same shape as success) so the
    # response doesn't leak which counter tripped or whether the
    # account exists.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )

    skip_hw_picker = parse_bool(request.query_params.get("otp_fallback"))

    def _login_email_db_work() -> tuple[str, dict]:
        """/ — lockout gate + user lookup + (hardware-key
        check) + OTP store, all in ONE threadpool hop. Returns
        ``(kind, payload)``:
          - ("locked", {retry_min})  → step=email lockout screen
          - ("not_found", {})        → step=email not-found screen
          - ("disabled", {})         → step=verify (no OTP, no SMTP)
          - ("choose", {})           → step=choose hardware-key picker
          - ("otp", {code})          → handler sends SMTP then renders
        The OTP generation + store live inside this hop so the SMTP
        send below is the only thing the handler does on the loop.
        """
        try:
            check_login_allowed(
                db, email=email, ip=client_host, config=config,
            )
        except LoginLocked as locked:
            record_login_lockout(
                db, surface="otp_request", email=email, ip=client_host,
                user_agent=user_agent, scope=locked.scope,
                threshold=locked.retry_after_secs,
            )
            retry_min = max(1, locked.retry_after_secs // 60)
            return "locked", {"retry_min": retry_min}

        user_ = get_user_by_email(db, email)
        user_disabled = bool(user_ and user_.get("disabled"))
        if user_ is None:
            # Failure row so the rate-limiter sees no-such-account
            # spraying. ``email`` is the operator-supplied input —
            # could be junk, but the COUNT is what matters.
            record_login_failure(
                db, surface="otp_request", email=email, ip=client_host,
                user_agent=user_agent, reason="account_not_found",
            )
            return "not_found", {}

        if user_disabled:
            return "disabled", {}

        #  — hardware-key picker. If the user has at least one
        # active passkey, render the choose-method step (touch
        # security key primary + send-OTP-instead fallback) WITHOUT
        # sending the OTP. User picks "OTP fallback" to fall through
        # into the existing path (posts back with otp_fallback=1).
        if not skip_hw_picker:
            from email_triage.web.db_auth_helpers import (
                user_has_active_hardware_key as _has_hw,
            )
            try:
                has_hw = _has_hw(db, user_["id"])
            except Exception:
                has_hw = False
            if has_hw:
                return "choose", {}

        # HIPAA risk 4 (operator rulings 2026-11-07): the dev console delivers
        # only to an admin, and never to anyone who can reach a HIPAA-flagged
        # mailbox (owner or delegate), even while install-wide HIPAA mode is
        # off. Placed AFTER the  hardware-key picker (which mints no code)
        # so a key holder still reaches it; refused before a code is minted,
        # so nothing undeliverable is stored. The refusal writes a failure
        # row (§164.308(a)(5)(ii)(C) log-in monitoring).
        if delivery == "console" and _console_otp_refused(db, user_):
            record_login_failure(
                db, surface="otp_request", email=email, ip=client_host,
                user_agent=user_agent, reason="console_otp_refused",
                user_id=user_["id"],
            )
            return "console_refused_hipaa", {}

        code_ = generate_otp()
        store_otp(db, email, code_)
        return "otp", {"code": code_}

    kind, payload = await db_call(_login_email_db_work)
    if kind == "locked":
        retry_min = payload["retry_min"]
        return await _render(templates, request, "login.html", {
            "step": "email",
            "error": (
                f"Too many login attempts. Please try again in "
                f"{retry_min} minute{'s' if retry_min != 1 else ''}."
            ),
        })
    if kind == "not_found":
        return await _render(templates, request, "login.html", {
            "step": "email", "error": "No account found for that email.",
        })
    if kind == "console_refused_hipaa":
        get_logger("web.auth").warning(
            "OTP login refused: the dev console delivers only to an admin "
            "with no HIPAA-flagged account. Set smtp.host.",
        )
        return await _render(templates, request, "login.html", {
            "step": "email", "error": _OTP_NO_DELIVERY_ERROR,
        })
    if kind == "disabled":
        # Don't generate or store an OTP. Don't call SMTP. Don't reveal
        # the account is disabled — present the same verify screen so
        # there's no account-state oracle for a probing attacker.
        log = get_logger("web.auth")
        log.warning("OTP delivery skipped: user disabled", email=email)
        return await _render(templates, request, "login.html", {
            "step": "verify", "email": email,
        })
    if kind == "choose":
        return await _render(templates, request, "login.html", {
            "step": "choose", "email": email,
        })

    code = payload["code"]

    # Send the code by SMTP, or (dev install only) print it to stderr.
    smtp = config.smtp

    if delivery == "smtp":
        secrets = get_secrets(request)
        from email_triage.secrets import SecretsDecryptError, read_secret
        # A5: explicit decrypt-error handling — an unreadable secret store
        # (master-key mismatch) fails closed (no blank-password send).
        try:
            smtp_password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
        except SecretsDecryptError:
            get_logger("web.auth").error(
                "OTP login email aborted — SMTP password unreadable "
                "(corrupt secret row / master-key mismatch)",
                email=email,
            )
            return await _render(templates, request, "login.html", {
                "step": "email",
                "error": "Could not send login code. Please try again or contact admin.",
            })
        try:
            # smtplib is blocking — run it off the event loop so the
            # login request doesn't stall every other request + the
            # watchers during the SMTP handshake.
            await asyncio.to_thread(
                send_otp_email,
                smtp_host=smtp.host,
                smtp_port=smtp.port,
                smtp_user=smtp.username,
                smtp_password=smtp_password,
                from_addr=smtp.from_addr,
                to_addr=email,
                code=code,
                use_tls=smtp.use_tls,
                from_name=smtp.from_name,
            )
        except Exception as exc:
            log = get_logger("web.auth")
            log.error("Failed to send OTP email", error=str(exc))
            return await _render(templates, request, "login.html", {
                "step": "email",
                "error": "Could not send login code. Please try again or contact admin.",
            })
    else:
        # delivery == "console": smtp.dev_console_otp on a non-HIPAA
        # process. Punch 595: this used to be
        # ``log.warning("... code=%s" % code)``, inlined to dodge the
        # ``code`` kwarg redaction, which wrote every code in clear into
        # log_entries. stderr only, never the logging tree.
        _print_dev_console_otp(email, code)

    return await _render(templates, request, "login.html", {
        "step": "verify", "email": email,
    })


@router.post("/login/verify", response_class=HTMLResponse)
async def login_verify(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
):
    """Step 2: user submits the 6-digit code.

     — login_guard runs before verify_otp; a tipped counter
    refuses without consuming the OTP code. Bad-code attempts
    write a failure row into ``auth_events`` so the rolling
    window catches the next attempt.
    """
    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    #  lockout gate.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )

    def _login_verify_db_work() -> tuple[str, dict]:
        """/ — lockout gate + OTP check + user lookup + audit, all in
        ONE threadpool hop (no network awaits). Returns ``(kind, payload)``:
          - ("locked", {retry_min})  → step=verify lockout screen
          - ("invalid", {})          → step=verify bad-code screen
          - ("not_found", {})        → step=email account-not-found
          - ("disabled", {})         → step=email account-disabled
          - ("ok", {user})           → handler mints the session token

        N-520 step 2 (s2 panel hipaa ruling, credential burns):
        * SUCCESS edge: the one-shot burn, the last_login stamp and the
          ``login_otp`` success row commit in ONE transaction
          (``record_witnessed_state_change``); the cookie is minted only after
          this returns. A failed witness (or any other failure of that
          transaction) rolls it back, and the matched code is then burned in
          its own transaction (hipaa-sme 2026-11-06, option A): no session.
          A failure of the post-match reads takes the same path. If the
          burn itself fails it is only logged and the code lives to its
          TTL (register residual, punch 907). A lost race (a concurrent
          verify spent the code first) refuses as invalid and writes a
          lockout-neutral denied:otp_already_used row (the concurrent writer
          may also be a fresh OTP request or the expiry purge). Only the concurrent
          race writes it: a later replay of a spent code no longer matches
          (classify_otp reads only unused codes) and is a counting failure.
        * FAILURE / refusal edges: the burn is a TIGHTENING write and never
          depends on chain health. Each refusal's row is written first, then
          the burn commits on its own (``burn_otp``) whatever the row did.
        """
        from email_triage.web.auth import (
            burn_otp, burn_otp_txn, classify_otp, update_last_login_txn,
        )
        from email_triage.db.audit import (
            record_auth_event_txn, record_witnessed_state_change,
        )
        try:
            check_login_allowed(
                db, email=email, ip=client_host, config=config,
            )
        except LoginLocked as locked:
            record_login_lockout(
                db, surface="otp", email=email, ip=client_host,
                user_agent=user_agent, scope=locked.scope,
                threshold=locked.retry_after_secs,
            )
            retry_min = max(1, locked.retry_after_secs // 60)
            return "locked", {"retry_min": retry_min}

        # OTP verification is the only path through this handler.
        # Other auth surfaces (admin-managed keypair at
        # /admin/dev-keys, per-user WebAuthn at
        # /profile/hardware-keys) are routed separately and never
        # short-circuit this code-shape check.
        status, otp_id = classify_otp(db, email, code)
        # Decide first (reads only); every row is written below, and every
        # burn comes after every witness in source order.
        refusal = "invalid"
        user_ = None
        success_failure: Exception | None = None
        success = False

        def _burn_after_failure(cause: BaseException) -> None:
            # Option A: a matched code whose login failed is burned in its own
            # transaction; a failure of that burn is only logged (register
            # residual, punch 907) and the caller re-raises ``cause``.
            try:
                burn_otp(db, otp_id)
            except Exception as burn_exc:
                _log.error(
                    "login_verify: OTP burn after a failed login also failed",
                    error=fmt_exc(burn_exc), cause=fmt_exc(cause),
                )

        mfa_required = False
        if status == "valid":
            try:
                user_ = get_user_by_email(db, email)
                from email_triage.web.mfa import is_mfa_required_for
                mfa_required = bool(
                    user_ is not None and not user_.get("disabled")
                    and is_mfa_required_for(db, user_)
                )
            except Exception as exc:
                # Option A covers the post-match reads too (s2h DA gap 2): a
                # read that raises after the code matched burns the code below
                # and re-raises, so a valid code is never left unburned.
                success_failure = exc
        if status == "valid" and success_failure is None:
            if user_ is None:
                # Punch 687: a VALID code for an address with no user row is
                # a log-in discrepancy (§164.308(a)(5)(ii)(C)).
                refusal = "not_found"
            elif user_.get("disabled"):
                # Fail-closed: even with a valid OTP, a disabled user cannot
                # log in (no dev-bypass reaches here; panel Z DA). Punch 687:
                # a disabled (terminated) user presenting a valid credential
                # is a log-in discrepancy (§164.308(a)(5)(ii)(C),
                # §164.308(a)(3)(ii)(C)).
                refusal = "disabled"
            elif mfa_required:
                # H-05 (Cycle 7) — §164.312(d) MFA enforcement gate. In HIPAA
                # mode, a user with any registered passkey OR any unconsumed
                # recovery code MUST authenticate via the WebAuthn /
                # recovery-code path; OTP-only login is the non-MFA factor.
                # Mirrors the "hardware_key_required" gate on the dev_keypair
                # path.
                refusal = "mfa_required"
            else:
                # Run the success transaction LAST, after every refusal
                # row and the tightening burn (n520 ratchet: no commit
                # before a witness in source order).
                success = True

        # Refusal rows. ``denied:`` outcomes are lockout-neutral by
        # construction (login_guard._count_failures_since counts only
        # ``outcome = 'failure'``, and no guess was made).
        from email_triage.web.db import record_auth_event
        if success_failure is not None or success:
            pass  # a matched code: no refusal row (burned and re-raised, or the success transaction below)
        elif refusal == "not_found":
            safe_audit_write(
                lambda: record_auth_event(
                    db,
                    event_type="login_otp",
                    email=email,
                    user_id=None,
                    key_id=None,
                    ip=client_host,
                    user_agent=user_agent,
                    outcome="denied:user_not_found",
                ),
                description="auth_event login_otp outcome=denied:user_not_found",
            )
        elif refusal == "disabled":
            safe_audit_write(
                lambda: record_auth_event(
                    db,
                    event_type="login_otp",
                    email=email,
                    user_id=user_["id"],
                    key_id=None,
                    ip=client_host,
                    user_agent=user_agent,
                    outcome="denied:account_disabled",
                ),
                description="auth_event login_otp outcome=denied:account_disabled",
            )
        elif refusal == "mfa_required":
            safe_audit_write(
                lambda: record_auth_event(
                    db,
                    event_type="login_otp",
                    email=email,
                    user_id=user_["id"],
                    key_id=None,
                    ip=client_host,
                    user_agent=user_agent,
                    outcome="denied:mfa_required",
                ),
                description="auth_event login_otp outcome=denied:mfa_required",
            )
        else:
            #  — record the failure so the rolling window counts it.
            record_login_failure(
                db, surface="otp", email=email, ip=client_host,
                user_agent=user_agent, reason="invalid_code",
            )
        if success:
            def _login_state(c) -> bool:
                if not burn_otp_txn(c, otp_id):
                    return False  # a concurrent write spent it first
                update_last_login_txn(c, email)
                return True

            def _login_witness(c, ok: bool):
                # A lost race (ok=False) is witnessed in the same transaction
                # as a lockout-neutral ``denied:`` row: a second use of a spent
                # code may mean it was intercepted (§164.308(a)(5)(ii)(C)), so
                # it is never silent (a re-request is a harmless source of the
                # same row), and a correct code never counts toward
                # the lockout window. Concurrent race only: a later replay of a
                # spent code no longer matches and writes a counting failure row.
                if ok:
                    return record_auth_event_txn(
                        c, event_type="login_otp", email=email,
                        user_id=user_["id"], key_id=None, ip=client_host,
                        user_agent=user_agent, outcome="success",
                    )
                return record_auth_event_txn(
                    c, event_type="login_otp", email=email,
                    user_id=user_["id"], key_id=None, ip=client_host,
                    user_agent=user_agent, outcome="denied:otp_already_used",
                )

            # PR 9 / D4: append-only auth audit (auth_events is the historical
            # source of truth; last_login is the admin UI's display column).
            # hipaa-sme ruling 2026-11-06 (s2 N1 fold, option A, §164.312(d)):
            # ANY failure of the success transaction after the code matched (a
            # failed witness, a busy DB) burns the code in its own transaction
            # and re-raises at once (fail closed, no session). No refusal row is
            # written (the code was not wrong).
            try:
                won = record_witnessed_state_change(
                    db, operation="login_otp",
                    state_txn=_login_state,
                    witness_txn=_login_witness,
                )
            except Exception as exc:
                _burn_after_failure(exc)
                raise
            if won:
                return "ok", {"user": user_}
            # Lost the race: a concurrent write spent this code first:
            # another verify, a fresh OTP request (web/auth.py::store_otp)
            # or the expiry purge (web/auth.py::cleanup_expired_otps). The
            # witness above wrote the denied row; refuse as invalid.
            return refusal, {}
        # The TIGHTENING burn (an expired code, or a valid code that was
        # refused): its own transaction, never dependent on the row above,
        # so a probing attacker can't tell refusal reasons apart by retrying.
        # Also a valid code whose post-match reads failed (option A above).
        if otp_id is not None:
            if success_failure is None:
                burn_otp(db, otp_id)
            else:
                _burn_after_failure(success_failure)
        if success_failure is not None:
            raise success_failure
        return refusal, {}

    kind, payload = await db_call(_login_verify_db_work)
    if kind == "locked":
        retry_min = payload["retry_min"]
        return await _render(templates, request, "login.html", {
            "step": "verify", "email": email,
            "error": (
                f"Too many login attempts. Please try again in "
                f"{retry_min} minute{'s' if retry_min != 1 else ''}."
            ),
        })
    if kind == "invalid":
        return await _render(templates, request, "login.html", {
            "step": "verify", "email": email,
            "error": "Invalid or expired code. Please try again.",
        })
    if kind == "not_found":
        return await _render(templates, request, "login.html", {
            "step": "email", "error": "Account not found.",
        })
    if kind == "disabled":
        log = get_logger("web.auth")
        log.warning("Login blocked: user disabled", email=email)
        return await _render(templates, request, "login.html", {
            "step": "email",
            "error": "Account disabled. Contact admin.",
        })
    if kind == "mfa_required":
        # H-05 (Cycle 7) — HIPAA-mode MFA gate. User has registered
        # MFA credentials; OTP-only login is rejected. Redirect to
        # WebAuthn / passkey flow. No error-message disclosure of
        # the user's MFA enrollment state (prevents
        # enumerate-which-accounts-have-MFA probing).
        log = get_logger("web.auth")
        log.info(
            "OTP login refused: MFA required in HIPAA mode",
            email=email,
        )
        return RedirectResponse("/login/webauthn", status_code=303)

    user = payload["user"]

    # PR 10 / E — success-edge metric via the shared funnel (record_login_success).
    from email_triage.web.login_guard import record_login_success
    record_login_success(surface="otp")

    secret = get_session_secret(request)
    # H-05 (Cycle 7) — first-login bootstrap fix per DA-4 R-Surface-1
    # verify-don't-accept review 2026-05-24. If HIPAA mode is on
    # AND we reach this branch (NOT the mfa_required branch above),
    # the user has zero hardware_keys AND zero recovery_codes —
    # first-login bootstrap case per Q7 ("CLI operator-driven for
    # first admin + first-login automatic for subsequent users").
    # Stamp mfa_verified_at so require_auth doesn't infinite-loop
    # the user back to /login/webauthn when they have no passkey
    # to use. The OTP authentication IS the verified-identity proof
    # for the bootstrap window; the user can now reach
    # /profile/hardware-keys to enroll a passkey. record_auth_event
    # at the OTP-verify path already captures auth_source="otp"
    # for the audit-trail correlation.
    mfa_verified_at: int | None = None
    from email_triage.triage_logging import is_hipaa_mode
    if is_hipaa_mode():
        from email_triage.web.mfa import mfa_verified_now
        mfa_verified_at = mfa_verified_now()
    token = create_session_token(
        secret, email, user["role"],
        session_epoch=int(user.get("session_epoch", 0)),
        mfa_verified_at=mfa_verified_at,
    )
    response = RedirectResponse("/dashboard", status_code=303)
    # PR 8 / D1 follow-up: cookie max_age tracks the effective
    # session TTL (HIPAA-aware) so the browser drops the cookie at
    # the same moment the server stops accepting it.
    set_session_cookie(response, token, request.app.state.config, request=request)
    return response


@router.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, user: RequireUser):
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    templates = get_templates(request)
    users = await db_call(_users_page_snapshot, db)

    return await _render(templates, request, "users/manage.html", {
        "user": user,
        "users": users,
        "roles": [r.value for r in UserRole],
    })


@router.post("/users/create", response_class=HTMLResponse)
async def create_user(
    request: Request,
    email: str = Form(...),
    name: str = Form(...),
    role: str = Form("user"),
    notify_email: str = Form(""),
):
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    #  R32 DA-fold R1 — canonicalise on write to match the read-side
    # SSOT (canonical_email); idempotent for ASCII, A-label for IDN.
    from email_triage.mail_headers import canonical_email
    email = canonical_email(email)

    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))

    def _create_user_snapshot(db, email, name, role, notify_email, actor, client_host):
        """ phase 2 — insert + witness + commit in one hop.

        Returns "ok" | "active_dup" | "disabled_dup". A "removed" (offboarded)
        user is soft-disabled, not deleted, so its email lingers —
        distinguish that from a live duplicate so the admin gets an actionable
        recovery path (re-enable) instead of a bare "already exists" (R2).

        Punch 668: creating a user is the root access grant (§164.312(b)). The
        row and its user_created witness commit together in record_user_creation
        (fail closed). There is no route pre-check: the users.email UNIQUE is
        the one duplicate detector, and a duplicate comes back as USER_DUPLICATE,
        already witnessed (``denied:duplicate_email``); the SELECT below only
        picks the message for it.
        """
        created = record_user_creation(
            db, email=email, name=name, role=role,
            notify_email=notify_email or None,
            actor_user_id=actor["id"], actor_email=actor.get("email") or "",
            ip=client_host, source="ui",
        )
        if isinstance(created, GrantRefused):
            row = db.execute(
                "SELECT disabled FROM users WHERE email = ?", (email,)
            ).fetchone()
            return "disabled_dup" if (row and row["disabled"]) else "active_dup"
        return "ok"

    result = await db_call(
        _create_user_snapshot, db, email, name, role, notify_email, user,
        client_host,
    )
    if result == "disabled_dup":
        return HTMLResponse(
            '<p class="error">That email belongs to a <strong>removed (disabled)</strong> '
            'user. User records are retained for the audit trail and are never deleted — '
            '<strong>re-enable</strong> them from the user list to restore the account, or '
            'use a different address.</p>',
            status_code=409,
        )
    if result == "active_dup":
        return HTMLResponse(
            '<p class="error">A user with that email already exists.</p>',
            status_code=409,
        )

    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/update", response_class=HTMLResponse)
async def update_user(
    request: Request,
    user_id: int,
    email: str = Form(""),
    name: str = Form(...),
    role: str = Form(...),
    notify_email: str = Form(""),
):
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    client_host = audit_forwarded_for(request).host or None  # N-337 SSOT (§164.312(b))

    # Punch 674: the funnel refuses a role outside UserRole (fail closed);
    # answer that as a form error here instead of a 500.
    if role not in {r.value for r in UserRole}:
        return HTMLResponse('<p class="error">Invalid role.</p>', status_code=400)

    def _update_user_snapshot(db, user_id, email, name, role, notify_email,
                              actor, client_host):
        """ phase 2 — conflict check + update + commit in one hop.

         R32 DA-fold R1 — canonicalise the email before the conflict
        SELECT + INSERT so all three sides (dup-check, WHERE, stored form)
        share one normalisation (canonical_email SSOT).

        Punch 674: the UPDATE and, on a role or login-email change, its
        chained user_role_changed / user_email_changed witness commit
        together in record_user_update (fail closed; panel Z MUST-Z1-1). It also carries the N-238 R24 session_epoch bump
        (§164.312(a)(2)(iii): a demoted admin's live cookie loses authority
        immediately). Returns "ok" | "dup" | "not_found".
        """
        if email:
            from email_triage.mail_headers import canonical_email
            email = canonical_email(email)
            existing = db.execute(
                "SELECT id FROM users WHERE email = ? AND id != ?",
                (email, user_id),
            ).fetchone()
            if existing:
                return "dup"
        found = record_user_update(
            db, user_id=user_id, name=name, role=role, email=email or None,
            notify_email=notify_email or "",
            actor_user_id=actor["id"], actor_email=actor.get("email") or "",
            ip=client_host, source="ui",
        )
        return "ok" if found else "not_found"

    result = await db_call(
        _update_user_snapshot, db, user_id, email, name, role, notify_email,
        user, client_host,
    )
    if result == "not_found":
        return HTMLResponse('<p class="error">User not found.</p>', status_code=404)
    if result == "dup":
        return HTMLResponse(
            '<p class="error">A user with that email already exists.</p>',
            status_code=409,
        )

    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/delete", response_class=HTMLResponse)
async def delete_user(
    request: Request,
    user_id: int,
):
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)

    def _delete_user_preflight(db, user_id, current_email):
        """ phase 2 — self-delete check + account_id enumeration.

        Returns (False, []) on self-delete (refuse).
        Returns (True, [account_id, ...]) on success — account IDs are
        collected BEFORE the user row is deleted so the funnel can purge
        watcher/secrets state; the actual DELETE happens in the async
        caller after the funnel runs.
        """
        target = db.execute(
            "SELECT email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if target and target["email"] == current_email:
            return False, []
        # Enumerate account_ids NOW (before the row is gone).
        from email_triage.db.accounts import list_email_accounts
        accounts = list_email_accounts(db, user_id=user_id, include_delegated=False)
        account_ids = [a["id"] for a in accounts]
        return True, account_ids

    ok, account_ids = await db_call(
        _delete_user_preflight, db, user_id, user["email"],
    )
    if not ok:
        return HTMLResponse(
            '<p class="error">Cannot delete your own account.</p>',
            status_code=400,
        )

    # L1 + L2 — purge watcher/secrets for EACH account owned by this user
    # BEFORE offboarding the user. Nothing cascades: the user and the accounts
    # are deactivated, never deleted, so
    # this purge is the only disposal of settings, secrets and the PHI-derived
    # style rows, and the watcher manager has no FK awareness. Fail CLOSED: if
    # ANY account's purge raises, do NOT delete the user — that would orphan
    # that account's credentials (§164.310(d)(2)(i)); the operator retries. Watcher-stop is
    # best-effort inside the funnel, so only a real purge failure trips this.
    from email_triage.db.accounts import purge_account_local_state
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)
    for acct_id in account_ids:
        try:
            if watcher_mgr is not None:
                await watcher_mgr.apply_account_deleted(
                    acct_id, actor_user_id=user["id"],
                )
            else:
                secrets = getattr(request.app.state, "secrets", None)
                await db_call(purge_account_local_state, db, acct_id, secrets)
        except Exception as _e:
            _log.error(
                "delete_user: local-state purge FAILED for account — aborting "
                "user delete to avoid orphaning stored credentials",
                user_id=user_id,
                account_id=acct_id,
                error=fmt_exc(_e),
            )
            return HTMLResponse(
                "Delete failed: an account's stored credentials could not be "
                "purged. The user was NOT deleted — please retry.",
                status_code=500,
            )

    def _offboard_user(db, user_id, account_ids, actor_user_id):
        """Offboard — NEVER hard-delete (operator ruling 2026-06-19, ).

        A ``DELETE FROM users`` would (a) NULL the actor link across the 9
        tamper-evident audit tables (their actor FK is ON DELETE SET NULL,
        breaking the §164.312(c)(1) verify chain) AND (b) cascade-delete each
        account's ``hipaa_access_events`` (``account_id`` is ON DELETE CASCADE)
        — wiping the §164.312(b) PHI-access trail. So we SOFT-DISABLE the user
        and DEACTIVATE (not delete) the accounts; credentials are already purged
        above. The user + account rows + all audit history are retained.

        NOTE: the direct account-delete actuator now ALSO soft-deactivates
        (operator ruled 2026-06-20: never delete accounts either — N-108), so
        BOTH the user and account offboard legs preserve the audit trail.
        """
        # N-520 step 2: each deactivation commits with its own witness row.
        from email_triage.db.audit import record_user_offboard
        record_user_offboard(
            db, user_id=user_id, account_ids=list(account_ids),
            actor_user_id=actor_user_id,
            reason="offboarded via admin Remove (soft-disable; row retained for audit)",
        )
        return True

    await db_call(_offboard_user, db, user_id, account_ids, user["id"])

    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/disable", response_class=HTMLResponse)
async def disable_user(
    request: Request,
    user_id: int,
    reason: str = Form(""),
):
    """Disable a user — fail-closed kill switch.

    Admin-only. Self-disable is refused (don't lock the admin out of
    their own console). Flipping the flag is atomic with the audit-row
    write; on success any running IMAP-IDLE watchers for the user's
    accounts are stopped immediately.
    """
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)

    if user_id == user["id"]:
        return HTMLResponse(
            '<p class="error">Cannot disable your own account.</p>',
            status_code=400,
        )

    from email_triage.web.db import set_user_disabled

    def _disable_user_snapshot(db, user_id, actor_user_id, reason):
        """ phase 2 — target check + disable + audit row in one hop."""
        target = db.execute(
            "SELECT id, email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if target is None:
            return None, False
        changed = set_user_disabled(
            db, user_id, True, actor_user_id=actor_user_id, reason=reason or "",
        )
        return dict(target), changed

    target, changed = await db_call(
        _disable_user_snapshot, db, user_id, user["id"], reason,
    )
    if target is None:
        return HTMLResponse("User not found", status_code=404)

    if changed:
        # Tear down any running watchers for this user (keeps the
        # persisted watch:<id> preference so re-enable restores).
        try:
            from email_triage.web.app import get_watcher_manager
            mgr = get_watcher_manager(request)
            await mgr.stop_for_user(user_id)
        except Exception as e:
            _log.warning("Failed to stop watchers for disabled user",
                         user_id=user_id, error=fmt_exc(e))
        _log.warning(
            "User disabled",
            actor=user["email"], target=target["email"], reason=reason or "",
        )

    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/enable", response_class=HTMLResponse)
async def enable_user(
    request: Request,
    user_id: int,
    reason: str = Form(""),
):
    """Re-enable a previously disabled user.

    Admin-only. The user's persisted watcher preferences are untouched
    by disable, so re-enabling does not by itself restart watchers —
    the user (or admin) re-flips the watch toggle on the account page.
    Kept explicit: we'd rather an admin reconfirm push wiring than
    silently resume it.
    """
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)

    from email_triage.web.db import set_user_disabled

    def _enable_user_snapshot(db, user_id, actor_user_id, reason):
        """ phase 2 — target check + enable + audit row in one hop."""
        target = db.execute(
            "SELECT id, email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if target is None:
            return None, False
        changed = set_user_disabled(
            db, user_id, False, actor_user_id=actor_user_id, reason=reason or "",
        )
        return dict(target), changed

    target, changed = await db_call(
        _enable_user_snapshot, db, user_id, user["id"], reason,
    )
    if target is None:
        return HTMLResponse("User not found", status_code=404)

    if changed:
        _log.info(
            "User re-enabled",
            actor=user["email"], target=target["email"], reason=reason or "",
        )

    return RedirectResponse("/users", status_code=303)


# ---------------------------------------------------------------------------
# Classification lists
# ---------------------------------------------------------------------------

