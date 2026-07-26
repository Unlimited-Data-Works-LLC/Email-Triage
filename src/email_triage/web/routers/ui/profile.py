"""Routes for the profile concern.

Split out of the legacy `web/routers/ui.py`. Helpers
live in `_shared`; this file holds only the @router-decorated
handlers + handler-local helpers for this URL surface.
No behavior changes from pre-split — every handler body is
byte-for-byte identical.
"""
from __future__ import annotations

import asyncio
import base64
import email as email_mod
import email.policy
import email.utils
import html as _html
import os
import sqlite3
import time
from datetime import datetime, timezone
from email_triage._isotime import now_utc_iso, to_utc_iso
from typing import Any
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.db._helpers import load_json_col
from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_manage_account
from email_triage.web.account_scope import (
    filter_to_manageable,
    filter_to_manageable_accounts,
    intersect_ids,
    is_manageable,
    manageable_account_ids as _manageable_account_ids,
    manageable_accounts as _manageable_accounts,
)
from email_triage.web._resource_authz import can_modify_owned_resource
from email_triage.web.routers._redirect import msg_qs, read_flash
from email_triage.web import settings_keys as _S
from email_triage.web.app import get_config, get_db, get_secrets, get_templates
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    generate_otp,
    get_user_by_email,
    send_otp_email,
    store_otp,
    update_last_login,
    verify_otp,
)
from email_triage.web.db_threadpool import db_call
from email_triage.web.db_writelock import get_write_lock
from email_triage.web.dependencies import (
    is_admin as _is_admin,  # N-222h R22 SSOT alias (local `is_admin` shadows callable)
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    RequireUser,
    RequireUserFragment,
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage._envbool import parse_bool
from email_triage.secrets import SecretsDecryptError, read_secret
from email_triage.triage_logging import REDACTED_PLACEHOLDER, get_logger, is_account_hipaa  # N-226 R22 HIPAA-fold SSOT
from email_triage._errfmt import fmt_exc, scrub_class_error_for_persist, scrub_error_for_persist
from email_triage._secret_keys import SMTP_PASSWORD_KEY  # N-231 R22 stored-secret-key SSOT
from email_triage._int_utils import bounded_int, parse_int_or_none  # N-219c R23

_log = get_logger("web.ui.profile")

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


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, user: RequireUser):
    """User settings page — notify address + per-category escalation."""
    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.sms_carriers import US_CELL_CARRIERS

    snap = await db_call(_profile_page_snapshot, db, user)
    #  — the topic-digest tab pane lands on the master card list.
    # Card summaries are mailbox-count-scoped to the requester's
    # MANAGEABLE set (never names an account they can't manage).
    topics = await db_call(_topic_digest_cards_snapshot, db, user)

    return await _render(templates, request, "profile.html", {
        "user": user,
        "current_user": user,
        "categories": snap["categories"],
        "personal_categories": snap["personal_categories"],
        "personal_cap": snap["personal_cap"],
        "escalation_categories": snap["escalation_categories"],
        "meeting_prefs": snap["meeting_prefs"],
        "ordered_zones": _ordered_timezones(),
        "sms_carriers": US_CELL_CARRIERS,
        "sms_prefs": snap["sms_prefs"],
        "save_msg": None,
        "active_tab": _resolve_profile_tab(request),
        #  master card-list — rendered by profile/_topic_digest.html.
        "topics": topics,
        **snap["writing_ctx"],
    })


@router.post("/profile/sign-out-all")
async def profile_sign_out_all(request: Request, user: RequireUser):
    """ — revoke every session for the current user.

    Bumps ``users.session_epoch``; every outstanding session token —
    including the cookie making this request — carries an older epoch
    and is rejected by :func:`dependencies.get_current_user` on its
    next use. Drops the current cookie and redirects to /login. Use
    this if a device or a copied session is suspected compromised:
    ``/logout`` only clears one cookie, this kills them all.
    """
    from email_triage.web.db import bump_session_epoch
    db = get_db(request)
    await db_call(bump_session_epoch, db, int(user["id"]))
    log.info(
        "All sessions revoked via sign-out-all",
        user_id=user.get("id"), email=user.get("email"),
    )
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


@router.get("/profile/security", response_class=HTMLResponse)
async def profile_security_page(request: Request, user: RequireUser):
    """Consolidated "Security" tab — sign out all sessions, hardware
    keys (passkeys), and API access tokens in one place.

    Replaces three scattered surfaces (2026-06-07): the page-header
    "Sign out all sessions" button that used to render on every My
    Settings tab, plus the standalone /profile/hardware-keys and
    /accounts/api-keys pages (both now 303-redirect here). The
    ``?owner_filter=`` query param drives the admin hardware-key
    owner filter, same as the old hardware-keys page.
    """
    db = get_db(request)
    templates = get_templates(request)
    owner_filter = request.query_params.get("owner_filter") or ""
    hw_snap = await db_call(
        _hardware_keys_page_snapshot, db, user, owner_filter,
    )
    api_snap = await db_call(_api_keys_page_snapshot, db, user)
    return await _render(templates, request, "profile/security.html", {
        "user": user,
        "current_user": user,
        "hw_keys": hw_snap["keys"],
        "hw_visible_owners": hw_snap["visible_owners"],
        "hw_owner_filter": hw_snap["owner_filter"],
        "api_keys": api_snap["keys"],
        "api_all_users": api_snap["all_users"],
        "is_admin": hw_snap["is_admin"],
    })


@router.post("/profile/save", response_class=HTMLResponse)
async def profile_save(request: Request, user: RequireUser):
    """Save user settings (notify address + escalation prefs).

     — primary path is the carrier dropdown + cell number, which
    computes the email-to-SMS gateway address and writes it into
    ``users.notify_email``. Free-text ``notify_email`` field stays as
    an Advanced override for non-SMS recipients.
    """
    db = get_db(request)
    templates = get_templates(request)
    form = await request.form()

    from email_triage.web.db import (
        list_categories, set_user_escalation_categories,
        get_user_escalation_categories,
        get_setting, set_setting, delete_setting,
        MAX_PERSONAL_CATEGORIES_PER_USER,
    )
    from email_triage.web.sms_carriers import (
        US_CELL_CARRIERS, build_sms_address, normalize_us_cell_number,
    )

    sms_number_raw = (form.get("sms_number") or "").strip()
    sms_carrier = (form.get("sms_carrier") or "").strip()
    notify_email_free = (form.get("notify_email") or "").strip()

    #  — render-state reads (categories ×2, meeting prefs, the
    # writing-tab context) all touch the shared connection. Dispatch
    # them through one db_call hop so none run on the event-loop thread.
    def _profile_save_render_reads() -> dict:
        return {
            "categories": list_categories(db, user_id=user["id"]),
            "personal_categories": list_categories(
                db, user_id=user["id"], scope="personal",
            ),
            "meeting_prefs": _load_meeting_prefs_with_default_tz(
                db, user["id"],
            ),
            "writing_ctx": _writing_tab_context(db, user),
        }

    _reads = await db_call(_profile_save_render_reads)
    categories = _reads["categories"]
    personal_categories = _reads["personal_categories"]
    meeting_prefs = _reads["meeting_prefs"]
    writing_ctx = _reads["writing_ctx"]

    # Thread the form-submitted tab back into the re-render so the
    # operator stays on the tab they saved from. profile.html's
    # hidden ``active_tab`` field is the source of truth post-POST
    # (query params are empty after form submit).
    active_tab = _resolve_profile_tab(request, form)

    async def _re_render(*, save_msg: str | None, error: str | None,
                         sms_prefs: dict, escalation: set[str]) -> HTMLResponse:
        #  / Option B — async because the shared `_render` is async.
        return await _render(templates, request, "profile.html", {
            "user": user,
            "current_user": user,
            "categories": categories,
            "personal_categories": personal_categories,
            "personal_cap": MAX_PERSONAL_CATEGORIES_PER_USER,
            "escalation_categories": escalation,
            "meeting_prefs": meeting_prefs,
            "ordered_zones": _ordered_timezones(),
            "sms_carriers": US_CELL_CARRIERS,
            "sms_prefs": sms_prefs,
            "save_msg": save_msg,
            "error": error,
            "active_tab": active_tab,
            **writing_ctx,
        })

    notify_email: str | None = None
    sms_prefs: dict = {}

    if sms_number_raw and sms_carrier:
        norm = normalize_us_cell_number(sms_number_raw)
        if norm is None:
            escalation = await db_call(
                get_user_escalation_categories, db, user["id"],
            )
            return await _re_render(
                save_msg=None,
                error="Cell number must be a 10-digit US number "
                      "(11 digits OK if it starts with 1).",
                sms_prefs={"number": sms_number_raw, "carrier": sms_carrier},
                escalation=escalation,
            )
        addr = build_sms_address(norm, sms_carrier)
        if addr is None:
            escalation = await db_call(
                get_user_escalation_categories, db, user["id"],
            )
            return await _re_render(
                save_msg=None,
                error=f"Unknown carrier: {sms_carrier!r}.",
                sms_prefs={"number": sms_number_raw, "carrier": sms_carrier},
                escalation=escalation,
            )
        notify_email = addr
        sms_prefs = {"number": norm, "carrier": sms_carrier}
    elif notify_email_free:
        notify_email = notify_email_free
    else:
        notify_email = None

    # Build escalation categories from the form checkboxes.
    selected = []
    for cat in categories:
        slug = cat["slug"]
        if f"escalate_{slug}" in form:
            selected.append(slug)
    escalation_categories = set(selected)

    #  — fold every write (escalation-SMS setting, the raw
    # users.notify_email UPDATE, escalation-categories save) into one
    # threadpool hop so none of it — nor the  lock acquisition —
    # runs on the event-loop thread.
    def _profile_save_writes() -> None:
        if sms_number_raw and sms_carrier:
            set_setting(db, _S.escalation_sms(user["id"]), sms_prefs)
        else:
            # Free-text override or both-empty: clear any prior SMS
            # dropdown choice so the form doesn't render a stale
            # carrier on revisit.
            delete_setting(db, _S.escalation_sms(user["id"]))
        # Raw write on the shared connection — runs under the DB lock
        # held by db_call for the whole closure.
        db.execute(
            "UPDATE users SET notify_email = ? WHERE id = ?",
            (notify_email, user["id"]),
        )
        db.commit()
        set_user_escalation_categories(db, user["id"], selected)

    await db_call(_profile_save_writes)
    user = dict(user)
    user["notify_email"] = notify_email

    msg = "Settings saved."
    if selected and notify_email:
        msg += f" Escalation active for: {', '.join(selected)}"
    elif selected and not notify_email:
        msg += " Warning: escalation categories selected but no notify address set."

    _log.info(
        "User settings saved",
        user=user["email"],
        escalation_categories=selected,
        notify_email=notify_email or "(none)",
        sms_carrier=sms_prefs.get("carrier") or "(none)",
    )

    return await _re_render(
        save_msg=msg, error=None,
        sms_prefs=sms_prefs, escalation=escalation_categories,
    )


# ---------------------------------------------------------------------------
# the backlog  — "Test Now" button on /profile?tab=notifications
#
# Operator sets cell + carrier (or free-text notify_email), flips one or
# more Escalation Categories on, then taps Test Now to fire a single
# fixed-text message through the same SMTP path the real escalation
# uses. Surfaces wiring problems (wrong carrier, cell typo, blocked
# relay) BEFORE waiting for an actual urgent email.
#
# Rate-limit: 1 test send per minute per user, in-process dict on
# app.state. Single-process only — when this scales horizontally the
# limiter becomes Redis-backed (same surface as ratelimit.py). The
# dict isn't lock-protected; the worst race outcome is two near-
# simultaneous test sends from one user, which costs at most one
# extra SMS — acceptable for a manual diagnostic surface.
# ---------------------------------------------------------------------------

# (user_id -> last_send_monotonic) for the rate-limiter. Lazily
# attached to app.state on first POST so we don't have to mutate the
# app factory.
@router.post(
    "/profile/escalation-test-send", response_class=HTMLResponse,
)
async def profile_escalation_test_send(request: Request, user: RequireUser):
    """Fire a single fixed-text test message through the live
    escalation send path so the operator can verify wiring before
    waiting on a real urgent email.

    No PHI is ever included — the body is a synthetic constant.
    Audit row written to ``auth_events`` (event_type
    ``escalation_test``) with the resolved gateway address in
    ``detail`` (NOT the body).
    """
    db = get_db(request)
    is_htmx = _shared.is_htmx(request)

    from email_triage.web.db import (
        get_user_escalation_categories,
        list_categories,
        record_auth_event,
    )

    # Defense-in-depth: button shouldn't render without a notify
    # address, but a direct POST must still fail soft.
    notify_email = (user.get("notify_email") or "").strip()
    if not notify_email:
        #  — record_auth_event is @db_write; off-loop hop.
        await db_call(
            record_auth_event,
            db,
            event_type="escalation_test",
            email=user["email"],
            user_id=user["id"],
            outcome="failure",
            detail='{"reason":"no_address"}',
        )
        return HTMLResponse(
            _test_send_chip_html(state="no_address"),
            status_code=200,
        )

    # Pick the lowest-impact escalate-eligible category. ``sort_order``
    # ascends with priority — earlier slugs are more critical
    # (action-required, to-respond …); larger sort_order = lower
    # impact. Using a category the user has actually flagged means the
    # synthetic alert text matches what they'd see in production, so
    # the test exercises the same _build_notification branch.
    #  — get_user_escalation_categories touches the shared
    # connection; dispatch off the event-loop thread.
    selected = await db_call(get_user_escalation_categories, db, user["id"])
    if not selected:
        await db_call(
            record_auth_event,
            db,
            event_type="escalation_test",
            email=user["email"],
            user_id=user["id"],
            outcome="failure",
            detail='{"reason":"no_category"}',
        )
        return HTMLResponse(
            _test_send_chip_html(state="no_category"),
            status_code=200,
        )

    cats = await db_call(list_categories, db, user_id=user["id"])
    # Highest sort_order among the user's escalation set = lowest
    # impact. Fall back to the last selected slug if no row matches.
    eligible = [c for c in cats if c["slug"] in selected]
    if eligible:
        synthetic_category = max(
            eligible, key=lambda c: c.get("sort_order", 0),
        )["slug"]
    else:
        synthetic_category = sorted(selected)[-1]

    # Per-user rate-limit: 1/min. Single-process in-memory dict on
    # app.state — see the comment above this handler block.
    state = request.app.state
    bucket: dict[int, float] = getattr(state, _ESCALATION_TEST_RL_KEY, None)
    if bucket is None:
        bucket = {}
        setattr(state, _ESCALATION_TEST_RL_KEY, bucket)
    now_mono = time.monotonic()
    last = bucket.get(user["id"], 0.0)
    if last and (now_mono - last) < _ESCALATION_TEST_RL_WINDOW_SEC:
        await db_call(
            record_auth_event,
            db,
            event_type="escalation_test",
            email=user["email"],
            user_id=user["id"],
            outcome="failure",
            detail='{"reason":"rate_limit"}',
        )
        return HTMLResponse(
            _test_send_chip_html(state="rate_limit"),
            status_code=200,
        )

    # Fixed synthetic body — never carries PHI. The HH:MM:SS suffix
    # makes repeated test sends distinguishable on the recipient
    # device. ``datetime.now()`` (no tz) gives the host's local time,
    # which matches the chip text we render below.
    now_local = datetime.now()
    when_local = now_local.strftime("%H:%M:%S")
    body_text = f"email-triage test send — {when_local}"
    subject = "[email-triage] Test send"

    # SMTP config + secrets from app.state (same wiring escalate.py
    # gets via flow.state_bag).
    cfg = state.config
    secrets = getattr(state, "secrets", None)
    smtp = getattr(cfg, "smtp", None)

    if smtp is None or not getattr(smtp, "host", ""):
        # Mirror the escalate-action's "smtp not configured" path. The
        # operator-visible chip says "sender rejected" because to a
        # non-developer the result is identical: nothing arrived.
        await db_call(
            record_auth_event,
            db,
            event_type="escalation_test",
            email=user["email"],
            user_id=user["id"],
            outcome="failure",
            detail=(
                f'{{"gateway_address":"{notify_email}",'
                f'"error":"smtp not configured"}}'
            ),
        )
        return HTMLResponse(
            _test_send_chip_html(
                state="error", error="not configured on this server",
            ),
            status_code=200,
        )

    smtp_password = ""
    if secrets is not None:
        try:
            smtp_password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
        except SecretsDecryptError:
            # A5 — fail closed + diagnose distinctly: an unreadable secret
            # store (master-key mismatch) is not "no password configured".
            _log.error("SMTP test aborted — password unreadable (corrupt "
                       "secret row or master-key mismatch)")
            return HTMLResponse(
                _test_send_chip_html(
                    state="error",
                    error="secret store unreadable (master-key mismatch)",
                ),
                status_code=200,
            )

    # Send. Errors propagate as smtplib.SMTPException (or generic
    # OSError on connection failure) — the failure chip + audit row
    # both record the truncated message. Don't swallow the error
    # silently; we want the operator to see what the relay said.
    import json as _json
    from email_triage.web.smtp_send import send_simple_smtp_email
    try:
        # smtplib is blocking — run it off the event loop.
        await asyncio.to_thread(
            send_simple_smtp_email,
            smtp_host=smtp.host,
            smtp_port=smtp.port,
            smtp_user=smtp.username,
            smtp_password=smtp_password,
            from_addr=smtp.from_addr,
            to_addr=notify_email,
            subject=subject,
            body=body_text,
            use_tls=smtp.use_tls,
            from_name=smtp.from_name,
            triage_source="escalation_test",
        )
    except Exception as e:
        err_str = scrub_class_error_for_persist(e)
        await db_call(
            record_auth_event,
            db,
            event_type="escalation_test",
            email=user["email"],
            user_id=user["id"],
            outcome="failure",
            detail=_json.dumps({
                "gateway_address": notify_email,
                "category": synthetic_category,
                "error": err_str,
            }),
        )
        _log.warning(
            "Escalation test send failed",
            user=user["email"],
            error=err_str,
        )
        return HTMLResponse(
            _test_send_chip_html(state="error", error=err_str),
            status_code=200,
        )

    # Success — only update the rate-limiter on a successful send so a
    # transient SMTP failure doesn't lock the operator out for a minute.
    bucket[user["id"]] = now_mono

    await db_call(
        record_auth_event,
        db,
        event_type="escalation_test",
        email=user["email"],
        user_id=user["id"],
        outcome="success",
        detail=_json.dumps({
            "gateway_address": notify_email,
            "category": synthetic_category,
        }),
    )
    _log.info(
        "Escalation test send",
        user=user["email"],
        gateway=notify_email,
    )

    chip = _test_send_chip_html(state="ok", when_local=when_local)
    if is_htmx:
        return HTMLResponse(chip, status_code=200)
    # Non-HTMX direct POST (rare; CLI / curl) — 303 back to the
    # notifications tab so the GET handler re-renders the form.
    return RedirectResponse(
        "/profile?tab=notifications", status_code=303,
    )


@router.post("/profile/writing/save", response_class=HTMLResponse)
async def profile_writing_save(request: Request, user: RequireUser):
    """Save the per-user writing-style knobs (M-1 + M-2).

    Tone / length / greeting are validated against the canonical
    allowlists; any value outside those sets is replaced with the
    column default rather than rejecting the whole save (the form
    radio groups make invalid values impossible from the UI, but
    a hand-crafted POST should still produce a coherent stored
    state). Free-text fields are length-capped before the DB write.
    """
    db = get_db(request)
    form = await request.form()

    from email_triage.web.db import (
        ANTI_AI_STYLE_GUIDE_MAX_LEN,
        set_user_anti_ai_style_guide,
        set_user_style_knobs,
        STYLE_TONE_CHOICES, STYLE_LENGTH_CHOICES, STYLE_GREETING_CHOICES,
        STYLE_KNOB_DEFAULTS,
    )

    def _validated(name: str, choices: tuple[str, ...]) -> str:
        raw = (form.get(name) or "").strip()
        if raw in choices:
            return raw
        return STYLE_KNOB_DEFAULTS[name]

    knobs = {
        "style_tone":            _validated("style_tone", STYLE_TONE_CHOICES),
        "style_length":          _validated("style_length", STYLE_LENGTH_CHOICES),
        "style_greeting":        _validated("style_greeting", STYLE_GREETING_CHOICES),
        # Free-text fields: trim whitespace + length-cap so a malicious
        # 1MB POST can't stuff the DB.
        "style_signature":       (form.get("style_signature") or "").strip()[:200],
        "style_greeting_custom": (form.get("style_greeting_custom") or "").strip()[:120],
        "style_guide":           (form.get("style_guide") or "").strip()[:2000],
    }
    # Anti-AI style guide (per-user override + disable-global flag).
    # Cap length defensively so a hand-crafted 1MB POST can't stuff the
    # DB even though the UI textarea sets ``maxlength`` server-side.
    anti_ai_user_text = (
        form.get("anti_ai_style_guide_user") or ""
    ).strip()[:ANTI_AI_STYLE_GUIDE_MAX_LEN]
    anti_ai_disable_global = parse_bool(
        form.get("anti_ai_style_guide_disable_global")
    )

    #  — both writes are @db_write helpers; fold them into one
    # threadpool hop so neither runs (nor locks) on the loop thread.
    def _writing_save_db_work() -> None:
        set_user_style_knobs(db, user["id"], knobs)
        set_user_anti_ai_style_guide(
            db, user["id"],
            text=anti_ai_user_text,
            disable_global=anti_ai_disable_global,
        )

    await db_call(_writing_save_db_work)

    _log.info(
        "User writing knobs saved",
        user=user["email"],
        tone=knobs["style_tone"],
        length=knobs["style_length"],
        greeting=knobs["style_greeting"],
        guide_len=len(knobs["style_guide"]),
        signature_set=bool(knobs["style_signature"]),
        anti_ai_user_len=len(anti_ai_user_text),
        anti_ai_disable_global=anti_ai_disable_global,
    )

    # PRG redirect back to the Writing tab so a refresh doesn't re-POST.
    return RedirectResponse("/profile?tab=writing", status_code=303)


@router.post("/profile/meeting-prefs", response_class=HTMLResponse)
async def profile_meeting_prefs_save(request: Request, user: RequireUser):
    """Save the per-user meeting-request intercept preferences."""
    db = get_db(request)
    form = await request.form()

    from email_triage.engine.models import (
        MeetingPreferences, OutOfOfficeOverride, WorkingHours,
    )
    from email_triage.web.db import set_meeting_prefs

    #  — request ints via the _safe_int SSOT (non-numeric => default, never
    # a 500). Each preserves its prior default (the try/except fell back to the
    # same value as the .get default), and the surrounding clamp is unchanged.
    length = _safe_int(form.get("default_length_minutes"), 30)
    if length not in (15, 30, 45, 60, 90, 120):
        # Constrain to the dropdown's allowed values.
        length = 30
    count = max(1, min(5, _safe_int(form.get("suggestion_count"), 3)))
    # 2026-05-14 — "over Number of Days" knob. Bounded 1..14 to match
    # MeetingPreferences.from_dict; values outside that range collapse
    # to the default 5.
    days = max(1, min(14, _safe_int(form.get("suggestion_days"), 5)))
    horizon = max(1, min(60, _safe_int(form.get("search_horizon_days"), 14)))
    lead = max(0, _safe_int(form.get("minimum_lead_time_hours"), 24))

    # Collect per-weekday working hours from the matrix.
    wh = WorkingHours(mon=[], tue=[], wed=[], thu=[], fri=[], sat=[], sun=[])
    for day in ("mon", "tue", "wed", "thu", "fri", "sat", "sun"):
        intervals: list[tuple[str, str]] = []
        for slot in (0, 1):
            s = (form.get(f"wh_{day}_start_{slot}") or "").strip()
            e = (form.get(f"wh_{day}_end_{slot}") or "").strip()
            if s and e and s < e:
                intervals.append((s, e))
        setattr(wh, day, intervals)

    # OOO override.
    ooo = OutOfOfficeOverride(enabled=("ooo_enabled" in form))
    ooo.note = (form.get("ooo_note") or "").strip()
    for key, attr in (("ooo_start", "start"), ("ooo_end", "end")):
        v = (form.get(key) or "").strip()
        if v:
            # N-269d R28: parse_iso_aware handles Z-form natively + returns
            # None on failure (datetime-local form fields lack a tz; treat
            # as UTC). N-357 R31 (2026-07-05 SSOT collapse): was 4 lines
            # of parse + None-guard + tzinfo-assume; now one call.
            from email_triage._isotime import parse_iso_aware
            dt = parse_iso_aware(v)
            if dt is not None:
                setattr(ooo, attr, dt)

    prefs = MeetingPreferences(
        default_length_minutes=length,
        suggestion_count=count,
        suggestion_days=days,
        business_hours_start=(form.get("business_hours_start") or "09:00").strip(),
        business_hours_end=(form.get("business_hours_end") or "17:00").strip(),
        skip_weekends=("skip_weekends" in form),
        search_horizon_days=horizon,
        minimum_lead_time_hours=lead,
        timezone=(form.get("timezone") or "UTC").strip() or "UTC",
        working_hours=wh,
        ooo_override=ooo,
    )
    #  — set_meeting_prefs touches the shared connection; dispatch
    # it off the event-loop thread.
    await db_call(set_meeting_prefs, db, user["id"], prefs.to_dict())

    # 303-redirect to the GET so the page reloads on the same tab the
    # operator submitted from. profile_page's tab resolver reads from
    # ?tab=<slug>; profile.html's hidden ``active_tab`` field carries
    # the value through the form. Without this redirect the
    # post-POST re-render would default to "notifications".
    active_tab = _resolve_profile_tab(request, form)
    return RedirectResponse(
        f"/profile?tab={active_tab}", status_code=303,
    )


@router.post("/profile/meeting-prefs/group-apply", response_class=HTMLResponse)
async def profile_meeting_prefs_group_apply(request: Request, user: RequireUser):
    """Apply one start/end pair to all weekdays / weekend / all days.

    Overwrites the first interval of each affected day and clears any
    second interval (the user can re-add lunch breaks per-day).
    """
    db = get_db(request)
    form = await request.form()
    scope = (form.get("scope") or "weekdays").strip()
    start = (form.get("start") or "").strip()
    end = (form.get("end") or "").strip()

    from email_triage.engine.models import MeetingPreferences
    from email_triage.web.db import get_meeting_prefs, set_meeting_prefs

    if scope == "weekend":
        days = ("sat", "sun")
    elif scope == "all":
        days = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    else:  # weekdays (default)
        days = ("mon", "tue", "wed", "thu", "fri")

    #  — read-modify-write the meeting prefs in one threadpool hop
    # so neither the get nor the set touches the event-loop thread.
    def _group_apply_db_work() -> None:
        prefs = MeetingPreferences.from_dict(get_meeting_prefs(db, user["id"]))
        if start and end and start < end:
            for day in days:
                setattr(prefs.working_hours, day, [(start, end)])
        elif not start and not end:
            # Both blank → mark scope as off.
            for day in days:
                setattr(prefs.working_hours, day, [])
        set_meeting_prefs(db, user["id"], prefs.to_dict())

    await db_call(_group_apply_db_work)
    # 303-redirect mirrors profile_meeting_prefs_save — keeps the
    # operator on the Meetings tab they just edited rather than
    # bouncing to "notifications".
    active_tab = _resolve_profile_tab(request, form)
    return RedirectResponse(
        f"/profile?tab={active_tab}", status_code=303,
    )


# ---------------------------------------------------------------------------
# /profile/style-data — M-8 training-data governance UI
#
# Per HIPAA §164.524 ("right of access") + the operator-private posture
# more generally, every user gets a single "show me / delete me / export
# me" surface for the writing-style data we collect on their behalf.
# Three layers stack here:
#
#   * Writing-style summary (M-3) — small structured profile distilled
#     from past sent mail. Lives in settings under
#     style_profile:<account_id>.
#   * Recent reply examples (M-4) — sent_mail_index rows + embeddings
#     used to show AI a few similar past replies before drafting.
#   * Captured edit pairs (M-6) — sent_mail_index rows tagged with
#     is_captured_pair=1, where the user edited an AI draft before
#     sending so the system can learn from the diff.
#
# The route handlers in this section read ALL three (with graceful
# degradation when M-4 / M-6 aren't installed yet) and offer four
# write actions: export, delete-profile, delete-index, delete-all.
# Each write writes an auth_events audit row; HIPAA-flagged accounts
# accessed by a non-owner additionally write a hipaa_access_events
# row per feedback_hipaa_actor_owner_gate.md.
# ---------------------------------------------------------------------------


@router.get("/profile/style-data", response_class=HTMLResponse)
async def profile_style_data_page(request: Request, user: RequireUser):
    """M-8 — show what writing-style data we have for each account."""
    db = get_db(request)
    templates = get_templates(request)

    snap = await db_call(_profile_style_data_snapshot, db, user)

    # 2026-05-11 — async decorate each account entry with
    # ``sent_folder_candidates`` so the multi-select picker has a
    # live list to render. The probe runs ``list_sent_like_folders``
    # against the account's actual provider; provider build / probe
    # failure falls back to the synthetic candidate set so the picker
    # always renders SOMETHING (saved overrides + discovered default).
    state = request.app.state
    secrets = getattr(state, "secrets", None)
    for entry in snap["accounts"]:
        entry["sent_folder_candidates"] = await _probe_sent_folder_candidates(
            entry, secrets,
        )

    #  F — embedding-runtime gate. Probes app.state for the live
    # backend (post-boot truth) + the configured backend type. End-
    # user-facing copy in resolve_embedding_gate names "the AI Backends
    # config page" but does NOT carry the admin URL — disabled state
    # communicates that admin action is needed (per
    # feedback_no_admin_path_in_user_copy).
    from email_triage.web.routers.ui._shared import resolve_embedding_gate
    live = getattr(state, "embedding_backend", None)
    live_btype = getattr(live, "backend_type", None) if live else None
    config = getattr(state, "config", None)
    emb = getattr(config, "embedding", None) if config else None
    configured_btype = getattr(emb, "backend", "") if emb else ""
    # 2026-05-18: include the configured fallback so the gate treats
    # a not-installed primary + reachable fallback chain as ready.
    # See `resolve_embedding_gate` case 2.
    fb_cfg = getattr(emb, "fallback", None) if emb else None
    fallback_btype = getattr(fb_cfg, "backend", "") if fb_cfg else ""
    embedding_gate = resolve_embedding_gate(
        live_backend_type=live_btype,
        configured_backend_type=configured_btype,
        fallback_backend_type=fallback_btype,
    )

    return await _render(templates, request, "profile/style_data.html", {
        "user": user,
        "current_user": user,
        "accounts": snap["accounts"],
        "master_enabled": snap["master_enabled"],
        #  — cadence banner + install-default placeholder for the
        # per-account "Messages to mine" override.
        "capture_interval_hours": snap.get("capture_interval_hours", 6),
        "mine_limit_install_default": snap.get(
            "mine_limit_install_default", 50,
        ),
        "inline_limit_ceiling": snap.get("inline_limit_ceiling", 50),
        #  F — embedding-runtime gate (end-user audience copy).
        "embedding_required": embedding_gate["required"],
        "embedding_runtime_ready": embedding_gate["ready"],
        "embedding_disabled_reason": embedding_gate["reason"],
        "save_msg": None,
    })


async def _probe_sent_folder_candidates(entry: dict, secrets) -> list[dict]:
    """Build the list of sent-like folders for the picker on one
    account entry.

    Returns a list of ``{"name": <str>, "is_discovered": <bool>}``
    dicts. The discovered default lands at the FRONT with
    ``is_discovered=True``; subsequent matches keep provider order.

    Provider build / probe failure falls back to a synthetic candidate
    set so the operator always gets a usable picker: the saved override
    values + the synthetic discovered name. This keeps the page render
    cheap on accounts whose provider can't be reached right now
    (expired token, unreachable mail server) instead of failing the
    whole page render.
    """
    from email_triage.providers.sent_folder import (
        find_sent_folder,
        list_sent_like_folders,
    )

    acct = entry.get("account") or {}
    saved = list(entry.get("sent_folder_override_list") or [])
    synthetic_default = entry.get("sent_folder_discovered") or "Sent"

    # Synthetic fallback used on any failure path. Discovered name
    # appears first + flagged; saved overrides keep insertion order.
    fallback: list[dict] = [{
        "name": synthetic_default, "is_discovered": True,
    }]
    seen = {synthetic_default}
    for s in saved:
        if s and s not in seen:
            fallback.append({"name": s, "is_discovered": False})
            seen.add(s)

    try:
        provider = _create_provider_from_account(acct, secrets)
    except Exception:
        return fallback

    try:
        try:
            names = await list_sent_like_folders(provider)
            try:
                discovered = await find_sent_folder(provider)
            except Exception:
                discovered = synthetic_default
        except Exception:
            return fallback
        finally:
            try:
                await provider.close()
            except Exception:
                pass
    except Exception:
        return fallback

    candidates: list[dict] = []
    seen2: set[str] = set()
    if discovered:
        candidates.append({"name": discovered, "is_discovered": True})
        seen2.add(discovered)
    for n in names:
        if n in seen2:
            continue
        candidates.append({"name": n, "is_discovered": False})
        seen2.add(n)
    # Ensure every previously-saved override appears as a candidate
    # even if the provider's current folder list doesn't include it
    # (operator may have picked a folder that was later renamed
    # server-side; we want them to see it still selected so they can
    # consciously remove it).
    for s in saved:
        if s and s not in seen2:
            candidates.append({"name": s, "is_discovered": False})
            seen2.add(s)
    return candidates


@router.post("/profile/style-data/export", response_class=HTMLResponse)
async def profile_style_data_export(request: Request, user: RequireUser):
    """Export the per-account style metadata as a JSON download.

    The export deliberately excludes raw message bodies and embedding
    vectors — the goal is "operator can verify what's saved" not "give
    the user a backup that re-creates the index from scratch". Under
    HIPAA, sample subjects + recipient lists in the saved-replies
    section are redacted to the literal string ``[redacted]`` so the
    export never leaks PHI to disk; counts and timestamps remain
    accurate so the user can compare to what's on screen.
    """
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")

    from fastapi.responses import JSONResponse
    from email_triage.triage_logging import is_account_hipaa as _iah_export
    from email_triage.web.db import (
        get_style_profile,
        get_sent_mail_index_summary,
        get_captured_pair_count,
    )

    #  — every shared-connection touch (account resolve, the three
    # style-data reads, the audit + HIPAA-access writes) folds into one
    # threadpool hop. Returns (acct_or_None, err, payload_or_None).
    def _style_data_export_db_work():
        acct, err = _resolve_style_data_account(db, user, account_id_raw)
        if acct is None:
            _record_style_data_audit(
                db,
                event_type="style_data_export",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=_safe_int(account_id_raw, 0),
                outcome="failure",
                detail=err,
            )
            return None, err, None

        profile_dict = get_style_profile(db, acct["id"]) or {}
        index_summary = get_sent_mail_index_summary(db, acct["id"])
        captured = get_captured_pair_count(db, acct["id"])

        # HIPAA-aware sample shaping. The summary helper does NOT
        # redact; gating happens here so a non-HIPAA install gets
        # readable subjects in the download while HIPAA installs are
        # scrubbed.  Route through is_account_hipaa (N-81: folds system
        # flag — a system-HIPAA install with acct["hipaa"]=0 still
        # redacts).
        if _iah_export(acct):
            sample_subjects = [
                REDACTED_PLACEHOLDER  # N-217c R23
                for _ in (index_summary.get("sample_subjects") or [])
            ]
        else:
            sample_subjects = list(index_summary.get("sample_subjects") or [])

        payload = {
            "schema": "email-triage style-data export v1",
            "exported_at": now_utc_iso(),
            "account": {
                "id": acct["id"],
                "name": acct.get("name") or "",
                "hipaa": is_account_hipaa(acct),  # N-226 R22 — fold on system_hipaa OR acct.hipaa
            },
            "writing_style_summary": profile_dict,
            "recent_reply_examples": {
                "count": index_summary.get("count", 0),
                "oldest": index_summary.get("oldest"),
                "newest": index_summary.get("newest"),
                "embedding_model": index_summary.get("embedding_model", ""),
                "sample_subjects": sample_subjects,
            },
            "captured_edit_pairs": {
                "count": captured,
            },
            "notes": (
                "This export contains metadata and the structured "
                "writing-style summary only. Raw message bodies and "
                "embedding vectors are NOT included by design."
            ),
        }

        _record_style_data_audit(
            db,
            event_type="style_data_export",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome="success",
        )
        audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="style_data_export",
        )
        return acct, None, payload

    acct, err, payload = await db_call(_style_data_export_db_work)
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    filename = f"style-data-account-{acct['id']}.json"
    return JSONResponse(
        content=payload,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.post("/profile/style-data/delete-profile", response_class=HTMLResponse)
async def profile_style_data_delete_profile(request: Request, user: RequireUser):
    """Delete the writing-style summary (M-3) for an account."""
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")

    from email_triage.web.db import (
        delete_account_style_per_alias,
        delete_style_profile,
    )

    #  — account resolve + both delete helpers + audit/HIPAA-access
    # writes fold into one threadpool hop. Returns (acct_or_None, err).
    def _delete_profile_db_work():
        acct, err = _resolve_style_data_account(db, user, account_id_raw)
        if acct is None:
            _record_style_data_audit(
                db,
                event_type="style_data_delete_profile",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=_safe_int(account_id_raw, 0),
                outcome="failure",
                detail=err,
            )
            return None, err

        try:
            deleted = delete_style_profile(db, acct["id"])
            # Punch list  — drop per-alias descriptors alongside
            # the account-wide row. The two are conceptually one
            # "writing-style summary" surface, and the user-facing
            # "Delete writing-style summary" button has to clear both
            # for the page to render an empty state consistently.
            alias_deleted = delete_account_style_per_alias(db, acct["id"])
            outcome = "success" if (deleted or alias_deleted) else "noop"
        except Exception as e:
            _record_style_data_audit(
                db,
                event_type="style_data_delete_profile",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="failure",
                detail=fmt_exc(e),
            )
            raise

        _record_style_data_audit(
            db,
            event_type="style_data_delete_profile",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome=outcome,
        )
        audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="style_data_delete_profile",
        )
        return acct, None

    acct, err = await db_call(_delete_profile_db_work)
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    return RedirectResponse("/profile/style-data", status_code=303)


@router.post("/profile/style-data/delete-index", response_class=HTMLResponse)
async def profile_style_data_delete_index(request: Request, user: RequireUser):
    """Delete the recent reply examples (M-4 sent_mail_index) for an account."""
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")

    from email_triage.web.db import delete_sent_mail_index_for_account

    #  — account resolve + delete helper + audit/HIPAA-access
    # writes fold into one threadpool hop. Returns (acct_or_None, err).
    def _delete_index_db_work():
        acct, err = _resolve_style_data_account(db, user, account_id_raw)
        if acct is None:
            _record_style_data_audit(
                db,
                event_type="style_data_delete_index",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=_safe_int(account_id_raw, 0),
                outcome="failure",
                detail=err,
            )
            return None, err

        try:
            deleted = delete_sent_mail_index_for_account(db, acct["id"])
        except Exception as e:
            _record_style_data_audit(
                db,
                event_type="style_data_delete_index",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="failure",
                detail=fmt_exc(e),
            )
            raise

        _record_style_data_audit(
            db,
            event_type="style_data_delete_index",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome="success",
            detail=f"deleted={deleted}",
        )
        audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="style_data_delete_index",
        )
        return acct, None

    acct, err = await db_call(_delete_index_db_work)
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    return RedirectResponse("/profile/style-data", status_code=303)


@router.post("/profile/style-data/delete-all", response_class=HTMLResponse)
async def profile_style_data_delete_all(request: Request, user: RequireUser):
    """Delete EVERYTHING (profile + index) for an account, transactionally.

    Wrapped in a single SAVEPOINT so a partial failure (e.g. profile
    delete OK, index delete fails) rolls back so the user can retry
    without leaving half the data behind.
    """
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")

    from email_triage.web.db import _has_table, invalidate_setting_cache

    #  — the whole unit (account resolve, the raw SAVEPOINT delete
    # block, the audit + HIPAA-access writes) folds into one threadpool
    # hop. db_call holds the process-wide DB lock for the whole closure,
    # which is exactly the / invariant the old explicit
    # ``with get_write_lock()`` block enforced — no other writer's
    # commit() can prematurely release the savepoint. Returns
    # (acct_or_None, err).
    def _delete_all_db_work():
        acct, err = _resolve_style_data_account(db, user, account_id_raw)
        if acct is None:
            _record_style_data_audit(
                db,
                event_type="style_data_delete_all",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=_safe_int(account_id_raw, 0),
                outcome="failure",
                detail=err,
            )
            return None, err

        # Atomic two-step delete via raw SQL inside one SAVEPOINT. We
        # bypass the per-helper ``conn.commit()`` calls (which would
        # implicitly release the savepoint) and emit DELETE statements
        # directly so a failure on the second statement rolls back the
        # first via ROLLBACK TO SAVEPOINT.
        sp_name = "m8_delete_all"
        try:
            db.execute(f"SAVEPOINT {sp_name}")
            try:
                # Profile row in the settings table.
                db.execute(
                    "DELETE FROM settings WHERE key = ?",
                    (_S.style_profile(acct["id"]),),
                )
                # Sent-mail-index rows (M-4 + M-6 share this table;
                # deleting by account_id removes both reply examples
                # and captured edit pairs in one shot).
                if _has_table(db, "sent_mail_index"):
                    db.execute(
                        "DELETE FROM sent_mail_index WHERE account_id = ?",
                        (acct["id"],),
                    )
                # Punch list  — per-alias descriptor rows. Dropped
                # under the same savepoint so a partial failure rolls
                # back together.
                if _has_table(db, "account_style_per_alias"):
                    db.execute(
                        "DELETE FROM account_style_per_alias "
                        "WHERE account_id = ?",
                        (acct["id"],),
                    )
                db.execute(f"RELEASE SAVEPOINT {sp_name}")
                db.commit()
            except Exception:
                try:
                    db.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                    db.execute(f"RELEASE SAVEPOINT {sp_name}")
                except Exception:
                    pass
                raise
            # Keep the in-process settings cache coherent —
            # the DELETE above bypassed delete_setting() to share the
            # savepoint transaction.
            invalidate_setting_cache(_S.style_profile(acct["id"]))
        except Exception as e:
            _record_style_data_audit(
                db,
                event_type="style_data_delete_all",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="failure",
                detail=fmt_exc(e),
            )
            raise

        _record_style_data_audit(
            db,
            event_type="style_data_delete_all",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome="success",
        )
        audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="style_data_delete_all",
        )
        return acct, None

    acct, err = await db_call(_delete_all_db_work)
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    return RedirectResponse("/profile/style-data", status_code=303)


# ---------------------------------------------------------------------------
# /profile/regulatory-clocks — operator-OWNED IRB/INTERNAL deadline templates
#
# A My-Settings editor where a site can define its OWN IRB/INTERNAL reporting-
# deadline templates (the built-in FDA/EU sponsor clocks stay read-only — legal
# durations are not operator-editable). Sensitive: an owned template feeds the
# immutable clock audit chain, so the actuator gate is can_administer_account
# (owner/admin, NO delegate — a delegate must not alter legal policy) and every
# create/edit/delete writes a governance row to the access_log (readable
# account_id) + a HIPAA-access row when the actor isn't the owner.
# ---------------------------------------------------------------------------


def _resolve_clock_def_account(db, user: dict, account_id_raw):
    """Resolve ``account_id`` and require ADMINISTER rights (owner/admin, no
    delegate) — legal-policy edits are a sensitive op. Returns ``(acct, err)``."""
    from email_triage.db.accounts import can_administer_account
    from email_triage.web.db import get_email_account
    # N-219c/40 R23: parse_int_or_none + explicit None-check preserves
    # the "invalid id" vs "missing id" error distinction.
    if account_id_raw:
        account_id = parse_int_or_none(account_id_raw)
        if account_id is None:
            return None, "Invalid account id."
    else:
        account_id = 0
    if account_id <= 0:
        return None, "Account id required."
    acct = get_email_account(db, int(account_id))
    if acct is None:
        return None, "That account does not exist."
    if not can_administer_account(db, user, acct):
        return None, "You don't have administrator access to that account."
    return acct, None


def _record_clock_def_governance(
    db, *, action: str, actor_user_id: int, account: dict,
    outcome: str, status_code: int, detail: str | None = None,
):
    """Audit a clock-def governance change. Routes through record_access_event
    so the account_id is READABLE in the chained access_log (an auditor can see
    WHICH account's reporting policy changed — record_auth_event would bury it in
    a hash-only field). When the actor is NOT the account owner, ALSO write the
    HIPAA actor≠owner access-event row (feedback_hipaa_actor_owner_gate).

    D2 (2026-07-16, hipaa-sme panel-1 obs #2): the ``route`` field written to
    ``access_log`` mirrors the ACTUAL URL segment, not the underscored Python
    action name (``action="set_enabled"`` → ``route=".../set-enabled"``). An
    auditor grepping ``access_log.route`` for the HTTP path finds the row;
    ``create``/``update``/``delete`` are unchanged (no underscore).
    """
    from email_triage.db.audit import (
        record_access_event,
        record_hipaa_access_event,
    )
    record_access_event(
        db,
        actor_user_id=actor_user_id,
        method="POST",
        # D2 (2026-07-16): action names use underscores (create/update/
        # delete/set_enabled) but URL segments hyphenate (set-enabled). The
        # audit log records the real URL so an auditor can match the
        # access_log row to the actual HTTP route without a mental rewrite.
        route=f"/profile/regulatory-clocks/{action.replace('_', '-')}",
        account_id=int(account["id"]),
        message_id=None,
        status_code=status_code,
        outcome=outcome,
        detail=detail,
    )
    from email_triage.triage_logging import account_hipaa_effective
    from email_triage.web.account_scope import is_account_owner
    if account_hipaa_effective(account=account) and (
        not is_account_owner(account, actor_user_id)
    ):
        record_hipaa_access_event(
            db,
            actor_user_id=actor_user_id,
            account_id=int(account["id"]),
            operation=f"clock_def_{action}",
            outcome=outcome,
        )


def _decorate_owned_lead_pcts(owned: list) -> list:
    """Add a parsed ``lead_pcts`` int-list to each owned def so the editor can
    pre-check the reminder-rung checkboxes (the stored value is a JSON string)."""
    for d in owned:
        # load_json_col SSOT (census #16b): the stored escalation_lead_pcts
        # JSON column degrades to [] on NULL/corrupt/wrong-shape; the try still
        # guards the int(x) coercion of a non-numeric reminder rung.
        # N-219c/29 R23: load_json_col is the JSON-col SSOT (degrades to []
        # on any decode / shape issue) so the try was only guarding int().
        # Preserve pre-migration "all-or-nothing" semantic: any non-numeric
        # rung → whole list drops to [].
        raw = load_json_col(
            d.get("escalation_lead_pcts"), default=[],
            label="regulatory_clock_def.escalation_lead_pcts",
        )
        _pcts = [parse_int_or_none(x) for x in raw]
        d["lead_pcts"] = _pcts if all(p is not None for p in _pcts) else []
    return owned


def _working_day_calendar_configured(config) -> bool:
    """True when the per-install working-day calendar has holidays configured —
    the prerequisite to arm a working_day deadline (an empty holiday set would
    mis-count around real holidays and chain a false breach)."""
    rc = getattr(config, "regulatory_clock", None)
    return bool(rc and (getattr(rc, "working_day_holidays", None) or []))


@router.get("/profile/regulatory-clocks", response_class=HTMLResponse)
async def profile_regulatory_clocks_page(request: Request, user: RequireUser):
    """The deadline-templates editor (account-scoped)."""
    db = get_db(request)
    templates = get_templates(request)
    config = get_config(request)
    account_id_raw = request.query_params.get("account_id")

    def _page_db_work():
        from email_triage.db.regulatory_clock import list_owned_clock_defs
        accts = _resolve_managed_accounts(db, user)
        # Only accounts the user can ADMINISTER may edit templates.
        # N-109: filter inactive HERE (the regulatory-clocks editor picker), NOT
        # in the shared _resolve_managed_accounts (which also feeds the
        # style-data MANAGEMENT page, where deactivated accounts must stay). A
        # deactivated mailbox has no incoming mail to match a clock template, so
        # configuring its templates is moot — hide it from the editor picker.
        # (The read-only compliance/deadline display keeps inactive accounts —
        # a regulatory deadline can still be legally due after deactivation.)
        from email_triage.db.accounts import can_administer_account
        admin_accts = [
            a for a in accts
            if can_administer_account(db, user, a) and a.get("is_active", True)
        ]
        selected, err = (None, None)
        owned: list = []
        if account_id_raw:
            selected, err = _resolve_clock_def_account(db, user, account_id_raw)
            if selected is not None:
                # D2 fix 2026-07-16 — the editor MUST see disabled rows too
                # so an operator can restore an off template (a listing that
                # hid disabled rows would be a UX dead-end — no path to
                # turn them back on).
                owned = _decorate_owned_lead_pcts(list_owned_clock_defs(
                    db, selected["id"], include_disabled=True))
        elif admin_accts:
            selected = admin_accts[0]
            owned = _decorate_owned_lead_pcts(list_owned_clock_defs(
                db, selected["id"], include_disabled=True))
        base = [
            dict(r) for r in db.execute(
                "SELECT * FROM regulatory_clock_def "
                "WHERE config_owner_account_id IS NULL ORDER BY regime, title"
            ).fetchall()
        ]
        return admin_accts, selected, owned, base, err

    admin_accts, selected, owned, base, err = await db_call(_page_db_work)
    return await _render(templates, request, "profile/regulatory_clocks.html", {
        "user": user, "current_user": user,
        "admin_accounts": admin_accts,
        "selected_account": selected,
        "owned_defs": owned,
        "base_defs": base,
        "working_day_calendar_configured": _working_day_calendar_configured(config),
        "save_msg": None, "error_msg": err,
    })


async def _clock_def_write(request: Request, user: dict, action: str):
    """Shared create/update/delete actuator: resolve + administer-gate + the
    write helper + the governance audit, all in one db_call. 303 on success,
    re-render with the error on a validation/gate miss."""
    db = get_db(request)
    config = get_config(request)
    form = await request.form()
    account_id_raw = form.get("account_id") or request.query_params.get("account_id")
    wd_configured = _working_day_calendar_configured(config)

    def _work():
        from email_triage.db.regulatory_clock import (
            ClockDefValidationError,
            create_owned_clock_def,
            delete_owned_clock_def,
            set_owned_clock_def_enabled,
            update_owned_clock_def,
        )
        acct, err = _resolve_clock_def_account(db, user, account_id_raw)
        if acct is None:
            # Finding A — audit the gate-DENY too (a non-administrator probing a
            # mutating endpoint must leave a §164.308(a)(1)(ii)(D) trail). The
            # account may be unresolvable, so log the RAW submitted id.
            from email_triage.db.audit import record_access_event
            _raw_id = parse_int_or_none(account_id_raw) if account_id_raw else None  # N-219c/40 R23: SSOT
            record_access_event(
                db, actor_user_id=user["id"], method="POST",
                # D2 (2026-07-16): mirror the URL-form (set_enabled → set-enabled)
                # so the deny-audit route matches the real URL segment.
                route=f"/profile/regulatory-clocks/{action.replace('_', '-')}",
                account_id=_raw_id, message_id=None, status_code=403,
                outcome="denied", detail=err)
            return None, err, 403
        try:
            if action == "create":
                payload = _clock_def_payload_from_form(form)
                create_owned_clock_def(
                    db, account_id=acct["id"], actor_user_id=user["id"],
                    payload=payload, working_day_calendar_configured=wd_configured)
            elif action == "update":
                payload = _clock_def_payload_from_form(form)
                update_owned_clock_def(
                    db, def_id=_safe_int(form.get("def_id"), 0),
                    account_id=acct["id"], actor_user_id=user["id"],
                    payload=payload, working_day_calendar_configured=wd_configured)
            elif action == "set_enabled":
                # D2 fix 2026-07-16 — enable/disable an owned clock-def
                # template (the missing partner of the delete-refusal
                # error string in db/regulatory_clock.py:544-547 that
                # tells the operator to "turn it off instead of deleting
                # it"). The form's ``enabled`` field is parsed via the
                # ``_envbool.parse_bool`` SSOT (accepts 1/true/yes/on
                # case-insensitively; A9 divergence pin enforces the
                # SSOT — hand-rolled str->bool would trip
                # tests/test_envbool_ssot_pin_a9.py) so a checkbox OR a
                # hidden-input toggle button both flow through the same
                # writer SSOT.
                set_owned_clock_def_enabled(
                    db, def_id=_safe_int(form.get("def_id"), 0),
                    account_id=acct["id"], actor_user_id=user["id"],
                    enabled=parse_bool(form.get("enabled")))
            else:  # delete
                delete_owned_clock_def(
                    db, def_id=_safe_int(form.get("def_id"), 0),
                    account_id=acct["id"], actor_user_id=user["id"])
        except ClockDefValidationError as e:
            # ADJ-1 — canonical access_log outcome vocabulary (ok/denied/error).
            _record_clock_def_governance(
                db, action=action, actor_user_id=user["id"], account=acct,
                outcome="error", status_code=400,
                detail=scrub_error_for_persist(e))  # run13 #2 — chained audit detail (PHI+secret)
            return acct, str(e), 400
        _record_clock_def_governance(
            db, action=action, actor_user_id=user["id"], account=acct,
            outcome="ok", status_code=200)
        return acct, None, 200

    acct, err, code = await db_call(_work)
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)
    if err:
        # Validation bounce — re-render the editor with the message (no PRG).
        def _reload():
            from email_triage.db.accounts import can_administer_account
            from email_triage.db.regulatory_clock import list_owned_clock_defs
            admin = [a for a in _resolve_managed_accounts(db, user)
                     if can_administer_account(db, user, a)]
            base = [dict(r) for r in db.execute(
                "SELECT * FROM regulatory_clock_def "
                "WHERE config_owner_account_id IS NULL ORDER BY regime, title"
            ).fetchall()]
            # D2 fix 2026-07-16 — editor reload also shows disabled rows.
            return admin, _decorate_owned_lead_pcts(list_owned_clock_defs(
                db, acct["id"], include_disabled=True)), base
        admin_accts, owned, base = await db_call(_reload)
        resp = await _render(
            get_templates(request), request,
            "profile/regulatory_clocks.html", {
                "user": user, "current_user": user,
                "admin_accounts": admin_accts,
                "selected_account": acct, "owned_defs": owned, "base_defs": base,
                "working_day_calendar_configured": wd_configured,
                "save_msg": None, "error_msg": err,
            })
        resp.status_code = 400
        return resp
    return RedirectResponse(
        f"/profile/regulatory-clocks?account_id={acct['id']}", status_code=303)


def _clock_def_payload_from_form(form) -> dict:
    """Form -> owned-def payload. A BLANK numeric field is left ABSENT so the
    write helper's never-clobber preserves the stored value on edit."""
    days_raw = (form.get("duration_value") or "").strip()
    leads = [v for v in form.getlist("escalation_lead_pcts") if str(v).strip()]
    regime = (form.get("regime") or "IRB").strip()
    # severity_class is DERIVED from regime (the user never picks a redundant
    # field): IRB -> irb_up, INTERNAL -> internal.
    severity = "internal" if regime == "INTERNAL" else "irb_up"
    payload = {
        "title": (form.get("title") or "").strip(),
        "regime": regime,
        "severity_class": severity,
        "clock_kind": (form.get("clock_kind") or "escalating").strip(),
        "duration_unit": (form.get("duration_unit") or "working_day").strip(),
        "clock_start_kind": (form.get("clock_start_kind") or "on_awareness").strip(),
        "calendar_tz": (form.get("calendar_tz") or "America/New_York").strip(),
        "citation": (form.get("citation") or "").strip(),
    }
    if days_raw:
        payload["duration_value"] = days_raw
    # ack_required is a CHECKBOX — an unchecked box posts NOTHING, which would
    # otherwise clobber a live clock's stored ack to 0 (the checkbox never-clobber
    # trap, Finding B). Only set it when the hidden ``ack_required_submitted``
    # marker is present (mirrors the rag_submitted/hipaa_submitted pattern); a
    # stale/partial POST without the marker leaves ack_required absent => the
    # update merge preserves the stored value.
    if "ack_required_submitted" in form:
        payload["ack_required"] = (
            1 if parse_bool(form.get("ack_required")) else 0
        )
    # escalation_lead_pcts: only set when at least one reminder rung was picked;
    # absent => the merge preserves the stored ladder (it is in the preserve set).
    if leads:
        payload["escalation_lead_pcts"] = [
            int(x) for x in leads if str(x).lstrip("-").isdigit()
        ]
    return payload


@router.post("/profile/regulatory-clocks/create", response_class=HTMLResponse)
async def profile_regulatory_clocks_create(request: Request, user: RequireUser):
    return await _clock_def_write(request, user, "create")


@router.post("/profile/regulatory-clocks/update", response_class=HTMLResponse)
async def profile_regulatory_clocks_update(request: Request, user: RequireUser):
    return await _clock_def_write(request, user, "update")


@router.post("/profile/regulatory-clocks/delete", response_class=HTMLResponse)
async def profile_regulatory_clocks_delete(request: Request, user: RequireUser):
    return await _clock_def_write(request, user, "delete")


@router.post("/profile/regulatory-clocks/set-enabled", response_class=HTMLResponse)
async def profile_regulatory_clocks_set_enabled(request: Request, user: RequireUser):
    """D2 fix 2026-07-16 — enable/disable an owned clock-def template.

    The partner of :func:`profile_regulatory_clocks_delete`'s refusal path
    (``db/regulatory_clock.py::delete_owned_clock_def`` refuses to hard-
    delete a template with instance history, telling the operator to
    "turn it off" instead). Wraps
    :func:`~email_triage.db.regulatory_clock.set_owned_clock_def_enabled`
    through the shared ``_clock_def_write`` actuator so the write inherits
    the manageable-set gate + the governance audit that already covers
    create/update/delete."""
    return await _clock_def_write(request, user, "set_enabled")


# ---------------------------------------------------------------------------
# 2026-05-11 — Relocated AI-learns toggle + sent-folder override
#
# Two POST endpoints land here. Both write to per-account state — the
# AI-learns toggle is a `settings`-table boolean (helper:
# `set_rag_sent_index_enabled`); the sent-folder override is a key in
# `email_accounts.config_json` (helper: `update_account_config_keys`).
#
# Both gate on the HIPAA opt-in shape the mine-now endpoint uses:
# HIPAA-flagged account without `style_knobs_hipaa_allow` opt-in →
# silently refuse the toggle write (the M-1+M-2 opt-in lives on the
# account-edit page, which the user-facing UI surfaces via a chip).
# Sent-folder override has no PHI angle — it's a folder name, not
# message contents — so it's allowed regardless of HIPAA gate.
# ---------------------------------------------------------------------------


@router.post("/profile/style-data/toggle-rag", response_class=HTMLResponse)
async def profile_style_data_toggle_rag(request: Request, user: RequireUser):
    """Persist the per-account "AI learns from your past replies" toggle.

    Form fields:
      * ``rag_sent_index_enabled`` — checkbox value=1 when ticked.
      * ``rag_submitted`` — hidden marker so the handler knows the
        form rendered (vs a bare POST that omitted the field). Mirrors
        the hipaa_submitted pattern in /accounts/<id>/save.

    HIPAA gate: HIPAA-flagged accounts without the M-1+M-2 opt-in
    (``style_knobs_hipaa_allow:<id>``) get a save-message and no
    write. The opt-in lives on the account-edit page; user-facing
    UI here surfaces a reason chip on the checkbox.
    """
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    #  — account resolve touches the shared connection; off-loop.
    acct, err = await db_call(
        _resolve_style_data_account, db, user, account_id_raw,
    )
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    form = await request.form()
    desired = "rag_sent_index_enabled" in form

    # HIPAA gate — refuse write when HIPAA + no opt-in. Don't auto-flip
    # the opt-in; that lives on the account-edit page so the operator
    # sees the full opt-in copy before agreeing.
    from email_triage.web.db import (
        is_style_knobs_hipaa_allow,
        set_rag_sent_index_enabled,
    )

    from email_triage.triage_logging import is_account_hipaa as _iah_rag

    #  — HIPAA gate read + the toggle write fold into one hop.
    def _toggle_rag_db_work() -> bool:
        if _iah_rag(acct) and not is_style_knobs_hipaa_allow(
            db, acct["id"],
        ):
            return False
        set_rag_sent_index_enabled(db, acct["id"], enabled=desired)
        return True

    saved = await db_call(_toggle_rag_db_work)
    if not saved:
        _log.info(
            "AI-learns toggle refused — HIPAA without opt-in",
            account_id=acct["id"],
            actor_user_id=user["id"],
        )
        return RedirectResponse("/profile/style-data", status_code=303)

    _log.info(
        "AI-learns toggle saved",
        account_id=acct["id"],
        actor_user_id=user["id"],
        enabled=desired,
    )

    return RedirectResponse("/profile/style-data", status_code=303)


@router.post(
    "/profile/style-data/toggle-auto-scan",
    response_class=HTMLResponse,
)
async def profile_style_data_toggle_auto_scan(request: Request, user: RequireUser):
    """ item 2 — per-account "Auto-scan on schedule" toggle.

    When OFF, the background ``_sent_mail_capture_loop`` skips this
    account on every tick (logged INFO with account_id + reason). The
    operator-driven "Mine the Sent Items Now" button still works.

    Form fields:
      * ``auto_scan_enabled`` — checkbox value=1 when ticked.
      * ``auto_scan_submitted`` — hidden marker so the handler can
        tell "form rendered + checkbox unchecked" apart from "form
        not rendered". Mirrors the rag_submitted pattern above.

    HIPAA gate: HIPAA-flagged accounts without the M-1+M-2 opt-in
    silently refuse the save (the underlying capture loop already
    short-circuits HIPAA-without-opt-in via M-3's per-account opt-in
    gate; flipping this checkbox would be a no-op + confuse the
    operator). The opt-in lives on the account-edit page.
    """
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    #  — account resolve touches the shared connection; off-loop.
    acct, err = await db_call(
        _resolve_style_data_account, db, user, account_id_raw,
    )
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    form = await request.form()
    desired = "auto_scan_enabled" in form

    from email_triage.web.db import (
        is_style_knobs_hipaa_allow,
        set_auto_scan_enabled_for_account,
    )

    from email_triage.triage_logging import is_account_hipaa as _iah_scan

    #  — HIPAA gate read + the toggle write fold into one hop.
    def _toggle_auto_scan_db_work() -> bool:
        if _iah_scan(acct) and not is_style_knobs_hipaa_allow(
            db, acct["id"],
        ):
            return False
        set_auto_scan_enabled_for_account(db, acct["id"], desired)
        return True

    saved = await db_call(_toggle_auto_scan_db_work)
    if not saved:
        _log.info(
            "Auto-scan toggle refused — HIPAA without opt-in",
            account_id=acct["id"],
            actor_user_id=user["id"],
        )
        return RedirectResponse("/profile/style-data", status_code=303)

    _log.info(
        "Auto-scan toggle saved",
        account_id=acct["id"],
        actor_user_id=user["id"],
        enabled=desired,
    )

    return RedirectResponse("/profile/style-data", status_code=303)


@router.post(
    "/profile/style-data/mine-limit-override",
    response_class=HTMLResponse,
)
async def profile_style_data_mine_limit_override(request: Request, user: RequireUser):
    """ item 4 — per-account "Messages to mine" override.

    Persisted on ``email_accounts.config_json["mine_limit_override"]``
    as int | None. Empty submit clears the key (falls back to the
    install-wide default on /config); non-empty integer overrides
    the install default for this account on the inline mine-now /
    preview path.

    Clamped to the documented range
    (``STYLE_LEARNING_MINE_LIMIT_MIN..STYLE_LEARNING_MINE_LIMIT_MAX``)
    so a typo can't queue a multi-thousand-message scan. Resolved
    values > ``STYLE_LEARNING_INLINE_LIMIT_CEILING`` route through
    the bulk worker at click time — the save itself doesn't care
    about the threshold, it just records the operator's preference.

    No HIPAA gate — the limit is metadata, not source mail; the
    M-3 distill path itself enforces the HIPAA opt-in.
    """
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    #  — account resolve touches the shared connection; off-loop.
    acct, err = await db_call(
        _resolve_style_data_account, db, user, account_id_raw,
    )
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    form = await request.form()
    raw = (form.get("mine_limit_override") or "").strip()

    from email_triage.web.db import (
        update_account_config_keys,
        STYLE_LEARNING_MINE_LIMIT_MIN,
        STYLE_LEARNING_MINE_LIMIT_MAX,
    )
    value: int | None
    if raw == "":
        value = None  # None means "delete the key" — fall back to install default.
    else:
        # N-219c/41 R23: parse_int_or_none + explicit-guard redirect on
        # non-numeric (bounded_int would collapse to a default we'd have to
        # detect); preserved clamp logic below.
        v = parse_int_or_none(raw)
        if v is None:
            return RedirectResponse(
                "/profile/style-data", status_code=303,
            )
        if v < STYLE_LEARNING_MINE_LIMIT_MIN:
            v = STYLE_LEARNING_MINE_LIMIT_MIN
        elif v > STYLE_LEARNING_MINE_LIMIT_MAX:
            v = STYLE_LEARNING_MINE_LIMIT_MAX
        value = v
    #  — update_account_config_keys is @db_write; off-loop hop.
    await db_call(
        update_account_config_keys,
        db, acct["id"], mine_limit_override=value,
    )
    _log.info(
        "Mine-limit override saved",
        account_id=acct["id"],
        actor_user_id=user["id"],
        value=value,
    )

    return RedirectResponse("/profile/style-data", status_code=303)


@router.post(
    "/profile/style-data/sent-folder-override",
    response_class=HTMLResponse,
)
async def profile_style_data_sent_folder_override(request: Request, user: RequireUser):
    """Persist the per-account Sent-folder override (config_json key).

    Empty submit clears the override; non-empty stores the literal
    folder name. Read by the mine-now path (and the M-3/M-4/M-6
    capture-loop paths) in preference to ``find_sent_folder`` when
    set. No HIPAA gate — folder names aren't PHI.
    """
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    #  — account resolve touches the shared connection; off-loop.
    acct, err = await db_call(
        _resolve_style_data_account, db, user, account_id_raw,
    )
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    form = await request.form()
    # 2026-05-11 — multi-select: the form posts ``sent_folder_override``
    # one or more times (once per ticked option). ``getlist`` returns
    # them all; whitespace-only / duplicate values are dropped.
    raw_values = form.getlist("sent_folder_override")
    seen: set[str] = set()
    folders: list[str] = []
    for v in raw_values:
        if not isinstance(v, str):
            continue
        s = v.strip()
        if not s or s in seen:
            continue
        folders.append(s)
        seen.add(s)
    # Empty list → clear the key (None deletes via
    # update_account_config_keys' None-means-delete contract); non-empty
    # → store the list verbatim.
    from email_triage.web.db import update_account_config_keys
    #  — update_account_config_keys is @db_write; off-loop hop.
    await db_call(
        update_account_config_keys,
        db, acct["id"],
        sent_folder_override=(folders if folders else None),
    )
    _log.info(
        "Sent-folder override saved",
        account_id=acct["id"],
        actor_user_id=user["id"],
        folder_count=len(folders),
    )

    return RedirectResponse("/profile/style-data", status_code=303)


# ---------------------------------------------------------------------------
# Punch list  — alias-aware learning toggle
#
# A single per-account checkbox that flips the style mine + draft
# stitch into partition-by-From-address mode. When off, behaviour is
# identical to pre-#162. When on, the mine path produces one
# descriptor per distinct ``From:`` address; the draft path picks
# the alias-matching descriptor at prompt-build time.
#
# Same HIPAA gate as the AI-learns toggle: partitioning still reads
# source mail, so the opt-in lives behind the same
# ``style_knobs_hipaa_allow:<id>`` flag. Non-owner ticking the toggle
# on a HIPAA-flagged account writes a hipaa_access_events row per
# ``feedback_hipaa_actor_owner_gate.md``.
# ---------------------------------------------------------------------------


@router.post(
    "/profile/style-data/toggle-alias-mode",
    response_class=HTMLResponse,
)
async def profile_style_data_toggle_alias_mode(request: Request, user: RequireUser):
    """Persist the per-account alias-aware-learning toggle.

    Form fields:
      * ``style_alias_mode_enabled`` — checkbox value=1 when ticked.
      * ``alias_mode_submitted`` — hidden marker so the handler can
        distinguish "checkbox unchecked" from "form never rendered".

    HIPAA gate: refused (silently — same shape as the AI-learns
    toggle) when account is HIPAA-flagged and the M-1+M-2 opt-in
    hasn't been ticked on the account-edit page. The audit row +
    HIPAA-access row write regardless so an operator-side review
    can see refused attempts.
    """
    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")

    #  — account resolve + the not-found audit write fold into one
    # threadpool hop. Returns (acct_or_None, err).
    def _alias_mode_resolve_db_work():
        acct, err = _resolve_style_data_account(db, user, account_id_raw)
        if acct is None:
            _record_style_data_audit(
                db,
                event_type="style_data_toggle_alias_mode",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=_safe_int(account_id_raw, 0),
                outcome="failure",
                detail=err,
            )
        return acct, err

    acct, err = await db_call(_alias_mode_resolve_db_work)
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    form = await request.form()
    desired = "style_alias_mode_enabled" in form

    from email_triage.triage_logging import is_account_hipaa as _iah_alias
    from email_triage.web.db import (
        is_style_knobs_hipaa_allow,
        set_alias_mode_enabled_for_account,
    )

    #  — HIPAA gate read + the toggle write + audit / HIPAA-access
    # rows fold into one threadpool hop. Returns True iff the toggle
    # was applied (False = HIPAA gate refused).
    def _alias_mode_apply_db_work() -> bool:
        # HIPAA gate. Refuse the write when account is HIPAA + not
        # opted in. Audit row + HIPAA access row are both written so
        # an admin review surfaces the refused attempt as well as a
        # successful flip. The owner-self-access carve-out applies to
        # the HIPAA access row; the audit row writes regardless.
        # N-81: route through is_account_hipaa (folds system flag so
        # system-HIPAA installs with acct["hipaa"]=0 are gated).
        is_hipaa = _iah_alias(acct)
        if is_hipaa and not is_style_knobs_hipaa_allow(db, acct["id"]):
            _record_style_data_audit(
                db,
                event_type="style_data_toggle_alias_mode",
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="failure",
                detail="hipaa_gate",
            )
            audit_phi_access(
                db,
                actor_user_id=user["id"],
                account=acct,
                operation="style_data_toggle_alias_mode",
                outcome="failure",
            )
            return False

        set_alias_mode_enabled_for_account(db, acct["id"], enabled=desired)
        _record_style_data_audit(
            db,
            event_type="style_data_toggle_alias_mode",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome="success",
            detail=f"enabled={desired}",
        )
        audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="style_data_toggle_alias_mode",
        )
        return True

    await db_call(_alias_mode_apply_db_work)
    return RedirectResponse("/profile/style-data", status_code=303)


# ---------------------------------------------------------------------------
#  — On-demand mine + dry-run preview for the style-data page
#
# Two handlers + one shared corpus-builder so the dry-run preview and
# the "Mine the Sent Items Now" button stay in lockstep on which
# messages get fed to the distillation LLM. The split is one POST
# parameter (commit / dry-run): commit writes the result to
# settings.style_profile:<id>; dry-run returns the descriptor without
# touching the persistent store.
#
# HIPAA gate ordering:
#   1.  ownership check (the existing _resolve_style_data_account)
#   2.  acct["hipaa"] AND not style_knobs_hipaa_allow:<id> → refuse
#   3.  reach for sent mail via the live provider
#   4.  run extract_style_profile via the configured classifier
#
# The HIPAA gate runs BEFORE the LLM call (and before any provider
# fetch) so a HIPAA-flagged account without the per-account opt-in
# never leaves the function with bytes from its Sent folder in
# memory. The opt-in (``style_knobs_hipaa_allow``) is the same flag
#  phase 2 plumbed for M-1+M-2; we reuse it for M-3 dry-run /
# mine-now because the same §164.502(a) self-disclosure carve-out
# applies — operator is the data subject, so opt-in by operator
# lifts the hard-off posture.
# ---------------------------------------------------------------------------


async def _mine_or_preview(
    request: Request,
    *,
    commit: bool,
) -> HTMLResponse:
    """Shared body for the preview + mine-now endpoints.

    ``commit=False`` runs the M-3 distillation and returns a
    descriptor preview without writing to the descriptor store.
    ``commit=True`` writes the resulting profile via
    ``set_style_profile`` AND writes an audit row.

    Returns an HTMX fragment (``text/html``) for both branches so
    the page's ``hx-swap`` target updates inline.
    """
    db = get_db(request)
    #  — get_current_user takes the DB write lock; off-loop hop.
    user = await db_call(get_current_user, request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    account_id_raw = request.query_params.get("account_id")
    event_type = (
        "style_data_mine_now" if commit else "style_data_preview"
    )

    from email_triage.web.db import is_style_knobs_hipaa_allow

    #  — account resolve + the not-found audit + the HIPAA gate
    # read & refusal audit all touch the shared connection. Fold the
    # whole preamble into one threadpool hop. Returns a 3-tuple:
    #   (acct_or_None, err, gate)  where gate is one of
    #   'ok' | 'not_found' | 'hipaa'.
    def _mine_preamble_db_work():
        acct, err = _resolve_style_data_account(db, user, account_id_raw)
        if acct is None:
            _record_style_data_audit(
                db,
                event_type=event_type,
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=_safe_int(account_id_raw, 0),
                outcome="failure",
                detail=err,
            )
            return None, err, "not_found"
        # HIPAA gate — must run BEFORE the provider fetch. M-3 reads
        # source-mail bodies; the per-account opt-in lifts that for
        # operator-owned HIPAA mailboxes per §164.502(a). Without the
        # opt-in we refuse and audit.
        if is_account_hipaa(acct) and not is_style_knobs_hipaa_allow(
            db, acct["id"],
        ):
            _record_style_data_audit(
                db,
                event_type=event_type,
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="failure",
                detail="hipaa_gate",
            )
            return acct, err, "hipaa"
        return acct, err, "ok"

    acct, err, _gate = await db_call(_mine_preamble_db_work)
    if _gate == "not_found":
        return HTMLResponse(
            _mine_result_fragment(
                state="error",
                title="Could not find that account",
                body=err or "Forbidden",
            ),
            status_code=403,
        )
    if _gate == "hipaa":
        return HTMLResponse(
                _mine_result_fragment(
                    state="error",
                    title="HIPAA mailbox — opt-in required",
                    body=(
                        "This account is marked HIPAA. To preview or "
                        "build a writing-style summary, first turn on "
                        "\"Your writing-style preferences on this "
                        "HIPAA account\" on the account's settings tab."
                    ),
                ),
                status_code=200,
            )

    # Sent-folder discovery: surface the resolved name so the
    # operator can verify on-screen + know what was scanned. The
    # provider build can fail (e.g. missing secret); treat any
    # exception as an operator-facing error rather than a 500.
    state = request.app.state
    secrets = getattr(state, "secrets", None)
    config = getattr(state, "config", None)

    from email_triage.providers.sent_folder import find_sent_folder

    try:
        provider = _create_provider_from_account(acct, secrets)
    except Exception as exc:
        await db_call(
            _record_style_data_audit,
            db,
            event_type=event_type,
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome="failure",
            detail=f"provider_build: {fmt_exc(exc)[:200]}",
        )
        return HTMLResponse(
            _mine_result_fragment(
                state="error",
                title="Could not connect to this mailbox",
                body=(
                    "Email Triage tried to connect to this account "
                    "but the connection failed. Check the account's "
                    "settings tab — you may need to sign in again or "
                    "re-enter the password."
                ),
            ),
            status_code=200,
        )

    # 2026-05-13 — per-account ``sent_folder_override`` wins over
    # the discovery path. The override is a list (one or more folders);
    # the preview / mine-now path runs against EVERY entry + merges
    # the UIDs as ``(folder, uid)`` pairs (UIDs are mailbox-scoped per
    # RFC 3501 § 2.3.1.1, so each must be fetched against its source
    # folder). Mirrors the pattern in ``sent_mail_index.py`` /
    # ``sent_mail_capture.py``. Empty / unset falls through to
    # ``find_sent_folder`` discovery as a single-folder default.
    #
    # Pre-2026-05-13 the inline path used ``_override_list[0]`` only —
    # operators who configured ``['Sent Items', 'Sent']`` saw style
    # mining run against only the first folder. The screen now reads
    # from every folder per operator catch.
    from email_triage.providers.sent_folder import (
        normalize_sent_folder_override,
    )
    _override_list = normalize_sent_folder_override(
        (acct.get("config") or {}).get("sent_folder_override"),
    )
    if _override_list:
        sent_folders = list(_override_list)
    else:
        try:
            sent_folders = [await find_sent_folder(provider)]
        except Exception as exc:
            _log.warning(
                "Sent folder discovery failed",
                account_id=acct["id"],
                error=fmt_exc(exc),
            )
            sent_folders = ["Sent"]
    # Display string for the result fragment — comma-joined when
    # multi-folder, bare when single. Used in "Folder used: …"
    # banner + error-message context.
    sent_folder = (
        sent_folders[0] if len(sent_folders) == 1
        else ", ".join(sent_folders)
    )

    # Default search query per provider trait — Gmail uses
    # ``in:sent``, IMAP uses ``ALL`` (and the SELECT picks the
    # right folder), O365 has no native default; we fall through
    # with the empty string and the helper below substitutes
    # ``in:sent`` so the call has something to send.
    from email_triage.providers.traits import default_search_query
    query = default_search_query(acct.get("provider_type", "")) or "in:sent"
    #  item 4 — limit resolution:
    #   per-account override > install-wide default > 50.
    # Resolved value > STYLE_LEARNING_INLINE_LIMIT_CEILING triggers
    # the bulk-handoff branch below. Inline path keeps
    # the historical "50 messages, ~30 s" behaviour for the common
    # case so most operators see the result in the page without
    # leaving it.
    from email_triage.web.db import (
        resolve_account_mine_limit,
        STYLE_LEARNING_INLINE_LIMIT_CEILING,
    )
    #  — resolve_account_mine_limit touches the shared connection.
    limit = await db_call(resolve_account_mine_limit, db, acct)

    #  item 5 — Bulk-worker handoff for limits > ceiling. The
    # inline HTMX request would block past the browser timeout on a
    # 200-message scan; hand off to the supervised bulk runner
    # (kind='style_mine'), return immediately with a "watching the
    # bulk runs page" fragment. Only the commit path queues a job —
    # the preview path is dry-run, opt-out, and operator can rerun
    # easily; queueing a bulk preview would create a permanent row
    # for a throwaway descriptor. So preview with limit > ceiling
    # silently clamps to the inline ceiling (the descriptor still
    # represents the operator's style on the most-recent
    # ``ceiling`` messages, which is enough signal for a sanity-
    # check render).
    if commit and limit > STYLE_LEARNING_INLINE_LIMIT_CEILING:
        from email_triage.web.db import (
            create_triage_job, count_active_triage_jobs_for_account,
        )
        # Close the provider — the bulk runner builds its own.
        try:
            await provider.close()
        except Exception:
            pass
        #  — active-job check + create_triage_job (@db_write) +
        # audit / HIPAA-access writes fold into one threadpool hop.
        # Returns job_id, or None if a bulk run is already active.
        def _bulk_handoff_db_work() -> str | None:
            if count_active_triage_jobs_for_account(db, acct["id"]) > 0:
                return None
            job_id = create_triage_job(
                db,
                account_id=acct["id"],
                actor_user_id=user["id"],
                # Encode the resolved limit into the query column so
                # the bulk-style-mine runner can recover it without a
                # second DB hop on the account row. Format is stable +
                # parsed in run_triage_all_style_mine.
                query=f"style_mine:limit={limit}",
                rate_msg_per_min=int(limit),
                concurrency=1,
                kind="style_mine",
            )
            _record_style_data_audit(
                db,
                event_type=event_type,
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="queued",
                detail=f"job_id={job_id}; limit={limit}",
            )
            audit_phi_access(
                db,
                actor_user_id=user["id"],
                account=acct,
                operation=event_type,
            )
            return job_id

        job_id = await db_call(_bulk_handoff_db_work)
        if job_id is None:
            return HTMLResponse(
                _mine_result_fragment(
                    state="empty",
                    title="A bulk run is already active on this account",
                    body=(
                        "Wait for the running job to finish (or cancel "
                        "it on the Bulk runs page) before starting a "
                        "new mine. The current job's progress is on "
                        "<a href=\"/triage/jobs\">the bulk runs page</a>."
                    ),
                ),
                status_code=200,
            )
        return HTMLResponse(
            _mine_result_fragment(
                state="ok",
                title=(
                    f"Mining {limit} messages in the background — "
                    "you can leave this page"
                ),
                body=(
                    "Watch progress on "
                    f"<a href=\"/triage/jobs/{job_id}\">the bulk runs "
                    "page</a>. The writing-style summary will be saved "
                    "automatically when the mine finishes."
                ),
                committed=True,
            ),
            status_code=200,
        )

    # Inline path stays clamped to the ceiling so an operator who
    # set a 75-msg per-account override but clicked Preview (which
    # doesn't hand off) still gets a reasonable response. Capture
    # the pre-clamp resolved limit so the result fragment can tell
    # the operator their setting was larger than the preview ran
    # against — otherwise a 75-msg setting silently rendering as
    # ~50 messages looks like a bug rather than a documented cap.
    preview_clamped_from: int | None = None
    if limit > STYLE_LEARNING_INLINE_LIMIT_CEILING:
        preview_clamped_from = int(limit)
        limit = STYLE_LEARNING_INLINE_LIMIT_CEILING

    # 2026-05-13 — multi-folder fan-out. Search each configured Sent
    # folder + merge UIDs into ``(folder, uid)`` pairs so each fetch
    # targets the correct mailbox (UIDs are mailbox-scoped per RFC 3501
    # § 2.3.1.1). Same pattern as ``sent_mail_index.py`` /
    # ``sent_mail_capture.py``. Per-folder errors don't abort the
    # batch — one bad folder logs + continues; only an empty merged
    # result counts as a failure.
    from email_triage.engine.models import MailFilter
    merged_pairs: list[tuple[str, str]] = []  # (folder, uid)
    seen_uids: set[tuple[str, str]] = set()   # de-dup across folders
    per_folder_errors: list[str] = []
    # Divide the limit roughly across folders so a single folder
    # doesn't monopolize the corpus when the operator configured
    # multiple. Round up so ``limit=50`` + 2 folders yields 25 each
    # (not 50/2=25 rounded down to 0 on edge cases).
    per_folder_limit = max(1, -(-limit // max(1, len(sent_folders))))
    for folder in sent_folders:
        try:
            part = await provider.search(
                query, per_folder_limit,
                filter=MailFilter(folder=folder),
            )
        except Exception as exc:
            per_folder_errors.append(
                f"{folder}: {type(exc).__name__}"
            )
            _log.warning(
                "Mine-now: per-folder search failed; continuing",
                account_id=acct["id"],
                folder=folder,
                error=fmt_exc(exc),
            )
            continue
        for mid in part or ():
            key = (folder, mid)
            if key not in seen_uids:
                seen_uids.add(key)
                merged_pairs.append(key)

    if not merged_pairs:
        await db_call(
            _record_style_data_audit,
            db,
            event_type=event_type,
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome="failure",
            detail=(
                f"search: every folder empty or failed "
                f"({len(per_folder_errors)} error(s))"
            ),
        )
        try:
            await provider.close()
        except Exception:
            pass
        # Different fragment shape depending on whether the failures
        # were errors (server refused) or just empty folders.
        if per_folder_errors:
            return HTMLResponse(
                _mine_result_fragment(
                    state="error",
                    title="Sent-folder search failed",
                    body=(
                        f"Tried to search "
                        f"{', '.join(repr(f) for f in sent_folders)} "
                        "but the mail server refused on every folder. "
                        "The account is still connected; try again in "
                        "a minute. If it keeps happening, check the "
                        "folder names on the Sent folders picker above."
                    ),
                ),
                status_code=200,
            )
        return HTMLResponse(
            _mine_result_fragment(
                state="empty",
                title="Nothing to learn from yet",
                body=(
                    f"No messages found in "
                    f"{', '.join(repr(f) for f in sent_folders)}. "
                    "The AI builds your writing-style summary from "
                    "your past sent mail — send a few replies and "
                    "try again."
                ),
                folder_label=sent_folder,
            ),
            status_code=200,
        )

    messages = []
    for folder, mid in merged_pairs:
        try:
            msg = await provider.fetch_message(mid, folder=folder)
            messages.append(msg)
        except Exception as exc:
            _log.warning(
                "Mine-now: fetch failed; continuing",
                account_id=acct["id"],
                folder=folder,
                message_id=mid,
                error=fmt_exc(exc),
            )

    try:
        await provider.close()
    except Exception:
        pass

    if not messages:
        return HTMLResponse(
            _mine_result_fragment(
                state="empty",
                title="Could not read any sent messages",
                body=(
                    f"Found message ids in the Sent folder "
                    f"({sent_folder!r}) but none of them could be "
                    "fetched. Try again later — this is usually a "
                    "transient mail-server issue."
                ),
                folder_label=sent_folder,
            ),
            status_code=200,
        )

    # Punch list  — alias-aware learning. When alias-mode is on,
    # the per-alias picker may scope this mine to one From-address.
    # The picker submits ``alias_from_address`` as a query param; the
    # rest of the path partitions by parsed-From header and either
    # (a) writes ALL buckets when no specific alias was requested, or
    # (b) writes ONLY the matching bucket when ``alias_from_address``
    # is set. Unknown buckets (From values not in the declared alias
    # list) are surfaced in the result fragment but not persisted —
    # operator decides via the picker whether to add the address.
    from email_triage.web.db import (
        account_addresses as _account_addresses,
        is_alias_mode_enabled_for_account as _is_alias_mode_on,
        normalise_from_address as _norm_addr,
        set_account_style_per_alias as _set_alias_descriptor,
    )
    alias_from_address = (
        request.query_params.get("alias_from_address") or ""
    )
    from email_triage.mail_headers import canonical_email  # N-346 partial 5 R31
    alias_from_address = canonical_email(alias_from_address)
    alias_from_address_norm = _norm_addr(alias_from_address)
    known_addresses = _account_addresses(acct)

    #  — the M-6 captured-pair read + the alias-mode flag read both
    # touch the shared connection; fold them into one threadpool hop.
    def _mine_corpus_reads() -> tuple[set[str], bool]:
        # M-6 hook — captured edit pairs get double-weighted in the
        # distillation corpus. Same shape as the CLI path.
        captured_ids: set[str] = set()
        try:
            rows = db.execute(
                "SELECT message_id FROM sent_mail_index "
                "WHERE account_id = ? AND is_captured_pair = 1",
                (acct["id"],),
            ).fetchall()
            for r in rows:
                mid = r["message_id"] if hasattr(r, "keys") else r[0]
                if mid:
                    captured_ids.add(str(mid))
        except Exception:
            # Pre-M-6 install (sent_mail_index table missing) — fall
            # through with an empty set.
            captured_ids = set()
        return captured_ids, _is_alias_mode_on(db, acct["id"])

    captured_ids, alias_mode_on = await db_call(_mine_corpus_reads)

    from email_triage.actions.style_profile import extract_style_profile
    if config is None:
        return HTMLResponse(
            _mine_result_fragment(
                state="error",
                title="AI is not configured on this server",
                body=(
                    "Email Triage can't reach the language-model "
                    "backend. Ask your administrator to set up an "
                    "AI provider in the install settings."
                ),
            ),
            status_code=200,
        )
    classifier = _build_classifier_from_config(config)

    # Punch list  — when alias-mode is on, split the corpus by
    # From-address. The result drives either a single-bucket write
    # (when the picker scoped to one alias) or a multi-bucket write
    # (when the operator clicked the top-level mine button while
    # alias-mode is on). When alias-mode is off, fall through to the
    # account-wide pre-#162 path.
    alias_descriptors: dict[str, object] | None = None
    alias_unknown_counts: list[tuple[str, int]] = []
    if alias_mode_on:
        from email_triage.actions.style_profile import (
            extract_style_profiles_per_alias,
        )
        try:
            alias_descriptors, alias_unknown_counts = (
                await extract_style_profiles_per_alias(
                    messages, classifier,
                    known_addresses=known_addresses,
                    captured_message_ids=captured_ids,
                    account_hipaa=is_account_hipaa(acct), conn=db,  # N-114 BAA gate
                )
            )
        except Exception as exc:
            await db_call(
                _record_style_data_audit,
                db,
                event_type=event_type,
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="failure",
                detail=f"distill_per_alias: {fmt_exc(exc)[:200]}",
            )
            return HTMLResponse(
                _mine_result_fragment(
                    state="error",
                    title="AI did not return a writing-style summary",
                    body=(
                        "The AI backend was reached but did not return a "
                        "usable summary. Try again — this is usually a "
                        "transient hiccup. If it keeps happening, the "
                        "AI's model may need an update."
                    ),
                    folder_label=sent_folder,
                ),
                status_code=200,
            )
        # When the picker scoped to a specific alias, keep only that
        # bucket. Picker uses normalised values so the comparison is
        # case + suffix safe.
        if alias_from_address_norm:
            alias_descriptors = {
                k: v for k, v in alias_descriptors.items()
                if k == alias_from_address_norm
            }
        # Commit branch — persist one row per bucket. The audit row
        # uses a comma-separated detail listing every alias written
        # so an admin review sees the full set in one row.
        if commit:
            from email_triage.web.db import set_style_profile

            #  — the per-alias descriptor writes + the account-wide
            # fallback refresh fold into one threadpool hop. Returns
            # (persisted_addrs, persist_err).
            def _alias_persist_db_work() -> tuple[list[str], str]:
                persisted_addrs: list[str] = []
                persist_err: str = ""
                try:
                    # Persist each non-empty bucket into the per-alias
                    # table.
                    for addr, prof in alias_descriptors.items():
                        _set_alias_descriptor(
                            db, acct["id"], addr, prof.to_dict(),
                            sample_count=prof.sample_count,
                        )
                        persisted_addrs.append(addr or "(no-bucket)")
                    # Also refresh the account-wide descriptor when the
                    # operator mined every alias at once (no
                    # ``alias_from_address`` filter). The account-wide
                    # row stays as the fallback when alias-mode is
                    # later turned off; without this refresh it would
                    # point at a stale single-style result.
                    if not alias_from_address_norm and alias_descriptors:
                        # Pick the largest-sample bucket as the
                        # account-wide fallback. Operators with one
                        # dominant address get the natural choice; the
                        # account-wide row is never the "no-bucket"
                        # unknown unless that's the only data we have.
                        best = max(
                            alias_descriptors.values(),
                            key=lambda p: p.sample_count,
                        )
                        try:
                            set_style_profile(
                                db, acct["id"], best.to_dict(),
                            )
                        except Exception:
                            # Non-fatal — per-alias rows are still
                            # saved.
                            pass
                except Exception as exc:
                    persist_err = fmt_exc(exc)[:200]
                return persisted_addrs, persist_err

            persisted_addrs, persist_err = await db_call(
                _alias_persist_db_work,
            )
            if persist_err:
                await db_call(
                    _record_style_data_audit,
                    db,
                    event_type=event_type,
                    actor_user_id=user["id"],
                    actor_email=user.get("email") or "",
                    account_id=acct["id"],
                    outcome="failure",
                    detail=f"persist_per_alias: {persist_err}",
                )
                return HTMLResponse(
                    _mine_result_fragment(
                        state="error",
                        title="Could not save the per-alias summaries",
                        body=(
                            "The AI built per-alias writing-style "
                            "summaries but the server couldn't save "
                            "them. Try the button again."
                        ),
                        folder_label=sent_folder,
                    ),
                    status_code=200,
                )
            #  — success audit + HIPAA-access rows fold into one
            # threadpool hop.
            def _alias_success_audit_db_work() -> None:
                _record_style_data_audit(
                    db,
                    event_type=event_type,
                    actor_user_id=user["id"],
                    actor_email=user.get("email") or "",
                    account_id=acct["id"],
                    outcome="success",
                    detail=(
                        f"aliases={','.join(sorted(persisted_addrs))};"
                        f"unknown_count={len(alias_unknown_counts)}"
                    ),
                )
                audit_phi_access(
                    db,
                    actor_user_id=user["id"],
                    account=acct,
                    operation=event_type,
                )

            await db_call(_alias_success_audit_db_work)
        # Both commit + preview return the per-alias fragment.
        return HTMLResponse(
            _mine_result_fragment(
                state="ok",
                title=(
                    "Saved — per-alias writing-style summaries"
                    if commit else
                    "Preview — per-alias writing-style summaries"
                ),
                body=_format_alias_descriptors_for_preview(
                    alias_descriptors, alias_unknown_counts,
                ),
                folder_label=sent_folder,
                committed=commit,
            ),
            status_code=200,
        )

    try:
        profile = await extract_style_profile(
            messages, classifier,
            captured_message_ids=captured_ids,
            account_hipaa=is_account_hipaa(acct), conn=db,  # N-114 BAA egress gate
        )
    except Exception as exc:
        await db_call(
            _record_style_data_audit,
            db,
            event_type=event_type,
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome="failure",
            detail=f"distill: {fmt_exc(exc)[:200]}",
        )
        return HTMLResponse(
            _mine_result_fragment(
                state="error",
                title="AI did not return a writing-style summary",
                body=(
                    "The AI backend was reached but did not return a "
                    "usable summary. Try again — this is usually a "
                    "transient hiccup. If it keeps happening, the "
                    "AI's model may need an update."
                ),
                folder_label=sent_folder,
            ),
            status_code=200,
        )

    # Commit branch — persist + audit.
    if commit:
        from email_triage.web.db import set_style_profile

        #  — the descriptor write + the success/failure audit +
        # HIPAA-access rows fold into one threadpool hop. Returns the
        # persist-failure string, or "" on success.
        def _mine_persist_db_work() -> str:
            try:
                set_style_profile(db, acct["id"], profile.to_dict())
            except Exception as exc:
                persist_err = fmt_exc(exc)[:200]
                _record_style_data_audit(
                    db,
                    event_type=event_type,
                    actor_user_id=user["id"],
                    actor_email=user.get("email") or "",
                    account_id=acct["id"],
                    outcome="failure",
                    detail=f"persist: {persist_err}",
                )
                return persist_err
            _record_style_data_audit(
                db,
                event_type=event_type,
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="success",
                detail=f"samples={profile.sample_count}",
            )
            audit_phi_access(
                db,
                actor_user_id=user["id"],
                account=acct,
                operation=event_type,
            )
            return ""

        persist_err = await db_call(_mine_persist_db_work)
        if persist_err:
            return HTMLResponse(
                _mine_result_fragment(
                    state="error",
                    title="Could not save the summary",
                    body=(
                        "The AI built a writing-style summary but the "
                        "server couldn't save it. Try the button "
                        "again."
                    ),
                    folder_label=sent_folder,
                ),
                status_code=200,
            )

    # Both branches render the same descriptor fragment; the commit
    # branch also got the audit + persistence above.
    return HTMLResponse(
        _mine_result_fragment(
            state="ok",
            title=(
                "Saved — writing-style summary built from "
                f"{profile.sample_count} sent messages"
                if commit else
                "Preview — this is what would be saved"
            ),
            body=_format_profile_for_preview(profile),
            folder_label=sent_folder,
            committed=commit,
            # Preview-only: when the resolved mine-limit exceeded the
            # inline ceiling, render a notice that Preview ran against
            # fewer messages than the operator's "Messages to mine"
            # setting. Commit path never reaches here when over the
            # ceiling (bulk-runner hand-off returned earlier).
            clamped_from=None if commit else preview_clamped_from,
        ),
        status_code=200,
    )


def _format_profile_for_preview(profile) -> str:
    """Render a StyleProfile as an operator-readable HTML block.

    Keeps the shape parallel to the existing
    ``profile_preview`` line on the page — persona summary first
    (the most human-readable field), then the structured knobs
    underneath. Output is safe to inject into the page because we
    HTML-escape every dynamic value here.
    """
    from html import escape as _e
    parts: list[str] = []
    persona = (profile.persona_summary or "").strip()
    if persona:
        parts.append(
            f"<p><strong>Persona:</strong> {_e(persona)}</p>"
        )
    rows: list[tuple[str, str]] = []
    if profile.greeting:
        rows.append(("Typical greeting", profile.greeting))
    if profile.signoff:
        rows.append(("Typical sign-off", profile.signoff.replace("\n", " / ")))
    if profile.signature:
        rows.append(("Signature block", profile.signature))
    rows.append(("Formality", f"{profile.formality}/5"))
    if profile.avg_sentence_length:
        rows.append((
            "Average sentence length",
            f"~{profile.avg_sentence_length} words",
        ))
    if profile.phrases_used:
        #  — cap the displayed list but say how many more exist so
        # the truncation isn't silent.
        _pu = profile.phrases_used
        _pu_extra = f"  (+{len(_pu) - 10} more)" if len(_pu) > 10 else ""
        rows.append((
            "Phrases you use",
            ", ".join(_pu[:10]) + _pu_extra,
        ))
    if profile.phrases_avoided:
        _pa = profile.phrases_avoided
        _pa_extra = f"  (+{len(_pa) - 5} more)" if len(_pa) > 5 else ""
        rows.append((
            "Phrases the AI should avoid",
            ", ".join(_pa[:5]) + _pa_extra,
        ))
    if rows:
        parts.append("<ul style='margin:0.25rem 0 0 1rem;'>")
        for label, value in rows:
            parts.append(
                f"<li><strong>{_e(label)}:</strong> {_e(str(value))}</li>"
            )
        parts.append("</ul>")
    parts.append(
        f"<p style='color:var(--pico-muted-color);font-size:0.85em;'>"
        f"Built from {int(profile.sample_count)} sent messages "
        f"&middot; AI model: {_e(profile.model_used or 'unknown')}"
        f"</p>"
    )
    return "".join(parts)


def _format_alias_descriptors_for_preview(
    descriptors: dict | None,
    unknown_counts: list[tuple[str, int]] | None,
) -> str:
    """Render the alias-aware result fragment.

    Lists one block per persisted alias plus a "From addresses not
    in your list" footer when the corpus contained messages from
    addresses outside the declared alias set. Operator-facing copy:
    plain English, no jargon. Used by both preview + mine-now.
    """
    from html import escape as _e
    parts: list[str] = []
    if not descriptors:
        parts.append(
            "<p>No usable sent messages were found for any address. "
            "Send a few replies from each address you write from and "
            "try again.</p>"
        )
    else:
        parts.append(
            f"<p>Built <strong>{len(descriptors)}</strong> "
            f"writing-style summar{'y' if len(descriptors) == 1 else 'ies'} "
            f"— one per ``From:`` address found in the sent corpus.</p>"
        )
        for addr in sorted(descriptors.keys()):
            prof = descriptors[addr]
            persona = (
                getattr(prof, "persona_summary", "") or ""
            ).strip()
            samples = int(getattr(prof, "sample_count", 0) or 0)
            label = addr if addr else "(no From: address)"
            parts.append(
                "<article style='border-left:3px solid "
                "var(--pico-muted-border-color);padding:0.4rem 0.8rem;"
                "margin:0.5rem 0;'>"
                f"<p style='margin:0;'><strong>From: "
                f"{_e(label)}</strong> "
                f"<small style='color:var(--pico-muted-color);'>"
                f"&middot; {samples} messages</small></p>"
            )
            if persona:
                #  — trailing ellipsis when the persona is clipped
                # so the operator knows there's more than the preview.
                _persona_clip = "…" if len(persona) > 200 else ""
                parts.append(
                    f"<p style='margin:0.3rem 0 0 0;font-size:0.9em;'>"
                    f"{_e(persona[:200])}{_persona_clip}</p>"
                )
            parts.append("</article>")
    if unknown_counts:
        parts.append(
            "<p style='margin-top:0.75rem;'>"
            "<strong>Found messages from addresses not in your "
            "alias list:</strong></p>"
            "<ul style='margin:0.25rem 0 0 1rem;font-size:0.9em;'>"
        )
        for addr, count in unknown_counts:
            parts.append(
                f"<li><code>{_e(addr or '(empty)')}</code> "
                f"&mdash; {int(count)} messages</li>"
            )
        parts.append("</ul>")
        parts.append(
            "<p style='color:var(--pico-muted-color);font-size:0.85em;'>"
            "Add any of these on the account's settings page if you "
            "want a separate writing-style for them too.</p>"
        )
    return "".join(parts)


def _mine_result_fragment(
    *,
    state: str,
    title: str,
    body: str,
    folder_label: str | None = None,
    committed: bool = False,
    clamped_from: int | None = None,
) -> str:
    """Render the HTMX response fragment that swaps into
    ``#mine-result-<account_id>``.

    ``state`` is one of ``ok`` / ``empty`` / ``error`` and picks
    the left-border colour (operator-visible signal that this is
    a success / soft-fail / hard-fail). ``body`` may contain pre-
    rendered HTML; the caller is responsible for escaping its
    inputs (``_format_profile_for_preview`` does this). Any string
    we substitute in HERE is HTML-escaped to keep the fragment
    XSS-safe.

    ``clamped_from`` — when the preview path's resolved mine-limit
    exceeded :data:`STYLE_LEARNING_INLINE_LIMIT_CEILING` and got
    silently clamped to the ceiling, the original (pre-clamp) value
    is passed here so the operator sees an explicit notice that
    Preview ran against fewer messages than their "Messages to
    mine" setting. Mine Now bypasses this clamp via the bulk-runner
    hand-off; Preview does not (would create a permanent triage_jobs
    row for a throwaway descriptor).
    """
    from html import escape as _e
    from email_triage.web.db import STYLE_LEARNING_INLINE_LIMIT_CEILING
    color_for_state = {
        "ok": "var(--pico-ins-color)",
        "empty": "var(--pico-muted-border-color)",
        "error": "var(--pico-del-color)",
    }
    color = color_for_state.get(state, "var(--pico-muted-border-color)")
    folder_line = ""
    if folder_label:
        folder_line = (
            f"<p style='color:var(--pico-muted-color);font-size:0.85em;"
            f"margin:0 0 0.5rem 0;'>"
            f"Folder used: <code>{_e(folder_label)}</code>"
            f"</p>"
        )
    clamp_line = ""
    if clamped_from and clamped_from > STYLE_LEARNING_INLINE_LIMIT_CEILING:
        clamp_line = (
            f"<p style='color:var(--pico-muted-color);font-size:0.85em;"
            f"margin:0 0 0.5rem 0;'>"
            f"Previewed from the <strong>{STYLE_LEARNING_INLINE_LIMIT_CEILING}"
            f"</strong> most-recent messages. Your <em>Messages to mine</em> "
            f"setting is <strong>{_e(str(int(clamped_from)))}</strong> — "
            f"click <em>Mine the Sent Items Now</em> to run against the full "
            f"setting (large scans run in the background and appear under "
            f"Triage → Bulk runs)."
            f"</p>"
        )
    discard_line = ""
    if state == "ok" and not committed:
        # Dry-run output — let the operator dismiss it. The button
        # just clears the result container client-side.
        discard_line = (
            "<p style='margin-top:0.5rem;'>"
            "<button type='button' class='outline secondary' "
            "onclick=\"this.closest('[id^=&quot;mine-result-&quot;]')."
            "innerHTML=''\">Discard preview</button>"
            "</p>"
        )
    return (
        f"<article style='border-left:3px solid {color};"
        f"padding:0.5rem 1rem;margin-top:0.5rem;'>"
        f"<p><strong>{_e(title)}</strong></p>"
        f"{folder_line}"
        f"{clamp_line}"
        f"<div>{body}</div>"
        f"{discard_line}"
        f"</article>"
    )


@router.post("/profile/style-data/preview", response_class=HTMLResponse)
async def profile_style_data_preview(request: Request):
    """ — dry-run M-3 distillation. Returns the descriptor the
    install would save, without writing it. Operator uses this to
    sanity-check the privacy / style trade before opting in.
    """
    return await _mine_or_preview(request, commit=False)


@router.post("/profile/style-data/mine-now", response_class=HTMLResponse)
async def profile_style_data_mine_now(request: Request):
    """ — on-demand M-3 distillation. Runs the same distillation
    as the scheduled tick + persists the result + writes an audit
    row. Operator uses this to refresh after a big style shift.
    """
    return await _mine_or_preview(request, commit=True)


@router.get("/accounts/api-keys")
async def api_keys_page(request: Request, user: RequireUser):
    """Legacy URL — API Keys folded into the consolidated Security tab
    (2026-06-07). 303-redirect to /profile/security so bookmarks, the
    /accounts tab strip, and deep links keep resolving.

    The ``user: RequireUser`` dependency runs first, so anonymous
    callers still bounce to /login (preserves the pre-consolidation
    auth-gate contract) before the redirect fires. The POST (mint) and
    DELETE (revoke) handlers below stay put as action endpoints — the
    Create/Revoke controls on the Security page still target them.
    """
    return RedirectResponse("/profile/security", status_code=303)


@router.post("/accounts/api-keys", response_class=HTMLResponse)
async def api_keys_create(request: Request, user: RequireUserFragment):
    """Mint a new API key. Returns an HTMX fragment that shows the
    raw key exactly once — it's stored hashed server-side."""
    db = get_db(request)
    form = await request.form()
    name = (form.get("name") or "").strip()
    if not name:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">Name is required.</small>',
            status_code=400,
        )

    # Determine target user. Admins can create keys for other users;
    # regular users can only create for themselves (the form enforces
    # this client-side via a hidden field, but we re-check here).
    target_email = (form.get("user_email") or user["email"]).strip()
    is_admin = _is_admin(user)  # N-222h R22 (was: user["role"] == "admin")
    if target_email != user["email"] and not is_admin:
        return HTMLResponse("Forbidden", status_code=403)

    from email_triage.web.auth import (
        get_user_by_email, generate_api_key, hash_api_key, store_api_key,
    )
    #  — get_user_by_email touches the shared connection; off-loop.
    target = await db_call(get_user_by_email, db, target_email)
    if target is None:
        # N-68 — target_email is form-derived (form.get("user_email")); escape
        # it before it lands in the HTML body (reflected-XSS class).
        import html as _html_mod
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">'
            f'Unknown user: {_html_mod.escape(target_email)}</small>',
            status_code=404,
        )

    # Expires-at selector: blank = never, or an "Nd" relative offset.
    expires_choice = (form.get("expires") or "never").strip()
    expires_at: str | None = None
    if expires_choice.endswith("d") and expires_choice[:-1].isdigit():
        from datetime import timedelta
        days = int(expires_choice[:-1])
        expires_at = to_utc_iso(datetime.now(timezone.utc) + timedelta(days=days))

    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    #  — store_api_key is @db_write; dispatch off the loop thread.
    key_id = await db_call(
        store_api_key,
        db, key_hash, name, target["id"], expires_at,
        actor_user_id=user["id"],
        actor_email=user["email"],
        source="ui",
    )

    # Alias for the "tell your AI assistant to use this" instructions.
    # Default is the email local-part, but the form lets the user
    # override if their admin gave them a specific alias.
    alias_raw = (form.get("alias") or "").strip().lower()
    if not alias_raw or not all(c.isalnum() or c in "_-" for c in alias_raw):
        alias_raw = target_email.split("@", 1)[0].lower()
    # Keep the alias short + safe for CLI use — no quoting surprises.
    alias = "".join(c for c in alias_raw if c.isalnum() or c in "_-")[:32] or "me"

    # The exact sentence the user should send to their AI assistant.
    # Kept literal so a non-technical user can copy-paste it verbatim.
    agent_sentence = (
        f"Please save my new email-triage token. "
        f"Run this command: email-triage-api register-me "
        f"--as {alias} --token {raw_key}"
    )

    # Return the "shown-once" panel. JS copy-button is nice but the
    # click-to-select input is enough — keeps us out of any clipboard
    # permission funk.
    return HTMLResponse(
        f'<article style="border-left:3px solid var(--pico-ins-color);'
        f'padding:0.75rem 1rem;">'
        f'<p><strong>&#10003; Token created.</strong>'
        f' <strong>Copy this value now.</strong> It will not be shown again.'
        f' If you lose it, come back and create a new one.</p>'
        f'<input type="text" readonly onclick="this.select()"'
        f' value="{raw_key}"'
        f' style="width:100%;font-family:var(--pico-font-family-monospace);'
        f' font-size:0.85rem;">'
        f'<p><small>'
        # N-68 — name/target_email/expires_choice are user/form-derived;
        # escape before they land in the HTML body (reflected-XSS class). The
        # widened N-68 pin caught target_email here (a 2nd profile.py site).
        # raw_key (generated) + alias (isalnum-sanitised) are safe as-is.
        f'Name: <strong>{_html.escape(str(name))}</strong> &middot; '
        f'For: <strong>{_html.escape(target_email)}</strong> &middot; '
        f'Alias: <strong>{alias}</strong> &middot; '
        f'Expires: <strong>{_html.escape(str(expires_choice))}</strong>'
        f'</small></p>'

        f'<hr style="margin:0.75rem 0;">'
        f'<p><strong>Using an AI assistant?</strong> Paste this message '
        f'into its chat window <em>word for word</em> — it will save the '
        f'token so your assistant can act on your mail and calendar:</p>'
        f'<textarea readonly onclick="this.select()" rows="3"'
        f' style="width:100%;font-family:var(--pico-font-family-monospace);'
        f' font-size:0.85rem;resize:vertical;">{agent_sentence}</textarea>'
        f'<p><small style="color:var(--pico-muted-color);">'
        f'After your assistant runs that command once, every future request '
        f'("summarise today\'s unread mail", "find me a free 30-minute slot" '
        f'etc.) uses this token automatically. You don\'t have to paste it '
        f'again unless you create a brand-new token later.'
        f'</small></p>'

        f'<p><small><a href="/accounts/api-keys">Refresh the list</a> '
        f'to see this token alongside any others you have.</small></p>'
        f'</article>'
    )


@router.delete("/accounts/api-keys/{key_id}", response_class=HTMLResponse)
async def api_keys_delete(request: Request, key_id: int, user: RequireUserFragment):
    """Revoke an API key. Ownership required (admin or own key)."""
    db = get_db(request)
    from email_triage.web.auth import delete_api_key

    def _api_key_delete_snapshot(
        db, key_id, actor_user_id, actor_email, user_role,
    ):
        """ phase 2 — auth check + delete in one threadpool hop."""
        row = db.execute(
            "SELECT user_id FROM api_keys WHERE id = ?", (key_id,),
        ).fetchone()
        if row is None:
            return "not_found"
        if not can_modify_owned_resource(
            row["user_id"], requester_id=actor_user_id, role=user_role, admin_bypass=True):
            return "forbidden"
        delete_api_key(
            db, key_id, actor_user_id=actor_user_id,
            actor_email=actor_email, source="ui",
        )
        return "ok"

    status = await db_call(
        _api_key_delete_snapshot, db, key_id, user["id"], user["email"],
        user["role"],
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)

    return HTMLResponse("")


# ---------------------------------------------------------------------------
# /profile/watches —  match-and-fire watch editor (replaces the
# per-account /accounts/{id}/edit?tab=watches surface, which is retired).
#
# Schema shape post-migration v17: one ``email_watches`` row per
# (watch_group_id, account_id). The editor reads all rows where the
# current user owns at least one and groups them by ``watch_group_id``
# (or ``(created_by_user_id, name)`` for legacy NULL-group rows). Save
# fans out one row per ticked account_id; unticked accounts get their
# row DELETEd.
#
# HIPAA gate: accounts flagged HIPAA render as disabled checkboxes;
# the operator can't bind a cross-account watch to a PHI mailbox from
# this surface (separate watch made on the account directly). On
# multi-account save, the route writes an ``access_log`` audit row
# per non-owner account touched (per feedback_hipaa_actor_owner_gate).
# ---------------------------------------------------------------------------


def _profile_watches_user_accounts(db, user) -> list[dict]:
    """List accounts the user can attach a watch to.

    Owner accounts + delegated accounts. Each entry gets
    ``is_hipaa`` + ``is_delegate`` + ``is_owner`` flags so the template
    can render a disabled-with-reason checkbox for accounts the
    operator can't bind from this surface, AND enable the HIPAA
    checkbox for first-party self-access (owner ticking own HIPAA
    account per §164.502(a) self-disclosure carve-out).

    HIPAA gate by actor:
      * Owner of a HIPAA account = first-party = checkbox ENABLED.
      * Non-owner (admin / delegate) of a HIPAA account = third-party
        = checkbox DISABLED (template renders reason chip).
    """
    from email_triage.web.db import list_email_accounts, account_email
    # N-109: per-account watch checkbox list — a deactivated (creds-purged)
    # account can't be watched (the watcher skips is_active=0), so hide it from
    # the picker; re-enabling via Edit restores it to the list.
    rows = list_email_accounts(db, user_id=user["id"], active_only=True)
    out: list[dict] = []
    actor_id = user["id"]
    for r in rows:
        owner_id = r.get("user_id")
        out.append({
            "id": r["id"],
            "name": r.get("name") or "",
            # census run17  — account_email SSOT, not the open-coded key.
            "email_address": account_email(r),
            "is_hipaa": is_account_hipaa(r),
            "is_delegate": bool(r.get("is_delegate")),
            "is_owner": owner_id == actor_id,
            "user_id": owner_id,
        })
    return out


def _profile_watches_page_snapshot(db, user) -> dict:
    """One threadpool hop: list user-owned watches + user's accounts."""
    from email_triage.web.email_watches import list_watch_groups_for_user
    return {
        "groups": list_watch_groups_for_user(db, user["id"]),
        "user_accounts": _profile_watches_user_accounts(db, user),
    }


@router.get("/profile/watches", response_class=HTMLResponse)
async def profile_watches_page(request: Request, user: RequireUser):
    """List the operator's watches + show the New-watch form."""
    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(_profile_watches_page_snapshot, db, user)

    # Empty watch shell for the "New watch" form. Default to no
    # accounts ticked — the operator must opt in.
    from email_triage.web.email_watches import EmailWatch
    blank_watch = EmailWatch(enabled=True)

    return await _render(templates, request, "profile/watches.html", {
        "user": user,
        "current_user": user,
        "groups": snap["groups"],
        "user_accounts": snap["user_accounts"],
        "group": None,
        "w": blank_watch,
        "errors": [],
        "save_msg": None,
    })


@router.get(
    "/profile/watches/{group_id:path}/edit", response_class=HTMLResponse,
)
async def profile_watches_edit_page(request: Request, group_id: str, user: RequireUser):
    """Edit an existing watch group (fan-out across accounts)."""
    db = get_db(request)
    templates = get_templates(request)
    from email_triage.web.email_watches import (
        list_watch_groups_for_user, get_watch_group,
    )

    def _fetch(db, user, group_id):
        groups = list_watch_groups_for_user(db, user["id"])
        group = None
        for g in groups:
            if g["group_id"] == group_id:
                group = g
                break
        return {
            "groups": groups,
            "group": group,
            "user_accounts": _profile_watches_user_accounts(db, user),
        }

    snap = await db_call(_fetch, db, user, group_id)
    if snap["group"] is None:
        return HTMLResponse("Watch not found", status_code=404)

    return await _render(templates, request, "profile/watches.html", {
        "user": user,
        "current_user": user,
        "groups": snap["groups"],
        "user_accounts": snap["user_accounts"],
        "group": snap["group"],
        "w": snap["group"]["representative"],
        "errors": [],
        # PRG flash: the save POSTs redirect here with the count-only notice
        # (how MANY PHI accounts were skipped from the fan-out, never which) via
        # msg_qs; read it so the confirmation + HIPAA-skip count actually render
        # (census run14 #7 live-bug).
        "save_msg": read_flash(request)[0],
    })


def _build_watch_save_notice(target_ids: list, hipaa_attempts: list) -> str:
    """The watch-save confirmation notice — COUNT-ONLY (it states how MANY PHI
    accounts were skipped from the fan-out, never WHICH; no account name or
    address rides the PRG redirect). ONE builder so the save-new and
    save-existing paths cannot drift (PD#5 — they were a byte-identical copy)."""
    msg = f"Watch saved on {len(target_ids)} "
    msg += "account" if len(target_ids) == 1 else "accounts"
    if hipaa_attempts:
        msg += (
            f". {len(hipaa_attempts)} account(s) marked Protected "
            "Health Info were skipped — set a watch on those accounts "
            "directly."
        )
    return msg


def _profile_watches_collect_target_ids(
    form, user_accounts: list[dict],
) -> tuple[list[int], list[int]]:
    """Pull ``account_ids[]`` from the form and filter to entries
    the actor is allowed to bind a watch to.

    Rules:
      * Owner of any account (incl. HIPAA-flagged) — ALLOWED.
        First-party self-access per §164.502(a) self-disclosure
        carve-out. The owner's own mailbox is not third-party PHI.
      * Delegate of an account — DROPPED. Delegate is read-only on
        watches; the editor renders the checkbox disabled but a
        hand-crafted POST could still include the id, so enforce
        server-side too.
      * Non-owner HIPAA accounts (admin viewing someone else's
        HIPAA mailbox) — DROPPED into ``hipaa_attempts`` so the
        caller can render a save message. Admin-actor third-party
        access on a HIPAA mailbox needs its own surface (audit row
        + explicit confirmation) — not the bulk fan-out.

    Returns ``(allowed, hipaa_attempts)``:
      * ``allowed`` — account_ids that survived the filter, ready
                      to fan out into email_watches rows.
      * ``hipaa_attempts`` — account_ids the operator ticked that
                      were silently dropped because actor != owner
                      AND account is HIPAA-flagged. Caller renders
                      a save message naming them.

    2026-05-11 fix: previous version dropped ALL HIPAA accounts
    including the owner's own, leaving the operator with no surface
    to create a watch on their own HIPAA-flagged mailbox after
     removed the per-account Watches tab.
    """
    raw = form.getlist("account_ids") if hasattr(form, "getlist") else []
    requested: set[int] = set()
    for v in raw:
        _iv = parse_int_or_none(v)  # N-219c/9 R23: SSOT
        if _iv is not None:
            requested.add(_iv)

    accounts_by_id = {a["id"]: a for a in user_accounts}
    allowed: list[int] = []
    hipaa_attempts: list[int] = []
    for acct_id in sorted(requested):
        a = accounts_by_id.get(acct_id)
        if a is None:
            # Not the user's account at all — silently drop.
            continue
        if a.get("is_delegate"):
            # Delegate is read-only on watches.
            continue
        if a.get("is_hipaa") and not a.get("is_owner"):
            # Third-party touching a HIPAA mailbox via the bulk
            # editor — not allowed from this surface.
            hipaa_attempts.append(acct_id)
            continue
        # Owner of own HIPAA mailbox falls through to allowed —
        # §164.502(a) self-disclosure carve-out.
        allowed.append(acct_id)
    return allowed, hipaa_attempts


@router.post(
    "/profile/watches/new/save", response_class=HTMLResponse,
)
async def profile_watches_save_new(request: Request, user: RequireUser):
    """Create a new watch group across the ticked accounts."""
    db = get_db(request)
    templates = get_templates(request)
    form = await request.form()

    from email_triage.web.email_watches import (
        save_watch_group, validate, hmac_secret_key,
    )

    user_accounts = await db_call(
        _profile_watches_user_accounts, db, user,
    )
    target_ids, hipaa_attempts = _profile_watches_collect_target_ids(
        form, user_accounts,
    )

    w = _parse_watch_form(form)
    errors = validate(w)
    if not target_ids:
        errors.append(
            "Pick at least one account for this watch to fire on."
        )

    if errors:
        groups = await db_call(
            lambda db, u: __import__(
                "email_triage.web.email_watches",
                fromlist=["list_watch_groups_for_user"],
            ).list_watch_groups_for_user(db, u["id"]),
            db, user,
        )
        return await _render(templates, request, "profile/watches.html", {
            "user": user, "current_user": user,
            "groups": groups, "user_accounts": user_accounts,
            "group": None, "w": w, "errors": errors,
            "save_msg": None,
        })

    secrets = request.app.state.secrets

    def _save_and_audit(db):
        group_id_final, created_watch_ids, _deleted = save_watch_group(
            db,
            user_id=user["id"],
            group_id=None,
            name=w.name,
            enabled=w.enabled,
            filter_=w.filter,
            actions=w.actions,
            target_account_ids=target_ids,
        )
        # HIPAA §164.312(b) audit per
        # feedback_hipaa_actor_owner_gate.md: write a row for every
        # non-owner account this actor touched. The owner-self case
        # (actor_user_id == account.user_id) is first-party and not
        # audited.
        from email_triage.web.db import (
            record_access_event, get_email_account,
        )
        from email_triage.triage_logging import is_account_hipaa as _iah
        for acct_id in target_ids:
            acct = get_email_account(db, acct_id)
            if acct is None:
                continue
            from email_triage.web.account_scope import is_account_owner
            if (not is_account_owner(acct, user["id"])
                    and _iah(acct)):
                # Defensive — should already be filtered out, but
                # belt-and-braces if a delegate-grant matrix changes
                # mid-form.
                record_access_event(
                    db,
                    actor_user_id=user["id"],
                    method="POST",
                    route="/profile/watches/new/save",
                    account_id=acct_id,
                    message_id=None,
                    status_code=200,
                    outcome="watch_save",
                    detail=f'{{"group_id":"{group_id_final}"}}',
                )
        return group_id_final, created_watch_ids

    group_id_final, created_watch_ids = await db_call(_save_and_audit, db)

    # Mint HMAC secret per newly-inserted watch row. Each fan-out row
    # has its OWN signing secret so a leaked-receiver scenario is
    # contained to one account's worth of traffic.
    # N-349 hybrid (2026-07-05, operator decision landed) — route the
    # watch-HMAC hydration through the `get_or_mint_secret` SSOT with
    # fail-CLOSED-plus-CLI-bypass semantics. See sibling at
    # web/routers/agent_api.py:2510 + web/routers/ui/profile.py:3646.
    from email_triage.secrets import get_or_mint_secret
    from email_triage.web.db import (
        consume_hmac_clobber_bypass,  # N-363 atomic check+consume (2026-07-05)
    )
    from email_triage.db.audit import record_hmac_clobber_bypass_consumed
    from email_triage.web._audit import safe_audit_write
    import secrets as _stdlib_secrets
    for wid in created_watch_ids:
        _hmac_key = hmac_secret_key(wid)
        _wid = wid
        try:
            # N-349b Item 3 (2026-07-08): async-DB seam wrap. See sibling
            # at agent_api.py:2519 for the RLock re-entry rationale.
            await db_call(
                get_or_mint_secret,
                secrets,
                _hmac_key,
                lambda: _stdlib_secrets.token_urlsafe(32),
                # N-363 R31 (2026-07-05 atomic check+consume — SME F1
                # residual). See sibling at agent_api.py:2510 + this
                # file at :3646 for the same pattern.
                bypass_check=lambda: consume_hmac_clobber_bypass(db),
                bypass_clear=None,
                # N-349b Item 1 (2026-07-07): HMAC-chained emitter-owned
                # audit row on bypass consumption. Routed through
                # `safe_audit_write` for /health drift-counter parity.
                # `actor_user_id=user["id"]` closes the
                # §164.308(a)(4)(ii)(C) traceability (SME panel 2026-07-07
                # DA fix 1 + hipaa-sme fix 1). Late-bind via default arg
                # so the loop-variable capture stays correct.
                # See sibling at agent_api.py:2510.
                bypass_audit_emit=lambda k=_hmac_key, w=_wid, aid=user["id"]: safe_audit_write(
                    lambda: record_hmac_clobber_bypass_consumed(
                        db, secret_key=k,
                        actor_user_id=aid, watch_id=w,
                    ),
                    description=f"hmac_clobber_bypass_consumed watch={w}",
                ),
            )
        except SecretsDecryptError:
            # Fail-CLOSED per N-349 hybrid. Operator arms
            # `secrets allow-hmac-clobber-once` to recover.
            _log.error(
                "watch HMAC secret unreadable — fail-CLOSED per N-349 hybrid; "
                "operator arms `secrets allow-hmac-clobber-once` to mint fresh",
                watch_id=wid,
            )
        except Exception:
            # SME panel 2026-07-05 DB-SME #2 — parity with agent_api
            # sibling: log rather than silently swallow. Read-only
            # secrets backend, quota, or DB failure lands here; the
            # watch row exists but the receiver won't verify signatures.
            _log.warning(
                "watch HMAC secret store failed",
                watch_id=wid,
            )

    msg = _build_watch_save_notice(target_ids, hipaa_attempts)
    _log.info(
        "Profile watch saved (new)",
        user=user["email"],
        group_id=group_id_final,
        account_count=len(target_ids),
        hipaa_skipped=len(hipaa_attempts),
    )
    return RedirectResponse(
        f"/profile/watches/{group_id_final}/edit?{msg_qs(msg)}",
        status_code=303,
    )


@router.post(
    "/profile/watches/{group_id:path}/save", response_class=HTMLResponse,
)
async def profile_watches_save_existing(request: Request, group_id: str, user: RequireUser):
    """Update an existing watch group across the ticked accounts."""
    db = get_db(request)
    templates = get_templates(request)
    form = await request.form()

    from email_triage.web.email_watches import (
        save_watch_group, validate, get_watch_group,
        list_watch_groups_for_user, hmac_secret_key,
    )

    # Ownership pre-check: refuse if the group_id isn't visible to
    # this user. Avoids enumeration attacks on the synthetic group
    # key shape (gid:<uuid> / legacy:<creator>:<name>).
    def _ownership(db, user, group_id):
        return get_watch_group(db, group_id, user["id"])

    existing = await db_call(_ownership, db, user, group_id)
    if existing is None:
        return HTMLResponse("Watch not found", status_code=404)

    user_accounts = await db_call(
        _profile_watches_user_accounts, db, user,
    )
    target_ids, hipaa_attempts = _profile_watches_collect_target_ids(
        form, user_accounts,
    )

    w = _parse_watch_form(form)
    errors = validate(w)
    if not target_ids:
        errors.append(
            "Pick at least one account for this watch to fire on."
        )

    if errors:
        groups = await db_call(
            list_watch_groups_for_user, db, user["id"],
        )
        return await _render(templates, request, "profile/watches.html", {
            "user": user, "current_user": user,
            "groups": groups, "user_accounts": user_accounts,
            "group": existing, "w": w, "errors": errors,
            "save_msg": None,
        })

    secrets = request.app.state.secrets

    def _save(db):
        return save_watch_group(
            db,
            user_id=user["id"],
            group_id=group_id,
            name=w.name,
            enabled=w.enabled,
            filter_=w.filter,
            actions=w.actions,
            target_account_ids=target_ids,
        )

    group_id_final, created_watch_ids, deleted_watch_ids = await db_call(
        _save, db,
    )

    # Mint HMAC for newly-inserted rows; revoke for deleted rows.
    # N-349 hybrid (2026-07-05, operator decision landed) — route the
    # watch-HMAC hydration through the `get_or_mint_secret` SSOT with
    # fail-CLOSED-plus-CLI-bypass semantics. See sibling at :3543.
    from email_triage.secrets import get_or_mint_secret as _get_or_mint_secret
    from email_triage.web.db import (
        consume_hmac_clobber_bypass as _consume_bypass,  # N-363 atomic
    )
    from email_triage.db.audit import (
        record_hmac_clobber_bypass_consumed as _emit_bypass_consumed,
    )
    # NOTE: import `safe_audit_write` under its canonical name — the
    # audit-emit swallow pin's seam-wrapper walker does not track an
    # ImportFrom asname on this SSOT (only `db_call as ...` is asname-
    # tracked). Aliasing would slip past the pin's swallow-safe-lambda
    # detection and fire a false-positive offender.
    from email_triage.web._audit import safe_audit_write
    import secrets as _stdlib_secrets
    for wid in created_watch_ids:
        _hmac_key = hmac_secret_key(wid)
        _wid = wid
        try:
            # N-349b Item 3 (2026-07-08): async-DB seam wrap. See sibling
            # at agent_api.py:2519 for the RLock re-entry rationale.
            await db_call(
                _get_or_mint_secret,
                secrets,
                _hmac_key,
                lambda: _stdlib_secrets.token_urlsafe(32),
                # N-363 R31 (2026-07-05 atomic check+consume).
                bypass_check=lambda: _consume_bypass(db),
                bypass_clear=None,
                # N-349b Item 1 (2026-07-07): HMAC-chained emitter-owned
                # audit row on bypass consumption. Routed through
                # `safe_audit_write` for /health drift-counter parity.
                # `actor_user_id=user["id"]` closes §164.308(a)(4)(ii)(C)
                # traceability (SME panel 2026-07-07 DA fix 1). See :3543.
                bypass_audit_emit=lambda k=_hmac_key, w=_wid, aid=user["id"]: safe_audit_write(
                    lambda: _emit_bypass_consumed(
                        db, secret_key=k,
                        actor_user_id=aid, watch_id=w,
                    ),
                    description=f"hmac_clobber_bypass_consumed watch={w}",
                ),
            )
        except SecretsDecryptError:
            # Fail-CLOSED per N-349 hybrid. Operator arms
            # `secrets allow-hmac-clobber-once` to recover.
            _log.error(
                "watch HMAC secret unreadable — fail-CLOSED per N-349 hybrid; "
                "operator arms `secrets allow-hmac-clobber-once` to mint fresh",
                watch_id=wid,
            )
        except Exception:
            # SME panel 2026-07-05 DB-SME #2 — parity with agent_api
            # sibling: log rather than silently swallow.
            _log.warning(
                "watch HMAC secret store failed",
                watch_id=wid,
            )

    _log.info(
        "Profile watch saved (existing)",
        user=user["email"],
        group_id=group_id_final,
        account_count=len(target_ids),
        created=len(created_watch_ids),
        deleted=len(deleted_watch_ids),
        hipaa_skipped=len(hipaa_attempts),
    )

    # The save-existing path previously redirected a bare ?saved=1, dropping the
    # HIPAA-skip notice entirely (census run14 #7 live-bug); carry the shared
    # COUNT-ONLY notice through the PRG via msg_qs.
    msg = _build_watch_save_notice(target_ids, hipaa_attempts)
    return RedirectResponse(
        f"/profile/watches/{group_id_final}/edit?{msg_qs(msg)}",
        status_code=303,
    )


@router.post(
    "/profile/watches/{group_id:path}/delete", response_class=HTMLResponse,
)
async def profile_watches_delete(request: Request, group_id: str, user: RequireUser):
    """Delete every row in a watch group."""
    db = get_db(request)
    from email_triage.web.email_watches import (
        get_watch_group, delete_watch,
    )

    def _delete(db, user, group_id):
        g = get_watch_group(db, group_id, user["id"])
        if g is None:
            return 0
        count = 0
        for wid in g["watch_ids"]:
            if delete_watch(db, wid):
                count += 1
        return count

    deleted = await db_call(_delete, db, user, group_id)
    if deleted == 0:
        return HTMLResponse("Watch not found", status_code=404)

    _log.info(
        "Profile watch deleted",
        user=user["email"],
        group_id=group_id,
        rows_deleted=deleted,
    )
    return RedirectResponse("/profile/watches", status_code=303)


# ===========================================================================
#  — Topic Digest router (My Settings cluster tab + full-page editor)
#
# Topics are USER-scoped (RequireUser, no account_id parameter): a Topic
# spans the user's OWN mailboxes via an in-Topic multiselect. The CRUD
# lives in ``actions/topic_configs.py``; the (band/K) matcher in
# ``actions/topic_matcher.py``; the durable back-scan in
# ``jobs/topic_backscan.py``. This router owns ONLY the URL surface —
# it never classifies, never persists a body, never forks an HMAC chain.
#
# §5 fail-closed authorization (the make-or-break invariant): every
# account a Topic touches (the multiselect, every preview hit) is
# intersected with ``list_email_accounts(db, user_id=requester)`` and
# DROPPED if the requester can't manage it. A Topic is user-scoped but a
# malicious/stale ``selected_account_ids`` could name a foreign account;
# the intersection is the gate, applied PER ACCOUNT, fail-closed.
#
# Templates are owned by the template builder — referenced here by the
# contract names only (profile/_topic_digest.html — master card list;
# profile/_topic_digest_editor.html — full-page editor;
# profile/_topic_digest_preview.html — the HTMX preview/search fragment).
# ===========================================================================


# The self-scoped manageable-account-set SSOT moved to
# ``web/account_scope.py`` (divergence census run12 #1, the multi-id half).
# ``_manageable_account_ids`` / ``_manageable_accounts`` are imported above as
# aliases of ``account_scope.manageable_account_ids`` / ``.manageable_accounts``
# so the existing call sites are unchanged; the membership/intersection sites now
# route through ``is_manageable`` / ``filter_to_manageable`` /
# ``filter_to_manageable_accounts`` (pinned: no inline ``<id> in manageable``).


def _topic_digest_cards_snapshot(db, user: dict) -> list[dict]:
    """Master card-list rows for the tab landing (one DB hop).

    Each card carries: the Topic's ``name`` + first Subject chip (+N more),
    the mailbox COUNT scoped to the requester's manageable set (never a
    raw account_id, never an account they can't manage), a most-restrictive
    HIPAA ``protected`` badge flag, and the last-sent timestamp from
    ``study_digest_state``. Pure read — no write, consistent WAL snapshot.
    """
    from email_triage.actions.topic_configs import list_topics

    manageable = _manageable_account_ids(db, user)
    topics = list_topics(db, user["id"])

    # Resolve HIPAA flags + names for the manageable accounts once.
    acct_by_id: dict[int, dict] = {
        int(a["id"]): a for a in _manageable_accounts(db, user)
    }

    cards: list[dict] = []
    for t in topics:
        # §5: scope the mailbox count to accounts the requester manages.
        scoped_ids = intersect_ids(t.selected_account_ids, manageable)
        # N-81 consistency: route the badge through is_account_hipaa so it
        # reflects EFFECTIVE HIPAA (system flag OR per-account); a raw-column
        # read silently un-showed the padlock on a system-HIPAA install with
        # acct["hipaa"]=0, contradicting the badge's most-restrictive-wins doc.
        from email_triage.triage_logging import is_account_hipaa as _iah_badge
        protected = any(
            _iah_badge(acct_by_id.get(int(aid), {}))
            for aid in scoped_ids
        )
        first_subject = t.subjects[0] if t.subjects else ""
        more = max(0, len(t.subjects) - 1)
        # One readable line: first Subject chip + "+N more" (§3b). A
        # study's name/acronym/sponsor collapse here; the full chip-list
        # lives in the detail editor.
        subject_summary = first_subject
        if subject_summary and more:
            subject_summary = f"{subject_summary} +{more} more"

        # last-sent — most recent across the per-format watermark rows.
        last_sent_at = None
        try:
            row = db.execute(
                "SELECT MAX(last_sent_at) AS mx FROM study_digest_state "
                "WHERE topic_id = ?",
                (int(t.id),),
            ).fetchone()
            if row is not None:
                last_sent_at = row["mx"] if hasattr(row, "keys") else row[0]
        except Exception:
            last_sent_at = None

        cards.append({
            "id": t.id,
            "name": t.name,
            "enabled": t.enabled,
            # Template (profile/_topic_digest.html) reads these names.
            "subject_summary": subject_summary,
            "mailbox_count": len(scoped_ids),
            "protected_mode": protected,
            "last_sent_at": last_sent_at,
        })
    return cards


def _topic_editor_snapshot(db, user: dict, topic_id: int | None) -> dict:
    """Build the full-page editor context: ``topic + manageable_accounts +
    enums`` (the contract ctx bundle), in one DB hop.

    ``topic_id is None`` → a blank new Topic (the ``…/new`` route).
    A non-None id is authorized HERE: the Topic must belong to the
    requester (``user_id`` match) or the editor 404s (returned as
    ``topic=None`` so the caller emits the 404). The enum bundle reuses
    the digest editor's CADENCES/WINDOW_KINDS/… plus the Topic ``MODES``.
    """
    from email_triage.actions.topic_configs import MODES, TopicConfig, get_topic
    from email_triage.actions.digest_configs import (
        CADENCES, COLUMN_KEYS, GROUP_BYS, READ_STATES, RENDER_AS,
        SORT_DIRECTIONS, WINDOW_KINDS,
    )

    manageable = _manageable_accounts(db, user)
    manageable_ids = {int(a["id"]) for a in manageable}

    if topic_id is None:
        topic = TopicConfig(user_id=user["id"], name="")
        authorized = True
    else:
        topic = get_topic(db, int(topic_id))
        # §5 ownership gate: a Topic that isn't the requester's is a 404.
        authorized = topic is not None and can_modify_owned_resource(
            topic.user_id, requester_id=user["id"], admin_bypass=False)
        if not authorized:
            topic = None

    # §5 most-restrictive-wins protected badge on the editor too — fires
    # when ANY selected, manageable account is HIPAA-flagged.
    protected = False
    if topic is not None:
        acct_by_id = {int(a["id"]): a for a in manageable}
        # N-81 consistency: badge through is_account_hipaa (effective HIPAA).
        from email_triage.triage_logging import is_account_hipaa as _iah_badge
        protected = any(
            _iah_badge(acct_by_id.get(aid, {}))
            for aid in intersect_ids(topic.selected_account_ids, manageable_ids)
        )

    #  v3 — the Topic's MUTED senders (thumbs-down learned signals), shown
    # in the editor with an un-mute control. This is the ONLY undo: once a
    # sender is muted its mail never reappears in the Preview/digest, so there's
    # nothing left to thumbs-UP — the editor list is how you reverse a mute.
    muted_senders: list[dict] = []
    if topic is not None and topic_id is not None:
        from email_triage.actions.topic_configs import get_topic_sender_signals
        muted_senders = [
            {
                "addr": s,
                "b64": base64.b64encode(s.encode("utf-8")).decode("ascii"),
            }
            for s in sorted(
                k for k, v in get_topic_sender_signals(db, int(topic_id)).items()
                if v == -1
            )
        ]

    # N-109: the multiselect DISPLAY hides deactivated accounts EXCEPT any the
    # Topic already selected — a now-deactivated selected account stays checked
    # so Save round-trips it (no silent drop). The auth set (manageable_ids) and
    # decoration (acct_by_id) keep the FULL manageable set above; only the
    # rendered options are narrowed.
    _selected_ids = {
        int(aid)
        for aid in (topic.selected_account_ids if topic is not None else ())
    }
    picker_accounts = [
        a for a in manageable
        if a.get("is_active", True) or int(a["id"]) in _selected_ids
    ]

    return {
        "topic": topic,
        "authorized": authorized if topic_id is not None else True,
        "manageable_accounts": picker_accounts,
        "protected": protected,
        "muted_senders": muted_senders,
        "enums": {
            "modes": MODES,
            "cadences": CADENCES,
            "window_kinds": WINDOW_KINDS,
            "read_states": READ_STATES,
            "render_as": RENDER_AS,
            "group_bys": GROUP_BYS,
            "column_keys": COLUMN_KEYS,
            "sort_directions": SORT_DIRECTIONS,
        },
        "errors": [],
    }


@router.get("/profile/topic-digest/new", response_class=HTMLResponse)
async def profile_topic_digest_new(request: Request, user: RequireUser):
    """Full-page blank Topic editor (§3c — committed full-page nav)."""
    db = get_db(request)
    templates = get_templates(request)
    ctx = await db_call(_topic_editor_snapshot, db, user, None)
    return await _render(
        templates, request, "profile/_topic_digest_editor.html", {
            "user": user,
            "current_user": user,
            "active_tab": "topic-digest",
            "is_new": True,
            **ctx,
        },
    )


@router.get(
    "/profile/topic-digest/{topic_id:int}/edit", response_class=HTMLResponse,
)
async def profile_topic_digest_edit(
    request: Request, topic_id: int, user: RequireUser,
):
    """Full-page editor for an existing Topic (§3c).

    404s if the Topic isn't the requester's (§5 ownership gate, resolved
    inside ``_topic_editor_snapshot``).
    """
    db = get_db(request)
    templates = get_templates(request)
    ctx = await db_call(_topic_editor_snapshot, db, user, topic_id)
    if ctx["topic"] is None:
        return HTMLResponse("Topic not found", status_code=404)
    return await _render(
        templates, request, "profile/_topic_digest_editor.html", {
            "user": user,
            "current_user": user,
            "active_tab": "topic-digest",
            "is_new": False,
            **ctx,
        },
    )


def _parse_topic_form(form, user: dict, manageable_ids: set[int]) -> "Any":
    """Build a :class:`TopicConfig` from the editor form, fail-closed on
    the account multiselect.

    §5: ``selected_account_ids`` from the form is INTERSECTED with the
    requester's manageable set — any account id the requester can't manage
    is silently dropped (a tampered/stale POST cannot make a Topic watch a
    foreign mailbox). Subjects arrive as a repeatable ``subjects`` field
    (plural — matches the template's ``name="subjects"`` inputs; a
    singular ``subject`` here silently dropped every chip pre-2026-06-08);
    blanks are dropped. ``mode`` is allow-listed against ``MODES`` (a bad
    value falls back to the default at ``validate``-time, not a 500).
    """
    import re

    from email_triage.actions.topic_configs import TopicConfig, TopicDigest
    from email_triage.actions.digest_configs import (
        DigestSchedule, DigestWindow, DigestFormat,
    )

    raw_id = (form.get("topic_id") or "").strip()
    tid = bounded_int(raw_id, default=0) if raw_id else 0  # N-219c/35 R23: SSOT

    subjects = [s.strip() for s in form.getlist("subjects") if s.strip()]

    # §5 PER-ACCOUNT auth intersection (fail-closed): keep only ids the
    # requester can manage. Junk / non-int values are dropped too.
    selected = intersect_ids(form.getlist("selected_account_ids"), manageable_ids)

    #  v2 — "Keep a match for" is a dropdown (30 / 60 / 90 / Forever / a
    # freeform Custom number). "0" = Forever (validate allows >= 0). The
    # template posts ``retention_days`` (one of those, or "custom") and a
    # ``retention_days_custom`` number used only when "custom" is picked.
    raw_ret = (form.get("retention_days") or "90").strip()
    if raw_ret == "custom":
        retention_days = _safe_int(form.get("retention_days_custom"), 90)  # 
    else:
        # raw_ret is a request value laundered through a local (not a direct
        # form.get accessor) — kept guarded; outside the _safe_int request-parse
        # pin's net (it bans int(<request-accessor>), not int(<local>)).
        retention_days = bounded_int(raw_ret, default=90)  # N-219c R23: SSOT
    if retention_days < 0:
        retention_days = 90

    # Per-Topic confidence floor (operator 2026-06-15): blank => None (inherit
    # the global default ET_TOPIC_MATCH_CONFIDENCE_FLOOR). A present value is kept
    # as a float so an out-of-range typo (e.g. 1.5) is BOUNCED by validate() with
    # an actionable message + the editor re-render, NOT silently reverted. A
    # non-numeric value (shouldn't occur on a number input) falls back to None.
    raw_floor = (form.get("confidence_floor") or "").strip()
    if not raw_floor:
        confidence_floor = None
    else:
        try:
            confidence_floor = float(raw_floor)
        except (TypeError, ValueError):
            confidence_floor = None

    #  v2 — repeatable named digests. Each digest block posts indexed
    # fields ``digest-<i>-<field>``; gather every index that appears, build
    # one TopicDigest per block in index order. A block with no fields at
    # all is skipped (a cloned-but-removed row never submits). Bad enum
    # values fall through to ``validate`` (actionable error), never a 500.
    digest_idx: set[int] = set()
    _idx_re = re.compile(r"^digest-(\d+)-")
    for key, _ in form.multi_items():
        m = _idx_re.match(key)
        if m:
            digest_idx.add(int(m.group(1)))

    digests: list[TopicDigest] = []
    for i in sorted(digest_idx):
        p = f"digest-{i}-"
        cadence = (form.get(p + "cadence") or "daily").strip()
        time_local = (form.get(p + "time") or "08:10").strip()
        days: list[int] = []
        for raw in form.getlist(p + "days"):
            _iv = parse_int_or_none(raw)  # N-219c/11 R23: SSOT
            if _iv is not None:
                days.append(_iv)
        mode = (form.get(p + "mode") or "full").strip()
        render_as = (form.get(p + "render_as") or "table").strip()
        group_by = (form.get(p + "group_by") or "category").strip()
        max_rows = _safe_int(form.get(p + "max_rows"), 50)  # 
        digests.append(TopicDigest(
            id=(form.get(p + "id") or "").strip(),
            name=(form.get(p + "name") or "").strip(),
            enabled=((p + "enabled") in form),
            mode=mode,
            schedule=DigestSchedule(
                cadence=cadence, time_local=time_local,
                days_of_week=days,
            ),
            format=DigestFormat(
                render_as=render_as, group_by=group_by,
                max_rows=max_rows,
                include_body_preview=((p + "include_body_preview") in form),
            ),
        ))

    cfg = TopicConfig(
        id=tid,
        user_id=int(user["id"]),
        name=(form.get("name") or "").strip(),
        subjects=subjects,
        details=(form.get("details") or "").strip(),
        details_source=(form.get("details_source") or "manual").strip()
        or "manual",
        selected_account_ids=selected,
        retention_days=retention_days,
        confidence_floor=confidence_floor,
        digests=digests,
        schedule=DigestSchedule(),
        window=DigestWindow(),
        format=DigestFormat(),
        enabled=("enabled" in form),
    )
    return cfg


@router.post("/profile/topic-digest/save", response_class=HTMLResponse)
async def profile_topic_digest_save(request: Request, user: RequireUser):
    """Create or update a Topic (own endpoint — never the big /profile/save).

    Re-renders ``?tab=topic-digest`` (PRG) on success — mirrors the
    Writing/Meeting own-endpoint pattern so a Topic save never cross-talks
    with the escalation form. On a validation failure, re-renders the
    editor with the error list. §5: the account multiselect is intersected
    with the requester's manageable set inside ``_parse_topic_form`` BEFORE
    the write; updating an EXISTING Topic additionally re-asserts ownership.
    """
    db = get_db(request)
    templates = get_templates(request)
    form = await request.form()

    from email_triage.actions.topic_configs import (
        bump_topic_version, get_topic, upsert_topic, validate,
        TopicScrubBlocked,
    )

    # Per-card "Enabled" autosave (§3b) — the master card list posts
    # ``enabled_only=1`` + ``topic_id`` + the new ``enabled`` checkbox
    # state, expecting an inline confirmation chip (HTMX), NOT a full
    # editor save or a redirect. This path NEVER touches name/subjects/
    # accounts so it does not bump topic_version (design §2 — an enable
    # toggle is not a cache-invalidating change). §5 ownership re-assert.
    if parse_bool(form.get("enabled_only")):
        raw_id = (form.get("topic_id") or "").strip()
        tid = bounded_int(raw_id, default=0) if raw_id else 0  # N-219c/41 R23: SSOT
        desired = ("enabled" in form)

        def _toggle_db_work() -> str:
            existing = get_topic(db, tid)
            if existing is None or not can_modify_owned_resource(existing.user_id, requester_id=user["id"], admin_bypass=False):
                return "not_found"
            existing.enabled = desired
            #  C-V1.2 — the enable-toggle re-save still routes through the
            # fail-closed V1 PHI gate inside upsert_topic. A clean Topic
            # re-verifies for free; a legacy/pre-gate Topic carrying PHI is
            # blocked here rather than silently re-persisted. Surface the
            # block instead of letting it 500 the autosave chip.
            try:
                upsert_topic(db, existing)
            except TopicScrubBlocked as blocked:
                _log.warning(
                    "Topic enable-toggle blocked by V1 PHI scrubber "
                    "(fail-closed)",
                    user=user["email"], topic_id=tid,
                    phi_labels=blocked.labels, scrubber_raised=blocked.raised,
                )
                return "phi_blocked"
            return "ok"

        result = await db_call(_toggle_db_work)
        if result == "not_found":
            return HTMLResponse("Topic not found", status_code=404)
        if result == "phi_blocked":
            return HTMLResponse(
                "Cannot save: this Topic's text contains personal or health "
                "information. Edit the Subjects/Details first.",
                status_code=422,
            )
        _log.info(
            "Topic enabled toggled",
            user=user["email"], topic_id=tid, enabled=desired,
        )
        return HTMLResponse("Saved", status_code=200)

    def _save_db_work():
        manageable_ids = _manageable_account_ids(db, user)
        cfg = _parse_topic_form(form, user, manageable_ids)

        # §5 ownership re-assert on update: an existing id must belong to
        # the requester. A foreign / unknown id is treated as a fresh
        # insert under the requester (id reset to 0) rather than silently
        # clobbering another user's Topic.
        if cfg.id:
            existing = get_topic(db, cfg.id)
            if existing is None or not can_modify_owned_resource(existing.user_id, requester_id=user["id"], admin_bypass=False):
                cfg.id = 0
            else:
                # Preserve created_at + carry the version forward; a
                # name/subjects/accounts/details change bumps it after save.
                cfg.created_at = existing.created_at
                cfg.topic_version = existing.topic_version

        errs = validate(cfg)
        if errs:
            return None, errs, cfg

        #  C-V1.2 — the V1 PHI gate lives inside upsert_topic and is
        # fail-CLOSED: a PHI-pattern trip (or a scrubber that raises) blocks
        # the write. Convert that block into the same validation-error
        # surface so the operator gets an actionable editor message rather
        # than a 500. The Topic is NOT persisted on a block.
        try:
            saved = upsert_topic(db, cfg)
        except TopicScrubBlocked as blocked:
            _log.warning(
                "Topic save blocked by V1 PHI scrubber (fail-closed)",
                user=user["email"],
                topic_id=cfg.id or None,
                phi_labels=blocked.labels,  # labels only — never matched text
                scrubber_raised=blocked.raised,
            )
            return None, [str(blocked)], cfg
        # Any change to name/subjects/details/accounts invalidates the
        # back-scan match cache + re-triggers a fresh scan (design §2).
        if saved.id:
            bump_topic_version(db, saved.id)
        return saved, [], cfg

    saved, errs, submitted = await db_call(_save_db_work)

    if errs:
        # Re-render the editor with the error list AND the operator's
        # submitted values — re-render the parsed ``cfg`` as ``topic`` so a
        # validation bounce never wipes everything they typed (the previous
        # code re-rendered a blank snapshot, discarding all input). Rebuild
        # only the surrounding context (manageable accounts + enums) and
        # recompute the protected flag for the submitted account selection.
        def _err_ctx() -> dict:
            base = _topic_editor_snapshot(db, user, None)
            acct_by_id = {
                int(a["id"]): a for a in base["manageable_accounts"]
            }
            # N-81 consistency: badge through is_account_hipaa (effective HIPAA).
            from email_triage.triage_logging import is_account_hipaa as _iah_badge
            protected = any(
                int(aid) in acct_by_id
                and _iah_badge(acct_by_id[int(aid)])
                for aid in submitted.selected_account_ids
            )
            base["topic"] = submitted
            base["protected"] = protected
            base["errors"] = errs
            return base

        ctx = await db_call(_err_ctx)
        return await _render(
            templates, request, "profile/_topic_digest_editor.html", {
                "user": user,
                "current_user": user,
                "active_tab": "topic-digest",
                "is_new": not submitted.id,
                **ctx,
            },
        )

    _log.info(
        "Topic saved",
        user=user["email"],
        topic_id=saved.id,
        name=saved.name,
        mailbox_count=len(saved.selected_account_ids),
        mode=saved.mode,
    )
    # PRG back to the Topic Digest tab. The full-page Topic editor is
    # ALWAYS reached from the topic-digest tab, so redirect there
    # unconditionally — the editor form carries no ``active_tab`` field, so
    # ``_resolve_profile_tab`` would fall back to "notifications" and dump
    # the operator on the wrong tab (the save test masked this by POSTing
    # active_tab itself).
    return RedirectResponse("/profile?tab=topic-digest", status_code=303)


@router.post("/profile/topic-digest/{topic_id:int}/delete")
async def profile_topic_digest_delete(
    request: Request, topic_id: int, user: RequireUser,
):
    """Soft-delete a Topic (tombstone — keeps hit history queryable).

    §5 ownership gate before the delete: a Topic that isn't the
    requester's 404s rather than soft-deleting a foreign Topic.
    """
    db = get_db(request)

    from email_triage.actions.topic_configs import get_topic, soft_delete_topic

    def _delete_db_work() -> bool:
        existing = get_topic(db, topic_id)
        if existing is None or not can_modify_owned_resource(existing.user_id, requester_id=user["id"], admin_bypass=False):
            return False
        return soft_delete_topic(db, topic_id)

    ok = await db_call(_delete_db_work)
    if not ok:
        return HTMLResponse("Topic not found", status_code=404)
    _log.info("Topic soft-deleted", user=user["email"], topic_id=topic_id)
    return RedirectResponse("/profile?tab=topic-digest", status_code=303)


# ---------------------------------------------------------------------------
# Preview — the user-triggered, EPHEMERAL back-scan over a bounded recent
# sample. This is NOT the durable jobs/topic_backscan job: it runs in-
# process over a small recent-mail window and builds an ephemeral ``hits``
# ctx (metadata only — NEVER stored). Per-account auth intersection is the
# §5 fail-closed gate, applied to every account BEFORE any provider hit.
# ---------------------------------------------------------------------------

#: How many recent messages per account the bounded preview pulls. Small
#: by design — the preview is a tuning sample, not the full back-scan.
# Step-1 keyword Preview (operator 2026-06-12): scan the WHOLE "how far back"
# window across all folders — no per-folder starvation. A high SAFETY ceiling,
# not a 25-message sample. This replaces the old first-N-messages LLM cap that
# starved mail filed in a non-INBOX folder on a busy mailbox (the mempalace
# `Tech/GitHub` miss — Preview only ever looked at the first 25 messages, which
# the INBOX exhausted before the scan reached the filed folder).
_TOPIC_PREVIEW_KEYWORD_MAX = 5000
# Step-1 SERVER-SIDE search cap (operator 2026-06-12 "very slow … just spinning"):
# the Preview asks the provider to SEARCH its Subject chips server-side
# (SUBJECT/subject:/$filter) and fetches ONLY the matches, instead of pulling
# EVERY header in the window (hundreds of IMAP TLS+LOGIN round-trips on a big
# mailbox → the request spun). This bounds how many matched candidates we fetch
# per account; hitting it is surfaced (the banner), never silent.
_TOPIC_PREVIEW_SEARCH_CAP = 400
#: Header-fetch chunk for the matched candidates (one IMAP connection per chunk).
_TOPIC_PREVIEW_FETCH_CHUNK = 50
# Step-2 "Test Details": LLM-confirm only the keyword candidates, bounded so a
# huge candidate set can't hang the request or hammer the model.
_TOPIC_PREVIEW_LLM_MAX = 60
# Retained as an alias only so any external reference keeps resolving; it is no
# longer a first-N-messages sample cap.
_TOPIC_PREVIEW_PER_ACCOUNT = _TOPIC_PREVIEW_KEYWORD_MAX
_TOPIC_PREVIEW_WINDOW_DAYS = 30
#: Lookback windows the Preview dropdown offers (operator 2026-06-11 — added 7
#: + 15 for a faster/finer tuning sample). The handler clamps the submitted
#: ``lookback_days`` to this set; the template renders one <option> per value.
_TOPIC_PREVIEW_ALLOWED_DAYS: tuple[int, ...] = (7, 15, 30, 60, 90)


def _confidence_band(confidence: float) -> str:
    """Map a [0..1] confidence to a 3-band glyph label (never a raw float).

    The preview surfaces strong/likely/weak — a doctor/exec audience reads
    a band, not ``0.73`` (design §3d). Thresholds match the digest
    confidence-floor slider's three stops.
    """
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        c = 0.0
    if c >= 0.75:
        return "strong"
    if c >= 0.45:
        return "likely"
    return "weak"


#: Placeholder shown in the From/Subject/Date columns when the per-hit
#: EPHEMERAL header fetch fails. A
#: degraded "metadata unavailable" row beats dropping the match: the operator
#: still sees a hit happened + can Include/Remove it (those key on the durable
#: RFC Message-ID, not on the rendered headers).
_PREVIEW_METADATA_UNAVAILABLE = "(metadata unavailable)"


def _hit_from_verdict(
    topic_id: int,
    account: dict,
    msg: "Any",
    verdict: "Any",
    *,
    header_meta: dict | None = None,
) -> dict:
    """Build ONE ephemeral preview-hit ctx row from a matched verdict.

    EPHEMERAL metadata only — this dict is rendered and discarded, never
    persisted (persistence is the durable back-scan job's job, design §2).
    Carries the matched Topic-TERMS (the user's OWN public Subject/Details
    terms — never a body quote) + a 3-band why-matched glyph (never a raw
    confidence float). The message identity is the durable RFC Message-ID
    so an Include/Remove action can key the real ``topic_hits`` row.

    **#33 §3d — ephemeral display headers.** From/Subject/Date come from
    ``header_meta`` — an independent, per-hit, headers-only ``imap_blocking``
    fetch the caller ran (display-then-discard, never stored). When that
    fetch failed for THIS hit, ``header_meta`` is ``None`` and the row
    degrades to a "metadata unavailable" placeholder (fail-OPEN: a degraded
    row beats no preview). The durable Message-ID + folder used by the
    Include/Remove actions are taken from the matched ``msg`` and are NOT
    affected by a header-fetch miss.

    Field names match the preview template's documented hit contract
    (profile/_topic_digest_preview.html lines 22-35): ``topic_id`` /
    ``account_id`` / ``account_name`` / ``message_id`` / ``when`` /
    ``sender`` / ``subject`` / ``confidence_band`` / ``matched_terms`` /
    ``included``.
    """
    from email_triage.jobs.topic_backscan import (
        _msg_folder, _msg_rfc_message_id,
    )

    def _vget(v, key, default=None):
        if isinstance(v, dict):
            return v.get(key, default)
        return getattr(v, key, default)

    raw_terms = _vget(verdict, "reason_terms", None) or []
    confidence = _vget(verdict, "confidence", 0.0)

    if header_meta is None:
        # Fail-OPEN render: the per-hit header fetch did not produce usable
        # metadata for this row. Show a placeholder rather than dropping the
        # match (§3d step 5).
        subject = _PREVIEW_METADATA_UNAVAILABLE
        sender = _PREVIEW_METADATA_UNAVAILABLE
        when = _PREVIEW_METADATA_UNAVAILABLE
    else:
        subject = header_meta.get("subject") or ""
        sender = header_meta.get("sender") or ""
        when = header_meta.get("when") or ""

    return {
        "topic_id": int(topic_id),
        "account_id": int(account["id"]),
        "account_name": account.get("name") or "",
        "message_id": _msg_rfc_message_id(msg),
        "folder": _msg_folder(msg),
        "when": str(when),
        "sender": str(sender),
        # base64 of the sender so the thumbs-feedback hx-vals can carry it
        # safely (a raw From header has quotes that break JSON-in-attr).
        "sender_b64": base64.b64encode(str(sender).encode("utf-8")).decode("ascii"),
        "subject": subject,
        "matched_terms": [str(t) for t in raw_terms],
        "confidence_band": _confidence_band(confidence),
        "included": False,
        "hipaa": is_account_hipaa(account),  # N-226 R22 — fold on system_hipaa OR acct.hipaa
    }


def _hit_from_keyword(
    topic_id: int,
    account: dict,
    msg: "Any",
    matched_terms: list,
    *,
    header_meta: dict | None = None,
) -> dict:
    """Build ONE ephemeral preview-hit row from a STEP-1 keyword candidate
    (operator 2026-06-12). Same ephemeral, never-persisted contract + field
    names as :func:`_hit_from_verdict`, but sourced from the deterministic,
    no-LLM :func:`keyword_match` (the cheap full-window pass). The band is
    ``'likely'`` — a keyword candidate is NOT an LLM-confirmed semantic match;
    the on-demand "Test Details" step upgrades it to the model's verdict band.
    ``matched_terms`` are already the operator's OWN readable Topic terms
    (Subject chips / structural signals), never a body quote (§3d / R6).
    """
    from email_triage.jobs.topic_backscan import (
        _msg_folder, _msg_rfc_message_id,
    )
    if header_meta is None:
        subject = _PREVIEW_METADATA_UNAVAILABLE
        sender = _PREVIEW_METADATA_UNAVAILABLE
        when = _PREVIEW_METADATA_UNAVAILABLE
    else:
        subject = header_meta.get("subject") or ""
        sender = header_meta.get("sender") or ""
        when = header_meta.get("when") or ""
    return {
        "topic_id": int(topic_id),
        "account_id": int(account["id"]),
        "account_name": account.get("name") or "",
        "message_id": _msg_rfc_message_id(msg),
        "folder": _msg_folder(msg),
        "when": str(when),
        "sender": str(sender),
        "sender_b64": base64.b64encode(str(sender).encode("utf-8")).decode("ascii"),
        "subject": subject,
        "matched_terms": [str(t) for t in (matched_terms or [])],
        "confidence_band": "likely",
        "included": False,
        "hipaa": is_account_hipaa(account),  # N-226 R22 — fold on system_hipaa OR acct.hipaa
    }


def _header_meta_from_msg(msg: "Any") -> dict | None:
    """Display From/Subject/Date ALREADY carried by the Step-1 keyword scan.

    The keyword pass fetches ``BODY.PEEK[HEADER]`` for the WHOLE window through
    the provider's ``imap_blocking`` stdlib path — the SAME parser-safe path the separate per-hit :func:`_ephemeral_header_meta` would
    use — so every candidate ``msg`` already holds From/Subject/Date (that is
    how :func:`keyword_match` read the Subject). Reading them straight off the
    message:

      * fixes the prod "(metadata unavailable)" on EVERY row — the IMAP
        ``EmailMessage`` carries no ``provider_uid`` (only ``message_id`` = the
        UID), so the re-fetch's ``uid is None`` guard always returned None and
        every row degraded; the headers were in hand the whole time, and
        ``_msg_provider_uid`` only resolves on a back-scan identity dict, not on
        a live provider message; and
      * drops a redundant per-hit IMAP round-trip (one TLS+LOGIN each).

    Returns ``None`` only when the msg exposes NO usable header at all (a
    non-IMAP fetcher that yields bare coordinates), so the caller can fall back
    to the per-hit :func:`_ephemeral_header_meta` fetch. PHI note: Subject can
    carry PHI — this stays ephemeral (rendered then discarded, never stored),
    identical to the ephemeral-fetch path it replaces.
    """
    is_dict = isinstance(msg, dict)

    def _attr(name: str) -> "Any":
        return msg.get(name) if is_dict else getattr(msg, name, None)

    headers = _attr("headers")
    headers = headers if isinstance(headers, dict) else {}
    subject = _attr("subject") or headers.get("Subject") or headers.get("subject") or ""
    sender = _attr("sender") or headers.get("From") or headers.get("from") or ""
    when = headers.get("Date") or headers.get("date") or ""
    if not when:
        d = _attr("date")
        when = str(d) if d else ""
    if not (subject or sender or when):
        return None
    return {"subject": str(subject), "sender": str(sender), "when": str(when)}


async def _ephemeral_header_meta(provider: "Any", msg: "Any") -> dict | None:
    """Fetch ONE message's From/Subject/Date for ephemeral preview render.

    **#33 §3d — display-then-discard, per-hit independent, fail-OPEN.** Runs a
    headers-ONLY fetch through the provider's ``imap_blocking`` stdlib path
    (``ImapProvider.fetch_message(uid, headers_only=True)`` → BODY.PEEK[HEADER]
    via ``providers.imap_blocking`` — NEVER raw aioimaplib, NEVER a full body
    fetch). The returned headers are read into a tiny ``{sender, subject,
    when}`` dict and the fetched message is discarded — nothing is stored.

    Per-hit isolation: any failure (one bad Subject literal, a vanished UID, a
    provider that can't be reached) returns ``None`` so ONLY this row degrades
    to "metadata unavailable" — one bad message never poisons the rest of the
    batch. Returns ``None`` on any miss; a dict on success.
    """
    from email_triage.jobs.topic_backscan import (
        _msg_folder, _msg_provider_uid,
    )

    uid = _msg_provider_uid(msg)
    folder = _msg_folder(msg) or None
    fetch_fn = getattr(provider, "fetch_message", None)
    if uid is None or fetch_fn is None:
        return None
    try:
        # headers_only=True → BODY.PEEK[HEADER] via imap_blocking; folder
        # pins the UID to its mailbox (UIDs are mailbox-scoped, RFC 3501
        # §2.3.1.1). Body / link / attachment fields stay empty.
        fetched = await fetch_fn(str(uid), headers_only=True, folder=folder)
    except TypeError:
        # A provider whose fetch_message lacks the headers_only/folder kwargs
        # (non-IMAP) — fall back to the plain signature, still headers-intent.
        try:
            fetched = await fetch_fn(str(uid))
        except Exception:
            return None
    except Exception:
        # Per-hit fail-OPEN: degrade THIS row only, never raise into the batch.
        return None

    headers = getattr(fetched, "headers", None) or {}
    subject = getattr(fetched, "subject", "") or ""
    sender = getattr(fetched, "sender", "") or ""
    when = ""
    if isinstance(headers, dict):
        subject = subject or headers.get("Subject") or headers.get("subject") or ""
        sender = sender or headers.get("From") or headers.get("from") or ""
        when = headers.get("Date") or headers.get("date") or ""
    return {
        "sender": str(sender),
        "subject": str(subject),
        "when": str(when),
    }


async def _aiter_empty():
    """An async iterator that yields nothing — used when the preview provider
    couldn't be built (degrade to no hits, fail-open) without special-casing the
    ``async for`` loop."""
    return
    yield  # pragma: no cover — makes this an async generator


async def _preview_candidate_batches(provider, topic, after_dt, *, cap):
    """Server-side candidate search for the keyword Preview (operator 2026-06-12).

    Instead of fetching EVERY header in the window and filtering client-side
    (hundreds of IMAP TLS+LOGIN round-trips on a big mailbox → the request spun),
    ask the provider to SEARCH the Topic's Subject chips server-side and fetch
    ONLY the matches. ``MailFilter(subject=chip, after=after_dt)`` emits the
    right ``SUBJECT "x" SINCE d`` (IMAP), ``subject:x after:d`` (Gmail), and
    ``$filter`` (Graph) on every provider, so the server does the filtering and
    the cross-folder coverage (the mempalace ``Tech/GitHub`` mail still surfaces).

    Yields headers-only, folder-stamped message batches — the SAME shape the
    keyword loop consumes. One server search per Subject chip, union+dedup,
    bounded at ``cap`` (the caller surfaces a ``truncated`` banner when the
    fetched count reaches ``cap``). A Topic with NO Subject chips yields nothing:
    the cheap Preview is Subject-driven; the full free-text Details are tested by
    the LLM in "Test Details".
    """
    from email_triage.actions.topic_prefilter import _subjects
    from email_triage.engine.models import MailFilter

    chips = _subjects(topic)
    if not chips:
        return

    search_all = getattr(provider, "search_all_folders", None)
    seen_keys: set = set()
    pairs: list = []
    for chip in chips:
        if len(pairs) >= cap:
            break
        mf = MailFilter(subject=chip, after=after_dt)
        try:
            if callable(search_all):
                got = await search_all(
                    "", cap, filter=mf, exclude_special_use=True,
                )
            else:
                mids = await provider.search("", cap, filter=mf)
                got = [(None, mid) for mid in (mids or ())]
        except Exception:  # noqa: BLE001 — one bad chip search ≠ kill the preview
            continue
        for folder, uid in (got or ()):
            key = (folder, str(uid))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            pairs.append((folder, str(uid)))
            if len(pairs) >= cap:
                break

    if not pairs:
        return

    by_folder: dict = {}
    for folder, uid in pairs:
        by_folder.setdefault(folder, []).append(uid)
    batch_fetch = getattr(provider, "fetch_messages_batch", None)

    for folder, uids in by_folder.items():
        for i in range(0, len(uids), _TOPIC_PREVIEW_FETCH_CHUNK):
            chunk = uids[i:i + _TOPIC_PREVIEW_FETCH_CHUNK]
            out: list = []
            if folder is not None and callable(batch_fetch):
                try:
                    out = list(await batch_fetch(
                        chunk, folder=folder, headers_only=True,
                    ))
                except Exception:  # noqa: BLE001 — per-message fallback
                    out = []
            if not out:
                for uid in chunk:
                    try:
                        m = (
                            await provider.fetch_message(
                                uid, folder=folder, headers_only=True)
                            if folder is not None
                            else await provider.fetch_message(
                                uid, headers_only=True)
                        )
                        if m is not None:
                            out.append(m)
                    except Exception:  # noqa: BLE001 — one bad fetch, skip
                        pass
            if folder is not None:
                for m in out:
                    try:
                        m.folder = folder
                    except Exception:  # noqa: BLE001 — stamp best-effort
                        pass
            if out:
                yield out


async def _preview_account_hits(
    request: Request,
    account: dict,
    topic: "Any",
    classifier: "Any",
    window_days: int = _TOPIC_PREVIEW_WINDOW_DAYS,
    mode: str = "keyword",
) -> list[dict]:
    """Run the bounded ephemeral preview for ONE authorized account.

    ``mode`` (operator 2026-06-12):
      * ``'keyword'`` — the default Preview: a cheap, deterministic, NO-LLM
        keyword pass over the WHOLE "how far back" window (every folder, every
        message up to ``_TOPIC_PREVIEW_KEYWORD_MAX``). This is what fixes the
        filed-folder miss — no first-25-messages starvation.
      * ``'details'`` — the on-demand "Test Details" step: the SAME keyword
        pass, but each candidate is then LLM-matched against the full Topic
        (Subject + Details), bounded by ``_TOPIC_PREVIEW_LLM_MAX`` calls. For
        tuning the Details against real mail.

    Pulls a small recent window via the account's provider (reusing the
    back-scan's injectable fetcher), runs ``await
    match_topics_for_message`` per message (the REAL async signature —
    fail-open), and returns the ephemeral hit ctx rows. Any provider /
    classifier failure degrades THIS account's preview to ``[]`` — it
    never raises into the handler (design §4.4 fail-open).

    **Floor divergence (operator 2026-06-15).** The Preview is a TUNING view: it
    shows EVERY candidate match with its confidence band (strong/likely/weak),
    INCLUDING matches below the digest confidence floor
    (``TOPIC_MATCH_CONFIDENCE_FLOOR``). The delivered digest additionally
    SUPPRESSES sub-floor hits (in ``gather_live_topic_hits``), so the Preview is
    intentionally a SUPERSET of what a recipient receives — that is the point:
    the operator sees the weak matches the floor would hide and can decide the
    floor. The Preview DOES mirror the digest's sender-signal filtering (a
    thumbs-DOWN sender is dropped here too); it does NOT mirror the floor.

    **#33 §3d — ephemeral display headers via imap_blocking.** For every
    matched message, From/Subject/Date are fetched in a SEPARATE, per-hit,
    headers-ONLY pass through the provider's ``imap_blocking`` stdlib path
    (:func:`_ephemeral_header_meta`) — display-then-discard, never stored.
    The per-hit fetch is independently fail-OPEN: one bad Subject degrades
    only that single row to "metadata unavailable" and never poisons the
    rest of the batch. A provider is built ONCE for this account and reused
    for every per-hit header fetch (then closed in ``finally``).
    """
    from datetime import timedelta
    from email_triage.actions.topic_matcher import match_topics_for_message
    from email_triage.actions.topic_prefilter import keyword_match
    from email_triage.jobs.topic_backscan import (
        _msg_body_keywords, _msg_folder, _msg_provider_uid,
    )

    db = get_db(request)
    #  categories-threading — match_topics_for_message re-classifies each
    # message; its taxonomy gate drops every verdict (fail-open) when the
    # parsed category is not in ``categories``. The production classifier
    # never carries a ``.categories`` attribute, so the matcher's fallback
    # resolves to ``{}`` and the preview shows zero matches. Pass the Topic
    # owner's taxonomy explicitly.
    from email_triage.web.db import get_categories_dict
    owner_uid = int(getattr(topic, "user_id", 0) or 0) or None
    categories = await db_call(get_categories_dict, db, user_id=owner_uid)
    # N-113 — HIPAA + BAA egress gate (shared SSOT baa_block_status; §164.308(b)(1)).
    # The 'details' pass below LLM-matches the FULL re-fetched message body via
    # match_topics_for_message -> the configured classifier. For a HIPAA account
    # whose classifier is external with no BAA ack, that PHI must NOT egress to the
    # non-BAA subprocessor. Degrade to the no-LLM keyword pass (fail-safe — the
    # preview is already fail-open) so the operator still sees keyword candidates
    # but nothing leaves. Same decision as the back-scan job + the live runner.
    if mode == "details":
        from email_triage.classify.baa_gate import baa_block_status
        if is_account_hipaa(account):
            _baa_block = await db_call(baa_block_status, db, classifier, True)
            if _baa_block is not None:
                mode = "keyword"
                _log.warning(
                    "topic preview: 'details' LLM pass suppressed for HIPAA "
                    f"account {account.get('id')} — classifier "
                    f"{_baa_block.get('backend')} @ {_baa_block.get('host') or '?'} "
                    "is not BAA-acked; degraded to keyword-only (no PHI egress, N-113)."
                )
    #  v3 reinforcement (operator 2026-06-12): this Topic's learned SENDER
    # signals — a thumbs-DOWN sender is dropped from the Preview too, so the
    # operator sees the same SENDER-filtered set the digest will produce (the
    # digest additionally hides sub-floor hits — see the floor-divergence note
    # in the docstring; the Preview deliberately shows them).
    from email_triage.actions.topic_configs import normalize_feedback_sender
    from email_triage.cache.topic_feedback import load_topic_sender_signals
    from email_triage.mail_headers import get_triage_header
    # Cache-aware read: the OPTIONAL Redis mirror if configured, else the DB.
    sender_signals = await load_topic_sender_signals(
        db, int(getattr(topic, "id", 0) or 0),
    )
    after_dt = datetime.now(timezone.utc) - timedelta(days=int(window_days))
    hits: list[dict] = []
    seen = 0

    # Build the provider ONCE for the per-hit ephemeral header fetches. A
    # build failure is non-fatal — every hit then renders the fail-OPEN
    # "metadata unavailable" placeholder (the match itself still surfaces).
    secrets = getattr(request.app.state, "secrets", None)
    header_provider = None
    try:
        header_provider = _create_provider_from_account(account, secrets)
    except Exception:
        header_provider = None

    llm_used = 0
    truncated = False        # keyword scan hit the per-account ceiling
    llm_budget_hit = False   # details mode ran out of LLM budget (more candidates)
    topic_id = int(getattr(topic, "id", 0) or 0)
    try:
        # STEP-1 (operator 2026-06-12 "very slow … just spinning"): SERVER-SIDE
        # search the Topic's Subject chips and fetch ONLY the matching messages —
        # not every header in the window (that was hundreds of IMAP round-trips
        # on a big mailbox). The provider does the filtering + cross-folder
        # coverage; ``keyword_match`` below re-confirms + extracts the readable
        # evidence. Degrades to no hits if the provider couldn't be built.
        batches = (
            _preview_candidate_batches(
                header_provider, topic, after_dt,
                cap=_TOPIC_PREVIEW_SEARCH_CAP,
            )
            if header_provider is not None else None
        )
        async for batch in (batches or _aiter_empty()):
            for msg in batch or ():
                if seen >= _TOPIC_PREVIEW_SEARCH_CAP:
                    truncated = True
                    break
                seen += 1
                # Never surface email-triage's OWN generated content (drafts,
                # digests it sent) — flagged with the X-Email-Triage
                # loop-prevention header (operator 2026-06-12).
                if get_triage_header(getattr(msg, "headers", None) or {}):
                    continue
                body_kws = _msg_body_keywords(msg)   # [] for a headers-only msg
                # STEP 1 (both modes): cheap, deterministic, NO-LLM PRECISION
                # match — does this server-matched message hit the Topic's
                # Subject chips / structural signals? matched_terms are the
                # operator's own readable Topic terms, never a body quote.
                matched_terms = keyword_match(
                    topic, getattr(msg, "headers", None) or {}, body_kws,
                )
                if not matched_terms:
                    continue
                #  v3 reinforcement: drop a thumbs-DOWN sender (the operator
                # taught this Topic to ignore it) so the Preview mirrors the
                # digest's SENDER filtering (the confidence floor is the one
                # divergence — the Preview shows sub-floor candidates; see the
                # docstring floor-divergence note).
                if sender_signals:
                    _hdrs = getattr(msg, "headers", None) or {}
                    _sender = (
                        getattr(msg, "sender", "")
                        or _hdrs.get("From") or _hdrs.get("from") or ""
                    )
                    _skey = normalize_feedback_sender(_sender)
                    if _skey and sender_signals.get(_skey) == -1:
                        continue
                # Display From/Subject/Date are ALREADY in the keyword scan's
                # headers-only fetch (imap_blocking — the  §3d / N-26-safe
                # stdlib path). Read them straight off ``msg``; only fall back to
                # a per-hit ephemeral RE-fetch when the msg carries no header (a
                # non-IMAP fetcher yielding bare coordinates). This fixes the
                # prod "(metadata unavailable)" on every row (the IMAP message
                # has no provider_uid, so the re-fetch's UID guard always tripped)
                # and drops a redundant per-hit IMAP round-trip. Stays ephemeral.
                header_meta = _header_meta_from_msg(msg)
                if header_meta is None and header_provider is not None:
                    header_meta = await _ephemeral_header_meta(
                        header_provider, msg,
                    )
                if mode == "details" and llm_used < _TOPIC_PREVIEW_LLM_MAX:
                    # STEP 2 ("Test Details"): spend the LLM ONLY on keyword
                    # candidates (bounded). The keyword scan was headers-only, so
                    # re-fetch the FULL body for THIS candidate before the LLM
                    # (the model needs the content). categories MUST be threaded
                    # or the taxonomy gate drops every verdict.
                    llm_used += 1
                    llm_msg, llm_body_kws = msg, body_kws
                    if header_provider is not None:
                        # The IMAP ``EmailMessage``'s ``message_id`` IS the UID
                        # (``provider_uid`` is never populated on a live provider
                        # message — it only exists on a back-scan identity dict),
                        # and the fetcher stamped ``.folder`` (UIDs are mailbox-
                        # scoped, so the folder must ride along). Empty folder →
                        # None = whole-mailbox provider (Gmail/Graph).
                        _uid = _msg_provider_uid(msg) or getattr(msg, "message_id", None)
                        _fldr = _msg_folder(msg) or None
                        if _uid:
                            try:
                                _full = (
                                    await header_provider.fetch_message(
                                        str(_uid), folder=_fldr)
                                    if _fldr is not None
                                    else await header_provider.fetch_message(str(_uid))
                                )
                                # Skip the empty-shell a provider returns for a
                                # UID it couldn't refetch (subject+body both "").
                                if _full is not None and (
                                    getattr(_full, "body_text", "")
                                    or getattr(_full, "subject", "")
                                ):
                                    llm_msg = _full
                                    llm_body_kws = _msg_body_keywords(_full)
                            except Exception:  # noqa: BLE001 — degrade, don't drop
                                pass
                    verdicts = await match_topics_for_message(
                        llm_msg, [topic], classifier,
                        body_keywords=llm_body_kws,
                        categories=categories,
                    )
                    for v in verdicts or ():
                        hits.append(
                            _hit_from_verdict(
                                topic_id, account, msg, v,
                                header_meta=header_meta,
                            ),
                        )
                else:
                    # Keyword mode, or details mode PAST the LLM budget — surface
                    # the deterministic keyword candidate (NOT silently as
                    # "AI-tested"; the budget-hit is surfaced by the banner).
                    if mode == "details":
                        llm_budget_hit = True
                    hits.append(
                        _hit_from_keyword(
                            topic_id, account, msg, matched_terms,
                            header_meta=header_meta,
                        ),
                    )
            if seen >= _TOPIC_PREVIEW_SEARCH_CAP:
                truncated = True
                break
    except Exception as exc:  # noqa: BLE001 — fail-open per §4.4
        _log.warning(
            "Topic preview: account scan failed; degrading to no hits",
            topic_id=getattr(topic, "id", None),
            account_id=account.get("id"),
            error=type(exc).__name__,
        )
        return {"hits": [], "truncated": False, "scanned": seen,
                "llm_budget_hit": False}
    finally:
        if header_provider is not None:
            try:
                close = getattr(header_provider, "close", None)
                if close is not None:
                    result = close()
                    if asyncio.iscoroutine(result):
                        await result
            except Exception:  # noqa: BLE001 — best-effort close
                pass
    if truncated:
        # No silent caps (style guide): the cap is operator-visible in logs, and
        # the banner surfaces it in the UI.
        _log.warning(
            "Topic preview: server-side match search hit the per-account cap",
            topic_id=topic_id, account_id=account.get("id"),
            matched=seen, cap=_TOPIC_PREVIEW_SEARCH_CAP, mode=mode,
        )
    return {"hits": hits, "truncated": truncated, "scanned": seen,
            "llm_budget_hit": llm_budget_hit}


@router.post(
    "/profile/topic-digest/{topic_id:int}/preview",
    response_class=HTMLResponse,
)
async def profile_topic_digest_preview(
    request: Request, topic_id: int, user: RequireUser,
):
    """HTMX Preview fragment — STEP 1 (operator 2026-06-12): a cheap,
    deterministic, NO-LLM keyword pass over the WHOLE "how far back" window
    across the Topic's AUTHORIZED accounts. Shows every message whose
    headers/keywords hit the Topic's Subject/Details terms — with no
    first-25-messages starvation of filed folders (the mempalace fix). The
    on-demand "Test Details" step then LLM-confirms these candidates.
    """
    return await _run_topic_preview(request, topic_id, user, mode="keyword")


@router.post(
    "/profile/topic-digest/{topic_id:int}/test-details",
    response_class=HTMLResponse,
)
async def profile_topic_digest_test_details(
    request: Request, topic_id: int, user: RequireUser,
):
    """HTMX "Test Details" fragment — STEP 2 (operator 2026-06-12): the SAME
    keyword pass, but each candidate is then LLM-matched against the FULL
    Topic (Subject + Details), bounded by ``_TOPIC_PREVIEW_LLM_MAX`` calls.
    This is the tuning surface — it shows what the full Topic actually catches
    (vs the keyword first pass), so the operator can refine the Details. Same
    §5 fail-closed / ephemeral contract as the Preview.
    """
    return await _run_topic_preview(request, topic_id, user, mode="details")


async def _run_topic_preview(
    request: Request, topic_id: int, user: dict, *, mode: str,
) -> "Any":
    """Shared body for the keyword Preview (``mode='keyword'``) and the LLM
    "Test Details" (``mode='details'``) fragments above.

    §5 fail-closed: the Topic's ``selected_account_ids`` are intersected with
    the requester's manageable set PER ACCOUNT; any account the requester can't
    manage is DROPPED before a single provider round-trip (no foreign mailbox
    is ever scanned, even on a tampered Topic row). The ``hits`` ctx is
    ephemeral — built, rendered, discarded; NOTHING is persisted.
    """
    db = get_db(request)
    templates = get_templates(request)

    # Honor the submitted lookback window (operator 2026-06-11 — the dropdown
    # offers 7/15/30/60/90 and was previously IGNORED, always 30). Clamp to the
    # allowed set; default 30. group_by_account drives the rendered grouping.
    form = await request.form()
    lookback_days = bounded_int(  # N-219c/35 R23: SSOT
        (form.get("lookback_days") or "").strip() or _TOPIC_PREVIEW_WINDOW_DAYS,
        default=_TOPIC_PREVIEW_WINDOW_DAYS,
    )
    if lookback_days not in _TOPIC_PREVIEW_ALLOWED_DAYS:
        lookback_days = _TOPIC_PREVIEW_WINDOW_DAYS
    group_by_account = bool(form.get("group_by_account"))

    from email_triage.actions.topic_configs import get_topic
    from email_triage.jobs.topic_backscan import _build_classifier
    #  V2 — actor≠owner audit gate uses the resolved HIPAA state
    # (covers system-wide HIPAA mode, not just the per-account column).

    # Resolve Topic + the §5-intersected, AUTHORIZED account set in one hop.
    def _resolve() -> dict:
        topic = get_topic(db, topic_id)
        if topic is None or not can_modify_owned_resource(
            topic.user_id, requester_id=user["id"], admin_bypass=False):
            return {"topic": None, "accounts": []}
        # PER-ACCOUNT intersection, fail-closed: drop unauthorized ids.
        authorized = filter_to_manageable_accounts(
            topic.selected_account_ids, db, user,
        )
        return {"topic": topic, "accounts": authorized}

    resolved = await db_call(_resolve)
    topic = resolved["topic"]
    if topic is None:
        return HTMLResponse("Topic not found", status_code=404)

    accounts = resolved["accounts"]
    dropped = len(topic.selected_account_ids) - len(accounts)
    if dropped:
        _log.info(
            "Topic preview: dropped unauthorized accounts (fail-closed)",
            user=user["email"], topic_id=topic_id, dropped=dropped, mode=mode,
        )

    classifier = _build_classifier(request.app)

    hits: list[dict] = []
    truncated = False        # any account hit the keyword-scan ceiling
    llm_budget_hit = False   # details mode ran out of LLM budget on any account
    if classifier is not None:
        for account in accounts:
            result = await _preview_account_hits(
                request, account, topic, classifier,
                window_days=lookback_days, mode=mode,
            )
            account_hits = result["hits"]
            truncated = truncated or result["truncated"]
            llm_budget_hit = llm_budget_hit or result["llm_budget_hit"]
            hits.extend(account_hits)

            #  V2 / §5 — actor≠owner HIPAA access audit. When the actor
            # is NOT the account owner AND the account is HIPAA-flagged AND
            # the preview actually surfaced PHI-bearing hits from it, fire a
            # hipaa_access_event. Owner self-access is EXEMPT (§164.502(a)
            # self-disclosure carve-out, per feedback_hipaa_actor_owner_gate).
            # ``is_account_hipaa`` (not a bare ``account["hipaa"]``) covers a
            # system-wide HIPAA-mode install too. Only fired on a real hit
            # (no hit ⇒ no PHI surfaced ⇒ nothing to audit).
            from email_triage.web.account_scope import is_account_owner
            if account_hits and (
                is_account_hipaa(account)
                and not is_account_owner(account, user["id"])
            ):
                await db_call(
                    audit_phi_access,
                    db,
                    actor_user_id=user["id"],
                    account=account,
                    operation=(
                        "study_digest_details_hit" if mode == "details"
                        else "study_digest_preview_hit"
                    ),
                )

    mailbox_count = len({h["account_id"] for h in hits})
    return await _render(
        templates, request, "profile/_topic_digest_preview.html", {
            "user": user,
            "current_user": user,
            "topic": topic,
            # Ephemeral preview metadata — never stored (design §2). Field
            # names match the preview template contract: hits / match_count
            # / mailbox_count / lookback_days / group_by_account / mode.
            "hits": hits,
            "match_count": len(hits),
            "mailbox_count": mailbox_count,
            "lookback_days": lookback_days,
            "group_by_account": group_by_account,
            "mode": mode,
            # Truncation surfacing (no silent caps): the keyword scan hit its
            # ceiling on at least one mailbox, and/or details mode ran past its
            # AI budget — the template shows a banner so the user knows results
            # may be incomplete (operator 2026-06-12).
            "truncated": truncated,
            "llm_budget_hit": llm_budget_hit,
            "keyword_cap": _TOPIC_PREVIEW_SEARCH_CAP,
            "llm_cap": _TOPIC_PREVIEW_LLM_MAX,
        },
    )


@router.post(
    "/profile/topic-digest/{topic_id:int}/retriage",
    response_class=HTMLResponse,
)
async def profile_topic_digest_retriage(
    request: Request, topic_id: int, user: RequireUser,
):
    """On-demand Re-Triage — enqueue a back-scan that STORES hits.

    Unlike the ephemeral preview, this records every match into
    ``topic_hits`` (source='backscan') so it collects into the digest. The
    window is [30 / 60 / 90 / All] (``window_days`` form field; ``0`` =
    All mail). §5 fail-closed: only accounts the requester can manage are
    enqueued — a foreign / stale ``selected_account_ids`` entry is dropped
    before any job is created. Returns an HTMX confirmation fragment.

    The back-scan enqueue carries the  idempotency guard (one in-flight
    ``topic_backscan`` job install-wide), so a multi-mailbox Topic queues
    its mailboxes one at a time across presses; the fragment says so.
    """
    db = get_db(request)
    form = await request.form()

    from email_triage.actions.topic_configs import get_topic
    from email_triage.jobs.topic_backscan import (
        ALLOWED_WINDOW_DAYS, DEFAULT_WINDOW_DAYS, enqueue_topic_backscan,
    )
    from email_triage.web.db import get_triage_job

    window_days = bounded_int(  # N-219c/35 R23: SSOT
        (form.get("window_days") or "").strip() or DEFAULT_WINDOW_DAYS,
        default=DEFAULT_WINDOW_DAYS,
    )
    if window_days not in ALLOWED_WINDOW_DAYS:
        window_days = DEFAULT_WINDOW_DAYS

    def _enqueue() -> dict:
        topic = get_topic(db, topic_id)
        if topic is None or not can_modify_owned_resource(
            topic.user_id, requester_id=user["id"], admin_bypass=False):
            return {"ok": False}
        authorized = filter_to_manageable(topic.selected_account_ids, db, user)
        queued = 0
        first_job_id = None
        for aid in authorized:
            jid = enqueue_topic_backscan(
                db, topic_id=topic_id, account_id=aid,
                actor_user_id=int(user["id"]), window_days=window_days,
            )
            if jid:
                queued += 1
                if first_job_id is None:
                    first_job_id = jid
        # Full dedup (a topic_backscan is already in flight install-wide, 
        # guard) → poll THAT job. But the guard is INSTALL-WIDE, so an unscoped
        # lookup could return another user's OR another topic's job — polling /
        # cancelling the WRONG scan (db-sme/DA 2026-06-11). Gate at the actuator
        # (PD#9): restrict to accounts THIS requester manages AND the job whose
        # descriptor topic_id == this topic.
        if first_job_id is None and authorized:
            ph = ",".join("?" * len(authorized))
            rows = db.execute(
                f"SELECT job_id, query FROM triage_jobs WHERE "
                f"kind='topic_backscan' AND status IN ('queued','running') "
                f"AND account_id IN ({ph}) ORDER BY created_at DESC",
                authorized,
            ).fetchall()
            for r in rows:
                # load_json_col SSOT (census #16b): a corrupt job-descriptor
                # column degrades to {} → topic_id mismatch → skip, never a
                # 500. topic_id is a path int and get_topic() already early-
                # returned for a missing topic, so it is > 0 here; a {} default
                # can therefore never false-match, exactly reproducing the
                # prior except→continue skip.
                q = load_json_col(
                    r["query"], default={}, label="triage_jobs.query",
                )
                if int(q.get("topic_id", 0) or 0) == topic_id:
                    first_job_id = r["job_id"]
                    break
        job = get_triage_job(db, first_job_id) if first_job_id else None
        return {
            "ok": True, "authorized": len(authorized),
            "queued": queued, "job": job,
        }

    res = await db_call(_enqueue)
    if not res["ok"]:
        return HTMLResponse("Topic not found", status_code=404)

    _log.info(
        "Topic re-triage enqueued",
        user=user["email"], topic_id=topic_id, window_days=window_days,
        authorized=res["authorized"], queued=res["queued"],
    )

    job = res.get("job")
    if job is not None:
        # Live, self-polling status fragment (advancing scanned-count +
        # staleness heartbeat) with a Stop button — the operator's "alive
        # indicator" + "cancel an in-progress scan" asks. Replaces the old
        # static <small>. The  guard means ≤1 topic_backscan runs
        # install-wide, so this one job's status stands for the whole
        # Re-Triage; later mailboxes queue as it finishes.
        templates = get_templates(request)
        return await _render(
            templates, request, "profile/_topic_backscan_status.html",
            {
                "topic_id": topic_id, "job": job,
                "stale_secs": _backscan_stale_secs(job),
            },
        )

    # No job to poll — the only path here is "no authorized mailbox on this
    # Topic" (every other case produced or found an in-flight job above).
    return HTMLResponse(
        '<small style="color:var(--pico-muted-color);">Add a mailbox to this '
        "Topic first — there's nothing to scan.</small>"
    )


def _job_topic_id(job: dict) -> "int | None":
    """The topic_id a topic_backscan job carries in its ``query`` JSON
    descriptor (triage_jobs has no topic_id column). Used to scope the
    topic-digest progress/cancel routes to the path topic_id (PD#9 — gate at the
    actuator) so a route under ``/topic-digest/{A}/...`` can't poll or cancel a
    DIFFERENT topic B's in-flight scan (the install-wide  dedup makes that
    reachable for a user who owns both topics)."""
    # N-219c/30 R23: load_json_col SSOT can't raise per the JSON-col contract;
    # only int() could. Migrated to parse_int_or_none + `or None` short-circuit
    # (0 → None; None → None; positive int → int).
    q = load_json_col(job.get("query"), default={}, label="triage_jobs.query")
    _tid = parse_int_or_none(q.get("topic_id", 0))
    return _tid or None


def _backscan_stale_secs(job: dict) -> "int | None":
    """Seconds since the job's ``last_progress_at`` heartbeat (None when it has
    not started advancing yet). Drives the status fragment's alive-vs-stalled
    copy: ``bump_triage_job_counters`` refreshes ``last_progress_at`` each
    batch, so a frozen value means the scan has stalled."""
    ts = job.get("last_progress_at")
    if not ts:
        return None
    # N-357b (2026-07-06 baseline shrink): migrated to parse_iso_aware SSOT
    # (was N-269d R28 parse_iso + inline assume-UTC shim).
    from email_triage._isotime import parse_iso_aware
    t = parse_iso_aware(str(ts))
    if t is None:
        return None
    return max(0, int((datetime.now(timezone.utc) - t).total_seconds()))


@router.get(
    "/profile/topic-digest/{topic_id:int}/retriage/{job_id}/progress",
    response_class=HTMLResponse,
)
async def profile_topic_retriage_progress(
    request: Request, topic_id: int, job_id: str, user: RequireUserFragment,
):
    """Poll target for the Re-Triage live status fragment (every 2s; the
    fragment self-stops at a terminal status). Owner-gated: the requester must
    manage the job's account AND the job must be a ``topic_backscan`` (so this
    topic-scoped endpoint can't read an unrelated triage job — PD#9, gate at
    the actuator)."""
    db = get_db(request)
    templates = get_templates(request)
    from email_triage.web.db import get_email_account, get_triage_job

    def _reads():
        job = get_triage_job(db, job_id)
        if not job or (job.get("kind") or "") != "topic_backscan":
            return None, False
        # Topic-scope (PD#9): a route under /topic-digest/{topic_id}/ must not
        # read another topic's in-flight scan (the install-wide  dedup makes
        # that reachable for a user who owns both topics).
        if _job_topic_id(job) != topic_id:
            return None, False
        acct = get_email_account(db, job["account_id"])
        return job, bool(acct and can_manage_account(db, user, acct))

    job, can = await db_call(_reads)
    if job is None:
        return HTMLResponse("Not found", status_code=404)
    if not can:
        return HTMLResponse("Forbidden", status_code=403)
    return await _render(
        templates, request, "profile/_topic_backscan_status.html",
        {"topic_id": topic_id, "job": job,
         "stale_secs": _backscan_stale_secs(job)},
    )


@router.post(
    "/profile/topic-digest/{topic_id:int}/retriage/{job_id}/cancel",
    response_class=HTMLResponse,
)
async def profile_topic_retriage_cancel(
    request: Request, topic_id: int, job_id: str, user: RequireUserFragment,
):
    """Stop an in-progress Re-Triage scan. Flips the job to ``cancelled``
    through the app's single writer (``request_triage_job_cancel`` — never a
    2nd connection); the drain observes it at its next batch boundary and exits
    cleanly (matches already found are kept). Owner-gated + ``topic_backscan``-
    pinned + topic-scoped, same as the progress route (PD#9 — gate at the
    actuator). ``RequireUserFragment`` (not ``RequireUser``) so a mid-poll
    session-expiry returns an HTMX-safe 401 rather than swapping a login
    redirect body into the status card."""
    db = get_db(request)
    templates = get_templates(request)
    from email_triage.web.db import (
        get_email_account, get_triage_job, request_triage_job_cancel,
    )

    def _apply():
        job = get_triage_job(db, job_id)
        if not job or (job.get("kind") or "") != "topic_backscan":
            return None
        if _job_topic_id(job) != topic_id:
            return None   # cross-topic — not this topic's scan (PD#9)
        acct = get_email_account(db, job["account_id"])
        if not acct or not can_manage_account(db, user, acct):
            return "forbidden"
        request_triage_job_cancel(db, job_id)
        return get_triage_job(db, job_id)   # re-read so the fragment shows it

    res = await db_call(_apply)
    if res is None:
        return HTMLResponse("Not found", status_code=404)
    if res == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)
    _log.info(
        "Topic re-triage cancelled", user=user["email"],
        topic_id=topic_id, job_id=job_id,
    )
    return await _render(
        templates, request, "profile/_topic_backscan_status.html",
        {"topic_id": topic_id, "job": res, "stale_secs": None},
    )


def _account_ids_include_hipaa(db: Any, account_ids: Any) -> bool:
    """True if ANY of ``account_ids`` is HIPAA-flagged — FAIL-CLOSED.

    Most-restrictive-wins (design §1a): a single HIPAA mailbox flips the
    whole Topic to protected mode, so the free-text Internet Search path is
    gated OFF (registry-only). **Fail-closed**: an account id we cannot read
    (deleted / forged / DB error) is treated as PROTECTED — we can't prove
    it's safe, so the Topic stays registry-only. The caller passes the UNION
    of the SAVED Topic's mailboxes AND the editor's live (possibly unsaved)
    selection, so adding a HIPAA mailbox in the editor — before Save — still
    closes the gate (SME 2026-06-08: gating on saved-only state was a
    fail-open). Runs sync DB reads; dispatch via ``db_call``.
    """
    from email_triage.db.accounts import get_email_account

    for aid in account_ids:
        try:
            acct = get_email_account(db, int(aid))
        except Exception:
            acct = None
        # acct is None (unreadable) ⇒ count as protected ⇒ registry-only.
        if acct is None or is_account_hipaa(acct):
            return True
    return False


def _gate_account_ids(topic: Any, form: Any, manageable_ids: set) -> set:
    """Account ids the HIPAA gate evaluates: the SAVED Topic's mailboxes
    PLUS the editor's LIVE (possibly unsaved) ``selected_account_ids``, so a
    HIPAA mailbox added in the editor — before Save — still flips the Topic
    to registry-only (SME 2026-06-08: gating on saved-only state let an
    unsaved HIPAA-mailbox add slip through to web egress).

    The CLIENT-submitted ids are INTERSECTED with ``manageable_ids`` (the
    §5 per-account auth set) before use — otherwise a user could POST an
    arbitrary ``selected_account_ids=<N>`` and read registry-only-vs-web-
    results as an is-HIPAA enumeration oracle over any account in the
    install (hipaa-sme 2026-06-08, §164.502(a) minimum-necessary /
    §164.308(a)(4)). Saved-Topic ids are kept as-is: they're the user's own
    Topic and including a now-unmanaged HIPAA mailbox only fails toward
    registry-only (the safe direction)."""
    ids: set = set()
    for aid in (getattr(topic, "selected_account_ids", None) or []):
        _iv = parse_int_or_none(aid)  # N-219c/9 R23: SSOT
        if _iv is not None:
            ids.add(_iv)
    # CLIENT-submitted ids: intersect with the manageable set (fail-closed)
    # via the account_scope SSOT, then union with the saved-Topic ids above.
    ids.update(intersect_ids(form.getlist("selected_account_ids"), manageable_ids))
    return ids


@router.post(
    "/profile/topic-digest/{topic_id}/search-details",
    response_class=HTMLResponse,
)
async def profile_topic_digest_search_details(
    request: Request, topic_id: str, user: RequireUser,
):
    """HTMX Internet-Search fragment — NCT registry lookup (design §3d).

    Detects an NCT id in the typed query and resolves it via the NCT
    service the service-builder owns (``resolve_nct`` — async, returns a
    whitelisted-fields result or ``None`` on a 404 / unrecognized id). The
    handler NEVER overwrites the operator's Details — it renders a
    confirm-before-replace fragment ([Replace] [Append] [Cancel]); the
    actual replace is a subsequent save. §5 ownership gate first.

    The ``nct_result`` ctx is the whitelisted study fields rendered AS
    DATA, not instructions (the egress payload is the user's typed query —
    the only incremental surface over the inventoried embedding fetch).
    """
    db = get_db(request)
    templates = get_templates(request)
    form = await request.form()
    query = (form.get("query") or "").strip()

    from email_triage.actions.topic_configs import get_topic

    # §5 ownership gate. A NEW (unsaved) editor posts topic_id="new" — there
    # is no saved Topic to own-check yet and no saved mailboxes, so the HIPAA
    # gate evaluates over the editor's LIVE submitted selection ONLY (still
    # fail-closed via _account_ids_include_hipaa). For a saved Topic the id
    # is an int and ownership IS enforced. (Bug fix 2026-06-08: the route was
    # `{topic_id:int}`, so the editor's `.../new/...` POST 404'd — the lookup
    # never worked on an unsaved Topic; every route test used a saved one.)
    topic = None
    if topic_id != "new":
        tid = parse_int_or_none(topic_id)  # N-219c/41 R23: SSOT
        if tid is None:
            return HTMLResponse("Topic not found", status_code=404)
        topic = await db_call(get_topic, db, tid)
        if topic is None or not can_modify_owned_resource(
            topic.user_id, requester_id=user["id"], admin_bypass=False):
            return HTMLResponse("Topic not found", status_code=404)

    #  — per-user Internet-Search cooldown. Each "Look up" can fan out to
    # clinicaltrials.gov / SearXNG / the local LLM; a short min-interval caps
    # rapid-fire (double-clicks, scripted abuse) of the egress. In-memory
    # dict on app.state (single-process), mirroring the escalation-test
    # limiter. The bucket updates on every ACCEPTED request so the cooldown
    # runs from the last attempt.
    _state = request.app.state
    _rl_bucket = getattr(_state, _TOPIC_SEARCH_RL_KEY, None)
    if _rl_bucket is None:
        _rl_bucket = {}
        setattr(_state, _TOPIC_SEARCH_RL_KEY, _rl_bucket)
    _now_mono = time.monotonic()
    _last = _rl_bucket.get(user["id"], 0.0)
    if _last and (_now_mono - _last) < _TOPIC_SEARCH_RL_WINDOW_SEC:
        return await _render(
            templates, request, "profile/_topic_nct_result.html", {
                "user": user, "current_user": user, "topic": topic,
                "nct_id": None, "nct_result": None, "web_results": None,
                "web_summary": None, "query": query,
                "search_error": (
                    "You're searching a bit fast — wait a moment and try "
                    "again."
                ),
                "search_panel": True,
            },
        )
    _rl_bucket[user["id"]] = _now_mono

    # Import the NCT resolver from the module that owns it
    # (``actions.clinicaltrials`` — the  §3 registry resolver).
    # ``resolve_nct(nct_id) -> dict | None`` (async; whitelisted fields
    # only — design §3d). ``normalize_nct`` detects + canonicalizes an
    # NCT id; aliased to ``normalize_nct_id`` so the rest of this handler
    # is unchanged. Imported lazily so this router loads cleanly even if
    # the resolver module is ever absent (air-gapped install), and so a
    # contract test can patch the HTTP boundary underneath the real
    # import path. If the module isn't present, degrade the button to
    # "not configured" rather than 500 — the design's backend-absent
    # posture, never an admin-path hint.
    try:
        from email_triage.actions.clinicaltrials import (  # type: ignore
            normalize_nct as normalize_nct_id,
            resolve_nct,
        )
        from email_triage.actions.web_search import (  # type: ignore
            web_search_bundle,
        )
        from email_triage.web.topic_search_summary import (  # type: ignore
            summarize_web_results,
        )
        from email_triage.web.db import get_web_search_searxng_url
    except ImportError:
        return await _render(
            templates, request, "profile/_topic_nct_result.html", {
                "user": user,
                "current_user": user,
                "topic": topic,
                "nct_id": None,
                "nct_result": None,
                "search_error": "Internet search is not configured.",
                "search_panel": True,
            },
        )

    nct_id = normalize_nct_id(query)
    nct_result = None
    web_results = None
    web_summary = None
    error = None

    if nct_id is not None:
        # ── Registry path (existing): the query is a study number. ──
        try:
            nct_result = await resolve_nct(nct_id)
        except Exception as exc:  # noqa: BLE001 — degrade, never 500 the editor
            _log.warning(
                "Topic search-details: NCT lookup failed",
                user=user["email"], topic_id=topic_id,
                nct_id=nct_id, error=type(exc).__name__,
            )
            nct_result = None
        if nct_result is None:
            error = (
                f"No public study found for {nct_id} — check the number "
                "or type Details by hand."
            )
    elif not query:
        error = "Type a study number, or a few words to search for."
    elif await db_call(
        _account_ids_include_hipaa, db,
        _gate_account_ids(
            topic, form, await db_call(_manageable_account_ids, db, user),
        ),
    ):
        # ── Most-restrictive-wins (design §1a): a HIPAA mailbox flips the
        # whole Topic to registry-only. NO free-text web egress. The gate is
        # over the saved Topic's mailboxes + the editor's live (possibly
        # unsaved) selection — adding a HIPAA mailbox in the editor closes
        # the gate before Save (SME 2026-06-08 fail-open fix). Client-
        # submitted ids are intersected with the requester's manageable set
        # inside _gate_account_ids so they can't be an is-HIPAA enumeration
        # oracle (hipaa-sme 2026-06-08, §164.502(a)/§164.308(a)(4)).
        error = (
            "This Topic includes a protected (HIPAA) mailbox, so Internet "
            "search is limited to public study-registry numbers (for example "
            "NCT00000419). Enter a registry number, or type the Details by "
            "hand."
        )
    else:
        # ── Free-text web path (non-HIPAA, opt-in SearXNG). ──
        # db_call: the settings read runs off-loop under the process-wide
        # DB lock (a raw on-loop execute would race db_call workers on a
        # cache miss — SME 2026-06-08).
        searxng_url = await db_call(get_web_search_searxng_url, db)
        if not searxng_url:
            error = (
                "Internet search isn't set up on this install. Enter a public "
                "study number (for example NCT00000419), or type the Details "
                "by hand."
            )
        else:
            try:
                bundle = await web_search_bundle(
                    query, base_url=searxng_url, top_n=10,
                )
            except Exception as exc:  # noqa: BLE001 — degrade, never 500
                _log.warning(
                    "Topic search-details: web search failed",
                    user=user["email"], topic_id=topic_id,
                    error=type(exc).__name__,
                )
                bundle = None
            if not bundle or not bundle.get("results"):
                error = (
                    f'No web results for "{query}" — try different words, or '
                    "type the Details by hand."
                )
            else:
                # The result list (title/url/content) feeds the Sources URL
                # list AND the raw-card fallback. Then try an LLM summary —
                # local backend, the bundle FENCED as untrusted data
                # (topic_search_summary) — and degrade to the raw card if the
                # backend is slow/unhealthy (web_summary stays None).
                web_results = bundle["results"]
                try:
                    web_summary = await summarize_web_results(
                        query, bundle, config=request.app.state.config,
                    )
                except Exception as exc:  # noqa: BLE001 — never 500
                    _log.warning(
                        "Topic search-details: summary failed",
                        user=user["email"], topic_id=topic_id,
                        error=type(exc).__name__,
                    )
                    web_summary = None

    return await _render(
        templates, request, "profile/_topic_nct_result.html", {
            "user": user,
            "current_user": user,
            "topic": topic,
            "nct_id": nct_id,
            # Whitelisted study fields — rendered as data, not instructions.
            "nct_result": nct_result,
            # Free-text web results (title/url/content), data not instructions.
            "web_results": web_results,
            # LLM-drafted Details summary (None → template shows the raw card).
            "web_summary": web_summary,
            "query": query,
            "search_error": error,
            "search_panel": True,
        },
    )


@router.post(
    "/profile/topic-digest/{topic_id:int}/hits/include",
    response_class=HTMLResponse,
)
async def profile_topic_digest_hit_include(
    request: Request, topic_id: int, user: RequireUser,
):
    """Mark a previewed hit as operator-included (``source='included'``).

    A preview hit is ephemeral; Include promotes it to a durable
    ``topic_hits`` row via ``insert_topic_hit(source='included')`` (the
    UPSERT with the ``first_seen_at = MIN`` pin). The ``account_id`` +
    ``message_id`` arrive in the form body (the preview template's
    ``hx-vals``). §5 fail-closed: BOTH the Topic ownership AND the
    account-manageability are re-asserted server-side — the account is
    intersected with the requester's manageable set, so a forged POST
    can't include a hit on a foreign mailbox.
    """
    db = get_db(request)
    form = await request.form()
    # Template sends ``message_id`` (the durable RFC Message-ID) +
    # ``account_id`` via hx-vals; tolerate the long alias too.
    rfc822_message_id = (
        form.get("message_id") or form.get("rfc822_message_id") or ""
    ).strip()
    folder = (form.get("folder") or "").strip()
    account_id = _safe_int(form.get("account_id"), 0)  # 
    if not rfc822_message_id or account_id <= 0:
        return HTMLResponse("Missing message id or account", status_code=400)

    from email_triage.actions.topic_configs import get_topic, insert_topic_hit

    def _include_db_work() -> bool:
        topic = get_topic(db, topic_id)
        if topic is None or not can_modify_owned_resource(
            topic.user_id, requester_id=user["id"], admin_bypass=False):
            return False
        # §5 per-account auth intersection (fail-closed).
        if not is_manageable(account_id, db, user):
            return False
        insert_topic_hit(
            db,
            topic_id=topic_id,
            account_id=account_id,
            rfc822_message_id=rfc822_message_id,
            folder=folder,
            source="included",
        )
        return True

    ok = await db_call(_include_db_work)
    if not ok:
        return HTMLResponse("Forbidden", status_code=403)
    _log.info(
        "Topic hit included",
        user=user["email"], topic_id=topic_id, account_id=account_id,
    )
    # Matches the preview template's included-state markup — the button
    # cell (hx-target="closest td") is replaced with this confirmation.
    return HTMLResponse(
        '<small style="color:var(--pico-ins-color);">&#x2713; Included</small>',
        status_code=200,
    )


@router.post(
    "/profile/topic-digest/{topic_id:int}/hits/feedback",
    response_class=HTMLResponse,
)
async def profile_topic_digest_hit_feedback(
    request: Request, topic_id: int, user: RequireUser,
):
    """Operator thumbs feedback on a Topic match (operator 2026-06-12,
    "curation + reinforcement loop").

    ``vote`` = ``up`` | ``down``. Records BOTH:
      * message-level curation — up promotes (``source='included'``), down
        soft-removes (``removed_at``) the stored hit (the existing model);
      * a learned per-Topic SENDER signal the matcher honors on FUTURE matches
        (down ⇒ the back-scan + Preview auto-drop that sender).

    §5 fail-closed: Topic ownership AND account-manageability are both
    re-asserted server-side, so a forged POST can't vote on a foreign mailbox.
    ``sender`` is the message's From header (the preview template's hx-vals).
    The operator is acting on their OWN Topic — no actor≠owner audit event (same
    as the sibling Include / Remove curation handlers); the stored sender key is
    operator curation, SAME category as the shipped ``list_rules`` sender
    patterns, SQLCipher-at-rest + cascade-deleted with the Topic.
    """
    db = get_db(request)
    form = await request.form()
    vote_raw = (form.get("vote") or "").strip().lower()
    vote = 1 if vote_raw in ("up", "1", "+1", "yes", "keep") else -1
    rfc822_message_id = (
        form.get("message_id") or form.get("rfc822_message_id") or ""
    ).strip()
    # The sender rides as base64 (a raw From header has quotes that break
    # JSON-in-attr); accept a plaintext ``sender`` fallback too (tests / curl).
    sender = (form.get("sender") or "").strip()
    sender_b64 = (form.get("sender_b64") or "").strip()
    if sender_b64 and not sender:
        try:
            sender = base64.b64decode(sender_b64).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001 — a bad b64 just yields no sender signal
            sender = ""
    account_id = _safe_int(form.get("account_id"), 0)  # 
    if account_id <= 0:
        return HTMLResponse("Missing account", status_code=400)

    from email_triage.actions.topic_configs import (
        get_topic, record_topic_feedback,
    )

    def _fb_db_work() -> dict | None:
        topic = get_topic(db, topic_id)
        if topic is None or not can_modify_owned_resource(
            topic.user_id, requester_id=user["id"], admin_bypass=False):
            return None
        # §5 per-account auth intersection (fail-closed).
        if not is_manageable(account_id, db, user):
            return None
        return record_topic_feedback(
            db, topic_id=topic_id, account_id=account_id, vote=vote,
            sender=sender or None,
            rfc822_message_id=rfc822_message_id or None,
        )

    result = await db_call(_fb_db_work)
    if result is None:
        return HTMLResponse("Forbidden", status_code=403)
    # Invalidate the OPTIONAL Redis mirror — the DB just changed (no-op when the
    # mirror is disabled; the DB read remains the source of truth).
    from email_triage.cache.topic_feedback import invalidate_topic_feedback_cache
    invalidate_topic_feedback_cache(topic_id)
    # NOTE: never log the sender value (PHI) — only whether a signal was learned.
    _log.info(
        "Topic hit feedback",
        user=user["email"], topic_id=topic_id, account_id=account_id,
        vote=vote, learned_sender=bool(result.get("sender_key")),
    )
    if vote > 0:
        return HTMLResponse(
            '<small style="color:var(--pico-ins-color);">&#x1F44D; Kept</small>',
            status_code=200,
        )
    # Two fully-STATIC fragments (no interpolation) — the N-83 styled-HTML
    # escape pin forbids a dynamic read inside a styled fragment, and these
    # carry no dynamic value (the sender is never echoed into the response).
    if result.get("sender_key"):
        return HTMLResponse(
            '<small style="color:var(--pico-muted-color);">'
            '&#x1F44E; Dropped &amp; muting this sender</small>',
            status_code=200,
        )
    return HTMLResponse(
        '<small style="color:var(--pico-muted-color);">&#x1F44E; Dropped</small>',
        status_code=200,
    )


@router.post(
    "/profile/topic-digest/{topic_id:int}/feedback/unmute",
    response_class=HTMLResponse,
)
async def profile_topic_digest_feedback_unmute(
    request: Request, topic_id: int, user: RequireUser,
):
    """Un-mute a sender previously thumbs-down'd for this Topic.

    This is the ONLY undo for a mute: once a sender is muted, its mail never
    reappears in the Preview/digest, so there is nothing left to thumbs-UP — the
    editor's muted-senders list is how a mute is reversed. §5: Topic ownership is
    re-asserted server-side. Empty 200 body = the row removes itself (hx-swap
    outerHTML).
    """
    db = get_db(request)
    form = await request.form()
    sender = (form.get("sender") or "").strip()
    sender_b64 = (form.get("sender_b64") or "").strip()
    if sender_b64 and not sender:
        try:
            sender = base64.b64decode(sender_b64).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001
            sender = ""
    if not sender:
        return HTMLResponse("Missing sender", status_code=400)

    from email_triage.actions.topic_configs import (
        clear_topic_feedback, get_topic, normalize_feedback_sender,
    )

    def _unmute_db_work() -> bool:
        topic = get_topic(db, topic_id)
        if topic is None or not can_modify_owned_resource(
            topic.user_id, requester_id=user["id"], admin_bypass=False):
            return False
        clear_topic_feedback(
            db, topic_id=topic_id, signal_type="sender",
            signal_value=normalize_feedback_sender(sender),
        )
        return True

    ok = await db_call(_unmute_db_work)
    if not ok:
        return HTMLResponse("Forbidden", status_code=403)
    from email_triage.cache.topic_feedback import invalidate_topic_feedback_cache
    invalidate_topic_feedback_cache(topic_id)
    _log.info(
        "Topic feedback un-muted", user=user["email"], topic_id=topic_id,
    )
    return HTMLResponse("", status_code=200)


@router.delete(
    "/profile/topic-digest/{topic_id:int}/hits/{account_id:int}/{msgid:path}",
    response_class=HTMLResponse,
)
async def profile_topic_digest_hit_remove(
    request: Request, topic_id: int, account_id: int, msgid: str,
    user: RequireUser,
):
    """Per-hit Remove = feedback (design §3d). SOFT-remove (set
    ``removed_at``) — kept for audit/teaching, never a hard row delete.

    §5 fail-closed: Topic ownership AND account-manageability are both
    re-asserted before the soft-remove. The soft-remove keeps the row for
    the removed-hit feedback aggregation the digest build runs.
    """
    db = get_db(request)

    from email_triage.actions.topic_configs import get_topic

    def _remove_db_work() -> bool:
        topic = get_topic(db, topic_id)
        if topic is None or not can_modify_owned_resource(
            topic.user_id, requester_id=user["id"], admin_bypass=False):
            return False
        if not is_manageable(account_id, db, user):
            return False
        cur = db.execute(
            "UPDATE topic_hits SET removed_at = ? "
            "WHERE topic_id = ? AND account_id = ? "
            "AND rfc822_message_id = ? AND removed_at IS NULL",
            (
                now_utc_iso(),
                int(topic_id), int(account_id), msgid,
            ),
        )
        db.commit()
        return cur.rowcount > 0

    ok = await db_call(_remove_db_work)
    if not ok:
        # Idempotent / not-found / unauthorized all collapse to a quiet
        # 200 with an empty body so the HTMX row swap removes the chip
        # either way — but a genuine auth failure is logged.
        _log.info(
            "Topic hit remove: no-op (not found / already removed / "
            "unauthorized)",
            user=user["email"], topic_id=topic_id, account_id=account_id,
        )
    else:
        _log.info(
            "Topic hit soft-removed (feedback)",
            user=user["email"], topic_id=topic_id, account_id=account_id,
        )
    return HTMLResponse("", status_code=200)


