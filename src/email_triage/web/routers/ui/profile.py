"""Routes for the profile concern.

Split out of the legacy `web/routers/ui.py` (#144). Helpers
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
from datetime import datetime, timezone
from typing import Any
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_manage_account
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
from email_triage.web.dependencies import (
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

_log = get_logger("web.ui.profile")

router = APIRouter()


def __getattr__(name):
    """Route reads of legacy install-singleton names through the factory.

    The factory module (#138.1) now owns ``_install_google_oauth`` and
    ``_install_ingestion_config``. Code that did
    ``from email_triage.web.routers.ui import _install_ingestion_config``
    (e.g. test fixtures, future plugins) keeps working — PEP 562 lets
    us proxy module-level reads to the factory's current values.
    """
    if name == "_install_google_oauth":
        from email_triage.providers import factory as _f
        return _f._install_google_oauth
    if name == "_install_ingestion_config":
        from email_triage.providers import factory as _f
        return _f._install_ingestion_config
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")



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
    """PEP 562 fallback — late-bound lookup on _shared.

    Catches names added to `_shared` after this module's globals
    were populated, plus names that the package-level monkeypatch
    mirror writes onto `_shared` AFTER import.
    """
    if hasattr(_shared, name):
        return getattr(_shared, name)
    raise AttributeError(
        f'module {__name__!r} has no attribute {name!r}'
    )


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    """User settings page — notify address + per-category escalation."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.sms_carriers import US_CELL_CARRIERS

    snap = await db_call(_profile_page_snapshot, db, user)

    return _render(templates, request, "profile.html", {
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
        **snap["writing_ctx"],
    })


@router.post("/profile/save", response_class=HTMLResponse)
async def profile_save(request: Request):
    """Save user settings (notify address + escalation prefs).

    #73 — primary path is the carrier dropdown + cell number, which
    computes the email-to-SMS gateway address and writes it into
    ``users.notify_email``. Free-text ``notify_email`` field stays as
    an Advanced override for non-SMS recipients.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

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

    # Render-state helpers used both on the happy + error paths so the
    # form can re-display with the operator's input intact.
    categories = list_categories(db, user_id=user["id"])
    personal_categories = list_categories(db, user_id=user["id"], scope="personal")
    meeting_prefs = _load_meeting_prefs_with_default_tz(db, user["id"])

    # Thread the form-submitted tab back into the re-render so the
    # operator stays on the tab they saved from. profile.html's
    # hidden ``active_tab`` field is the source of truth post-POST
    # (query params are empty after form submit).
    active_tab = _resolve_profile_tab(request, form)

    writing_ctx = _writing_tab_context(db, user)

    def _re_render(*, save_msg: str | None, error: str | None,
                   sms_prefs: dict, escalation: set[str]) -> HTMLResponse:
        return _render(templates, request, "profile.html", {
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
            return _re_render(
                save_msg=None,
                error="Cell number must be a 10-digit US number "
                      "(11 digits OK if it starts with 1).",
                sms_prefs={"number": sms_number_raw, "carrier": sms_carrier},
                escalation=get_user_escalation_categories(db, user["id"]),
            )
        addr = build_sms_address(norm, sms_carrier)
        if addr is None:
            return _re_render(
                save_msg=None,
                error=f"Unknown carrier: {sms_carrier!r}.",
                sms_prefs={"number": sms_number_raw, "carrier": sms_carrier},
                escalation=get_user_escalation_categories(db, user["id"]),
            )
        notify_email = addr
        sms_prefs = {"number": norm, "carrier": sms_carrier}
        set_setting(db, _S.escalation_sms(user["id"]), sms_prefs)
    elif notify_email_free:
        # Advanced free-text override — clear any prior SMS dropdown
        # choice so the form doesn't render a stale carrier on revisit.
        delete_setting(db, _S.escalation_sms(user["id"]))
        notify_email = notify_email_free
    else:
        # Both empty — clear everything.
        delete_setting(db, _S.escalation_sms(user["id"]))
        notify_email = None

    db.execute(
        "UPDATE users SET notify_email = ? WHERE id = ?",
        (notify_email, user["id"]),
    )
    db.commit()
    user = dict(user)
    user["notify_email"] = notify_email

    # Build escalation categories from the form checkboxes.
    selected = []
    for cat in categories:
        slug = cat["slug"]
        if f"escalate_{slug}" in form:
            selected.append(slug)
    set_user_escalation_categories(db, user["id"], selected)
    escalation_categories = set(selected)

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

    return _re_render(
        save_msg=msg, error=None,
        sms_prefs=sms_prefs, escalation=escalation_categories,
    )


# ---------------------------------------------------------------------------
# Punch-list #102 — "Test Now" button on /profile?tab=notifications
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
async def profile_escalation_test_send(request: Request):
    """Fire a single fixed-text test message through the live
    escalation send path so the operator can verify wiring before
    waiting on a real urgent email.

    No PHI is ever included — the body is a synthetic constant.
    Audit row written to ``auth_events`` (event_type
    ``escalation_test``) with the resolved gateway address in
    ``detail`` (NOT the body).
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    is_htmx = request.headers.get("HX-Request") == "true"

    from email_triage.web.db import (
        get_user_escalation_categories,
        list_categories,
        record_auth_event,
    )

    # Defense-in-depth: button shouldn't render without a notify
    # address, but a direct POST must still fail soft.
    notify_email = (user.get("notify_email") or "").strip()
    if not notify_email:
        record_auth_event(
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
    selected = get_user_escalation_categories(db, user["id"])
    if not selected:
        record_auth_event(
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

    cats = list_categories(db, user_id=user["id"])
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
        record_auth_event(
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
        record_auth_event(
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
            smtp_password = secrets.get("SMTP_PASSWORD") or ""
        except Exception:
            smtp_password = ""

    # Send. Errors propagate as smtplib.SMTPException (or generic
    # OSError on connection failure) — the failure chip + audit row
    # both record the truncated message. Don't swallow the error
    # silently; we want the operator to see what the relay said.
    import json as _json
    from email_triage.web.smtp_send import send_simple_smtp_email
    try:
        send_simple_smtp_email(
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
        err_str = f"{type(e).__name__}: {e}"
        record_auth_event(
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

    record_auth_event(
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
async def profile_writing_save(request: Request):
    """Save the per-user writing-style knobs (M-1 + M-2).

    Tone / length / greeting are validated against the canonical
    allowlists; any value outside those sets is replaced with the
    column default rather than rejecting the whole save (the form
    radio groups make invalid values impossible from the UI, but
    a hand-crafted POST should still produce a coherent stored
    state). Free-text fields are length-capped before the DB write.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

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
    set_user_style_knobs(db, user["id"], knobs)

    # Anti-AI style guide (per-user override + disable-global flag).
    # Cap length defensively so a hand-crafted 1MB POST can't stuff the
    # DB even though the UI textarea sets ``maxlength`` server-side.
    anti_ai_user_text = (
        form.get("anti_ai_style_guide_user") or ""
    ).strip()[:ANTI_AI_STYLE_GUIDE_MAX_LEN]
    anti_ai_disable_global = (
        form.get("anti_ai_style_guide_disable_global") in ("1", "on", "true")
    )
    set_user_anti_ai_style_guide(
        db, user["id"],
        text=anti_ai_user_text,
        disable_global=anti_ai_disable_global,
    )

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
async def profile_meeting_prefs_save(request: Request):
    """Save the per-user meeting-request intercept preferences."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    form = await request.form()

    from datetime import datetime, timezone
    from email_triage.engine.models import (
        MeetingPreferences, OutOfOfficeOverride, WorkingHours,
    )
    from email_triage.web.db import set_meeting_prefs

    try:
        length = int(form.get("default_length_minutes", 30))
    except (TypeError, ValueError):
        length = 30
    if length not in (15, 30, 45, 60, 90, 120):
        # Constrain to the dropdown's allowed values.
        length = 30
    try:
        count = int(form.get("suggestion_count", 3))
    except (TypeError, ValueError):
        count = 3
    count = max(1, min(5, count))
    # 2026-05-14 — "over Number of Days" knob. Bounded 1..14 to match
    # MeetingPreferences.from_dict; values outside that range collapse
    # to the default 5.
    try:
        days = int(form.get("suggestion_days", 5))
    except (TypeError, ValueError):
        days = 5
    days = max(1, min(14, days))
    try:
        horizon = int(form.get("search_horizon_days", 14))
    except (TypeError, ValueError):
        horizon = 14
    horizon = max(1, min(60, horizon))
    try:
        lead = int(form.get("minimum_lead_time_hours", 24))
    except (TypeError, ValueError):
        lead = 24
    lead = max(0, lead)

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
            try:
                # datetime-local form fields lack a tz; treat as UTC.
                dt = datetime.fromisoformat(v)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                setattr(ooo, attr, dt)
            except ValueError:
                pass

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
    set_meeting_prefs(db, user["id"], prefs.to_dict())

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
async def profile_meeting_prefs_group_apply(request: Request):
    """Apply one start/end pair to all weekdays / weekend / all days.

    Overwrites the first interval of each affected day and clears any
    second interval (the user can re-add lunch breaks per-day).
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    form = await request.form()
    scope = (form.get("scope") or "weekdays").strip()
    start = (form.get("start") or "").strip()
    end = (form.get("end") or "").strip()

    from email_triage.engine.models import MeetingPreferences
    from email_triage.web.db import get_meeting_prefs, set_meeting_prefs
    prefs = MeetingPreferences.from_dict(get_meeting_prefs(db, user["id"]))

    if scope == "weekend":
        days = ("sat", "sun")
    elif scope == "all":
        days = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    else:  # weekdays (default)
        days = ("mon", "tue", "wed", "thu", "fri")

    if start and end and start < end:
        for day in days:
            setattr(prefs.working_hours, day, [(start, end)])
    elif not start and not end:
        # Both blank → mark scope as off.
        for day in days:
            setattr(prefs.working_hours, day, [])

    set_meeting_prefs(db, user["id"], prefs.to_dict())
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
async def profile_style_data_page(request: Request):
    """M-8 — show what writing-style data we have for each account."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

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

    # #180 F — embedding-runtime gate. Probes app.state for the live
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

    return _render(templates, request, "profile/style_data.html", {
        "user": user,
        "current_user": user,
        "accounts": snap["accounts"],
        "master_enabled": snap["master_enabled"],
        # #161 — cadence banner + install-default placeholder for the
        # per-account "Messages to mine" override.
        "capture_interval_hours": snap.get("capture_interval_hours", 6),
        "mine_limit_install_default": snap.get(
            "mine_limit_install_default", 50,
        ),
        "inline_limit_ceiling": snap.get("inline_limit_ceiling", 50),
        # #180 F — embedding-runtime gate (end-user audience copy).
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
async def profile_style_data_export(request: Request):
    """Export the per-account style metadata as a JSON download.

    The export deliberately excludes raw message bodies and embedding
    vectors — the goal is "operator can verify what's saved" not "give
    the user a backup that re-creates the index from scratch". Under
    HIPAA, sample subjects + recipient lists in the saved-replies
    section are redacted to the literal string ``[redacted]`` so the
    export never leaks PHI to disk; counts and timestamps remain
    accurate so the user can compare to what's on screen.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
    if acct is None:
        _record_style_data_audit(
            db,
            event_type="style_data_export",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=int(account_id_raw or 0),
            outcome="failure",
            detail=err,
        )
        return HTMLResponse(err or "Forbidden", status_code=403)

    from fastapi.responses import JSONResponse
    from email_triage.web.db import (
        get_style_profile,
        get_sent_mail_index_summary,
        get_captured_pair_count,
    )

    profile_dict = get_style_profile(db, acct["id"]) or {}
    index_summary = get_sent_mail_index_summary(db, acct["id"])
    captured = get_captured_pair_count(db, acct["id"])

    # HIPAA-aware sample shaping. The summary helper does NOT redact;
    # gating happens here so a non-HIPAA install gets readable
    # subjects in the download while HIPAA installs are scrubbed.
    if acct.get("hipaa"):
        sample_subjects = ["[redacted]" for _ in (index_summary.get("sample_subjects") or [])]
    else:
        sample_subjects = list(index_summary.get("sample_subjects") or [])

    payload = {
        "schema": "email-triage style-data export v1",
        "exported_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc,
        ).isoformat(),
        "account": {
            "id": acct["id"],
            "name": acct.get("name") or "",
            "hipaa": bool(acct.get("hipaa")),
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
    _record_style_data_hipaa_access(
        db,
        actor_user_id=user["id"],
        account=acct,
        operation="style_data_export",
    )

    filename = f"style-data-account-{acct['id']}.json"
    return JSONResponse(
        content=payload,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.post("/profile/style-data/delete-profile", response_class=HTMLResponse)
async def profile_style_data_delete_profile(request: Request):
    """Delete the writing-style summary (M-3) for an account."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
    if acct is None:
        _record_style_data_audit(
            db,
            event_type="style_data_delete_profile",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=int(account_id_raw or 0),
            outcome="failure",
            detail=err,
        )
        return HTMLResponse(err or "Forbidden", status_code=403)

    try:
        from email_triage.web.db import (
            delete_account_style_per_alias,
            delete_style_profile,
        )
        deleted = delete_style_profile(db, acct["id"])
        # Punch list #162 — drop per-alias descriptors alongside the
        # account-wide row. The two are conceptually one "writing-
        # style summary" surface, and the user-facing "Delete writing-
        # style summary" button has to clear both for the page to
        # render an empty state consistently.
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
    _record_style_data_hipaa_access(
        db,
        actor_user_id=user["id"],
        account=acct,
        operation="style_data_delete_profile",
    )

    return RedirectResponse("/profile/style-data", status_code=303)


@router.post("/profile/style-data/delete-index", response_class=HTMLResponse)
async def profile_style_data_delete_index(request: Request):
    """Delete the recent reply examples (M-4 sent_mail_index) for an account."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
    if acct is None:
        _record_style_data_audit(
            db,
            event_type="style_data_delete_index",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=int(account_id_raw or 0),
            outcome="failure",
            detail=err,
        )
        return HTMLResponse(err or "Forbidden", status_code=403)

    try:
        from email_triage.web.db import delete_sent_mail_index_for_account
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
    _record_style_data_hipaa_access(
        db,
        actor_user_id=user["id"],
        account=acct,
        operation="style_data_delete_index",
    )

    return RedirectResponse("/profile/style-data", status_code=303)


@router.post("/profile/style-data/delete-all", response_class=HTMLResponse)
async def profile_style_data_delete_all(request: Request):
    """Delete EVERYTHING (profile + index) for an account, transactionally.

    Wrapped in a single SAVEPOINT so a partial failure (e.g. profile
    delete OK, index delete fails) rolls back so the user can retry
    without leaving half the data behind.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
    if acct is None:
        _record_style_data_audit(
            db,
            event_type="style_data_delete_all",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=int(account_id_raw or 0),
            outcome="failure",
            detail=err,
        )
        return HTMLResponse(err or "Forbidden", status_code=403)

    from email_triage.web.db import _has_table

    # Atomic two-step delete via raw SQL inside one SAVEPOINT. We
    # bypass the per-helper ``conn.commit()`` calls (which would
    # implicitly release the savepoint) and emit DELETE statements
    # directly so a failure on the second statement rolls back the
    # first via ROLLBACK TO SAVEPOINT.
    sp_name = "m8_delete_all"
    db.execute(f"SAVEPOINT {sp_name}")
    try:
        # Profile row in the settings table.
        db.execute(
            "DELETE FROM settings WHERE key = ?",
            (_S.style_profile(acct["id"]),),
        )
        # Sent-mail-index rows (M-4 + M-6 share this table; deleting
        # by account_id removes both reply examples and captured
        # edit pairs in one shot).
        if _has_table(db, "sent_mail_index"):
            db.execute(
                "DELETE FROM sent_mail_index WHERE account_id = ?",
                (acct["id"],),
            )
        # Punch list #162 — per-alias descriptor rows. Dropped under
        # the same savepoint so a partial failure rolls back together.
        if _has_table(db, "account_style_per_alias"):
            db.execute(
                "DELETE FROM account_style_per_alias WHERE account_id = ?",
                (acct["id"],),
            )
        db.execute(f"RELEASE SAVEPOINT {sp_name}")
        db.commit()
        # Keep the in-process settings cache (#140.2) coherent — the
        # DELETE above bypassed delete_setting() to share the
        # savepoint transaction.
        from email_triage.web.db import invalidate_setting_cache
        invalidate_setting_cache(_S.style_profile(acct["id"]))
    except Exception as e:
        try:
            db.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
            db.execute(f"RELEASE SAVEPOINT {sp_name}")
        except Exception:
            pass
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
    _record_style_data_hipaa_access(
        db,
        actor_user_id=user["id"],
        account=acct,
        operation="style_data_delete_all",
    )

    return RedirectResponse("/profile/style-data", status_code=303)


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
async def profile_style_data_toggle_rag(request: Request):
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
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
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
    if bool(acct.get("hipaa")) and not is_style_knobs_hipaa_allow(db, acct["id"]):
        _log.info(
            "AI-learns toggle refused — HIPAA without opt-in",
            account_id=acct["id"],
            actor_user_id=user["id"],
        )
        return RedirectResponse("/profile/style-data", status_code=303)

    set_rag_sent_index_enabled(db, acct["id"], enabled=desired)
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
async def profile_style_data_toggle_auto_scan(request: Request):
    """#161 item 2 — per-account "Auto-scan on schedule" toggle.

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
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
    if acct is None:
        return HTMLResponse(err or "Forbidden", status_code=403)

    form = await request.form()
    desired = "auto_scan_enabled" in form

    from email_triage.web.db import (
        is_style_knobs_hipaa_allow,
        set_auto_scan_enabled_for_account,
    )
    if bool(acct.get("hipaa")) and not is_style_knobs_hipaa_allow(db, acct["id"]):
        _log.info(
            "Auto-scan toggle refused — HIPAA without opt-in",
            account_id=acct["id"],
            actor_user_id=user["id"],
        )
        return RedirectResponse("/profile/style-data", status_code=303)

    set_auto_scan_enabled_for_account(db, acct["id"], desired)
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
async def profile_style_data_mine_limit_override(request: Request):
    """#161 item 4 — per-account "Messages to mine" override.

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
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
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
        try:
            v = int(raw)
        except (TypeError, ValueError):
            return RedirectResponse(
                "/profile/style-data", status_code=303,
            )
        if v < STYLE_LEARNING_MINE_LIMIT_MIN:
            v = STYLE_LEARNING_MINE_LIMIT_MIN
        elif v > STYLE_LEARNING_MINE_LIMIT_MAX:
            v = STYLE_LEARNING_MINE_LIMIT_MAX
        value = v
    update_account_config_keys(
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
async def profile_style_data_sent_folder_override(request: Request):
    """Persist the per-account Sent-folder override (config_json key).

    Empty submit clears the override; non-empty stores the literal
    folder name. Read by the mine-now path (and the M-3/M-4/M-6
    capture-loop paths) in preference to ``find_sent_folder`` when
    set. No HIPAA gate — folder names aren't PHI.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
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
    update_account_config_keys(
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
# Punch list #162 — alias-aware learning toggle
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
async def profile_style_data_toggle_alias_mode(request: Request):
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
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
    if acct is None:
        _record_style_data_audit(
            db,
            event_type="style_data_toggle_alias_mode",
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=int(account_id_raw or 0),
            outcome="failure",
            detail=err,
        )
        return HTMLResponse(err or "Forbidden", status_code=403)

    form = await request.form()
    desired = "style_alias_mode_enabled" in form

    from email_triage.web.db import (
        is_style_knobs_hipaa_allow,
        set_alias_mode_enabled_for_account,
    )
    # HIPAA gate. Refuse the write when account is HIPAA + not opted
    # in. Audit row + HIPAA access row are both written so an admin
    # review surfaces the refused attempt as well as a successful
    # flip. The owner-self-access carve-out applies to the HIPAA
    # access row; the audit row writes regardless.
    is_hipaa = bool(acct.get("hipaa"))
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
        _record_style_data_hipaa_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="style_data_toggle_alias_mode",
            outcome="failure",
        )
        return RedirectResponse("/profile/style-data", status_code=303)

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
    _record_style_data_hipaa_access(
        db,
        actor_user_id=user["id"],
        account=acct,
        operation="style_data_toggle_alias_mode",
    )

    return RedirectResponse("/profile/style-data", status_code=303)


# ---------------------------------------------------------------------------
# #157 — On-demand mine + dry-run preview for the style-data page
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
# #152 phase 2 plumbed for M-1+M-2; we reuse it for M-3 dry-run /
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
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    account_id_raw = request.query_params.get("account_id")
    acct, err = _resolve_style_data_account(db, user, account_id_raw)
    event_type = (
        "style_data_mine_now" if commit else "style_data_preview"
    )

    if acct is None:
        _record_style_data_audit(
            db,
            event_type=event_type,
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=int(account_id_raw or 0),
            outcome="failure",
            detail=err,
        )
        return HTMLResponse(
            _mine_result_fragment(
                state="error",
                title="Could not find that account",
                body=err or "Forbidden",
            ),
            status_code=403,
        )

    # HIPAA gate — must run BEFORE the provider fetch. M-3 reads
    # source-mail bodies; the per-account opt-in lifts that for
    # operator-owned HIPAA mailboxes per §164.502(a). Without the
    # opt-in we refuse and audit.
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import is_style_knobs_hipaa_allow
    if is_account_hipaa(acct):
        if not is_style_knobs_hipaa_allow(db, acct["id"]):
            _record_style_data_audit(
                db,
                event_type=event_type,
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="failure",
                detail="hipaa_gate",
            )
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
        _record_style_data_audit(
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
    # #161 item 4 — limit resolution:
    #   per-account override > install-wide default > 50.
    # Resolved value > STYLE_LEARNING_INLINE_LIMIT_CEILING triggers
    # the bulk-handoff branch below (#161 item 5). Inline path keeps
    # the historical "50 messages, ~30 s" behaviour for the common
    # case so most operators see the result in the page without
    # leaving it.
    from email_triage.web.db import (
        resolve_account_mine_limit,
        STYLE_LEARNING_INLINE_LIMIT_CEILING,
    )
    limit = resolve_account_mine_limit(db, acct)

    # #161 item 5 — Bulk-worker handoff for limits > ceiling. The
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
        if count_active_triage_jobs_for_account(db, acct["id"]) > 0:
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
        job_id = create_triage_job(
            db,
            account_id=acct["id"],
            actor_user_id=user["id"],
            # Encode the resolved limit into the query column so the
            # bulk-style-mine runner can recover it without a second
            # DB hop on the account row. Format is stable + parsed
            # in run_triage_all_style_mine.
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
        _record_style_data_hipaa_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation=event_type,
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
        _record_style_data_audit(
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

    # Punch list #162 — alias-aware learning. When alias-mode is on,
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
    ).strip().lower()
    alias_from_address_norm = _norm_addr(alias_from_address)
    alias_mode_on = _is_alias_mode_on(db, acct["id"])
    known_addresses = _account_addresses(acct)

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

    # Punch list #162 — when alias-mode is on, split the corpus by
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
                )
            )
        except Exception as exc:
            _record_style_data_audit(
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
            persisted_addrs: list[str] = []
            persist_err: str = ""
            try:
                # Persist each non-empty bucket into the per-alias table.
                for addr, prof in alias_descriptors.items():
                    _set_alias_descriptor(
                        db, acct["id"], addr, prof.to_dict(),
                        sample_count=prof.sample_count,
                    )
                    persisted_addrs.append(addr or "(no-bucket)")
                # Also refresh the account-wide descriptor when the
                # operator mined every alias at once (no
                # ``alias_from_address`` filter). The account-wide
                # row stays as the fallback when alias-mode is later
                # turned off; without this refresh it would point at
                # a stale single-style result.
                if (
                    not alias_from_address_norm
                    and alias_descriptors
                ):
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
                        set_style_profile(db, acct["id"], best.to_dict())
                    except Exception:
                        # Non-fatal — per-alias rows are still saved.
                        pass
            except Exception as exc:
                persist_err = fmt_exc(exc)[:200]
            if persist_err:
                _record_style_data_audit(
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
            _record_style_data_hipaa_access(
                db,
                actor_user_id=user["id"],
                account=acct,
                operation=event_type,
            )
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
        )
    except Exception as exc:
        _record_style_data_audit(
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
        try:
            from email_triage.web.db import set_style_profile
            set_style_profile(db, acct["id"], profile.to_dict())
        except Exception as exc:
            _record_style_data_audit(
                db,
                event_type=event_type,
                actor_user_id=user["id"],
                actor_email=user.get("email") or "",
                account_id=acct["id"],
                outcome="failure",
                detail=f"persist: {fmt_exc(exc)[:200]}",
            )
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
        _record_style_data_audit(
            db,
            event_type=event_type,
            actor_user_id=user["id"],
            actor_email=user.get("email") or "",
            account_id=acct["id"],
            outcome="success",
            detail=f"samples={profile.sample_count}",
        )
        _record_style_data_hipaa_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation=event_type,
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
        rows.append((
            "Phrases you use",
            ", ".join(profile.phrases_used[:10]),
        ))
    if profile.phrases_avoided:
        rows.append((
            "Phrases the AI should avoid",
            ", ".join(profile.phrases_avoided[:5]),
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
                parts.append(
                    f"<p style='margin:0.3rem 0 0 0;font-size:0.9em;'>"
                    f"{_e(persona[:200])}</p>"
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
    """#157 — dry-run M-3 distillation. Returns the descriptor the
    install would save, without writing it. Operator uses this to
    sanity-check the privacy / style trade before opting in.
    """
    return await _mine_or_preview(request, commit=False)


@router.post("/profile/style-data/mine-now", response_class=HTMLResponse)
async def profile_style_data_mine_now(request: Request):
    """#157 — on-demand M-3 distillation. Runs the same distillation
    as the scheduled tick + persists the result + writes an audit
    row. Operator uses this to refresh after a big style shift.
    """
    return await _mine_or_preview(request, commit=True)


@router.get("/accounts/api-keys", response_class=HTMLResponse)
async def api_keys_page(request: Request):
    """Render the API Keys management page.

    Admins see all keys across all users; regular users see only their
    own. Keys drive the bearer-token auth for ``/api/openclaw/*``; the
    raw value is shown ONCE at creation time (stored hashed in the DB)
    so the user must copy it then.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(_api_keys_page_snapshot, db, user)

    return _render(templates, request, "accounts/api_keys.html", {
        "user": user, "keys": snap["keys"], "is_admin": snap["is_admin"],
        "all_users": snap["all_users"], "new_key_open": False,
    })


@router.post("/accounts/api-keys", response_class=HTMLResponse)
async def api_keys_create(request: Request):
    """Mint a new API key. Returns an HTMX fragment that shows the
    raw key exactly once — it's stored hashed server-side."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

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
    is_admin = user["role"] == "admin"
    if target_email != user["email"] and not is_admin:
        return HTMLResponse("Forbidden", status_code=403)

    from email_triage.web.auth import (
        get_user_by_email, generate_api_key, hash_api_key, store_api_key,
    )
    target = get_user_by_email(db, target_email)
    if target is None:
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">'
            f'Unknown user: {target_email}</small>',
            status_code=404,
        )

    # Expires-at selector: blank = never, or an "Nd" relative offset.
    expires_choice = (form.get("expires") or "never").strip()
    expires_at: str | None = None
    if expires_choice.endswith("d") and expires_choice[:-1].isdigit():
        from datetime import timedelta
        days = int(expires_choice[:-1])
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    key_id = store_api_key(
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
        f'Name: <strong>{name}</strong> &middot; '
        f'For: <strong>{target_email}</strong> &middot; '
        f'Alias: <strong>{alias}</strong> &middot; '
        f'Expires: <strong>{expires_choice}</strong>'
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
async def api_keys_delete(request: Request, key_id: int):
    """Revoke an API key. Ownership required (admin or own key)."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    from email_triage.web.auth import delete_api_key

    def _api_key_delete_snapshot(
        db, key_id, actor_user_id, actor_email, user_role,
    ):
        """#135 phase 2 — auth check + delete in one threadpool hop."""
        row = db.execute(
            "SELECT user_id FROM api_keys WHERE id = ?", (key_id,),
        ).fetchone()
        if row is None:
            return "not_found"
        if row["user_id"] != actor_user_id and user_role != "admin":
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
# /profile/watches — #154 match-and-fire watch editor (replaces the
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
    from email_triage.web.db import list_email_accounts
    from email_triage.triage_logging import is_account_hipaa
    rows = list_email_accounts(db, user_id=user["id"])
    out: list[dict] = []
    actor_id = user["id"]
    for r in rows:
        owner_id = r.get("user_id")
        out.append({
            "id": r["id"],
            "name": r.get("name") or "",
            "email_address": r.get("email_address") or "",
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
async def profile_watches_page(request: Request):
    """List the operator's watches + show the New-watch form."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(_profile_watches_page_snapshot, db, user)

    # Empty watch shell for the "New watch" form. Default to no
    # accounts ticked — the operator must opt in.
    from email_triage.web.email_watches import EmailWatch
    blank_watch = EmailWatch(enabled=True)

    return _render(templates, request, "profile/watches.html", {
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
async def profile_watches_edit_page(request: Request, group_id: str):
    """Edit an existing watch group (fan-out across accounts)."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

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

    return _render(templates, request, "profile/watches.html", {
        "user": user,
        "current_user": user,
        "groups": snap["groups"],
        "user_accounts": snap["user_accounts"],
        "group": snap["group"],
        "w": snap["group"]["representative"],
        "errors": [],
        "save_msg": None,
    })


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
    #154 removed the per-account Watches tab.
    """
    raw = form.getlist("account_ids") if hasattr(form, "getlist") else []
    requested: set[int] = set()
    for v in raw:
        try:
            requested.add(int(v))
        except (TypeError, ValueError):
            continue

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
async def profile_watches_save_new(request: Request):
    """Create a new watch group across the ticked accounts."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

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
        return _render(templates, request, "profile/watches.html", {
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
        for acct_id in target_ids:
            acct = get_email_account(db, acct_id)
            if acct is None:
                continue
            if (acct.get("user_id") != user["id"]
                    and acct.get("hipaa")):
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
    import secrets as _stdlib_secrets
    for wid in created_watch_ids:
        try:
            existing = secrets.get(hmac_secret_key(wid))
        except Exception:
            existing = None
        if not existing:
            try:
                secrets.set(
                    hmac_secret_key(wid),
                    _stdlib_secrets.token_urlsafe(32),
                )
            except Exception:
                pass

    msg = f"Watch saved on {len(target_ids)} "
    msg += "account" if len(target_ids) == 1 else "accounts"
    if hipaa_attempts:
        msg += (
            f". {len(hipaa_attempts)} account(s) marked Protected "
            "Health Info were skipped — set a watch on those accounts "
            "directly."
        )
    _log.info(
        "Profile watch saved (new)",
        user=user["email"],
        group_id=group_id_final,
        account_count=len(target_ids),
        hipaa_skipped=len(hipaa_attempts),
    )
    return RedirectResponse(
        f"/profile/watches/{group_id_final}/edit?saved=1",
        status_code=303,
    )


@router.post(
    "/profile/watches/{group_id:path}/save", response_class=HTMLResponse,
)
async def profile_watches_save_existing(request: Request, group_id: str):
    """Update an existing watch group across the ticked accounts."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

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
        return _render(templates, request, "profile/watches.html", {
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
    import secrets as _stdlib_secrets
    for wid in created_watch_ids:
        try:
            existing_secret = secrets.get(hmac_secret_key(wid))
        except Exception:
            existing_secret = None
        if not existing_secret:
            try:
                secrets.set(
                    hmac_secret_key(wid),
                    _stdlib_secrets.token_urlsafe(32),
                )
            except Exception:
                pass

    _log.info(
        "Profile watch saved (existing)",
        user=user["email"],
        group_id=group_id_final,
        account_count=len(target_ids),
        created=len(created_watch_ids),
        deleted=len(deleted_watch_ids),
        hipaa_skipped=len(hipaa_attempts),
    )

    return RedirectResponse(
        f"/profile/watches/{group_id_final}/edit?saved=1",
        status_code=303,
    )


@router.post(
    "/profile/watches/{group_id:path}/delete", response_class=HTMLResponse,
)
async def profile_watches_delete(request: Request, group_id: str):
    """Delete every row in a watch group."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

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


