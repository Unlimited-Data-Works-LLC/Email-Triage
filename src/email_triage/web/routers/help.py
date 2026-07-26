"""Help / how-to runbook surface.

Static, anonymous-accessible task walkthroughs for end users + medical
researchers. The page is intentionally non-PHI: every example is generic
("your work-email account", "BCBSM newsletter") and never references a
specific user, account, or message. That's why no auth is required —
the help text is the same for everyone, and forcing a login on the
how-to page would block users who hit it from a deep link in an
operator email or a printout.

Single GET route renders ``help/tasks.html`` (extends base.html so
the nav strip + tooltip engine come along). The template is the
single source of truth for the task list — adding task #7 is a
template-only change, no router code touches it.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from email_triage.web.app import get_templates
from email_triage.web._audit import safe_audit_write

router = APIRouter()


@router.get("/help/tasks", response_class=HTMLResponse)
async def help_tasks(request: Request):
    """Render the simple-task guide.

    Anonymous access is fine: the page is generic how-to copy with
    no per-account / per-user state. Same reason we don't gate
    /static/style.css behind auth — these are non-PHI surfaces.

    Reuses ``ui._render`` so dev-mode banner + HIPAA chip + nav
    strip behave identically to authenticated pages.
    """
    from email_triage.web.routers.ui import _render
    from email_triage.web.dependencies import get_current_user
    from email_triage.web.db_threadpool import db_call

    templates = get_templates(request)
    #  — get_current_user takes the DB write lock (verify_api_key
    # is @db_write); run it off the event-loop thread.
    user = await db_call(get_current_user, request)
    return await _render(
        templates, request, "help/tasks.html",
        {"user": user},
    )


@router.get("/help/integrations", response_class=HTMLResponse)
async def help_integrations(request: Request):
    """Step-by-step setup guides for Gmail + Office 365 ingestion.

    Four walkthroughs:

      - Gmail Pub/Sub (push) — Google Cloud Console setup + token
        plumbing
      - Gmail Poll — simpler OAuth-only path; no Pub/Sub topic
      - Office 365 push — Azure app registration + Graph
        subscription
      - Office 365 Poll — OAuth-only path for tenants where Graph
        push isn't viable

    Anonymous access, same reasoning as /help/tasks — generic
    setup copy, no per-account state. Authenticated operators
    will follow links FROM /admin/integrations or /accounts/new;
    the page itself is reachable cold.
    """
    from email_triage.web.routers.ui import _render
    from email_triage.web.dependencies import get_current_user
    from email_triage.web.db_threadpool import db_call

    templates = get_templates(request)
    #  — get_current_user takes the DB write lock (verify_api_key
    # is @db_write); run it off the event-loop thread.
    user = await db_call(get_current_user, request)
    return await _render(
        templates, request, "help/integrations.html",
        {"user": user},
    )


# ---------------------------------------------------------------------------
#  — AI guide for user actions ("/help/me")
#
# State-aware "what do I do next?" explainer. Unlike /help/tasks (static,
# anonymous, generic), this is grounded in the signed-in user's OWN setup
# (account count, privacy mode, role) — so it requires login. It expands the
# shipped explain-this-error button from decoding errors into
# guiding actions. NOT an open-ended chat panel (a bounded, role-scoped,
# structural-state-only ask — see action_guide module docstring).
# ---------------------------------------------------------------------------

#: A few non-PHI starter prompts shown on the page. Plain user language.
_GUIDE_STARTERS = [
    "How do I connect my email account?",
    "How do I send all mail from one sender to a category?",
    "How do I set up an alert for important mail?",
    "How do I set up a daily digest?",
]


def _build_user_state(db, user: dict) -> dict:
    """Build a NON-PHI structural snapshot of the user's setup for the AI
    guide. Every field is defensive: a failed lookup omits that field
    rather than breaking the page (the guidance is fail-soft anyway). No
    account names, message contents, or email addresses — counts/booleans/
    role only."""
    state: dict = {}
    role = (user.get("role") or "").strip() if user else ""
    if role:
        state["role"] = role
    is_admin = role == "admin"

    # Accounts CONNECTED (admin → all; standard → owned + delegated).
    # N-109: a deactivated (creds-purged) account isn't "connected", so
    # active_only=True keeps this count honest (and consistent with the pickers).
    try:
        from email_triage.db.accounts import list_email_accounts
        accts = list_email_accounts(
            db, user_id=None if is_admin else user["id"], active_only=True,
        )
        state["accounts_connected"] = len(accts)
    except Exception:
        pass

    # Privacy (HIPAA) mode — global flag SSOT.
    try:
        from email_triage.triage_logging import is_hipaa_mode
        state["hipaa_mode"] = bool(is_hipaa_mode())
    except Exception:
        pass

    # Alerts (watches) — install-wide count is an admin-only surface; for a
    # standard user we omit it rather than scan per-account.
    if is_admin:
        try:
            from email_triage.web.email_watches import list_watches
            state["watches_count"] = len(list_watches(db, account_id=None))
        except Exception:
            pass

    return state


def _require_login(request: Request):
    from email_triage.web.dependencies import get_current_user
    user = get_current_user(request)
    return user


@router.get("/help/me", response_class=HTMLResponse)
async def help_me_page(request: Request):
    """Render the AI "Guide me" page. Login-gated (state-aware → needs a
    user); anonymous visitors bounce to /login."""
    from fastapi.responses import RedirectResponse
    from email_triage.web.routers.ui import _render
    from email_triage.web.db_threadpool import db_call

    templates = get_templates(request)
    db = request.app.state.db
    user = await db_call(_require_login, request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    state = await db_call(_build_user_state, db, user)
    return await _render(
        templates, request, "help/me.html",
        {"user": user, "guide_state": state, "starters": _GUIDE_STARTERS},
    )


@router.post("/help/me/ask", response_class=HTMLResponse)
async def help_me_ask(request: Request):
    """HTMX: take the user's question, build their state server-side, ask
    the AI, return an escaped guidance fragment. Login-gated; the state is
    NEVER trusted from the client (only an optional ``page`` hint is, and it
    is fenced). A §164.312(b) audit row is written — without the question
    text (user free-text could contain anything)."""
    from email_triage.web.db_threadpool import db_call

    db = request.app.state.db
    config = request.app.state.config
    secrets = getattr(request.app.state, "secrets", None)

    user = await db_call(_require_login, request)
    if user is None:
        return HTMLResponse("Please sign in to use the guide.", status_code=401)

    form = await request.form()
    question = (form.get("question") or "").strip()
    page_hint = (form.get("page") or "").strip() or None

    state = await db_call(_build_user_state, db, user)
    if page_hint:
        state["page"] = page_hint

    # Audit — record the consultation, NOT the question text (free-text may
    # carry anything). Mirrors the explain_error audit shape.
    def _guide_audit() -> None:
        from email_triage.web.db import record_auth_event
        role = state.get("role") or ""
        safe_audit_write(
            lambda: record_auth_event(
                db,
                event_type="help_me",
                email=user.get("email", ""),
                user_id=user.get("id"),
                outcome="success",
                detail=f"role={role}, q={'yes' if question else 'no'}",
            ),
            description="auth_event help_me",
        )

    await db_call(_guide_audit)

    from email_triage.web.action_guide import guide_user_action
    guidance = await guide_user_action(
        question=question or None,
        state=state,
        db=db,
        secrets=secrets,
        config=config,
    )

    from markupsafe import escape
    safe = escape(guidance)
    return HTMLResponse(
        '<div class="guide-answer" role="status" aria-label="AI guidance" '
        'style="margin:0.6rem 0;padding:0.8rem 1rem;'
        'background:var(--pico-card-background-color);border-radius:6px;'
        'border-left:3px solid var(--pico-primary);'
        'overflow-wrap:anywhere;white-space:pre-wrap;">'
        f'{safe}</div>'
    )
