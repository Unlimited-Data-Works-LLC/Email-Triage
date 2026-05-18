"""Help / how-to runbook surface (#128).

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

    templates = get_templates(request)
    user = get_current_user(request)
    return _render(
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

    templates = get_templates(request)
    user = get_current_user(request)
    return _render(
        templates, request, "help/integrations.html",
        {"user": user},
    )
