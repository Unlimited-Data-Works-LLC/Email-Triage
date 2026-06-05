"""Best-effort audit-row writing.

An audit / access-event row is forensic metadata: losing one must never
break the request or auth flow that triggered it — but a failure
swallowed with no trace is invisible drift. :func:`safe_audit_write` is
the single home for that "run it, never raise, log on failure" policy.

Before this it was hand-rolled at five call sites (``auth.py`` ×2,
``login_guard.py`` ×2, ``csrf.py``) with two inconsistent failure
dispositions — ``auth.py`` logged a WARNING, the other three silently
``pass``-ed. The silent ``pass`` was the wrong half of that split: the
``login_guard`` / ``csrf`` comments both noted the failure *should* be
visible via /health's audit-failure drift counter but had no mechanism.
A WARNING log line is that mechanism, so this helper standardises all
five on log-on-failure.
"""

from __future__ import annotations

from typing import Any, Callable

from email_triage.triage_logging import get_logger

log = get_logger("web.audit")


def safe_audit_write(write: Callable[[], Any], *, description: str) -> None:
    """Run a best-effort audit-table write; never let a failure escape.

    Parameters
    ----------
    write:
        A zero-argument callable that performs the actual insert —
        typically ``lambda: record_*_event(...)``. It is invoked
        synchronously; any exception it raises is caught here.
    description:
        A short human tag for the failure log line, e.g.
        ``"api_key_created key_id=42"`` or ``"login_web"``.

    A failure is logged at WARNING (so a /health audit-failure drift
    check can see it) and swallowed — it never propagates to the caller.
    """
    try:
        write()
    except Exception as exc:
        log.warning(
            "audit_write_failed",
            audit=description,
            error=str(exc),
        )
