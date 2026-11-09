"""Login-attempt rate limiting for the OTP / WebAuthn / dev-keypair surfaces.

the backlog . Counts recent ``auth_events`` failure rows by email
and by client IP within a sliding window; raises ``LoginLocked`` when
the running count tips over the configured threshold. Combined with
the existing ``web/ratelimit.py`` token bucket (which protects the
the outbound-webhook API, a different surface), the two together cover both
patient brute force (rotate codes against one email) and credential
stuffing (rotate emails behind one IP).

Design notes:

* No new schema. Rolling-window ``COUNT(*)`` against
  ``auth_events`` (which already records every credential-use
  attempt) is the source of truth. A successful login does not
  reset the window — it just falls outside it as time advances.
  Acceptable because the window is short (default 10 min) and a
  legitimate user typing the wrong code 10 times in 10 minutes is
  flagged for the same window length.

* No in-process state. The function is a pure SQLite read; safe
  for multi-process deployments and survives process restart.

* Failure-row writes happen at the call sites — this module
  doesn't know what surfaces look like. ``record_login_failure``
  is the canonical helper.

* ``check_login_allowed`` runs BEFORE the credential check. If
  the threshold has tipped, the actual credential is never
  evaluated — that's the point. Guards against timing-based
  enumeration (was this a real account? is this code valid?) by
  returning the same lockout response regardless of whether the
  email exists.

* ``record_login_lockout`` writes a separate ``login_lockout``
  audit row when the threshold trips, so an admin scanning
  ``auth_events`` can distinguish "user fat-fingered" from "we
  refused the request."

HIPAA §164.312(a)(2)(i) "Unique User Identification" — brute-force
protection is part of the access-control safeguard family. Lockout
events are auditable on the same ``auth_events`` trail as the
underlying failures.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any


class LoginLocked(Exception):
    """Raised by ``check_login_allowed`` when the threshold has tipped.

    ``scope`` ∈ {``"email"``, ``"ip"``} names which counter
    triggered. ``retry_after_secs`` is the configured window for
    that counter — a conservative wait that guarantees the count
    will have decayed below the threshold by the time the operator
    retries (it might decay sooner if oldest failures fall off
    earlier, but the operator-visible message is the worst case).
    """

    def __init__(self, scope: str, retry_after_secs: int):
        self.scope = scope
        self.retry_after_secs = retry_after_secs
        super().__init__(
            f"login_locked scope={scope} retry_after_secs={retry_after_secs}"
        )


def _auth_tunables(config: Any) -> dict[str, int]:
    """Pull the four  tunables off config.auth with safe defaults.

    Defaults match ``AuthConfig`` field defaults so an install that
    has never written its YAML (fresh dev install) still gets the
    protection.
    """
    auth = getattr(config, "auth", None)
    return {
        "per_email_max": int(getattr(auth, "login_per_email_max", 10)),
        "per_email_window_secs": int(getattr(
            auth, "login_per_email_window_secs", 600,
        )),
        "per_ip_max": int(getattr(auth, "login_per_ip_max", 30)),
        "per_ip_window_secs": int(getattr(
            auth, "login_per_ip_window_secs", 600,
        )),
    }


def _count_failures_since(
    db: sqlite3.Connection, *, column: str, value: str, since_iso: str,
) -> int:
    """Count auth_events failure rows for a given column / value since
    a cutoff timestamp. Includes the ``login_lockout`` rows themselves
    (a locked-out attacker who keeps probing should stay locked).
    """
    # Only LOGIN event types (``login_<surface>`` and ``login_lockout``) count toward a
    # lockout. Without the filter any ``outcome='failure'`` row counted: an admin's
    # failed or in-flight-rejected embedding-update click (``embedding_runtime_update``)
    # moved that admin toward a login lockout (panel T db NOTE).
    return int(db.execute(
        f"SELECT COUNT(*) FROM auth_events "
        f"WHERE {column} = ? AND outcome = 'failure' "
        f"AND event_type LIKE ? ESCAPE '\\' AND ts >= ?",
        (value, _LOCKOUT_EVENT_LIKE, since_iso),
    ).fetchone()[0])


#: Only failure rows whose ``event_type`` starts with this prefix count toward a lockout
#: (``login_<surface>``, ``login_lockout``). That makes the NAME a security control: a
#: login surface writing its failures under another name would silently stop counting.
#: Every login-surface failure writer is pinned to it by
#: ``tests/test_lockout_event_prefix_pin.py`` (panel T db S-R2-A2).
LOCKOUT_EVENT_PREFIX = "login_"
_LOCKOUT_EVENT_LIKE = LOCKOUT_EVENT_PREFIX.replace("_", "\\_") + "%"


def check_login_allowed(
    db: sqlite3.Connection,
    *,
    email: str | None,
    ip: str | None,
    config: Any,
    now: datetime | None = None,
) -> None:
    """Raise ``LoginLocked`` when the guard threshold has tipped.

    Both per-email and per-ip counters are evaluated; the first one
    over its limit raises. ``email=None`` skips the email check
    (passkey discoverable-credential flow doesn't supply email
    upfront — only the IP guard applies). ``ip=None`` skips the IP
    check (rare; e.g. tests with no client info).

    A ``*_max`` of 0 disables the corresponding scope. ``now`` is
    test-injectable; otherwise UTC clock.
    """
    tun = _auth_tunables(config)
    now = now or datetime.now(timezone.utc)
    # N-203 R22 (2026-07-02): route through A10 stored-ISO SSOT.
    from email_triage._isotime import to_utc_iso

    if email and tun["per_email_max"] > 0:
        cutoff = (now - timedelta(seconds=tun["per_email_window_secs"]))
        # N-253 R25: canonical-email SSOT keeps the rate-limit key
        # stable across display-name / bare envelope shapes.
        from email_triage.mail_headers import canonical_email
        count = _count_failures_since(
            db,
            column="email",
            value=canonical_email(email),
            since_iso=to_utc_iso(cutoff),
        )
        if count >= tun["per_email_max"]:
            raise LoginLocked(
                scope="email",
                retry_after_secs=tun["per_email_window_secs"],
            )

    if ip and tun["per_ip_max"] > 0:
        cutoff = (now - timedelta(seconds=tun["per_ip_window_secs"]))
        count = _count_failures_since(
            db, column="ip", value=ip, since_iso=to_utc_iso(cutoff),
        )
        if count >= tun["per_ip_max"]:
            raise LoginLocked(
                scope="ip",
                retry_after_secs=tun["per_ip_window_secs"],
            )


def record_login_failure(
    db: sqlite3.Connection,
    *,
    surface: str,
    email: str | None,
    ip: str | None,
    user_agent: str | None,
    reason: str,
    user_id: int | None = None,
    key_id: int | None = None,
) -> None:
    """Best-effort: write an ``auth_events`` failure row for a login attempt
    and increment the ``et_auth_attempts_total`` Prometheus counter on the
    failure edge.

    ``surface`` ∈ {``otp``, ``webauthn``, ``passkey``,
    ``dev_keypair``, ``otp_request``, ``recovery_code``}. NOTE:
    ``operator_recovery`` (single-use operator-issued tokens) routes its
    FAILURE edge through ``record_auth_event(outcome="denied:…")`` DIRECTLY,
    not this funnel — so it is intentionally absent from this list and from
    the ``et_auth_attempts_total`` failure metric (different threat model;
    a one-shot operator-bootstrap token, not a brute-forceable login surface).
    Do not add it here without re-considering that. ``reason``
    is a short slug (``invalid_code``, ``expired_code``, ``key_revoked``,
    ``signature_invalid``, ``account_disabled``,
    ``email_not_in_allowlist``, ``no_active_challenge``) that lands in the
    ``detail`` column for forensic review. ``no_active_challenge`` (punch )
    is a passkey handle whose single-use server-side row is gone -- a REPLAY or
    an expiry, which the row cannot tell apart. NEVER surface ``reason`` back to
    the caller — it would expose a side-channel (account exists vs.
    code wrong).

    The ``et_auth_attempts_total`` counter was previously incremented
    ONLY on the success edge (inside each login handler), leaving
    ``/metrics`` blind to the failure edge — no brute-force or lockout
    signal. The failure increment is co-located here (the canonical
    failure funnel, shared by all login surfaces) so every
    ``record_login_failure`` call site gets it automatically without
    per-surface duplication. Mirrors the success-edge label vocabulary
    (``surface=<surface> outcome="failure"``).

    Audit-write failures are swallowed: the running auth flow has
    already rejected the request, and a missing audit row is a
    degraded-but-not-broken condition. The ``audit_failures``
    counter on ``/health`` would be the right place to flag drift.
    """
    # FIX B — failure-edge metric increment (PD#18 observability companion).
    # Swallowed independently so a metrics failure cannot block the audit write.
    try:
        from email_triage import metrics as _metrics
        _metrics.counter(
            "et_auth_attempts_total",
            "Login attempts by surface and outcome.",
        ).inc(surface=surface, outcome="failure")
    except Exception:
        pass

    from email_triage.web._audit import safe_audit_write
    from email_triage.web.db import record_auth_event
    safe_audit_write(
        lambda: record_auth_event(
            db,
            event_type=f"login_{surface}",
            email=email or "",
            user_id=user_id,
            key_id=key_id,
            ip=ip,
            user_agent=user_agent,
            outcome="failure",
            detail=reason,
        ),
        description=f"login_{surface}",
    )


def record_login_success(*, surface: str) -> None:
    """Best-effort: increment ``et_auth_attempts_total{surface, outcome="success"}``
    on the SUCCESS edge of a login surface — the success-metric twin of
    ``record_login_failure``'s failure-edge increment.

    ``surface`` ∈ {``otp``, ``webauthn``, ``passkey``, ``dev_keypair``,
    ``recovery_code``}. NOTE the two deliberate ABSENCES, symmetric with
    ``record_login_failure``: ``otp_request`` has a failure edge (rate-limit)
    but NO success edge (requesting an OTP is not a successful login), and
    ``operator_recovery`` is excluded from ``et_auth_attempts_total`` entirely
    (different threat model — see ``record_login_failure``'s docstring).

    Co-located here (the canonical success-metric funnel) so every login
    surface increments it IDENTICALLY. Previously each handler hand-rolled the
    same ``metrics_mod.counter(...).inc(surface=…, outcome="success")`` block,
    and the ``recovery_code`` surface MISSED it entirely — its success was
    never counted while its failure was (the exact PD#5 duplication-drift that
    a single funnel prevents).

    This funnel owns ONLY the metric. The success AUDIT row
    (``record_auth_event(event_type="login_<surface>", outcome="success")``) is
    the ``last_login`` terminus (FIX C): it lives INSIDE each surface's
    ``db_call`` closure, transactional with ``update_last_login``, carries
    surface-specific ``key_id``/``user_id``, and is pinned separately by
    ``test_last_login_terminus_pin``. Do NOT fold it here — that would pull a
    transactional write out of its closure.

    Metric failures are swallowed (a missing metric is degraded-not-broken).
    """
    try:
        from email_triage import metrics as _metrics
        _metrics.counter(
            "et_auth_attempts_total",
            "Login attempts by surface and outcome.",
        ).inc(surface=surface, outcome="success")
    except Exception:
        pass


def record_login_lockout(
    db: sqlite3.Connection,
    *,
    surface: str,
    email: str | None,
    ip: str | None,
    user_agent: str | None,
    scope: str,
    threshold: int,
) -> None:
    """Best-effort: write a ``login_lockout`` audit row and increment the
    ``et_auth_attempts_total`` counter on the failure edge.

    Distinct event_type so an admin scanning ``auth_events`` can
    separate "user fat-fingered" from "guard tripped." ``scope``
    + ``threshold`` land in ``detail`` so a forensic reader can
    reconstruct which counter fired.

    The metric increment uses ``outcome="lockout"`` (distinct from
    ``"failure"``) so the operator can separately observe the rate of
    individual bad-credential attempts versus rate-limiter trips — the
    two together give a brute-force signal; lockout alone signals the
    guard is actively defending.
    """
    # FIX B — lockout-edge metric increment.  Swallowed so a metrics
    # failure cannot block the audit write.
    try:
        from email_triage import metrics as _metrics
        _metrics.counter(
            "et_auth_attempts_total",
            "Login attempts by surface and outcome.",
        ).inc(surface=surface, outcome="lockout")
    except Exception:
        pass

    from email_triage.web._audit import safe_audit_write
    from email_triage.web.db import record_auth_event
    safe_audit_write(
        lambda: record_auth_event(
            db,
            event_type="login_lockout",
            email=email or "",
            user_id=None,
            key_id=None,
            ip=ip,
            user_agent=user_agent,
            outcome="failure",
            detail=f"surface={surface} scope={scope} threshold={threshold}",
        ),
        description="login_lockout",
    )
