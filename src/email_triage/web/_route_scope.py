"""Punch  — the route-scope / principal-fence SSOT.

Two independent fences on what a resolved principal may reach, both evaluated at
the ONE seam where a principal comes into existence
(:func:`email_triage.web.dependencies.get_current_user`):

**(D) the CREDENTIAL fence — ``api_keys.scope``.** An api key authenticates a
PRINCIPAL, not a route, so before this a key minted "for ``GET /health/build``" was
accepted by every Bearer-authenticated route in the app. What bounded the cve-arc
monitoring key was that its user owned zero accounts and every PHI path intersects
the requester's manageable set — least privilege by OWNERSHIP (a property of
today's rows) rather than by SCOPE (a property of the credential). Attach one
account to that principal for any reason and the credential silently becomes
PHI-capable with nothing in code, tests or audit objecting. ``scope`` makes the
bound a property of the credential, which no later data edit can widen.

**(E) the PRINCIPAL fence — the ``health_ro`` role.** A read-only monitoring role
that may reach only :data:`HEALTH_RO_ALLOWED_ROUTES` and may never hold a web
session. Independent of (D): either fence alone bounds the credential, and neither
depends on the principal owning no data.

WHY THIS IS NOT A FASTAPI DEPENDENCY OR A PER-ROUTE DECORATOR
=============================================================
The 2026-09-29 route census walked the live route table: of **310** unique
``(method, path)`` routes, **129** carry NO auth dependency in their signature —
they resolve the principal *inside the handler body*
(``require_admin_ui(request)`` / ``get_current_user(request)`` /
``await db_call(_get_current_user, request)``). That set includes the entire
``/api/v1/*`` agent surface — e.g. ``GET /api/v1/accounts/{account_id}/messages/{message_id}``,
a PHI read — and ``GET /health/detail``.

So a fence written as a ``Depends(...)``, or wrapped around ``require_auth`` /
``OwnedAccount``, would be blind to 129 of 310 routes *including the PHI-bearing
ones*. ``get_current_user`` is the only seam BOTH shapes share, and the
bearer-resolution chain below it is single-caller at every hop
(``get_current_user`` → ``_check_bearer_token`` → ``verify_api_key``, one caller
each, and ``auth.py``'s ``WHERE ak.key_hash = ?`` is the only lookup-by-hash in
``src/``). Enforcing there means **a route added next year inherits the fence
without its author knowing this feature exists** — the PD#2 interprocedural
property, held by construction rather than by remembering. That single-caller chain
is asserted structurally by ``tests/test_n535_route_scope_pin.py``.

FAIL CLOSED (PD#8)
==================
A scope is a POSITIVE grant, the inverse of a breaker that only subtracts
permission — so every ambiguity resolves to "grants nothing":

* unparseable JSON, a JSON ``null``, a non-list, or any non-string member →
  grants NOTHING (not "full authority").
* an empty list ``[]`` → grants nothing (an operator can mint a deliberately
  inert key).
* ``NULL`` / absent / empty-string column → **unscoped**, i.e. exactly today's
  full-principal behaviour. This is the ONE widening read, and it is what makes
  the migration meaning-preserving for every key minted before .

EXACT MATCH ONLY — NO GLOBS
===========================
A scope entry is the literal string ``"<METHOD> <path>"``. Globs are deliberately
absent: ``"GET /health/*"`` would re-admit ``/health/detail``, which is the exact
body the 2026-06-13 two-token NO-GO review protects (``30b503ad``). Consequences,
stated rather than discovered later:

* A **parametrized** route cannot be scoped — ``"GET /api/v1/accounts/{id}"`` never
  matches a real request path. Scopes are for fixed monitoring endpoints.
* Starlette auto-adds ``HEAD`` to any ``GET`` route, so a scope of
  ``"GET /health/build"`` REFUSES ``HEAD /health/build``. Fail-closed and
  intentional; a monitor that needs HEAD scopes HEAD explicitly.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from email_triage.db._helpers import load_json_col
from email_triage.engine.models import UserRole
from email_triage.triage_logging import get_logger

log = get_logger("web.route_scope")

# --------------------------------------------------------------------------
# (E) the health_ro allowlist SSOT
# --------------------------------------------------------------------------

#: The ONLY routes a ``health_ro`` principal may reach. Every other route in the
#: app — ``/health/detail``, ``/ops/*``, every UI page and every API endpoint — is
#: refused at the seam.
#:
#: ``GET /health`` is unauthenticated today (``routers/health.py`` never resolves a
#: principal there), so its presence is a declared contract rather than a grant.
#: ``GET /health/runtime-deps`` does not exist yet — it is punch , on another
#: branch; the path is allow-listed now so the two land in either order.
#:
#: This is a hand-written allowlist ON PURPOSE (contrast R1's ban on hardcoded
#: lists as a pin's PRIMARY catch): it is the SPECIFICATION of least privilege, not
#: a census of sites. The count-agnostic property-scan that guards it walks the
#: whole route table and asserts the COMPLEMENT is unreachable, so adding a route
#: to the app can never silently widen this set.
HEALTH_RO_ALLOWED_ROUTES: frozenset[str] = frozenset({
    "GET /health",
    "GET /health/build",
    "GET /health/runtime-deps",
})

#: Roles that may NEVER hold a web session. Enforced at the one session-minting
#: funnel (``auth.create_session_token``) so all four login surfaces — OTP,
#: WebAuthn, passkey/recovery, admin dev-keypair — are covered at one site, and
#: re-checked on the cookie READ path in ``get_current_user`` (both edges of one
#: predicate, per R42).
API_ONLY_ROLES: frozenset[str] = frozenset({UserRole.HEALTH_RO.value})

#: Roles whose reachable route set is an explicit allowlist. Maps role → allowlist.
#: A role absent from this map is NOT route-restricted (its authority is decided by
#: the ordinary role predicates: ``is_admin``, ``can_manage_account``, …).
ROLE_ROUTE_ALLOWLISTS: dict[str, frozenset[str]] = {
    UserRole.HEALTH_RO.value: HEALTH_RO_ALLOWED_ROUTES,
}


class ScopeRefused(PermissionError):
    """A resolved principal may not reach THIS route.

    Carries the machine-readable ``reason`` so the seam can log one WARNING and
    the caller can map it to a 403 without re-deriving which fence tripped.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class SessionMintRefused(PermissionError):
    """An :data:`API_ONLY_ROLES` principal tried to mint a web session.

    Raised by ``auth.create_session_token``. ``web/app.py`` registers a handler
    that turns it into a 403 so the operator sees a refusal rather than a stack
    trace — the refusal is a POLICY answer, not a crash.
    """


# --------------------------------------------------------------------------
# canonical route key
# --------------------------------------------------------------------------

def route_key(method: str, path: str) -> str:
    """The canonical ``"<METHOD> <path>"`` scope key.

    ONE spelling, used by the parser, the matcher, the CLI validator and the
    pins — so a scope written by ``apikey create`` and a scope matched at request
    time cannot drift in normalization. Method upper-cased; path keeps its leading
    slash and loses a trailing one (``/health/build/`` → ``/health/build``) except
    for the root path.
    """
    m = (method or "").strip().upper()
    p = (path or "").strip()
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/") or "/"
    return f"{m} {p}"


def validate_scope_entry(entry: str) -> str:
    """Normalize one operator-supplied scope entry, or raise ``ValueError``.

    Called at MINT time (the CLI) so a typo is refused loudly with the key never
    created — rather than silently producing a credential that reaches nothing and
    a monitor that 403s in production. The request-time matcher does NOT call this:
    at request time a malformed stored entry must simply grant nothing, never raise
    into a handler.
    """
    raw = (entry or "").strip()
    if not raw:
        raise ValueError("empty scope entry")
    parts = raw.split()
    if len(parts) != 2:
        raise ValueError(
            f"scope entry must be exactly '<METHOD> </path>': {entry!r}"
        )
    method, path = parts
    if not method.isalpha():
        raise ValueError(f"scope method must be alphabetic: {method!r}")
    if not path.startswith("/"):
        raise ValueError(f"scope path must start with '/': {path!r}")
    return route_key(method, path)


# --------------------------------------------------------------------------
# (D) the credential fence
# --------------------------------------------------------------------------

def parse_key_scope(raw: Any) -> frozenset[str] | None:
    """Decode the stored ``api_keys.scope`` column.

    Returns:
        ``None`` when the key is **unscoped** (NULL / absent / empty string) —
        full-principal authority, i.e. pre-#420 behaviour.
        A ``frozenset`` of canonical route keys otherwise. The set may be EMPTY,
        which grants nothing.

    Fail-closed (PD#8): a corrupt, ``null``, non-list or mixed-type value decodes
    to the EMPTY set (grants nothing), never to ``None`` (which would silently
    restore full authority to a credential whose fence became unreadable).

    The decode goes through the ``load_json_col`` SSOT (R43) with
    ``default=[]`` — note the default's TYPE is load-bearing: that helper returns
    the default whenever the decoded value's type does not match the default's, so
    ``default=None`` would swallow every VALID list.
    """
    if raw is None:
        return None
    if isinstance(raw, str) and not raw.strip():
        return None
    entries = load_json_col(raw, default=[], label="api_keys.scope")
    if not isinstance(entries, list):
        return frozenset()
    if not all(isinstance(e, str) for e in entries):
        # A mixed list is corruption, not a partial grant.
        return frozenset()
    out: set[str] = set()
    for entry in entries:
        try:
            out.add(validate_scope_entry(entry))
        except ValueError:
            # ONE malformed member invalidates the WHOLE scope. Dropping the bad
            # entry and honouring the rest would be a partial grant derived from
            # corrupt data — the caller cannot know what the operator meant, so
            # the answer is "nothing" (PD#8).
            return frozenset()
    return frozenset(out)


def scope_permits(scope: frozenset[str] | None, method: str, path: str) -> bool:
    """Does ``scope`` admit ``method path``? ``None`` (unscoped) admits everything."""
    if scope is None:
        return True
    return route_key(method, path) in scope


# --------------------------------------------------------------------------
# (E) the principal fence
# --------------------------------------------------------------------------

def role_may_hold_web_session(role: Any) -> bool:
    """False for an :data:`API_ONLY_ROLES` role. Fail-closed on a non-string."""
    if not isinstance(role, str):
        return True  # unknown shape is handled by the ordinary role predicates
    return role not in API_ONLY_ROLES


def role_route_allowed(role: Any, method: str, path: str) -> bool:
    """Does ``role``'s allowlist admit ``method path``?

    A role with no allowlist entry is unrestricted HERE (its authority is decided
    by ``is_admin`` / ``can_manage_account`` / ``require_role`` as before) — this
    fence only ever SUBTRACTS, so it can never widen an existing role.

    Exception (db-sme r14 SHOULD 2): an ``API_ONLY_ROLES`` role with no
    allowlist entry is REFUSED, not unrestricted -- a missing entry for a
    fenced role must fail closed (PD#8).
    """
    if not isinstance(role, str):
        return True
    allowed = ROLE_ROUTE_ALLOWLISTS.get(role)
    if allowed is None:
        return role not in API_ONLY_ROLES
    return route_key(method, path) in allowed


# --------------------------------------------------------------------------
# bounded refusal audit (punch  item 6)
# --------------------------------------------------------------------------

#: One window per source (a client address for an unknown key, a key id for a
#: scope refusal). Inside a window the first ``REFUSAL_AUDIT_MAX_PER_WINDOW``
#: refusals are each recorded; the next one is recorded ONCE as a "capped" row
#: that says further refusals from the source are not written; the rest write
#: nothing. Every refusal that writes nothing is COUNTED (``suppressed``): the
#: count rides on the source's next audit row, or, when the source never comes
#: back, on ONE WARNING when the expired window is swept. So the loss and its
#: volume are on the record, and the write rate onto the serialized SQLite
#: writer is bounded by (sources x cap) per window.
REFUSAL_AUDIT_WINDOW_S: float = 60.0
REFUSAL_AUDIT_MAX_PER_WINDOW: int = 20
#: Hard bound on tracked ``unknown_key:*`` sources, the overflow slot included.
#: Only that class is attacker-mintable (a client address costs nothing to
#: rotate), so only it is bounded: past the bound a NEW unknown-key source is
#: folded into :data:`REFUSAL_AUDIT_OVERFLOW_SOURCE`, which writes ONE row per
#: window (its cap notice) and counts the rest. The table cannot grow, and
#: nothing is dropped without a count.
REFUSAL_AUDIT_MAX_SOURCES: int = 1024
#: The ONE shared source the unknown-key sources past the table bound fall into.
REFUSAL_AUDIT_OVERFLOW_SOURCE: str = "unknown_key:*overflow"
#: Sources only a RESOLVED principal can mint (``key:<api_key_id>``,
#: ``user:<user_id>``): they are bounded by real rows, so an attacker cannot
#: grow them and they are never subject to the table bound. A flood of rotated
#: unknown-key addresses must not blind the record of an authenticated
#: principal's off-scope use (the stronger signal, design 420 item 6). They keep
#: the per-source window cap.
REFUSAL_AUDIT_PRINCIPAL_PREFIXES: tuple[str, ...] = ("key:", "user:")

_refusal_audit_lock = threading.Lock()
# source -> [window_start, count, suppressed]. ``suppressed`` is the number of
# refusals this window wrote nothing for.
_refusal_audit_state: dict[str, list[float]] = {}        # unknown_key:* + the overflow; bounded
_refusal_audit_principals: dict[str, list[float]] = {}   # key:* / user:*; not table-capped
_refusal_audit_last_sweep: float | None = None


@dataclass(frozen=True)
class RefusalAuditVerdict:
    """What :func:`refusal_audit_verdict` decided for one refusal.

    ``decision`` is ``"emit"``, ``"capped"`` or ``"skip"``. ``source`` is the
    source the refusal was charged to: the caller's, or
    :data:`REFUSAL_AUDIT_OVERFLOW_SOURCE` when the table was full.
    ``suppressed`` is the number of refusals the PREVIOUS window of this source
    wrote nothing for; the caller puts it on the row it writes now.
    """

    decision: str
    source: str
    suppressed: int = 0


def _live_entry(
    table: dict[str, list[float]], source: str, t: float,
) -> tuple[list[float] | None, int]:
    """``(entry, 0)`` while the source's window is open. An expired entry is
    removed and ``(None, its suppressed count)`` returned, so the count is not lost."""
    entry = table.get(source)
    if entry is None:
        return None, 0
    if t - entry[0] >= REFUSAL_AUDIT_WINDOW_S:
        del table[source]
        return None, int(entry[2])
    return entry, 0


def _sweep_expired(table: dict[str, list[float]], t: float) -> tuple[int, int]:
    """Drop every expired window from ``table``. Returns ``(sources, suppressed)``
    for the dropped windows that still held an unreported suppressed count."""
    stale = [k for k, v in table.items() if t - v[0] >= REFUSAL_AUDIT_WINDOW_S]
    sources = suppressed = 0
    for key in stale:
        n = int(table.pop(key)[2])
        if n:
            sources += 1
            suppressed += n
    return sources, suppressed


def refusal_audit_verdict(source: str, *, now: float | None = None) -> RefusalAuditVerdict:
    """Decide one refusal: record it, record the cap notice, or write nothing
    (and COUNT it). The one funnel for the bounded refusal audit.

    Fail-quiet on the WRITE side only: the refusal itself is never affected by
    this decision, it only bounds how many audit rows a refusal stream can cost.
    """
    global _refusal_audit_last_sweep
    t = time.monotonic() if now is None else now
    swept = [0, 0]
    with _refusal_audit_lock:
        principal = source.startswith(REFUSAL_AUDIT_PRINCIPAL_PREFIXES)
        table = _refusal_audit_principals if principal else _refusal_audit_state
        entry, carried = _live_entry(table, source, t)
        if entry is None and not principal and source != REFUSAL_AUDIT_OVERFLOW_SOURCE:
            # The last slot is the overflow's, so a full table can always take it.
            if len(table) >= REFUSAL_AUDIT_MAX_SOURCES - 1:
                n_sources, n_suppressed = _sweep_expired(table, t)
                swept[0] += n_sources
                swept[1] += n_suppressed
            if len(table) >= REFUSAL_AUDIT_MAX_SOURCES - 1:
                # Re-routed: the overflow now owes this source's own expired
                # count too, so ADD it, never overwrite it (DA re-attest R1).
                source = REFUSAL_AUDIT_OVERFLOW_SOURCE
                entry, overflow_carried = _live_entry(table, source, t)
                carried += overflow_carried
        if entry is None and source == REFUSAL_AUDIT_OVERFLOW_SOURCE:
            # The shared overflow writes ONE row per window: the cap notice, at
            # once. Its many sources would otherwise buy 20 more rows apiece.
            table[source] = [t, REFUSAL_AUDIT_MAX_PER_WINDOW + 1.0, 0.0]
            verdict = RefusalAuditVerdict("capped", source, carried)
        elif entry is None:
            table[source] = [t, 1.0, 0.0]
            verdict = RefusalAuditVerdict("emit", source, carried)
        else:
            # ``carried`` is non-zero here only for a source re-routed onto a live
            # overflow; a row written now carries it, a skip adds it to the count.
            entry[1] += 1.0
            if entry[1] <= REFUSAL_AUDIT_MAX_PER_WINDOW:
                verdict = RefusalAuditVerdict("emit", source, carried)
            elif entry[1] == REFUSAL_AUDIT_MAX_PER_WINDOW + 1:
                verdict = RefusalAuditVerdict("capped", source, carried)
            else:
                entry[2] += 1.0 + carried
                verdict = RefusalAuditVerdict("skip", source)
        # One sweep per window, AFTER this refusal's own source took its carried
        # count above, so an expired window whose source never came back still
        # has its suppressed count reported (below, once).
        if _refusal_audit_last_sweep is None:
            _refusal_audit_last_sweep = t
        elif t - _refusal_audit_last_sweep >= REFUSAL_AUDIT_WINDOW_S:
            _refusal_audit_last_sweep = t
            for swept_table in (_refusal_audit_state, _refusal_audit_principals):
                n_sources, n_suppressed = _sweep_expired(swept_table, t)
                swept[0] += n_sources
                swept[1] += n_suppressed
    if swept[1]:
        log.warning(
            "refusal audit: refusals from expired windows wrote no row",
            sources=swept[0],
            suppressed=swept[1],
        )
    return verdict


def refusal_audit_decision(source: str, *, now: float | None = None) -> str:
    """``"emit"`` (record this refusal), ``"capped"`` (record the one cap-notice
    row for this window) or ``"skip"`` (write nothing, counted). The decision half
    of :func:`refusal_audit_verdict`, for callers that need no carried count."""
    return refusal_audit_verdict(source, now=now).decision


def reset_refusal_audit_state() -> None:
    """Test hook: forget every window."""
    global _refusal_audit_last_sweep
    with _refusal_audit_lock:
        _refusal_audit_state.clear()
        _refusal_audit_principals.clear()
        _refusal_audit_last_sweep = None


# --------------------------------------------------------------------------
# the seam
# --------------------------------------------------------------------------

def _log_route(request: Any) -> str:
    """The ROUTE TEMPLATE for a log line, never the raw path.

    ``/api/v1/accounts/1/messages/<id>`` embeds a message id; the template
    ``/api/v1/accounts/{account_id}/messages/{message_id}`` does not. R30 — a
    diagnostic log carries the shape, not the identifiers.
    """
    try:
        return getattr(request.scope.get("route"), "path", "") or "<unrouted>"
    except Exception:       # pragma: no cover - a bare scope in a unit test
        return "<unrouted>"


def refusal_route_label(request: Any) -> str:
    """``"<METHOD> <route template>"`` for an audit row's ``detail`` — the shape,
    never the raw path (R30: a path can embed a message id or an address)."""
    return f"{getattr(request, 'method', '') or ''} {_log_route(request)}"


def check_principal_fences(request: Any, user: dict[str, Any]) -> None:
    """Raise :class:`ScopeRefused` if ``user`` may not reach this request's route.

    Called from ``get_current_user`` for a principal resolved by EITHER auth
    method, so both fences cover both paths. Silent (no raise) for an unscoped key
    held by an unrestricted role — the overwhelmingly common case — so the hot path
    pays two frozenset lookups and nothing else.

    Refusals are LOGGED (one WARNING) here; the seam
    (``dependencies._fence_or_403``) additionally records each one through the
    ``record_auth_event`` emitter SSOT, so a scoped credential used off-scope is
    observable in the chained ``auth_events`` table (design 420 item 6: a refusal
    is a more interesting signal than a bad key). The refusal rate is controlled
    by whoever holds the token, so the audit INSERT is BOUNDED by
    :func:`refusal_audit_decision` (a per-source window cap): a token holder
    cannot drive unbounded writes onto the single serialized SQLite writer.
    """
    method = getattr(request, "method", "") or ""
    path = ""
    try:
        path = request.url.path or ""
    except Exception:       # pragma: no cover
        path = ""

    role = user.get("role")

    # (E) principal fence — the role's route allowlist.
    if not role_route_allowed(role, method, path):
        log.warning(
            "route refused: role allowlist",
            role=role if isinstance(role, str) else "<non-string>",
            method=method,
            route=_log_route(request),
            user_id=user.get("id"),
        )
        raise ScopeRefused("role_not_allowed_on_route")

    # (E) principal fence — an API-only role may not ride a cookie session.
    if user.get("auth_method") != "api_key" and not role_may_hold_web_session(role):
        log.warning(
            "route refused: api-only role presented a web session",
            role=role if isinstance(role, str) else "<non-string>",
            method=method,
            route=_log_route(request),
            user_id=user.get("id"),
        )
        raise ScopeRefused("api_only_role_web_session")

    # (D) credential fence — the key's own route scope.
    if user.get("auth_method") != "api_key":
        return
    scope = parse_key_scope(user.get("api_key_scope"))
    if scope_permits(scope, method, path):
        return
    log.warning(
        "route refused: api key out of scope",
        key_name=user.get("key_name"),
        api_key_id=user.get("api_key_id"),
        method=method,
        route=_log_route(request),
        scope_entries=len(scope) if scope is not None else -1,
    )
    raise ScopeRefused("api_key_out_of_scope")
