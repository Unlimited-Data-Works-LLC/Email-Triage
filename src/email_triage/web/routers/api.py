"""JSON REST API endpoints.

Mirror the web UI operations for programmatic access (webhook clients, scripts).
All endpoints return JSON.  Auth: session cookie or Bearer API key.
"""

from __future__ import annotations

from email_triage._int_utils import parse_int_or_none  # N-219c/13 R23
from email_triage._isotime import now_utc_iso

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from email_triage.engine.models import UserRole
from email_triage.web.app import get_config, get_db
from email_triage.web.db import (
    get_categories_dict,
    get_category as get_category_db,
    create_category as create_category_db,
    update_category as update_category_db,
    delete_category as delete_category_db,
)
from email_triage.web.db_threadpool import db_call
from email_triage._secret_keys import SESSION_SECRET_KEY  # N-231 R22 stored-secret-key SSOT
from email_triage.web.auth import (
    delete_api_key,
    generate_api_key,
    get_user_by_email,
    hash_api_key,
    list_api_keys,
    store_api_key,
)
from email_triage.web.dependencies import assert_admin, get_current_user, is_admin  # N-222e R22
from email_triage.web._list_authz import (
    is_list_deletable_by,
    is_list_readable_by,
    is_list_writable_by,
    may_manage_global_lists,
)
from email_triage.web.error_surface import (  #  tranche 4 R32
    api_error_response,
    raise_api_error,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class UserCreate(BaseModel):
    email: str
    name: str
    role: str = "user"
    notify_email: str | None = None


class UserUpdate(BaseModel):
    name: str | None = None
    role: str | None = None
    notify_email: str | None = None


# ---------------------------------------------------------------------------
# Auth check helper
# ---------------------------------------------------------------------------

def _require_auth(request: Request) -> dict:
    user = get_current_user(request)
    if user is None:
        raise raise_api_error("Not authenticated", status_code=401, purpose="misc")
    return user


def _require_admin(request: Request) -> dict:
    # Sync-to-sync call: _require_admin is itself dispatched via
    # db_call by its async callers, so this inner _require_auth runs
    # off-loop under the write lock already — no db_call hop here.
    user = _require_auth(request)
    assert_admin(user)  # role-gate SSOT (raise-twin of admin_gate_response)
    return user


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@router.get("/metrics")
async def api_metrics(request: Request):
    """Prometheus text-format metrics export.

    PR 10 / E. Admin-token gated to avoid leaking traffic patterns
    (counters per provider / category) to unauthenticated callers.
    Same gate that ``/logs`` uses.

    Pulls live counters from app.state where applicable
    (audit_failures, csrf_rejects) and the in-process registry
    (everything else). Returns the text format directly with the
    standard ``text/plain; version=0.0.4`` content type.
    """
    # Admin-gated (same gate as /logs): route through _require_admin so the
    # 403 contract matches the other admin API routes (was a divergent inline
    # PlainTextResponse — census run12 #1 API straggler).
    await db_call(_require_admin, request)

    # Pull live counters off app.state so they show up in the
    # rendered output without requiring every read site to also
    # bump a registry counter.
    from email_triage import metrics as metrics_mod
    audit_failures = int(getattr(request.app.state, "audit_failures", 0))
    csrf_rejects = int(getattr(request.app.state, "csrf_rejects", 0))
    metrics_mod.counter(
        "et_audit_failures_total",
        "Audit-write failures (PR 1 / A2 fail-fast counter).",
    ).inc(amount=max(
        0,
        audit_failures - metrics_mod.counter(
            "et_audit_failures_total"
        ).value(),
    ))
    metrics_mod.counter(
        "et_csrf_rejects_total",
        "CSRF token validation failures (PR 8 / D1 counter).",
    ).inc(amount=max(
        0,
        csrf_rejects - metrics_mod.counter(
            "et_csrf_rejects_total"
        ).value(),
    ))

    # run17 #9 — bridge the webhook security counters into /metrics. The Gmail
    # Pub/Sub + MS Graph receivers bump ``app.state.metrics[<key>]`` (keys like
    # ``gmail_push.auth_failed`` / ``office365_push.client_state_mismatch``),
    # which until now lived ONLY in that parallel app.state dict + the
    # /admin/stats rollup — INVISIBLE to Prometheus. Each key is a fixed literal
    # per receiver call site (a bounded enum), so a single ``event``-labelled
    # counter stays cardinality-safe. Same catch-up-delta pattern the
    # audit_failures / csrf_rejects bridges above use.
    webhook_counts = getattr(request.app.state, "metrics", None)
    if isinstance(webhook_counts, dict):
        wh_counter = metrics_mod.counter(
            "et_webhook_events_total",
            "Inbound webhook events by type (Gmail Pub/Sub + MS Graph receivers).",
        )
        for _evt, _val in webhook_counts.items():
            _iv = parse_int_or_none(_val)  # N-219c/13 R23: SSOT
            if _iv is None:
                continue
            delta = _iv - wh_counter.value(event=str(_evt))
            if delta > 0:
                wh_counter.inc(amount=delta, event=str(_evt))

    body = metrics_mod.render_text()
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/csrf-token")
async def api_csrf_token(request: Request):
    """Mint + return a CSRF token for the current session.

    JS-driven UIs fetch this once on load and echo the value back in
    the X-CSRF-Token header on every state-changing request. The
    server also sets the et_csrf cookie as part of the response so
    plain-form callers (no JS) can read the same token from the
    cookie. The token is bound to the session — leaking one session's
    token doesn't authorise requests on another session.

    Returns 401 if the caller has no session cookie; the CSRF token
    only makes sense for authenticated users.
    """
    from email_triage.web.auth import SESSION_COOKIE_NAME
    from email_triage.web.csrf import attach_csrf_cookie, mint_csrf_token
    from fastapi.responses import JSONResponse
    session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    if not session_token:
        return api_error_response("no_session", status_code=401, purpose="misc")
    secret_key = getattr(request.app.state, SESSION_SECRET_KEY, "")
    if not secret_key:
        return api_error_response("csrf_unconfigured", status_code=500, purpose="misc")
    # Honour the listener mode: cookie ``Secure`` only when serving
    # HTTPS, else browsers reject it on the dev HTTP listener.
    # N-200 R22 (2026-07-02): route Secure decision through the _cookies SSOT
    # so reverse-proxy topology (nginx-front) is captured (request.url.scheme
    # == 'https') alongside direct-uvicorn HTTPS (config.tls.enabled).
    from email_triage.web._cookies import is_request_https
    config = getattr(request.app.state, "config", None)
    https = is_request_https(request, config)
    # Mint first so the body + the cookie carry the SAME token. Then
    # build ONE response with the real body, then attach the cookie.
    # No placeholder response, no header copying -- the prior shape
    # caused Content-Length to be computed for the empty-token body
    # then attached to a different response with the real (longer)
    # body, producing ERR_CONTENT_LENGTH_MISMATCH on the wire.
    token = mint_csrf_token(secret_key, session_token)
    resp = JSONResponse({"token": token})
    attach_csrf_cookie(resp, token, secure=https)
    return resp


@router.get("/status")
async def api_status(request: Request):
    user = await db_call(_require_auth, request)
    db = get_db(request)
    config = get_config(request)

    def _status_snapshot(db, user_id):
        # ASYNC-DB: flow-status rollup + category read off-loop.
        stats = {}
        try:
            rows = db.execute(
                "SELECT status, COUNT(*) as cnt FROM flows GROUP BY status"
            ).fetchall()
            stats = {row["status"]: row["cnt"] for row in rows}
        except Exception:
            pass
        # 2026-05-17 fix: user-scoped so personal categories appear
        # alongside the system set. Pre-fix this returned system-only
        # (``user_id IS NULL``) which hid the caller's own categories
        # from /api/status responses.
        cats = list(get_categories_dict(db, user_id=user_id).keys())
        return stats, cats

    stats, cats = await db_call(_status_snapshot, db, user["id"])

    return {
        "user": {"email": user["email"], "role": user["role"]},
        "flows": stats,
        "categories": cats,
    }


# ---------------------------------------------------------------------------
# Users (admin)
# ---------------------------------------------------------------------------

@router.get("/users")
async def api_list_users(request: Request):
    await db_call(_require_admin, request)
    db = get_db(request)

    def _list_users(db):
        # ASYNC-DB: user listing off-loop.
        return db.execute(
            "SELECT id, email, name, role, notify_email, created_at, last_login FROM users ORDER BY id"
        ).fetchall()

    rows = await db_call(_list_users, db)
    return {"users": [dict(r) for r in rows]}


@router.post("/users", status_code=201)
async def api_create_user(request: Request, body: UserCreate):
    await db_call(_require_admin, request)
    db = get_db(request)

    if body.role not in {r.value for r in UserRole}:
        raise raise_api_error(f"Invalid role: {body.role}", status_code=422, purpose="misc")
    now = now_utc_iso()
    #  R32 DA-fold R1 — canonicalise on write to match the read-side
    # SSOT (get_user_by_email); idempotent for ASCII, A-label for IDN.
    from email_triage.mail_headers import canonical_email
    canonical_body_email = canonical_email(body.email)

    def _create_user(db, email, name, role, notify_email, now):
        # ASYNC-DB: dup-check + insert + commit, one off-loop hop
        # (db_call serialises via the / lock — replaces the
        # explicit get_write_lock() that  added).
        if get_user_by_email(db, email) is not None:
            return None
        cursor = db.execute(
            "INSERT INTO users (email, name, role, notify_email, created_at) VALUES (?, ?, ?, ?, ?)",
            (email, name, role, notify_email, now),
        )
        db.commit()
        return cursor.lastrowid

    new_id = await db_call(
        _create_user, db, canonical_body_email, body.name, body.role,
        body.notify_email, now,
    )
    if new_id is None:
        raise raise_api_error("User already exists", status_code=409, purpose="misc")
    return {
        "id": new_id,
        "email": body.email,
        "name": body.name,
        "role": body.role,
        "notify_email": body.notify_email,
        "created_at": now,
    }


def _get_user_row(db, user_id):
    # ASYNC-DB: single-user read off-loop (shared sync helper).
    return db.execute(
        "SELECT id, email, name, role, notify_email, created_at, last_login FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


@router.get("/users/{user_id}")
async def api_get_user(request: Request, user_id: int):
    await db_call(_require_admin, request)
    db = get_db(request)
    row = await db_call(_get_user_row, db, user_id)
    if row is None:
        raise raise_api_error("User not found", status_code=404, purpose="misc")
    return dict(row)


@router.patch("/users/{user_id}")
async def api_update_user(request: Request, user_id: int, body: UserUpdate):
    await db_call(_require_admin, request)
    db = get_db(request)

    if body.role is not None and body.role not in {r.value for r in UserRole}:
        raise raise_api_error(f"Invalid role: {body.role}", status_code=422, purpose="misc")
    def _update_user(db, user_id, body):
        # ASYNC-DB: existence check + conditional update + commit,
        # one off-loop hop (replaces 's get_write_lock()).
        row = db.execute(
            "SELECT id FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            return False
        updates = []
        params: list = []
        privileged_change = False  # N-250 R25 — trip on role/email/notify_email
        if body.name is not None:
            updates.append("name = ?")
            params.append(body.name)
        if body.role is not None:
            updates.append("role = ?")
            params.append(body.role)
            privileged_change = True  # role demotion must invalidate cookie
        if body.notify_email is not None:
            updates.append("notify_email = ?")
            params.append(body.notify_email or None)
        if updates:
            # N-250 R25 §164.312(a)(2)(iii): the sibling UI form at
            # `web/routers/ui/users.py:618/623` bumps session_epoch on
            # every privileged change (per N-238); this /api PATCH
            # surface was BLIND — a demoted admin's cookie kept
            # authority. Bump here on privileged fields.
            if privileged_change:
                updates.append("session_epoch = session_epoch + 1")
            params.append(user_id)
            db.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            db.commit()
        return True

    found = await db_call(_update_user, db, user_id, body)
    if not found:
        raise raise_api_error("User not found", status_code=404, purpose="misc")
    row = await db_call(_get_user_row, db, user_id)
    if row is None:
        raise raise_api_error("User not found", status_code=404, purpose="misc")
    return dict(row)


@router.delete("/users/{user_id}", status_code=204)
async def api_delete_user(request: Request, user_id: int):
    # N-242 R24: route through the TriageLogger SSOT so this HIPAA-
    # sensitive admin user-delete audit rides the HMAC chain instead of
    # forking to a raw stdlib logger. The prior `import logging as
    # _logging` alias bypassed the SSOT + hid this admin action from any
    # literal-substring `logging.getLogger` grep.
    from email_triage.triage_logging import get_logger
    _log = get_logger("web.routers.api")

    admin = await db_call(_require_admin, request)
    db = get_db(request)

    def _delete_user_preflight(db, user_id, admin_email):
        # ASYNC-DB: existence + self-delete guard + account enumeration.
        # Returns ("not_found", []) / ("self", []) / ("ok", [account_ids]).
        # Actual DELETE deferred to after the watcher/purge funnel.
        target = db.execute(
            "SELECT email FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if target is None:
            return "not_found", []
        if target["email"] == admin_email:
            return "self", []
        from email_triage.db.accounts import list_email_accounts
        accounts = list_email_accounts(db, user_id=user_id, include_delegated=False)
        account_ids = [a["id"] for a in accounts]
        return "ok", account_ids

    outcome, account_ids = await db_call(
        _delete_user_preflight, db, user_id, admin["email"]
    )
    if outcome == "not_found":
        raise raise_api_error("User not found", status_code=404, purpose="misc")
    if outcome == "self":
        raise raise_api_error("Cannot delete yourself", status_code=400, purpose="misc")
    # L1 + L2 — purge watcher/secrets for EACH account BEFORE the user delete.
    # Fail CLOSED: if any account's purge raises, do NOT delete the user — that
    # would orphan the account's credentials (§164.310(d)(2)(i)); 500 + retry.
    # Watcher-stop is best-effort inside the funnel, so only a real purge
    # failure trips this.
    from email_triage._errfmt import fmt_exc
    from email_triage.db.accounts import purge_account_local_state
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)
    for acct_id in account_ids:
        try:
            if watcher_mgr is not None:
                await watcher_mgr.apply_account_deleted(
                    acct_id, actor_user_id=admin["id"],
                )
            else:
                secrets = getattr(request.app.state, "secrets", None)
                await db_call(purge_account_local_state, db, acct_id, secrets)
        except Exception as _e:
            _log.error(
                "api_delete_user: local-state purge FAILED for account — "
                "aborting user delete to avoid orphaning credentials",
                extra={"user_id": user_id, "account_id": acct_id,
                       "error": fmt_exc(_e)},
            )
            raise raise_api_error(
                "Stored credentials for one of the user's accounts "
                "could not be purged; user not deleted. Retry.",
                status_code=500, purpose="misc",
            ) from _e

    def _offboard_user(db, user_id, account_ids, actor_user_id):
        # Offboard — NEVER hard-delete (operator ruling 2026-06-19, ). A
        # DELETE FROM users NULLs the actor link across the 9 audit tables AND
        # cascade-deletes each account's hipaa_access_events (ON DELETE CASCADE)
        # — wiping the §164.312(b)/(c)(1) trail. Soft-disable the user +
        # deactivate (not delete) the accounts; credentials already purged above.
        # NOTE: the direct account-delete actuator now ALSO soft-deactivates
        # (operator ruled 2026-06-20, N-108) — both legs preserve the audit trail.
        from email_triage.db.accounts import set_account_active
        from email_triage.db.audit import set_user_disabled
        for acct_id in account_ids:
            set_account_active(db, acct_id, False)
        set_user_disabled(
            db, user_id, True, actor_user_id=actor_user_id,
            reason="offboarded via admin API (soft-disable; row retained for audit)",
        )
        return "ok"

    await db_call(_offboard_user, db, user_id, account_ids, admin["id"])


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

@router.get("/categories")
async def api_list_categories(request: Request):
    # 2026-05-17 fix: capture the user dict so the categories lookup
    # can pass ``user_id``. Pre-fix this endpoint returned only the
    # system categories (``user_id IS NULL``) — the caller's own
    # personal categories were silently filtered out, contradicting
    # the same caller's expectation from the /categories UI page
    # which DOES return system ∪ personal.
    user = await db_call(_require_auth, request)
    db = get_db(request)
    # ASYNC-DB: category read off-loop.
    cats = await db_call(get_categories_dict, db, user_id=user["id"])
    return {"categories": cats}


class CategoryCreate(BaseModel):
    slug: str
    description: str = ""


class CategoryUpdate(BaseModel):
    slug: str | None = None
    description: str | None = None


@router.post("/categories", status_code=201)
async def api_create_category(request: Request, body: CategoryCreate):
    await db_call(_require_admin, request)
    db = get_db(request)

    slug = body.slug.strip().lower()
    desc = body.description.strip()

    def _create(db, slug, desc):
        # ASYNC-DB: category insert off-loop (helper is @db_write).
        try:
            return create_category_db(db, slug, desc)
        except Exception:
            return None

    cat_id = await db_call(_create, db, slug, desc)
    if cat_id is None:
        raise raise_api_error(f"Category '{slug}' already exists", status_code=409, purpose="misc")
    return {"id": cat_id, "slug": slug, "description": body.description}


@router.put("/categories/{cat_id}")
async def api_update_category(request: Request, cat_id: int, body: CategoryUpdate):
    await db_call(_require_admin, request)
    db = get_db(request)

    def _update(db, cat_id, body):
        # ASYNC-DB: existence read + update + commit, one off-loop
        # hop (update_category_db is @db_write — reentrant under db_call).
        existing = get_category_db(db, cat_id)
        if existing is None:
            return None
        slug_ = (body.slug or existing["slug"]).strip().lower()
        desc_ = (
            body.description if body.description is not None
            else existing["description"]
        )
        update_category_db(db, cat_id, slug_, desc_.strip())
        return slug_, desc_

    result = await db_call(_update, db, cat_id, body)
    if result is None:
        raise raise_api_error("Category not found", status_code=404, purpose="misc")
    slug, desc = result
    return {"id": cat_id, "slug": slug, "description": desc}


@router.delete("/categories/{cat_id}", status_code=204)
async def api_delete_category(request: Request, cat_id: int):
    await db_call(_require_admin, request)
    db = get_db(request)
    # ASYNC-DB: category delete off-loop (helper is @db_write).
    deleted = await db_call(delete_category_db, db, cat_id)
    if not deleted:
        raise raise_api_error("Category not found", status_code=404, purpose="misc")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Classification lists
# ---------------------------------------------------------------------------

class ListCreate(BaseModel):
    name: str
    category: str
    is_global: bool = False


class RuleCreate(BaseModel):
    rule_type: str
    pattern: str
    skip_ai: bool = False


def _enrich_list(db, row) -> dict:
    d = dict(row)
    rules = db.execute(
        "SELECT * FROM list_rules WHERE list_id = ? ORDER BY id", (d["id"],)
    ).fetchall()
    d["rules"] = [dict(r) for r in rules]
    return d


@router.get("/lists")
async def api_list_lists(request: Request):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    def _list_lists(db, user_id):
        # ASYNC-DB: list reads + per-list rule enrichment off-loop.
        personal = db.execute(
            "SELECT * FROM classification_lists WHERE owner_id = ? ORDER BY id",
            (user_id,),
        ).fetchall()
        global_lists = db.execute(
            "SELECT * FROM classification_lists WHERE is_global = 1 ORDER BY id",
        ).fetchall()
        return (
            [_enrich_list(db, r) for r in personal],
            [_enrich_list(db, r) for r in global_lists],
        )

    personal, global_lists = await db_call(_list_lists, db, user["id"])
    return {"personal": personal, "global": global_lists}


@router.post("/lists", status_code=201)
async def api_create_list(request: Request, body: ListCreate):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    if body.is_global and not may_manage_global_lists(user["role"]):
        raise raise_api_error("Insufficient permissions", status_code=403, purpose="misc")
    now = now_utc_iso()

    def _create_list(db, name, category, owner_id, is_global, now):
        # ASYNC-DB: insert + commit off-loop (db_call serialises via
        # the / lock — replaces 's get_write_lock()).
        cursor = db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, category, owner_id, int(is_global), now),
        )
        db.commit()
        return cursor.lastrowid

    new_id = await db_call(
        _create_list, db, body.name, body.category, user["id"],
        body.is_global, now,
    )
    return {"id": new_id, "name": body.name, "category": body.category,
            "is_global": body.is_global, "created_at": now}


@router.get("/lists/{list_id}")
async def api_get_list(request: Request, list_id: int):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    def _get_list(db, list_id):
        # ASYNC-DB: list read + rule enrichment off-loop.
        row = db.execute(
            "SELECT * FROM classification_lists WHERE id = ?", (list_id,)
        ).fetchone()
        if row is None:
            return None
        return row, _enrich_list(db, row)

    result = await db_call(_get_list, db, list_id)
    if result is None:
        raise raise_api_error("List not found", status_code=404, purpose="misc")
    row, enriched = result

    # Read gate: owner, admin, or any global list (census run15 #2 — route through
    # the is_list_readable_by SSOT instead of the inline owner/is_global/admin gate).
    if not is_list_readable_by(row, user_id=user["id"], role=user["role"]):
        raise raise_api_error("Forbidden", status_code=403, purpose="misc")
    return enriched


@router.delete("/lists/{list_id}", status_code=204)
async def api_delete_list(request: Request, list_id: int):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    def _delete_list(db, list_id, user_id, is_admin):
        # ASYNC-DB: ownership read + delete + commit, one off-loop
        # hop (replaces 's get_write_lock()).
        row = db.execute(
            "SELECT * FROM classification_lists WHERE id = ?", (list_id,)
        ).fetchone()
        if row is None:
            return "not_found"
        # Delete-LIST gate: owner or admin only (census run15 #2 — the
        # is_list_deletable_by SSOT; STRICTER than is_list_writable_by, a
        # power_user may edit global rules but not delete the global list).
        if not is_list_deletable_by(row, user_id=user_id, role=("admin" if is_admin else None)):
            return "forbidden"
        db.execute("DELETE FROM classification_lists WHERE id = ?", (list_id,))
        db.commit()
        return "ok"

    outcome = await db_call(
        _delete_list, db, list_id, user["id"], is_admin(user),  # N-222e R22
    )
    if outcome == "not_found":
        raise raise_api_error("List not found", status_code=404, purpose="misc")
    if outcome == "forbidden":
        raise raise_api_error("Forbidden", status_code=403, purpose="misc")
@router.post("/lists/{list_id}/rules", status_code=201)
async def api_add_rule(request: Request, list_id: int, body: RuleCreate):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    from email_triage.engine.models import WEB_ALLOWED_RULE_TYPES
    valid_types = set(WEB_ALLOWED_RULE_TYPES)
    if body.rule_type not in valid_types:
        raise raise_api_error(f"Invalid rule_type: {body.rule_type}", status_code=422, purpose="misc")
    #  preventative: empty / whitespace-only patterns would silently
    # match every email through the substring branch in _rule_matches.
    # Reject at the boundary alongside the rule_type 422.
    if not body.pattern or not body.pattern.strip():
        raise raise_api_error("pattern must not be empty", status_code=422, purpose="misc")
    now = now_utc_iso()

    def _add_rule(db, list_id, body, user_id, role, now):
        # ASYNC-DB: ownership read + insert + commit, one off-loop
        # hop (replaces 's get_write_lock()).
        row = db.execute(
            "SELECT * FROM classification_lists WHERE id = ?", (list_id,)
        ).fetchone()
        if row is None:
            return "not_found", None
        # N-60 (Loop-5 census) — power_user may write rules ONLY on a GLOBAL
        # list, never another user's personal one; owner/admin always. SSOT.
        if not is_list_writable_by(row, user_id=user_id, role=role):
            return "forbidden", None
        cursor = db.execute(
            "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, created_at) VALUES (?, ?, ?, ?, ?)",
            (list_id, body.rule_type, body.pattern, int(body.skip_ai), now),
        )
        db.commit()
        return "ok", cursor.lastrowid

    outcome, new_id = await db_call(
        _add_rule, db, list_id, body, user["id"], user["role"], now,
    )
    if outcome == "not_found":
        raise raise_api_error("List not found", status_code=404, purpose="misc")
    if outcome == "forbidden":
        raise raise_api_error("Forbidden", status_code=403, purpose="misc")
    return {"id": new_id, "list_id": list_id, "rule_type": body.rule_type,
            "pattern": body.pattern, "skip_ai": body.skip_ai}


@router.delete("/lists/{list_id}/rules/{rule_id}", status_code=204)
async def api_delete_rule(request: Request, list_id: int, rule_id: int):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    def _delete_rule(db, list_id, rule_id, user_id, role):
        # ASYNC-DB: ownership read + rule existence + delete + commit,
        # one off-loop hop (replaces 's get_write_lock()).
        row = db.execute(
            "SELECT * FROM classification_lists WHERE id = ?", (list_id,)
        ).fetchone()
        if row is None:
            return "list_not_found"
        # N-60 — power_user only on GLOBAL lists; owner/admin always (SSOT).
        if not is_list_writable_by(row, user_id=user_id, role=role):
            return "forbidden"
        rule = db.execute(
            "SELECT id FROM list_rules WHERE id = ? AND list_id = ?",
            (rule_id, list_id),
        ).fetchone()
        if rule is None:
            return "rule_not_found"
        db.execute("DELETE FROM list_rules WHERE id = ?", (rule_id,))
        db.commit()
        return "ok"

    outcome = await db_call(
        _delete_rule, db, list_id, rule_id, user["id"], user["role"],
    )
    if outcome == "list_not_found":
        raise raise_api_error("List not found", status_code=404, purpose="misc")
    if outcome == "forbidden":
        raise raise_api_error("Forbidden", status_code=403, purpose="misc")
    if outcome == "rule_not_found":
        raise raise_api_error("Rule not found", status_code=404, purpose="misc")
# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

class ApiKeyCreate(BaseModel):
    name: str
    user_email: str | None = None  # Admin can create for another user.
    expires_at: str | None = None  # ISO 8601 datetime or None for no expiry.


@router.get("/keys")
async def api_list_keys(request: Request):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    # ASYNC-DB: API-key listing off-loop.
    if is_admin(user):  # N-222e R22
        keys = await db_call(list_api_keys, db)
    else:
        keys = await db_call(list_api_keys, db, user_id=user["id"])
    return {"keys": keys}


@router.post("/keys", status_code=201)
async def api_create_key(request: Request, body: ApiKeyCreate):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    # Determine target user.
    cross_user = bool(body.user_email and body.user_email != user["email"])
    if cross_user and not is_admin(user):  # N-222e R22
        raise raise_api_error("Only admins can create keys for other users", status_code=403, purpose="misc")
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)

    def _create_key(db, key_hash, body, cross_user, actor_id, actor_email):
        # ASYNC-DB: target-user lookup + key store + commit, one
        # off-loop hop.
        target_user_id = actor_id
        if cross_user:
            target = get_user_by_email(db, body.user_email)
            if target is None:
                return "no_user", None, None
            target_user_id = target["id"]
        key_id_ = store_api_key(
            db, key_hash, body.name, target_user_id, body.expires_at,
            actor_user_id=actor_id,
            actor_email=actor_email,
            source="api",
        )
        return "ok", key_id_, target_user_id

    outcome, key_id, target_user_id = await db_call(
        _create_key, db, key_hash, body, cross_user, user["id"],
        user["email"],
    )
    if outcome == "no_user":
        raise raise_api_error(f"User not found: {body.user_email}", status_code=404, purpose="misc")
    return {
        "id": key_id,
        "key": raw_key,  # Only returned once at creation time.
        "name": body.name,
        "user_id": target_user_id,
        "expires_at": body.expires_at,
    }


@router.delete("/keys/{key_id}", status_code=204)
async def api_delete_key(request: Request, key_id: int):
    user = await db_call(_require_auth, request)
    db = get_db(request)

    def _delete_key(db, key_id, user_id, is_admin, actor_email):
        # ASYNC-DB: ownership read + key delete, one off-loop hop.
        row = db.execute(
            "SELECT user_id FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
        if row is None:
            return "not_found"
        from email_triage.web._resource_authz import can_modify_owned_resource
        if not can_modify_owned_resource(
            row["user_id"], requester_id=user_id,
            role="admin" if is_admin else None, admin_bypass=True,
        ):
            return "forbidden"
        delete_api_key(
            db, key_id,
            actor_user_id=user_id,
            actor_email=actor_email,
            source="api",
        )
        return "ok"

    outcome = await db_call(
        _delete_key, db, key_id, user["id"], is_admin(user),  # N-222e R22
        user["email"],
    )
    if outcome == "not_found":
        raise raise_api_error("API key not found", status_code=404, purpose="misc")
    if outcome == "forbidden":
        raise raise_api_error("Forbidden", status_code=403, purpose="misc")