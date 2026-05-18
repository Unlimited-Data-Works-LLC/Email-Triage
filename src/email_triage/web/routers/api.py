"""JSON REST API endpoints.

Mirror the web UI operations for programmatic access (OpenClaw, scripts).
All endpoints return JSON.  Auth: session cookie or Bearer API key.
"""

from __future__ import annotations

from datetime import datetime, timezone

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
from email_triage.web.auth import (
    delete_api_key,
    generate_api_key,
    get_user_by_email,
    hash_api_key,
    list_api_keys,
    store_api_key,
)
from email_triage.web.dependencies import get_current_user

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
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def _require_admin(request: Request) -> dict:
    user = _require_auth(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Insufficient permissions")
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
    user = _require_auth(request)
    if user["role"] != "admin":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse("forbidden", status_code=403)

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
        return JSONResponse(
            {"error": "no_session"}, status_code=401,
        )
    secret_key = getattr(request.app.state, "session_secret", "")
    if not secret_key:
        return JSONResponse(
            {"error": "csrf_unconfigured"}, status_code=500,
        )
    # Honour the listener mode: cookie ``Secure`` only when serving
    # HTTPS, else browsers reject it on the dev HTTP listener.
    config = getattr(request.app.state, "config", None)
    https = bool(getattr(getattr(config, "tls", None), "enabled", False))
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
    user = _require_auth(request)
    db = get_db(request)
    config = get_config(request)

    stats = {}
    try:
        rows = db.execute(
            "SELECT status, COUNT(*) as cnt FROM flows GROUP BY status"
        ).fetchall()
        stats = {row["status"]: row["cnt"] for row in rows}
    except Exception:
        pass

    return {
        "user": {"email": user["email"], "role": user["role"]},
        "flows": stats,
        # 2026-05-17 fix: user-scoped so personal categories appear
        # alongside the system set. Pre-fix this returned system-only
        # (``user_id IS NULL``) which hid the caller's own categories
        # from /api/status responses.
        "categories": list(
            get_categories_dict(db, user_id=user["id"]).keys()
        ),
    }


# ---------------------------------------------------------------------------
# Users (admin)
# ---------------------------------------------------------------------------

@router.get("/users")
async def api_list_users(request: Request):
    _require_admin(request)
    db = get_db(request)
    rows = db.execute(
        "SELECT id, email, name, role, notify_email, created_at, last_login FROM users ORDER BY id"
    ).fetchall()
    return {"users": [dict(r) for r in rows]}


@router.post("/users", status_code=201)
async def api_create_user(request: Request, body: UserCreate):
    _require_admin(request)
    db = get_db(request)

    if body.role not in {r.value for r in UserRole}:
        raise HTTPException(status_code=422, detail=f"Invalid role: {body.role}")

    existing = get_user_by_email(db, body.email)
    if existing is not None:
        raise HTTPException(status_code=409, detail="User already exists")

    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO users (email, name, role, notify_email, created_at) VALUES (?, ?, ?, ?, ?)",
        (body.email, body.name, body.role, body.notify_email, now),
    )
    db.commit()

    return {
        "id": cursor.lastrowid,
        "email": body.email,
        "name": body.name,
        "role": body.role,
        "notify_email": body.notify_email,
        "created_at": now,
    }


@router.get("/users/{user_id}")
async def api_get_user(request: Request, user_id: int):
    _require_admin(request)
    db = get_db(request)
    row = db.execute(
        "SELECT id, email, name, role, notify_email, created_at, last_login FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)


@router.patch("/users/{user_id}")
async def api_update_user(request: Request, user_id: int, body: UserUpdate):
    _require_admin(request)
    db = get_db(request)

    row = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    updates = []
    params = []
    if body.name is not None:
        updates.append("name = ?")
        params.append(body.name)
    if body.role is not None:
        if body.role not in {r.value for r in UserRole}:
            raise HTTPException(status_code=422, detail=f"Invalid role: {body.role}")
        updates.append("role = ?")
        params.append(body.role)
    if body.notify_email is not None:
        updates.append("notify_email = ?")
        params.append(body.notify_email or None)

    if updates:
        params.append(user_id)
        db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()

    return await api_get_user(request, user_id)


@router.delete("/users/{user_id}", status_code=204)
async def api_delete_user(request: Request, user_id: int):
    admin = _require_admin(request)
    db = get_db(request)

    target = db.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target["email"] == admin["email"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()


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
    user = _require_auth(request)
    db = get_db(request)
    return {"categories": get_categories_dict(db, user_id=user["id"])}


class CategoryCreate(BaseModel):
    slug: str
    description: str = ""


class CategoryUpdate(BaseModel):
    slug: str | None = None
    description: str | None = None


@router.post("/categories", status_code=201)
async def api_create_category(request: Request, body: CategoryCreate):
    _require_admin(request)
    db = get_db(request)

    slug = body.slug.strip().lower()
    try:
        cat_id = create_category_db(db, slug, body.description.strip())
    except Exception:
        raise HTTPException(status_code=409, detail=f"Category '{slug}' already exists")
    return {"id": cat_id, "slug": slug, "description": body.description}


@router.put("/categories/{cat_id}")
async def api_update_category(request: Request, cat_id: int, body: CategoryUpdate):
    _require_admin(request)
    db = get_db(request)

    existing = get_category_db(db, cat_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Category not found")

    slug = (body.slug or existing["slug"]).strip().lower()
    desc = body.description if body.description is not None else existing["description"]
    update_category_db(db, cat_id, slug, desc.strip())
    return {"id": cat_id, "slug": slug, "description": desc}


@router.delete("/categories/{cat_id}", status_code=204)
async def api_delete_category(request: Request, cat_id: int):
    _require_admin(request)
    db = get_db(request)
    if not delete_category_db(db, cat_id):
        raise HTTPException(status_code=404, detail="Category not found")
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
    user = _require_auth(request)
    db = get_db(request)

    personal = db.execute(
        "SELECT * FROM classification_lists WHERE owner_id = ? ORDER BY id",
        (user["id"],),
    ).fetchall()
    global_lists = db.execute(
        "SELECT * FROM classification_lists WHERE is_global = 1 ORDER BY id",
    ).fetchall()

    return {
        "personal": [_enrich_list(db, r) for r in personal],
        "global": [_enrich_list(db, r) for r in global_lists],
    }


@router.post("/lists", status_code=201)
async def api_create_list(request: Request, body: ListCreate):
    user = _require_auth(request)
    db = get_db(request)

    if body.is_global and user["role"] not in ("admin", "power_user"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
        (body.name, body.category, user["id"], int(body.is_global), now),
    )
    db.commit()

    return {"id": cursor.lastrowid, "name": body.name, "category": body.category,
            "is_global": body.is_global, "created_at": now}


@router.get("/lists/{list_id}")
async def api_get_list(request: Request, list_id: int):
    user = _require_auth(request)
    db = get_db(request)

    row = db.execute(
        "SELECT * FROM classification_lists WHERE id = ?", (list_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="List not found")

    # Only owner, admin, or if global.
    if row["owner_id"] != user["id"] and not row["is_global"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")

    return _enrich_list(db, row)


@router.delete("/lists/{list_id}", status_code=204)
async def api_delete_list(request: Request, list_id: int):
    user = _require_auth(request)
    db = get_db(request)

    row = db.execute(
        "SELECT * FROM classification_lists WHERE id = ?", (list_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="List not found")

    if row["owner_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")

    db.execute("DELETE FROM classification_lists WHERE id = ?", (list_id,))
    db.commit()


@router.post("/lists/{list_id}/rules", status_code=201)
async def api_add_rule(request: Request, list_id: int, body: RuleCreate):
    user = _require_auth(request)
    db = get_db(request)

    row = db.execute(
        "SELECT * FROM classification_lists WHERE id = ?", (list_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="List not found")

    if row["owner_id"] != user["id"] and user["role"] not in ("admin", "power_user"):
        raise HTTPException(status_code=403, detail="Forbidden")

    valid_types = {"sender", "sender_domain", "subject"}
    if body.rule_type not in valid_types:
        raise HTTPException(status_code=422, detail=f"Invalid rule_type: {body.rule_type}")

    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, created_at) VALUES (?, ?, ?, ?, ?)",
        (list_id, body.rule_type, body.pattern, int(body.skip_ai), now),
    )
    db.commit()

    return {"id": cursor.lastrowid, "list_id": list_id, "rule_type": body.rule_type,
            "pattern": body.pattern, "skip_ai": body.skip_ai}


@router.delete("/lists/{list_id}/rules/{rule_id}", status_code=204)
async def api_delete_rule(request: Request, list_id: int, rule_id: int):
    user = _require_auth(request)
    db = get_db(request)

    row = db.execute(
        "SELECT * FROM classification_lists WHERE id = ?", (list_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="List not found")

    if row["owner_id"] != user["id"] and user["role"] not in ("admin", "power_user"):
        raise HTTPException(status_code=403, detail="Forbidden")

    rule = db.execute(
        "SELECT id FROM list_rules WHERE id = ? AND list_id = ?", (rule_id, list_id)
    ).fetchone()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    db.execute("DELETE FROM list_rules WHERE id = ?", (rule_id,))
    db.commit()


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

class ApiKeyCreate(BaseModel):
    name: str
    user_email: str | None = None  # Admin can create for another user.
    expires_at: str | None = None  # ISO 8601 datetime or None for no expiry.


@router.get("/keys")
async def api_list_keys(request: Request):
    user = _require_auth(request)
    db = get_db(request)

    if user["role"] == "admin":
        keys = list_api_keys(db)
    else:
        keys = list_api_keys(db, user_id=user["id"])
    return {"keys": keys}


@router.post("/keys", status_code=201)
async def api_create_key(request: Request, body: ApiKeyCreate):
    user = _require_auth(request)
    db = get_db(request)

    # Determine target user.
    target_user_id = user["id"]
    if body.user_email and body.user_email != user["email"]:
        if user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Only admins can create keys for other users")
        target = get_user_by_email(db, body.user_email)
        if target is None:
            raise HTTPException(status_code=404, detail=f"User not found: {body.user_email}")
        target_user_id = target["id"]

    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    key_id = store_api_key(
        db, key_hash, body.name, target_user_id, body.expires_at,
        actor_user_id=user["id"],
        actor_email=user["email"],
        source="api",
    )

    return {
        "id": key_id,
        "key": raw_key,  # Only returned once at creation time.
        "name": body.name,
        "user_id": target_user_id,
        "expires_at": body.expires_at,
    }


@router.delete("/keys/{key_id}", status_code=204)
async def api_delete_key(request: Request, key_id: int):
    user = _require_auth(request)
    db = get_db(request)

    # Verify ownership or admin.
    row = db.execute(
        "SELECT user_id FROM api_keys WHERE id = ?", (key_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="API key not found")
    if row["user_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")

    delete_api_key(
        db, key_id,
        actor_user_id=user["id"],
        actor_email=user["email"],
        source="api",
    )
