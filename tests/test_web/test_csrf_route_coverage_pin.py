"""PD#1 pin: EVERY guarded (POST/PUT/PATCH/DELETE) route is CSRF-protected.

The token-injecting ``csrf_client`` + the reject tracker are the down-payment;
THIS is the prevention (devils-advocate F1, task ). It is count-agnostic —
it enumerates the live FastAPI route table (not a hand list) and asserts each
guarded, non-exempt route returns 403 when POSTed WITHOUT a token (under
enforce), with a real session cookie. So a route that became CSRF-exempt by
mistake — added to the exempt-prefix list, or a middleware regression — fails
LOUDLY here instead of shipping unprotected (the deploy-time 403 class, but
caught at the route-table level, not per-form-template).

The CSRF middleware guards by method + path-prefix BEFORE the handler runs, so a
no-token POST to a guarded path 403s regardless of body / path-param validity —
which is exactly what lets one parametrized check cover the whole table.
"""

from __future__ import annotations

import re

from email_triage.web.csrf import _GUARDED_METHODS, _is_exempt_path

# Routes that are LEGITIMATELY exempt beyond the always-on prefixes (each needs
# a one-line reason). Keep this EMPTY unless a route has a real cross-origin-safe
# justification — every entry is a hole the pin can no longer see.
_INTENTIONAL_EXEMPT: dict[str, str] = {}

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")


def _fill_params(path: str) -> str:
    """Substitute ``{id}``-style path params with a dummy ``1`` — the CSRF check
    fires before routing-to-handler, so the dummy never reaches business logic."""
    return _PATH_PARAM_RE.sub("1", path)


def _guarded_routes(app) -> list[tuple[str, str]]:
    """Enumerate every guarded (POST/PUT/PATCH/DELETE) leaf route in the app.

    fastapi 0.139.x changed the ``include_router()`` shape: sub-routers
    now sit in ``app.routes`` as ``_IncludedRouter`` wrappers whose real
    routes live under ``included_router.original_router.routes`` with a
    prefix in ``included_router.include_context.prefix``. Pre-0.139 those
    routes were expanded into ``app.routes`` at the top level. Mount
    objects (``StaticFiles`` etc.) still recurse via ``.routes``. The
    walk handles all three shapes so the pin stays count-agnostic across
    fastapi versions — the interprocedural drift class the count-agnostic
    style-guide directive is about.
    """
    out: list[tuple[str, str]] = []

    def _walk(route, prefix: str) -> None:
        # fastapi 0.139.x _IncludedRouter — routes live on the original
        # APIRouter, prefix on include_context.
        original = getattr(route, "original_router", None)
        ctx = getattr(route, "include_context", None)
        if original is not None and hasattr(original, "routes"):
            sub_prefix = prefix + (getattr(ctx, "prefix", "") or "")
            for child in original.routes:
                _walk(child, sub_prefix)
            return
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        # Mount / sub-router with own .routes list (StaticFiles, WSGI
        # mounts, and pre-0.139 include-router expansions).
        children = getattr(route, "routes", None)
        if children is not None and path is not None:
            for child in children:
                _walk(child, prefix + path)
            return
        if not path:
            return
        full_path = prefix + path
        guarded = sorted(set(methods) & _GUARDED_METHODS)
        if not guarded:
            return
        if _is_exempt_path(full_path, ()):     # the real exempt logic, reused
            return
        if full_path in _INTENTIONAL_EXEMPT:
            return
        out.append((guarded[0], full_path))

    for route in app.routes:
        _walk(route, "")
    return out


def test_every_guarded_route_rejects_a_token_less_post(
    raw_client, app, admin_cookies,
):
    app.state.csrf_enforce = True
    offenders: list[str] = []
    routes = _guarded_routes(app)
    assert routes, "no guarded routes enumerated — the pin lost its target"
    for method, path in routes:
        url = _fill_params(path)
        resp = raw_client.request(
            method, url, cookies=admin_cookies, follow_redirects=False,
        )
        # 403 = the CSRF middleware rejected it (guarded — good). Anything else
        # means the middleware let a token-less request through = NOT guarded.
        if resp.status_code != 403:
            offenders.append(f"{method} {path} -> {resp.status_code}")
    assert not offenders, (
        "guarded route(s) did NOT 403 on a token-less POST — they are CSRF-"
        "EXEMPT (accidentally in the exempt list, or a middleware regression). "
        "Add a real csrf token requirement, or justify in _INTENTIONAL_EXEMPT:\n  "
        + "\n  ".join(offenders)
    )


def test_pin_has_teeth(app, raw_client, admin_cookies):
    """Anti-vacuous: a genuinely-exempt path (/health/*) does NOT 403 on a
    token-less POST — proving the 403 in the main test is meaningful, not a
    blanket reject."""
    app.state.csrf_enforce = True
    resp = raw_client.post("/health", cookies=admin_cookies, follow_redirects=False)
    assert resp.status_code != 403          # exempt prefix => not csrf-rejected
