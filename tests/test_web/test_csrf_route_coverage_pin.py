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

from _pin_harness import iter_app_routes  # PD#6 — the ONE route-table walk
from email_triage.web.csrf import _GUARDED_METHODS, _is_exempt_path


_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")


def _fill_params(path: str) -> str:
    """Substitute ``{id}``-style path params with a dummy ``1`` — the CSRF check
    fires before routing-to-handler, so the dummy never reaches business logic."""
    return _PATH_PARAM_RE.sub("1", path)


def _guarded_routes(app) -> list[tuple[str, str]]:
    """Enumerate every guarded (POST/PUT/PATCH/DELETE) leaf route in the app.

    The three-shape route-table walk (fastapi 0.139.x ``_IncludedRouter``,
    ``Mount``/sub-router, plain leaf) moved to
    ``tests/_pin_harness.iter_app_routes`` in , when the route-scope pin
    needed the identical walk — PD#6, the pins obey the SSOT rule, so a second
    hand-rolled walker is the drift the harness exists to stop. The
    guarded-method filter + the real ``_is_exempt_path`` reuse stay here: they are
    THIS pin's detection logic, not scaffolding.

    One entry per guarded (method, path) pair — the harness walk yields a row per
    method, so a route declaring both POST and DELETE is now checked on BOTH
    instead of only the alphabetically-first, which is a small widening.
    """
    out: list[tuple[str, str]] = []
    for method, full_path, _module, _name in iter_app_routes(app):
        if method not in _GUARDED_METHODS:
            continue
        if _is_exempt_path(full_path, ()):     # the real exempt logic, reused
            continue
        out.append((method, full_path))
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
        "Add a real csrf token requirement (no per-route exempt list exists):\n  "
        + "\n  ".join(offenders)
    )


def test_pin_has_teeth(app, raw_client, admin_cookies):
    """Anti-vacuous: a genuinely-exempt path (/health/*) does NOT 403 on a
    token-less POST — proving the 403 in the main test is meaningful, not a
    blanket reject."""
    app.state.csrf_enforce = True
    resp = raw_client.post("/health", cookies=admin_cookies, follow_redirects=False)
    assert resp.status_code != 403          # exempt prefix => not csrf-rejected
