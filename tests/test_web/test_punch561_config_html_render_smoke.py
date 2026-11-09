"""Punch 561 — every route that renders ``config.html`` renders it StrictUndefined-clean.

POST /config/health-email/send-now re-rendered ``config.html`` with only six
keys; the General tab reads more (``version_status``,
``classifier_baa_status``, the style-learning knobs ...), so under
StrictUndefined it 500'd and in production those sections rendered blank after
every send. /config/save had the same defect (punch 553, db panel F-O5-3).

Two halves (PD-17 / R39):

* ``test_every_config_html_route_has_a_smoke`` — count-agnostic enumeration.
  AST-walks every module under ``web/`` for a call passing the literal
  ``"config.html"``, resolves the enclosing route handler's ``@router.<verb>``
  decorator, and asserts each (verb, path) has a case in ``_CASES`` (and every
  case still names a live route). A new route that re-renders the page cannot
  ship without a strict render.
* ``test_config_html_route_renders_strict_clean`` — the render smoke itself,
  under the ``strict_undefined_templates`` fixture. GET /config runs once per
  tab slug in ``admin._CONFIG_TAB_SLUGS`` (derived, not listed).

A third, structural half (punch 560 panel, devils-advocate F5):
``test_general_tab_context_is_built_in_one_place``. The three General-tab
re-renders build their context through ``admin._general_tab_ctx``; no other
dict literal under ``web/`` may carry the General tab's signature keys, so a
fourth hand-built context (which could drift in a key or a value) goes red.

SCOPE CAVEAT: the enumeration sees a literal ``"config.html"`` argument. A
template name built at runtime or passed through a variable is not followed;
nor is a non-route helper that renders the page (it is reported as an
unresolved site so it cannot pass silently).
"""

from __future__ import annotations

import ast

import pytest

from tests._pin_harness import (
    assert_pin_has_teeth, enclosing_fn, innermost_fn_at_lineno,
    iter_src_files, parse_module, relpath,
)

_TEMPLATE = "config.html"
_VERBS = frozenset({"get", "post", "put", "patch", "delete"})


def _route_of(fn: ast.AST) -> tuple[str, str] | None:
    for dec in getattr(fn, "decorator_list", []):
        if (
            isinstance(dec, ast.Call)
            and isinstance(dec.func, ast.Attribute)
            and dec.func.attr in _VERBS
            and dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            return dec.func.attr.upper(), dec.args[0].value
    return None


def _render_sites(tree) -> list[tuple[str | None, int]]:
    """(route or None, line) for every call passing the literal template."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not any(
            isinstance(a, ast.Constant) and a.value == _TEMPLATE
            for a in node.args
        ):
            continue
        fn = innermost_fn_at_lineno(tree, node.lineno)
        out.append((_route_of(fn) if fn is not None else None, node.lineno))
    return out


def _enumerate() -> tuple[set[tuple[str, str]], list[str]]:
    routes: set[tuple[str, str]] = set()
    unresolved: list[str] = []
    for path in iter_src_files("web"):
        tree = parse_module(path)
        if tree is None:
            continue
        for route, line in _render_sites(tree):
            if route is None:
                unresolved.append(f"{relpath(path)}:{line}")
            else:
                routes.add(route)
    return routes, unresolved


# ---------------------------------------------------------------------------
# One case per route. Each POST case drives the handler far enough to reach
# its re-render; the assertion is a 200 plus a General-tab marker.
# ---------------------------------------------------------------------------

_SAVE_FORM = {
    "log_level": "INFO", "classifier_backend": "ollama",
    "classifier_model": "qwen3.5:35b",
    "classifier_ollama_url": "http://localhost:11434",
    "smtp_port": "587", "logging_format": "text",
}


def _get_config(client, cookies, monkeypatch, tab):
    return client.get(f"/config?tab={tab}", cookies=cookies)


def _post_save(client, cookies, monkeypatch, tab):
    return client.post("/config/save", data=_SAVE_FORM, cookies=cookies)


def _post_send_now(client, cookies, monkeypatch, tab):
    import email_triage.web.daily_health as dh

    # The handler imports the sender at call time; stub it so no SMTP is
    # attempted. Both outcomes re-render the same page.
    monkeypatch.setattr(
        dh, "send_daily_health_email",
        lambda *a, **k: (False, "punch 561 stub: not sent"),
    )
    return client.post("/config/health-email/send-now", cookies=cookies)


_CASES = {
    ("GET", "/config"): _get_config,
    ("POST", "/config/save"): _post_save,
    ("POST", "/config/health-email/send-now"): _post_send_now,
}


def _params():
    from email_triage.web.routers.ui.admin import _CONFIG_TAB_SLUGS

    for route in sorted(_CASES):
        tabs = _CONFIG_TAB_SLUGS if route == ("GET", "/config") else ("general",)
        for tab in tabs:
            yield pytest.param(route, tab, id=f"{route[0]} {route[1]} [{tab}]")


def test_every_config_html_route_has_a_smoke():
    routes, unresolved = _enumerate()
    assert not unresolved, (
        f"{_TEMPLATE} is rendered outside a route handler at {unresolved}; "
        "give its route callers a case in _CASES"
    )
    assert routes, f"enumeration found no {_TEMPLATE} render site (rig broken?)"
    missing = routes - set(_CASES)
    assert not missing, (
        f"routes render {_TEMPLATE} with no StrictUndefined smoke: {sorted(missing)}"
    )
    stale = set(_CASES) - routes
    assert not stale, f"_CASES names routes that no longer render {_TEMPLATE}: {sorted(stale)}"


def test_enumeration_has_teeth():
    from tests._pin_harness import parse_source

    tree = parse_source(
        "@router.post('/config/new-thing')\n"
        "async def h(request):\n"
        "    return await _render(t, request, 'config.html', {})\n"
        "async def helper(request):\n"
        "    return await _render(t, request, 'config.html', {})\n"
        "async def other(request):\n"
        "    return await _render(t, request, 'stats.html', {})\n"
    )
    assert _render_sites(tree) == [(("POST", "/config/new-thing"), 3), (None, 5)]


@pytest.mark.parametrize("route,tab", list(_params()))
def test_config_html_route_renders_strict_clean(
    route, tab, client, admin_cookies, monkeypatch, strict_undefined_templates,
):
    resp = _CASES[route](client, admin_cookies, monkeypatch, tab)
    assert resp.status_code == 200, resp.text[-2000:]
    if tab == "general":
        # The General tab body rendered (its own form field), not just chrome.
        assert 'name="anti_ai_style_guide_global"' in resp.text
    if route == ("POST", "/config/health-email/send-now"):
        assert "punch 561 stub: not sent" in resp.text


# ---------------------------------------------------------------------------
# One General-tab render context (punch 560 panel, devils-advocate F5).
# ---------------------------------------------------------------------------

# Two keys only the General tab's context carries together.
_GENERAL_TAB_SIGNATURE = frozenset({
    "classifier_baa_status", "anti_ai_style_guide_global",
})

# (repo-relative path, function) -> why it may build a dict with those keys.
_GENERAL_TAB_CTX_HOMES: dict[tuple[str, str], str] = {
    ("web/routers/ui/admin.py", "_general_tab_ctx"): (
        "the one General-tab render-context builder every re-render uses"
    ),
    ("web/routers/ui/_shared.py", "_config_page_snapshot"): (
        "the data snapshot the builder reads (one DB hop), not a render context"
    ),
}


def _general_tab_dicts(tree) -> list[tuple[str, int]]:
    """(enclosing fn, line) of every dict literal holding the signature keys."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {
            k.value for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        if _GENERAL_TAB_SIGNATURE <= keys:
            out.append((enclosing_fn(node), node.lineno))
    return out


def _scan_general_tab_dicts() -> dict[tuple[str, str], list[int]]:
    found: dict[tuple[str, str], list[int]] = {}
    for path in iter_src_files("web"):
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        for fn, line in _general_tab_dicts(tree):
            found.setdefault((rel, fn), []).append(line)
    return found


def test_general_tab_context_is_built_in_one_place():
    found = _scan_general_tab_dicts()
    bad = {k: v for k, v in found.items() if k not in _GENERAL_TAB_CTX_HOMES}
    assert not bad, (
        "A General-tab render context is hand-built outside "
        "admin._general_tab_ctx; route it through the builder (overrides "
        "for what the route knows better):\n"
        + "\n".join(f"  {p}::{fn} lines {lines}" for (p, fn), lines in sorted(bad.items()))
    )
    stale = [k for k in _GENERAL_TAB_CTX_HOMES if k not in found]
    assert not stale, f"_GENERAL_TAB_CTX_HOMES entries match nothing: {stale}"


def test_general_tab_context_pin_has_teeth():
    assert_pin_has_teeth(
        _general_tab_dicts,
        "ctx = {'runtime': r, 'classifier_baa_status': b,\n"
        "       'anti_ai_style_guide_global': g}\n",
        good_source=(
            "ctx = {'user': u, **_general_tab_ctx(snap, vs, save_msg=m)}\n"
            "ack = {'classifier_baa_status': b}\n"
        ),
    )
