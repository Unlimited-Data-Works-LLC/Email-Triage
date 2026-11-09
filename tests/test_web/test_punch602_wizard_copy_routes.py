"""Punch 602 — the account wizard's "copy routes from another account" works.

``wizard_step4_submit`` hand-rolled ``SELECT category_slug, action_name,
config_json, sort_order`` / ``INSERT INTO account_routes (... category_slug,
action_name, config_json, sort_order)``. The table has ``category`` and
``actions_json`` (``web/db.py`` ``_ACCOUNT_ROUTES_DDL``), so the SELECT raised
``no such column`` into a best-effort ``except`` and the copy silently did
nothing. The fix routes the copy through the account_routes SSOT
(``list_account_routes`` -> ``upsert_account_route``), so the schema mapping and
the JSON round-trip cannot drift from the table.

Tests run against the real initialised test DB (the ``db`` fixture via
``init_db``), drive the real handler, and check the RENDERED routes editor of
the target account. PD-9: the copy needs ``can_manage_account`` on BOTH the
target (``_wizard_fetch_and_auth``) and the source.

PIN (count-agnostic, every string literal in src): no SQL write to
``account_routes`` outside ``db/accounts.py`` (the writer SSOT), except the
named, function-keyed allowlist entry below.

SCOPE CAVEAT: a green run says nothing about SQL whose table name arrives
through a variable, ``.format()`` or ``%`` (``f"UPDATE {table}"``), nor about
``scripts/`` or ``cve-arc/`` (the walk is ``src/email_triage`` only). The
allowlist is keyed by (path, enclosing function), so a write moved into a
DIFFERENT function of ``web/db.py`` is flagged, which is the intended direction.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from _pin_harness import (
    SRC_ROOT, assert_pin_has_teeth, enclosing_fn, iter_src_files,
    iter_string_literals, parse_module, relpath,
)
from email_triage.web.db import (
    create_email_account, list_account_routes, upsert_account_route,
)


_SOURCE_ACTIONS = [
    {"action": "move", "config": {"folder_map": {"newsletters": "Reading/News"}}},
    {"action": "label", "config": {"labels": ["Label_12", "Label_7"]}},
    {"action": "add-label", "config": {
        "labels": ["tax-2026"], "provider_labels": ["Receipts/2026", "Tax"],
    }},
    {"action": "mute", "config": {}},
]


def _acct(db, user_id, name):
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.example.invalid", "username": f"{name}@example.com"},
    )


def _copy(client, cookies, target, source):
    return client.post(
        "/accounts/new/step4",
        data={"account_id": str(target), "route_source": f"copy:{source}"},
        cookies=cookies, follow_redirects=False,
    )


def _strip_ids(routes):
    return sorted(
        (r["category"], r["actions"]) for r in routes
    )


class _CardState(HTMLParser):
    """Per route-row form: checked action names + the add-label provider text."""

    def __init__(self):
        super().__init__()
        self.cards: dict[str, dict] = {}
        self._slug = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and "route-row-form" in (a.get("class") or ""):
            self._slug = a.get("data-slug") or ""
            self.cards[self._slug] = {"checked": set(), "provider": None}
        elif tag == "input" and self._slug is not None:
            if a.get("name") == "actions" and "checked" in a:
                self.cards[self._slug]["checked"].add(a.get("value"))
            if a.get("name") == "add_label_provider":
                self.cards[self._slug]["provider"] = a.get("value")

    def handle_endtag(self, tag):
        if tag == "form":
            self._slug = None


# ---------------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------------

def test_copy_routes_copies_actions_json_intact_and_renders(
    client, db, regular_user, user_cookies, strict_undefined_templates,
):
    src = _acct(db, regular_user["id"], "src602")
    dst = _acct(db, regular_user["id"], "dst602")
    upsert_account_route(db, src, "newsletters", _SOURCE_ACTIONS)
    upsert_account_route(db, src, "receipts", [{"action": "notify", "config": {}}])

    resp = _copy(client, user_cookies, dst, src)
    assert resp.status_code == 303, resp.text
    assert "step=5" in resp.headers["location"]

    # The actions JSON survives the copy exactly (decoded equality).
    assert _strip_ids(list_account_routes(db, dst)) == _strip_ids(
        list_account_routes(db, src)
    )
    # The source is untouched.
    assert len(list_account_routes(db, src)) == 2

    # The rendered editor of the target shows the copied configuration.
    page = client.get(f"/accounts/{dst}/routes", cookies=user_cookies)
    assert page.status_code == 200, page.text[:400]
    p = _CardState()
    p.feed(page.text)
    assert "newsletters" in p.cards, "copied category card did not render"
    assert p.cards["newsletters"]["checked"] == {"move", "label", "add-label", "mute"}
    assert p.cards["newsletters"]["provider"] == "Receipts/2026, Tax"


def test_copy_routes_overwrites_same_category_on_resubmit(
    client, db, regular_user, user_cookies,
):
    """Re-submitting step 4 (back button) is idempotent: one row per
    (account, category), the source's actions win."""
    src = _acct(db, regular_user["id"], "src602b")
    dst = _acct(db, regular_user["id"], "dst602b")
    upsert_account_route(db, src, "newsletters", _SOURCE_ACTIONS)
    upsert_account_route(db, dst, "newsletters", [{"action": "notify", "config": {}}])
    _copy(client, user_cookies, dst, src)
    _copy(client, user_cookies, dst, src)
    rows = list_account_routes(db, dst)
    assert len(rows) == 1
    assert rows[0]["actions"] == _SOURCE_ACTIONS


def test_copy_refused_when_requester_cannot_manage_source(
    client, db, admin_user, regular_user, user_cookies,
):
    """PD-9: the source account_id is client-submitted; a source the requester
    cannot manage copies nothing."""
    src = _acct(db, admin_user["id"], "admin_src602")
    dst = _acct(db, regular_user["id"], "dst602c")
    upsert_account_route(db, src, "newsletters", _SOURCE_ACTIONS)
    resp = _copy(client, user_cookies, dst, src)
    assert resp.status_code == 303
    assert list_account_routes(db, dst) == []


def test_copy_refused_when_requester_cannot_manage_target(
    client, db, admin_user, regular_user, user_cookies,
):
    """PD-9 on the write side: the target is client-submitted too."""
    src = _acct(db, regular_user["id"], "src602d")
    dst = _acct(db, admin_user["id"], "admin_dst602")
    upsert_account_route(db, src, "newsletters", _SOURCE_ACTIONS)
    resp = _copy(client, user_cookies, dst, src)
    assert resp.status_code == 303
    assert "step=1" in resp.headers["location"]
    assert list_account_routes(db, dst) == []


def test_copy_from_self_is_a_noop(client, db, regular_user, user_cookies):
    a = _acct(db, regular_user["id"], "self602")
    upsert_account_route(db, a, "newsletters", _SOURCE_ACTIONS)
    _copy(client, user_cookies, a, a)
    rows = list_account_routes(db, a)
    assert len(rows) == 1 and rows[0]["actions"] == _SOURCE_ACTIONS


# ---------------------------------------------------------------------------
# Pin: account_routes writes live in the SSOT
# ---------------------------------------------------------------------------

_WRITE_RE = re.compile(
    r"\b(INSERT(\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+account_routes\b",
    re.IGNORECASE,
)

_SSOT_FILE = "db/accounts.py"

# (repo-relative path, enclosing function) -> reason. Keyed by function, not
# line, so an unrelated edit cannot break it (R38).
_ALLOW = {
    ("web/db.py", "scrub_queue_summary_from_routes"): (
        "boot-time one-shot that strips the removed queue_summary action from "
        "actions_json; writes the real columns"
    ),
}


def _write_sites(tree) -> list[tuple[int, str]]:
    import ast
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            for s in iter_string_literals(node):
                if _WRITE_RE.search(s):
                    out.append((getattr(node, "lineno", 0), enclosing_fn(node)))
                break
    return out


def _offenders() -> tuple[list[str], set]:
    offenders, seen_allow = [], set()
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_FILE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno, fn in _write_sites(tree):
            if (rel, fn) in _ALLOW:
                seen_allow.add((rel, fn))
                continue
            offenders.append(f"{rel}:{lineno} in {fn}")
    return sorted(set(offenders)), seen_allow


def test_no_account_routes_write_outside_ssot():
    offenders, _ = _offenders()
    assert not offenders, (
        "SQL write to account_routes outside db/accounts.py. Route it through "
        "upsert_account_route / delete_account_route (punch 602: a hand-rolled "
        f"copy used columns the table does not have):\n" + "\n".join(offenders)
    )


def test_allowlist_is_not_stale():
    _, seen = _offenders()
    stale = sorted(set(_ALLOW) - seen)
    assert not stale, f"_ALLOW entries no longer match a write site: {stale}"


def test_ssot_file_actually_writes_account_routes():
    tree = parse_module(SRC_ROOT / _SSOT_FILE)
    assert _write_sites(tree), "the SSOT no longer writes account_routes"


def test_pin_has_teeth():
    assert_pin_has_teeth(
        _write_sites,
        'def f(db):\n    db.execute("INSERT INTO account_routes "\n'
        '               "(account_id, category_slug) VALUES (?, ?)", (1, 2))\n',
        'def f(db):\n    db.execute("SELECT COUNT(*) FROM account_routes '
        'WHERE account_id = ?", (1,))\n',
    )
    # Lower-case and f-string forms are caught too.
    assert_pin_has_teeth(
        _write_sites,
        'def g(db, t):\n    db.execute(f"update account_routes set x={t}")\n',
    )
