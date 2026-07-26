"""N-181 R20_5 structural pin — INSTALL_OAUTH_FIELDS SSOT bijection.

The census run20 R20_5 finding: `admin_integrations_save` (V3) hand-mirrors
`hydrate_and_register_install_oauth` (V2). Both list the same 7 install-OAuth
key constants side-by-side. A new key added to hydrate that never landed a
save writer = N-130 recurrence surface (install-wide OAuth death on next
hydrate — save-side blanks the key, hydrate reads it back empty, all providers
fail with `client_id not configured`).

The N-181 SSOT `web/oauth_secret_keys.py::INSTALL_OAUTH_FIELDS` names every
install-OAuth field with its (key_const, section, attr, form_field, kind)
tuple entry. The hydrate side iterates it; the save side is EXACT-SET pinned
against it — every KEY_CONST in the tuple MUST be referenced (by name) inside
`admin_integrations_save`, else the save-writer drifted.

Per N-161 style-guide guidance: EXACT-SET (bijection), not subset — a save
handler that references 6 of 7 fields silently drops 1.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module

from email_triage.web.oauth_secret_keys import INSTALL_OAUTH_FIELDS


_KEY_CONSTS = frozenset(f[0] for f in INSTALL_OAUTH_FIELDS)
_KEY_NAME_MAP = {
    "GOOGLE_OAUTH_WEB_CLIENT_ID",
    "GOOGLE_OAUTH_WEB_CLIENT_SECRET",
    "GOOGLE_OAUTH_DESKTOP_CLIENT_ID",
    "GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET",
    "O365_OAUTH_TENANT_ID",
    "O365_OAUTH_CLIENT_ID",
    "O365_OAUTH_CLIENT_SECRET",
}


def _find_fn(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


_SECRET_WRITE_FNS = frozenset({
    "set_secret_if_changed",     # secret write w/ never-clobber + validation
    "set_id_preserve_blank",     # id write w/ never-clobber on blank
    "clear_secret",              # explicit tenant "common" clear path
})


def _name_refs(node: ast.AST) -> set[str]:
    """Every Name reference PLUS every ImportFrom alias — db-sme N-181 must-fix
    (c) — a function-body `from X import (A, B, C)` binds A/B/C locally but
    they show up as `ast.alias` nodes inside `ast.ImportFrom`, NOT as `ast.Name`
    on the walk. Missing them false-positives the exact-set pin."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id)
        elif isinstance(sub, ast.ImportFrom):
            for alias in sub.names:
                out.add(alias.asname or alias.name)
    return out


def _resolve_alias_map(tree: ast.AST) -> dict[str, str]:
    """DA N-181 must-fix (A): resolve `from X import KEY as _K` → {_K: KEY}
    so a call using the aliased local name still counts as actuating KEY."""
    aliases: dict[str, str] = {}
    for sub in ast.walk(tree):
        if isinstance(sub, ast.ImportFrom):
            for a in sub.names:
                if a.name in _KEY_NAME_MAP and a.asname:
                    aliases[a.asname] = a.name
    return aliases


def _keys_actuated_by_secret_write(node: ast.AST, aliases: dict[str, str] | None = None) -> set[str]:
    """hipaa-sme + db-sme N-181 must-fix (d): trace each KEY_CONST reference to
    an ACTUATOR call — one of `_secret_write` SSOT helpers (set_secret_if_changed
    / set_id_preserve_blank / clear_secret). Aliases resolved per DA must-fix A."""
    if aliases is None:
        aliases = {}
    def _resolve(name: str) -> str:
        return aliases.get(name, name)
    actuated: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            called = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else None)
            if called not in _SECRET_WRITE_FNS:
                continue
            if len(sub.args) >= 2 and isinstance(sub.args[1], ast.Name):
                actuated.add(_resolve(sub.args[1].id))
            for kw in sub.keywords:
                if kw.arg == "key" and isinstance(kw.value, ast.Name):
                    actuated.add(_resolve(kw.value.id))
    return actuated


def test_hydrate_iterates_install_oauth_fields():
    """The hydrate side must iterate INSTALL_OAUTH_FIELDS — no hand-list
    of `read_secret(secrets, KEY)` calls."""
    tree = parse_module(SRC_ROOT / "providers" / "factory.py")
    assert tree is not None
    fn = _find_fn(tree, "hydrate_and_register_install_oauth")
    assert fn is not None, "hydrate_and_register_install_oauth() vanished"
    names = _name_refs(fn)
    assert "INSTALL_OAUTH_FIELDS" in names, (
        "hydrate no longer iterates INSTALL_OAUTH_FIELDS — a hand-list has "
        "returned and will drift from the save side."
    )


def test_save_actuates_every_install_oauth_key_via_secret_write():
    """EXACT-SET actuator pin (hipaa-sme + db-sme + DA N-181 must-fix): every
    INSTALL_OAUTH_FIELDS key_const MUST appear as the KEY argument of a
    `_secret_write` SSOT helper call (`set_secret_if_changed` /
    `set_id_preserve_blank` / `clear_secret`) somewhere in
    `web/routers/integrations.py` (DA must-fix B: MODULE-scope, not
    admin_integrations_save-scope — a future refactor into helper functions
    like `_save_google_oauth()` would false-negative a fn-only pin).

    Name-reference alone was insufficient (a future refactor could reference
    the const in a log line while writing via `secrets[KEY] = value`, bypassing
    the never-clobber guard added post-2026-06-08). Per PD#13 + incident
    2026-06-08: the write MUST route through the `_secret_write` funnel.

    Aliased imports (`from ... import KEY as _K`) resolved per DA must-fix (A).
    """
    tree = parse_module(SRC_ROOT / "web" / "routers" / "integrations.py")
    assert tree is not None
    aliases = _resolve_alias_map(tree)
    actuated = _keys_actuated_by_secret_write(tree, aliases)
    missing = sorted(_KEY_NAME_MAP - actuated)
    assert not missing, (
        f"web/routers/integrations.py does NOT actuate {missing} via a "
        "`_secret_write` SSOT call ({set_secret_if_changed / set_id_preserve_blank "
        "/ clear_secret}). PD#13 + incident_2026-06-08: every OAuth key MUST "
        "route through the never-clobber funnel; a bare `secrets[K] = v` silently "
        "re-opens the 8-day OAuth outage window."
    )


def test_ssot_tuple_wellformed():
    """No duplicate key_const / form_field; every kind is one of the
    supported strings."""
    supported_kinds = {"id", "secret", "google_secret", "tenant_id"}
    keys = [f[0] for f in INSTALL_OAUTH_FIELDS]
    form_fields = [f[3] for f in INSTALL_OAUTH_FIELDS]
    kinds = [f[4] for f in INSTALL_OAUTH_FIELDS]
    assert len(set(keys)) == len(keys), f"dup key_const: {keys}"
    assert len(set(form_fields)) == len(form_fields), f"dup form_field: {form_fields}"
    for kind in kinds:
        assert kind in supported_kinds, f"unsupported kind {kind!r}"


def test_pin_has_teeth():
    """Planted bad shapes must trigger the actuator-check assertion."""
    bad_bare_write = ast.parse("""
def h(secrets):
    from email_triage.web.oauth_secret_keys import GOOGLE_OAUTH_WEB_CLIENT_ID
    secrets[GOOGLE_OAUTH_WEB_CLIENT_ID] = "value"  # bypasses SSOT
""")
    actuated = _keys_actuated_by_secret_write(bad_bare_write)
    assert not actuated, "teeth: bare secrets[K]=v is NOT counted as SSOT actuation"

    good_write = ast.parse("""
def h(secrets):
    from email_triage.web.oauth_secret_keys import GOOGLE_OAUTH_WEB_CLIENT_ID
    set_id_preserve_blank(secrets, GOOGLE_OAUTH_WEB_CLIENT_ID, "value", "current")
""")
    actuated = _keys_actuated_by_secret_write(good_write)
    assert "GOOGLE_OAUTH_WEB_CLIENT_ID" in actuated, \
        "teeth: SSOT-actuator call MUST be counted"

    # ImportFrom aliases picked up by _name_refs (db-sme must-fix c)
    good_ref = ast.parse("""
def h():
    from email_triage.web.oauth_secret_keys import INSTALL_OAUTH_FIELDS as _fields
    return _fields
""")
    names = _name_refs(good_ref)
    assert "_fields" in names, "teeth: ImportFrom alias must be in name refs"
