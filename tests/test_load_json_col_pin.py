"""load_json_col-bypass pin — the ``_json``-suffixed bare NAME shape (run17 #7,
census #16b).

This pin completes a THREE-pin layered net over the ``db/_helpers.load_json_col``
SSOT (a persisted JSON column decoded by a bare ``json.loads`` 500s the whole
page/flow on a corrupt/NULL/wrong-shape value; ``load_json_col`` degrades to a
fresh copy of the default instead). The three partition the value-shape space —
they do NOT mirror one another (that would be the exact CIDI drift the Prime
Directives forbid):

  * ``test_json_col_decode_pin`` — a bare ``json.loads`` of a ``_json``-
    SUFFIXED COLUMN read: the inline ``row["x_json"]`` / ``d.pop("x_json")`` /
    ``d.get("x_json")`` shapes, the N-16 dual-factory ternary, and a per-function
    taint-follow of a name ASSIGNED from one of those.
  * ``test_json_col_naming_pin`` — a NON-``_json`` string COLUMN name
    (``query`` / ``adds_labels`` / …) must be REGISTERED and (run17 #7) must
    decode via ``load_json_col``, not a bare ``json.loads``.
  * THIS pin (run17 #7) — a ``_json``-SUFFIXED bare LOCAL / PARAMETER NAME fed
    to a bare ``json.loads`` — e.g. ``json.loads(lead_pcts_json or "[]")`` where
    ``lead_pcts_json`` is a *parameter* carrying the ``def_escalation_lead_pcts``
    column value (``db/regulatory_clock.py`` _sweep_decide, the run17 #7
    finding). The decode-pin's taint sees a name only when it is ASSIGNED from a
    column-read in the SAME function; a column value arriving as a ``_json``-
    named PARAMETER (or assigned from a non-column-read expression) is invisible
    to it. The ``_json`` suffix is itself the column-shape signal here.

A flagged site is resolved by ROUTING through ``load_json_col(raw, default=…)``
(after which it is no longer a ``json.loads`` and this pin no longer sees it), OR
by an ``_ALLOWLIST`` entry below for a ``_json``-named value that is NOT a
persisted column — the only legitimate cases are client-submitted request bodies
and library-generated JSON (always-valid / not corrupt-tolerant by contract).

SCOPE CAVEAT (honest, per R38):
  * **NAME shape only — subscripts/`.get`/`.pop` are the SIBLINGS' job.** This
    pin deliberately does NOT re-flag ``json.loads(row["x_json"])`` (decode-pin)
    or ``json.loads(d.get("query"))`` (naming-pin) — re-implementing those here
    would be a duplicate walker. It keys purely on a bare ``Name`` / ``Attribute``
    ending ``_json`` (after unwrapping a ``… or "{}"`` / ``… or "[]"`` guard).
  * **No DB-vs-not-DB oracle for a ``_json`` name.** ``lead_pcts_json`` (a column
    value) and ``response_json`` (a client request body) are structurally
    identical — the suffix can't tell them apart. The four genuine non-column
    sites are ``_ALLOWLIST``-ed WITH A REASON rather than silently excluded; a
    NEW ``_json``-named bare ``json.loads`` fails until it is routed or
    consciously allow-listed.
  * **Allow-list key is ``(relpath, enclosing_fn)``** (R38 line-stable) — a new
    bad site added INSIDE an allow-listed function would be masked. The four
    allow-listed functions are auth-flow leaves that decode exactly one library/
    client JSON each; revisit the entry if one grows a second decode.
  * **Alias evasion.** Like the siblings, ``_is_loads_call`` keys on the
    ``json`` / ``_json`` aliases; a future ``import json as jm; jm.loads(x_json)``
    would slip all three. No live offender at HEAD (run17 #7 routed the two that
    used ``json_mod`` / ``_json_decode``).
"""

from __future__ import annotations

import ast

from _pin_harness import JSON_DECODE_ALIASES, enclosing_fn, parse_source, relpath as _relpath, walk_src

SSOT_REL = "db/_helpers.py"

# (relpath, enclosing_fn) -> reason. A ``_json``-suffixed NAME fed to a bare
# json.loads that is NOT a persisted DB column (so load_json_col — which exists
# to make a *corrupt persisted column* degrade to a default — does not apply).
_ALLOWLIST: dict[tuple[str, str], str] = {
    ("web/webauthn_auth.py", "finish_registration"):
        "response_json is the client-submitted WebAuthn registration response "
        "(request body str), not a persisted column; bad JSON already raises a "
        "typed WebAuthnAuthError.",
    ("web/webauthn_auth.py", "finish_authentication"):
        "response_json is the client-submitted WebAuthn assertion response, not "
        "a persisted column; bad JSON already raises WebAuthnAuthError.",
    ("web/webauthn_auth.py", "finish_passkey_authentication"):
        "response_json is the client-submitted passkey assertion response, not "
        "a persisted column; bad JSON already raises WebAuthnAuthError.",
    ("web/routers/auth_keys.py", "login_passkey_begin"):
        "options_json is library-generated WebAuthn options (py_webauthn), "
        "always-valid JSON, not a persisted column.",
}


def _unwrap_or(arg: ast.AST) -> ast.AST:
    """``X or "{}"`` / ``X or "[]"`` NULL-guard -> X (the underlying read)."""
    if isinstance(arg, ast.BoolOp) and isinstance(arg.op, ast.Or):
        return arg.values[0]
    return arg


def _json_suffixed_name(arg: ast.AST):
    """The bare ``Name`` / ``Attribute`` ending ``_json`` feeding a loads(),
    after unwrapping an ``or``-guard — else ``None``."""
    a = _unwrap_or(arg)
    if isinstance(a, ast.Name) and a.id.endswith("_json"):
        return a.id
    if isinstance(a, ast.Attribute) and a.attr.endswith("_json"):
        return a.attr
    return None


def _is_loads_call(n: ast.AST) -> bool:
    """``json.loads(...)`` / ``_json.loads(...)`` with >=1 positional arg."""
    return (isinstance(n, ast.Call) and bool(n.args)
            and isinstance(n.func, ast.Attribute) and n.func.attr == "loads"
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id in JSON_DECODE_ALIASES)


def _violations_in_tree(tree: ast.AST):
    """list of (lineno, enclosing_fn, name) for a bare json.loads of a
    ``_json``-suffixed NAME in this (parent-annotated) tree."""
    out = []
    for n in ast.walk(tree):
        if not _is_loads_call(n):
            continue
        nm = _json_suffixed_name(n.args[0])
        if nm:
            out.append((n.lineno, enclosing_fn(n), nm))
    return out


def test_json_suffixed_name_loads_route_through_load_json_col():
    offenders = []
    for _path, rel, tree in walk_src():
        if rel == SSOT_REL:
            continue
        for ln, fn, nm in _violations_in_tree(tree):
            if (rel, fn) in _ALLOWLIST:
                continue
            offenders.append(f"{rel}:{ln} {fn}() -> json.loads({nm} ...)")
    assert not offenders, (
        "A `_json`-suffixed NAME decoded by a bare json.loads outside the "
        "db/_helpers.load_json_col SSOT (run17 #7 / census #16b — a corrupt "
        f"persisted column → 500): {offenders}. Route through "
        "load_json_col(raw, default={}/[]); or, if the value is NOT a persisted "
        "column (a client body / library JSON), add a (relpath, enclosing_fn) "
        "entry to _ALLOWLIST in this file WITH a reason."
    )


def test_allowlist_entries_are_live():
    """No stale _ALLOWLIST entry — each must still name a real flagged site, so
    the allow-list reflects HEAD (a routed/removed site must drop its entry)."""
    live: set[tuple[str, str]] = set()
    for _path, rel, tree in walk_src():
        if rel == SSOT_REL:
            continue
        for _ln, fn, _nm in _violations_in_tree(tree):
            live.add((rel, fn))
    dead = sorted(k for k in _ALLOWLIST if k not in live)
    assert not dead, (
        f"Stale _ALLOWLIST entr(ies) — no bare json.loads(<_json name>) remains "
        f"in these functions; remove them: {dead}."
    )


def test_pin_has_teeth():
    # BAD: a `_json`-suffixed param via a bare json.loads (the run17 #7 shape).
    bad = parse_source(
        "import json\n"
        "def f(lead_pcts_json):\n"
        "    return json.loads(lead_pcts_json or '[]')\n"
    )
    v = _violations_in_tree(bad)
    assert v and v[0][2] == "lead_pcts_json", v
    # BAD-2: a bare _json name (no or-guard), alias _json.loads.
    bad2 = parse_source(
        "import json as _json\n"
        "def f(options_json):\n"
        "    return _json.loads(options_json)\n"
    )
    assert _violations_in_tree(bad2), "missed a bare _json-name loads"


def test_pin_no_false_positive_on_routed_or_plain_names():
    # GOOD-1: routed through the SSOT — not a json.loads, so invisible here.
    ok1 = parse_source(
        "def f(lead_pcts_json):\n"
        "    return load_json_col(lead_pcts_json, default=[])\n"
    )
    assert not _violations_in_tree(ok1)
    # GOOD-2: a NON-`_json` name (LLM output / HTTP body / generic raw) — NOT
    # this pin's shape (avoids the false positives the decode-pin also dodges).
    ok2 = parse_source(
        "import json\n"
        "def f(raw, resp):\n"
        "    a = json.loads(raw)\n"
        "    b = json.loads(resp.text)\n"
        "    return a, b\n"
    )
    assert not _violations_in_tree(ok2)
    # GOOD-3: a subscript column read is the SIBLING pins' job, not this one.
    ok3 = parse_source(
        "import json\n"
        "def f(row):\n"
        "    return json.loads(row['value_json'])\n"
    )
    assert not _violations_in_tree(ok3)


def test_ssot_helper_importable():
    from email_triage.db._helpers import load_json_col
    assert load_json_col("nope{", default={}) == {}
    assert load_json_col(None, default=[]) == []
