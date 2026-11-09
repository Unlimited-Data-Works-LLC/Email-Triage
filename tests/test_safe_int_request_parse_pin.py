"""Request-input int parse — count-agnostic structural pin (run18  / ).

THE LIVE DEFECT (db-sme VERIFIED, is_live_defect at HEAD): two POST handlers
parsed a tampered form field with a bare ``int(form.get("def_id") or 0)``
(``web/routers/ui/profile.py`` — the regulatory-clocks update/delete actuator).
``or 0`` only covers None/empty; a NON-numeric ``def_id`` ("abc") raised an
UNCAUGHT ``ValueError`` (the enclosing ``except ClockDefValidationError`` does not
catch it) → an HTTP 500 on attacker-controlled input — a §164.308(a)(7)
availability hole (a reachable crash, NOT a PHI disclosure).

THE SSOT: ``_safe_int`` (``web/routers/ui/_shared.py``) — ``int(raw)`` wrapped in
``except (TypeError, ValueError): return default``. The fix routes every
request-supplied int parse through it.

THE DRIFT (why a count-agnostic pin, per ``pattern_count_agnostic_structural_drift_catch``):
besides the 2 live 500s, ~24 sibling sites hand-rolled their OWN
``try/except (TypeError, ValueError)`` around ``int(form.get(...))`` — correct,
but DIVERGENT: the protection lived in N per-site copies instead of the SSOT, so a
NEW ``int(form.get(...))`` added without its own try/except (exactly the def_id
bug) had nothing to catch it. Converging the whole class onto ``_safe_int`` makes
this pin UNMASKABLE — there is one protection, and the pin enforces it over every
site (a PROPERTY of the AST, never ``len(sites) == N``).

MEMBERSHIP PREDICATE (declared — PD#4; the pin's net ⊇ the migrated class):
a VIOLATION is a call to the builtin ``int`` whose first positional argument —
after unwrapping ``X or default`` (BoolOp) and ``X if c else d`` (IfExp) — is a
REQUEST-ACCESSOR, i.e. either

  * ``<recv>.get(...)``  — a ``.get`` call on a request-source receiver, or
  * ``<recv>[...]``      — a subscript of a request-source receiver,

where a REQUEST-SOURCE RECEIVER is an expression whose ROOT name is one of
``form`` / ``request`` / ``query_params`` / ``path_params`` (the canonical
``await request.form()`` binding and the Starlette request param maps). This is
keyed on the request-accessor receiver SHAPE — NOT on data-flow. Two deliberate
consequences (honest residuals):

  * ``int(<local>)`` where ``<local>`` is bound from a request value earlier in the
    SAME function — INCLUDING a closure-captured outer var read in a nested helper
    (``account_id_raw = request.query_params.get("account_id"); ... int(account_id_raw
    or 0)``) — is OUT of the net. This pin is SYNTACTIC (it keys on the call-site
    accessor shape) and is NOT interprocedural, so it cannot follow the
    outer-assign -> nested-use hop; catching it would need data-flow analysis. So a
    NEW closure-laundered ``int(<local-from-request>)`` is a DOCUMENTED RESIDUAL the
    pin can't cheaply catch — such a site is NOT automatically safe:
      - GUARDED launders (their own ``try/except (TypeError, ValueError)`` /
        ``continue``) stay individually guarded and are correctly out-of-net: e.g.
        ``profile.py`` retention/digest parses keep their ``continue`` (it FILTERS
        bad rows — a semantic ``_safe_int`` cannot replicate). Left as-is.
      - UNGUARDED launders were LIVE 500s and were FIXED in this change BY HAND (the
        pin neither did nor can catch the closure hop): the 6 HIPAA style-data sites
        ``int(account_id_raw or 0)`` — a non-numeric ``?account_id=abc`` makes the
        resolver return ``(None, err)`` -> the ``acct is None`` branch -> ``int("abc")``
        -> uncaught ValueError -> HTTP 500 across 6 endpoints, AND the crash destroys
        the §164.312(b) failure-audit row. (The 2 ``int(form.get("def_id") or 0)``
        actuator sites were also unguarded 500s, but those ARE request accessors —
        ``form.get`` — so the pin DOES enforce them going forward.) The behavioral
        regression tests below — NOT this syntactic pin — are the prevention for the
        closure-laundered class.
  * The ``int(<local>.get(...))`` sites on the OAuth/push paths are NOT inbound
    request bodies (correcting an earlier mis-framing — they are signed-token /
    external-API-response parses, not client request bodies):
      - ``oauth.py`` callback parses an itsdangerous-SIGNED STATE TOKEN we issued
        (``payload = serializer.loads(state); int(payload.get("acct"))``). A tampered
        value fails the signature BEFORE this line, so it stays a bare ``int()`` —
        out of the request-parse class, effectively safe.
      - ``oauth.py`` / ``push.py`` / ``integrations.py`` / ``ingestion_push.py`` parse
        the Gmail API register_watch RESPONSE (``int(data.get("expiration", 0))``),
        not a client request. As of this change these route through ``_safe_int`` too
        — a malformed provider ``expiration`` is a reachable 500 if Gmail's contract
        breaks (external-API robustness), so they get the SSOT as defense-in-depth
        even though the syntactic pin (request-accessor receiver only) does not flag
        a ``data``-rooted receiver (one operation-class at a time, PD#4).

Trusted receivers (``int(row["id"])``, ``int(user["id"])``, ``int(q.get(...))``
where ``q`` is a DB-loaded JSON column) are NOT request accessors and are NOT
flagged — coercing a DB/internal value is correct and must stay.

The walk routes through ``_pin_harness`` (R5b — no hand-rolled ``rglob``).
"""

from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth,
    enclosing_fn,
    parse_source,
    walk_src,
)

# Root receiver names that denote request-supplied input. ``form`` is the
# ``await request.form()`` binding used install-wide; ``request`` roots the
# ``request.query_params``/``request.path_params`` chains; the bare
# ``query_params``/``path_params`` names cover a local alias of those maps.
_REQUEST_ROOTS = frozenset({"form", "request", "query_params", "path_params"})


def _receiver_root(node: ast.AST) -> str | None:
    """Root Name id of an attribute/name receiver chain (``form`` for ``form``,
    ``request`` for ``request.query_params``), else None."""
    cur = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


def _is_request_source(recv: ast.AST) -> bool:
    return _receiver_root(recv) in _REQUEST_ROOTS


def _is_request_accessor(arg: ast.AST) -> bool:
    """True when ``arg`` reads request input via ``<req>.get(...)`` or
    ``<req>[...]`` — unwrapping ``X or d`` / ``X if c else d`` so the common
    ``int(form.get("k") or 0)`` shape is seen."""
    if isinstance(arg, ast.BoolOp):
        return any(_is_request_accessor(v) for v in arg.values)
    if isinstance(arg, ast.IfExp):
        return any(_is_request_accessor(v) for v in (arg.body, arg.test, arg.orelse))
    if (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "get"
        and _is_request_source(arg.func.value)
    ):
        return True
    if isinstance(arg, ast.Subscript) and _is_request_source(arg.value):
        return True
    return False


def _bare_request_int_lines(tree: ast.AST) -> list[int]:
    """Lines of every ``int(<request-accessor>)`` — the bare-parse shape the SSOT
    replaces. (Detector for the teeth; the suite test adds allow-list filtering.)"""
    hits: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "int"
            and node.args
            and _is_request_accessor(node.args[0])
        ):
            hits.append(node.lineno)
    return hits


def test_no_bare_int_on_request_accessor():
    """No ``int(<request-accessor>)`` anywhere under src/email_triage — every
    request-supplied int parse routes through ``_safe_int`` (never a 500)."""
    offenders: list[str] = []
    for _path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "int"
                and node.args
                and _is_request_accessor(node.args[0])
            ):
                continue
            fn = enclosing_fn(node)
            offenders.append(f"{rel}:{node.lineno} (in {fn})")
    assert not offenders, (
        "Bare int(<request-accessor>) found — a non-numeric form/query/path value "
        "raises an UNCAUGHT ValueError → HTTP 500 on attacker input (run18 #12 / "
        "#203, §164.308(a)(7) availability):\n  " + "\n  ".join(offenders)
        + "\nRoute it through _safe_int (web/routers/ui/_shared.py): "
        "`_safe_int(form.get(\"k\"), <default>)` — non-numeric falls back to the "
        "default instead of crashing. There is no allow-list: a site that "
        "must parse a request int WITHOUT the SSOT needs one, keyed (relpath, enclosing_fn), with a reason."
    )


# --------------------------------------------------------------------------
# Teeth — the detector flags the bare shapes (incl. `or 0` / subscript / the
# request.query_params chain) and does NOT flag _safe_int / trusted receivers.
# --------------------------------------------------------------------------
def test_pin_has_teeth():
    assert_pin_has_teeth(
        _bare_request_int_lines,
        bad_source='x = int(form.get("def_id") or 0)\n',   # the live def_id bug
        good_source='from m import _safe_int\nx = _safe_int(form.get("def_id"), 0)\n',
    )


def test_teeth_request_variants_flagged():
    # the `or 0` BoolOp shape, a plain .get, the query_params chain, a subscript
    assert _bare_request_int_lines(parse_source('x = int(form.get("k"))\n'))
    assert _bare_request_int_lines(parse_source('x = int(form.get("k") or 0)\n'))
    assert _bare_request_int_lines(
        parse_source('x = int(request.query_params.get("offset"))\n'))
    assert _bare_request_int_lines(parse_source('x = int(request.path_params["id"])\n'))
    assert _bare_request_int_lines(parse_source('x = int(form["user_id"])\n'))


def test_teeth_trusted_and_ssot_not_flagged():
    # _safe_int is the SSOT (not a bare int) — not flagged.
    assert not _bare_request_int_lines(parse_source('x = _safe_int(form.get("k"), 0)\n'))
    # Trusted DB-row / internal-dict receivers must stay int()-coerced.
    assert not _bare_request_int_lines(parse_source('x = int(row["id"])\n'))
    assert not _bare_request_int_lines(parse_source('x = int(user["id"])\n'))
    # A DB-loaded JSON column read via a local `q` is NOT a request accessor.
    assert not _bare_request_int_lines(parse_source('x = int(q.get("topic_id", 0))\n'))
    # _safe_int's OWN body — int(raw) on a plain param — is not a request accessor.
    assert not _bare_request_int_lines(parse_source('def _safe_int(raw, d=0):\n    return int(raw)\n'))
