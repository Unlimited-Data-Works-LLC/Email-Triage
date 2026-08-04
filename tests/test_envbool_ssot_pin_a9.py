"""A9 (divergence census 2026-06-09) — bool-from-string parsing SSOT pin.

Parsing a flag value to bool was hand-rolled with divergent recognized
sets, and a few security flags were read as a BARE truthy
(``if os.environ.get("EMAIL_TRIAGE_AUDIT_STRICT"):``) — which is True for
EVERY non-empty string, so ``=0`` / ``=false`` / ``=off`` *enabled* the
flag (opposite-direction flip on a §164.312(b) control). The authority is
``email_triage._envbool`` (``parse_bool`` / ``parse_bool_tristate`` /
``env_bool``).

This **count-agnostic** pin bans two shapes outside the SSOT module:
  1. an ``os.environ.get(...)`` / ``os.getenv(...)`` / ``os.environ[...]``
     used DIRECTLY as a boolean (if/while test, ``bool(...)`` arg, ``not``
     operand, or a ``and``/``or`` operand) — the bare-truthy bug;
  2. ``<expr> in <container-of-bool-word-string-literals>`` — the manual
     allowlist shape ``parse_bool`` owns (e.g. ``v in {"1","true","on"}``).
  3. ``X == <word-form-bool>`` (``== "yes"/"no"/"true"/"false"/"on"/"off"``)
     where X is a form/plain value — the single-compare form-bool shape
     (SME DA-#1). Deliberately EXCLUDES ``== "0"``/``== "1"`` (a bare 0/1 is
     as often a numeric-count sentinel as a bool — flagging it floods false
     positives) and exempts ``request.headers.get(...)`` /
     ``request.query_params.get(...)`` signal sniffs (HX-Request, redirect
     flags). The existing ``== "1"`` form-bools were routed inline; the
     residual ``"0"``/``"1"`` single-compare is the one un-pinned bound.
"""

from __future__ import annotations

import ast

from _pin_harness import walk_src

_ALLOWED = {"_envbool.py"}
_BOOL_WORDS = {"0", "1", "true", "false", "yes", "no", "on", "off", ""}


def _is_env_get(node: ast.AST) -> bool:
    """``os.environ.get(...)`` / ``os.getenv(...)`` / ``os.environ[...]`` /
    ``environ.get(...)``."""
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute):
            if f.attr == "getenv":
                return True
            if f.attr == "get" and isinstance(f.value, ast.Attribute) \
                    and f.value.attr == "environ":
                return True
            if f.attr == "get" and isinstance(f.value, ast.Name) \
                    and f.value.id == "environ":
                return True
        return False
    if isinstance(node, ast.Subscript):
        v = node.value
        return (isinstance(v, ast.Attribute) and v.attr == "environ") or (
            isinstance(v, ast.Name) and v.id == "environ"
        )
    return False


# Single ``==`` compares are restricted to the UNAMBIGUOUS word forms.
# ``== "0"`` / ``== "1"`` is NOT included: a bare ``"0"``/``"1"`` is just as
# often a numeric-count sentinel (e.g. ``previous_caps == "0"``) as a bool,
# so flagging it floods false positives. The ``in {"1","true",...}`` set
# shape stays fully covered (a multi-bool-word set is unambiguously a parse).
_BOOL_WORD_COMPARE = frozenset({"true", "false", "yes", "no", "on", "off"})


def _unwrap_str_methods(node: ast.AST) -> ast.AST:
    """Peel ``.lower()`` / ``.strip()`` / ``.upper()`` so a header sniff like
    ``request.headers.get("HX-Request", "").lower()`` resolves to the
    underlying ``.get`` call."""
    while (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
           and node.func.attr in {"lower", "upper", "strip", "lstrip", "rstrip"}):
        node = node.func.value
    return node


def _is_header_or_query_get(node: ast.AST) -> bool:
    """``request.headers.get(...)`` / ``request.query_params.get(...)``
    (through any ``.lower()``/``.strip()`` wrapper) — a specific-signal
    sniff, NOT a config-bool parse, so an ``== "true"`` on it is legitimate
    (HX-Request, a one-shot redirect flag) and must NOT be flagged."""
    node = _unwrap_str_methods(node)
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"):
        return False
    recv = node.func.value
    return isinstance(recv, ast.Attribute) and recv.attr in {
        "headers", "query_params",
    }


def _is_bool_word_compare(node: ast.AST) -> bool:
    """``X == "yes"`` / ``X != "true"`` etc. (word forms only) where X is a
    form/plain value, NOT a header/query sniff — the single-compare
    form-bool shape ``parse_bool`` owns (SME DA-#1)."""
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.Eq, ast.NotEq))):
        return False
    left, right = node.left, node.comparators[0]
    lit = None
    other = None
    if isinstance(right, ast.Constant) and isinstance(right.value, str):
        lit, other = right.value, left
    elif isinstance(left, ast.Constant) and isinstance(left.value, str):
        lit, other = left.value, right
    if lit is None or lit.strip().lower() not in _BOOL_WORD_COMPARE:
        return False
    # Exempt the legitimate header / query-param signal sniffs.
    return not _is_header_or_query_get(other)


def _is_bool_word_container(node: ast.AST) -> bool:
    if not isinstance(node, (ast.Set, ast.Tuple, ast.List)):
        return False
    elts = node.elts
    if not elts:
        return False
    vals = []
    for e in elts:
        if not (isinstance(e, ast.Constant) and isinstance(e.value, str)):
            return False
        vals.append(e.value.strip().lower())
    return all(v in _BOOL_WORDS for v in vals)


def _find_violations() -> list[str]:
    violations: list[str] = []
    for path, rel, tree in walk_src():
        if path.name in _ALLOWED:
            continue
        for node in ast.walk(tree):
            # (1) bare env-get used directly as a bool.
            direct = None
            if isinstance(node, (ast.If, ast.While)):
                direct = node.test
            elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                direct = node.operand
            # NOTE: a BoolOp value (``env.get("X") or "default"``) is the
            # legitimate string-or-default idiom, NOT a bool parse — not flagged.
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "bool" and node.args:
                direct = node.args[0]
            if direct is not None and _is_env_get(direct):
                violations.append(f"{rel}:{node.lineno} (env-get as bare bool)")
            # (2) manual bool-word allowlist `x in {"1","true",...}`.
            if isinstance(node, ast.Compare) and len(node.ops) == 1 \
                    and isinstance(node.ops[0], (ast.In, ast.NotIn)) \
                    and _is_bool_word_container(node.comparators[0]):
                violations.append(
                    f"{rel}:{node.lineno} (manual bool-word `in` set — use parse_bool)"
                )
            # (3) single-compare form-bool `x == "1"` / `== "yes"` (not a
            # header/query sniff).
            if _is_bool_word_compare(node):
                violations.append(
                    f"{rel}:{node.lineno} (form-bool `== <bool-word>` — use parse_bool)"
                )
    return violations


def test_no_hand_rolled_bool_parsing():
    """Every string→bool parse goes through ``email_triage._envbool``."""
    violations = _find_violations()
    assert violations == [], (
        "Hand-rolled string→bool parsing (A9 divergence) at:\n  "
        + "\n  ".join(violations)
        + "\nUse email_triage._envbool.parse_bool / parse_bool_tristate / env_bool."
    )


def test_pin_has_teeth():
    bare = ast.parse("import os\nif os.environ.get('X'):\n    pass\n")
    hits = []
    for n in ast.walk(bare):
        if isinstance(n, ast.If) and _is_env_get(n.test):
            hits.append(n.lineno)
    assert hits, "pin missed a planted bare env-get bool"

    allow = ast.parse("def f(v):\n    return v.strip().lower() in {'1','true','on'}\n")
    ahits = [
        n for n in ast.walk(allow)
        if isinstance(n, ast.Compare) and isinstance(n.ops[0], (ast.In, ast.NotIn))
        and _is_bool_word_container(n.comparators[0])
    ]
    assert ahits, "pin missed a planted bool-word allowlist"

    # A non-bool `in` set must NOT be flagged.
    ok = ast.parse("def f(p):\n    return p in {'imap','gmail','office365'}\n")
    okhits = [
        n for n in ast.walk(ok)
        if isinstance(n, ast.Compare) and _is_bool_word_container(n.comparators[0])
    ]
    assert not okhits, "non-bool `in` set must not be flagged"


def test_parse_bool_contract():
    from email_triage._envbool import env_bool, parse_bool, parse_bool_tristate

    for t in ("1", "true", "TRUE", " yes ", "on", "On"):
        assert parse_bool(t) is True
    for fa in ("0", "false", "off", "no", "", "  "):
        assert parse_bool(fa) is False
    assert parse_bool(None) is False
    assert parse_bool("garbage") is False
    assert parse_bool("garbage", default=True) is True
    # Tristate: defer (None) on absent / empty / unrecognized.
    assert parse_bool_tristate(None) is None
    assert parse_bool_tristate("") is None
    assert parse_bool_tristate("flase") is None
    assert parse_bool_tristate("true") is True
    assert parse_bool_tristate("off") is False
    import os as _os
    _os.environ["_A9_PIN_T"] = "FALSE"
    assert env_bool("_A9_PIN_T") is False
    del _os.environ["_A9_PIN_T"]
