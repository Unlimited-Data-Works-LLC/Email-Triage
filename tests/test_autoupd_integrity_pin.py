"""hipaa-sme R3 (2026-10-25): the automatic updater heals MANIFEST-DRIVEN staleness
only. A prefix that no longer matches its own record (or whose record / the image's
manifest is unreadable) is possible tamper evidence under §164.312(c)(1); the app
alerts and waits, and never overwrites it as a routine update.

That only holds if two structural facts hold, so they are pinned over every site
(PD-1, never ``len(X) == N``):

1. **Integrity before drift (MUST-R3-1).** ``runtime_status`` runs
   ``_tree_integrity_refusal`` before it reads the manifest or classifies any
   drift. If drift were classified first, a tampered prefix would read
   ``security_drift`` / ``set_mismatch`` as soon as the manifest moved (every few
   days), and the automatic updater, which keys on the reason token, would heal it.
2. **Every refusal token is classified.** Each reason token the status funnel can
   produce is either manifest-driven drift (a ``refuse("<token>", ...)`` call in
   ``_drift_status``, or ``stale_ok``) or a member of
   ``embedding_bits.INTEGRITY_TOKENS``. A NEW token added without a ruling fails
   here, because an unclassified token would default to one side silently.

The behavioural twin (tampered prefix + moved manifest, no automatic update, the
URGENT alert, bytes unchanged) is ``tests/test_web/test_autoupd_integrity.py``.

SCOPE CAVEAT: the token scan reads string literals in the three status functions; a
token assembled at runtime from a variable is not seen. The order check follows
direct calls inside ``runtime_status``, not a call hidden behind a helper.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import assert_pin_has_teeth, parse_source, walk_src

from email_triage import embedding_bits as eb

_DOMAIN = "embedding_bits/__init__.py"
_STATUS_FUNCS = ("runtime_status", "_tree_integrity_refusal", "_drift_status")
_TOKEN = re.compile(r"^([a-z][a-z_]*):\s")


def _domain_tree() -> ast.AST:
    for _path, rel, tree in walk_src():
        if rel == _DOMAIN:
            return tree
    raise AssertionError(f"{_DOMAIN} not found under src/")


def _fn(tree: ast.AST, name: str) -> ast.AST | None:
    return next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name),
        None,
    )


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")


# ---------------------------------------------------------------------------
# 1. integrity before drift
# ---------------------------------------------------------------------------

#: What must come AFTER the integrity check inside ``runtime_status``.
_AFTER_INTEGRITY = ("_load_raw_manifest", "manifest_expected_versions", "_drift_status")


def integrity_order_violations(tree: ast.AST) -> list[str]:
    """Names called in ``runtime_status`` before ``_tree_integrity_refusal``
    (or the absence of that call, which is the worst case)."""
    fn = _fn(tree, "runtime_status")
    if fn is None:
        return ["runtime_status is missing"]
    first: dict[str, int] = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            first.setdefault(_call_name(node), node.lineno)
            first[_call_name(node)] = min(first[_call_name(node)], node.lineno)
    if "_tree_integrity_refusal" not in first:
        return ["runtime_status never calls _tree_integrity_refusal"]
    at = first["_tree_integrity_refusal"]
    return [
        f"{name} (line {first[name]}) comes before _tree_integrity_refusal (line {at})"
        for name in _AFTER_INTEGRITY
        if name in first and first[name] < at
    ]


def test_integrity_is_checked_before_any_drift_classification():
    assert integrity_order_violations(_domain_tree()) == []


def test_the_integrity_order_pin_has_teeth():
    drift_first = (
        "def runtime_status():\n"
        "    raw = _load_raw_manifest(p)\n"
        "    if wrong:\n"
        "        return _drift_status()\n"
        "    return _tree_integrity_refusal(m, r, t)\n"
    )
    never = "def runtime_status():\n    return _drift_status()\n"
    good = (
        "def runtime_status():\n"
        "    i = _tree_integrity_refusal(m, r, t)\n"
        "    raw = _load_raw_manifest(p)\n"
        "    return _drift_status()\n"
    )
    assert_pin_has_teeth(lambda t: integrity_order_violations(t), drift_first, good)
    assert_pin_has_teeth(lambda t: integrity_order_violations(t), never, good)


# ---------------------------------------------------------------------------
# 2. every refusal token is classified
# ---------------------------------------------------------------------------

def _append_arg_ids(fn: ast.AST) -> set[int]:
    """ids of every node inside a ``<list>.append(...)`` call in ``fn``.
    ``runtime_status`` builds its drift DETAIL fragments that way (``"stale: ..."``);
    a fragment is not a reason token."""
    ids: set[int] = set()
    for call in ast.walk(fn):
        if isinstance(call, ast.Call) and _call_name(call) == "append":
            ids.update(id(sub) for sub in ast.walk(call))
    return ids


def _produced_tokens(tree: ast.AST) -> tuple[set[str], set[str]]:
    """``(literal_tokens, drift_tokens)`` produced by the status funnel: literal
    ``"<token>: ..."`` reasons anywhere in the three functions (detail fragments
    appended to a list excluded), and the first argument of every ``refuse(...)`` /
    ``_drift_refusal(...)`` call."""
    literal: set[str] = set()
    drift: set[str] = set()
    for name in _STATUS_FUNCS:
        fn = _fn(tree, name)
        if fn is None:
            continue
        in_append = _append_arg_ids(fn)
        for node in ast.walk(fn):
            text = None
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            elif isinstance(node, ast.JoinedStr) and node.values:
                head = node.values[0]
                if isinstance(head, ast.Constant) and isinstance(head.value, str):
                    text = head.value
            if text and (m := _TOKEN.match(text)) and id(node) not in in_append:
                literal.add(m.group(1))
            if (
                isinstance(node, ast.Call)
                and _call_name(node) in ("refuse", "_drift_refusal")
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                drift.add(node.args[0].value)
    return literal, drift


def unclassified_tokens(tree: ast.AST, integrity: frozenset[str]) -> list[str]:
    literal, drift = _produced_tokens(tree)
    return sorted(literal - integrity - drift - {"stale_ok"})


def test_every_refusal_token_is_drift_or_a_ruled_integrity_token():
    assert unclassified_tokens(_domain_tree(), eb.INTEGRITY_TOKENS) == []


def test_every_integrity_token_is_actually_produced():
    literal, _drift = _produced_tokens(_domain_tree())
    assert eb.INTEGRITY_TOKENS <= literal, sorted(eb.INTEGRITY_TOKENS - literal)


def test_the_four_ruled_integrity_tokens_and_none_other():
    """hipaa-sme R3: no token moves. A change to this set is a compliance ruling,
    not a refactor."""
    assert eb.INTEGRITY_TOKENS == frozenset({
        "disk_marker_mismatch", "duplicate_versions", "marker_invalid", "manifest_unreadable",
    })


def test_drift_and_integrity_tokens_are_disjoint():
    _literal, drift = _produced_tokens(_domain_tree())
    assert drift and not (drift & eb.INTEGRITY_TOKENS), drift & eb.INTEGRITY_TOKENS


def test_the_token_classification_pin_has_teeth():
    planted = parse_source(
        "def runtime_status():\n"
        "    return RuntimeStatus(state=REFUSED, reason='brand_new_refusal: x')\n"
    )
    assert unclassified_tokens(planted, eb.INTEGRITY_TOKENS) == ["brand_new_refusal"]
    ok = parse_source(
        "def runtime_status():\n"
        "    return RuntimeStatus(state=REFUSED, reason='marker_invalid: x')\n"
    )
    assert unclassified_tokens(ok, eb.INTEGRITY_TOKENS) == []


def test_status_properties_follow_the_token_set():
    for token in eb.INTEGRITY_TOKENS:
        st = eb.RuntimeStatus(state=eb.STATE_REFUSED, reason=f"{token}: x")
        assert st.integrity_refusal and not st.auto_updatable
    for token in ("set_mismatch", "security_drift"):
        st = eb.RuntimeStatus(state=eb.STATE_REFUSED, reason=f"{token}: x")
        assert not st.integrity_refusal and st.auto_updatable
    stale = eb.RuntimeStatus(state=eb.STATE_STALE_OK, reason="stale_ok: x")
    assert not stale.integrity_refusal and stale.auto_updatable
    ok = eb.RuntimeStatus(state=eb.STATE_OK, reason="ok")
    assert not ok.auto_updatable
