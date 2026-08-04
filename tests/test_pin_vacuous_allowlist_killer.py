"""VALK — Vacuous Allow-List Killer meta-pin.

RATIONALE (2026-07-16, DA-F1 lesson): allow-lists in structural pins are
PROMISES that the exempted call-sites satisfy the invariant via an EXTERNAL
guarantee ("payload assembled externally + guaranteed to carry the key"). If
that guarantee is not itself pinned, the allow-list is a VACUOUS promise —
the pin ships green while the invariant is violated at every allow-listed
site.

DA-F1 shipped ``_FIRE_NOTIFICATION_KNOWN_CALLERS`` at
``tests/test_webhook_ssot_pins.py:239`` allowing
``email_triage/actions/notify.py::execute`` on the promise that the
notification payload guarantees an ``account_id`` key.
``NotifyAction._build_notification`` never wrote that key. Every notification
silently degraded to wildcard-only routing (D1 prod bug 2026-07-16 —
the scoped-webhook per-account routing feature shipped DOA).

INVARIANT this meta-pin enforces: every module-level allow-list collection
literal in ``tests/**/*.py`` whose NAME matches :data:`_ALLOWLIST_NAME_RE`
and whose value is a NON-EMPTY set / frozenset / dict / dict/set/frozenset
call must be REGISTERED in ``tests/valk_allowlist_registry.json`` with
either:

  * ``"enforced_by": "<file>::<function>"`` — the companion pin that PROVES
    the allow-list's promise. Sentinel ``"same_file"`` means the allow-list
    is consumed by a test in the same source file (baseline MVP; tighten
    follow-up replaces with explicit function name).
  * ``"exempt": "<one-line reason>"`` — no companion pin needed (e.g.
    baseline ratchet, teeth planted-string, no exempted sites at HEAD).

EMPTY allow-lists (zero literal members) carry no vacuous promise and are
NOT tracked. LOCAL allow-lists inside function bodies are NOT tracked (they
are private to their enclosing pin function).

**Growth ratchet** (opt-in): a registry entry MAY carry ``"size_at_seed":
N``; when present, the current allow-list size must be ``<= N`` unless
``"growth_ok": true``. Adding to an allow-list widens the exemption and
should force re-verification of the promise.

Prime Directive #6/#7 (pins obey the SSOT rule; census the censusers) —
this meta-pin self-registers as ``exempt`` and does not enumerate its own
allow-list-named symbols (it has none by construction).

See also: :mod:`test_pin_harness_adoption` (harness-adoption meta-pin) is
the DIFFERENT class of meta-pin — it enforces harness-USE, VALK enforces
allow-list DISCIPLINE.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re

from _pin_harness import iter_files, parse_module, relpath

_TESTS_ROOT = pathlib.Path(__file__).resolve().parent
_REGISTRY_PATH = _TESTS_ROOT / "valk_allowlist_registry.json"

# Name pattern for module-level allow-list-shaped symbols. Anchored at the
# leading underscore. Any of the words ALLOW / KNOWN / APPROVED / WHITELIST /
# ALLOWLIST / EXEMPT / CALLERS anywhere in the name after the leading `_`.
# NOT included: _OK / _SKIP / _SAFE — these overlap with unrelated symbols
# (constants, sentinels) and are better added case-by-case if a live vacuous
# exemption is found.
_ALLOWLIST_NAME_RE = re.compile(
    r"^_[A-Z][A-Z0-9_]*"
    r"(ALLOW|KNOWN|APPROVED|WHITELIST|ALLOWLIST|EXEMPT|CALLERS)"
    r"[A-Z0-9_]*$"
)


def _element_key(node: ast.AST) -> str:
    """Best-effort rendering of a collection member for the fail message."""
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Tuple):
        return "(" + ", ".join(_element_key(e) for e in node.elts) + ")"
    return ast.unparse(node) if hasattr(ast, "unparse") else "<expr>"


def _extract_members(value: ast.AST | None) -> list | None:
    """Return the literal members of a collection RHS, or ``None`` if the RHS
    is not a set / dict / frozenset literal. Empty list = empty collection
    (no vacuous promise; caller can still register but no enforcement fires).
    Non-collection RHS (re.compile / string / call other than
    frozenset/set/dict) returns ``None`` and the caller skips."""
    if value is None:
        return None
    if isinstance(value, ast.Set):
        return [_element_key(e) for e in value.elts]
    if isinstance(value, ast.Dict):
        return [_element_key(k) for k in value.keys if k is not None]
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        if value.func.id in ("frozenset", "set", "dict"):
            if not value.args:
                return []
            inner = value.args[0]
            if isinstance(inner, ast.Set):
                return [_element_key(e) for e in inner.elts]
            if isinstance(inner, ast.Dict):
                return [_element_key(k) for k in inner.keys if k is not None]
            if isinstance(inner, (ast.List, ast.Tuple)):
                return [_element_key(e) for e in inner.elts]
    return None


def _module_level_allow_lists(tree: ast.AST):
    """Yield ``(name, lineno, members)`` for every module-level allow-list
    collection literal whose name matches :data:`_ALLOWLIST_NAME_RE`. Skips
    assigns inside functions/classes."""
    if not isinstance(tree, ast.Module):
        return
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        for tgt in targets:
            if not isinstance(tgt, ast.Name):
                continue
            if not _ALLOWLIST_NAME_RE.match(tgt.id):
                continue
            members = _extract_members(value)
            if members is None:
                continue
            yield tgt.id, node.lineno, members


def _load_registry() -> dict:
    if not _REGISTRY_PATH.exists():
        return {"__schema": "v1", "entries": {}}
    return json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))


def _validate_entry(entry, key: str, tree: ast.AST) -> str | None:
    """Return an error string if entry is invalid; ``None`` if OK."""
    if not isinstance(entry, dict):
        return f"{key} — registry entry must be a JSON object"
    if "exempt" in entry:
        if not entry["exempt"] or not isinstance(entry["exempt"], str):
            return f"{key} — 'exempt' must be a non-empty string reason"
        return None
    enforced_by = entry.get("enforced_by")
    if not enforced_by:
        return f"{key} — must have 'enforced_by' (str) OR 'exempt' (str)"
    if not isinstance(enforced_by, str):
        return f"{key} — 'enforced_by' must be a string"
    if enforced_by == "same_file":
        has_test = False
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_"):
                has_test = True
                break
            if isinstance(n, ast.ClassDef) and n.name.startswith("Test"):
                if any(
                    isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and m.name.startswith("test_") for m in n.body
                ):
                    has_test = True
                    break
        if not has_test:
            return (
                f"{key} — enforced_by=same_file requires >= 1 test_* function "
                "(module-level def OR method on a Test* class) in the source file"
            )
        return None
    if "::" not in enforced_by:
        return (
            f"{key} — enforced_by={enforced_by!r} must be 'same_file' OR "
            "'<file>::<function>'"
        )
    ef_file, ef_fn = enforced_by.split("::", 1)
    ef_rel = ef_file[len("tests/"):] if ef_file.startswith("tests/") else ef_file
    ef_path = _TESTS_ROOT / ef_rel
    if not ef_path.exists():
        return f"{key} — enforced_by file {ef_file!r} does not exist"
    ef_tree = parse_module(ef_path)
    if ef_tree is None:
        return f"{key} — enforced_by file {ef_file!r} did not parse"
    # Accept both module-level `def test_foo` and `Test*.test_foo` class methods.
    module_fns = {
        n.name for n in ef_tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    class_methods: set[str] = set()
    for n in ef_tree.body:
        if isinstance(n, ast.ClassDef):
            for m in n.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    class_methods.add(f"{n.name}.{m.name}")
    if ef_fn in module_fns or ef_fn in class_methods:
        return None
    return (
        f"{key} — enforced_by function {ef_fn!r} not found in {ef_file} "
        "(module-level test_* def OR Test*.method form both accepted)"
    )


def test_every_allowlist_registered():
    registry = _load_registry()
    entries = registry.get("entries", {})
    stale = set(entries.keys())
    offenders: list[str] = []
    for path in iter_files(_TESTS_ROOT, "*.py"):
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path, base=_TESTS_ROOT)
        for name, lineno, members in _module_level_allow_lists(tree):
            key = f"{rel}::{name}"
            stale.discard(key)
            if not members:
                continue
            entry = entries.get(key)
            if entry is None:
                template = {"enforced_by": "same_file", "notes": ""}
                offenders.append(
                    f"UNREGISTERED: {key} at {rel}:{lineno} "
                    f"({len(members)} members)\n"
                    f"  Add to tests/valk_allowlist_registry.json[\"entries\"]:\n"
                    f"    \"{key}\": {json.dumps(template)}"
                )
                continue
            err = _validate_entry(entry, key, tree)
            if err:
                offenders.append(err)
                continue
            seed = entry.get("size_at_seed")
            if (isinstance(seed, int) and len(members) > seed
                    and not entry.get("growth_ok", False)):
                offenders.append(
                    f"GROWTH: {key} has {len(members)} members, "
                    f"size_at_seed={seed}. Adding to an allow-list widens "
                    "the exemption. Update tests/valk_allowlist_registry.json: "
                    "bump size_at_seed after re-verifying the promise still "
                    "holds (or set 'growth_ok': true)."
                )
    for key in sorted(stale):
        offenders.append(
            f"STALE: {key} in registry but no matching allow-list found — "
            "remove from tests/valk_allowlist_registry.json"
        )
    assert not offenders, (
        "VALK meta-pin (2026-07-16 DA-F1 lesson):\n\n"
        + "\n\n".join(offenders)
        + "\n\nSee module docstring for rationale + registry shape."
    )


def test_valk_has_teeth():
    """Planted-shape teeth: various shapes yield / do not yield correctly."""
    tree = ast.parse('_FOO_ALLOW = {"a", "b"}\n')
    hits = list(_module_level_allow_lists(tree))
    assert hits and hits[0][0] == "_FOO_ALLOW" and len(hits[0][2]) == 2

    tree = ast.parse("_BAR_ALLOW: dict = {}\n")
    hits = list(_module_level_allow_lists(tree))
    assert hits and hits[0][0] == "_BAR_ALLOW" and hits[0][2] == []

    tree = ast.parse("import re\n_URL_SAFE = re.compile(r'x')\n")
    assert not list(_module_level_allow_lists(tree)), (
        "re.compile is not an allow-list — must be ignored"
    )

    tree = ast.parse("_KNOWN_CALLERS = frozenset([('a.py', 'foo')])\n")
    hits = list(_module_level_allow_lists(tree))
    assert hits and hits[0][0] == "_KNOWN_CALLERS" and len(hits[0][2]) == 1

    tree = ast.parse("def f():\n    _V_ALLOW = {'a'}\n")
    assert not list(_module_level_allow_lists(tree)), (
        "local allow-list inside function body must be skipped"
    )

    # Names that don't match pattern are not yielded.
    tree = ast.parse('_MY_CONSTANT = {"a"}\n')
    assert not list(_module_level_allow_lists(tree))


def test_registry_schema():
    """Registry file exists, parses, has ``__schema`` = ``"v1"``,
    ``entries`` is a dict."""
    assert _REGISTRY_PATH.exists(), (
        f"VALK registry not found at {_REGISTRY_PATH} — bootstrap with "
        '{"__schema":"v1","entries":{}}.'
    )
    registry = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    assert registry.get("__schema") == "v1", "registry __schema must be 'v1'"
    assert isinstance(registry.get("entries"), dict), (
        "registry.entries must be a dict"
    )
