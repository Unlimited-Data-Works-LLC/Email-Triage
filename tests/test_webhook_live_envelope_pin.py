"""Count-agnostic pin for the wizard preview's last-real-event store (punch 414).

PD#1/PD#2: the store (``web/_webhook_live_envelope.LastEnvelopeStore``) holds
envelopes, so who may WRITE it and who may READ it are properties over every
site in ``src/``, not a list of the sites that exist today:

* **Writer.** Every ``.record_fire(...)`` call is made from the dispatcher
  module and passes ``is_hipaa=`` by keyword, and nothing outside the store
  module assigns into ``_by_target``. The store's own ``record_fire`` refuses
  unless ``is_hipaa is not False`` is false (the belt, spec DEC-2).
* **Reader.** Every function that calls ``.last_fire(...)`` also calls the
  read gate ``live_refusal_reason`` AND the witness emitter
  ``record_webhook_preview_live_render`` (the suspenders and spec DEC-3), so a
  new reader cannot show an envelope that skipped either.

SCOPE CAVEAT (PD#2): the pin follows calls by NAME inside one function. It does
not follow a store reference passed to another module's helper, an envelope
copied out of the store into a dict that is returned elsewhere, or a call made
through ``getattr(store, "last_fire")``.
"""

from __future__ import annotations

import ast

from _pin_harness import assert_pin_has_teeth, parse_source, walk_src

STORE_MODULE = "web/_webhook_live_envelope.py"
# Repo-relative (PD#6): the only module allowed to call ``record_fire``.
WRITER_MODULES = {"web/events.py"}
GATE = "live_refusal_reason"
WITNESS = "record_webhook_preview_live_render"


def _call_name(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def _unkeyworded_record_fire(tree: ast.AST) -> list[int]:
    """Lines of ``.record_fire(...)`` calls that do not pass ``is_hipaa=``."""
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _call_name(n) == "record_fire"
        and not any(k.arg == "is_hipaa" for k in n.keywords)
    ]


def _record_fire_lines(tree: ast.AST) -> list[int]:
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _call_name(n) == "record_fire"
    ]


def _by_target_writes(tree: ast.AST) -> list[int]:
    """Lines that assign or delete through ``<x>._by_target[...]``."""
    hits = []
    for n in ast.walk(tree):
        targets = []
        if isinstance(n, (ast.Assign, ast.Delete)):
            targets = n.targets
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
            targets = [n.target]
        for t in targets:
            if (isinstance(t, ast.Subscript)
                    and isinstance(t.value, ast.Attribute)
                    and t.value.attr == "_by_target"):
                hits.append(n.lineno)
    return hits


def _ungated_readers(tree: ast.AST) -> list[str]:
    """Functions calling ``.last_fire(...)`` without the gate AND the witness."""
    bad = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = {
            _call_name(c) for c in ast.walk(fn) if isinstance(c, ast.Call)
        }
        # ``record_webhook_preview_live_render`` is passed to ``db_call`` as a
        # value, not called, so count a bare Name reference as well.
        names |= {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        if "last_fire" in names and not {GATE, WITNESS} <= names:
            bad.append(fn.name)
    return bad


def _belt_refuses_non_false(tree: ast.AST) -> bool:
    """``LastEnvelopeStore.record_fire`` returns early on ``is_hipaa is not False``."""
    for cls in ast.walk(tree):
        if not (isinstance(cls, ast.ClassDef) and cls.name == "LastEnvelopeStore"):
            continue
        for fn in cls.body:
            if not (isinstance(fn, ast.FunctionDef) and fn.name == "record_fire"):
                continue
            for stmt in fn.body:
                if (isinstance(stmt, ast.If)
                        and isinstance(stmt.test, ast.Compare)
                        and isinstance(stmt.test.left, ast.Name)
                        and stmt.test.left.id == "is_hipaa"
                        and isinstance(stmt.test.ops[0], ast.IsNot)
                        and isinstance(stmt.test.comparators[0], ast.Constant)
                        and stmt.test.comparators[0].value is False
                        and any(isinstance(b, ast.Return) for b in stmt.body)):
                    return True
    return False


def test_record_fire_only_from_the_dispatcher_and_always_keyworded():
    for _path, rel, tree in walk_src():
        if rel == STORE_MODULE:
            continue
        lines = _record_fire_lines(tree)
        if lines:
            assert rel in WRITER_MODULES, (
                f"{rel}:{lines} calls LastEnvelopeStore.record_fire; only "
                f"{sorted(WRITER_MODULES)} may (the dispatcher owns the belt)"
            )
        assert not _unkeyworded_record_fire(tree), (
            f"{rel}:{_unkeyworded_record_fire(tree)} calls record_fire without "
            "an explicit is_hipaa= keyword"
        )


def test_by_target_written_only_inside_the_store_module():
    for _path, rel, tree in walk_src():
        if rel == STORE_MODULE:
            continue
        assert not _by_target_writes(tree), (
            f"{rel}:{_by_target_writes(tree)} writes the store's _by_target "
            "directly; route through LastEnvelopeStore.record_fire (the belt)"
        )


def test_store_belt_refuses_anything_but_literal_false():
    for _path, rel, tree in walk_src():
        if rel == STORE_MODULE:
            assert _belt_refuses_non_false(tree), (
                "LastEnvelopeStore.record_fire must return before storing "
                "when `is_hipaa is not False` (spec DEC-2 belt, fail closed)"
            )
            return
    raise AssertionError(f"{STORE_MODULE} not found")


def test_every_store_reader_runs_the_gate_and_the_witness():
    for _path, rel, tree in walk_src():
        if rel == STORE_MODULE:
            continue
        bad = _ungated_readers(tree)
        assert not bad, (
            f"{rel}: {bad} call LastEnvelopeStore.last_fire without both "
            f"{GATE} (read-side HIPAA gate) and {WITNESS} (§164.312(b) witness)"
        )


def test_the_reader_scan_sees_the_real_reader():
    """Guard against a green-and-blind scan: the real reader must be seen."""
    seen = []
    for _path, rel, tree in walk_src():
        if rel == STORE_MODULE:
            continue
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                isinstance(c, ast.Call) and _call_name(c) == "last_fire"
                for c in ast.walk(fn)
            ):
                seen.append((rel, fn.name))
    assert seen, "no .last_fire reader found in src; the reader pin is blind"


def test_the_writer_scan_sees_the_real_writer():
    seen = [
        rel for _p, rel, tree in walk_src()
        if rel != STORE_MODULE and _record_fire_lines(tree)
    ]
    assert seen and set(seen) <= WRITER_MODULES, (
        f"expected the dispatcher to call record_fire, saw {seen}"
    )


def test_pin_has_teeth():
    assert_pin_has_teeth(
        _unkeyworded_record_fire,
        "def f(s):\n    s.record_fire(0, env)\n",
        "def f(s):\n    s.record_fire(0, env, is_hipaa=h)\n",
    )
    assert_pin_has_teeth(
        _by_target_writes,
        "def f(s):\n    s._by_target[0] = 1\n",
        "def f(s):\n    s.record_fire(0, e, is_hipaa=False)\n",
    )
    assert_pin_has_teeth(
        _ungated_readers,
        "def f(s):\n    return s.last_fire(0)\n",
        "def f(s):\n    live_refusal_reason()\n    x = record_webhook_preview_live_render\n    return s.last_fire(0)\n",
    )
    assert not _belt_refuses_non_false(parse_source(
        "class LastEnvelopeStore:\n"
        "    def record_fire(self, k, e, *, is_hipaa, account_id):\n"
        "        if is_hipaa:\n            return False\n"
    )), "belt detector accepted a truthiness check (None would store)"
    assert _belt_refuses_non_false(parse_source(
        "class LastEnvelopeStore:\n"
        "    def record_fire(self, k, e, *, is_hipaa, account_id):\n"
        "        if is_hipaa is not False:\n            return False\n"
    ))
