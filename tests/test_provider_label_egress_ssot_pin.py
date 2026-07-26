"""Provider-label egress SSOT pin (divergence census 2026-06-09 class #5).

Writing a label/category up to the upstream mailbox (``provider.apply_label``)
is a §164.502(e) egress of a PHI-adjacent string. The HIPAA gate that skips
that write in HIPAA mode was implemented once correctly (``AddLabelAction``)
and was **missing** on two automated triage paths — ``LabelAction`` and
``web/triage_one._apply_rule_provider_labels`` — which pushed labels on every
HIPAA triage run with no gate.

All five label-apply sinks now route through the single SSOT
``actions/provider_labels.push_provider_labels``, which owns the gate. This pin
is the count-agnostic teeth: a raw ``<x>.apply_label(...)`` **call** may appear
nowhere outside the SSOT module, so a new (or re-divergent) sink physically
cannot reach the provider without going through the gate.

Count-agnostic by construction: the check is "zero raw ``apply_label`` calls
outside the SSOT", an AST predicate over every call expression — never a
``len(sinks) == N`` assertion. It naturally ignores the provider ``def
apply_label`` method definitions (FunctionDef, not Call), the FastAPI route
handler also named ``apply_label`` (a def), and the differently-named
``apply_labels_to_message`` DB writer (different attribute).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, walk_src  # N-350 R31

# ``SRC_ROOT`` is the package root (``src/email_triage``) — the SAME base this
# pin used for its old ``SRC`` constant (``parents[1]/src/email_triage``), so
# the relpath form (``actions/provider_labels.py``) is unchanged and the
# allow-list key below needs no re-keying.
# Allow-list — the ONE module permitted to reach ``provider.apply_label``.
SSOT = SRC_ROOT / "actions" / "provider_labels.py"


def _apply_label_egress_lines(tree: ast.AST) -> list[int]:
    """Lines that *reach* ``provider.apply_label`` outside the SSOT.

    Teeth (DA review 2026-06-09): an attribute-name-keyed pin that only
    matches ``x.apply_label(...)`` CALLS is evadable. This flags EVERY way
    a re-divergent sink can grab the method:

    * any ``.apply_label`` **attribute access** — ``provider.apply_label(...)``
      (a call) AND ``fn = provider.apply_label`` (a bound-method grab passed
      to ``await fn(...)``); both are an ``ast.Attribute`` with
      ``attr == 'apply_label'``;
    * ``getattr(<expr>, "apply_label")`` — a string-keyed dynamic grab whose
      ``func`` is a bare ``Call`` (so the attribute form above misses it).

    Does NOT match ``async def apply_label(...)`` (a ``FunctionDef``, not an
    attribute access) nor ``apply_labels_to_message(...)`` (a different name).
    """
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and n.attr == "apply_label":
            out.append(n.lineno)
        elif (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "getattr"
            and len(n.args) >= 2
            and isinstance(n.args[1], ast.Constant)
            and n.args[1].value == "apply_label"
        ):
            out.append(n.lineno)
    return out


def test_no_raw_apply_label_call_outside_ssot():
    offenders = []
    for p, rel, tree in walk_src():
        if p == SSOT:
            continue
        locs = _apply_label_egress_lines(tree)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "A provider.apply_label reference (call, bound-method grab, or "
        "getattr) outside the egress SSOT actions/provider_labels.py — this "
        f"bypasses the §164.502(e) HIPAA gate: {offenders}. Route through "
        "email_triage.actions.provider_labels.push_provider_labels(...)."
    )


def test_ssot_defines_push_provider_labels():
    tree = parse_module(SSOT); assert tree is not None  # N-350 R31
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "push_provider_labels" in names


# --------------------------------------------------------------------------
# Behavioural teeth on the GATE itself (not just the funnel): if someone
# deletes the ``if hipaa:`` skip from the SSOT, these fail.
# --------------------------------------------------------------------------

class _RecordingProvider:
    name = "rec"

    def __init__(self, raises=None):
        self.calls: list[tuple[str, str]] = []
        self._raises = raises

    async def apply_label(self, message_id: str, label: str) -> None:
        self.calls.append((message_id, label))
        if self._raises is not None:
            raise self._raises


def _run(coro):
    import asyncio
    return asyncio.run(coro)


def test_gate_skips_provider_write_in_hipaa_mode():
    from email_triage.actions.provider_labels import push_provider_labels
    prov = _RecordingProvider()
    applied, skipped, errors = _run(
        push_provider_labels(prov, "m1", ["Lab-Results", "Billing"], hipaa=True)
    )
    # The §164.502(e) gate: nothing left the perimeter.
    assert prov.calls == []
    assert applied == []
    assert skipped == ["Lab-Results", "Billing"]
    assert errors == []


def test_applies_all_when_not_hipaa():
    from email_triage.actions.provider_labels import push_provider_labels
    prov = _RecordingProvider()
    applied, skipped, errors = _run(
        push_provider_labels(prov, "m1", ["a", "b"], hipaa=False)
    )
    assert prov.calls == [("m1", "a"), ("m1", "b")]
    assert applied == ["a", "b"]
    assert skipped == [] and errors == []


def test_not_implemented_skips_remainder():
    from email_triage.actions.provider_labels import push_provider_labels
    prov = _RecordingProvider(raises=NotImplementedError())
    applied, skipped, errors = _run(
        push_provider_labels(prov, "m1", ["a", "b", "c"], hipaa=False)
    )
    # Whole-provider lack of support → stop after the first, skip the rest.
    assert applied == []
    assert skipped == ["a", "b", "c"]
    assert errors == []
    assert len(prov.calls) == 1  # did not hammer the provider per-label


def test_per_label_error_isolated():
    from email_triage.actions.provider_labels import push_provider_labels
    prov = _RecordingProvider(raises=RuntimeError("boom"))
    applied, skipped, errors = _run(
        push_provider_labels(prov, "m1", ["a", "b"], hipaa=False)
    )
    # Generic failures don't abort the loop; each lands in errors as a
    # (label, detail, exc) triple so callers can log label= structured AND
    # preserve exc_info= (the live exception object).
    assert applied == []
    assert skipped == []
    assert [lbl for lbl, _, _ in errors] == ["a", "b"]
    assert all("boom" in detail for _, detail, _ in errors)
    assert all(isinstance(exc, RuntimeError) for _, _, exc in errors)


def test_empty_names_is_noop():
    from email_triage.actions.provider_labels import push_provider_labels
    prov = _RecordingProvider()
    for names in ([], None, ["", None]):
        applied, skipped, errors = _run(
            push_provider_labels(prov, "m1", names, hipaa=False)
        )
        assert (applied, skipped, errors) == ([], [], [])
    assert prov.calls == []


def test_pin_has_teeth(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "async def sink(provider, mid, label):\n"
        "    await provider.apply_label(mid, label)\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _apply_label_egress_lines(tree)


def test_pin_catches_getattr_evasion(tmp_path):
    """DA review 2026-06-09: ``getattr(provider, "apply_label")(...)`` must be
    flagged — a string-keyed dynamic grab that an attribute-only matcher
    misses."""
    bad = tmp_path / "g.py"
    bad.write_text(
        "async def sink(provider, mid, label):\n"
        '    fn = getattr(provider, "apply_label")\n'
        "    await fn(mid, label)\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _apply_label_egress_lines(tree)


def test_pin_catches_bound_method_evasion(tmp_path):
    """A bound-method grab ``fn = provider.apply_label; await fn(...)`` is an
    attribute ACCESS (not a call) and must still be flagged."""
    bad = tmp_path / "b.py"
    bad.write_text(
        "async def sink(provider, mid, label):\n"
        "    fn = provider.apply_label\n"
        "    await fn(mid, label)\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _apply_label_egress_lines(tree)


def test_pin_ignores_def_and_sibling_name(tmp_path):
    """A ``def apply_label`` and an ``apply_labels_to_message(...)`` call must
    NOT be flagged — the pin targets reaching ``provider.apply_label``, not the
    method definition or a differently-named helper."""
    ok = tmp_path / "p.py"
    ok.write_text(
        "async def apply_label(self, message_id, label):\n"
        "    return None\n"
        "def caller(conn, mid, acct, slugs):\n"
        "    return apply_labels_to_message(conn, mid, acct, slugs)\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _apply_label_egress_lines(tree)
