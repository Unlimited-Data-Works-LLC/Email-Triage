"""BAA runtime-egress gate — count-agnostic structural pin (census N-63).

The live defect: the style-learning *distill* path loaded an ``ai_backends``
backend and sent a HIPAA account's PHI-bearing style corpus to it via
``chat_complete`` with **no runtime BAA check** — while the classifier path
DID gate (``is_safe_for_hipaa``). A HIPAA account pointed at a non-BAA /
expired backend egressed PHI to an uncertified subprocessor
(§164.502(a)(1) impermissible disclosure / §164.308(b)(1) BAA-required).

The fix planted a fail-closed BAA chokepoint in ``load_backend`` (a
``require_baa_certified`` flag → :class:`BackendBAARequiredError`) and routed
the single BAA-validity rule through ONE SSOT predicate
(``baa_expiry.is_backend_baa_valid_for_phi``) used by BOTH the runtime gate
and the account-setup selector gate.

This pin keeps the net complete as the code evolves, per
``pattern_count_agnostic_structural_drift_catch`` — a property over EVERY
site, never ``len(...) == N``:

  * Invariant 1 (interprocedural seam) — EVERY ``load_backend(...)`` call in
    the ``style_learning`` package (the PHI-egress distill actuators) must
    pass a ``require_baa_certified=`` keyword. A NEW distill module / a new
    call inherits the requirement; a refactor can't silently drop the flag.
  * Invariant 2 (one SSOT, no re-inline) — no module outside ``baa_expiry``
    may hand-roll the BAA-validity rule (a boolean that mixes a
    ``baa_certified`` read with a ``baa_expires_at`` comparison). That inline
    shape is exactly what drifted (the selector gate had it; the runtime path
    had nothing). New gates must call ``is_backend_baa_valid_for_phi``.
  * Invariant 3 (the SSOT predicate is correct + fail-closed).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

# Back-compat aliases so the detector/test bodies below read unchanged. The
# walk / relpath / parse scaffolding now lives in the shared harness
# (tests/_pin_harness.py, R5b) so this pin cannot drift in its scoping.
SRC = SRC_ROOT
STYLE_LEARNING = SRC_ROOT / "style_learning"


# --------------------------------------------------------------------------
# Invariant 1 — every load_backend call in style_learning carries the flag.
# --------------------------------------------------------------------------
def _load_backend_calls(tree: ast.AST) -> list[ast.Call]:
    """Return the Call nodes that INVOKE load_backend, AND that carry its
    keyword arguments — either a direct ``load_backend(...)`` OR the
    interprocedural dispatcher seam ``db_call(load_backend, ..., require_...)``
    where load_backend is a positional arg and the kwargs ride on db_call
    (PD#2 — pin the seam, not the source, or it's blind by construction)."""
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = (
            f.id if isinstance(f, ast.Name)
            else f.attr if isinstance(f, ast.Attribute)
            else None
        )
        # (a) direct call: load_backend(...) — kwargs on this node.
        if name == "load_backend":
            out.append(n)
            continue
        # (b) dispatcher seam: X(load_backend, ...) — load_backend passed as
        # a positional callable; the kwargs (require_baa_certified=) ride on
        # the dispatcher Call, so return THAT node for the kwarg check.
        if any(isinstance(a, ast.Name) and a.id == "load_backend"
               for a in n.args):
            out.append(n)
    return out


def test_every_load_backend_call_passes_require_baa_flag():
    """Scope is ALL of src/ (not just style_learning/) — a NEW PHI-egress
    caller of load_backend anywhere inherits the requirement (DA should-fix:
    a future style_export/ or a route-direct distill must not be born exempt).
    Today the only two call sites are the style-learning distill actuators; a
    legitimate future NON-PHI caller passes require_baa_certified=False
    explicitly, documenting the decision (PD#2).

    Scoping limit (db-sme): the seam detector matches the literal
    db_call(load_backend, ...) shape. A future wrapper (functools.partial, a
    local alias `fn = load_backend; db_call(fn, ...)`) would slip past while a
    direct call elsewhere keeps seen_any True. If you add such an indirection,
    extend _load_backend_calls to follow it."""
    offenders: list[str] = []
    seen_any = False
    for mod in iter_src_files():
        tree = parse_module(mod)
        if tree is None:
            continue
        for call in _load_backend_calls(tree):
            seen_any = True
            kwds = {k.arg for k in call.keywords if k.arg}
            if "require_baa_certified" not in kwds:
                rel = relpath(mod)
                offenders.append(f"{rel}:{call.lineno}")
    assert seen_any, (
        "no load_backend() call found in src/ — the scanner is blind "
        "(renamed import? wrapper? alias?). Re-point this pin."
    )
    assert not offenders, (
        "a load_backend() call omits require_baa_certified= : "
        f"{offenders}. If it is a PHI-egress path a HIPAA account's PHI could "
        "reach an uncertified/expired backend (census N-63) — pass "
        "require_baa_certified=is_account_hipaa(account_dict). If it is a "
        "non-PHI path, pass require_baa_certified=False explicitly to record "
        "the decision."
    )


# --------------------------------------------------------------------------
# Invariant 2 — the BAA-validity rule lives in ONE SSOT; no inline re-derive.
# --------------------------------------------------------------------------
def _refs_name(node: ast.AST, needle: str) -> bool:
    """True if `node` references the string-literal key or attr `needle`."""
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and n.value == needle:
            return True
        if isinstance(n, ast.Attribute) and n.attr == needle:
            return True
        if isinstance(n, ast.Name) and n.id == needle:
            return True
    return False


def _has_inline_baa_rule(tree: ast.AST) -> list[int]:
    """Lines of a boolean test that mixes a baa_certified read AND a
    baa_expires_at comparison — the hand-rolled BAA-validity shape."""
    hits: list[int] = []
    for n in ast.walk(tree):
        # The gate shape is an `if`/BoolOp whose test references BOTH the
        # certified flag and an expiry comparison.
        test = None
        if isinstance(n, ast.If):
            test = n.test
        elif isinstance(n, ast.BoolOp):
            test = n
        if test is None:
            continue
        if not _refs_name(test, "baa_certified"):
            continue
        # an expiry comparison: a Compare node anywhere in the test that
        # touches baa_expires_at
        has_expiry_cmp = any(
            isinstance(c, ast.Compare) and _refs_name(c, "baa_expires_at")
            for c in ast.walk(test)
        )
        if has_expiry_cmp:
            hits.append(getattr(n, "lineno", 0))
    return hits


def test_no_inline_baa_validity_rule_outside_ssot():
    offenders: list[str] = []
    for mod in iter_src_files():
        rel = relpath(mod)
        if rel == "baa_expiry.py":
            continue  # the SSOT home — the rule is allowed to live here
        tree = parse_module(mod)
        if tree is None:
            continue
        for ln in _has_inline_baa_rule(tree):
            offenders.append(f"{rel}:{ln}")
    assert not offenders, (
        "an inline BAA-validity rule (baa_certified AND an expiry compare) "
        f"was found outside baa_expiry.py: {offenders}. Route it through "
        "baa_expiry.is_backend_baa_valid_for_phi — a second copy of the "
        "expiry boundary WILL drift (census N-63 / PD#5)."
    )


# --------------------------------------------------------------------------
# Invariant 3 — the SSOT predicate is correct + fail-closed.
# --------------------------------------------------------------------------
def test_predicate_truth_table_is_fail_closed():
    from datetime import date

    from email_triage.baa_expiry import is_backend_baa_valid_for_phi as v
    today = date(2026, 6, 10)

    # Valid ONLY for certified + parseable + future expiry.
    assert v(baa_certified=1, baa_expires_at="2099-01-01", today=today) is True
    # Fail-closed on every degenerate input:
    assert v(baa_certified=0, baa_expires_at="2099-01-01", today=today) is False
    assert v(baa_certified=1, baa_expires_at="2000-01-01", today=today) is False
    # Expiry == today → INVALID (boundary mirrors the selector's <= today).
    assert v(baa_certified=1, baa_expires_at="2026-06-10", today=today) is False
    assert v(baa_certified=1, baa_expires_at=None, today=today) is False
    assert v(baa_certified=1, baa_expires_at="not-a-date", today=today) is False
    # Empty-string expiry is the most likely real-world bad DB row
    # (operator-entered text) → _parse_expiry returns None → fail closed
    # (hipaa-sme should-fix: pin it so a _parse_expiry refactor can't regress).
    assert v(baa_certified=1, baa_expires_at="", today=today) is False
    # The day before expiry is still valid.
    assert v(baa_certified=1, baa_expires_at="2026-06-11", today=today) is True


# --------------------------------------------------------------------------
# Teeth — both structural invariants must catch a planted regression.
# --------------------------------------------------------------------------
def test_invariant1_has_teeth():
    ungated = ast.parse(
        "async def distill(acct):\n"
        "    adapter = await db_call(load_backend, bid, db_conn=db)\n"
    )
    calls = _load_backend_calls(ungated)
    assert calls and "require_baa_certified" not in {
        k.arg for k in calls[0].keywords if k.arg
    }


def test_invariant2_has_teeth():
    inline = ast.parse(
        "def gate(b):\n"
        "    if (not b.get('baa_certified')\n"
        "            or str(b['baa_expires_at']) <= today):\n"
        "        return False\n"
    )
    assert _has_inline_baa_rule(inline), (
        "the inline-BAA-rule detector failed to flag a planted hand-roll"
    )


def test_invariant2_ssot_call_is_not_flagged():
    """A gate that DELEGATES to the SSOT (no inline expiry compare) passes."""
    ok = ast.parse(
        "def gate(b):\n"
        "    if (not b.get('enabled')\n"
        "            or not is_backend_baa_valid_for_phi(\n"
        "                baa_certified=b.get('baa_certified'),\n"
        "                baa_expires_at=b.get('baa_expires_at'))):\n"
        "        return False\n"
    )
    assert not _has_inline_baa_rule(ok)
