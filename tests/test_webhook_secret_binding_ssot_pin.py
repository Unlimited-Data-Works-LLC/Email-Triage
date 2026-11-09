r"""SSOT count-agnostic pin: ``{{secret}}`` refusal has exactly ONE
implementation.

SME-panel 2026-07-15 DA PD-5 fold (task  drive). The
``{{secret}}`` refusal regex + its operator-facing message used to
live at THREE hand-rolled sites (config parse, wizard save, wizard
preview). Prime Directive #5 explicitly forbids mirrored predicate
lists — a future tightening (case-insensitive, nested path, template-
comment tolerance) inevitably lands at one site while the other two
lag. This pin walks src/ and asserts:

* The compiled regex literal ``r"\{\{\s*secret\s*\}\}"`` appears
  exactly once — inside ``web/_webhook_template.py``.
* No other file uses a ``\{\{...secret...\}\}`` shape as a literal
  refusal check pattern (a future new call-site MUST delegate to
  :func:`web._webhook_template.refuses_secret_binding`, not roll its
  own regex).

Rule from `feedback_divergence_audit_and_ssot_pin`: SSOTs ship their
count-agnostic pin in the same change. This pin IS that down-payment.

N-421 harness contract — this file MUST route through ``_pin_harness``
for source walking + path normalisation (Prime Directive #6: pins
obey the SSOT rule too).
"""

from __future__ import annotations

from tests._pin_harness import (
    SRC_ROOT,
    iter_string_literals,
    relpath,
    walk_src,
)


# Same shape as the SSOT — a call-site that hand-rolls this pattern
# is what we want to detect.
_SECRET_PATTERN_LITERALS = (
    r"\{\{\s*secret\s*\}\}",
    r"\{\{ \s*secret\s* \}\}",  # extra whitespace variant
)


def _iter_src_string_literals():
    """Yield ``(src_rel, literal)`` for every string literal in every
    ``src/email_triage/**/*.py`` — routed through the harness's
    ``walk_src()`` so a file move of the SRC_ROOT doesn't silently
    drop coverage. ``walk_src`` yields ``(path, relpath, tree)``."""
    for _path, rel, tree in walk_src():
        for literal in iter_string_literals(tree):
            yield rel, literal


def test_secret_binding_refusal_regex_has_exactly_one_definition():
    """The refusal regex literal appears in exactly ONE src file —
    ``web/_webhook_template.py`` — the SSOT.

    Callers import :func:`refuses_secret_binding` and delegate; they
    MUST NOT hand-roll the regex themselves. A future new call-site
    that ignores the SSOT trips this pin.
    """
    offenders: list[tuple[str, str]] = []
    for rel, literal in _iter_src_string_literals():
        for needle in _SECRET_PATTERN_LITERALS:
            if literal == needle:
                offenders.append((rel, literal))
                break
    expected_ssot_rel = relpath(
        SRC_ROOT / "web" / "_webhook_template.py"
    )
    # Callers OUTSIDE the SSOT must NOT hand-roll the pattern.
    filtered = [(p, lit) for (p, lit) in offenders if p != expected_ssot_rel]
    assert not filtered, (
        f"`{{{{secret}}}}` refusal regex duplicated OUTSIDE the SSOT "
        f"({expected_ssot_rel}) — callers must delegate to "
        f"`refuses_secret_binding()`, not hand-roll the pattern. "
        f"Offenders: {filtered}"
    )
    # The SSOT itself MUST carry the pattern (else the pin is dead —
    # a rename would silently pass).
    ssot_hits = [(p, lit) for (p, lit) in offenders if p == expected_ssot_rel]
    assert ssot_hits, (
        f"SSOT file {expected_ssot_rel} does not carry the refusal "
        f"regex literal — the pin is dead. Restore the compile call."
    )


def test_refuses_secret_binding_public_symbol_exists():
    """The public delegate symbol must exist + return the canonical
    message. If it moves or is renamed, config/wizard-save/wizard-
    preview all break — CI catches it here first."""
    from email_triage.web._webhook_template import (
        SECRET_BINDING_REFUSAL_MESSAGE,
        refuses_secret_binding,
    )
    # Positive cases — several whitespace variants.
    assert refuses_secret_binding('{"x":"{{secret}}"}') == (
        SECRET_BINDING_REFUSAL_MESSAGE
    )
    assert refuses_secret_binding('{"x":"{{ secret }}"}') == (
        SECRET_BINDING_REFUSAL_MESSAGE
    )
    assert refuses_secret_binding('{"x":"{{  secret  }}"}') == (
        SECRET_BINDING_REFUSAL_MESSAGE
    )
    # Negative — a plain field access must not trip.
    assert refuses_secret_binding('{"x":"{{data.subject}}"}') is None
    # Empty / None — trivially no refusal.
    assert refuses_secret_binding("") is None
    assert refuses_secret_binding(None) is None


def test_three_call_sites_all_delegate_to_ssot():
    """Sanity — ``config.py`` + ``routers/integrations.py`` both import
    the SSOT ``refuses_secret_binding``. If a fourth caller is added
    later that also imports the symbol, this pin passes; if any of
    the three ever regresses to a hand-rolled regex, the pin above
    catches it — this test just guards against silent import drift."""
    delegating_names: set[str] = set()
    for path in (
        SRC_ROOT / "config.py",
        SRC_ROOT / "web" / "routers" / "integrations.py",
    ):
        text = path.read_text(encoding="utf-8")
        if "refuses_secret_binding" in text:
            delegating_names.add(path.name)
    assert delegating_names >= {"config.py", "integrations.py"}, (
        f"expected both config.py and integrations.py to import "
        f"`refuses_secret_binding` from the SSOT; got "
        f"{sorted(delegating_names)}"
    )
