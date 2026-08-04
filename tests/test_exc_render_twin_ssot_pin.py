"""Exception-render twin-idiom SSOT pin (divergence census run13 #8).

The hand-rolled idiom ``f"{type(e).__name__}: {e}"`` — the exception CLASS name
prefixed to the raw exception MESSAGE — was duplicated at ~30 sites repo-wide
(logs, persisted ``error_text`` fields, operator-facing JSON). Two failure
modes followed from the duplication:

* **PHI / secret leak** — the raw ``{e}`` half echoes a recipient address or a
  mailbox/filesystem path (PHI) and sometimes a token (secret). Only the sites
  that happened to wrap the render in a scrubber were safe; the bare twin
  persisted cleartext PHI into operator fields (and, worst, the HMAC-chained
  audit ``detail``/``last_error`` columns that cannot be expunged).
* **Drift** — each copy could format the class differently (``: `` vs ``- ``),
  guard the ``__str__``-bomb differently, or scrub differently.

The SSOT is :func:`email_triage._errfmt.fmt_exc` with ``with_class=True`` (PHI
leg, ``__str__``-bomb-safe) for a LOG render, or
:func:`email_triage._errfmt.scrub_error_for_persist` (both legs) wrapping the
twin for a PERSISTED / operator-facing field.

COUNT-AGNOSTIC PROPERTY (over every f-string in ``src/email_triage`` except
``_errfmt.py``): no f-string may contain a ``{type(X).__name__}`` FormattedValue
followed — later in the SAME f-string — by a FormattedValue that renders ``X``
(``{X}`` or ``{str(X)}`` / ``{repr(X)}``). That adjacency IS the twin idiom and
must instead route through ``fmt_exc(X, with_class=True)`` (which carries the
``ClassName:`` prefix internally). A bare ``{type(X).__name__}`` with NO value
render of ``X`` is class-name-ONLY (PHI-free) and is FINE — that is how the
privacy-conscious paths already record a failure.

EXEMPTION: a twin f-string that is the DIRECT argument of a sanctioned scrubber
call (``scrub_error_for_persist(f"…")`` / ``redact_exc(f"…")`` / ``fmt_exc(…)``)
is the routed-through form and passes — the scrub neutralises the leak.
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, parse_source, relpath

# Sanctioned SSOT funnels: a twin f-string passed DIRECTLY as an arg here is a
# routed-through SSOT-consumer form.
#
# ``scrub_error_for_persist`` is DELIBERATELY NOT in this set (census run13 #8 F4):
# even though the scrub neutralises the PHI/secret leak at that call, letting
# the twin literal recur per-site invites drift (`` : `` vs `` - ``, order
# flip, missing prefix) that the anti-drift SSOT was built to prevent. The
# canonical shape for the "persist a class-prefixed exception" idiom is now
# :func:`email_triage._errfmt.scrub_class_error_for_persist`; the persist-side
# scrubber accepts only rendered strings, never a raw twin f-string.
_SCRUBBERS = {
    "redact_exc", "fmt_exc", "_scrub_error",
    # Bare-function SSOT for the persist path; takes a BaseException, not an
    # f-string. Included here for symmetry — the harness only inspects
    # JoinedStr args so this entry is a no-op today but documents intent.
    "scrub_class_error_for_persist",
}
# The SSOT module itself defines fmt_exc(with_class=...) — exempt from the scan.
_ALLOWED = {"_errfmt.py"}


def _subject_key(node: ast.AST) -> str | None:
    """Canonical dotted-path key for a Name or attribute chain, else ``None``:
    ``e`` -> ``"e"``; ``self.err`` -> ``"self.err"``; ``self.flow.error`` ->
    ``"self.flow.error"``. Used to match the ``type(X).__name__`` subject
    against the value half so an ATTRIBUTE-subject twin
    (``type(self.x).__name__`` … ``{self.x}``) is caught, not just a bare-Name
    subject (DA forward-drift caveat, census run13 #8)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _subject_key(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _classname_var(node: ast.AST) -> str | None:
    """If ``node`` is ``type(X).__name__`` with ``X`` a Name OR an attribute
    chain, return ``X``'s canonical subject key; else ``None``. (A more complex
    subject — a subscript, a call — has no stable key to match a value half
    against, so it is not treated as a twin.)"""
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "__name__"
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "type"
        and node.value.args
    ):
        return _subject_key(node.value.args[0])
    return None


def _renders_var(node: ast.AST, key: str) -> bool:
    """True if ``node`` renders the exception subject ``key`` as a value:
    ``{X}`` / ``{self.x}`` (the subject itself) or ``{str(X)}`` / ``{repr(X)}``
    (a str/repr call on it). Subject equality is by canonical dotted key, so an
    attribute chain matches only its EXACT self (``{self.x}`` matches, a
    sub-attribute ``{self.x.detail}`` does not — that is a different render)."""
    if _subject_key(node) == key:
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in {"str", "repr"} and node.args:
            return _renders_var(node.args[0], key)
    return False


def _scrubber_wrapped_fstrings(tree: ast.AST) -> set[int]:
    """ids() of every JoinedStr that is a DIRECT positional argument of a
    sanctioned scrubber call — those are the routed-through (safe) form."""
    wrapped: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = (
                fn.id if isinstance(fn, ast.Name)
                else fn.attr if isinstance(fn, ast.Attribute)
                else None
            )
            if name in _SCRUBBERS:
                for arg in node.args:
                    if isinstance(arg, ast.JoinedStr):
                        wrapped.add(id(arg))
    return wrapped


def _twin_offenders(tree: ast.AST) -> list[int]:
    """Lines of every bare (un-routed) twin f-string in ``tree``."""
    wrapped = _scrubber_wrapped_fstrings(tree)
    out: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        if id(node) in wrapped:
            continue  # routed through a scrubber → safe
        vals = node.values
        for i, v in enumerate(vals):
            if not isinstance(v, ast.FormattedValue):
                continue
            var = _classname_var(v.value)
            if var is None:
                continue
            # Look for a LATER FormattedValue that renders the same var.
            if any(
                isinstance(w, ast.FormattedValue) and _renders_var(w.value, var)
                for w in vals[i + 1:]
            ):
                out.append(getattr(node, "lineno", -1))
                break
    return out


def test_no_exc_render_twin_idiom():
    offenders: list[str] = []
    for p in iter_src_files():
        if p.name in _ALLOWED:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        bad = _twin_offenders(tree)
        if bad:
            offenders.append(f"{relpath(p)}: lines {bad}")
    assert not offenders, (
        "The hand-rolled exception-render twin idiom "
        'f"{type(X).__name__}: {X}" is duplicated outside the SSOT '
        f"(census run13 #8 + F4 widening): {offenders}. Replace each with: "
        "fmt_exc(X, with_class=True) (operator LOG — carries the ClassName: "
        "prefix, PHI-scrubbed) OR scrub_class_error_for_persist(X) "
        "(PERSISTED / operator-facing field — composes fmt_exc + secret-scrub "
        "+ length-cap). scrub_error_for_persist(f\"twin\") NO LONGER passes: "
        "the routed-through exemption was removed to close the per-site drift "
        "risk that persisted despite the scrub. A bare {type(X).__name__} "
        "with no {X} value render is class-name-only and is fine."
    )


def test_pin_has_teeth():
    # A planted bare twin IS flagged …
    bad = 'x = f"{type(e).__name__}: {e}"\n'
    assert _twin_offenders(parse_source(bad)), "missed a planted bare twin"
    # … with a prefix and the str() value form too …
    bad2 = 'y = f"boom: {type(exc).__name__}: {str(exc)}"\n'
    assert _twin_offenders(parse_source(bad2)), "missed prefixed/str() twin"
    bad3 = 'z = f"({type(err).__name__}: {err}) tail"\n'
    assert _twin_offenders(parse_source(bad3)), "missed mid-string twin"
    # … and the ATTRIBUTE-subject twin (DA forward-drift caveat, run13 #8) …
    bad4 = 'w = f"{type(self.err).__name__}: {self.err}"\n'
    assert _twin_offenders(parse_source(bad4)), "missed an attribute-subject twin"
    bad5 = 'v = f"{type(self.flow.error).__name__}: {self.flow.error}"\n'
    assert _twin_offenders(parse_source(bad5)), "missed a deep-attr-chain twin"

    # F4 widening (2026-07-06): a twin f-string DIRECTLY inside
    # scrub_error_for_persist IS flagged now — the per-site drift risk
    # persisted despite the scrub. Callers must use
    # scrub_class_error_for_persist(exc) which takes the exception itself.
    bad6 = 'u = scrub_error_for_persist(f"{type(e).__name__}: {e}")\n'
    assert _twin_offenders(parse_source(bad6)), (
        "missed a persist-scrubbed twin (F4 widening)"
    )
    bad7 = "t = scrub_error_for_persist(f'{type(exc).__name__}: {exc}')\n"
    assert _twin_offenders(parse_source(bad7)), (
        "missed a persist-scrubbed single-quote twin (F4 widening)"
    )
    # The SSOT call is NOT flagged …
    ok1 = 'a = fmt_exc(e, with_class=True)\n'
    assert not _twin_offenders(parse_source(ok1)), "flagged the SSOT call"
    # … the persist-side SSOT call is NOT flagged (bare function, no f-string) …
    ok2 = 'b = scrub_class_error_for_persist(e)\n'
    assert not _twin_offenders(parse_source(ok2)), (
        "flagged the persist-side SSOT call"
    )
    # … a twin ROUTED through fmt_exc / redact_exc is NOT flagged (those are
    # the LOG-side + PHI-only funnels; the persist-side twin case is the one
    # that drifted, not these) …
    ok3 = 'c = redact_exc(f"{type(exc).__name__}: {exc}")\n'
    assert not _twin_offenders(parse_source(ok3)), "flagged a redact_exc-routed twin"
    # … a LONE class-name-only render is NOT flagged (no value half) …
    ok4 = 'd = f"{type(e).__name__} does not support embed()"\n'
    assert not _twin_offenders(parse_source(ok4)), "flagged a class-name-only render"
    ok5 = 'm = f"migration failed; type={type(exc).__name__}"\n'
    assert not _twin_offenders(parse_source(ok5)), "flagged a class-name-only render"
    # … a value render of a DIFFERENT var than the class subject is NOT a twin …
    ok6 = 'n = f"{type(e).__name__}: {other}"\n'
    assert not _twin_offenders(parse_source(ok6)), "flagged a non-matching var"
    # … the scrubbed cousin f"setup: {fmt_exc(e, with_class=True)}" is fine
    # (the inner is fmt_exc, not a bare {e}); the OUTER f-string has no
    # type().__name__ FormattedValue, so it is not a twin.
    ok7 = 'o = f"setup: {fmt_exc(e, with_class=True)}"\n'
    assert not _twin_offenders(parse_source(ok7)), "flagged the fmt_exc cousin"
    # F4 widening: an ATTRIBUTE twin under scrub_error_for_persist is also
    # flagged now (same drift-per-site risk as the bare-Name form; the
    # attribute-subject case in bad4/bad5 must reach here too).
    bad8 = 'p = scrub_error_for_persist(f"{type(self.err).__name__}: {self.err}")\n'
    assert _twin_offenders(parse_source(bad8)), (
        "missed a persist-scrubbed attribute-subject twin (F4 widening)"
    )
    # … an attribute twin ROUTED through redact_exc (PHI-only, LOG-side) is
    # still an exemption — persist-side is the drifted class, not this one …
    ok8 = 'p2 = redact_exc(f"{type(self.err).__name__}: {self.err}")\n'
    assert not _twin_offenders(parse_source(ok8)), (
        "flagged an attr twin under the LOG-side PHI-only funnel"
    )
    # … rendering a SUB-attribute of the class subject is NOT the twin …
    ok9 = 'q = f"{type(self.err).__name__}: {self.err.detail}"\n'
    assert not _twin_offenders(parse_source(ok9)), "flagged an attr sub-render"
    # … a DIFFERENT attribute than the class subject is NOT a twin …
    ok10 = 'r = f"{type(self.err).__name__}: {self.other}"\n'
    assert not _twin_offenders(parse_source(ok10)), "flagged a non-matching attr"


def test_ssot_renders_class_prefix_and_scrubs():
    """The SSOT actually produces the ``ClassName:`` prefix, scrubs PHI, and is
    ``__str__``-bomb-safe — the behaviour the pin assumes when it greenlights
    ``fmt_exc(X, with_class=True)``."""
    from email_triage._errfmt import fmt_exc

    assert fmt_exc(ValueError("rcpt a@b.com"), with_class=True) == (
        "ValueError: rcpt [redacted-addr]"
    )
    # __str__-bomb: an exception whose __str__ raises must degrade, not escape.
    class _Bomb(Exception):
        def __str__(self):  # noqa: D401
            raise RuntimeError("boom")

    out = fmt_exc(_Bomb(), with_class=True)
    assert out.startswith("_Bomb: ")
    assert "unrenderable" in out
