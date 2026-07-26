"""Operator-rendered error-LIST scrub-coverage pin (divergence census run18 #3).

The triage + discover result pages render an ``errors`` list straight to the
operator's authenticated, PHI-bearing admin session::

    {% for err in errors %}<p><strong>Error:</strong> {{ err }}</p>{% endfor %}

The sibling read-only ``triage_preview`` ALREADY routes its exception text
through the scrub SSOT (``_errfmt.scrub_error_for_persist`` — PHI addresses /
mailbox+fs paths AND token-shaped secrets), but the BUILD sites that populate
the rendered ``errors`` list (``run_triage`` and ``discover_run``) interpolated
the RAW exception (``f"...{e}..."`` / ``str(e)``) — a CIDI divergence from the
sibling. The strongest leak: ``discover_run`` interpolated the IMAP FOLDER NAME
(a patient-named mailbox = a PHI shape) directly into the error. This is a LIVE
§164.502(b) minimum-necessary / §164.514(d)(1) defect, not a latent one.

COUNT-AGNOSTIC PROPERTY (over every ``*.py`` in ``src/email_triage``): a raw
exception-MESSAGE render (``str(e)`` / ``repr(e)`` / an f-string interpolating
``e``/``exc``/``.error``/``.msg``…) must NOT be appended to, or built into, the
operator-rendered ``errors`` list UNLESS it routes through a sanctioned scrubber
(``scrub_error_for_persist`` / ``fmt_exc`` / ``redact_exc`` / a funnel that wraps
one — e.g. ``_scrub_folder_scan_error``). The exception CLASS name
(``type(exc).__name__``), counts, and literals are PHI-free and pass.

INTERPROCEDURAL by construction: the text hops modules
(``run_triage`` builds the list → ``triage_classify`` renders it → the Jinja
template), so the pin guards the SOURCE — the list BUILD site — not the render
site. Scrubbing where the raw exception ENTERS the list covers every downstream
render (the template ``{{ err }}`` AND the ``error_article(run["errors"][0])``
N-83 path) regardless of which function/module renders it. The scan walks ALL of
``src/email_triage``, so a build site in ANY module is covered.

The exception-render predicate is REUSED from ``test_persisted_error_scrub_pin``
(PD#5/#6 — one funnel, no second copy): the persisted-error class and this
rendered-error class are the SAME "raw exc text reaches a surface" shape on a
DIFFERENT sink (a persisted column vs the operator ``errors`` list), so they
share ``_renders_exc_message`` (which already short-circuits a sanctioned
scrubber call to False) rather than forking a divergent matcher.

MUTATOR SCOPE (run18 #3 DA pin-hardening — the ``errors`` list sinks covered):
the Call mutators ``.append`` / ``.extend`` / ``.insert``, the ``errors=[…]``
call-kwarg, and the ``errors =`` / ``errors:`` / ``errors +=`` bindings
(``ast.Assign`` / ``ast.AnnAssign`` / ``ast.AugAssign``). The original net was
``.append`` + kwarg + ``=``/``:`` only — blind to ``extend`` / ``insert`` /
``+=`` re-intros of the SAME leak through a different mutator (no live instance,
hardened pre-emptively). A mutation through an ALIAS (``e2 = errors;
e2.append(str(x))``) or a list built elsewhere and bound to ``errors`` by
reference stays out of net — the load-bearing proof for those is the
rendered-view test, not the pin.

DELIBERATE SCOPING (documented residuals, not accidental — see census run18 #3
``enumeration_complete=false``):
* The sink is keyed on the LIST variable name ``errors`` (the
  triage/discover operator surface). A differently-named list (e.g.
  ``per_folder_errors``) is out of this pin's net — a pin-completeness residual.
* A ``_render(..., {"errors": <X>})`` render-CONTEXT dict whose value is a raw
  exc render is NOT scanned here; the load-bearing assertion is the BUILD site
  (where the raw exception enters the list), and the render context for these
  pages carries a Subscript (``run["errors"]``), not a raw render. The
  variable-built-context shape is the census's acknowledged inline-Dict residual.
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, parse_source, relpath
# Reuse the SINGLE exception-render predicate (PD#5/#6 — never a second copy).
from test_persisted_error_scrub_pin import _renders_exc_message

# The operator-rendered error LIST variable. The triage results
# (templates/triage/_results.html) and discover results
# (templates/triage/_discover_results.html) both render ``{% for err in errors
# %}{{ err }}``.
_ERRORS_VAR = "errors"


def _is_errors_name(node: ast.AST) -> bool:
    """True if ``node`` is the bare ``errors`` Name (the rendered list var)."""
    return isinstance(node, ast.Name) and node.id == _ERRORS_VAR


def _list_has_raw_exc(node: ast.AST) -> bool:
    """True if ``node`` is a List literal with any element that renders a raw
    exception message."""
    return isinstance(node, ast.List) and any(
        _renders_exc_message(elt) for elt in node.elts
    )


def _offenders(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            # Sink A — a list MUTATOR on ``errors``: ``.append(<raw exc>)`` /
            # ``.extend([<raw exc>, …])`` / ``.insert(i, <raw exc>)``. A pin keyed
            # only on ``.append`` is blind to a future ``.extend`` / ``.insert``
            # re-intro of the SAME leak through a different mutator (DA pin-
            # hardening, run18 #3) — no live instance today, but the net must
            # cover the mutator CLASS, not one method. (For ``.insert`` the VALUE
            # is the 2nd positional arg; arg 0 is the index.)
            if isinstance(f, ast.Attribute) and _is_errors_name(f.value):
                if (f.attr == "append" and node.args
                        and _renders_exc_message(node.args[0])):
                    out.append(f"errors.append@{getattr(node, 'lineno', '?')}")
                elif (f.attr == "extend" and node.args
                        and _list_has_raw_exc(node.args[0])):
                    out.append(f"errors.extend@{getattr(node, 'lineno', '?')}")
                elif (f.attr == "insert" and len(node.args) >= 2
                        and _renders_exc_message(node.args[1])):
                    out.append(f"errors.insert@{getattr(node, 'lineno', '?')}")
            # Sink B — a call kwarg ``errors=[<raw exc render>, ...]``
            # (e.g. ``TriageRunResult(errors=[f"Provider error: {e}"])``).
            for kw in node.keywords:
                if kw.arg == _ERRORS_VAR and _list_has_raw_exc(kw.value):
                    out.append(
                        f"errors=[...]kwarg@{getattr(node, 'lineno', '?')}"
                    )
        # Sink C — ``errors = [<raw exc render>, ...]`` / annotated assign.
        elif isinstance(node, ast.Assign):
            if any(_is_errors_name(t) for t in node.targets) and _list_has_raw_exc(
                node.value
            ):
                out.append(f"errors=assign@{node.lineno}")
        elif isinstance(node, ast.AnnAssign):
            if _is_errors_name(node.target) and _list_has_raw_exc(node.value):
                out.append(f"errors=annassign@{node.lineno}")
        # Sink D — ``errors += [<raw exc render>, ...]`` (ast.AugAssign — the
        # in-place ``+=`` extend; a DISTINCT node type from Sink C's Assign, so
        # the ``.append``-only net missed it too).
        elif isinstance(node, ast.AugAssign):
            if _is_errors_name(node.target) and _list_has_raw_exc(node.value):
                out.append(f"errors+=@{node.lineno}")
    return out


def test_no_unscrubbed_exc_in_operator_errors_list():
    offenders: list[str] = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        bad = _offenders(tree)
        if bad:
            offenders.append(f"{relpath(p)}: {bad}")
    assert not offenders, (
        "A raw exception MESSAGE is built into the operator-rendered `errors` "
        "list (PHI leak into the authenticated admin page, census run18 #3 / "
        f"§164.502(b)): {offenders}. Route it through "
        "email_triage._errfmt.scrub_error_for_persist(...) (the same SSOT the "
        "sibling triage_preview uses), or a funnel that wraps it "
        "(e.g. _scrub_folder_scan_error for the discover folder sites). The "
        "exception CLASS name (type(exc).__name__) is PHI-free and passes."
    )


def test_pin_has_teeth():
    # Planted bad shapes ARE flagged …
    assert _offenders(parse_source("errors.append(str(e))\n")), (
        "missed errors.append(str(e))"
    )
    assert _offenders(parse_source('errors.append(f"search: {e}")\n')), (
        "missed errors.append(f'...{e}')"
    )
    assert _offenders(parse_source('errors.append(f"Error selecting {folder}: {exc}")\n')), (
        "missed the raw discover folder f-string"
    )
    assert _offenders(
        parse_source('r = TriageRunResult(errors=[f"Provider error: {e}"])\n')
    ), "missed the errors=[f'...{e}'] kwarg"
    assert _offenders(parse_source('errors = [f"boom {exc}"]\n')), (
        "missed errors = [f'...{exc}']"
    )
    assert _offenders(parse_source("errors: list[str] = [str(e)]\n")), (
        "missed annotated errors = [str(e)]"
    )
    # run18 #3 (DA pin-hardening) — the non-``.append`` mutators of the SAME
    # ``errors`` list must also be flagged (extend / insert / ``+=``).
    assert _offenders(parse_source("errors.extend([str(e)])\n")), (
        "missed errors.extend([str(e)])"
    )
    assert _offenders(parse_source('errors.insert(0, f"boom {e}")\n')), (
        "missed errors.insert(0, f'...{e}')"
    )
    assert _offenders(parse_source("errors += [str(e)]\n")), (
        "missed errors += [str(e)] (AugAssign)"
    )

    # … and the routed / PHI-free / different-shape forms are NOT flagged:
    ok_scrub = 'errors.append(scrub_error_for_persist(f"search: {e}"))\n'
    assert not _offenders(parse_source(ok_scrub)), "flagged a scrubbed append"
    ok_funnel = (
        'errors.append(_scrub_folder_scan_error("Could not peek", folder, e, '
        "account_hipaa=h))\n"
    )
    assert not _offenders(parse_source(ok_funnel)), "flagged the funnel-wrapped append"
    ok_kwarg_scrub = 'r = T(errors=[scrub_error_for_persist(f"Provider error: {e}")])\n'
    assert not _offenders(parse_source(ok_kwarg_scrub)), "flagged a scrubbed kwarg list"
    ok_lit = 'errors.append("No categories configured.")\n'
    assert not _offenders(parse_source(ok_lit)), "flagged a literal append"
    ok_count = 'errors.append(f"Row {i}: category missing.")\n'
    assert not _offenders(parse_source(ok_count)), "flagged a non-exc count f-string"
    ok_dict = 'errors.append({"message_id": mid, "error": fmt_exc(e)})\n'
    assert not _offenders(parse_source(ok_dict)), "flagged a dict append (fmt_exc-scrubbed)"
    ok_fmt = 'errors.append(f"internal: {fmt_exc(e)}")\n'
    assert not _offenders(parse_source(ok_fmt)), "flagged an fmt_exc-routed append"
    ok_comp = "errors = [r[1] for r in results if r[0] == 'err']\n"
    assert not _offenders(parse_source(ok_comp)), "flagged a list-comprehension"
    ok_empty = "errors=[]\n"
    assert not _offenders(parse_source(ok_empty)), "flagged an empty list kwarg"
    ok_other_var = 'per_folder_errors.append(str(e))\n'
    assert not _offenders(parse_source(ok_other_var)), (
        "flagged a differently-named list (documented scoping residual)"
    )
    # The new mutators' routed / PHI-free / different-shape forms stay clean:
    ok_extend_scrub = 'errors.extend([scrub_error_for_persist(f"x {e}")])\n'
    assert not _offenders(parse_source(ok_extend_scrub)), "flagged a scrubbed extend"
    ok_insert_lit = 'errors.insert(0, "No categories configured.")\n'
    assert not _offenders(parse_source(ok_insert_lit)), "flagged a literal insert"
    ok_augassign_scrub = 'errors += [scrub_error_for_persist(f"x {e}")]\n'
    assert not _offenders(parse_source(ok_augassign_scrub)), "flagged a scrubbed +="
    ok_other_extend = "per_folder_errors.extend([str(e)])\n"
    assert not _offenders(parse_source(ok_other_extend)), (
        "flagged a differently-named list extend (documented scoping residual)"
    )
