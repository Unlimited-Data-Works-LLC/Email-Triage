"""Persisted-error PHI+secret scrub SSOT pin (divergence census run13 #2).

An exception rendered into a PERSISTED, operator-facing ``*error*`` field
(``triage_jobs.error_text`` / ``flows.error`` / ``*.last_error`` …) can echo a
recipient address or mailbox path (PHI) AND a token (secret). The N-42 scrub
(:func:`email_triage._errfmt.redact_exc`, PHI) + the token scrub
(``scrub_secrets_from_text``) must BOTH apply — and only one site
(``embedding_bits._scrub_error``) composed both, so the funnel was promoted to
``_errfmt.scrub_error_for_persist`` (the SSOT). Several other writers rendered
the raw exception MESSAGE (``str(e)`` / ``f"…{output.error}…"``) straight into
the column, so a mail-path failure persisted PHI cleartext in an operator field.

Count-agnostic property: a persisted-error SINK — a call kwarg named
``error_text`` / ``last_error`` / ``last_error_msg``, OR a ``<x>.error =``
assignment — must NOT be bound to a raw exception-MESSAGE render (``str(<exc>)``
/ ``repr(<exc>)`` / a bare exception name / a ``.error`` / ``.message`` / ``.msg``
attribute / an f-string interpolating any of those) UNLESS the whole expression
flows through a sanctioned scrubber. The exception CLASS name
(``type(exc).__name__`` / ``result.error_class``), counts, and literals are PHI-
free and pass — those are how the privacy-conscious style-learning paths already
record failures.
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath

_SINK_KWARGS = {
    "error_text", "last_error", "last_error_msg", "error_msg",
    # census run13 #2 (DA) — the chained audit ``detail`` column. A raw exc
    # MESSAGE here lands PERMANENTLY in the §164.312(b) HMAC chain (can't be
    # expunged). Structured details (``detail={...}`` dict / ``json.dumps(...)``)
    # are NOT exc-message renders, so _renders_exc_message exempts them.
    "detail",
}
# Funnels whose output is already scrubbed for persistence (or for an
# operator-facing log). scrub_error_for_persist/_scrub_error = both legs;
# fmt_exc/redact_exc = PHI leg; failure_text now routes through the SSOT.
_SCRUBBERS = {
    "scrub_error_for_persist", "_scrub_error", "fmt_exc", "redact_exc",
    "failure_text",
}
# CANONICAL exception-object binders (``except … as e``). Deliberately NOT
# ``err`` / ``error`` — those routinely name a built guidance STRING or an error
# DICT (e.g. a local ``err = f"half-installed … try [Re-install]"`` or a Graph
# ``error`` payload), which carry no exception message and must not trip.
_EXC_NAMES = {"e", "exc", "ex", "exception"}
# Attribute tails that render the exception MESSAGE (NOT the class — that's
# ``error_class`` / ``__name__``, which carry no PHI).
_MSG_ATTRS = {"error", "message", "msg", "stderr", "stdout"}
# The SSOT module itself defines the funnels — exempt from the scan.
_ALLOWED = {"_errfmt.py"}


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _renders_exc_message(node: ast.AST) -> bool:
    """True if ``node`` renders an exception MESSAGE (the PHI-bearing shape),
    NOT merely its class name. A sanctioned scrubber call short-circuits to
    False (the message is scrubbed)."""
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name in _SCRUBBERS:
            return False  # scrubbed
        if name in {"str", "repr"} and node.args:
            a = node.args[0]
            if isinstance(a, ast.Name) and a.id in _EXC_NAMES:
                return True  # str(e) / repr(exc)
            return _renders_exc_message(a)  # str(output.error)
        return False
    if isinstance(node, ast.Attribute):
        # A direct ``.error`` / ``.message`` / ``.msg`` message attribute (e.g.
        # ``output.error``). NOT a bare Name — a value literally named ``e`` is
        # almost always a real exception, but as a DB param a bare exception
        # object would crash sqlite3 (un-adaptable); the live leak shape is the
        # RENDERED message (``str(e)`` / ``f"…{e}…"`` / ``.error``), caught here.
        return node.attr in _MSG_ATTRS
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue)
            and (_renders_exc_message(v.value)
                 or (isinstance(v.value, ast.Name) and v.value.id in _EXC_NAMES))
            for v in node.values
        )
    if isinstance(node, ast.IfExp):
        # census run13 #8 (acme evasion ii) — a conditional sink value
        # ``error_text=<X> if <c> else <Y>`` leaks if EITHER branch renders a
        # raw exc message (e.g. ``last_error=_fmt_exc(e) if e else None``). Both
        # arms must be scrubbed, so flag if either is a raw render.
        return _renders_exc_message(node.body) or _renders_exc_message(node.orelse)
    return False


def _is_failure_sink(name: str | None) -> bool:
    """census run13 #8 (acme evasion iii) — a ``finish_failure`` /
    ``*_failure`` actuator takes the persisted error as its FIRST POSITIONAL
    arg (``acme_job_state.finish_failure(<err>, kind=…)``), so a kwarg-only scan
    misses it. Match ``finish_failure`` and any ``*_failure`` callee name."""
    return bool(name) and (name == "finish_failure" or name.endswith("_failure"))


def _offenders(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        # Sink 1 — a column-named kwarg: foo(error_text=<expr>), …
        if isinstance(node, ast.Call):
            # ``detail=`` on an HTTPException is a TRANSIENT HTTP response, not a
            # persisted field (hipaa-sme ruling — out of scope). The PERSISTED
            # detail sink is the chained audit emitter (record_*_event).
            if _call_name(node) == "HTTPException":
                continue
            for kw in node.keywords:
                if kw.arg in _SINK_KWARGS and _renders_exc_message(kw.value):
                    out.append(f"{kw.arg}@{getattr(node, 'lineno', '?')}")
            # Sink 1b — the positional ``*_failure`` actuator (acme evasion iii).
            cn = _call_name(node)
            if _is_failure_sink(cn) and node.args:
                if _renders_exc_message(node.args[0]):
                    out.append(f"{cn}(arg0)@{getattr(node, 'lineno', '?')}")
        # Sink 2 — the engine ``flow.error`` assign (the one attribute that maps
        # to a persisted error column, store.py). Scoped to a receiver named
        # ``flow`` so a generic ``self.error = …`` (e.g. an exception
        # constructor like GraphError) is not mistaken for a DB write.
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Attribute) and tgt.attr == "error"
                        and isinstance(tgt.value, ast.Name) and tgt.value.id == "flow"
                        and _renders_exc_message(node.value)):
                    out.append(f"flow.error@{node.lineno}")
    return out


def test_no_raw_exc_message_in_persisted_error_sink():
    offenders = []
    for p in iter_src_files():
        if p.name in _ALLOWED:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        bad = _offenders(tree)
        if bad:
            offenders.append(f"{relpath(p)}: {bad}")
    assert not offenders, (
        "A raw exception MESSAGE is rendered into a persisted/operator-facing "
        f"error field (PHI + secret risk, census run13 #2): {offenders}. Route "
        "it through email_triage._errfmt.scrub_error_for_persist(...) (both legs "
        "— redact_exc PHI + token scrub). The exception CLASS name "
        "(type(exc).__name__ / result.error_class) is PHI-free and is the "
        "sanctioned way to record a failure without scrubbing."
    )


def test_scrub_error_for_persist_redacts_phi_and_handles_none():
    """The SSOT actually scrubs PHI (address + mailbox/fs path) and survives
    None/empty — the behaviour the pin assumes when it greenlights a routed
    write."""
    from email_triage._errfmt import scrub_error_for_persist as S
    out = S(ValueError(
        "rcpt jane.doe@hosp.org refused at /var/mail/.INBOX.Smith/cur/1.eml"
    ))
    assert "jane.doe@hosp.org" not in out and "[redacted-addr]" in out
    assert ".INBOX.Smith" not in out and "[redacted-path]" in out
    assert S(None) is None
    assert S("") is None  # empty → None (via the secret-scrub SSOT cap/collapse)


def test_pin_has_teeth():
    bad_str = "finish_triage_job(c, j, error_text=str(e))\n"
    assert _offenders(ast.parse(bad_str)), "missed error_text=str(e)"
    bad_fstr = "f = g(error_text=f\"failed: {output.error}\")\n"
    assert _offenders(ast.parse(bad_fstr)), "missed error_text=f'...{.error}'"
    bad_assign = "flow.error = f\"boom {exc}\"\n"
    assert _offenders(ast.parse(bad_assign)), "missed flow.error = f'...{exc}'"
    bad_strexc = "upd(last_error=str(exc))\n"
    assert _offenders(ast.parse(bad_strexc)), "missed last_error=str(exc)"
    bad_attr = "g(error_text=output.error)\n"
    assert _offenders(ast.parse(bad_attr)), "missed error_text=<.error attr>"
    # Sanctioned + PHI-free shapes must NOT trip:
    ok_self_error = "self.error = error\n"   # an exception constructor, not a DB write
    assert not _offenders(ast.parse(ok_self_error)), "flagged an exc constructor self.error"
    ok_built_err = "_update_state(c, last_error_msg=err)\n"  # err = a built guidance str
    assert not _offenders(ast.parse(ok_built_err)), "flagged a built guidance var"
    # The chained-audit detail sink (run13 #2 / DA):
    bad_detail = "record_auth_event(db, detail=f'cat reason={e}')\n"
    assert _offenders(ast.parse(bad_detail)), "missed audit detail=f'...{e}'"
    ok_http = "raise HTTPException(status_code=502, detail=f'calendar_error: {e}')\n"
    assert not _offenders(ast.parse(ok_http)), "flagged a transient HTTPException detail"
    ok_dict_detail = "record_auth_event(db, detail={'k': str(e)})\n"  # structured payload
    assert not _offenders(ast.parse(ok_dict_detail)), "flagged a structured dict detail"
    ok_scrub = "g(error_text=scrub_error_for_persist(f'failed {e}'))\n"
    assert not _offenders(ast.parse(ok_scrub)), "false-positived a scrubbed write"
    ok_failtext = "finish_triage_job(c, j, error_text=failure_text(exc))\n"
    assert not _offenders(ast.parse(ok_failtext)), "false-positived failure_text()"
    ok_class = "upd(last_error=f'backend_fail:{result.error_class}')\n"
    assert not _offenders(ast.parse(ok_class)), "flagged a class-name (no PHI)"
    ok_clsname = "self.x = dict(last_error=type(exc).__name__)\n"
    assert not _offenders(ast.parse(ok_clsname)), "flagged type(exc).__name__"
    ok_count = "f(error_text=f'{errors} rows failed, {ok} ok')\n"
    assert not _offenders(ast.parse(ok_count)), "flagged a count f-string"
    ok_literal = "f(error_text='account not found')\n"
    assert not _offenders(ast.parse(ok_literal)), "flagged a literal"

    # census run13 #8 — the 3 acme evasions the verify pass surfaced:
    # (ii) an IfExp-wrapped sink value — flag if EITHER branch is a raw render.
    bad_ifexp = "upd(last_error=str(e) if e else None)\n"
    assert _offenders(ast.parse(bad_ifexp)), "missed last_error=str(e) if … else"
    bad_ifexp2 = "upd(last_error=None if ok else f'{type(e).__name__}: {e}')\n"
    assert _offenders(ast.parse(bad_ifexp2)), "missed the else-branch twin"
    ok_ifexp = "upd(last_error=scrub_error_for_persist(x) if x else None)\n"
    assert not _offenders(ast.parse(ok_ifexp)), "flagged a scrubbed IfExp"
    # (iii) a positional ``*_failure`` actuator whose FIRST arg is a raw render.
    bad_pos = "finish_failure(f'{type(exc).__name__}: {exc}', kind=k)\n"
    assert _offenders(ast.parse(bad_pos)), "missed finish_failure(positional twin)"
    bad_pos2 = "mark_failure(str(e))\n"
    assert _offenders(ast.parse(bad_pos2)), "missed *_failure(str(e))"
    ok_pos = "finish_failure(fmt_exc(exc, with_class=True), kind=k)\n"
    assert not _offenders(ast.parse(ok_pos)), "flagged a routed finish_failure arg"
    ok_pos_lit = "finish_failure('cancelled by operator')\n"
    assert not _offenders(ast.parse(ok_pos_lit)), "flagged a literal finish_failure arg"
    # (i) A def-level local exc-renderer reimplementation (the deleted acme
    # ``_fmt_exc``) is covered by the twin-idiom SSOT pin
    # (test_exc_render_twin_ssot_pin): its body f-string IS the twin shape and
    # is flagged there regardless of the enclosing function — no separate teeth
    # needed in THIS pin, which scans persisted SINKS, not renderer defs.
