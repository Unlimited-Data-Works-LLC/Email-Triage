"""the backlog  (Census v3 re-run error-surface UPGRADED HIGH) — pin.

Structural + cross-module: no ``<subscript>["_hipaa_error"] = <expr>``
(nor the un-prefixed ``"hipaa_error"`` render alias) may bind to
anything OTHER than a ``scrub_exc(...)`` call inside ``src/email_triage``.

Why this shape gets its own key rather than folding into
``_FLASH_CTX_KEYS`` of the 4-arm pin: the accounts.py:1685 defect
(``bad_acct["_hipaa_error"] = str(e)``) writes to an account-model dict
that is returned across function seams (nested-def → outer handler)
before the ``hipaa_error`` binding lands in a TemplateResponse. Arm C
of the 4-arm pin walks INSIDE the enclosing fn only (documented
scope caveat), so the interprocedural handoff hides the defect.

A per-KEY, cross-module ban catches the shape wherever it lands —
narrow, cheap, no full alias-track needed.

The key set is HIPAA-tagged because the class importance is HIPAA-
scope error-message surfacing (§164.502(a) minimum-necessary): a raw
exception's ``__str__`` may echo PHI from an inner parser/lookup. The
same shape for a non-HIPAA key would live in the 4-arm pin's Arm C.

Prime Directive #6: routes through the shared ``_pin_harness`` walker.
Enforces PD #9 (fix-all-sites SSOT) — the 4-arm pin is the class SSOT;
this is its HIPAA-scope satellite.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


_HIPAA_ERROR_KEYS: frozenset[str] = frozenset({"_hipaa_error", "hipaa_error"})

_SCRUB_CALL_NAMES: frozenset[str] = frozenset({
    "scrub_exc", "flash_context", "flash_htmx",
    "api_error_response", "raise_api_error",
    "error_chip", "error_article",
})


def _is_scrub_call(expr: ast.AST) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    func = expr.func
    if isinstance(func, ast.Name):
        return func.id in _SCRUB_CALL_NAMES
    if isinstance(func, ast.Attribute):
        return func.attr in _SCRUB_CALL_NAMES
    return False


def _is_safe_rhs(expr: ast.AST) -> bool:
    """Allowed RHS shapes for a `_hipaa_error` binding:
    * `scrub_exc(...)` or another scrub-family call
    * `""` (empty-clear on success paths)
    * `None`
    * A ``.get("_hipaa_error", "")`` / ``.get("hipaa_error", "")`` — the
      READ side, not a write of exception text.
    """
    if _is_scrub_call(expr):
        return True
    if isinstance(expr, ast.Constant):
        v = expr.value
        return v is None or v == "" or (isinstance(v, str) and v == "")
    if isinstance(expr, ast.Call):
        f = expr.func
        if isinstance(f, ast.Attribute) and f.attr == "get":
            for a in expr.args:
                if isinstance(a, ast.Constant) and a.value in _HIPAA_ERROR_KEYS:
                    return True
    return False


def _scan_module(tree: ast.Module, rel: str, offenders: list[str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if not isinstance(tgt, ast.Subscript):
                continue
            slc = tgt.slice
            if not (isinstance(slc, ast.Constant) and slc.value in _HIPAA_ERROR_KEYS):
                continue
            if _is_safe_rhs(node.value):
                continue
            offenders.append(
                f"{rel}:{node.lineno}  <dict>[{slc.value!r}] = "
                f"<non-scrub expr>"
            )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if not (isinstance(k, ast.Constant) and k.value in _HIPAA_ERROR_KEYS):
                continue
            if _is_safe_rhs(v):
                continue
            offenders.append(
                f"{rel}:{node.lineno}  {{... {k.value!r}: <non-scrub expr> ...}}"
            )


def test_no_hipaa_error_key_bound_to_unscrubbed_expression():
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        # The SSOT itself + this pin's tests are exempt.
        if rel.endswith("web/_flash.py"):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        _scan_module(tree, rel, offenders)
    assert not offenders, (
        "Census #112 error-surface HIGH (HIPAA-scope): a `_hipaa_error` "
        "(or `hipaa_error`) dict key is bound to something OTHER than a "
        "`scrub_exc(...)` call — the raw exception's `__str__` may echo "
        "PHI or lock-guard internals to an authenticated view "
        "(§164.502(a) minimum-necessary). Route through "
        "`web/_flash.py::scrub_exc(e, purpose='form')`:\n\n" +
        "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
#  widening (DA F3 on the 2026-07-11 batched panel for the down-payment
# fold): the original arm above bans subscript-writes to the `_hipaa_error`/
# `hipaa_error` KEY set. But the class shape extends to plain-Name
# assignments that echo `str(e)` / `f"...{e}"` / `fmt_exc(e)` into a
# user-facing sink — variables named ``save_error`` / ``save_msg`` /
# ``error`` in HTTP router handlers land in a URL query redirect or a
# TemplateResponse, and both are user-visible surfaces the same class
# covers. Not a HIPAA-scope-only concern — a raw exception echo may leak
# credentials, lock-guard internals, PHI-adjacent addresses, etc. This
# arm bans the plain-Name assignment shape in `src/email_triage/web/**`.
# Interprocedural residual: the assignment's downstream sink is off-scope
# for this pin (we ONLY check the write-side); a caller that later scrubs
# the value before rendering would still trip here — same tradeoff as the
# original arm. Add a `(rel, lineno)` to the allow-list below if a legit
# non-user-visible use case arises (unlikely for these specific
# variable-name conventions in `web/routers/**`).
# ---------------------------------------------------------------------------


_USER_FACING_ERROR_NAMES: frozenset[str] = frozenset({
    # Original  down-payment coverage.
    "save_error", "save_msg", "error", "error_msg",
    #  widening (2026-07-11) — LHS names that surface exception
    # echo through RedirectResponse URL query positions, HTTPException
    # detail fields, or TemplateResponse context binds. Verified
    # via llm-host `qwen3.6:35b` broader offload at
    # `scratchpad_llm_host_118_broader.json` — 12 candidate sites across
    # `msg`/`reason`/`body`/`detail` classified, all correctly
    # INTERNAL_PREDICATE_SAFE or AUDIT_LOG_SINK_SAFE at HEAD except
    # 1 REFUTED false-positive (app.py:1561 — internal predicate).
    "msg", "reason", "body", "detail",
})


_WEB_SCOPE_PATH_PREFIX = "web/"


def _rhs_echoes_exception(expr: ast.AST) -> bool:
    """True if the RHS looks like a raw exception echo: ``str(e)``,
    ``fmt_exc(e)`` (WITHOUT a scrub wrapper), an f-string containing an
    ``{e}`` / ``{exc}`` interpolation, or a `.format(e)` / `.format(exc)`
    call. Deliberately narrow: literal strings, dict lookups, function
    calls to scrub-family names all pass through cleanly."""
    if isinstance(expr, ast.Call):
        f = expr.func
        name = f.id if isinstance(f, ast.Name) else (
            f.attr if isinstance(f, ast.Attribute) else None
        )
        if name in _SCRUB_CALL_NAMES:
            return False
        if name in {"str", "fmt_exc"} and expr.args:
            arg0 = expr.args[0]
            if isinstance(arg0, ast.Name) and arg0.id in {"e", "exc"}:
                return True
    if isinstance(expr, ast.JoinedStr):
        for part in expr.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            v = part.value
            if isinstance(v, ast.Name) and v.id in {"e", "exc"}:
                return True
    # A Subscript RHS whose slice is `[:N]` around an offender —
    # recurse into the value.
    if isinstance(expr, ast.Subscript):
        return _rhs_echoes_exception(expr.value)
    return False


def _scan_plain_name_assignments(
    tree: ast.Module, rel: str, offenders: list[str],
) -> None:
    """Walk plain ``ast.Name = <expr>`` assignments whose LHS name is in
    the ``_USER_FACING_ERROR_NAMES`` set + whose RHS is a raw exception
    echo (per :func:`_rhs_echoes_exception`)."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if not isinstance(tgt, ast.Name):
                continue
            if tgt.id not in _USER_FACING_ERROR_NAMES:
                continue
            if not _rhs_echoes_exception(node.value):
                continue
            offenders.append(
                f"{rel}:{node.lineno}  {tgt.id} = <raw-exception-echo>"
            )


# ---------------------------------------------------------------------------
#  Arm F (HIPAA-SME + DA F3 must-fix on the 2026-07-11 batched panel):
# ban ``<subscript>["error"] = <raw-exception-echo>`` inside an ``except`` handler
# in ``src/email_triage/web/**``. Catches the `entry["error"] = str(e)` shape
# folded at `triage_runner.py:513` and `triage_one.py:961` which the original
# subscript arm (keyed to `_HIPAA_ERROR_KEYS`) and the plain-Name arm (keyed to
# `_USER_FACING_ERROR_NAMES`) both MISSED. The result-entry lands in the
# batch-return + is shown to the user via triage-completed webhook / UI.
# ---------------------------------------------------------------------------


_SUBSCRIPT_ERROR_KEYS: frozenset[str] = frozenset({
    "error", "error_msg", "detail", "reason", "msg",
})


def _scan_entry_error_subscript_writes(
    tree: ast.Module, rel: str, offenders: list[str],
) -> None:
    """Walk ``ast.Assign`` where the LHS is ``<subscript>[<literal-key>]``
    with ``<literal-key>`` in :data:`_SUBSCRIPT_ERROR_KEYS` and the RHS
    is a raw exception echo per :func:`_rhs_echoes_exception`. Emits an
    offender line per hit."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if not isinstance(tgt, ast.Subscript):
                continue
            slc = tgt.slice
            if not (isinstance(slc, ast.Constant)
                    and isinstance(slc.value, str)
                    and slc.value in _SUBSCRIPT_ERROR_KEYS):
                continue
            if not _rhs_echoes_exception(node.value):
                continue
            offenders.append(
                f"{rel}:{node.lineno}  <subscript>[{slc.value!r}] = "
                "<raw-exception-echo>"
            )


def test_no_unscrubbed_subscript_error_write_in_web():
    """ Arm F — no ``<subscript>[<error-key>] = <raw-exception-echo>``
    in ``src/email_triage/web/**``. Route through
    ``web/_flash.scrub_exc(e, purpose=<...>)`` so a raw exception `__str__`
    cannot echo PHI or lock-guard internals to the user-facing sink."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith("web/_flash.py"):
            continue
        if _WEB_SCOPE_PATH_PREFIX not in rel:
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        _scan_entry_error_subscript_writes(tree, rel, offenders)
    assert not offenders, (
        "#118 Arm F: a ``<subscript>[<error-key>] = <raw-exception-echo>`` "
        "write in ``src/email_triage/web/**`` — route through "
        "``web/_flash.py::scrub_exc(e, purpose='form'|'triage'|'admin')``. "
        f"Covered keys: {sorted(_SUBSCRIPT_ERROR_KEYS)}. §164.502(b) "
        "minimum-necessary + §164.530(c)(1) reasonable safeguards.\n\n"
        + "\n".join(offenders)
    )


def test_no_unscrubbed_user_facing_error_name_assignment():
    """ tail — plain-Name assignments to ``save_error``/``save_msg``/
    ``error``/``error_msg`` in ``src/email_triage/web/**.py`` must NOT
    bind a raw exception echo — route via ``_flash.scrub_exc(e, purpose=
    '<...>')``. Widens the subscript-key ban to the plain-Name shape the
     down-payment folded (accounts.py:2665, admin.py:830/1304/1448,
    integrations.py:693, triage_runner.py:513, triage_one.py:961, _shared.py:2563)."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith("web/_flash.py"):
            continue
        # Restrict to the web/ subtree — the class's user-facing sink
        # class lives entirely under `web/**`. Non-web sites (CLI, jobs,
        # etc.) have their own error-surface conventions.
        if _WEB_SCOPE_PATH_PREFIX not in rel:
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        _scan_plain_name_assignments(tree, rel, offenders)
    assert not offenders, (
        "#118 tail (widening from Census #112 subscript-key arm to plain-"
        "Name assignments): a ``save_error`` / ``save_msg`` / ``error`` / "
        "``error_msg`` variable in ``src/email_triage/web/**`` is bound to "
        "a raw exception echo (``str(e)`` / ``fmt_exc(e)`` / f-string "
        "``{e}``). Route through ``web/_flash.py::scrub_exc(e, purpose="
        "'form'|'triage'|'admin')`` so PHI or secret shapes cannot echo "
        "to the user-facing sink (§164.502(a) minimum-necessary + "
        "§164.312(b) audit-control integrity).\n\n"
        + "\n".join(offenders)
    )
