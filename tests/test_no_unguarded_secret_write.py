"""Structural pin (2026-06-08 OAuth-clobber incident): no web POST handler
writes a *form-derived* value straight into the secrets store.

What this defends
-----------------
The save-handler clobber class: a handler reads a credential/secret from a
form field and calls ``secrets.set(key, <that form value>)`` directly. On a
bundled multi-setting form the field value is not under the operator's sole
control (a password-manager autofills a blank ``type=password`` field; an
emptied ``type=text`` id writes back blank), so saving one unrelated setting
silently destroys a stored credential. On 2026-06-08 saving only the SearXNG
URL blanked ``GOOGLE_OAUTH_WEB_CLIENT_ID`` and overwrote the Google + O365
client secrets, killing all Gmail/O365 auth install-wide.

The fix routes every such write through the never-clobber-on-blank helpers in
``web/routers/_secret_write.py`` (``set_secret_if_changed`` /
``set_id_preserve_blank`` / ``clear_secret``). This pin converts that
convention into an ENFORCED INVARIANT: a ``secrets.set(...)`` in a router
whose value argument is form-derived trips CI — the next hand-rolled
clobber site fails the build with its file:line.

Count-agnostic
--------------
Per ``pattern_count_agnostic_structural_drift_catch.md`` this asserts a
PROPERTY over every call site (no form-derived ``secrets.set`` outside the
SSOT), not a count. The companion behavioural guard
``tests/test_web/test_secret_write_no_clobber.py`` proves the runtime
contract (POST blank/garbage → stored secret unchanged); this proves the
*shape* can't silently come back.

Scope + allowlist
-----------------
Scoped to ``web/routers/`` — the only place ``request.form()`` is handled.
``_secret_write.py`` is exempt (it is the one sanctioned ``secrets.set``
site). ``_ALLOWED_FORM_DERIVED`` is the explicit, documented set of
``(module, function)`` writes whose value merely *passes through* a
form-handling function but is NOT a preserve-able stored credential (e.g. an
OAuth refresh token freshly minted by the token exchange). Each entry is a
reviewed exception; a NEW form-derived ``secrets.set`` that is not listed is
a violation, and a STALE listed entry that no longer matches also fails (so
the allowlist can't rot).

The allow-list / violation ``module`` key is the canonical
``SRC_ROOT``-relative, forward-slash path from the shared pin harness
(``relpath`` → ``web/routers/ai_backends_crud.py`` form), NOT the legacy
routers-root-relative basename. An entry added here must use that form.
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


# (module-path, function-name) writes that are form-handler-adjacent but
# legitimately NOT the clobber class. The module-path is the canonical
# harness ``relpath`` form (``web/routers/ui/oauth.py``). Empty today: after the
# fix every real credential write routes through the SSOT helpers, and the
# only refresh-token write (oauth.py) is sourced from the token exchange, not
# a form field, so it is not form-derived and never matches. Add here ONLY
# with a one-line justification if a genuine pass-through ever appears.
_ALLOWED_FORM_DERIVED: set[tuple[str, str]] = set()

# Base name that roots a "form" access. Handlers bind the parsed body either
# to ``form = await request.form()`` OR to per-field FastAPI ``Form(...)``
# parameters; both styles are credential-clobber surfaces, so both are
# treated as form roots (the latter per-function — see _form_param_names).
_FORM_ROOTS = {"form"}
# FastAPI dependency factories whose parameter value comes from the request
# body / form — i.e. attacker-or-autofill-controllable like a form field.
_FORM_PARAM_FACTORIES = {"Form", "Body", "File"}
_SECRETS_OBJ = "secrets"


def _dotted(node: ast.AST) -> str | None:
    """Render an attribute/name chain to a dotted string, else None.

    ``config.google_oauth.web_client_id`` → ``"config.google_oauth.web_client_id"``;
    ``x`` → ``"x"``; anything else → None.
    """
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _is_form_factory(default: ast.AST | None) -> bool:
    """True when a parameter default is a ``Form(...)`` / ``Body(...)`` /
    ``File(...)`` call — i.e. the parameter is bound to the request body."""
    if not isinstance(default, ast.Call):
        return False
    f = default.func
    name = (
        f.id if isinstance(f, ast.Name)
        else f.attr if isinstance(f, ast.Attribute)
        else None
    )
    return name in _FORM_PARAM_FACTORIES


def _form_param_names(fn: ast.AST) -> set[str]:
    """Parameter names of ``fn`` bound to a Form/Body/File factory default —
    the per-field FastAPI form-injection style (vs ``request.form()``)."""
    a = fn.args  # type: ignore[attr-defined]
    names: set[str] = set()
    positional = list(getattr(a, "posonlyargs", [])) + list(a.args)
    defaults = list(a.defaults)
    offset = len(positional) - len(defaults)  # defaults right-align
    for i, arg in enumerate(positional):
        di = i - offset
        if di >= 0 and _is_form_factory(defaults[di]):
            names.add(arg.arg)
    for arg, dflt in zip(a.kwonlyargs, a.kw_defaults):
        if _is_form_factory(dflt):
            names.add(arg.arg)
    return names


def _is_form_expr(node: ast.AST, roots: set[str]) -> bool:
    """True if the expression references a form root anywhere — i.e. its
    value is (partly) sourced from the submitted form body."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in roots:
            return True
    return False


def _form_derived_places(fn: ast.AST, roots: set[str]) -> set[str]:
    """Dotted targets (names AND attribute chains) assigned from a form-
    derived value anywhere in ``fn`` (incl. nested functions — an over-
    approximation that only ever adds genuine form-derived flags)."""
    places: set[str] = set()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Assign):
            if _is_form_expr(sub.value, roots):
                for tgt in sub.targets:
                    d = _dotted(tgt)
                    if d:
                        places.add(d)
        elif isinstance(sub, ast.AnnAssign) and sub.value is not None:
            if _is_form_expr(sub.value, roots):
                d = _dotted(sub.target)
                if d:
                    places.add(d)
        elif isinstance(sub, ast.NamedExpr):  # walrus
            if _is_form_expr(sub.value, roots):
                d = _dotted(sub.target)
                if d:
                    places.add(d)
    return places


def _secrets_set_calls(fn: ast.AST):
    """Yield ``secrets.set(...)`` Call nodes anywhere in ``fn``."""
    for sub in ast.walk(fn):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "set"
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == _SECRETS_OBJ
        ):
            yield sub


def _value_is_form_derived(
    call: ast.Call, places: set[str], roots: set[str],
) -> bool:
    """True when the value argument of ``secrets.set(key, value)`` is sourced
    from the form: directly references a form root, OR is a name/attribute
    that was assigned from a form-derived value earlier in the function, OR
    is itself a form-bound parameter."""
    if len(call.args) < 2:
        return False
    value = call.args[1]
    if _is_form_expr(value, roots):
        return True
    d = _dotted(value)
    return d is not None and d in places


def _param_names(fn: ast.AST) -> list[str]:
    """Ordered positional+kw-only parameter names of ``fn`` (for taint
    propagation by position and by keyword)."""
    a = fn.args  # type: ignore[attr-defined]
    names: list[str] = []
    names.extend(arg.arg for arg in getattr(a, "posonlyargs", []))
    names.extend(arg.arg for arg in a.args)
    names.extend(arg.arg for arg in a.kwonlyargs)
    return names


# Threadpool/dispatch wrappers that invoke ``fn(*args, **kwargs)`` — the
# codebase's standard "hop off the event loop" shape, e.g.
# ``await db_call(_x_db_work, db, secrets, ..., api_key_plain=...)``. The
# helper is the FIRST positional arg; the rest bind to the helper's params.
_DISPATCHERS = {"db_call", "db_call_async", "run_in_threadpool"}


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _callee_bindings(fn: ast.AST, local_func_names: set[str]):
    """Yield (callee_name, positional_arg_nodes, keyword_nodes) for every
    call within ``fn`` that invokes a locally-defined function — BOTH:

      * direct  ``helper(a, b, kw=...)``                → args/keywords as-is
      * dispatched ``db_call(helper, a, b, kw=...)``    → args[1:]/keywords
        bind to the helper's params (the dispatcher forwards ``*args,
        **kwargs`` to ``helper``).
    """
    for sub in ast.walk(fn):
        if not isinstance(sub, ast.Call):
            continue
        name = _call_name(sub)
        # Dispatched form: db_call(helper, *helper_args, **helper_kwargs)
        if (
            name in _DISPATCHERS
            and sub.args
            and isinstance(sub.args[0], ast.Name)
            and sub.args[0].id in local_func_names
        ):
            yield sub.args[0].id, sub.args[1:], sub.keywords
            continue
        # Direct form: helper(*args, **kwargs)
        if isinstance(sub.func, ast.Name) and sub.func.id in local_func_names:
            yield sub.func.id, sub.args, sub.keywords


def _arg_is_form_derived(arg, roots: set[str], places: set[str]) -> bool:
    if _is_form_expr(arg, roots):
        return True
    d = _dotted(arg)
    return d is not None and d in places


def _scan() -> tuple[list[tuple[str, str, int]], set[tuple[str, str]]]:
    """Return (violations, matched_allowlist).

    A violation is a ``secrets.set(key, <form-derived>)`` in a router file
    (excluding the SSOT) that is not in the documented allowlist.

    INTERPROCEDURAL (one-hop + fixpoint). The codebase's dominant idiom is to
    read a form value in an endpoint and pass it as a plain argument into a
    module-level ``_*_db_work`` helper (the threadpool hop), which then calls
    ``secrets.set``. A purely intra-function walk misses that shape (the SME
    review caught ``ai_backends_crud.py`` doing exactly this). So per file we
    run a fixpoint: when a function passes a form-derived value into a
    locally-defined function (by position OR keyword), the callee's matching
    parameter becomes a form root too, and we re-evaluate until no new taint
    appears. Then we flag form-derived ``secrets.set`` under the augmented
    roots.

    Honest scope: this follows values across in-module function-call
    boundaries and through name/one-level-attribute assignment. It does NOT
    track values smuggled through data structures (dict/list), through a
    cross-MODULE call, or through ``**kwargs`` spreads — those still rely on
    review + the behavioural test. Closures are covered separately by the
    parent-walk over-approximation (``ast.walk`` of an enclosing function
    includes its nested functions' bodies + assignments).
    """
    violations: list[tuple[str, str, int]] = []
    matched_allow: set[tuple[str, str]] = set()

    for p in iter_src_files("web/routers"):
        if p.name == "_secret_write.py":
            continue  # the one sanctioned secrets.set site
        rel = relpath(p)  # canonical: web/routers/<module>.py
        tree = parse_module(p)
        if tree is None:  # unparseable — skip (harness convention)
            continue
        funcs = [
            n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        local_func_names = {f.name for f in funcs}
        params = {f.name: _param_names(f) for f in funcs}
        base_roots = {
            f.name: _FORM_ROOTS | _form_param_names(f) for f in funcs
        }
        # Params tainted by a caller passing a form-derived value in.
        tainted: dict[str, set[str]] = {f.name: set() for f in funcs}

        changed = True
        while changed:
            changed = False
            for f in funcs:
                roots_f = base_roots[f.name] | tainted[f.name]
                places_f = _form_derived_places(f, roots_f)
                for callee, pos_args, kw_args in _callee_bindings(
                    f, local_func_names,
                ):
                    cps = params.get(callee, [])
                    for i, arg in enumerate(pos_args):
                        if isinstance(arg, ast.Starred):
                            continue
                        if i < len(cps) and _arg_is_form_derived(
                            arg, roots_f, places_f,
                        ):
                            if cps[i] not in tainted[callee]:
                                tainted[callee].add(cps[i])
                                changed = True
                    for kw in kw_args:
                        if kw.arg is None:  # **kwargs spread — can't track
                            continue
                        if _arg_is_form_derived(kw.value, roots_f, places_f):
                            if kw.arg not in tainted[callee]:
                                tainted[callee].add(kw.arg)
                                changed = True

        seen_lines: set[int] = set()  # dedup nested double-walks per file
        for f in funcs:
            roots_f = base_roots[f.name] | tainted[f.name]
            places_f = _form_derived_places(f, roots_f)
            for call in _secrets_set_calls(f):
                if not _value_is_form_derived(call, places_f, roots_f):
                    continue
                if call.lineno in seen_lines:
                    continue
                seen_lines.add(call.lineno)
                key = (rel, f.name)
                if key in _ALLOWED_FORM_DERIVED:
                    matched_allow.add(key)
                    continue
                violations.append((rel, f.name, call.lineno))
    return violations, matched_allow


# ---------------------------------------------------------------------------
# The pins
# ---------------------------------------------------------------------------

def test_no_form_derived_secrets_set_in_routers():
    """No router writes a form-derived value straight into the secrets store
    — every credential/secret write routes through the _secret_write SSOT."""
    violations, _matched = _scan()
    assert not violations, (
        "Form-derived secrets.set() outside the SSOT — this re-introduces "
        "the 2026-06-08 silent-clobber class (a save handler writes a "
        "credential straight from a form field that a password-manager can "
        "autofill or a blank submit can empty):\n"
        + "\n".join(
            f"  {rel}::{name} (line {lineno})"
            for rel, name, lineno in violations
        )
        + "\n\nFix: route the write through web/routers/_secret_write.py "
        "(set_secret_if_changed / set_id_preserve_blank / clear_secret), "
        "which never clobbers a stored value on a blank/autofilled field. "
        "Only add to _ALLOWED_FORM_DERIVED if the value is NOT a "
        "preserve-able stored credential (e.g. a freshly-minted token) — "
        "with a one-line justification."
    )


def test_secret_write_allowlist_is_not_stale():
    """Every _ALLOWED_FORM_DERIVED entry still matches a real form-derived
    write — a stale exception must be pruned so the allowlist stays honest."""
    _violations, matched = _scan()
    stale = _ALLOWED_FORM_DERIVED - matched
    assert not stale, (
        "Stale _ALLOWED_FORM_DERIVED entries (no longer match a form-derived "
        "secrets.set) — remove them:\n"
        + "\n".join(f"  {rel}::{name}" for rel, name in sorted(stale))
    )


def test_secret_write_ssot_exports_helpers():
    """The SSOT module exists and exposes the never-clobber helpers the
    handlers depend on."""
    from email_triage.web.routers import _secret_write as sw

    for fn in ("set_secret_if_changed", "set_id_preserve_blank", "clear_secret"):
        assert hasattr(sw, fn), f"_secret_write missing {fn}"
    # set_secret_if_changed preserves on blank (no write) and writes on value.
    writes: dict[str, str] = {}

    class _FakeSecrets:
        def set(self, k, v):
            writes[k] = v

    s = _FakeSecrets()
    assert sw.set_secret_if_changed(s, "K", "") == "preserved" and "K" not in writes
    assert sw.set_secret_if_changed(s, "K", "   ") == "preserved" and "K" not in writes
    assert sw.set_secret_if_changed(s, "K", "val") == "written" and writes["K"] == "val"
    # validate rejects (visibly) without writing.
    writes.clear()
    status = sw.set_secret_if_changed(
        s, "K", "not-a-secret", validate=sw.looks_like_google_secret,
    )
    assert status == "rejected" and "K" not in writes
    assert sw.set_secret_if_changed(
        s, "K", "GOCSPX-abc", validate=sw.looks_like_google_secret,
    ) == "written" and writes["K"] == "GOCSPX-abc"
    # id preserve-blank: blank writes NOTHING (returns current); value writes.
    writes.clear()
    assert sw.set_id_preserve_blank(s, "ID", "", "old") == "old" and "ID" not in writes
    assert sw.set_id_preserve_blank(s, "ID", "new", "old") == "new" and writes["ID"] == "new"
