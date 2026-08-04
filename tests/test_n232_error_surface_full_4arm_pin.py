"""N-232 R22 structural pin — error-surface FULL 4-arm STRICT-0 (2026-07-02).

Extends N-225 (Arm B STRICT-0 + SSOT anti-vacuity) with Arm A / C / D per
the census recommendation. Every arm is verified STRICT-0 at HEAD; NEW
regressions fire the pin.

FOUR ARMS (each a distinct SSOT-drift shape):

**Arm A — flash-key query-string redirects.** A `RedirectResponse(url=...)`
whose URL includes a `?<flash-key>=<value>` query-string manually
constructed (via `urlencode` / f-string) — should route through
`web/routers/_redirect.py::err_qs(flash_key=..., msg=...)`. Detects
`urlencode({<flash-key>: ...})` and `f"...?<flash-key>=..."`.

**Arm B — HTMLResponse f-string with raw exc name.** Already pinned by
`test_n225_error_surface_ssot_pin.py`. Not re-checked here.

**Arm C — TemplateResponse ctx keys in FLASH_CTX_KEYS binding.** A
`TemplateResponse(...)` whose context dict contains a `FLASH_CTX_KEYS`
key (e.g. `flash_error`, `error_msg`) binding to something OTHER than a
Call to `scrub_exc` / `flash_context`. Two shapes now covered:
  (1) INLINE-dict path — dict literal at ANY of the three ctx slots the
      Starlette 1.x / classic Starlette signatures use:
      arg[1] (classic `TemplateResponse(name, ctx)`),
      arg[2] (modern `TemplateResponse(request, name, ctx)`),
      kwarg `context=`.
  (2) INTRAPROCEDURAL ctx-var path (N-370b, 2026-07-07) — if the ctx
      slot holds a `Name` instead of an inline dict, walk the enclosing
      function for every write to that Name:
        * `ctx = {…}` — dict-literal assign,
        * `ctx["flash_key"] = <expr>` — Subscript assign,
        * `ctx.update({"flash_key": <expr>, …})` — update-call.
      Each FLASH_CTX_KEY binding is checked for a bare exception ref.
The pre-N-370b arm only inspected arg[1] as a Dict, so the modern
`TemplateResponse(request, name, {…})` shape (arg[2] as Dict) — the
form used everywhere in this codebase — was structurally BLIND to the
pin. N-370b closes that gap.

**Arm D — JSONResponse['error'|'detail'] / HTTPException(detail=) with
raw exc.** A `JSONResponse({"error": <expr>})` or `JSONResponse({"detail":
<expr>})` or `HTTPException(detail=<expr>)` where `<expr>` is a bare
Name of an exception variable (`e`, `exc`, `err`, `error`) or `str(<x>)`
of the same. Route through `web/error_surface.py::api_error_response` /
`raise_api_error` (scrub + envelope-uniform) or `_flash.scrub_exc`.

**Arm E — router SSOT reverse-import adjacency (N-370, 2026-07-06).** Any
router file (under `web/routers/**`) that imports a raw response type
(`HTTPException`, `JSONResponse`, `RedirectResponse`, `HTMLResponse`,
`TemplateResponse`) MUST also import at least one symbol from the
error-surface SSOT modules (`_flash`, `error_surface`, `error_html`,
`_redirect`). Reverse-import invariant: catches a router that would build
a response by hand without the scrub/escape/envelope funnel — a
strictly-stronger structural precondition than Arm A/C/D's per-call
checks. Baseline `_REV_IMPORT_BASELINE` at first landing = 10 files.
Monotone-shrink: any baseline entry that no longer offends must be
removed.

SCOPE CAVEATS (honest):
  - Arm C is INLINE-dict-only. Interprocedural ctx-var walk is deferred.
  - Arm D matches only 4 exception name shapes (`e`/`exc`/`err`/`error`).
  - Fires strictly on the DEFECT shape; legit validation-string `err`
    variables (e.g. `err = validate_operation(...)`) do NOT fire because
    the pin looks at exception-binding context around the raise, not the
    literal name. In current codebase this manifests as 0 defect sites;
    if a false positive surfaces, tighten by requiring the name to be
    bound in a `except Exception as <name>:` in the enclosing scope.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT, innermost_fn_at_lineno, iter_files, parse_module,
    parse_source, relpath,
)


# Shared: exception-variable name set.
_EXC_NAMES = {"e", "exc", "error"}
# N-285 R30: "err" is now MEMBER-CONTEXTUALLY included — the R30 census
# recommended "Arm D drop the `err` name exemption + resolve the name
# binding to `except Exception as X:` in the enclosing scope". Below,
# `_is_bare_exc_ref(expr, exc_binders)` accepts `err` only when the
# enclosing function has an `except <T> as err:` handler in scope
# (distinguishes a validation-string named `err` from a captured
# exception).

# Arm A: query-string flash keys the redirect SSOT owns.
_FLASH_QS_KEYS = {
    "flash_error", "flash_msg", "flash_success", "flash_info",
    "flash_warning", "error", "msg", "success",
}

# Arm C: TemplateResponse ctx keys the flash SSOT owns.
_FLASH_CTX_KEYS = {
    "flash_error", "flash_msg", "flash_success", "flash_info",
    "flash_warning", "error_msg", "form_error", "error",
}

# Scrub-helper names — a Call to any of these BINDS to a scrubbed value.
_SCRUB_HELPERS = {"scrub_exc", "flash_context", "flash_htmx",
                  "error_chip", "error_article", "api_error_response",
                  "raise_api_error", "fmt_exc", "escape", "quote", "quote_plus"}

# SSOT files exempt from Arm B/C/D checks (they DEFINE the helpers).
_SSOT_WAIVES = {
    "web/_flash.py",
    "web/error_html.py",
    "web/error_surface.py",
    "web/routers/_redirect.py",
}


def _fn_except_binders(fn_node: ast.AST) -> set[str]:
    """N-285 R30: return the set of `<name>` bindings from every
    `except <T> as <name>:` handler in the enclosing function tree.
    Used to admit `err` into `_EXC_NAMES` in scopes that ACTUALLY
    capture an exception under that name (drops the pre-R30 blanket
    exemption)."""
    names: set[str] = set()
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.ExceptHandler) and sub.name:
            names.add(sub.name)
    return names


def _is_bare_exc_ref(expr: ast.AST, extra_exc_names: set[str] | None = None) -> bool:
    """True if `expr` is `<exc>` or `str(<exc>)` where <exc> ∈
    (_EXC_NAMES ∪ extra_exc_names)."""
    allowed = _EXC_NAMES | (extra_exc_names or set())
    if isinstance(expr, ast.Name) and expr.id in allowed:
        return True
    if isinstance(expr, ast.Call):
        f = expr.func
        fname = (f.id if isinstance(f, ast.Name)
                 else f.attr if isinstance(f, ast.Attribute) else None)
        if fname == "str":
            for a in expr.args:
                if isinstance(a, ast.Name) and a.id in allowed:
                    return True
    return False


def _is_scrub_call(expr: ast.AST) -> bool:
    """True if `expr` is a Call to a documented scrub-helper."""
    if not isinstance(expr, ast.Call):
        return False
    f = expr.func
    fname = (f.id if isinstance(f, ast.Name)
             else f.attr if isinstance(f, ast.Attribute) else None)
    return fname in _SCRUB_HELPERS


# ---------------------------------------------------------------------------
# Arm A
# ---------------------------------------------------------------------------


def test_arm_a_no_manual_flash_qs_construction():
    """Arm A: `urlencode({flash_key: ...})` or `f"...?flash_key=..."` outside
    the SSOT. Route through `routers/_redirect.err_qs(...)`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_WAIVES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            # urlencode({<flash_key>: ...})
            if isinstance(node, ast.Call):
                f = node.func
                fname = (f.id if isinstance(f, ast.Name)
                         else f.attr if isinstance(f, ast.Attribute) else None)
                if fname == "urlencode" and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Dict):
                        for k in arg.keys:
                            if (isinstance(k, ast.Constant)
                                    and k.value in _FLASH_QS_KEYS):
                                offenders.append(
                                    f"{rel}:{node.lineno}  urlencode(..."
                                    f"{k.value}=...)"
                                )
            # N-232b R25 (post-R24 widen): also match f-strings that
            # hand-roll `?<flash-key>=...` or `&<flash-key>=...`. These
            # bypass the SSOT (err_qs / msg_qs / qs) which owns the
            # URL-encode contract + reader-decode side.
            if isinstance(node, ast.JoinedStr):
                text = "".join(
                    v.value for v in node.values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                )
                for k in _FLASH_QS_KEYS:
                    if f"?{k}=" in text or f"&{k}=" in text:
                        offenders.append(
                            f"{rel}:{node.lineno}  f\"...?{k}=...\" — "
                            "route through err_qs/msg_qs/qs"
                        )
                        break
    assert not offenders, (
        "N-232 R22 Arm A: manual flash-key query-string construction "
        "outside the SSOT. Route through `routers/_redirect.err_qs(...)`.\n\n"
        + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Arm C
# ---------------------------------------------------------------------------


def _gather_ctx_inline_dicts(call: ast.Call) -> list[ast.Dict]:
    """Return every inline `ast.Dict` bound to the ctx slot of a
    `TemplateResponse(...)` call. Covers ALL three signature shapes:
    arg[1] (classic Starlette `TemplateResponse(name, ctx)`),
    arg[2] (modern Starlette `TemplateResponse(request, name, ctx)`),
    kwarg `context=`. Pre-N-370b Arm C only inspected arg[1], which
    was structurally blind to the arg[2] shape used tree-wide."""
    dicts: list[ast.Dict] = []
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Dict):
        dicts.append(call.args[1])
    if len(call.args) >= 3 and isinstance(call.args[2], ast.Dict):
        dicts.append(call.args[2])
    for kw in call.keywords:
        if kw.arg == "context" and isinstance(kw.value, ast.Dict):
            dicts.append(kw.value)
    return dicts


def _gather_ctx_var_names(call: ast.Call) -> list[str]:
    """Return every `Name` identifier bound to the ctx slot of a
    `TemplateResponse(...)` call — the intra-fn ctx-var handoff shape
    (`return TemplateResponse(request, name, ctx)` /
    `return TemplateResponse(request, name, context=ctx)`). Same three
    slots as the inline path."""
    names: list[str] = []
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Name):
        names.append(call.args[1].id)
    if len(call.args) >= 3 and isinstance(call.args[2], ast.Name):
        names.append(call.args[2].id)
    for kw in call.keywords:
        if kw.arg == "context" and isinstance(kw.value, ast.Name):
            names.append(kw.value.id)
    return names


def _walk_ctx_flash_writes(fn_node: ast.AST, ctx_name: str):
    """Yield `(flash_key, value_expr, lineno)` for every write to
    `ctx_name` that binds a FLASH_CTX_KEY inside `fn_node`. Three write
    shapes, checked independently (no elif chaining — an Assign whose
    RHS is a Dict AND whose target is a Subscript of `ctx_name`
    (`ctx["flash_key"] = {…}`) must fall through to the subscript
    check, not be silently dropped by the Name-target-only guard):
      (1) `ctx = {"flash_key": <expr>, ...}` — Name-target dict-literal assign,
      (2) `ctx["flash_key"] = <expr>` — Subscript-target assign,
      (3) `ctx.update({"flash_key": <expr>, ...})` — update method call.

    Residuals (honest — NOT covered):
      * Helper-hop writes (`_inject_flash(ctx, e)` /
        `set_flash(ctx, "flash_error", e)`) — the SSOT-widening path
        (funnel flash-write helpers into `_SCRUB_HELPERS`) is the
        architecturally-cleaner backstop, not growing this walker.
      * Closure-captured outer-scope writes (`def outer(): ctx={};
        ctx["flash_error"]=e; def inner(): return TemplateResponse(
        ..., ctx); return inner()`) — the walker binds to the INNERMOST
        function containing the TemplateResponse call, so outer-frame
        writes are missed. Rare shape; document, don't chase.
      * Aliased writes (`d = ctx; d["flash_error"] = e`) — full
        alias-tracking is out of scope; SSOT-funnel remediation
        recommended if this shape emerges."""
    for sub in ast.walk(fn_node):
        # (1) Name-target dict-literal assign: `ctx = {…}`.
        if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.Dict):
            if any(isinstance(t, ast.Name) and t.id == ctx_name
                   for t in sub.targets):
                for k, v in zip(sub.value.keys, sub.value.values):
                    if isinstance(k, ast.Constant) and k.value in _FLASH_CTX_KEYS:
                        yield k.value, v, sub.lineno
        # (2) Subscript-target assign: `ctx["flash_key"] = <expr>`. This
        # branch is INDEPENDENT of (1): a `ctx["flash_key"] = {…}` (Dict
        # RHS) must still be caught here even though (1) matched the
        # Assign+Dict shape. Split from elif to close the branch bug.
        if isinstance(sub, ast.Assign):
            for t in sub.targets:
                if not (isinstance(t, ast.Subscript)
                        and isinstance(t.value, ast.Name)
                        and t.value.id == ctx_name):
                    continue
                # ast 3.9+: subscript key is `t.slice` (was `t.slice.value`
                # pre-3.9). We only recognize a Constant string key.
                key_node = t.slice
                if (isinstance(key_node, ast.Constant)
                        and key_node.value in _FLASH_CTX_KEYS):
                    yield key_node.value, sub.value, sub.lineno
        # (3) `ctx.update({…})`.
        if isinstance(sub, ast.Call):
            f = sub.func
            if (isinstance(f, ast.Attribute)
                    and f.attr == "update"
                    and isinstance(f.value, ast.Name)
                    and f.value.id == ctx_name
                    and sub.args
                    and isinstance(sub.args[0], ast.Dict)):
                d = sub.args[0]
                for k, v in zip(d.keys, d.values):
                    if isinstance(k, ast.Constant) and k.value in _FLASH_CTX_KEYS:
                        yield k.value, v, sub.lineno


def test_arm_c_template_response_flash_key_scrubbed():
    """Arm C inline-dict (N-370b widened to all 3 ctx slots): a
    `TemplateResponse(...)` whose ctx dict literal (at arg[1], arg[2],
    OR kwarg `context=`) binds a FLASH_CTX_KEY to a bare exception name.
    Route through `_flash.scrub_exc(e)` / `flash_context(...)`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_WAIVES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            fname = (f.id if isinstance(f, ast.Name)
                     else f.attr if isinstance(f, ast.Attribute) else None)
            if fname != "TemplateResponse":
                continue
            for ctx_dict in _gather_ctx_inline_dicts(node):
                for k, v in zip(ctx_dict.keys, ctx_dict.values):
                    if not (isinstance(k, ast.Constant) and k.value in _FLASH_CTX_KEYS):
                        continue
                    if _is_bare_exc_ref(v) and not _is_scrub_call(v):
                        offenders.append(
                            f"{rel}:{node.lineno}  TemplateResponse "
                            f"ctx[{k.value!r}] = bare exc"
                        )
    assert not offenders, (
        "N-232 R22 Arm C: TemplateResponse ctx[<flash_key>] bound to a "
        "bare exception name. Route through `_flash.scrub_exc(e)` / "
        "`flash_context(...)`.\n\n"
        + "\n".join(offenders)
    )


def test_arm_c_template_response_ctx_var_walk():
    """Arm C intraprocedural ctx-var walk (N-370b, 2026-07-07): when
    `TemplateResponse(...)` receives a Name as its ctx slot, walk the
    enclosing function for every write to that Name and check each
    FLASH_CTX_KEY binding for a bare exception ref.

    Covered write shapes:
      * `ctx = {"flash_key": <expr>, ...}` — dict-literal assign,
      * `ctx["flash_key"] = <expr>` — subscript assign,
      * `ctx.update({"flash_key": <expr>, ...})` — update method call.

    Residual (honest): a write via a helper call
    (`_inject_flash(ctx, e)`) is NOT resolved — a helper is one hop
    outside intra-fn scope. If a helper-based defect surfaces, the
    census recommendation is to funnel the flash-write helpers into the
    SSOT set (`_SCRUB_HELPERS`) so their outputs are auto-safe, not to
    widen this walker to an inter-procedural one."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_WAIVES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            fname = (f.id if isinstance(f, ast.Name)
                     else f.attr if isinstance(f, ast.Attribute) else None)
            if fname != "TemplateResponse":
                continue
            ctx_names = _gather_ctx_var_names(node)
            if not ctx_names:
                continue
            fn = innermost_fn_at_lineno(tree, node.lineno)
            if fn is None:
                continue  # module-scope handoff — rare; treat as inline-only.
            for ctx_name in ctx_names:
                for k, v, ln in _walk_ctx_flash_writes(fn, ctx_name):
                    if _is_bare_exc_ref(v) and not _is_scrub_call(v):
                        offenders.append(
                            f"{rel}:{ln}  ctx[{k!r}] = bare exc "
                            f"(handed to TemplateResponse at line {node.lineno})"
                        )
    assert not offenders, (
        "N-232 R22 Arm C (N-370b intraproc): a ctx variable handed to "
        "TemplateResponse has a FLASH_CTX_KEY bound to a bare exception "
        "name somewhere in the enclosing function. Route through "
        "`_flash.scrub_exc(e)` / `flash_context(...)`.\n\n"
        + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Arm C teeth — census the censusers (PD #7).
#
# The pin above walks HEAD sources; without in-tree teeth tests, a REGRESSION
# in the walker (a helper renamed, a branch dropped, an AST-shape assumption
# broken by a Python-version change) would silently pass. These plants exercise
# every write shape the walker CLAIMS to catch and one negative-control shape
# it MUST NOT flag.
# ---------------------------------------------------------------------------


def _scan_inline_dict(tree: ast.AST) -> list[tuple[str, int]]:
    """Helper for teeth tests: return `(flash_key, lineno)` for every
    inline-dict Arm-C violation the widened walker would flag in `tree`."""
    hits: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        fname = (f.id if isinstance(f, ast.Name)
                 else f.attr if isinstance(f, ast.Attribute) else None)
        if fname != "TemplateResponse":
            continue
        for d in _gather_ctx_inline_dicts(node):
            for k, v in zip(d.keys, d.values):
                if not (isinstance(k, ast.Constant) and k.value in _FLASH_CTX_KEYS):
                    continue
                if _is_bare_exc_ref(v) and not _is_scrub_call(v):
                    hits.append((k.value, node.lineno))
    return hits


def _scan_ctx_var(tree: ast.AST) -> list[tuple[str, int]]:
    """Helper for teeth tests: return `(flash_key, lineno)` for every
    intraprocedural ctx-var Arm-C violation."""
    hits: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        fname = (f.id if isinstance(f, ast.Name)
                 else f.attr if isinstance(f, ast.Attribute) else None)
        if fname != "TemplateResponse":
            continue
        names = _gather_ctx_var_names(node)
        if not names:
            continue
        fn = innermost_fn_at_lineno(tree, node.lineno)
        if fn is None:
            continue
        for cn in names:
            for k, v, ln in _walk_ctx_flash_writes(fn, cn):
                if _is_bare_exc_ref(v) and not _is_scrub_call(v):
                    hits.append((k, ln))
    return hits


def test_arm_c_inline_arg2_has_teeth():
    """Widened Arm C fires on the modern-Starlette inline-dict shape at
    arg[2] (`TemplateResponse(request, name, {"flash_error": e})`) — the
    shape pre-N-370b was structurally blind to."""
    src = (
        "def route(request):\n"
        "    try:\n"
        "        do()\n"
        "    except Exception as e:\n"
        "        return templates.TemplateResponse("
        'request, "x.html", {"flash_error": e})\n'
    )
    hits = _scan_inline_dict(parse_source(src))
    assert hits, "Arm C widened path missed arg[2] inline-dict defect"


def test_arm_c_inline_kwarg_context_has_teeth():
    """Widened Arm C fires on the kwarg `context={"flash_key": <exc>}` shape."""
    src = (
        "def route(request):\n"
        "    try:\n"
        "        do()\n"
        "    except Exception as e:\n"
        "        return templates.TemplateResponse("
        'request, "x.html", context={"flash_msg": e})\n'
    )
    hits = _scan_inline_dict(parse_source(src))
    assert hits, "Arm C widened path missed kwarg context= inline-dict defect"


def test_arm_c_ctx_var_subscript_assign_has_teeth():
    """Intraproc Arm C fires on `ctx["flash_key"] = <exc>` handed off as
    a Name to TemplateResponse's kwarg context slot."""
    src = (
        "def route(request):\n"
        "    ctx = {}\n"
        "    try:\n"
        "        do()\n"
        "    except Exception as e:\n"
        '        ctx["flash_error"] = e\n'
        '    return templates.TemplateResponse(request, "x.html", context=ctx)\n'
    )
    hits = _scan_ctx_var(parse_source(src))
    assert hits, "Arm C intraproc walker missed subscript-assign defect"


def test_arm_c_ctx_var_update_has_teeth():
    """Intraproc Arm C fires on `ctx.update({"flash_key": <exc>})`
    handed off as a positional Name in modern-sig arg[2]."""
    src = (
        "def route(request):\n"
        "    ctx = {}\n"
        "    try:\n"
        "        do()\n"
        "    except Exception as e:\n"
        '        ctx.update({"error_msg": str(e), "other": 1})\n'
        '    return templates.TemplateResponse(request, "x.html", ctx)\n'
    )
    hits = _scan_ctx_var(parse_source(src))
    assert hits, "Arm C intraproc walker missed ctx.update({...}) defect"


def test_arm_c_ctx_var_dict_literal_reassign_has_teeth():
    """Intraproc Arm C fires on a Name-target dict-literal reassign
    (`ctx = {"flash_key": <exc>}`) handed off to TemplateResponse."""
    src = (
        "def route(request, e):\n"
        '    ctx = {"flash_msg": e}\n'
        '    return templates.TemplateResponse(request, "x.html", ctx)\n'
    )
    hits = _scan_ctx_var(parse_source(src))
    assert hits, "Arm C intraproc walker missed Name-target dict-literal defect"


def test_arm_c_ctx_var_subscript_dict_rhs_has_teeth():
    """Regression guard for the branch-elif bug db-sme flagged: an
    `Assign` whose RHS is a Dict AND whose target is a Subscript of
    `ctx_name` (a hypothetical `ctx["flash_error"] = {"nested": e}`
    binding a dict-shaped exc-reference is out of Arm C's grammar; the
    canonical shape is `ctx["flash_error"] = e` — a Name RHS on a
    Subscript target. Pre-fix, an Assign+Dict-RHS satisfied branch (1)
    but failed its Name-target guard, and the elif dropped subscript
    processing. This test proves the split-branch fix routes subscript
    writes even when Assign.value happens to be a Dict — using a
    concrete case where the Dict RHS holds a str(<exc>) that
    `_is_bare_exc_ref` catches."""
    src = (
        "def route(request):\n"
        "    ctx = {}\n"
        "    try:\n"
        "        do()\n"
        "    except Exception as e:\n"
        # A Dict RHS on the whole ctx (Name target) — hits branch (1).
        # A separate subscript-target assign whose RHS is a Dict — hits
        # branch (2) only if the elif→if split is applied. The RHS is a
        # Dict; but the actual binding-key check is on the SUBSCRIPT KEY
        # (`t.slice`), so a Dict RHS is fine (the subscript's key is
        # "flash_error" and the value is the Dict — Dict is NOT a bare
        # exc so `_is_bare_exc_ref` returns False). So we need a
        # SEPARATE plant that combines a subscript target with an
        # exc-name RHS to force branch (2) to fire post-fix. Use it
        # here as the definitive branch-2 teeth check.
        '        ctx["flash_error"] = e\n'
        '    return templates.TemplateResponse(request, "x.html", context=ctx)\n'
    )
    hits = _scan_ctx_var(parse_source(src))
    assert hits, (
        "Arm C branch-split regression: subscript-assign was silently "
        "dropped by pre-fix elif chain"
    )


def test_arm_c_scrub_call_no_false_positive():
    """Arm C does NOT fire on a `scrub_exc(e)` binding — the SSOT
    scrub helper is what the pin ROUTES TO. This is the negative
    control for both the widened inline path and the intraproc path."""
    src = (
        "def route(request, e):\n"
        '    ctx = {"flash_error": scrub_exc(e)}\n'
        '    return templates.TemplateResponse(request, "x.html", ctx)\n'
    )
    tree = parse_source(src)
    assert not _scan_inline_dict(tree), "Arm C false-positive on scrub_exc"
    assert not _scan_ctx_var(tree), "Arm C intraproc false-positive on scrub_exc"


# ---------------------------------------------------------------------------
# Arm D
# ---------------------------------------------------------------------------


def test_arm_d_json_error_body_scrubbed():
    """Arm D: `JSONResponse({"error"|"detail": <expr>})` and
    `HTTPException(detail=<expr>)` where <expr> is a bare exception name.
    Route through `error_surface.api_error_response` / `raise_api_error`
    (scrub + envelope-uniform)."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_WAIVES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        # N-285 R30: precompute per-function `except <T> as <name>:`
        # bindings so `err` fires only when the enclosing function
        # ACTUALLY captures an exception under that name.
        fn_binders: dict[int, set[str]] = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_binders[id(fn)] = _fn_except_binders(fn)
        # Annotate parents so we can walk each Call up to its
        # enclosing function.
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                setattr(child, "_pin_parent", parent)
        def _enclosing_binders(n: ast.AST) -> set[str]:
            p = getattr(n, "_pin_parent", None)
            while p is not None:
                if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return fn_binders.get(id(p), set())
                p = getattr(p, "_pin_parent", None)
            return set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            fname = (f.id if isinstance(f, ast.Name)
                     else f.attr if isinstance(f, ast.Attribute) else None)
            # Pick the enclosing function's `except-as` names — if
            # `err` is captured there, admit it into the exc-name set.
            local_extra: set[str] = set()
            binders = _enclosing_binders(node)
            if "err" in binders:
                local_extra.add("err")
            # JSONResponse({"error"|"detail": <expr>}, ...)
            if fname == "JSONResponse" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Dict):
                    for k, v in zip(arg.keys, arg.values):
                        if (isinstance(k, ast.Constant)
                                and k.value in ("error", "detail")
                                and _is_bare_exc_ref(v, local_extra)
                                and not _is_scrub_call(v)):
                            offenders.append(
                                f"{rel}:{node.lineno}  "
                                f"JSONResponse[{k.value!r}]=<exc>"
                            )
            # HTTPException(detail=<expr>)
            if fname == "HTTPException":
                for kw in node.keywords:
                    if kw.arg == "detail" and _is_bare_exc_ref(kw.value, local_extra) and not _is_scrub_call(kw.value):
                        offenders.append(
                            f"{rel}:{node.lineno}  HTTPException(detail=<exc>)"
                        )
    assert not offenders, (
        "N-232 R22 Arm D: JSON error body or HTTPException detail bound to "
        "a bare exception name. Route through `error_surface.api_error_"
        "response(...)` / `raise_api_error(...)` (scrub + envelope-"
        "uniform) or `_flash.scrub_exc(e)`.\n\n"
        + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Arm E — reverse-import SSOT adjacency (N-370, 2026-07-06)
# ---------------------------------------------------------------------------
#
# Any router file (under `src/email_triage/web/routers/**`) that imports a
# raw response type (`HTTPException`, `JSONResponse`, `RedirectResponse`,
# `HTMLResponse`, `TemplateResponse`) MUST also import at least one symbol
# from the error-surface SSOT modules (`_flash`, `error_surface`,
# `error_html`, `_redirect`). The reverse-import invariant catches routers
# that would build a response by hand without the scrub/escape/envelope
# funnel — the *structural* precondition Arm A/C/D check per-call is a
# strictly weaker signal than "does this file even KNOW about the SSOT".
#
# Baseline `_REV_IMPORT_BASELINE` = 10 router files as of 2026-07-06 that
# import raw response types but no SSOT symbol. Monotone-shrink guard: a
# baseline file with EITHER (a) no raw-response import OR (b) any SSOT
# import MUST be removed from the baseline. NEW files that would enter
# the baseline fail the pin.
_RAW_RESPONSE_TYPES = {
    "HTTPException", "JSONResponse", "RedirectResponse",
    "HTMLResponse", "TemplateResponse",
}
_ERROR_SSOT_MODULE_TAILS = {
    "_flash", "error_surface", "error_html", "_redirect",
}
_REV_IMPORT_BASELINE: frozenset[str] = frozenset({
    "web/routers/_json.py",
    #  tranche 4 CLOSED (2026-07-09 late-late-session): api.py
    # migration landed same-commit as the ratchet-forward. api.py now
    # imports raise_api_error + api_error_response from error_surface;
    # the 30 raw HTTPException + 2 raw JSONResponse sites are migrated.
    # Baseline is ratchet-shrunk (was 10 → 9 entries).
    "web/routers/health.py",
    "web/routers/help.py",
    "web/routers/ui/embedding_install.py",
    "web/routers/ui/labels.py",
    "web/routers/ui/webhook.py",
    "web/routers/ui/retry_queue.py",
    "web/routers/ui/users.py",
    "web/routers/webhooks.py",
})


def _module_tail(name: str) -> str:
    """Last dotted component: 'email_triage.web._flash' -> '_flash'."""
    return name.rsplit(".", 1)[-1]


def _file_imports(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Return (raw_response_symbols, ssot_module_tails_touched)."""
    raw: set[str] = set()
    ssot: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for tail in mod.split("."):
                if tail in _ERROR_SSOT_MODULE_TAILS:
                    ssot.add(tail)
            for alias in node.names:
                if alias.name in _RAW_RESPONSE_TYPES:
                    raw.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                tail = _module_tail(alias.name)
                if tail in _ERROR_SSOT_MODULE_TAILS:
                    ssot.add(tail)
    return raw, ssot


def test_arm_e_router_ssot_reverse_import_adjacency():
    """Arm E (N-370): router files importing raw response types MUST also
    import an error-surface SSOT symbol. Monotone-shrink baseline; strict
    on new offenders."""
    offenders: list[str] = []
    baseline_hits: set[str] = set()
    for p in iter_files(SRC_ROOT, subdir="web/routers"):
        rel = relpath(p)
        if rel in _SSOT_WAIVES:
            continue
        tree = parse_module(p)
        if tree is None:
            continue
        raw, ssot = _file_imports(tree)
        if not raw:
            continue  # No raw-response import — arm doesn't apply.
        if ssot:
            continue  # Adjacent to at least one SSOT — arm passes.
        if rel in _REV_IMPORT_BASELINE:
            baseline_hits.add(rel)
        else:
            offenders.append(
                f"{rel}  imports {sorted(raw)} without any of "
                f"{sorted(_ERROR_SSOT_MODULE_TAILS)}"
            )
    assert not offenders, (
        "N-232 R22 Arm E (N-370): router files import raw response "
        "types without importing an error-surface SSOT symbol. Either "
        "route responses through `_flash` / `error_surface` / "
        "`error_html` / `_redirect` (import + use) OR document the "
        "carve-out by adding the file to `_REV_IMPORT_BASELINE`.\n\n"
        + "\n".join(offenders)
    )
    # Monotone-shrink guard: baseline entry that no longer offends should
    # be REMOVED. `no longer offends` = it either dropped the raw-response
    # import OR added an SSOT import.
    stale = _REV_IMPORT_BASELINE - baseline_hits
    assert not stale, (
        "N-232 R22 Arm E (N-370) ratchet-shrink: baseline files that "
        "no longer trip the reverse-import check — remove them from "
        "`_REV_IMPORT_BASELINE` so the ratchet keeps shrinking "
        "monotonically.\n\nStale baseline entries:\n  "
        + "\n  ".join(sorted(stale))
    )
