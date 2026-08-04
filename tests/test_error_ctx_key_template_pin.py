"""Error-surfacing ctx-key → template-reference pin (divergence census run13 #5).

A request handler that wants to show an error on a rendered page passes an
ERROR-FAMILY context key — ``error`` / ``form_error`` / ``error_message`` /
``error_msg`` / ``flash_error`` — into the template context. If the rendered
template never REFERENCES that key (because a sibling handler/template settled
on a different key-name — ``error`` vs ``form_error`` — and the two drifted),
Jinja silently renders the missing variable as empty: the user submits a bad
form, the save fails, and the page comes back with NO visible error. The bug is
invisible to a unit test that asserts on the model/DB (the handler "worked"),
and invisible to ``py_compile`` — it only shows in the rendered VIEW (the
binding rule ``feedback_test_the_view_not_just_machinery``).

Census run13 #5 verified the ~7 current error-render handler/template pairs are
CONSISTENT at HEAD (no live blank-render). This pin is the FORWARD-DRIFT guard:
it makes the consistency a structural invariant so the next ``error`` vs
``form_error`` fork fails a test instead of shipping a silent blank.

COUNT-AGNOSTIC PROPERTY (over every render call in ``src/email_triage/web``):
for every call that passes an error-family key K into a LITERAL-named template T,
T — or any template it ``{% extends %}`` / ``{% include %}`` / ``{% import %}`` /
``{% from %}`` (transitively, bounded) — must REFERENCE K inside a Jinja
expression/statement block. No ``len(...)==N``; the AST self-enumerates the
render sites, so a new handler is covered the moment it is written.

DELIBERATE SCOPING (documented, not accidental):
* A render call is identified structurally — a ``*.html`` string-literal arg
  alongside an error-family context key — so it is render-HELPER-agnostic
  (``_render`` / ``TemplateResponse`` / any wrapper). It does not hard-code a
  helper name.
* The context keys are read from an inline ``{...}`` dict (or ``context=``/``ctx=``
  dict kwarg, or an ``error=``-style kwarg), AND from a ``ctx = {...}`` dict
  literal assigned in the SAME function and passed by name. A context built by
  ``dict(**a, **b)`` or mutated across calls is not traced (rare; a residual a
  future true-up re-measures).
* A template NAME that does not resolve to a file under ``TEMPLATES_ROOT``
  (dynamic name, or a name built at runtime) is EXEMPT — the pin cannot judge a
  template it cannot read, and must not false-positive a consistent pair.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    TEMPLATES_ROOT,
    enclosing_fn,
    iter_src_files,
    parse_module,
    parse_source,
    relpath,
)

# The message-bearing context keys whose value is rendered as text. A handler
# passing one of these MUST have the rendered template reference it, or the
# message shows blank. (A status-code / boolean ``*_error`` flag is not in this
# set — only the keys that render as text.) Widened run17  from the error
# family to ALSO cover the SUCCESS-flash render keys (``save_msg`` / ``save_error``)
# and the validation-error LIST key (``errors``) — these are passed to inline
# (no-redirect) renders (e.g. config.html / profile/watches.html) and a sibling
# key-name fork would silently blank the notice just the same (census run17 
# S7: profile.py:3494 ``errors``/``save_msg``, admin.py:1207 ``save_msg``/``save_error``).
_ERROR_KEYS = {
    "error", "form_error", "error_message", "error_msg", "flash_error",
    "save_msg", "save_error", "errors",
}

# Jinja expression / statement blocks — a key is "referenced" only inside one of
# these (NOT in plain HTML prose, so the literal word "error" in body copy is
# not a false reference).
_JINJA_BLOCK_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL)
# Inherited / included template names (literal only — a dynamic include is
# unresolvable and the inheriting template's own blocks still get scanned).
_INHERIT_RE = re.compile(
    r"""\{%-?\s*(?:extends|include|import|from)\s+['"]([^'"]+\.html)['"]"""
)


def _str_const(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _template_name(call: ast.Call) -> str | None:
    """The first ``*.html`` string-literal arg/kwarg of a call, else None."""
    for a in call.args:
        s = _str_const(a)
        if s and s.endswith(".html"):
            return s
    for kw in call.keywords:
        s = _str_const(kw.value)
        if s and s.endswith(".html"):
            return s
    return None


def _error_keys_in_dict(d: ast.Dict) -> set[str]:
    out: set[str] = set()
    for k in d.keys:
        s = _str_const(k) if k is not None else None
        if s in _ERROR_KEYS:
            out.add(s)
    return out


def _error_keys_for_call(call: ast.Call, dict_vars: dict[str, set[str]]) -> set[str]:
    """Error-family keys this render call supplies — from inline dict literals,
    error-family kwargs, and a same-function ``ctx = {...}`` passed by name."""
    found: set[str] = set()
    for a in call.args:
        if isinstance(a, ast.Dict):
            found |= _error_keys_in_dict(a)
        elif isinstance(a, ast.Name) and a.id in dict_vars:
            found |= dict_vars[a.id]
    for kw in call.keywords:
        if isinstance(kw.value, ast.Dict):
            found |= _error_keys_in_dict(kw.value)
        elif isinstance(kw.value, ast.Name) and kw.value.id in dict_vars:
            found |= dict_vars[kw.value.id]
        elif kw.arg in _ERROR_KEYS:
            found.add(kw.arg)
    return found


def _dict_vars_in_fn(fn: ast.AST) -> dict[str, set[str]]:
    """Map ``name -> error-keys`` for every ``name = {...dict literal...}``
    assignment inside a function body (the ``ctx = {...}`` build pattern)."""
    out: dict[str, set[str]] = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            keys = _error_keys_in_dict(node.value)
            if not keys:
                continue
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out.setdefault(tgt.id, set()).update(keys)
    return out


def _template_blocks(name: str, _seen: set[str] | None = None, _depth: int = 0) -> str | None:
    """Combined Jinja-block text of template ``name`` + its transitive
    extends/include/import targets (bounded). Returns None if ``name`` does not
    resolve to a readable file under TEMPLATES_ROOT (unjudgeable → exempt)."""
    if _seen is None:
        _seen = set()
    if name in _seen or _depth > 4:
        return ""
    _seen.add(name)
    path = TEMPLATES_ROOT / name
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    blocks = "\n".join(_JINJA_BLOCK_RE.findall(raw))
    for child in _INHERIT_RE.findall(raw):
        child_blocks = _template_blocks(child, _seen, _depth + 1)
        if child_blocks:
            blocks += "\n" + child_blocks
    return blocks


def _references(name: str, key: str) -> bool | None:
    """True/False if template ``name`` (transitively) references ``key`` in a
    Jinja block; None if the template is unresolvable (exempt)."""
    blocks = _template_blocks(name)
    if blocks is None:
        return None
    return re.search(r"\b" + re.escape(key) + r"\b", blocks) is not None


def _offenders(tree: ast.AST) -> list[tuple[str, str]]:
    """(template, key) pairs where a render call passes an error-family key the
    named (resolvable) template never references."""
    bad: list[tuple[str, str]] = []
    fn_cache: dict[int, dict[str, set[str]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _template_name(node)
        if name is None:
            continue
        fn = node
        # find enclosing function node for the dict-var scan
        cur = getattr(node, "_ph_parent", None)
        fn_node: ast.AST | None = None
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_node = cur
                break
            cur = getattr(cur, "_ph_parent", None)
        if fn_node is not None:
            dv = fn_cache.get(id(fn_node))
            if dv is None:
                dv = _dict_vars_in_fn(fn_node)
                fn_cache[id(fn_node)] = dv
        else:
            dv = {}
        keys = _error_keys_for_call(node, dv)
        for k in keys:
            ref = _references(name, k)
            if ref is False:
                bad.append((name, k))
    return bad


def test_error_ctx_key_referenced_by_template():
    offenders: list[str] = []
    for p in iter_src_files("web"):
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        for name, key in _offenders(tree):
            offenders.append(f"{relpath(p)}: template {name!r} never references {key!r}")
    assert not offenders, (
        "A handler passes an error-family context key the rendered template "
        "NEVER references — the error message renders BLANK (census run13 #5):\n  "
        + "\n  ".join(sorted(set(offenders)))
        + "\nFix: rename the handler key OR the template reference so they match "
        "(the canonical key for a form page is `form_error`; for a flash, "
        "`error`). Test the rendered VIEW, not just the model."
    )


def test_pin_has_teeth():
    # END-TO-END: a planted render call passing `form_error` to a REAL,
    # resolvable template (login.html) that references `error` but NOT
    # `form_error` IS flagged as an offender (the blank-render bug shape).
    planted = parse_source(
        'def h(templates, request):\n'
        '    return _render(templates, request, "login.html", {"form_error": "boom"})\n'
    )
    offs = _offenders(planted)
    assert ("login.html", "form_error") in offs, (
        "pin missed a planted handler/template error-key MISMATCH"
    )
    # … and the consistent twin (passing `error` to login.html) is NOT flagged.
    ok = parse_source(
        'def h(templates, request):\n'
        '    return _render(templates, request, "login.html", {"error": "boom"})\n'
    )
    assert _offenders(ok) == [], "pin false-flagged a CONSISTENT error-render pair"
    # A template name that does not resolve to a file is EXEMPT (unjudgeable),
    # never an offender — the pin must not false-positive a dynamic name.
    exempt = parse_source(
        'x = _render(t, r, "__definitely_not_a_real_template__.html", {"error": e})\n'
    )
    assert _offenders(exempt) == [], "pin flagged an unresolvable (exempt) template"

    # Inline + dict-var + kwarg extraction all detect the key:
    t1 = parse_source(
        'def a(t, r):\n'
        '    return _render(t, r, "x.html", {"form_error": e})\n'
    )
    call1 = next(n for n in ast.walk(t1) if isinstance(n, ast.Call) and _template_name(n))
    assert _error_keys_for_call(call1, {}) == {"form_error"}, "missed inline-dict key"

    t2 = parse_source(
        'def b(t, r):\n'
        '    ctx = {"error": msg, "user": u}\n'
        '    return _render(t, r, "x.html", ctx)\n'
    )
    fn2 = next(n for n in ast.walk(t2) if isinstance(n, ast.FunctionDef))
    call2 = next(n for n in ast.walk(t2) if isinstance(n, ast.Call) and _template_name(n))
    assert _error_keys_for_call(call2, _dict_vars_in_fn(fn2)) == {"error"}, (
        "missed ctx-variable-built key"
    )

    t3 = parse_source('x = render(request, "y.html", error="boom")\n')
    call3 = next(n for n in ast.walk(t3) if isinstance(n, ast.Call) and _template_name(n))
    assert _error_keys_for_call(call3, {}) == {"error"}, "missed error= kwarg"

    # A call with NO error-family key yields nothing (no false render-site)
    t4 = parse_source('x = _render(t, r, "z.html", {"user": u, "count": 3})\n')
    call4 = next(n for n in ast.walk(t4) if isinstance(n, ast.Call) and _template_name(n))
    assert _error_keys_for_call(call4, {}) == set(), "flagged a non-error context"
