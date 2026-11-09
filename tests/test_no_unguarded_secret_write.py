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
from functools import lru_cache

import pytest

from _pin_harness import (
    REEXPORT_DEPTH,
    TaintResult,
    arg_is_derived,
    assert_pin_has_teeth,
    derived_places,
    iter_defs,
    iter_src_files,
    param_taint_fixpoint,
    parse_module,
    parse_source,
    relpath,
)


# (module-path, qualified function name) writes that are form-handler-adjacent but
# legitimately NOT the clobber class. The module-path is the canonical
# harness ``relpath`` form (``web/routers/ui/oauth.py``); the function is the harness's
# qualified def name (``save``, ``Handler.post``, ``endpoint._work``). Empty today: after the
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


def _form_roots_of(fn: ast.AST) -> set[str]:
    """A def's own form roots: the ``form`` body binding plus its ``Form(..)`` parameters."""
    return _FORM_ROOTS | _form_param_names(fn)


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
    return arg_is_derived(call.args[1], roots, places)


@lru_cache(maxsize=1)
def _router_modules() -> dict[str, ast.AST]:
    """``{canonical relpath: tree}`` for every router file except the SSOT. Parsed once per process:
    every caller only reads the trees, and one dict of one set of trees is what lets ``_taint``
    reuse the live graph (sme-db NOTE-6)."""
    modules: dict[str, ast.AST] = {}
    for p in iter_src_files("web/routers"):
        if p.name == "_secret_write.py":
            continue  # the one sanctioned secrets.set site
        tree = parse_module(p)
        if tree is None:  # unparseable — skip (harness convention)
            continue
        modules[relpath(p)] = tree  # canonical: web/routers/<module>.py
    return modules


def _taint(modules: dict[str, ast.AST]):
    """The pin's OWN taint run, the one both the violation scan and the unresolved-hop pin use.

    ``loose_receivers=True`` restores an edge the d6adcce0 walker followed and the first harness
    port dropped: a dispatcher hop whose callee has an unknown receiver (``db_call(obj.f, v)``,
    ``db_call(mod.f, v)`` with ``mod`` not an import the resolver knows) binds to the def named
    ``f``. The graph follows it when exactly one def of that name exists in the tree; when several
    do, the hop is NOT followed and ``unresolved`` carries it (see ``_unresolved_hops``), as it
    carries a dispatcher hop whose callee names no def but may run one of the tree (a subscript or
    call-result callable, a module-set import resolving to no def, a callable held in a parameter or
    a local, an inherited ``self.f``).

    Memoised per module set (sme-db NOTE-6): the live router graph was rebuilt by every test that
    scans it."""
    return _taint_of(tuple(modules.items()))


@lru_cache(maxsize=32)
def _taint_of(items: tuple) -> TaintResult:
    """``_taint`` keyed on the module set's ``(rel, tree)`` pairs. A tree hashes by identity, so two
    planted sets that reuse the rels ``web/routers/a.py`` / ``b.py`` with different sources never
    share an entry, and the cache holds its keys' trees, so no id is reused while it is a key. Callers
    only read the result."""
    return param_taint_fixpoint(dict(items), _form_roots_of, loose_receivers=True)


def _unresolved(modules: dict[str, ast.AST]) -> list:
    """Every call or hop that carries a form-derived value to a def the graph could not name (PD-8:
    such a hop must fail the pin, never read as "does not reach"): an unknown receiver not pinned to
    ONE def, or an ``UnresolvedHop``. Sorted by module, def and line."""
    return sorted(_taint(modules).unresolved, key=lambda u: (*u.caller, u.call.lineno, u.callee))


def _unresolved_hops(modules: dict[str, ast.AST]) -> list[tuple[str, str, str, int]]:
    """``(module, calling def, callee, line)`` for each of :func:`_unresolved`."""
    return [(u.caller[0], u.caller[1], u.callee, u.call.lineno) for u in _unresolved(modules)]


def _scan_modules(
    modules: dict[str, ast.AST],
) -> tuple[list[tuple[str, str, int]], set[tuple[str, str]], set[tuple[str, str, str]]]:
    """Return (violations, matched_allowlist, crossings) over ``modules`` (``{relpath: tree}``).

    A violation is a ``secrets.set(key, <form-derived>)`` in one of ``modules``
    that is not in the documented allowlist. ``crossings`` is every
    ``(caller module, callee module, callee name)`` where a form-derived value was
    handed to a function of ANOTHER module: the proof the cross-module hop was
    followed (the live pin asserts it is non-empty, so a resolver that stops seeing
    the live route cannot pass vacuously).

    INTERPROCEDURAL (fixpoint over the whole module set). The codebase's dominant
    idiom is to read a form value in an endpoint and pass it as a plain argument
    into a module-level ``_*_db_work`` helper (the threadpool hop), which then calls
    ``secrets.set``. A purely intra-function walk misses that shape (the SME
    review caught ``ai_backends_crud.py`` doing exactly this). The fixpoint is the
    harness's ``param_taint_fixpoint`` (census-r2 B4): when a function passes a
    form-derived value into a function of this tree (by position OR keyword), the
    callee's matching parameter becomes a form root too, and it re-evaluates until no
    new taint appears. Then we flag form-derived ``secrets.set`` under the augmented roots.

    The callee may be in another module (punch 672): imported by name (a re-export is chased
    ``REEXPORT_DEPTH`` modules deep), reached as ``mod.f(..)``, or
    reached bare through the ``globals().update(vars(_shared))`` snapshot the ``web/routers/ui``
    concern files use (see ``_pin_harness.CrossModuleResolver``).

    Honest scope: this pin owns the form roots and the ``secrets.set`` sink; what a call
    follows is the harness ``CallGraph`` scope (see its header). It does NOT track values
    smuggled through data structures (dict/list), through ``**kwargs`` spreads, or into a
    helper OUTSIDE ``web/routers`` — those still rely on review + the behavioural test.
    Closures are covered separately by the parent-walk over-approximation (``ast.walk`` of an
    enclosing function includes its nested functions' bodies + assignments).
    """
    taint = _taint(modules)
    violations: list[tuple[str, str, int]] = []
    matched_allow: set[tuple[str, str]] = set()
    seen_lines: dict[str, set[int]] = {}  # dedup nested double-walks per file
    for rel, qual, f in iter_defs(modules):
        roots_f = _form_roots_of(f) | taint.tainted[(rel, qual)]
        places_f = derived_places(f, roots_f)
        for call in _secrets_set_calls(f):
            if not _value_is_form_derived(call, places_f, roots_f):
                continue
            if call.lineno in seen_lines.setdefault(rel, set()):
                continue
            seen_lines[rel].add(call.lineno)
            key = (rel, qual)
            if key in _ALLOWED_FORM_DERIVED:
                matched_allow.add(key)
                continue
            violations.append((rel, qual, call.lineno))
    return violations, matched_allow, taint.crossings


def _scan() -> tuple[list[tuple[str, str, int]], set[tuple[str, str]]]:
    """Return (violations, matched_allowlist) over the live router tree."""
    violations, matched_allow, _crossings = _scan_modules(_router_modules())
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


# ---------------------------------------------------------------------------
# Punch 672 — the cross-module hop. Teeth feed planted router pairs to the pure scan; the live
# test asserts the real router tree is crossed (the rig can SEE the live route, not only pass).
# ---------------------------------------------------------------------------

_HANDLER = "async def handler(request, secrets):\n    form = await request.form()\n    {call}\n"
_UNSAFE_HELPER = "def save(secrets, value):\n    secrets.set('K', value)\n"
_SAFE_HELPER = (
    "from email_triage.web.routers._secret_write import set_secret_if_changed\n"
    "def save(secrets, value):\n    set_secret_if_changed(secrets, 'K', value)\n"
)
_SNAPSHOT = "from . import b\nglobals().update({n: v for n, v in vars(b).items()})\n"


def _planted(head: str, call: str, helper: str = _UNSAFE_HELPER):
    """Scan a planted router (``head`` + a handler making ``call``) and a helper module ``b``."""
    modules = {
        "web/routers/a.py": ast.parse(head + _HANDLER.format(call=call)),
        "web/routers/b.py": ast.parse(helper),
    }
    return _scan_modules(modules)


_CROSS_MODULE_RED = {
    "import by name": ("from .b import save\n", "save(secrets, form['k'])"),
    "import under an alias": ("from .b import save as store\n", "store(secrets, form['k'])"),
    "absolute import": ("from email_triage.web.routers.b import save\n", "save(secrets, form['k'])"),
    "dispatched by name": ("from .b import save\n", "await db_call(save, secrets, form['k'])"),
    "dispatched through a lambda": (
        "from .b import save\n", "await db_call(lambda: save(secrets, form['k']))"),
    "module attribute": ("from . import b\n", "b.save(secrets, form['k'])"),
    "module attribute, dispatched": ("from . import b\n", "await db_call(b.save, secrets, form['k'])"),
    "import as module alias": (
        "import email_triage.web.routers.b as helpers\n", "helpers.save(secrets, form['k'])"),
    "globals().update(vars(b)) snapshot": (_SNAPSHOT, "save(secrets, form['k'])"),
    "snapshot, dispatched": (_SNAPSHOT, "await db_call(save, secrets, form['k'])"),
}


@pytest.mark.parametrize("label", sorted(_CROSS_MODULE_RED))
def test_a_form_value_handed_to_a_helper_in_another_module_is_caught(label):
    """Punch 672: every way a router reaches a helper defined in another module, with a form value
    in hand, trips the pin at the helper's ``secrets.set`` (it saw only same-module helpers)."""
    head, call = _CROSS_MODULE_RED[label]
    violations, _allow, crossings = _planted(head, call)
    assert violations == [("web/routers/b.py", "save", 2)], (label, violations)
    assert ("web/routers/a.py", "web/routers/b.py", "save") in crossings, (label, crossings)


def test_the_cross_module_hop_does_not_over_reach():
    """The legal neighbours stay green: a helper that routes through the SSOT, a literal value, an
    own ``def`` that shadows the import, and a same-named helper in a module never imported."""
    safe, _a, crossings = _planted("from .b import save\n", "save(secrets, form['k'])", _SAFE_HELPER)
    assert safe == [], safe
    assert ("web/routers/a.py", "web/routers/b.py", "save") in crossings  # followed, and clean
    literal, _a, crossings = _planted("from .b import save\n", "save(secrets, 'literal')")
    assert literal == [] and not crossings, (literal, crossings)
    shadow, _a, crossings = _planted(
        "from .b import save\ndef save(secrets, value):\n    return None\n", "save(secrets, form['k'])")
    assert shadow == [] and not crossings, (shadow, crossings)
    unimported, _a, crossings = _planted("", "save(secrets, form['k'])")
    assert unimported == [] and not crossings, (unimported, crossings)


# ---------------------------------------------------------------------------
# Census-r2 B fold (sme-da MUST-1 / SHOULD-1): a hop on an UNKNOWN receiver. The d6adcce0 walker bound
# `db_call(obj.f, v)` / `db_call(mod.f, v)` to the def named `f` whatever the receiver; the first
# harness port dropped it silently. Followed again when `f` names exactly one def; when it names
# several, the hop is reported (`_unresolved_hops`), never dropped.
# ---------------------------------------------------------------------------

_METHOD_SINK = "class W:\n    def f(self, value):\n        secrets.set('K', value)\n"
_FUNCTION_SINK = "def f(value):\n    secrets.set('K', value)\n"

_UNKNOWN_RECEIVER_RED = {
    "obj.f hop, f a method": ("await db_call(obj.f, form['k'])", _METHOD_SINK, "W.f", 3),
    "mod.f hop, mod not an import": ("await db_call(mod.f, form['k'])", _FUNCTION_SINK, "f", 2),
    "obj.f hop through a lambda": ("await db_call(lambda: obj.f(form['k']))", _METHOD_SINK, "W.f", 3),
    "obj.f direct call": ("obj.f(form['k'])", _METHOD_SINK, "W.f", 3),
    "mod.f hop, keyword": ("await db_call(mod.f, value=form['k'])", _FUNCTION_SINK, "f", 2),
}


@pytest.mark.parametrize("label", sorted(_UNKNOWN_RECEIVER_RED))
def test_a_form_value_handed_to_an_unknown_receivers_def_is_caught(label):
    call, helper, qual, line = _UNKNOWN_RECEIVER_RED[label]
    violations, _allow, crossings = _planted("", call, helper)
    assert violations == [("web/routers/b.py", qual, line)], (label, violations)
    assert ("web/routers/a.py", "web/routers/b.py", qual) in crossings, (label, crossings)
    modules = {"web/routers/a.py": ast.parse(_HANDLER.format(call=call)), "web/routers/b.py": ast.parse(helper)}
    assert _unresolved_hops(modules) == [], label  # followed, so nothing is left unresolved


def test_an_unknown_receiver_hop_to_a_name_several_defs_share_is_reported_never_dropped():
    two = {
        "web/routers/a.py": ast.parse(_HANDLER.format(call="await db_call(mod.f, form['k'])")),
        "web/routers/b.py": ast.parse(_FUNCTION_SINK),
        "web/routers/c.py": ast.parse(_FUNCTION_SINK),
    }
    violations, _allow, _crossings = _scan_modules(two)
    assert violations == []  # not followed: it could be either def
    assert _unresolved_hops(two) == [("web/routers/a.py", "handler", "f", 3)]
    # a literal, or a call that reaches nothing derived, is not reported
    literal = dict(two, **{"web/routers/a.py": ast.parse(_HANDLER.format(call="await db_call(mod.f, 'k')"))})
    assert _unresolved_hops(literal) == []
    direct = dict(two, **{"web/routers/a.py": ast.parse(_HANDLER.format(call="obj.f(form['k'])"))})
    assert _unresolved_hops(direct) == [("web/routers/a.py", "handler", "f", 3)]  # a direct call too


# ---------------------------------------------------------------------------
# Census-r2 B fold 2 (sme-da SHOULD-1 residual, sme-db NOTE-2 / NOTE-3): a dispatcher hop whose callee
# names no def is REPORTED, never read as "does not reach". A hop into a module outside the set is
# not: the resolver's import table decides that, never a name list.
# ---------------------------------------------------------------------------

_A = "web/routers/a.py"
_DEPTH_CHAIN = (
    ("web/routers/m0.py", _UNSAFE_HELPER),
    *((f"web/routers/m{i}.py", f"from .m{i - 1} import save\n") for i in range(1, REEXPORT_DEPTH + 2)),
)


def _hop_detector(*helpers: tuple[str, str]):
    """A detector over a planted ``web/routers/a.py`` tree plus helper modules ``(rel, source)``."""
    trees = {rel: parse_source(src) for rel, src in helpers}
    return lambda tree: _unresolved({_A: tree, **trees})


_UNRESOLVED_RED = {
    # label: (head, call, helper modules, callee text, a word of the reason)
    "subscript callee": ("", "await db_call(table['k'], secrets, form['k'])", (), "table['k']", "subscript"),
    "call-result callee": ("", "await db_call(make(), secrets, form['k'])", (), "make()", "call result"),
    "called call-result callee": ("", "await db_call(make()(1), secrets, form['k'])", (), "make()(1)", "call result"),
    "constant getattr callee": ("from . import b\n", "await db_call(getattr(b, 'save'), secrets, form['k'])",
                                (("web/routers/b.py", _UNSAFE_HELPER),), "getattr(b, 'save')", "getattr"),
    "re-export past REEXPORT_DEPTH": (f"from .m{REEXPORT_DEPTH + 1} import save\n",
                                      "await db_call(save, secrets, form['k'])", _DEPTH_CHAIN, "save", "REEXPORT_DEPTH"),
    "callable held in a local": ("", "fn = pick(); await db_call(fn, secrets, form['k'])", (), "fn", "no import"),
}


@pytest.mark.parametrize("label", sorted(_UNRESOLVED_RED))
def test_a_form_value_handed_to_a_hop_whose_callee_names_no_def_is_reported(label):
    head, call, helpers, callee, why = _UNRESOLVED_RED[label]
    detect = _hop_detector(*helpers)
    bad = head + _HANDLER.format(call=call)
    assert_pin_has_teeth(detect, bad, bad.replace("form['k']", "'x'"))  # a literal is not reported
    [u] = detect(parse_source(bad))
    assert (u.caller, u.callee) == ((_A, "handler"), callee) and why in u.reason, (label, u)


def test_the_reexport_past_the_depth_lists_the_def_it_may_run():
    head, call, helpers, _callee, _why = _UNRESOLVED_RED["re-export past REEXPORT_DEPTH"]
    [u] = _hop_detector(*helpers)(parse_source(head + _HANDLER.format(call=call)))
    assert u.candidates == (("web/routers/m0.py", "save"),)


_INHERITED = ("from .b import Base\nclass H(Base):\n    async def ep(self, request, secrets):\n"
              "        form = await request.form()\n        await db_call(self.save, secrets, {value})\n")
_BASE = "class Base:\n    def save(self, secrets, value):\n        secrets.set('K', value)\n"


def test_a_form_value_handed_to_an_inherited_self_method_is_reported():
    """`self.save` with no method `save` in this module: the graph does not follow an inherited
    method, so the hop is reported with the defs it may run."""
    detect = _hop_detector(("web/routers/b.py", _BASE))
    assert_pin_has_teeth(detect, _INHERITED.format(value="form['k']"), _INHERITED.format(value="'x'"))
    [u] = detect(parse_source(_INHERITED.format(value="form['k']")))
    assert (u.caller, u.callee, u.candidates) == ((_A, "H.ep"), "self.save", (("web/routers/b.py", "Base.save"),))


_LIBRARY_HOPS = {
    # label: (an import of a module OUTSIDE the set, the same local name bound by the set, the call)
    "module attribute": ("import bcrypt\n", "from . import b as bcrypt\n",
                         "await run_in_threadpool(bcrypt.hashpw, form['pw'])"),
    "imported name": ("from bcrypt import hashpw\n", "from .b import hashpw\n",
                      "await run_in_threadpool(hashpw, form['pw'])"),
    "aliased module": ("import bcrypt as bc\n", "import email_triage.web.routers.b as bc\n",
                       "await to_thread(bc.hashpw, form['pw'])"),
}


@pytest.mark.parametrize("label", sorted(_LIBRARY_HOPS))
def test_a_hop_into_a_module_outside_the_set_is_not_reported(label):
    """`run_in_threadpool(bcrypt.hashpw, form_pw)`: bcrypt is no module of the set, so the hop runs no
    def the pin scans. The SAME call with its root bound by an import of the set IS reported, so the
    import table decides, not the callee's name."""
    library, in_set, call = _LIBRARY_HOPS[label]
    detect = _hop_detector(("web/routers/b.py", _UNSAFE_HELPER))
    assert_pin_has_teeth(detect, in_set + _HANDLER.format(call=call), library + _HANDLER.format(call=call))


def test_no_form_derived_value_reaches_an_unresolved_hop_in_the_live_routers():
    """PD-8 on the live tree: a form value handed, by hop or call, to a def the graph cannot name (a
    receiver of unknown type whose method name several defs share, or a dispatcher hop to a subscript,
    a call result, a module-set import resolving to no def, an inherited ``self.f``) is a silent pass.
    Zero today; any appearance fails here, naming the caller, the call line, the reason and every
    candidate def (sme-db NOTE-4)."""
    found = _unresolved(_router_modules())
    assert not found, (
        "A form-derived value reaches a callee the secret-write scan cannot follow, so a "
        "secrets.set behind it would read green (PD-8):\n"
        + "\n".join(
            f"  {u.caller[0]}::{u.caller[1]} line {u.call.lineno}: {u.callee}: {u.reason}; candidates: "
            + (", ".join(f"{rel}::{qual}" for rel, qual in u.candidates) or "none in web/routers")
            for u in found)
        + "\n\nFix: call the helper by a name the graph resolves (a def of this module, or an import "
        "of the def itself). Never add an allow-list for this.")


def test_the_secret_write_scan_follows_the_live_cross_module_route():
    """The real router tree: a form value does cross a module boundary (the ``ui/`` concern files
    reach ``_shared.py`` helpers through the ``globals().update(vars(_shared))`` snapshot, with no
    import naming them), so the cross-module arm is exercised on live code and a resolver that
    stopped seeing that idiom would fail here instead of reading green over an unscanned route."""
    violations, _allow, crossings = _scan_modules(_router_modules())
    assert not violations, violations
    assert any(caller != callee for caller, callee, _name in crossings), (
        "no form-derived value crossed a module boundary in web/routers: the cross-module "
        "resolver sees nothing in the live tree (punch 672)")
