"""N-200 R22 structural pin — cookie `Secure` flag MUST route through the
`web/_cookies.py::is_request_https` SSOT (2026-07-02).

Census run22 discovery: 3 `set_cookie` sites in web/ still used the OLD
`config.tls.enabled`-only formula — un-Secure on nginx-terminated HTTPS.
N-197 fixed 1 site inline; N-200 introduces the SSOT + widens the pin so
every future `set_cookie` inherits the correct posture.

This pin is the WIDER version of `test_n197_cookie_secure_flag_pin.py`
(which bans bool literals). N-200 additionally bans the OLD formula:

    secure = bool(getattr(getattr(config, "tls", None), "enabled", False))

Every `set_cookie(..., secure=<name>)` in `src/email_triage/web/**` MUST
have `<name>` assigned from a call whose func is `is_request_https`
(direct call or aliased through the SSOT module). Interprocedural: a
caller that passes `secure=X` where X came from `is_request_https(request,
config)` is fine; anything else is a defect.

Exemptions: `web/_cookies.py` itself (defines the SSOT). Waivable per
line with `# n200-secure-ssot-allowed: <reason>` end-of-line marker.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    enclosing_scope_chain,
    iter_files,
    parse_module,
    parse_source,
    relpath,
)


WEB_DIR = SRC_ROOT / "web"
SSOT_NAME = "is_request_https"
SSOT_MODULE_NAME = "_cookies"
_ALLOWED_MARKER = "n200-secure-ssot-allowed"


def _line_is_waived(source_lines: list[str], lineno: int) -> bool:
    if 1 <= lineno <= len(source_lines):
        return _ALLOWED_MARKER in source_lines[lineno - 1]
    return False


def _module_ssot_aliases(tree: ast.AST) -> set[str]:
    """Names in the module's top scope that resolve to the SSOT.

    Always includes the canonical ``SSOT_NAME`` (a bare direct call is
    the base case). Extended with:

    * **ImportFrom-alias** — ``from _cookies import is_request_https``
      (name = ``is_request_https``) or ``... as ir_https`` (name =
      ``ir_https``). The module test is ``mod == "_cookies"`` or
      ``mod.endswith(".<_cookies>")`` — i.e., a top-level or dotted-suffix
      import of the SSOT module.
    * **Same-file wrapper-fn** — a top-level ``def X(...): return <call>``
      whose ``<call>``'s func is already in the alias set (transitive:
      wrapper-of-wrapper works because ``ast.iter_child_nodes`` visits in
      source order and wrappers come after imports).

    N-383-tail R32 (2026-07-10 satellite): closes the two LOW false-
    positive shapes DA + hipaa panels flagged on the N-383 fold-set. Both
    are legit forwarding of the SSOT; the pre-tail pin over-restricted.
    Complement: non-SSOT alias / non-SSOT wrapper still fail — the pin's
    teeth carry the negative arms.
    """
    aliases: set[str] = {SSOT_NAME}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == SSOT_MODULE_NAME or mod.endswith("." + SSOT_MODULE_NAME):
                for al in node.names:
                    if al.name == SSOT_NAME:
                        aliases.add(al.asname or al.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Call):
                call = body[0].value
                fn = call.func
                fname = fn.id if isinstance(fn, ast.Name) else (
                    fn.attr if isinstance(fn, ast.Attribute) else None
                )
                if fname in aliases:
                    aliases.add(node.name)
    return aliases


def _iter_assigns_in_scope(scope: ast.AST):
    """Yield every ``ast.Assign`` that lives in ``scope`` — walking down
    through if/for/while/try/with block statements but STOPPING at
    nested ``FunctionDef``/``AsyncFunctionDef``/``ClassDef`` (each nested
    scope owns its own bindings; the caller's
    :func:`_pin_harness.enclosing_scope_chain` visits every enclosing
    scope in turn).

    Top-down descent (no ``_ph_parent`` walk needed — PD#6). Depth-first
    over ``ast.iter_child_nodes``; scope-barrier children are pruned
    rather than filtered post-hoc.
    """
    def descend(node: ast.AST):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Assign):
                yield child
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Scope barrier — inner bindings belong to the inner scope.
                continue
            yield from descend(child)
    yield from descend(scope)


def _bindings_directly_in_scope(scope: ast.AST, aliases: set[str]) -> set[str]:
    """The set of variable names assigned directly in ``scope`` whose RHS
    carries a call to any name in ``aliases`` (any depth). Multi-target
    assigns (``a = b = <alias>(...)``) count both. Nested scopes' Assigns
    are pruned — walk those via their own
    :func:`_pin_harness.enclosing_scope_chain` entry.

    N-383 R32 (2026-07-10 post-deploy census wf_69674c7e-c67 close): scope
    resolution routed through ``_pin_harness.enclosing_scope_chain`` per
    PD#6 (pins share the shared harness for scope walks). A module-wide
    walk let a peer-function same-name assign whitewash a real defect in
    ``auth_keys.py:411`` — see harness helper's docstring for evidence.

    N-383-tail R32 (2026-07-10 satellite): the accepted-call set is now
    ``aliases`` (module-scope alias imports + same-file wrappers), not a
    single ``SSOT_NAME`` — closes the two LOW false-positive shapes from
    the N-383 DA + hipaa panels.
    """
    names: set[str] = set()
    for assign in _iter_assigns_in_scope(scope):
        _maybe_bind(assign, names, aliases)
    return names


def _maybe_bind(assign: ast.Assign, names: set[str], aliases: set[str]) -> None:
    """If ``assign``'s RHS carries a Call whose func is in ``aliases``
    (any depth), add every top-level Name target to ``names``."""
    for call in ast.walk(assign.value):
        if not isinstance(call, ast.Call):
            continue
        fn = call.func
        fname = fn.id if isinstance(fn, ast.Name) else (
            fn.attr if isinstance(fn, ast.Attribute) else None
        )
        if fname not in aliases:
            continue
        for tgt in assign.targets:
            if isinstance(tgt, ast.Name):
                names.add(tgt.id)


def _find_ssot_derived_names_at(tree: ast.AST, lineno: int, aliases: set[str]) -> set[str]:
    """The set of SSOT-derived names VISIBLE at ``lineno`` — union across
    every enclosing scope (innermost function → module) per Python's LEGB
    rule. Routes scope-chain resolution through
    ``_pin_harness.enclosing_scope_chain`` (PD #6). ``aliases`` is the
    module's accepted-call set (SSOT_NAME + import aliases + wrappers)."""
    names: set[str] = set()
    for scope in enclosing_scope_chain(tree, lineno):
        names |= _bindings_directly_in_scope(scope, aliases)
    return names


def _find_set_cookie_secure_offenders(
    tree: ast.AST, source_lines: list[str]
) -> list[tuple[int, str]]:
    """Every `<obj>.set_cookie(..., secure=<x>)` call in `tree` whose
    `<x>` is NOT (a) a Name resolving to an is_request_https-derived
    variable IN THE CALLER'S ENCLOSING FUNCTION scope, (b) a direct
    is_request_https(...) call, (c) waived per line.

    N-383 R32 (2026-07-10): the ssot-names computation moved from
    module-level to enclosing-function-level per the census-caught false
    negative (see `_find_ssot_derived_names` docstring). A module-wide
    scope let a same-name assign in a peer function whitewash a real
    inline-formula defect in this function.

    N-383-tail R32 (2026-07-10 satellite): the accepted-call set is the
    module's ``aliases`` (SSOT_NAME + ImportFrom-alias + same-file
    wrapper) — was ``{SSOT_NAME}`` alone. Direct-call check + Name-
    binding funnel both use the shared alias set. Non-SSOT alias / non-
    SSOT wrapper still fail (teeth arms below carry the negatives).
    """
    aliases = _module_ssot_aliases(tree)
    offenders: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "set_cookie":
            continue
        ssot_names = _find_ssot_derived_names_at(tree, node.lineno, aliases)
        for kw in node.keywords:
            if kw.arg != "secure":
                continue
            v = kw.value
            # (a) Name → check membership.
            if isinstance(v, ast.Name):
                if v.id in ssot_names:
                    break
            # (b) direct call to is_request_https or any alias/wrapper
            if isinstance(v, ast.Call):
                fn = v.func
                fname = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else None)
                if fname in aliases:
                    break
            # (c) waived
            if _line_is_waived(source_lines, kw.value.lineno):
                break
            # Else: defect
            offenders.append((node.lineno, ast.unparse(kw.value) if hasattr(ast, "unparse") else "<expr>"))
            break
    return offenders


def test_no_set_cookie_bypasses_the_secure_ssot():
    """Every `set_cookie` in `web/**` MUST source `secure=` from
    `is_request_https(request, config)`, either directly or through a
    variable assigned from that SSOT."""
    offenders: list[str] = []
    for path in iter_files(WEB_DIR):
        rel = relpath(path)
        # SSOT module itself is exempt (it defines is_request_https).
        if rel.endswith(f"{SSOT_MODULE_NAME}.py"):
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        source_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for lineno, expr in _find_set_cookie_secure_offenders(tree, source_lines):
            offenders.append(f"{rel}:{lineno}  secure={expr}")
    assert not offenders, (
        "N-200 R22: cookie Secure flag MUST route through "
        f"`web/_cookies.py::{SSOT_NAME}(request, config)`. The pre-N-200 "
        "formula `bool(getattr(config, 'tls', None).enabled)` misses the "
        "nginx-reverse-proxy topology and leaves cookies un-Secure on the "
        "HTTPS hop → §164.312(e)(1) session credential leak. Fix each site: "
        f"import `{SSOT_NAME}` + assign `secure = {SSOT_NAME}(request, config)` "
        f"+ pass `secure=<name>` to set_cookie. Or waive per line with "
        f"`# {_ALLOWED_MARKER}: <reason>` when the cookie is scoped to a "
        "path that CAN NEVER be behind TLS (e.g., a deliberately-HTTP-only "
        "healthcheck).\n\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# TEETH — N-383 R32 (2026-07-10 post-deploy census wf_69674c7e-c67 close)
# ---------------------------------------------------------------------------

_TEETH_MODULE_WITH_FALSE_NEG = '''\
"""Planted-drift teeth module — the exact false-negative shape the
pre-N-383 module-scope walk let through: a peer function using the SSOT
(and thus binding `https` to an is_request_https-derived name) alongside
a DIFFERENT function hand-rolling the inline formula but SET_COOKIE-ing
against a same-named local. The pre-N-383 pin PASSED this. Post-N-383
scope tightening MUST flag the inline-formula site."""

def good_route(request, config, response):
    https = is_request_https(request, config)  # binds `https` OK
    response.set_cookie("k", "v", secure=https)


def bad_route(request, config, response):
    scheme = getattr(getattr(request, "url", None), "scheme", "") or ""
    https = (scheme == "https") or bool(
        getattr(getattr(config, "tls", None), "enabled", False)
    )
    # Pre-N-383: `ssot_names` had "https" from good_route (module-scope walk)
    # → this line PASSED the pin. Post-N-383: fn-scope walk sees only bad_
    # route's own binds → `https` NOT in ssot_names → FLAG.
    response.set_cookie("k", "v", secure=https)
'''


_TEETH_MODULE_CLEAN = '''\
"""Clean teeth module — both fns route through the SSOT. Post-N-383 MUST
return zero offenders (no false-positive on legit peer-fn same-name)."""

def route_a(request, config, response):
    https = is_request_https(request, config)
    response.set_cookie("k", "v", secure=https)


def route_b(request, config, response):
    https = is_request_https(request, config)  # same-name in peer fn — OK
    response.set_cookie("k", "v", secure=https)
'''


def test_teeth_planted_false_negative_now_flags():
    """PLANTED-DRIFT: the census's exact false-negative shape (peer fn
    uses SSOT + this fn hand-rolls the formula) MUST fire post-fix."""
    tree = parse_source(_TEETH_MODULE_WITH_FALSE_NEG)
    source_lines = _TEETH_MODULE_WITH_FALSE_NEG.splitlines()
    hits = _find_set_cookie_secure_offenders(tree, source_lines)
    assert hits, (
        "N-383 R32 teeth (planted false-negative): the pin did NOT fire "
        "on the pre-N-383 shape (module-scope name-collision that let a "
        "peer-fn same-name assign whitewash a real inline-formula defect). "
        f"Expected >=1 offender; got 0. This means the fn-scope guard "
        "regressed OR is not being applied at the check site."
    )


_TEETH_MODULE_NESTED_CLOSURE = '''\
"""Nested-closure teeth (DA panel HIGH + hipaa-sme LOW): outer fn binds
`https = is_request_https(...)` and an inner async closure does the
set_cookie — LEGB says the outer binding IS visible in the inner scope.
Post-fix pin MUST return 0 offenders (no false-positive on closure over
outer-scope SSOT var)."""

async def outer_handler(request, config, response):
    https = is_request_https(request, config)

    async def _do():
        response.set_cookie("k", "v", secure=https)

    await _do()
'''


def test_teeth_nested_closure_over_outer_ssot_does_not_false_positive():
    """NESTED-CLOSURE: inner set_cookie references outer fn's SSOT-derived
    var; LEGB binds it correctly and post-fix scope-chain walk unions
    outer's ssot_names — pin must NOT false-positive.

    DA panel HIGH (fn-scope tightening breaks Python closure semantics)
    close: enclosing_scope_chain walks innermost → module, so the outer
    fn's `https = is_request_https(...)` binding IS visible when the
    inner closure's set_cookie is checked.
    """
    tree = parse_source(_TEETH_MODULE_NESTED_CLOSURE)
    source_lines = _TEETH_MODULE_NESTED_CLOSURE.splitlines()
    hits = _find_set_cookie_secure_offenders(tree, source_lines)
    assert not hits, (
        "N-383 R32 teeth (nested-closure false-positive): the outer fn "
        "binds `https = is_request_https(...)`; LEGB makes it visible in "
        "the inner closure's set_cookie call. Post-fix scope-chain walk "
        "MUST union outer bindings; pin flagged the site anyway. Hits: "
        f"{hits}. The enclosing_scope_chain visit is broken OR the pin's "
        "check dropped the union step."
    )


def test_teeth_clean_module_does_not_false_positive():
    """CLEAN: both fns route through the SSOT; pin returns 0 offenders."""
    tree = parse_source(_TEETH_MODULE_CLEAN)
    source_lines = _TEETH_MODULE_CLEAN.splitlines()
    hits = _find_set_cookie_secure_offenders(tree, source_lines)
    assert not hits, (
        "N-383 R32 teeth (clean-module false-positive): a module where BOTH "
        f"peer functions route through the SSOT should have 0 offenders; "
        f"pin flagged {hits}. The fn-scope walk is over-restricting."
    )


# ---------------------------------------------------------------------------
# TEETH — N-383-tail R32 (2026-07-10 satellite — LOW panel followups)
# Closes the two DA + hipaa-sme LOW false-positive shapes:
#   * ImportFrom-alias: `from _cookies import is_request_https as ir_https`
#   * Same-file wrapper: `def _is_https(r, c): return is_request_https(r, c)`
# Legit shapes MUST NOT flag; non-SSOT alias / non-SSOT wrapper MUST flag.
# ---------------------------------------------------------------------------

_TEETH_MODULE_ALIAS_LEGIT = '''\
"""ALIAS-LEGIT: `from ._cookies import is_request_https as ir_https` +
`https = ir_https(...)` at the set_cookie site. Post-tail widen MUST
NOT flag — aliased SSOT ref counts."""
from ._cookies import is_request_https as ir_https


def route(request, config, response):
    https = ir_https(request, config)
    response.set_cookie("k", "v", secure=https)
'''


_TEETH_MODULE_ALIAS_NON_SSOT = '''\
"""ALIAS-NON-SSOT: SSOT alias is imported but the `secure=` name is
assigned from a NON-SSOT call. Pin must still flag — the alias import is
a bystander, not a whitewash."""
from ._cookies import is_request_https as ir_https  # noqa: F401 — imported but unused here on purpose


def route(request, config, response):
    https = some_other_predicate(request, config)  # not an alias for the SSOT
    response.set_cookie("k", "v", secure=https)
'''


_TEETH_MODULE_WRAPPER_LEGIT = '''\
"""WRAPPER-LEGIT: same-file 1-line wrapper `def _is_https(r, c): return
is_request_https(r, c)` used at the set_cookie site. Post-tail widen
MUST NOT flag — a bare forward of the SSOT."""

def _is_https(request, config):
    return is_request_https(request, config)


def route(request, config, response):
    https = _is_https(request, config)
    response.set_cookie("k", "v", secure=https)
'''


_TEETH_MODULE_WRAPPER_NON_SSOT = '''\
"""WRAPPER-NON-SSOT: same-file 1-line fn whose body does NOT return the
SSOT (it inlines the pre-N-200 formula). Pin must still flag — a bogus
wrapper is not an escape hatch."""

def _bad_https(request, config):
    return bool(getattr(getattr(config, "tls", None), "enabled", False))


def route(request, config, response):
    https = _bad_https(request, config)
    response.set_cookie("k", "v", secure=https)
'''


def test_teeth_import_alias_of_ssot_does_not_false_positive():
    """ALIAS-LEGIT: an aliased SSOT import is a legit forward and MUST
    NOT be flagged at the set_cookie site."""
    tree = parse_source(_TEETH_MODULE_ALIAS_LEGIT)
    source_lines = _TEETH_MODULE_ALIAS_LEGIT.splitlines()
    hits = _find_set_cookie_secure_offenders(tree, source_lines)
    assert not hits, (
        "N-383-tail R32 teeth (import-alias false-positive): "
        "`from _cookies import is_request_https as ir_https` + `https = "
        "ir_https(request, config)` is a legit SSOT usage; pin must NOT "
        f"flag. Got hits: {hits}. `_module_ssot_aliases` did not include "
        "the ImportFrom alias name."
    )


def test_teeth_non_ssot_alias_bystander_still_flags():
    """ALIAS-NON-SSOT: imported SSOT alias does NOT excuse a `secure=`
    name assigned from a different call. Pin must still flag."""
    tree = parse_source(_TEETH_MODULE_ALIAS_NON_SSOT)
    source_lines = _TEETH_MODULE_ALIAS_NON_SSOT.splitlines()
    hits = _find_set_cookie_secure_offenders(tree, source_lines)
    assert hits, (
        "N-383-tail R32 teeth (alias-bystander false-negative): merely "
        "importing the SSOT (aliased) must NOT whitewash a set_cookie "
        "whose `secure=` name resolves from a non-SSOT call. Expected "
        "≥1 offender; got 0 — `aliases` swallowed too much."
    )


def test_teeth_same_file_wrapper_of_ssot_does_not_false_positive():
    """WRAPPER-LEGIT: a same-file 1-line wrapper returning the SSOT
    forwards it; pin must NOT flag its use at set_cookie."""
    tree = parse_source(_TEETH_MODULE_WRAPPER_LEGIT)
    source_lines = _TEETH_MODULE_WRAPPER_LEGIT.splitlines()
    hits = _find_set_cookie_secure_offenders(tree, source_lines)
    assert not hits, (
        "N-383-tail R32 teeth (wrapper-forward false-positive): "
        "`def _is_https(r, c): return is_request_https(r, c)` used at "
        f"the set_cookie site is a bare forward; pin must NOT flag. Got "
        f"hits: {hits}. `_module_ssot_aliases` did not include the "
        "top-level 1-return wrapper's name."
    )


def test_teeth_same_file_non_ssot_wrapper_still_flags():
    """WRAPPER-NON-SSOT: a same-file 1-line fn whose body does NOT
    return the SSOT must NOT be an escape hatch. Pin must still flag."""
    tree = parse_source(_TEETH_MODULE_WRAPPER_NON_SSOT)
    source_lines = _TEETH_MODULE_WRAPPER_NON_SSOT.splitlines()
    hits = _find_set_cookie_secure_offenders(tree, source_lines)
    assert hits, (
        "N-383-tail R32 teeth (bogus-wrapper false-negative): a same-"
        "file `def _bad_https(...): return <non-SSOT>` must NOT be "
        "accepted at set_cookie. Expected ≥1 offender; got 0 — the "
        "wrapper-detection accepted a non-SSOT body."
    )
