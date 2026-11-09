"""Pin (t20, panel X): every live provider probe a request handler reaches goes through the
``render_probe`` SSOT (``providers/render_probe.py``, re-exported by ``web/routers/ui/_shared``),
which bounds the whole probe (connect, greeting, LIST) at ``RENDER_PROBE_TIMEOUT_S``.

Property (PD-2, interprocedural): no direct ``<x>.list_folders()`` / ``<x>.list_labels()`` call
in any module under ``web/routers``, NOR in any src function those modules reach by name,
transitively. A call is followed when it names a function bound by ``from email_triage... import
f`` (module level or function local, absolute or relative), a module attribute ``m.f(...)`` on a
module bound the same way, or a module-level function of the same module. That is how the
label-picker helper ``providers/provider_labels.list_provider_labels_for_account`` (reached from
the rule editor, the digest editor and the routes page) sits inside the net. The probe is spelled
``render_probe(provider)`` or ``render_probe(provider, "list_labels")``.

Punch 819 widened the net to ATTRIBUTE-CALL DISPATCH. A dataclass field annotated ``Callable``
(``providers.dispatcher.ProviderDispatch.test_connection``) holds a function that a registry
fills in by keyword (``ProviderDispatch(test_connection=_gmail_test_connection)``), and a handler
reaches it as ``disp.test_connection(...)``. A call ``<x>.<field>(...)`` where ``<field>`` is such
a field is followed to EVERY function registered under that field name, anywhere in src. The field
set and the registrations are derived from the tree, not listed here.

The watcher and poller are not reached from ``web/routers``; they keep the provider's own budget,
which is ONE combined 10 s connect + TLS + greeting budget since t20 (it was up to 2 x 10 s).

SCOPE CAVEAT: a call through any OTHER object attribute (``provider.x()``, ``self.x()``), a class
method, a callable passed as a value, a registration that is not a keyword argument naming a
function (a dict value, a lambda), or ``getattr`` is not followed. The render test
``tests/test_web/test_account_edit_probe_bound.py`` covers the edit page end to end and
``tests/test_render_probe_bound.py`` the label-picker helper.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth, iter_src_files, parse_module, parse_source, relpath,
)

PROBE_CALLS = frozenset({"list_folders", "list_labels"})
SSOT_HOME = "providers/render_probe.py"
SSOT = ("email_triage.providers.render_probe", "render_probe")
ROOTS = "web/routers"

_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


def unbounded_probes(tree: ast.AST) -> list[int]:
    """Line numbers of direct ``<x>.list_folders()`` / ``<x>.list_labels()`` calls."""
    return [node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in PROBE_CALLS]


def module_name(rel: str) -> tuple[str, bool]:
    """``web/routers/ui/_shared.py`` -> (``email_triage.web.routers.ui._shared``, is_package)."""
    parts = rel[:-3].split("/")
    is_pkg = parts[-1] == "__init__"
    if is_pkg:
        parts = parts[:-1]
    return ".".join(["email_triage", *parts]), is_pkg


def _import_source(mod: str, is_pkg: bool, node: ast.ImportFrom) -> str | None:
    if node.level == 0:
        return node.module
    base = mod.split(".") if is_pkg else mod.split(".")[:-1]
    if node.level > 1:
        base = base[: len(base) - (node.level - 1)]
    return ".".join(base + ([node.module] if node.module else []))


def _bindings(mod: str, is_pkg: bool, tree: ast.AST, known: set[str]) -> dict[str, tuple]:
    """Local name -> ``("func", module, name)`` or ``("module", module)``, from every
    ``email_triage`` import anywhere in the module (function-local ones included; merging them
    module-wide over-follows, which fails closed)."""
    out: dict[str, tuple] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            src = _import_source(mod, is_pkg, node)
            if not src or not src.startswith("email_triage"):
                continue
            for alias in node.names:
                sub = f"{src}.{alias.name}"
                out[alias.asname or alias.name] = (
                    ("module", sub) if sub in known else ("func", src, alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.name.startswith("email_triage"):
                    out[alias.asname] = ("module", alias.name)
    return out


def _is_dataclass_decorator(dec: ast.expr) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    return (isinstance(target, ast.Name) and target.id == "dataclass") or (
        isinstance(target, ast.Attribute) and target.attr == "dataclass")


def dispatch_fields(modules: dict[str, tuple[ast.AST, bool]]) -> frozenset[str]:
    """Names of the ``Callable``-annotated fields of every dataclass in src (punch 819)."""
    out: set[str] = set()
    for tree, _ in modules.values():
        for cls in ast.walk(tree):
            if not (isinstance(cls, ast.ClassDef)
                    and any(_is_dataclass_decorator(d) for d in cls.decorator_list)):
                continue
            out.update(st.target.id for st in cls.body
                       if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name)
                       and "Callable" in ast.unparse(st.annotation))
    return frozenset(out)


def registrations(modules: dict[str, tuple[ast.AST, bool]], index: dict,
                  fields: frozenset[str]) -> dict[str, list[tuple[str, str]]]:
    """``field -> [(module, function)]``: every function a call registers under a dispatch
    field by keyword (``ProviderDispatch(test_connection=_gmail_test_connection)``)."""
    out: dict[str, list[tuple[str, str]]] = {}
    for mod, (tree, _) in modules.items():
        defs, binds = index[mod]
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            for kw in call.keywords:
                if kw.arg not in fields or not isinstance(kw.value, ast.Name):
                    continue
                bound = binds.get(kw.value.id)
                if bound and bound[0] == "func":
                    out.setdefault(kw.arg, []).append((bound[1], bound[2]))
                elif kw.value.id in defs:
                    out.setdefault(kw.arg, []).append((mod, kw.value.id))
    return out


def _callees(node: ast.AST, mod: str, defs: dict, binds: dict, dispatch: dict | None = None):
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if isinstance(func, ast.Name):
            bound = binds.get(func.id)
            if bound and bound[0] == "func":
                yield bound[1], bound[2]
            elif func.id in defs:
                yield mod, func.id
        elif isinstance(func, ast.Attribute):
            # Punch 819: ``<x>.<dispatch field>(...)`` runs whatever was registered under it.
            yield from (dispatch or {}).get(func.attr, ())
            if isinstance(func.value, ast.Name):
                bound = binds.get(func.value.id)
                if bound and bound[0] == "module":
                    yield bound[1], func.attr


def reached_probes(modules: dict[str, tuple[ast.AST, bool]], roots: set[str]) -> list[tuple[str, int]]:
    """``(module, line)`` of every direct probe in a root module or in a function reached from
    one. ``modules`` maps a dotted module name to ``(tree, is_package)``."""
    known = set(modules)
    index = {}
    for mod, (tree, is_pkg) in modules.items():
        defs = {n.name: n for n in getattr(tree, "body", []) if isinstance(n, _FUNCS)}
        index[mod] = (defs, _bindings(mod, is_pkg, tree, known))
    dispatch = registrations(modules, index, dispatch_fields(modules))
    hits: set[tuple[str, int]] = set()
    work: list[tuple[str, str]] = []
    for mod in roots:
        tree = modules[mod][0]
        hits.update((mod, line) for line in unbounded_probes(tree))
        work.extend(_callees(tree, mod, *index[mod], dispatch))
    seen: set[tuple[str, str]] = set()
    while work:
        key = work.pop()
        if key in seen or key == SSOT or key[0] not in index or key[0] in roots:
            continue
        seen.add(key)
        mod, name = key
        defs, binds = index[mod]
        fn = defs.get(name)
        if fn is None:  # a re-export: follow the binding it names
            bound = binds.get(name)
            if bound and bound[0] == "func":
                work.append((bound[1], bound[2]))
            continue
        hits.update((mod, line) for line in unbounded_probes(fn))
        work.extend(_callees(fn, mod, defs, binds, dispatch))
    return sorted(hits)


def _src_modules() -> tuple[dict[str, tuple[ast.AST, bool]], set[str], dict[str, str]]:
    modules, roots, rels = {}, set(), {}
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        mod, is_pkg = module_name(rel)
        modules[mod] = (tree, is_pkg)
        rels[mod] = rel
        if rel.startswith(ROOTS + "/"):
            roots.add(mod)
    return modules, roots, rels


def test_every_probe_a_handler_reaches_goes_through_the_ssot():
    modules, roots, rels = _src_modules()
    assert SSOT[0] in modules, f"the render_probe SSOT moved from {SSOT_HOME}"
    offenders = [f"{rels[mod]}:{line}" for mod, line in reached_probes(modules, roots)]
    assert not offenders, (
        "A request handler reaches a provider probe that is not bounded. Route it through "
        "`render_probe(provider)` (providers/render_probe.py) so the page is bounded at "
        "RENDER_PROBE_TIMEOUT_S:\n  " + "\n  ".join(offenders))


def test_the_label_picker_helper_is_inside_the_net():
    """The net reaches the helper db MUST-1 named, so it is not seam-keyed on web/routers."""
    modules, roots, _ = _src_modules()
    probe = "email_triage.providers.provider_labels"
    tree, is_pkg = modules[probe]
    planted = parse_source(
        "async def list_provider_labels_for_account(*, db, secrets, account_id):\n"
        "    return await provider.list_labels()\n")
    modules = {**modules, probe: (planted, is_pkg)}
    assert (probe, 2) in reached_probes(modules, roots)


def test_the_ssot_bounds_with_its_constant():
    tree = parse_module(next(p for p in iter_src_files("providers") if relpath(p) == SSOT_HOME))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == SSOT[1])
    bounds = [item.context_expr for n in ast.walk(fn) if isinstance(n, ast.AsyncWith)
              for item in n.items
              if isinstance(item.context_expr, ast.Call)
              and isinstance(item.context_expr.func, ast.Attribute)
              and item.context_expr.func.attr == "timeout"]
    assert bounds, "render_probe lost its bound"
    # Punch 693: the bound is the `timeout_s` parameter, whose DEFAULT is resolved inside the
    # body at call time (a def-time default would freeze the constant at import and break every
    # test that patches it): `if timeout_s is None: timeout_s = RENDER_PROBE_TIMEOUT_S`.
    assert any(isinstance(a, ast.Name) and a.id in {"RENDER_PROBE_TIMEOUT_S", "timeout_s"}
               for b in bounds for a in b.args), "render_probe lost its bound"
    defaults = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "timeout_s" for t in n.targets)
                and isinstance(n.value, ast.Name) and n.value.id == "RENDER_PROBE_TIMEOUT_S"]
    uses_param = any(isinstance(a, ast.Name) and a.id == "timeout_s"
                     for b in bounds for a in b.args)
    assert not uses_param or defaults, (
        "render_probe bounds on `timeout_s` but its unset default no longer resolves to "
        "RENDER_PROBE_TIMEOUT_S: the page-render bound is gone")


def test_detector_has_teeth():
    assert_pin_has_teeth(
        unbounded_probes,
        bad_source="async def h(p):\n    return await p.list_folders()\n",
        good_source="async def h(p):\n    return await render_probe(p)\n",
    )


def _two_modules(helper_body: str, call: str) -> dict[str, tuple[ast.AST, bool]]:
    return {
        "email_triage.web.routers.page": (parse_source(
            "from email_triage.providers.helper import labels\n"
            "from email_triage.providers import helper\n"
            f"async def handler(p):\n    return await {call}\n"), False),
        "email_triage.providers.helper": (parse_source(
            "async def labels(p):\n    return await _inner(p)\n"
            f"async def _inner(p):\n    return await {helper_body}\n"), False),
    }


def test_the_interprocedural_net_has_teeth():
    """A probe two hops away (an imported helper, then a same-module function) is found, through
    a bound name AND through a module attribute; the bounded spelling is not."""
    roots = {"email_triage.web.routers.page"}
    assert reached_probes(_two_modules("p.list_labels()", "labels(p)"), roots) == [
        ("email_triage.providers.helper", 4)]
    assert reached_probes(_two_modules("p.list_labels()", "helper.labels(p)"), roots) == [
        ("email_triage.providers.helper", 4)]
    assert reached_probes(_two_modules('render_probe(p, "list_labels")', "labels(p)"), roots) == []


def _dispatch_modules(body: str) -> dict[str, tuple[ast.AST, bool]]:
    return {
        "email_triage.web.routers.page": (parse_source(
            "async def handler(disp, a):\n    return await disp.test_connection(a)\n"), False),
        "email_triage.providers.reg": (parse_source(
            "from dataclasses import dataclass\nfrom typing import Callable\n"
            "@dataclass\nclass D:\n    test_connection: Callable[..., int]\n    name: str = ''\n"
            f"async def _probe(a):\n    return await {body}\n"
            "TABLE = D(test_connection=_probe)\n"), False),
    }


def test_the_dispatch_net_has_teeth():
    """Punch 819: a probe behind ``disp.<field>(...)`` is found through the keyword
    registration of a ``Callable`` dataclass field; the bounded spelling is not."""
    roots = {"email_triage.web.routers.page"}
    assert dispatch_fields(_dispatch_modules("x")) == {"test_connection"}
    assert reached_probes(_dispatch_modules("a.list_labels()"), roots) == [
        ("email_triage.providers.reg", 8)]
    assert reached_probes(_dispatch_modules('render_probe(a, "list_labels")'), roots) == []


def test_the_dispatch_net_sees_the_real_registry():
    """Guard against a green-and-blind net: the real ``ProviderDispatch`` table is derived."""
    modules, roots, _ = _src_modules()
    fields = dispatch_fields(modules)
    assert "test_connection" in fields
    index = {}
    for mod, (tree, is_pkg) in modules.items():
        defs = {n.name: n for n in getattr(tree, "body", []) if isinstance(n, _FUNCS)}
        index[mod] = (defs, _bindings(mod, is_pkg, tree, set(modules)))
    assert ("email_triage.providers.dispatcher", "_gmail_test_connection") in registrations(
        modules, index, fields)["test_connection"]
