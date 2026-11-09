"""Census round 2, class B (T8): teeth for the harness hop / reach / taint helpers.

The divergence census seeds marked ``NEEDS_HARNESS_HOPS`` need "does this value or call reach
that sink through helpers". Round 1 answered with throwaway detectors: an unguarded bare-name
closure grew from 408 to 2530 names, and ``reachers_of`` saw only direct calls. ``tests/_pin_harness.py``
now owns the answer (PD#6, one resolver, one call-edge reader):

* ``reachers_of`` follows the callee a dispatcher hands off (B1);
* ``reach_closure`` / ``CallGraph.reach`` is the qualified, cross-module closure (B2) and
  follows pure-forwarder calls (B6);
* ``CrossModuleResolver`` chases a re-export ``REEXPORT_DEPTH`` modules deep and reads a
  PEP 562 module ``__getattr__`` fallback (B3);
* ``param_taint_fixpoint`` is the interprocedural taint fixpoint the secret-write pin used
  to carry (B4); ``call_sites`` / ``outermost_enclosing_def`` replace a hand-rolled call
  loop (B5); ``module_ssot_imports`` reads ``importlib.import_module`` (B7).

Every edge kind a helper claims to follow has a planted shape it must catch, and a planted
neighbour it must not over-reach to. The secret-write pin's own teeth and live-route test
(``test_no_unguarded_secret_write.py``) are the proof the taint hoist kept behaviour; the
resolver's punch-672 teeth live in ``test_punch672_hop_callee_resolver_pin.py``.
"""
from __future__ import annotations

import ast

import pytest

from _pin_harness import (
    REEXPORT_DEPTH,
    CallGraph,
    CrossModuleResolver,
    ReachBoundExceeded,
    assert_pin_has_teeth,
    call_sites,
    enclosing_qualified_name,
    forwarder_edges,
    is_call_of,
    iter_defs,
    module_ssot_imports,
    outermost_enclosing_def,
    param_taint_fixpoint,
    pass_through_calls,
    parse_source,
    reach_closure,
    reachers_of,
    scope_key,
    walk_src,
)

R = "web/routers/"
A, B, C, D = (f"{R}{n}.py" for n in "abcd")


def _mods(**sources: str) -> dict[str, ast.AST]:
    """``{"web/routers/<name>.py": tree}`` for planted module sources."""
    return {f"{R}{name}.py": parse_source(src) for name, src in sources.items()}


def _expr(src: str) -> ast.AST:
    return ast.parse(src, mode="eval").body


# --- B1: reachers_of follows a dispatch -----------------------------------------------------------

#: Every way a caller hands `helper` to a dispatcher (the hop_target forms).
_VIA = {
    "db_call by name": "await db_call(helper, 1)",
    "db_call_async": "await db_call_async(helper, 1)",
    "run_in_threadpool": "await run_in_threadpool(helper, 1)",
    "to_thread": "await asyncio.to_thread(helper, 1)",
    "to_thread partial": "await asyncio.to_thread(partial(helper, 1))",
    "functools.partial": "await run_in_threadpool(functools.partial(helper))",
    "lambda": "await db_call(lambda: helper(1))",
    "run_in_executor": "await loop.run_in_executor(None, helper, 1)",
    "self attribute": "await db_call(self.helper, 1)",
}


@pytest.mark.parametrize("label", sorted(_VIA))
def test_reachers_of_follows_a_dispatched_helper(label):
    tree = parse_source(
        "def target():\n    pass\n"
        "def helper():\n    target()\n"
        f"async def outer():\n    {_VIA[label]}\n"
        "def bystander():\n    pass\n")
    assert reachers_of(tree, "target") == {"helper", "outer"}, label


def test_reachers_of_keeps_the_calls_of_both_defs_of_one_name():
    """The second `def run` used to replace the first's call set, dropping `run` and its caller."""
    tree = parse_source(
        "def target():\n    pass\n"
        "def run():\n    target()\n"
        "def run():\n    pass\n"
        "def caller():\n    run()\n")
    assert reachers_of(tree, "target") == {"run", "caller"}


def test_reachers_of_counts_a_lambda_only_when_a_dispatcher_runs_it():
    """A stored lambda and a bare `partial(f)` are not calls (amendment 2); a lambda handed to a
    dispatcher runs, even with several calls in its body."""
    stored = parse_source(
        "def target(x):\n    pass\n"
        "def f(rows):\n    cb = lambda r: target(r)\n    return sorted(rows, key=lambda r: target(r))\n"
        "def g():\n    return partial(target, 1)\n")
    assert reachers_of(stored, "target") == set()
    ran = parse_source(
        "def target():\n    pass\ndef other():\n    pass\n"
        "async def f():\n    await db_call(lambda: (other(), target()))\n"
        "async def h():\n    await loop.run_in_executor(None, lambda: (other(), target()))\n")
    assert reachers_of(ran, "target") == {"f", "h"}


def test_reachers_of_has_teeth_through_the_dispatcher():
    bad = "def target():\n    pass\nasync def outer():\n    await db_call(target)\n"
    good = "def target():\n    pass\nasync def outer():\n    await db_call(other)\n"
    assert_pin_has_teeth(lambda tree: reachers_of(tree, "target"), bad, good)


# --- B5: call_sites / outermost_enclosing_def -------------------------------------------------------

_SITE_FORMS = {
    "direct": "{n}(1)",
    "attribute": "obj.{n}(1)",
    "awaited hop": "await db_call({n}, 1)",
    "partial hop": "await asyncio.to_thread(partial({n}, 1))",
    "lambda hop": "await db_call(lambda: {n}(1))",
    "executor hop": "await loop.run_in_executor(None, {n}, 1)",
}


@pytest.mark.parametrize("label", sorted(_SITE_FORMS))
def test_call_sites_finds_every_form_and_only_the_name(label):
    template = "async def w():\n    " + _SITE_FORMS[label] + "\n"
    assert_pin_has_teeth(lambda tree: call_sites(tree, "f"),
                         template.format(n="f"), template.format(n="g"))


def test_call_sites_does_not_count_a_name_that_is_only_an_argument():
    tree = parse_source("async def w():\n    x = f\n    await db_call(g, f)\n")
    assert call_sites(tree, "f") == []


def test_outermost_enclosing_def_is_the_outer_def_for_closures_and_lambdas():
    tree = parse_source(
        "def a():\n    def b():\n        x = lambda: c()\n    class K:\n        def m(self):\n            d()\ne()\n")
    by_name = {s.func.id: s for s in ast.walk(tree) if isinstance(s, ast.Call)}
    assert outermost_enclosing_def(by_name["c"]).name == "a"
    assert outermost_enclosing_def(by_name["d"]).name == "a"
    assert outermost_enclosing_def(by_name["e"]) is None


# --- B2: reach_closure ------------------------------------------------------------------------------

def test_reach_closure_finds_the_cross_module_route_through_a_hop():
    mods = _mods(a="from .b import helper\nasync def outer():\n    await db_call(helper, 1)\n",
                 b="def helper(x):\n    target(x)\n")
    assert reach_closure(mods, {"target"}) == {(A, "outer"), (B, "helper")}


def test_two_defs_of_one_name_in_different_modules_stay_apart():
    mods = _mods(a="def run():\n    target()\n",
                 b="def run():\n    pass\n",
                 c="from .a import run\ndef caller():\n    run()\n",
                 d="from .b import run\ndef other():\n    run()\n")
    assert reach_closure(mods, {"target"}) == {(A, "run"), (C, "caller")}


def test_two_nested_defs_of_one_name_stay_apart():
    """The endpoint-local `_work` helper: only the endpoint whose own `_work` reaches is returned."""
    mods = _mods(a=("async def one():\n    def _work():\n        target()\n    await db_call(_work)\n"
                    "async def two():\n    def _work():\n        pass\n    await db_call(_work)\n"))
    assert reach_closure(mods, {"target"}) == {(A, "one"), (A, "one._work")}


def test_two_classes_with_one_method_name_stay_apart():
    mods = _mods(a=("class Reader:\n    def go(self):\n        self.fetch()\n    def fetch(self):\n        target()\n"
                    "class Writer:\n    def go(self):\n        self.fetch()\n    def fetch(self):\n        pass\n"))
    assert reach_closure(mods, {"target"}) == {(A, "Reader.go"), (A, "Reader.fetch")}


def test_a_call_on_an_unknown_receiver_is_followed_only_when_loose_and_unique():
    mods = _mods(a="class Svc:\n    def run(self):\n        target()\ndef use(svc):\n    svc.run()\n")
    off = reach_closure(mods, {"target"})
    assert off == {(A, "Svc.run")} and off.ambiguous_edges == 1  # not followed, but counted
    on = reach_closure(mods, {"target"}, loose_receivers=True)
    assert on == {(A, "Svc.run"), (A, "use")} and on.ambiguous_edges == 0


def test_an_unknown_receiver_with_several_candidates_is_counted_never_fanned_out():
    mods = _mods(a=("class Svc:\n    def run(self):\n        target()\n"
                    "class Other:\n    def run(self):\n        pass\ndef use(x):\n    x.run()\n"),
                 b="class Third:\n    def run(self):\n        pass\n")
    reach = reach_closure(mods, {"target"}, loose_receivers=True)
    assert reach == {(A, "Svc.run")} and reach.ambiguous_edges == 1
    [edge] = CallGraph(mods, loose_receivers=True).ambiguous_edges
    assert edge.attr == "run" and edge.caller == (A, "use")
    assert set(edge.candidates) == {(A, "Svc.run"), (A, "Other.run"), (B, "Third.run")}
    # one def per module is still two defs in the corpus
    split = _mods(a="class Svc:\n    def run(self):\n        target()\ndef use(x):\n    x.run()\n",
                  b="class Third:\n    def run(self):\n        pass\n")
    assert reach_closure(split, {"target"}, loose_receivers=True) == {(A, "Svc.run")}


def test_an_unknown_receiver_may_be_a_module_so_a_unique_module_level_def_is_followed_unbound():
    """`mod.helper()` with `mod` not an import the resolver knows: the one def named `helper` is a
    module-level function (no receiver placeholder), and a method of the same name makes it ambiguous."""
    mods = _mods(a="def use(mod):\n    mod.helper()\n", b="def helper():\n    target()\n")
    off = reach_closure(mods, {"target"})
    assert off == {(B, "helper")} and off.ambiguous_edges == 1
    on = reach_closure(mods, {"target"}, loose_receivers=True)
    assert on == {(B, "helper"), (A, "use")} and on.ambiguous_edges == 0
    [edge] = [e for e in CallGraph(mods, loose_receivers=True).edges if e.caller == (A, "use")]
    assert edge.callee == (B, "helper") and edge.args == ()  # unbound: no receiver placeholder first
    both = _mods(a="def use(mod):\n    mod.helper()\n", b="def helper():\n    target()\n",
                 c="class K:\n    def helper(self):\n        pass\n")
    again = reach_closure(both, {"target"}, loose_receivers=True)
    assert again == {(B, "helper")} and again.ambiguous_edges == 1


def test_reach_closure_follows_a_module_attribute():
    mods = _mods(a=("import email_triage.web.routers.b as helpers\n"
                    "def one():\n    helpers.helper()\n"),
                 b="def helper():\n    target()\n")
    assert reach_closure(mods, {"target"}) == {(A, "one"), (B, "helper")}


def test_a_target_may_be_a_resolved_def_instead_of_a_name():
    mods = _mods(a="from .b import helper\nasync def outer():\n    await db_call(helper, 1)\n",
                 b="def helper(x):\n    pass\n",
                 c="def helper(x):\n    pass\ndef other():\n    helper(1)\n")
    assert reach_closure(mods, {(B, "helper")}) == {(A, "outer")}


def test_reach_closure_counts_an_edge_and_stops_loudly_past_its_bound():
    n = 30
    chain = "def f0():\n    target()\n" + "".join(f"def f{i}():\n    f{i - 1}()\n" for i in range(1, n))
    mods = _mods(a=chain)
    reach = reach_closure(mods, {"target"})
    assert reach.edge_count == n - 1 and len(reach) == n
    with pytest.raises(ReachBoundExceeded) as err:
        reach_closure(mods, {"target"}, max_nodes=10)
    message = str(err.value)
    assert "bound of 10" in message and f"{n - 1} call edges" in message and "11 nodes" in message, message


def test_a_class_body_and_module_level_call_belong_to_the_module_scope():
    mods = _mods(a="class K:\n    x = target()\nvalue = target()\n")
    assert reach_closure(mods, {"target"}) == {(A, "<module>")}


def test_scope_keys_agree_with_the_enclosing_qualified_name():
    """`scope_key` and the graph's keys are the harness's `enclosing_qualified_name` spelling."""
    tree = parse_source(
        "class K:\n    def m(self):\n        def inner():\n            target()\n        inner()\n"
        "def top():\n    class L:\n        def n(self):\n            target()\n")
    graph = CallGraph({A: tree})
    scopes = graph.scopes[A].scopes
    seen_defs = 0
    for qual, scope in scopes.items():
        for call in scope.calls:
            assert scope_key(call) == qual, (qual, ast.unparse(call))
        if qual == "<module>":
            continue
        for node in scope.nodes:
            seen_defs += 1
            outer = enclosing_qualified_name(node)
            assert (node.name if outer == "<module>" else f"{outer}.{node.name}") == qual
            assert scope_key(node) == qual
    assert seen_defs and {"K.m", "K.m.inner", "top", "top.L.n"} <= set(scopes)
    assert [q for _rel, q, _n in iter_defs({A: tree})].index("K.m") < [
        q for _rel, q, _n in iter_defs({A: tree})].index("K.m.inner")


# --- B6: forwarder edges ----------------------------------------------------------------------------

_FORWARDERS = (
    "def call_ollama(model, prompt):\n    return None\n"
    "def my_call(*a, **k):\n    return call_ollama(*a, **k)\n"
    "async def my_hop(*a, **k):\n    return await db_call(call_ollama, *a, **k)\n"
    "def outer_fwd(*args, **kwargs):\n    return my_call(*args, **kwargs)\n"
    "def adder(*a):\n    return call_ollama(1, *a)\n"
    "def caller():\n    my_call('m', 'p')\n"
)


def test_forwarder_edges_name_every_pure_pass_through():
    assert forwarder_edges(parse_source(_FORWARDERS)) == {
        ("my_call", "call_ollama"), ("my_hop", "call_ollama"), ("outer_fwd", "my_call")}


def test_reach_closure_follows_a_forwarder_between_caller_and_target():
    mods = _mods(a=_FORWARDERS)
    everything = reach_closure(mods, {"call_ollama"})
    assert everything == {(A, q) for q in ("my_call", "my_hop", "outer_fwd", "adder", "caller")}
    forwarders = reach_closure(mods, {"call_ollama"}, forwarders_only=True)
    assert forwarders == {(A, q) for q in ("my_call", "my_hop", "outer_fwd")}


def test_pass_through_calls_still_exempts_only_the_named_forwarder():
    tree = parse_source(_FORWARDERS)
    assert pass_through_calls(tree, "my_call") and not pass_through_calls(tree, "adder")
    assert not pass_through_calls(tree, "my_hop")  # a hop forwarder: forwarder_edges' job


# --- B3: the resolver follows re-exports and a PEP 562 module __getattr__ ---------------------------------

def _reexport_chain(n: int) -> dict[str, ast.AST]:
    """m0 defines f; m1..mn each re-export it; `top` imports it from mn and calls it."""
    sources = {"m0": "def f():\n    pass\n"}
    sources.update({f"m{i}": f"from .m{i - 1} import f\n" for i in range(1, n + 1)})
    sources["top"] = f"from .m{n} import f\ndef user():\n    f()\n"
    return _mods(**sources)


@pytest.mark.parametrize("n", range(1, REEXPORT_DEPTH + 1))
def test_a_reexported_name_resolves_through_n_modules(n):
    mods = _reexport_chain(n)
    assert CrossModuleResolver(mods).resolve(f"{R}top.py", _expr("f")) == (f"{R}m0.py", "f")
    edges = CallGraph(mods).edges
    assert any(e.caller == (f"{R}top.py", "user") and e.callee == (f"{R}m0.py", "f") for e in edges)


def test_the_reexport_depth_covers_at_least_a_two_hop_chain():
    """The parametrized chain rows above vanish if the depth is set to 0; this one cannot."""
    assert REEXPORT_DEPTH >= 2


def test_a_reexport_chain_past_the_depth_bound_is_not_followed():
    mods = _reexport_chain(REEXPORT_DEPTH + 1)
    assert CrossModuleResolver(mods).resolve(f"{R}top.py", _expr("f")) is None


def test_a_reexport_cycle_terminates_unresolved():
    mods = _mods(a="from .b import f\n", b="from .a import f\n", c="from .a import f\ndef user():\n    f()\n")
    assert CrossModuleResolver(mods).resolve(C, _expr("f")) is None


def test_a_module_alias_reexported_through_a_second_module_resolves():
    mods = _mods(a="def f():\n    pass\n", b="from . import a\n", c="from .b import a\ndef user():\n    a.f()\n")
    assert CrossModuleResolver(mods).resolve(C, _expr("a.f")) == (A, "f")


def test_a_snapshot_reaches_a_name_its_module_reexports():
    mods = _mods(a="def f():\n    pass\n",
                 b="from .a import f\n",
                 c="from . import b\nglobals().update({n: v for n, v in vars(b).items()})\ndef user():\n    f()\n")
    assert CrossModuleResolver(mods).resolve(C, _expr("f")) == (A, "f")


_PKG = "web/routers/pkg/"
_PEP562_PACKAGE = (
    "import types\n"
    "from . import _shared\n"
    "_CONCERN = ('.accounts', '.users', '.missing')\n"
    "class _Pkg(types.ModuleType):\n"
    "    def __getattr__(self, name):\n"
    "        if hasattr(_shared, name):\n"
    "            return getattr(_shared, name)\n"
    "        from importlib import import_module\n"
    "        for _modname in _CONCERN:\n"
    "            _m = import_module(_modname, package=self.__name__)\n"
    "            if hasattr(_m, name):\n"
    "                return getattr(_m, name)\n"
    "        raise AttributeError(name)\n"
)


def _pep562_modules(**extra: str) -> dict[str, ast.AST]:
    sources = {
        f"{_PKG}__init__.py": _PEP562_PACKAGE,
        f"{_PKG}_shared.py": "def shared_helper():\n    pass\ndef both():\n    pass\n",
        f"{_PKG}accounts.py": "def concern_helper():\n    pass\ndef both():\n    pass\n",
        f"{_PKG}users.py": "def user_helper():\n    pass\n",
        f"{_PKG}unlisted.py": "def unlisted_helper():\n    pass\n",
        "consumer.py": "from email_triage.web.routers.pkg import shared_helper, concern_helper, user_helper, both, unlisted_helper, nope\n",
    }
    sources.update(extra)
    return {rel: parse_source(src) for rel, src in sources.items()}


def test_a_module_getattr_fallback_resolves_the_shared_module_then_each_listed_concern():
    resolver = CrossModuleResolver(_pep562_modules())
    where = lambda name: resolver.resolve("consumer.py", _expr(name))  # noqa: E731
    assert where("shared_helper") == (f"{_PKG}_shared.py", "shared_helper")
    assert where("concern_helper") == (f"{_PKG}accounts.py", "concern_helper")
    assert where("user_helper") == (f"{_PKG}users.py", "user_helper")
    assert where("both") == (f"{_PKG}_shared.py", "both")  # `_shared` is asked first
    assert where("unlisted_helper") is None  # a module the fallback does not list
    assert where("nope") is None


def test_a_package_without_a_module_getattr_has_no_fallback():
    modules = _pep562_modules(**{f"{_PKG}__init__.py": "from . import _shared\n_CONCERN = ('.accounts',)\n"})
    resolver = CrossModuleResolver(modules)
    assert resolver.resolve("consumer.py", _expr("concern_helper")) is None


# --- B4: the taint fixpoint, on a sink that is not a secret write ----------------------------------------

def _tainted(mods):
    return param_taint_fixpoint(mods, lambda fn: {"user_input"})


def test_taint_reaches_a_helper_through_a_hop_and_a_second_helper_by_keyword():
    mods = _mods(a=("async def ep(user_input):\n    await db_call(helper, 1, user_input)\n"
                    "async def ep2():\n    await db_call(clean, 1, 'literal')\n"
                    "def helper(conn, value):\n    inner(v=value)\n"
                    "def inner(v):\n    sink(v)\n"
                    "def clean(conn, value):\n    sink(value)\n"))
    tainted = _tainted(mods).tainted
    assert tainted[(A, "helper")] == {"value"} and tainted[(A, "inner")] == {"v"}
    assert tainted[(A, "clean")] == set()


def test_taint_records_the_module_a_value_crossed_into():
    mods = _mods(a="from .b import save\nasync def ep(user_input):\n    save(user_input)\n",
                 b="def save(value):\n    sink(value)\n")
    result = _tainted(mods)
    assert result.tainted[(B, "save")] == {"value"} and (A, B, "save") in result.crossings


def test_taint_lines_a_bound_method_up_past_the_receiver():
    """`self.save(x)` passes x as save's SECOND parameter; the receiver fills `self`."""
    mods = _mods(a=("class Handler:\n    def ep(self, user_input):\n        self.save(user_input)\n"
                    "    def save(self, value):\n        sink(value)\n"))
    assert _tainted(mods).tainted[(A, "Handler.save")] == {"value"}


def test_taint_reaches_a_helper_called_from_a_closure_over_a_derived_name():
    mods = _mods(a=("def ep(user_input):\n    v = user_input\n    def _w():\n        helper(v)\n    return _w\n"
                    "def helper(x):\n    sink(x)\n"))
    assert _tainted(mods).tainted[(A, "helper")] == {"x"}


def test_taint_reports_a_derived_value_sent_to_a_name_it_cannot_pin_to_one_def():
    """An unknown receiver whose method name several defs share is neither followed nor dropped: a
    derived value reaching it is in `TaintResult.unresolved` (a pin fails on it, PD-8)."""
    shared = _mods(a="async def ep(user_input):\n    await db_call(obj.save, user_input)\n",
                   b="def save(value):\n    sink(value)\n", c="class K:\n    def save(self, value):\n        pass\n")
    result = param_taint_fixpoint(shared, lambda fn: {"user_input"}, loose_receivers=True)
    assert [(u.caller, u.attr) for u in result.unresolved] == [((A, "ep"), "save")]
    assert result.tainted[(B, "save")] == set()  # not followed
    # the same hop with ONE def of the name is followed, so nothing is left unresolved
    unique = _mods(a="async def ep(user_input):\n    await db_call(obj.save, user_input)\n",
                   b="def save(value):\n    sink(value)\n")
    followed = param_taint_fixpoint(unique, lambda fn: {"user_input"}, loose_receivers=True)
    assert followed.unresolved == []
    assert followed.tainted[(B, "save")] == {"value"}
    # a literal is not a derived value; a direct call and a keyword are judged the same way
    literal = _mods(a="async def ep(user_input):\n    await db_call(obj.save, 'x')\n",
                    b="def save(value):\n    pass\n", c="class K:\n    def save(self, value):\n        pass\n")
    assert param_taint_fixpoint(literal, lambda fn: {"user_input"}, loose_receivers=True).unresolved == []
    keyword = _mods(a="def ep(user_input):\n    obj.save(value=user_input)\n",
                    b="def save(value):\n    pass\n", c="class K:\n    def save(self, value):\n        pass\n")
    assert len(param_taint_fixpoint(keyword, lambda fn: {"user_input"}).unresolved) == 1  # loose off: also unresolved


# --- B7: module_ssot_imports reads importlib.import_module --------------------------------------------------

_SSOT = "email_triage.classify.baa_gate"
_DYNAMIC_RED = {
    "literal": f"import importlib\nbg = importlib.import_module({_SSOT!r})\n",
    "descendant": f"import importlib\nbg = importlib.import_module({_SSOT + '.child'!r})\n",
    "module constant": f"import importlib\n_M = {_SSOT!r}\nbg = importlib.import_module(_M)\n",
    "aliased importlib": f"import importlib as il\nbg = il.import_module({_SSOT!r})\n",
    "import_module by name": f"from importlib import import_module as im\nbg = im({_SSOT!r})\n",
    "annotated": f"import importlib\nbg: object = importlib.import_module({_SSOT!r})\n",
    "walrus": f"import importlib\n(bg := importlib.import_module({_SSOT!r}))\n",
}
_DYNAMIC_GREEN = {
    "another module": "import importlib\nbg = importlib.import_module('email_triage.classify.other')\n",
    "a computed name": "import importlib\nbg = importlib.import_module(f'email_triage.classify.{x}')\n",
    "an unknown constant": "import importlib\nbg = importlib.import_module(_UNSET)\n",
    "another library": f"import other\nbg = other.import_module({_SSOT!r})\n",
    "a return of another module": "import importlib\ndef load():\n    return importlib.import_module('email_triage.x')\n",
}
#: Resolved, but no plain name holds the module: "*", as a star-import answers (the tls.py:410 shape).
_DYNAMIC_STAR = {
    "an attribute target": f"import importlib\nself.bg = importlib.import_module({_SSOT!r})\n",
    "a return of a module constant": f"import importlib\n_M = {_SSOT!r}\ndef load():\n    return importlib.import_module(_M)\n",
    "an argument": f"import importlib\nuse(importlib.import_module({_SSOT!r}))\n",
    "a bare call by name": f"from importlib import import_module\ndef load():\n    return import_module({_SSOT!r})\n",
}


@pytest.mark.parametrize("label", sorted(_DYNAMIC_RED))
def test_module_ssot_imports_reads_a_dynamic_import_bound_to_a_name(label):
    assert module_ssot_imports(parse_source(_DYNAMIC_RED[label]), _SSOT) == {"bg"}, label


@pytest.mark.parametrize("label", sorted(_DYNAMIC_STAR))
def test_module_ssot_imports_answers_star_for_a_dynamic_import_no_name_holds(label):
    assert module_ssot_imports(parse_source(_DYNAMIC_STAR[label]), _SSOT) == {"*"}, label


@pytest.mark.parametrize("label", sorted(_DYNAMIC_GREEN))
def test_module_ssot_imports_ignores_what_is_not_the_ssot(label):
    assert module_ssot_imports(parse_source(_DYNAMIC_GREEN[label]), _SSOT) == set(), label


# --- the live tree: the rig can PASS --------------------------------------------------------------------

@pytest.fixture(scope="module")
def live_graph():
    return CallGraph({rel: tree for _path, rel, tree in walk_src()})


def test_every_live_call_site_of_a_funnel_is_in_its_own_closure(live_graph):
    """For the n201 funnel (called through `db_call` at every src site) each hop site's def is
    in the closure: a closure that could not see the live dispatch would drop them."""
    reach = live_graph.reach({"mark_backfill_capped"})
    sites = {(rel, qual) for rel, ms in live_graph.scopes.items() for qual, sc in ms.scopes.items()
             for call in sc.calls if is_call_of(call, "mark_backfill_capped")}
    assert sites and sites <= set(reach)
    assert reach.edge_count > 0


def test_the_live_ui_package_fallback_resolves_the_dispatcher_import(live_graph):
    """`providers/dispatcher.py` imports `_test_account_connection` from `routers.ui`, which defines it
    only in `_shared.py`: the package's snapshot and its PEP 562 `__getattr__` both lead there. Every
    module `_CONCERN_MODULES` lists is a fallback of the package, read from the AST."""
    ui = "web/routers/ui/__init__.py"
    found = live_graph.resolver.resolve("providers/dispatcher.py", _expr("_test_account_connection"))
    assert found == ("web/routers/ui/_shared.py", "_test_account_connection")
    tree = next(t for _p, rel, t in walk_src() if rel == ui)
    listed = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                  and any(getattr(t, "id", "") == "_CONCERN_MODULES" for t in n.targets))
    fallbacks = live_graph.resolver._fallbacks[ui]
    assert fallbacks[0] == "web/routers/ui/_shared.py" and len(listed) > 1
    assert fallbacks[1:] == [f"web/routers/ui/{name.lstrip('.')}.py" for name in listed]


def test_the_live_dynamic_import_in_tls_is_read():
    """`tls.py:410` returns `importlib.import_module(_SPKI_MODULE)`: no name holds the module."""
    tree = next(t for _p, rel, t in walk_src() if rel == "tls.py")
    assert module_ssot_imports(tree, "email_triage._distrusted_spki") == {"*"}


def test_the_live_graph_crosses_module_boundaries(live_graph):
    assert any(e.caller[0] != e.callee[0] for e in live_graph.edges), (
        "no call edge crosses a module in src/: the resolver sees nothing")
