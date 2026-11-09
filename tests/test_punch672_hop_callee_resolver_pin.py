"""Punch 672 (panel Q, PD-2 / PD-6): ONE resolver for the callee a dispatcher hands off.

N-520's ``resolve``, the secret-write scanner's ``_callee_bindings`` and the punch-627
call-site pin each read a dispatcher's first argument their own way (``ast.Name`` only,
or Name and Attribute), and none unwrapped ``lambda: f(..)``, ``functools.partial(f, ..)``
or ``loop.run_in_executor(None, f, ..)``; N-73's reader took run_in_executor's EXECUTOR
as the callee. A funnel reached any of those ways was a false green (latent: 0 live
sites, hipaa-sme). They now ask ``_pin_harness.hop_target``.

* per form, the resolver answers the callee and the arguments it receives;
* per form AND per named consumer, the consumer sees the funnel (teeth: each of these
  rows fails on the 06663585 copy of that consumer for every form past Name);
* structural, count-agnostic: no test module outside the harness reads a dispatcher's
  ``.args[0]`` itself; teeth plant the old punch-627 shape.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for p in (TESTS, TESTS / "test_web"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from _pin_harness import (  # noqa: E402
    assert_pin_has_teeth,
    hop_target,
    iter_files,
    load_repo_script,
    parse_module,
    parse_source,
    relpath,
)

#: (label, call source). Every one hands off `f` with the argument `a`.
FORMS = [
    ("name", "db_call(f, a)"),
    ("attribute", "db_call(self.f, a)"),
    ("module attribute", "db_call(mod.f, a)"),
    ("unknown receiver", "db_call(obj.f, a)"),
    ("awaited", "await db_call(f, a)"),
    ("to_thread partial", "asyncio.to_thread(partial(f, a))"),
    ("functools.partial", "run_in_threadpool(functools.partial(f, a))"),
    ("lambda", "db_call(lambda: f(a))"),
    ("lambda over partial", "db_call(lambda: partial(f, a)())"),
    ("run_in_executor", "loop.run_in_executor(None, f, a)"),
    ("run_in_executor partial", "loop.run_in_executor(pool, partial(f, a))"),
]


def _call(src: str) -> ast.AST:
    tree = parse_source(f"async def _w():\n    return {src}\n")
    return tree.body[0].body[0].value


@pytest.mark.parametrize(("label", "src"), FORMS, ids=[f[0] for f in FORMS])
def test_the_resolver_answers_the_callee_and_its_argument(label, src):
    hop = hop_target(_call(src))
    assert hop is not None and hop.name == "f", label
    assert [a.id for a in hop.args if isinstance(a, ast.Name)] == ["a"], label


@pytest.mark.parametrize("src", [
    "f(a)", "db_call()", "db_call(make()(a))", "db_call(table[k], a)",
    "loop.run_in_executor(None)", "db_call(*fns)",
])
def test_the_resolver_answers_none_for_anything_else(src):
    hop = hop_target(_call(src))
    assert hop is None or hop.name is None


# --- per consumer ----------------------------------------------------------

CONSUMER_FORMS = FORMS


def _secret_write_sees(src: str) -> bool:
    # The pin's OWN path (census-r2 B fold, sme-da MUST-1): `ep` hands the form-derived `a` to `f`
    # through the form under test, and `f` writes it with `secrets.set`; the answer is whether
    # `sw._scan_modules` (not a proxy graph config) reports that write. `f` is a method only for
    # the `self.f` form; everywhere else it is the one module-level def of the name.
    import test_no_unguarded_secret_write as sw
    body = src.replace("await ", "")
    sink = ("class W:\n    def f(self, value):\n        secrets.set('K', value)\n" if "self." in body
            else "def f(value):\n    secrets.set('K', value)\n")
    tree = parse_source(sink + f"async def ep(form, secrets):\n    a = form['x']\n    await {body}\n")
    violations, _allowed, _crossings = sw._scan_modules({"m.py": tree})
    return any(rel == "m.py" and qual in ("f", "W.f") for rel, qual, _line in violations)


def _punch627_sees(src: str) -> bool:
    # By path, not a bare import: a bare `test_punch627...` reads as an undeclared
    # third-party module to the N-537 declared-imports pin (it lives under test_web/).
    p627 = load_repo_script("tests/test_web/test_punch627_grant_refusal_edges.py")
    return p627._calls_funnel(_call(src), {"f"})


def _n520_sees(src: str) -> bool:
    import test_n520_commit_before_witness_ratchet_pin as n520
    idx = n520.SrcIndex(defs={"m.py": {"f": ("m.py", "f")}})
    node = _call(src)
    if isinstance(node, ast.Await):
        node = node.value
    return n520.resolve(idx, "m.py", node) == ("m.py", "f")


CONSUMERS = {"secret-write": _secret_write_sees, "punch-627": _punch627_sees,
             "n520-resolve": _n520_sees}


@pytest.mark.parametrize("consumer", list(CONSUMERS))
@pytest.mark.parametrize(("label", "src"), CONSUMER_FORMS, ids=[f[0] for f in CONSUMER_FORMS])
def test_every_consumer_sees_the_funnel_through_every_form(consumer, label, src):
    assert CONSUMERS[consumer](src), f"{consumer} is blind to the {label} form: {src}"


# N-73's own row (its reader takes run_in_executor's hop callee, not the executor) lives in
# tests/test_n73_recipient_digest_hipaa_audit.py: that file does not ship, and a shipped test
# may not read an unshipped path (test_publish_no_operator_tooling).


# --- structural: nobody re-rolls the read ----------------------------------

def _dispatcher_set_name(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and (node.id.endswith("DISPATCHERS") or node.id == "_HOPS")


def _hand_rolled_hop_reads(tree: ast.AST) -> list[int]:
    """Lines of functions that test membership in a dispatcher set AND read a call's
    ``.args[0]`` themselves: the shape punch 672 retired."""
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        member = any(isinstance(n, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops)
                     and any(_dispatcher_set_name(c) for c in n.comparators)
                     for n in ast.walk(fn))
        reads = any(isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute)
                    and n.value.attr == "args" and isinstance(n.slice, ast.Constant)
                    and n.slice.value == 0 for n in ast.walk(fn))
        if member and reads:
            out.append(fn.lineno)
    return out


def test_no_test_module_reads_a_dispatchers_callee_itself():
    offenders = []
    for path in sorted(iter_files(TESTS, "*.py")):
        if path.name == "_pin_harness.py":
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        offenders += [f"{relpath(path, TESTS)}:{ln}" for ln in _hand_rolled_hop_reads(tree)]
    assert not offenders, (
        "these read a dispatcher's callee by hand; use _pin_harness.hop_target "
        f"(punch 672): {offenders}")


def test_teeth_the_old_punch627_shape_is_caught():
    bad = ("def _calls_funnel(node, funnels):\n"
           "    if _call_name(node) not in HOP_DISPATCHERS or not node.args:\n"
           "        return False\n"
           "    arg = node.args[0]\n"
           "    return isinstance(arg, ast.Name) and arg.id in funnels\n")
    good = ("def _calls_funnel(node, funnels):\n"
            "    hop = hop_target(node, HOP_DISPATCHERS)\n"
            "    return hop is not None and hop.name in funnels\n")
    assert_pin_has_teeth(_hand_rolled_hop_reads, bad, good)
