"""Pin (punch 426): no raw exception text reaches the two surfaces the ACME cert reader feeds,
``templates/admin/acme_status.html`` (through ``cert_metadata()``) and ``/health/detail`` (through
``read_tls_cert_health()``).

The N-179 error-surface pins could not see this: ``web/acme_renewer.py`` is outside the router
walk, and the value hops a HELPER RETURN (``cert_metadata()`` -> the route / the health block),
the residual ``web/_flash.py`` documents. So the scrub is pinned AT THE PRODUCER, the one place
every consumer inherits it from:

* every ``parse_error`` dict value / keyword / subscript-assign anywhere in src is a
  ``scrub_exc(...)`` call, never an exception reference;
* every ``error`` / ``parse_error`` dict value in ``web/acme_renewer.py`` that mentions an
  ``except``-bound name is a ``scrub_exc(...)`` call. (A log call's ``error=`` keyword is a
  privileged sink and is not a dict key, so it is not in scope.)

``parse_error`` also joined ``ERR_KEYS`` in ``test_n179_error_surface_pin.py``, so a router that
re-introduces the shape is caught there.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth, iter_src_files, parse_module, parse_source, relpath,
)

SCRUB = "scrub_exc"
PRODUCER = "web/acme_renewer.py"
PRODUCER_KEYS = frozenset({"error", "parse_error"})
GLOBAL_KEYS = frozenset({"parse_error"})
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _is_scrubbed(value: ast.AST) -> bool:
    return (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
            and value.func.id == SCRUB)


def _except_names(tree: ast.AST) -> set[str]:
    return {n.name for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler) and n.name}


def _mentions(value: ast.AST, names: set[str]) -> bool:
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(value))


def _keyed_values(tree: ast.AST, keys: frozenset[str], *, keywords: bool):
    """``(line, value)`` for every dict-literal / subscript-assign (and, when asked, keyword)
    value written under one of ``keys``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value in keys:
                    yield v.lineno, v
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                        and t.slice.value in keys):
                    yield node.lineno, node.value
        elif keywords and isinstance(node, ast.keyword) and node.arg in keys:
            yield node.value.lineno, node.value


def raw_surface_values(tree: ast.AST, *, producer: bool) -> list[int]:
    """Lines where a surface key carries something other than a ``scrub_exc(...)`` call."""
    names = _except_names(tree)
    hits = [line for line, v in _keyed_values(tree, GLOBAL_KEYS, keywords=True)
            if not _is_scrubbed(v)]
    if producer:
        hits += [line for line, v in _keyed_values(tree, PRODUCER_KEYS, keywords=False)
                 if _mentions(v, names) and not _is_scrubbed(v)]
    return sorted(set(hits))


def test_no_raw_exception_reaches_the_cert_status_surfaces():
    offenders, producer_seen = [], False
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        producer_seen |= rel == PRODUCER
        offenders += [f"{rel}:{line}" for line in raw_surface_values(tree, producer=rel == PRODUCER)]
    assert producer_seen, f"the cert reader moved from {PRODUCER}"
    assert not offenders, (
        "A raw exception string is written under a user-facing cert-status key (punch 426). "
        "Route it through `scrub_exc(e, purpose='config')`:\n  " + "\n  ".join(offenders))


def _detector(producer: bool):
    return lambda tree: raw_surface_values(tree, producer=producer)


def test_detector_has_teeth_on_parse_error():
    assert_pin_has_teeth(
        _detector(False),
        bad_source="def f():\n    try:\n        pass\n    except Exception as e:\n"
                   "        return {'parse_error': str(e)}\n",
        good_source="def f():\n    try:\n        pass\n    except Exception as e:\n"
                    "        return {'parse_error': scrub_exc(e, purpose='config')}\n",
    )


def test_detector_has_teeth_on_the_producers_error_key():
    bad = ("def f():\n    try:\n        pass\n    except Exception as e:\n"
           "        return {'error': fmt_exc(e, with_class=True)}\n")
    assert_pin_has_teeth(
        _detector(True), bad_source=bad,
        good_source=bad.replace("fmt_exc(e, with_class=True)", "scrub_exc(e, purpose='config')"))
    # outside the producer the generic `error` key is not this pin's business
    assert not raw_surface_values(parse_source(bad), producer=False)
    # a pass-through of an already-scrubbed field is not an exception reference
    assert not raw_surface_values(parse_source(
        "def f(meta):\n    try:\n        pass\n    except Exception as e:\n        pass\n"
        "    return {'error': meta['parse_error']}\n"), producer=True)


def test_detector_catches_keyword_and_subscript_forms():
    for src in ("def f(e):\n    return g(parse_error=str(e))\n",
                "def f(e):\n    d = {}\n    d['parse_error'] = repr(e)\n    return d\n"):
        assert raw_surface_values(parse_source(src), producer=False), src
