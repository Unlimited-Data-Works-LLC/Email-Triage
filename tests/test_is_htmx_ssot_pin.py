""" (divergence census 2026-06-10) — HTMX-detection SSOT pin.

The "is this an HTMX request?" check (``HX-Request`` header) was inlined in 6
ui handlers, FIVE of them as a CASE-SENSITIVE ``request.headers.get("HX-Request")
== "true"``. HTMX itself sends ``"true"``, but an intermediary proxy can mangle
the header value's case, so the bare ``== "true"`` form is fragile + the six
copies can drift. The SSOT is ``web.routers.ui._shared.is_htmx`` (case-INSENSITIVE
``.lower() == "true"``).

Count-agnostic (``pattern_count_agnostic_structural_drift_catch``): asserts a
property over every site — no ``<x>.headers.get("HX-Request")`` read may exist
outside the SSOT, regardless of how many handlers there are. AST of the CALL, so
the ``HX-Request`` mentions in comments/docstrings don't trip it.

Scaffolding (src walk / relpath / parse) routes through ``tests/_pin_harness.py``
(R5b) — ``relpath`` is ``SRC_ROOT``-relative (``web/routers/ui/_shared.py`` form),
the SAME base this pin's ``_SSOT`` allow-list key was already written against, so
no re-key was needed in the migration.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath, walk_src

_SSOT = "web/routers/ui/_shared.py"


def _hx_request_read_lines(tree: ast.AST) -> list[int]:
    """Lines of ``<x>.headers.get("HX-Request", ...)`` reads — the inline
    HTMX-detection shape the SSOT replaces."""
    out: list[int] = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "get" and n.args):
            continue
        # receiver is a `.headers` attribute (request.headers / self.headers)
        recv = n.func.value
        if not (isinstance(recv, ast.Attribute) and recv.attr == "headers"):
            continue
        a0 = n.args[0]
        if (isinstance(a0, ast.Constant) and isinstance(a0.value, str)
                and a0.value.lower() == "hx-request"):
            out.append(n.lineno)
    return out


def test_no_inline_hx_request_read_outside_ssot():
    """Every HX-Request read routes through _shared.is_htmx — no inline
    ``headers.get("HX-Request")`` elsewhere (case-insensitive SSOT, proxy-safe)."""
    offenders = []
    for _path, rel, tree in walk_src():
        if rel == _SSOT:
            continue
        for ln in _hx_request_read_lines(tree):
            offenders.append(f"{rel}:{ln}")
    assert offenders == [], (
        "inline HX-Request read outside the is_htmx SSOT (#17): "
        f"{offenders}. Use email_triage.web.routers.ui._shared.is_htmx(request)."
    )


def test_ssot_defines_is_htmx():
    tree = parse_module(SRC_ROOT / "web" / "routers" / "ui" / "_shared.py")
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "is_htmx" in names


def test_is_htmx_is_case_insensitive():
    from email_triage.web.routers.ui._shared import is_htmx

    class _Req:
        def __init__(self, val):
            self.headers = {"HX-Request": val} if val is not None else {}

    assert is_htmx(_Req("true")) is True
    assert is_htmx(_Req("True")) is True   # proxy-mangled case still detected
    assert is_htmx(_Req("TRUE")) is True
    assert is_htmx(_Req("false")) is False
    assert is_htmx(_Req(None)) is False    # header absent


def test_pin_has_teeth():
    bad = (
        "def h(request):\n"
        "    return request.headers.get('HX-Request') == 'true'\n"
    )
    assert _hx_request_read_lines(ast.parse(bad)) == [2]
    ok = (
        "def h(request):\n"
        "    return _shared.is_htmx(request)\n"          # routed -> not an inline read
        "def g(d):\n"
        "    return d.get('HX-Request')\n"               # plain dict .get, not .headers.get
    )
    assert _hx_request_read_lines(ast.parse(ok)) == []
