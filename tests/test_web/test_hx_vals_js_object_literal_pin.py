"""Pin: every ``hx-vals`` with a ``js:``/``javascript:`` prefix is an object literal.

htmx 2.0.4 wraps a ``js:`` value that does not start with ``{`` in braces and evaluates
``return ({<value>})``. A bare call such as ``js:etOutboundPreviewVals()`` becomes
``({etOutboundPreviewVals()})``, a SyntaxError thrown inside htmx's trigger handler: no
request is sent and no console message names the cause. Cycle Q's punch 414 refactor did
exactly that on all six webhook-preview controls, and only the e2e walk caught it. The
working spelling for a helper is ``js:{...helper()}``.

htmx trims the attribute once, BEFORE it strips the prefix, so ``js: {...}`` (a space
after the colon) is wrapped as well and breaks the same way. The ``{`` must follow the
prefix directly.

Count-agnostic: a property over every template the harness walks.
"""
from __future__ import annotations

import re

from tests._pin_harness import TEMPLATES_ROOT, iter_template_files, relpath

_HX_VALS = re.compile(r"""hx-vals\s*=\s*(?P<q>['"])(?P<v>.*?)(?P=q)""", re.DOTALL)
_JS_PREFIX = re.compile(r"^(?:js|javascript):")


def _offenders(text: str) -> list[str]:
    """Each ``js:`` hx-vals value whose expression is not a ``{`` object literal."""
    bad = []
    for m in _HX_VALS.finditer(text):
        value = m.group("v").strip()
        prefix = _JS_PREFIX.match(value)
        if prefix and not value[prefix.end():].startswith("{"):
            bad.append(value[:80])
    return bad


def test_every_js_hx_vals_is_an_object_literal():
    hits = {
        relpath(path, TEMPLATES_ROOT): found
        for path in iter_template_files()
        if (found := _offenders(path.read_text(encoding="utf-8")))
    }
    assert not hits, (
        "a js: hx-vals that is not an object literal throws inside htmx and sends no request; "
        f"spell a helper call as js:{{...helper()}}: {hits}")


def test_the_pin_has_teeth():
    assert _offenders("""<i hx-vals='js:etOutboundPreviewVals()'>""") == ["js:etOutboundPreviewVals()"]
    assert _offenders('''<i hx-vals="javascript: f()">''') == ["javascript: f()"]
    assert _offenders("""<i hx-vals='js: {a: 1}'>""") == ["js: {a: 1}"]
    assert _offenders("""<i hx-vals='js:{...etOutboundPreviewVals()}'>""") == []
    assert _offenders("""<i hx-vals='js:{
        a: f()}'>""") == []
    assert _offenders("""<i hx-vals='{"a": 1}'>""") == []
