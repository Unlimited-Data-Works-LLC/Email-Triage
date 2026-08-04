"""N-233 R22 structural pin — JSON body parse SSOT (2026-07-02).

Census R22 discovered class (MED, live 500-on-malformed defect):
`await request.json()` in the 4 WebAuthn/passkey/MFA finish handlers
(auth_keys.py:760, 935, 1146, 1260) raised JSONDecodeError → HTTP 500
instead of 400. Parallel Mode C at `agent_api.py:2620` (watch test fire)
fail-open silently treated malformed body as `{}` — intentional in
that context but the same shape was defect on auth entry points.

N-233 landed:
  - `web/routers/_json.py::parse_json_body(request, *, require_dict=True)`
    — the SSOT. Raises HTTPException(400) on JSONDecodeError + on
    non-dict when require_dict=True.
  - 4 auth_keys.py sites migrated (`body = await parse_json_body(request)`).
  - agent_api.py:2620 `watch_test_fire` stays as-is (intentional fail-
    open per handler docstring: "Fire the watch's actions against a
    synthetic envelope … no body required").

WHAT IT PINS (count-agnostic, tree-wide):

Every `await request.json()` outside the SSOT and the allow-listed
fail-open handler fires. Route through `parse_json_body`.

SCOPE CAVEAT: matches only the exact `await request.json()` AST shape.
A helper that wraps `request.json()` (not tree-wide today) would need
an interprocedural extension.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, annotate_parents, enclosing_fn, iter_files, parse_module, relpath


_SSOT_FILES = {"web/routers/_json.py"}

# Legit fail-open handlers (allow-listed keyed on (relpath, fn_name)).
# Census wf_56d1585d 2026-07-09 R22 residual: the previous file-
# level None allow was too broad — 6 raw `await request.json()` sites in
# agent_api.py sailed past the pin because ANYTHING in the file was
# whitelisted. Tightened to per-fn: only `webhook_watches_test_fire` is
# a legitimate fail-open (docstring: "Fire the watch's actions against a
# synthetic envelope … missing body → use synthetic default"). Every
# other agent_api.py handler routes through `parse_json_body`.
_ALLOW = frozenset({
    ("web/routers/agent_api.py", "webhook_watches_test_fire"),
})


# N-224b R23: parent-annotate routes through the shared harness
# `annotate_parents` + `enclosing_fn` (which returns the enclosing fn NAME
# directly). Removes the V4 hand-rolled parent-annotate offender.


def test_no_raw_request_json_outside_ssot():
    """STRICT tree-wide: every `await request.json()` outside `_json.py`
    and the allow-listed fail-open sites fires. Route through
    `parse_json_body(request)`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        # Skip file-level allow-listed files
        if (rel, None) in _ALLOW:
            continue
        annotate_parents(tree)  # N-224b R23: harness parent-annotator (V4 fix).
        for node in ast.walk(tree):
            # `await <call>` where <call> is `request.json()` /
            # `<any>.json()` on a Name matching "request".
            if not isinstance(node, ast.Await):
                continue
            call = node.value
            if not isinstance(call, ast.Call):
                continue
            f = call.func
            if not (isinstance(f, ast.Attribute) and f.attr == "json"):
                continue
            recv = f.value
            if not (isinstance(recv, ast.Name) and recv.id == "request"):
                continue
            # Get enclosing fn NAME via harness (returns "<module>" if
            # no enclosing fn). Normalise "<module>" → None for allow-list.
            fn_str = enclosing_fn(node)
            fn_name = None if fn_str == "<module>" else fn_str
            if (rel, fn_name) in _ALLOW:
                continue
            offenders.append(f"{rel}:{node.lineno} in `{fn_name}`")
    assert not offenders, (
        "N-233 R22 JSON body parse STRICT: raw `await request.json()` "
        "outside `web/routers/_json.py`. Route through "
        "`parse_json_body(request, *, require_dict=True)` so a malformed "
        "body returns HTTP 400 (not 500).\n\n"
        + "\n".join(offenders)
    )


def test_ssot_is_reachable():
    """Anti-vacuity: `parse_json_body` must import + be an async callable."""
    from email_triage.web.routers._json import parse_json_body
    import inspect
    assert inspect.iscoroutinefunction(parse_json_body)


def test_ssot_default_shape():
    """db-sme batch-2 Q2 satellite (2026-07-09): `parse_json_body`'s
    `require_dict` default MUST stay ``True``.

    The 6 migrated callers in ``agent_api.py`` (drive ) removed
    their own ``isinstance(body, dict)`` guards because the SSOT's
    ``require_dict=True`` default enforces the shape. A silent flip to
    ``False`` in a future refactor would break every caller — this
    assertion is the belt on the SSOT contract itself.
    """
    from email_triage.web.routers._json import parse_json_body
    import inspect
    sig = inspect.signature(parse_json_body)
    assert sig.parameters["require_dict"].default is True, (
        "parse_json_body's require_dict default flipped — this is a "
        "silent contract change; migrated callers depend on it."
    )
