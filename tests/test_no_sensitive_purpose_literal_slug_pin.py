"""Structural pin (post-drive-full-census 2026-07-09 MF-1 fold): forbid
`raise_api_error(<literal-str-slug>, ..., purpose=<sensitive>)` and the
sibling `api_error_response(<literal-str-slug>, ..., purpose=<sensitive>)`
where the slug is a Python string constant and `purpose` is in
`_SENSITIVE_PURPOSES` ({auth, config, backup, provider, digest}) per
`web/_flash.py:58-66`.

What this defends
-----------------
The slug-destruction class the census + db-fast-review MF-1 caught:
`scrub_exc(exc, purpose=<sensitive>)` (web/_flash.py:87-88) REPLACES the
input with `f'{purpose} operation failed'` regardless of the input.
`raise_api_error` routes its first arg through scrub_exc; so
`raise_api_error("hipaa_blocked", purpose="auth")` yields
`detail={"error": "auth operation failed"}` — the developer-authored
machine slug is DESTROYED.

The sensitive-purpose defense is designed for the CAUGHT-EXCEPTION path
(where an OAuth lib may leak a token in `str(e)`). It is WRONG for a
fixed developer slug (a curated identifier, not a secret carrier).

The MF-1 drive fix at `a3cf46d8` swapped 5 dict-detail sites in
`agent_api.py` from `purpose="auth"|"provider"` → `purpose="misc"` —
`purpose="misc"` passes the slug through unchanged. This pin catches
the class going forward.

Count-agnostic
--------------
Per ``pattern_count_agnostic_structural_drift_catch.md`` — asserts a
PROPERTY over every raise_api_error/api_error_response call site (no
literal-slug arg + sensitive purpose), not a count.

Scope
-----
Repo-wide under `src/email_triage/`.

Allow-list
----------
`_ALLOWED_SLUG_DESTRUCTIONS` is the explicit set of `(relpath, funcname)`
exemptions for calls that INTENTIONALLY use a sensitive purpose with a
literal-str arg (rare — the developer must justify why the string is
NOT a machine-readable slug but a stand-in for a scrubbed message).
Empty at build time.

Meta-drift guarantee (PD#7)
---------------------------
Routes the walk through `_pin_harness.iter_src_files` + `parse_module` +
`relpath` + `innermost_fn_at_lineno` — meta-pin clean.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    innermost_fn_at_lineno,
    iter_src_files,
    parse_module,
    relpath,
)


_SSOT_FN_NAMES = frozenset({"raise_api_error", "api_error_response"})

_SENSITIVE_PURPOSES = frozenset({"auth", "config", "backup", "provider", "digest"})


_ALLOWED_SLUG_DESTRUCTIONS: set[tuple[str, str]] = set()


def _get_kwarg_value(call: ast.Call, name: str):
    """Return the ast node for kwarg `name` on `call`, or None."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_literal_str(node) -> bool:
    """True if `node` is a string constant (`"..."`)."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _scan() -> list[tuple[str, int, str, str, str]]:
    """Return `[(relpath, lineno, funcname, ssot_name, slug), ...]` for
    every `raise_api_error(<literal-str>, ..., purpose=<sensitive-str-literal>)`
    or `api_error_response(<literal-str>, ..., purpose=<sensitive>)` call."""
    offenders: list[tuple[str, int, str, str, str]] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            called = (
                f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute) else None
            )
            if called not in _SSOT_FN_NAMES:
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            if not _is_literal_str(first_arg):
                continue
            purpose_node = _get_kwarg_value(node, "purpose")
            if not _is_literal_str(purpose_node):
                continue
            if purpose_node.value not in _SENSITIVE_PURPOSES:
                continue
            fn = innermost_fn_at_lineno(tree, node.lineno)
            fn_name = fn.name if fn is not None else "<module>"
            if (rp, fn_name) in _ALLOWED_SLUG_DESTRUCTIONS:
                continue
            offenders.append((rp, node.lineno, fn_name, called, first_arg.value))
    return offenders


def test_no_sensitive_purpose_literal_slug():
    """No `raise_api_error(<literal>, ..., purpose=<sensitive>)` outside
    the allow-list — the slug will be destroyed by scrub_exc's sensitive-
    purpose flatten (web/_flash.py:87-88)."""
    offenders = _scan()
    if offenders:
        lines = [
            f"  {rp}:{ln} in `{fn}` — `{ssot}({slug!r}, ..., purpose=<sensitive>)`"
            for rp, ln, fn, ssot, slug in offenders
        ]
        raise AssertionError(
            "Slug-destruction class (post-drive-full-census 2026-07-09 MF-1): "
            "`raise_api_error(<literal-slug>, ..., purpose=<sensitive>)` will "
            "destroy the slug via scrub_exc's sensitive-purpose flatten. Use "
            "`purpose='misc'` for literal-str slug args (curated identifier, "
            "not a leak vector). Reserve `purpose='auth'|'provider'|'config'"
            "|'backup'|'digest'` for calls passing a real Exception whose "
            "`str()` could carry secrets.\n\n" + "\n".join(lines)
        )


def test_pin_has_teeth():
    """Detector flags a planted bad shape and passes a clean one."""
    from _pin_harness import parse_source
    bad = (
        "def handler():\n"
        "    raise raise_api_error('hipaa_blocked', status_code=403, "
        "purpose='auth')\n"
    )
    bad_api_error_response = (
        "def handler():\n"
        "    return api_error_response('csrf_unconfigured', "
        "status_code=500, purpose='auth')\n"
    )
    good_misc = (
        "def handler():\n"
        "    raise raise_api_error('hipaa_blocked', status_code=403, "
        "purpose='misc')\n"
    )
    good_exc = (
        "def handler(e):\n"
        "    raise raise_api_error(e, status_code=502, purpose='provider')\n"
    )
    for src in (bad, bad_api_error_response):
        tree = parse_source(src)
        hits = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in _SSOT_FN_NAMES
            and n.args and _is_literal_str(n.args[0])
            and _is_literal_str(_get_kwarg_value(n, "purpose"))
            and _get_kwarg_value(n, "purpose").value in _SENSITIVE_PURPOSES
        ]
        assert hits, f"pin missed a planted bad shape: {src!r}"
    for src in (good_misc, good_exc):
        tree = parse_source(src)
        hits = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "raise_api_error"
            and n.args and _is_literal_str(n.args[0])
            and _is_literal_str(_get_kwarg_value(n, "purpose"))
            and _get_kwarg_value(n, "purpose").value in _SENSITIVE_PURPOSES
        ]
        assert not hits, f"pin false-flagged clean shape: {src!r}"


def test_allow_list_is_grounded():
    """Every allow-list entry must correspond to a real
    sensitive-purpose slug destruction at HEAD."""
    live: set[tuple[str, str]] = set()
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            called = (
                f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute) else None
            )
            if called not in _SSOT_FN_NAMES:
                continue
            if not node.args or not _is_literal_str(node.args[0]):
                continue
            purpose_node = _get_kwarg_value(node, "purpose")
            if not _is_literal_str(purpose_node):
                continue
            if purpose_node.value not in _SENSITIVE_PURPOSES:
                continue
            fn = innermost_fn_at_lineno(tree, node.lineno)
            if fn is not None:
                live.add((rp, fn.name))
    stale = _ALLOWED_SLUG_DESTRUCTIONS - live
    assert not stale, (
        f"Stale _ALLOWED_SLUG_DESTRUCTIONS entries (no matching HEAD "
        f"call — delete): {sorted(stale)}"
    )


def test_sensitive_purposes_set_matches_ssot():
    """Anti-vacuity: the pin's `_SENSITIVE_PURPOSES` MUST match the SSOT
    at `web/_flash.py::_SENSITIVE_PURPOSES` — else the pin under- or
    over-scopes."""
    from email_triage.web._flash import _SENSITIVE_PURPOSES as SSOT_SET
    assert set(_SENSITIVE_PURPOSES) == set(SSOT_SET), (
        f"Pin _SENSITIVE_PURPOSES ({_SENSITIVE_PURPOSES}) differs from "
        f"SSOT ({SSOT_SET}) — sync the pin."
    )
