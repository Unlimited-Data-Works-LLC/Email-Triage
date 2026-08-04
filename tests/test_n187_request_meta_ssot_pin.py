"""N-187 R20_12 structural pin — request_meta SSOT.

Census run20 R20_12 finding: the tree hand-rolls `request.client.host if
request.client else None` (~14 sites), `.scope.get("client")[0] if _c else ""`
(health.py:1197 — the authz boundary), and `request.headers.get("user-agent")`
(~10 sites) with drifting fallback conventions (None vs "" vs missing). The
scope-form `""` fallback fed `_ops_token_authorized` (authz-boundary); a
divergence between fallback conventions is an authz-boundary drift shape.

SSOT: `web/dependencies.py::request_meta(request) -> RequestMeta(host, ua)`
with `host` and `ua` guaranteed non-None (empty string on unknown). Every
new caller MUST route through the SSOT; existing hand-rolls ride a ratchet
baseline burn-down under commit-coupled decrement (per N-178 pattern).

Fix landed 2026-07-01: SSOT added, authz-boundary health.py:1197 migrated.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


# Ratchet baseline (2026-07-01) — inline request.client.host + user-agent reads.
# Decrement in the SAME commit that migrates a callsite (N-178 commit-coupled).
_MAX_RAW_HOST = 1  # 2026-07-02 N-212c R23: SSOT def line only (census target). Auth_keys 8 + categories 2 + users 2 migrated; only dependencies.py:126 (the SSOT def) remains.
_MAX_RAW_UA = 10


def _iter_inline_host_reads(tree: ast.AST) -> list[int]:
    """Every `request.client.host` chain in `tree` (raw fallback pattern)."""
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "host":
            base = node.value
            if isinstance(base, ast.Attribute) and base.attr == "client":
                if isinstance(base.value, ast.Name) and base.value.id == "request":
                    hits.append(node.lineno)
    return hits


def _iter_inline_ua_reads(tree: ast.AST) -> list[int]:
    """Every `request.headers.get("user-agent")` call in `tree`."""
    hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "get":
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        if node.args[0].value != "user-agent":
            continue
        # Verify base is `request.headers`
        f = node.func.value
        if isinstance(f, ast.Attribute) and f.attr == "headers" \
                and isinstance(f.value, ast.Name) and f.value.id == "request":
            hits.append(node.lineno)
    return hits


def _walk_and_collect(check):
    reports = []
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        for ln in check(tree):
            reports.append(f"{rel}:{ln}")
    return reports


def test_inline_host_reads_ratchet():
    """Every new `request.client.host` chain must route through `request_meta`.
    Baseline ratchets down per commit (N-178 pattern)."""
    sites = _walk_and_collect(_iter_inline_host_reads)
    assert len(sites) <= _MAX_RAW_HOST, (
        f"N-187 R20_12 inline `request.client.host` count {len(sites)} > "
        f"baseline {_MAX_RAW_HOST}: " + ", ".join(sites[:10])
    )


def test_inline_ua_reads_ratchet():
    """Every new `request.headers.get('user-agent')` must route through
    `request_meta`. Baseline ratchets down per commit."""
    sites = _walk_and_collect(_iter_inline_ua_reads)
    assert len(sites) <= _MAX_RAW_UA, (
        f"N-187 R20_12 inline user-agent count {len(sites)} > "
        f"baseline {_MAX_RAW_UA}: " + ", ".join(sites[:10])
    )


def _binds_to_request_meta(tree: ast.AST, name: str) -> bool:
    """DA + hipaa-sme N-187 must-fix (interproc): return True if `name` is bound
    anywhere in `tree` to a `request_meta(...)` call — the 1-hop taint the
    strict authz pin follows through a `_meta = request_meta(request);
    client_host=_meta.host` shape."""
    for sub in ast.walk(tree):
        if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.Call):
            cf = sub.value.func
            called = cf.id if isinstance(cf, ast.Name) else (
                cf.attr if isinstance(cf, ast.Attribute) else None)
            if called != "request_meta":
                continue
            for tgt in sub.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return True
    return False


def test_authz_boundary_uses_ssot():
    """STRICT (hipaa-sme + DA N-187 must-fix): every `_ops_token_authorized`
    call in web/routers/**  MUST pass `client_host=` sourced from a
    `request_meta(...)` bound value (or a literal loopback constant) — no
    raw `request.client.host` / `request.scope.get("client")` walk at the
    authz boundary. Repo-wide sweep (DA must-fix #4: MODULE-wide walk, not
    single-file — a future refactor extracting to a helper won't false-pass)."""
    calls_found = 0
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            called = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else None)
            if called != "_ops_token_authorized":
                continue
            calls_found += 1
            for kw in node.keywords:
                if kw.arg != "client_host":
                    continue
                ok = False
                v = kw.value
                # 1) `request_meta(...).host` (inline).
                if isinstance(v, ast.Attribute) and v.attr == "host":
                    for sub in ast.walk(v):
                        if isinstance(sub, ast.Call):
                            cf = sub.func
                            cn = cf.id if isinstance(cf, ast.Name) else (
                                cf.attr if isinstance(cf, ast.Attribute) else None)
                            if cn == "request_meta":
                                ok = True
                                break
                # 2) `_meta.host` where _meta is bound to request_meta(...).
                if not ok and isinstance(v, ast.Attribute) and v.attr == "host" \
                        and isinstance(v.value, ast.Name):
                    if _binds_to_request_meta(tree, v.value.id):
                        ok = True
                # 3) Literal loopback (test seams).
                if not ok and isinstance(v, ast.Constant) and v.value in {
                    "127.0.0.1", "localhost", "::1"
                }:
                    ok = True
                assert ok, (
                    "N-187 R20_12 STRICT (hipaa-sme + DA must-fix): "
                    f"_ops_token_authorized client_host= at {relpath(path)}:"
                    f"{node.lineno} MUST route through `request_meta(request).host` "
                    "or a `request_meta`-bound `<name>.host` — no raw "
                    "`request.client.host` at the authz boundary."
                )
    assert calls_found >= 1, "no _ops_token_authorized call found — pin scope drifted"


def test_loopback_hosts_never_include_empty_string():
    """hipaa-sme N-187 must-fix #1: the `""` fallback in `_ops_token_authorized`
    is fail-closed ONLY because `_LOOPBACK_HOSTS` doesn't include `""`. Make
    the census-flagged concern STRUCTURAL — the set MUST NOT contain the
    empty string (a future edit adding it would silently invert the authz
    posture from fail-closed to fail-OPEN)."""
    from email_triage.web.routers import health as _h
    assert "" not in _h._LOOPBACK_HOSTS, (
        "N-187 R20_12 STRICT (hipaa-sme must-fix #1): _LOOPBACK_HOSTS must "
        "not contain the empty string — `request_meta` returns `\"\"` on "
        "unknown-peer, and admitting `\"\"` here would silently make "
        "`_ops_token_authorized` fail-OPEN on every no-client request."
    )
    # And the `.startswith` needle must not be empty either.
    assert not any(needle == "" for needle in ("127.",)), \
        "startswith needle drift check"


def test_pin_has_teeth():
    bad_host = ast.parse("def h(request):\n    return request.client.host\n")
    assert _iter_inline_host_reads(bad_host), "host teeth: bad shape must fire"

    bad_ua = ast.parse(
        "def h(request):\n"
        "    return request.headers.get('user-agent')\n"
    )
    assert _iter_inline_ua_reads(bad_ua), "ua teeth: bad shape must fire"

    good = ast.parse("def h(request):\n    return request_meta(request)\n")
    assert not _iter_inline_host_reads(good), "good must not fire"
    assert not _iter_inline_ua_reads(good), "good must not fire"
