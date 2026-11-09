""" -- `httpx.AsyncClient(...)` construction SSOT pin.

Every outbound HTTP client construction in the codebase must route
through `email_triage._egress.egress_async_client(...)` -- the SSOT
that (a) sets the timeout at construction, (b) applies the egress-
allowlist netloc guard, (c) plumbs the intent tag for observability.
Callers hold the client via `email_triage._http_client.LazyHttpClient`
which internally invokes `egress_async_client`.

A new `httpx.AsyncClient(...)` construction elsewhere in the codebase
would (a) skip the timeout policy (per  hunt: HTTP no-timeout
audit resolved 41 raw findings to CLIENT_INHERITED_TIMEOUT via those
2 SSOTs), (b) skip egress netloc-allowlist enforcement.

Grounding: 2026-07-11 workflow `wf_387b82b7-171` HTTP-no-timeout
llm-host audit (4-parallel llm-host offload) recommendation: promote the
existing SSOT policy from ad-hoc audit into a count-agnostic AST
pin. Only 1 legit construction site at HEAD: `_egress.py:194`.

Prime Directive #6: routes through `_pin_harness`. Name-anchored per
 R38.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


_SSOT_HOME = "_egress.py"


def _is_httpx_asyncclient_construction(node: ast.AST) -> bool:
    """Match `httpx.AsyncClient(...)`."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr != "AsyncClient":
        return False
    v = node.func.value
    return isinstance(v, ast.Name) and v.id == "httpx"


def test_no_httpx_asyncclient_construction_outside_egress_ssot():
    """Every `httpx.AsyncClient(...)` construction MUST live in
    `email_triage._egress` — the SSOT that applies timeout policy +
    egress netloc allowlist + intent tag."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith(_SSOT_HOME):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if _is_httpx_asyncclient_construction(node):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "#144 httpx.AsyncClient SSOT: `httpx.AsyncClient(...)` "
        "construction outside `email_triage._egress`. The SSOT sets "
        "the timeout at construction (per the 2 grounding SSOTs: "
        "`LazyHttpClient` + `egress_async_client`), applies the "
        "egress-allowlist netloc guard, and plumbs the intent tag. "
        "Route through `email_triage._egress.egress_async_client(...)`.\n\n"
        + "\n".join(offenders)
    )
