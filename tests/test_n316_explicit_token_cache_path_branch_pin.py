"""N-316 (2026-07-08) count-agnostic structural pin — the explicit-config
`token_cache_path` branch at `cli.py:496-498` is a documented
§164.306(d)(3)(ii)(B) equivalent-measure disposition per the N-316-close
register row (§4.9). Its structural shape MUST NOT drift silently — any
add / remove / invert of the guard reshapes the equivalent-measure
disposition and requires a fresh SME panel.

Pinned invariant (functional, structural — count-agnostic):

Inside the `_create_provider(config)` function in `src/email_triage/cli.py`
(the CLI provider factory), the O365 branch MUST include:

  1. An assignment `_token_cache_path = <call to o365_cfg.get("token_cache_path")>`
     (or an equivalent `.get(...)` on the o365 config dict).
  2. Followed by an `if not _token_cache_path:` guard body containing a
     Call to `msal_cache_path_for_cli(...)` — the N-307 SSOT-derived
     default that ONLY fires when the operator did not supply an
     explicit path.
  3. A `token_cache_path=_token_cache_path` kwarg passed to the O365
     provider constructor.

If ANY of these pieces are absent — for example, the guard is inverted
so the SSOT-derived path always overrides the explicit config (breaking
the equivalent-measure disposition), OR the SSOT call is removed so
blank-username installs silently write nowhere, OR the assignment is
routed through a different helper without the guard — the pin FIRES so
the class re-lands with a fresh SME panel per PD .

Not covered by this pin (deliberate scope):
  * The equivalent-measure story is documented in the register row; a
    future runtime-warning satellite lands as a SEPARATE change with
    its own SME panel.
  * The N-307 SSOT itself (`msal_cache_path_for_cli`) has its own pin
    at `test_no_forked_per_account_msal_cache_literal.py`; this pin
    only guards the CALLSITE's disposition-shape.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module


CLI_SRC = SRC_ROOT / "cli.py"


def _find_create_provider_fn(tree: ast.AST) -> ast.FunctionDef | None:
    """Locate the `_create_provider` function (may be `def` or nested)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_create_provider":
            return node
    return None


def _has_explicit_token_cache_path_assignment(fn: ast.FunctionDef) -> bool:
    """True if the function contains an assignment binding `_token_cache_path`
    (or `token_cache_path`) to a call whose target contains `token_cache_path`
    as a string arg — the "read the explicit config value" step."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id not in ("_token_cache_path", "token_cache_path"):
                continue
            # Inspect the RHS for a call to `.get("token_cache_path")` or
            # equivalent (via a `Dict.get` shape).
            for inner in ast.walk(node.value):
                if not isinstance(inner, ast.Call):
                    continue
                func = inner.func
                if isinstance(func, ast.Attribute) and func.attr == "get":
                    for arg in inner.args:
                        if isinstance(arg, ast.Constant) and arg.value == "token_cache_path":
                            return True
    return False


def _has_if_not_token_cache_path_with_ssot_call(fn: ast.FunctionDef) -> bool:
    """True if the function contains an `if not _token_cache_path:` (or
    equivalent test on the identifier's truthiness) whose body contains a
    call to `msal_cache_path_for_cli(...)` — the N-307 SSOT-derived
    default that guards blank-username installs."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        # Recognize `if not <name>:` shape.
        test = node.test
        if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
            continue
        operand = test.operand
        if not (isinstance(operand, ast.Name) and operand.id in ("_token_cache_path", "token_cache_path")):
            continue
        # Body must contain a call to `msal_cache_path_for_cli(...)`.
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            func = inner.func
            if isinstance(func, ast.Name) and func.id == "msal_cache_path_for_cli":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "msal_cache_path_for_cli":
                return True
    return False


def _has_o365_kwarg_from_local(fn: ast.FunctionDef) -> bool:
    """True if the function passes `token_cache_path=_token_cache_path`
    to a Call — the "thread the config value into the constructor" step."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != "token_cache_path":
                continue
            v = kw.value
            if isinstance(v, ast.Name) and v.id in ("_token_cache_path", "token_cache_path"):
                return True
    return False


def test_cli_o365_explicit_token_cache_path_branch_shape():
    """N-316 R30: the explicit-config `token_cache_path` branch in
    `_create_provider()` MUST maintain its §164.306(d)(3)(ii)(B)
    equivalent-measure structural shape. See the N-316-close register
    row (internal documentation §4.9)."""
    tree = parse_module(CLI_SRC)
    assert tree is not None, (
        "N-316 pin blind: cli.py failed to parse. Fix the source first."
    )
    fn = _find_create_provider_fn(tree)
    assert fn is not None, (
        "N-316 pin blind: `_create_provider` function not found in "
        "cli.py. Refactor may have moved / renamed it — update the "
        "pin's function-name allow-list."
    )
    assert _has_explicit_token_cache_path_assignment(fn), (
        "N-316: `_create_provider` no longer reads "
        "`o365_cfg.get('token_cache_path')` into a local. The N-307 "
        "explicit-config branch that closes the §164.306(d)(3)(ii)(B) "
        "equivalent-measure disposition is missing — the arrangement's "
        "documented shape has drifted. Re-panel or restore."
    )
    assert _has_if_not_token_cache_path_with_ssot_call(fn), (
        "N-316: `_create_provider` no longer contains the "
        "`if not _token_cache_path: _token_cache_path = str("
        "msal_cache_path_for_cli(...))` guard. The N-307 SSOT-derived "
        "default no longer protects blank-username installs — "
        "§164.310(d)(2)(i) disposal boundary has degraded. Re-panel."
    )
    assert _has_o365_kwarg_from_local(fn), (
        "N-316: `_create_provider` no longer threads "
        "`token_cache_path=_token_cache_path` into the O365 provider "
        "constructor. The whole branch's purpose has broken — the O365 "
        "provider will fall back to its dataclass default. Re-panel."
    )
