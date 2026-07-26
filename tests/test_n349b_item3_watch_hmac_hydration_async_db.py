"""N-349b Item 3 R31 structural pin — watch-HMAC hydration bloc is
off-loop (2026-07-08).

The `get_or_mint_secret` SSOT's first positional arg is a
`SecretsProvider` (a Python protocol), NOT a `sqlite3.Connection`.
The `test_async_db_safety.py`  cross-module walker discovers
DB-touching names by transitive-import through catalogued
`db.py` / `db_writelock.py` helpers — but `SecretsProvider.get/set`
is an interface method whose IMPLEMENTATION (`DbSecrets`) hits the
DB, without a static-analyzable link the walker can follow through
the abstraction. Pre-Item-3, the 3 watch-HMAC hydration callsites
(agent_api.py, profile.py×2) called `get_or_mint_secret` SYNCHRONOUSLY
on the FastAPI event loop and slipped past the  pin — a documented
scope-boundary of the walker's transitive-import model, not a bug in it.

Item 3 wraps the 3 sites in `await db_call(get_or_mint_secret, ...)`
so the whole bloc runs off-loop under the process-wide RLock. INNER
`@db_write` helpers (secrets.set, consume_hmac_clobber_bypass,
record_hmac_clobber_bypass_consumed) re-enter the SAME RLock in the
SAME worker thread — `threading.RLock` semantics per
`web/db_writelock.py:69` — so no cross-thread wait, no deadlock class.

WHAT IT PINS (count-agnostic structural):

Every call to `get_or_mint_secret` (in ANY module under
`src/email_triage/**` — routers, watch_runner, background_sweepers,
web/app.py background tasks, actions, everywhere) whose NEAREST
enclosing function is `async def` MUST be wrapped in
`await db_call(get_or_mint_secret, ...)`. A future 4th consumer that
calls `get_or_mint_secret` directly on the event loop FIRES this pin
at import time — closing the walker-scope-boundary class documented
above.

Call-shape coverage (per SME panel 2026-07-08 DA F2):

- Bare-name  : `get_or_mint_secret(...)`
- Aliased    : `_get_or_mint_secret(...)` (via `import ... as ...`)
- Attribute  : `email_triage.secrets.get_or_mint_secret(...)`
- Attribute  : `secrets_mod.get_or_mint_secret(...)` (aliased module import)
- Relative import: `from ..secrets import get_or_mint_secret`
  (`node.level > 0` in ImportFrom)

Async-context coverage (per SME panel 2026-07-08 DA F3):

- The pin walks ancestors innermost-to-outermost and consults ONLY the
  NEAREST enclosing `FunctionDef` or `AsyncFunctionDef`. A SYNC `def`
  nested inside an `async def` closure IS a sync context — the pin
  MUST NOT fire on a `get_or_mint_secret` call inside that inner sync
  def (its caller is responsible for off-loop dispatch), only inside
  the async body proper.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    iter_files,
    parse_module,
    relpath,
)


def _collect_get_or_mint_secret_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Return (name_aliases, module_aliases) resolving to
    `email_triage.secrets.get_or_mint_secret` in this module.

    - name_aliases  : local names for the FUNCTION itself
      (from `from email_triage.secrets import get_or_mint_secret as X`
      OR relative `from ..secrets import get_or_mint_secret`).
    - module_aliases: local names for the MODULE
      (from `import email_triage.secrets` OR
      `import email_triage.secrets as X`). A call would look like
      `<module_alias>.get_or_mint_secret(...)`.

    Relative-import handling: any ImportFrom whose module ends in
    ``"secrets"`` (or is exactly ``"secrets"``) — whether absolute
    (`email_triage.secrets`) or relative (`from ..secrets import ...`,
    `node.level > 0`) — carries the function into scope. This closes
    the DA-flagged relative-import blind spot (SME panel 2026-07-08).
    """
    name_aliases: set[str] = {"get_or_mint_secret"}
    module_aliases: set[str] = {"email_triage.secrets"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            # Accept `email_triage.secrets` (absolute) OR any `secrets`
            # module reached relatively — the relative resolver can't
            # know the anchor here, so err on the side of INCLUSION.
            if (
                module == "email_triage.secrets"
                or (node.level > 0 and module == "secrets")
                or module.endswith(".secrets")
            ):
                for name in node.names:
                    if name.name == "get_or_mint_secret":
                        name_aliases.add(name.asname or name.name)
        elif isinstance(node, ast.Import):
            for name in node.names:
                if name.name == "email_triage.secrets":
                    module_aliases.add(name.asname or name.name)


    return name_aliases, module_aliases


def _call_target_name(call: ast.Call) -> str | None:
    """Return the callable name the call resolves to, or None.

    Handles both `ast.Name` (bare / aliased function call) and
    `ast.Attribute` (module.function call, one hop deep). Deeper
    attribute chains are ignored — the callable would need chain
    resolution beyond ast.dump().
    """
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return f"{call.func.value.id}.{call.func.attr}"
    return None


def _call_is_get_or_mint_secret(
    call: ast.Call,
    name_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    """True iff the call is `get_or_mint_secret(...)` in any covered
    shape (bare, aliased, `<mod>.get_or_mint_secret`, aliased-module)."""
    target = _call_target_name(call)
    if target is None:
        return False
    if target in name_aliases:
        return True
    if "." in target:
        mod, fn = target.split(".", 1)
        if fn == "get_or_mint_secret" and mod in module_aliases:
            return True
    return False


def _is_db_call_wrapped(
    call: ast.Call,
    name_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    """True iff ``call`` is ``db_call(<sync_fn>, ...)`` and `<sync_fn>`
    resolves to `get_or_mint_secret` in any covered shape."""
    if not isinstance(call.func, ast.Name):
        return False
    if call.func.id != "db_call":
        return False
    if not call.args:
        return False
    first = call.args[0]
    if isinstance(first, ast.Name):
        return first.id in name_aliases
    if isinstance(first, ast.Attribute) and isinstance(first.value, ast.Name):
        target = f"{first.value.id}.{first.attr}"
        if first.attr == "get_or_mint_secret" and first.value.id in module_aliases:
            return True
    return False


def _nearest_enclosing_is_async(ancestors: list[ast.AST]) -> bool:
    """True iff the NEAREST enclosing FunctionDef ancestor is
    `AsyncFunctionDef`. A sync `def` nested inside an `async def`
    closure IS a sync context — the pin MUST NOT fire on a
    `get_or_mint_secret` call inside that inner sync def (its caller
    is responsible for off-loop dispatch), only inside the async body
    proper. Walk ancestors innermost-to-outermost."""
    for a in reversed(ancestors):
        if isinstance(a, ast.AsyncFunctionDef):
            return True
        if isinstance(a, ast.FunctionDef):
            return False
    return False


def test_watch_hmac_hydration_is_off_loop():
    """Count-agnostic: every `get_or_mint_secret` call whose NEAREST
    enclosing function is `async def` (anywhere in `src/email_triage/**`)
    MUST be wrapped in `await db_call(get_or_mint_secret, ...)`. A
    direct call on the event loop is the N-349b Item 3 defect the wrap
    closed."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        name_aliases, module_aliases = _collect_get_or_mint_secret_aliases(tree)

        # Track ancestor chain during the walk so we can ask "am I
        # inside an async def" AND skip children of a db_call wrapper.
        ancestors: list[ast.AST] = []

        def visit(node: ast.AST) -> None:
            ancestors.append(node)
            try:
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.Call):
                        if _is_db_call_wrapped(child, name_aliases, module_aliases):
                            # A db_call wrapper that consumes a
                            # get_or_mint_secret alias — do NOT recurse
                            # into args[0] (the sync_fn positional
                            # reference is NOT a direct call). Recurse
                            # into the other args + kwargs (they may
                            # contain lambdas the walker still needs
                            # to see).
                            for arg in child.args[1:]:
                                visit(arg)
                            for kw in child.keywords:
                                if kw.value is not None:
                                    visit(kw.value)
                            continue
                        if (
                            _call_is_get_or_mint_secret(
                                child, name_aliases, module_aliases,
                            )
                            and _nearest_enclosing_is_async(ancestors)
                        ):
                            target = _call_target_name(child) or "<unknown>"
                            offenders.append(
                                f"{rel}:{child.lineno} — "
                                f"`{target}(...)` called "
                                "directly on the event loop; wrap in "
                                "`await db_call(get_or_mint_secret, ...)` "
                                "(N-349b Item 3 async-DB seam)."
                            )
                    visit(child)
            finally:
                ancestors.pop()

        visit(tree)

    assert not offenders, (
        "N-349b Item 3 async-DB seam breach: `get_or_mint_secret` "
        "MUST run off the FastAPI event loop via "
        "`await db_call(get_or_mint_secret, ...)`. Direct calls slip "
        "past the  walker (SecretsProvider abstracts the DB out "
        "of the transitive-import graph) — this pin is the closure.\n\n"
        + "\n".join(offenders)
    )
