"""the backlog  (Census v3 finding #8) — encryption-aware SQLite
open SSOT pin.

Structural: every ``sqlite3.connect(...)`` call site under
``src/email_triage/`` — encrypted OR plaintext, RW OR RO — MUST route
through one of the boot-encryption-aware SSOT openers in
``db/_engine.py``:

  * :func:`open_dedicated_conn` (RW, encryption-aware).
  * :func:`open_dedicated_conn_readish` (RO, encryption-aware; new
    at the backlog  landing).
  * :func:`open_dedicated_encrypted_conn_readish` (encrypted-only
    RO — leaf helper wrapped by ``open_dedicated_conn_readish``).

Raw ``sqlite3.connect(...)`` outside the allow-set drifts vs the
init_db argument profile (missing ``timeout=30.0``,
``cached_statements=0``, ``check_same_thread=False``) — pre-fix, 7
call sites hand-rolled the encrypted/plaintext branch and each
dropped a different subset of those args. Converging on ONE opener
+ this pin closes the class going forward
(§164.312(a)(2)(iv) encryption at rest + reliability under WAL
busy contention).

Prime Directive #6: routes through shared ``_pin_harness`` walker.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


# Files that are BY-DESIGN raw sqlite3.connect users — they define
# the SSOT openers themselves OR are part of the boot / init /
# migration surface that the SSOTs delegate to.
_ALLOW_FILES: frozenset[str] = frozenset({
    "db/_engine.py",       # DEFINES open_dedicated_conn* + init_db opener seed
    "db/_migrate.py",      # migration + baseline schema seeding
    "web/db.py",           # init_db lifespan owner
})


def _module_imports_sqlite3_connect(tree: ast.Module) -> bool:
    """DA NIT fold: catch ``from sqlite3 import connect`` too."""
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module != "sqlite3":
            continue
        for alias in node.names:
            if alias.name == "connect":
                return True
    return False


def _is_sqlite3_connect(node: ast.Call, bare_connect_bound: bool) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        # ``sqlite3.connect(...)`` — flag only the stdlib sqlite3 shape;
        # sqlcipher3 lives in _engine.py's encryption arm (allow-listed).
        if func.attr != "connect":
            return False
        base = func.value
        if isinstance(base, ast.Name) and base.id == "sqlite3":
            return True
        return False
    if isinstance(func, ast.Name) and func.id == "connect":
        # DA NIT fold: ``from sqlite3 import connect`` + ``connect(...)``.
        # Only flag when the module has that ImportFrom on the top
        # scope — a bare ``connect(...)`` from an unrelated import
        # would false-positive.
        return bare_connect_bound
    return False


def _walk_offenders() -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for path in iter_src_files():
        rp = relpath(path)
        if rp in _ALLOW_FILES:
            continue
        tree = parse_module(path)
        if tree is None or not isinstance(tree, ast.Module):
            continue
        bare = _module_imports_sqlite3_connect(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_sqlite3_connect(node, bare):
                out.append((rp, node.lineno))
    return out


def test_no_raw_sqlite3_connect_outside_ssot_openers():
    offenders = _walk_offenders()
    assert not offenders, (
        "Raw ``sqlite3.connect(...)`` outside the SSOT openers — "
        "boot-encryption + init_db argument-profile drift (§164.312"
        "(a)(2)(iv) encryption-at-rest + reliability under WAL busy "
        "contention):\n"
        + "\n".join(f"  {rp}:{ln}" for rp, ln in offenders)
        + "\nRoute through ``db/_engine.open_dedicated_conn`` (RW) "
        "OR ``db/_engine.open_dedicated_conn_readish`` (RO). Both "
        "are boot-encryption-aware + carry the full init_db argument "
        "set (timeout=30.0, check_same_thread=False, "
        "cached_statements=0). Legit exemptions belong in "
        "``_ALLOW_FILES`` with an explanatory comment."
    )
