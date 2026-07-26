"""N-222 R22 structural pin — raw `user['role']` / `user.get('role')` growth cap (2026-07-02).

Census R22 (run22 backlog HIGH #4) discovered: the admin-role predicate
`user.get("role") == "admin"` is duplicated across 60+ Python sites — with
`admin_gate_response` / `assert_admin` covering only the "return 403 / raise"
branches. Conditional boolean logic had no funnel, so the raw comparison
drifted INTO the domain-gate SSOTs (`can_manage_account`,
`can_modify_owned_resource`, `is_list_*_by`).

N-222 adds `web/dependencies.py::is_admin(user) -> bool` as the boolean
SSOT, folds `admin_gate_response` + `assert_admin` onto it, AND lands a
growth-cap ratchet pin (N-178 pattern): baseline captured at the current
count; every NEW `user["role"]` / `user.get("role")` site fires the pin.
Migration of the existing 61 sites is deferred WITH BOUNDS (ratchet
prevents regression while incremental migrations decrement the cap).

WHAT IT PINS (count-agnostic, over-every-site):
Every COMPARISON of `user["role"]` / `user.get("role")` against a string
constant (typically `"admin"`) — i.e. the CHECK shape — is a raw
predicate that MUST route through `is_admin`. Data-passthrough reads
where `user["role"]` is passed as an argument to a session-token
encoder are LEGIT (the role IS the data being encoded, not checked
against a string) and are EXCLUDED from the count.

Baseline drops accordingly to the check-shape subset. On each migration
commit the baseline decrements to lock in the win.

SCOPE CAVEAT (honest): matches only `user["role"]` / `user.get("role")` at
the LEXICAL name `user` compared against a Constant on either side of
`==` / `!=`. Misses aliases (`current_user["role"]`, `self.user.role`)
and comparisons wrapped through helper variables. Extend `_ALIAS_NAMES`
if surface with drift.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_MAX_RAW_USER_ROLE_READS = 0  # 2026-07-02 N-222h R22 STRICT-0 CONVERGED: -13 more (push+routes+triage_classify+wizard+oauth+profile — all check-shape sites migrated)
_SSOT_FILES = {"web/dependencies.py"}
_ALIAS_NAMES = {"user"}


def _is_user_role_read(node: ast.AST) -> bool:
    """True if `node` is `user["role"]` or `user.get("role"[, ...])`."""
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name) and node.value.id in _ALIAS_NAMES:
            sl = node.slice
            if isinstance(sl, ast.Constant) and sl.value == "role":
                return True
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "get":
            if isinstance(f.value, ast.Name) and f.value.id in _ALIAS_NAMES:
                if (node.args
                        and isinstance(node.args[0], ast.Constant)
                        and node.args[0].value == "role"):
                    return True
    return False


def _count_sites_in_tree(tree: ast.AST) -> int:
    """Count Compare nodes where one side is user['role']/user.get('role') and
    the other side is a string Constant. That's the CHECK shape — a raw
    predicate that should route through is_admin. Data-passthrough reads
    (role passed to a session-token encoder etc.) don't fire the pin."""
    n = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        # Compare shape: `<left> <op> <right>` (multiple ops possible)
        parts = [node.left] + list(node.comparators)
        has_role_read = any(_is_user_role_read(p) for p in parts)
        has_str_const = any(
            isinstance(p, ast.Constant) and isinstance(p.value, str) for p in parts
        )
        if has_role_read and has_str_const:
            n += 1
    return n


def test_is_admin_ssot_exists():
    """Anti-vacuity: the SSOT `is_admin` must exist in `web/dependencies.py`."""
    for path in iter_files(SRC_ROOT):
        if relpath(path) == "web/dependencies.py":
            tree = parse_module(path)
            assert tree is not None
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "is_admin":
                    return
    raise AssertionError(
        "N-222 R22 anti-vacuity: `is_admin(user)` SSOT missing from "
        "`web/dependencies.py`. Restore it before enforcing the pin."
    )


def test_raw_user_role_reads_growth_cap():
    """Ratchet: total raw user role reads outside the SSOT must be <= baseline."""
    total = 0
    per_file: list[tuple[str, int]] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        n = _count_sites_in_tree(tree)
        if n > 0:
            total += n
            per_file.append((rel, n))
    assert total <= _MAX_RAW_USER_ROLE_READS, (
        f"N-222 R22 ratchet: raw `user['role']` / `user.get('role')` count "
        f"{total} > baseline {_MAX_RAW_USER_ROLE_READS}. NEW hand-rolls "
        "must route through `web/dependencies.is_admin(user)` (bool SSOT) "
        "OR the existing gates `admin_gate_response(user)` / "
        "`assert_admin(user)`.\n\n"
        + "\n".join(f"{p}: {n}" for p, n in per_file[:12])
    )
