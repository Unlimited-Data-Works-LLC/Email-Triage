"""N-249 R24 structural pin — raw settings table write outside SSOT (2026-07-03).

Census R24 discovered LOW (raw `UPDATE settings` in migration): 1 site
at `web/migrations.py:669` inside `_v5` doesn't call
`invalidate_setting_cache` — invariant lie, but the migration body is
FROZEN per `incident_2026-06-11_migration_body_immutability`.

The migration body cannot be edited; the LOW severity reflects that
future runs execute this once at startup + then never again. But a
NEW raw settings write outside the SSOT is a defect — this pin
prevents that.

WHAT IT PINS:

Any `conn.execute("(INSERT|UPDATE|DELETE) ... settings ...")` outside:
- `settings_keys.py` (the SSOT that wraps + calls
  `invalidate_setting_cache`).
- `_capture_chain_anchor` / `delete_account_settings` /
  `profile_style_data_delete_all` (specifically-scoped writers that
  have their own cache-invariant handling per docstring).
- `@register(...)`-decorated migration bodies (frozen; excluded by
  line-range per `_migration_body_line_ranges`).
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SETTINGS_WRITE_RE = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE)\s+.*\bsettings\b",
    re.IGNORECASE | re.DOTALL,
)

_ALLOW_FILES = {
    "web/settings_keys.py",  # SSOT
}

# Fn names whose bodies legitimately write to settings AND correctly
# handle the cache invariant (either call `invalidate_setting_cache`
# themselves, or write to an account-scoped sub-table not covered by
# the process-wide settings cache).
_ALLOW_FNS = {
    # web/db.py — the WRITE SSOTs: both call `invalidate_setting_cache`
    # in the same fn (verified at HEAD).
    "set_setting",
    "delete_setting",
    "_capture_chain_anchor",
    "delete_account_settings",
    "profile_style_data_delete_all",
}


def _is_register_decorated(node: ast.AST) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Name) and target.id == "register":
            return True
        if isinstance(target, ast.Attribute) and target.attr == "register":
            return True
    return False


def _register_line_ranges(tree: ast.AST) -> list[tuple[int, int]]:
    return [
        (n.lineno, n.end_lineno or n.lineno)
        for n in ast.walk(tree)
        if _is_register_decorated(n)
    ]


def _enclosing_fn_name(tree: ast.AST, lineno: int) -> str | None:
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if n.lineno <= lineno <= (n.end_lineno or n.lineno):
                # Innermost win — nested defs are picked up by continuing.
                return n.name
    return None


def test_no_raw_settings_write_outside_ssot():
    """STRICT-0: raw `INSERT/UPDATE/DELETE ... settings ...` outside
    the SSOT + allow-listed fns + `@register` migration bodies fires."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _ALLOW_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        frozen = _register_line_ranges(tree) if "migrations.py" in rel else []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not (isinstance(f, ast.Attribute) and f.attr == "execute"):
                continue
            if not node.args:
                continue
            arg = node.args[0]
            sql = None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                sql = arg.value
            elif isinstance(arg, ast.JoinedStr):
                sql = "".join(
                    v.value for v in arg.values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                )
            if sql is None:
                continue
            if not _SETTINGS_WRITE_RE.match(sql.lstrip()):
                continue
            # Skip @register-frozen migration bodies (line-range).
            if any(lo <= node.lineno <= hi for lo, hi in frozen):
                continue
            # Skip explicitly-allowed fns.
            fn = _enclosing_fn_name(tree, node.lineno)
            if fn in _ALLOW_FNS:
                continue
            offenders.append(f"{rel}:{node.lineno} in `{fn}`")
    assert not offenders, (
        "N-249 R24 raw settings-table write outside SSOT. Route through "
        "`web/settings_keys.py` (wraps `invalidate_setting_cache`) or "
        "add the fn to `_ALLOW_FNS` with a justification.\n\n"
        + "\n".join(offenders)
    )
