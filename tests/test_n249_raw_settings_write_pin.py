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
- the settings-write SSOT fns and the reviewed `relpath::fn` exceptions
  of `test_config_store_disjoint_pin` (one exemption list per rule, PD#5;
  punch 729).
- `@register(...)`-decorated migration bodies (frozen; excluded by
  line-range per `_migration_body_line_ranges`).
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, innermost_fn_at_lineno, iter_files, parse_module, relpath
# PD#5 (punch 729): this pin and test_config_store_disjoint_pin guard ONE rule (no
# raw settings-table write outside the SSOT), so they share ONE exemption list. The
# private `_ALLOW_FNS` set it replaces had grown to 7 names, 3 of them dead:
# set_setting / delete_setting hold no SQL since their `*_txn` siblings took it
# (N-466, punch 708), and delete_account_settings lived in an `_ALLOW_FILES` file (that list was cut as
# dead 2026-11-05, allow-list step 6).
# The shared list is keyed `relpath::fn`, carries a reason per entry, is
# VALK-registered and has a staleness check; a new exception goes THERE.
from test_config_store_disjoint_pin import _SETTINGS_WRITE_ALLOW, _SETTINGS_WRITE_SSOT


_SETTINGS_WRITE_RE = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE)\s+.*\bsettings\b",
    re.IGNORECASE | re.DOTALL,
)


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


def test_no_raw_settings_write_outside_ssot():
    """STRICT-0: raw `INSERT/UPDATE/DELETE ... settings ...` outside
    the SSOT + allow-listed fns + `@register` migration bodies fires."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
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
            # Skip the SSOT fns and the shared reviewed exceptions. INNERMOST
            # def: the old private helper returned the first `ast.walk` (BFS)
            # hit, the OUTERMOST def, so an exempt route exempted every helper
            # nested in it.
            fn = innermost_fn_at_lineno(tree, node.lineno)
            fname = fn.name if fn is not None else "<module>"
            if fname in _SETTINGS_WRITE_SSOT or f"{rel}::{fname}" in _SETTINGS_WRITE_ALLOW:
                continue
            offenders.append(f"{rel}:{node.lineno} in `{fname}`")
    assert not offenders, (
        "N-249 R24 raw settings-table write outside SSOT. Route through "
        "`web/settings_keys.py` (wraps `invalidate_setting_cache`) or "
        "add a `relpath::fn` entry with a reason to `_SETTINGS_WRITE_ALLOW` in "
        "tests/test_config_store_disjoint_pin.py (the one list for this rule).\n\n"
        + "\n".join(offenders)
    )
