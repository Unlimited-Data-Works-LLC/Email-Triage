"""YAML-secret-value disjointness pin (llm-host census MED #2, 2026-07-24).

Structural guarantee: the YAML config-persist SSOT
`web/routers/ui/_shared.py::_write_config_yaml_locked` must never
carry a raw secret VALUE — only secret-store REFERENCES (fields whose
name terminates `_ref`, `_id`, `_key_name`) or empty/None sentinels.

Anchors: llm-host census wf_372dbfb0-8f2 row 2 (MED, effort S). HIPAA
§164.312(a)(2)(iv) encryption-at-rest drift-prevention.

Companion to `test_no_unguarded_secret_write.py` (that pin scans the
write-side funnel; this pin scans the YAML rebuild-side for raw
values leaking into the persisted config file).

Every raw-secret write must instead route through the `_secret_write`
SSOT + secret backend, and the YAML persists ONLY the store-side
pointer.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath

YAML_SSOT = SRC_ROOT / "web" / "routers" / "ui" / "_shared.py"

# Field names that would name a raw secret VALUE if assigned into the
# YAML data dict. These are the KEYS the pin scans for — the check is
# that the VALUE side of any assignment to one of these keys is safe
# (a `_ref` / `_id` / `_key_name` name, or empty/None).
_SECRET_KEY_NAMES = frozenset({
    "password", "passwd",
    "secret", "client_secret", "web_client_secret", "desktop_client_secret",
    "api_key", "apikey",
    "refresh_token", "access_token", "id_token", "session_token",
    "private_key", "signing_key",
    "google_secret", "office365_secret",
})

# Safe VALUE-side name suffixes — a value bound to a `foo_ref` /
# `foo_id` / `foo_key_name` variable is a reference, not the secret
# itself. Also allow explicit None/empty literals.
_SAFE_VALUE_SUFFIXES = ("_ref", "_id", "_key_name", "_name")


def _find_write_config_yaml_locked(mod_ast: ast.Module) -> ast.FunctionDef | None:
    for node in ast.walk(mod_ast):
        if isinstance(node, ast.FunctionDef) and node.name == "_write_config_yaml_locked":
            return node
    return None


def _value_is_safe(value: ast.AST) -> bool:
    # None / empty-string / bare False -> safe
    if isinstance(value, ast.Constant):
        if value.value in (None, "", False, 0):
            return True
    # Name whose id ends in a safe suffix -> reference, not raw value
    if isinstance(value, ast.Name):
        return any(value.id.endswith(s) for s in _SAFE_VALUE_SUFFIXES)
    # Attribute like config.secrets.google_client_secret_ref -> check the attr name
    if isinstance(value, ast.Attribute):
        return any(value.attr.endswith(s) for s in _SAFE_VALUE_SUFFIXES)
    # Subscript is safe ONLY when indexing the `existing` dict (the
    # prior YAML content, which already passed this pin on its own
    # write) — `existing["provider"]` preserve-as-is. Reviewer 2026-07-24:
    # an unconditional Subscript-safe would let a future
    # `data["password"] = secret_cache["password"]` slip past.
    if isinstance(value, ast.Subscript):
        base = value.value
        return isinstance(base, ast.Name) and base.id == "existing"
    # A ternary that both branches produce safe values
    if isinstance(value, ast.IfExp):
        return _value_is_safe(value.body) and _value_is_safe(value.orelse)
    return False


def _iter_key_value_pairs(fn: ast.FunctionDef):
    """Yield (key_name, value_node, lineno) for every literal-key dict
    assignment (data[...][KEY] = VALUE or data[...] = {KEY: VALUE, ...})
    inside the SSOT function body."""
    for node in ast.walk(fn):
        # data[...][KEY] = VALUE  (subscript assignment)
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.slice, ast.Constant)
                        and isinstance(tgt.slice.value, str)):
                    yield tgt.slice.value, node.value, node.lineno
        # data[...] = {KEY: VALUE, ...}  (dict literal)
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    yield k.value, v, k.lineno if hasattr(k, "lineno") else 0


def test_yaml_config_persist_carries_no_raw_secret_values():
    """Every KEY in the YAML SSOT that names a secret must bind to a
    safe VALUE — a `_ref`/`_id`/`_key_name` reference or an
    empty/None sentinel — never a raw secret literal or a bare
    variable name that could hold one.
    """
    tree = parse_module(YAML_SSOT)
    assert tree is not None, (
        f"could not parse {relpath(YAML_SSOT)} — YAML config-persist SSOT unreadable"
    )
    fn = _find_write_config_yaml_locked(tree)
    assert fn is not None, (
        f"expected `_write_config_yaml_locked` in {relpath(YAML_SSOT)} "
        "— YAML config-persist SSOT missing or renamed"
    )

    unsafe: list[tuple[str, int]] = []
    for key, value, lineno in _iter_key_value_pairs(fn):
        if key.lower() not in _SECRET_KEY_NAMES:
            continue
        if _value_is_safe(value):
            continue
        unsafe.append((key, lineno))

    assert not unsafe, (
        "YAML-secret-value disjointness violation in "
        f"`_write_config_yaml_locked` (see census wf_372dbfb0-8f2 row 2, "
        "HIPAA §164.312(a)(2)(iv) drift-prevention). Every YAML key that "
        "names a secret must bind to a `_ref` / `_id` / `_key_name` "
        "reference or empty/None, never a raw secret value. Offenders:\n"
        + "\n".join(f"  - key={k!r} at {YAML_SSOT.name}:{ln}" for k, ln in unsafe)
    )
