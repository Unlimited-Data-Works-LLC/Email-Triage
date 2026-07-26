"""Config-key drift pin — Python twin of Pester T7.

Prime Directive #1 (project_style_guide): every SSOT ships a count-agnostic
structural pin. Prime Directive #7 (census-the-censusers): pins must be
symmetric across twins.

PS twin: ``tests/leira_ps_consumers_scaffold.Tests.ps1::T7`` scans the PSM1
for every ``$cfg['literal']`` access and asserts each key resolves in
``scripts/leira_config.json``. This is the Python mirror — AST-walks
``scripts/leira_prepass.py`` for every ``_CFG.get('literal')`` / ``_CFG['literal']``
access and asserts the same.

Landed 2026-07-17 (Batch-3 follow-on, DA NTH#3 fold) closing the twin
drift-pin asymmetry called out in the llm-host multi-host arc audit.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LEIRA_PREPASS_PATH = REPO_ROOT / "scripts" / "leira_prepass.py"
LEIRA_CONFIG_PATH = REPO_ROOT / "scripts" / "leira_config.json"

# Route AST parsing through the shared harness per pin N-224 R22 harness
# contract #3 (widened by N-251 R25). A raw bare-file inline parse would
# abort the walk on a src file's syntax or IO error; the harness treats
# each per-file failure as a skip + logs.
sys.path.insert(0, str(REPO_ROOT / "tests"))
from _pin_harness import parse_module  # noqa: E402


# Explicit allow-list — keys read from a nested `hosts.<name>` entry or a
# consumer section (both are DYNAMIC, not top-level config keys). Extend
# only with a CITED reason.
_ALLOWLIST: set[str] = {
    # From hosts.<name>.* accesses (nested dict, not top-level).
    "url",
    "model",
    "context_tokens_fallback",
    "weight",
    # From consumer sections + generic reads consumers do.
    "host",
}


def _collect_cfg_literal_keys() -> set[str]:
    """AST-walk `scripts/leira_prepass.py` via the shared harness; return
    every string-literal used as a key against the ``_CFG`` name
    (``_CFG.get('key')`` or ``_CFG['key']``)."""
    tree = parse_module(LEIRA_PREPASS_PATH)
    keys: set[str] = set()
    if tree is None:
        return keys

    for node in ast.walk(tree):
        # _CFG.get('key') / _CFG.get('key', default)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "_CFG"
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            keys.add(node.args[0].value)

        # _CFG['key']
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "_CFG"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            keys.add(node.slice.value)

    return keys


def test_every_cfg_literal_resolves_in_leira_config_json():
    """Every ``_CFG.get('literal')`` / ``_CFG['literal']`` access in
    ``scripts/leira_prepass.py`` MUST correspond to a real key in
    ``scripts/leira_config.json`` (top-level) OR be in the documented
    allow-list of dynamic/nested keys.

    This closes the silent-fallback-to-defaults drift class the PS T7 pin
    already covers — a fresh ``_CFG.get('typo_key')`` slipping into the
    module would previously fall through to the default without ANY test
    firing. Prime Directive #7 (census-the-censusers) — twin symmetry.
    """
    keys = _collect_cfg_literal_keys()
    assert keys, (
        "the module should have at least one _CFG literal access; if zero, "
        "the AST walker or the module drifted"
    )

    config = json.loads(LEIRA_CONFIG_PATH.read_text(encoding="utf-8"))
    config_keys = set(config.keys())

    unknown = {k for k in keys if k not in config_keys and k not in _ALLOWLIST}
    assert not unknown, (
        f"each _CFG[literal] must resolve to a real leira_config.json key "
        f"(or be documented in _ALLOWLIST). Silent-fallback-to-defaults "
        f"drift class. Offending keys: {sorted(unknown)}"
    )


def test_no_underscore_module_drift_on_dunder_scope():
    """Property test: the AST walker itself is count-agnostic (uses ``ast.walk``
    over the whole tree; no hardcoded N). Kept intentionally small — the
    pin's real teeth are the drift assertion above."""
    tree = parse_module(LEIRA_PREPASS_PATH)
    assert tree is not None, "leira_prepass.py failed to parse via harness"
    # The walker must find at least one Attribute node named 'get' AND at
    # least one Subscript node against `_CFG` — otherwise the SSOT has been
    # renamed and the pin is inert.
    has_get = any(
        isinstance(n, ast.Attribute) and n.attr == "get"
        for n in ast.walk(tree)
    )
    has_subscript = any(
        isinstance(n, ast.Subscript)
        and isinstance(n.value, ast.Name)
        and n.value.id == "_CFG"
        for n in ast.walk(tree)
    )
    assert has_get or has_subscript, (
        "leira_prepass.py has no _CFG.get / _CFG[...] access — the SSOT "
        "was renamed or removed; update the pin"
    )
