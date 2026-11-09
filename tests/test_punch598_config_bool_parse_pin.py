"""Punch 598 — structural pin: every boolean config setting parses through the strict funnel.

The property (count-agnostic, R1): for EVERY field annotated ``bool`` /
``bool | None`` on ANY class in ``config.py``, every constructor keyword and every
``cfg.<field> = ...`` assignment in that file is a call to the funnel
(``_cfg_bool`` / ``_parse_config_bool`` / the ``_parse_encryption_enabled``
wrapper), optionally under ``<funnel> if isinstance(...) else <constant>``. A new
bool field parsed with ``bool(x.get(...))`` or a raw ``.get`` turns this RED —
those are the shapes that read a quoted ``"false"`` as True.

The field set is DERIVED from the dataclass annotations, not listed, so field
N+1 is covered the day it is added.

ALLOW_LIST (by field name, each with its reason): the classifier knobs whose
parse accepts ONLY a real bool (and null for the tri-state) and warns + keeps the
default otherwise (N-378 F1 panel shape). They never coerce a string, so they are
not the loose-parse class; folding them into a refusing parser would turn a
warned typo into a boot failure, which is a separate decision.

SCOPE CAVEAT: ``config.py`` only. Settings read from YAML-derived dicts outside
the loader (provider config blocks, account ``config_json``) are written by the
app as real bools and are not covered here.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, assert_pin_has_teeth, parse_module

CONFIG = SRC_ROOT / "config.py"
FUNNEL = frozenset({"_cfg_bool", "_parse_config_bool", "_parse_encryption_enabled"})
ALLOW_LIST = {
    "ollama_think": "N-378 tri-state: real bool or null only; anything else warned + ignored",
    "ollama_no_think_marker": "N-378 F1: real bool only; anything else warned + ignored",
    "debug_capture_raw_head": "real bool only; anything else warned + ignored",
    "cert_check": "operator certificate modes (2026-10-21): tls.coerce_tristate, an "
                  "unrecognised value inherits / keeps the default with a warning; a "
                  "setup / troubleshooting switch never refuses the load",
    "cert_enforce": "operator certificate modes (2026-10-21): as cert_check",
}


def bool_fields(tree: ast.AST) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for st in node.body:
                if (isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name)
                        and ast.unparse(st.annotation) in ("bool", "bool | None", "Optional[bool]")):
                    out.setdefault(node.name, set()).add(st.target.id)
    return out


def _is_funnel_call(expr: ast.AST) -> bool:
    if isinstance(expr, ast.IfExp):
        # Each branch is a funnel call or a constant, and at least one is a
        # funnel call: `True if raw.get(x) else False` reads a quoted "false"
        # as True (panel B3 DA F3).
        branches = (expr.body, expr.orelse)
        return (all(_is_funnel_call(b) or isinstance(b, ast.Constant) for b in branches)
                and any(_is_funnel_call(b) for b in branches))
    return (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name)
            and expr.func.id in FUNNEL)


def loose_bool_sites(tree: ast.AST) -> list[str]:
    """``Class.field@line`` for every bool-field parse site not routed through the funnel."""
    fields = bool_fields(tree)
    every = {f for fs in fields.values() for f in fs} - set(ALLOW_LIST)
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in fields:
            for kw in node.keywords:
                if kw.arg in fields[node.func.id] and kw.arg not in ALLOW_LIST \
                        and not _is_funnel_call(kw.value):
                    out.append(f"{node.func.id}.{kw.arg}@{kw.value.lineno}")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and t.attr in every \
                        and not _is_funnel_call(node.value):
                    out.append(f"<assign>.{t.attr}@{node.lineno}")
    return out


def test_every_bool_setting_parses_through_the_strict_funnel():
    tree = parse_module(CONFIG)
    assert tree is not None
    fields = bool_fields(tree)
    assert sum(len(v) for v in fields.values()) >= 20, "rig: bool-field discovery found too few fields"
    bad = loose_bool_sites(tree)
    assert not bad, (
        "bool config setting(s) parsed without the strict funnel (_cfg_bool / "
        "_parse_config_bool); a quoted \"false\" would read as True (punch 598): "
        f"{bad}"
    )


def test_allow_list_is_not_stale():
    tree = parse_module(CONFIG)
    assert tree is not None
    every = {f for fs in bool_fields(tree).values() for f in fs}
    stale = sorted(set(ALLOW_LIST) - every)
    assert not stale, f"ALLOW_LIST names fields that no longer exist: {stale}"


def test_funnel_routes_strings_through_the_envbool_ssot():
    """The funnel is not a second recognised-token list (PD-5): its string arm
    calls ``parse_bool_tristate``."""
    tree = parse_module(CONFIG)
    assert tree is not None
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_parse_config_bool")
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "parse_bool_tristate" in calls
    assert not any(isinstance(n, (ast.Set, ast.List, ast.Tuple)) and len(getattr(n, "elts", ())) >= 2
                   and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in n.elts)
                   for n in ast.walk(fn)), "funnel re-inlines a token list"


def test_pin_has_teeth():
    header = "from dataclasses import dataclass\n@dataclass\nclass PushConfig:\n    webhook_enabled: bool = True\n"
    assert_pin_has_teeth(
        loose_bool_sites,
        header + "def f(p):\n    return PushConfig(webhook_enabled=p.get('webhook_enabled', True))\n",
        header + "def f(p):\n    return PushConfig(webhook_enabled=_cfg_bool(p, 'webhook_enabled', default=True, section='push'))\n",
    )
    assert_pin_has_teeth(
        loose_bool_sites,
        header + "def f(p):\n    return PushConfig(webhook_enabled=bool(p.get('webhook_enabled', True)))\n",
    )
    assert_pin_has_teeth(  # attribute-assign shape + IfExp good shape
        loose_bool_sites,
        header + "def f(cfg, raw):\n    cfg.webhook_enabled = bool(raw['webhook_enabled'])\n",
        header + "def f(cfg, raw):\n    cfg.webhook_enabled = _cfg_bool(raw, 'webhook_enabled', default=True, section='') if isinstance(raw, dict) else False\n",
    )
    assert_pin_has_teeth(  # IfExp of two constants: neither branch is the funnel (panel B3 DA F3)
        loose_bool_sites,
        header + "def f(cfg, raw):\n    cfg.webhook_enabled = True if raw.get('webhook_enabled') else False\n",
        header + "def f(cfg, raw):\n    cfg.webhook_enabled = _cfg_bool(raw, 'webhook_enabled', default=True, section='') if raw else False\n",
    )
    assert_pin_has_teeth(  # the same shape on the constructor-keyword leg
        loose_bool_sites,
        header + "def f(p):\n    return PushConfig(webhook_enabled=True if p.get('webhook_enabled') else False)\n",
    )
