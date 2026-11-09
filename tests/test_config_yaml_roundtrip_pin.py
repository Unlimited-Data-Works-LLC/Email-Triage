"""Config-store YAML round-trip completeness pin (divergence census run12 #4).

The full-rebuild config writer ``web/routers/ui/_shared._write_config_yaml_locked``
rebuilds the entire YAML from ``config.*`` on every admin-form Save. If it FORGETS
to emit a top-level section the loader reads, that section is SILENTLY DROPPED on
the next Save — the exact class of bug that once dropped
``persistence.encryption_enabled`` (§164.312(a)(2)(iv) at-rest encryption silently
OFF; fixed N-105/N-106). The census flagged this as a "store-boundary" gap.

Count-agnostic property (never ``len()==N``): every top-level section the LOADER
reads (``if "X" in raw:`` in ``config.py``) MUST be emitted by the writer
(``data["X"] = …``) OR be an allow-listed non-persistable section (e.g. a
removed-section guard that *raises* on its presence). A NEW config section added to
the loader but forgotten in the writer turns this RED before it silently eats an
operator's setting on their next Save.

Verify-don't-accept note (census run12 #4): the census's two "live" claims were
BOTH refuted at HEAD — (a) the ``INSERT INTO settings`` at ``db/audit.py`` is a
DOCUMENTED transactional UPSERT of the audit-chain *anchor* key (must share the
prune transaction; ``set_setting`` auto-commits) + invalidates the cache, not a
config bypass; (b) the ``encryption_enabled`` drop is already fixed (the writer
emits ``data["persistence"]`` with it). This pin is the PREVENTION layer for the
*next* such drop, not a live-bug fix.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

_CONFIG = SRC_ROOT / "config.py"
_WRITER = SRC_ROOT / "web" / "routers" / "ui" / "_shared.py"
_WRITER_FN = "_write_config_yaml_locked"
# The TOP-LEVEL loader — `raw` is the whole config dict. The per-section
# sub-parsers (`_parse_classifier`, `_parse_provider`, …) ALSO take a `raw` param
# (a sub-dict), so their `"X" in raw` checks are sub-keys (e.g. classifier's
# `categories`), NOT top-level sections — scoping to `_parse_raw` excludes them.
_LOADER_FN = "_parse_raw"

# Loader sections that are intentionally NOT round-tripped by the writer, each
# with a source-verified reason — NOT a writer gap. Keep SHORT; a new entry is a
# conscious decision that a readable section should not persist via a Save.
_NOT_PERSISTED: dict[str, str] = {
    # The loader RAISES ConfigError on a `_dev:` block (dev-mode removed in v0.x,
    # config.py ~:1718) — it is a removed-section REJECT guard, never persisted.
    "_dev": "removed legacy section — loader raises ConfigError on its presence",
    # NB `webhooks_allow_external` is NOT here: the writer DOES emit it (a
    # conditional scalar `data["webhooks_allow_external"] = True` when the operator
    # allowed external; absence = the deny default), so the writer-emit set covers
    # it and no exemption is needed — keeping it here would falsely imply it drops.
}


def _loader_sections(tree: ast.AST) -> set[str]:
    """Every ``if "X" in raw:`` top-level section-presence check — scoped to the
    ``_parse_raw`` loader so the sub-parsers' sub-key checks aren't mistaken for
    top-level sections (the `categories` false positive)."""
    out: set[str] = set()
    for fn in ast.walk(tree):
        if not (isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                and fn.name == _LOADER_FN):
            continue
        for n in ast.walk(fn):
            if (isinstance(n, ast.Compare) and len(n.ops) == 1
                    and isinstance(n.ops[0], ast.In)):
                left = n.left
                right = n.comparators[0]
                if (isinstance(left, ast.Constant) and isinstance(left.value, str)
                        and isinstance(right, ast.Name) and right.id == "raw"):
                    out.add(left.value)
    return out


def _writer_emissions(tree: ast.AST) -> set[str]:
    """Every top-level ``data["X"]`` key (assign target or ``data.setdefault("X")``)
    inside the writer fn — the sections it round-trips back to the YAML."""
    out: set[str] = set()
    for fn in ast.walk(tree):
        if not (isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                and fn.name == _WRITER_FN):
            continue
        for n in ast.walk(fn):
            # data["X"]  (top-level only — value must be the Name `data`)
            if (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name)
                    and n.value.id == "data" and isinstance(n.slice, ast.Constant)
                    and isinstance(n.slice.value, str)):
                out.add(n.slice.value)
            # data.setdefault("X", …)
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "setdefault"
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "data"
                    and n.args and isinstance(n.args[0], ast.Constant)
                    and isinstance(n.args[0].value, str)):
                out.add(n.args[0].value)
    return out


def test_writer_emits_every_loader_section():
    loader = _loader_sections(parse_module(_CONFIG))
    writer = _writer_emissions(parse_module(_WRITER))
    dropped = loader - writer - set(_NOT_PERSISTED)
    assert not dropped, (
        "Config section(s) READ by the loader but NOT emitted by the full-rebuild "
        f"writer ({_WRITER_FN}): {sorted(dropped)}. They are SILENTLY DROPPED on "
        "the next admin-form Save (the persistence.encryption_enabled drop class, "
        '§164.312(a)(2)(iv)). Emit `data["<section>"] = …` in the writer, or add '
        "to _NOT_PERSISTED with a source-verified reason if it is intentionally "
        "not round-tripped."
    )


def test_writer_emissions_include_persistence_encryption():
    """Belt-and-braces on the specific field whose silent drop motivated this —
    the writer must keep emitting persistence (carrying encryption_enabled)."""
    writer = _writer_emissions(parse_module(_WRITER))
    assert "persistence" in writer, (
        "the writer stopped emitting `persistence` — encryption_enabled would "
        "silently revert to OFF on the next Save (§164.312(a)(2)(iv))"
    )


def test_settings_table_write_single_owner():
    """The ``settings`` kv table is written ONLY through the ``set_setting`` SSOT
    (``web/db.py``) + the documented audit-chain-anchor transactional UPSERT
    (``db/audit.py`` — it must share the prune transaction, and ``set_setting``
    auto-commits, so it writes the one specific anchor key inline + invalidates
    the cache). A NEW raw ``INSERT INTO settings`` anywhere else forks the
    config-store boundary (census run12 #4 — verify-don't-accept confirmed the
    db/audit.py site is the documented exception, not a live bypass)."""
    allowed = {"web/db.py", "db/audit.py"}
    offenders = []
    for p in iter_src_files():
        rel = relpath(p)
        if rel in allowed:
            continue
        low = p.read_text(encoding="utf-8").lower()
        if "insert into settings" in low or "insert or replace into settings" in low:
            offenders.append(rel)
    assert not offenders, (
        "Raw `INSERT INTO settings` outside the set_setting SSOT (web/db.py) + the "
        f"documented audit-anchor (db/audit.py): {offenders}. Route config-store "
        "writes through web.db.set_setting (it auto-commits + invalidates the "
        "cache); the audit-anchor's inline UPSERT is the one transactional exception."
    )


def test_not_persisted_entries_are_real():
    """Each _NOT_PERSISTED entry must still be a loader section (else stale)."""
    loader = _loader_sections(parse_module(_CONFIG))
    stale = [s for s in _NOT_PERSISTED if s not in loader]
    assert not stale, (
        f"_NOT_PERSISTED names non-loader sections: {stale} — they no longer "
        "appear in the loader; drop the stale exemptions."
    )


def test_pin_has_teeth():
    loader_src = f'def {_LOADER_FN}(raw):\n    if "newthing" in raw:\n        cfg.x = 1\n'
    l = _loader_sections(ast.parse(loader_src))
    assert "newthing" in l
    # A SUB-parser's `"X" in raw` is NOT a top-level section (the categories
    # false-positive the scoping fixed).
    sub_src = 'def _parse_classifier(raw):\n    if "categories" in raw:\n        c.x = 1\n'
    assert "categories" not in _loader_sections(ast.parse(sub_src))
    # A writer that does NOT emit it → flagged (dropped).
    w_bad = ast.parse(
        f"def {_WRITER_FN}(config):\n    data = {{}}\n    data['other'] = 1\n"
    )
    assert "newthing" not in _writer_emissions(w_bad)
    # A writer that DOES emit it → not flagged.
    w_ok = ast.parse(
        f"def {_WRITER_FN}(config):\n    data = {{}}\n    data['newthing'] = 1\n"
    )
    assert "newthing" in _writer_emissions(w_ok)
