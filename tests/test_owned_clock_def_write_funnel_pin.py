"""PD#1 pin: every WRITE to ``regulatory_clock_def`` goes through the ONE funnel
module (``db/regulatory_clock.py``), and no SEED row carries an owner.

Operator-owned defs can ONLY be created/updated via create_owned_clock_def /
update_owned_clock_def, which force ``config_owner_account_id`` + a namespaced
``OWN_`` code and route through ``validate_owned_clock_def``. A raw INSERT/UPDATE
to ``regulatory_clock_def`` anywhere ELSE would bypass the regime-lock + the
owner/code immutability + the validation — so this count-agnostic structural pin
(AST string-literal scan over every src module, NOT ``len(X)==N``) flags any such
write outside the funnel module. Plus the seed-shaped property: every base seed
row is owner-NULL by construction (a seed carrying a non-NULL owner would slip an
operator-owned-looking row past the funnel).
"""

from __future__ import annotations

import ast
import re

from _pin_harness import parse_source, walk_src

from email_triage.db.regulatory_clock import _REGULATORY_CLOCK_SEED_CATALOG

# The ONE module allowed to write regulatory_clock_def (the seed + the owned-def
# CRUD funnel both live here).
_FUNNEL = "db/regulatory_clock.py"
_TABLE = "regulatory_clock_def"
_WRITE_RE = re.compile(r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b", re.IGNORECASE)


def _writes_clock_def_in_tree(tree: ast.AST) -> bool:
    """True if the module contains a string literal that is an INSERT/UPDATE/
    DELETE touching ``regulatory_clock_def`` (a raw SQL write to the table)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value
            if _TABLE in s and _WRITE_RE.search(s):
                return True
    return False


def _offenders() -> list[str]:
    out: list[str] = []
    for _path, rel, tree in walk_src():
        if rel == _FUNNEL:
            continue  # the sanctioned funnel home
        if _writes_clock_def_in_tree(tree):
            out.append(rel)
    return out


def test_clock_def_writes_only_in_the_funnel_module():
    offenders = _offenders()
    assert not offenders, (
        f"raw SQL write(s) to {_TABLE} OUTSIDE the {_FUNNEL} funnel — these "
        "bypass the regime-lock + owner/code immutability + validation. Route "
        "through create_owned_clock_def / update_owned_clock_def / "
        "delete_owned_clock_def instead:\n  " + "\n  ".join(offenders)
    )


def test_pin_has_teeth():
    """Flags a planted raw owned INSERT; passes a module with only a SELECT
    (anti-vacuous, PD#16)."""
    bad = parse_source(
        "q = 'INSERT INTO regulatory_clock_def (config_owner_account_id) "
        "VALUES (?)'\n"
    )
    good = parse_source(
        "q = 'SELECT * FROM regulatory_clock_def WHERE id = ?'\n"
    )
    assert _writes_clock_def_in_tree(bad)
    assert not _writes_clock_def_in_tree(good)


def test_no_seed_row_carries_an_owner():
    """Every base catalog seed row is owner-NULL by construction (a non-NULL
    owner would slip an operator-owned-looking row past the funnel)."""
    for entry in _REGULATORY_CLOCK_SEED_CATALOG:
        assert entry.get("config_owner_account_id") in (None, 0) or \
            "config_owner_account_id" not in entry, entry["code"]
        # And no base code uses the owned OWN_ namespace.
        assert not entry["code"].startswith("OWN_"), entry["code"]
