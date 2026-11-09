"""Secret-key NAME derivation — count-agnostic structural pin (census run15 #7).

The secrets-store key for an account's password / refresh-token
(``ACCOUNT_<id>_IMAP_PASSWORD`` / ``..._O365_SECRET`` /
``..._GMAIL_REFRESH_TOKEN``) must be derived in ONE place: the table-driven
``providers.traits.secret_key_for_account`` (reading
``TRAITS[ptype].secret_key_template``). Before this fix the key name was ALSO
hardcoded as an f-string in ``providers/factory.py`` (3 branches) and
``web/db.py`` (the O365 copy) — a CIDI twin: add a new provider to ``TRAITS``
but forget the factory branch (or change a key name in one fork only) and the
WRITE side and the READ side derive DIFFERENT keys → a secret saved under one
key, read under another → fail-CLOSED credential loss for that provider class.
At HEAD the forks were byte-identical, so there was no live bug — this is
forward drift-prevention of a security-critical (credential-resolution) value.

INVARIANT: no per-account secret-key TEMPLATE/instance — an f-string or a
``.format`` template of the shape ``ACCOUNT_{…}_<…PASSWORD|SECRET|TOKEN>`` — may
appear in ``src/email_triage`` OUTSIDE ``providers/traits.py`` (where the TRAITS
``secret_key_template`` strings are the SSOT). The bare ``ACCOUNT_{id}_``
LIKE-prefix (the account-purge sweep) has no credential suffix and is not
matched; docstrings start with prose (not ``ACCOUNT_``) and are excluded by the
``^`` anchor.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

# The TRAITS registry is the one sanctioned home of the key templates.
_SSOT_RELPATH = "providers/traits.py"

# A per-account secret-key shape: starts ACCOUNT_, carries a placeholder, ends
# in a credential word. Four build idioms are covered (DA run15 #7 — close the
# dormant blind spots, don't just note them):
#   * f-string SKELETON (FormattedValues rendered as ``{}``)        → _FSTRING_SHAPE
#   * ``.format``-template Constant (``{account_id}`` placeholder)  → _TEMPLATE_SHAPE
#   * ``%``-format Constant (``ACCOUNT_%d_..._SECRET`` % id)        → _PERCENT_SHAPE
#   * ``"ACCOUNT_" + str(id) + "_SECRET"`` additive concat          → _CONCAT_SHAPE
_FSTRING_SHAPE = re.compile(r"^ACCOUNT_.*\{\}.*(PASSWORD|SECRET|TOKEN)")
_TEMPLATE_SHAPE = re.compile(r"^ACCOUNT_.*\{[^}]*\}.*(PASSWORD|SECRET|TOKEN)")
_PERCENT_SHAPE = re.compile(r"^ACCOUNT_.*%[sd].*(PASSWORD|SECRET|TOKEN)")
# Concat skeleton uses \x00 for each dynamic (non-literal) operand.
_CONCAT_SHAPE = re.compile(r"^ACCOUNT_.*\x00.*(PASSWORD|SECRET|TOKEN)")


def _fstring_skeleton(node: ast.JoinedStr) -> tuple[str, bool]:
    """(literal skeleton with ``{}`` for each FormattedValue, has_placeholder)."""
    parts: list[str] = []
    has_ph = False
    for v in node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
        elif isinstance(v, ast.FormattedValue):
            has_ph = True
            parts.append("{}")
    return "".join(parts), has_ph


def _flatten_add(node: ast.AST) -> list[ast.AST]:
    """Flatten a left-assoc string ``+`` chain into ordered operands."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _concat_skeleton(node: ast.BinOp) -> tuple[str, bool]:
    """(literal skeleton with \\x00 for each dynamic operand, has_dynamic)."""
    parts: list[str] = []
    has_dyn = False
    for op in _flatten_add(node):
        if isinstance(op, ast.Constant) and isinstance(op.value, str):
            parts.append(op.value)
        else:
            has_dyn = True
            parts.append("\x00")
    return "".join(parts), has_dyn


def _secret_key_literals(tree: ast.AST) -> list[int]:
    """Line numbers of per-account secret-key build sites (all four idioms)."""
    out: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            skel, has_ph = _fstring_skeleton(node)
            if has_ph and _FSTRING_SHAPE.search(skel):
                out.append(node.lineno)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            skel, has_dyn = _concat_skeleton(node)
            if has_dyn and _CONCAT_SHAPE.search(skel):
                out.append(node.lineno)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _TEMPLATE_SHAPE.search(node.value) or _PERCENT_SHAPE.search(node.value):
                out.append(node.lineno)
    return out


def test_secret_key_name_derived_only_in_traits():
    offenders = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_RELPATH:
            continue
        locs = _secret_key_literals(parse_module(path))
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "a per-account secret-key NAME is hardcoded outside the table-driven "
        f"SSOT providers/traits.py: {offenders}. Derive it via "
        "providers.traits.secret_key_for_account(account_id, ptype) (or the "
        "factory / _shared delegators) — a hardcoded ACCOUNT_{id}_*_PASSWORD/"
        "SECRET/TOKEN fork desyncs the write side from the read side on any "
        "future key-name change (census run15 #7)."
    )


def test_ssot_actually_holds_the_templates():
    """Anti-vacuity: traits.py must still carry the key templates (the
    detector FIRES on them), else the invariant above is vacuously true."""
    locs = _secret_key_literals(parse_module(SRC_ROOT / "providers" / "traits.py"))
    assert len(locs) >= 3, (
        "the TRAITS secret_key_template strings vanished from providers/traits.py "
        f"(found {locs}) — the SSOT no longer holds the key templates, so the "
        "pin is vacuous."
    )


# --------------------------------------------------------------------------
# Teeth — the detector must catch a planted hardcoded key and ignore non-keys.
# --------------------------------------------------------------------------
def test_pin_has_teeth_fstring_key_flagged():
    bad = ast.parse('sk = f"ACCOUNT_{account_id}_IMAP_PASSWORD"\n')
    assert _secret_key_literals(bad)


def test_pin_has_teeth_format_template_flagged():
    bad = ast.parse('T = "ACCOUNT_{account_id}_O365_SECRET"\n')
    assert _secret_key_literals(bad)


def test_pin_has_teeth_percent_format_flagged():
    """DA run15 #7 — a %-format key build is caught."""
    bad = ast.parse('sk = "ACCOUNT_%d_O365_SECRET" % account_id\n')
    assert _secret_key_literals(bad)


def test_pin_has_teeth_concat_flagged():
    """DA run15 #7 — a string-concat key build is caught (and only the full
    chain flags, not the prefix-only inner BinOp)."""
    bad = ast.parse('sk = "ACCOUNT_" + str(account_id) + "_IMAP_PASSWORD"\n')
    assert _secret_key_literals(bad)
    # The bare prefix concat (no credential suffix) is NOT a key.
    ok = ast.parse('p = "ACCOUNT_" + str(account_id) + "_"\n')
    assert not _secret_key_literals(ok)


def test_pin_has_teeth_like_prefix_not_flagged():
    """The account-purge LIKE-prefix has no credential suffix → not a key."""
    ok = ast.parse('prefix = f"ACCOUNT_{int(account_id)}_"\n')
    assert not _secret_key_literals(ok)


def test_pin_has_teeth_docstring_prose_not_flagged():
    """A docstring listing the key shapes starts with prose, not ACCOUNT_."""
    ok = ast.parse(
        'def f():\n'
        '    """Purges:\n'
        '       * ``ACCOUNT_{id}_IMAP_PASSWORD``\n'
        '       * ``ACCOUNT_{id}_O365_SECRET``\n'
        '    """\n'
        '    return None\n'
    )
    assert not _secret_key_literals(ok)
