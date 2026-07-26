"""Session-epoch-on-credential-revoke SSOT pin (divergence census run12 #2).

VERIFIED-REAL finding (verify-don't-accept at HEAD): ``session_epoch`` is the
live session-revocation mechanism — ``web/auth.py`` stamps the user's epoch into
the session token and the user-loader rejects any cookie stamped with a stale
epoch. ``set_user_disabled`` already bumps it inline, but the two
*credential-revoke* writers (``revoke_hardware_key`` / ``revoke_dev_key``) set
``revoked_at`` WITHOUT bumping the epoch — so a session that authenticated via a
now-revoked (possibly compromised) passkey/dev-key stayed ALIVE until expiry.
Revoking a credential must CUT the live session, not merely block the next login
(§164.308(a)(5)(ii)(C) — access management / response to a compromise).

Count-agnostic structural property (PD#1/#3 — the SSOT writer emits the coupled
effect so no caller can forget): ANY function that writes ``revoked_at`` on
``hardware_keys`` / ``dev_keys`` must, in the SAME function body, bump
``session_epoch`` (an inline ``UPDATE users SET session_epoch = session_epoch +
1`` or a call to the ``bump_session_epoch`` SSOT). A new revoke path that drops
the bump turns this RED. Keyed on the write SEAM (the SQL), not on a count.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import iter_src_files, parse_module, relpath

# A single SQL string literal that revokes a credential row: ``UPDATE
# <hardware_keys|dev_keys> SET ... revoked_at``. Both writers put the table +
# ``revoked_at`` in one literal, so a per-literal match is sufficient and
# precise (no cross-literal bleed).
_REVOKE_WRITE = re.compile(
    r"UPDATE\s+(?:hardware_keys|dev_keys)\s+SET\b[^\"';]*revoked_at", re.IGNORECASE
)
# The epoch bump: the inline UPDATE (what both writers + set_user_disabled use)
# OR a literal naming the column assignment.
_EPOCH_BUMP = re.compile(
    r"UPDATE\s+users\s+SET\s+session_epoch|session_epoch\s*=\s*session_epoch\s*\+\s*1",
    re.IGNORECASE,
)


def _string_consts(node: ast.AST) -> list[str]:
    return [
        n.value
        for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def _call_names(node: ast.AST) -> set[str]:
    """Every called function name (Name.id or Attribute.attr) in the subtree."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def _calls_bump(node: ast.AST) -> bool:
    """True if the function calls the ``bump_session_epoch`` SSOT (Name or attr)."""
    return "bump_session_epoch" in _call_names(node)


# A call to either credential-revoke WRITER, by its own name or the common
# ``db_`` import alias (``revoke_dev_key as db_revoke_dev_key``).
_REVOKE_CALL = re.compile(r"^(?:db_)?revoke_(?:dev_key|hardware_key)$")


def _offenders(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        blob = "\n".join(_string_consts(fn))
        if not _REVOKE_WRITE.search(blob):
            continue
        if _EPOCH_BUMP.search(blob) or _calls_bump(fn):
            continue
        out.append(fn.name)
    return out


def test_credential_revoke_bumps_session_epoch():
    offenders = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        bad = _offenders(tree)
        if bad:
            offenders.append(f"{relpath(p)}: {bad}")
    assert not offenders, (
        "A function revokes a credential (UPDATE hardware_keys/dev_keys SET "
        f"revoked_at) WITHOUT bumping session_epoch in the same body: {offenders}. "
        "A revoked credential whose live session survives is a session-fixation "
        "gap(5)(ii)(C)). Bump session_epoch on the same edge "
        "— inline `UPDATE users SET session_epoch = session_epoch + 1` (the owner "
        "for hardware_keys, every allowlisted email for dev_keys) or call "
        "db.audit.bump_session_epoch — so revoking the credential cuts the session."
    )


def test_pin_has_teeth():
    bad = (
        "def f(c):\n"
        '    c.execute("UPDATE hardware_keys SET revoked_at = ? WHERE id = ?")\n'
    )
    assert _offenders(ast.parse(bad)) == ["f"], "missed an un-bumped revoke"
    bad_dev = (
        "def d(c):\n"
        '    c.execute("UPDATE dev_keys SET revoked_at = ?, revoked_by_user_id = ? WHERE id = ?")\n'
    )
    assert _offenders(ast.parse(bad_dev)) == ["d"]
    good_inline = (
        "def g(c):\n"
        '    c.execute("UPDATE hardware_keys SET revoked_at = ? WHERE id = ?")\n'
        '    c.execute("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = 1")\n'
    )
    assert _offenders(ast.parse(good_inline)) == [], "false-positived a bumped revoke"
    good_call = (
        "def h(c, u):\n"
        '    c.execute("UPDATE dev_keys SET revoked_at = ? WHERE id = ?")\n'
        "    bump_session_epoch(c, u)\n"
    )
    assert _offenders(ast.parse(good_call)) == []
    unrelated = (
        "def k(c):\n"
        '    c.execute("UPDATE users SET last_login = ? WHERE id = ?")\n'
    )
    assert _offenders(ast.parse(unrelated)) == [], "flagged a non-revoke write"


# ---------------------------------------------------------------------------
# Audit-emit half (N-121 / hipaa-sme MUST-FIX): credential revocation is an
# access-termination event (§164.312(b)+(c)(1)) — it must ride the HMAC audit
# chain via record_auth_event, not just a structured log. Inverse coupling:
# any function (handler/closure) that CALLS a credential-revoke writer must
# also call record_auth_event in the same body. (The writers themselves stay
# audit-free — the emit is route-level where the actor/IP context lives, the
# established record_auth_event pattern in auth_keys.py.)
# ---------------------------------------------------------------------------


def _audit_offenders(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = _call_names(fn)
        if not any(_REVOKE_CALL.match(n) for n in names):
            continue
        if "record_auth_event" in names:
            continue
        out.append(fn.name)
    return out


def test_credential_revoke_call_sites_emit_audit_event():
    offenders = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        bad = _audit_offenders(tree)
        if bad:
            offenders.append(f"{relpath(p)}: {bad}")
    assert not offenders, (
        "A handler calls a credential-revoke writer (revoke_dev_key / "
        f"revoke_hardware_key) WITHOUT emitting record_auth_event: {offenders}. "
        "Credential revocation is a §164.312(b)+(c)(1) access-termination event "
        "and must be written to the tamper-evident HMAC audit chain (N-121), not "
        "only log.info — mirror the existing auth_keys.py record_auth_event calls."
    )


def test_audit_pin_has_teeth():
    bad = (
        "def route(db, key_id):\n"
        "    db_revoke_dev_key(db, key_id, 1)\n"
    )
    assert _audit_offenders(ast.parse(bad)) == ["route"], "missed an un-audited revoke"
    bad_hw = (
        "def route(db, k):\n"
        "    revoke_hardware_key(db, k)\n"
    )
    assert _audit_offenders(ast.parse(bad_hw)) == ["route"]
    good = (
        "def route(db, key_id, actor):\n"
        "    db_revoke_dev_key(db, key_id, actor['id'])\n"
        "    record_auth_event(db, event_type='dev_key_revoked', email='a')\n"
    )
    assert _audit_offenders(ast.parse(good)) == [], "false-positived an audited revoke"
    unrelated = (
        "def route(db, k):\n"
        "    mark_dev_key_used(db, k)\n"
    )
    assert _audit_offenders(ast.parse(unrelated)) == [], "flagged a non-revoke call"
