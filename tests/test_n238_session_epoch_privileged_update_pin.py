"""N-238 R24 structural pin — session_epoch bump on privileged UPDATE users (2026-07-03).

Census R24 discovered HIGH class (HIPAA §164.312(a)(2)(iii) live drift):
`web/routers/ui/users.py::_update_user_snapshot` fired
`UPDATE users SET email = ?, name = ?, role = ?, notify_email = ? WHERE
id = ?` — a role change WITHOUT bumping `session_epoch`. A demoted admin
kept their live cookie authority until they logged out — §164.312(a)(2)
(iii) automatic-logoff drift.

N-238 fix:
  - `web/routers/ui/users.py:618/623` — both branches now include
    `session_epoch = session_epoch + 1` in the same UPDATE.

WHAT IT PINS (count-agnostic, STRICT):

Every SQL statement that matches `UPDATE users SET ...` and mentions one
of the privileged columns (`role`, `email`, `disabled`) MUST also mention
`session_epoch` in the same SET clause. `disabled` alone is legit only in
the disable-side branch of the audit-log flip (which already bumps
session_epoch inline); the enable-side stays exempt (a re-enable
doesn't need to bump since the disable already did).

SCOPE CAVEAT: matches SQL text via regex, so a query built up via
concatenation across variables would sneak past. At HEAD every UPDATE
statement is a single string constant + f-string param placeholders.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import (
    SRC_ROOT,
    iter_files,
    parse_module,
    relpath,
)


# UPDATE users SET [...] — case-insensitive, capture the SET body.
_UPDATE_USERS_RE = re.compile(
    r"UPDATE\s+users\s+SET\s+([^;]+?)\s+WHERE",
    re.IGNORECASE | re.DOTALL,
)

# Privileged columns that mutate the actor's authorization surface.
_PRIVILEGED_COLS = ("role", "email", "disabled")

# Allow-list: sites that mutate a privileged column but LEGITIMATELY do
# not need to bump session_epoch. Keyed on (relpath, matched_column).
_ALLOW = frozenset({
    # `db/audit.py::_disable_or_enable_user` disable branch bumps
    # inline; enable branch doesn't need to (re-enable of a previously
    # disabled user — the disable's bump already killed the pre-disable
    # sessions, so a fresh login is required regardless).
    ("db/audit.py", "disabled"),
})


def _sql_string_constants(tree: ast.AST) -> list[tuple[int, str]]:
    """Return (lineno, sql_text) for every string constant + JoinedStr
    that looks like a SQL statement (contains UPDATE users SET)."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if "UPDATE" in node.value.upper() and "users" in node.value.lower():
                out.append((node.lineno, node.value))
        elif isinstance(node, ast.JoinedStr):
            text = "".join(
                v.value for v in node.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            if "UPDATE" in text.upper() and "users" in text.lower():
                out.append((node.lineno, text))
    return out


def _adjacent_string_constants(tree: ast.AST) -> list[tuple[int, str]]:
    """Some sites split the UPDATE across two adjacent Constant strings
    (`"UPDATE users SET foo = ?, " "session_epoch = ..." "..."`). Python
    concatenates these implicitly. Walk parent BinOp/Adjacent nodes."""
    # Simpler heuristic: concatenate all string constants in the same
    # `ast.Call` args to catch the `conn.execute("UPDATE ...", (...))`
    # multi-string pattern.
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for arg in node.args:
            if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                continue
            v = arg.value
            if "UPDATE" in v.upper() and "users" in v.lower():
                out.append((arg.lineno, v))
    return out


def test_privileged_update_users_bumps_session_epoch():
    """STRICT: every `UPDATE users SET <priv-col>` must also SET
    `session_epoch`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno, sql in _sql_string_constants(tree):
            m = _UPDATE_USERS_RE.search(sql)
            if m is None:
                continue
            set_body = m.group(1).lower()
            touched_priv = [
                c for c in _PRIVILEGED_COLS
                if re.search(rf"\b{c}\s*=", set_body)
            ]
            if not touched_priv:
                continue
            bumps_epoch = bool(
                re.search(r"\bsession_epoch\s*=", set_body)
            )
            if bumps_epoch:
                continue
            # Allow-list check keyed on each touched column.
            not_allowed = [c for c in touched_priv if (rel, c) not in _ALLOW]
            if not_allowed:
                offenders.append(
                    f"{rel}:{lineno} — UPDATE users SET touches "
                    f"{'+'.join(not_allowed)} without bumping session_epoch"
                )
    assert not offenders, (
        "N-238 R24 §164.312(a)(2)(iii): `UPDATE users SET` touching "
        "`role`/`email`/`disabled` MUST also SET `session_epoch = "
        "session_epoch + 1` in the same statement — otherwise a demoted "
        "admin keeps live cookie authority until logout. If a specific "
        "site legitimately doesn't need to bump (rare — the disable/enable "
        "audit path is one), add it to `_ALLOW` with a comment.\n\n"
        + "\n".join(offenders)
    )


def test_dynamic_update_users_bumps_session_epoch_when_role_touched():
    """N-250 R25 widening (post-run25): a HANDLER that dynamically builds
    an `UPDATE users SET {...}` clause via an f-string / join AND appends
    a `role = ?` (or `email = ?` / `disabled = ?`) column MUST route the
    session_epoch bump through the same handler.

    The N-238 pin above reads Constant strings + regex-parses the SET
    body. A dynamic clause like
    `f"UPDATE users SET {', '.join(updates)} WHERE id = ?"` — where
    `updates.append("role = ?")` — has an EMPTY constant body, so the
    N-238 regex sees no privileged column and misses the site (which is
    exactly what happened at `web/routers/api.py:345` per run25 census).

    This second test walks every FunctionDef and asserts: if the
    function body contains a Constant `"role = ?"` (or similar
    privileged-column-fragment) AND a `UPDATE users SET` string, it MUST
    also textually contain `session_epoch` (either inline in the SET
    body or via a bump call)."""
    offenders: list[str] = []
    # Fn-name allow-list: not-a-privileged-mutation handlers whose
    # `email = ?` (or similar) fragment is either a WHERE-clause
    # identifier (auth.py's last-login stamp) or a self-service profile
    # save (user editing own notify_email — not their login email/role).
    _FN_ALLOW = {
        "profile_save",        # self-service notify_email update.
        "_profile_save_writes",  # helper for the above.
    }
    priv_fragments = [f"{c} = ?" for c in _PRIVILEGED_COLS]
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if fn.name in _FN_ALLOW:
                continue
            # Collect all Constant strings in the fn body.
            consts: list[str] = []
            for n in ast.walk(fn):
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    consts.append(n.value)
            has_update_users = any(
                "UPDATE users" in s.upper() or "UPDATE\nusers" in s.upper()
                or ("UPDATE" in s.upper() and "users" in s.lower())
                for s in consts
            )
            if not has_update_users:
                continue
            # A fragment after WHERE is an identifier, not a SET target
            # (2026-11-06, N-520 step 2: `update_last_login_txn`'s
            # `WHERE email = ?` tripped this; precision fix, not allow-list
            # growth). Only the text before the first WHERE counts.
            set_side = [
                re.split(r"\bWHERE\b", s, maxsplit=1, flags=re.IGNORECASE)[0]
                for s in consts
            ]
            touched_priv_frags = [
                f for f in priv_fragments
                if any(f in s for s in set_side)
            ]
            if not touched_priv_frags:
                continue
            # Concatenate ALL text (Constants only) for the epoch check.
            body_text = " ".join(consts).lower()
            if "session_epoch" in body_text:
                continue
            # Also check calls to `bump_session_epoch` (SSOT).
            calls_bump = any(
                (isinstance(c.func, ast.Name) and c.func.id == "bump_session_epoch")
                or (isinstance(c.func, ast.Attribute) and c.func.attr == "bump_session_epoch")
                for c in ast.walk(fn)
                if isinstance(c, ast.Call)
            )
            if calls_bump:
                continue
            offenders.append(
                f"{rel}:{fn.lineno} in `{fn.name}` — dynamic `UPDATE users "
                f"SET` handler touches {'+'.join(touched_priv_frags)} "
                "without session_epoch bump / bump_session_epoch call"
            )
    assert not offenders, (
        "N-250 R25 §164.312(a)(2)(iii) — dynamic UPDATE users handler "
        "gap: a handler that builds `UPDATE users SET {...}` via f-string "
        "AND appends a privileged column (`role = ?` / `email = ?` / "
        "`disabled = ?`) MUST bump `session_epoch`. Add "
        "`updates.append(\"session_epoch = session_epoch + 1\")` on the "
        "privileged-change branch, or call `bump_session_epoch` in the "
        "same fn.\n\n"
        + "\n".join(offenders)
    )
