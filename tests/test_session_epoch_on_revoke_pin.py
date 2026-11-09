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

from _pin_harness import (
    docstring_constant_ids,
    emergency_sanctioned_handlers,
    emergency_sanctioned_lines,
    iter_src_files,
    iter_string_literals,
    parse_module,
    relpath,
)

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
        "gap (#205 / §164.308(a)(5)(ii)(C)). Bump session_epoch on the same edge "
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


# ---------------------------------------------------------------------------
# Grant half (punch , widened by punch 627 / N-611 and by punch 668): every
# INSERT-created CREDENTIAL or USER grant is audited at GRANT, not only at
# teardown. A grant made by UPDATE is NOT covered (see SCOPE CAVEAT). THE SET OF
# GRANT TABLES IS DISCOVERED, NOT LISTED (punch 668 / hipaa-sme R1b: the old
# hardcoded 3-tuple could not see ``operator_recovery_keys``). The schema DDL
# literals in src name a CREDENTIAL table by the credential-material column it
# declares (``_CREDENTIAL_COLUMN``), and the USER table is whatever a credential
# table's ``*user_id`` column REFERENCES (``_discover_grant_tables``). Every
# discovered table is then classified exactly once, in ``_GRANT_EVENTS`` (its
# grant event + emitter: INTENT, because the witness sits in another function
# than the INSERT or does not exist yet) or ``_NOT_A_GRANT`` (a reason). A new
# credential table with no entry turns the pin RED, and so does an entry whose
# table no DDL declares (stale). A credential grant is an access-granting event
# (§164.312(b); §164.308(a)(4)) and must ride an HMAC chain as its class's grant
# event on BOTH edges -- the success terminus and the refused-grant branch (the
# admin UV policy of punch  refuses enrolments, a duplicate dev-key
# fingerprint refuses a grant, and a refusal must leave a tamper-evident row).
# Hardware and dev keys emit ``record_auth_event(event_type=...)``; API keys emit
# on their own lifecycle chain, ``record_api_key_event(event="api_key_created")``.
# The writers of a class are its named ``*_txn``/own-commit pair PLUS every src
# function holding an ``INSERT INTO <table>`` literal for its table, discovered
# by the scan, so a new raw grant path is in scope without editing the table.
#
# Count-agnostic, interprocedural (PD-1/PD-2). The writers (``add_hardware_key``
# and its ``*_txn`` sibling) carry no actor/IP context, and the value hops
# writer -> grant funnel (``db.audit.record_hardware_key_registration``) ->
# helper (``webauthn_auth.finish_registration``) -> off-loop closure (passed by
# NAME to ``db_call``) -> route. A "grant emit" is a ``record_auth_event`` /
# ``record_auth_event_txn`` call whose ``event_type`` is the literal
# ``hardware_key_registered``. Two fixpoints over every src function:
#   G (unaudited) := writers; a function that REFERENCES a name in G (a call,
#     or a bare name passed as an argument, e.g. ``db_call(_finish_reg, db)``)
#     and does NOT itself grant-emit joins G as a pass-through.
#   R (reachers)  := writers; ANY function referencing a name in R joins R
#     (emitting or not -- the refused edge sits above the emitting funnel).
# Property 1 (success edge): every pass-through in G must be referenced from
#   somewhere in src -- a G member that nothing references is an entry point
#   (a route/CLI) that grants a credential without the audit row.
# Property 2 (refused edge): every ``try`` whose body references R has, in each
#   handler that does not re-raise, its own grant-event emit.
# Property 0 (writer witness, punch 668): every src function that itself holds an
#   ``INSERT INTO <table>`` literal for a grant table must emit that table's grant
#   event in its OWN body, unless it is a named seed (the audit-free ``*_txn``
#   pair under an emitting funnel). Property 1 reads the REFERENCE graph, and a
#   CLI command is wired by a dispatch dict (``cli.py`` ``"user": cmd_user``) that
#   the old flat reference set counted as a caller, so ``cmd_user`` -- a direct
#   ``INSERT INTO users`` -- read as "referenced, therefore not an entry point".
#   Property 0 is keyed on the SEAM THE ROW IS WRITTEN AT, so no reference
#   topology can hide it; and a dict value / ``func=`` keyword no longer counts
#   as a caller in Property 1 either (``_dispatch_ids``).
# Property 0 also carries an ORDERING clause (punch 668, panel R): a writer that
# emits its grant event must not ``.commit()`` after the INSERT before that emit
# on its own fall-through path (a preceding sibling statement of the commit, or of
# an enclosing block). Only an UNCONDITIONAL SUCCESS emit counts: an emit inside an
# ``except`` handler, an ``if`` / ``for`` / ``while`` / ``match`` arm or after a
# short-circuit does not, nor does one whose ``outcome`` is not ``success`` (that
# witnesses a REFUSAL; the refused arm's own commit is judged against its own denied
# row). The N-520 ratchet (test_n520_commit_before_witness_ratchet_pin.py)
# does NOT keep that atomic for ``record_user_creation``: it counts an
# ``@audit_emitter`` funnel as the witness and does not police an inline commit
# inside one (measured, DA mutation M1: a ``conn.commit()`` between the users
# INSERT and the witness left both this pin and N-520 green). It does hold the two
# ``web/mfa.py`` writers (mutations M2/M3 turn it red). Atomicity of the user
# funnel is therefore pinned HERE (ordering clause) and at runtime
# (tests/test_web/test_punch668_grant_witness.py). This pin keeps the emit
# PRESENT and FIRST; it does NOT prove the emit is bound to the NEW row's id --
# that is a runtime test.
#
# SCOPE CAVEAT: INSERT-keyed. A grant made by UPDATE or ended by DELETE is covered
# by the UPDATE and REVOKE arms at the end of this file (punch 674 / 673), not by
# Properties 0-2. A credential column
# whose name misses ``_CREDENTIAL_COLUMN`` (e.g. a future ``totp_secret``) is not
# discovered. The ordering clause reads direct ``.commit()`` calls only: a commit
# by ``with conn:``, by a committing helper (``_commit(conn)``) or by
# ``execute('COMMIT')`` inside a grant writer that is itself a witness is covered by
# NEITHER this pin NOR the N-520 ratchet (N-520 excludes a witness's OWN body:
# test_n520_commit_before_witness_ratchet_pin.py, "A witness function's OWN body is
# out of scope"). For those shapes the writer's runtime fail-closed test
# (tests/test_web/test_punch668_grant_witness.py) is the ONLY control. The clause
# also orders by line number against the first INSERT, so a commit at the top of a
# loop that holds the INSERT (the 2nd iteration) is not seen (DA probe F).
#
# SCOPE CAVEAT (names): name-keyed (Name.id / Attribute.attr). An ``import ... as``
# alias IS followed (punch 627: the N-611 route granted via ``add_dev_key as
# db_add_dev_key``); a plain assignment rebinding a grant function, or a
# callable smuggled through a dict / list, is not; Property 1 sees an emit ANYWHERE in the function (it
# cannot prove the emit is on the success path -- the route test
# tests/test_web/test_punch525_hw_register_audit.py is what pins both edges at
# runtime). A nested def is scanned both on its own and inside its parent.
# ---------------------------------------------------------------------------

_AUTH_EMITTERS = frozenset({"record_auth_event", "record_auth_event_txn"})
_API_KEY_EMITTERS = frozenset({"record_api_key_event", "record_api_key_event_txn"})

# table -> (grant event, emitters, the keyword naming the event, named writers).
# The INTENT list: what witnesses a discovered table's grant cannot be DERIVED
# (the hardware/dev witness is emitted by a funnel, not by the function holding
# the INSERT). Named writers are the audit-free seeds under an emitting funnel
# (Properties 0 and 1 skip them); the punch 668 classes have none, because the
# function that holds each INSERT emits its own witness
# (``db.audit.record_user_creation``, ``web.mfa.issue_operator_recovery_token`` /
# ``issue_recovery_codes``).
#
# Punch 668: ``user_created``, ``operator_recovery_key_issued`` and
# ``recovery_codes_issued`` are the names the lead accepted (2026-10-23), emitted
# through ``record_auth_event_txn(event_type=...)``. There is no event-type
# registry in src (``auth_events.event_type`` is free TEXT); a funnel's only
# registration is its ``_AUDIT_EMITTER_REDACTION_MAP`` entry, so this map plus
# Property 0 is what pins the names.
_GRANT_EVENTS = {
    "hardware_keys": ("hardware_key_registered", _AUTH_EMITTERS, "event_type",
                      frozenset({"add_hardware_key", "add_hardware_key_txn"})),
    "dev_keys": ("dev_key_registered", _AUTH_EMITTERS, "event_type",
                 frozenset({"add_dev_key", "add_dev_key_txn"})),
    "api_keys": ("api_key_created", _API_KEY_EMITTERS, "event", frozenset()),
    "users": ("user_created", _AUTH_EMITTERS, "event_type", frozenset()),
    "operator_recovery_keys": ("operator_recovery_key_issued", _AUTH_EMITTERS,
                               "event_type", frozenset()),
    "recovery_codes": ("recovery_codes_issued", _AUTH_EMITTERS, "event_type",
                       frozenset()),
    # Punch 673: an ACCESS grant (who may act on whose mailbox), discovered by
    # ``_discover_access_link_tables``; written by
    # ``db.audit.record_account_delegate_grant``.
    "account_delegates": ("account_delegate_granted", _AUTH_EMITTERS,
                          "event_type", frozenset()),
}

# Discovered credential tables that are NOT a standing grant to a principal, each
# with the reason its grant event cannot be derived. Staleness-checked both ways.
_NOT_A_GRANT = {
    "otp_codes": (
        "a login challenge, not a standing credential: a short-TTL one-time code "
        "emailed at sign-in; its use is audited as the login_otp auth event"),
    "secrets_store": (
        "the app's config-secret key/value store (DbSecrets); writes go through a "
        "dynamic table name (secrets.py) and the never-clobber _secret_write SSOT, "
        "pinned by test_no_unguarded_secret_write -- a stored secret grants no "
        "principal access"),
    # Punch 673: user-to-row LINK tables (``_discover_access_link_tables``) whose
    # user column is an ACTOR or a subject of record, not a grantee.
    "access_log": (
        "the ASGI access-audit trail: actor_user_id is who made the request; "
        "it records access, it grants none"),
    "discover_runs": (
        "a discovery-job run record: actor_user_id started the run"),
    "hipaa_access_events": (
        "the chained HIPAA access-event audit table: actor_user_id is the "
        "reader of record; it records PHI access, it grants none"),
    "message_labels": (
        "a label applied to a message: applied_by_actor is who applied it"),
    "regulatory_clock_event": (
        "a breach-clock event row: actor_user_id is who acted on the clock"),
    "regulatory_clock_instance": (
        "a breach-notification clock: acked_by / submitted_by are the users "
        "who acknowledged / submitted it"),
    "style_distill_events": (
        "a style-distillation run record: actor_user_id started the run"),
    "triage_runs": (
        "a triage run record: actor_user_id triggered the run"),
}


def _grant_class(table: str):
    """``(table, event, emitters, kwname, named writers)`` for one grant table."""
    event, emitters, kwname, named = _GRANT_EVENTS[table]
    return (table, event, emitters, kwname, named)


_HW = _grant_class("hardware_keys")

# --- discovery: which tables are credential / user tables ---------------------

_CREATE_TABLE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(", re.I)
_SQL_COMMENT = re.compile(r"--[^\n]*")
_TABLE_CONSTRAINT = re.compile(r"^(?:UNIQUE|PRIMARY|FOREIGN|CHECK|CONSTRAINT)\b", re.I)
_REFERENCES = re.compile(r"\bREFERENCES\s+(\w+)", re.I)
# Credential MATERIAL, tight on purpose: ``log_entries.prev_hash``, the dedup
# digest ``triaged_messages.msg_id_hash`` and ``auth_events.key_id`` are not it.
_CREDENTIAL_COLUMN = re.compile(
    r"^(?:(?:key|token|code|secret|password)_hash|public_key|credential_id|ciphertext)$",
    re.I,
)
_USER_FK_COLUMN = re.compile(r"^(?:\w+_)?user_id$", re.I)


def _split_top_level(body: str) -> list[str]:
    out: list[str] = []
    depth, cur = 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return [s.strip() for s in out if s.strip()]


def _ddl_tables(trees, *, constraints: bool = False) -> dict[str, list[tuple[str, str]]]:
    """``{table: [(column, rest of its definition)]}`` from every ``CREATE TABLE``
    literal in src (comments stripped, table constraints skipped, or kept as
    ``(keyword, rest)`` with ``constraints=True``)."""
    tables: dict[str, list[tuple[str, str]]] = {}
    for tree in trees:
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Constant) and isinstance(n.value, str)):
                continue
            if "CREATE" not in n.value.upper():
                continue
            text = _SQL_COMMENT.sub("", n.value)
            for m in _CREATE_TABLE.finditer(text):
                depth, i = 1, m.end()
                while i < len(text) and depth:
                    depth += (text[i] == "(") - (text[i] == ")")
                    i += 1
                cols = tables.setdefault(m.group(1), [])
                for item in _split_top_level(text[m.end():i - 1]):
                    if _TABLE_CONSTRAINT.match(item) and not constraints:
                        continue
                    parts = item.split(None, 1)
                    cols.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return tables


def _discover_grant_tables(trees) -> set[str]:
    """Credential tables (declare credential material) plus the user table(s)
    their ``*user_id`` columns reference."""
    tables = _ddl_tables(trees)
    credential = {t for t, cols in tables.items()
                  if any(_CREDENTIAL_COLUMN.match(c) for c, _ in cols)}
    users = {m.group(1) for t in credential for c, d in tables[t]
             if _USER_FK_COLUMN.match(c) for m in [_REFERENCES.search(d)] if m}
    return credential | users


def _discover_access_link_tables(trees) -> set[str]:
    """Punch 673: every table that LINKS a principal (a user table found by
    ``_discover_grant_tables``) to a row of another table: one column REFERENCES
    a user table and another REFERENCES a different table. That is the shape of an
    access grant (``account_delegates``: user -> account); most such tables are
    event records whose user column is an actor, so each one is CLASSIFIED (grant
    in ``_GRANT_EVENTS``, or a reason in ``_NOT_A_GRANT``) and a new link table
    turns the classification ratchet RED until someone decides which it is."""
    tables = _ddl_tables(trees)
    principals = _discover_grant_tables(trees) - {
        t for t, cols in tables.items()
        if any(_CREDENTIAL_COLUMN.match(c) for c, _ in cols)}
    out = set()
    for t, cols in tables.items():
        refs = {m.group(1) for _c, d in cols for m in [_REFERENCES.search(d)] if m}
        if refs & principals and refs - principals - {t}:
            out.add(t)
    return out


def _discover_classified(trees) -> set[str]:
    """Every table the grant pin must classify: credential + user tables and the
    access-link tables."""
    return _discover_grant_tables(trees) | _discover_access_link_tables(trees)


_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SQL_NODES = (ast.Constant, ast.JoinedStr, ast.BinOp)
# ``INSERT [OR x] INTO`` / ``REPLACE INTO``, optionally schema- or quote-wrapped.
_INSERT_INTO = r"(?:INSERT\s+(?:OR\s+\w+\s+)?|REPLACE\s+)INTO\s+(?:main\.)?[\"`\[]?"


def _insert_rx(table: str) -> re.Pattern:
    return re.compile(rf"{_INSERT_INTO}{table}\b", re.I)


def _holds_insert(node: ast.AST, rx: re.Pattern) -> bool:
    """``node`` is (or contains) a SQL string that matches ``rx``. Uses the
    harness ``iter_string_literals`` so a ``"INSERT INTO " + "users"`` split and
    an f-string are read as the string they build (PD-6: one string reader)."""
    return any(rx.search(s) for s in iter_string_literals(node))


def _own_walk(fn: ast.AST):
    """Every node of ``fn`` WITHOUT descending into a nested def / lambda, so a
    literal is attributed to its innermost owner."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, (*_FUNCS, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(n))


def _insert_writers(trees, table: str) -> set[str]:
    """Every src function holding an ``INSERT INTO <table>`` string literal."""
    rx = _insert_rx(table)
    return {
        fn.name for tree in trees for fn in ast.walk(tree)
        if isinstance(fn, _FUNCS) and _holds_insert(fn, rx)
    }


def _refs(node: ast.AST) -> set[str]:
    """Every name the subtree calls OR passes by name (PD-2: ``db_call(h, db)``)."""
    out = _call_names(node)
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            for a in n.args:
                if isinstance(a, ast.Name):
                    out.add(a.id)
                elif isinstance(a, ast.Attribute):
                    out.add(a.attr)
    return out


def _is_grant_emit(call: ast.AST, cls) -> bool:
    """``call`` is the class's emitter called with the grant event literal."""
    _table, event, emitters, kwname, _named = cls
    if not isinstance(call, ast.Call):
        return False
    f = call.func
    name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
    if name not in emitters:
        return False
    return any(kw.arg == kwname and isinstance(kw.value, ast.Constant)
               and kw.value.value == event for kw in call.keywords)


def _emits_grant(node: ast.AST, cls=_HW, *, own: bool = False) -> bool:
    """``node`` calls the class's emitter with the grant event literal. ``own``
    reads the node's own body only (not a nested def's), for Property 0."""
    return any(_is_grant_emit(n, cls)
               for n in (_own_walk(node) if own else ast.walk(node)))


def _dispatch_ids(tree: ast.AST) -> set[int]:
    """``id()`` of every Name / Attribute in a DISPATCH position: a dict VALUE
    (``{"user": cmd_user}``) or the ``func=`` keyword (argparse
    ``set_defaults(func=cmd)``). That wires a function to its caller-less entry
    (a CLI command, a table-driven handler); it is not a caller that audits."""
    out: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            out.update(id(v) for v in n.values
                       if isinstance(v, (ast.Name, ast.Attribute)))
        elif isinstance(n, ast.Call):
            out.update(id(kw.value) for kw in n.keywords
                       if kw.arg == "func" and isinstance(kw.value, (ast.Name, ast.Attribute)))
    return out


def _all_referenced(trees) -> set[str]:
    out: set[str] = set()
    for tree in trees:
        wiring = _dispatch_ids(tree)
        for n in ast.walk(tree):
            if id(n) in wiring:
                continue
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                out.add(n.id)
            elif isinstance(n, ast.Attribute):
                out.add(n.attr)
    return out


def _closure(trees, cls=_HW, *, stop_at_emit: bool) -> set[str]:
    fns = [
        fn for tree in trees for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    found = _insert_writers(trees, cls[0])
    if stop_at_emit:
        # A discovered writer that witnesses its own insert (``store_api_key``)
        # is a funnel, not an unaudited seed.
        found = {n for n in found if not any(
            fn.name == n and _emits_grant(fn, cls) for fn in fns)}
    g = set(cls[4]) | found
    # ``from x import add_dev_key as db_add_dev_key``: the alias is the writer.
    # The N-611 route granted through exactly this alias, so a name-only scan
    # passed on the pre-fix tree (measured, punch 627).
    aliases = [
        (a.name, a.asname) for tree in trees for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) for a in n.names if a.asname
    ]
    changed = True
    while changed:
        changed = False
        for name, asname in aliases:
            if name in g and asname not in g:
                g.add(asname)
                changed = True
        for fn in fns:
            if fn.name in g or (stop_at_emit and _emits_grant(fn, cls)):
                continue
            if _refs(fn) & g:
                g.add(fn.name)
                changed = True
    return g


def _reraises(handler: ast.ExceptHandler) -> bool:
    return any(isinstance(n, ast.Raise) for n in ast.walk(handler))


def _grant_offenders(trees, cls=_HW) -> list[str]:
    trees = list(trees)
    g = _closure(trees, cls, stop_at_emit=True)
    reach = _closure(trees, cls, stop_at_emit=False)
    referenced = _all_referenced(trees)
    defined = {fn.name for tree in trees for fn in ast.walk(tree)
               if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}
    out = sorted(f"unaudited grant entry point: {n}"
                 for n in g - cls[4] if n in defined and n not in referenced)
    for tree in trees:
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for t in ast.walk(fn):
                if not isinstance(t, ast.Try):
                    continue
                body_refs: set[str] = set()
                for stmt in t.body:
                    body_refs |= _refs(stmt)
                if not (body_refs & reach):
                    continue
                for h in t.handlers:
                    if not _reraises(h) and not _emits_grant(h, cls):
                        out.append(f"refused grant not audited: {fn.name}:{h.lineno}")
    return sorted(set(out))


def _src_modules():
    """``[(SRC_ROOT-relative path, tree)]`` for every parseable src module."""
    mods = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is not None:
            mods.append((relpath(p), tree))
    return mods


def _src_trees():
    return [tree for _rel, tree in _src_modules()]


def _live_classes(trees):
    """The grant classes the scan runs over: discovered AND classified as grants."""
    found = _discover_classified(trees)
    return [_grant_class(t) for t in sorted(found) if t in _GRANT_EVENTS]


def _def_sites(modules) -> dict[str, list[str]]:
    sites: dict[str, list[str]] = {}
    for rel, tree in modules:
        for fn in ast.walk(tree):
            if isinstance(fn, _FUNCS):
                sites.setdefault(fn.name, []).append(f"{rel}:{fn.lineno}")
    return sites


def _where(offender: str, sites: dict[str, list[str]]) -> str:
    """Append ``file:line`` of the offending function's def to an offender string."""
    name = offender.split(": ", 1)[1].rsplit(":", 1)[0] if ": " in offender else ""
    return f"{offender} [{', '.join(sites.get(name, []))}]" if name in sites else offender


# --- Property 0: the function that writes the row witnesses it ----------------


def _blocks_of(stmt: ast.AST) -> list[list[ast.stmt]]:
    """The statement lists one compound statement owns. Each is a fall-through
    block: a statement runs after its EARLIER SIBLINGS in the same block (and
    after the earlier siblings of every enclosing block)."""
    blocks = [v for f in ("body", "orelse", "finalbody")
              for v in [getattr(stmt, f, None)]
              if isinstance(v, list) and v and isinstance(v[0], ast.stmt)]
    blocks += [h.body for h in getattr(stmt, "handlers", None) or []]
    blocks += [c.body for c in getattr(stmt, "cases", None) or []]
    return blocks


_TRY_NODES = tuple(t for t in (ast.Try, getattr(ast, "TryStar", None)) if t)
# A compound statement whose body may run zero times, or only on one arm: an emit
# inside it is CONDITIONAL on the path (DA probes A and B).
_CONDITIONAL_STMTS = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Match)
# An expression that may skip part of itself: ``x and emit(..)``, ``emit(..) if x
# else y``, a comprehension, a lambda.
_CONDITIONAL_EXPRS = (ast.IfExp, ast.BoolOp, ast.Lambda, ast.ListComp, ast.SetComp,
                      ast.DictComp, ast.GeneratorExp)


def _is_success_emit(call: ast.AST, cls) -> bool:
    """A grant emit whose ``outcome`` keyword is absent (the emitter's default is
    ``success``) or the literal ``"success"``. A ``denied:...`` / ``failure`` emit
    witnesses a REFUSAL, not the grant (DA probe A: the refused edge's emit must not
    satisfy a later commit on the success path)."""
    if not _is_grant_emit(call, cls):
        return False
    return all(kw.value.value == "success" if isinstance(kw.value, ast.Constant) else False
               for kw in call.keywords if kw.arg == "outcome")


def _diverts(handler: ast.ExceptHandler) -> bool:
    """The handler never falls through to the statement after its ``try``: it ends
    in ``raise`` or ``return``. So reaching that statement proves the ``try`` body
    ran to its end (a handler that swallows, e.g. ``pass``, proves nothing)."""
    return bool(handler.body) and isinstance(handler.body[-1], (ast.Raise, ast.Return))


def _emits_on_fallthrough(stmt: ast.AST, cls, *, refused: bool = False, pred=None) -> bool:
    """``stmt`` holds a grant emit that runs UNCONDITIONALLY on the normal
    (no-exception) path past it (punch 668, panel R2 / DA SHOULD-2). It counts only
    when (i) its ``outcome`` is absent or ``"success"`` (``refused=True`` lifts this
    for the refused-edge branch's own commit, whose witness IS the denied row), and
    (ii) nothing on the way to it is conditional: a direct statement, a ``with``
    body, or a ``try`` body / ``else`` / ``finally`` whose handlers all end in
    ``raise`` / ``return``. An emit inside an ``if`` / ``for`` / ``while`` /
    ``match``, in a handler that falls through, after a short-circuit, or in a nested
    def does NOT count."""
    if isinstance(stmt, (*_FUNCS, ast.ClassDef, *_CONDITIONAL_STMTS)):
        return False
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return (any(_emits_in_expr(i, cls, refused, pred) for i in stmt.items)
                or any(_emits_on_fallthrough(s, cls, refused=refused, pred=pred)
                       for s in stmt.body))
    if isinstance(stmt, _TRY_NODES):
        blocks = [stmt.finalbody]
        if all(_diverts(h) for h in stmt.handlers):
            blocks += [stmt.body, stmt.orelse]
        return any(_emits_on_fallthrough(s, cls, refused=refused, pred=pred)
                   for blk in blocks for s in blk)
    return _emits_in_expr(stmt, cls, refused, pred)


def _emits_in_expr(node: ast.AST, cls, refused: bool, pred=None) -> bool:
    """A grant emit among ``node``'s own expressions, pruning a conditional
    expression, a comprehension and a nested def. ``pred(call)`` replaces the
    class's emit test when given (the UPDATE arm's per-column witness, punch 674)."""
    emit = (lambda n, _c: pred(n)) if pred else (
        _is_grant_emit if refused else _is_success_emit)
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, (*_FUNCS, *_CONDITIONAL_EXPRS)):
            continue
        if emit(n, cls):
            return True
        stack.extend(ast.iter_child_nodes(n))
    return False


def _branch_blocks(stmt: ast.AST) -> set[int]:
    """``id()`` of each statement list that runs on ONE arm only: an ``if`` / ``else``
    / ``match`` case body or an ``except`` handler body. A commit in one is the
    commit of that arm (the refused edge writes its own denied row, then commits)."""
    out: set[int] = set()
    if isinstance(stmt, ast.If):
        out.update(id(b) for b in (stmt.body, stmt.orelse) if b)
    elif isinstance(stmt, ast.Match):
        out.update(id(c.body) for c in stmt.cases)
    elif isinstance(stmt, _TRY_NODES):
        out.update(id(h.body) for h in stmt.handlers)
    return out


def _own_expr_commits(stmt: ast.AST) -> list[ast.Call]:
    """``.commit()`` calls in ``stmt``'s own expressions (not in a nested block)."""
    out, stack = [], [c for c in ast.iter_child_nodes(stmt)
                      if not isinstance(c, (ast.stmt, ast.ExceptHandler, ast.match_case))]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Lambda):
            continue
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "commit"):
            out.append(n)
        stack.extend(ast.iter_child_nodes(n))
    return out


def _commits_before_witness(fn: ast.AST, cls, first_insert: int) -> list[int]:
    """Line of every ``.commit()`` in ``fn``'s own body that FOLLOWS the grant
    INSERT without a grant emit on its fall-through path before it (punch 668,
    panel R: the N-520 ratchet counts an ``@audit_emitter`` funnel as the witness
    and does not police an inline commit inside it, so a commit between the
    INSERT and the witness left a committed grant with no chained row if the
    witness then failed). Ordering is by BLOCK, not by line number: the emit must
    be a preceding sibling of the commit's statement, or of an enclosing one, and
    it must be an unconditional success emit (``_emits_on_fallthrough``: a denied
    emit, an emit under ``if`` / ``for`` / ``while``, in a swallowing handler or
    after a short-circuit does not count). The one exception is a commit that sits
    IN an arm of its own (an ``except`` handler, an ``if`` / ``else`` / ``case``
    body): it is that arm's commit, so a preceding sibling emit of ANY outcome in
    THAT arm counts (the refused edge writes its denied row, then commits)."""
    out: list[int] = []

    def visit(block, chain, branch):
        for i, stmt in enumerate(block):
            if isinstance(stmt, (*_FUNCS, ast.ClassDef)):
                continue
            here = chain + [(block, i)]
            for c in _own_expr_commits(stmt):
                if c.lineno > first_insert and not any(
                        _emits_on_fallthrough(b[j], cls, refused=branch and b is block)
                        for b, k in here for j in range(k)):
                    out.append(c.lineno)
            arms = _branch_blocks(stmt)
            for sub in _blocks_of(stmt):
                visit(sub, here, id(sub) in arms)

    visit(fn.body, [], False)
    return sorted(set(out))


def _unwitnessed_writers(modules, cls) -> list[str]:
    """Every function whose OWN body holds an ``INSERT INTO <table>`` literal for
    this grant class and either does not emit the class's grant event itself
    (``unwitnessed grant writer``) or commits after the INSERT before that emit
    (``commit before witness``), unless it is a named seed. Reported as
    ``name (file:line of the INSERT / of the early commit)``."""
    table, named = cls[0], cls[4]
    rx = _insert_rx(table)
    out = []
    for rel, tree in modules:
        for fn in ast.walk(tree):
            if not isinstance(fn, _FUNCS) or fn.name in named:
                continue
            lits = [n for n in _own_walk(fn)
                    if isinstance(n, _SQL_NODES) and _holds_insert(n, rx)]
            if not lits:
                continue
            if not _emits_grant(fn, cls, own=True):
                lit = next(iter(lits))
                out.append(f"unwitnessed grant writer: {fn.name} ({rel}:{lit.lineno})")
                continue
            out.extend(
                f"commit before witness: {fn.name} ({rel}:{ln})"
                for ln in _commits_before_witness(fn, cls, min(n.lineno for n in lits)))
    return sorted(set(out))


def _stray_insert_literals(modules, tables) -> list[str]:
    """Grant-table INSERT SQL sitting OUTSIDE every function (a module- or
    class-level constant): no function owns it, so Property 0 cannot see it."""
    rxs = [_insert_rx(t) for t in sorted(tables)]
    out = []
    for rel, tree in modules:
        inside = {id(n) for fn in ast.walk(tree) if isinstance(fn, _FUNCS)
                  for n in ast.walk(fn)}
        docs = docstring_constant_ids(tree)
        for n in ast.walk(tree):
            if (id(n) in inside or id(n) in docs or not isinstance(n, _SQL_NODES)):
                continue
            if any(_holds_insert(n, rx) for rx in rxs):
                out.append(f"{rel}:{n.lineno}")
    return sorted(set(out))


# An INSERT whose table name is not a literal: ``INTO {table}`` (f-string slot),
# ``"INSERT INTO " + tbl``, ``INTO %s``. ``iter_string_literals`` leaves the slot
# empty, so the table position holds ``(`` or nothing.
_DYNAMIC_INTO = re.compile(
    r"(?:INSERT\s+(?:OR\s+\w+\s+)?|REPLACE\s+)INTO\s*(?:$|[({%?:])", re.I)


def _dynamic_insert_sites(modules) -> dict[tuple[str, str], int]:
    """``{(module, function): line}`` for every function whose own body builds an
    INSERT with a non-literal table name: the one shape the literal scan is blind to."""
    out: dict[tuple[str, str], int] = {}
    for rel, tree in modules:
        for fn in ast.walk(tree):
            if not isinstance(fn, _FUNCS):
                continue
            for n in _own_walk(fn):
                if (isinstance(n, _SQL_NODES)
                        and any(_DYNAMIC_INTO.search(s) for s in iter_string_literals(n))):
                    out.setdefault((rel, fn.name), n.lineno)
    return out


# (module, function) -> why a dynamic-table INSERT there is not a grant writer.
# Staleness-checked both ways: a new dynamic INSERT site, or an entry whose site
# vanished, turns ``test_every_dynamic_table_insert_is_accounted_for`` RED.
_DYNAMIC_INSERT_INTENT = {
    ("db/audit.py", "_chain_insert"): (
        "the table must be a key of _AUDIT_CHAIN_CANONICAL_FIELDS (ValueError "
        "otherwise): chained AUDIT tables only, disjoint from the grant tables"),
    ("secrets.py", "set"): "DbSecrets.set writes self._table, the secrets_store",
    ("secrets.py", "rotate_master_key"): (
        "DbSecrets key rotation writes the wrapped-history row into self._table, "
        "the secrets_store"),
}


def _classification_problems(found, grants, not_grants) -> list[str]:
    classified = set(grants) | set(not_grants)
    return (
        [f"unclassified credential table: {t}" for t in sorted(found - classified)]
        + [f"stale classification (no such credential table in the DDL): {t}"
           for t in sorted(classified - found)]
        + [f"classified as both a grant and not a grant: {t}"
           for t in sorted(set(grants) & set(not_grants))]
    )


def _dynamic_problems(seen, intent) -> list[str]:
    return (
        [f"unaccounted dynamic-table INSERT: {rel}::{fn}"
         for rel, fn in sorted(seen - set(intent))]
        + [f"stale _DYNAMIC_INSERT_INTENT entry (no such site): {rel}::{fn}"
           for rel, fn in sorted(set(intent) - seen)]
    )


def test_credential_grants_emit_audit_event_on_both_edges():
    modules = _src_modules()
    trees = [t for _rel, t in modules]
    sites = _def_sites(modules)
    offenders = [f"{cls[0]} / {cls[1]}: {_where(o, sites)}"
                 for cls in _live_classes(trees) for o in _grant_offenders(trees, cls)]
    assert not offenders, (
        "A credential- or user-GRANT path is not on the HMAC audit chain "
        f"(Properties 1+2): {offenders}. A grant is an access-granting event "
        "(§164.312(b); §164.308(a)(4)) -- write the grant row and its grant "
        "event in ONE transaction through the class funnel "
        "(record_hardware_key_registration / record_dev_key_registration / "
        "store_api_key), and emit the grant event with outcome 'denied:<slug>' "
        "in every non-re-raising handler of the refused branch (punch #525, "
        "punch 627, punch 668)."
    )


def test_every_grant_writer_witnesses_its_own_insert():
    modules = _src_modules()
    trees = [t for _rel, t in modules]
    offenders = [f"{cls[0]} / {cls[1]}: {o}"
                 for cls in _live_classes(trees) for o in _unwitnessed_writers(modules, cls)]
    assert not offenders, (
        "A function INSERTs a credential or user grant row and either does not emit "
        "the grant event in the same body, or commits after the INSERT before that "
        f"emit on its own path (Property 0): {offenders}. The row and "
        "its chained witness commit in ONE transaction, and a failed witness "
        "rolls the row back (fail closed, PD-8). The reference graph cannot be "
        "trusted to find these: a CLI command is wired by a dispatch dict."
    )


def test_every_grant_class_has_a_live_writer():
    """``pattern_prove_the_input_is_in_the_set_the_control_acts_on``: a class
    whose table literal no src function holds would pass vacuously."""
    trees = _src_trees()
    for cls in _live_classes(trees):
        assert _insert_writers(trees, cls[0]), (
            f"no src function holds an INSERT INTO {cls[0]} literal; the "
            f"{cls[1]} grant class is scanning nothing")


def test_every_discovered_credential_table_is_classified():
    """The ratchet that makes the table set count-agnostic: a credential or user
    table the DDL declares must be a grant class or carry a reason it is not."""
    problems = _classification_problems(
        _discover_classified(_src_trees()), _GRANT_EVENTS, _NOT_A_GRANT)
    assert not problems, (
        f"{problems}. Add the table to _GRANT_EVENTS (with the event that witnesses "
        "its grant) or to _NOT_A_GRANT (with the reason no grant event applies)."
    )


def test_every_dynamic_table_insert_is_accounted_for():
    """A literal-table scan is blind to ``INSERT INTO {table}``: every such site
    is listed with the reason it cannot reach a grant table."""
    problems = _dynamic_problems(
        set(_dynamic_insert_sites(_src_modules())), _DYNAMIC_INSERT_INTENT)
    assert not problems, problems


def test_the_audit_chain_tables_are_not_grant_tables():
    """Backs the ``_chain_insert`` reason: its dynamic table is bounded by
    ``_AUDIT_CHAIN_CANONICAL_FIELDS``, which must stay disjoint from the grant set."""
    from email_triage.db.audit import _AUDIT_CHAIN_CANONICAL_FIELDS

    grants = _discover_grant_tables(_src_trees()) | set(_GRANT_EVENTS)
    overlap = set(_AUDIT_CHAIN_CANONICAL_FIELDS) & grants
    assert not overlap, f"_chain_insert can write a grant table: {sorted(overlap)}"


def test_no_grant_insert_sql_sits_outside_a_function():
    stray = _stray_insert_literals(_src_modules(), _GRANT_EVENTS)
    assert not stray, (
        f"a grant-table INSERT literal sits at module/class level: {stray}. "
        "Property 0 attributes a row write to the function that holds the SQL; "
        "a constant owned by no function is invisible to it.")


def test_grant_pin_has_teeth():
    # A route that grants directly with no emit -> entry point flagged.
    bad_direct = (
        "def route(db, u):\n"
        "    add_hardware_key(db, user_id=u)\n"
    )
    assert _grant_offenders([ast.parse(bad_direct)]) == [
        "unaudited grant entry point: route"]
    # The interprocedural hop: helper -> closure passed by NAME -> route.
    bad_hop = (
        "def finish(db):\n"
        "    return add_hardware_key(db)\n"
        "def route(db):\n"
        "    def _inner(db):\n"
        "        return finish(db)\n"
        "    return db_call(_inner, db)\n"
    )
    assert _grant_offenders([ast.parse(bad_hop)]) == [
        "unaudited grant entry point: route"], "missed the db_call(name) hop"
    # Success audited but the refused branch swallowed silently.
    bad_refusal = (
        "def route(db):\n"
        "    def _inner(db):\n"
        "        try:\n"
        "            k = finish(db)\n"
        "        except AuthError:\n"
        "            return 'verify_failed'\n"
        "        record_auth_event(db, event_type='hardware_key_registered')\n"
        "        return k\n"
        "    return db_call(_inner, db)\n"
        "def finish(db):\n"
        "    return add_hardware_key(db)\n"
    )
    got = _grant_offenders([ast.parse(bad_refusal)])
    assert got and all(s.startswith("refused grant not audited:") for s in got), got
    # The wrong event type is not a grant emit.
    wrong_event = (
        "def route(db, u):\n"
        "    add_hardware_key(db, user_id=u)\n"
        "    record_auth_event(db, event_type='hardware_key_revoked')\n"
    )
    assert _grant_offenders([ast.parse(wrong_event)]) == [
        "unaudited grant entry point: route"]
    good = (
        "def finish(db):\n"
        "    return add_hardware_key(db)\n"
        "def route(db):\n"
        "    def _inner(db):\n"
        "        try:\n"
        "            k = finish(db)\n"
        "        except AuthError:\n"
        "            record_auth_event(db, event_type='hardware_key_registered',\n"
        "                              outcome='denied:verify_failed')\n"
        "            return 'verify_failed'\n"
        "        record_auth_event(db, event_type='hardware_key_registered')\n"
        "        return k\n"
        "    return db_call(_inner, db)\n"
    )
    assert _grant_offenders([ast.parse(good)]) == [], "false-positived an audited grant"
    reraise = (
        "def helper(db):\n"
        "    try:\n"
        "        return add_hardware_key(db)\n"
        "    except ValueError:\n"
        "        raise\n"
        "def route(db):\n"
        "    record_auth_event(db, event_type='hardware_key_registered')\n"
        "    return helper(db)\n"
    )
    assert _grant_offenders([ast.parse(reraise)]) == [], "flagged a re-raising handler"
    # The SHIPPED shape: an atomic funnel emits via the *_txn witness, so the
    # success edge is clean -- but a refusal ABOVE the funnel must still emit.
    funnel = (
        "def funnel(db):\n"
        "    try:\n"
        "        k = add_hardware_key_txn(db)\n"
        "        record_auth_event_txn(db, event_type='hardware_key_registered')\n"
        "        db.commit()\n"
        "    except Exception:\n"
        "        db.rollback()\n"
        "        raise\n"
        "    return k\n"
        "def finish(db):\n"
        "    verify(db)\n"
        "    return funnel(db)\n"
        "def route(db):\n"
        "    def _inner(db):\n"
        "        try:\n"
        "            return finish(db)\n"
        "        except AuthError:\n"
        "            return 'verify_failed'\n"
        "    return db_call(_inner, db)\n"
    )
    got = _grant_offenders([ast.parse(funnel)])
    assert got and all(s.startswith("refused grant not audited:") for s in got), (
        "missed a silent refusal above an emitting funnel", got)
    funnel_ok = funnel.replace(
        "        except AuthError:\n            return 'verify_failed'\n",
        "        except AuthError:\n"
        "            record_auth_event(db, event_type='hardware_key_registered',\n"
        "                              outcome='denied:verify_failed')\n"
        "            return 'verify_failed'\n")
    assert funnel_ok != funnel
    assert _grant_offenders([ast.parse(funnel_ok)]) == [], "false-positived the shipped shape"


def test_grant_pin_has_teeth_for_dev_and_api_keys():
    dev, api = _grant_class("dev_keys"), _grant_class("api_keys")
    # Punch 627 pre-fix shape: a route that grants a dev key with no emit.
    bad_dev = (
        "def _inner(db):\n"
        "    return add_dev_key(db, name='n')\n"
        "def route(db):\n"
        "    return db_call(_inner, db)\n"
    )
    assert _grant_offenders([ast.parse(bad_dev)], dev) == [
        "unaudited grant entry point: route"]
    # The N-611 shape exactly: the writer reached through an import alias.
    aliased = (
        "from email_triage.web.db_auth_helpers import add_dev_key as db_add_dev_key\n"
        + bad_dev.replace("return add_dev_key(", "return db_add_dev_key(")
    )
    assert _grant_offenders([ast.parse(aliased)], dev) == [
        "unaudited grant entry point: route"], "missed the import-alias hop"
    # Another class's event does not witness a dev-key grant.
    cross = bad_dev.replace(
        "    return add_dev_key(db, name='n')\n",
        "    k = add_dev_key(db, name='n')\n"
        "    record_auth_event(db, event_type='hardware_key_registered')\n"
        "    return k\n")
    assert _grant_offenders([ast.parse(cross)], dev) == [
        "unaudited grant entry point: route"]
    # The shipped dev-key shape: funnel + a duplicate refused with its own row.
    dev_ok = (
        "def funnel(db):\n"
        "    try:\n"
        "        k = add_dev_key_txn(db)\n"
        "        record_auth_event_txn(db, event_type='dev_key_registered')\n"
        "        db.commit()\n"
        "    except Exception:\n"
        "        db.rollback()\n"
        "        raise\n"
        "    return k\n"
        "def _inner(db):\n"
        "    try:\n"
        "        return funnel(db)\n"
        "    except IntegrityError:\n"
        "        safe_audit_write(lambda: record_auth_event(\n"
        "            db, event_type='dev_key_registered', outcome='denied:dup'))\n"
        "        return None\n"
        "def route(db):\n"
        "    return db_call(_inner, db)\n"
    )
    assert _grant_offenders([ast.parse(dev_ok)], dev) == []
    silent_dup = dev_ok.replace(
        "        safe_audit_write(lambda: record_auth_event(\n"
        "            db, event_type='dev_key_registered', outcome='denied:dup'))\n", "")
    assert silent_dup != dev_ok
    got = _grant_offenders([ast.parse(silent_dup)], dev)
    assert got and all(s.startswith("refused grant not audited:") for s in got), got
    # API keys: the writer is DISCOVERED by its INSERT literal (no named writer).
    api_ok = (
        "def mint(db):\n"
        "    db.execute('INSERT INTO api_keys (key_hash) VALUES (?)', ('h',))\n"
        "    record_api_key_event_txn(db, event='api_key_created', key_id=1)\n"
        "    db.commit()\n"
        "def route(db):\n"
        "    return db_call(mint, db)\n"
    )
    assert _grant_offenders([ast.parse(api_ok)], api) == []
    # Punch 627 pre-fix shape gone wrong further: the mint with no witness.
    api_bad = api_ok.replace(
        "    record_api_key_event_txn(db, event='api_key_created', key_id=1)\n", "")
    assert api_bad != api_ok
    assert _grant_offenders([ast.parse(api_bad)], api) == [
        "unaudited grant entry point: route"]
    # The right event under the wrong keyword is not this class's emit.
    api_kw = api_ok.replace("event='api_key_created'", "event_type='api_key_created'")
    assert api_kw != api_ok
    assert _grant_offenders([ast.parse(api_kw)], api) == [
        "unaudited grant entry point: route"]


# ---------------------------------------------------------------------------
# Punch 668 teeth: the discovery, Property 0, the dispatch-wiring rule and the
# completeness scans each flag a planted bad shape and pass a planted good one.
# ---------------------------------------------------------------------------

_DDL_FIXTURE = """
CREATE TABLE IF NOT EXISTS people (
    id    INTEGER PRIMARY KEY,
    email TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS magic_links (
    id      INTEGER PRIMARY KEY,
    -- a comment, with a comma, and (parens)
    user_id INTEGER NOT NULL REFERENCES people(id),
    token_hash TEXT NOT NULL,
    UNIQUE(user_id, token_hash)
);
CREATE TABLE IF NOT EXISTS dedup (id INTEGER PRIMARY KEY, msg_id_hash TEXT);
CREATE TABLE IF NOT EXISTS chain (id INTEGER PRIMARY KEY, prev_hash TEXT, row_hash TEXT);
CREATE TABLE IF NOT EXISTS widgets (id INTEGER PRIMARY KEY, name TEXT);
"""


def test_grant_table_discovery_has_teeth():
    tree = ast.parse(f"DDL = {_DDL_FIXTURE!r}")
    # The credential table AND the user table its user_id column references; not
    # a dedup digest, a chain hash or an unrelated table.
    assert _discover_grant_tables([tree]) == {"magic_links", "people"}
    # The table constraint and the SQL comment are not columns.
    cols = [c for c, _ in _ddl_tables([tree])["magic_links"]]
    assert cols == ["id", "user_id", "token_hash"], cols


def test_classification_ratchet_has_teeth():
    found = {"a", "b"}
    assert _classification_problems(found, {"a": 1}, {"b": "why"}) == []
    assert _classification_problems(found, {"a": 1}, {}) == [
        "unclassified credential table: b"]
    assert _classification_problems(found, {"a": 1, "b": 1, "gone": 1}, {}) == [
        "stale classification (no such credential table in the DDL): gone"]
    assert _classification_problems({"a"}, {"a": 1}, {"a": "why"}) == [
        "classified as both a grant and not a grant: a"]


def test_every_live_grant_table_is_a_discovered_one():
    """Every class in the intent map is found by the DDL scan (none is only
    asserted), and the three punch-627 classes did not move."""
    found = _discover_classified(_src_trees())
    assert set(_GRANT_EVENTS) <= found
    assert {"hardware_keys", "dev_keys", "api_keys"} <= set(_GRANT_EVENTS)
    assert {"users", "operator_recovery_keys"} <= found
    assert "account_delegates" in _discover_access_link_tables(_src_trees())


def test_unwitnessed_writer_has_teeth():
    users = _grant_class("users")

    def run(src, cls=users):
        return _unwitnessed_writers([("m.py", ast.parse(src))], cls)

    bad = (
        "def cmd(args):\n"
        "    db.execute('INSERT INTO users (email) VALUES (?)', (a,))\n"
        "    db.commit()\n"
    )
    assert run(bad) == ["unwitnessed grant writer: cmd (m.py:2)"]
    # Every spelling of the same write is read as the write it is.
    for sql in (
        "'INSERT OR REPLACE INTO users (email) VALUES (?)'",
        "'REPLACE INTO users (email) VALUES (?)'",
        "'insert into main.users (email) values (?)'",
        "'INSERT INTO \"users\" (email) VALUES (?)'",
        "'INSERT INTO ' + 'users (email) VALUES (?)'",
    ):
        assert run(f"def w(db):\n    db.execute({sql})\n") == [
            "unwitnessed grant writer: w (m.py:2)"], sql
    emitted = (
        "def cmd(db):\n"
        "    db.execute('INSERT INTO users (email) VALUES (?)', (a,))\n"
        "    record_auth_event_txn(db, event_type='user_created')\n"
        "    db.commit()\n"
    )
    assert run(emitted) == [], "false-positived a self-witnessing writer"
    wrong = emitted.replace("user_created", "hardware_key_registered")
    assert wrong != emitted
    assert run(wrong) == ["unwitnessed grant writer: cmd (m.py:2)"]
    # ORDERING (panel R, DA mutation M1): a commit between the INSERT and the
    # witness leaves a committed grant with no chained row if the witness fails.
    early = (
        "def cmd(db):\n"
        "    db.execute('INSERT INTO users (email) VALUES (?)', (a,))\n"
        "    db.commit()\n"
        "    record_auth_event_txn(db, event_type='user_created')\n"
        "    db.commit()\n"
    )
    assert run(early) == ["commit before witness: cmd (m.py:3)"]
    # The SHIPPED funnel shape: the refused-grant edge emits (then commits) inside an
    # ``except`` handler that sits ABOVE the success commit in the source. A line
    # number check would call that emit "earlier"; the handler is a different path.
    funnel = (
        "def create(conn):\n"
        "    try:\n"
        "        try:\n"
        "            cur = conn.execute('INSERT INTO users (email) VALUES (?)', (a,))\n"
        "        except IntegrityError:\n"
        "            conn.rollback()\n"
        "            record_auth_event_txn(conn, event_type='user_created', outcome='denied')\n"
        "            conn.commit()\n"
        "            return DUP\n"
        "        record_auth_event_txn(conn, event_type='user_created')\n"
        "        conn.commit()\n"
        "    except Exception:\n"
        "        conn.rollback()\n"
        "        raise\n"
        "    return cur.lastrowid\n"
    )
    assert run(funnel) == [], "false-positived the shipped funnel shape"
    m1 = funnel.replace(
        "        record_auth_event_txn(conn, event_type='user_created')\n"
        "        conn.commit()\n",
        "        conn.commit()\n"
        "        record_auth_event_txn(conn, event_type='user_created')\n"
        "        conn.commit()\n")
    assert m1 != funnel
    assert run(m1) == ["commit before witness: create (m.py:10)"], run(m1)
    # A handler that commits WITHOUT its own emit is not covered by the success emit.
    bare_handler = funnel.replace(
        "            record_auth_event_txn(conn, event_type='user_created', outcome='denied')\n", "")
    assert bare_handler != funnel
    assert run(bare_handler) == ["commit before witness: create (m.py:7)"], run(bare_handler)
    # WHAT COUNTS AS THE WITNESS (panel R2, DA SHOULD-2, probes A/B/C): a preceding
    # emit satisfies a commit only if it is an unconditional SUCCESS emit on the path.
    ins = "    db.execute('INSERT INTO users (email) VALUES (?)', (a,))\n"
    ok_emit = "record_auth_event_txn(db, event_type='user_created')"
    denied_emit = "record_auth_event_txn(db, event_type='user_created', outcome='denied')"
    # A: the refused edge (an ``if`` arm) emits a DENIED row and commits, then the
    # success path commits BEFORE its own witness. The denied emit is not that witness.
    probe_a = (
        "def w(db):\n" + ins +
        "    if dup:\n"
        f"        {denied_emit}\n"
        "        db.commit()\n"
        "        return DUP\n"
        "    db.commit()\n"
        f"    {ok_emit}\n"
        "    db.commit()\n"
    )
    assert run(probe_a) == ["commit before witness: w (m.py:7)"], run(probe_a)
    # ...and the arm's OWN commit (line 5, after its denied row) is the refused edge's
    # commit, not a defect: dropping the early success-path commit leaves it clean.
    assert run(probe_a.replace("    db.commit()\n" + f"    {ok_emit}", f"    {ok_emit}")) == []
    # B: the emit is CONDITIONAL (an ``if`` body), the commit is not.
    probe_b = "def w(db):\n" + ins + f"    if admin:\n        {ok_emit}\n    db.commit()\n"
    assert run(probe_b) == ["commit before witness: w (m.py:5)"], run(probe_b)
    # C: the witness is SWALLOWED, so the grant commits without it.
    probe_c = (
        "def w(db):\n" + ins +
        "    try:\n"
        f"        {ok_emit}\n"
        "    except Exception:\n"
        "        pass\n"
        "    db.commit()\n"
    )
    assert run(probe_c) == ["commit before witness: w (m.py:7)"], run(probe_c)
    # The same shapes with an UNCONDITIONAL success witness stay clean: a ``try``
    # whose handlers all re-raise (or return), a ``with`` body, an explicit literal
    # ``outcome='success'``.
    for good in (
        "    try:\n        " + ok_emit + "\n    except Exception:\n        db.rollback()\n        raise\n",
        "    try:\n        " + ok_emit + "\n    except OSError:\n        return None\n",
        "    with lock:\n        " + ok_emit + "\n",
        "    " + ok_emit.replace("'user_created')", "'user_created', outcome='success')") + "\n",
    ):
        assert run("def w(db):\n" + ins + good + "    db.commit()\n") == [], good
    # Not unconditional / not the success witness: each commit is flagged.
    for bad in (
        "    for _ in rows:\n        " + ok_emit + "\n",
        "    while x:\n        " + ok_emit + "\n        break\n",
        "    " + denied_emit + "\n",
        "    ok and " + ok_emit + "\n",
        "    x = " + ok_emit + " if y else None\n",
        "    _ = [" + ok_emit + " for _ in rows]\n",
        "    try:\n        " + ok_emit + "\n    except Exception:\n        log(1)\n",
        "    def inner():\n        " + ok_emit + "\n",
    ):
        assert run("def w(db):\n" + ins + bad + "    db.commit()\n") != [], bad
    # A commit before the INSERT is another transaction, not this grant's.
    before = (
        "def cmd(db):\n"
        "    db.commit()\n"
        "    db.execute('INSERT INTO users (email) VALUES (?)', (a,))\n"
        "    record_auth_event_txn(db, event_type='user_created')\n"
        "    db.commit()\n"
    )
    assert run(before) == []
    # The witness must sit in the INNERMOST writer's own body, not its parent's.
    nested = (
        "def route(db):\n"
        "    def _w(db):\n"
        "        db.execute('INSERT INTO users (email) VALUES (?)')\n"
        "    record_auth_event_txn(db, event_type='user_created')\n"
        "    return db_call(_w, db)\n"
    )
    assert run(nested) == ["unwitnessed grant writer: _w (m.py:3)"]
    # A named seed is exempt; a longer table name is another table.
    seed = "def add_dev_key_txn(db):\n    db.execute('INSERT INTO dev_keys (n) VALUES (?)')\n"
    assert run(seed, _grant_class("dev_keys")) == []
    other = (
        "def f(db):\n"
        "    db.execute('INSERT INTO users_new SELECT * FROM users')\n"
        "    db.execute('INSERT INTO user_status_events (event) VALUES (?)')\n"
    )
    assert run(other) == []


def test_dispatch_wiring_is_not_a_caller():
    """``cli.py`` wires ``"user": cmd_user`` in a dict: the old flat reference set
    counted that as a caller, so a CLI command that grants without a witness read
    as referenced, hence not an entry point."""
    base = (
        "def helper(db):\n"
        "    return add_hardware_key(db)\n"
        "def cmd(args):\n"
        "    return helper(args.db)\n"
    )
    for wiring in ("TABLE = {'user': cmd}\n", "TABLE = {'u': mod.cmd}\n",
                   "parser.set_defaults(func=cmd)\n"):
        tree = ast.parse(base + wiring)
        assert "cmd" not in _all_referenced([tree]), wiring
        assert _grant_offenders([tree]) == ["unaudited grant entry point: cmd"], wiring
    # A real call is still a caller (the entry point moves up to the caller).
    called = ast.parse(base + "def main(args):\n    return cmd(args)\n")
    assert "cmd" in _all_referenced([called])
    assert _grant_offenders([called]) == ["unaudited grant entry point: main"]


def test_every_hop_dispatcher_reaches_the_grant_funnel():
    """N-520's ``HOP_DISPATCHERS`` (PD-6: reused, not re-listed): a grant writer
    handed to ANY off-loop dispatcher by name still makes its caller an entry point."""
    from test_n520_commit_before_witness_ratchet_pin import HOP_DISPATCHERS

    assert HOP_DISPATCHERS
    for d in sorted(HOP_DISPATCHERS):
        for call in (f"{d}(_w, db)", f"x.{d}(_w, db)"):
            src = (
                "def _w(db):\n"
                "    return add_hardware_key(db)\n"
                "def route(db):\n"
                f"    return {call}\n"
            )
            assert _grant_offenders([ast.parse(src)]) == [
                "unaudited grant entry point: route"], call


def test_dynamic_insert_site_has_teeth():
    def sites(src):
        return set(_dynamic_insert_sites([("m.py", ast.parse(src))]))

    for sql in ("f'INSERT INTO {t} (a) VALUES (?)'",
                "'INSERT INTO ' + t + ' (a) VALUES (?)'",
                "'INSERT INTO %s (a) VALUES (?)' % t"):
        assert sites(f"def w(db, t):\n    db.execute({sql})\n") == {("m.py", "w")}, sql
    assert sites("def w(db):\n    db.execute('INSERT INTO users (a) VALUES (?)')\n") == set()
    assert _dynamic_problems({("m.py", "w")}, {}) == [
        "unaccounted dynamic-table INSERT: m.py::w"]
    assert _dynamic_problems(set(), {("m.py", "w"): "why"}) == [
        "stale _DYNAMIC_INSERT_INTENT entry (no such site): m.py::w"]
    assert _dynamic_problems({("m.py", "w")}, {("m.py", "w"): "why"}) == []


def test_stray_insert_literal_has_teeth():
    def stray(src):
        return _stray_insert_literals([("m.py", ast.parse(src))], {"users"})

    assert stray("SQL = 'INSERT INTO users (e) VALUES (?)'\n"
                 "def f(db):\n    db.execute(SQL)\n") == ["m.py:1"]
    assert stray("def f(db):\n    db.execute('INSERT INTO users (e) VALUES (?)')\n") == []
    assert stray('"""This module never runs INSERT INTO users."""\n') == []


def test_the_punch_627_classes_stay_green_under_the_widened_scan():
    """Teeth the other way: the three fixed credential classes are discovered,
    scanned by ALL THREE properties, and clean -- so the RED list of the widened
    pin is only the unfixed writers, never a regression of 627."""
    modules = _src_modules()
    trees = [t for _rel, t in modules]
    found = _discover_grant_tables(trees)
    for table in ("hardware_keys", "dev_keys", "api_keys"):
        cls = _grant_class(table)
        assert table in found
        assert _grant_offenders(trees, cls) == [], table
        assert _unwitnessed_writers(modules, cls) == [], table


# ---------------------------------------------------------------------------
# Punch 673 / 674: the REVOKE (DELETE) arm and the UPDATE arm.
#
# Property 0 is keyed on INSERTs, so it could not see an access grant ended by a
# DELETE (``account_delegates``) or changed by an UPDATE (``users.role``).
#
# REVOKE arm (punch 673): every access-link GRANT class (a table found by
# ``_discover_access_link_tables`` and classified in ``_GRANT_EVENTS``) names the
# event that witnesses its revocation in ``_REVOKE_EVENTS`` (checked both ways),
# and every src function whose own body holds a ``DELETE FROM <table>`` literal
# emits that event in its own body, with no ``.commit()`` after the DELETE before
# the emit (Property 0's ordering clause, reused).
#
# UPDATE arm (punch 674): every column an ``UPDATE <grant table> SET`` literal
# writes is CLASSIFIED, once: a grant column with the witness that must follow
# the write (``_UPDATE_GRANT_COLUMNS``), a column waiting on an SME ruling
# (``_UPDATE_PENDING_RULING``), or a column that grants nothing, with the reason
# (``_UPDATE_NOT_A_GRANT``). A new column, a stale entry, or an UPDATE whose SET
# list is not a literal (an f-string ``SET {...}``: its columns cannot be read)
# turns the pin RED. For a grant column, the statement holding the UPDATE must be
# FOLLOWED on its fall-through path by an unconditional witness before any
# ``.commit()``: a later statement of its own block, else of each enclosing block
# outward (so ``if changed: UPDATE; emit`` and ``try: if x: UPDATE; emit; COMMIT``
# both pass, and an emit BEFORE the write, in a swallowing ``try``, or after a
# commit does not).
#
# Punch 689 widened the REVOKE arm from the access-link grants to EVERY grant
# class: a table in ``_GRANT_EVENTS`` that any src function DELETEs from must name
# its revoke event in ``_REVOKE_EVENTS`` (discovered, checked both ways), and the
# emitter + event keyword come from its ``_GRANT_EVENTS`` entry (``api_keys``
# revokes through ``record_api_key_event_txn(event=...)``). Hardware and dev keys
# are revoked by an UPDATE of ``revoked_at`` (Property 1 above), not a DELETE.
#
# Punch 690: a grant row removed by ``ON DELETE CASCADE`` has no DELETE literal and
# no witness, so the cascade must be UNREACHABLE: no src function hard-deletes a
# table that a revoke-arm table references with ``ON DELETE CASCADE``
# (``users`` / ``email_accounts`` today; both are soft-disabled, operator rulings
#  / , and the N-275 + user-soft-delete pins hold the same line per table).
#
# SCOPE CAVEAT: a DELETE whose table name is not a literal (``f"DELETE FROM
# {tbl}"``) is not seen by either clause. An UPDATE whose
# TABLE name is not a literal (``secrets.py``'s ``self._table``) is not seen; it
# writes the ``secrets_store``, which is not a grant. The ordering reads direct
# ``.commit()`` calls only (``execute('COMMIT')`` is not seen, as in Property 0).
# A witness bound to the right ROW is a runtime property
# (tests/test_web/test_punch673_674_grant_witness.py).
# ---------------------------------------------------------------------------

_REVOKE_EVENTS = {
    "account_delegates": "account_delegate_revoked",
    # Punch 689: web/auth.py delete_api_key.
    "api_keys": "api_key_revoked",
}


def _delete_rx(table: str) -> re.Pattern:
    return re.compile(rf"DELETE\s+FROM\s+(?:main\.)?[\"`\[]?{table}\b", re.I)


def _revoke_class(table: str):
    """The revoke event, with the table's own emitters and event keyword."""
    _grant_event, emitters, kwname, _named = _GRANT_EVENTS[table]
    return (table, _REVOKE_EVENTS[table], emitters, kwname, frozenset())


def _revoke_tables_due(modules) -> set[str]:
    """Every grant class that must name a revoke event: the access-link grants,
    plus every ``_GRANT_EVENTS`` table that a src function DELETEs from."""
    trees = [t for _rel, t in modules]
    access_grants = {t for t in _discover_access_link_tables(trees) if t in _GRANT_EVENTS}
    return access_grants | {t for t in _GRANT_EVENTS if _delete_writers(modules, t)}


_ON_DELETE_CASCADE = re.compile(r"\bREFERENCES\s+(\w+).*?\bON\s+DELETE\s+CASCADE\b", re.I | re.S)


def _cascade_parent_deleters(modules, tables) -> list[str]:
    """Punch 690: every src function that hard-deletes a table one of ``tables``
    references with ``ON DELETE CASCADE`` (that cascade drops grant rows with no
    revoke witness). Column and table-level ``FOREIGN KEY`` clauses both count."""
    ddl = _ddl_tables([t for _rel, t in modules], constraints=True)
    parents = {m.group(1) for t in tables for _c, d in ddl.get(t, [])
               for m in [_ON_DELETE_CASCADE.search(d)] if m}
    return sorted(f"{p}: {fn}" for p in parents for fn in _delete_writers(modules, p))


def _delete_lits(fn: ast.AST, rx: re.Pattern, doc_ids: frozenset[int]) -> list[ast.AST]:
    """The SQL nodes of ``fn``'s own body matching ``rx``; a docstring that names
    the statement (``A DELETE FROM users would ...``) is prose, not a write."""
    return [n for n in _own_walk(fn)
            if isinstance(n, _SQL_NODES) and id(n) not in doc_ids and _holds_insert(n, rx)]


def _delete_writers(modules, table: str) -> set[str]:
    rx = _delete_rx(table)
    out = set()
    for _rel, tree in modules:
        doc_ids = docstring_constant_ids(tree)
        out |= {fn.name for fn in ast.walk(tree)
                if isinstance(fn, _FUNCS) and _delete_lits(fn, rx, doc_ids)}
    return out


# Punch 709 (operator decision 2026-11-02 8:13 PM): the EMERGENCY revoke. With the audit
# chain broken, ``delete_api_key`` and ``set_user_disabled`` -- called with the explicit
# ``emergency_reason`` flag -- commit the revoke WITHOUT its in-line witness and call
# ``db.audit.record_emergency_revoke`` (a PHI-free alarmed gap row, a CRITICAL line, the
# ``/health`` marker). That is the one sanctioned unwitnessed-revoke shape, and it is NOT
# a blanket allow. A site is exempt only inside a function that (i) still carries the
# normal witness, (ii) calls the funnel with the ``kind`` literal of that grant class, and
# (iii) for a DELETE, only a commit AFTER the ``if emergency_reason is None: ... raise``
# guard inside the same ``except`` handler (the emergency arm, dominated by the flag); for
# the ``users.disabled`` UPDATE, only that column, and only when its witness sits in a
# ``try`` whose handler carries that guard. The guard test is the shared harness predicate
# (``_pin_harness.emergency_sanctioned_lines``, cycle P db-sme P2 items 1-2), the same one
# the swallow pin uses. Everything else in those functions is held to the rule as before.
# The flag shape (keyword-only, validated, ``is not None`` guard) is pinned by
# tests/test_709_emergency_revoke_pin.py.
_EMERGENCY_FUNNEL = "record_emergency_revoke"
_EMERGENCY_KIND = {"api_keys": "api_key", "users": "user"}


def _emergency_kinds(fn: ast.AST) -> set[str]:
    """The ``kind=`` literal of every ``record_emergency_revoke`` call in ``fn``'s own body."""
    return {kw.value.value for c in _own_walk(fn) if _call_name_of(c) == _EMERGENCY_FUNNEL
            for kw in c.keywords if kw.arg == "kind" and isinstance(kw.value, ast.Constant)}


def _emergency_update_sanctioned(fn: ast.AST, table: str, column: str, witness) -> bool:
    """The ``users.disabled`` UPDATE inside a function that calls the emergency funnel
    with this table's kind AND keeps its normal chained witness inside a ``try`` whose
    handler carries the flag guard (so the unwitnessed commit is reached only with the
    flag set)."""
    if column != "disabled" or _EMERGENCY_KIND.get(table) not in _emergency_kinds(fn):
        return False
    guarded = {id(h) for h, _i in emergency_sanctioned_handlers(fn)}
    return any(witness(n) for t in _own_walk(fn) if isinstance(t, ast.Try)
               and any(id(h) in guarded for h in t.handlers)
               for s in t.body for n in ast.walk(s))


def _unwitnessed_revokers(modules, table: str) -> list[str]:
    """Every function whose own body DELETEs from a grant table and does not
    emit the revoke event itself, or commits between the DELETE and it."""
    cls, rx = _revoke_class(table), _delete_rx(table)
    out = []
    for rel, tree in modules:
        doc_ids = docstring_constant_ids(tree)
        for fn in ast.walk(tree):
            if not isinstance(fn, _FUNCS):
                continue
            lits = _delete_lits(fn, rx, doc_ids)
            if not lits:
                continue
            first = min(n.lineno for n in lits)
            if not _emits_grant(fn, cls, own=True):
                out.append(f"unwitnessed revoke writer: {fn.name} ({rel}:{first})")
                continue
            sanctioned = (emergency_sanctioned_lines(fn)
                          if _EMERGENCY_KIND.get(table) in _emergency_kinds(fn) else set())
            out.extend(f"commit before witness: {fn.name} ({rel}:{ln})"
                       for ln in _commits_before_witness(fn, cls, first) if ln not in sanctioned)
    return sorted(set(out))


def test_every_access_grant_revocation_is_witnessed():
    modules = _src_modules()
    due = _revoke_tables_due(modules)
    assert set(_REVOKE_EVENTS) == due, (
        "every access-link grant class, and every grant class a src function "
        "DELETEs from, names its revoke event in _REVOKE_EVENTS (and no stale "
        f"entry): due={sorted(due)} revoke map={sorted(_REVOKE_EVENTS)}")
    for table in sorted(_REVOKE_EVENTS):
        assert _delete_writers(modules, table), (
            f"no src function DELETEs from {table}: the revoke arm scans nothing")
    offenders = [f"{t} / {_REVOKE_EVENTS[t]}: {o}"
                 for t in sorted(_REVOKE_EVENTS) for o in _unwitnessed_revokers(modules, t)]
    assert not offenders, (
        f"An access grant is revoked without its chained witness: {offenders}. "
        "Revocation is access modification (§164.308(a)(4)(ii)(C), §164.312(b)): "
        "DELETE and emit the revoke event in ONE transaction, fail closed "
        "(db.audit.record_account_delegate_revoke, punch 673; "
        "web.auth.delete_api_key, punch 689).")


def test_no_cascade_parent_of_a_revoked_grant_is_hard_deleted():
    """Punch 690: the ON DELETE CASCADE on a revoke-arm table drops grant rows
    with no witness, so its parent is never hard-deleted in src."""
    modules = _src_modules()
    tables = sorted(_REVOKE_EVENTS)
    ddl = _ddl_tables([t for _rel, t in modules], constraints=True)
    assert any(_ON_DELETE_CASCADE.search(d) for t in tables for _c, d in ddl.get(t, [])), (
        "no revoke-arm table declares ON DELETE CASCADE: this clause scans nothing")
    offenders = _cascade_parent_deleters(modules, tables)
    assert not offenders, (
        f"A src function hard-deletes the cascade parent of a grant table: {offenders}. "
        "The ON DELETE CASCADE removes the grant rows with no revoke witness "
        "(§164.312(b)). Soft-disable the parent (set_user_disabled / "
        "set_account_active), or revoke each child through its witnessed funnel first.")


def test_revoke_arm_covers_api_keys_with_teeth():
    """Punch 689: the pre-fix ``delete_api_key`` shape (DELETE, commit, then the
    own-commit emitter inside a ``safe_audit_write`` lambda) is red; the txn
    sibling before the commit is green; the auth-event keyword is the wrong class."""
    def run(src):
        return _unwitnessed_revokers([("m.py", ast.parse(src))], "api_keys")

    old = ("def delete_api_key(conn, key_id):\n"
           "    cur = conn.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))\n"
           "    conn.commit()\n"
           "    safe_audit_write(lambda: record_api_key_event(\n"
           "        conn, event='api_key_revoked', key_id=key_id), description='x')\n")
    assert run(old) == ["unwitnessed revoke writer: delete_api_key (m.py:2)"]
    good = ("def delete_api_key(conn, key_id):\n"
            "    cur = conn.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))\n"
            "    record_api_key_event_txn(conn, event='api_key_revoked', key_id=key_id)\n"
            "    conn.commit()\n")
    assert run(good) == []
    early = good.replace(
        "    record_api_key_event_txn(conn, event='api_key_revoked', key_id=key_id)\n"
        "    conn.commit()\n",
        "    conn.commit()\n"
        "    record_api_key_event_txn(conn, event='api_key_revoked', key_id=key_id)\n")
    assert early != good
    assert run(early) == ["commit before witness: delete_api_key (m.py:3)"]
    wrong_kw = good.replace("event='api_key_revoked'", "event_type='api_key_revoked'")
    assert run(wrong_kw) == ["unwitnessed revoke writer: delete_api_key (m.py:2)"]
    grant_event = good.replace("api_key_revoked", "api_key_created")
    assert run(grant_event) == ["unwitnessed revoke writer: delete_api_key (m.py:2)"]


def test_revoke_map_discovery_has_teeth():
    """A grant table a function starts DELETEing from is due a revoke event."""
    planted = [("m.py", ast.parse(
        "def drop(c, k):\n    c.execute('DELETE FROM dev_keys WHERE id = ?', (k,))\n"))]
    assert _revoke_tables_due(planted) == {"dev_keys"}
    assert _revoke_tables_due([("m.py", ast.parse("x = 1\n"))]) == set()


def test_cascade_parent_clause_has_teeth():
    ddl = ("CREATE TABLE IF NOT EXISTS people (id INTEGER PRIMARY KEY);\n"
           "CREATE TABLE IF NOT EXISTS boxes (id INTEGER PRIMARY KEY);\n"
           "CREATE TABLE IF NOT EXISTS grants (id INTEGER PRIMARY KEY,"
           " person_id INTEGER REFERENCES people(id) ON DELETE CASCADE,"
           " box_id INTEGER NOT NULL,"
           " FOREIGN KEY (box_id) REFERENCES boxes(id) ON DELETE CASCADE);\n")
    ddl_mod = ("ddl.py", ast.parse(f"DDL = {ddl!r}"))

    def run(src):
        return _cascade_parent_deleters([ddl_mod, ("m.py", ast.parse(src))], ["grants"])

    assert run("def purge(c):\n    c.execute('DELETE FROM people WHERE id = 1')\n") == [
        "people: purge"]
    # A table-level FOREIGN KEY clause counts too.
    assert run("def purge(c):\n    c.execute('DELETE FROM boxes WHERE id = 1')\n") == [
        "boxes: purge"]
    assert run("def off(c):\n    c.execute('UPDATE people SET disabled = 1')\n") == []
    # A docstring naming the forbidden statement is prose, not a delete.
    assert run('def off(c):\n    """A DELETE FROM people would cascade."""\n'
               "    c.execute('UPDATE people SET disabled = 1')\n") == []
    # A non-cascading reference is not a parent.
    no_cascade = ("ddl.py", ast.parse(f"DDL = {ddl.replace(' ON DELETE CASCADE', '')!r}"))
    assert _cascade_parent_deleters(
        [no_cascade, ("m.py", ast.parse(
            "def purge(c):\n    c.execute('DELETE FROM people WHERE id = 1')\n"))],
        ["grants"]) == []


def test_revoke_arm_has_teeth():
    def run(src):
        return _unwitnessed_revokers([("m.py", ast.parse(src))], "account_delegates")

    bad = ("def rm(db, a, u):\n"
           "    db.execute('DELETE FROM account_delegates WHERE account_id = ?', (a,))\n"
           "    db.commit()\n")
    assert run(bad) == ["unwitnessed revoke writer: rm (m.py:2)"]
    good = bad.replace(
        "    db.commit()\n",
        "    record_auth_event_txn(db, event_type='account_delegate_revoked', email=e)\n"
        "    db.commit()\n")
    assert good != bad and run(good) == []
    early = bad.replace(
        "    db.commit()\n",
        "    db.commit()\n"
        "    record_auth_event_txn(db, event_type='account_delegate_revoked', email=e)\n")
    assert run(early) == ["commit before witness: rm (m.py:3)"]
    wrong = good.replace("account_delegate_revoked", "account_delegate_granted")
    assert run(wrong) == ["unwitnessed revoke writer: rm (m.py:2)"]


def test_access_link_discovery_has_teeth():
    ddl = _DDL_FIXTURE + (
        "CREATE TABLE IF NOT EXISTS shares (id INTEGER PRIMARY KEY,"
        " item_id INTEGER REFERENCES widgets(id),"
        " grantee_id INTEGER REFERENCES people(id));\n"
        "CREATE TABLE IF NOT EXISTS logins (id INTEGER PRIMARY KEY,"
        " actor INTEGER REFERENCES people(id));\n")
    tree = ast.parse(f"DDL = {ddl!r}")
    # A user-to-row link is found; a table that only references the user table,
    # or only a non-user table, is not.
    assert _discover_access_link_tables([tree]) == {"shares"}
    assert _discover_classified([tree]) == {"magic_links", "people", "shares"}


# --- UPDATE arm (punch 674) ----------------------------------------------------

_SET_BODY = re.compile(r"\bSET\b(?P<body>.*?)(?:\bWHERE\b|\bRETURNING\b|$)", re.I | re.S)


def _update_rx(table: str) -> re.Pattern:
    return re.compile(
        rf"UPDATE\s+(?:OR\s+\w+\s+)?(?:main\.)?[\"`\[]?{table}\b(?P<rest>.*)", re.I | re.S)


def _set_columns(rest: str) -> list[str] | None:
    """The column names an UPDATE's SET list writes; ``None`` when the list is not
    a literal (an f-string slot leaves it empty)."""
    m = _SET_BODY.search(rest)
    if not m:
        return None
    cols = []
    for item in _split_top_level(m.group("body")):
        if "=" not in item:
            return None
        cols.append(item.split("=", 1)[0].strip().strip('"`[]').lower())
    return cols or None


def _update_sites(modules, tables):
    """``(rel, fn, node, table, columns | None)`` for every UPDATE literal on a
    table in ``tables``, attributed to its innermost function. Only the OUTERMOST
    SQL node is read (a part of a ``+`` concatenation or of an f-string is not a
    statement of its own)."""
    rxs = {t: _update_rx(t) for t in sorted(tables)}
    out, seen = [], set()
    for rel, tree in modules:
        docs = docstring_constant_ids(tree)
        for fn in ast.walk(tree):
            if not isinstance(fn, _FUNCS):
                continue
            own = [n for n in _own_walk(fn)
                   if isinstance(n, _SQL_NODES) and id(n) not in docs]
            inner = {id(c) for n in own if isinstance(n, (ast.BinOp, ast.JoinedStr))
                     for c in ast.walk(n) if c is not n}
            for n in own:
                if id(n) in inner:
                    continue
                for s in iter_string_literals(n):
                    for t, rx in rxs.items():
                        m = rx.search(s)
                        key = (rel, fn.name, n.lineno, t)
                        if m and key not in seen:
                            seen.add(key)
                            out.append((rel, fn, n, t, _set_columns(m.group("rest"))))
    return out


def _call_name_of(call: ast.AST) -> str | None:
    if not isinstance(call, ast.Call):
        return None
    f = call.func
    return f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)


def _auth_event_witness(event: str):
    """A success ``record_auth_event[_txn](event_type=<event>)`` call."""
    def pred(call):
        if _call_name_of(call) not in _AUTH_EMITTERS:
            return False
        kw = {k.arg: k.value for k in call.keywords}
        ev, oc = kw.get("event_type"), kw.get("outcome")
        return (isinstance(ev, ast.Constant) and ev.value == event
                and (oc is None or (isinstance(oc, ast.Constant) and oc.value == "success")))
    return pred


def _chain_row_witness(table: str):
    """A ``_chain_insert(conn, "<table>", ...)`` call (the chained row writer)."""
    def pred(call):
        return (_call_name_of(call) == "_chain_insert" and len(call.args) >= 2
                and isinstance(call.args[1], ast.Constant) and call.args[1].value == table)
    return pred


# (table, column) -> (what witnesses it, the witness predicate).
_UPDATE_GRANT_COLUMNS = {
    ("users", "role"): ("auth_events user_role_changed",
                        _auth_event_witness("user_role_changed")),
    # Disable / re-enable (the re-enable is a grant): set_user_disabled writes
    # the user_status_events chain row in the same transaction.
    ("users", "disabled"): ("a user_status_events chain row",
                            _chain_row_witness("user_status_events")),
    # Panel Z MUST-Z1-1 (hipaa-sme ruling, punch 674): the login address is where
    # OTP codes are sent, so changing it re-binds the authenticator
    # (§164.308(a)(5)(ii)(D)). record_user_update is its one writer (UI form and
    # the cli.py re-normalize sweep).
    ("users", "email"): ("auth_events user_email_changed",
                         _auth_event_witness("user_email_changed")),
}

# (table, column) -> the open question. Classified, so the ratchet stays closed,
# but NOT asserted to be harmless. Empty since panel Z ruled on users.email.
_UPDATE_PENDING_RULING: dict = {}

_UPDATE_NOT_A_GRANT = {
    ("users", "session_epoch"): "a session REVOCATION bump (N-238 / #205), never a grant",
    ("users", "disabled_at"): "disable metadata, written with users.disabled",
    ("users", "disabled_by_user_id"): "disable metadata, written with users.disabled",
    ("users", "name"): "display name",
    ("users", "notify_email"): (
        "the digest/notification address; not an authentication factor (OTP codes "
        "go to users.email)"),
    ("users", "last_login"): "a login timestamp",
    ("users", "webauthn_user_handle"): (
        "the opaque WebAuthn user handle, assigned once; a passkey grant is a "
        "hardware_keys INSERT"),
    ("users", "style_guide"): "a drafting-style preference",
    ("users", "style_tone"): "a drafting-style preference",
    ("users", "style_length"): "a drafting-style preference",
    ("users", "style_signature"): "a drafting-style preference",
    ("users", "style_greeting"): "a drafting-style preference",
    ("users", "style_greeting_custom"): "a drafting-style preference",
    ("users", "anti_ai_style_guide_user"): "a drafting-style preference",
    ("users", "anti_ai_style_guide_disable_global"): "a drafting-style preference",
    ("dev_keys", "revoked_at"): (
        "revocation, witnessed by dev_key_revoked "
        "(test_credential_revoke_call_sites_emit_audit_event)"),
    ("dev_keys", "revoked_by_user_id"): "revocation metadata, written with revoked_at",
    ("dev_keys", "last_used_at"): "a use stamp",
    ("dev_keys", "last_used_email"): "a use stamp",
    ("dev_keys", "last_used_ip"): "a use stamp",
    ("hardware_keys", "revoked_at"): (
        "revocation, witnessed by hardware_key_revoked "
        "(test_credential_revoke_call_sites_emit_audit_event)"),
    ("hardware_keys", "sign_count"): "the authenticator signature counter (a use stamp)",
    ("hardware_keys", "last_used_at"): "a use stamp",
    ("api_keys", "last_used_at"): "a use stamp",
    ("operator_recovery_keys", "used_at"): "single-use CONSUMPTION (audited on use), not a grant",
    ("recovery_codes", "used_at"): "single-use CONSUMPTION (audited on use), not a grant",
}


def _update_column_problems(sites, grant, pending, not_grant) -> list[str]:
    seen = {(t, c) for *_x, t, cols in sites for c in cols or ()}
    maps = (set(grant), set(pending), set(not_grant))
    classified = set().union(*maps)
    both = {k for i, a in enumerate(maps) for b in maps[i + 1:] for k in a & b}
    return (
        [f"unclassified UPDATE column: {t}.{c}" for t, c in sorted(seen - classified)]
        + [f"stale UPDATE column classification: {t}.{c}" for t, c in sorted(classified - seen)]
        + [f"UPDATE column classified twice: {t}.{c}" for t, c in sorted(both)]
    )


def _dynamic_update_sites(sites) -> list[str]:
    return sorted(f"{rel}::{fn.name}:{n.lineno} ({t})"
                  for rel, fn, n, t, cols in sites if cols is None)


def _stmt_chain(fn: ast.AST, target: ast.AST):
    """``[(block, index), ...]`` outermost-first down to the innermost statement of
    ``fn`` that holds ``target`` (nested defs skipped)."""
    def visit(block, chain):
        for i, stmt in enumerate(block):
            if isinstance(stmt, (*_FUNCS, ast.ClassDef)):
                continue
            if not any(n is target for n in ast.walk(stmt)):
                continue
            here = chain + [(block, i)]
            for sub in _blocks_of(stmt):
                deeper = visit(sub, here)
                if deeper:
                    return deeper
            return here
        return None
    return visit(fn.body, [])


def _witness_follows(fn: ast.AST, node: ast.AST, pred) -> bool:
    """The statement holding ``node`` is followed, on its fall-through path, by an
    unconditional witness (``pred``) before any ``.commit()``."""
    chain = _stmt_chain(fn, node) or []
    for block, i in reversed(chain):
        for stmt in block[i + 1:]:
            if _emits_on_fallthrough(stmt, None, pred=pred):
                return True
            if any(_own_expr_commits(s) for s in ast.walk(stmt) if isinstance(s, ast.stmt)):
                return False
    return False


def _update_witness_problems(sites) -> list[str]:
    out = set()
    for rel, fn, node, t, cols in sites:
        for c in cols or ():
            spec = _UPDATE_GRANT_COLUMNS.get((t, c))
            if (spec and not _witness_follows(fn, node, spec[1])
                    and not _emergency_update_sanctioned(fn, t, c, spec[1])):
                out.add(f"{t}.{c} written with no {spec[0]} after it: "
                        f"{fn.name} ({rel}:{node.lineno})")
    return sorted(out)


def _grant_tables_for_update_arm(trees) -> list[str]:
    return [cls[0] for cls in _live_classes(trees)]


def test_every_update_column_on_a_grant_table_is_classified():
    modules = _src_modules()
    sites = _update_sites(modules, _grant_tables_for_update_arm([t for _r, t in modules]))
    problems = _update_column_problems(
        sites, _UPDATE_GRANT_COLUMNS, _UPDATE_PENDING_RULING, _UPDATE_NOT_A_GRANT)
    assert not problems, (
        f"{problems}. Classify the column: a grant (with its witness) in "
        "_UPDATE_GRANT_COLUMNS, an open ruling in _UPDATE_PENDING_RULING, or a "
        "reason it grants nothing in _UPDATE_NOT_A_GRANT (punch 674).")


def test_no_grant_table_update_has_a_non_literal_set_list():
    modules = _src_modules()
    sites = _update_sites(modules, _grant_tables_for_update_arm([t for _r, t in modules]))
    dyn = _dynamic_update_sites(sites)
    assert not dyn, (
        f"UPDATE of a grant table with a non-literal SET list: {dyn}. Its columns "
        "cannot be classified, so a role (or other grant) write there is invisible "
        "to this pin; write one literal statement per column group (punch 674: "
        "the api.py PATCH /users dynamic SET was exactly this).")


def test_every_grant_column_update_is_followed_by_its_witness():
    modules = _src_modules()
    sites = _update_sites(modules, _grant_tables_for_update_arm([t for _r, t in modules]))
    for col in ("role", "email"):
        assert any(t == "users" and col in (cols or ()) for *_x, t, cols in sites), (
            f"no src UPDATE writes users.{col}: the {col} arm scans nothing")
    problems = _update_witness_problems(sites)
    assert not problems, (
        f"A grant column is UPDATEd with no witness after it: {problems}. Raising a "
        "role is access modification (§164.308(a)(4)(ii)(C), §164.312(b)): write it "
        "and its chained witness in ONE transaction, fail closed "
        "(db.audit.record_user_update, punch 674).")


def test_update_arm_has_teeth():
    def sites(src):
        return _update_sites([("m.py", ast.parse(src))], ["users"])

    def problems(src):
        return _update_witness_problems(sites(src))

    ok = "record_auth_event_txn(db, event_type='user_role_changed', email=a)"
    # The pre-fix ui/users.py shape: role written inline, committed, no witness.
    inline = ("def snap(db, r, u):\n"
              "    db.execute('UPDATE users SET name = ?, role = ?, "
              "session_epoch = session_epoch + 1 WHERE id = ?', (n, r, u))\n"
              "    db.commit()\n")
    assert problems(inline) == [
        "users.role written with no auth_events user_role_changed after it: snap (m.py:2)"]
    funnel = ("def f(db, r, u):\n"
              "    try:\n"
              "        if r != old:\n"
              "            db.execute('UPDATE users SET role = ? WHERE id = ?', (r, u))\n"
              f"            {ok}\n"
              "        db.commit()\n"
              "    except Exception:\n"
              "        db.rollback()\n"
              "        raise\n")
    assert problems(funnel) == [], "false-positived the shipped funnel shape"
    for bad in (
        # the witness BEFORE the write
        funnel.replace(
            "            db.execute('UPDATE users SET role = ? WHERE id = ?', (r, u))\n"
            f"            {ok}\n",
            f"            {ok}\n"
            "            db.execute('UPDATE users SET role = ? WHERE id = ?', (r, u))\n"),
        # a commit between the write and the witness
        funnel.replace(f"            {ok}\n", f"            db.commit()\n            {ok}\n"),
        # a denied (refusal) row is not the grant's witness
        funnel.replace("email=a)", "email=a, outcome='denied:x')"),
        # a swallowed witness
        funnel.replace(f"            {ok}\n",
                       f"            try:\n                {ok}\n"
                       "            except Exception:\n                pass\n"),
    ):
        assert bad != funnel
        assert problems(bad), bad
    # The pre-fix api.py shape: a dynamic SET list hides the role column.
    dyn = ("def p(db, ups, u):\n"
           "    db.execute(f\"UPDATE users SET {', '.join(ups)} WHERE id = ?\", (u,))\n")
    assert _dynamic_update_sites(sites(dyn)) == ["m.py::p:2 (users)"]
    # Column reading: WHERE is not a SET column; a concatenated statement is read whole.
    got = sites("def s(db):\n    db.execute('UPDATE users SET last_login = ? WHERE email = ?')\n")
    assert [c for *_x, c in got] == [["last_login"]]
    got = sites("def s(db):\n    db.execute('UPDATE users SET ' + 'role = ? WHERE id = ?')\n")
    assert [c for *_x, c in got] == [["role"]]
    # The classification ratchet, both ways.
    two = sites(inline)
    assert _update_column_problems(two, {("users", "role"): 1}, {}, {
        ("users", "name"): "x", ("users", "session_epoch"): "x"}) == []
    assert _update_column_problems(two, {("users", "role"): 1}, {}, {
        ("users", "name"): "x"}) == ["unclassified UPDATE column: users.session_epoch"]
    assert _update_column_problems(two, {("users", "role"): 1}, {("users", "gone"): "?"}, {
        ("users", "name"): "x", ("users", "session_epoch"): "x"}) == [
        "stale UPDATE column classification: users.gone"]
    # The disable flip's witness is the chained user_status_events row after the if.
    flip = ("def d(conn, t, x):\n"
            "    try:\n"
            "        if x:\n"
            "            conn.execute('UPDATE users SET disabled = 1 WHERE id = ?', (t,))\n"
            "        _chain_insert(conn, 'user_status_events', {})\n"
            "        conn.commit()\n"
            "    except Exception:\n"
            "        raise\n")
    assert problems(flip) == []
    assert problems(flip.replace("'user_status_events'", "'log_entries'"))
    # Panel Z MUST-Z1-1: the pre-fix cli.py re-normalize shape, an unwitnessed
    # SET email in a loop, then one commit.
    renorm = ("def rn(db, rows):\n"
              "    for uid, e, n in rows:\n"
              "        db.execute('UPDATE users SET email = ?, notify_email = ?, "
              "session_epoch = session_epoch + 1 WHERE id = ?', (e, n, uid))\n"
              "    db.commit()\n")
    assert problems(renorm) == [
        "users.email written with no auth_events user_email_changed after it: rn (m.py:3)"]
    email_ok = ("def eu(db, e, u):\n"
                "    if e != old:\n"
                "        db.execute('UPDATE users SET email = ? WHERE id = ?', (e, u))\n"
                "        record_auth_event_txn(db, event_type='user_email_changed', email=a)\n"
                "    db.commit()\n")
    assert problems(email_ok) == [], "false-positived the shipped email-arm shape"
    # the role's witness does not witness an email change
    assert problems(email_ok.replace("user_email_changed", "user_role_changed"))


def test_the_emergency_revoke_exemption_is_narrow():
    """Punch 709: the one sanctioned unwitnessed-revoke shape, and only that shape."""
    def update_problems(src):
        return _update_witness_problems(_update_sites([("m.py", ast.parse(src))], ["users"]))

    def revoke_problems(src):
        return _unwitnessed_revokers([("web/auth.py", ast.parse(src))], "api_keys")

    flip = ("def d(conn, t, *, emergency_reason=None):\n"
            "    for phase in ('a', 'b'):\n"
            "        conn.execute('UPDATE users SET disabled = 1 WHERE id = ?', (t,))\n"
            "        if phase == 'b':\n"
            "            break\n"
            "        try:\n"
            "            _chain_insert(conn, 'user_status_events', {})\n"
            "            break\n"
            "        except Exception:\n"
            "            if emergency_reason is None:\n"
            "                raise\n"
            "    conn.commit()\n"
            "    if emergency_reason is not None:\n"
            "        record_emergency_revoke(conn, kind='user', target_id=t)\n")
    funnel = "record_emergency_revoke(conn, kind='user', target_id=t)"
    assert update_problems(flip) == [], "the sanctioned emergency shape was flagged"
    for bad in (
        flip.replace(funnel, "pass"),                                      # no funnel call
        flip.replace("kind='user'", "kind='api_key'"),                      # the wrong grant class
        flip.replace("_chain_insert(conn, 'user_status_events', {})", "pass"),  # no normal witness
        flip.replace("disabled = 1", "role = ?"),                          # another grant column
    ):
        assert bad != flip
        assert update_problems(bad), bad

    revoke = ("def delete_api_key(conn, k, *, emergency_reason=None):\n"
              "    conn.execute('DELETE FROM api_keys WHERE id = ?', (k,))\n"
              "    try:\n"
              "        record_api_key_event_txn(conn, event='api_key_revoked', key_id=k)\n"
              "        conn.commit()\n"
              "    except Exception:\n"
              "        conn.rollback()\n"
              "        if emergency_reason is None:\n"
              "            raise\n"
              "        conn.execute('DELETE FROM api_keys WHERE id = ?', (k,))\n"
              "        conn.commit()\n"
              "        record_emergency_revoke(conn, kind='api_key', target_id=k)\n")
    rfunnel = "record_emergency_revoke(conn, kind='api_key', target_id=k)"
    assert revoke_problems(revoke) == [], "the sanctioned emergency shape was flagged"
    handler_commit = "commit before witness: delete_api_key (web/auth.py:11)"
    assert revoke_problems(revoke.replace(rfunnel, "pass")) == [handler_commit]
    assert revoke_problems(revoke.replace("kind='api_key'", "kind='user'")) == [handler_commit]
    # a commit OUTSIDE the emergency handler is never sanctioned by the funnel's presence
    assert revoke_problems(revoke + "    conn.commit()\n") == [
        "commit before witness: delete_api_key (web/auth.py:13)"]
    # and the normal witness must still be there
    assert revoke_problems(revoke.replace("event='api_key_revoked'", "event='x'")) == [
        "unwitnessed revoke writer: delete_api_key (web/auth.py:2)"]

    # Cycle P db-sme P2 item 1 (probe_q4): before the shared guard predicate both of these
    # read [] and passed, because every line of every handler was sanctioned.
    guard = "        if emergency_reason is None:\n            raise\n"
    # (a) the `is None: raise` guard deleted: every witness failure commits unwitnessed
    unguarded = revoke.replace(guard, "")
    assert unguarded != revoke
    assert revoke_problems(unguarded) == ["commit before witness: delete_api_key (web/auth.py:9)"]
    # (b) an unrelated handler that commits before the witness, in the same function
    other = revoke.replace(
        "    try:\n        record_api_key_event_txn",
        "    try:\n        prep(conn)\n    except ValueError:\n        conn.commit()\n"
        "    try:\n        record_api_key_event_txn")
    assert other != revoke
    assert revoke_problems(other) == ["commit before witness: delete_api_key (web/auth.py:6)"]
    # a commit BEFORE the guard in the emergency handler runs on both paths: not sanctioned
    early = revoke.replace("        conn.rollback()\n", "        conn.rollback()\n        conn.commit()\n")
    assert revoke_problems(early) == ["commit before witness: delete_api_key (web/auth.py:8)"]
    # a guard that can leave without raising is not a guard
    soft = revoke.replace(guard, "        if emergency_reason is None:\n            return False\n")
    assert revoke_problems(soft) == ["commit before witness: delete_api_key (web/auth.py:11)"]
    # the UPDATE arm, narrowed the same way: the guard deleted from the witness's handler
    flip_unguarded = flip.replace(
        "            if emergency_reason is None:\n                raise\n", "            pass\n")
    assert flip_unguarded != flip
    assert update_problems(flip_unguarded) == [
        "users.disabled written with no a user_status_events chain row after it: d (m.py:3)"]
