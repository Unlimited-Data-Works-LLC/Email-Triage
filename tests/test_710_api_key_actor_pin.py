"""Punch 710: every api_key_events row records WHO granted or revoked the key.

Before, the witness stored ``actor_user_id`` only, so a CLI grant or revoke
(no session; ``actor_user_id`` NULL by design) was chained with no actor, and the
kernel principal ``_cli_actor()`` reached a log line alone. ``actor_email`` is now
a column of the row, written by the ONE chain-writer
(``record_api_key_event_txn``) and passed by every src caller of the four
api-key witness funnels.

The column is stored, NOT hashed: ``_AUDIT_CHAIN_CANONICAL_FIELDS`` is a frozen
per-table contract and the verifier reads one field tuple per table, so hashing
a new column would break verification of every existing row. A writer with
database access can therefore edit ``actor_email`` without breaking the chain
(the hashed ``actor_user_id`` / ``source`` still bind the rest of the row).

SCOPE: the call-site pin reads direct calls and ``db_call``-style hops by NAME
across src; a call through a variable or a ``**kwargs`` spread is not read.
"""
from __future__ import annotations

import ast

from _pin_harness import call_args_of, parse_source, walk_src

_FUNNELS = frozenset({
    "store_api_key", "delete_api_key", "record_api_key_event", "record_api_key_event_txn",
})


def _missing_actor(tree, rel: str) -> list[str]:
    out = []
    for n in ast.walk(tree):
        for name in sorted(_FUNNELS):
            got = call_args_of(n, name)
            if got is None:
                continue
            kw = next((k for k in got[1] if k.arg == "actor_email"), None)
            if kw is None or (isinstance(kw.value, ast.Constant) and kw.value.value is None):
                out.append(f"{rel}:{n.lineno} {name}")
    return out


def test_every_api_key_witness_call_passes_the_actor():
    found, offenders = set(), []
    for _path, rel, tree in walk_src():
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                f = n.func
                nm = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                if nm in _FUNNELS:
                    found.add(nm)
        offenders += _missing_actor(tree, rel)
    # Anti-vacuity: the grant/revoke funnels and the txn writer are all called in src.
    assert {"store_api_key", "delete_api_key", "record_api_key_event_txn"} <= found, found
    assert not offenders, (
        "An api-key grant/revoke witness call passes no actor_email (punch 710): "
        "the chained row would record no actor (a CLI caller has no actor_user_id). "
        "Pass the session user's address or cli._cli_actor():\n  " + "\n  ".join(offenders))


def test_the_actor_pin_has_teeth():
    bad = "def f(db):\n    store_api_key(db, 'h', 'n', 1, actor_user_id=None, source='cli')\n"
    assert _missing_actor(parse_source(bad), "m.py") == ["m.py:2 store_api_key"]
    good = bad.replace("source='cli'", "actor_email=_cli_actor(), source='cli'")
    assert _missing_actor(parse_source(good), "m.py") == []
    assert _missing_actor(parse_source(bad.replace("source='cli'", "actor_email=None")),
                          "m.py") == ["m.py:2 store_api_key"]
    hop = "async def g(db):\n    await db_call(delete_api_key, db, 3, source='ui')\n"
    assert _missing_actor(parse_source(hop), "m.py") == ["m.py:2 delete_api_key"]


def test_the_chain_writer_writes_the_actor_column():
    from email_triage.db import audit
    from _pin_harness import SRC_ROOT, parse_module
    tree = parse_module(SRC_ROOT / "db" / "audit.py")
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "record_api_key_event_txn")
    keys = {k.value for n in ast.walk(fn) if isinstance(n, ast.Dict)
            for k in n.keys if isinstance(k, ast.Constant)}
    assert "actor_email" in keys
    # Stored, not hashed (the frozen per-table contract), and kept out of a gap row.
    assert "actor_email" not in audit._AUDIT_CHAIN_CANONICAL_FIELDS["api_key_events"]
    assert "actor_email" in audit._AUDIT_EMITTER_REDACTION_MAP["record_api_key_event"]["out"]
