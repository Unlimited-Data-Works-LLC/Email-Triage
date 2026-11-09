"""N-539 / N-540 — a witnessed state write is reachable only through its funnel.

Two register rows, one shape, so one detector (PD#6):

* **N-539 (punch 544).** The watch-group rows. ``profile_watches_save_new``
  committed the rows and then wrote its ``access_log`` rows (late witness);
  ``profile_watches_save_existing`` and ``profile_watches_delete`` wrote none
  (no witness). All three now go through ``db/audit.record_watch_group_save`` /
  ``record_watch_group_delete``, which write the rows and the non-owner HIPAA
  access rows in one transaction.
* **N-540 (punch 545).** The ``runtime_settings`` blob (``dry_run``,
  ``log_level``, the bulk-triage knobs). ``config_save`` own-committed it with no
  audit row on any path; it now goes through
  ``db/audit.record_runtime_settings_change``.

WHAT THE PIN ASSERTS, per family, over every parseable file under
``src/email_triage`` (``walk_src``, count-agnostic):

1. **Funnel exclusivity.** Every reference to a writer of the family, outside
   the writer's own home module, sits inside an ``@audit_emitter`` def in
   ``AUDIT_EMITTER_MODULES`` or is a reasoned ``ALLOW`` entry. "Reference" is a
   direct call AND the ``db_call(writer, conn, …)`` seam, where the writer is
   passed as an argument (PD#2).
2. **Each funnel actually witnesses.** Every ``@audit_emitter`` def that
   references a writer of the family calls a chain-writing ``*_txn`` witness,
   directly or through one same-module helper. The witness set is derived: every
   ``db/audit.py`` def named ``*_txn`` whose body calls ``_chain_insert``.
3. **Teeth** for each arm and each resolver branch, and a known-member guard so a
   green run cannot come from an empty set.

THE WRITER SETS ARE DERIVED, not listed:

* N-539: every def in ``web/email_watches.py`` whose body holds an
  ``INSERT INTO`` / ``DELETE FROM`` / ``UPDATE`` on ``email_watches``, closed
  under same-module callers (so ``save_watch_group_txn`` joins through
  ``upsert_watch_txn``).
* N-540: ``set_setting`` / ``set_setting_txn`` / ``delete_setting`` from
  ``web/db.py``, keyed on the settings KEY argument: only a reference whose key
  argument is the literal ``"runtime_settings"`` or a name/attribute
  ``_RUNTIME_SETTINGS_KEY`` counts.

WHAT IT DOES NOT SEE (each a fail-OPEN direction; stated so a green run is not
read as more than it is):

* A writer reached through a variable, ``getattr``, a dict of callables or a
  re-export under a new name in another module. Same-file
  ``from … import writer as alias`` IS resolved.
* For N-540, a key passed through a variable (``set_setting(db, k, v)``). Both
  funnels take the key as a parameter and are found by arm 2 instead.
* Whether the witness is CONDITIONAL. ``record_system_hipaa_flip`` witnesses only
  on a flip, ``record_runtime_settings_change`` only on a changed blob, and the
  watch funnels only for non-owner HIPAA accounts. Arm 2 proves a witness call
  exists in the funnel, not that it fires; the behavioural tests in
  ``tests/test_web/test_n539_n540_witness_routes.py`` cover when it fires.
* Writers outside these two families. This is not the N-520 class pin.
* **Arm 2 reads module-level defs only.** An ``@audit_emitter`` METHOD in an
  emitter module passes arm 1 (the innermost decorated def admits it) but arm 2
  never checks that it witnesses. None exists today (panel B2 DA-4b).
* **The home module is exempt from arm 1.** Any function in
  ``web/email_watches.py`` may call the watch writers, and any function in
  ``web/db.py`` may write ``runtime_settings``, unwitnessed. Neither happens
  today: the email_watches home holds only the writers themselves and the
  system auto-retire, and no ``web/db.py`` function names the runtime key
  (panel B2 DA-4c).
* Closed rather than listed (DA-4a): ``INSERT OR <x> INTO``, ``REPLACE INTO``
  and ``UPDATE OR <x>`` on ``email_watches`` are in ``_WATCH_SQL``, with teeth;
  so are a schema prefix (``main.email_watches``) and a quoted or bracketed
  name (``"email_watches"``, ``[email_watches]``, backticks) (panel B2
  landing, devils-advocate). Stated limits, both fail-OPEN: (1) SQL whose verb
  and table name are not in one string constant (concatenation, f-string or
  format placeholders, a comment between words, spaces around a schema dot);
  none in src at 2026-10-06. (2) Rows written by an FK cascade, which no SQL
  names; LIVE in src: ``email_watches.account_id ... ON DELETE CASCADE`` and
  the creator column ``ON DELETE SET NULL`` (web/migrations.py), so account
  and user deletion write email_watches outside any funnel.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import (
    AUDIT_EMITTER_MODULES,
    SRC_ROOT,
    _is_audit_emitter_decorator,
    assert_pin_has_teeth,
    enclosing_qualified_name,
    innermost_fn_at_lineno,
    parse_module,
    parse_source,
    walk_src,
)

_WATCH_HOME = "web/email_watches.py"
_SETTINGS_HOME = "web/db.py"
_SETTINGS_WRITERS = frozenset({"set_setting", "set_setting_txn", "delete_setting"})
_RUNTIME_KEY_LITERAL = "runtime_settings"
_RUNTIME_KEY_NAME = "_RUNTIME_SETTINGS_KEY"
_WATCH_SQL = re.compile(
    r"\b(INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|DELETE\s+FROM"
    r"|UPDATE(?:\s+OR\s+\w+)?)\s+"
    r"(?:[\"`\[]?\w+[\"`\]]?\.)?[\"`\[]?email_watches[\"`\]]?(?!\w)",
    re.IGNORECASE,
)

#: Writer references outside a funnel, each reviewed. Keyed on
#: ``(relpath, enclosing qualified name)`` (R38, line-stable). A stale entry fails
#: ``test_allow_entries_are_live``.
ALLOW: dict[tuple[str, str], str] = {
    ("web/routers/agent_api.py", "_upsert_watch_on_account"): (
        "The agent-API create/update write (N-564). In the same hop as the "
        "write, _scoped_watch_account requires the key holder to manage the "
        "path account and refuses a HIPAA account (is_account_hipaa, system "
        "flag included), so this helper itself cannot bind a HIPAA account "
        "(hipaa-sme B9). No N-539 witness is owed: the funnel witnesses "
        "non-owner HIPAA-effective accounts. Scope is pinned by "
        "test_f5_watch_writer_scope_pin.py."
    ),
    ("web/routers/agent_api.py", "webhook_watches_delete._delete_watch"): (
        "The agent-API delete (N-564): _get_watch_on_account runs "
        "_scoped_watch_account (requester may manage, not HIPAA) and the path "
        "binding in the same hop as the delete, so no N-539 witness is owed "
        "(see _upsert_watch_on_account)."
    ),
    ("web/watch_runner.py", "fire_watches_for_message"): (
        "The #48 auto-retire (maybe_auto_retire_watch disables or deletes a "
        "group at its match threshold). The actor is the system, not a user, so "
        "PD#14's actor-not-owner gate has no actor to compare; it writes its "
        "own write_auto_retire_audit_row. Not an N-539 path."
    ),
}

#: Funnels that must be found, so a green arm 2 is not a green over nothing
#: (pattern_prove_the_input_is_in_the_set_the_control_acts_on).
KNOWN_FUNNELS: dict[str, frozenset[str]] = {
    "watch": frozenset({"record_watch_group_save", "record_watch_group_delete"}),
    "settings": frozenset({"record_runtime_settings_change", "record_system_hipaa_flip"}),
}


# ---------------------------------------------------------------------------
# Derivations
# ---------------------------------------------------------------------------


def _called_names(fn: ast.AST) -> set[str]:
    out: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def _module_defs(tree: ast.AST) -> dict[str, ast.AST]:
    return {
        n.name: n for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def watch_writers(tree: ast.AST | None = None) -> frozenset[str]:
    """Defs in ``web/email_watches.py`` that write ``email_watches``, closed under
    same-module callers."""
    tree = tree if tree is not None else parse_module(SRC_ROOT / _WATCH_HOME)
    defs = _module_defs(tree)
    out = {
        name for name, fn in defs.items()
        if any(
            isinstance(c, ast.Constant) and isinstance(c.value, str)
            and _WATCH_SQL.search(c.value)
            for c in ast.walk(fn)
        )
    }
    changed = True
    while changed:
        changed = False
        for name, fn in defs.items():
            if name not in out and _called_names(fn) & out:
                out.add(name)
                changed = True
    return frozenset(out)


def chain_witness_txns() -> frozenset[str]:
    """Every ``db/audit.py`` def named ``*_txn`` whose body calls ``_chain_insert``."""
    defs = _module_defs(parse_module(SRC_ROOT / "db/audit.py"))
    return frozenset(
        name for name, fn in defs.items()
        if name.endswith("_txn") and "_chain_insert" in _called_names(fn)
    )


# ---------------------------------------------------------------------------
# The ONE reference detector (both families)
# ---------------------------------------------------------------------------


def _aliases(tree: ast.AST, writers: frozenset[str]) -> dict[str, str]:
    return {
        a.asname: a.name
        for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
        for a in n.names if a.name in writers and a.asname
    }


def _is_runtime_key(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Constant):
        return node.value == _RUNTIME_KEY_LITERAL
    if isinstance(node, ast.Name):
        return node.id == _RUNTIME_KEY_NAME
    if isinstance(node, ast.Attribute):
        return node.attr == _RUNTIME_KEY_NAME
    return False


def writer_references(
    tree: ast.AST, writers: frozenset[str], *, key_is_runtime: bool = False,
) -> list[ast.Call]:
    """Every Call that invokes a writer, or passes one as an argument (the
    ``db_call(writer, conn, key, …)`` seam). With ``key_is_runtime`` only a
    reference whose key argument (the one after ``conn``) is the runtime-settings
    key counts."""
    names = set(writers) | set(_aliases(tree, writers))

    def _is_writer(e: ast.AST) -> bool:
        return (
            (isinstance(e, ast.Name) and e.id in names)
            or (isinstance(e, ast.Attribute) and e.attr in writers)
        )

    def _key(call: ast.Call, after: int) -> ast.AST | None:
        if len(call.args) > after:
            return call.args[after]
        for kw in call.keywords:
            if kw.arg == "key":
                return kw.value
        return None

    hits: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        keys: list[ast.AST | None] = []
        if _is_writer(node.func):
            keys.append(_key(node, 1))
        for i, a in enumerate(node.args):
            if _is_writer(a):
                keys.append(node.args[i + 2] if len(node.args) > i + 2 else None)
        if not keys:
            continue
        if not key_is_runtime or any(_is_runtime_key(k) for k in keys):
            hits.append(node)
    return hits


def _in_funnel(tree: ast.AST, node: ast.AST, rel: str) -> bool:
    fn = innermost_fn_at_lineno(tree, node.lineno)
    return (
        rel in AUDIT_EMITTER_MODULES and fn is not None
        and any(_is_audit_emitter_decorator(d) for d in fn.decorator_list)
    )


def out_of_funnel(
    tree: ast.AST, rel: str, writers: frozenset[str], *, home: str,
    key_is_runtime: bool = False,
) -> list[tuple[str, str]]:
    """``(rel, qualified fn)`` for every writer reference outside a funnel."""
    if rel == home:
        return []
    return [
        (rel, enclosing_qualified_name(c))
        for c in writer_references(tree, writers, key_is_runtime=key_is_runtime)
        if not _in_funnel(tree, c, rel)
    ]


def _families() -> dict[str, dict]:
    return {
        "watch": {"writers": watch_writers(), "home": _WATCH_HOME, "key": False},
        "settings": {"writers": _SETTINGS_WRITERS, "home": _SETTINGS_HOME, "key": True},
    }


def scan_family(fam: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for _p, rel, tree in walk_src():
        out += out_of_funnel(
            tree, rel, fam["writers"], home=fam["home"], key_is_runtime=fam["key"],
        )
    return out


def funnels_and_witnessing(tree: ast.AST, writers: frozenset[str]) -> dict[str, bool]:
    """For each ``@audit_emitter`` def in ``tree`` that references a writer (any
    key): does it call a chain witness ``*_txn``, directly or through one
    same-module helper?"""
    witnesses = chain_witness_txns()
    defs = _module_defs(tree)
    out: dict[str, bool] = {}
    for name, fn in defs.items():
        if not any(_is_audit_emitter_decorator(d) for d in fn.decorator_list):
            continue
        if not writer_references(fn, writers):
            continue
        calls = _called_names(fn)
        reach = set(calls)
        for c in calls:
            if c in defs:
                reach |= _called_names(defs[c])
        out[name] = bool(reach & witnesses)
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWitnessedWriteFunnelPin:
    def test_writer_sets_are_derived_and_nonempty(self) -> None:
        ww = watch_writers()
        for name in ("upsert_watch_txn", "delete_watch_txn", "save_watch_group_txn",
                     "upsert_watch", "delete_watch"):
            assert name in ww, f"watch-writer derivation missed {name}: {sorted(ww)}"
        assert {"record_access_event_txn", "record_auth_event_txn"} <= chain_witness_txns()

    def test_every_writer_reference_is_in_a_funnel(self) -> None:
        bad: list[str] = []
        for fam_name, fam in _families().items():
            for key in scan_family(fam):
                if key not in ALLOW:
                    bad.append(f"[{fam_name}] {key[0]}::{key[1]}")
        assert not bad, (
            "a witnessed state write is referenced outside its funnel — route it "
            "through db/audit.record_watch_group_save / record_watch_group_delete "
            "(watch rows) or record_runtime_settings_change (runtime_settings), "
            "or add a reasoned ALLOW entry:\n  " + "\n  ".join(sorted(set(bad)))
        )

    def test_allow_entries_are_live(self) -> None:
        live = set()
        for fam in _families().values():
            live |= set(scan_family(fam))
        stale = sorted(k for k in ALLOW if k not in live)
        assert not stale, f"ALLOW entr(ies) match no live reference; delete: {stale}"

    def test_every_funnel_witnesses_and_the_known_ones_are_found(self) -> None:
        for fam_name, fam in _families().items():
            found: dict[str, bool] = {}
            for rel in AUDIT_EMITTER_MODULES:
                found |= funnels_and_witnessing(parse_module(SRC_ROOT / rel), fam["writers"])
            missing = KNOWN_FUNNELS[fam_name] - set(found)
            assert not missing, f"[{fam_name}] funnel(s) not detected: {sorted(missing)}"
            silent = sorted(n for n, ok in found.items() if not ok)
            assert not silent, (
                f"[{fam_name}] @audit_emitter funnel(s) write the state but call no "
                f"chain witness *_txn: {silent}"
            )

    def test_route_closures_reach_the_funnels(self) -> None:
        """The three watch routes and config_save call the funnels by name — the
        positive half of arm 1, so its 'nothing outside a funnel' is not true only
        because the routes stopped writing at all."""
        callers: dict[str, set[str]] = {}
        for _p, rel, tree in walk_src("web/routers"):
            for n in ast.walk(tree):
                if isinstance(n, ast.Call):
                    f = n.func
                    nm = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                    if nm in {"record_watch_group_save", "record_watch_group_delete",
                              "record_runtime_settings_change"}:
                        callers.setdefault(nm, set()).add(
                            f"{rel}::{enclosing_qualified_name(n)}")
        assert callers.get("record_watch_group_save", set()) >= {
            "web/routers/ui/profile.py::profile_watches_save_new._save_and_audit",
            "web/routers/ui/profile.py::profile_watches_save_existing._save",
        }, callers
        assert "web/routers/ui/profile.py::profile_watches_delete._delete" in callers.get(
            "record_watch_group_delete", set()), callers
        assert ("web/routers/ui/admin.py::config_save._save_runtime_settings_atomic"
                in callers.get("record_runtime_settings_change", set())), callers

    # -- teeth -------------------------------------------------------------

    def test_teeth_watch_direct_call_outside_funnel(self) -> None:
        ww = watch_writers()
        assert_pin_has_teeth(
            lambda t: out_of_funnel(t, "web/routers/ui/x.py", ww, home=_WATCH_HOME),
            "def _save(db):\n    return save_watch_group_txn(db, user_id=1)\n",
            "def _save(db):\n    return record_watch_group_save(db, actor_user_id=1)\n",
        )

    def test_teeth_watch_db_call_seam_and_alias(self) -> None:
        ww = watch_writers()
        det = lambda t: out_of_funnel(t, "web/routers/ui/x.py", ww, home=_WATCH_HOME)
        assert_pin_has_teeth(det, "async def h(db, w):\n    await db_call(_w.upsert_watch, db, w)\n")
        assert_pin_has_teeth(
            det,
            "from email_triage.web.email_watches import delete_watch as _dw\n"
            "def h(db):\n    _dw(db, 'x')\n",
        )

    def test_teeth_settings_key_resolution(self) -> None:
        det = lambda t: out_of_funnel(
            t, "web/routers/ui/x.py", _SETTINGS_WRITERS, home=_SETTINGS_HOME,
            key_is_runtime=True,
        )
        assert_pin_has_teeth(
            det,
            "def f(db, v):\n    set_setting(db, _RUNTIME_SETTINGS_KEY, v)\n",
            "def f(db, v):\n    set_setting(db, 'other_key', v)\n",
        )
        assert_pin_has_teeth(det, "def f(db, v):\n    set_setting(db, 'runtime_settings', v)\n")
        # DA-3: the Attribute key arm, the key= keyword arm, and delete_setting.
        assert_pin_has_teeth(det, "def f(db, v):\n    set_setting(db, _shared._RUNTIME_SETTINGS_KEY, v)\n")
        assert_pin_has_teeth(det, "def f(db, v):\n    set_setting(db, key=_RUNTIME_SETTINGS_KEY, value=v)\n")
        assert_pin_has_teeth(det, "def f(db):\n    delete_setting(db, 'runtime_settings')\n")
        assert_pin_has_teeth(det, "async def f(db, v):\n    await db_call(set_setting, db, _RUNTIME_SETTINGS_KEY, v)\n")

    def test_teeth_inside_a_funnel_is_admitted_only_in_an_emitter_module(self) -> None:
        src = (
            "@db_write\n@audit_emitter\n"
            "def f(conn, *, v):\n    set_setting_txn(conn, _RUNTIME_SETTINGS_KEY, v)\n"
        )
        tree = parse_source(src)
        assert not out_of_funnel(tree, "db/audit.py", _SETTINGS_WRITERS,
                                 home=_SETTINGS_HOME, key_is_runtime=True)
        assert out_of_funnel(tree, "web/routers/ui/x.py", _SETTINGS_WRITERS,
                             home=_SETTINGS_HOME, key_is_runtime=True), (
            "an @audit_emitter outside AUDIT_EMITTER_MODULES must not launder the write"
        )

    def test_teeth_watch_sql_variants_are_writers(self) -> None:
        """DA-4a + panel B2 landing: every listed DML spelling on
        email_watches makes a writer, including a schema prefix and a quoted or
        bracketed name; a read, and a different table whose name starts with
        email_watches, do not. The module docstring lists what is not seen."""
        for sql in ("INSERT OR REPLACE INTO email_watches VALUES (1)",
                    "REPLACE INTO email_watches VALUES (1)",
                    "UPDATE OR IGNORE email_watches SET enabled = 0",
                    "insert into email_watches values (1)",
                    'UPDATE "email_watches" SET enabled = 0',
                    "INSERT INTO main.email_watches VALUES (1)",
                    "DELETE FROM [email_watches] WHERE id = 1",
                    "DELETE FROM `email_watches` WHERE id = 1",
                    'UPDATE "main"."email_watches" SET enabled = 0'):
            tree = parse_source(f"def w(db):\n    db.execute({sql!r})\n")
            assert watch_writers(tree) == {"w"}, sql
        for sql in ("SELECT * FROM email_watches",
                    "DELETE FROM email_watches_archive WHERE id = 1"):
            tree = parse_source(f"def r(db):\n    db.execute({sql!r})\n")
            assert watch_writers(tree) == set(), sql

    def test_teeth_funnel_without_witness(self) -> None:
        ww = watch_writers()
        silent = parse_source(
            "@db_write\n@audit_emitter\n"
            "def f(conn, *, g):\n    save_watch_group_txn(conn, group_id=g)\n    conn.commit()\n"
        )
        assert funnels_and_witnessing(silent, ww) == {"f": False}
        via_helper = parse_source(
            "def _h(conn):\n    record_access_event_txn(conn)\n"
            "@db_write\n@audit_emitter\n"
            "def f(conn, *, g):\n    save_watch_group_txn(conn, group_id=g)\n    _h(conn)\n"
        )
        assert funnels_and_witnessing(via_helper, ww) == {"f": True}
