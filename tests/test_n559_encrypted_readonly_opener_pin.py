"""N-559 (punch 556) — the encrypted read-only opener is really read-only.

Before this fix ``open_dedicated_encrypted_conn_readish`` opened a READ-WRITE
SQLCipher handle and ran the WAL pragmas, on a docstring claim that sqlcipher3
has no ``mode=ro``. sqlcipher3's ``connect`` takes ``uri=`` and passes
``SQLITE_OPEN_URI`` to ``sqlite3_open_v2`` (coleifer/sqlcipher3
``src/connection.c``), so ``file:...?mode=ro`` works under SQLCipher as it does
under stdlib sqlite3. The encrypted arm now routes through
``_make_encrypted_conn(..., read_only=True)``.

Structural half (runs everywhere, count-agnostic, over every file under src/):

  * S1 — every ``*.connect(...)`` whose first argument carries ``mode=ro``
    passes ``uri=True``. On a SQLite built without ``SQLITE_USE_URI`` the
    string is a plain filename, so the open is read-write on a different,
    newly created file (measured: Windows CPython, SQLite 3.50.4). Both
    shipped builds (SQLCipher/SQLite 3.53.3 and stdlib 3.46.1) set
    ``SQLITE_USE_URI`` (measured), so today S1 guards portability; it is the
    only thing that makes ``mode=ro`` mean read-only on every build.
  * S2 — every function whose name says read-only intent (``readish`` /
    ``readonly`` / ``read_only``) and calls ``_make_encrypted_conn`` passes
    ``read_only=True``, and never calls ``_apply_standard_pragmas`` (whose
    ``journal_mode`` pragma is a write).
  * S3 — the branch itself. In every function under src/ that takes a
    ``read_only`` parameter and calls ``*.connect``, the statements reachable
    with ``read_only=True`` (``if`` tests on ``read_only`` resolved, any other
    test taken both ways, a ``return``/``raise`` ending the path) must:
    reach at least one ``connect``; pass every reachable ``connect`` a first
    argument whose only ``mode=`` value is ``ro``, with ``uri=True``; and reach
    no ``_apply_standard_pragmas`` call and no ``PRAGMA journal_mode`` /
    ``wal_autocheckpoint`` / ``foreign_keys`` assignment. S1 and S2 stay green
    when the branch is inverted, when ``mode=rwc`` replaces ``mode=ro``, or when
    the pragmas run on the read-only path; S3 goes red on each (the teeth apply
    those three mutations to the real ``db/_engine.py`` source).
  * S4 — every value interpolated into a ``mode=ro`` connect URI is wrapped
    in ``quote(...)``. In a URI a raw ``?`` or ``#`` ends the path and a raw
    ``%`` starts an escape, so an unquoted path holding one opens a different
    file (measured on Windows CPython: a ``#`` in the directory name opened a
    new file named after the part before it).
  * S5 — the CALLER's branch (DA, panel B1, LOW-MED, fail-open on integrity).
    Every ``if``/conditional expression under src/ whose test reads
    ``read_only`` (a name or an attribute, optionally under ``not``) and whose
    arms call one of the dedicated-conn openers must call a read-only opener
    (``open_dedicated_conn_readish`` / ``open_dedicated_encrypted_conn_readish``)
    in its read-only-TRUE arm and never ``open_dedicated_conn`` there. A test
    that reads ``read_only`` in a compound expression is reported as
    unanalysable rather than passed. In-scope proof: ``cmd_audit_reconcile``
    (``--read-only`` promises ``mode=ro``) is among the branches found. Teeth:
    the real ``cli.py`` branch with its test inverted.
  * S5-route (db F-R3-11, runs everywhere, no sqlcipher3) — drives
    ``cli.main(["audit", "reconcile", "--db", <temp plaintext DB>, ...])`` with
    BOTH openers replaced by recording stand-ins: with ``--read-only`` ONLY
    ``open_dedicated_conn_readish`` is called, without it ONLY
    ``open_dedicated_conn``. Teeth: the real ``cmd_audit_reconcile`` with its
    branch test inverted, compiled and swapped in, makes both directions RED.
    ``audit verify`` and ``version.py`` open read-only unconditionally and are
    covered by S2 and the plaintext/encrypted runtime tests, so they are not
    routed here.

Runtime half (needs a real SQLCipher build). CI runs it:
``.github/workflows/tests.yml`` installs ``.[dev,encryption]`` (the PyPI
``sqlcipher3==0.6.2`` manylinux wheel; SQLCipher 4.12.0 community in the
2026-10-06 CI log), asserts ``PRAGMA cipher_version`` is 4.x, then runs
``pytest tests/``, then re-runs this file with ``-rA`` and fails on any skip,
so the CI log carries a PASSED line per arm. ``importorskip`` skips it only on a host without
``sqlcipher3``, such as the Windows workstation. For N-559 it was also run in a
throwaway container of the shipped image (the source-built SQLCipher):

  * R1 — INSERT and CREATE TABLE through ``open_dedicated_conn_readish`` under
    the encrypted context raise "attempt to write a readonly database", and
    still do after ``PRAGMA query_only = OFF``. That second half is what
    proves ``mode=ro``: with ``query_only`` on, a ``mode=rwc`` handle refuses
    the same writes with the same message (measured), so the first half alone
    cannot tell the two layers apart.
  * R2 — the reader sees a row a concurrent writer committed after it opened.
  * R3 — a wrong key fails at OPEN, not at the caller's first query.
  * R4 — a missing path raises and creates no file.
  * R5 — ``PRAGMA query_only`` reads 1 on the handle.
  * R6 — a read-only session leaves the main DB file byte-identical.
  * R7 — ``PRAGMA cipher_integrity_check`` runs on the handle (backup.py's
    snapshot verify depends on it).
  * R8 — sidecars a reader leaves on a quiescent WAL database are harmless: it
    creates ``-shm`` and an EMPTY ``-wal`` and leaves them (a read-only
    connection cannot run the close-time checkpoint that deletes them); the
    main file is unchanged, and the read-write opener then writes through
    them and a new reader sees the write. They are kept, not deleted:
    deleting a ``-wal``/``-shm`` is safe only when no other connection can
    have the file open, which the CLI and banner callers cannot know.
  * R9 — an encrypted DB whose directory name holds ``#``, ``?`` and ``%``
    opens read-only, reads, and refuses a write.

SCOPE — residual (DA, panel B1, LOW): S2 and S3 infer read-only INTENT from a
NAME. S2 keys on the function name (``readish``/``readonly``/``read_only``) and
S3 on a parameter named ``read_only``. A future read-only caller in an
ordinarily named function, with no ``read_only`` parameter, that opens through
``open_dedicated_conn`` (the read-write opener) is invisible to both. That shape
is live today: ``cli.py``'s ``audit reconcile`` handler imports both openers and
chooses by ``args.read_only``, an attribute, not a parameter, so neither arm
sees that choice. What the pin does guarantee is narrower: the read-only OPENER
itself cannot write, and any function that says it is read-only routes through it.
That ``audit reconcile`` instance is now covered by S5, which reads the branch
test (``args.read_only``) instead of the function name. The residual that
remains: a read-only caller that encodes its intent in neither a name, a
``read_only`` parameter, nor a ``read_only`` branch test.
S5 itself stays GREEN on five planted escapes (DA, panel B1, LOW): an alias
variable (``ro = args.read_only`` then ``if ro:``); a ternary choosing a
function REFERENCE (``opener = open_dedicated_conn_readish if
args.read_only else open_dedicated_conn``, called later); a dict dispatch keyed
on ``read_only``; ``getattr(args, "read_only")``; and a renamed flag. None of
the five exists in src/ (checked 2026-10-02: a grep for the alias, ``getattr``,
dict-key and function-reference shapes, positive-controlled 4/4 on planted
lines, finds 0; an AST scan for any if/ternary that calls
``open_dedicated_conn`` in one arm and ``open_dedicated_conn_readish`` in the
other finds exactly one, ``cli.py`` ``cmd_audit_reconcile``'s
``if args.read_only:``, which S5 covers. Widened to the engine's own
``_make_encrypted_conn`` / ``open_dedicated_encrypted_conn_readish``, the same
scan also finds the engine's encrypted/plaintext dispatch in ``_engine.py``,
which is not a caller choosing read-only). For that live instance the S5 route
test, which drives ``cli.main`` and records which opener runs, is the
behavioural backstop: it does not depend on the branch's shape.

R0 (runs everywhere): the encrypted read-only opener raises ``RuntimeError``
when no master key is stamped, before any connect.
P1 (runs everywhere, stdlib sqlite3): the PLAINTEXT arm of
``open_dedicated_conn_readish`` opens a DB whose directory name holds ``#`` and
``%`` (``?`` is not a legal Windows filename character), reads it, refuses a
write, and creates no stray file next to that directory.
"""
from __future__ import annotations

import ast
import hashlib
import re
import sys
from pathlib import Path

import pytest

from _pin_harness import (
    SRC_ROOT,
    annotate_parents,
    assert_pin_has_teeth,
    iter_src_files,
    parse_module,
    parse_source,
    relpath,
)

_RO_INTENT = re.compile(r"read_?only|readish", re.IGNORECASE)


def _first_arg_has_mode_ro(call: ast.Call) -> bool:
    if not call.args:
        return False
    arg = call.args[0]
    parts: list[ast.AST] = list(arg.values) if isinstance(arg, ast.JoinedStr) else [arg]
    return any(
        isinstance(p, ast.Constant) and isinstance(p.value, str) and "mode=ro" in p.value
        for p in parts
    )


def _kw_is_true(call: ast.Call, name: str) -> bool:
    return any(
        kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in call.keywords
    )


def _call_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """``{local name: original name}`` for every ``import X as Y`` and
    ``from M import X as Y`` in ``tree``. A name-keyed predicate reads the local
    name, so ``from ..._engine import _make_encrypted_conn as op`` hid the opener
    from it (panel F, F8: the bake-overlay INVARIANT 3 returned [] on it)."""
    out: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                if a.asname:
                    out[a.asname] = a.name.rsplit(".", 1)[-1] if isinstance(n, ast.ImportFrom) else a.name
    return out


def _resolved_call_name(call: ast.Call, aliases: dict[str, str]) -> str:
    """:func:`_call_name` with import aliases resolved. ``""`` for a computed
    callee (``getattr(m, "connect")(...)``, a subscript, a call result)."""
    f = call.func
    if isinstance(f, ast.Name):
        return aliases.get(f.id, f.id)
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _is_dynamic_call(call: ast.Call) -> bool:
    """A call whose callee is computed (``getattr(...)(...)`` and the like):
    no name-keyed predicate can say what it opens, so callers treat it as
    unanalysable (a violation), never as a pass."""
    return not isinstance(call.func, (ast.Name, ast.Attribute))


#: The names that open (or migrate) a SQLite/SQLCipher DB, matched in full
#: against a resolved call name. Callers hold an ALLOW-list inside this set
#: (panel F, F8), so a new opener is a violation until it is shown read-only.
#: ``Connection`` is the constructor form (``sqlite3.Connection(p)``,
#: ``sqlcipher3.dbapi2.Connection(p)``, ``apsw.Connection(p)``; panel F r2,
#: DA-b): the resolved name of an attribute call is its last part, so all
#: three resolve to it, and no read-only form of it is allowed.
_DB_OPENER_NAME = re.compile(
    r"(?:\w+_)?connect|open_\w*conn\w*|_make_\w*conn\w*|init_db\w*|run_migrations|_cli_open_config_db"
    r"|Connection"
)


def _ro_open_allowed(call: ast.Call, name: str) -> bool:
    """True when the opener call ``name`` is a KNOWN read-only open: a readish
    opener, ``_make_encrypted_conn(..., read_only=True)``, or
    ``connect(<mode=ro literal>, uri=True)``."""
    if name in _RO_OPENERS:
        return True
    if name == "_make_encrypted_conn":
        return _kw_is_true(call, "read_only")
    if name == "connect":
        return _first_arg_has_mode_ro(call) and _kw_is_true(call, "uri")
    return False


def _mode_ro_without_uri(tree: ast.AST) -> list[int]:
    """S1 detector: line numbers of ``connect(<mode=ro>, ...)`` without ``uri=True``."""
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _call_name(node) == "connect"
        and _first_arg_has_mode_ro(node)
        and not _kw_is_true(node, "uri")
    ]


def _mode_ro_connect_sites(tree: ast.AST) -> list[int]:
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _call_name(node) == "connect"
        and _first_arg_has_mode_ro(node)
    ]


def _ro_intent_fns(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _RO_INTENT.search(node.name):
            yield node


def _ro_fns_opening_rw(tree: ast.AST) -> list[str]:
    """S2 detector: read-only-intent functions that open the encrypted DB
    read-write or run the standard (writing) pragma set."""
    bad: list[str] = []
    for fn in _ro_intent_fns(tree):
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name == "_make_encrypted_conn" and not _kw_is_true(node, "read_only"):
                bad.append(f"{fn.name}:{node.lineno} _make_encrypted_conn without read_only=True")
            elif name == "_apply_standard_pragmas":
                bad.append(f"{fn.name}:{node.lineno} _apply_standard_pragmas")
    return bad


def _ro_fns_calling_encrypted_opener(tree: ast.AST) -> list[str]:
    return [
        fn.name
        for fn in _ro_intent_fns(tree)
        if any(
            isinstance(n, ast.Call) and _call_name(n) == "_make_encrypted_conn"
            for n in ast.walk(fn)
        )
    ]


_RO_WRITE_PRAGMA = re.compile(
    r"PRAGMA\s+(journal_mode|wal_autocheckpoint|foreign_keys)\s*=", re.IGNORECASE
)


def _ro_value(test: ast.expr):
    """Truth value of an ``if`` test when ``read_only`` is True, or None when
    the test does not depend on ``read_only`` alone (then both arms are live)."""
    if isinstance(test, ast.Name) and test.id == "read_only":
        return True
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = _ro_value(test.operand)
        return None if inner is None else not inner
    if (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "read_only"
        and len(test.ops) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and isinstance(test.comparators[0].value, bool)
    ):
        same = test.comparators[0].value is True
        if isinstance(test.ops[0], (ast.Is, ast.Eq)):
            return same
        if isinstance(test.ops[0], (ast.IsNot, ast.NotEq)):
            return not same
    return None


def _calls_in(node: ast.AST) -> list[ast.Call]:
    """Calls in ``node``, not descending into nested function or class bodies."""
    out: list[ast.Call] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur is not node and isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(cur, ast.Call):
            out.append(cur)
        stack.extend(ast.iter_child_nodes(cur))
    return out


def _ro_path_calls(stmts: list[ast.stmt]) -> tuple[list[ast.Call], bool]:
    """Calls reachable through ``stmts`` with ``read_only=True``, and whether
    every path through them ends in ``return``/``raise``."""
    calls: list[ast.Call] = []
    for st in stmts:
        if isinstance(st, (ast.Return, ast.Raise)):
            calls += _calls_in(st)
            return calls, True
        if isinstance(st, ast.If):
            calls += _calls_in(st.test)
            v = _ro_value(st.test)
            arms = [st.body] if v is True else [st.orelse] if v is False else [st.body, st.orelse]
            ends = []
            for arm in arms:
                c, e = _ro_path_calls(arm)
                calls += c
                ends.append(e)
            if all(ends):
                return calls, True
            continue
        if isinstance(st, ast.Try):
            for block in [st.body, st.orelse, st.finalbody] + [h.body for h in st.handlers]:
                calls += _ro_path_calls(block)[0]
            continue
        if isinstance(st, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            if isinstance(st, (ast.For, ast.AsyncFor)):
                calls += _calls_in(st.iter)
            elif isinstance(st, ast.While):
                calls += _calls_in(st.test)
            else:
                for item in st.items:
                    calls += _calls_in(item.context_expr)
            calls += _ro_path_calls(st.body)[0]
            calls += _ro_path_calls(getattr(st, "orelse", []))[0]
            continue
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        calls += _calls_in(st)
    return calls, False


def _mode_values(call: ast.Call) -> list[str]:
    if not call.args:
        return []
    arg = call.args[0]
    parts = list(arg.values) if isinstance(arg, ast.JoinedStr) else [arg]
    text = "".join(
        p.value for p in parts if isinstance(p, ast.Constant) and isinstance(p.value, str)
    )
    return re.findall(r"[?&]mode=([A-Za-z]+)", text)


def _read_only_fns(tree: ast.AST):
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        a = fn.args
        if "read_only" not in [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]:
            continue
        if any(_call_name(c) == "connect" for c in _calls_in(fn)):
            yield fn


def _ro_branch_violations(tree: ast.AST) -> list[str]:
    """S3 detector."""
    bad: list[str] = []
    for fn in _read_only_fns(tree):
        calls, _ = _ro_path_calls(fn.body)
        connects = [c for c in calls if _call_name(c) == "connect"]
        if not connects:
            bad.append(f"{fn.name}: no connect reachable with read_only=True")
        for c in connects:
            modes = _mode_values(c)
            if modes != ["ro"]:
                bad.append(f"{fn.name}:{c.lineno} connect modes {modes or 'none'} with read_only=True")
            if not _kw_is_true(c, "uri"):
                bad.append(f"{fn.name}:{c.lineno} connect without uri=True with read_only=True")
        for c in calls:
            if _call_name(c) == "_apply_standard_pragmas":
                bad.append(f"{fn.name}:{c.lineno} _apply_standard_pragmas reachable with read_only=True")
            for a in c.args:
                parts = list(a.values) if isinstance(a, ast.JoinedStr) else [a]
                for p in parts:
                    if isinstance(p, ast.Constant) and isinstance(p.value, str) and _RO_WRITE_PRAGMA.search(p.value):
                        bad.append(f"{fn.name}:{c.lineno} write pragma reachable with read_only=True")
    return bad


def _is_quote_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node) == "quote"


def _unquoted_mode_ro_paths(tree: ast.AST) -> list[int]:
    """S4 detector: ``connect(f"...{x}...mode=ro")`` where some ``{x}`` is not ``quote(...)``."""
    bad: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _call_name(node) == "connect" and _first_arg_has_mode_ro(node)):
            continue
        arg = node.args[0]
        if isinstance(arg, ast.JoinedStr) and any(
            isinstance(v, ast.FormattedValue) and not _is_quote_call(v.value) for v in arg.values
        ):
            bad.append(node.lineno)
    return bad


_RW_OPENER = "open_dedicated_conn"
_RO_OPENERS = frozenset({"open_dedicated_conn_readish", "open_dedicated_encrypted_conn_readish"})


def _ro_test_polarity(test: ast.expr):
    """True if the test is ``X``, False if ``not X`` (X a ``read_only`` name or
    attribute), None if it reads ``read_only`` in any other shape, and the
    string "absent" if it does not read ``read_only`` at all."""
    def is_ro(n):
        return (isinstance(n, ast.Name) and n.id == "read_only") or (
            isinstance(n, ast.Attribute) and n.attr == "read_only"
        )
    if is_ro(test):
        return True
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and is_ro(test.operand):
        return False
    return None if any(is_ro(n) for n in ast.walk(test)) else "absent"


def _arm_calls(arm) -> set[str]:
    nodes = arm if isinstance(arm, list) else [arm]
    return {_call_name(c) for n in nodes for c in _calls_in(n)}


def _opener_branches(tree: ast.AST):
    """(node, polarity, true_arm_calls) for every read_only branch whose arms call an opener."""
    openers = _RO_OPENERS | {_RW_OPENER}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.If, ast.IfExp)):
            continue
        pol = _ro_test_polarity(node.test)
        if pol == "absent":
            continue
        body, orelse = node.body, node.orelse
        if not (_arm_calls(body) | _arm_calls(orelse)) & openers:
            continue
        true_arm = body if pol is not False else orelse
        yield node, pol, _arm_calls(true_arm)


def _ro_branch_opener_violations(tree: ast.AST) -> list[str]:
    """S5 detector."""
    bad: list[str] = []
    for node, pol, calls in _opener_branches(tree):
        if pol is None:
            bad.append(f"{node.lineno}: read_only branch test is not analysable: {ast.unparse(node.test)}")
            continue
        if _RW_OPENER in calls:
            bad.append(f"{node.lineno}: read_only arm calls {_RW_OPENER}")
        if not calls & _RO_OPENERS:
            bad.append(f"{node.lineno}: read_only arm calls no read-only opener")
    return bad


def _scan(detector) -> dict[str, list]:
    out: dict[str, list] = {}
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        annotate_parents(tree)
        hits = detector(tree)
        if hits:
            out[relpath(path)] = hits
    return out


# ---------------------------------------------------------------------------
# Structural (S1, S2) + teeth
# ---------------------------------------------------------------------------


def test_s1_every_mode_ro_connect_passes_uri_true():
    # In-scope proof: the scan must actually see mode=ro connect sites, or a
    # green result means nothing.
    assert _scan(_mode_ro_connect_sites), "S1 scanned no mode=ro connect site"
    offenders = _scan(_mode_ro_without_uri)
    assert not offenders, f"mode=ro connect without uri=True: {offenders}"


def test_s2_read_only_intent_functions_never_open_read_write():
    # In-scope proof: at least one read-only-intent function opens the
    # encrypted DB (the sanctioned one), so S2 is not vacuous.
    assert _scan(_ro_fns_calling_encrypted_opener), (
        "S2 found no read-only-intent function calling _make_encrypted_conn"
    )
    offenders = _scan(_ro_fns_opening_rw)
    assert not offenders, f"read-only-intent function opens read-write: {offenders}"


def test_s1_has_teeth():
    assert_pin_has_teeth(
        _mode_ro_without_uri,
        bad_source='import sqlite3\nsqlite3.connect(f"file:{p}?mode=ro")\n',
        good_source='import sqlite3\nsqlite3.connect(f"file:{p}?mode=ro", uri=True)\n',
    )
    assert_pin_has_teeth(
        _mode_ro_without_uri,
        bad_source='import sqlcipher3\nsqlcipher3.dbapi2.connect("file:x.db?mode=ro", uri=False)\n',
    )


def test_s2_has_teeth():
    assert_pin_has_teeth(
        _ro_fns_opening_rw,
        bad_source=(
            "def open_x_readish(p):\n"
            "    return _make_encrypted_conn(p, k, purpose='triage')\n"
        ),
        good_source=(
            "def open_x_readish(p):\n"
            "    return _make_encrypted_conn(p, k, purpose='triage', read_only=True)\n"
        ),
    )
    assert_pin_has_teeth(
        _ro_fns_opening_rw,
        bad_source=(
            "def open_readonly(p):\n"
            "    c = _make_encrypted_conn(p, k, read_only=True)\n"
            "    _apply_standard_pragmas(c)\n"
            "    return c\n"
        ),
    )


def test_r0_no_stamped_key_raises_before_any_connect(tmp_path):
    from email_triage.db._engine import (
        open_dedicated_encrypted_conn_readish,
        reset_dedicated_conn_encryption,
    )

    reset_dedicated_conn_encryption()
    target = tmp_path / "never.db"
    with pytest.raises(RuntimeError, match="no master key stamped"):
        open_dedicated_encrypted_conn_readish(str(target))
    assert not target.exists()


def test_s3_read_only_branch_reaches_only_a_read_only_open():
    # In-scope proof: the scan must find the read_only opener, or green is empty.
    found = [
        fn.name
        for path in iter_src_files()
        if (tree := parse_module(path)) is not None
        for fn in _read_only_fns(tree)
    ]
    assert "_make_encrypted_conn" in found, f"S3 scanned no read_only opener: {found}"
    offenders = _scan(_ro_branch_violations)
    assert not offenders, f"read_only=True path is not read-only: {offenders}"


_ENGINE = SRC_ROOT / "db" / "_engine.py"

# The three mutants the static arms S1/S2 stay green on (panel B1 round 3, DA).
# Each is applied to the REAL ``_make_encrypted_conn`` source; S3 must flag it.
_S3_MUTANTS = {
    "inverted read_only branch": (
        "    if read_only:\n        conn = sqlcipher3.dbapi2.connect(",
        "    if not read_only:\n        conn = sqlcipher3.dbapi2.connect(",
    ),
    "mode=rwc instead of mode=ro": (
        '?mode=ro",',
        '?mode=rwc",',
    ),
    "standard pragmas on the read-only path": (
        # Inside the key-check ``try`` since punch 418 (a wrong key becomes a typed refusal).
        "        if not read_only:\n            _apply_standard_pragmas(conn)\n            return conn\n",
        "        _apply_standard_pragmas(conn)\n        if not read_only:\n            return conn\n",
    ),
}


def _mutate_fn(source: str, fn_name: str, old: str, new: str) -> str:
    tree = parse_source(source)
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == fn_name
    )
    lines = source.splitlines(keepends=True)
    start = sum(len(x) for x in lines[: fn.lineno - 1])
    end = sum(len(x) for x in lines[: fn.end_lineno])
    body = source[start:end]
    assert body.count(old) == 1, f"mutation anchor not found once in {fn_name}: {old!r}"
    return source[:start] + body.replace(old, new) + source[end:]


@pytest.mark.parametrize("label", sorted(_S3_MUTANTS))
def test_s3_has_teeth_on_the_real_opener(label):
    source = _ENGINE.read_text(encoding="utf-8")
    assert not _ro_branch_violations(parse_source(source)), "S3 red on the unmutated opener"
    old, new = _S3_MUTANTS[label]
    mutant = _mutate_fn(source, "_make_encrypted_conn", old, new)
    assert _ro_branch_violations(parse_source(mutant)), f"S3 missed mutant: {label}"


def test_s3_has_teeth_on_planted_shapes():
    good = (
        "def _open(p, *, read_only=False):\n"
        "    if read_only:\n"
        "        c = dbapi2.connect(f'file:{p}?mode=ro', uri=True)\n"
        "        c.execute('PRAGMA query_only = ON')\n"
        "        return c\n"
        "    c = dbapi2.connect(p)\n"
        "    c.execute('PRAGMA journal_mode = WAL')\n"
        "    return c\n"
    )
    # a write pragma inlined on the read-only path, not via the helper
    assert_pin_has_teeth(
        _ro_branch_violations,
        bad_source=good.replace("PRAGMA query_only = ON", "PRAGMA journal_mode = WAL"),
        good_source=good,
    )
    # uri=True dropped on the read-only path
    assert_pin_has_teeth(
        _ro_branch_violations,
        bad_source=good.replace("?mode=ro', uri=True)", "?mode=ro')"),
    )
    # the read-only path reaches no connect at all (vacuity guard)
    assert_pin_has_teeth(
        _ro_branch_violations,
        bad_source=(
            "def _open(p, *, read_only=False):\n"
            "    if read_only:\n"
            "        return None\n"
            "    return dbapi2.connect(p)\n"
        ),
    )


def test_s4_every_mode_ro_uri_quotes_its_path():
    assert _scan(_mode_ro_connect_sites), "S4 scanned no mode=ro connect site"
    offenders = _scan(_unquoted_mode_ro_paths)
    assert not offenders, f"mode=ro URI with an unquoted path: {offenders}"


def test_s4_has_teeth():
    assert_pin_has_teeth(
        _unquoted_mode_ro_paths,
        bad_source='sqlite3.connect(f"file:{p}?mode=ro", uri=True)\n',
        good_source='sqlite3.connect(f"file:{quote(p, safe=\'/\')}?mode=ro", uri=True)\n',
    )
    source = _ENGINE.read_text(encoding="utf-8")
    mutant = _mutate_fn(
        source, "_make_encrypted_conn",
        "f\"file:{quote(db_path, safe='/')}?mode=ro\",", "f\"file:{db_path}?mode=ro\",",
    )
    assert _unquoted_mode_ro_paths(parse_source(mutant)), "S4 missed the unquoted real opener"


_CLI = SRC_ROOT / "cli.py"


def test_s5_read_only_branches_open_read_only():
    found = {
        relpath(path): [n.lineno for n, _, _ in _opener_branches(tree)]
        for path in iter_src_files()
        if (tree := parse_module(path)) is not None
    }
    found = {k: v for k, v in found.items() if v}
    cli_tree = parse_source(_CLI.read_text(encoding="utf-8"))
    reconcile = next(
        n for n in ast.walk(cli_tree)
        if isinstance(n, ast.FunctionDef) and n.name == "cmd_audit_reconcile"
    )
    assert any(True for _ in _opener_branches(reconcile)), (
        f"S5 did not find the cmd_audit_reconcile opener branch; found {found}"
    )
    offenders = _scan(_ro_branch_opener_violations)
    assert not offenders, f"read_only branch opens read-write: {offenders}"


def test_s5_has_teeth_on_the_real_cli_branch():
    source = _CLI.read_text(encoding="utf-8")
    assert not _ro_branch_opener_violations(parse_source(source))
    for old, new in (
        ("        if args.read_only:\n            conn = open_dedicated_conn_readish(",
         "        if not args.read_only:\n            conn = open_dedicated_conn_readish("),
        ("            conn = open_dedicated_conn_readish(str(db_path))\n        else:\n"
         "            conn = open_dedicated_conn(str(db_path), check_same_thread=False)",
         "            conn = open_dedicated_conn(str(db_path), check_same_thread=False)\n        else:\n"
         "            conn = open_dedicated_conn_readish(str(db_path))"),
    ):
        mutant = _mutate_fn(source, "cmd_audit_reconcile", old, new)
        assert _ro_branch_opener_violations(parse_source(mutant)), f"S5 missed: {new[:50]!r}"


class _OpenRecorded(Exception):
    """Raised by the opener stand-ins so the route stops right after the open."""


def _reconcile_route_calls(monkeypatch, tmp_path, *, read_only: bool, handler=None) -> list[str]:
    import sqlite3

    from email_triage import cli
    from email_triage.db import _engine

    calls: list[str] = []

    def stand_in(name):
        def _open(*_a, **_k):
            calls.append(name)
            raise _OpenRecorded(name)
        return _open

    for name in ("open_dedicated_conn", "open_dedicated_conn_readish"):
        monkeypatch.setattr(_engine, name, stand_in(name))
    if handler is not None:
        monkeypatch.setattr(cli, "cmd_audit_reconcile", handler)
    db = tmp_path / f"route-{read_only}.db"
    sqlite3.connect(str(db)).close()
    argv = ["audit", "reconcile", "--db", str(db)] + (["--read-only"] if read_only else [])
    rc = cli.main(argv)
    assert rc == 2, f"route did not stop at the open (rc={rc})"
    return calls


@pytest.mark.parametrize(
    "read_only, expected",
    [(True, ["open_dedicated_conn_readish"]), (False, ["open_dedicated_conn"])],
)
def test_s5_route_reconcile_opens_by_flag(monkeypatch, tmp_path, read_only, expected):
    assert _reconcile_route_calls(monkeypatch, tmp_path, read_only=read_only) == expected


def test_s5_route_has_teeth_on_the_real_cli_branch(monkeypatch, tmp_path):
    import inspect
    import textwrap

    from email_triage import cli

    source = textwrap.dedent(inspect.getsource(cli.cmd_audit_reconcile))
    old = "if args.read_only:\n            conn = open_dedicated_conn_readish("
    assert source.count(old) == 1, "route-teeth anchor not found once in cmd_audit_reconcile"
    mutant_src = source.replace(old, "if not args.read_only:\n            conn = open_dedicated_conn_readish(")
    glb = dict(vars(cli))
    exec(compile(mutant_src, cli.__file__, "exec"), glb)
    mutant = glb["cmd_audit_reconcile"]
    assert _reconcile_route_calls(monkeypatch, tmp_path, read_only=True, handler=mutant) == [
        "open_dedicated_conn"
    ], "route test would not catch --read-only opening read-write"
    assert _reconcile_route_calls(monkeypatch, tmp_path, read_only=False, handler=mutant) == [
        "open_dedicated_conn_readish"
    ]


def test_s5_has_teeth_on_planted_shapes():
    good = "c = open_dedicated_conn_readish(p) if args.read_only else open_dedicated_conn(p)\n"
    assert_pin_has_teeth(
        _ro_branch_opener_violations,
        bad_source="c = open_dedicated_conn(p) if args.read_only else open_dedicated_conn_readish(p)\n",
        good_source=good,
    )
    assert_pin_has_teeth(  # compound test: unanalysable, reported
        _ro_branch_opener_violations,
        bad_source="if args.read_only and x:\n    c = open_dedicated_conn_readish(p)\nelse:\n    c = open_dedicated_conn(p)\n",
    )
    assert_pin_has_teeth(  # read-only arm opens nothing read-only
        _ro_branch_opener_violations,
        bad_source="if read_only:\n    c = None\nelse:\n    c = open_dedicated_conn(p)\n",
    )


def test_p1_plaintext_arm_opens_a_path_with_uri_metacharacters(tmp_path):
    import sqlite3

    from email_triage.db._engine import open_dedicated_conn_readish, reset_dedicated_conn_encryption

    reset_dedicated_conn_encryption()
    odd = tmp_path / "we #ird%25dir"
    odd.mkdir()
    db = odd / "p1.db"
    c = sqlite3.connect(str(db))
    c.execute("CREATE TABLE t (a)")
    c.execute("INSERT INTO t VALUES (1)")
    c.commit()
    c.close()
    before = sorted(x.name for x in tmp_path.iterdir())
    ro = open_dedicated_conn_readish(str(db))
    try:
        assert ro.execute("SELECT count(*) FROM t").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ro.execute("INSERT INTO t VALUES (2)")
    finally:
        ro.close()
    assert sorted(x.name for x in tmp_path.iterdir()) == before


# ---------------------------------------------------------------------------
# Runtime (R1..R7) — real SQLCipher only
# ---------------------------------------------------------------------------

MASTER_KEY = "n559-readonly-opener-master-key-0123456789abcdef"
WRONG_KEY = "n559-readonly-opener-WRONG-key-0123456789abcdef"


@pytest.fixture
def sqlcipher():
    return pytest.importorskip("sqlcipher3")


@pytest.fixture
def enc_db(sqlcipher, tmp_path):
    """A real WAL-mode encrypted DB built by the RW opener, with one row, and
    the encrypted dedicated-conn context stamped. The RW conn is yielded open
    so tests can write concurrently; it is closed on teardown."""
    from email_triage.db._engine import (
        _make_encrypted_conn,
        reset_dedicated_conn_encryption,
        set_dedicated_conn_encryption,
    )

    path = tmp_path / "n559.db"
    rw = _make_encrypted_conn(str(path), MASTER_KEY, purpose="triage")
    rw.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    rw.execute("INSERT INTO t (v) VALUES ('one')")
    rw.commit()
    assert rw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    set_dedicated_conn_encryption(encrypted=True, master_key=MASTER_KEY)
    try:
        yield path, rw
    finally:
        reset_dedicated_conn_encryption()
        rw.close()


def _open_ro(path: Path):
    from email_triage.db._engine import open_dedicated_conn_readish

    return open_dedicated_conn_readish(str(path))


def test_r1_writes_through_the_readonly_handle_fail(sqlcipher, enc_db):
    path, _rw = enc_db
    ro = _open_ro(path)
    try:
        for sql in ("INSERT INTO t (v) VALUES ('x')", "CREATE TABLE u (a)"):
            with pytest.raises(sqlcipher.dbapi2.OperationalError, match="readonly"):
                ro.execute(sql)
        ro.rollback()
        ro.execute("PRAGMA query_only = OFF")
        for sql in ("INSERT INTO t (v) VALUES ('x')", "CREATE TABLE u (a)"):
            with pytest.raises(sqlcipher.dbapi2.OperationalError, match="readonly"):
                ro.execute(sql)
    finally:
        ro.close()


def test_r2_reader_sees_rows_committed_after_it_opened(enc_db):
    path, rw = enc_db
    ro = _open_ro(path)
    try:
        assert ro.execute("SELECT count(*) FROM t").fetchone()[0] == 1
        rw.execute("INSERT INTO t (v) VALUES ('two')")
        rw.commit()
        assert ro.execute("SELECT count(*) FROM t").fetchone()[0] == 2
    finally:
        ro.close()


def test_r3_wrong_key_fails_at_open(sqlcipher, enc_db):
    from email_triage.db._engine import (
        EncryptedDbKeyRefused,
        set_dedicated_conn_encryption,
    )

    path, _rw = enc_db
    set_dedicated_conn_encryption(encrypted=True, master_key=WRONG_KEY)
    # Punch 418: a wrong key is refused at open with the typed error, chained to
    # sqlcipher3's own DatabaseError, so the refusal still comes from the driver.
    with pytest.raises(EncryptedDbKeyRefused) as info:
        _open_ro(path)
    assert isinstance(info.value.__cause__, sqlcipher.dbapi2.DatabaseError)


def test_r4_missing_path_raises_and_creates_nothing(sqlcipher, enc_db, tmp_path):
    missing = tmp_path / "absent.db"
    with pytest.raises(sqlcipher.dbapi2.OperationalError):
        _open_ro(missing)
    assert not missing.exists()


def test_r5_query_only_is_set(enc_db):
    path, _rw = enc_db
    ro = _open_ro(path)
    try:
        assert ro.execute("PRAGMA query_only").fetchone()[0] == 1
    finally:
        ro.close()


def test_r6_readonly_session_leaves_main_file_unchanged(enc_db):
    path, rw = enc_db
    rw.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    ro = _open_ro(path)
    try:
        ro.execute("SELECT count(*) FROM t").fetchone()
        ro.execute("PRAGMA integrity_check").fetchall()
    finally:
        ro.close()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_r7_cipher_integrity_check_runs_on_the_handle(enc_db):
    path, _rw = enc_db
    ro = _open_ro(path)
    try:
        assert ro.execute("PRAGMA cipher_integrity_check").fetchall() == []
    finally:
        ro.close()


def test_r8_sidecars_left_on_a_quiescent_db_are_harmless(enc_db):
    from email_triage.db._engine import _make_encrypted_conn

    path, rw = enc_db
    rw.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    rw.close()  # last connection: SQLite checkpoints and deletes -wal/-shm
    wal, shm = Path(f"{path}-wal"), Path(f"{path}-shm")
    assert not wal.exists() and not shm.exists(), "precondition: quiescent DB has no sidecars"
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    ro = _open_ro(path)
    try:
        assert ro.execute("SELECT count(*) FROM t").fetchone()[0] == 1
    finally:
        ro.close()
    assert wal.exists() and shm.exists(), "the reader is expected to leave both sidecars"
    assert wal.stat().st_size == 0, "a reader must never put frames in the -wal"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    rw2 = _make_encrypted_conn(str(path), MASTER_KEY, purpose="triage")
    try:
        rw2.execute("INSERT INTO t (v) VALUES ('after-reader')")
        rw2.commit()
        assert rw2.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        ro2 = _open_ro(path)
        try:
            assert ro2.execute("SELECT count(*) FROM t").fetchone()[0] == 2
        finally:
            ro2.close()
    finally:
        rw2.close()


def test_r9_encrypted_path_with_uri_metacharacters(sqlcipher, tmp_path):
    from email_triage.db._engine import (
        _make_encrypted_conn,
        reset_dedicated_conn_encryption,
        set_dedicated_conn_encryption,
    )

    # `?` is the URI query delimiter, so it stays wherever the filesystem allows it (Linux CI and
    # the image). Windows rejects `?` in a path (WinError 123, punch 923), so there the name keeps
    # the other URI metacharacters (`#`, `%25`, space) and still tests the quoting.
    odd = tmp_path / ("we #ird%25dir" if sys.platform == "win32" else "we #ird?dir%25")
    odd.mkdir()
    path = odd / "r9.db"
    rw = _make_encrypted_conn(str(path), MASTER_KEY, purpose="triage")
    rw.execute("CREATE TABLE t (a)")
    rw.execute("INSERT INTO t VALUES (1)")
    rw.commit()
    set_dedicated_conn_encryption(encrypted=True, master_key=MASTER_KEY)
    try:
        before = sorted(x.name for x in tmp_path.iterdir())
        ro = _open_ro(path)
        try:
            assert ro.execute("SELECT count(*) FROM t").fetchone()[0] == 1
            with pytest.raises(sqlcipher.dbapi2.OperationalError, match="readonly"):
                ro.execute("INSERT INTO t VALUES (2)")
        finally:
            ro.close()
        assert sorted(x.name for x in tmp_path.iterdir()) == before
    finally:
        reset_dedicated_conn_encryption()
        rw.close()
