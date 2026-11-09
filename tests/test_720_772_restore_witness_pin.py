"""Punches 720 and 772: structural pins over the restore-witness marker (backup.py / cli.py).

Two properties, each read over src on the shared harness (``_pin_harness.walk_src`` /
``iter_string_literals`` / ``assert_pin_has_teeth``), each with teeth:

1. ``_restore_marker_recorded`` decides on the parsed witness FIELDS: it ``json.loads`` the row
   and names ``marker``, ``cli_phase`` and ``cli_command``. A substring match over the whole
   ``extra_json`` takes any row that merely mentions the name and the phase as a witness
   (punch 772). It is NOT ``json_extract``: N-522's MEDIUM grade rests on src issuing no json1
   function (``test_n522_no_fts_or_json1_query_pin.py``), so the field match is made in Python.
2. Every key the CLI hands ``write_restore_witness_marker`` is in ``RESTORE_WITNESS_KEYS``. The
   writer silently DROPS an unlisted key, so a new marker field the CLI computes but the set
   omits is lost with no error (punch 720 added ``live_chain_head_ts``).

SCOPE: (1) reads the one named helper, not every ``extra_json`` reader in src; the SQL ``instr``
that narrows its scan is allowed because the decision is the parsed fields. (2) reads a dict
LITERAL argument at the call; a dict built elsewhere or a ``**`` spread is not followed.
"""
from __future__ import annotations

import ast

from _pin_harness import assert_pin_has_teeth, parse_source, walk_src

from email_triage.backup import RESTORE_WITNESS_KEYS

_WITNESS_FIELDS = ("marker", "cli_phase", "cli_command")
_WRITER = "write_restore_witness_marker"


def _function(tree, name: str):
    return next((n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)


def _field_match_gaps(tree) -> list[str]:
    """What ``_restore_marker_recorded`` lacks of a parsed-field decision (empty = sound)."""
    fn = _function(tree, "_restore_marker_recorded")
    if fn is None:
        return ["no _restore_marker_recorded"]
    out = []
    if not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "loads"
               and getattr(n.func.value, "id", None) == "json" for n in ast.walk(fn)):
        out.append("no json.loads of the row")
    names = {n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    out += [f"field {f!r} not read" for f in _WITNESS_FIELDS if f not in names]
    return out


def _unlisted_marker_keys(tree, allowed) -> list[str]:
    out = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and getattr(n.func, "attr", getattr(n.func, "id", None)) == _WRITER):
            continue
        for a in (*n.args, *(k.value for k in n.keywords)):
            if isinstance(a, ast.Dict):
                out += [k.value for k in a.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value not in allowed]
    return out


def test_the_marker_dedupe_decides_on_the_parsed_witness_fields():
    (tree,) = [t for _p, rel, t in walk_src() if rel == "backup.py"]
    assert not _field_match_gaps(tree), _field_match_gaps(tree)


def test_the_witness_field_pin_has_teeth():
    good = (
        "def _restore_marker_recorded(conn, name, phases):\n"
        "    for (raw,) in conn.execute('SELECT extra_json FROM t WHERE instr(extra_json, ?) > 0', (name,)):\n"
        "        d = json.loads(raw)\n"
        "        if d.get('marker') == name and d.get('cli_command') == 'restore' and d.get('cli_phase') in phases:\n"
        "            return True\n"
        "    return False\n")
    substring = (
        "def _restore_marker_recorded(conn, name, phases):\n"
        "    return conn.execute('SELECT 1 FROM t WHERE instr(extra_json, ?) > 0 AND instr(extra_json, ?) > 0',\n"
        "                        (name, phases[0])).fetchone() is not None\n")
    no_phase = good.replace(" and d.get('cli_phase') in phases", "")
    assert_pin_has_teeth(_field_match_gaps, substring, good)
    assert _field_match_gaps(parse_source(no_phase)) == ["field 'cli_phase' not read"]
    assert _field_match_gaps(parse_source("x = 1")) == ["no _restore_marker_recorded"]


def test_every_marker_key_the_cli_writes_is_in_the_set_the_writer_keeps():
    # Anti-vacuity: the CLI really calls the writer with a dict literal that has the 720 key.
    (cli,) = [t for _p, rel, t in walk_src() if rel == "cli.py"]
    keys = [k.value for n in ast.walk(cli) if isinstance(n, ast.Call)
            and getattr(n.func, "attr", getattr(n.func, "id", None)) == _WRITER
            for a in n.args if isinstance(a, ast.Dict) for k in a.keys if isinstance(k, ast.Constant)]
    assert "live_chain_head" in keys and "live_chain_head_ts" in keys, keys
    offenders = [f"{rel}: {k}" for _p, rel, tree in walk_src() for k in _unlisted_marker_keys(tree, RESTORE_WITNESS_KEYS)]
    assert not offenders, (
        "A key passed to write_restore_witness_marker is not in RESTORE_WITNESS_KEYS; the "
        "writer drops it silently:\n  " + "\n  ".join(offenders))


def test_the_marker_key_pin_has_teeth():
    allowed = frozenset({"a", "b"})
    bad = f"{_WRITER}(d, {{'a': 1, 'zzz': 2}})"
    good = f"{_WRITER}(d, {{'a': 1, 'b': 2}})"
    assert_pin_has_teeth(lambda t: _unlisted_marker_keys(t, allowed), bad, good)
