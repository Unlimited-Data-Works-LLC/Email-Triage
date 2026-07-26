"""HWM-value SSOT pin (divergence census 2026-06-09, finding  / N-50).

A persisted high-water-mark value must carry ``uidvalidity`` alongside ``uid``.
IMAP UIDs are monotonic only within a UIDVALIDITY epoch; if the stored HWM omits
``uidvalidity`` the reset guard ``app._resolve_hwm_with_uidvalidity`` can't
compare epochs and a mailbox rebuild silently SKIPS every new message whose
reused UID is <= the stale mark (mail loss).

The first fix (b5bb862) only added the field to the operator "Set HWM" path and
pinned "the dict has the field" — a SYMPTOM pin. The real divergence is that the
unified poll, the IDLE watcher, AND the operator path all **hand-rolled** the HWM
dict literal; one of three omitted ``uidvalidity``. The complete fix routes ALL
HWM-value construction through one builder ``db.make_hwm_value(uid, uidvalidity)``
and pins the SSOT directly: **no raw HWM-dict literal (``{"uid", ...,
"updated_at"}``) may exist outside ``make_hwm_value``.** This is count-agnostic —
a property over every dict literal, not ``len(...) == N``.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

DB = SRC_ROOT / "web" / "db.py"
BUILDER = "make_hwm_value"


def _string_keys(d: ast.Dict) -> set[str]:
    return {
        k.value for k in d.keys
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }


def _hwm_dict_literal_lines(tree: ast.AST) -> list[int]:
    """Dict literals with the HWM shape (``uid`` + ``updated_at`` keys)."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict) and {"uid", "updated_at"} <= _string_keys(n):
            out.append(n.lineno)
    return out


def _builder_range(tree: ast.AST) -> tuple[int, int] | None:
    for n in ast.walk(tree):
        if (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == BUILDER):
            return (n.lineno, getattr(n, "end_lineno", n.lineno))
    return None


def test_no_raw_hwm_dict_literal_outside_builder():
    db_tree = parse_module(DB)
    rng = _builder_range(db_tree)
    assert rng, "make_hwm_value builder vanished from web/db.py"
    lo, hi = rng
    offenders = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        for lineno in _hwm_dict_literal_lines(tree):
            inside_builder = (p == DB and lo <= lineno <= hi)
            if not inside_builder:
                offenders.append(f"{relpath(p)}:{lineno}")
    assert not offenders, (
        "a raw high-water-mark dict literal ({'uid', ..., 'updated_at'}) outside "
        f"db.make_hwm_value: {offenders}. Build the value via "
        "make_hwm_value(uid, uidvalidity) so the uidvalidity epoch (the reset "
        "guard's input) can't be omitted — a hand-rolled literal that drops it "
        "silently loses mail after a UIDVALIDITY change (census /N-50)."
    )


def test_builder_emits_uidvalidity():
    """Guards the pin: the builder must still produce the uidvalidity key (else
    the SSOT is hollow)."""
    db_tree = parse_module(DB)
    rng = _builder_range(db_tree)
    assert rng
    lo, hi = rng
    keys = set()
    for n in ast.walk(db_tree):
        if (isinstance(n, ast.Dict) and lo <= n.lineno <= hi):
            keys |= _string_keys(n)
    assert {"uid", "uidvalidity", "updated_at"} <= keys


def test_builder_behaviour():
    from email_triage.web.db import make_hwm_value
    v = make_hwm_value(42, 7)
    assert v["uid"] == 42 and v["uidvalidity"] == 7 and "updated_at" in v
    # None uidvalidity (Gmail/O365) is preserved — the key is still present so
    # the guard sees "no epoch known" rather than a missing field.
    v2 = make_hwm_value(5, None)
    assert v2["uid"] == 5 and v2["uidvalidity"] is None and "uidvalidity" in v2


def test_pin_has_teeth(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "def f(db, k, uid):\n"
        "    set_setting(db, k, {'uid': uid, 'updated_at': now()})\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _hwm_dict_literal_lines(tree)


def test_pin_ignores_non_hwm_dicts(tmp_path):
    ok = tmp_path / "q.py"
    ok.write_text(
        "a = {'uid': 1}\n"
        "b = {'updated_at': 'x', 'name': 'y'}\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _hwm_dict_literal_lines(tree)
