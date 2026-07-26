"""run18 #6 (env-token half) — ops-token env-read funnel pin (PD#1/#2).

The ``ET_HEALTH_OPS_TOKEN`` ops-bypass secret was read raw, three times, with no
reader SSOT:

  - ``web/routers/health.py``  — ``/health/detail`` admin-bypass
  - ``web/routers/backup.py``  — ``/ops/db-backup`` loopback trigger
  - ``cli.py``                 — the ``backup now`` CLI trigger

The auth DECISION (``_ops_token_authorized``: ``.strip()`` + length floor +
loopback gate + constant-time compare) was ALREADY one SSOT; what was missing is
the thin READER SSOT for the raw env read. ``health._read_ops_token()`` is now
that one reader; this **count-agnostic** pin bans a raw env read of the token NAME
anywhere except ``_read_ops_token``'s own body, so a fourth un-funnelled read can't
re-introduce the divergence (the census's secret-read net was ``SecretsProvider``-
scoped and missed all three of these). §164.312(d)+(a)(1) credential-handling
hygiene / drift-prevention — NOT a live defect.

WHY a funnel matters: a single literal env-var NAME means a future rename / alias
is a one-line change. ``test_ops_token_env_name_is_single_literal`` cross-checks
that ``_read_ops_token`` reads exactly the one expected NAME, so the banned-literal
constant here and the SSOT reader cannot drift apart (and the net can't silently go
empty — fail-closed at the meta level).

Detects every env-read shape (``os.environ.get`` / ``os.getenv`` / bare ``getenv``
/ ``os.environ[...]`` subscript, via ``os.environ`` or a bare ``environ``) keyed on
the literal token name — not just the ``.get`` form the census happened to spot.
Function-keyed allow-list (run18 #2 lesson: ``(relpath, enclosing_fn)``, never
file-level which masks a sibling, never lineno which breaks on an unrelated shift).
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    enclosing_fn,
    parse_module,
    parse_source,
    walk_src,
)

# The ops-token env-var NAME — a single literal (no alias). Cross-checked against
# the SSOT reader by test_ops_token_env_name_is_single_literal so this constant and
# health._read_ops_token cannot drift in the name.
_TOKEN_ENV_NAME = "ET_HEALTH_OPS_TOKEN"

# The ONE sanctioned reader: this (file, function) is the funnel; a raw read here IS
# the SSOT. Everything else routes through ``_read_ops_token()``.
_READER_FILE = "web/routers/health.py"
_READER_FN = "_read_ops_token"


def _is_environ(node: ast.AST) -> bool:
    """``os.environ`` (Attribute) or a bare ``environ`` (Name) — the mapping the
    ``.get`` / subscript forms read from."""
    return (isinstance(node, ast.Attribute) and node.attr == "environ") or (
        isinstance(node, ast.Name) and node.id == "environ"
    )


def _str_const(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _env_read_key(node: ast.AST) -> str | None:
    """If ``node`` reads a STRING-LITERAL-keyed value out of the process
    environment, return that key; else ``None``. Covers every spelling:
      * ``os.environ.get(KEY, ...)`` / ``environ.get(KEY, ...)``
      * ``os.getenv(KEY, ...)`` / bare ``getenv(KEY, ...)`` (``from os import getenv``)
      * ``os.environ[KEY]`` / ``environ[KEY]`` (subscript)
    A non-literal key (a variable) returns ``None`` — it can't be the static
    token-name read this pin governs.
    """
    if isinstance(node, ast.Call):
        f = node.func
        key_arg = node.args[0] if node.args else None
        if isinstance(f, ast.Attribute):
            if f.attr == "getenv":  # os.getenv(KEY, ...)
                return _str_const(key_arg)
            if f.attr == "get" and _is_environ(f.value):  # os.environ.get / environ.get
                return _str_const(key_arg)
        elif isinstance(f, ast.Name) and f.id == "getenv":  # from os import getenv
            return _str_const(key_arg)
        return None
    if isinstance(node, ast.Subscript) and _is_environ(node.value):  # os.environ[KEY]
        return _str_const(node.slice)
    return None


def _violations_in_tree(tree: ast.AST, rel: str) -> list[str]:
    """Every raw token-name env read in ``tree`` (relpath ``rel``) that is NOT the
    sanctioned ``_read_ops_token`` reader. ONE detector core — shared by the real
    net (:func:`_find_violations`) and the teeth tests, so they can't fork."""
    out: list[str] = []
    for node in ast.walk(tree):
        if _env_read_key(node) != _TOKEN_ENV_NAME:
            continue
        fn = enclosing_fn(node)
        if rel == _READER_FILE and fn == _READER_FN:
            continue  # the ONE funnel
        out.append(f"{rel}:{node.lineno} ({fn})")
    return out


def _find_violations() -> list[str]:
    bad: list[str] = []
    for _path, rel, tree in walk_src():
        bad.extend(_violations_in_tree(tree, rel))
    return bad


def test_no_raw_ops_token_env_read_outside_reader():
    offenders = _find_violations()
    assert offenders == [], (
        f"Raw os.environ read of {_TOKEN_ENV_NAME!r} outside "
        f"{_READER_FILE}::{_READER_FN} — route through health._read_ops_token(): "
        f"{offenders}"
    )


def test_ops_token_env_name_is_single_literal():
    """The SSOT reader reads exactly the one expected env-var NAME (deliverable #3:
    no second spelling / alias). Keeps the banned-literal constant honest AND makes
    the ban fail-CLOSED — if the reader is emptied/renamed this fails loud rather
    than the net silently matching nothing."""
    tree = parse_module(SRC_ROOT / "web" / "routers" / "health.py")
    assert tree is not None
    reader = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == _READER_FN),
        None,
    )
    assert reader is not None, "health._read_ops_token reader SSOT is missing"
    keys = {k for node in ast.walk(reader) if (k := _env_read_key(node)) is not None}
    assert keys == {_TOKEN_ENV_NAME}, (
        f"_read_ops_token must read exactly {{{_TOKEN_ENV_NAME!r}}}; got {keys}"
    )


def test_pin_has_teeth():
    # A planted raw read at a NEW site (.get) → flagged.
    bad = parse_source(
        "import os\n"
        "def handler():\n"
        '    return os.environ.get("ET_HEALTH_OPS_TOKEN") or ""\n'
    )
    assert _violations_in_tree(bad, "web/routers/other.py") == ["web/routers/other.py:3 (handler)"]

    # os.getenv form → flagged.
    g = parse_source('import os\ndef h():\n    return os.getenv("ET_HEALTH_OPS_TOKEN", "")\n')
    assert _violations_in_tree(g, "cli.py") == ["cli.py:3 (h)"]

    # os.environ[...] subscript form → flagged.
    s = parse_source('import os\ndef h():\n    return os.environ["ET_HEALTH_OPS_TOKEN"]\n')
    assert _violations_in_tree(s, "cli.py") == ["cli.py:3 (h)"]

    # The reader form INSIDE _read_ops_token → NOT flagged (the funnel).
    reader = parse_source(
        "import os\n"
        "def _read_ops_token():\n"
        '    return os.environ.get("ET_HEALTH_OPS_TOKEN")\n'
    )
    assert _violations_in_tree(reader, _READER_FILE) == []
    # ...but the SAME read in a sibling fn of the reader FILE IS flagged (function-
    # keyed, not file-keyed — a file-level allow would mask this).
    sibling = parse_source(
        "import os\n"
        "def other():\n"
        '    return os.environ.get("ET_HEALTH_OPS_TOKEN")\n'
    )
    assert _violations_in_tree(sibling, _READER_FILE) == [f"{_READER_FILE}:3 (other)"]

    # A DIFFERENT env key → NOT flagged (no false positive on unrelated env reads).
    other_key = parse_source('import os\ndef h():\n    return os.environ.get("ET_BACKUP_TRIGGER_URL", "")\n')
    assert _violations_in_tree(other_key, "cli.py") == []

    # Routed through the SSOT (no raw env read) → NOT flagged.
    routed = parse_source("def h():\n    return _read_ops_token() or ''\n")
    assert _violations_in_tree(routed, "cli.py") == []
