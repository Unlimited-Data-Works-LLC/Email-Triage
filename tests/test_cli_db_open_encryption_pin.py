"""Count-agnostic structural pin (N-129): a CLI handler must open the
*configured* DB encryption-aware, never via raw ``init_db``.

THE BUG THIS CATCHES
====================
``web.db.init_db`` is the PLAINTEXT opener (a bare ``sqlite3.connect``). On an
encrypted install (the default / HIPAA-class posture) opening the live DB with
it raises ``sqlite3.DatabaseError: file is not a database`` — the encrypted
bytes aren't a valid plaintext sqlite file. The CLI runs OUTSIDE the server
boot, so nothing stamps the dedicated-conn encryption context; a handler MUST
call :func:`email_triage.cli._cli_open_config_db` (which stamps + opens via the
shared encrypted-aware opener), never raw ``init_db(config.persistence.db_path)``.

N-129: ~6 handlers (style-profile, sent-mail-index, apikey, user, secrets, the
CLI audit auto-emit) opened raw and were silently broken on encrypted installs.
The bug surfaced live, mining a style profile on encrypted prod. **No pin caught
it** because the unit tests MOCK ``init_db`` (e.g. test_cli_audit.py) — they
never exercise the real encrypted open (the mock-the-boundary miss). This pin is
the structural backstop: it fails the build if any CLI handler opens the
configured DB via ``init_db`` again, regardless of how many handlers exist (a
property over every site, not ``len(X) == N``).

Why scoped to cli.py: the server boot (``web/app.py``) correctly branches
``init_db_encrypted`` vs ``init_db`` after stamping; the plaintext ``init_db``
there is the legitimate not-encrypted branch. The bug is specifically the CLI
surface opening the *configured* path raw without stamping. A temp/smoke-copy
``init_db(str(smoke))`` (verify-migrations) is on a throwaway path, not
``config.persistence.db_path``, so it is correctly NOT flagged.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, parse_source

CLI_PATH = SRC_ROOT / "cli.py"

# The SSOT funnel itself IS the one sanctioned branched open: it calls
# `init_db` / `init_db_encrypted` (mirroring the server boot) AFTER
# `_cli_stamp_db_encryption`, and every OTHER handler routes through it. Exempt
# it BY NAME (not by weakening the detector) — the sole allow-listed site, so
# green still proves teeth on every real handler.
_SSOT_FUNNEL = "_cli_open_config_db"


# N-336: widened to catch typo variants (`database_path`, `path`, etc.).
# The pre-N-336 pin required `attr == "db_path"` — so cli.py:1267's
# `_init_db(config.persistence.database_path)` (a typo — real attr is
# `db_path`) was UN-caught by the pin AND crashed at runtime with an
# AttributeError on the CLI verb's first invocation. Widen the AST match
# to ANY attribute on `config.persistence` — the SSOT rule is "route
# through _cli_open_config_db," so no attribute chain of that shape
# passed to init_db is legitimate outside the funnel.
def _is_config_db_path(node: ast.AST) -> bool:
    """True iff ``node`` is any attribute on ``config.persistence`` — e.g.
    ``config.persistence.db_path`` (canonical) OR
    ``config.persistence.database_path`` (a typo the pre-N-336 pin missed)."""
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "persistence"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "config"
    )


def _enclosing_fn_node(node: ast.AST):
    """Nearest enclosing FunctionDef NODE (parents annotated by parse_*)."""
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = getattr(cur, "_ph_parent", None)
    return None


def _config_path_local_names(fn: ast.AST) -> set[str]:
    """Local names in ``fn`` bound to ``config.persistence.db_path`` — directly
    (``p = config.persistence.db_path``) or via ``Path(config.persistence.db_path)``.
    Keeps the pin interprocedural-within-the-function: ``init_db(db_path)`` is
    caught when ``db_path`` traces to the configured path (PD#2 — key on the
    value's binding, not only the literal attribute chain at the call site)."""
    names: set[str] = set()
    for n in ast.walk(fn):
        if (
            isinstance(n, ast.Assign)
            and len(n.targets) == 1
            and isinstance(n.targets[0], ast.Name)
        ):
            val = n.value
            if _is_config_db_path(val):
                names.add(n.targets[0].id)
            elif (
                isinstance(val, ast.Call)
                and val.args
                and _is_config_db_path(val.args[0])
            ):
                names.add(n.targets[0].id)
    return names


def _find_offenders(tree: ast.AST) -> list[tuple[int, str]]:
    """``init_db(...)`` calls whose argument resolves to the configured DB path.
    Returns ``[(lineno, enclosing_fn_name), ...]``."""
    offenders: list[tuple[int, str]] = []
    for call in ast.walk(tree):
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "init_db"
            and call.args
        ):
            continue
        arg = call.args[0]
        fn = _enclosing_fn_node(call)
        fn_name = fn.name if fn is not None else "<module>"
        if fn_name == _SSOT_FUNNEL:
            # The funnel's own branched init_db / init_db_encrypted (after the
            # encryption stamp) is the ONE sanctioned config-DB open.
            continue
        if _is_config_db_path(arg):
            offenders.append((getattr(call, "lineno", -1), fn_name))
        elif (
            isinstance(arg, ast.Name)
            and fn is not None
            and arg.id in _config_path_local_names(fn)
        ):
            offenders.append((getattr(call, "lineno", -1), fn_name))
    return offenders


def test_cli_config_db_open_is_encryption_aware():
    """No CLI handler opens the configured DB via raw ``init_db`` (PD#1/)."""
    tree = parse_module(CLI_PATH)
    assert tree is not None, f"could not parse {CLI_PATH}"
    offenders = _find_offenders(tree)
    assert not offenders, (
        "CLI handler(s) open the CONFIGURED DB via raw init_db (the plaintext "
        "opener) — this raises 'file is not a database' on an encrypted install. "
        "Route through cli._cli_open_config_db (stamp + open_dedicated_conn). "
        f"Offenders (lineno, fn): {offenders}"
    )


def test_pin_has_teeth():
    """RED on both shapes the N-129 bug took; GREEN on the SSOT + temp-path."""
    bad_direct = (
        "def cmd_x(config):\n"
        "    db = init_db(config.persistence.db_path)\n"
    )
    bad_via_path = (
        "def cmd_y(config):\n"
        "    db_path = Path(config.persistence.db_path)\n"
        "    db = init_db(db_path)\n"
    )
    bad_via_direct_name = (
        "def cmd_z(config):\n"
        "    p = config.persistence.db_path\n"
        "    db = init_db(p)\n"
    )
    # SAME shape as the funnel body but under a NON-funnel name → still flagged
    # (proves the exemption is NAME-scoped, not a detector weakening / a `str()`
    # wrapper evasion).
    bad_impostor = (
        "def cmd_impostor(config):\n"
        "    db_path = str(config.persistence.db_path)\n"
        "    return init_db(db_path)\n"
    )
    good_ssot = (
        "def cmd_ok(config):\n"
        "    db = _cli_open_config_db(config)\n"
    )
    good_temp = (
        "def cmd_smoke(config):\n"
        "    db = init_db(str(smoke))\n"  # throwaway path, not the configured DB
    )
    good_funnel = (  # the SSOT funnel itself — its branched init_db is sanctioned
        "def _cli_open_config_db(config):\n"
        "    db_path = str(config.persistence.db_path)\n"
        "    return init_db(db_path)\n"
    )
    for src in (bad_direct, bad_via_path, bad_via_direct_name, bad_impostor):
        assert _find_offenders(parse_source(src)), f"pin missed a bad shape:\n{src}"
    for src in (good_ssot, good_temp, good_funnel):
        assert not _find_offenders(parse_source(src)), (
            f"pin false-positive on a good shape:\n{src}"
        )


def test_cli_open_config_db_bootstraps_fresh_db(tmp_path):
    """BEHAVIORAL complement to the AST pin (db-sme N-129 MUST-FIX guard).

    The AST pin proves the *shape* (no raw init_db), but the regression the
    db-sme found was BEHAVIORAL: the first cut of `_cli_open_config_db` used
    `open_dedicated_conn` + bare `run_migrations`, which dropped
    `_bootstrap_schema`'s `_ALL_DDL` — so on a FRESH DB the base tables were
    never created and the documented `cmd_user create` first-admin bootstrap
    crashed `no such table: settings`. This test opens the SSOT against a fresh
    (non-existent) PLAINTEXT DB and asserts the base tables exist — so that
    regression class can't recur. (Plaintext keeps it runnable without
    sqlcipher; the encrypted open is proven by the real-sqlcipher CI suite + the
    on-prod re-mine.)
    """
    from email_triage.cli import _cli_open_config_db, load_config

    db_path = tmp_path / "fresh.db"
    keyfile = tmp_path / "et.key"
    keyfile.write_text("x" * 44)  # dummy; unused on the plaintext (encryption-off) path
    yaml_path = tmp_path / "email-triage.yaml"
    yaml_path.write_text(
        "logging:\n"
        "  level: INFO\n"
        "  format: json\n"
        "persistence:\n"
        f"  db_path: {db_path}\n"
        "  encryption_enabled: false\n"
        "secrets:\n"
        "  backend: keyfile\n"
        f"  keyfile_path: {keyfile}\n"
        "  master_key_name: ET_MASTER_KEY\n"
    )
    config = load_config(str(yaml_path))
    assert not db_path.exists(), "precondition: DB must be FRESH (non-existent)"

    conn = _cli_open_config_db(config)
    try:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        conn.close()
    # The base tables every CLI handler relies on must exist after a fresh open.
    missing = {"users", "settings"} - tables
    assert not missing, (
        f"_cli_open_config_db must bootstrap the full schema on a FRESH DB "
        f"(db-sme N-129 regression guard); missing tables: {sorted(missing)}; "
        f"got {sorted(tables)[:12]}…"
    )
