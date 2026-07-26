"""run17  — settings-key delete-sweep catalog reconciliation pin.

A bidirectional, count-agnostic, interprocedural guard on
``settings_keys._ACCOUNT_KEY_CATALOG`` — the per-account delete sweep that
``delete_account_settings`` / ``purge_account_local_state`` run as the L1
§164.310(d)(2)(i) media-disposal SSOT for account-scoped ``settings`` rows.

Two failure modes this pin makes structurally impossible to re-introduce:

* **ORPHAN** — an account-scoped ``settings`` row WRITTEN somewhere in src but
  ABSENT from the catalog → it survives an account delete (a disposal gap).
  run17  found five: ``recipient_digest_state:``, ``digest_state:``,
  ``digest_configs:``, ``mailbox_routes:``, ``ratelimit:triage_preview:``.
* **PHANTOM** — a catalog prefix with NO ``set_setting`` writer AND NO
  ``settings_keys`` builder → dead / false coverage. run17  found three:
  ``digest_test_lock:``, ``backup_paths:``, ``listener_restart_pending:`` (the
  last is an in-memory ``app.state`` flag + a health-report dict key — NEVER a
  settings row).

``office365_clientstate:`` lives in the SECRETS store, not settings — it is
purged via the secrets path in ``purge_account_local_state`` and was REMOVED
from this SETTINGS catalog (run17 ). It is therefore deliberately NOT
required here: it is never a ``set_setting`` write (so the orphan check never
demands it), and although it remains a ``settings_keys`` builder, the catalog
is not obliged to list every declared builder.

THE INTERPROCEDURAL NET (PD#1/#2, verify-don't-accept)
------------------------------------------------------
The WRITTEN set is computed from every ``set_setting`` / ``set_bool_setting``
call (direct OR wrapped in ``db_call(set_setting, conn, KEY, …)``), resolving
the key argument through:
  (a) an inline f-string (``JoinedStr``), with module-level string-constant
      prefixes (``_STORE_KEY_PREFIX`` = ``"digest_configs:"`` etc.) resolved;
  (b) a key-builder CALL — a ``settings_keys`` helper (``_S.watch`` /
      bare ``poll_state``) OR a SAME-MODULE builder (``_store_key`` /
      ``_state_key`` / ``_hwm_key_for`` / ``_wizard_step_setting_key``), one of
      which may itself DELEGATE to a ``settings_keys`` helper (one more hop);
  (c) a local variable assigned — in the same function — from (a) or (b)
      (``key = f"mailbox_routes:{account_id}:{mailbox}"; set_setting(db, key, …)``).
ACCOUNT scope = the FIRST dynamic interpolation references ``account_id``;
USER-scoped keys (``user:``, ``meeting_prefs:``, ``escalation_sms:`` … keyed by
``user_id``) are EXCLUDED — an account delete must never touch a user's rows.

SCOPE CAVEAT (honest)
---------------------
* Resolution is by the static shapes above; it does NOT follow an import
  ALIAS (``office365_poll_cursor as _o365_poll_cursor_key``), so a key
  reachable ONLY through an alias is not seen as "written". Harmless here
  because every such key (``office365_poll_cursor:``, ``poll_state:``,
  ``watch:``) is ALSO a declared ``settings_keys`` builder (covered for the
  phantom check) and already catalogued (covered for the orphan check).
* An UNRESOLVED write is dropped (not invented as a false orphan — a wrong "add"
  would plant a bad sweep entry). HONEST framing (run17  db+DA): this is
  "fails closed against a false ADD", NOT "fails closed for disposal" — from the
  §164.310(d)(2)(i) disposal view, dropping an unresolved write is fail-OPEN: a
  REAL orphan can be silently missed. Two concrete latent blind spots (no live
  orphan at HEAD — every written key today resolves + is catalogued):
    (1) inline/local-var scope detection keys on the LITERAL identifiers
        ``account_id`` / ``user_id`` only — an inline ``set_setting(db,
        f"newkey:{aid}", …)`` where ``aid`` aliases account_id is classified
        scope="other" and would NOT be flagged as an orphan; and
    (2) a RAW ``INSERT/REPLACE INTO settings`` outside the ``set_setting`` funnel
        is not seen at all. The standing convention (account-scoped settings
        keys go through ``set_setting`` with an ``account_id``-named arg) is what
        keeps the net complete; drift is MANAGED, not eliminated (layered defense).
* The phantom direction is bounded by the union of the resolved writers AND the
  ``settings_keys`` account-builder set, so a declared legacy key kept for
  vestigial-row cleanup (``digest:`` / ``digest_schedules:``, whose write UIs were
  retired) is NOT mistaken for a phantom.

This pin uses ``_pin_harness`` (R5b) for the src walk / parse so it can't drift
in its scoping.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    annotate_parents,
    iter_src_files,
    parse_module,
    parse_source,
)

from email_triage.web import settings_keys as _S

# The settings key/value write funnel (db.py). Reads (get_setting) are not
# disposal-relevant — only a WRITE creates a row that an account delete must
# reach. ``set_bool_setting`` ultimately calls ``set_setting`` but carries its
# own account-scoped key at the call site, so both are write entry points.
WRITE_FUNCS = frozenset({"set_setting", "set_bool_setting"})
_MAX_DEPTH = 8


# ---------------------------------------------------------------------------
# AST resolution helpers
# ---------------------------------------------------------------------------

def _module_str_consts(tree: ast.AST) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` string constants (for f-string
    leading-prefix interpolations like ``f"{_STORE_KEY_PREFIX}{account_id}"``)."""
    consts: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        if (isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    consts[tgt.id] = node.value.value
        elif (isinstance(node, ast.AnnAssign) and node.value is not None
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and isinstance(node.target, ast.Name)):
            consts[node.target.id] = node.value.value
    return consts


def _top_funcdefs(tree: ast.AST) -> dict[str, ast.AST]:
    return {
        n.name: n for n in getattr(tree, "body", [])
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _first_return_value(fn: ast.AST | None):
    if fn is None:
        return None
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and node.value is not None:
            return node.value
    return None


def _prefix_and_scope(joined: ast.AST, consts: dict[str, str]):
    """``(prefix, scope)`` for an f-string KEY.

    ``prefix`` = the literal text up to (not including) the first DYNAMIC
    interpolation; a leading ``FormattedValue`` whose ``Name`` is a known
    module string-constant is folded into the literal prefix. ``scope`` ∈
    {``"account"``, ``"user"``, ``"other"``}.
    """
    if not isinstance(joined, ast.JoinedStr):
        return None, None
    parts: list[str] = []
    for v in joined.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
            continue
        if isinstance(v, ast.FormattedValue):
            inner = v.value
            if isinstance(inner, ast.Name) and inner.id in consts:
                parts.append(consts[inner.id])
                continue
            ids = {n.id for n in ast.walk(inner) if isinstance(n, ast.Name)}
            if "account_id" in ids:
                return "".join(parts), "account"
            if "user_id" in ids:
                return "".join(parts), "user"
            return "".join(parts), "other"
        break
    # No dynamic interpolation at all → a constant string key (install-wide).
    return "".join(parts), "other"


def _resolve_key_expr(node, consts, funcs, sk_builders, assignments, depth=0):
    """Resolve a settings KEY expression to ``(prefix, scope)`` or ``(None, None)``.

    Interprocedural: a builder CALL is resolved through its def (same-module or
    a ``settings_keys`` helper, which may delegate once more); a local ``Name``
    is resolved through its in-function assignment.
    """
    if node is None or depth > _MAX_DEPTH:
        return None, None
    if isinstance(node, ast.JoinedStr):
        return _prefix_and_scope(node, consts)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, "other"  # literal install-wide key
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            # ``_S.watch(...)`` / ``S.calendar_enabled(...)`` /
            # ``_settings_keys.auth_stale(...)`` — the attr names a
            # settings_keys helper (unique names; the qualifier is an alias).
            if func.attr in sk_builders:
                return sk_builders[func.attr]
            return None, None
        if isinstance(func, ast.Name):
            name = func.id
            if name in funcs:  # same-module builder — recurse into its return
                return _resolve_key_expr(
                    _first_return_value(funcs[name]),
                    consts, funcs, sk_builders, {}, depth + 1,
                )
            if name in sk_builders:  # bare-imported settings_keys helper
                return sk_builders[name]
        return None, None
    if isinstance(node, ast.Name):
        val = assignments.get(node.id)
        if val is not None:
            return _resolve_key_expr(
                val, consts, funcs, sk_builders, assignments, depth + 1,
            )
    return None, None


def _enclosing_func(node):
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = getattr(cur, "_ph_parent", None)
    return None


def _assignments_in(fn) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    if fn is None:
        return out
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out[tgt.id] = node.value
    return out


def _account_written_prefixes(tree, consts, funcs, sk_builders) -> set[str]:
    """Every account-scoped settings-key PREFIX written in one module."""
    annotate_parents(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        key_node = None
        if isinstance(func, ast.Name) and func.id in WRITE_FUNCS:
            if len(node.args) >= 2:
                key_node = node.args[1]
        elif isinstance(func, ast.Name) and func.id == "db_call":
            # db_call(set_setting, conn, KEY, …) → fn(conn, KEY, …)
            if (len(node.args) >= 3 and isinstance(node.args[0], ast.Name)
                    and node.args[0].id in WRITE_FUNCS):
                key_node = node.args[2]
        if key_node is None:
            continue
        assignments = _assignments_in(_enclosing_func(node))
        prefix, scope = _resolve_key_expr(
            key_node, consts, funcs, sk_builders, assignments,
        )
        if scope == "account" and prefix:
            found.add(prefix)
    return found


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------

def _build_sk_builders() -> dict[str, tuple[str, str]]:
    """``settings_keys`` key-builder registry: ``name -> (prefix, scope)`` for
    every helper that returns a single f-string. ``account_state`` (account) and
    ``user_scoped`` (user) — the documented legacy ``<scope>:<id>:<thing>``
    builders — are included with their correct scope."""
    tree = parse_module(SRC_ROOT / "web" / "settings_keys.py")
    assert tree is not None, "settings_keys.py failed to parse"
    consts = _module_str_consts(tree)
    out: dict[str, tuple[str, str]] = {}
    for name, fn in _top_funcdefs(tree).items():
        ret = _first_return_value(fn)
        if isinstance(ret, ast.JoinedStr):
            prefix, scope = _prefix_and_scope(ret, consts)
            if prefix and scope in ("account", "user"):
                out[name] = (prefix, scope)
    return out


def _collect():
    """Return ``(written_account, declared_account)`` prefix sets."""
    sk_builders = _build_sk_builders()
    written_account: set[str] = set()
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        written_account |= _account_written_prefixes(
            tree, _module_str_consts(tree), _top_funcdefs(tree), sk_builders,
        )
    declared_account = {p for (p, s) in sk_builders.values() if s == "account"}
    return written_account, declared_account


def _catalog_prefixes() -> set[str]:
    return {prefix for (prefix, _exact) in _S._ACCOUNT_KEY_CATALOG}


# ---------------------------------------------------------------------------
# The bidirectional pin
# ---------------------------------------------------------------------------

def test_no_orphan_account_scoped_settings_key():
    """(a) Every account-scoped ``set_setting``-written prefix is catalogued."""
    written, _declared = _collect()
    catalog = _catalog_prefixes()
    orphans = written - catalog
    assert not orphans, (
        "Account-scoped settings key(s) WRITTEN in src but ABSENT from "
        "settings_keys._ACCOUNT_KEY_CATALOG — they ORPHAN on account delete "
        "(§164.310(d)(2)(i) incomplete media disposal). Add each to the "
        "catalog with the right exact_match flag (False for a "
        "``<prefix><id>:<segment>`` shape):\n  " + "\n  ".join(sorted(orphans))
    )


def test_no_phantom_catalog_prefix():
    """(b) Every catalogued prefix has a writer OR a settings_keys builder."""
    written, declared = _collect()
    catalog = _catalog_prefixes()
    phantoms = catalog - (written | declared)
    assert not phantoms, (
        "settings_keys._ACCOUNT_KEY_CATALOG prefix(es) with NO set_setting "
        "writer and NO settings_keys builder — dead / false coverage that "
        "makes the sweep LOOK complete while doing nothing. Remove each, or "
        "(if the value actually lives in the SECRETS store) route it through "
        "the secrets-purge path in purge_account_local_state instead:\n  "
        + "\n  ".join(sorted(phantoms))
    )


# ---------------------------------------------------------------------------
# Teeth
# ---------------------------------------------------------------------------

def test_resolver_has_teeth_on_real_shapes():
    """The interprocedural resolver actually RESOLVES the run17  orphan
    shapes (inline f-string, module-const-prefixed builder, builder delegation,
    local-var hop, db_call seam) — and does NOT mistake ``office365_clientstate``
    (a SECRETS key) for a settings write."""
    written, declared = _collect()
    for p in ("mailbox_routes:", "recipient_digest_state:", "digest_state:",
              "digest_configs:", "ratelimit:triage_preview:"):
        assert p in written, f"resolver lost the {p!r} writer — no teeth"
    # Resolved through helper hops (proves interprocedural resolution works).
    for p in ("watch_hwm:", "style_profile:", "openclaw_quiet:", "account_state:"):
        assert p in written, f"resolver lost the helper-resolved {p!r} writer"
    # office365_clientstate is written to SECRETS, never via set_setting → it
    # must NOT look like a settings write (else the pin would demand it back).
    assert "office365_clientstate:" not in written
    assert "office365_clientstate:" in declared  # but it IS a declared builder
    # The three removed phantoms have NEITHER a writer NOR a builder → re-adding
    # any to the catalog WOULD trip test_no_phantom_catalog_prefix.
    for ghost in ("digest_test_lock:", "backup_paths:", "listener_restart_pending:"):
        assert ghost not in (written | declared), (
            f"{ghost!r} unexpectedly has a writer/builder — re-check before "
            "treating it as a phantom"
        )


def test_resolver_distinguishes_account_from_user_scope():
    """Planted shapes: account_id-keyed writes are caught (inline, builder hop,
    db_call); a user_id-keyed write and an install-wide literal are EXCLUDED —
    an account delete must not sweep a user's rows or install-wide config."""
    sk = _build_sk_builders()
    src = (
        "PFX = 'planted_state:'\n"
        "def _k(account_id):\n"
        "    return f'{PFX}{account_id}'\n"
        "def writer(db, account_id, user_id):\n"
        "    set_setting(db, _k(account_id), {})\n"            # builder + const
        "    rl = f'rl:thing:{account_id}'\n"
        "    set_setting(db, rl, 0)\n"                          # local-var hop
        "    set_setting(db, f'uacct:{int(user_id)}:x', {})\n"  # user-scoped
        "    set_setting(db, 'install_wide_key', {})\n"         # literal
        "    db_call(set_bool_setting, db, f'viadb:{account_id}', True)\n"  # seam
    )
    tree = parse_source(src)
    got = _account_written_prefixes(
        tree, _module_str_consts(tree), _top_funcdefs(tree), sk,
    )
    assert "planted_state:" in got     # builder hop + module const prefix
    assert "rl:thing:" in got          # inline local-var f-string
    assert "viadb:" in got             # db_call(set_bool_setting, …) seam
    assert "uacct:" not in got         # user-scoped → excluded
    assert "install_wide_key" not in got  # install-wide literal → excluded


def test_catalog_well_formed():
    """Every catalog entry is a ``(str-prefix-ending-':' , bool)`` pair."""
    for entry in _S._ACCOUNT_KEY_CATALOG:
        assert isinstance(entry, tuple) and len(entry) == 2, entry
        prefix, exact = entry
        assert isinstance(prefix, str) and prefix.endswith(":"), prefix
        assert isinstance(exact, bool), entry
    # No duplicate prefixes (a duplicate would double-delete harmlessly but
    # signals a copy-paste slip).
    prefixes = [p for (p, _e) in _S._ACCOUNT_KEY_CATALOG]
    assert len(prefixes) == len(set(prefixes)), "duplicate catalog prefix"
