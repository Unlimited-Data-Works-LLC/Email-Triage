"""Account-delete local-state purge — count-agnostic structural pin
(Loop-6 census, L1 §164.310(d)(2)(i) media-disposal + L2 watcher-teardown).

When an account or user is deleted, ALL of the following must be cleaned up:
  * live IMAP IDLE watcher tasks (L2 — leaked connection)
  * unified-poll registration (L2)
  * settings rows keyed by account_id (L1 — settings table sweep)
  * secrets_store credentials: ACCOUNT_{id}_IMAP_PASSWORD,
    ACCOUNT_{id}_O365_SECRET, ACCOUNT_{id}_GMAIL_REFRESH_TOKEN (L1)
  * secrets_store office365_clientstate:{id} (L1 — Graph webhook HMAC)

The fix plants:
  * ``purge_account_local_state(conn, account_id, secrets)`` — DB SSOT
    for the two-store sweep.
  * ``WatcherManager.apply_account_deleted(account_id)`` — lifecycle funnel
    that calls stop(persist=True) + purge_account_local_state.
  * Three delete actuators routed through the funnel:
    - ``accounts_delete`` (routers/ui/accounts.py)
    - ``delete_user``     (routers/ui/users.py)
    - ``api_delete_user`` (routers/api.py)

This pin keeps that net COMPLETE as the code evolves.

Invariants:

  1. (Structural, count-agnostic) The SSOT ``purge_account_local_state``
     references BOTH ``delete_account_settings`` (settings sweep) AND at
     least one ``secrets.delete`` call keyed on the ``ACCOUNT_{`` prefix
     AND ``office365_clientstate`` — so a new account-scoped secret can't
     be added without touching the purge SSOT.

  2. (Interprocedural) Every account-DELETE actuator calls
     ``apply_account_deleted`` (or ``purge_account_local_state`` in the
     no-watcher-mgr fallback) — verified at the AST seam level so an
     inline refactor can't silently drop the call.

  3. (Funnel shape) ``apply_account_deleted`` calls ``self.stop`` with
     ``persist=True`` AND ``purge_account_local_state``.

Teeth: each invariant has a planted-failure case.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    enclosing_fn,
    iter_src_files,
    parse_module,  # N-388 R33 — replaces the raw parse-of-read_text pair
    parse_source,
    relpath,
    walk_src,
)

# Local alias preserved so the per-pin detection bodies below read unchanged.
# SRC == SRC_ROOT (src/email_triage); the harness computes it ONCE so this pin
# can no longer drift in its package-root scoping (R5b).
SRC = SRC_ROOT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse(subpath: str) -> ast.AST:
    # N-350 R31 (2026-07-04, census DISCOVERED MED): route through
    # `_pin_harness.parse_module` so a decode/syntax error in the
    # target file doesn't silently vacuous-pass the pin — the SSOT
    # returns None on failure and the caller asserts.
    tree = parse_module(SRC / subpath)
    assert tree is not None, f"parse_module returned None for {subpath}"
    return tree


def _find_func(tree: ast.AST, name: str) -> ast.AST | None:
    """First function/method with the given name in the AST."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            node.name == name
        ):
            return node
    return None


def _src_text(subpath: str) -> str:
    return (SRC / subpath).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Invariant 1 — purge SSOT covers BOTH stores + the correct key schemes
# ---------------------------------------------------------------------------

def test_purge_ssot_calls_delete_account_settings():
    """purge_account_local_state must delegate the settings sweep to
    delete_account_settings (the pre-existing SSOT for the settings table).
    """
    tree = _parse("db/accounts.py")
    func = _find_func(tree, "purge_account_local_state")
    assert func is not None, (
        "purge_account_local_state not found in db/accounts.py — the L1 "
        "media-disposal SSOT is missing."
    )
    # Must call delete_account_settings somewhere in its body.
    calls = [
        n for n in ast.walk(func)
        if isinstance(n, ast.Call)
        and (
            (isinstance(n.func, ast.Name) and n.func.id == "delete_account_settings")
            or (isinstance(n.func, ast.Attribute) and n.func.attr == "delete_account_settings")
        )
    ]
    assert calls, (
        "purge_account_local_state does not call delete_account_settings — the "
        "settings sweep for the deleted account is missing."
    )


def test_purge_ssot_covers_account_prefix_secrets():
    """purge_account_local_state must contain references to an ACCOUNT_ prefix
    secret delete (covering IMAP_PASSWORD, O365_SECRET, GMAIL_REFRESH_TOKEN
    and any future ACCOUNT_{id}_* keys).
    """
    src = _src_text("db/accounts.py")
    func_tree = _parse("db/accounts.py")
    func = _find_func(func_tree, "purge_account_local_state")
    assert func is not None

    func_src_lines = ast.get_source_segment(
        (SRC / "db/accounts.py").read_text(encoding="utf-8"),
        func,
    ) or ""

    # The SSOT must reference the ACCOUNT_ pattern or secret_key_for_account
    # (the canonical key-derivation SSOT) so it stays linked to the provider list.
    has_account_prefix = "ACCOUNT_" in func_src_lines or "secret_key_for_account" in func_src_lines
    assert has_account_prefix, (
        "purge_account_local_state does not reference ACCOUNT_ keys or "
        "secret_key_for_account — the provider-credential secrets purge is missing."
    )


def test_purge_ssot_covers_office365_clientstate():
    """purge_account_local_state must explicitly target office365_clientstate,
    which is stored in secrets (not settings) and therefore NOT covered by
    delete_account_settings.
    """
    func_tree = _parse("db/accounts.py")
    func = _find_func(func_tree, "purge_account_local_state")
    assert func is not None

    func_src = ast.get_source_segment(
        (SRC / "db/accounts.py").read_text(encoding="utf-8"),
        func,
    ) or ""

    assert "office365_clientstate" in func_src, (
        "purge_account_local_state does not reference office365_clientstate — the "
        "Graph webhook clientState secret will persist after account deletion."
    )


# ---------------------------------------------------------------------------
# Invariant 2 — delete actuators route through the funnel (interprocedural)
# ---------------------------------------------------------------------------

_FUNNEL_NAMES = {"apply_account_deleted", "purge_account_local_state"}

# Names that legitimately delete an account/user row WITHOUT routing through
# the funnel — the SSOT primitives the actuators build on. Everything else that
# deletes such a row MUST route through the funnel (count-agnostic: a NEW
# bulk-delete / admin script / handler inherits the requirement, DA should-fix).
_ALLOWLIST_FUNCS = {
    "delete_email_account",        # the low-level row-delete primitive itself
    "purge_account_local_state",   # the purge SSOT (does not delete the row)
    "apply_account_deleted",       # the funnel itself
}
# Modules that are schema/infra, not delete actuators.
_SKIP_MODULES = {"migrations.py"}


def _routes_through_funnel(node: ast.AST) -> bool:
    """True if the function (incl. nested closures) calls apply_account_deleted
    or purge_account_local_state — directly OR via the db_call seam (the name
    appears as a bare callable arg / string)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            fname = None
            if isinstance(n.func, ast.Name):
                fname = n.func.id
            elif isinstance(n.func, ast.Attribute):
                fname = n.func.attr
            if fname in _FUNNEL_NAMES:
                return True
            # db_call(apply_account_deleted, ...) / db_call(purge_..., ...)
            for a in n.args:
                if isinstance(a, ast.Name) and a.id in _FUNNEL_NAMES:
                    return True
        if isinstance(n, ast.Constant) and n.value in _FUNNEL_NAMES:
            return True
    return False


def _deletes_account_or_user_row(node: ast.AST, src_text: str) -> bool:
    """True if this function (incl. nested) deletes an email_accounts/users
    row — either a raw DELETE-FROM SQL string or a delete_email_account call."""
    seg = ast.get_source_segment(src_text, node) or ""
    if "DELETE FROM email_accounts" in seg or "DELETE FROM users" in seg:
        return True
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            fn = (n.func.id if isinstance(n.func, ast.Name)
                  else n.func.attr if isinstance(n.func, ast.Attribute)
                  else None)
            if fn == "delete_email_account":
                return True
    return False


def _top_level_funcs(tree: ast.AST):
    """Yield module-level functions + class methods (NOT nested closures)."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node
        elif isinstance(node, ast.ClassDef):
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield m


def test_every_account_or_user_row_delete_routes_through_funnel():
    """COUNT-AGNOSTIC (PD#1/PD#2): scan ALL of src/ — every function that
    deletes an email_accounts / users row must route through the funnel
    (apply_account_deleted or purge_account_local_state). A new bulk-delete or
    admin path inherits the requirement; the SSOT primitives are allow-listed.
    """
    offenders: list[str] = []
    seen_any = False
    for p in iter_src_files():
        if p.name in _SKIP_MODULES:
            continue
        source_text = p.read_text(encoding="utf-8")
        tree = parse_module(p)
        if tree is None:
            import pytest
            pytest.fail(
                f"{p} did not parse — a non-parsing src module is a defect "
                "this guard must surface, not skip"
            )
        rel = relpath(p)
        for fn in _top_level_funcs(tree):
            if fn.name in _ALLOWLIST_FUNCS:
                continue
            if not _deletes_account_or_user_row(fn, source_text):
                continue
            seen_any = True
            if not _routes_through_funnel(fn):
                offenders.append(f"{rel}::{fn.name}:{fn.lineno}")
    assert seen_any, (
        "no account/user-row-delete function found in src/ — the scanner is "
        "blind (delete_email_account renamed? raw SQL reshaped?). Re-point this pin."
    )
    assert not offenders, (
        "a function deletes an email_accounts/users row WITHOUT routing through "
        f"apply_account_deleted / purge_account_local_state: {offenders}. The "
        "deleted account's credentials + PHI state + watcher will leak "
        "(§164.310(d)(2)(i)). Route it through the funnel, or (if it is a new "
        "SSOT primitive) add it to _ALLOWLIST_FUNCS with justification."
    )


# ---------------------------------------------------------------------------
# Invariant 3 — funnel shape: stop(persist=True) + purge_account_local_state
# ---------------------------------------------------------------------------

def test_funnel_calls_stop_with_persist_true():
    """apply_account_deleted must call self.stop with persist=True.

    persist=True is load-bearing: it clears the watch:{id} settings preference
    so the account is not re-started on process restart.  persist=False (the
    deactivation posture) would leave the preference intact — wrong for a
    permanent delete.
    """
    tree = _parse("web/watcher.py")
    func = _find_func(tree, "apply_account_deleted")
    assert func is not None, (
        "apply_account_deleted not found in web/watcher.py — the L1+L2 "
        "lifecycle funnel is missing."
    )

    # Find stop() calls and check at least one has persist=True (as a keyword).
    stop_calls = [
        n for n in ast.walk(func)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "stop"
    ]
    assert stop_calls, (
        "apply_account_deleted does not call self.stop — live watcher teardown is missing."
    )

    def _has_persist_true(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg == "persist" and isinstance(kw.value, ast.Constant) and (
                kw.value.value is True
            ):
                return True
        return False

    assert any(_has_persist_true(c) for c in stop_calls), (
        "apply_account_deleted calls self.stop but NOT with persist=True — the "
        "watch:{id} preference will persist after permanent account delete, "
        "risking watcher resurrection on restart."
    )


def test_funnel_calls_purge_account_local_state():
    """apply_account_deleted must call purge_account_local_state (directly
    or via db_call) to sweep settings + secrets.
    """
    func_src = ast.get_source_segment(
        (SRC / "web/watcher.py").read_text(encoding="utf-8"),
        _find_func(_parse("web/watcher.py"), "apply_account_deleted"),
    ) or ""
    assert "purge_account_local_state" in func_src, (
        "apply_account_deleted does not call purge_account_local_state — the "
        "settings + secrets sweep is missing from the funnel."
    )


# ---------------------------------------------------------------------------
# Teeth — each invariant must catch its planted regression
# ---------------------------------------------------------------------------

def test_teeth_purge_ssot_missing_delete_account_settings():
    """A purge function that does NOT call delete_account_settings is rejected."""
    code = (
        "def purge_account_local_state(conn, account_id, secrets=None):\n"
        "    return {'settings_deleted': 0, 'secrets_deleted': 0}\n"
    )
    func = _find_func(ast.parse(code), "purge_account_local_state")
    assert func is not None
    calls = [
        n for n in ast.walk(func)
        if isinstance(n, ast.Call)
        and (
            (isinstance(n.func, ast.Name) and n.func.id == "delete_account_settings")
            or (isinstance(n.func, ast.Attribute) and n.func.attr == "delete_account_settings")
        )
    ]
    assert not calls, "planted regression should have no delete_account_settings call"


def test_teeth_actuator_missing_funnel_is_caught():
    """An actuator that does NOT call the funnel is caught."""
    code = (
        "async def accounts_delete(request, account_id, user):\n"
        "    db = get_db(request)\n"
        "    await db_call(delete_email_account, db, account_id)\n"
        "    return HTMLResponse('')\n"
    )
    func = _find_func(ast.parse(code), "accounts_delete")
    assert func is not None
    assert not _routes_through_funnel(func), (
        "planted regression should not route through funnel"
    )


def test_teeth_funnel_without_persist_true_is_caught():
    """A funnel that calls stop() without persist=True is rejected."""
    code = (
        "async def apply_account_deleted(self, account_id):\n"
        "    await self.stop(account_id, persist=False)\n"
        "    return {}\n"
    )
    func = _find_func(ast.parse(code), "apply_account_deleted")
    assert func is not None
    stop_calls = [
        n for n in ast.walk(func)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "stop"
    ]
    assert stop_calls
    def _has_persist_true(call):
        for kw in call.keywords:
            if kw.arg == "persist" and isinstance(kw.value, ast.Constant) and (
                kw.value.value is True
            ):
                return True
        return False
    assert not any(_has_persist_true(c) for c in stop_calls), (
        "planted regression: persist=False should not satisfy the persist=True check"
    )


# ---------------------------------------------------------------------------
# Invariant 4 — ON-DISK per-account MSAL TOKEN-CACHE file disposal (run18 #1)
#
# The pre-existing invariants above are DB-row / call-shape only — BLIND to the
# on-disk ``./data/msal_cache_<id>.json`` token cache (PLAINTEXT O365 OAuth
# tokens, written OUTSIDE the SQLCipher DB). That blindness IS the run18 #1
# defect: the cache was written per-account while purge_account_local_state
# unlinked nothing, so the most-exposed token copy SURVIVED the §164.310
# (d)(2)(i) purge chartered to erase it.
#
# The MSAL-cache file-artifact invariant (count-agnostic, bidirectional,
# interprocedural-aware — the writer hops factory→provider, the disposal lives
# in purge):
#   (a) every per-account MSAL-cache path is built via the factory SSOT
#       ``msal_cache_path_for_account`` — NO module re-forks the literal
#       (a forked literal is a writer the purge can't reach);
#   (b) at least one such WRITER exists (blindness guard — else re-point);
#   (c) a writer existing REQUIRES the disposal: purge_account_local_state
#       unlinks the SSOT path with ``missing_ok=True``.
#
# SCOPE — honest de-claim (DA Attack 3): this invariant is MSAL-cache-SPECIFIC,
# NOT the general "any per-account on-disk artifact" file-artifact pin. The
# detector ``_is_per_account_cache_fstring`` keys on the ``msal_cache_`` +
# ``.json`` literal, so it ONLY catches the O365 token cache. A FUTURE
# per-account on-disk credential/state file under a different name — e.g. a
# ``./data/google_token_<id>.json`` written without a matching disposal unlink —
# would NOT be caught here. That broader "account-scoped on-disk credential file
# whose CREATE side is broad but DISPOSE side is narrow" class is tracked
# SEPARATELY as the run18 census ``ondisk-artifact-disposal`` seeded lens
# (audit-reports/divergence-census-2026-06-27-run18.md §1 class #1 / §7(b));
# broadening this detector to cover it is THAT class's work, deliberately NOT
# done here (per the brief: make the naming honest, do not broaden the net).
# ---------------------------------------------------------------------------

def _callee_name(call: ast.AST) -> str | None:
    """The called name for a Call node — ``f(...)`` -> ``f`` / ``x.f(...)`` ->
    ``f`` — or None."""
    if not isinstance(call, ast.Call):
        return None
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _is_true_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_per_account_cache_fstring(node: ast.AST) -> bool:
    """True if ``node`` is an f-string of the PER-ACCOUNT cache shape
    ``...msal_cache_{<expr>}.json`` — a ``JoinedStr`` whose STATIC parts span
    ``msal_cache_`` + ``.json`` AND that interpolates a value.

    This is the FORKED-LITERAL shape the SSOT replaces. It deliberately does
    NOT match the legacy SHARED constant ``./data/msal_cache.json`` (a plain
    ``ast.Constant`` with no interpolation), which is a different file and out
    of scope for the per-account disposal pin.
    """
    if not isinstance(node, ast.JoinedStr):
        return False
    static = "".join(
        v.value for v in node.values
        if isinstance(v, ast.Constant) and isinstance(v.value, str)
    )
    has_interp = any(isinstance(v, ast.FormattedValue) for v in node.values)
    return has_interp and "msal_cache_" in static and ".json" in static


def _scan_forked_per_account_cache_literals():
    """(relpath, enclosing_fn, lineno) for every per-account cache f-string in
    ``src/`` that is NOT inside the SSOT definition itself."""
    hits = []
    _ALLOWED_SSOT_FNS = {
        "msal_cache_path_for_account",
        # N-209 R23 (2026-07-02): sibling SSOT for CLI-scoped path (username-
        # keyed, not account_id-keyed) — CLI has no account_id at bootstrap.
        "msal_cache_path_for_cli",
        # N-356 R31 (2026-07-05): CLI-scoped disposer that must construct the
        # pre-N-307 OLD-shape path literal `./data/msal_cache_cli_<username>.json`
        # in order to unlink orphaned files from upgraded installs. The OLD
        # shape is DEAD after this dispose runs — no writer exists for it, so
        # there is no SSOT to route through. See providers/factory.py
        # `dispose_msal_cache_for_cli` docstring for full grounding.
        "dispose_msal_cache_for_cli",
    }
    for _path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if _is_per_account_cache_fstring(node):
                if enclosing_fn(node) in _ALLOWED_SSOT_FNS:
                    continue  # SSOT body — the allowed literal(s)
                hits.append((rel, enclosing_fn(node), node.lineno))
    return hits


def _scan_ssot_writer_sites():
    """(relpath, enclosing_fn, lineno) for every WRITE/create call of the SSOT
    ``msal_cache_path_for_account(...)`` — i.e. excluding the SSOT def and the
    disposal site in purge_account_local_state."""
    hits = []
    for _path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if _callee_name(node) == "msal_cache_path_for_account":
                fn = enclosing_fn(node)
                if fn in ("msal_cache_path_for_account", "purge_account_local_state"):
                    continue
                hits.append((rel, fn, node.lineno))
    return hits


def _purge_disposes_msal_cache(func: ast.AST) -> bool:
    """True if ``func`` disposes the per-account MSAL cache file. Two accepted
    shapes:

    - **Inline (pre-N-236)**: calls ``msal_cache_path_for_account(...)`` AND
      ``.unlink(missing_ok=True)`` on that SSOT result — directly OR via an
      intermediate ``p = SSOT(...)`` assignment.
    - **SSOT dispose (N-236+)**: calls ``dispose_msal_cache_for_account(...)``
      — the extracted dispose actuator that internally unlinks the SSOT path
      with ``missing_ok=True``. This shape closes §164.310(d)(2)(i) IDENTICALLY
      to the inline shape while collapsing the writer + disposer into ONE
      module (`providers/factory.py`).

    Requiring one of the two shapes keeps the disposal path from drifting."""
    # Shape 2: SSOT dispose helper OR registry-funnel dispose — check
    # first (short-circuit). N-245b R24 added the registry funnel
    # `dispose_all_per_account_artifacts(account_id)` which internally
    # walks every registered artifact builder (msal_cache included).
    for n in ast.walk(func):
        name = _callee_name(n)
        if name in ("dispose_msal_cache_for_account",
                    "dispose_all_per_account_artifacts"):
            return True
    # Shape 1: inline unlink via SSOT-derived receiver (legacy pre-N-236 shape).
    cache_vars: set[str] = set()
    calls_ssot = False
    for n in ast.walk(func):
        if _callee_name(n) == "msal_cache_path_for_account":
            calls_ssot = True
        if (isinstance(n, ast.Assign) and _callee_name(n.value) == "msal_cache_path_for_account"):
            for tgt in n.targets:
                if isinstance(tgt, ast.Name):
                    cache_vars.add(tgt.id)
    if not calls_ssot:
        return False
    for n in ast.walk(func):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "unlink"):
            recv = n.func.value
            recv_is_ssot = (
                (_callee_name(recv) == "msal_cache_path_for_account")
                or (isinstance(recv, ast.Name) and recv.id in cache_vars)
            )
            has_missing_ok = any(
                kw.arg == "missing_ok" and _is_true_const(kw.value)
                for kw in n.keywords
            )
            if recv_is_ssot and has_missing_ok:
                return True
    return False


def test_no_forked_per_account_msal_cache_literal():
    """(a) COUNT-AGNOSTIC: no module outside the factory SSOT may hardcode a
    per-account ``msal_cache_<id>.json`` path literal. Every writer must derive
    the path from ``msal_cache_path_for_account`` so the file the §164.310
    (d)(2)(i) purge unlinks can NEVER disagree with the writer (run18 #1)."""
    offenders = _scan_forked_per_account_cache_literals()
    assert not offenders, (
        "a per-account MSAL token-cache path is hardcoded as an f-string "
        "instead of via providers.factory.msal_cache_path_for_account: "
        f"{offenders}. A forked literal is exactly how the run18 #1 disposal "
        "gap arose — the cache is written per-account but "
        "purge_account_local_state cannot unlink a path it does not share. "
        "Route it through the SSOT."
    )


def test_purge_ssot_disposes_msal_token_cache_file():
    """(c) The §164.310(d)(2)(i) SSOT must UNLINK the on-disk per-account MSAL
    token-cache file via ``msal_cache_path_for_account(...).unlink(
    missing_ok=True)`` — DB-row sweeps alone leave the PLAINTEXT OAuth tokens
    in ``./data/msal_cache_<id>.json`` on disk after account deletion."""
    func = _find_func(_parse("db/accounts.py"), "purge_account_local_state")
    assert func is not None
    assert _purge_disposes_msal_cache(func), (
        "purge_account_local_state does NOT unlink the per-account MSAL token-"
        "cache file via msal_cache_path_for_account(...).unlink(missing_ok="
        "True) — the PLAINTEXT O365 OAuth tokens in ./data/msal_cache_<id>.json "
        "SURVIVE account deletion (§164.310(d)(2)(i) disposal gap, run18 #1)."
    )


def test_per_account_msal_cache_writer_requires_disposal():
    """(b)+(c) BIDIRECTIONAL + count-agnostic: at least one per-account
    MSAL-cache WRITER exists (blindness guard), and a writer existing REQUIRES
    the disposal unlink reachable from purge_account_local_state."""
    writers = _scan_ssot_writer_sites()
    assert writers, (
        "no per-account MSAL-cache WRITER found (no msal_cache_path_for_account "
        "call in the provider factories). The create path was renamed/removed "
        "or bypassed the SSOT — the file-disposal pin is now BLIND. Re-point it."
    )
    func = _find_func(_parse("db/accounts.py"), "purge_account_local_state")
    assert func is not None and _purge_disposes_msal_cache(func), (
        f"{len(writers)} per-account cache writer(s) exist {writers} but "
        "purge_account_local_state does NOT dispose the on-disk file — every "
        "per-account file-artifact WRITER must have a matching disposal unlink "
        "reachable from the §164.310(d)(2)(i) SSOT (run18 #1)."
    )


# --- Teeth for Invariant 4 -------------------------------------------------

def test_teeth_forked_per_account_cache_literal_is_caught():
    """A hardcoded per-account cache f-string (bypassing the SSOT) is detected
    as a forked literal."""
    tree = parse_source(
        "def build_x(acct):\n"
        "    token_cache_path = f\"./data/msal_cache_{acct['id']}.json\"\n"
        "    return token_cache_path\n"
    )
    found = [n for n in ast.walk(tree) if _is_per_account_cache_fstring(n)]
    assert found, "teeth: a forked per-account cache f-string must be detected"


def test_teeth_shared_cache_constant_is_not_flagged():
    """The legacy SHARED constant ``./data/msal_cache.json`` (no interpolation)
    is a DIFFERENT file and must NOT be flagged as a per-account literal (no
    false positive against the provider defaults)."""
    tree = parse_source(
        "def build_y():\n"
        "    return \"./data/msal_cache.json\"\n"
    )
    found = [n for n in ast.walk(tree) if _is_per_account_cache_fstring(n)]
    assert not found, "teeth: the shared msal_cache.json constant is not per-account"


def test_teeth_purge_without_msal_unlink_is_caught():
    """A purge that does NOT unlink the MSAL cache file fails the disposal
    check."""
    func = _find_func(parse_source(
        "def purge_account_local_state(conn, account_id, secrets=None):\n"
        "    delete_account_settings(conn, account_id)\n"
        "    return {'settings_deleted': 0}\n"
    ), "purge_account_local_state")
    assert func is not None
    assert not _purge_disposes_msal_cache(func), (
        "teeth: a purge with no msal_cache unlink must NOT pass the disposal check"
    )


def test_teeth_purge_unlink_bypassing_ssot_is_caught():
    """An ``unlink`` on a hardcoded path (NOT via the SSOT) does not satisfy the
    disposal check — such a path could silently drift from the writer."""
    func = _find_func(parse_source(
        "def purge_account_local_state(conn, account_id, secrets=None):\n"
        "    from pathlib import Path\n"
        "    Path(f'./data/msal_cache_{account_id}.json').unlink(missing_ok=True)\n"
        "    return {}\n"
    ), "purge_account_local_state")
    assert func is not None
    assert not _purge_disposes_msal_cache(func), (
        "teeth: an unlink that bypasses the SSOT path must not satisfy the check"
    )


def test_teeth_purge_unlink_without_missing_ok_is_caught():
    """A disposal unlink WITHOUT ``missing_ok=True`` is rejected — the benign
    absent-file (the common case) would raise FileNotFoundError and the purge
    would fail spuriously."""
    func = _find_func(parse_source(
        "def purge_account_local_state(conn, account_id, secrets=None):\n"
        "    p = msal_cache_path_for_account(account_id)\n"
        "    p.unlink()\n"
        "    return {}\n"
    ), "purge_account_local_state")
    assert func is not None
    assert not _purge_disposes_msal_cache(func), (
        "teeth: an unlink without missing_ok=True must not satisfy the check"
    )
