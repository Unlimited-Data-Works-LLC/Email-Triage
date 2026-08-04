"""auth_stale lifecycle — count-agnostic structural pin (divergence census
2026-06-09, finding #1).

The per-account ``auth_stale`` flag (the "Re-authenticate required" chip + the
daily-health call-out) is a *lifecycle flag*: SET on an auth-revoked provider
failure, CLEARED on a successful credentialed provider call. Before this fix it
had diverged three ways:

  * the auth-revoked **needle list** was duplicated in ``web/app.py`` and
    ``web/watcher_retry.py`` and the two had drifted (the retry copy carried
    ``OAuthRefreshFailed``/``IMAPAuthError`` and scanned the class name);
  * SET fired on the **poll path only** — push / IDLE / renewers never set, so a
    dead token on those paths looked healthy;
  * CLEAR fired on **poll + OAuth re-auth only** — so an account flagged by the
    poll path stayed stuck on the chip once it recovered via another path.

These three property-tests keep the machinery from re-diverging. They assert a
property over **every** site (never ``len(...) == N``), per
``pattern_count_agnostic_structural_drift_catch``.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath, walk_src  # N-350 R31

SSOT = SRC_ROOT / "web" / "_auth_revoked.py"

# The full needle vocabulary. A SINGLE one of these as a string literal is fine
# (e.g. a provider matching the OAuth ``error: "invalid_grant"`` response
# field); a *collection* of two-or-more is a re-inlined needle list — the
# divergence this pin guards.
NEEDLES = frozenset({
    "Token has been expired or revoked", "invalid_grant", "AUTHENTICATIONFAILED",
    "InvalidAuthenticationToken", "Invalid Credentials", "OAuthRefreshFailed",
    "IMAPAuthError", "invalid_client", "unauthorized_client", "401: Unauthorized",
})


# --------------------------------------------------------------------------
# Invariant 1 — the auth-revoked needle LIST lives only in the SSOT module.
# --------------------------------------------------------------------------
def _needle_collection_lines(tree: ast.AST) -> list[int]:
    """Line numbers of list/tuple/set literals holding >=2 needle strings."""
    out: list[int] = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            count = sum(
                1 for e in n.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
                and e.value in NEEDLES
            )
            if count >= 2:
                out.append(n.lineno)
    return out


def test_needle_list_only_in_ssot():
    offenders = []
    for p, rel, tree in walk_src():
        if p == SSOT:
            continue
        locs = _needle_collection_lines(tree)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "An auth-revoked needle LIST was re-inlined outside web/_auth_revoked.py "
        f"— the divergence the 2026-06-09 census fixed: {offenders}. Import "
        "`is_auth_revoked` (or AUTH_REVOKED_NEEDLES) from web/_auth_revoked "
        "instead of copying the needles."
    )


def test_ssot_actually_holds_the_needles():
    """Guards the pin itself: the SSOT must still carry the needle list, else
    invariant 1 is vacuously true."""
    _t = parse_module(SSOT); assert _t is not None  # N-350 R31
    locs = _needle_collection_lines(_t)
    assert locs, "the needle list vanished from web/_auth_revoked.py"


# --------------------------------------------------------------------------
# Invariant 2 — the flag is SET/CLEARED only through the funnel.
# --------------------------------------------------------------------------
# The two private impls that actually touch the settings row.
_IMPLS = {"_maybe_mark_auth_stale", "_clear_auth_stale"}
# Files allowed to reference the impls directly, by REPO-RELATIVE path (not
# basename — a future ``oauth.py`` elsewhere must not be silently allow-listed):
# web/app.py DEFINES them + the ``record_provider_outcome`` funnel that
# dispatches to them; web/routers/ui/oauth.py is the explicit OAuth re-auth flow
# (a legitimate, audited direct clearer). Every OTHER credentialed path must go
# through ``record_provider_outcome``.
_ALLOWED_RELPATHS = {"web/app.py", "web/routers/ui/oauth.py"}


def _impl_references(tree: ast.AST) -> list[tuple[str, int]]:
    """Calls to OR bare-name references of the impls (the latter catches
    ``db_call(_clear_auth_stale, ...)`` indirection)."""
    refs: list[tuple[str, int]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else "")
            if name in _IMPLS:
                refs.append((name, n.lineno))
        elif isinstance(n, ast.Name) and n.id in _IMPLS:
            refs.append((n.id, n.lineno))
    return refs


def test_set_clear_only_via_funnel():
    offenders = []
    for p, rel, tree in walk_src():
        if rel in _ALLOWED_RELPATHS:
            continue
        refs = _impl_references(tree)
        if refs:
            offenders.append(f"{rel}: {refs}")
    assert not offenders, (
        "auth_stale SET/CLEAR impl referenced outside the record_provider_outcome "
        f"funnel / allow-list {_ALLOWED_RELPATHS}: {offenders}. A new credentialed "
        "path must route its outcome through record_provider_outcome(db, acct, "
        "exc) so set and clear stay symmetric — do not hand-roll a set/clear."
    )


# --------------------------------------------------------------------------
# Invariant 3 — every continuous credentialed-ingestion module is wired to the
# funnel (regression guard: a wired path can't silently lose its call).
# --------------------------------------------------------------------------
_WIRED_MODULES = (
    "web/poll_ingestion.py",       # unified poll
    "web/ingestion_push.py",       # Gmail + O365 push consumers + watch renewer
    "web/o365_renewer.py",         # O365 subscription renewer
    "web/watcher.py",              # IMAP IDLE watcher
    "web/background_sweepers.py",  # sent-mail capture
    "jobs/topic_backscan.py",      # operator-initiated backscan (same credential)
    "web/triage_runner_bulk.py",   # N-82: bulk triage + style-mine (same credential)
)


def test_continuous_ingestion_routes_through_funnel():
    missing = [
        m for m in _WIRED_MODULES
        if "record_provider_outcome" not in (SRC_ROOT / m).read_text(encoding="utf-8")
    ]
    assert not missing, (
        f"a continuous credentialed-ingestion path lost its auth_stale funnel "
        f"wiring: {missing}. Each must call record_provider_outcome on success "
        f"(clear) and on an auth-revoked failure (set)."
    )


# --------------------------------------------------------------------------
# Teeth — the pin must actually catch a planted regression.
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Invariant 5 (N-67) — every top-level async function in background_sweepers
# that performs a credentialed scan (scan_recent) must reference
# record_provider_outcome.  The module-string check in Invariant 3 can't
# distinguish a wired function from a sibling that is missing the call;
# this AST walk is function-granular.
# --------------------------------------------------------------------------
_SWEEPERS = SRC_ROOT / "web" / "background_sweepers.py"
_SCAN_RECENT = "scan_recent"


def _sweeper_funcs_with_scan_recent(tree: ast.AST):
    """Top-level async functions in background_sweepers that call scan_recent."""
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(
            isinstance(n, ast.Attribute) and n.attr == _SCAN_RECENT
            for n in ast.walk(node)
        ):
            yield node.name, node.lineno, node


def test_sweeper_scan_funcs_route_through_funnel():
    """Every async sweeper function that calls scan_recent must reference
    record_provider_outcome (N-67: the HIPAA counter previously lacked it)."""
    tree = parse_module(_SWEEPERS); assert tree is not None  # N-350 R31
    offenders = [
        f"background_sweepers.py::{name}:{lineno}"
        for name, lineno, node in _sweeper_funcs_with_scan_recent(tree)
        if not _references_funnel(node)
    ]
    assert not offenders, (
        "a background_sweepers.py scan function does NOT route its outcome "
        f"through record_provider_outcome: {offenders}. Wire both the scan "
        "failure edge (pass exc) and the success edge (pass None) through "
        "db_call(record_provider_outcome, db, acct, exc_or_none) — mirroring "
        "the non-HIPAA sent-mail capture twin."
    )


def test_pin_has_teeth_sweeper_scan_unwired(tmp_path):
    bad = tmp_path / "sweepers.py"
    bad.write_text(
        "async def _run_counter(db, secrets, acct):\n"
        "    result = await loop.scan_recent(limit=50)\n"
        "    return result\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    funcs = list(_sweeper_funcs_with_scan_recent(tree))
    assert funcs and not _references_funnel(funcs[0][2])


def test_pin_has_teeth_sweeper_scan_wired_passes(tmp_path):
    ok = tmp_path / "sweepers2.py"
    ok.write_text(
        "from email_triage.web.app import record_provider_outcome\n"
        "async def _run_counter(db, secrets, acct):\n"
        "    result = await loop.scan_recent(limit=50)\n"
        "    await db_call(record_provider_outcome, db, acct, None)\n"
        "    return result\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    funcs = list(_sweeper_funcs_with_scan_recent(tree))
    assert funcs and _references_funnel(funcs[0][2])


# --------------------------------------------------------------------------
# Teeth — the pin must actually catch a planted regression.
# --------------------------------------------------------------------------
def test_pin_has_teeth_needle_list(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "NEEDLES = ('invalid_grant', 'AUTHENTICATIONFAILED', 'invalid_client')\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _needle_collection_lines(tree)


def test_pin_has_teeth_single_literal_is_not_a_list(tmp_path):
    """A lone protocol-field literal (a provider matching one OAuth error code)
    must NOT trip invariant 1 — only a *collection* of needles does."""
    ok = tmp_path / "p.py"
    ok.write_text(
        "if err.get('error') == 'invalid_grant':\n    raise OAuthRefreshFailed()\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _needle_collection_lines(tree)


def test_pin_has_teeth_direct_impl_call(tmp_path):
    bad = tmp_path / "n.py"
    bad.write_text(
        "async def f(db, acct):\n"
        "    await db_call(_clear_auth_stale, db, acct['id'])\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _impl_references(tree)


# --------------------------------------------------------------------------
# Invariant 4 — every ROUTER handler that performs a
# credentialed LIVENESS op (one that PROVES the token is alive: a Gmail watch
# register, an O365 subscription create, a profile fetch, or the /me probe)
# must route its outcome through record_provider_outcome. The 4 manual
# operator-triggered endpoints (Force-renew, Gmail/O365 Start Push, O365 Probe)
# each called such an op but neither SET nor CLEARED the chip — a set-broad/
# clear-narrow lie (PD#18) the hand-listed _WIRED_MODULES (continuous paths
# only, Invariant 3) was structurally blind to. This invariant is the
# count-agnostic interprocedural net the verifier asked for: it covers a FUTURE
# manual endpoint automatically. Liveness ops ONLY — stop_watch /
# delete_subscription are NOT liveness proofs (a failed stop drops the row
# anyway), so they are deliberately excluded.
# --------------------------------------------------------------------------
_LIVENESS_METHODS = {"register_watch", "create_subscription", "get_profile"}
# oauth.py clears the chip directly via the audited OAuth re-auth flow — it is
# the Invariant-2 allow-list; app.py DEFINES the funnel. Same set reused.
_FUNNEL_EXEMPT_RELPATHS = _ALLOWED_RELPATHS  # {web/app.py, web/routers/ui/oauth.py}


def _is_liveness_call(n: ast.AST) -> bool:
    if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
        return False
    if n.func.attr in _LIVENESS_METHODS:
        return True
    # The O365 probe is the bespoke shape ``provider._request("GET", "/me")``.
    if n.func.attr == "_request":
        return any(
            isinstance(a, ast.Constant) and a.value == "/me" for a in n.args
        )
    return False


def _module_funcs_with_liveness_op(tree: ast.AST):
    """Yield ``(name, lineno, node)`` for each MODULE-LEVEL function whose body
    (incl. nested defs) performs a credentialed liveness op."""
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_is_liveness_call(c) for c in ast.walk(node)):
            yield node.name, node.lineno, node


def _references_funnel(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id == "record_provider_outcome":
            return True
        if isinstance(n, ast.Attribute) and n.attr == "record_provider_outcome":
            return True
    return False


def test_router_liveness_ops_route_through_funnel():
    offenders = []
    for p, rel, tree in walk_src("web/routers"):
        if rel in _FUNNEL_EXEMPT_RELPATHS:
            continue
        for name, lineno, node in _module_funcs_with_liveness_op(tree):
            if not _references_funnel(node):
                offenders.append(f"{rel}::{name}:{lineno}")
    assert not offenders, (
        "a router handler performs a credentialed LIVENESS op (register_watch / "
        "create_subscription / get_profile / the /me probe) but does NOT route "
        f"its outcome through record_provider_outcome: {offenders}. Wire it "
        "(CLEAR on success, SET on failure — the funnel needle-filters transient "
        "errors), or add the module to _FUNNEL_EXEMPT_RELPATHS with justification "
        "(an audited direct clearer like the OAuth re-auth flow)."
    )


def test_pin_has_teeth_router_liveness_unwired(tmp_path):
    bad = tmp_path / "h.py"
    bad.write_text(
        "async def start(request, account_id, owned):\n"
        "    user, acct, db, secrets = owned\n"
        "    data = await provider.register_watch(topic)\n"
        "    return data\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    funcs = list(_module_funcs_with_liveness_op(tree))
    assert funcs and not _references_funnel(funcs[0][2])


# --------------------------------------------------------------------------
# Invariant 6 (N-82) — every bulk-dispatcher module that contains a
# credentialed search call (provider.search / provider.search_iter) must
# reference record_provider_outcome.  This is the count-agnostic net that
# supersedes the hand-typed _WIRED_MODULES entry for bulk dispatchers:
# adding a new bulk file with a provider.search without wiring the funnel
# is caught automatically, even if _WIRED_MODULES is not updated.
# --------------------------------------------------------------------------
_BULK_DISPATCHERS = SRC_ROOT / "web" / "triage_runner_bulk.py"
_CREDENTIALED_SEARCH_ATTRS = {"search", "search_iter"}


def _module_funcs_with_credentialed_search(tree: ast.AST):
    """Yield ``(name, lineno, node)`` for each module-level function whose
    body calls ``provider.search`` or ``provider.search_iter``."""
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(
            isinstance(n, ast.Attribute) and n.attr in _CREDENTIALED_SEARCH_ATTRS
            for n in ast.walk(node)
        ):
            yield node.name, node.lineno, node


def test_bulk_dispatcher_credentialed_search_funcs_route_through_funnel():
    """Every module-level function in triage_runner_bulk.py that performs a
    credentialed search (provider.search / provider.search_iter) must
    reference record_provider_outcome (N-82)."""
    tree = parse_module(_BULK_DISPATCHERS); assert tree is not None  # N-350 R31
    offenders = [
        f"triage_runner_bulk.py::{name}:{lineno}"
        for name, lineno, node in _module_funcs_with_credentialed_search(tree)
        if not _references_funnel(node)
    ]
    assert not offenders, (
        "a triage_runner_bulk.py function performs a credentialed search "
        "(provider.search / provider.search_iter) but does NOT reference "
        f"record_provider_outcome: {offenders}. Wire both edges (SET on "
        "auth-revoked failure, CLEAR on success) — see run_triage_all and "
        "run_style_mine_job for the pattern (N-82)."
    )


def test_pin_has_teeth_bulk_dispatcher_search_unwired(tmp_path):
    bad = tmp_path / "bulk.py"
    bad.write_text(
        "async def run_job(app, conn, job):\n"
        "    async for batch in provider.search_iter(q):\n"
        "        pass\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    funcs = list(_module_funcs_with_credentialed_search(tree))
    assert funcs and not _references_funnel(funcs[0][2])


def test_pin_has_teeth_bulk_dispatcher_search_wired_passes(tmp_path):
    ok = tmp_path / "bulk2.py"
    ok.write_text(
        "from email_triage.web.app import record_provider_outcome\n"
        "async def run_job(app, conn, job):\n"
        "    async for batch in provider.search_iter(q):\n"
        "        pass\n"
        "    await db_call(record_provider_outcome, conn, acct, None)\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    funcs = list(_module_funcs_with_credentialed_search(tree))
    assert funcs and _references_funnel(funcs[0][2])


def test_pin_has_teeth_router_liveness_wired_passes(tmp_path):
    ok = tmp_path / "h2.py"
    ok.write_text(
        "from email_triage.web.app import record_provider_outcome\n"
        "async def start(request, account_id, owned):\n"
        "    user, acct, db, secrets = owned\n"
        "    data = await provider.create_subscription(url, cs)\n"
        "    await db_call(record_provider_outcome, db, acct, None)\n"
        "    return data\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    funcs = list(_module_funcs_with_liveness_op(tree))
    assert funcs and _references_funnel(funcs[0][2])


def test_pin_has_teeth_probe_me_request_is_liveness(tmp_path):
    """The bespoke O365 probe shape ``_request("GET", "/me")`` is detected."""
    code = "async def probe():\n    return await provider._request('GET', '/me')\n"
    funcs = list(_module_funcs_with_liveness_op(ast.parse(code)))
    assert funcs, "the /me probe liveness shape was not detected"
    # A non-/me _request is NOT a liveness op.
    code2 = "async def other():\n    return await provider._request('GET', '/messages')\n"
    assert not list(_module_funcs_with_liveness_op(ast.parse(code2)))


# --------------------------------------------------------------------------
# Invariant 7 (census run15 #4) — every top-level async function in
# background_sweepers that performs a credentialed RE-FETCH
# (``provider.fetch_message`` — the retry-queue drainer's recovery op) must
# reference record_provider_outcome.  Invariant 5 is keyed on ``scan_recent``;
# the retry drainer (``_recover_one_retry_row``) uses ``fetch_message``, a
# DIFFERENT credentialed op that BOTH the module-string check (Invariant 3 —
# the file already has the call via the sent-scan twins) and the scan_recent
# walk (Invariant 5) were blind to.  So the drainer could (and did) re-fetch
# with the account credential without ever clearing/setting the auth_stale chip
# — a PD#18 set-broad/clear-narrow lie: a row that drained DURING an outage left
# the re-auth chip stuck, and a dead token on the drainer path looked healthy.
# --------------------------------------------------------------------------
# The provider ABC (providers/base.py) exposes BOTH a single-message
# ``fetch_message`` and a batch ``fetch_messages_batch``. Key the pin on the
# whole credentialed-re-fetch family (DA run15 #4): the drainer uses
# ``fetch_message`` today, but a FUTURE batch-drainer using
# ``fetch_messages_batch`` would otherwise slip the net silently (the same
# single-needle blind spot that hid the drainer from Invariant 3/5).
_REFETCH_ATTRS = {"fetch_message", "fetch_messages_batch"}


def _sweeper_funcs_with_refetch(tree: ast.AST):
    """Top-level async functions in background_sweepers that call a credentialed
    re-fetch (``provider.fetch_message`` / ``provider.fetch_messages_batch``)."""
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(
            isinstance(n, ast.Attribute) and n.attr in _REFETCH_ATTRS
            for n in ast.walk(node)
        ):
            yield node.name, node.lineno, node


def test_sweeper_refetch_funcs_route_through_funnel():
    """Every async sweeper function that re-fetches a message
    (provider.fetch_message) must reference record_provider_outcome — both the
    fetch failure edge (SET iff auth-revoked; the funnel needle-filters) and the
    success edge (CLEAR). (census run15 #4 — the retry drainer was the missing
    credentialed surface.)"""
    tree = parse_module(_SWEEPERS); assert tree is not None  # N-350 R31
    offenders = [
        f"background_sweepers.py::{name}:{lineno}"
        for name, lineno, node in _sweeper_funcs_with_refetch(tree)
        if not _references_funnel(node)
    ]
    assert not offenders, (
        "a background_sweepers.py re-fetch function does NOT route its outcome "
        f"through record_provider_outcome: {offenders}. Wire BOTH edges — the "
        "fetch failure (pass the exc; the funnel SETs only on an auth-revoked "
        "needle) and the success (pass None to CLEAR) — mirroring the sent-mail "
        "capture twin / ingestion_push.py:300."
    )


def test_pin_has_teeth_sweeper_refetch_unwired(tmp_path):
    bad = tmp_path / "sweepers3.py"
    bad.write_text(
        "async def _recover(app, row):\n"
        "    message = await provider.fetch_message(fetch_id)\n"
        "    return 'done'\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    funcs = list(_sweeper_funcs_with_refetch(tree))
    assert funcs and not _references_funnel(funcs[0][2])


def test_pin_has_teeth_sweeper_refetch_wired_passes(tmp_path):
    ok = tmp_path / "sweepers4.py"
    ok.write_text(
        "from email_triage.web.app import record_provider_outcome\n"
        "async def _recover(app, row):\n"
        "    message = await provider.fetch_message(fetch_id)\n"
        "    await db_call(record_provider_outcome, db, acct, None)\n"
        "    return 'done'\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    funcs = list(_sweeper_funcs_with_refetch(tree))
    assert funcs and _references_funnel(funcs[0][2])


# --------------------------------------------------------------------------
# Invariant 8 (census run16 #1, HIGH) — a SWALLOWING fetch leg in a funnel-wired
# sweep must classify auth-revoked. The auth_stale funnel CLEARs the re-auth chip
# on a successful sweep; if a per-message fetch_message/fetch_messages_batch hits
# an auth-revoked (dead-token) error that the ``except`` SWALLOWS (continue /
# return, no raise), the sweep completes "successfully" and CLEARs the chip on a
# REVOKED credential — masking re-auth (the search legs already re-raise via N-82).
# So every swallowing fetch-leg handler in a record_provider_outcome-wired file
# must EITHER reference ``is_auth_revoked_exc`` (re-raise the dead token) OR route
# the exc through ``record_provider_outcome`` (SET via the funnel needle-filter,
# e.g. the retry-drainer). HIPAA §164.312(b) / §164.308(a)(7).
# --------------------------------------------------------------------------
_FETCH_ATTRS_8 = {"fetch_message", "fetch_messages_batch"}

# The census-"weaker" delta-CLEAR ingestion paths: their record_provider_outcome
# CLEAR fires on the DELTA/poll/IDLE fetch (the credential proved alive getting
# the message list), NOT after the per-message loop — so a swallowed per-message
# fetch does not mask delta-time liveness the same way (run16 #1: "5 clean + 4
# weaker"). Allow-listed by relpath + reason; tracked as a lower-severity follow-up.
_DELTA_CLEAR_ALLOW = {
    "web/poll_ingestion.py": "per-message swallow; CLEAR is on the poll/delta fetch, not post-loop (run16 #1 'weaker')",
    "web/ingestion_push.py": "per-message swallow; CLEAR is on the push-delta fetch, not post-loop (run16 #1 'weaker')",
    "web/watcher.py": "IMAP IDLE per-message; CLEAR/SET on the IDLE connect, not post-fetch (run16 #1 'weaker')",
}


def _try_body_has_fetch(try_node: ast.Try) -> bool:
    for stmt in try_node.body:
        for n in ast.walk(stmt):
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in _FETCH_ATTRS_8
            ):
                return True
    return False


def _handler_swallows_without_auth_guard(h: ast.ExceptHandler) -> bool:
    """An ``except`` that SWALLOWS the fetch error — does NOT re-raise (via
    ``continue``, ``return``, OR an IMPLICIT fall-through past the handler, the
    most common shape and the one the DA found my first cut missed) — AND does
    NOT classify auth-revoked (no ``is_auth_revoked_exc`` re-raise, no
    ``record_provider_outcome`` SET-route). A handler that re-raises ANYWHERE
    (incl. ``if is_auth_revoked_exc(e): raise``) is fine; the no-``raise`` test
    catches the implicit-fall-through swallow that a ``Continue``/``Return``
    check is blind to."""
    nodes = list(ast.walk(h))
    has_raise = any(isinstance(n, ast.Raise) for n in nodes)
    refs_guard = any(
        (isinstance(n, ast.Name) and n.id in ("is_auth_revoked_exc", "record_provider_outcome"))
        or (isinstance(n, ast.Attribute) and n.attr in ("is_auth_revoked_exc", "record_provider_outcome"))
        for n in nodes
    )
    return (not has_raise) and (not refs_guard)


def _fn_references(node: ast.AST, names: set[str]) -> bool:
    for n in ast.walk(node):
        if (isinstance(n, ast.Name) and n.id in names) or (
            isinstance(n, ast.Attribute) and n.attr in names
        ):
            return True
    return False


def test_swallowing_fetch_leg_classifies_auth_revoked():
    # Scope (DA run16 #1): every file WIRED to the auth_stale funnel (references
    # record_provider_outcome). The earlier is_auth_revoked_exc FUNCTION-gate was
    # CIRCULAR — a reverted site loses its only auth-ref and escapes scope, so the
    # pin couldn't regression-guard it (it protected only 2 of the 5 fixed sites).
    # File-scope + the no-``raise`` swallow detector also covers a pure per-message
    # worker inside a funnel-CLEAR sweep (e.g. triage_runner_bulk._process_one_message,
    # whose search leg lives in the CALLER run_triage_all — a cross-function asymmetry).
    offenders = set()
    for p, rel, tree in walk_src():
        if rel in _DELTA_CLEAR_ALLOW:
            continue
        if "record_provider_outcome" not in p.read_text(encoding="utf-8"):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Try) and _try_body_has_fetch(node):
                for h in node.handlers:
                    if _handler_swallows_without_auth_guard(h):
                        offenders.add(f"{rel}:{h.lineno}")
    offenders = sorted(offenders)
    assert not offenders, (
        "a SWALLOWING fetch_message/fetch_messages_batch leg in a "
        "record_provider_outcome-wired file does NOT classify auth-revoked "
        f"(census run16 #1): {offenders}. A swallowed dead-token error lets the "
        "sweep's success-path CLEAR fire on a REVOKED credential, masking re-auth. "
        "Add `if is_auth_revoked_exc(exc): raise` (re-raise to the SET edge, like "
        "the search leg / N-82) or route the exc through record_provider_outcome; "
        "or, if the CLEAR fires on the delta/IDLE fetch (not post-loop), add the "
        "file to _DELTA_CLEAR_ALLOW with a reason."
    )


def test_invariant8_has_teeth():
    bad = ast.parse(
        "from email_triage.web.app import record_provider_outcome\n"
        "async def sweep(provider, db, acct):\n"
        "    await db_call(record_provider_outcome, db, acct, None)\n"
        "    for mid in ids:\n"
        "        try:\n"
        "            m = await provider.fetch_message(mid)\n"
        "        except Exception as exc:\n"
        "            continue\n"
    )
    tries = [n for n in ast.walk(bad) if isinstance(n, ast.Try)]
    assert tries and _try_body_has_fetch(tries[0])
    assert _handler_swallows_without_auth_guard(tries[0].handlers[0])
    # ...the guarded form is NOT flagged.
    good = ast.parse(
        "async def sweep(provider):\n"
        "    try:\n"
        "        m = await provider.fetch_message(mid)\n"
        "    except Exception as exc:\n"
        "        if is_auth_revoked_exc(exc):\n"
        "            raise\n"
        "        continue\n"
    )
    gtries = [n for n in ast.walk(good) if isinstance(n, ast.Try)]
    assert not _handler_swallows_without_auth_guard(gtries[0].handlers[0])
