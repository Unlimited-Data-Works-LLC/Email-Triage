""" /  — permanent regression guard for async-reachable DB safety.

Background
----------
The app keeps ONE shared ``sqlite3.Connection`` as ``app.state.db``.
Any ``async def`` (router handler, background-loop tick, push / IDLE /
scan consumer, action-loop body) that touches that connection WITHOUT
hopping to a worker thread via ``db_call`` runs SQLite work on the
event-loop thread. Under concurrency that surfaces as
``sqlite3.InterfaceError`` / ``OperationalError`` — the Python
``sqlite3`` driver rejects two threads using one ``Connection``
concurrently — or, at best, a frozen event loop for the query
duration.

The fix infrastructure (``web/db_threadpool.db_call`` +
``web/db_writelock``) routes every async-reachable DB touch through a
threadpool worker that also holds the process-wide DB lock.  was
the sweep that closed the then-known offenders; three prior cycles had
each missed sites by hand-scoped enumeration.

Why  had to rewrite this guard
----------------------------------
The first version of this guard was meant to make connection-safety a
permanent ratchet — and it did not, because it was structurally too
narrow. The Cycle-3 verification gate found four ways real offenders
slipped past a green guard:

  (a) **Module scope.** Discovery scanned only ``web/routers/**`` plus
      ``web/app.py`` — never ``actions/``, ``web/watch_runner.py``,
      ``web/triage_one.py``, ``web/triage_runner*.py``,
      ``web/access_audit.py``, ``secrets.py``. Offenders in those
      modules were simply never looked at.
  (b) **Import aliases.** ``from … import get_current_user as
      _get_current_user`` (health.py) and ``import enqueue_watcher_retry
      as _wr_enqueue`` (app.py ×5) defeated the bare-name catalogue
      match — and an aliased ``db_call`` (``import db_call as _db_call``
      in access_audit.py) defeated *safe-zone* recognition, which would
      have produced false positives.
  (c) **Sync wrapper helpers.** The walker cleared the async context at
      every nested ``def``, assuming every sync def is a ``db_call``
      closure. That is false for sync *instance methods* and *module
      helpers* — ``watch_runner._record_watch_fired``,
      ``sent_mail_capture._captured_row_count``, the auth wrappers
      ``_require_auth`` / ``_require_admin_user`` — each does DB work
      (or calls a DB helper) and is called *inline* from an ``async
      def``. The old guard saw none of them.
  (d) **Opt-out.** ``# async-db-ok`` matched the bare substring
      anywhere on the line — even inside a string literal or unrelated
      prose — so a coincidental occurrence could silently suppress a
      real finding.

 closes all four. See "What this guard does" below.

What this guard does
--------------------
A pure AST + ``tokenize`` walk (no DB, no event loop, no network — so
fully deterministic, cannot flake) over **every module under
``src/email_triage`` that contains an ``async def``**. Module discovery
is dynamic: a new async-bearing module is in scope automatically, so
the guard can never silently shrink.

It works in three layers:

  * **Cross-module pass.** Before scanning any single module, the guard
    builds — to a global fixpoint — the set of DB-touching function
    *names* per module: both names a module DEFINES that touch the DB
    and names it IMPORTS from a DB-touching definition elsewhere (so a
    re-export through a package ``__init__`` is followed). This is the
    structural completeness layer: a per-module scan
    alone cannot know that an imported wrapper — ``app.py`` calling
    ``_ice_eff``, an alias of ``is_calendar_effectively_enabled`` from
    ``…ui._shared`` — touches the DB. Hand-listing every such wrapper in
    a catalogue is the enumeration that failed three cycles; the
    cross-module pass removes the need for it.

  * **Pass 1 — local DB-touching sync helpers.** For each module,
    catalogue every sync ``def`` / method whose own body unsafely
    touches the DB: a raw ``.execute``/``.commit``/… on a
    connection-like name, a call to a catalogued ``db.py`` helper, a
    call to a known authz wrapper, an explicit ``get_write_lock()``
    acquisition, a call to another local helper already catalogued, or
    a call to a cross-module DB-touching import resolved by the layer
    above. Pass 1 iterates to a fixpoint, so a sync wrapper that is
    DB-touching only transitively (``_require_admin_user`` →
    ``get_current_user``) is still caught.

  * **Pass 2 — async offenders.** Walk every ``async def`` body and
    fail on a non-``db_call``-wrapped call to: (a) a raw sqlite method
    on a connection-like name; (b) a catalogued ``db.py`` read helper;
    (c) a catalogued ``@db_write`` write helper; (d) a catalogued authz
    wrapper; (f) a *local* sync helper catalogued by pass 1; (g) a
    cross-module DB-touching helper resolved by the cross-module pass.

Import-``as`` aliases are resolved module-by-module for every name the
guard matches — including ``db_call`` itself, so an aliased safe-zone
marker is honoured rather than mis-flagged.

A *call* to a ``@contextmanager`` / ``@asynccontextmanager`` /
generator function is never treated as a DB touch — calling it only
builds the object; the body runs at ``__enter__`` / iteration, which
the async callers correctly drive off-loop. A DB touch inside a
``lambda`` belongs to the lambda's own sync scope, not the enclosing
``async def``.

…unless the offending site is inside an ``await db_call(...)`` argument
(the safe zone) or carries an explicit ``# async-db-ok`` opt-out
comment on the line or the line above. The opt-out is now matched as a
real ``tokenize`` COMMENT token — a coincidental ``async-db-ok``
substring inside a string literal no longer suppresses anything.

Legitimate exception: the ``# async-db-ok`` opt-out
----------------------------------------------------
A handful of direct touches are intentionally on the loop thread
because there is provably no event-loop contention — chiefly the
FastAPI ``lifespan`` startup body (runs ONCE before the server
accepts any request) and CLI entrypoints (single-threaded, no loop).
Those carry a ``# async-db-ok`` comment with a rationale. This guard
honours that opt-out; adding one is a deliberate, reviewable act.

Cross-references
----------------
- ``src/email_triage/web/db_threadpool.py`` — ``db_call``.
- ``src/email_triage/web/db_writelock.py`` — ``@db_write`` + the lock.
- ``tests/test_web/test_db_threadpool.py`` — the wrapper's own tests.
- ``tests/test_web/test_db_writelock.py`` — the write-lock's tests.
"""

from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path

import pytest

from _pin_harness import SRC_ROOT, iter_files, iter_src_files, parse_module, relpath, parse_source  # N-350 R31

# ---------------------------------------------------------------------------
# Helper-name catalogues — extracted from web/db.py / db_auth_helpers /
# auth.py / dependencies.py. These mirror the one-shot  analyzer.
# If db.py grows a new DB-touching helper that an async handler calls
# directly, add it here so the guard keeps catching the shape.
#
# NOTE: these catalogues are the *cross-module* layer. Sync
# wrappers defined and called *within one module* no longer need to be
# listed here — pass 1's per-module call-graph discovers them. The
# catalogues are only for DB-touching names that travel across module
# boundaries via ``import``.
# ---------------------------------------------------------------------------

# @db_write-decorated helpers (write + commit, must run off-loop).
_DB_WRITE = set("""
_apply_migrations migrate_oauth_creds_to_install_level
migrate_o365_creds_to_install_level scrub_queue_summary_from_routes
ensure_categories_indexes ensure_categories_user_id_migration
seed_categories ensure_upgrade_categories create_category update_category
delete_category promote_category_to_system demote_category_to_user
set_setting delete_setting add_account_delegate remove_account_delegate
create_email_account set_account_active set_account_hipaa
update_email_account update_email_account_config update_account_config_keys
update_email_account_aliases delete_email_account upsert_account_route
delete_account_route save_folder_prefs record_triage_run create_triage_job
claim_next_queued_triage_job bump_triage_job_counters finish_triage_job
request_triage_job_cancel update_triage_job_cursor record_processed_message
requeue_orphaned_triage_jobs prune_triage_runs insert_log_entry
prune_log_entries prune_log_entries_by_age_and_count
set_user_escalation_categories record_user_status_event set_user_disabled
bump_session_epoch record_auth_event record_hipaa_boundary
record_hipaa_access_event update_hipaa_access_event record_discover_run
record_api_key_event record_access_event mark_triaged
prune_triaged_messages upsert_gmail_watch update_gmail_watch_history
delete_gmail_watch upsert_o365_subscription delete_o365_subscription
record_push_delivery prune_push_deliveries record_o365_notification
update_o365_subscription_delta_link record_o365_subscription_renewal
record_o365_subscription_error set_alias_mode_enabled_for_account
set_account_style_per_alias delete_account_style_per_alias
set_user_style_knobs set_hipaa_style_descriptor
delete_hipaa_style_descriptor record_style_distill_event
enqueue_style_distill_retry pause_style_distill_account
unpause_style_distill_account clear_style_distill_queue_entry
set_per_contact_style_hipaa delete_per_contact_style_hipaa
delete_all_per_contact_style_hipaa gc_per_contact_style_hipaa
enqueue_style_distill_contact_retry pause_style_distill_contact
unpause_style_distill_contact clear_style_distill_contact_queue_entry
record_hipaa_sent_message record_hipaa_sent_message_if_new
prune_hipaa_sent_dedup reset_hipaa_send_counter
set_user_anti_ai_style_guide delete_sent_mail_index_for_account
create_label update_label delete_label apply_labels_to_message
set_rule_provider_labels remove_label_from_message create_ai_backend
update_ai_backend delete_ai_backend set_account_style_learning_backend
enqueue_retry mark_retry_done mark_retry_dead
""".split())

# Undecorated sync db.py helpers that still hit the DB (excludes pure
# in-memory helpers like account_email / clamp_poll_interval_minutes).
_DB_READ = set("""
list_categories get_categories_dict count_personal_categories get_category
get_setting get_bool_setting set_bool_setting get_mailbox_hwm
set_mailbox_hwm delete_mailbox_hwm get_mailbox_route_overrides
set_mailbox_route_overrides effective_routes_by_cat list_email_accounts
list_account_delegates is_account_delegate can_manage_account
get_email_account list_account_routes get_account_route get_folder_prefs
get_visible_folders list_triage_runs get_triage_job list_triage_jobs
count_active_triage_jobs_for_account is_message_processed_in_job
count_processed_messages_in_job list_log_entries
get_user_escalation_categories should_escalate is_user_disabled
disabled_user_ids list_user_status_events list_auth_events
list_hipaa_boundary_events latest_hipaa_boundary
latest_hipaa_boundaries_for_accounts list_discover_runs
list_hipaa_access_events list_api_key_events list_access_events
get_last_log_row_hash verify_log_chain is_triaged get_gmail_watch
get_gmail_watch_by_email list_gmail_watches_expiring list_gmail_watches
get_o365_subscription get_o365_subscription_by_subscription_id
list_o365_subscriptions list_o365_subscriptions_expiring
get_push_deliveries_window get_meeting_prefs set_meeting_prefs
is_calendar_enabled get_style_profile set_style_profile
delete_style_profile get_account_style_per_alias
list_account_style_per_alias get_user_style_knobs
is_style_learning_master_enabled set_style_learning_master_enabled
get_style_learning_capture_interval_hours
set_style_learning_capture_interval_hours
get_style_learning_mine_limit_default
set_style_learning_mine_limit_default resolve_account_mine_limit
set_auto_scan_enabled_for_account is_rag_sent_index_enabled
set_rag_sent_index_enabled is_style_knobs_hipaa_allow
set_style_knobs_hipaa_allow is_hipaa_style_distill_enabled
set_hipaa_style_distill_enabled get_hipaa_style_descriptor
style_distill_event_counts list_style_distill_events
get_style_distill_queue_entry list_paused_style_distill_accounts
claim_next_style_distill_queue_entry get_per_contact_style_hipaa
list_per_contact_style_hipaa_for_account
get_style_distill_contact_queue_entry list_paused_style_distill_contacts
claim_next_style_distill_contact_queue_entry get_hipaa_send_counter
list_hipaa_per_contact_counters last_successful_style_distill_at
get_global_anti_ai_style_guide set_global_anti_ai_style_guide
get_user_anti_ai_style_guide get_sent_mail_index_summary
get_captured_pair_count get_dashboard_dismissed_steps
set_dashboard_dismissed_steps get_dashboard_getting_started
get_recent_triage_runs_for_user count_triage_messages_in_window
triage_performance_per_message triage_category_counts
triage_account_breakdown triage_error_rate list_labels get_label
get_rule_provider_labels list_labels_on_message list_messages_with_label
list_ai_backends get_ai_backend count_accounts_using_ai_backend
get_account_style_learning_backend list_due_retries get_retry
list_retries_for_admin count_recent_deads count_pending_retries
""".split())

# db_auth_helpers — all DB-touching.
_DB_AUTH = set("""
add_dev_key list_dev_keys find_dev_key_by_fingerprint revoke_dev_key
mark_dev_key_used add_hardware_key list_hardware_keys
find_hardware_key_by_credential_id update_hardware_key_sign_count
revoke_hardware_key user_has_active_hardware_key
get_or_create_webauthn_user_handle find_user_by_webauthn_handle
store_webauthn_challenge consume_webauthn_challenge
prune_expired_webauthn_challenges insert_acme_renewal_log
list_acme_renewal_log
""".split())

# auth.py DB helpers commonly called directly inside async bodies.
_AUTH_HELPERS = set("""
get_user_by_email verify_api_key create_api_key list_api_keys
revoke_api_key get_user_by_id list_users create_user update_user_role
delete_user count_users record_login_failure clear_login_failures
""".split())

# Authz / wrapper helpers that do DB work (directly, or transitively via
# a catalogued helper) and travel across modules via ``import``. Calling
# any of these inline from an ``async def`` runs sync SQLite — and, for
# the lock-taking ones, blocks the loop while it waits on the lock.
#  added the cross-module wrappers (`_require_auth`,
# `_require_admin_user`, `enqueue_watcher_retry`); pass 1 catches the
# *same-module* call sites of these names structurally, this catalogue
# is the cross-import backstop.
_AUTHZ_DIRECT = set("""
get_current_user _require_admin _require_login require_auth
_require_user_fragment _require_owned_account
_require_owned_account_or_login _require_auth _require_admin_user
enqueue_watcher_retry
""".split())

# sqlite3.Connection methods that mutate / iterate the connection.
_DB_METHODS = {
    "execute", "executemany", "executescript", "commit", "cursor",
    "rollback",
}

# Bare names that conventionally hold the shared connection. ``_conn``
# was added in  — ``DbSecrets`` stores the connection as
# ``self._conn`` and ran raw ``.execute``/``.commit`` past the old
# guard's ``_DB_NAMES`` set.
_DB_NAMES = {"db", "conn", "connection", "_db", "_conn"}

# The canonical safe-zone marker. Aliases of this name (``import
# db_call as _db_call``) are resolved per module so an aliased safe
# zone is still recognised.
_DB_CALL_CANON = "db_call"

# Everything the guard treats as a DB-touching name when it appears as
# a bare-name call — the union the matcher consults after alias
# resolution.
_ALL_HELPERS = _DB_WRITE | _DB_READ | _DB_AUTH | _AUTH_HELPERS | _AUTHZ_DIRECT


# ---------------------------------------------------------------------------
# Opt-out detection — real COMMENT tokens only)
# ---------------------------------------------------------------------------

def _optout_lines(src: str) -> set[int]:
    """Line numbers carrying a genuine ``# async-db-ok`` opt-out comment.

    Uses ``tokenize`` so the marker is matched only inside a real
    COMMENT token — an ``async-db-ok`` substring inside a string literal
    or other source text can no longer suppress a finding. The marker
    must appear as a whitespace-delimited token within the comment
    (``# async-db-ok: rationale``), not as an arbitrary
    substring.
    """
    flagged: set[int] = set()
    try:
        toks = tokenize.generate_tokens(io.StringIO(src).readline)
        for tok in toks:
            if tok.type != tokenize.COMMENT:
                continue
            # Strip the leading '#' and split on whitespace; the marker
            # must be a standalone token (tolerating a trailing ':' so
            # "# async-db-ok: why" works). Backticks are deliberately
            # NOT stripped — a real opt-out is written plain
            # (``# async-db-ok: rationale``); a markdown-styled
            # ``async-db-ok`` in a prose comment is explanatory text,
            # not an opt-out, and must not suppress an adjacent line.
            body = tok.string.lstrip("#").strip()
            words = body.replace(",", " ").split()
            for w in words:
                if w.rstrip(":-").lower() in ("async-db-ok", "async-db-todo"):
                    flagged.add(tok.start[0])
                    break
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # A file that does not tokenize cleanly will also fail to parse;
        # the parse step raises the real, actionable error.
        pass
    return flagged


# ---------------------------------------------------------------------------
# Import-alias resolution)
# ---------------------------------------------------------------------------

def _alias_map(tree: ast.AST) -> dict[str, str]:
    """Map every locally-bound name to the canonical name it imports.

    Handles both ``import x as y`` and ``from m import x as y`` (and the
    non-aliased forms, which map a name to itself). The map lets the
    matcher recognise an aliased ``db_call`` or an aliased DB helper by
    its canonical name. Function-local imports are included — the app
    uses them heavily (``from … import get_current_user`` inside a
    handler body), so a module-level-only scan would miss them.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                bound = n.asname or n.name.split(".")[-1]
                canon = n.name.split(".")[-1]
                aliases[bound] = canon
        elif isinstance(node, ast.ImportFrom):
            for n in node.names:
                if n.name == "*":
                    continue
                bound = n.asname or n.name
                aliases[bound] = n.name
    return aliases


def _resolve_relative_import(
    node: ast.ImportFrom, this_module: str, is_package: bool,
) -> str:
    """Resolve an ``ast.ImportFrom``'s ``module`` to an absolute dotted
    path, honouring ``node.level`` (relative-import dots).

    The subtlety: Python resolves a relative import against the
    importing module's ``__package__``, not its ``__name__``. For a
    *non-package* module ``pkg.sub.mod``, ``__package__`` is
    ``pkg.sub`` — one component shorter than ``__name__``. For a
    *package* ``__init__.py`` whose dotted name is ``pkg.sub``,
    ``__package__`` is ``pkg.sub`` itself — equal to ``__name__``.

    ``_module_dotted_name`` already collapses an ``__init__.py`` to its
    package name, so ``this_module`` for a package IS the package. The
    ``is_package`` flag tells the two cases apart:

      * package ``__init__`` — ``__package__`` == ``this_module``;
      * regular module — ``__package__`` == ``this_module`` minus its
        last component.

    ``level == 1`` then means ``__package__``; each extra level strips
    one more trailing component. The old code stripped ``level``
    components off ``this_module`` unconditionally — correct for a
    regular module but off-by-one for a package ``__init__``, which is
    exactly why ``routers/ui/__init__.py``'s ``from . import _shared``
    resolved to ``…routers._shared`` instead of ``…routers.ui._shared``.
    """
    abs_module = node.module or ""
    if not node.level:
        return abs_module
    parts = this_module.split(".")
    if not is_package:
        parts = parts[:-1]
    # ``parts`` is now ``__package__``; level 1 == __package__, each
    # further level strips one trailing component.
    if node.level > 1:
        parts = parts[: len(parts) - (node.level - 1)]
    return ".".join(parts + ([abs_module] if abs_module else []))


def _import_sources(
    tree: ast.AST, this_module: str, is_package: bool,
) -> dict[str, tuple[str, str]]:
    """Map every name imported *from an ``email_triage`` module* to the
    ``(source_dotted_module, canonical_name)`` it resolves to.

    Used by the cross-module pass: once the guard
    knows the full set of DB-touching function definitions keyed by
    ``(module, name)``, this map lets each module resolve an imported
    helper — ``from …ui._shared import is_calendar_effectively_enabled
    as _ice_eff`` — back to its defining module and decide whether
    calling it is a DB touch. Both module-level and function-local
    imports are captured (the app imports helpers inside handler
    bodies heavily). Relative imports are resolved against
    ``this_module`` (see :func:`_resolve_relative_import`).
    """
    sources: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        mod = _resolve_relative_import(node, this_module, is_package)
        if not mod.startswith("email_triage"):
            continue
        for n in node.names:
            if n.name == "*":
                continue
            bound = n.asname or n.name
            sources[bound] = (mod, n.name)
    return sources


def _name_to_module(
    tree: ast.AST, this_module: str, is_package: bool,
) -> dict[str, str]:
    """Map every locally-bound name that refers to a *whole module* to
    the dotted module it names.

    Covers ``import a.b.c`` / ``import a.b.c as x`` (the bound name is
    the module object) and ``from pkg import sub`` / ``from . import
    sub`` where ``sub`` is itself a submodule (the bound name is again a
    module object). The cross-module star-re-export resolver needs this:
    ``globals().update(vars(_shared))`` references the local name
    ``_shared``, and that name was bound by ``from . import _shared`` —
    to know which module ``_shared`` *is*, the resolver must turn that
    bound name back into a dotted module path. Relative imports are
    resolved against ``this_module`` (see
    :func:`_resolve_relative_import`).
    """
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                # ``import a.b.c`` binds ``a``; ``import a.b.c as x``
                # binds ``x`` to the leaf module ``a.b.c``.
                if n.asname:
                    out[n.asname] = n.name
                else:
                    out[n.name.split(".")[0]] = n.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            mod = _resolve_relative_import(node, this_module, is_package)
            for n in node.names:
                if n.name == "*":
                    continue
                bound = n.asname or n.name
                # ``from pkg import sub`` — ``sub`` *might* be a
                # submodule ``pkg.sub``. Record the candidate dotted
                # path; the resolver only keeps it if that path is a
                # real indexed module.
                if mod:
                    out[bound] = f"{mod}.{n.name}"
    return out


def _star_reexport_modules(
    tree: ast.AST, this_module: str, is_package: bool,
) -> set[str]:
    """Dotted modules this module *wildcard*-re-exports into its own
    namespace via ``globals().update(... vars(X) ...)``.

    The ``routers/ui`` package does not re-export helpers with static
    ``from ._shared import name`` lines — every concern file *and* the
    package ``__init__`` instead run::

        from . import _shared
        globals().update({
            _n: _v for _n, _v in vars(_shared).items()
            if not _n.startswith("__")
        })

    That is a *runtime* star re-export: every non-dunder name of
    ``_shared`` becomes an attribute of the importing module. A consumer
    then does ``from email_triage.web.routers.ui import _is_dry_run`` and
    the name resolves — at runtime — through the package façade to
    ``_shared._is_dry_run``.

    ``_import_sources`` only walks ``ast.ImportFrom`` nodes, so it never
    sees this re-export: the cross-module pass had no way to know the
    ``ui`` package "exports" ``_is_dry_run``, and a direct
    ``_is_dry_run(db)`` call in an ``async def`` of ``app.py`` slipped
    the guard (Cycle-4 R1 HIGH-1, the push-consumer hole).

    This helper detects the pattern as an AST shape: any ``X.update(arg)``
    call whose target attribute is ``update`` and whose ``arg`` subtree
    contains a ``vars(NAME)`` / ``NAME.__dict__`` reference, where
    ``NAME`` resolves (via :func:`_name_to_module`) to a real dotted
    module. The ``X`` side is deliberately *not* constrained to a literal
    ``globals()`` call — ``globals()`` bound to a local first, or a
    ``self.__dict__.update`` form, are equally a namespace merge; what
    makes it a *re-export* is the ``vars(module)`` source, and that is
    what this matches on.
    """
    name_to_mod = _name_to_module(tree, this_module, is_package)
    sources: set[str] = set()

    def _vars_targets(call: ast.Call) -> list[str]:
        """If ``call`` is ``vars(NAME)`` return ``[NAME]``; else []."""
        if (
            isinstance(call.func, ast.Name)
            and call.func.id == "vars"
            and len(call.args) == 1
            and isinstance(call.args[0], ast.Name)
        ):
            return [call.args[0].id]
        return []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # The merge target: ``<something>.update(...)``.
        if not (isinstance(func, ast.Attribute) and func.attr == "update"):
            continue
        # Scan the call's argument subtrees for a ``vars(NAME)`` or a
        # ``NAME.__dict__`` reference — the re-export *source*.
        candidate_names: set[str] = set()
        for arg in [*node.args, *(kw.value for kw in node.keywords)]:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Call):
                    candidate_names.update(_vars_targets(sub))
                elif (
                    isinstance(sub, ast.Attribute)
                    and sub.attr == "__dict__"
                    and isinstance(sub.value, ast.Name)
                ):
                    candidate_names.add(sub.value.id)
        for nm in candidate_names:
            dotted = name_to_mod.get(nm)
            if dotted:
                sources.add(dotted)
    return sources


def _module_dotted_name(path: Path, src_root: Path) -> str:
    """``…/web/routers/ui/_shared.py`` -> ``email_triage.web.routers.ui
    ._shared``. ``__init__.py`` resolves to the package name."""
    rel = path.relative_to(src_root.parent).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


# ---------------------------------------------------------------------------
# Context-manager / generator detection (false-positive guard)
# ---------------------------------------------------------------------------

def _deferred_call_functions(tree: ast.AST) -> set[str]:
    """Names of module-level functions whose *call* does NOT run their
    body — ``@contextmanager`` / ``@asynccontextmanager``-decorated
    functions and plain generator functions.

    Calling ``acquire_db_lock(conn, name)`` (a ``@contextmanager``)
    merely builds the context-manager object; the DB work runs only
    when the caller does ``with …:`` or ``cm.__enter__()`` — and the
    app's async callers correctly drive that ``__enter__`` through
    ``asyncio.to_thread`` (see ``single_flight.acquire_db_lock_async``).
    Treating the bare *call* as a DB touch would be a false positive.

    The guard still inspects such a function's *body* (a ``with`` doing
    DB work inside it is real) — this set only suppresses flagging the
    construction call.
    """
    deferred: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # contextmanager / asynccontextmanager decorator (bare or
        # attribute form, e.g. ``contextlib.contextmanager``).
        for dec in node.decorator_list:
            dname = None
            if isinstance(dec, ast.Name):
                dname = dec.id
            elif isinstance(dec, ast.Attribute):
                dname = dec.attr
            if dname in ("contextmanager", "asynccontextmanager"):
                deferred.add(node.name)
        # A plain generator function — a top-level ``yield`` in the
        # body (not inside a nested def/lambda) — also defers.
        if _is_generator(node):
            deferred.add(node.name)
    return deferred


def _is_generator(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if ``fn``'s own body contains a ``yield`` / ``yield from``
    that belongs to ``fn`` (not to a nested function scope).

    A manual stack walk — ``ast.walk`` cannot stop descending — so a
    ``yield`` inside a nested ``def``/``lambda`` is correctly ignored.
    """
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.Lambda)):
            # A nested scope owns its own yields — do not descend.
            continue
        stack.extend(ast.iter_child_nodes(node))
    return False


# ---------------------------------------------------------------------------
# Pass 1 — catalogue local sync helpers that touch the DB unsafely
# ---------------------------------------------------------------------------

class _CallGraphCollector(ast.NodeVisitor):
    """Single AST walk that extracts a module's sync-function call
    graph — the input to the fast set-propagation fixpoint below.

    For every sync ``def`` it records:
      * whether the function's body *directly* touches the DB — a raw
        sqlite method on a connection-like name, a call to a catalogued
        helper, or a ``get_write_lock()`` acquisition;
      * the set of helper-names it *calls* — so a function that is
        DB-touching only because a callee is can be discovered by set
        propagation, without re-walking the AST.

    Walking once and propagating as set math (vs. re-running the walker
    each fixpoint iteration) is what keeps the whole-package
    cross-module pass tractable.

    Crossing into a nested ``async def`` is ignored — pass 2 owns async
    bodies. A nested sync ``def`` is followed (its DB work makes the
    enclosing sync function DB-touching when called inline); a ``lambda``
    is its own scope and is suspended. A ``db_call(...)`` argument
    subtree is the safe zone and contributes nothing.
    """

    def __init__(self, aliases: dict[str, str], deferred: set[str]) -> None:
        self._aliases = aliases
        self._deferred = deferred
        self._fn_stack: list[str] = []
        self._dbcall_depth = 0
        # fn name -> does its body directly touch the DB?
        self.direct: set[str] = set()
        # fn name -> set of helper-names it calls (canonical + raw).
        self.calls: dict[str, set[str]] = {}

    def _canon(self, name: str) -> str:
        return self._aliases.get(name, name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        for child in node.body:
            self.visit(child)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._fn_stack.append(node.name)
        self.calls.setdefault(node.name, set())
        self.generic_visit(node)
        self._fn_stack.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        saved = self._fn_stack
        self._fn_stack = []
        self.generic_visit(node)
        self._fn_stack = saved

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # db_call(...) — its arguments are the safe zone.
        if _is_db_call(func, self._aliases):
            self._dbcall_depth += 1
            for arg in node.args:
                self.visit(arg)
            for kw in node.keywords:
                self.visit(kw.value)
            self._dbcall_depth -= 1
            return

        if self._fn_stack and self._dbcall_depth == 0:
            enclosing = self._fn_stack[-1]
            # (a) raw sqlite method on a connection-like name.
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _DB_METHODS
                and _db_like_base(func) is not None
            ):
                self.direct.add(enclosing)
            else:
                name = _called_helper_name(func)
                if name is not None and name not in self._deferred:
                    canon = self._canon(name)
                    # A ``self.X()`` method call is never one of the
                    # module-level catalogue helpers — those are free
                    # functions, never methods. Skip the catalogue
                    # match for it (a same-name class method like
                    # ``GmailApiProvider.list_labels`` would otherwise
                    # be a false-positive direct toucher). The graph
                    # edge IS still recorded — if ``self.X`` is a
                    # genuinely DB-touching method of this class, pass 1
                    # catalogues it from its own body and the
                    # propagation step picks the caller up via the edge.
                    is_self_method = _call_is_self_method(func)
                    # A call to a catalogued helper / get_write_lock is
                    # a direct DB touch; any other call is recorded as a
                    # graph edge for the propagation step.
                    if not is_self_method and (
                        canon in _ALL_HELPERS or name in _ALL_HELPERS
                        or canon == "get_write_lock"
                        or name == "get_write_lock"
                    ):
                        self.direct.add(enclosing)
                    self.calls[enclosing].add(name)
                    if canon != name:
                        self.calls[enclosing].add(canon)

        self.generic_visit(node)


def _module_callgraph(
    tree: ast.AST, aliases: dict[str, str], deferred: set[str],
) -> tuple[set[str], dict[str, set[str]]]:
    """One-shot ``(direct_db_touchers, calls_map)`` for a module —
    computed once per module, reused across every fixpoint iteration."""
    collector = _CallGraphCollector(aliases, deferred)
    collector.visit(tree)
    return collector.direct, collector.calls


def _local_db_helpers_from_graph(
    direct: set[str],
    calls: dict[str, set[str]],
    extra_db_names: set[str],
) -> set[str]:
    """Pass 1 fixpoint as pure set propagation over a pre-built call
    graph.

    A function is DB-touching if it is a ``direct`` toucher, or it calls
    a name that is already known DB-touching — a catalogued helper, an
    ``extra_db_names`` entry (a cross-module DB-touching import resolved
    by the global pass), or another local function found DB-touching on
    an earlier round. Iterates to a fixpoint; returns only locally
    *defined* functions (``extra_db_names`` are imports, not local
    definitions — ``_scan`` tracks those separately).
    """
    touching: set[str] = set(direct)
    while True:
        new: set[str] = set()
        for fn, callees in calls.items():
            if fn in touching:
                continue
            for callee in callees:
                if callee in touching or callee in extra_db_names:
                    new.add(fn)
                    break
        if not new:
            return touching
        touching |= new


def _local_db_helpers(
    tree: ast.AST,
    aliases: dict[str, str],
    deferred: set[str],
    imported_db_names: set[str] | None = None,
) -> set[str]:
    """Pass 1 — every sync helper in the module that is DB-touching,
    directly or transitively. Thin wrapper over the call-graph
    extraction + propagation, kept for the synthetic ``_findings``
    tests and as the standalone-scan fallback.
    """
    direct, calls = _module_callgraph(tree, aliases, deferred)
    return _local_db_helpers_from_graph(
        direct, calls, set(imported_db_names or ()),
    )


# ---------------------------------------------------------------------------
# Cross-module pass — the structural completeness layer
# ---------------------------------------------------------------------------
#
# Option B (per-module call graph) catches sync wrappers defined and
# called within ONE module. It cannot see a wrapper IMPORTED from
# another module: ``app.py`` calls ``_ice_eff`` — an alias of
# ``is_calendar_effectively_enabled`` defined in ``…ui._shared`` — and a
# per-module scan has no way to know that callee touches the DB. Hand-
# listing every such cross-module wrapper in a catalogue is exactly the
# enumeration that failed three cycles.
#
# The cross-module pass closes it. It builds, to a global fixpoint, the
# set of DB-touching *names* per module — both names a module DEFINES
# that touch the DB and names it IMPORTS from a DB-touching definition
# elsewhere (so a re-export chain through a package ``__init__`` is
# followed automatically). Each module's per-module scan then resolves
# its imports against that global set. The result is a guard that is
# provably complete: no DB-touching helper, however many import hops
# away, escapes it.


class _ModuleInfo:
    """Parsed, pre-analysed view of one source module — built once,
    reused across every fixpoint iteration of the cross-module pass."""

    __slots__ = (
        "path", "dotted", "tree", "aliases", "import_sources",
        "star_reexports", "deferred", "direct", "calls", "db_touching",
    )

    def __init__(self, path: Path, src_root: Path) -> None:
        self.path = path
        self.dotted = _module_dotted_name(path, src_root)
        # A package ``__init__.py`` resolves relative imports against
        # itself, not its parent — the flag the relative-import resolver
        # needs to avoid an off-by-one.
        is_package = path.name == "__init__.py"
        self.tree = parse_module(path); assert self.tree is not None  # N-350 R31
        self.aliases = _alias_map(self.tree)
        self.import_sources = _import_sources(
            self.tree, self.dotted, is_package,
        )
        # Dotted modules this module wildcard-re-exports via
        # ``globals().update(vars(X))`` — the ``routers/ui`` façade
        # pattern the static ImportFrom scan cannot see ( R1
        # HIGH-2).
        self.star_reexports = _star_reexport_modules(
            self.tree, self.dotted, is_package,
        )
        self.deferred = _deferred_call_functions(self.tree)
        # Call graph extracted ONCE — reused across every fixpoint
        # iteration so the AST is walked exactly once per module.
        self.direct, self.calls = _module_callgraph(
            self.tree, self.aliases, self.deferred,
        )
        # Grows across fixpoint iterations: every bound name in THIS
        # module that resolves to a DB-touching function (defined here
        # or imported from a DB-touching definition elsewhere).
        self.db_touching: set[str] = set()


def _build_module_index(src_root: Path) -> dict[str, _ModuleInfo]:
    """Parse every ``.py`` under ``src/email_triage`` into a
    ``{dotted_name: _ModuleInfo}`` index. Every module is included (not
    only async-bearing ones) — a sync-only module can still DEFINE a
    DB-touching helper that an async module imports."""
    index: dict[str, _ModuleInfo] = {}
    # Route the src walk through the shared harness (run17  DA catch — this
    # file already imports the harness, so a hand-rolled rglob here was the one
    # live "harness-importer that still re-rolls a walk" the substring-exemption
    # masked). iter_files == sorted(root.rglob(pattern)) minus __pycache__.
    for path in iter_files(src_root, "*.py"):
        try:
            info = _ModuleInfo(path, src_root)
        except (SyntaxError, UnicodeDecodeError):
            continue
        index[info.dotted] = info
    return index


def _resolve_through_reexports(
    src_mod: str,
    orig_name: str,
    index: dict[str, _ModuleInfo],
) -> tuple[bool, bool]:
    """Resolve ``orig_name`` as exported by ``src_mod``, following
    ``globals().update(vars(X))`` star re-exports.

    Returns ``(is_db_touching, is_deferred)``.

    A name an importer reaches via ``from src_mod import orig_name``
    might not be DEFINED (or statically imported) in ``src_mod`` at all:
    the ``routers/ui`` façade re-exports every helper of ``_shared``
    *at runtime* through ``globals().update(vars(_shared))``. The
    cross-module pass already credits ``src_mod.db_touching`` with names
    ``src_mod`` defines or statically imports; this function adds the
    missing hop — if ``src_mod`` star-re-exports from ``M'`` and the
    name is DB-touching (or deferred) at ``M'``, that property carries
    through the façade.

    The ``deferred`` half is load-bearing for false-positive safety: a
    re-exported ``@contextmanager`` must still be recognised as
    deferred, or calling it through the façade would be wrongly flagged.

    The search follows star-re-export hops to a fixpoint with a visited
    set, so a re-export chain of any depth (and an accidental cycle)
    terminates.
    """
    seen: set[str] = set()
    stack: list[str] = [src_mod]
    db_touching = False
    deferred = False
    while stack:
        mod = stack.pop()
        if mod in seen:
            continue
        seen.add(mod)
        src = index.get(mod)
        if src is None:
            continue
        if orig_name in src.deferred:
            deferred = True
        if orig_name in src.db_touching:
            db_touching = True
        # Follow this module's own star re-exports — the name may be
        # re-exported from here in turn (``__init__`` <- ``_shared``).
        stack.extend(src.star_reexports)
    return db_touching, deferred


def _imported_db_names(
    info: _ModuleInfo, index: dict[str, _ModuleInfo],
) -> set[str]:
    """Bound names in ``info`` imported from a *currently-known*
    DB-touching definition in another indexed module.

    A name whose source definition is a ``@contextmanager`` / generator
    (deferred-call) is excluded — calling it only builds the object, so
    flagging the call would be a cross-module false positive, exactly as
    it would be for a same-module ``@contextmanager``.

    Resolution follows ``globals().update(vars(X))`` star re-exports: a name imported from a package façade that
    re-exports it at runtime resolves through to its true defining
    module.
    """
    out: set[str] = set()
    for bound, (src_mod, orig_name) in info.import_sources.items():
        if src_mod not in index:
            continue
        db_touching, deferred = _resolve_through_reexports(
            src_mod, orig_name, index,
        )
        # A deferred (``@contextmanager`` / generator) source is never a
        # call-site DB touch — exclude it even if some other re-export
        # hop also marks the name db_touching (the definition is one
        # thing; ``deferred`` is the authoritative call semantics).
        if deferred:
            continue
        if db_touching:
            out.add(bound)
    return out


def _compute_global_db_touchers(
    index: dict[str, _ModuleInfo],
) -> None:
    """Fill every ``_ModuleInfo.db_touching`` set to a global fixpoint.

    Each iteration, for each module: resolve which imported names are
    DB-touching given the current global state, run the per-module
    pass-1 fixpoint seeded with them, and union the result (local
    DB-touchers + DB-touching imports) into ``db_touching``. Repeat
    until no module's set grows. The outer loop terminates because the
    union is monotone and bounded by the (finite) set of all names.
    """
    while True:
        changed = False
        for info in index.values():
            imported = _imported_db_names(info, index)
            local = _local_db_helpers_from_graph(
                info.direct, info.calls, imported,
            )
            updated = info.db_touching | local | imported
            if updated != info.db_touching:
                info.db_touching = updated
                changed = True
        if not changed:
            return


# Module-level singleton — the cross-module index is expensive to build
# (parses the whole package) so it is computed once and shared by every
# parametrised ``test_no_async_reachable_unsafe_db_touch`` case.
_MODULE_INDEX: dict[str, _ModuleInfo] | None = None


def _module_index() -> dict[str, _ModuleInfo]:
    global _MODULE_INDEX
    if _MODULE_INDEX is None:
        index = _build_module_index(_src_root())
        _compute_global_db_touchers(index)
        _MODULE_INDEX = index
    return _MODULE_INDEX


# ---------------------------------------------------------------------------
# Shared AST helpers
# ---------------------------------------------------------------------------

def _is_db_call(func: ast.AST, aliases: dict[str, str]) -> bool:
    """True if ``func`` is a reference to ``db_call`` (alias-resolved)."""
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id) == _DB_CALL_CANON
    if isinstance(func, ast.Attribute):
        return func.attr == _DB_CALL_CANON
    return False


def _db_like_base(func: ast.Attribute) -> str | None:
    """Return the connection-like base name of an ``x.execute(...)``
    attribute access, or ``None`` if the base is not connection-like.

    Recognises a bare name (``db``), a one-level attribute
    (``self._db`` / ``app.state.db`` → ``db``), and the ``_conn`` form
    used by ``DbSecrets``.
    """
    base = func.value
    base_name: str | None = None
    if isinstance(base, ast.Name):
        base_name = base.id
    elif isinstance(base, ast.Attribute):
        base_name = base.attr
    if base_name in _DB_NAMES:
        return base_name
    return None


def _called_helper_name(func: ast.AST) -> str | None:
    """Return the helper-name a call targets, or ``None``.

    Recognises a bare-name call (``get_email_account(...)``) and a
    ``self``-based method call (``self._row_count(...)``). The
    ``self.``-restriction on method calls is deliberate: an arbitrary
    ``obj.get_setting()`` could be an unrelated class's method, but
    ``self._captured_row_count()`` inside the same class is the real
    sync-instance-helper shape  must catch — restricting to
    ``self`` keeps the match precise and false-positive-free.
    """
    if isinstance(func, ast.Name):
        return func.id
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "self"
    ):
        return func.attr
    return None


def _call_is_self_method(func: ast.AST) -> bool:
    """True if the call target is ``self.<name>(...)`` — an instance
    method of the enclosing class.

    A ``self.``-method call must never be matched against the
    cross-module helper *catalogues* (``_DB_READ`` / ``_DB_WRITE`` /
    ``_DB_AUTH`` / ``_AUTH_HELPERS`` / ``_AUTHZ_DIRECT``): those
    catalogue the module-level free functions of ``db.py`` /
    ``auth.py`` / ``dependencies.py``, which are NEVER methods. A class
    that happens to define a method sharing a catalogued name —
    ``GmailApiProvider.list_labels`` (an async HTTP call) vs. the
    ``db.py`` ``list_labels`` read helper — would otherwise be a false
    positive. A ``self.``-method call is still matched against pass 1's
    local-helper set, which catalogues genuinely DB-touching methods of
    the same class by analysing their bodies.
    """
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "self"
    )


# ---------------------------------------------------------------------------
# Pass 2 — async offenders
# ---------------------------------------------------------------------------

class _AsyncDbFinder(ast.NodeVisitor):
    """Collect unsafe DB touches reachable from an ``async def``.

    A site is "safe" when it is inside an ``await db_call(...)``
    argument (``_dbcall_depth > 0``) or carries an ``# async-db-ok``
    opt-out comment.

    Crossing a *sync* ``def`` boundary clears the async context — a
    nested sync closure's body runs synchronously. But the *call* to a
    sync helper from the async body is still inspected: if that helper
    is a pass-1 catalogued local DB-touching helper, the call is an
    offender. (The pure ``db_call(_closure)`` pattern is still safe —
    the closure is inside the ``db_call`` argument subtree.)
    """

    def __init__(
        self,
        src: str,
        aliases: dict[str, str],
        local_helpers: set[str],
        deferred: set[str],
        imported_helpers: set[str] | None = None,
    ) -> None:
        self._optout = _optout_lines(src)
        self._aliases = aliases
        self._local_helpers = local_helpers
        # Bound names imported from a DB-touching definition in another
        # module — reported as a distinct kind so the
        # message names the cross-module hop accurately.
        self._imported_helpers = imported_helpers or set()
        self._deferred = deferred
        self.findings: list[tuple[str, str, int, str]] = []
        self._async_stack: list[tuple[str, int]] = []
        self._dbcall_depth = 0

    def _canon(self, name: str) -> str:
        return self._aliases.get(name, name)

    def _opted_out(self, lineno: int) -> bool:
        # An opt-out marker on the offending line or the line above.
        return lineno in self._optout or (lineno - 1) in self._optout

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._async_stack.append((node.name, node.lineno))
        self.generic_visit(node)
        self._async_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # A nested sync def breaks the async context: its body runs
        # synchronously (it is usually the closure dispatched via
        # db_call). Save/clear/restore the async stack across it. Its
        # DB work, if any, was already catalogued by pass 1 — and the
        # *call site* of this helper from an async body is what pass 2
        # flags, not the body here.
        saved = self._async_stack
        self._async_stack = []
        self.generic_visit(node)
        self._async_stack = saved

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # A lambda is a sync-function scope, exactly like a nested def:
        # its body runs whenever the lambda is *called*, not where it is
        # defined. Clear the async context across it so a DB touch
        # inside a ``lambda: helper()`` is not mis-attributed to the
        # enclosing async def. (A lambda handed to ``db_call`` is still
        # inside the safe zone via ``_dbcall_depth``.)
        saved = self._async_stack
        self._async_stack = []
        self.generic_visit(node)
        self._async_stack = saved

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # db_call(...) — its argument subtree is the safe zone.
        if _is_db_call(func, self._aliases):
            self._dbcall_depth += 1
            for arg in node.args:
                self.visit(arg)
            for kw in node.keywords:
                self.visit(kw.value)
            self._dbcall_depth -= 1
            return

        in_async = bool(self._async_stack)
        if (
            in_async
            and self._dbcall_depth == 0
            and not self._opted_out(node.lineno)
        ):
            func_name = self._async_stack[-1][0]

            # (a) direct sqlite method on a connection-like name.
            if isinstance(func, ast.Attribute) and func.attr in _DB_METHODS:
                base_name = _db_like_base(func)
                if base_name is not None:
                    self.findings.append((
                        "a", func_name, node.lineno,
                        f".{func.attr}() on '{base_name}'",
                    ))

            # (b)/(c)/(d)/(f)/(g) bare-name and ``self``-method calls to
            # DB-touching names. ``_called_helper_name`` resolves both
            # ``get_email_account(...)`` and ``self._row_count(...)``.
            # A call to a deferred-call function (``@contextmanager`` /
            # generator) is skipped — it only builds the object; the DB
            # work runs at ``__enter__``/iteration, which the caller is
            # expected to drive off-loop (``acquire_db_lock_async``).
            raw = _called_helper_name(func)
            if raw is not None and raw not in self._deferred:
                canon = self._canon(raw)
                alias_note = f" (alias of {canon})" if canon != raw else ""
                # A ``self.X()`` method call is NEVER one of the
                # module-level catalogue helpers (db.py / auth.py /
                # dependencies.py free functions) or an imported name —
                # match it only against pass 1's local-helper set. This
                # prevents a class method that shares a catalogued name
                # (``GmailApiProvider.list_labels``, an HTTP call, vs.
                # the ``db.py`` ``list_labels`` read helper) from being
                # a false positive.
                is_self_method = _call_is_self_method(func)

                if not is_self_method and (canon in _DB_WRITE
                                           or raw in _DB_WRITE):
                    self.findings.append((
                        "c", func_name, node.lineno,
                        f"@db_write helper {raw}(){alias_note} "
                        "called directly",
                    ))
                elif not is_self_method and (
                    canon in _DB_READ or raw in _DB_READ
                    or canon in _DB_AUTH or raw in _DB_AUTH
                    or canon in _AUTH_HELPERS or raw in _AUTH_HELPERS
                ):
                    self.findings.append((
                        "b", func_name, node.lineno,
                        f"sync DB helper {raw}(){alias_note} "
                        "called directly",
                    ))
                elif not is_self_method and (
                    canon in _AUTHZ_DIRECT or raw in _AUTHZ_DIRECT
                ):
                    self.findings.append((
                        "d", func_name, node.lineno,
                        f"authz/wrapper helper {raw}(){alias_note} "
                        "called directly (DB-touching / takes the "
                        "write lock)",
                    ))
                elif not is_self_method and raw in self._imported_helpers:
                    self.findings.append((
                        "g", func_name, node.lineno,
                        f"cross-module DB-touching helper {raw}()"
                        f"{alias_note} called directly (resolved via "
                        "the cross-module import pass)",
                    ))
                elif raw in self._local_helpers:
                    self.findings.append((
                        "f", func_name, node.lineno,
                        f"local sync DB helper {raw}() called directly "
                        "(catalogued by the in-module call-graph pass)",
                    ))

        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Module discovery
# ---------------------------------------------------------------------------

def _src_root() -> Path:
    """Locate ``src/email_triage`` — the package root.

    Delegates to the shared pin harness ``SRC_ROOT`` (computed once,
    R5b) so this guard can never drift in its src-root resolution. The
    ``is_dir`` assert is kept as a fail-loud sanity check: a broken root
    would make every parametrised guard below pass vacuously.
    """
    assert SRC_ROOT.is_dir(), f"src tree not found at {SRC_ROOT}"
    return SRC_ROOT


def _has_async_def(path: Path) -> bool:
    """True if the module contains at least one ``async def``."""
    try:
        tree = parse_module(path); assert tree is not None  # N-350 R31
    except (SyntaxError, UnicodeDecodeError):
        return False
    return any(
        isinstance(n, ast.AsyncFunctionDef) for n in ast.walk(tree)
    )


def _guarded_modules() -> list[Path]:
    """Every module under ``src/email_triage`` that contains an
    ``async def`` — the true async-reachable surface.

    Discovery is dynamic): there is no hand-maintained list,
    so a new async-bearing module is in scope automatically and the
    guarded set can never silently shrink. ``__pycache__`` is excluded
    (the shared pin harness ``iter_src_files`` walk owns that, R5b).
    """
    return [f for f in iter_src_files() if f.is_file() and _has_async_def(f)]


def _scan(path: Path) -> list[tuple[str, str, int, str]]:
    """Scan one module for async-reachable unsafe DB touches.

    Uses the cross-module index: the module's imported
    DB-touching names are resolved against the global fixpoint, then the
    per-module pass-1 + pass-2 run with those imports folded in — so a
    call to an imported wrapper (``_ice_eff`` ⇒
    ``is_calendar_effectively_enabled``) is flagged just like a local
    one.
    """
    index = _module_index()
    dotted = _module_dotted_name(path, _src_root())
    info = index.get(dotted)
    if info is None:
        # Module outside the index (should not happen for a guarded
        # module) — fall back to a standalone parse.
        src = path.read_text(encoding="utf-8")
        tree = parse_source(src)
        aliases = _alias_map(tree)
        deferred = _deferred_call_functions(tree)
        local = _local_db_helpers(tree, aliases, deferred)
        finder = _AsyncDbFinder(src, aliases, local, deferred)
        finder.visit(tree)
        return finder.findings

    src = info.path.read_text(encoding="utf-8")
    imported = _imported_db_names(info, index)
    # Reuse the call graph cached on ``_ModuleInfo`` — purely local
    # DB-touchers; ``imported`` is tracked separately so pass 2 can
    # label a local vs. a cross-module offender accurately.
    local = _local_db_helpers_from_graph(
        info.direct, info.calls, imported,
    )
    finder = _AsyncDbFinder(
        src, info.aliases, local, info.deferred, imported,
    )
    finder.visit(info.tree)
    return finder.findings


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_guarded_module_set_is_comprehensive():
    """Sanity: dynamic discovery found the full async surface.

    A broken path resolver or discovery glob would make every guard
    below pass vacuously — assert the surface is real, large, and
    contains the modules  explicitly widened scope to include.
    """
    modules = _guarded_modules()
    assert len(modules) >= 30, (
        f"expected the full async surface (>=30 modules), found "
        f"{len(modules)}: {sorted(m.name for m in modules)}"
    )
    rels = {relpath(m) for m in modules}
    names = {m.name for m in modules}

    # Router surface (the old guard's only scope).
    for required in ("app.py", "api.py", "profile.py", "accounts.py"):
        assert required in names, f"{required} missing from guarded set"

    #  — the modules the old guard never scanned. Each contains at
    # least one ``async def`` and must now be in scope.
    for required in (
        "web/watch_runner.py",
        "web/triage_one.py",
        "web/triage_runner_bulk.py",
        "web/access_audit.py",
    ):
        assert required in rels, (
            f"{required} missing — #248 widened scope must include it"
        )
    # At least one actions/ module must be in scope (the package has
    # several async-bearing modules).
    assert any(r.startswith("actions/") for r in rels), (
        "no actions/ module in scope — #248 widened scope must "
        "include the actions package"
    )


@pytest.mark.parametrize(
    "module_path",
    _guarded_modules(),
    ids=relpath,
)
def test_no_async_reachable_unsafe_db_touch(module_path: Path):
    """ /  — no ``async def`` may touch the shared connection
    without a ``db_call`` hop (or an explicit ``# async-db-ok``
    opt-out).

    See the module docstring for the offending shapes. If this fails,
    the offending site needs its DB work folded into a sync closure
    dispatched via ``await db_call(_closure)`` — or, if the touch is
    provably free of event-loop contention (lifespan startup, CLI), an
    ``# async-db-ok`` comment with a rationale.
    """
    findings = _scan(module_path)
    if findings:
        rel = relpath(module_path)
        lines = "\n".join(
            f"  [{kind}] {rel}:{lineno}  in async def {func}(): {desc}"
            for kind, func, lineno, desc in sorted(
                findings, key=lambda f: f[2],
            )
        )
        pytest.fail(
            f"{len(findings)} async-reachable unsafe DB touch(es) in "
            f"{rel}:\n{lines}\n\n"
            "Route each through `await db_call(...)`, or add an "
            "`# async-db-ok` opt-out comment with a rationale if the "
            "touch is provably free of event-loop contention."
        )


# ---------------------------------------------------------------------------
# Guard-of-the-guard — each detection shape  added has its own test
# ---------------------------------------------------------------------------

def _findings(src: str) -> list[tuple[str, str, int, str]]:
    """Run the full two-pass scan on a synthetic source string."""
    tree = parse_source(src)
    aliases = _alias_map(tree)
    deferred = _deferred_call_functions(tree)
    local_helpers = _local_db_helpers(tree, aliases, deferred)
    finder = _AsyncDbFinder(src, aliases, local_helpers, deferred)
    finder.visit(tree)
    return finder.findings


def test_opt_out_comment_is_honoured():
    """The ``# async-db-ok`` opt-out suppresses a finding — and only
    when it is a real comment token.
    """
    offending = (
        "async def handler(db):\n"
        "    db.execute('SELECT 1')\n"
    )
    assert len(_findings(offending)) == 1, (
        "the synthetic offending touch must be flagged"
    )

    opted_out = (
        "async def handler(db):\n"
        "    db.execute('SELECT 1')  # async-db-ok: synthetic test\n"
    )
    assert _findings(opted_out) == [], (
        "the `# async-db-ok` opt-out comment must suppress the finding"
    )

    # On the line above is also honoured.
    opted_out_above = (
        "async def handler(db):\n"
        "    # async-db-ok: synthetic test\n"
        "    db.execute('SELECT 1')\n"
    )
    assert _findings(opted_out_above) == [], (
        "an `# async-db-ok` on the line above must suppress the finding"
    )


def test_opt_out_substring_in_string_literal_does_not_suppress():
    """ (d) — a coincidental ``async-db-ok`` substring inside a
    string literal must NOT suppress a real finding. The old guard
    matched the bare substring anywhere on the line.
    """
    sneaky = (
        "async def handler(db):\n"
        "    note = 'see async-db-ok docs'\n"
        "    db.execute('SELECT 1')\n"
    )
    assert len(_findings(sneaky)) == 1, (
        "an `async-db-ok` substring inside a string literal must not "
        "be treated as an opt-out"
    )

    # And on the offending line itself, inside a string argument.
    sneaky_inline = (
        "async def handler(db):\n"
        "    db.execute('SELECT async-db-ok')\n"
    )
    assert len(_findings(sneaky_inline)) == 1, (
        "an `async-db-ok` substring inside a call argument string must "
        "not be treated as an opt-out"
    )


def test_db_call_argument_is_a_safe_zone():
    """A DB touch *inside* an ``await db_call(...)`` argument — a bare
    helper call or a sync closure passed by reference — must NOT be
    flagged. That is exactly the correct pattern.
    """
    safe_ref = (
        "async def handler(db):\n"
        "    row = await db_call(get_email_account, db, 1)\n"
    )
    assert _findings(safe_ref) == [], (
        "a helper dispatched via db_call must not be flagged"
    )

    safe_closure = (
        "async def handler(db):\n"
        "    def _work():\n"
        "        return db.execute('SELECT 1').fetchone()\n"
        "    row = await db_call(_work)\n"
    )
    assert _findings(safe_closure) == [], (
        "a sync closure dispatched via db_call must not be flagged"
    )

    unsafe = (
        "async def handler(db):\n"
        "    row = get_email_account(db, 1)\n"
    )
    assert len(_findings(unsafe)) == 1, (
        "an undecorated DB helper called directly from an async def "
        "must be flagged"
    )


def test_aliased_db_call_is_recognised_as_safe_zone():
    """ (b) — an aliased ``db_call`` (``import db_call as _db_call``,
    as access_audit.py actually does) must still be recognised as the
    safe-zone marker. The old guard matched only the literal name and
    would false-positive on this.
    """
    src = (
        "from email_triage.web.db_threadpool import db_call as _db_call\n"
        "async def handler(db):\n"
        "    row = await _db_call(get_email_account, db, 1)\n"
    )
    assert _findings(src) == [], (
        "an aliased db_call must be honoured as the safe zone"
    )


def test_aliased_helper_call_is_flagged():
    """ (b) — an aliased DB helper call must be flagged by its
    canonical name. ``get_current_user as _get_current_user``
    (health.py) and ``enqueue_watcher_retry as _wr_enqueue`` (app.py)
    are the real cases.
    """
    aliased_authz = (
        "from email_triage.web.dependencies import "
        "get_current_user as _get_current_user\n"
        "async def handler(request):\n"
        "    user = _get_current_user(request)\n"
    )
    findings = _findings(aliased_authz)
    assert len(findings) == 1, (
        "an aliased authz helper called directly must be flagged"
    )
    assert "get_current_user" in findings[0][3], (
        "the finding must name the canonical helper"
    )

    aliased_write = (
        "from email_triage.web.watcher_retry import "
        "enqueue_watcher_retry as _wr_enqueue\n"
        "async def handler(db):\n"
        "    _wr_enqueue(db, account_id=1, provider_type='imap', "
        "error=Exception())\n"
    )
    assert len(_findings(aliased_write)) == 1, (
        "an aliased cross-module DB wrapper called directly must be "
        "flagged"
    )


def test_sync_instance_method_helper_is_flagged():
    """ (c) — a sync *instance method* that does raw DB work, called
    inline from an ``async def`` of the same class, must be flagged.
    ``sent_mail_capture._captured_row_count`` /
    ``watch_runner._record_watch_fired`` are the real cases the old
    guard missed because it cleared the async context at the sync def.
    """
    src = (
        "class Scanner:\n"
        "    def _row_count(self):\n"
        "        return self._db.execute('SELECT COUNT(*)').fetchone()\n"
        "    async def scan(self):\n"
        "        n = self._row_count()\n"
        "        return n\n"
    )
    findings = _findings(src)
    assert len(findings) == 1, (
        f"a sync DB-touching instance method called inline from an "
        f"async method must be flagged; got {findings}"
    )
    assert findings[0][0] == "f", "expected a kind-(f) local-helper finding"


def test_self_method_sharing_a_catalogued_name_is_not_flagged():
    """ false-positive guard — a class method whose name collides
    with a catalogued ``db.py`` helper must NOT be flagged just for
    that name. The real case is ``GmailApiProvider.list_labels`` — an
    async HTTP call to the Gmail API — vs. the ``db.py`` ``list_labels``
    read helper in the ``_DB_READ`` catalogue. ``self.list_labels()``
    is a method call; catalogue helpers are module-level free
    functions, never methods.
    """
    src = (
        "class GmailApiProvider:\n"
        "    async def list_labels(self):\n"
        "        return await self._request('GET', '/labels')\n"
        "    async def list_folders(self):\n"
        "        labels = await self.list_labels()\n"
        "        return labels\n"
        "    async def _resolve(self, name):\n"
        "        rows = self.list_labels()\n"
        "        return rows\n"
    )
    assert _findings(src) == [], (
        "a self-method call that merely shares a name with a "
        "catalogued db.py helper must not be flagged — the catalogues "
        "are free functions, never methods"
    )

    # Negative control: a self-method that genuinely does raw DB work
    # IS still flagged (the catalogue-name collision fix must not blind
    # the guard to real sync-instance-method offenders).
    real = (
        "class Store:\n"
        "    def list_labels(self):\n"
        "        return self._db.execute('SELECT * FROM labels').fetchall()\n"
        "    async def handler(self):\n"
        "        return self.list_labels()\n"
    )
    real_findings = _findings(real)
    assert len(real_findings) == 1 and real_findings[0][0] == "f", (
        f"a self-method that genuinely touches the DB must still be "
        f"flagged as a local helper; got {real_findings}"
    )


def test_sync_module_helper_taking_write_lock_is_flagged():
    """ (c) — a sync module helper that acquires ``get_write_lock()``
    (i.e. it deliberately touches the shared connection), called inline
    from an ``async def``, must be flagged. This is the
    ``watch_runner._user_notify_email`` / ``_watch_already_fired``
    shape: connection-safe but loop-blocking.
    """
    src = (
        "def _lookup(db, uid):\n"
        "    with get_write_lock():\n"
        "        return db.execute('SELECT 1', (uid,)).fetchone()\n"
        "async def handler(db):\n"
        "    row = _lookup(db, 1)\n"
    )
    findings = _findings(src)
    assert len(findings) == 1, (
        f"a sync helper that takes the write lock, called inline from "
        f"an async def, must be flagged; got {findings}"
    )


def test_transitive_sync_wrapper_is_flagged():
    """ (c) — pass 1's fixpoint must catch a wrapper that is
    DB-touching only *transitively*: ``_require_admin_user`` does no DB
    work itself, it calls ``get_current_user`` (which does). Calling
    ``_require_admin_user`` inline from an async def must still flag.
    """
    src = (
        "from email_triage.web.dependencies import get_current_user\n"
        "def _require_admin_user(request):\n"
        "    user = get_current_user(request)\n"
        "    return user\n"
        "async def handler(request):\n"
        "    user = _require_admin_user(request)\n"
    )
    findings = _findings(src)
    assert len(findings) >= 1, (
        f"a transitively-DB-touching sync wrapper called inline from "
        f"an async def must be flagged; got {findings}"
    )


def test_db_call_wrapped_local_helper_is_safe():
    """A pass-1 local helper dispatched THROUGH ``db_call`` is correct
    and must NOT be flagged — the call is inside the safe zone.
    """
    src = (
        "class Scanner:\n"
        "    def _row_count(self):\n"
        "        return self._db.execute('SELECT COUNT(*)').fetchone()\n"
        "    async def scan(self):\n"
        "        n = await db_call(self._row_count)\n"
        "        return n\n"
    )
    assert _findings(src) == [], (
        "a local DB helper dispatched via db_call must not be flagged"
    )


def test_conn_attribute_name_is_recognised():
    """ — ``DbSecrets`` stores the connection as ``self._conn``;
    raw ``.execute``/``.commit`` on a ``_conn``-named base must be
    flagged. The old ``_DB_NAMES`` set lacked ``_conn``.
    """
    src = (
        "async def handler(self):\n"
        "    self._conn.execute('SELECT 1')\n"
        "    self._conn.commit()\n"
    )
    assert len(_findings(src)) == 2, (
        "raw DB methods on a `_conn`-named base must be flagged"
    )


def test_fastapi_depends_argument_is_not_flagged():
    """A ``get_current_user`` reference passed as an argument to
    ``Depends(...)`` (or as a parameter default) is NOT a direct call —
    FastAPI runs sync dependencies in its own threadpool. It must not
    be flagged; only an inline *call* is unsafe.
    """
    src = (
        "from email_triage.web.dependencies import get_current_user\n"
        "async def handler(user=Depends(get_current_user)):\n"
        "    return user\n"
    )
    assert _findings(src) == [], (
        "a helper passed to Depends() is not a direct call and must "
        "not be flagged"
    )


def test_contextmanager_construction_call_is_not_flagged():
    """ false-positive guard — *calling* a ``@contextmanager`` (or a
    generator) function only builds the CM object; it does not run the
    body. The real case is ``single_flight.acquire_db_lock_async``,
    which calls the ``@contextmanager`` ``acquire_db_lock`` and then
    drives ``__enter__`` through ``asyncio.to_thread``. The bare
    construction call must NOT be flagged.
    """
    cm_src = (
        "from contextlib import contextmanager\n"
        "@contextmanager\n"
        "def acquire_db_lock(conn):\n"
        "    with get_write_lock():\n"
        "        conn.execute('INSERT INTO lock VALUES (1)')\n"
        "    yield 'held'\n"
        "async def handler(conn):\n"
        "    cm = acquire_db_lock(conn)\n"
        "    holder = await db_call(cm.__enter__)\n"
    )
    assert _findings(cm_src) == [], (
        "constructing a @contextmanager object must not be flagged — "
        "the DB work runs at __enter__, driven off-loop by the caller"
    )

    # A plain generator function — same reasoning, the body does not
    # run on the bare call.
    gen_src = (
        "def _rows(db):\n"
        "    for r in db.execute('SELECT 1'):\n"
        "        yield r\n"
        "async def handler(db):\n"
        "    g = _rows(db)\n"
    )
    assert _findings(gen_src) == [], (
        "constructing a generator must not be flagged — the body does "
        "not run until iteration"
    )


def test_db_touch_inside_lambda_is_not_attributed_to_async_def():
    """ false-positive guard — a ``lambda`` is a sync-function
    scope. A DB touch inside ``lambda: helper()`` belongs to the
    lambda, not the enclosing ``async def`` — defining the async def
    does not run the lambda. It must not be flagged at the async def's
    expense.

    (A lambda whose DB touch genuinely runs on the loop — because some
    callee invokes it on-loop — is out of this per-module guard's
    reach, exactly as a ``db_call``-style indirection is; that residue
    is tracked for the connection-safety sweep, not papered over with a
    false positive here.)
    """
    src = (
        "async def loop(app):\n"
        "    schedule(lambda: get_setting(app.state.db, 'k'))\n"
    )
    assert _findings(src) == [], (
        "a DB touch inside a lambda must not be attributed to the "
        "enclosing async def"
    )

    # And a lambda dispatched through db_call is unambiguously safe.
    safe = (
        "async def handler(db):\n"
        "    row = await db_call(lambda: get_setting(db, 'k'))\n"
    )
    assert _findings(safe) == [], (
        "a lambda dispatched via db_call must not be flagged"
    )


# ---------------------------------------------------------------------------
# Cross-module pass — synthetic-package tests
# ---------------------------------------------------------------------------

def _scan_synthetic_package(pkg_root: Path) -> dict[str, list]:
    """Build a module index over a synthetic ``email_triage`` package
    tree, run the cross-module fixpoint, and return ``{rel_path:
    findings}`` for every async-bearing module — the same pipeline
    ``_scan`` uses, but rooted at a temp tree instead of the real src.
    """
    index = _build_module_index(pkg_root)
    _compute_global_db_touchers(index)
    out: dict[str, list] = {}
    for info in index.values():
        if not any(
            isinstance(n, ast.AsyncFunctionDef)
            for n in ast.walk(info.tree)
        ):
            continue
        imported = _imported_db_names(info, index)
        local = _local_db_helpers(
            info.tree, info.aliases, info.deferred, imported,
        )
        finder = _AsyncDbFinder(
            info.path.read_text(encoding="utf-8"),
            info.aliases, local, info.deferred, imported,
        )
        finder.visit(info.tree)
        rel = str(info.path.relative_to(pkg_root)).replace("\\", "/")
        out[rel] = finder.findings
    return out


def test_cross_module_wrapper_is_resolved(tmp_path):
    """ Option C — a sync wrapper IMPORTED from another module,
    whose body touches the DB, must be flagged at its call site in an
    ``async def``. This is the real ``app.py`` → ``_ice_eff`` →
    ``is_calendar_effectively_enabled`` (in ``…ui._shared``) miss that
    a per-module-only guard cannot see.
    """
    pkg = tmp_path / "email_triage"
    (pkg).mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    # The defining module: a sync helper that does a raw DB touch.
    (pkg / "helpers.py").write_text(
        "def is_calendar_effectively_enabled(db, acct):\n"
        "    return db.execute('SELECT 1').fetchone() is not None\n",
        encoding="utf-8",
    )
    # The consuming module: imports it aliased, calls it in an async def.
    (pkg / "app.py").write_text(
        "from email_triage.helpers import (\n"
        "    is_calendar_effectively_enabled as _ice_eff,\n"
        ")\n"
        "async def handler(db, acct):\n"
        "    if _ice_eff(db, acct):\n"
        "        return True\n",
        encoding="utf-8",
    )
    results = _scan_synthetic_package(pkg)
    app_findings = results.get("app.py", [])
    assert len(app_findings) == 1, (
        f"the cross-module wrapper call must be flagged; got "
        f"{app_findings}"
    )
    assert app_findings[0][0] == "g", (
        "a cross-module import offender must be reported as kind 'g'"
    )
    assert "is_calendar_effectively_enabled" in app_findings[0][3], (
        "the finding must name the canonical cross-module helper"
    )


def test_cross_module_reexport_chain_is_followed(tmp_path):
    """ Option C — a DB-touching helper re-exported through a
    package ``__init__`` must still resolve. ``app.py`` imports it from
    the package, the package ``__init__`` imports it from the leaf
    module — the global fixpoint must follow both hops.
    """
    pkg = tmp_path / "email_triage"
    (pkg / "ui").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    # Leaf module defines the DB-touching helper.
    (pkg / "ui" / "_shared.py").write_text(
        "def build_ctx(db):\n"
        "    return db.execute('SELECT 1').fetchall()\n",
        encoding="utf-8",
    )
    # Package __init__ re-exports it.
    (pkg / "ui" / "__init__.py").write_text(
        "from email_triage.ui._shared import build_ctx\n",
        encoding="utf-8",
    )
    # Consumer imports it from the package, not the leaf.
    (pkg / "app.py").write_text(
        "from email_triage.ui import build_ctx\n"
        "async def handler(db):\n"
        "    return build_ctx(db)\n",
        encoding="utf-8",
    )
    results = _scan_synthetic_package(pkg)
    app_findings = results.get("app.py", [])
    assert len(app_findings) == 1, (
        f"a re-exported DB helper must resolve through the package "
        f"__init__; got {app_findings}"
    )
    assert app_findings[0][0] == "g"


def test_cross_module_contextmanager_import_is_not_flagged(tmp_path):
    """ Option C false-positive guard — importing and *calling* a
    ``@contextmanager`` from another module only builds the CM; it must
    not be flagged. The real case is ``acquire_db_lock`` imported by
    ``single_flight.acquire_db_lock_async``.
    """
    pkg = tmp_path / "email_triage"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "locks.py").write_text(
        "from contextlib import contextmanager\n"
        "@contextmanager\n"
        "def acquire_lock(db):\n"
        "    db.execute('INSERT INTO lock VALUES (1)')\n"
        "    yield 'held'\n",
        encoding="utf-8",
    )
    (pkg / "app.py").write_text(
        "from email_triage.locks import acquire_lock\n"
        "async def handler(db):\n"
        "    cm = acquire_lock(db)\n"
        "    return cm\n",
        encoding="utf-8",
    )
    results = _scan_synthetic_package(pkg)
    assert results.get("app.py", []) == [], (
        "constructing an imported @contextmanager must not be flagged"
    )


def test_globals_update_star_reexport_is_followed(tmp_path):
    """ R1 HIGH-2 — a DB helper re-exported through a package façade
    via ``globals().update(vars(X))`` (NOT a static ``from X import``)
    must still resolve to its defining module.

    This is the EXACT shape ``routers/ui`` uses and the blind spot that
    let the push-consumer ``_is_dry_run`` hole (R1 HIGH-1) escape a
    green guard. ``routers/ui/__init__.py`` does ``from . import
    _shared`` then ``globals().update({n: v for n, v in
    vars(_shared).items() ...})`` — a *runtime* star re-export. A
    consumer imports the helper from the package, not the leaf module.
    The static ``ImportFrom`` scan cannot see the re-export; the
    ``globals().update(vars(...))`` AST-shape detector must.
    """
    pkg = tmp_path / "email_triage"
    (pkg / "ui").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    # Leaf module defines the DB-touching helper.
    (pkg / "ui" / "_shared.py").write_text(
        "def is_dry_run(db):\n"
        "    return db.execute('SELECT v FROM settings').fetchone()\n",
        encoding="utf-8",
    )
    # Package __init__ re-exports it the runtime way — `from . import
    # _shared` + `globals().update(vars(_shared))`. NO static
    # `from ._shared import is_dry_run` line exists.
    (pkg / "ui" / "__init__.py").write_text(
        "from . import _shared\n"
        "globals().update({\n"
        "    _n: _v for _n, _v in vars(_shared).items()\n"
        "    if not _n.startswith('__')\n"
        "})\n",
        encoding="utf-8",
    )
    # Consumer imports it from the PACKAGE façade, calls it in async def.
    (pkg / "app.py").write_text(
        "from email_triage.ui import is_dry_run\n"
        "async def handler(db):\n"
        "    return is_dry_run(db)\n",
        encoding="utf-8",
    )
    results = _scan_synthetic_package(pkg)
    app_findings = results.get("app.py", [])
    assert len(app_findings) == 1, (
        f"a helper re-exported via globals().update(vars(_shared)) must "
        f"resolve through the package façade; got {app_findings}"
    )
    assert app_findings[0][0] == "g", (
        "a façade-re-exported cross-module offender is kind 'g'"
    )
    assert "is_dry_run" in app_findings[0][3]


def test_globals_update_star_reexport_relative_from_init(tmp_path):
    """ R1 HIGH-2 — relative-import resolution from a package
    ``__init__.py`` must NOT be off-by-one.

    ``routers/ui/__init__.py`` does ``from . import _shared``. A
    package ``__init__`` resolves a ``level==1`` relative import against
    the package ITSELF (``…routers.ui``), not its parent
    (``…routers``). The pre-fix resolver stripped ``level`` components
    off the dotted name unconditionally, so ``from . import _shared``
    inside ``routers/ui/__init__.py`` resolved to ``…routers._shared``
    — a module that does not exist — and the star re-export silently
    pointed nowhere. This test pins the package-vs-module distinction:
    the consumer reaches the helper only if the ``__init__``'s relative
    ``from . import _shared`` resolves to ``…ui._shared``.
    """
    pkg = tmp_path / "email_triage"
    (pkg / "web" / "ui").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "web" / "__init__.py").write_text("", encoding="utf-8")
    # A decoy ``_shared`` ONE level up — if the resolver is off-by-one
    # it would bind here instead. This decoy has NO DB work, so an
    # off-by-one bug would make the test fail (zero findings).
    (pkg / "web" / "_shared.py").write_text(
        "def is_dry_run(db):\n"
        "    return False\n",
        encoding="utf-8",
    )
    # The REAL leaf — the DB-touching one, inside the ui package.
    (pkg / "web" / "ui" / "_shared.py").write_text(
        "def is_dry_run(db):\n"
        "    return db.execute('SELECT 1').fetchone()\n",
        encoding="utf-8",
    )
    (pkg / "web" / "ui" / "__init__.py").write_text(
        "from . import _shared\n"
        "globals().update(vars(_shared))\n",
        encoding="utf-8",
    )
    (pkg / "web" / "app.py").write_text(
        "from email_triage.web.ui import is_dry_run\n"
        "async def handler(db):\n"
        "    return is_dry_run(db)\n",
        encoding="utf-8",
    )
    results = _scan_synthetic_package(pkg)
    app_findings = results.get("web/app.py", [])
    assert len(app_findings) == 1, (
        f"the package __init__'s `from . import _shared` must resolve "
        f"to the in-package leaf, not the parent-level decoy; got "
        f"{app_findings}"
    )
    assert app_findings[0][0] == "g"


def test_star_reexport_does_not_follow_a_contextmanager(tmp_path):
    """ R1 HIGH-2 false-positive guard — a ``@contextmanager``
    re-exported through a ``globals().update(vars(X))`` façade must
    still be treated as deferred. Calling it only builds the CM object;
    flagging the construction call would be a cross-module false
    positive, exactly as for a same-module ``@contextmanager``.
    """
    pkg = tmp_path / "email_triage"
    (pkg / "ui").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "ui" / "_shared.py").write_text(
        "from contextlib import contextmanager\n"
        "@contextmanager\n"
        "def acquire_lock(db):\n"
        "    db.execute('INSERT INTO lock VALUES (1)')\n"
        "    yield 'held'\n",
        encoding="utf-8",
    )
    (pkg / "ui" / "__init__.py").write_text(
        "from . import _shared\n"
        "globals().update(vars(_shared))\n",
        encoding="utf-8",
    )
    (pkg / "app.py").write_text(
        "from email_triage.ui import acquire_lock\n"
        "async def handler(db):\n"
        "    cm = acquire_lock(db)\n"
        "    return cm\n",
        encoding="utf-8",
    )
    results = _scan_synthetic_package(pkg)
    assert results.get("app.py", []) == [], (
        "a @contextmanager re-exported via globals().update(vars(_shared)) "
        "must remain deferred — constructing it is not a DB touch"
    )


# ===========================================================================
#  — connection-holding-class guard (follow-up to )
# ===========================================================================
#
# 's guard scans a module ONLY when the module contains an
# ``async def`` (``_guarded_modules()`` filters on ``_has_async_def``).
# That leaves a whole class of offender invisible: a SYNC method of a
# class that stashes a ``sqlite3.Connection`` on ``self`` and runs raw
# ``self._conn.execute``/``commit`` with no ``get_write_lock()``.
#
# The headline case is ``DbSecrets`` in ``src/email_triage/secrets.py``
# — ``__init__`` does ``self._conn = conn``; ``set``/``get``/``delete``/
# ``list_keys`` run raw ``self._conn.execute``/``commit``. ``secrets.py``
# has no ``async def`` at all, so it is never in 's guarded set —
# yet ``DbSecrets`` is constructed once and shared, and its methods are
# called from ~23 ``async def`` handlers. A method that touches the
# shared connection off the write lock is a genuine
# ``InterfaceError``/corruption hazard exactly like a raw touch in an
# ``async def`` — 's blind spot, one class-shape over.
#
# This guard is INDEPENDENT of the async-def filter: it scans every
# module under ``src/email_triage`` for classes whose ``__init__``
# binds a connection to an instance attribute, then flags raw DB
# touches in their sync methods that are not inside a
# ``get_write_lock()`` block (or a ``# async-db-ok`` opt-out). It
# generalises beyond ``DbSecrets`` to any connection-holding class
# (FlowStore, SQLiteLogHandler, acme_job_state, …).


def _connection_attrs_from_init(cls: ast.ClassDef) -> set[str]:
    """Return the instance-attribute names a class binds a sqlite
    connection to in ``__init__``.

    Detects the shape ``self.<attr> = <param>`` where ``<param>`` is an
    ``__init__`` parameter that is connection-like — either named in
    ``_DB_NAMES`` (``conn`` / ``db`` / ``connection`` / ``_conn`` /
    ``_db``) or annotated with a ``sqlite3.Connection`` type. Name-based
    detection is the load-bearing path: ``DbSecrets.__init__(self,
    conn: Any, ...)`` types the param ``Any``, so only the name
    ``conn`` identifies it.

    Returns the set of ``self.<attr>`` names — e.g. ``{"_conn"}`` for
    ``DbSecrets``. Empty if the class is not a connection holder.
    """
    init = next(
        (
            n for n in cls.body
            if isinstance(n, ast.FunctionDef) and n.name == "__init__"
        ),
        None,
    )
    if init is None:
        return set()

    # Collect connection-like parameter names of __init__.
    conn_params: set[str] = set()
    all_args = (
        list(init.args.posonlyargs)
        + list(init.args.args)
        + list(init.args.kwonlyargs)
    )
    for arg in all_args:
        if arg.arg == "self":
            continue
        if arg.arg in _DB_NAMES:
            conn_params.add(arg.arg)
            continue
        # Annotated sqlite3.Connection (``conn: sqlite3.Connection``)?
        ann = arg.annotation
        ann_name = None
        if isinstance(ann, ast.Attribute):
            ann_name = ann.attr
        elif isinstance(ann, ast.Name):
            ann_name = ann.id
        if ann_name == "Connection":
            conn_params.add(arg.arg)

    if not conn_params:
        return set()

    # Find ``self.<attr> = <conn_param>`` assignments in __init__.
    conn_attrs: set[str] = set()
    for node in ast.walk(init):
        if not isinstance(node, ast.Assign):
            continue
        # RHS must be a bare name that is a connection param.
        rhs = node.value
        if not (isinstance(rhs, ast.Name) and rhs.id in conn_params):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                conn_attrs.add(target.attr)
    return conn_attrs


class _ConnHolderMethodFinder(ast.NodeVisitor):
    """Flag raw DB touches in the sync methods of a connection-holding
    class that are NOT inside a ``get_write_lock()`` block.

    A "raw DB touch" is ``self.<connattr>.execute``/``commit``/… where
    ``<connattr>`` is one of the connection attributes the class binds
    in ``__init__``. It is *safe* only when lexically inside a ``with
    get_write_lock():`` block — that is the one correct way for a sync
    method to touch the shared connection (the same RLock ``db_call``
    and ``@db_write`` take). An ``# async-db-ok`` opt-out on the line
    (or the line above) also suppresses it, for the rare provably-safe
    touch (single-threaded bootstrap, CLI).

    ``async def`` methods are skipped here — those are 's job (and
    an ``async def`` doing raw DB work is already caught by the main
    guard, which now scans this module too if it has any ``async def``).
    Nested ``def``/``lambda`` inside a method are skipped: their body is
    a separate sync scope dispatched elsewhere (typically through
    ``db_call``).
    """

    def __init__(self, src: str, conn_attrs: set[str]) -> None:
        self._optout = _optout_lines(src)
        self._conn_attrs = conn_attrs
        self._writelock_depth = 0
        # (method_name, lineno, description)
        self.findings: list[tuple[str, int, str]] = []
        self._method: str | None = None

    def _opted_out(self, lineno: int) -> bool:
        return lineno in self._optout or (lineno - 1) in self._optout

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self._method is not None:
            # A nested sync def inside a method — its own scope, not the
            # method's. The connection-holding guard only judges the
            # method body itself.
            return
        self._method = node.name
        self._writelock_depth = 0
        self.generic_visit(node)
        self._method = None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        # async methods belong to the  async-scan, not this guard.
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # A lambda is its own scope.
        return

    def visit_With(self, node: ast.With) -> None:
        # Does any item of this ``with`` acquire get_write_lock()?
        takes_lock = any(
            isinstance(item.context_expr, ast.Call)
            and _called_helper_name(item.context_expr.func) == "get_write_lock"
            for item in node.items
        )
        if takes_lock:
            self._writelock_depth += 1
            for child in node.body:
                self.visit(child)
            self._writelock_depth -= 1
        else:
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if (
            self._method is not None
            and self._writelock_depth == 0
            and isinstance(func, ast.Attribute)
            and func.attr in _DB_METHODS
            and isinstance(func.value, ast.Attribute)
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "self"
            and func.value.attr in self._conn_attrs
            and not self._opted_out(node.lineno)
        ):
            self.findings.append((
                self._method, node.lineno,
                f"self.{func.value.attr}.{func.attr}() — raw DB touch "
                "outside get_write_lock()",
            ))
        self.generic_visit(node)


def _scan_connection_holding_classes(
    tree: ast.AST, src: str,
) -> list[tuple[str, str, int, str]]:
    """Scan one parsed module for unguarded raw DB touches in the sync
    methods of connection-holding classes.

    Returns ``(class_name, method_name, lineno, description)`` tuples.
    """
    findings: list[tuple[str, str, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        conn_attrs = _connection_attrs_from_init(node)
        if not conn_attrs:
            continue
        finder = _ConnHolderMethodFinder(src, conn_attrs)
        for item in node.body:
            finder.visit(item)
        for method, lineno, desc in finder.findings:
            findings.append((node.name, method, lineno, desc))
    return findings


def _all_source_modules() -> list[Path]:
    """Every ``.py`` under ``src/email_triage`` — NOT filtered by
    ``async def``. A connection-holding class can live in a sync-only
    module (``secrets.py`` is exactly that), so this guard must scan
    the whole tree. ``__pycache__`` is excluded via the shared pin
    harness ``iter_src_files`` walk (R5b).
    """
    return [p for p in iter_src_files() if p.is_file()]


# --- detector unit tests (synthetic source — no real-tree dependency) ------

def _conn_holder_findings(src: str) -> list[tuple[str, str, int, str]]:
    """Run the connection-holding-class scan on a synthetic source."""
    return _scan_connection_holding_classes(parse_source(src), src)


def test_conn_holder_unguarded_method_is_flagged():
    """A sync method doing raw ``self._conn.execute`` with NO
    ``get_write_lock()`` — the ``DbSecrets.set`` shape — is flagged."""
    src = (
        "class Store:\n"
        "    def __init__(self, conn):\n"
        "        self._conn = conn\n"
        "    def save(self, k, v):\n"
        "        self._conn.execute('INSERT INTO t VALUES (?,?)', (k, v))\n"
        "        self._conn.commit()\n"
    )
    findings = _conn_holder_findings(src)
    assert len(findings) == 2, (
        f"both the raw execute and commit must be flagged; got {findings}"
    )
    assert all(f[0] == "Store" and f[1] == "save" for f in findings)


def test_conn_holder_method_under_write_lock_is_safe():
    """The same raw touch INSIDE ``with get_write_lock():`` is correct —
    that is the one safe way a sync method may touch the shared
    connection — and must NOT be flagged."""
    src = (
        "class Store:\n"
        "    def __init__(self, conn):\n"
        "        self._conn = conn\n"
        "    def save(self, k, v):\n"
        "        with get_write_lock():\n"
        "            self._conn.execute('INSERT INTO t VALUES (?,?)', (k, v))\n"
        "            self._conn.commit()\n"
    )
    assert _conn_holder_findings(src) == [], (
        "raw DB touches inside a get_write_lock() block must not be flagged"
    )


def test_conn_holder_connection_typed_param_is_detected():
    """The connection param can be identified by a ``sqlite3.Connection``
    annotation, not only by name — ``__init__(self, c: sqlite3.Connection)``
    with ``self._db = c`` is still a connection holder."""
    src = (
        "import sqlite3\n"
        "class Store:\n"
        "    def __init__(self, c: sqlite3.Connection):\n"
        "        self._db = c\n"
        "    def save(self):\n"
        "        self._db.execute('DELETE FROM t')\n"
    )
    findings = _conn_holder_findings(src)
    assert len(findings) == 1, (
        f"a Connection-annotated param assigned to self must make the "
        f"class a connection holder; got {findings}"
    )


def test_conn_holder_opt_out_comment_is_honoured():
    """An ``# async-db-ok`` opt-out on the offending line suppresses the
    finding — for the rare provably-safe sync touch (bootstrap / CLI)."""
    src = (
        "class Store:\n"
        "    def __init__(self, conn):\n"
        "        self._conn = conn\n"
        "    def save(self):\n"
        "        self._conn.execute('X')  # async-db-ok: single-threaded boot\n"
    )
    assert _conn_holder_findings(src) == [], (
        "an `# async-db-ok` opt-out must suppress a connection-holder "
        "finding"
    )


def test_conn_holder_non_holder_class_is_ignored():
    """A class that does NOT bind a connection in ``__init__`` is not a
    connection holder — even raw ``.execute`` on an unrelated attribute
    is out of this guard's scope (it is not the shared connection)."""
    src = (
        "class NotAStore:\n"
        "    def __init__(self, name):\n"
        "        self._name = name\n"
        "    def go(self):\n"
        "        self._name.execute('not a db')\n"
    )
    assert _conn_holder_findings(src) == [], (
        "a class that binds no connection must not be scanned"
    )


def test_conn_holder_async_method_is_left_to_the_main_guard():
    """An ``async def`` method of a connection-holding class is NOT this
    guard's concern — 's async scan owns async bodies (and already
    scans this module if it has any async def). This guard only judges
    SYNC methods."""
    src = (
        "class Store:\n"
        "    def __init__(self, conn):\n"
        "        self._conn = conn\n"
        "    async def save(self):\n"
        "        self._conn.execute('X')\n"
    )
    assert _conn_holder_findings(src) == [], (
        "an async method is the main #248 guard's job, not this one"
    )


def test_conn_holder_nested_def_is_its_own_scope():
    """A raw touch inside a nested ``def`` within a method belongs to
    that nested scope (typically a ``db_call`` closure), not the method
    — it must not be flagged against the enclosing method."""
    src = (
        "class Store:\n"
        "    def __init__(self, conn):\n"
        "        self._conn = conn\n"
        "    def save(self):\n"
        "        def _work():\n"
        "            self._conn.execute('X')\n"
        "        return _work\n"
    )
    assert _conn_holder_findings(src) == [], (
        "a touch inside a nested def is that closure's scope, not the "
        "method's"
    )


def test_conn_holder_dbsecrets_is_detected_as_a_holder():
    """Sanity against the real tree: ``DbSecrets`` in
    ``src/email_triage/secrets.py`` MUST be recognised as a
    connection-holding class — it binds ``self._conn = conn`` in
    ``__init__``. If this regresses, the ratchet below scans nothing.
    """
    secrets_py = _src_root() / "secrets.py"
    assert secrets_py.is_file(), f"secrets.py not found at {secrets_py}"
    tree = parse_module(secrets_py); assert tree is not None  # N-350 R31
    holders = {
        cls.name: _connection_attrs_from_init(cls)
        for cls in ast.walk(tree)
        if isinstance(cls, ast.ClassDef)
        and _connection_attrs_from_init(cls)
    }
    assert "DbSecrets" in holders, (
        "DbSecrets must be detected as a connection-holding class — "
        f"detected holders: {holders}"
    )
    assert "_conn" in holders["DbSecrets"], (
        f"DbSecrets must bind the connection to self._conn; got "
        f"{holders['DbSecrets']}"
    )


def test_no_unguarded_connection_holding_class_methods():
    """ ratchet — no sync method of a connection-holding class may
    touch the shared connection outside ``get_write_lock()``.

    Scans the ENTIRE ``src/email_triage`` tree (not only async-bearing
    modules — ``secrets.py`` has no ``async def`` yet houses
    ``DbSecrets``). This closes 's structural blind spot: a
    connection-holding class whose sync methods run raw
    ``self._conn.execute``/``commit`` is invisible to the async-scan
    guard.

    Enforced — a permanent green ratchet. The offenders the initial
    whole-tree scan revealed (across ``secrets.py``, ``actions/``,
    ``engine/store.py`` and ``triage_logging.py``) were closed by
    task  (wrap each raw ``.execute``/``.commit`` in
    ``with get_write_lock():``) and the  opt-out pass
    (``# async-db-ok`` on the provably contention-free sites). The
    detector logic itself is independently verified by the synthetic
    ``test_conn_holder_*`` cases above; this test is the live whole-
    tree assertion that no NEW offender slips in. If this test fails,
    a recently-added or recently-modified class binds a sqlite
    connection in its ``__init__`` and runs raw ``.execute``/
    ``.commit`` on it from a sync method outside a
    ``get_write_lock()`` block — the failure message enumerates every
    offender ``class.method`` with file:line. Fix each: wrap the raw
    touch in ``with get_write_lock():``, or — only for a provably
    contention-free site (single-threaded bootstrap, CLI) — add an
    ``# async-db-ok`` opt-out comment with a rationale.
    """
    all_findings: list[str] = []
    for path in _all_source_modules():
        try:
            src = path.read_text(encoding="utf-8")
            tree = parse_source(src)
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = relpath(path)
        for cls, method, lineno, desc in _scan_connection_holding_classes(
            tree, src,
        ):
            all_findings.append(
                f"  {rel}:{lineno}  class {cls}.{method}(): {desc}"
            )
    if all_findings:
        joined = "\n".join(sorted(all_findings))
        pytest.fail(
            f"{len(all_findings)} unguarded connection-holding-class "
            f"method DB touch(es):\n{joined}\n\n"
            "A sync method of a class that holds the shared "
            "sqlite3.Connection must wrap every raw .execute/.commit in "
            "`with get_write_lock():` — the same RLock db_call and "
            "@db_write take. Otherwise two threads can use the one "
            "connection concurrently (InterfaceError / corruption)."
        )
