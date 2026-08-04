"""Command-line interface for email-triage.

Usage:
    email-triage run [--query Q] [--limit N] [--dry-run]
    email-triage watch [--interval 300] [--query Q] [--push]
    email-triage status [--status STATUS]
    email-triage summary [--since 24h] [--clear]
    email-triage serve [--host 0.0.0.0] [--port 8080]
    email-triage secrets set KEY
    email-triage secrets list
    email-triage user create --email EMAIL [--name NAME] [--role admin]
    email-triage user list
    email-triage apikey create --name NAME --user EMAIL
    email-triage apikey list
    email-triage apikey delete KEY_ID
    email-triage config --validate [PATH]
    email-triage init [PATH]
    email-triage style-profile build --account ID [--limit N] [--query Q]
    email-triage audit verify [--db PATH] [--since ISO] [--quiet]
    email-triage sent-mail-index build --account ID [--limit N]
    email-triage version-check [--db PATH] [--json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from email_triage._isotime import now_utc_iso
from pathlib import Path
from typing import Any

from email_triage.config import (
    TriageConfig,
    load_config,
    validate_config,
)
from email_triage.triage_logging import get_logger, setup_logging
from email_triage.web.task_supervisor import next_backoff_delay  # N-228 R22 SSOT
from email_triage._errfmt import fmt_exc
from email_triage.db._helpers import apply_compatible_row_factory

log = get_logger("cli")


class CliAuditGateClosed(RuntimeError):
    """N-157 (2026-07-09) — CLI audit auto-emit at handler ENTRY failed
    AND ``--allow-unaudited`` is NOT set.

    The wrapping ``@_cli_audit`` decorator lets this propagate out of
    the handler so the CLI exits nonzero with a specific error message
    naming ``--allow-unaudited`` as the recovery lever.  Prime Directive
    #8 (controls fail CLOSED) is anchored here: the operator MUST make
    an explicit decision to run an unaudited op instead of silently
    getting fail-soft.  operator-directed 2026-07-08 (AskUserQuestion N-157
    answer: 'Fail-loud with recovery flag').
    """


async def _aclose_provider_quietly(provider: object) -> None:
    """Close a provider's async client in the CURRENT event loop, logging — never
    raising, never masking the command's exit code — on failure ( leak
    diagnostic; db-sme [269]).

    N-131: this MUST be awaited inside the SAME ``asyncio.run`` that drove the
    provider's work. A provider's ``httpx.AsyncClient`` is created lazily in that
    loop; closing it from a SECOND ``asyncio.run(provider.close())`` (the old
    shape) fails ``RuntimeError: Event loop is closed`` on EVERY run — so the
     warning fired constantly (drowning a real leak) and the un-wrapped
    cmd_watch_push site even RAISED out of its finally. Every CLI command that
    builds a provider wraps its ``_run`` so close happens in-loop. Enforced by
    ``tests/test_cli_provider_close_in_loop_pin.py``.
    """
    try:
        await provider.close()  # type: ignore[attr-defined]
    except Exception as e:
        # NB (PD#10): `log` is a TriageLogger; its .warning() does NOT forward
        # `exc_info` (only .error() does) — an exc_info=True would land as a dead
        # structured field and the close-failure would log with NO traceback,
        # hollowing out the  diagnostic. Use the repo cli.py idiom
        # error=fmt_exc(e) so the warning actually carries the WHY. (db-sme N-131.)
        log.warning("provider.close failed", error=fmt_exc(e))


# ---------------------------------------------------------------------------
# H-03-auto — CLI audit auto-emit (defense-in-depth, §164.312(b))
# ---------------------------------------------------------------------------
#
# H-03 (CLI administrative actions not in log_entries hash chain) closed at
# 26687f4 + 85f6fcd via a PROCEDURAL mechanism per §164.312(b)'s "and/or
# procedural" reading — the break-glass `actions_taken` field documented in
# INCIDENT_RESPONSE.md satisfies the audit-control requirement when an
# operator runs CLI ops as documented incident response. H-03-auto is the
# defense-in-depth upgrade: every DB-mutating CLI subcommand now auto-emits
# a structured log_entries chain row at entry and at exit, eliminating the
# procedural-vs-automated gap.
#
# DESIGN — HIPAA-mode-gated, not always-on:
#   - §164.312(b) only applies in HIPAA mode by definition
#   - log_entries hash-chain writes are D1 fail-closed per H-02a — they
#     RuntimeError if no HMAC key is provisioned. HMAC wiring requires
#     DbSecrets backend + master key, which non-HIPAA dev/CI installs
#     legitimately may not have. Always-on auto-emit would block CLI ops
#     on installs that don't have full secrets setup → HARM in non-HIPAA
#     scope → falls under the dispatch's "evidence non-HIPAA installs
#     would be harmed" carve-out from default-always-on
#   - H-03's procedural closure was HIPAA-scoped; H-03-auto's automated
#     upgrade matches that scope (operator policy + regulatory boundary
#     are aligned)
#
# Non-HIPAA installs retain identical posture to H-03: no automated CLI
# audit chain row, no compliance requirement to satisfy.
#
# FAIL-SOFT — emission errors are LOGGED, not RAISED:
#   The H-02a HMAC chain is D1 fail-closed for the PRODUCTION hot path
#   (SQLiteLogHandler.emit) because that path's correctness IS the
#   compliance posture. The CLI audit auto-emit is defense-in-depth on top
#   of the procedural mechanism — an emission failure must NOT block the
#   underlying CLI operation (the operator would lose break-glass
#   capability mid-incident). On emission failure we log a warning so the
#   operator can investigate; the procedural mechanism still satisfies
#   §164.312(b) under the original H-03 closure shape.
#
# REDACTION:
#   args are already redacted by argparse parsers — secrets `set`/`delete`
#   accept only a KEY NAME (the value is read via getpass, never on argv).
#   No PHI surfaces in CLI args by design. Sensitive shapes (passphrase
#   file paths) are recorded as PATHS not contents. The actor field
#   captures the OS user via $USER/$USERNAME, matching the existing
#   cmd_apikey pattern at cli.py:606.

_CLI_ACTOR_ENV_KEYS = ("USER", "USERNAME", "LOGNAME")


def _cli_actor() -> str:
    """Resolve the OS-level actor for CLI audit attribution.

    Matches the existing pattern at ``cmd_apikey`` / ``cmd_apikey delete``
    (cli.py:606,644) so CLI-driven api_key_events rows and CLI-driven
    log_entries auto-emit rows attribute to the same identifier shape.
    """
    for env_key in _CLI_ACTOR_ENV_KEYS:
        val = os.environ.get(env_key)
        if val:
            return f"cli:{val}"
    return "cli:unknown"


def _emit_cli_audit_event(
    command: str,
    args: argparse.Namespace,
    *,
    phase: str,
    exit_code: int | None = None,
    error_class: str | None = None,
    error_msg: str | None = None,
    duration_ms: int | None = None,
) -> None:
    """Emit one log_entries chain row for a CLI admin event.

    HIPAA-gated: returns early without writing if HIPAA mode is OFF (see
    DESIGN note above). Fail-soft: emission errors surface via
    ``log.warning`` and never propagate (the procedural H-03 closure is
    still in force; defense-in-depth must not block the underlying op).

    Args:
        command: dotted command path, e.g. ``"user.create"``,
            ``"secrets.rotate-master-key"``.
        args: the argparse Namespace handed to the CLI handler. Used to
            extract a few well-known non-sensitive fields for the audit
            row's extra. No PHI is present in CLI argv by design.
        phase: ``"start"`` (entered handler) or ``"end"`` (handler
            returned, exit_code known).
        exit_code: integer exit code; ``None`` on ``phase='start'`` or
            when the handler raised before returning.
        error_class: exception class name if the handler raised.
        error_msg: ``fmt_exc()`` rendering of the exception.
        duration_ms: wall-clock duration in milliseconds (set on
            ``phase='end'`` only).
    """
    try:
        # Lazy config load — the wrapper runs INSIDE the handler, so
        # load_config has already been performed by most handlers, but
        # we re-resolve cheaply via the args.config attr to remain
        # decoupled from handler internals. Some handlers (like cmd_init
        # which scaffolds a fresh config) intentionally do NOT have a
        # config to load; on those, args.config may be absent or point
        # to a non-existent file → catch and exit silently (no DB to
        # write to anyway).
        config = load_config(getattr(args, "config", None))
    except Exception:
        return
    if not getattr(config.logging, "hipaa", False):
        return
    try:
        # N-157 (2026-07-09): route through `record_cli_admin_op` — the
        # @db_write + @audit_emitter SSOT — so a write failure fires the
        # audit_gap_events sentinel per  D3.  The chain-primitive
        # `insert_log_entry` at db/audit.py is still the underlying
        # writer (via the emitter body); this indirection buys the
        # gap-event row on failure that the direct call lacked.
        from email_triage.db.audit import record_cli_admin_op
        from email_triage.secrets import (
            bootstrap_secrets_from_config,
            wire_audit_chain_hmac_keys,
        )

        # Extract non-sensitive args for the audit row. Allowlist
        # approach: we KNOW these arg names are safe (paths, ids, flags,
        # booleans, emails of admin actors, role names). Anything not in
        # the allowlist is dropped to avoid accidental disclosure of new
        # arg shapes added later that might carry sensitive content.
        _SAFE_ARG_KEYS = frozenset({
            "command", "secrets_cmd", "apikey_cmd", "user_cmd",
            "tls_cmd", "audit_cmd", "auth_cmd",
            "style_profile_cmd", "sent_mail_index_cmd",
            "embedding_bits_cmd",
            "force", "commit", "dry_run", "json", "quiet",
            "limit", "account", "interval", "key_id",
            "name", "email", "role", "user", "key",
            "host", "port", "path", "config",
            "save_old_key_to", "passphrase_file", "master_key_out",
            "target_dir", "source_dir", "manifest", "bundle",
            "since", "db", "list",
            # N-157 (2026-07-09) — audit-gate bypass flag. Recording
            # this in the row makes any bypass visible to forensic
            # review + register-row audit; the value is a bounded bool
            # (Safe-Harbor IN).
            "allow_unaudited",
        })
        safe_args: dict[str, Any] = {}
        for k, v in vars(args).items():
            if k not in _SAFE_ARG_KEYS:
                continue
            if v is None or v == "":
                continue
            # Convert Path / non-primitive to string for JSON safety.
            if isinstance(v, (str, int, bool, float)):
                safe_args[k] = v
            else:
                safe_args[k] = str(v)

        extra: dict[str, Any] = {
            "cli_command": command,
            "cli_phase": phase,
            "actor": _cli_actor(),
            "args": safe_args,
        }
        if exit_code is not None:
            extra["exit_code"] = exit_code
        if error_class is not None:
            extra["error_class"] = error_class
        if error_msg is not None:
            extra["error"] = error_msg
        if duration_ms is not None:
            extra["duration_ms"] = duration_ms

        # Open DB + wire HMAC keys if not already wired. The HMAC
        # registry is process-global, so a second call is a no-op when
        # the handler already wired it (e.g., cmd_secrets at line 435
        # has its own bootstrap). We wire it here to cover handlers
        # that DON'T currently bootstrap secrets (cmd_user, cmd_apikey,
        # restore, embedding-bits) — chain write must succeed.
        db_path = Path(config.persistence.db_path)
        if not db_path.exists():
            # Pre-init state — no DB to write to. Surface as a warning
            # so the operator knows the CLI op ran without an audit
            # row (the alternative is silent skip, which would hide
            # the gap).
            log.warning(
                "H-03-auto: CLI audit auto-emit skipped — DB does not "
                "exist yet (pre-init state)",
                cli_command=command, cli_phase=phase,
            )
            return
        conn = _cli_open_config_db(config)
        try:
            try:
                provider = bootstrap_secrets_from_config(conn, config)
            except Exception as e:
                # Secrets bootstrap failure under HIPAA mode is itself
                # a HIPAA finding — surface and skip emit. enforce_*
                # below would RuntimeError anyway; catch here to keep
                # the warning specific to the audit path.
                log.warning(
                    "H-03-auto: secrets bootstrap failed; CLI audit "
                    "auto-emit skipped",
                    cli_command=command, cli_phase=phase,
                    error=fmt_exc(e),
                )
                return
            # NOTE: we intentionally do NOT call
            # `enforce_master_key_at_rest_for_hipaa(config)` here. That
            # helper is a BOOT-time gate run by the wrapped CLI handler's
            # own bootstrap. Re-running it from the auto-emit path would
            # double-fire on success (cheap) but also raise asymmetrically
            # on the 'end' emit IF the wrapped handler is the one that
            # FIRST flipped `_hipaa_mode = True` via setup_logging — the
            # 'start' emit runs before setup_logging and would see HIPAA
            # mode off, the 'end' emit sees it on. The auto-emit's job
            # is to land the audit row, not to re-enforce the boot gate.
            wire_audit_chain_hmac_keys(provider, config)

            # N-182 R20_7: route the log_entries chain write through
            # safe_audit_write. The chain-primitive insert_log_entry is a
            # /health-visible emitter surface: routing here lands a specific
            # `audit_write_failed` WARNING (the drift-detector observability
            # convergence) instead of the generic fail-soft below, which
            # was invisible to /health.
            from email_triage.web._audit import safe_audit_write

            # db-sme N-182 must-fix M3: `conn.commit()` is OUTSIDE the lambda
            # so a commit failure surfaces to the outer H-03-auto handler
            # rather than being silently swallowed by safe_audit_write (a
            # swallowed commit after a successful INSERT would leave the
            # log_entries HMAC chain in an ambiguous state — PD#12 fail-closed
            # violation). A commit exception falls through to the outer
            # try/except which logs a H-03-auto WARNING w/ chain_commit_failed
            # context. safe_audit_write returns whatever the lambda yielded
            # (an int row id from insert_log_entry) on success, None on emit
            # failure — the `is None` gate discriminates emit-failure from
            # commit-failure (a distinction PD#12 requires).
            ts = now_utc_iso()
            # `record_cli_admin_op` returns None on both success + swallow
            # (its type is `-> None`); the trailing `True` in the tuple
            # returned by the lambda gives safe_audit_write a non-None
            # success sentinel to discriminate from its own None-on-
            # failure return semantics.
            # DA fold N-157 Fix #2 (hipaa-sme calibrated 2026-07-09):
            # pass `allow_unaudited` as a dedicated top-level IN kwarg
            # so it appears verbatim on the gap-row when the emit fails.
            # `_SAFE_ARG_KEYS` extension already lands it inside `extra`
            # on the SUCCESS path — the top-level pass is redundant then
            # but LOAD-BEARING on the failure path (investigator sees
            # the bypass bit without shell-history cross-match).
            allow_unaudited = bool(getattr(args, "allow_unaudited", False))
            _emit_result = safe_audit_write(
                lambda: (record_cli_admin_op(
                    conn,
                    ts=ts,
                    command=command,
                    phase=phase,
                    extra=extra,
                    allow_unaudited=allow_unaudited,
                ), True)[1],
                description=f"cli_admin_op:{command}:{phase}",
            )
            if _emit_result is None:
                # N-157 (2026-07-09) fail-loud gate — operator-directed close per
                # AskUserQuestion 2026-07-08 ("Fail-loud with recovery flag").
                # DEFAULT (allow_unaudited=False): raise at phase='start' so
                # the wrapping @_cli_audit decorator lets it bubble out and
                # the CLI exits nonzero with a specific error message —
                # operator sees an obvious audit-gate error instead of a
                # silent WARN + successful op.  At phase='end' the underlying
                # op has already run + been observed by the operator; fail-
                # loud here can't recover anything, so it stays fail-soft.
                # ``--allow-unaudited`` reverts to the pre-N-157 fail-soft
                # posture the H-03-auto docstring at cli.py:104-112
                # rationalizes for break-glass incident use.
                if phase == "start" and not allow_unaudited:
                    raise CliAuditGateClosed(
                        f"CLI audit emit failed for {command} (phase=start); "
                        "pass --allow-unaudited to bypass (procedural break-"
                        "glass fallback per INCIDENT_RESPONSE.md)."
                    )
                log.warning(
                    "H-03-auto: CLI audit auto-emit failed; procedural "
                    "fallback (break-glass actions_taken) remains in force",
                    cli_command=command, cli_phase=phase,
                    allow_unaudited=allow_unaudited,
                )
            else:
                conn.commit()  # only commit after the chain-write succeeded
        finally:
            conn.close()
    except CliAuditGateClosed:
        # N-157 fail-loud path: propagate to the wrapping @_cli_audit
        # decorator so the CLI exits non-zero.  Do NOT log a WARN — the
        # exception message names --allow-unaudited as the recovery
        # lever and will surface via the top-level entry point's stderr.
        raise
    except Exception as e:
        # Fail-soft: emission errors do NOT propagate. The procedural
        # H-03 closure (break-glass actions_taken in INCIDENT_RESPONSE.md)
        # remains the compliance fallback per §164.312(b)'s "and/or
        # procedural" reading.
        log.warning(
            "H-03-auto: CLI audit auto-emit failed; procedural "
            "fallback (break-glass actions_taken) remains in force",
            cli_command=command, cli_phase=phase,
            error=fmt_exc(e),
        )


def _cli_audit(command: str):
    """Decorator — wrap a CLI handler with H-03-auto audit auto-emit.

    Emits one row at handler entry (phase='start') and one at handler
    exit (phase='end' with exit_code + duration). On exception, emits an
    'end' row with error_class + error fields, then re-raises (the
    handler's own error path runs; the audit row preserves the failure
    context for forensic review).

    Per design above: HIPAA-gated and fail-soft. In non-HIPAA mode the
    decorator is a no-op wrapper (the inner ``_emit_cli_audit_event``
    early-returns when HIPAA mode is off).

    Usage:
        @_cli_audit("user.create")
        def cmd_user(args): ...
    """
    import functools

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(args: argparse.Namespace) -> int:
            t0 = time.monotonic()
            _emit_cli_audit_event(command, args, phase="start")
            try:
                rc = fn(args)
            except BaseException as e:
                dur_ms = int((time.monotonic() - t0) * 1000)
                _emit_cli_audit_event(
                    command, args, phase="end",
                    exit_code=None,
                    error_class=type(e).__name__,
                    error_msg=fmt_exc(e),
                    duration_ms=dur_ms,
                )
                raise
            dur_ms = int((time.monotonic() - t0) * 1000)
            _emit_cli_audit_event(
                command, args, phase="end",
                exit_code=int(rc) if rc is not None else 0,
                duration_ms=dur_ms,
            )
            return rc
        # Tag so the audit-pattern test can confirm every DB-mutating
        # CLI handler has the wrapper applied.
        wrapper._h03_auto_command = command  # type: ignore[attr-defined]
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Bootstrap — build the engine from config
# ---------------------------------------------------------------------------

def _build_engine(config: TriageConfig) -> Any:
    """Construct a FlowEngine from configuration.

    Lazily imports heavy modules and creates the provider, classifier,
    action registry, and flow engine.
    """
    from email_triage.actions.add_label import AddLabelAction
    from email_triage.actions.draft_reply import DraftReplyAction
    from email_triage.actions.escalate import EscalateAction
    from email_triage.actions.mute import MuteAction
    from email_triage.actions.invite import (
        AcceptInviteAction, DeclineInviteAction, TentativeInviteAction,
    )
    from email_triage.actions.label import LabelAction
    from email_triage.actions.move import MoveAction
    from email_triage.actions.notify import NotifyAction
    from email_triage.actions.registry import ActionRegistry
    from email_triage.actions.suggest_meeting_times import SuggestMeetingTimesAction
    from email_triage.actions.regulatory_clock import RegulatoryClockAction
    from email_triage.engine.flow import FlowEngine
    from email_triage.engine.store import FlowStore

    # Store.
    db_path = Path(config.persistence.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # N-17: stamp encryption context so FlowStore's own connection opens
    # against an encrypted install (CLI runs outside the server boot).
    _cli_stamp_db_encryption(config)
    store = FlowStore(db_path)

    # Provider.
    provider = _create_provider(config)

    # Classifier.
    classifier = _create_classifier(config)

    # Action registry.
    registry = ActionRegistry()
    registry.register(NotifyAction())
    registry.register(DraftReplyAction())
    registry.register(LabelAction())
    registry.register(AddLabelAction())
    registry.register(EscalateAction())
    registry.register(MuteAction())
    registry.register(MoveAction())
    registry.register(AcceptInviteAction())
    registry.register(DeclineInviteAction())
    registry.register(TentativeInviteAction())
    registry.register(SuggestMeetingTimesAction())
    registry.register(RegulatoryClockAction())

    return FlowEngine(
        store=store,
        provider=provider,
        classifier=classifier,
        config=config,
        registry=registry,
    )


def _create_provider(config: TriageConfig) -> Any:
    ptype = config.provider.type
    if ptype == "gmail_api":
        from email_triage.providers.gmail_api import GmailApiProvider
        g = config.provider.gmail_api
        return GmailApiProvider(
            account=g.get("account", ""),
            client_id=g.get("client_id", ""),
            client_secret=g.get("client_secret", ""),
            refresh_token=g.get("refresh_token", ""),
        )
    elif ptype == "imap":
        from email_triage.providers.imap import ImapProvider
        imap_cfg = config.provider.imap
        return ImapProvider(
            host=imap_cfg.get("host", "localhost"),
            port=imap_cfg.get("port", 993),
            username=imap_cfg.get("username", ""),
            password=imap_cfg.get("password", ""),
            use_ssl=imap_cfg.get("use_ssl", True),
            mailbox=imap_cfg.get("mailbox", "INBOX"),
            email_address=imap_cfg.get("email_address", ""),
            drafts_folder=imap_cfg.get("drafts_folder", ""),
        )
    elif ptype == "office365":
        from email_triage.providers.office365 import Office365Provider
        o365_cfg = config.provider.office365
        # N-209 R23 (2026-07-02): CLI-scoped msal-cache path via SSOT sibling
        # `providers.factory.msal_cache_path_for_cli(username)` — the
        # `test_no_forked_per_account_msal_cache_literal` pin bans f-strings
        # for these paths so both variants (per-account + per-CLI-username)
        # own their derivation in the ONE module.
        from email_triage.providers.factory import msal_cache_path_for_cli
        _cli_user = o365_cfg.get("account", "") or o365_cfg.get("username", "")
        # N-316 R30 (CI-red fix-forward on N-307): only compute the
        # SSOT-derived default when the config didn't already supply an
        # explicit `token_cache_path`. N-307 tightened
        # `msal_cache_path_for_cli` to fail-CLOSED on an empty username
        # (§164.310(d)(2)(i) cross-account credential-pool defect the
        # `cli_default` bucket represented) — this call was
        # unconditional and would raise ValueError on tests / configs
        # that supply `token_cache_path` explicitly but leave username
        # blank (a legitimate arrangement).
        _token_cache_path = o365_cfg.get("token_cache_path")
        if not _token_cache_path:
            _token_cache_path = str(msal_cache_path_for_cli(_cli_user))
        return Office365Provider(
            client_id=o365_cfg.get("client_id", ""),
            tenant_id=o365_cfg.get("tenant_id", "common"),
            client_secret=o365_cfg.get("client_secret", ""),
            token_cache_path=_token_cache_path,
            username=_cli_user,
        )
    else:
        raise ValueError(f"Unknown provider type: {ptype}")


def _create_classifier(config: TriageConfig) -> Any:
    backend = config.classifier.backend
    local_suffixes = list(getattr(config.tls, "local_url_suffixes", []) or [])
    if backend == "ollama":
        from email_triage.classify.ollama import OllamaClassifier
        return OllamaClassifier(
            model=config.classifier.model,
            base_url=config.classifier.ollama_url,
            prefer_loaded=config.classifier.prefer_loaded,
            local_url_suffixes=local_suffixes,
            prefer_loaded_skip_embeddings=(
                config.classifier.prefer_loaded_skip_embeddings
            ),
            embedding_name_markers=config.classifier.embedding_name_markers,
            backup_models=config.classifier.backup_models,
            num_ctx=config.classifier.num_ctx,
            ollama_think=config.classifier.ollama_think,
            ollama_no_think_marker=config.classifier.ollama_no_think_marker,
            ollama_probe_timeout_secs=config.classifier.ollama_probe_timeout_secs,
            ollama_admin_timeout_secs=config.classifier.ollama_admin_timeout_secs,
            ollama_keep_alive=config.classifier.ollama_keep_alive,
        )
    elif backend == "openai":
        from email_triage.classify.openai_compat import OpenAICompatClassifier
        return OpenAICompatClassifier(
            base_url=config.classifier.openai_base_url,
            model=config.classifier.openai_model,
            local_url_suffixes=local_suffixes,
        )
    elif backend == "gemini":
        from email_triage.classify.gemini import GeminiClassifier
        return GeminiClassifier(
            model=config.classifier.gemini_model or "gemini-2.0-flash",
        )
    else:
        raise ValueError(f"Unknown classifier backend: {backend}")


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    """Run a single triage cycle."""
    config = load_config(args.config)
    setup_logging(config.logging)

    if args.dry_run:
        log.info("Dry run mode — will fetch and classify but not act")

    engine = _build_engine(config)

    async def _run() -> list[Any]:
        try:
            return await engine.run_cycle(args.query, args.limit)
        finally:
            await engine.aclose()  # N-132: close the engine's provider+classifier in-loop

    results = asyncio.run(_run())

    for flow in results:
        cat = flow.classification.category if flow.classification else "?"
        conf = f"{flow.classification.confidence:.0%}" if flow.classification else "?"
        print(f"  {flow.flow_id[:8]}  {flow.status.value:<12} {cat:<20} {conf}")

    print(f"\nProcessed {len(results)} emails.")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Poll for new emails on an interval, or use push (IMAP IDLE)."""
    config = load_config(args.config)
    setup_logging(config.logging)

    if args.push:
        return _cmd_watch_push(config, args)

    engine = _build_engine(config)
    interval = args.interval

    log.info("Watch mode (polling)", interval=interval, query=args.query)
    print(f"Watching every {interval}s for: {args.query}")
    print("Press Ctrl+C to stop.\n")

    async def _watch() -> None:
        while True:
            try:
                results = await engine.run_cycle(args.query, args.limit)
                if results:
                    for flow in results:
                        cat = flow.classification.category if flow.classification else "?"
                        print(f"  [{cat}] {flow.flow_id[:8]} -> {flow.status.value}")
                    print(f"  Processed {len(results)} new emails.\n")
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log.error("Watch cycle failed", exc_info=True)
                print(f"  Error: {e}\n")
            await asyncio.sleep(interval)

    async def _watch_and_close() -> None:
        # N-132: close the engine's provider+classifier IN-LOOP (the work loop they
        # were created in). Ctrl-C re-raises inside _watch -> this finally runs
        # before KeyboardInterrupt escapes to the outer except (cf. N-131).
        try:
            await _watch()
        finally:
            await engine.aclose()

    try:
        asyncio.run(_watch_and_close())
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def _cmd_watch_push(config, args) -> int:
    """Watch using push notifications (IMAP IDLE / Gmail Pub/Sub / Graph).

    Instead of polling, the provider keeps a long-lived connection and
    yields new message IDs as they arrive.  Each new message is triaged
    immediately.
    """
    from email_triage.providers.base import PushCapable

    provider = _create_provider(config)
    if not isinstance(provider, PushCapable):
        print(f"Error: provider '{config.provider.type}' does not support push notifications.")
        print("Push is supported by: imap, gmail_api, office365")
        return 1

    engine = _build_engine(config)
    log.info("Watch mode (push)", provider=config.provider.type)
    print(f"Watching via push ({config.provider.type})")
    print("Press Ctrl+C to stop.\n")

    async def _watch_push() -> None:
        backoff = 5
        max_backoff = 300
        while True:
            try:
                async for uid in provider.watch():
                    try:
                        results = await engine.run_cycle(f"UID {uid}", 1)
                        if results:
                            for flow in results:
                                cat = flow.classification.category if flow.classification else "?"
                                print(f"  [{cat}] {flow.flow_id[:8]} -> {flow.status.value}")
                        else:
                            # Fallback: fetch + classify single message.
                            message = await provider.fetch_message(uid)
                            print(f"  New: {message.sender} — {message.subject}")
                    except Exception as e:
                        log.error("Push triage error", uid=uid, error=fmt_exc(e))
                        print(f"  Error processing UID {uid}: {e}")
                backoff = 5  # Reset on clean exit from generator.
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log.warning("Push connection lost, reconnecting",
                            error=fmt_exc(e), backoff=backoff)
                print(f"  Connection lost: {e}. Reconnecting in {backoff}s...")
                await asyncio.sleep(backoff)
                backoff = next_backoff_delay(backoff, factor=2.0, max_delay=max_backoff)  # N-228 R22 SSOT

    async def _watch_push_and_close() -> None:
        # N-131 — close in-loop (see _aclose_provider_quietly). The old bare
        # asyncio.run(provider.close()) ran in a 2nd loop AND had no 
        # wrapper, so the cross-loop 'Event loop is closed' RAISED out of the
        # finally on every Ctrl-C exit.
        try:
            await _watch_push()
        finally:
            await _aclose_provider_quietly(provider)  # N-131: the watched provider
            await engine.aclose()  # N-132: the engine's SEPARATE provider + classifier

    try:
        asyncio.run(_watch_push_and_close())
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show flow status summary."""
    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.engine.store import FlowStore

    db_path = Path(config.persistence.db_path)
    if not db_path.exists():
        print("No database found. Run 'email-triage run' first.")
        return 1

    # N-17: stamp encryption context so FlowStore's own connection opens
    # against an encrypted install (CLI runs outside the server boot).
    _cli_stamp_db_encryption(config)
    store = FlowStore(db_path)
    counts = store.count_by_status()

    if not counts:
        print("No flows in database.")
        return 0

    print("Flow Status Summary")
    print("-" * 30)
    total = 0
    for status, count in sorted(counts.items()):
        print(f"  {status:<15} {count:>5}")
        total += count
    print(f"  {'total':<15} {total:>5}")

    # Show recent flows if requested.
    if args.status:
        from email_triage.engine.models import FlowStatus
        try:
            target = FlowStatus(args.status)
        except ValueError:
            print(f"\nUnknown status: {args.status}")
            return 1
        flows = store.find_flows(status=target, limit=10)
        if flows:
            print(f"\nRecent {args.status} flows:")
            for f in flows:
                cat = f.classification.category if f.classification else "-"
                print(f"  {f.flow_id[:8]}  {cat:<20} {f.updated_at.strftime('%Y-%m-%d %H:%M')}")

    store.close()
    return 0


def cmd_config_validate(args: argparse.Namespace) -> int:
    """Validate a configuration file."""
    try:
        config = load_config(args.path)
    except Exception as e:
        print(f"Error loading config: {e}")
        return 1

    issues = validate_config(config)
    if issues:
        print("Configuration issues:")
        for issue in issues:
            print(f"  - {issue}")
        return 1

    print("Configuration is valid.")
    print(f"  Provider: {config.provider.type}")
    print(f"  Classifier: {config.classifier.backend} ({config.classifier.model})")
    print(f"  Categories: {len(config.classifier.categories)}")
    # `config.logging.hipaa` is the config-FILE value used to SEED HIPAA mode at
    # boot. The EFFECTIVE runtime value lives in the DB (runtime_settings.hipaa,
    # toggled via the admin Security page) and OVERRIDES this seed —
    # `triage_logging.is_hipaa_mode()` is the runtime source of truth. An offline
    # config validator cannot read the (possibly-encrypted) runtime DB, so label
    # this clearly rather than print a bare value an auditor could misread as the
    # live posture (divergence census 2026-06-09 #4 — verify-don't-accept REFUTED
    # the "dual-write" framing: the admin toggle writes only the settings table,
    # never the YAML, so the YAML is a boot seed, not a divergent second writer).
    print(f"  HIPAA mode (config-file boot seed): {config.logging.hipaa}")
    print(
        "    NOTE: the EFFECTIVE runtime HIPAA mode is stored in the DB "
        "(runtime_settings.hipaa), is toggled via the admin Security page, and "
        "overrides this seed — check the running install's admin UI for the live "
        "value; this offline validator reports the config-file seed only."
    )
    print(f"  Secrets backend: {config.secrets.backend}")
    return 0


@_cli_audit("secrets")
def cmd_secrets(args: argparse.Namespace) -> int:
    """Manage secrets.

    Most subcommands operate on the runtime DbSecrets store (the
    encrypted SQLite table).  ``init-master-key`` operates on the
    bootstrap backend (container/keyfile/keyring/env) that supplies the
    master key.
    """
    config = load_config(args.config)
    from email_triage.secrets import (
        DbSecrets,
        bootstrap_secrets_from_config,
        create_secrets_provider,
        read_secret,
    )

    # init-master-key works at the bootstrap layer — before DbSecrets exists.
    if args.secrets_cmd == "init-master-key":
        bootstrap = create_secrets_provider(
            config.secrets.backend,
            keyfile_path=config.secrets.keyfile_path,
            external_config=config.secrets.external,
            master_key_name=config.secrets.master_key_name,
        )
        key_name = config.secrets.master_key_name
        existing = read_secret(bootstrap, key_name)
        if existing and not args.force:
            print(
                f"Master key '{key_name}' already exists in the "
                f"{config.secrets.backend} backend. "
                "Use --force to overwrite (all existing encrypted secrets "
                "will become unreadable)."
            )
            return 1
        new_key = DbSecrets.generate_master_key()
        try:
            bootstrap.set(key_name, new_key)
        except NotImplementedError:
            # Read-only backends (container) — print so the user can
            # register it manually.
            print(
                f"Backend '{config.secrets.backend}' is read-only. "
                f"Register this key manually as '{key_name}':"
            )
            print(new_key)
            return 0
        print(f"Master key '{key_name}' generated and saved.")
        return 0

    # All other subcommands need the runtime DbSecrets store.
    conn = _cli_open_config_db(config)
    try:
        provider = bootstrap_secrets_from_config(conn, config)
    except Exception as e:
        print(f"Could not open runtime secrets store: {e}")
        print(
            "If the master key is missing, run: "
            "'email-triage secrets init-master-key'"
        )
        return 1

    # H-02a (Cycle 6, 2026-05-23): provision audit-chain HMAC keys for
    # every secrets CLI subcommand so any chain-writing operation
    # (including rotate-master-key, which writes a history row +
    # subsequent chain rows under the new master) sees a populated
    # registry. enforce_master_key_at_rest_for_hipaa is a no-op outside
    # HIPAA mode; wire_audit_chain_hmac_keys populates the version
    # registry.
    from email_triage.secrets import (
        enforce_master_key_at_rest_for_hipaa,
        wire_audit_chain_hmac_keys,
    )
    enforce_master_key_at_rest_for_hipaa(config)
    wire_audit_chain_hmac_keys(provider, config)

    if args.secrets_cmd == "list":
        keys = provider.list_keys()
        if keys:
            print("Stored secrets:")
            for key in keys:
                print(f"  - {key}")
        else:
            print("No secrets stored.")
        return 0

    elif args.secrets_cmd == "set":
        import getpass
        value = getpass.getpass(f"Enter value for {args.key}: ")
        provider.set(args.key, value)
        print(f"Secret '{args.key}' saved.")
        return 0

    elif args.secrets_cmd == "delete":
        if provider.delete(args.key):
            print(f"Secret '{args.key}' deleted.")
        else:
            print(f"Secret '{args.key}' not found.")
        return 0

    elif args.secrets_cmd == "rotate-master-key":
        # Re-encrypt every row in secrets_store with a new master key.
        # Expectation: the app is NOT running during rotation (running
        # app processes cache the old Fernet instance).
        bootstrap = create_secrets_provider(
            config.secrets.backend,
            keyfile_path=config.secrets.keyfile_path,
            external_config=config.secrets.external,
            master_key_name=config.secrets.master_key_name,
        )
        key_name = config.secrets.master_key_name

        # Save the outgoing key before anything else — disaster recovery.
        from email_triage.secrets import read_secret_required
        old_key = read_secret_required(bootstrap, key_name)
        new_key = DbSecrets.generate_master_key()

        if args.save_old_key_to:
            # census  — atomic + owner-only write of the PLAINTEXT old
            # master key (was a bare write_text + chmod → a power-loss could
            # truncate the disaster-recovery key, and the pre-chmod window
            # left it world-readable).
            from email_triage._atomicio import atomic_write_text
            atomic_write_text(args.save_old_key_to, old_key, mode=0o600)
            print(f"Old master key saved to {args.save_old_key_to} (mode 600)")

        if args.dry_run:
            n = len(provider.list_keys())
            print(f"DRY RUN: would re-encrypt {n} secret(s).")
            print("Old key kept. Run again with --commit to apply.")
            return 0

        if not args.commit:
            print(
                "Add --commit to actually rotate. Add --dry-run to preview. "
                "Make sure the app is stopped first."
            )
            return 1

        # H-02a (Cycle 6, 2026-05-23): record the version we are rotating
        # FROM before the rotate ceremony swaps state. After rotate
        # completes, this is the version number stamped on the new
        # master_key_history:v{N} row that preserves the outgoing
        # master.
        rotating_from_version = provider.current_master_version()

        try:
            n = provider.rotate_master_key(new_key)
        except Exception as e:
            print(f"Rotation failed; DB rolled back, old key still valid. Error: {e}")
            return 1

        print(f"Re-encrypted {n} secret(s) with new master key.")
        new_version = provider.current_master_version()
        print(
            f"\nH-02a audit-chain note: master_key_version bumped "
            f"{rotating_from_version} -> {new_version}. Outgoing master "
            f"preserved under secrets_store:master_key_history:v"
            f"{rotating_from_version} (key-encrypting-key per NIST SP "
            f"800-57 §6.2.2). New log_entries rows post-restart will "
            f"stamp master_key_version={new_version} and HMAC under the "
            f"new derived chain key.\n"
            f"\nDO NOT delete master_key_history:v{rotating_from_version} "
            f"(or any other master_key_history:v* row) from secrets_store "
            f"without an operator-approved manual prune of corresponding "
            f"log_entries rows. Legacy HMAC chain rows under that version "
            f"will fail verify_log_chain with an operator-detectable "
            f"break naming the missing version (§164.316(b)(2)(i) 6-year "
            f"retention)."
        )

        try:
            bootstrap.set(key_name, new_key)
            print(f"New master key written to {config.secrets.backend} backend.")
        except NotImplementedError:
            # Read-only bootstrap (container) — print new key; the operator
            # must register it themselves and restart.
            print(
                "\nThe bootstrap backend is read-only. DB rows are already "
                f"re-encrypted. Register this as the new '{key_name}' and "
                "restart the app:\n"
            )
            print(new_key)
        return 0

    elif args.secrets_cmd == "migrate-from-bootstrap":
        # One-shot migration: copy every key from the bootstrap store
        # (minus the master key itself) into DbSecrets.
        bootstrap = create_secrets_provider(
            config.secrets.backend,
            keyfile_path=config.secrets.keyfile_path,
            external_config=config.secrets.external,
            master_key_name=config.secrets.master_key_name,
        )
        master_key_name = config.secrets.master_key_name
        migrated = 0
        skipped = 0
        for key in bootstrap.list_keys():
            if key == master_key_name:
                continue
            val = read_secret(bootstrap, key)
            if val is None:
                skipped += 1
                continue
            provider.set(key, val)
            migrated += 1
            print(f"  migrated: {key}")
        print(f"Migrated {migrated} secret(s); skipped {skipped}.")
        return 0

    elif args.secrets_cmd == "purge-msal-cache":
        # N-267 R27: CLI-user MSAL cache purge. Routes through the
        # per-user artifact registry (`dispose_all_per_user_artifacts`)
        # — closes the V_B orphan gap census R27 flagged
        # (§164.310(d)(2)(i) plaintext OAuth refresh_token had no
        # production disposer). The registry funnel disposes every
        # registered per-user artifact family; today that's just
        # `msal_cache_cli_<user>.json` but the pattern extends
        # transparently if a new per-user artifact ships.
        from email_triage.providers._ondisk_artifacts import (
            dispose_all_per_user_artifacts,
        )
        username = args.username
        deleted = dispose_all_per_user_artifacts(username)
        print(f"Purged {deleted} MSAL cache artifact(s) for user '{username}'.")
        return 0

    elif args.secrets_cmd == "allow-hmac-clobber-once":
        # N-349 hybrid (2026-07-05, operator directive): arm the one-shot
        # HMAC clobber bypass in the settings table. The NEXT unreadable-
        # read triggered by a watch-HMAC hydration path in agent_api /
        # profile will consume the flag + log the bypass + mint a fresh
        # replacement. Env-flag DELIBERATELY NOT supported — the CLI's
        # `@_cli_audit("secrets")` wrapper emits the phase='start' +
        # phase='end' audit rows that are the compensating control.
        #
        # N-364 R31 (2026-07-05 SME F6 follow-up + the backlog N-349b
        # items 4+5): TTL + actor_id metadata are now stamped on the
        # arm — default 15-minute expiry closes the "operator arms +
        # forgets" observability gap; the arm row carries `armed_at`
        # + optional `armed_by_actor_id` for §164.308(a)(4)(ii)(C)
        # traceability that ties CONSUMPTION back to ESTABLISHMENT.
        from email_triage.web.db import (
            HMAC_CLOBBER_BYPASS_DEFAULT_TTL_SEC,
            arm_hmac_clobber_bypass,
            hmac_clobber_bypass_status,
        )
        config = load_config(args.config)
        conn = _cli_open_config_db(config)
        ttl_sec = getattr(args, "ttl_min", None)
        if ttl_sec is not None:
            ttl_sec = int(ttl_sec) * 60
        status = hmac_clobber_bypass_status(conn)
        if status["armed"]:
            print(
                "HMAC clobber bypass is ALREADY armed. Next admin watch-"
                f"save on an unreadable row will consume it. Expires at "
                f"{status['expires_at']!r}."
            )
            return 0
        arm_hmac_clobber_bypass(conn, ttl_sec=ttl_sec)
        effective_ttl_min = (
            ttl_sec // 60 if ttl_sec else HMAC_CLOBBER_BYPASS_DEFAULT_TTL_SEC // 60
        )
        new_status = hmac_clobber_bypass_status(conn)
        print(
            "HMAC clobber bypass ARMED (one-shot). SCOPE: the NEXT "
            "unreadable-row read triggered by an ADMIN watch SAVE "
            "(create-new or edit-existing via profile UI / agent API) "
            "will mint a fresh replacement + clear the flag. The "
            "receiver-side webhook signature-verify path is NOT "
            "covered by this bypass — it stays fail-CLOSED and drops "
            "the webhook; recovery for that path is an admin re-save "
            "(which triggers this bypass). No env-flag equivalent by "
            "operator directive."
        )
        print(
            f"TTL: {effective_ttl_min} minute(s). Expires at "
            f"{new_status['expires_at']!r}. Use `secrets show-hmac-"
            "clobber-bypass` to check status; re-arm to extend."
        )
        return 0

    elif args.secrets_cmd == "show-hmac-clobber-bypass":
        # N-364 R31 (2026-07-05 SME F6 + the backlog N-349b item 4) —
        # read-only observability verb. Reports the current arm state
        # so an operator who forgot whether they armed can check + so
        # a scheduled audit sweep can grep the output.
        from email_triage.web.db import hmac_clobber_bypass_status
        config = load_config(args.config)
        conn = _cli_open_config_db(config)
        status = hmac_clobber_bypass_status(conn)
        if status["armed"]:
            print(
                "HMAC clobber bypass: ARMED (one-shot). "
                f"armed_at={status['armed_at']!r} "
                f"expires_at={status['expires_at']!r} "
            )
        elif status["expired"]:
            print(
                "HMAC clobber bypass: EXPIRED (still in settings row but "
                f"past TTL). armed_at={status['armed_at']!r} "
                f"expires_at={status['expires_at']!r} "
                "(consume-a-secret path removes the row on next unreadable read)."
            )
        else:
            print("HMAC clobber bypass: NOT armed.")
        return 0

    elif args.secrets_cmd == "purge-retired-keys":
        # N-320 R30 (task  tranche  DA follow-up — CLI-verb
        # delivery per operator ruling 2026-07-03).
        # §164.308(a)(4)(ii)(A) rollback re-arms compromised creds.
        # Iterate every retired name in `_secret_keys.KEY_HISTORY`
        # and DELETE from the secrets store — idempotent
        # (delete-missing = no-op). @_cli_audit("secrets") wrapper
        # emits the audit event (phase='start' + phase='end').
        # `provider` is the SecretsProvider already wired above at
        # :850 via `wire_audit_chain_hmac_keys(provider, config)`.
        from email_triage._secret_keys import retired_names

        retired = retired_names()
        if not retired:
            print("KEY_HISTORY is empty; nothing to purge.")
            return 0
        deleted_count = 0
        preserved_count = 0
        for name in retired:
            if provider.delete(name):
                deleted_count += 1
                print(f"  deleted retired secret: {name}")
            else:
                preserved_count += 1
        print(
            f"Purged {deleted_count} retired secret-key row(s); "
            f"{preserved_count} already absent."
        )
        return 0

    return 1


@_cli_audit("apikey")
def cmd_apikey(args: argparse.Namespace) -> int:
    """Manage API keys."""
    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.web.auth import (
        generate_api_key,
        hash_api_key,
        store_api_key,
        list_api_keys,
        delete_api_key,
        get_user_by_email,
    )

    db_path = Path(config.persistence.db_path)
    if not db_path.exists():
        print("No database found. Run 'email-triage serve' first to create the schema.")
        return 1

    db = _cli_open_config_db(config)

    if args.apikey_cmd == "create":
        user = get_user_by_email(db, args.user)
        if user is None:
            print(f"User not found: {args.user}")
            db.close()
            return 1

        raw_key = generate_api_key()
        key_hash = hash_api_key(raw_key)
        # CLI actor: there's no authenticated session, so identify by
        # the OS-level user (or USERNAME on Windows) for the audit
        # trail. ``actor_user_id`` is left None — CLI runs are usually
        # by an operator who isn't a registered triage user.
        import os as _os
        cli_actor = (
            _os.environ.get("USER")
            or _os.environ.get("USERNAME")
            or "cli"
        )
        key_id = store_api_key(
            db, key_hash, args.name, user["id"],
            actor_user_id=None,
            actor_email=f"cli:{cli_actor}",
            source="cli",
        )
        db.close()

        print(f"API key created:")
        print(f"  ID:   {key_id}")
        print(f"  Name: {args.name}")
        print(f"  User: {args.user}")
        print(f"  Key:  {raw_key}")
        print(f"\nStore this key securely — it cannot be retrieved again.")
        return 0

    elif args.apikey_cmd == "list":
        keys = list_api_keys(db)
        db.close()
        if keys:
            print("API keys:")
            for k in keys:
                used = k.get("last_used_at") or "never"
                expires = k.get("expires_at") or "never"
                print(f"  [{k['id']}] {k['name']} — user: {k['email']}, "
                      f"last used: {used}, expires: {expires}")
        else:
            print("No API keys found.")
        return 0

    elif args.apikey_cmd == "delete":
        import os as _os
        cli_actor = (
            _os.environ.get("USER")
            or _os.environ.get("USERNAME")
            or "cli"
        )
        if delete_api_key(
            db, args.key_id,
            actor_user_id=None,
            actor_email=f"cli:{cli_actor}",
            source="cli",
        ):
            print(f"API key {args.key_id} deleted.")
        else:
            print(f"API key {args.key_id} not found.")
            db.close()
            return 1
        db.close()
        return 0

    return 1


@_cli_audit("user")
def cmd_user(args: argparse.Namespace) -> int:
    """Manage users."""
    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.web.auth import get_user_by_email

    db_path = Path(config.persistence.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = _cli_open_config_db(config)

    if args.user_cmd == "create":
        #  R32 DA-fold R1 — canonicalise the email at ingest so the
        # stored form matches the read-side lookup ([[canonical_email]]
        # SSOT). Idempotent for ASCII; A-label form for IDN.
        from email_triage.mail_headers import canonical_email
        args.email = canonical_email(args.email)
        existing = get_user_by_email(db, args.email)
        if existing:
            print(f"User already exists: {args.email} (role: {existing['role']})")
            db.close()
            return 1

        now = now_utc_iso()
        role = args.role or "user"
        name = args.name or args.email.split("@")[0]

        db.execute(
            "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
            (args.email, name, role, now),
        )
        db.commit()
        print(f"User created:")
        print(f"  Email: {args.email}")
        print(f"  Name:  {name}")
        print(f"  Role:  {role}")
        db.close()
        return 0

    elif args.user_cmd == "list":
        rows = db.execute(
            "SELECT id, email, name, role, last_login FROM users ORDER BY id"
        ).fetchall()
        db.close()
        if rows:
            print("Users:")
            for r in rows:
                last = r["last_login"] or "never"
                print(f"  [{r['id']}] {r['email']} — {r['name']} ({r['role']}) last login: {last}")
        else:
            print("No users found.")
        return 0

    elif args.user_cmd == "enroll-mfa":
        # H-05 (Cycle 7) — operator-driven recovery-code issuance.
        # Operator runs this for the first admin (Q7 design: operator
        # drives first-admin enrollment; subsequent users use the
        # first-login automatic flow). The operator hands the printed
        # codes to the user via a secure channel; user keeps the
        # codes physically until a passkey is registered. Per Q5:
        # printable single-use codes are the canonical recovery shape.
        user_ = get_user_by_email(db, args.email)
        if user_ is None:
            print(f"User not found: {args.email}", file=sys.stderr)
            db.close()
            return 1
        from email_triage.web.mfa import (
            issue_recovery_codes,
            RECOVERY_CODE_COUNT_DEFAULT,
        )
        count = int(getattr(args, "count", 0) or RECOVERY_CODE_COUNT_DEFAULT)
        codes = issue_recovery_codes(db, user_id=user_["id"], count=count)
        db.close()
        print(f"Issued {len(codes)} recovery code(s) for {args.email}:")
        print()
        for c in codes:
            print(f"  {c}")
        print()
        print("IMPORTANT: this is the only opportunity to capture these")
        print("plaintext codes. They are SHA-256 hashed at rest and cannot")
        print("be recovered. Print this output or store the codes in a")
        print("secure physical location. The user MUST register a passkey")
        print("at /profile/hardware-keys to fully complete MFA enrollment;")
        print("recovery codes are the fallback path only.")
        return 0

    elif args.user_cmd == "reset-mfa":
        # H-05 (Cycle 7) — operator-key recovery (last-resort).
        # Operator runs this when a user has lost their passkey AND
        # their recovery codes. Per Q5 design: operator-key recovery
        # is the second leg of the recovery design; the token is
        # short-lived (24h TTL default per Q3) + single-use; operator
        # hand-delivers to the target user out-of-band. The user
        # consumes the token at POST /auth/mfa/recovery and is
        # redirected to /profile/hardware-keys to register a fresh
        # passkey.
        user_ = get_user_by_email(db, args.email)
        if user_ is None:
            print(f"User not found: {args.email}", file=sys.stderr)
            db.close()
            return 1
        from email_triage.web.mfa import (
            issue_operator_recovery_token,
            OPERATOR_RECOVERY_TOKEN_TTL_SECS_DEFAULT,
        )
        ttl = int(
            getattr(args, "ttl_secs", 0)
            or OPERATOR_RECOVERY_TOKEN_TTL_SECS_DEFAULT
        )
        token = issue_operator_recovery_token(
            db,
            target_user_id=user_["id"],
            operator_user_id=None,  # CLI actor is captured via H-03-auto
            ttl_secs=ttl,
        )
        db.close()
        print(f"Operator-recovery token issued for {args.email}:")
        print()
        print(f"  {token}")
        print()
        print(f"TTL: {ttl} seconds (~{ttl // 3600}h). Single-use.")
        print("Hand-deliver this token to the target user out-of-band")
        print("(phone call, in-person handoff). They consume it at")
        print("POST /auth/mfa/recovery and will be redirected to")
        print("/profile/hardware-keys to register a fresh passkey.")
        print("This is the only opportunity to capture the plaintext")
        print("token (SHA-256 hashed at rest).")
        return 0

    elif args.user_cmd == "re-normalize-emails":
        # N-322 R30 (task  N-317 half-2). Persisted-key re-normalize
        # sweep. Scans every stored email column, compares against
        # `canonical_email(raw)`, reports + optionally UPDATEs.
        # Idempotent — a row already in canonical form is a no-op.
        # Live-DB migration when --apply is set; @_cli_audit("user")
        # gives us the phase='start'/'end' audit-emit for free.
        import json as _json
        from email_triage.db._helpers import row_get  # N-329 R30 (N-234 SSOT — fix-forward)
        from email_triage.mail_headers import canonical_email
        # N-336: was `_init_db(config.persistence.database_path)` — attribute
        # `database_path` does not exist on PersistenceConfig (real name is
        # `db_path`), so this raised AttributeError on first invocation
        # (LIVE showstopper — DB-SME Phase 2). Route through the SSOT
        # `_cli_open_config_db` (PD#11) — the encryption-aware opener that
        # every other CLI handler uses.
        db = _cli_open_config_db(config)
        try:
            # ---- users.email + users.notify_email ----
            users_rows = db.execute(
                "SELECT id, email, notify_email FROM users"
            ).fetchall()
            users_divergent: list[tuple[int, str, str, str, str]] = []
            for r in users_rows:
                uid = row_get(r, "id", 0)
                email = row_get(r, "email", 1)
                notify = row_get(r, "notify_email", 2)
                new_email = canonical_email(email) if email else email
                new_notify = canonical_email(notify) if notify else notify
                if (email or "") != (new_email or "") or \
                   (notify or "") != (new_notify or ""):
                    users_divergent.append(
                        (uid, email or "", new_email or "",
                         notify or "", new_notify or "")
                    )

            # ---- email_accounts.aliases_json ----
            acct_rows = db.execute(
                "SELECT id, aliases_json FROM email_accounts"
            ).fetchall()
            acct_divergent: list[tuple[int, list, list]] = []
            for r in acct_rows:
                aid = row_get(r, "id", 0)
                aj = row_get(r, "aliases_json", 1)
                if not aj:
                    continue
                # N-324 R30 (CI-red fix-forward on N-322 — census 
                # bare-json.loads pin). Route through the load_json_col
                # SSOT — corrupt column degrades to [] (fail-CLOSED
                # sweep skips this row), consistent with the pin's
                # "corrupt column → 500" surface.
                from email_triage.db._helpers import load_json_col
                aliases = load_json_col(aj, default=[])
                if not isinstance(aliases, list) or not aliases:
                    continue
                new_aliases = [
                    canonical_email(a) if isinstance(a, str) else a
                    for a in aliases
                ]
                if aliases != new_aliases:
                    acct_divergent.append((aid, aliases, new_aliases))

            # ---- Report ----
            print(f"Users needing re-normalize: {len(users_divergent)}")
            for uid, e_old, e_new, n_old, n_new in users_divergent[:20]:
                if e_old != e_new:
                    print(f"  user#{uid} email: {e_old!r} -> {e_new!r}")
                if n_old != n_new:
                    print(f"  user#{uid} notify: {n_old!r} -> {n_new!r}")
            if len(users_divergent) > 20:
                print(f"  ... and {len(users_divergent) - 20} more")
            print(
                f"Accounts with aliases needing re-normalize: "
                f"{len(acct_divergent)}"
            )
            for aid, old, new in acct_divergent[:20]:
                print(f"  account#{aid} aliases: {old!r} -> {new!r}")
            if len(acct_divergent) > 20:
                print(f"  ... and {len(acct_divergent) - 20} more")

            if not args.apply:
                print("[dry-run] No writes. Re-run with --apply to rewrite.")
                return 0

            # ---- Apply ----
            # N-329 R30 (§164.312(a)(2)(iii) session_epoch pin fix-
            # forward): touching `users.email` requires bumping
            # `session_epoch` in the same statement so any live cookie
            # authority tied to the OLD identity is invalidated at the
            # next request.
            #  R32 DA-fold R1 — canonicalise the target email so the
            # updated row matches the read-side lookup (canonical_email SSOT).
            from email_triage.mail_headers import canonical_email
            for uid, _, e_new, _, n_new in users_divergent:
                db.execute(
                    "UPDATE users SET email = ?, notify_email = ?, "
                    "session_epoch = session_epoch + 1 WHERE id = ?",
                    (canonical_email(e_new) if e_new else None, n_new or None, uid),
                )
            # N-324 R30 (CI-red fix-forward on N-322 — census 
            # write-side bare-json.dumps pin). Route through the
            # dump_json_col SSOT so ensure_ascii / serialization
            # semantics stay uniform with every other *_json write.
            from email_triage.db._helpers import dump_json_col
            for aid, _, new in acct_divergent:
                db.execute(
                    "UPDATE email_accounts SET aliases_json = ? "
                    "WHERE id = ?",
                    (dump_json_col(new), aid),
                )
            db.commit()
            print(
                f"Applied re-normalize on {len(users_divergent)} users + "
                f"{len(acct_divergent)} account aliases_json rows."
            )
            return 0
        finally:
            db.close()

    return 1


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the web UI server.

    TLS: if ``<data_dir>/certs/server.crt`` + ``server.key`` exist (or
    the operator passes ``--ssl-keyfile`` + ``--ssl-certfile`` flags
    that override), uvicorn serves HTTPS. Otherwise plain HTTP for
    dev/test convenience. The container quadlet bootstraps a self-
    signed cert on first start, so the deployed app is HTTPS by
    default — see ``email-triage tls bootstrap``.
    """
    config = load_config(args.config)
    setup_logging(config.logging)

    import uvicorn
    from email_triage.web.app import create_app
    from email_triage.tls import (
        generate_self_signed_cert, load_existing_cert_paths,
        write_cert_files,
    )

    # Resolve cert paths in this priority order:
    #   1. Explicit --ssl-certfile / --ssl-keyfile CLI flags.
    #   2. config.tls.cert_dir (operator-managed, e.g. external
    #      DNS-01 ACME pipeline drops files here).
    #   3. <data_dir>/certs/ (where `tls bootstrap` writes by default).
    # config.tls.enabled = false forces plain HTTP regardless.
    ssl_certfile = getattr(args, "ssl_certfile", None) or ""
    ssl_keyfile = getattr(args, "ssl_keyfile", None) or ""
    if not (ssl_certfile and ssl_keyfile) and config.tls.enabled:
        cert_dir_str = (config.tls.cert_dir or "").strip()
        cert_dir = (
            Path(cert_dir_str) if cert_dir_str
            else Path(config.persistence.db_path).parent / "certs"
        )
        crt, key = load_existing_cert_paths(cert_dir)
        # Auto-bootstrap a self-signed cert on first start if the
        # operator hasn't supplied one. Idempotent — only fires when
        # the cert dir is empty. Subsequent restarts pick up whatever
        # is already there (operator's external ACME-managed cert,
        # tailscale cert, or the original self-signed one).
        if not (crt and key):
            try:
                cert_pem, key_pem = generate_self_signed_cert(
                    hostname=args.host if args.host not in (
                        "0.0.0.0", "::", "")
                    else "localhost",
                )
                crt, key = write_cert_files(cert_dir, cert_pem, key_pem)
                log.info(
                    "Auto-generated self-signed TLS cert",
                    cert_dir=str(cert_dir),
                )
            except Exception as e:
                log.warning(
                    "TLS auto-bootstrap failed; falling back to HTTP",
                    error=fmt_exc(e),
                )
                crt, key = None, None
        if crt and key:
            ssl_certfile = str(crt)
            ssl_keyfile = str(key)

    app = create_app(config)
    # H-04-flag (Cycle 7, 2026-05-24) — plumb the actual bind host so
    # the lifespan-side `enforce_transmission_security_for_hipaa` can
    # classify it against the public-routable axis. Setting on
    # ``app.state`` here (after ``create_app`` but BEFORE uvicorn
    # starts the lifespan) ensures the lifespan reads the CLI-supplied
    # host, not the in-config default (host isn't config-stored
    # today; it's a CLI arg).
    app.state.bind_host = args.host
    # N-344 R31 (2026-07-04, Phase-4 DA finding): when the operator has
    # declared a reverse-proxy front by populating
    # ``config.audit.trusted_proxies`` (the same trust boundary
    # ``request_forwarded_for`` uses for §164.312(b) audit-identity),
    # ALSO tell uvicorn to honour ``X-Forwarded-Proto``/``X-Forwarded-
    # For`` from those peers so ``request.url.scheme`` resolves to
    # 'https' and the ``is_request_https`` cookie-Secure SSOT
    # (``web/_cookies.py``) fires branch (a) correctly. Without this,
    # uvicorn's default ``forwarded_allow_ips='127.0.0.1'`` rejects
    # XFP from an nginx sidecar/host and the Secure-cookie flag drops
    # silently under HTTPS-via-reverse-proxy — N-200's promised branch
    # (a) was inoperative pre-N-344.
    _trusted_proxies = list(getattr(config.audit, "trusted_proxies", []) or [])
    _uvicorn_proxy_kwargs: dict[str, Any] = {}
    if _trusted_proxies:
        _uvicorn_proxy_kwargs = {
            "proxy_headers": True,
            "forwarded_allow_ips": ",".join(_trusted_proxies),
        }
    if ssl_certfile and ssl_keyfile:
        log.info(
            "Starting web UI (HTTPS)", host=args.host, port=args.port,
            ssl_certfile=ssl_certfile,
        )
        # Use Config + Server explicitly (instead of uvicorn.run) so
        # we can grab a reference to the live SSLContext after
        # config.load() populates it. The watcher thread below uses
        # that reference to hot-reload the cert on mtime change --
        # closes the long-standing "always on, minimally interacted
        # with" gap (the backlog ). Without this, a renewed cert
        # sits on disk doing nothing until the next service restart.
        uv_config = uvicorn.Config(
            app, host=args.host, port=args.port,
            ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile,
            **_uvicorn_proxy_kwargs,
        )
        uv_config.load()  # populates uv_config.ssl

        if uv_config.ssl is not None:
            import threading

            def _watch_cert() -> None:
                """Poll cert mtime; reload SSLContext on change.

                SSLContext.load_cert_chain on the same context object
                replaces the certificate for future TLS handshakes.
                Existing connections finish on the old cert, which is
                acceptable for cert-renewal semantics.
                """
                import os
                import ssl as _ssl
                import time as _time
                last_mtime: float | None = None
                while True:
                    try:
                        m = os.path.getmtime(ssl_certfile)
                        if last_mtime is not None and m != last_mtime:
                            try:
                                uv_config.ssl.load_cert_chain(
                                    certfile=ssl_certfile,
                                    keyfile=ssl_keyfile,
                                )
                                # Print to stderr -- structured logger
                                # is set up but uses module-level
                                # state that this thread shouldn't
                                # mutate concurrently with request
                                # handlers; print is line-atomic.
                                print(
                                    "[tls] cert hot-reloaded "
                                    f"path={ssl_certfile} mtime={m}",
                                    flush=True,
                                )
                            except _ssl.SSLError as exc:
                                # Bad cert file (likely mid-atomic-
                                # write or operator dropped a wrong
                                # file); keep the old context. Next
                                # tick retries.
                                print(
                                    f"[tls] cert reload failed; "
                                    f"keeping old context: "
                                    f"{fmt_exc(exc, with_class=True)}",
                                    flush=True,
                                )
                                # Don't update last_mtime so we retry
                                # if the bad file gets replaced before
                                # the next tick.
                                _time.sleep(30)
                                continue
                        last_mtime = m
                    except FileNotFoundError:
                        # Cert temporarily missing (atomic swap in
                        # flight). Wait + retry.
                        pass
                    except Exception:
                        # Any other transient error -- swallow and
                        # retry next tick. Keep the old SSLContext.
                        pass
                    _time.sleep(30)

            threading.Thread(
                target=_watch_cert,
                daemon=True,
                name="tls-cert-watcher",
            ).start()

        uvicorn.Server(uv_config).run()
    else:
        log.warning(
            "Starting web UI (PLAIN HTTP — no cert configured). "
            "Run `email-triage tls bootstrap` to enable HTTPS.",
            host=args.host, port=args.port,
        )
        uvicorn.run(app, host=args.host, port=args.port, **_uvicorn_proxy_kwargs)
    return 0


def _cmd_tls_dispatch(args: argparse.Namespace) -> int:
    """Route ``tls <subcommand>`` to the right handler."""
    sub = getattr(args, "tls_cmd", None)
    if sub == "bootstrap":
        return cmd_tls_bootstrap(args)
    if sub == "fetch-tailscale":
        return cmd_tls_fetch_tailscale(args)
    print("Usage: email-triage tls {bootstrap|fetch-tailscale} ...")
    return 1


@_cli_audit("tls.bootstrap")
def cmd_tls_bootstrap(args: argparse.Namespace) -> int:
    """Generate a self-signed TLS cert + key for the local listener.

    Writes to ``<data_dir>/certs/`` by default. Idempotent-ish: if a
    cert already exists and ``--force`` is not set, refuses to
    overwrite (rotation: pass --force, restart the service).
    """
    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.tls import (
        generate_self_signed_cert, load_existing_cert_paths,
        write_cert_files,
    )

    cert_dir = Path(args.cert_dir) if args.cert_dir else (
        Path(config.persistence.db_path).parent / "certs"
    )
    crt, key = load_existing_cert_paths(cert_dir)
    if (crt or key) and not args.force:
        print(f"Cert already present at {cert_dir}. Pass --force to overwrite.")
        return 1

    extra_sans = [s.strip() for s in (args.san or "").split(",") if s.strip()]
    cert_pem, key_pem = generate_self_signed_cert(
        hostname=args.hostname,
        valid_days=int(args.days),
        extra_sans=extra_sans,
    )
    crt_path, key_path = write_cert_files(cert_dir, cert_pem, key_pem)
    print(f"Cert: {crt_path}")
    print(f"Key:  {key_path}")
    print(f"Valid for {args.days} days. Restart the service to pick up the new cert.")
    return 0


@_cli_audit("tls.fetch-tailscale")
def cmd_tls_fetch_tailscale(args: argparse.Namespace) -> int:
    """Fetch a real Let's Encrypt cert via the Tailscale daemon.

    Wraps ``tailscale cert <hostname>``. Tailscale's HTTPS feature
    issues LE certs for ``<host>.<tailnet>.ts.net`` names (free for
    personal use; enable in the Tailnet admin console). The daemon
    runs ACME + DNS-01 + renewal; we just call the CLI and stash
    the result.

    Cron pattern (operator-side): monthly invocation of this
    subcommand, then ``systemctl restart email-triage.service``.
    LE certs are 90-day; monthly refresh is comfortably within the
    Tailscale auto-renew window.
    """
    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.tls import fetch_tailscale_cert

    cert_dir = Path(args.cert_dir) if args.cert_dir else (
        Path(config.persistence.db_path).parent / "certs"
    )
    try:
        crt_path, key_path = fetch_tailscale_cert(
            hostname=args.hostname,
            cert_dir=cert_dir,
            tailscale_bin=args.tailscale_bin or "tailscale",
        )
    except RuntimeError as e:
        print(f"Error: {e}")
        return 1
    print(f"Cert: {crt_path}")
    print(f"Key:  {key_path}")
    print("Restart the service to pick up the new cert.")
    return 0


@_cli_audit("restore")
def cmd_restore(args: argparse.Namespace) -> int:
    """Decrypt + extract a backup bundle. Inverse of /admin/backup
    export. Operator drives the swap-in manually -- this CLI never
    starts/stops the service.

    Bundle types are auto-detected from the magic prefix:
      * ``*.etbk``    full bundle  (DB + YAML + certs + maybe key)
      * ``*.etbkkey`` key-only bundle (just the master key)

    See ``email-triage restore --help`` for flags.
    """
    import getpass
    from email_triage import backup as backup_mod

    bundle_path = Path(args.bundle).expanduser().resolve()
    if not bundle_path.is_file():
        print(f"Bundle not found: {bundle_path}")
        return 1

    bundle_bytes = bundle_path.read_bytes()

    #  public-key (ETBKP02) bundles: unwrap with the OFF-BOX private key
    # first — recovering the inner .etbk + its random passphrase — then fall
    # through to the normal symmetric restore path.
    recovered_passphrase = None
    if backup_mod.is_pubkey_sealed(bundle_bytes):
        pk_path = (getattr(args, "private_key", "") or "").strip()
        if not pk_path:
            print(
                "This is a public-key-sealed backup; pass "
                "--private-key <path> (the off-box X25519 private key)."
            )
            return 1
        pkp = Path(pk_path).expanduser()
        if not pkp.is_file():
            print(f"Private key file not found: {pkp}")
            return 1
        try:
            bundle_bytes, recovered_passphrase = (
                backup_mod.unwrap_pubkey_sealed_etbk(bundle_bytes, pkp.read_bytes())
            )
        except backup_mod.BackupError as e:
            print(f"Public-key unwrap failed: {e}")
            return 1
        print("Public-key bundle unwrapped with the private key.")

    try:
        sniffed_type = backup_mod._sniff_bundle_type(bundle_bytes)
    except backup_mod.BundleFormatError as e:
        print(f"Not a valid email-triage bundle: {e}")
        return 1

    # Passphrase: recovered (public-key) > file > getpass prompt. Never via flag.
    if recovered_passphrase is not None:
        passphrase = recovered_passphrase
    elif args.passphrase_file:
        pf = Path(args.passphrase_file).expanduser()
        if not pf.is_file():
            print(f"Passphrase file not found: {pf}")
            return 1
        passphrase = pf.read_text(encoding="utf-8").strip()
    else:
        passphrase = getpass.getpass("Passphrase: ")

    try:
        result = backup_mod.unbundle(bundle_bytes, passphrase=passphrase)
    except backup_mod.BundleAuthError as e:
        print(f"Decryption failed: {e}")
        return 1
    except backup_mod.ManifestHashError as e:
        print(f"Bundle integrity check failed: {e}")
        return 1
    except backup_mod.BundleFormatError as e:
        print(f"Bundle format error: {e}")
        return 1

    # Manifest summary is always printed -- regardless of --list.
    m = result.manifest
    print("─" * 60)
    print(f"Bundle:        {bundle_path.name}")
    print(f"Type:          {m.get('bundle_type')}")
    print(f"Hostname:      {m.get('hostname') or '(unset)'}")
    print(f"Exported at:   {m.get('exported_at')}")
    print(f"Operator:      {m.get('operator_email') or '(unset)'}")
    if m.get("commit_sha"):
        print(f"Commit:        {m['commit_sha']}")
    if m.get("schema_version"):
        print(f"Schema vers:   {m['schema_version']}")
    if m.get("include"):
        flags = ", ".join(
            f"{k}={v}" for k, v in m["include"].items()
        )
        print(f"Include flags: {flags}")
    print("Files:")
    for entry in m.get("files", []):
        print(
            f"  {entry['path']:30s}  "
            f"{entry['size']:>10d}  "
            f"sha256={entry['sha256'][:16]}…"
        )
    print("─" * 60)

    if args.list:
        return 0

    # Confirmation: warn but never refuse, per project rule that the
    # admin is the sysadmin. --force skips both confirmations.
    if not args.force:
        try:
            ans = input(
                f"Restore from {m.get('hostname') or '(unknown host)'} "
                f"snapshot dated {m.get('exported_at')}? [y/N]: "
            ).strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 0

    # Resolve target directory + master-key-out from args + config.
    if sniffed_type == "key-only" and not args.master_key_out:
        print(
            "Key-only bundle requires --master-key-out <path>; refusing "
            "to extract the raw key to a default path.",
        )
        return 2

    if args.target_dir:
        target_dir = Path(args.target_dir).expanduser()
    else:
        config = load_config(args.config)
        data_dir = Path(config.persistence.db_path).parent
        target_dir = data_dir / ".restore"

    master_key_out = (
        Path(args.master_key_out).expanduser()
        if args.master_key_out else None
    )

    try:
        written = backup_mod.write_unbundled_to_dir(
            result, target_dir, master_key_out=master_key_out,
        )
    except backup_mod.BackupError as e:
        print(f"Extraction failed: {e}")
        return 1

    print()
    print("Extracted:")
    for name, path in written.items():
        print(f"  {name:30s}  {path}")

    # Print swap-in instructions appropriate to the bundle type.
    print()
    print("To complete the restore:")
    if sniffed_type == "full":
        print("  1. sudo systemctl stop email-triage")
        print(f"  2. mv triage.db triage.db.preexisting && \\")
        print(f"     mv {target_dir / 'triage.db'} triage.db")
        print(f"  3. mv email-triage.yaml email-triage.yaml.preexisting && \\")
        print(f"     mv {target_dir / 'email-triage.yaml'} email-triage.yaml")
        if "data/master_key.bin" in result.files:
            print("  4. Load the bundled master key into the bootstrap backend:")
            print(f"        podman secret create ET_MASTER_KEY < "
                  f"{target_dir / 'data' / 'master_key.bin'}")
        print("  5. sudo systemctl start email-triage")
    else:  # key-only
        print(
            "  1. Load the master key into the bootstrap backend on the "
            "target host:",
        )
        print(
            f"        podman secret create ET_MASTER_KEY < "
            f"{master_key_out}",
        )
        print("  2. sudo systemctl restart email-triage")
        print(f"  3. shred -u {master_key_out}    # don't leave the raw key on disk")

    return 0


def _cmd_db_dispatch(args: argparse.Namespace) -> int:
    """Route ``db <subcommand>`` — the  one-time encrypt/decrypt migration."""
    sub = getattr(args, "db_cmd", None)
    if sub == "encrypt":
        return cmd_db_encrypt(args)
    if sub == "decrypt":
        return cmd_db_decrypt(args)
    print(
        "Usage: email-triage db {encrypt,decrypt} [--db PATH] [--yes]",
        file=sys.stderr,
    )
    return 1


def _db_resolve_master_key(args: argparse.Namespace) -> tuple[str | None, str]:
    """Return ``(master_key, db_path)`` resolved the SAME way the app boot does.

    The SQLCipher key is derived from this master key inside
    :mod:`email_triage.db._migrate` (``derive_storage_key("triage", mk)``) —
    the operator never supplies a raw key, which is exactly what makes a
    wrong-key permanent brick impossible (the DP-1 gap the cutover-readiness
    review flagged). Mirrors :func:`_cli_stamp_db_encryption`'s key read.
    """
    from email_triage.secrets import read_bootstrap_master_key

    config = load_config(args.config)
    db_path = args.db or str(config.persistence.db_path)
    try:
        master_key = read_bootstrap_master_key(config)
    except Exception:
        master_key = None
    return master_key, db_path


# NOTE: deliberately NOT wrapped in @_cli_audit. These commands swap the DB
# file itself mid-run; an audit 'end' row would try to open the just-encrypted
# file through the unstamped (plaintext) CLI context and be silently dropped
# (a §164.312(b) gap). The cutover is audited at a higher layer — the §164.316
# register row filed AT cutover + the operator's window timestamps / log_entries
# delta (the H-03/EQM-02 procedural §164.312(b) mechanism — hipaa-sme review
# 2026-05-31 concurred the omission is sound; a 'start'-only emit before the
# swap is a tracked Cycle-N+1 enhancement, not a gap).
def cmd_db_encrypt(args: argparse.Namespace) -> int:
    """One-time: migrate the existing PLAINTEXT ``triage.db`` to SQLCipher.

    The single safe v0.1.2 cutover primitive — a ``sqlcipher_export`` copy +
    verified swap (NOT an in-place ``PRAGMA rekey``), with the key derived
    from ``ET_MASTER_KEY``. New installs never need this (``init_db_encrypted``
    brings a fresh DB up encrypted). STOP THE SERVICE FIRST.
    """
    from email_triage.db import _migrate

    master_key, db_path = _db_resolve_master_key(args)
    if not master_key:
        print(
            "No master key available — cannot derive the SQLCipher key. "
            "Provision ET_MASTER_KEY first.",
            file=sys.stderr,
        )
        return 2

    print(f"About to ENCRYPT (one-time, in place): {db_path}")
    print("  * STOP the service first (this refuses if the DB is locked).")
    print(f"  * The plaintext original is backed up to {db_path}.plaintext.bak")
    if not args.yes:
        try:
            ans = input("Proceed? [y/N]: ").strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 0

    try:
        result = _migrate.encrypt_plaintext_db(db_path, master_key)
    except _migrate.MigrationError as e:
        print(f"Encrypt FAILED (original intact): {e}", file=sys.stderr)
        return 1
    print(
        f"ENCRYPTED OK — {result.result_tables} tables; raw sqlite3 rejects "
        f"the file, keyed open succeeds."
    )
    print(f"Plaintext backup: {result.backup_path}")
    print(
        f"SECURITY: {result.backup_path} is PLAINTEXT PHI. Once the cutover "
        f"is confirmed healthy, securely delete it (shred -u) per the runbook "
        f"disposal step (§164.310(d)(2)(i))."
    )
    print("Next: deploy the v0.1.2 image with EMAIL_TRIAGE_DB_ENCRYPTION=true.")
    return 0


def cmd_db_decrypt(args: argparse.Namespace) -> int:
    """Rollback: decrypt a SQLCipher ``triage.db`` back to plaintext.

    The inverse of :func:`cmd_db_encrypt` (gate §7 post-cutover decrypt path),
    same ``sqlcipher_export`` copy + verified swap. STOP THE SERVICE FIRST.
    """
    from email_triage.db import _migrate

    master_key, db_path = _db_resolve_master_key(args)
    if not master_key:
        print(
            "No master key available — cannot derive the SQLCipher key.",
            file=sys.stderr,
        )
        return 2

    print(f"About to DECRYPT (rollback, in place): {db_path}")
    print("  * STOP the service first (this refuses if the DB is locked).")
    print(f"  * The encrypted original is backed up to {db_path}.encrypted.bak")
    if not args.yes:
        try:
            ans = input("Proceed? [y/N]: ").strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 0

    try:
        result = _migrate.decrypt_encrypted_db(db_path, master_key)
    except _migrate.MigrationError as e:
        print(f"Decrypt FAILED (original intact): {e}", file=sys.stderr)
        return 1
    print(
        f"DECRYPTED OK — {result.result_tables} tables; raw sqlite3 now reads "
        f"the file."
    )
    print(f"Encrypted backup: {result.backup_path}")
    print(
        f"After the rollback is confirmed, securely delete "
        f"{result.backup_path} (§164.310(d)(2)(i))."
    )
    return 0


def _cmd_embedding_bits_dispatch(args: argparse.Namespace) -> int:
    """Route ``embedding-bits <subcommand>`` to the right handler.

     — operator-facing surface for the lazy embedding-stack
    install. Sub-commands: install / sideload / verify / status.
    The install + sideload paths share the same async installer the
    admin UI button drives.
    """
    sub = getattr(args, "embedding_bits_cmd", None)
    if sub == "install":
        return cmd_embedding_bits_install(args)
    if sub == "sideload":
        return cmd_embedding_bits_sideload(args)
    if sub == "verify":
        return cmd_embedding_bits_verify(args)
    if sub == "status":
        return cmd_embedding_bits_status(args)
    print(
        "Usage: email-triage embedding-bits {install|sideload|"
        "verify|status}",
        file=sys.stderr,
    )
    return 1


def _cli_stamp_db_encryption(config: Any) -> bool:
    """Resolve + stamp the encrypted-vs-plaintext DB context for a CLI run.

    N-17 — the CLI runs OUTSIDE the server, so the boot lifespan never
    stamped :func:`email_triage.db._engine.set_dedicated_conn_encryption`.
    Without this, every CLI DB opener (audit-verify / embedding-bits /
    audit-reconcile) would default to the plaintext path and fail to open
    an encrypted install. This reads the master key + resolves encryption
    the SAME way the app boot does, then stamps the process context so the
    shared :func:`open_dedicated_conn` self-selects correctly.

    Returns the resolved encrypted flag. Fail-closed identically to the
    app boot: if encryption is required but sqlcipher3 / the key is
    missing, :func:`enforce_db_encryption_boot_contract` raises — the CLI
    must not silently read a plaintext DB on an encrypted install.
    """
    from email_triage.db._engine import (
        enforce_db_encryption_boot_contract,
        set_dedicated_conn_encryption,
    )
    from email_triage.secrets import read_bootstrap_master_key

    master_key: str | None = None
    try:
        master_key = read_bootstrap_master_key(config)
    except Exception:
        master_key = None

    encrypted = enforce_db_encryption_boot_contract(
        config, master_key_available=master_key is not None
    )
    set_dedicated_conn_encryption(encrypted=encrypted, master_key=master_key)
    return encrypted


def _cli_open_config_db(config: Any) -> Any:
    """SSOT — open the live *configured* DB encryption-aware for a CLI handler.

    The CLI runs OUTSIDE the server boot, so nothing stamps the dedicated-conn
    encryption context. Raw ``init_db(config.persistence.db_path)`` is the
    PLAINTEXT opener (``web.db.init_db`` -> bare ``sqlite3.connect``) and raises
    ``sqlite3.DatabaseError: file is not a database`` on an encrypted install
    (the default / HIPAA-class posture). This stamps encryption from config
    (:func:`_cli_stamp_db_encryption`, fail-closed via the boot contract), then
    opens via the shared encrypted-aware opener + applies migrations — mirroring
    the server boot at ``web/app.py`` (``init_db_encrypted`` branch).

    EVERY CLI handler that opens the configured DB MUST use this — never raw
    ``init_db(config.persistence.db_path)``. (N-129: 6 handlers — style-profile,
    sent-mail-index, apikey, user, secrets, the audit auto-emit — opened raw and
    were silently broken on encrypted installs; the bug surfaced LIVE mining a
    profile on prod. On a FRESH encryption-required install raw ``init_db`` would
    also silently create a sibling PLAINTEXT ``triage.db`` a later encrypted
    ``serve`` can't open. The unit tests MOCKED ``init_db`` so they never
    exercised the real encrypted open — the mock-the-boundary miss.)

    PIN SCOPE (do not over-read — layered defense): the pin
    ``tests/test_cli_db_open_encryption_pin.py`` bans the
    ``init_db(config.persistence.db_path)`` SHAPE only. A raw ``sqlite3.connect``
    or an UNSTAMPED ``open_dedicated_conn`` on the config path is a SEPARATE,
    currently-uncovered shape (no such offender today) — a pin existing is not
    proof of full coverage. A behavioural test
    (``test_cli_open_config_db_bootstraps_fresh_db``) covers the fresh-DB schema.
    """
    from email_triage.secrets import read_bootstrap_master_key
    from email_triage.web.db import init_db, init_db_encrypted

    # N-17/N-129: stamp the dedicated-conn encryption context from config (the
    # CLI runs outside the server boot, so nothing else stamps it; fail-CLOSED
    # via the boot contract), then mirror the server boot's open branch EXACTLY
    # (web/app.py) — both `init_db_encrypted` and `init_db` run `_bootstrap_schema`
    # (full DDL + migrations + PRAGMAs + the N-16 row factory), so a FRESH DB (the
    # `cmd_user` first-admin bootstrap) gets its base tables. (db-sme MUST-FIX: the
    # earlier `open_dedicated_conn` + bare `run_migrations` shape dropped `_ALL_DDL`
    # and crashed 'no such table: settings' on a fresh DB.)
    encrypted = _cli_stamp_db_encryption(config)
    db_path = str(config.persistence.db_path)
    if encrypted:
        return init_db_encrypted(db_path, read_bootstrap_master_key(config))
    return init_db(db_path)


def _embedding_bits_open_db(args: argparse.Namespace) -> Any:
    """Open the configured DB + apply migrations. Used by every
    embedding-bits subcommand so install_state row reads are always
    against an up-to-date schema. Routes through the :func:`_cli_open_config_db`
    SSOT (N-129) so the encrypted-aware open can't drift per-command."""
    config = load_config(args.config)
    return _cli_open_config_db(config)


def _embedding_bits_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    """Resolve (manifest_path, target_dir) from CLI args + env + defaults."""
    from email_triage.embedding_bits import (
        DEFAULT_MANIFEST_PATH, get_runtime_deps_path,
    )
    manifest_raw = (
        getattr(args, "manifest", "") or
        os.environ.get("EMBEDDING_BITS_MANIFEST", "") or
        DEFAULT_MANIFEST_PATH
    )
    target_raw = getattr(args, "target_dir", "") or ""
    manifest_path = Path(manifest_raw).expanduser().resolve()
    target_dir = (
        Path(target_raw).expanduser().resolve()
        if target_raw else get_runtime_deps_path()
    )
    return manifest_path, target_dir


@_cli_audit("embedding-bits.install")
def cmd_embedding_bits_install(args: argparse.Namespace) -> int:
    """Run the auto-download installer synchronously."""
    # -followup-B — uses the module-level `import asyncio` at the
    # top of the file. A local `import asyncio` here would shadow it
    # (LEGB function-scope hides module-scope) — see the AST guard at
    # tests/test_no_legb_shadow_asyncio.py.
    conn = _embedding_bits_open_db(args)
    manifest_path, target_dir = _embedding_bits_paths(args)
    if not manifest_path.exists():
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        return 2
    from email_triage.embedding_bits import install_auto
    result = asyncio.run(install_auto(
        conn=conn, manifest_path=manifest_path, target_dir=target_dir,
    ))
    print(
        f"status={result.status} files={result.files_installed} "
        f"bytes={result.bytes_downloaded} duration={result.duration_secs:.1f}s",
    )
    if result.status == "installed":
        return 0
    if result.error_msg:
        print(
            f"error: {result.error_class}: {result.error_msg}",
            file=sys.stderr,
        )
    return 1


@_cli_audit("embedding-bits.sideload")
def cmd_embedding_bits_sideload(args: argparse.Namespace) -> int:
    """Run the sideload installer synchronously."""
    # -followup-B — same LEGB-shadow rationale as install above.
    conn = _embedding_bits_open_db(args)
    manifest_path, target_dir = _embedding_bits_paths(args)
    source_dir = Path(args.source_dir).expanduser().resolve()
    if not source_dir.exists() or not source_dir.is_dir():
        print(
            f"source-dir not found or not a directory: {source_dir}",
            file=sys.stderr,
        )
        return 2
    if not manifest_path.exists():
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        return 2
    from email_triage.embedding_bits import install_sideload
    result = asyncio.run(install_sideload(
        conn=conn, manifest_path=manifest_path,
        source_dir=source_dir, target_dir=target_dir,
    ))
    print(
        f"status={result.status} files={result.files_installed} "
        f"duration={result.duration_secs:.1f}s",
    )
    if result.status == "installed":
        return 0
    if result.error_msg:
        print(
            f"error: {result.error_class}: {result.error_msg}",
            file=sys.stderr,
        )
    return 1


def cmd_embedding_bits_verify(args: argparse.Namespace) -> int:
    """Re-hash on-disk files against the manifest. Exit 0 on match."""
    conn = _embedding_bits_open_db(args)
    manifest_path, target_dir = _embedding_bits_paths(args)
    if not manifest_path.exists():
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        return 2
    from email_triage.embedding_bits import reverify
    result = reverify(
        conn=conn, manifest_path=manifest_path, target_dir=target_dir,
    )
    print(
        f"status={result.status} files={result.files_installed} "
        f"duration={result.duration_secs:.1f}s",
    )
    if result.status == "installed":
        return 0
    if result.error_msg:
        print(
            f"error: {result.error_class}: {result.error_msg}",
            file=sys.stderr,
        )
    return 1


def cmd_embedding_bits_status(args: argparse.Namespace) -> int:
    """Print the install_state row + runtime-ready probe."""
    import json
    conn = _embedding_bits_open_db(args)
    from email_triage.embedding_bits import (
        get_install_status, is_runtime_ready,
    )
    state = get_install_status(conn)
    state["_runtime_ready"] = is_runtime_ready()
    print(json.dumps(state, indent=2, default=str))
    return 0


def _cmd_audit_dispatch(args: argparse.Namespace) -> int:
    """Route ``audit <subcommand>`` to the right handler."""
    sub = getattr(args, "audit_cmd", None)
    if sub == "verify":
        return cmd_audit_verify(args)
    if sub == "reconcile":
        return cmd_audit_reconcile(args)
    print(
        "Usage: email-triage audit {verify,reconcile} [...]",
        file=sys.stderr,
    )
    return 1


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify the ``log_entries`` hash chain integrity.

    HIPAA §164.312(c)(1) Integrity addressable spec — operator must
    be able to verify that electronic PHI hasn't been altered or
    destroyed in an unauthorized manner. This wraps
    :func:`verify_log_chain` in a CLI surface so external compliance
    reviewers can run the check post-suite without writing Python.

    Exit codes:
        0  chain verified end-to-end (or to the ``--since`` cutoff)
        1  chain break detected; stderr names the broken row
        2  could not open the DB
    """
    import sqlite3

    from email_triage.web.db import verify_log_chain

    # Resolve DB path: --db override wins (explicit plaintext target — does
    # NOT touch config, a long-standing contract), else load from config.
    # N-17: ONLY the config path resolves + stamps encryption — an
    # encrypted install's key lives in the config-referenced secrets
    # backend. ``--db PATH`` remains a plaintext-only escape hatch (an
    # operator pointing at a raw file; encrypted --db support would need a
    # separate --master-key-from flag, out of N-17 scope — flagged).
    db_path: Path
    encrypted = False
    if args.db:
        db_path = Path(args.db).expanduser().resolve()
    else:
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"Could not load config: {e}", file=sys.stderr)
            return 2
        db_path = Path(config.persistence.db_path)
        try:
            encrypted = _cli_stamp_db_encryption(config)
        except Exception as e:
            print(f"Could not open {db_path}: {e}", file=sys.stderr)
            return 2

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 2

    # the backlog  (Census v3 #8) — route through the SSOT
    # ``open_dedicated_conn_readish`` (boot-encryption-aware RO opener).
    # Encrypted: SQLCipher opens a RW handle (no mode=ro URI
    # equivalent); the verifier only issues SELECTs. Plaintext:
    # ``mode=ro`` URI + full init_db arg set (timeout=30 for WAL busy
    # overlap on a live DB, cached_statements=0 for CPython #118172
    # hardening).
    try:
        from email_triage.db._engine import open_dedicated_conn_readish
        conn = open_dedicated_conn_readish(str(db_path))
        # N-16: factory from the conn's own dbapi module (sqlite3.Row vs
        # sqlcipher3.dbapi2.Row).
        apply_compatible_row_factory(conn)
    except sqlite3.Error as e:
        print(f"Could not open {db_path}: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        # sqlcipher3 raises its own DBAPI Error subclass on bad key /
        # unreadable file — same "could not open" exit as sqlite3.Error.
        print(f"Could not open {db_path}: {e}", file=sys.stderr)
        return 2

    # H-02a / 2026-05-31 encrypted-cutover: verify_log_chain RE-COMPUTES
    # every ``hmac-sha256-v1`` row's hash, which REQUIRES the audit-chain
    # HMAC subkey registry to be populated — derived from the master key,
    # exactly as the web/app.py lifespan + every secrets-CLI bootstrap do.
    # Without it, the FIRST hmac row raises inside compute_log_row_hash
    # (fail-closed) and the verifier reports a FALSE break. This surfaced
    # at the v0.1.1->v0.1.2 cutover: legacy rows carry hash_alg='sha256'
    # (zero-key) and post-upgrade rows carry 'hmac-sha256-v1', so the
    # break landed at the first post-cutover row. Proven 2026-05-31: prod's
    # chain verifies clean (34213 rows) once keys are wired. The ``--db``
    # plaintext escape hatch has no config/master key and verifies legacy
    # 'sha256' rows only (documented limitation; warns + continues).
    if not args.db:
        try:
            from email_triage.secrets import (
                bootstrap_secrets_from_config,
                wire_audit_chain_hmac_keys,
            )
            _provider = bootstrap_secrets_from_config(conn, config)
            wire_audit_chain_hmac_keys(_provider, config)
        except Exception as e:
            print(
                f"Warning: could not wire audit-chain HMAC keys "
                f"({fmt_exc(e, with_class=True)}); any hmac-sha256-v1 rows will "
                f"report as a chain break.",
                file=sys.stderr,
            )

    try:
        result = verify_log_chain(conn, since=args.since)
    finally:
        conn.close()

    if result["first_break_id"] is None:
        rows = result["rows_checked"]
        if args.quiet:
            print(f"PASS {rows}")
        else:
            print(f"audit verify: PASS — {rows} rows checked")
        return 0

    # FAIL path — surface the break for the operator.
    bid = result["first_break_id"]
    bts = result["first_break_ts"] or "?"
    expected = result["first_break_expected"] or ""
    found = result["first_break_found"] or ""
    if args.quiet:
        print(f"FAIL {bid}", file=sys.stderr)
    else:
        print(
            f"audit verify: FAIL — chain breaks at row id={bid} "
            f"ts={bts} (expected hash {expected}, found {found})",
            file=sys.stderr,
        )
    return 1


def cmd_audit_reconcile(args: argparse.Namespace) -> int:
    """``email-triage audit reconcile`` — H-11 EQM-04 PHI-tables tooling.

    Cross-references live PHI-table state against the HMAC-chained
    ``log_entries`` audit trail (EQM-05). A row in a PHI-bearing table
    with no matching audit-chain entry is candidate-tampering; an
    audit-chain entry without a matching row is candidate-tampering or
    legitimate-cascade-delete (operator correlates against the cascade
    record).

    Closes H-11 (forward-stub disclosed in EQM-04 inline rationale at
    ``src/email_triage/engine/store.py:79+``). Per hipaa-sme-2 / 3
    calibration: not regulatorily required per literal §164.312(c)(2)
    Addressable doctrine (mechanism-EXISTS test satisfied by the
    investigator-workflow shape), but operationally-desirable +
    OCR-posture-aligned per NIST SP 800-66 R2 §4.4
    continuous-monitoring leanings.

    Read-only by design — no PHI is mutated, no audit-chain row is
    written by the reconciliation itself. When HIPAA mode is on AND
    divergence is detected, ONE ``hipaa_access_events`` row lands as
    a §164.308(a)(1)(ii)(D) Information System Activity Review surface
    (anchored on the lowest-id HIPAA-flagged account).

    Exit codes (designed for scripted callers — the monitoring system, monitoring):
        0  no divergence; PHI tables and audit chain are in sync
        1  divergence detected (counts in stdout / JSON output)
        2  could not open the DB
    """
    import sqlite3

    from email_triage.db.reconciliation import (
        emit_divergence_event,
        verify_phi_table_against_audit_log,
    )

    # DB-path resolution mirrors cmd_audit_verify so the two subcommands
    # have congruent CLI ergonomics. --db override wins (explicit
    # plaintext target — does NOT touch config); otherwise load_config,
    # read persistence.db_path + resolve/stamp encryption. N-17: encrypted
    # support is the config path only (--db is a plaintext escape hatch).
    db_path: Path
    encrypted = False
    if args.db:
        db_path = Path(args.db).expanduser().resolve()
    else:
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"Could not load config: {e}", file=sys.stderr)
            return 2
        db_path = Path(config.persistence.db_path)
        try:
            encrypted = _cli_stamp_db_encryption(config)
        except Exception as e:
            print(f"Could not open {db_path}: {e}", file=sys.stderr)
            return 2

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 2

    # the backlog  (Census v3 #8) — route through the SSOT openers
    # (boot-encryption-aware). Default = RW (audit-event emit on
    # HIPAA+divergence needs write); --read-only = RO SSOT which under
    # encryption falls back to a SQLCipher RW handle with the caller's
    # emit-suppression logic as the no-mutation gate. The SSOTs carry
    # the full init_db argument set uniformly (timeout=30.0 for the
    # WAL busy overlap that reconcile can race, cached_statements=0).
    try:
        from email_triage.db._engine import (
            open_dedicated_conn, open_dedicated_conn_readish,
        )
        if args.read_only:
            conn = open_dedicated_conn_readish(str(db_path))
        else:
            conn = open_dedicated_conn(str(db_path), check_same_thread=False)
        # N-16: factory from the conn's own dbapi module (sqlite3.Row vs
        # sqlcipher3.dbapi2.Row).
        apply_compatible_row_factory(conn)
    except sqlite3.Error as e:
        print(f"Could not open {db_path}: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        # sqlcipher3 raises its own DBAPI Error subclass on bad key.
        print(f"Could not open {db_path}: {e}", file=sys.stderr)
        return 2

    # Parse --since (ISO-8601) into a datetime, or None.
    # N-263b R31 fromisoformat sweep — route through `_isotime.parse_iso`
    # SSOT (returns None on unparseable). User-facing error message
    # preserved verbatim; the SSOT swallows the underlying ValueError so
    # we surface a generic message without the parse detail.
    from email_triage._isotime import parse_iso
    since_dt = None
    if args.since:
        since_dt = parse_iso(args.since)
        if since_dt is None:
            print(
                f"Invalid --since timestamp {args.since!r}",
                file=sys.stderr,
            )
            conn.close()
            return 2

    try:
        report = verify_phi_table_against_audit_log(
            conn,
            table=(args.table or None),
            since=since_dt,
        )
        # HIPAA-mode-only divergence-detected audit-event emit.
        # is_hipaa_mode() is process-global; in the CLI path it
        # reflects the result of setup_logging which the handler
        # wrapper has NOT run because this handler is read-only and
        # unwrapped. Re-resolve via config so the check matches the
        # install's posture, not the CLI process's transient state.
        if not args.read_only and report.divergence_count > 0:
            try:
                config = load_config(args.config)
                if getattr(config.logging, "hipaa", False):
                    emit_divergence_event(conn, report=report)
            except Exception:
                # Audit-emit failure does not poison the report.
                # Operator still gets the divergence counts in stdout.
                pass
    finally:
        conn.close()

    # Render: --json for scripted callers; human-friendly otherwise.
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        _print_reconcile_human(report)

    return 1 if report.divergence_count > 0 else 0


def _print_reconcile_human(report: Any) -> None:
    """One-screen operator summary; matches the style of audit verify."""
    if report.chain_verify_passed:
        chain_line = (
            f"audit chain: PASS — {report.chain_length} rows"
        )
    else:
        chain_line = (
            f"audit chain: FAIL — {report.chain_break_reason}"
        )
    print(chain_line)
    for t in report.tables:
        print(
            f"  table={t.table}: rows={t.table_row_count} "
            f"audit_pks={t.audit_pk_count} "
            f"matched={t.rows_with_audit_match} "
            f"rows_without_audit={t.rows_without_audit_match} "
            f"audit_without_rows={t.audit_rows_without_table_row}"
        )
        if t.sample_diverged_pks:
            print(f"    sample diverged PKs: {t.sample_diverged_pks}")
    if report.divergence_count == 0:
        print("reconcile: PASS — no divergence")
    else:
        print(
            f"reconcile: FAIL — {report.divergence_count} divergence(s) "
            f"across PHI tables; investigate via audit-chain history"
        )


#: Exit code: the new image would REFUSE the live DB on boot (a migration
#: tamper-guard / DDL failure). scripts/deploy.sh ABORTS the swap on this.
_VERIFY_MIGRATIONS_FAILED = 3
#: Exit code: the smoke could not RUN (config/key/copy infra error). The deploy
#: degrades to the boot + /health auto-rollback safety net — never blocks a
#: good deploy on a smoke-infra hiccup.
_VERIFY_MIGRATIONS_INFRA = 2


def _verify_migrations_on_copy(
    live_db: Path, *, encrypted: bool, master_key: object,
) -> tuple[int, str]:
    """Open a COPY of ``live_db`` through this image's boot migration path
    (``init_db_encrypted`` → ``run_migrations``, or plaintext ``init_db``) so an
    edited already-applied migration body (the N-85 checksum-guard break) — or
    any DDL break against the real data shape — surfaces HERE.

    NON-DESTRUCTIVE: copies ``live_db`` (+ any ``-wal`` / ``-shm`` sidecar) to a
    throwaway temp file and only ever migrates the copy. Returns
    ``(exit_code, message)``: ``0`` clean, ``_VERIFY_MIGRATIONS_FAILED`` the new
    image would refuse the DB, ``_VERIFY_MIGRATIONS_INFRA`` could-not-copy.

    Factored out of the CLI wrapper so the migration-checksum catch is unit-
    testable without a live container (see tests/test_cli_verify_migrations.py).
    """
    import shutil
    import tempfile

    from email_triage.web.db import init_db, init_db_encrypted

    tmpdir = tempfile.mkdtemp(prefix="et-verify-mig-")
    smoke = Path(tmpdir) / "smoke.db"
    try:
        try:
            shutil.copy(live_db, smoke)
            for suffix in ("-wal", "-shm"):
                side = Path(str(live_db) + suffix)
                if side.exists():
                    shutil.copy(side, str(smoke) + suffix)
        except Exception as e:  # noqa: BLE001
            return _VERIFY_MIGRATIONS_INFRA, f"could not copy live DB (infra): {e}"
        try:
            conn = (
                init_db_encrypted(str(smoke), master_key)  # type: ignore[arg-type]
                if encrypted else init_db(str(smoke))
            )
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        except Exception as e:  # noqa: BLE001 — MigrationError + any DDL break
            return (
                _VERIFY_MIGRATIONS_FAILED,
                f"the new image would REFUSE the live DB on boot: "
                f"{fmt_exc(e, with_class=True)}",
            )
        return 0, "OK — the new image migrates the live DB cleanly"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _verify_migrations_smoke(args: argparse.Namespace) -> int:
    """``version-check --verify-migrations`` — /N-85 deploy pre-flight.

    Loads config + (on an encrypted install) the master key the SAME way the
    app boot does, then runs :func:`_verify_migrations_on_copy` so a shipped-
    migration-body edit (the checksum tamper-guard, §164.312(c)(1)) is caught
    PRE-SWAP rather than at the new container's boot (post-swap → the slower
    auto-rollback). Replaces the plaintext-only ``init_db`` smoke + ``--db``
    version-check that scripts/deploy.sh had to SKIP on encrypted installs
    ("F6"), because ``--db`` opens plaintext-only and silently fails on a
    SQLCipher DB. The config path here is encryption-aware (N-17 stamping).
    """
    try:
        config = load_config(args.config)
        encrypted = _cli_stamp_db_encryption(config)
    except Exception as e:  # noqa: BLE001
        print(f"verify-migrations: could not load config (infra): {e}",
              file=sys.stderr)
        return _VERIFY_MIGRATIONS_INFRA
    live = Path(config.persistence.db_path)
    if not live.exists():
        # Fresh install (no DB yet) — nothing to upgrade; not a failure.
        print("verify-migrations: no live DB on disk yet — nothing to verify")
        return 0
    master_key: object = None
    if encrypted:
        try:
            from email_triage.secrets import read_bootstrap_master_key
            master_key = read_bootstrap_master_key(config)
        except Exception as e:  # noqa: BLE001
            print(f"verify-migrations: could not read master key (infra): {e}",
                  file=sys.stderr)
            return _VERIFY_MIGRATIONS_INFRA
    rc, msg = _verify_migrations_on_copy(
        live, encrypted=encrypted, master_key=master_key,
    )
    stream = sys.stderr if rc else sys.stdout
    print(f"verify-migrations: {msg}", file=stream)
    return rc


def cmd_version_check(args: argparse.Namespace) -> int:
    """``email-triage version-check`` — schema-compat status.

    Operator tool that prints the same status the /config admin banner
    renders, so SSH-only operators (sudo podman exec ... version-check)
    can drive their update decision without browser access.

    Exit codes are designed for scripted callers (the monitoring system, the future
    ``scripts/deploy.sh`` pre-flight gate):

        0  up_to_date            -- no update available, no action needed
        1  update_available      -- forward-compat update exists, rollback
                                    to :previous remains safe
        2  incompatible_rollback -- update exists BUT :previous image
                                    would not load the post-bump DB.
                                    Snapshot DB before applying.
        2  downgrade_not_supported -- live DB is newer than this binary;
                                    refuse-to-load enforced by migrations.

    Status 2 is shared between the two "DO NOT APPLY without thinking
    first" cases on purpose: a the monitoring system check can fire on >= 2 and treat
    both as "needs operator hands."
    """
    from email_triage.version import (
        STATUS_DOWNGRADE_NOT_SUPPORTED,
        STATUS_INCOMPATIBLE_ROLLBACK,
        STATUS_UPDATE_AVAILABLE,
        STATUS_UP_TO_DATE,
        gather_version_status,
        read_target_schema_caps,
    )

    # --print-target-schema-only: short-circuit. Prints the running
    # binary's target-schema-caps as a single integer on stdout and
    # exits 0. No DB read, no config load, no other output. This is
    # the hook ``scripts/deploy.sh`` uses to extract the cap from a
    # `:previous` image before swapping (lets the live container's
    # EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS env var be auto-populated
    # with the cap of whatever image will be retagged to :previous
    # on the next deploy).
    if getattr(args, "print_target_schema_only", False):
        print(read_target_schema_caps())
        return 0

    # --verify-migrations: not a schema-version read — it OPENS a
    # copy of the live DB through the boot migration path so an edited applied
    # migration (checksum-guard break) is caught pre-swap. Encryption-aware
    # (config path only); does not honour --db (the plaintext escape hatch
    # carries no master key).
    if getattr(args, "verify_migrations", False):
        return _verify_migrations_smoke(args)

    # Resolve DB path: --db override wins, else load from config.
    db_path: Path | None
    if args.db:
        db_path = Path(args.db).expanduser().resolve()
        if not db_path.exists():
            print(f"Database not found: {db_path}", file=sys.stderr)
            return 2
    else:
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"Could not load config: {e}", file=sys.stderr)
            return 2
        # F6/N-17: stamp the encrypted-vs-plaintext context so the schema read
        # below (version.py) opens an encrypted install WITH its key instead of
        # silently failing-to-plaintext and reporting db_schema=0 — which would
        # hand scripts/deploy.sh a wrong gate verdict on an encrypted DB. The
        # ``--db`` branch above stays the plaintext-only escape hatch and
        # intentionally does NOT stamp (mirrors cmd_audit_verify / reconcile).
        try:
            _cli_stamp_db_encryption(config)
        except Exception as e:
            print(f"Could not resolve DB encryption: {e}", file=sys.stderr)
            return 2
        db_path = Path(config.persistence.db_path)
        # An install before its first /serve run has no DB on disk.
        # Don't fail — report what we know (target caps + unknown DB).
        if not db_path.exists():
            db_path = None

    status = gather_version_status(db_path)

    if args.json:
        print(json.dumps(status.to_dict(), indent=2, sort_keys=True))
    else:
        # Single human-readable line with the three integers as
        # parenthetical detail. Matches the /config banner audience.
        prev = (
            "" if status.previous_schema_caps is None
            else f", previous={status.previous_schema_caps}"
        )
        print(
            f"version-check: {status.status} -- "
            f"app v{status.app_version}, "
            f"target_schema={status.target_schema_caps}, "
            f"db_schema={status.db_schema_version}"
            f"{prev}"
        )
        print(f"  {status.explanation}")

    if status.status == STATUS_UP_TO_DATE:
        return 0
    if status.status == STATUS_UPDATE_AVAILABLE:
        return 1
    if status.status in (
        STATUS_INCOMPATIBLE_ROLLBACK, STATUS_DOWNGRADE_NOT_SUPPORTED,
    ):
        return 2
    # Unknown status — refuse to claim "up to date".
    return 2


def cmd_init(args: argparse.Namespace) -> int:
    """Scaffold a new config directory."""
    target = Path(args.path or ".")

    config_file = target / "email-triage.yaml"
    if config_file.exists():
        print(f"Config already exists: {config_file}")
        return 1

    target.mkdir(parents=True, exist_ok=True)
    (target / "data").mkdir(exist_ok=True)

    # N-263c R31 (census r26 close-out): route through the atomic_write
    # SSOT so `et init` interrupted mid-write leaves either the empty
    # slot or the fully-written scaffold, never a torn half-config that
    # a subsequent bootstrap-config-read might mis-parse. The
    # exist-guard at line 2822 makes the base scenario bootstrap-fresh,
    # but atomic_write is the correct default posture for every
    # config-file writer per the A11 pin's intent.
    from email_triage._atomicio import atomic_write_text
    atomic_write_text(config_file, """\
# Email Triage Configuration
# See the project README for documentation.

provider:
  type: gmail_api              # gmail_api | imap | office365

classifier:
  backend: ollama              # ollama | openai | gemini
  model: qwen3.5:35b
  ollama_url: http://localhost:11434

routes:
  to-respond: [notify, draft_reply]
  action-required: [notify, label]
  invoices: [label]
  newsletters: [label]

escalation:
  enabled: false
  categories: [to-respond, action-required]
  cooldown_minutes: 15

logging:
  level: INFO
  format: json                 # json | text
  hipaa: false                 # true = strip PHI from logs

secrets:
  backend: auto                # auto (recommended) | container | keyfile | keyring | env (deprecated; dev/CI only — set EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY=1 to silence warning, see H-07)

persistence:
  db_path: ./data/triage.db
  encryption_enabled: true     # SQLCipher AES-256 encryption at rest — ON by default for new installs. Requires the master key (set up below) + the `encryption` extra (bundled in the container image). Set to false only for an explicitly-plaintext install.

backup:                        # Automated DB backup (also configurable in the UI: Admin -> Config -> Backup).
  enabled: false               # Master switch. Leave OFF until you have a restore path (see encryption below).
  cadence: manual              # manual (CLI/host-cron only, no in-app timer) | daily | weekly
  format: etbk                 # etbk (full bundle: DB + config + certs) | db (raw SQLCipher snapshot)
  retention: "14"              # keep-count, or "14d" = 14 days, "2w" = 2 weeks
  dir: ""                      # output dir; blank -> <data_dir>/backups (a host job relocates these off-box)
  encryption: master-key       # master-key (restore needs the master-key-only export) |
                               # public-key (seal each snapshot to an off-box X25519 public key;
                               #   a compromised container cannot READ its own backups)
  public_key: ""               # public-key mode ONLY: X25519 public-key PEM text, or a path to it.
                               # Generate the keypair OFF this host (email-triage backup gen-keypair) and
                               # paste only the PUBLIC key — the private key must never touch the server.
""")

    print(f"Created {config_file}")
    print(f"Created {target / 'data'}/")
    print("\nNext steps:")
    print("  1. Edit email-triage.yaml with your settings")
    print("  2. Set up secrets: email-triage secrets set SMTP_PASSWORD")
    print("  3. Run: email-triage run --query 'is:unread' --limit 5")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _cmd_auth_dispatch(args: argparse.Namespace) -> int:
    """Dispatch ``email-triage auth ...`` subcommands."""
    if args.auth_cmd == "dev-login":
        return cmd_auth_dev_login(args)
    print("Subcommand required (dev-login)", file=sys.stderr)
    return 1


@_cli_audit("style-profile")
def cmd_style_profile(args: argparse.Namespace) -> int:
    """``email-triage style-profile build`` — distil one account's writing
    style from a sample of its Sent folder.

    M-3 (see ``docs/major-features/style-learning.md``). Pulls the last
    ``--limit`` sent messages via the configured provider, calls
    :func:`extract_style_profile`, and persists the resulting structured
    profile under the settings key ``style_profile:<account_id>``.

    Subcommands:
      build  — build/refresh a profile for one account.
    """
    if args.style_profile_cmd != "build":
        print(
            "Usage: email-triage style-profile build "
            "--account <id> [--limit 50] [--query QUERY]",
        )
        return 1

    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.actions.style_profile import (
        extract_style_profile,
    )
    from email_triage.secrets import bootstrap_secrets_from_config
    from email_triage.web.db import (
        get_email_account, set_style_profile,
    )

    db = _cli_open_config_db(config)
    try:
        secrets = bootstrap_secrets_from_config(db, config)
    except Exception as e:
        print(f"Could not open runtime secrets store: {e}")
        return 1

    # H-02a (Cycle 6): see note at the secrets-CLI bootstrap above.
    from email_triage.secrets import (
        enforce_master_key_at_rest_for_hipaa,
        wire_audit_chain_hmac_keys,
    )
    enforce_master_key_at_rest_for_hipaa(config)
    wire_audit_chain_hmac_keys(secrets, config)

    # N-130: register the install-level OAuth creds with the provider factory —
    # the SAME wiring the server boot does — so build_provider can construct a
    # Gmail / O365 provider with the install client_id (else the build fails
    # "client_id not configured"). The CLI runs OUTSIDE the boot, so nothing
    # else registers it. Sibling of N-129's CLI-vs-boot divergence.
    from email_triage.providers.factory import hydrate_and_register_install_oauth
    hydrate_and_register_install_oauth(config, secrets, db)

    acct = get_email_account(db, args.account)
    if acct is None:
        print(f"Account #{args.account} not found.")
        return 1

    # Default per-provider Sent-folder search query. Operators can
    # override via --query when the install uses non-default folder
    # names. Gmail uses query syntax; IMAP uses RFC 3501 search;
    # Office365 uses a Graph $filter. Routes through the traits
    # registry so the default lives in one place.
    query = args.query
    if not query:
        from email_triage.providers.traits import default_search_query
        query = default_search_query(acct["provider_type"])

    # Build a provider scoped to this account.
    from email_triage.web.routers.ui import _create_provider_from_account
    provider = _create_provider_from_account(acct, secrets)

    async def _run() -> int:
        try:
            ids = await provider.search(query, args.limit)
        except Exception as e:
            print(f"search failed: {fmt_exc(e)}")
            return 1
        if not ids:
            print(
                f"No messages matched query '{query}' on account "
                f"{acct.get('owner_email', '?')} / {acct.get('name', '?')}.",
            )
            return 1

        messages = []
        for mid in ids:
            try:
                msg = await provider.fetch_message(mid)
            except Exception as e:
                log.warning("fetch failed", message_id=mid, error=fmt_exc(e))
                continue
            messages.append(msg)

        if not messages:
            print("No messages could be fetched; aborting.")
            return 1

        classifier = _create_classifier(config)
        # M-6 hook: pull the set of M-4-captured message ids for this
        # account so captured pairs (AI drafted, user edited + sent)
        # are double-weighted in the distillation corpus. Captured
        # pairs are flagged on ``sent_mail_index.is_captured_pair=1``
        # by the sent-mail capture loop.
        captured_ids: set[str] = set()
        try:
            # CLI-only path: the standalone `style-mine` command runs
            # single-threaded with no web event loop / concurrent
            # traffic, so there is no shared-connection contention to
            # serialise against.
            rows = db.execute(  # async-db-ok: CLI, no event loop
                "SELECT message_id FROM sent_mail_index "
                "WHERE account_id = ? AND is_captured_pair = 1",
                (args.account,),
            ).fetchall()
            for r in rows:
                mid = r["message_id"] if hasattr(r, "keys") else r[0]
                if mid:
                    captured_ids.add(str(mid))
        except Exception:
            # Pre-M-6 install (sent_mail_index table missing) -- fall
            # through with an empty set.
            captured_ids = set()
        from email_triage.triage_logging import is_account_hipaa as _iah_style
        profile = await extract_style_profile(
            messages, classifier,
            captured_message_ids=captured_ids,
            account_hipaa=_iah_style(acct), conn=db,  # N-114 BAA egress gate
        )
        # async-db-ok — CLI-only path, no web event loop.
        set_style_profile(db, args.account, profile.to_dict())

        print(
            f"Style profile built for account #{args.account} "
            f"(owner={acct.get('owner_email', '?')}) — "
            f"{profile.sample_count} messages, model={profile.model_used}, "
            f"formality={profile.formality}/5.",
        )
        return 0

    async def _run_and_close() -> int:
        # /N-131 — close the provider in the SAME loop _run used (its
        # httpx.AsyncClient lives there). The old asyncio.run(provider.close())
        # ran in a 2nd loop after asyncio.run(_run()) closed the 1st, so close
        # failed 'Event loop is closed' on EVERY mine — the  warning fired
        # constantly, masking a real leak. The exit code is still INTENTIONALLY
        # preserved (the finally never returns) and a genuine close failure is
        # logged, not swallowed/raised. db-sme [269].
        try:
            return await _run()
        finally:
            await _aclose_provider_quietly(provider)

    return asyncio.run(_run_and_close())


@_cli_audit("sent-mail-index")
def cmd_sent_mail_index(args: argparse.Namespace) -> int:
    """``email-triage sent-mail-index build`` -- index one account's
    sent mail for M-4 RAG retrieval.

    M-4 (retrieval-augmented few-shot examples). Pulls the last
    ``--limit`` sent messages via the configured provider, embeds
    them via the local embedding backend, and stores the vectors
    in ``sent_mail_index``. Refuses HIPAA-flagged accounts -- M-4
    is hard-off on PHI per the cross-cutting privacy gate.

    Subcommands:
      build  -- build/refresh the index for one account.
    """
    if getattr(args, "sent_mail_index_cmd", None) != "build":
        print(
            "Usage: email-triage sent-mail-index build "
            "--account <id> [--limit 200]",
        )
        return 1

    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.actions.sent_mail_index import (
        NonLocalBackendError, SentMailIndex,
    )
    from email_triage.secrets import bootstrap_secrets_from_config
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import get_email_account

    db = _cli_open_config_db(config)
    try:
        secrets = bootstrap_secrets_from_config(db, config)
    except Exception as e:
        print(f"Could not open runtime secrets store: {e}")
        return 1

    # H-02a (Cycle 6): see note at the secrets-CLI bootstrap above.
    from email_triage.secrets import (
        enforce_master_key_at_rest_for_hipaa,
        wire_audit_chain_hmac_keys,
    )
    enforce_master_key_at_rest_for_hipaa(config)
    wire_audit_chain_hmac_keys(secrets, config)

    # N-130: register the install-level OAuth creds with the provider factory —
    # the SAME wiring the server boot does — so build_provider can construct a
    # Gmail / O365 provider with the install client_id (else the build fails
    # "client_id not configured"). The CLI runs OUTSIDE the boot, so nothing
    # else registers it. Sibling of N-129's CLI-vs-boot divergence.
    from email_triage.providers.factory import hydrate_and_register_install_oauth
    hydrate_and_register_install_oauth(config, secrets, db)

    acct = get_email_account(db, args.account)
    if acct is None:
        print(f"Account #{args.account} not found.")
        return 1

    if is_account_hipaa(acct):
        owner = acct.get("owner_email", "?")
        name = acct.get("name", "?")
        print(
            f"Account #{args.account} ({owner} / {name}) is HIPAA-"
            f"flagged. M-4 sent-mail index is hard-off on HIPAA "
            f"accounts; nothing to do.",
        )
        return 1

    # Provider scoped to this account (mirrors style-profile build).
    from email_triage.web.routers.ui import _create_provider_from_account
    provider = _create_provider_from_account(acct, secrets)

    # Build a local-only embedding backend. M-4 ships scaffold-only;
    # the production wiring lands in M-5 alongside the prompt-
    # builder integration. The CLI accepts only Ollama because
    # that's the only allowlisted backend in the helper.
    classifier_backend = getattr(config.classifier, "backend", "ollama")
    if classifier_backend != "ollama":
        print(
            "M-4 sent-mail index requires the 'ollama' classifier "
            "backend (the embedding endpoint and the local-only rule "
            "ride along with it). Configured backend: "
            f"{classifier_backend!r}. Aborting.",
        )
        return 1

    # Tiny inline embedding shim: hits Ollama's /api/embeddings on
    # whichever model the operator picked for embeddings (default
    # nomic-embed-text). Inline because production wiring is M-5's
    # job; this shim makes the CLI usable for index seeding today.
    import httpx

    from email_triage._egress import Intent, egress_async_client

    embed_model = (
        getattr(config.classifier, "embedding_model", None)
        or "nomic-embed-text"
    )
    base_url = (
        getattr(config.classifier, "base_url", None)
        or "http://localhost:11434"
    ).rstrip("/")

    # A4b (census 2026-06-09, DA Finding 2 — verify-don't-accept on my own
    # refute). The M-series privacy invariant is "the embedding backend speaks
    # ONLY to a local Ollama." SentMailIndex's NonLocalBackendError guards the
    # backend_type LABEL ("ollama"), which this inline shim hardcodes — so
    # without an explicit base_url locality check a misconfigured
    # config.classifier.base_url would egress sent-mail content (subject/body
    # excerpt) to a non-local embedder. Gate it explicitly, like
    # embedding_backend.py:245 does for the production backend.
    from email_triage.classify.base import _is_local_host
    _local_suffixes = getattr(
        getattr(config, "tls", None), "local_url_suffixes", (),
    ) or ()
    if not _is_local_host(base_url, extra_suffixes=_local_suffixes):
        print(
            "M-4 sent-mail index requires a LOCAL embedding endpoint — "
            f"config.classifier.base_url={base_url!r} is not local. Sent-mail "
            "content must not egress to a remote embedder. Aborting.",
        )
        return 1

    class _OllamaEmbedShim:
        backend_type = "ollama"

        async def embed_text(self, text: str) -> list[float]:
            # N-220 R22 (2026-07-02): wrap POST /api/embeddings in the
            # breaker + timer so a dead local Ollama on the M-4 sent-mail-
            # index CLI path (a) trips the `ollama` circuit and (b)
            # emits an `et_llm_embed_seconds{backend="ollama"}` sample
            # on /metrics.
            # N-384 (2026-07-10 wf_69674c7e-c67, HIGH): emit the outcome-
            # counter twin — the timer records latency but was blind to
            # the failure edge.
            from email_triage import metrics as _metrics
            from email_triage.llm_health import translate_unreachable
            outcome = "transport_error"
            try:
                # -d: config-driven LLM_PHI embed timeout. Reads
                # ``config.classifier.embed_timeout_secs`` (default 60.0
                # preserves prior hardcoded value).
                _embed_timeout = float(getattr(
                    config.classifier, "embed_timeout_secs", 60.0,
                ))
                async with egress_async_client(
                    intent=Intent.LLM_PHI, timeout=_embed_timeout
                ) as client:
                    with _metrics.timer("et_llm_embed_seconds", backend="ollama"), \
                            translate_unreachable(
                                "ollama", base_url, default_port=11434,
                            ):
                        # N-431 (2026-07-19) — SSOT injects ``keep_alive``.
                        # M-4 sent-mail index seeding fires N embeds
                        # back-to-back; without a pinned TTL Ollama's
                        # default "5m" evicts the embedding model between
                        # cold-start batches. Read the same ``ollama_
                        # keep_alive`` knob the classifier reads.
                        from email_triage._ollama_reuse import merge_reuse_options
                        payload = {"model": embed_model, "prompt": text}
                        _cli_keep_alive = str(getattr(
                            config.classifier, "ollama_keep_alive", "10m",
                        ) or "10m")
                        await merge_reuse_options(
                            payload, base_url, embed_model, client,
                            default_keep_alive=_cli_keep_alive,
                        )
                        resp = await client.post(
                            f"{base_url}/api/embeddings",
                            json=payload,
                        )
                        resp.raise_for_status()
                        body = resp.json() or {}
                vec = body.get("embedding") or []
                outcome = "success"
                return [float(x) for x in vec]
            finally:
                _metrics.emit_llm_outcome("embed", "ollama", outcome)

    backend = _OllamaEmbedShim()

    try:
        index = SentMailIndex(
            db, args.account,
            embedding_backend=backend,
            embedding_model=embed_model,
            provider=provider,
        )
    except NonLocalBackendError as e:
        print(str(e))
        return 1

    async def _run() -> int:
        try:
            new_count = await index.index_recent(limit=args.limit)
        except Exception as e:
            print(f"index_recent failed: {fmt_exc(e)}")
            return 1
        skipped = max(0, args.limit - new_count)
        print(
            f"indexed {new_count} new messages, "
            f"skipped {skipped} (already present or empty)",
        )
        return 0

    async def _run_and_close() -> int:
        # /N-131 — see cmd_style_profile: close in-loop. Per §4 principle 2
        # (fix all sites of one root cause) all three CLI provider-close surfaces
        # (here, cmd_style_profile, cmd_watch_push) land in one commit.
        try:
            return await _run()
        finally:
            await _aclose_provider_quietly(provider)

    return asyncio.run(_run_and_close())


@_cli_audit("auth.dev-login")
def cmd_auth_dev_login(args: argparse.Namespace) -> int:
    """Sign a dev-keypair login challenge and print the session cookie.

    Wraps the manual flow at ``/login/dev-keypair``:

    1. GET the page to mint a fresh challenge cookie.
    2. Sign the challenge bytes with the local ed25519 private key.
    3. Compute the SHA256 fingerprint of the corresponding public key.
    4. POST email + fingerprint + base64url(signature) back; capture
       the et_session cookie from the 303 redirect.
    """
    import base64
    import os

    import httpx

    from email_triage._egress import Intent, egress_client
    from email_triage.web import dev_keypair as dk_mod

    key_path = Path(os.path.expanduser(args.key))
    if not key_path.is_file():
        print(f"Private key not found: {key_path}", file=sys.stderr)
        return 1

    # Load private key. Try OpenSSH format first, then PKCS8.
    from cryptography.hazmat.primitives import serialization
    pem = key_path.read_bytes()
    try:
        priv = serialization.load_ssh_private_key(pem, password=None)
    except (ValueError, serialization.UnsupportedAlgorithm):
        try:
            priv = serialization.load_pem_private_key(pem, password=None)
        except Exception as e:
            print(
                f"Could not load private key (encrypted keys unsupported "
                f"in this CLI): {e}",
                file=sys.stderr,
            )
            return 1

    from cryptography.hazmat.primitives.asymmetric import ed25519
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        print(
            "Only ed25519 keys are supported. Generate one with: "
            "ssh-keygen -t ed25519 -f ~/.ssh/et-dev",
            file=sys.stderr,
        )
        return 1

    # Derive the OpenSSH public key text + fingerprint.
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    import struct
    blob = (
        struct.pack(">I", 11) + b"ssh-ed25519"
        + struct.pack(">I", 32) + pub_raw
    )
    pub_text = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " cli"
    parsed = dk_mod.parse_ssh_ed25519_pubkey(pub_text)
    fp = dk_mod.fingerprint(parsed)

    server = args.server.rstrip("/")
    verify = not args.insecure

    with egress_client(
        intent=Intent.PUBLIC_FETCH, verify=verify, follow_redirects=False
    ) as client:
        # Step 1: fetch the login page to get the challenge cookie.
        r1 = client.get(server + "/login/dev-keypair")
        if r1.status_code != 200:
            print(f"GET /login/dev-keypair returned {r1.status_code}",
                  file=sys.stderr)
            return 1
        challenge_b64 = r1.cookies.get("et_devkp_challenge")
        if not challenge_b64:
            print("Server did not set the challenge cookie.",
                  file=sys.stderr)
            return 1

        # Step 2: decode challenge, sign it.
        #  tail — route the hand-rolled URL-safe base64 pair through
        # the `_base64url` SSOT so the pad-restore + pad-strip shape
        # cannot silently drift.
        from email_triage._base64url import (
            b64decode_permissive, b64encode_urlsafe,
        )
        challenge = b64decode_permissive(challenge_b64, urlsafe=True)
        signature = priv.sign(challenge)
        sig_b64 = b64encode_urlsafe(signature, strip_padding=True).decode("ascii")

        # Step 3: post back.
        r2 = client.post(
            server + "/login/dev-keypair",
            data={
                "email": args.email,
                "fingerprint": fp,
                "signature": sig_b64,
            },
        )
        if r2.status_code != 303:
            print(
                f"Login failed: HTTP {r2.status_code}\n{r2.text[:400]}",
                file=sys.stderr,
            )
            return 1

        token = r2.cookies.get("et_session")
        if not token:
            print("Login appeared to succeed but no et_session cookie set.",
                  file=sys.stderr)
            return 1

    print("Session cookie:")
    print(f"  et_session={token}")
    print()
    print("Use with curl:")
    print(f"  curl --cookie 'et_session={token}' {server}/dashboard")
    return 0


def _cmd_backup_gen_keypair() -> int:
    """Generate an X25519 keypair for  public-key backup mode.

    The PUBLIC key goes in the config (``backup.public_key``, stays on-box). The
    PRIVATE key goes OFF-BOX (the operator's password DB) and is needed ONLY for
    restore — never on the container."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv = X25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    # ASCII-only guidance: this is the safety-critical key-handling output and
    # must render correctly + never crash on ANY console encoding (a `→` here
    # was a UnicodeEncodeError on Windows cp1252 — ). The main() UTF-8
    # reconfigure covers the rest of the CLI; this command stays ASCII so the
    # operator can always read which key goes where.
    print("# X25519 backup keypair.")
    print("# PUBLIC KEY -> config backup.public_key (stays on-box):")
    print(pub_pem.rstrip())
    print("# PRIVATE KEY -> store OFF-BOX (your password DB); needed ONLY for")
    print("# restore. Do NOT leave it on the container.")
    print(priv_pem.rstrip())
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    """``email-triage backup now`` — trigger an on-demand backup.

    Runs INSIDE the container (a host cron/systemd does
    ``podman exec <ctr> email-triage backup now``); POSTs the LOOPBACK ops
    endpoint, prints "request received: outputting to <dir>" and exits 0. With
    ``--wait`` it polls the per-run status (``_LAST_RUN.json``) for the real
    outcome + a matching exit code. App offline (connection refused) →
    ``FATAL: unavailable, app offline`` + exit 2."""
    import json as _json
    import time as _time

    import httpx

    from email_triage._egress import EgressBlocked, Intent, egress_client

    sub = getattr(args, "backup_cmd", None)
    if sub == "gen-keypair":
        return _cmd_backup_gen_keypair()
    if sub != "now":
        print(
            "usage: email-triage backup {now [--format etbk|db] [--wait] "
            "| gen-keypair}",
            file=sys.stderr,
        )
        return 2

    base = (os.environ.get("ET_BACKUP_TRIGGER_URL", "") or "https://localhost:8080").rstrip("/")
    # run18 #6 — route the ops-token env read through the single reader SSOT
    # (behaviour-identical: ``_read_ops_token() or ""`` == the old
    # ``os.environ.get("ET_HEALTH_OPS_TOKEN", "")`` for unset / set / empty).
    from email_triage.web.routers.health import _read_ops_token

    token = _read_ops_token() or ""
    if not token:
        print(
            "FATAL: ET_HEALTH_OPS_TOKEN is not set (the ops trigger requires it)",
            file=sys.stderr,
        )
        return 2

    url = base + "/ops/db-backup"
    if getattr(args, "format", None):
        url += f"?format={args.format}"

    # Route the loopback trigger through the egress funnel (run17 #5 — was a raw
    # urllib.request.urlopen). Intent.LOCAL_ONLY: the ops endpoint is the app's
    # own loopback listener (ET_BACKUP_TRIGGER_URL defaults to
    # https://localhost:8080); the funnel fails CLOSED if it's ever misconfigured
    # to a non-local host. verify=False is justified + preserved — a loopback
    # self-signed cert (was ssl.CERT_NONE; httpx verify=False is the exact
    # equivalent, covering check_hostname=False too).
    out_dir = None
    # -d: env-tunable ops-backup trigger timeout. One-shot CLI
    # admin action against loopback — no persistent config surface
    # needed; env var lets an operator raise it for a slow container
    # cold-boot. Default 10s preserves prior hardcoded behavior.
    try:
        _ops_timeout = float(
            os.environ.get("ET_BACKUP_TRIGGER_TIMEOUT_SECS", "") or 10.0
        )
    except (TypeError, ValueError):
        _ops_timeout = 10.0
    try:
        with egress_client(intent=Intent.LOCAL_ONLY, verify=False) as c:
            resp = c.post(
                url, headers={"X-Ops-Token": token}, timeout=_ops_timeout,
            )
        resp.raise_for_status()
        body = _json.loads(resp.text)
        print(body.get("detail", "request received"))
        out_dir = body.get("dir")
    except httpx.HTTPStatusError as e:
        try:
            detail = _json.loads(e.response.text).get("detail", "")
        except Exception:
            detail = ""
        code = e.response.status_code
        if code == 409:
            print("a backup is already in flight", file=sys.stderr)
            return 1
        if code == 503:
            print(f"FATAL: backup disabled ({detail})", file=sys.stderr)
            return 2
        if code == 403:
            print("FATAL: ops trigger denied (token / not loopback)", file=sys.stderr)
            return 2
        print(f"FATAL: trigger failed: HTTP {code} {detail}", file=sys.stderr)
        return 2
    except EgressBlocked as e:
        # ET_BACKUP_TRIGGER_URL misconfigured to a non-local host — the
        # LOCAL_ONLY funnel refused the send (fail-closed; X-Ops-Token never
        # left the box). Surface it as the same clean FATAL/exit-2 contract the
        # other failure paths use, not an uncaught traceback (run17 #5 3-SME).
        print(f"FATAL: backup trigger URL is not local ({e})", file=sys.stderr)
        return 2
    except (httpx.RequestError, ConnectionError, OSError):
        # Connection refused / unreachable = the app isn't serving.
        print("FATAL: unavailable, app offline", file=sys.stderr)
        return 2

    if not getattr(args, "wait", False) or not out_dir:
        return 0

    # --wait: poll _LAST_RUN.json until a NEW run (ts changed) reaches a
    # terminal outcome — so we report THIS run, not a stale prior one.
    from email_triage import backup as _backup
    prior = _backup.read_run_status(out_dir)
    prior_ts = prior.get("ts") if prior else None
    deadline = _time.time() + 600
    while _time.time() < deadline:
        st = _backup.read_run_status(out_dir)
        if st and st.get("ts") != prior_ts and st.get("outcome") in ("success", "failure"):
            if st["outcome"] == "success":
                print(f"backup complete: {st.get('file')}")
                return 0
            print(f"FATAL: backup failed: {st.get('error')}", file=sys.stderr)
            return 1
        _time.sleep(3)
    print("WARN: timed out waiting for the backup to complete", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-triage",
        description="Portable email triage with LLM classification",
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to config file (default: search standard paths)",
    )
    # N-157 (2026-07-09) — CLI audit gate.  Default OFF (fail-CLOSED): an
    # H-03-auto emit failure at handler ENTRY blocks the handler from
    # running and exits non-zero, so an operator sees an obvious audit-
    # gate error instead of a silent WARN + successful op.  Set (fail-
    # SOFT) preserves the pre-N-157 defense-in-depth-on-top-of-procedural
    # posture the H-03-auto docstring at cli.py:104-112 rationalizes for
    # break-glass incident use.  The recovery lever is the same
    # documented `actions_taken` field in INCIDENT_RESPONSE.md the
    # original H-03 closure named.
    parser.add_argument(
        "--allow-unaudited",
        dest="allow_unaudited",
        action="store_true",
        default=False,
        help=(
            "Continue a CLI admin op even when the audit-chain emit "
            "fails (procedural break-glass fallback per "
            "INCIDENT_RESPONSE.md).  Default OFF (fail-CLOSED): audit "
            "emit failure at handler entry blocks the handler."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    # run
    run_p = subparsers.add_parser("run", help="Run a single triage cycle")
    run_p.add_argument("--query", "-q", default="is:unread", help="Search query")
    run_p.add_argument("--limit", "-n", type=int, default=50, help="Max messages")
    run_p.add_argument("--dry-run", action="store_true", help="Fetch + classify only")

    # watch
    watch_p = subparsers.add_parser("watch", help="Poll for new emails")
    watch_p.add_argument("--interval", "-i", type=int, default=300, help="Poll interval (seconds)")
    watch_p.add_argument("--query", "-q", default="is:unread", help="Search query")
    watch_p.add_argument("--limit", "-n", type=int, default=50, help="Max messages per cycle")
    watch_p.add_argument("--push", action="store_true", help="Use push notifications (IMAP IDLE / Gmail Pub/Sub)")

    # status
    status_p = subparsers.add_parser("status", help="Show flow status summary")
    status_p.add_argument("--status", "-s", help="Filter by status")

    # config
    config_p = subparsers.add_parser("config", help="Validate configuration")
    config_p.add_argument("--validate", dest="path", nargs="?", const=None, help="Config file to validate")

    # secrets
    secrets_p = subparsers.add_parser("secrets", help="Manage secrets")
    secrets_sub = secrets_p.add_subparsers(dest="secrets_cmd")
    secrets_sub.add_parser("list", help="List secret keys")
    set_p = secrets_sub.add_parser("set", help="Set a secret")
    set_p.add_argument("key", help="Secret key name")
    del_p = secrets_sub.add_parser("delete", help="Delete a secret")
    del_p.add_argument("key", help="Secret key name")
    init_mk_p = secrets_sub.add_parser(
        "init-master-key",
        help="Generate + save the Fernet master key in the bootstrap store",
    )
    init_mk_p.add_argument(
        "--force", action="store_true",
        help="Overwrite an existing master key (DESTROYS all stored secrets)",
    )
    secrets_sub.add_parser(
        "migrate-from-bootstrap",
        help="Copy all keys from the bootstrap backend into the runtime "
             "DbSecrets store (one-shot migration from pre-DbSecrets setups)",
    )
    # N-267 R27 — CLI-user MSAL cache purge. Closes V_B orphan gap.
    purge_msal_p = secrets_sub.add_parser(
        "purge-msal-cache",
        help="Delete on-disk MSAL cache artifacts for a CLI username "
             "(§164.310(d)(2)(i) disposal). Routes through the "
             "per-user artifact registry so a NEW artifact family ships"
             " covered automatically.",
    )
    purge_msal_p.add_argument(
        "--username", required=True,
        help="The CLI OAuth username whose msal_cache_cli_<user>.json"
             " should be deleted.",
    )
    # N-349 hybrid (2026-07-05, operator directive): CLI-only one-shot
    # HMAC clobber bypass. See `web/db.py::HMAC_CLOBBER_BYPASS_KEY` for
    # the recovery contract. Env-flag DELIBERATELY NOT supported.
    _allow_hmac = secrets_sub.add_parser(
        "allow-hmac-clobber-once",
        help="Arm a ONE-SHOT bypass of the fail-CLOSED HMAC read policy "
             "on the ADMIN watch-SAVE flow (agent_api create + profile "
             "create/edit). The NEXT unreadable-row read triggered by "
             "an admin re-save mints a fresh HMAC secret + clears the "
             "flag. Receiver-side webhook signature-verify path is NOT "
             "covered; it stays fail-CLOSED (drops the webhook) — "
             "recovery for that path IS the admin re-save. Batch save: "
             "the FIRST unreadable watch in the batch consumes the "
             "flag; remaining unreadable watches in the same batch "
             "stay fail-CLOSED. Default TTL 15 minutes — use `--ttl-min` "
             "to override; use `secrets show-hmac-clobber-bypass` to "
             "check status. Recovery lever ONLY; NEVER used in "
             "steady state. Env-flag deliberately not supported.",
    )
    _allow_hmac.add_argument(
        "--ttl-min",
        type=int,
        default=None,
        help="TTL in minutes for the arm (default 15). Pass 0 for no "
             "expiry (operator explicit break-glass — accept until "
             "manually cleared or consumed).",
    )
    # N-364 R31 (2026-07-05 SME F6 + the backlog N-349b item 4):
    # observability sibling. Read-only status of the arm — supports the
    # "did I remember to arm / has it expired" audit sweep.
    secrets_sub.add_parser(
        "show-hmac-clobber-bypass",
        help="Report the current arm state of the HMAC clobber bypass. "
             "Prints ARMED / EXPIRED / NOT-armed + armed_at + expires_at "
             "when present. Read-only: never mutates the row.",
    )
    # N-320 R30 (task  tranche  DA follow-up; CLI-verb delivery
    # per operator ruling 2026-07-03). §164.308(a)(4)(ii)(A) rollback-
    # resurrection close.
    secrets_sub.add_parser(
        "purge-retired-keys",
        help="Delete every secret-key row named in `_secret_keys."
             "KEY_HISTORY` retired-tuples. Run this as part of the "
             "secret-rotation ceremony so a subsequent rollback can "
             "NOT silently resume reading a retired/compromised name "
             "(§164.308(a)(4)(ii)(A)). Idempotent — delete-missing = "
             "no-op. Emits an audit event via @_cli_audit(\"secrets\").",
    )
    rotate_p = secrets_sub.add_parser(
        "rotate-master-key",
        help="Re-encrypt every DbSecrets row with a new master key. "
             "STOP THE APP FIRST. Required by NIST SP 800-57 cryptoperiod "
             "guidance; recommended annually.",
    )
    rotate_p.add_argument(
        "--dry-run", action="store_true",
        help="Report what would be re-encrypted and exit without writing.",
    )
    rotate_p.add_argument(
        "--commit", action="store_true",
        help="Actually perform the rotation (required to proceed).",
    )
    rotate_p.add_argument(
        "--save-old-key-to",
        help="Write the outgoing master key to this path (mode 600). "
             "Disaster-recovery backup — delete when rotation is verified.",
    )

    # db — one-time plaintext<->SQLCipher migration for an EXISTING install
    #. New installs come up encrypted via init_db_encrypted;
    # this only converts a running plaintext triage.db and back (rollback).
    db_p = subparsers.add_parser(
        "db", help="One-time DB encrypt/decrypt migration (existing installs)"
    )
    db_sub = db_p.add_subparsers(dest="db_cmd")
    db_enc_p = db_sub.add_parser(
        "encrypt",
        help="Encrypt the existing plaintext triage.db to SQLCipher (STOP "
             "THE SERVICE FIRST). Derives the key from ET_MASTER_KEY, backs "
             "up the plaintext original, verifies before swapping.",
    )
    db_enc_p.add_argument("--db", help="DB path override (default: from config)")
    db_enc_p.add_argument(
        "--yes", action="store_true", help="Skip the confirmation prompt.",
    )
    db_dec_p = db_sub.add_parser(
        "decrypt",
        help="Decrypt a SQLCipher triage.db back to plaintext (rollback; "
             "STOP THE SERVICE FIRST).",
    )
    db_dec_p.add_argument("--db", help="DB path override (default: from config)")
    db_dec_p.add_argument(
        "--yes", action="store_true", help="Skip the confirmation prompt.",
    )

    # init
    init_p = subparsers.add_parser("init", help="Scaffold a new config")
    init_p.add_argument("path", nargs="?", help="Target directory")

    # apikey
    apikey_p = subparsers.add_parser("apikey", help="Manage API keys")
    apikey_sub = apikey_p.add_subparsers(dest="apikey_cmd")
    create_p = apikey_sub.add_parser("create", help="Create an API key")
    create_p.add_argument("--name", required=True, help="Key label (e.g. 'openclaw-host')")
    create_p.add_argument("--user", required=True, help="User email to associate key with")
    apikey_sub.add_parser("list", help="List all API keys")
    del_p = apikey_sub.add_parser("delete", help="Delete an API key")
    del_p.add_argument("key_id", type=int, help="API key ID to delete")

    # user
    user_p = subparsers.add_parser("user", help="Manage users")
    user_sub = user_p.add_subparsers(dest="user_cmd")
    ucreate_p = user_sub.add_parser("create", help="Create a user")
    ucreate_p.add_argument("--email", required=True, help="User email address")
    ucreate_p.add_argument("--name", help="Display name (default: email prefix)")
    ucreate_p.add_argument("--role", choices=["admin", "power_user", "user"], default="user", help="User role")
    user_sub.add_parser("list", help="List all users")

    # H-05 (Cycle 7) — MFA enrollment + recovery operator commands.
    # `enroll-mfa` issues a fresh code-set (operator drives first-admin
    # enrollment per Q7); `reset-mfa` issues a one-time recovery token
    # (last-resort path per Q5). Both wrapped via @_cli_audit("user")
    # so H-03-auto chain rows capture every invocation.
    enroll_mfa_p = user_sub.add_parser(
        "enroll-mfa",
        help="Issue recovery codes for a user (H-05; operator-driven "
             "first-admin enrollment per Q7)",
    )
    enroll_mfa_p.add_argument(
        "--email", required=True,
        help="Target user email",
    )
    enroll_mfa_p.add_argument(
        "--count", type=int, default=0,
        help="Number of codes to issue (default: 10; cap 100)",
    )
    reset_mfa_p = user_sub.add_parser(
        "reset-mfa",
        help="Issue a one-time operator-recovery token for a user "
             "(H-05 last-resort recovery; single-use, default 24h TTL)",
    )
    reset_mfa_p.add_argument(
        "--email", required=True,
        help="Target user email",
    )
    reset_mfa_p.add_argument(
        "--ttl-secs", type=int, default=0, dest="ttl_secs",
        help="Token TTL in seconds (default: 86400 = 24h; cap 604800 = 7d)",
    )
    # N-322 R30 (task  N-317 half-2 — persisted-key re-normalize
    # sweep). Approved by operator 2026-07-03.
    renorm_p = user_sub.add_parser(
        "re-normalize-emails",
        help="One-shot re-normalize persisted email columns "
             "(users.email, users.notify_email, "
             "email_accounts.aliases_json) through "
             "`canonical_email()`. Reports divergences; --apply "
             "actually rewrites. Idempotent. Runs post-N-317 IDN "
             "normalize to close persisted-key silent-invalidation "
             "surface DA flagged on tranche .",
    )
    renorm_p.add_argument(
        "--apply", action="store_true",
        help="Actually apply the rewrites. Default is dry-run (report "
             "only). Live-DB migration — recommend running against a "
             "backup restore FIRST to confirm the diff.",
    )

    # serve
    serve_p = subparsers.add_parser("serve", help="Start web UI")
    serve_p.add_argument("--host", default="0.0.0.0")
    serve_p.add_argument("--port", type=int, default=8080)
    serve_p.add_argument("--ssl-certfile", default="",
                         help="Path to TLS cert PEM (overrides config.tls.cert_dir)")
    serve_p.add_argument("--ssl-keyfile", default="",
                         help="Path to TLS key PEM (overrides config.tls.cert_dir)")

    # tls
    tls_p = subparsers.add_parser("tls", help="Manage internal TLS certs")
    tls_sub = tls_p.add_subparsers(dest="tls_cmd")

    tls_boot = tls_sub.add_parser(
        "bootstrap", help="Generate a self-signed cert + key",
    )
    tls_boot.add_argument("--cert-dir", default="",
                          help="Output dir (default: <data_dir>/certs)")
    tls_boot.add_argument("--hostname", default="localhost",
                          help="CN + first SAN entry")
    tls_boot.add_argument("--san", default="",
                          help="Comma-separated extra SANs (DNS or IP)")
    tls_boot.add_argument("--days", default="365",
                          help="Validity in days (default 365)")
    tls_boot.add_argument("--force", action="store_true",
                          help="Overwrite existing cert + key")

    tls_ts = tls_sub.add_parser(
        "fetch-tailscale",
        help="Fetch a real Let's Encrypt cert via the Tailscale daemon",
    )
    tls_ts.add_argument("--cert-dir", default="",
                        help="Output dir (default: <data_dir>/certs)")
    tls_ts.add_argument("--hostname", required=True,
                        help="<host>.<tailnet>.ts.net")
    tls_ts.add_argument("--tailscale-bin", default="tailscale",
                        help="Path to the tailscale binary")

    # restore — the backlog , inverse of /admin/backup export.
    # Decrypts a bundle (full or key-only) and writes the contents
    # to side-by-side .restore files. Operator does the swap-in
    # manually; CLI never starts/stops the service.
    backup_p = subparsers.add_parser(
        "backup", help="On-demand backup trigger",
    )
    backup_sub = backup_p.add_subparsers(dest="backup_cmd")
    backup_now_p = backup_sub.add_parser(
        "now", help="Trigger a backup now (via the loopback ops endpoint)",
    )
    backup_now_p.add_argument(
        "--format", choices=["etbk", "db"], default=None,
        help="Backup format (default: the server's backup.format config)",
    )
    backup_now_p.add_argument(
        "--wait", action="store_true",
        help="Block until the backup completes; exit non-zero on failure",
    )
    backup_sub.add_parser(
        "gen-keypair",
        help="Generate an X25519 keypair for public-key backup mode "
             "(public → config, private → off-box)",
    )

    restore_p = subparsers.add_parser(
        "restore",
        help="Restore an encrypted backup bundle",
    )
    restore_p.add_argument(
        "bundle",
        help="Path to the .etbk (full) or .etbkkey (key-only) bundle",
    )
    restore_p.add_argument(
        "--target-dir",
        default="",
        help="Where to write the .restore files "
             "(default: <data_dir from config>/.restore/)",
    )
    restore_p.add_argument(
        "--master-key-out",
        default="",
        help="Path the key-only bundle's raw master key gets written "
             "to. Required for key-only bundles. Refuses to default "
             "this path -- operator must declare where the key goes.",
    )
    restore_p.add_argument(
        "--passphrase-file",
        default="",
        help="Read the passphrase from this file instead of prompting "
             "via getpass (intended for scripted disaster-recovery).",
    )
    restore_p.add_argument(
        "--private-key",
        default="",
        help="Path to the off-box X25519 private key (PEM) for a "
             "public-key-sealed (ETBKP02) backup. Required to restore those; "
             "the passphrase is recovered from the unwrap, not prompted.",
    )
    restore_p.add_argument(
        "--list",
        action="store_true",
        help="Decode + print manifest only; do not extract any files",
    )
    restore_p.add_argument(
        "--commit",
        action="store_true",
        help="After extraction, swap .restore files into place. "
             "Refuses to run when the destination DB is locked "
             "(means the service is running). The CLI never "
             "starts/stops the service for you.",
    )
    restore_p.add_argument(
        "--force",
        action="store_true",
        help="Skip the 'restore from <hostname>?' and "
             "'destination has newer data?' confirmations. "
             "Scripted / disaster-recovery use only.",
    )

    # style-profile — M-3 distillation
    sp_p = subparsers.add_parser(
        "style-profile",
        help="Build/manage per-account derived writing-style profiles",
    )
    sp_sub = sp_p.add_subparsers(dest="style_profile_cmd")
    sp_build = sp_sub.add_parser(
        "build",
        help="Distil a writing-style profile from an account's Sent folder",
    )
    sp_build.add_argument(
        "--account", type=int, required=True,
        help="email_accounts.id to build the profile for",
    )
    sp_build.add_argument(
        "--limit", type=int, default=50,
        help="Number of recent sent messages to sample (default: 50)",
    )
    sp_build.add_argument(
        "--query", default="",
        help="Optional provider-specific search query override "
             "(default: 'in:sent' for gmail_api, 'ALL' for imap)",
    )

    # audit —  hash-chain integrity verifier (HIPAA §164.312(c)(1))
    audit_p = subparsers.add_parser(
        "audit",
        help="Audit / compliance helpers (verify log-chain integrity)",
    )
    audit_sub = audit_p.add_subparsers(dest="audit_cmd")
    av_p = audit_sub.add_parser(
        "verify",
        help="Walk log_entries and verify the tamper-evident hash chain",
    )
    av_p.add_argument(
        "--db",
        default="",
        help="Path to triage.db (default: load from config). Use to "
             "verify a backup snapshot without flipping the live install.",
    )
    av_p.add_argument(
        "--since",
        default="",
        help="ISO-8601 cutoff timestamp. Tolerates breaks at rows with "
             "ts < cutoff; only flags breaks at or after the cutoff. "
             "Default: full chain.",
    )
    av_p.add_argument(
        "--quiet",
        action="store_true",
        help="Print only PASS/FAIL + count/id; no per-row detail.",
    )

    # audit reconcile — H-11 EQM-04 PHI-tables-vs-audit-chain integrity
    # check. Closes the tooling-gap forward-stub disclosed in the
    # §164.312(c)(2) inline rationale at engine/store.py:79+.
    ar_p = audit_sub.add_parser(
        "reconcile",
        help="Walk PHI tables and cross-reference against the audit "
             "chain — surfaces direct-DB-write tampering (H-11/EQM-04)",
    )
    ar_p.add_argument(
        "--db",
        default="",
        help="Path to triage.db (default: load from config). Use to "
             "reconcile a backup snapshot without touching the live install.",
    )
    ar_p.add_argument(
        "--table",
        default="",
        help="Reconcile only this PHI table (default: every "
             "registered table). Currently registered: 'flows'.",
    )
    ar_p.add_argument(
        "--since",
        default="",
        help="ISO-8601 cutoff: skip audit rows older than this timestamp. "
             "Default: full chain.",
    )
    ar_p.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as a JSON object on stdout (for the monitoring system "
             "/ scripted callers). Default is a one-screen human summary.",
    )

    ar_p.add_argument(
        "--read-only",
        action="store_true",
        help="Open the DB in mode=ro; suppress the HIPAA-mode "
             "divergence-detected audit-event emit. Use against a "
             "backup snapshot when the reconcile must not write.",
    )

    # embedding-bits —  lazy-install runtime helper
    eb_p = subparsers.add_parser(
        "embedding-bits",
        help="Manage the lazy-install local embedding stack "
             "(torch + sentence-transformers + all-MiniLM-L6-v2)",
    )
    eb_sub = eb_p.add_subparsers(dest="embedding_bits_cmd")
    eb_install_p = eb_sub.add_parser(
        "install",
        help="Auto-download the embedding stack from the manifest "
             "URLs + hash-verify + pip-install. Same code path the "
             "admin UI's [Install now] button uses.",
    )
    eb_install_p.add_argument(
        "--target-dir", default="",
        help="Override the runtime-deps install dir (default: "
             "EMBEDDING_BITS_RUNTIME_DEPS env or /app/data/runtime-deps)",
    )
    eb_install_p.add_argument(
        "--manifest", default="",
        help="Override the manifest path (default: "
             "EMBEDDING_BITS_MANIFEST env or "
             "/app/scripts/embedding-bits-manifest.json)",
    )
    eb_sideload_p = eb_sub.add_parser(
        "sideload",
        help="Sideload from an operator-staged source dir (the "
             "extracted air-gap tarball). Same hash verification "
             "as auto-install.",
    )
    eb_sideload_p.add_argument(
        "--source-dir", required=True,
        help="Directory containing wheels/ + hf-cache/ subdirs "
             "(populated by scripts/download-embedding-bits.sh on a "
             "connected machine)",
    )
    eb_sideload_p.add_argument(
        "--target-dir", default="",
        help="Override the runtime-deps install dir (default: "
             "EMBEDDING_BITS_RUNTIME_DEPS env or /app/data/runtime-deps)",
    )
    eb_sideload_p.add_argument(
        "--manifest", default="",
        help="Override the manifest path",
    )
    eb_sub.add_parser(
        "verify",
        help="Re-hash on-disk files against the manifest. No "
             "download. Exits 0 on match, 1 on mismatch.",
    )
    eb_sub.add_parser(
        "status",
        help="Print the embedding_bits_install_state row + whether "
             "the runtime imports.",
    )

    # sent-mail-index — M-4 retrieval-augmented few-shot examples
    smi_p = subparsers.add_parser(
        "sent-mail-index",
        help="Build/manage the per-account vector index of sent mail "
             "(used by AI draft replies as few-shot examples)",
    )
    smi_sub = smi_p.add_subparsers(dest="sent_mail_index_cmd")
    smi_build = smi_sub.add_parser(
        "build",
        help="Index recent sent mail for the given account",
    )
    smi_build.add_argument(
        "--account", type=int, required=True,
        help="email_accounts.id to index",
    )
    smi_build.add_argument(
        "--limit", type=int, default=200,
        help="Number of recent sent messages to index (default: 200)",
    )

    # auth —  dev-keypair login wrapper
    auth_p = subparsers.add_parser(
        "auth",
        help="Auth helpers (dev-keypair login)",
    )
    auth_sub = auth_p.add_subparsers(dest="auth_cmd")
    devlogin_p = auth_sub.add_parser(
        "dev-login",
        help="Sign a /login/dev-keypair challenge with a local "
             "ed25519 private key and print the session cookie",
    )
    devlogin_p.add_argument("--email", required=True,
                            help="Login as this email (must be in the "
                                 "key's allowlist)")
    devlogin_p.add_argument("--key", required=True,
                            help="Path to ed25519 private key (e.g. "
                                 "~/.ssh/et-dev)")
    devlogin_p.add_argument("--server", required=True,
                            help="Base URL of the email-triage install "
                                 "(e.g. https://triage.example.com)")
    devlogin_p.add_argument(
        "--insecure", action="store_true",
        help="Disable TLS verification (self-signed dev only)",
    )

    # version-check —  partial. Operator tool that prints the
    # same status the /config banner renders. Three exit codes drive
    # scripted callers (the monitoring system, deploy.sh pre-flight): 0 up-to-date,
    # 1 update available, 2 incompatible-rollback (or downgrade).
    vc_p = subparsers.add_parser(
        "version-check",
        help="Print app version + schema-compat status for the live DB",
    )
    vc_p.add_argument(
        "--db",
        default="",
        help="Path to triage.db (default: load from config). Use to "
             "check a backup snapshot without flipping the live install.",
    )
    vc_p.add_argument(
        "--json",
        action="store_true",
        help="Emit the status as a JSON object on stdout (for the monitoring system "
             "/ scripted callers). Default is a one-line human "
             "summary.",
    )
    vc_p.add_argument(
        "--print-target-schema-only",
        action="store_true",
        dest="print_target_schema_only",
        help="Print only the running binary's target schema cap (a "
             "single integer) on stdout and exit 0. No DB read, no "
             "config load. Used by scripts/deploy.sh to extract the "
             "schema cap from the :previous image before swapping.",
    )
    vc_p.add_argument(
        "--verify-migrations",
        action="store_true",
        dest="verify_migrations",
        help="/N-85 deploy pre-flight: open a COPY of the live DB "
             "through THIS image's boot migration path (encryption-aware via "
             "the config + ET_MASTER_KEY secret) so an edited already-applied "
             "migration body (a checksum tamper-guard break) is caught "
             "PRE-SWAP. Exit 0 OK / 3 verify-failed (caller aborts) / 2 "
             "could-not-run (caller falls back to boot + /health rollback). "
             "Non-destructive: migrates a temp copy only, never the live DB.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows-safe console output (SSOT for the whole CLI). The default Windows
    # console encoding is cp1252, which CANNOT encode common non-ASCII output
    # (e.g. a `→` arrow, ✓/✗ marks) → a bare print() raises UnicodeEncodeError
    # and crashes the command MID-OUTPUT. `backup gen-keypair` did exactly this
    # on Windows: it printed its first ASCII line, then died on the `→` in its
    # guidance — before emitting the keys. Force stdout/stderr
    # to UTF-8 so non-ASCII output never crashes, regardless of host locale.
    # Guarded: a captured/redirected stream may not be a reconfigurable TextIO.
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        "run": cmd_run,
        "watch": cmd_watch,
        "status": cmd_status,
        "config": cmd_config_validate,
        "secrets": cmd_secrets,
        "apikey": cmd_apikey,
        "user": cmd_user,
        "init": cmd_init,
        "serve": cmd_serve,
        "tls": _cmd_tls_dispatch,
        "backup": cmd_backup,
        "restore": cmd_restore,
        "db": _cmd_db_dispatch,
        "auth": _cmd_auth_dispatch,
        "style-profile": cmd_style_profile,
        "audit": _cmd_audit_dispatch,
        "sent-mail-index": cmd_sent_mail_index,
        "version-check": cmd_version_check,
        "embedding-bits": _cmd_embedding_bits_dispatch,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except CliAuditGateClosed as e:
        # N-157 (2026-07-09) — DA fold Fix #1.  Surface the fail-loud gate
        # as a CLEAN CLI error on stderr — NOT a Python traceback.  The
        # exception message names `--allow-unaudited` as the recovery
        # lever verbatim (per the raise-site in _emit_cli_audit_event);
        # exit code 3 is dedicated to this class so an operator's shell
        # script can discriminate (rc=0 success, rc=1 usage, rc=2 handler
        # error, rc=3 audit-gate closed).
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
