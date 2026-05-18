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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from email_triage.config import (
    TriageConfig,
    load_config,
    validate_config,
)
from email_triage.triage_logging import get_logger, setup_logging
from email_triage._errfmt import fmt_exc

log = get_logger("cli")


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
    from email_triage.actions.invite import (
        AcceptInviteAction, DeclineInviteAction, TentativeInviteAction,
    )
    from email_triage.actions.label import LabelAction
    from email_triage.actions.move import MoveAction
    from email_triage.actions.notify import NotifyAction
    from email_triage.actions.registry import ActionRegistry
    from email_triage.actions.suggest_meeting_times import SuggestMeetingTimesAction
    from email_triage.engine.flow import FlowEngine
    from email_triage.engine.store import FlowStore

    # Store.
    db_path = Path(config.persistence.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
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
    registry.register(MoveAction())
    registry.register(AcceptInviteAction())
    registry.register(DeclineInviteAction())
    registry.register(TentativeInviteAction())
    registry.register(SuggestMeetingTimesAction())

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
        return Office365Provider(
            client_id=o365_cfg.get("client_id", ""),
            tenant_id=o365_cfg.get("tenant_id", "common"),
            client_secret=o365_cfg.get("client_secret", ""),
            token_cache_path=o365_cfg.get("token_cache_path", "./data/msal_cache.json"),
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
        return await engine.run_cycle(args.query, args.limit)

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

    try:
        asyncio.run(_watch())
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
                backoff = min(backoff * 2, max_backoff)

    try:
        asyncio.run(_watch_push())
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        asyncio.run(provider.close())
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
    print(f"  HIPAA mode: {config.logging.hipaa}")
    print(f"  Secrets backend: {config.secrets.backend}")
    return 0


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
    )
    from email_triage.web.db import init_db

    # init-master-key works at the bootstrap layer — before DbSecrets exists.
    if args.secrets_cmd == "init-master-key":
        bootstrap = create_secrets_provider(
            config.secrets.backend,
            keyfile_path=config.secrets.keyfile_path,
            external_config=config.secrets.external,
        )
        key_name = config.secrets.master_key_name
        existing = bootstrap.get(key_name)
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
    conn = init_db(config.persistence.db_path)
    try:
        provider = bootstrap_secrets_from_config(conn, config)
    except Exception as e:
        print(f"Could not open runtime secrets store: {e}")
        print(
            "If the master key is missing, run: "
            "'email-triage secrets init-master-key'"
        )
        return 1

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
        )
        key_name = config.secrets.master_key_name

        # Save the outgoing key before anything else — disaster recovery.
        old_key = bootstrap.require(key_name)
        new_key = DbSecrets.generate_master_key()

        if args.save_old_key_to:
            Path(args.save_old_key_to).write_text(old_key)
            os.chmod(args.save_old_key_to, 0o600)
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

        try:
            n = provider.rotate_master_key(new_key)
        except Exception as e:
            print(f"Rotation failed; DB rolled back, old key still valid. Error: {e}")
            return 1

        print(f"Re-encrypted {n} secret(s) with new master key.")

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
        )
        master_key_name = config.secrets.master_key_name
        migrated = 0
        skipped = 0
        for key in bootstrap.list_keys():
            if key == master_key_name:
                continue
            val = bootstrap.get(key)
            if val is None:
                skipped += 1
                continue
            provider.set(key, val)
            migrated += 1
            print(f"  migrated: {key}")
        print(f"Migrated {migrated} secret(s); skipped {skipped}.")
        return 0

    return 1


def cmd_apikey(args: argparse.Namespace) -> int:
    """Manage API keys."""
    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.web.db import init_db
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

    db = init_db(db_path)

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


def cmd_user(args: argparse.Namespace) -> int:
    """Manage users."""
    config = load_config(args.config)
    setup_logging(config.logging)

    from email_triage.web.db import init_db
    from email_triage.web.auth import get_user_by_email

    db_path = Path(config.persistence.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = init_db(db_path)

    if args.user_cmd == "create":
        existing = get_user_by_email(db, args.email)
        if existing:
            print(f"User already exists: {args.email} (role: {existing['role']})")
            db.close()
            return 1

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
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
        # with" gap (PUNCH-LIST #79). Without this, a renewed cert
        # sits on disk doing nothing until the next service restart.
        uv_config = uvicorn.Config(
            app, host=args.host, port=args.port,
            ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile,
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
                                    f"{type(exc).__name__}: {exc}",
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
        uvicorn.run(app, host=args.host, port=args.port)
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
    try:
        sniffed_type = backup_mod._sniff_bundle_type(bundle_bytes)
    except backup_mod.BundleFormatError as e:
        print(f"Not a valid email-triage bundle: {e}")
        return 1

    # Passphrase: file > getpass prompt. Never accept via flag.
    if args.passphrase_file:
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


def _cmd_embedding_bits_dispatch(args: argparse.Namespace) -> int:
    """Route ``embedding-bits <subcommand>`` to the right handler.

    #180 — operator-facing surface for the lazy embedding-stack
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


def _embedding_bits_open_db(args: argparse.Namespace) -> Any:
    """Open the configured DB + apply migrations. Used by every
    embedding-bits subcommand so install_state row reads are always
    against an up-to-date schema."""
    import sqlite3
    config = load_config(args.config)
    db_path = Path(config.persistence.db_path)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Run migrations so the install_state row exists even on a fresh
    # DB. Cheap on already-migrated installs.
    from email_triage.web.migrations import run_migrations
    run_migrations(conn)
    return conn


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


def cmd_embedding_bits_install(args: argparse.Namespace) -> int:
    """Run the auto-download installer synchronously."""
    import asyncio
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


def cmd_embedding_bits_sideload(args: argparse.Namespace) -> int:
    """Run the sideload installer synchronously."""
    import asyncio
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
    print("Usage: email-triage audit verify [--db PATH] [--since ISO] [--quiet]",
          file=sys.stderr)
    return 1


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify the ``log_entries`` hash chain integrity (#93).

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

    # Resolve DB path: --db override wins, else load from config.
    db_path: Path
    if args.db:
        db_path = Path(args.db).expanduser().resolve()
    else:
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"Could not load config: {e}", file=sys.stderr)
            return 2
        db_path = Path(config.persistence.db_path)

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 2

    # Read-only connection: ``mode=ro`` keeps the verifier from
    # accidentally creating a new file or mutating the live DB.
    try:
        conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as e:
        print(f"Could not open {db_path}: {e}", file=sys.stderr)
        return 2

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


def cmd_version_check(args: argparse.Namespace) -> int:
    """``email-triage version-check`` — schema-compat status (#125 partial).

    Operator tool that prints the same status the /config admin banner
    renders, so SSH-only operators (sudo podman exec ... version-check)
    can drive their update decision without browser access.

    Exit codes are designed for scripted callers (Nagios, the future
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
    first" cases on purpose: a Nagios check can fire on >= 2 and treat
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

    config_file.write_text("""\
# Email Triage Configuration
# See the project README for documentation.

provider:
  type: gmail_api              # gmail_api | imap | office365

classifier:
  backend: ollama              # ollama | openai | gemini
  model: [local-llm-model]
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
  backend: env                 # container | keyfile | keyring | env

persistence:
  db_path: ./data/triage.db
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
        get_email_account, init_db, set_style_profile,
    )

    db = init_db(config.persistence.db_path)
    try:
        secrets = bootstrap_secrets_from_config(db, config)
    except Exception as e:
        print(f"Could not open runtime secrets store: {e}")
        return 1

    acct = get_email_account(db, args.account)
    if acct is None:
        print(f"Account #{args.account} not found.")
        return 1

    # Default per-provider Sent-folder search query. Operators can
    # override via --query when the install uses non-default folder
    # names. Gmail uses query syntax; IMAP uses RFC 3501 search;
    # Office365 uses a Graph $filter. Routes through the traits
    # registry (#138.2) so the default lives in one place.
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
            rows = db.execute(
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
        profile = await extract_style_profile(
            messages, classifier,
            captured_message_ids=captured_ids,
        )
        set_style_profile(db, args.account, profile.to_dict())

        print(
            f"Style profile built for account #{args.account} "
            f"(owner={acct.get('owner_email', '?')}) — "
            f"{profile.sample_count} messages, model={profile.model_used}, "
            f"formality={profile.formality}/5.",
        )
        return 0

    try:
        return asyncio.run(_run())
    finally:
        try:
            asyncio.run(provider.close())
        except Exception:
            pass


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
    from email_triage.web.db import get_email_account, init_db

    db = init_db(config.persistence.db_path)
    try:
        secrets = bootstrap_secrets_from_config(db, config)
    except Exception as e:
        print(f"Could not open runtime secrets store: {e}")
        return 1

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

    embed_model = (
        getattr(config.classifier, "embedding_model", None)
        or "nomic-embed-text"
    )
    base_url = (
        getattr(config.classifier, "base_url", None)
        or "http://localhost:11434"
    ).rstrip("/")

    class _OllamaEmbedShim:
        backend_type = "ollama"

        async def embed_text(self, text: str) -> list[float]:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{base_url}/api/embeddings",
                    json={"model": embed_model, "prompt": text},
                )
                resp.raise_for_status()
                body = resp.json() or {}
            vec = body.get("embedding") or []
            return [float(x) for x in vec]

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

    try:
        return asyncio.run(_run())
    finally:
        try:
            asyncio.run(provider.close())
        except Exception:
            pass


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
    from pathlib import Path

    import httpx

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

    with httpx.Client(verify=verify, follow_redirects=False) as client:
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
        pad = "=" * (-len(challenge_b64) % 4)
        challenge = base64.urlsafe_b64decode(challenge_b64 + pad)
        signature = priv.sign(challenge)
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-triage",
        description="Portable email triage with LLM classification",
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to config file (default: search standard paths)",
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

    # restore — punch-list #65, inverse of /admin/backup export.
    # Decrypts a bundle (full or key-only) and writes the contents
    # to side-by-side .restore files. Operator does the swap-in
    # manually; CLI never starts/stops the service.
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

    # audit — #93 hash-chain integrity verifier (HIPAA §164.312(c)(1))
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

    # embedding-bits — #180 lazy-install runtime helper
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

    # auth — #67 dev-keypair login wrapper
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

    # version-check — #125 partial. Operator tool that prints the
    # same status the /config banner renders. Three exit codes drive
    # scripted callers (Nagios, deploy.sh pre-flight): 0 up-to-date,
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
        help="Emit the status as a JSON object on stdout (for Nagios "
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

    return parser


def main(argv: list[str] | None = None) -> int:
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
        "restore": cmd_restore,
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

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
