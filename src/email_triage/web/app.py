"""FastAPI application for the email triage web interface.

Server-rendered UI with HTMX for dynamic interactions, Pico CSS for
classless styling.  No JavaScript build step.

Auth: passwordless email OTP (6-digit code, 10-minute expiry).
Roles: admin, power_user, user.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from email_triage.config import TriageConfig, load_config
from email_triage.secrets import SecretsProvider, create_secrets_provider
from email_triage.triage_logging import get_logger, setup_logging
from email_triage.web.db import init_db, seed_categories
from email_triage.web import settings_keys as _settings_keys
from email_triage._errfmt import fmt_exc
from email_triage._isotime import parse_iso

log = get_logger("web.app")

_WEB_DIR = Path(__file__).parent
_TEMPLATE_DIR = _WEB_DIR / "templates"
_STATIC_DIR = _WEB_DIR / "static"


def _resolve_version() -> str:
    """Resolve a short build identifier for the ``/health`` endpoint.

    Preference order:
        1. ``EMAIL_TRIAGE_VERSION`` env var (runtime override — ad-hoc
           testing, manual deploys, CI injection)
        2. ``GIT_SHA`` env var (common CI convention)
        3. ``/app/VERSION`` file baked in at container build time by
           the Containerfile (``COPY COMMIT /app/VERSION``). The deploy
           script writes ``git rev-parse HEAD`` into the ``COMMIT`` file
           in the build context before ``podman build``.
        4. ``.git/HEAD`` walked to a commit sha (first 7 chars) — dev
           checkout fallback.
        5. ``"unknown"``

    Resolved once at startup; the health endpoint reads the cached
    value from ``app.state.version`` and never shells out.
    """
    for key in ("EMAIL_TRIAGE_VERSION", "GIT_SHA"):
        val = os.environ.get(key, "").strip()
        if val:
            return val[:40]  # defensive cap — short sha is 7, full is 40

    # Baked-in build identifier — container image path.
    try:
        with open("/app/VERSION", encoding="utf-8") as f:
            v = f.read().strip()
    except OSError:
        v = ""
    # Treat the placeholder "dev" / "unknown" sentinels — and an UNSUBSTITUTED
    # ``$Format:%H$`` export-subst literal (a working-tree / non-``git archive``
    # build where the .gitattributes substitution never ran) — as "no baked
    # value" so local dev checkouts still fall through to the .git/HEAD walk.
    if v and v not in {"dev", "unknown"} and not v.startswith("$Format"):
        return v[:40]

    # Walk from this file up to find a .git directory or file.
    # Bounded by filesystem root to avoid infinite loops.
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        candidate = parent / ".git"
        if not candidate.exists():
            continue
        try:
            if candidate.is_file():
                # Worktree layout — ``.git`` is a file: "gitdir: <path>".
                first_line = candidate.read_text(encoding="utf-8").splitlines()[0]
                if first_line.startswith("gitdir:"):
                    gitdir = Path(first_line.split(":", 1)[1].strip())
                    if not gitdir.is_absolute():
                        gitdir = (parent / gitdir).resolve()
                else:
                    break
            else:
                gitdir = candidate

            head_file = gitdir / "HEAD"
            if not head_file.is_file():
                break
            head = head_file.read_text(encoding="utf-8").strip()
            if head.startswith("ref:"):
                ref = head.split(" ", 1)[1].strip()
                # Check packed refs first, then loose.
                loose = gitdir / ref
                if loose.is_file():
                    sha = loose.read_text(encoding="utf-8").strip()
                    if sha:
                        return sha[:7]
                # Try commondir (worktree shares objects + packed-refs).
                commondir_file = gitdir / "commondir"
                if commondir_file.is_file():
                    common = Path(commondir_file.read_text(encoding="utf-8").strip())
                    if not common.is_absolute():
                        common = (gitdir / common).resolve()
                    packed = common / "packed-refs"
                    loose_shared = common / ref
                    if loose_shared.is_file():
                        sha = loose_shared.read_text(encoding="utf-8").strip()
                        if sha:
                            return sha[:7]
                    if packed.is_file():
                        for line in packed.read_text(encoding="utf-8").splitlines():
                            if line.startswith("#") or line.startswith("^"):
                                continue
                            parts = line.split()
                            if len(parts) == 2 and parts[1] == ref:
                                return parts[0][:7]
                # Fall through to unknown.
                break
            else:
                # Detached HEAD — the file contains the sha directly.
                if head:
                    return head[:7]
        except Exception:
            break
        break

    return "unknown"


def _acct_log_extras(acct: dict) -> dict:
    """Return owner + account identifiers for structured logs.

    Always emits ``account_name``, ``owner_name`` (or ``owner_email`` as
    fallback), and ``account_id``. Operators identify accounts by
    name/owner; the id is a tiebreaker when names collide. Never log
    account_id alone — admins can't look it up.

    Splat into any log call where ``acct`` (from
    ``get_email_account`` / ``list_email_accounts``) is in scope.

    HIPAA: ``acct["name"]`` and owner identifiers are workforce-member
    identifiers (the operator of the mailbox), not patient data. Safe
    to log on any account. Message-level PHI (sender, subject, body)
    is handled separately by the logger's ``_PHI_KEYS`` scrubber.
    """
    out = {
        "account_name": acct.get("name", ""),
        "account_id": acct["id"],
    }
    owner_name = acct.get("owner_name") or ""
    owner_email = acct.get("owner_email") or ""
    if owner_name:
        out["owner"] = owner_name
    elif owner_email:
        out["owner"] = owner_email
    return out


# ---------------------------------------------------------------------------
# Watcher Manager — manages per-account IMAP IDLE background tasks
# ---------------------------------------------------------------------------



async def _resolve_hwm_with_uidvalidity(
    provider: Any,
    account_id: int,
    mailbox: str,
    hwm_data: dict | None,
) -> tuple[int, int | None]:
    """Resolve the effective starting UID for a mailbox, guarding a
    UIDVALIDITY change.

    IMAP UIDs are monotonic only within a UIDVALIDITY epoch. If the
    server bumped UIDVALIDITY (mailbox recreated, index rebuild), the
    stored high-water mark's UID space no longer exists — trusting it
    would silently drop every "new" message whose reused UID is <= the
    stale mark. On a mismatch this returns 0 so the caller re-seeds to
    the current latest UID.

    Returns ``(effective_uid, live_uidvalidity)``. ``live_uidvalidity``
    is ``None`` for providers that don't expose it (Gmail/O365) or when
    the server reported none — in which case no reset happens.
    """
    stored_uid = int((hwm_data or {}).get("uid", 0))
    stored_uidvalidity = (hwm_data or {}).get("uidvalidity")
    live_uidvalidity: int | None = None
    if hasattr(provider, "get_uidvalidity"):
        try:
            live_uidvalidity = await provider.get_uidvalidity()
        except Exception as e:
            log.warning(
                "Could not read mailbox UIDVALIDITY; skipping HWM guard",
                account_id=account_id, mailbox=mailbox, error=fmt_exc(e),
            )
    if (
        stored_uid
        and stored_uidvalidity is not None
        and live_uidvalidity is not None
        and int(stored_uidvalidity) != int(live_uidvalidity)
    ):
        log.warning(
            "IMAP UIDVALIDITY changed — resetting mailbox high-water "
            "mark; mailbox will be re-seeded to current latest",
            account_id=account_id, mailbox=mailbox,
            stored_uidvalidity=stored_uidvalidity,
            live_uidvalidity=live_uidvalidity,
        )
        return 0, live_uidvalidity
    return stored_uid, live_uidvalidity




def create_app(config: TriageConfig | None = None) -> FastAPI:
    """Build and return the FastAPI application.

    Accepts an optional config for testing.  When *None*, config is
    loaded from the standard search paths at startup.
    """
    if config is None:
        config = load_config()
    setup_logging(config.logging)

    db_path = Path(config.persistence.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        #  — every direct DB touch in this lifespan body is marked
        # ``async-db-ok``: lifespan runs ONCE at startup, before the
        # ASGI server accepts any request and before any background
        # task or db_call worker exists. There is no event-loop
        # contention to serialise against — these migrations / seeds /
        # one-time backfills run strictly single-threaded.
        #
        # v0.1.2 single-file encryption — encrypted-boot ordering.
        # Bootstrap order (documented per plan §4.4):
        #   (a) read the master key from the bootstrap secrets backend
        #       (env/keyfile/container/keyring/external) — NOT from the
        #       DB, so there is no chicken-and-egg with the encrypted
        #       file;
        #   (b) resolve + enforce the fail-closed encryption contract:
        #       HIPAA mode + encryption requested + (missing sqlcipher3
        #       OR missing master key) => RuntimeError, never a silent
        #       plaintext fallback (§164.312(a)(2)(iv));
        #   (c) open the DB encrypted (init_db_encrypted, which applies
        #       PRAGMA key as the first SQL) or plaintext (init_db);
        #   (d) DbSecrets wraps the now-decryptable secrets_store table
        #       (further down, reusing the master key read in step (a)).
        from email_triage.db._engine import enforce_db_encryption_boot_contract
        from email_triage.secrets import read_bootstrap_master_key
        from email_triage.web.db import init_db_encrypted

        # (a) Best-effort master-key read. ANY failure here is non-fatal
        # AT THIS POINT — we deliberately swallow it so that:
        #   * the plaintext path falls through to the canonical
        #     ``bootstrap_secrets_from_config`` site below, which re-reads
        #     and surfaces SecretNotFound / ImportError with the
        #     operator-friendly logging exactly as before this Phase 4
        #     change (no behavior change for existing installs);
        #   * the encrypted path's fail-closed contract (step b) converts
        #     a missing/unreadable key into a hard RuntimeError rather
        #     than silently opening plaintext.
        # ``master_key_available`` for the contract is simply "did we get
        # a usable key here", so a broad catch is correct.
        _boot_master_key: str | None = None
        try:
            _boot_master_key = read_bootstrap_master_key(config)
        except Exception:
            _boot_master_key = None

        # (b) Decide + enforce the boot DB mode.
        _open_encrypted = enforce_db_encryption_boot_contract(
            config, master_key_available=_boot_master_key is not None
        )

        # N-17: stamp the process-level context the  dedicated-conn
        # openers (audit-chain log handler, acme_jobs writer,  write-
        # lock conn) + the version banner read consult. They open their OWN
        # connections on this same DB file; without this they did a raw
        # plaintext sqlite3.connect and could not open an encrypted file.
        # Stamped HERE, once, right after the boot decision + key read, so
        # the openers self-select encrypted-vs-plaintext like the main conn.
        from email_triage.db._engine import set_dedicated_conn_encryption
        set_dedicated_conn_encryption(
            encrypted=_open_encrypted,
            master_key=_boot_master_key,
        )

        # (c) Open the DB. Both branches run strictly single-threaded at
        # lifespan startup before any worker exists — same safety as the
        # pre-Phase-4 plain init_db(db_path) touch this replaces.
        if _open_encrypted:
            log.info("Opening encrypted database (SQLCipher single-file)")
            # async-db-ok: lifespan startup, single-threaded
            conn = init_db_encrypted(db_path, _boot_master_key)  # type: ignore[arg-type]
        else:
            # async-db-ok: lifespan startup, single-threaded
            conn = init_db(db_path)
        #  — open the process-wide singleton lock_conn now,
        # before any background loop / db_call worker exists. The
        # alternative is the pre-#288 shape: open-then-close a
        # dedicated lock_conn on EVERY ``acquire_db_lock`` /
        # ``renew_db_lock`` call, which produced dozens of fresh
        # writer-connection lifecycles against the same WAL file at
        # container startup and drove the SQLITE_MISUSE / cursor-
        # state-corruption cascade catalogued live on the test container
        # (2026-05-25). For ``:memory:`` / in-memory DBs the
        # singleton is unused — each in-memory DB needs the
        # caller's own connection. ``init_lock_conn`` no-ops on the
        # in-memory path (returns the singleton if already set,
        # opens a new one otherwise; for ``:memory:`` we just don't
        # call it — the file-path resolver returns None and the
        # ``_open_lock_conn`` in-memory branch reuses the shared
        # connection as before).
        from email_triage.single_flight import init_lock_conn as _init_lock_conn
        from email_triage.single_flight import _resolve_db_path as _resolve_dbp
        # async-db-ok: lifespan startup, single-threaded
        _dbp = _resolve_dbp(conn)
        if _dbp:
            _init_lock_conn(_dbp)  # async-db-ok: lifespan startup
        # Per-user personal categories migration -- runs before
        # seeding so seed_categories writes into the new schema.
        from email_triage.web.db import ensure_categories_user_id_migration
        if ensure_categories_user_id_migration(conn):  # async-db-ok
            log.info("Migrated categories table to per-user schema")
        # Seed categories from YAML on first run.
        seeded = seed_categories(conn, config.classifier.categories)  # async-db-ok
        if seeded:
            log.info("Seeded categories from config", count=seeded)
        # Top up newer phases' system categories on existing installs.
        from email_triage.web.db import ensure_upgrade_categories
        added = ensure_upgrade_categories(conn)  # async-db-ok
        if added:
            log.info("Inserted upgrade categories", count=added)

        # One-time backfill — restore newsletter render_as on
        # legacy-migrated digest configs. The 2026-05-05
        # digest_configs migration silently mapped legacy
        # `digest_schedules:<id>` rows into custom DigestConfigs
        # with render_as="grouped_list", losing the LLM-extracted
        # article-card rendering the original scheduler produced.
        # Restored as a render_as option (commits this batch);
        # this backfill flips category-newsletter configs to use
        # the restored format. Idempotent — only flips configs
        # currently on grouped_list / plain_list (preserves any
        # operator-set explicit choice).
        try:
            from email_triage.actions.digest_configs import (
                _backfill_newsletter_render_as,
            )
            flipped = _backfill_newsletter_render_as(conn)  # async-db-ok: lifespan startup
            if flipped:
                log.info(
                    "Backfilled newsletter render_as on legacy configs",
                    count=flipped,
                )
        except Exception as e:
            log.warning(
                "Newsletter render_as backfill failed",
                error=fmt_exc(e),
            )

        # (d) Build the runtime secrets provider: DbSecrets wraps the
        # now-readable secrets_store table. Reuse the master key read in
        # step (a) above (``_boot_master_key``) when present — avoids a
        # redundant bootstrap-backend read on the encrypted path. When it
        # is None (plaintext path + the master key genuinely missing),
        # ``bootstrap_secrets_from_config`` re-reads and surfaces
        # SecretNotFound with the operator-friendly message below,
        # exactly as before this Phase 4 change.
        from email_triage.secrets import (
            bootstrap_secrets_from_config,
            SecretNotFound,
        )
        try:
            secrets = bootstrap_secrets_from_config(
                conn, config, master_key=_boot_master_key
            )
        except SecretNotFound as e:
            log.error(
                "Master key not found in bootstrap store. "
                "Generate one and add it via: "
                "'email-triage secrets init-master-key'",
                missing_key=e.key, backend=e.backend,
            )
            raise
        except ImportError as e:
            log.error("Cryptography package required for DbSecrets", error=fmt_exc(e))
            raise

        app.state.db = conn
        app.state.config = config
        app.state.secrets = secrets
        app.state.started_at = time.monotonic()
        app.state.version = _resolve_version()

        # v0.1.2 single-file encryption  — single-writer-thread serializer.
        # Phase-3 cutover (N-13, 2026-06-02): the Phase-2 A/B flag
        # (EMAIL_TRIAGE_WRITER_BACKEND_ENABLED) has been REMOVED — the writer
        # thread now starts UNCONDITIONALLY on container start (a restart, never
        # a hot flag-flip, which would race an in-flight RLock holder against a
        # freshly-started writer on the same connection). ALL @db_write helpers
        # route through it (db_call); the legacy  RLock path remains only as
        # the fallback when no writer is installed (unit tests). Validated by a
        # 43h clean encrypted+writer-on production soak (0 locks, 0 sheds, 0
        # restarts) before the flag removal.
        from email_triage.db._writer import (
            SqliteWriterThread,
            set_writer,
        )
        _writer = SqliteWriterThread()
        _writer.start()
        set_writer(_writer)
        app.state.db_writer = _writer
        log.info("db-writer thread started")

        # H-02a (Cycle 6, 2026-05-23): G1' boot-time enforcement of
        # master-key at-rest protection + audit-chain HMAC wiring.
        # Both helpers live in secrets.py; see their docstrings for the
        # regulatory framing + threat model. They MUST run BEFORE any
        # log emit that would write a chain row (the SQLiteLogHandler
        # hot path D1-fail-closes RuntimeError on every emit without
        # the registry populated).
        from email_triage.secrets import (
            enforce_master_key_at_rest_for_hipaa,
            wire_audit_chain_hmac_keys,
        )
        enforce_master_key_at_rest_for_hipaa(config)
        wire_audit_chain_hmac_keys(secrets, config)

        # H-04-flag (Cycle 7, 2026-05-24) — defense-in-depth
        # Transmission Security boot-enforcement. Closes EQM-03 GAP g3
        # (operator-deployment-discipline assumption). Mirrors the
        # G1' shape above: HIPAA-mode-only; non-HIPAA is a no-op.
        # ``bind_host`` is plumbed from ``cmd_serve`` via
        # ``app.state.bind_host`` (set right after ``create_app()`` so
        # this lifespan reaches it). Empty string = fail-closed
        # "treat as public-routable" per the helper docstring.
        from email_triage.web.transmission_security import (
            enforce_transmission_security_for_hipaa,
        )
        enforce_transmission_security_for_hipaa(
            config,
            bind_host=str(getattr(app.state, "bind_host", "") or ""),
        )

        #  -- capture the listener mode the uvicorn socket actually
        # bound at boot. Operator-facing surfaces compare this to the
        # current saved value to flag "you flipped the toggle but the
        # running listener is still on the old protocol." The boot
        # value is FROZEN here -- never re-read from config later, or
        # the chip would mask drift the moment the operator hits Save.
        app.state.tls_boot_mode = bool(getattr(config.tls, "enabled", False))

        #  -- bind the ACME job-state module to this process's
        # SQLite connection so the singleton write-throughs land on
        # disk. ``acme_jobs`` survives process restarts; the supervised
        # worker scans non-terminal rows on boot and decides
        # resume / cancel per the resume-policy table.
        try:
            from email_triage.web import acme_job_state
            acme_job_state.set_db_handle(conn)
            try:
                #  — ``resume_on_startup`` does a synchronous
                # SQLite scan of non-terminal ACME job rows. Run it off
                # the event loop so a slow scan does not stall lifespan
                # startup (and, with it, the readiness of the whole app).
                resolved = await asyncio.to_thread(
                    acme_job_state.resume_on_startup
                )
                if resolved:
                    log.info(
                        "ACME: resolved %d in-flight job(s) on startup",
                        len(resolved),
                    )
            except Exception as e:
                log.warning(
                    "ACME: resume_on_startup raised; continuing",
                    error=fmt_exc(e),
                )
        except Exception as e:
            log.warning(
                "ACME: set_db_handle binding failed; using RAM-only state",
                error=fmt_exc(e),
            )

        # Persistent session_secret. Pre-PR-9.5 the secret was a
        # module-level random in dependencies.py, regenerated on every
        # process start -- which meant every container restart kicked
        # everyone out (existing cookies' signatures stopped
        # validating). Now: read from the secrets store, generate +
        # store on first run only. Sessions survive deploys + restarts
        # bounded only by their TTL.
        existing_session_secret = secrets.get("session_secret")
        if not existing_session_secret:
            import secrets as _stdlib_secrets
            existing_session_secret = _stdlib_secrets.token_hex(32)
            secrets.set("session_secret", existing_session_secret)
            log.info("session_secret minted + stored in secrets store")
        app.state.session_secret = existing_session_secret

        # PR 8 / D1 follow-up: CSRF enforcement gate.
        # Two surfaces, env var wins:
        #   1. tls.csrf_enforce in YAML (operator-edited via UI).
        #   2. EMAIL_TRIAGE_CSRF_ENFORCE env var (truthy = enforce).
        # The env var wins so an operator who's debugging "CSRF is
        # rejecting my form" can flip it off without touching YAML +
        # waiting for a save round-trip.
        _env_csrf = (
            os.environ.get("EMAIL_TRIAGE_CSRF_ENFORCE", "")
            .strip().lower()
        )
        if _env_csrf in ("1", "true", "yes", "on"):
            app.state.csrf_enforce = True
        elif _env_csrf in ("0", "false", "no", "off"):
            app.state.csrf_enforce = False
        else:
            app.state.csrf_enforce = bool(
                getattr(config.tls, "csrf_enforce", False)
            )

        #  item 4 — operator-defined CSRF exempt path prefixes.
        # Stored on app.state so a /admin/security save can refresh
        # without a restart. The middleware reads this on every
        # request.
        app.state.csrf_extra_exempt_prefixes = list(
            getattr(config.tls, "csrf_exempt_prefixes", []) or [],
        )

        # M-4 scaffold: probe the sqlite-vec extension at startup so
        # the rest of the codebase can gate vector-search code paths
        # on a single boolean. Missing extension = M-4 retrieval
        # falls back to an in-memory cosine over the rows in
        # ``sent_mail_index`` (degrades gracefully -- the install
        # still works, retrieval is just slower for accounts with a
        # very large sent-mail backlog).
        #
        # The probe runs on the live ``conn``; sqlite3's
        # ``enable_load_extension`` is opt-in (compile-time flag on
        # the python-sqlite3 module). On Windows + on most distros'
        # default Python the flag is OFF, in which case the probe
        # exits via the AttributeError branch and leaves
        # ``sqlite_vec_available`` False. That is the expected,
        # supported behaviour for an install that hasn't installed
        # the extension.
        app.state.sqlite_vec_available = False
        try:
            import sqlite_vec  # type: ignore
            try:
                conn.enable_load_extension(True)
                sqlite_vec.load(conn)
                conn.enable_load_extension(False)
                app.state.sqlite_vec_available = True
                log.info("sqlite-vec extension loaded (M-4 retrieval enabled)")
            except (AttributeError, Exception) as e:
                # AttributeError: this Python's sqlite3 was built
                # without ``--enable-loadable-sqlite-extensions``.
                # OperationalError: extension binary present but the
                # SQLite library refused to load it. Either way the
                # feature degrades to the in-memory fallback path.
                log.info(
                    "sqlite-vec not loaded; M-4 retrieval will use "
                    "in-memory fallback",
                    error=type(e).__name__,
                )
        except ImportError:
            # Package not installed at all. M-4 is opt-in; this is
            # not an install-broken condition.
            log.info(
                "sqlite-vec package not installed; M-4 retrieval "
                "falls back to in-memory cosine",
            )

        # M-5: build the embedding backend that the draft-reply
        # prompt builder feeds to ``SentMailIndex.retrieve_similar``.
        # ``build_embedding_backend`` returns None when the operator
        # hasn't configured ``embedding:`` in YAML; the draft-reply
        # path treats absence as "RAG retrieval skipped" (one-time
        # INFO log) without blocking M-1+M-2 / M-3 layers.
        #
        # Non-allowlist backends raise ValueError at construction
        # (anthropic / openai / etc.). We let the error propagate
        # so a misconfigured YAML surfaces at boot rather than the
        # first draft-reply call.
        app.state.embedding_backend = None
        app.state.embedding_model = ""
        try:
            from email_triage.engine.embedding_backend import (
                build_embedding_backend,
            )
            backend = build_embedding_backend(config)
            if backend is not None:
                app.state.embedding_backend = backend
                app.state.embedding_model = (
                    getattr(config.embedding, "model_name", "") or ""
                )
                log.info(
                    "Embedding backend configured (M-5 RAG enabled)",
                    backend_type=getattr(backend, "backend_type", ""),
                    model=app.state.embedding_model,
                )
            else:
                log.info(
                    "No embedding backend configured; "
                    "M-5 RAG retrieval will be skipped at draft time",
                )
        except ValueError as e:
            # Non-local backend in YAML. Re-raise so the operator
            # sees it at boot, not at the first draft-reply call.
            log.error(
                "Embedding backend rejected by allowlist", error=str(e),
            )
            raise

        # Hydrate the soft-launch reject counter from log_entries so
        # the /health surface reflects cumulative state, not just
        # since-last-restart. Process-local counter is still
        # the live source of truth -- this just primes it.
        #
        # Operator can baseline-reset the counter without touching the
        # historical log_entries by setting the ``csrf_count_since``
        # setting to an ISO timestamp; hydration only counts entries
        # newer than that. Useful for "I addressed the historical
        # rejections, give me a clean slate to monitor on" without
        # losing the audit trail.
        try:
            from email_triage.web.db import get_setting
            baseline = (get_setting(conn, "csrf_count_since") or "").strip()  # async-db-ok: lifespan startup
            if baseline:
                row = conn.execute(  # async-db-ok: lifespan startup
                    "SELECT COUNT(*) AS n FROM log_entries "
                    "WHERE logger = 'email_triage.web.csrf' "
                    "AND message LIKE 'CSRF token%' "
                    "AND created_at > ?",
                    (baseline,),
                ).fetchone()
            else:
                row = conn.execute(  # async-db-ok: lifespan startup
                    "SELECT COUNT(*) AS n FROM log_entries "
                    "WHERE logger = 'email_triage.web.csrf' "
                    "AND message LIKE 'CSRF token%'",
                ).fetchone()
            app.state.csrf_rejects = int(row["n"]) if row else 0
        except Exception:
            app.state.csrf_rejects = 0

        # One-shot migration: lift any per-account Gmail OAuth creds
        # up to the install-level secrets store. Pre-B1 installs kept
        # client_id/client_secret per-account; B1 centralises them.
        from email_triage.web.db import (
            migrate_oauth_creds_to_install_level,
            migrate_o365_creds_to_install_level,
        )
        found = migrate_oauth_creds_to_install_level(conn)  # async-db-ok: lifespan startup
        if found is not None:
            cid, csec = found
            # Only seed the Web-app slot if it's currently empty; respect
            # any value the admin has already entered via /config.
            if not secrets.get("GOOGLE_OAUTH_WEB_CLIENT_ID"):
                secrets.set("GOOGLE_OAUTH_WEB_CLIENT_ID", cid)
                secrets.set("GOOGLE_OAUTH_WEB_CLIENT_SECRET", csec)
                log.warning(
                    "Migrated per-account Gmail OAuth creds to install-level "
                    "(Web-app slot). Verify at /config — retype in the "
                    "Desktop slot if that's the flow you intended.",
                )

        # Parallel migration for Office 365: lifts per-account
        # client_id/tenant_id from config_json + first non-empty
        # ACCOUNT_*_O365_SECRET from the secrets store to install-level.
        o365_found = migrate_o365_creds_to_install_level(conn, secrets)  # async-db-ok: lifespan startup
        if o365_found is not None:
            tid, cid, csec = o365_found
            if tid and not secrets.get("O365_OAUTH_TENANT_ID"):
                secrets.set("O365_OAUTH_TENANT_ID", tid)
            if cid and not secrets.get("O365_OAUTH_CLIENT_ID"):
                secrets.set("O365_OAUTH_CLIENT_ID", cid)
            if csec and not secrets.get("O365_OAUTH_CLIENT_SECRET"):
                secrets.set("O365_OAUTH_CLIENT_SECRET", csec)
            log.warning(
                "Migrated per-account Office 365 OAuth creds to install-level. "
                "Verify at /config — if accounts had different Azure tenants, "
                "only one was kept and the others will need their probe to be "
                "rerun after editing the install tenant.",
            )

        # Hydrate config.google_oauth from the secrets store so the
        # rest of the app can read it as plain attributes. Empty
        # strings when unset — callers must check before use.
        config.google_oauth.web_client_id = secrets.get("GOOGLE_OAUTH_WEB_CLIENT_ID") or ""
        config.google_oauth.web_client_secret = secrets.get("GOOGLE_OAUTH_WEB_CLIENT_SECRET") or ""
        config.google_oauth.desktop_client_id = secrets.get("GOOGLE_OAUTH_DESKTOP_CLIENT_ID") or ""
        config.google_oauth.desktop_client_secret = secrets.get("GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET") or ""

        # Sibling hydration for the install-level Office 365 OAuth creds.
        config.office365_oauth.tenant_id = secrets.get("O365_OAUTH_TENANT_ID") or ""
        config.office365_oauth.client_id = secrets.get("O365_OAUTH_CLIENT_ID") or ""
        config.office365_oauth.client_secret = secrets.get("O365_OAUTH_CLIENT_SECRET") or ""

        # Register the install-level OAuth creds with the provider
        # factory (module-level singleton — read by every provider
        # construction site without parameter threading).
        from email_triage.web.routers.ui import (
            set_install_google_oauth, set_install_ingestion_config,
            set_install_office365_oauth,
        )
        set_install_google_oauth(config.google_oauth)
        set_install_office365_oauth(config.office365_oauth)
        set_install_ingestion_config(config.ingestion)

        #  — install-level optional classification cache. Empty URL
        # returns None (no behaviour change). Lazy connect: nothing
        # actually talks to Redis until the first lookup.
        try:
            from email_triage.cache.classification import (
                build_cache_from_config, set_install_classification_cache,
            )
            set_install_classification_cache(
                build_cache_from_config(getattr(config, "redis_cache", None)),
            )
        except Exception as _cache_init_err:
            # Best-effort — don't block startup on a cache build hiccup.
            from email_triage._errfmt import fmt_exc as _fmt
            log.warning(
                "Classification cache init failed; cache disabled",
                error=_fmt(_cache_init_err),
            )

        # 2026-05-13 — persistent counter backend. Mirrors cache /
        # embedding / webhook counter increments to Redis so the
        # lifetime totals survive container restarts. Reuses the
        # same Redis URL the cache uses — no second URL field for
        # the operator to manage. Empty cache URL = persistence
        # disabled (process-local counters keep working unchanged).
        try:
            from email_triage.engine.persistent_counters import (
                build_counter_backend_from_config,
                set_install_counter_backend,
            )
            set_install_counter_backend(
                build_counter_backend_from_config(
                    getattr(config, "redis_cache", None),
                ),
            )
        except Exception as _pc_err:
            from email_triage._errfmt import fmt_exc as _fmt
            log.warning(
                "Persistent counter backend init failed; counters stay process-local",
                error=_fmt(_pc_err),
            )

        # Enable SQLite logging so admin log viewer works.
        from email_triage.triage_logging import add_sqlite_handler
        add_sqlite_handler(conn)  # async-db-ok: lifespan startup

        #  (hipaa-sme condition 2) — now that the §164.312(b) audit-
        # chain handler is attached, re-emit the HIPAA-mode-plaintext
        # advisory through it so "operator ran plaintext under HIPAA mode"
        # becomes a tamper-evident log_entries row (the earlier emit at
        # the boot-contract gate predates this handler and is console/file
        # only). Same message text via the shared constant.
        from email_triage.db._engine import (
            hipaa_plaintext_advisory_applies,
            HIPAA_PLAINTEXT_ADVISORY,
        )
        if hipaa_plaintext_advisory_applies(config):
            log.warning(HIPAA_PLAINTEXT_ADVISORY)

        # One-shot log_entries prune on boot — bounds the table after
        # every restart so a crash-loop or long offline stretch can't
        # leave a decade of rows hanging around.
        from email_triage.web.db import prune_log_entries_by_age_and_count
        try:
            _pruned = prune_log_entries_by_age_and_count(  # async-db-ok: lifespan startup
                conn,
                retention_days=config.logging.retention_days,
                max_rows=config.logging.max_rows,
            )
            if _pruned:
                log.info(
                    "Pruned log_entries on startup",
                    deleted=_pruned,
                    retention_days=config.logging.retention_days,
                    max_rows=config.logging.max_rows,
                )
        except Exception as e:
            log.error("Startup log_entries prune failed", error=fmt_exc(e))

        # Restore runtime settings (dry-run, log level, HIPAA) from DB.
        from email_triage.web.db import get_setting
        _rt_settings = get_setting(conn, "runtime_settings")  # async-db-ok: lifespan startup
        if _rt_settings:
            import logging as stdlib_logging
            from email_triage import triage_logging
            level_name = _rt_settings.get("log_level", "INFO").upper()
            root_logger = stdlib_logging.getLogger("email_triage")
            root_logger.setLevel(getattr(stdlib_logging, level_name, stdlib_logging.INFO))
            # Bundle E5  / Q4 — BOOT-TIME EXCEPTION to the
            # _apply_runtime_settings caller-intent gate. This lifespan
            # restore is the canonical "DB-as-source-of-truth across
            # restarts" replay; the kwarg-gate in
            # web/routers/ui/_shared.py:_apply_runtime_settings is for
            # POST-BOOT mutation attempts only. We write directly to
            # the module-global here so the Sub-check D test ("exactly
            # one source location passes allow_hipaa_change=True")
            # keeps its tight invariant — admin_security_save remains
            # the SOLE post-boot caller of the gate.
            triage_logging._hipaa_mode = _rt_settings.get("hipaa", False)
            log.info(
                "Runtime settings restored from DB",
                dry_run=_rt_settings.get("dry_run", False),
                log_level=level_name,
                hipaa=_rt_settings.get("hipaa", False),
            )

        # Startup mode breadcrumbs — one line each, in increasing severity.
        # Intentionally terse; the full picture is in /config and /compliance.
        from email_triage.triage_logging import is_hipaa_mode
        _system_hipaa = is_hipaa_mode()
        if _system_hipaa:
            log.info("Starting in HIPAA mode (system-wide)")

        # For DEBUG logs, set Python log level via standard config
        # (LOG_LEVEL env var, /admin runtime settings, or
        # logging.dictConfig) — there is no longer a YAML toggle.

        # Record a boundary event if the system HIPAA state has changed
        # since the last recorded system-scope boundary.  This keeps the
        # log viewer's "before/after" dividers accurate across restarts
        # and captures the effective state at each startup.
        from email_triage.web.db import (
            latest_hipaa_boundary, record_hipaa_boundary,
        )
        _last = latest_hipaa_boundary(conn, "system")  # async-db-ok: lifespan startup
        _last_direction = _last["direction"] if _last else "off"
        _current_direction = "on" if _system_hipaa else "off"
        if _last_direction != _current_direction:
            record_hipaa_boundary(  # async-db-ok: lifespan startup
                conn, "system", _current_direction,
                actor_id=None, reason="startup",
            )

        log.info("Web UI started", db_path=str(db_path))

        # Instantiate the Gmail push queue + consumer support state
        # before spawning supervised tasks (factories close over
        # app.state.push_queue, so it must exist first).
        app.state.push_queue = asyncio.Queue(maxsize=256)
        app.state.metrics = getattr(app.state, "metrics", {})

        # Outbound event dispatcher — used by the triage.completed
        # emitter from manual, watcher, push and OpenClaw API call sites.
        from email_triage.web.events import EventDispatcher
        app.state.event_dispatcher = EventDispatcher(
            targets=getattr(config, "webhooks", []) or [],
            secrets_provider=secrets,
            allow_external=getattr(config, "webhooks_allow_external", False),
            local_url_suffixes=list(
                getattr(config.tls, "local_url_suffixes", []) or [],
            ),
        )

        # Background-task supervisor (PR 2 / A3). Replaces the
        # bare-asyncio.create_task pattern with crash detection +
        # bounded restart + circuit breaker. Each task runs inside a
        # fresh request_id context so its log lines correlate.
        from email_triage.web.task_supervisor import TaskSupervisor
        supervisor = TaskSupervisor()
        app.state.supervisor = supervisor
        # NOTE: there is no legacy "digest-scheduler" cron task. The
        # 2026-05-05 multi-digest refactor (Phase 4) introduced
        # "recipient-digest-sender" below, which fully subsumes it:
        # list_digest_configs migrates every legacy digest_schedules
        # row into the unified digest_configs store and
        # _recipient_digest_sender fires both preset + custom digests.
        # The entire legacy digest_schedules subsystem -- the cron
        # functions, _run_scheduled_digest, and the orphaned CRUD UI
        # in web/routers/ui/digests.py -- was removed in  + .
        supervisor.supervise(
            "gmail-push-consumer", lambda: _gmail_push_consumer(app),
        )
        supervisor.supervise(
            "gmail-watch-renewer", lambda: _gmail_watch_renewer(app),
        )
        # O365 / Microsoft Graph subscription renewer.
        # Cron-anchored hourly sweep; refreshes any subscription whose
        # expiration_at falls within the configured window
        # (push.office365_subscription_renewal_window_hours, default 24h).
        # Subscriptions expire after ~3 days otherwise — without this loop
        # the push pipeline silently dies one window after enable.
        from email_triage.web.o365_renewer import (
            _o365_subscription_renewer_loop,
        )
        supervisor.supervise(
            "o365-subscription-renewer",
            lambda: _o365_subscription_renewer_loop(app),
        )
        # ACME (Let's Encrypt) cert auto-renewal. Before this the
        # renewer was dead code: ``renewal_loop`` had ZERO callers, so a
        # cert issued once via the admin "Issue Now" button silently
        # expired ~90 days later. Ticks every
        # ``config.tls.acme.check_interval_hours`` (default 24h);
        # lease-gated because an LE order burns a rate slot. Also drains
        # the ``resume_pending`` ACME job rows that
        # ``resume_on_startup`` stamps. Runs even when acme.enabled is
        # false — each tick just no-ops the skip path — so flipping the
        # toggle on later needs no restart.
        from email_triage.web.acme_renewer import acme_cert_renewer
        supervisor.supervise(
            "acme-cert-renewer",
            lambda: acme_cert_renewer(app),
        )
        # Unified push + poll ingestion loop: one tick every 60 s
        # evaluates every account across every provider; dispatches a
        # provider-specific one-shot poll for any account whose
        # ``poll_interval_minutes`` has elapsed. Acts as safety net when
        # push is on and primary ingestion when push is off.
        supervisor.supervise(
            "unified-poll-loop", lambda: _unified_poll_loop(app),
        )
        supervisor.supervise(
            "log-entries-pruner", lambda: _log_entries_prune_loop(app),
        )
        # PR 9 / D3 — HIPAA boundary drift detector.
        supervisor.supervise(
            "hipaa-boundary-drift-detector",
            lambda: _hipaa_boundary_drift_detector(app),
        )
        # Daily health email sender. Same cadence pattern as the
        # digest scheduler: ticks once a minute and fires when wall-clock
        # crosses ``config.health_email.send_at``.
        supervisor.supervise(
            "daily-health-email-sender",
            lambda: _daily_health_email_sender(app),
        )
        # Per-recipient per-account daily digest. Owner opt-in via the
        # account-edit form; ticks once a minute and fires when the
        # configured ``HH:10`` bucket matches.
        supervisor.supervise(
            "recipient-digest-sender",
            lambda: _recipient_digest_sender(app),
        )
        # Background whole-mailbox triage queue drainer. Runs
        # one job at a time under operator-tunable rate-limit +
        # concurrency knobs. The first thing this task does on
        # startup is requeue any 'running' rows orphaned by a
        # process restart.
        from email_triage.web.triage_runner_bulk import bulk_triage_runner
        supervisor.supervise(
            "bulk-triage-runner",
            lambda: bulk_triage_runner(app),
        )
        # M-6 edit-feedback capture loop. Cron-anchored every
        # ``style_learning.capture_interval_hours`` hours (default 6).
        # Scans Sent folders on opted-in non-HIPAA accounts for
        # AI-drafted-then-edited messages and writes captured pairs
        # into ``sent_mail_index`` for higher-weighted M-4 retrieval
        # + M-3 distillation.
        supervisor.supervise(
            "sent-mail-capture-loop",
            lambda: _sent_mail_capture_loop(app),
        )
        #  Wave 2-α I7 — daily BAA expiry sweep + auto-disable
        # for HIPAA accounts. Tick once per hour; the sweep itself
        # is idempotent so running it more often than needed is
        # safe + cheap.
        supervisor.supervise(
            "baa-expiry-daily-sweep",
            lambda: _baa_expiry_sweeper(app),
        )

        #  Wave 3 — daily GC sweep for per-contact HIPAA style
        # descriptors. Drops rows older than 90 days since last
        # distill (operator likely stopped emailing that contact).
        # Tick once per day; idempotent.
        supervisor.supervise(
            "per-contact-style-gc-daily-sweep",
            lambda: _per_contact_style_gc_sweeper(app),
        )

        # -B — M-3 + M-7 trigger watcher. Ticks every 15 minutes;
        # evaluates first-time + threshold + stale triggers on every
        # eligible HIPAA-opted-in account + per-contact pair, enqueues
        # rows on ``style_distill_queue`` / ``style_distill_queue_contacts``
        # for the existing worker to drain. Idempotent across ticks
        # (already-queued rows skip; no new sends → no work).
        supervisor.supervise(
            "style-distill-trigger-sweeper",
            lambda: _style_distill_trigger_sweeper(app),
        )

        # -215 — the single consolidated retry-queue drainer.
        # Ticks every 30s; per tick it caps exhausted rows to dead,
        # skips llm_unreachable rows while the LLM breaker is open,
        # and for every other due row re-fetches the message and runs
        # the FULL triage path (classify + route + ACT). Lease-gated
        # so exactly one instance drains per tick.
        supervisor.supervise(
            "watcher-retry-sweeper",
            lambda: _watcher_retry_sweeper(app),
        )

        # Start the watcher manager and restore previously-enabled watchers.
        watcher_mgr = WatcherManager(app)
        app.state.watcher_manager = watcher_mgr
        #  — isolate watcher restore from startup. A failure here
        # (a bad account config, a provider import error) must NOT
        # stop the app booting: an exception would skip the `yield`,
        # the app would never serve, and the already-spawned
        # supervised tasks + the DB connection would leak. The web UI
        # and supervised loops still come up; the operator can
        # re-enable watchers from the Accounts page.
        try:
            await watcher_mgr.restore_from_settings()
        except Exception as _restore_exc:
            log.error(
                "Watcher restore failed at startup; app starting "
                "without restored watchers",
                error=fmt_exc(_restore_exc),
            )

        yield

        # Shutdown: stop watchers first, then supervised tasks.
        await watcher_mgr.stop_all()
        await supervisor.stop_all()

        # Drain long-lived httpx clients introduced by . Each
        # close() is best-effort + idempotent — surface any error in
        # the log but never block shutdown on a stuck pool.
        try:
            await app.state.event_dispatcher.aclose()
        except Exception as e:
            log.warning("event_dispatcher aclose failed",
                        error=fmt_exc(e))
        try:
            from email_triage.web import watch_runner as _wr
            await _wr.aclose_module()
        except Exception as e:
            log.warning("watch_runner aclose failed", error=fmt_exc(e))
        try:
            cert_cache = getattr(app.state, "_gmail_cert_cache", None)
            if cert_cache is not None:
                await cert_cache.aclose()
        except Exception as e:
            log.warning("gmail_cert_cache aclose failed",
                        error=fmt_exc(e))
        try:
            backend = getattr(app.state, "embedding_backend", None)
            if backend is not None and hasattr(backend, "close"):
                await backend.close()
        except Exception as e:
            log.warning("embedding_backend close failed",
                        error=fmt_exc(e))
        try:
            classifier = getattr(app.state, "classifier", None)
            if classifier is not None and hasattr(classifier, "close"):
                await classifier.close()
        except Exception as e:
            log.warning("classifier close failed", error=fmt_exc(e))

        # v0.1.2  Phase 2 — drain + stop the writer thread BEFORE the
        # connection closes, so any queued writes flush against a live
        # conn. Idempotent + best-effort; a stuck writer must not block
        # shutdown (10s join bound inside shutdown()).
        try:
            from email_triage.db._writer import get_writer, set_writer

            _writer = get_writer()
            if _writer is not None:
                await _writer.shutdown()
                set_writer(None)
        except Exception as e:
            log.warning("db-writer shutdown failed", error=fmt_exc(e))

        conn.close()
        log.info("Web UI stopped")

    app = FastAPI(
        title="Email Triage",
        lifespan=lifespan,
    )

    # Access-audit middleware). Records every
    # authenticated request hitting a PHI-touch route prefix. Mounted
    # before any routes so it sees the response status from downstream
    # handlers.
    from email_triage.web.access_audit import (
        AccessAuditMiddleware,
        RequestIdMiddleware,
    )
    from email_triage.web.csrf import CsrfMiddleware
    app.add_middleware(AccessAuditMiddleware)
    # CSRF middleware (PR 8 / D1). Enforce-by-default as of 
    # (2026-05-10). Violations return HTTP 403. Operator can opt out
    # via ``tls: { csrf_enforce: false }`` in YAML or the
    # ``EMAIL_TRIAGE_CSRF_ENFORCE=0`` env var (env wins). When
    # disabled, violations still log + bump ``app.state.csrf_rejects``
    # so the operator can size + verify before re-enabling.
    app.add_middleware(CsrfMiddleware)
    # Request-ID middleware MUST be the outermost (added LAST in
    # FastAPI's onion model = executed FIRST on inbound). Otherwise
    # the audit middleware wouldn't see request.state.request_id and
    # the access_log row would land without a correlation ID.
    app.add_middleware(RequestIdMiddleware)

    # Static files
    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Templates
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    # Server-side CSRF input renderer — closes the JS-shim race where
    # cached /api/csrf-token fetch hadn't returned before a plain
    # HTML form submitted. See web/csrf.py:csrf_input docstring.
    from email_triage.web.csrf import csrf_input as _csrf_input
    templates.env.globals["csrf_input"] = _csrf_input
    # App semver — surfaced in the base-template footer on every page.
    from email_triage import __version__ as _app_version
    templates.env.globals["app_version"] = _app_version
    app.state.templates = templates

    # Register routers
    from email_triage.web.routers.ui import router as ui_router
    from email_triage.web.routers.api import router as api_router
    from email_triage.web.routers.webhooks import router as webhook_router
    from email_triage.web.routers.openclaw import router as openclaw_router
    from email_triage.web.routers.health import router as health_router
    #  — auth-surface upgrade routes (dev-keypair admin + login,
    # WebAuthn registration + login, ACME diagnostic test buttons).
    from email_triage.web.routers.auth_keys import router as auth_keys_router
    # External-integrations admin (Gmail Pub/Sub config + watch state).
    from email_triage.web.routers.integrations import (
        router as integrations_router,
    )
    # Backup export (admin-driven; pure-py module + CLI restore inverse).
    from email_triage.web.routers.backup import router as backup_router
    # Manual TLS CSR / sign / import workflow for institutional CAs.
    from email_triage.web.routers.tls_csr import router as tls_csr_router
    # End-user how-to runbook. Anonymous access — non-PHI.
    from email_triage.web.routers.help import router as help_router

    # Health probe is UNAUTHENTICATED by design — container HEALTHCHECK
    # and external monitors must be able to hit it without creds.  It
    # is mounted at the top level (no auth dependency on this router).
    app.include_router(health_router)
    app.include_router(ui_router)
    app.include_router(auth_keys_router)
    app.include_router(integrations_router)
    app.include_router(backup_router)
    app.include_router(tls_csr_router)
    app.include_router(help_router)
    app.include_router(api_router, prefix="/api")
    app.include_router(openclaw_router)
    app.include_router(webhook_router)

    _register_auth_error_handler(app)

    return app


# Statuses the auth/ownership deps raise (``dependencies.py`` —
# ``get_current_user``, ``require_role``, the ``OwnedAccount`` family).
# A browser hitting an owned-account 403/404 page used to get FastAPI's
# bare ``{"detail": "..."}`` JSON rendered as plain text — the
# ``dependencies.py`` docstrings promised a "global error handler [that]
# renders the operator-facing HTML or JSON wrapper depending on Accept"
# but no such handler was ever registered.
_AUTH_ERROR_STATUSES = frozenset({401, 403, 404})

_AUTH_ERROR_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {title}</title>
<style>
 body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif;
   background:#f6f7f9; color:#1c2530; margin:0;
   display:flex; align-items:center; justify-content:center;
   min-height:100vh; }}
 .card {{ background:#fff; border:1px solid #e3e6ea; border-radius:10px;
   padding:2.2rem 2.6rem; max-width:30rem; box-shadow:0 1px 3px rgba(0,0,0,.06); }}
 h1 {{ margin:0 0 .3rem; font-size:2.6rem; }}
 h2 {{ margin:0 0 .8rem; font-size:1.1rem; font-weight:600; }}
 p  {{ margin:0 0 1rem; line-height:1.5; color:#48535f; }}
 a  {{ color:#2563eb; text-decoration:none; }}
 a:hover {{ text-decoration:underline; }}
</style></head><body>
<div class="card">
 <h1>{code}</h1>
 <h2>{title}</h2>
 <p>{detail}</p>
 <p><a href="/">Return to the dashboard</a></p>
</div></body></html>
"""

_AUTH_ERROR_TITLES = {
    401: "Sign-in required",
    403: "Access denied",
    404: "Not found",
}


def _wants_html(request: Request) -> bool:
    """True when the caller looks like a browser navigation, not an API client.

    An ``/api/`` path or an ``Accept`` header that prefers JSON over
    HTML is treated as an API client and keeps the JSON error body.
    """
    if request.url.path.startswith("/api/"):
        return False
    accept = request.headers.get("accept", "")
    # A browser navigation sends ``text/html`` ahead of ``*/*``; an
    # API client sends ``application/json`` or nothing meaningful.
    if "application/json" in accept and "text/html" not in accept:
        return False
    return "text/html" in accept or "*/*" in accept


def _register_auth_error_handler(app: FastAPI) -> None:
    """Register the Accept-aware 401/403/404 handler the deps assume.

    Browsers get a small self-contained HTML page; API clients keep
    FastAPI's default ``{"detail": ...}`` JSON shape. Statuses outside
    401/403/404 fall through to FastAPI's built-in handler unchanged.

    The handler is registered for Starlette's ``HTTPException`` (the
    base class) rather than FastAPI's subclass, so it also covers the
    framework-raised 404 for an unknown route — not only the
    deps-raised 401/403/404.
    """
    from starlette.exceptions import HTTPException as StarletteHTTPException
    from fastapi.exception_handlers import http_exception_handler
    from fastapi.responses import HTMLResponse

    import html as _html_mod

    @app.exception_handler(StarletteHTTPException)
    async def _auth_error_handler(
        request: Request, exc: StarletteHTTPException,
    ):
        if exc.status_code in _AUTH_ERROR_STATUSES and _wants_html(request):
            title = _AUTH_ERROR_TITLES.get(exc.status_code, "Error")
            detail = exc.detail if isinstance(exc.detail, str) else title
            # HTML-escape every interpolated value. The detail strings
            # the auth deps raise are static today, but ``HTTPException``
            # detail is caller-controlled in general — escaping closes
            # any reflected-XSS path if user input ever reaches it.
            html = _AUTH_ERROR_PAGE.format(
                code=int(exc.status_code),
                title=_html_mod.escape(title),
                detail=_html_mod.escape(detail),
            )
            return HTMLResponse(
                html, status_code=exc.status_code, headers=exc.headers,
            )
        # API client, or a status this handler does not own — defer to
        # FastAPI's default JSON handler.
        return await http_exception_handler(request, exc)

    # v0.1.2 single-file encryption  — map writer-thread backpressure to HTTP 503.
    # When the single-writer queue saturates, ``submit_write`` raises
    # ``WriterQueueFull`` (a RuntimeError subclass) rather than blocking
    # the event loop. Without this handler that surfaces as an unhandled
    # 500; the contract (per _writer.py docstrings + the  eff501b
    # 503-tolerance posture) is a fast-loud 503 so the caller / load
    # balancer can retry or shed. The writer backend is default-OFF in
    # v0.1.2, but this mapping must be correct NOW so it holds the moment
    # Phase 6 flips the flag ON.
    from email_triage.db._writer import WriterQueueFull
    from fastapi.responses import JSONResponse

    @app.exception_handler(WriterQueueFull)
    async def _writer_queue_full_handler(
        request: Request, exc: WriterQueueFull,
    ):
        # 503 + Retry-After: transient saturation, retry is appropriate.
        return JSONResponse(
            {"detail": "Database writer is saturated; retry shortly."},
            status_code=503,
            headers={"Retry-After": "1"},
        )


def get_db(request: Request) -> sqlite3.Connection:
    """Retrieve the shared database connection from app state."""
    return request.app.state.db


def get_request_accounts(
    request: Request,
    *,
    user_id: int | None = None,
    include_delegated: bool = True,
) -> list[dict]:
    """Memoised per-request ``list_email_accounts``.

    Several handlers + their helpers each called ``list_email_accounts``
    independently inside a single request render — 2-3 calls per page on
    /accounts, /logs, /stats, etc. This helper caches the lookup on
    ``request.state`` so the second + subsequent calls within the same
    request reuse the result.

    The cache key is ``(user_id, include_delegated)`` because admin views
    pass ``user_id=None`` while user-scoped views pass an id; both shapes
    can co-exist in the same render (admin viewing their own row alongside
    the all-accounts list, etc.).
    """
    from email_triage.web.db import list_email_accounts
    cache: dict = getattr(request.state, "_accounts_cache", None)
    if cache is None:
        cache = {}
        try:
            request.state._accounts_cache = cache
        except Exception:
            # ``request.state`` is normally settable; if a test stub
            # rejects it, fall through to the no-cache path.
            return list_email_accounts(
                request.app.state.db,
                user_id=user_id,
                include_delegated=include_delegated,
            )
    key = (user_id, include_delegated)
    if key not in cache:
        cache[key] = list_email_accounts(
            request.app.state.db,
            user_id=user_id,
            include_delegated=include_delegated,
        )
    return cache[key]


def get_templates(request: Request) -> Jinja2Templates:
    """Retrieve the Jinja2 templates from app state."""
    return request.app.state.templates


def get_config(request: Request) -> TriageConfig:
    """Retrieve the triage config from app state."""
    return request.app.state.config


def get_secrets(request: Request) -> SecretsProvider:
    """Retrieve the secrets provider from app state."""
    return request.app.state.secrets


def get_watcher_manager(request: Request) -> WatcherManager:
    """Retrieve the watcher manager from app state."""
    return request.app.state.watcher_manager


# ---------------------------------------------------------------------------
# Listener-mode restart detection
# ---------------------------------------------------------------------------

def is_listener_restart_pending(app: FastAPI) -> bool:
    """Return True when the saved ``tls.enabled`` differs from the value
    the uvicorn listener bound at process boot.

    Set on first lifespan tick from ``config.tls.enabled``; never
    re-read after that. Comparing the FROZEN boot value to the LIVE
    config catches "operator flipped the toggle, hit Save, but the
    in-process socket is still serving the old protocol." The flag
    auto-clears on the next process restart, so no manual reset is
    needed -- ``systemctl restart email-triage`` makes the chip go
    away on its own.

    The comparison is intentionally a strict bool() vs bool() so a
    None / unset config field reads as False on both sides (i.e.
    "still off" rather than "drift detected").
    """
    boot_mode = getattr(app.state, "tls_boot_mode", None)
    if boot_mode is None:
        # State not initialised (test harness skipped lifespan, etc.).
        # Be conservative: no chip rather than a false positive.
        return False
    cfg = getattr(app.state, "config", None)
    if cfg is None:
        return False
    saved_mode = bool(getattr(cfg.tls, "enabled", False))
    return bool(boot_mode) != saved_mode


# ---------------------------------------------------------------------------
# Gmail push consumer + watch renewal
# ---------------------------------------------------------------------------





# ``settings`` row that records the calendar day the daily-health
# email last fired on. Persisting it (rather than an ``app.state``
# field) makes the "already sent today" guard survive a process
# restart AND a lease handoff between instances — without it, when
# leadership moves to another instance inside the send_at minute the
# new leader has a fresh in-memory guard and double-sends.


def _maybe_mark_auth_stale(db, acct: dict, err: Exception) -> None:
    """Detect OAuth refresh-token death and persist a per-account flag.

    Triggered by any provider exception whose message matches the
    Google "Token has been expired or revoked" / "invalid_grant"
    signatures or the IMAP / Graph "AUTHENTICATIONFAILED" /
    "InvalidAuthenticationToken" patterns. Cleared from the same
    setting key on the next successful provider call (see the success
    paths in the watcher loops).
    """
    try:
        msg = str(err) or ""
    except Exception:
        return
    needles = (
        "Token has been expired or revoked",
        "invalid_grant",
        "AUTHENTICATIONFAILED",
        "InvalidAuthenticationToken",
        "Invalid Credentials",
    )
    if not any(n in msg for n in needles):
        return
    try:
        from email_triage.web.db import set_setting
        from datetime import datetime, timezone
        set_setting(db, _settings_keys.auth_stale(acct["id"]), {
            "at": datetime.now(timezone.utc).isoformat(),
            "reason": msg[:300],
        })
        log.warning(
            "Account auth flagged stale — re-authentication required",
            **_acct_log_extras(acct), reason=msg[:200],
        )
    except Exception:
        pass


def _clear_auth_stale(db, account_id: int) -> None:
    """Clear the stale-auth flag on a successful provider call."""
    try:
        # Use the public helper so the in-process settings cache
        # is invalidated alongside the DB delete.
        from email_triage.web.db import delete_setting
        delete_setting(db, _settings_keys.auth_stale(account_id))
    except Exception:
        pass


async def _log_entries_prune_loop(app: FastAPI) -> None:
    """Periodically trim ``log_entries`` by age + row count.

    Cadence mirrors the watch renewer (every 30 min) — frequent enough
    that a log storm can't grow the table unchecked, but cheap: one
    DELETE against an indexed primary key.
    """
    from email_triage.web.db import (
        prune_log_entries_by_age_and_count,
        prune_push_deliveries,
        prune_triage_runs,
        prune_triaged_messages,
    )
    from email_triage.web.task_supervisor import supervised_interval_loop
    #  — these prune helpers are @db_write so a direct sync call is
    # correctness-safe, but it runs the DELETE on the EVENT-LOOP thread
    # and blocks the loop on the RLock whenever a db_call worker holds
    # it. Route every prune through db_call so it runs off the loop.
    from email_triage.web.db_threadpool import db_call

    async def _tick() -> None:
        db = app.state.db
        cfg = app.state.config
        deleted = await db_call(
            prune_log_entries_by_age_and_count,
            db,
            retention_days=cfg.logging.retention_days,
            max_rows=cfg.logging.max_rows,
        )
        if deleted:
            log.info(
                "Pruned log_entries",
                deleted=deleted,
                retention_days=cfg.logging.retention_days,
                max_rows=cfg.logging.max_rows,
            )
        # Loop-prevention dedup table: trim rows older than 90d. 90d is
        # far past any plausible cascade window (real cascades re-fire
        # within seconds) but bounded so the table can't grow unbounded
        # across years. Best-effort — must not block the other prunes.
        try:
            tr_deleted = await db_call(
                prune_triaged_messages, db, retention_days=90,
            )
            if tr_deleted:
                log.info("Pruned triaged_messages dedup rows",
                         deleted=tr_deleted, retention_days=90)
        except Exception as e2:
            log.warning("triaged_messages prune failed", error=str(e2))
        #  — push-delivery counter table: trim rows older than 90d.
        # /admin/stats renders only a rolling 14-day window so 90d is
        # generous for ad-hoc operator inspection.
        try:
            pd_deleted = await db_call(
                prune_push_deliveries, db, keep_days=90,
            )
            if pd_deleted:
                log.info("Pruned push_deliveries counter rows",
                         deleted=pd_deleted, keep_days=90)
        except Exception as e3:
            log.warning("push_deliveries prune failed", error=str(e3))
        #  — triage_runs (one row per completed inline run) had no
        # retention job and grew unbounded. Trim rows older than 90d on
        # the same cadence as the other prunes; best-effort.
        try:
            run_deleted = await db_call(
                prune_triage_runs, db, retention_days=90,
            )
            if run_deleted:
                log.info("Pruned triage_runs rows",
                         deleted=run_deleted, retention_days=90)
        except Exception as e4:
            log.warning("triage_runs prune failed", error=str(e4))

    #  — lease-gated: a global table prune; one instance per tick.
    await supervised_interval_loop(
        "log-entries-pruner", 30 * 60, _tick,
        warmup_secs=30,
        startup_jitter_secs=30.0,
        lease_name="log-entries-pruner",
        lease_conn=app.state.db,
    )


# ---------------------------------------------------------------------------
# #277d back-compat shim — poll-ingestion cluster moved to
# email_triage.web.poll_ingestion (2026-05-29). Explicit re-exports (NOT
# ``import *``) so the provider dispatch table, the lifespan task
# registration, and the test suite keep resolving the moved names — plus
# both back-compat aliases (_gmail_history_poller / _run_history_poll_tick).
# ---------------------------------------------------------------------------

from email_triage.web.poll_ingestion import (  # noqa: E402, F401
    _poll_once_office365,
    _poll_once_gmail,
    _poll_once_imap,
    _unified_poll_loop,
    _run_unified_poll_tick,
    _poll_state_key,
    _effective_poll_interval_min,
    _gmail_history_poller,
    _run_history_poll_tick,
)


# ---------------------------------------------------------------------------
# #277d back-compat shim — IMAP watcher cluster moved to
# email_triage.web.watcher (2026-05-29). Explicit re-exports (NOT
# ``import *``) so ``from email_triage.web.app import WatcherManager``
# (test suite + lifespan + get_watcher_manager dependency) keeps working.
# ---------------------------------------------------------------------------

from email_triage.web.watcher import (  # noqa: E402, F401
    WatcherManager,
    _watch_account,
)


# ---------------------------------------------------------------------------
# #277d back-compat shim — digest/daily-health senders moved to
# email_triage.web.digest (2026-05-29). Explicit re-exports so the test
# suite (`from email_triage.web.app import _fire_one_digest`) + the
# lifespan task registration keep resolving unchanged.
# ---------------------------------------------------------------------------

from email_triage.web.digest import (  # noqa: E402, F401
    _daily_health_email_sender,
    _filter_digest_candidates,
    _render_digest_payload,
    _fire_one_digest,
    _recipient_digest_sender,
)


# ---------------------------------------------------------------------------
# #277d back-compat shim — push/webhook ingestion moved to
# email_triage.web.ingestion_push (2026-05-29). Explicit re-exports so the
# test suite + the lifespan task registration keep resolving unchanged.
# ---------------------------------------------------------------------------

from email_triage.web.ingestion_push import (  # noqa: E402, F401
    _gmail_push_consumer,
    _process_push_item,
    _process_office365_push_item,
    _gmail_watch_renewer,
    _run_watch_renewal_sweep,
)


# ---------------------------------------------------------------------------
# #277d back-compat shim — background-sweepers cluster moved to
# email_triage.web.background_sweepers (2026-05-30). Explicit re-exports so
# the test suite (`from email_triage.web.app import _run_sent_mail_capture_sweep`
# / attribute access like `app_mod._recover_one_retry_row`) + the lifespan
# task registration keep resolving unchanged.
# ---------------------------------------------------------------------------

from email_triage.web.background_sweepers import (  # noqa: E402, F401
    _baa_expiry_sweeper,
    _per_contact_style_gc_sweeper,
    _style_distill_trigger_sweeper,
    _recover_one_retry_row,
    _watcher_retry_sweeper,
    _hipaa_boundary_drift_detector,
    _sent_mail_capture_loop,
    _resolve_capture_interval_hours,
    _seconds_until_next_capture_tick,
    _run_sent_mail_capture_sweep,
    _run_hipaa_counter_for_account,
)
