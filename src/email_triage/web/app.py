"""FastAPI application for the email triage web interface.

Server-rendered UI with HTMX for dynamic interactions, Pico CSS for
classless styling.  No JavaScript build step.

Auth: passwordless email OTP (6-digit code, 10-minute expiry).
Roles: admin, power_user, user.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from email_triage.config import TriageConfig, load_config
from email_triage.db._writer import WAL_SHUTDOWN_ENVELOPE_SECS  # punch 636 envelope SSOT
from email_triage.secrets import SecretsProvider, create_secrets_provider, read_secret
from email_triage.triage_logging import get_logger, setup_logging
from email_triage.web.db import init_db, seed_categories
from email_triage.web import settings_keys as _settings_keys
from email_triage._errfmt import fmt_exc
from email_triage._isotime import now_utc_iso, parse_iso
from email_triage._secret_keys import SESSION_SECRET_KEY  # N-231 R22 stored-secret-key SSOT

log = get_logger("web.app")

_WEB_DIR = Path(__file__).parent
_TEMPLATE_DIR = _WEB_DIR / "templates"
_STATIC_DIR = _WEB_DIR / "static"

# N-432 walresetbug hipaa-sme NTH-2 + db-sme NTH-1 fold (batched NTH-panel
# 2026-07-19): the lifespan-shutdown WAL checkpoint is bounded by the ONE
# writer/checkpoint envelope, ``db/_writer.WAL_SHUTDOWN_ENVELOPE_SECS``
# (punch 636 lifted the two 10 s literals onto it,
# feedback_da_hedge_shutdown_timeout_desync); imported at the top.

# Punch 582: bounded wait for in-flight audit writes at lifespan shutdown.
# Short enough to fit inside a container stop timeout together with the WAL
# checkpoint and the writer join; what is still running after it is recorded,
# not waited for.
_AUDIT_SHUTDOWN_DRAIN_TIMEOUT_SECS: float = 5.0

# Punch 636: the second audit sweep, after the writer stops, does not wait; it
# only records what is still running (its cost is the loss sink's lock bound).
_AUDIT_SHUTDOWN_SWEEP_TIMEOUT_SECS: float = 0.0


def _wal_bytes_left(db_path: "Path | str") -> int:
    """Bytes in ``<db_path>-wal``, 0 when there is none (punch 636). Read after
    the app's last connection closed: SQLite's last close deletes the -wal, so
    a non-zero size means frames were stranded. 0 for an in-memory database,
    which has no -wal file, and when the size cannot be read."""
    try:
        return Path(f"{db_path}-wal").stat().st_size
    except OSError:
        return 0


# The baked build identifier has ONE reader, in ``email_triage._build_sha``
# (punch 539 rebase, 2026-09-30: hipaa H539-1, db N-539-X1, da DA-C6). This
# module takes the raw value for the human-facing ``version`` and the
# shape-gated commit sha for ``app.state.build_sha``; it opens no baked file of
# its own.
from email_triage._build_sha import baked_build_sha, read_baked_version  # noqa: E402


def _resolve_version() -> str:
    """Resolve a short build identifier for the ``/health`` endpoint.

    Preference order:
        1. ``/app/VERSION`` file baked in at container build time by
           the Containerfile (``COPY COMMIT /app/VERSION``). The deploy
           script writes ``git rev-parse HEAD`` into the ``COMMIT`` file
           in the build context before ``podman build``.
        2. ``.git/HEAD`` walked to a commit sha (first 7 chars) — dev
           checkout fallback.
        3. ``"unknown"``

    **No environment.** ``EMAIL_TRIAGE_VERSION`` and ``GIT_SHA`` used to sit
    AHEAD of the baked file here, as a documented convenience for ad-hoc
    testing, manual deploys and CI injection. The operator directed that path
    gutted on 2026-09-29: a build identifier a runtime environment variable can
    set is not a build identifier, and "a human reads this one, a machine acts
    on the other one" is too thin a wall to hang the distinction on — the same
    value has keyed lock-manifest currency reads. So BOTH readers are now
    bounded by what was true at build time, and neither can be moved after the
    image is built. Enforced structurally, not just documented, by
    ``tests/test_web/test_health_build_endpoint.py``, which asserts that no
    build-identity resolver in this module reads the environment.

    Resolved once at startup; the health endpoint reads the cached
    value from ``app.state.version`` and never shells out.
    """
    # Baked-in build identifier — container image path. Through the ONE reader
    # in `_build_sha`, which also applies the placeholder predicate, so this
    # function neither opens the file nor re-inlines the sentinel test
    # (hipaa H538-5 / H539-1).
    v = read_baked_version()
    # The placeholder "dev" / "unknown" sentinels — and an UNSUBSTITUTED
    # export-subst literal (a working-tree / non-``git archive`` build where the
    # .gitattributes substitution never ran) — are "no baked value", so local
    # dev checkouts still fall through to the .git/HEAD walk. Through the shared
    # predicate, not a re-inlined copy of it (R5/PD-5): `read_baked_version`
    # returns "" for every placeholder. Unlike `build_sha` this route is
    # human-facing and deliberately NOT shape-gated: a short sha or a release
    # tag is a wanted answer here, so the defensive cap stays.
    if v:
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
        # Punch 547: refuse to start while the environment still carries a
        # removed control override (fail-closed + loud; _env_registry.RETIRED).
        from email_triage._env_registry import refuse_retired_env
        refuse_retired_env()
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
        # N-432 walresetbug P1 (2026-07-19) — sensor for SQLite < 3.51.3
        # exposure. Non-fatal; the P0 (``PRAGMA wal_autocheckpoint=0`` +
        # serialized ``checkpoint_wal_truncate`` under ``@db_write``) is
        # the actual mitigation. This warns to logs + stamps
        # ``app.state.sqlite_walresetbug_status`` for /health surfacing.
        from email_triage.db._engine import assert_sqlite_walresetbug_floor
        _wr_status = assert_sqlite_walresetbug_floor()
        _wr_status["at"] = now_utc_iso()
        app.state.sqlite_walresetbug_status = _wr_status
        # N-432 Path-3 (2026-07-20) — cipher_version boot FAIL-CLOSED guard
        # (hipaa-sme MF-4, §164.312(a)(2)(iv)). Sibling to the sensor above:
        # the sensor logs+surfaces exposure but is non-fatal; this assertion
        # RAISES if the running SQLCipher binding is < 4.14 (pre-walresetbug-fix)
        # so a base-image swap or image-drift can't put a walresetbug-buggy
        # encrypted binding into prod. Skipped cleanly on the plaintext boot
        # path (sqlcipher3 not importable) OR when the image carries no baked
        # Path-3 marker (non-container / pip-installed sqlcipher3 env; punch
        # 547 — no longer an env var). Wrapped in
        # ``asyncio.to_thread`` because the guard opens a :memory: SQLCipher
        # conn to probe PRAGMA cipher_version — even a memory-only conn is
        # an async-unsafe DB touch per test_no_async_reachable_unsafe_db_touch.
        from email_triage.db._engine import assert_cipher_version_floor
        _cv_status = await asyncio.to_thread(assert_cipher_version_floor)
        _cv_status["at"] = now_utc_iso()
        app.state.sqlcipher_version_status = _cv_status
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
        # Punch 605: stamp the update check's armed time HERE, at boot and not
        # in the hourly tick, so a ticker that never runs is still reported
        # (update_check.update_check_stale, "not_running").
        try:
            from email_triage.update_check import arm_check_health
            arm_check_health(  # async-db-ok: lifespan startup
                conn,
                getattr(getattr(config, "admin_email", None),
                        "release_check_url", "") or "",
                now_iso=now_utc_iso(),
            )
        except Exception as e:
            log.warning("Update check: could not stamp its armed time",
                        error=fmt_exc(e))
        app.state.version = _resolve_version()
        # ONE reader of the baked file (`_build_sha.read_baked_version`), two
        # states (punch 539 / N-523). Neither reads the environment (operator
        # directive 2026-09-29). `version` is human-facing and tolerant;
        # `build_sha` is shape-gated (`baked_build_sha`): the full sha or
        # nothing, because a scanner acts on it.
        app.state.build_sha = baked_build_sha()

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
        log.info("db-writer thread started (#291 single-writer, default-on per N-13)")

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
                        "ACME: resolved in-flight job(s) on startup",
                        extra={"n": len(resolved)},
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
        existing_session_secret = read_secret(secrets, SESSION_SECRET_KEY)
        if not existing_session_secret:
            import secrets as _stdlib_secrets
            existing_session_secret = _stdlib_secrets.token_hex(32)
            secrets.set(SESSION_SECRET_KEY, existing_session_secret)
            log.info("session_secret minted + stored in secrets store")
        app.state.session_secret = existing_session_secret

        # PR 8 / D1 follow-up: CSRF enforcement gate. ONE store:
        # ``tls.csrf_enforce`` in YAML, editable live at /admin/security.
        #
        # The ``EMAIL_TRIAGE_CSRF_ENFORCE`` env override was removed
        # 2026-09-12 (config-surface audit finding #1). It was read once
        # here in lifespan, so using it already cost a process restart —
        # exactly what editing YAML costs — while creating a SECOND
        # authoritative store for one value (style-guide R7) that no
        # surface displayed: /admin/security renders the CONFIG value,
        # so an operator could toggle enforcement ON in the UI, see it
        # checked, and have the env var silently revert it on the next
        # restart. The documented YAML break-glass
        # ``tls: { csrf_enforce: false }`` replaces it exactly.
        #
        # No missing-attribute default (DA B2 / db-sme F3). `TriageConfig.tls`
        # is `field(default_factory=TLSConfig)` and `TLSConfig.csrf_enforce:
        # bool = True`, so a `getattr` default is unreachable for any real
        # config — asserting "fails closed" on a dead branch is the same class
        # as the LOG_LEVEL comment this commit deletes for describing a control
        # nothing reads. Four sites once split three-to-one on the default;
        # they now share one read shape and a duck-typed config fails loud.
        app.state.csrf_enforce = bool(config.tls.csrf_enforce)

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
        # (AI provider / openai / etc.). We let the error propagate
        # so a misconfigured YAML surfaces at boot rather than the
        # first draft-reply call.
        # Punch 569 D3: resolve a runtime update that a crash interrupted,
        # BEFORE anything can import from the runtime prefix. Renames only
        # (O(1)): a leftover ``.next`` is retired, a leftover ``.prev`` is
        # retired when the live prefix serves and put back when it does not.
        # The retired bytes go through the removal-tombstone purge in a worker
        # thread, tracked like every fire-and-forget task. A failure
        # here is logged and boot continues: the status funnel still refuses
        # whatever it cannot verify (fail closed at the gate, not at boot).
        # Panel B3 hipaa F1 / DA F569-3: what recovery did is written to the
        # audit chain AFTER add_sqlite_handler below; here it is only captured.
        _boot_recovery: list[str] = []
        _boot_recovery_failed = False
        try:
            from email_triage.embedding_bits import (
                purge_removal_tombstones,
                reconcile_interrupted_install_row,
                recover_interrupted_update,
            )
            # Panel B3 db F569-1(c) / DA F569-8: a just-started process runs no
            # installer, so an in-flight install row is stale (a SIGKILL during
            # an update); left as is, every later install/update is refused.
            # Its own try: it must run even when the file recovery raises.
            try:
                # async-db-ok: lifespan startup, single-threaded
                _row_fix = reconcile_interrupted_install_row(conn)
                if _row_fix:
                    _boot_recovery.append(_row_fix)
            except Exception as e:  # noqa: BLE001
                _boot_recovery_failed = True
                _boot_recovery.append(f"install-record repair raised {type(e).__name__}")
                log.error("Embedding install record repair failed at boot", error=fmt_exc(e))
            _recovered = recover_interrupted_update()
            _boot_recovery.extend(_recovered)
            if _recovered:
                _purge_task = asyncio.create_task(
                    asyncio.to_thread(purge_removal_tombstones),
                )
                _pending = getattr(app.state, "_fire_and_forget_pending", None)
                if _pending is None:
                    _pending = set()
                    app.state._fire_and_forget_pending = _pending
                _pending.add(_purge_task)
                _purge_task.add_done_callback(_pending.discard)
        except Exception as e:  # noqa: BLE001
            _boot_recovery_failed = True
            _boot_recovery.append(f"recovery raised {type(e).__name__}")
            log.error(
                "Embedding runtime update recovery failed at boot",
                error=fmt_exc(e),
            )

        # Operator decision 2026-10-25: the embedding runtime updates itself.
        # AFTER the boot recovery above (it resolves a crashed update's
        # leftovers first), wire the switch every notice surface words itself
        # by and mirror the durable failure record; the sweeper's first tick
        # (_embedding_auto_update_sweeper) then runs the update funnel.
        try:
            from email_triage.embedding_bits import configure_auto_update
            from email_triage.web.embedding_update_runner import (
                rehydrate_auto_failure,
            )

            configure_auto_update(config.embedding.auto_update)
            rehydrate_auto_failure(conn)  # async-db-ok: lifespan startup
            # Panel T DA SHOULD-A1: hold the first embedding load until the first
            # auto-update decision when the runtime is stale_ok (so the deferral
            # converges); the sweeper's first tick then runs without its warmup.
            from email_triage.embedding_bits import arm_boot_update_gate

            arm_boot_update_gate()
        except Exception as e:  # noqa: BLE001
            log.error(
                "Embedding auto-update wiring failed at boot", error=fmt_exc(e),
            )

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

        # N-01-forward landing — register the draft runtime so
        # DraftReplyAction can resolve the install config + embedding backend
        # without threading app.state through every TriageContext constructor.
        try:
            from email_triage.actions.draft_reply import (
                register_draft_runtime,
            )
            register_draft_runtime(
                config=config,
                embedding_backend=app.state.embedding_backend,
                embedding_model=app.state.embedding_model,
                sqlite_vec_available=bool(
                    getattr(app.state, "sqlite_vec_available", False),
                ),
            )
        except Exception as _draft_rt_exc:  # pragma: no cover - best-effort
            log.warning(
                "draft runtime registration failed",
                error=str(_draft_rt_exc),
            )

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

        # MIGRATE (one-shot, pre-B1) -> HYDRATE -> REGISTER the install-level
        # Google + O365 OAuth creds with the provider factory — the ONE place
        # this full wiring lives (N-130). The CLI mine commands call the same
        # SSOT (passing their db conn) so a fresh/portable-reuse or un-migrated
        # O365 install gets the creds migrated + registered identically.
        from email_triage.providers.factory import (
            hydrate_and_register_install_oauth,
        )
        # async-db-ok: lifespan startup. The folded migrations are
        # the same single-threaded boot DB touches  already vetted (was
        # inline migrate_oauth_creds_to_install_level(conn) with this exact
        # opt-out); no concurrent traffic during startup, no event-loop contention.
        hydrate_and_register_install_oauth(config, secrets, conn)  # async-db-ok: lifespan startup

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

        #  v3 — OPTIONAL Redis mirror of Topic feedback signals. Reuses the
        # SAME redis_cache URL (empty URL = None = off; the feature stays
        # DB-only). Operator-confirmed strictly optional, never required.
        try:
            from email_triage.cache.topic_feedback import (
                build_feedback_cache_from_config,
                set_install_topic_feedback_cache,
            )
            set_install_topic_feedback_cache(
                build_feedback_cache_from_config(
                    getattr(config, "redis_cache", None),
                ),
            )
        except Exception as _fb_cache_err:
            from email_triage._errfmt import fmt_exc as _fmt
            log.warning(
                "Topic-feedback cache init failed; mirror disabled "
                "(DB stays the source of truth)",
                error=_fmt(_fb_cache_err),
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

        # Panel B3 hipaa F1 / DA F569-3: boot recovery may have changed which
        # embedding runtime set is live (a rollback to .prev) or released a
        # stuck install row. One PHI-free row through the emitter SSOT, under
        # the same event_type as the route's attempt/outcome rows, so one query
        # reads attempt -> crash -> recovery. Nothing done -> nothing written.
        if _boot_recovery:
            from email_triage.web._audit import safe_audit_write
            from email_triage.web.db import record_auth_event as _rae
            from email_triage.web.embedding_update_runner import (
                BOOT_RECOVERY_ACTOR_EMAIL,
            )
            safe_audit_write(
                lambda: _rae(  # async-db-ok: lifespan startup
                    conn,
                    event_type="embedding_runtime_update",
                    # Operator ruling R5 (2026-10-25): a named system actor, never
                    # blank, beside the automatic updater's own.
                    email=BOOT_RECOVERY_ACTOR_EMAIL,
                    user_id=None,
                    outcome="failure" if _boot_recovery_failed else "success",
                    detail="boot recovery: " + "; ".join(_boot_recovery),
                ),
                description="embedding_runtime_update boot recovery",
            )

        # Punch 547 + operator ruling A4 (2026-10-21): the classify raw-head
        # debug capture is a config decision, never refused; while on it logs a
        # loud WARNING (here, after the chain handler attaches, so it is a
        # log_entries row) and the admin pages show a banner.
        if getattr(config.classifier, "debug_capture_raw_head", False):
            from email_triage.classify.ollama import configure_debug_capture
            from email_triage.db.accounts import list_email_accounts
            from email_triage.triage_logging import account_hipaa_effective
            _any_hipaa_acct = any(
                account_hipaa_effective(account=a)
                for a in list_email_accounts(conn)  # async-db-ok: lifespan startup
            )
            configure_debug_capture(True, any_hipaa_account=_any_hipaa_acct)

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
        # Import the KEY CONSTANT rather than repeating the literal: the N-464
        # pin keys its predicate on this symbol, so a raw string here put the
        # boot path — including the never-clobber fold below, the one line that
        # decides the install's HIPAA posture — outside the net by a literal.
        from email_triage.web.routers.ui._shared import _RUNTIME_SETTINGS_KEY
        _rt_settings = get_setting(conn, _RUNTIME_SETTINGS_KEY)  # async-db-ok: lifespan startup
        if _rt_settings:
            import logging as stdlib_logging
            from email_triage import triage_logging
            # Never-clobber, same rule as `hipaa` below: a row that omits the
            # key carries no opinion, so keep the level the YAML seed set
            # rather than forcing INFO over it. LOW — the failure direction is
            # less logging, not less protection (hipaa-sme) — but it is the
            # identical shape, and `_apply_runtime_settings` already
            # establishes the preserve idiom for its sibling key.
            level_name = str(
                _rt_settings.get("log_level")
                or triage_logging.effective_level_name()
            ).upper()
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
            # N-464 fold — NEVER-CLOBBER at the last hop into the
            # process-global. A row that omits the key carries no
            # opinion about HIPAA mode; defaulting it to False turned a
            # missing field into a safeguard-disabling write. Both
            # writers emit the key today, so this is latent — but the
            # flat-`False` default IS the defect shape, and it sat on
            # the one line that decides the install's HIPAA posture.
            if "hipaa" in _rt_settings:
                # Bound to a named local rather than assigned straight to
                # the module global: the N-226 pin's allow-list keys on an
                # `ast.Name` assign target, and an Attribute target
                # (`triage_logging._hipaa_mode`) resolves to None — whose
                # only expressible exemption is `(path, None)`, i.e. the
                # WHOLE FILE. Naming the local keeps the exemption exactly
                # as wide as the one line that earned it.
                system_hipaa_from_row = bool(_rt_settings["hipaa"])
                triage_logging._hipaa_mode = system_hipaa_from_row
            log.info(
                "Runtime settings restored from DB",
                dry_run=_rt_settings.get("dry_run", False),
                log_level=level_name,
                # Report the EFFECTIVE flag, not a flat default: on a partial
                # row this startup record otherwise misstates the safeguard's
                # state in the audit-adjacent log (hipaa-sme, §164.312(b)).
                hipaa=triage_logging.is_hipaa_mode(),
            )

        # Startup mode breadcrumbs — one line each, in increasing severity.
        # Intentionally terse; the full picture is in /config and /compliance.
        from email_triage.triage_logging import is_hipaa_mode
        _system_hipaa = is_hipaa_mode()
        if _system_hipaa:
            log.info("Starting in HIPAA mode (system-wide)")

        # For DEBUG logs, set the Python log level via the /admin
        # runtime settings (the ``runtime_settings`` DB row restored
        # just above) or the YAML ``logging.level`` seed. There is no
        # LOG_LEVEL env var — this comment claimed one until 2026-09-12
        # and nothing in src/ has ever read it — and no dictConfig
        # path either: ``dictConfig``/``fileConfig`` appear in src/
        # exactly once, in this comment, so following that advice
        # requires the operator to run their own wrapper rather than
        # the shipped entrypoint. Half-correcting a false claim leaves
        # a false claim.

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

        # Punch 711: record any restore witness `email-triage restore` left in
        # the data dir into THIS (post-swap) chain, then remove it; the CLI's own
        # start/end rows went to the database the swap moved aside. A failure
        # keeps the marker for the next start and is logged; it does not block
        # startup.
        from email_triage.backup import ingest_restore_witness_markers
        try:
            _n711_count = ingest_restore_witness_markers(  # async-db-ok: lifespan startup
                conn, Path(db_path).parent,
            )
            if _n711_count:
                log.info("Restore witness recorded", count=_n711_count)
        except Exception as _n711_e:
            log.error(
                "Restore witness could not be recorded; the marker is kept "
                "for the next start",
                error=fmt_exc(_n711_e, with_class=True),
            )

        log.info("Web UI started", db_path=str(db_path))

        # Instantiate the Gmail push queue + consumer support state
        # before spawning supervised tasks (factories close over
        # app.state.push_queue, so it must exist first).
        app.state.push_queue = asyncio.Queue(maxsize=256)
        app.state.metrics = getattr(app.state, "metrics", {})

        # Outbound event dispatcher — used by the triage.completed
        # emitter from manual, watcher, push and outbound-webhook API call sites.
        from email_triage.web.events import (
            EventDispatcher,
            announce_external_egress_posture,
        )
        app.state.event_dispatcher = EventDispatcher(
            targets=getattr(config, "webhooks", []) or [],
            secrets_provider=secrets,
            allow_external=getattr(config, "webhooks_allow_external", False),
            local_url_suffixes=list(
                getattr(config.tls, "local_url_suffixes", []) or [],
            ),
        )
        # Punch 414: the wizard preview's "My last real event" store. The
        # dispatcher owns it (its ``record_fire`` belt is the only writer);
        # ``app.state`` carries the same object for the preview endpoint.
        app.state.last_envelope_per_target = (
            app.state.event_dispatcher.last_envelopes
        )
        # N-276 R28: register the dispatcher on a module-level accessor so
        # NotifyAction (background loop, no request context) can fire the
        # `notification` event via `fire_notification`. Row 77 closure.
        from email_triage.web.events import register_event_dispatcher
        register_event_dispatcher(app.state.event_dispatcher)
        #  deny-by-default egress guard — if external webhook targets are
        # PERMITTED, say so LOUDLY at every boot so the §164.502(e) disclosure
        # posture (and any silent deny→allow flip from a previously-inert
        # hand-edited YAML flag wired by the #8-FULL round-trip fix) is never
        # silent. See email_triage.web.events.announce_external_egress_posture.
        announce_external_egress_posture(config)

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
        # N-432 walresetbug P0 (2026-07-19) — periodic SERIALIZED
        # WAL-checkpoint. Paired with ``PRAGMA wal_autocheckpoint = 0``
        # at the opener SSOT (``db/_engine.py::_apply_standard_pragmas``)
        # so the ONLY checkpoint fire path in the process is this loop,
        # which runs ``checkpoint_wal_truncate`` under ``@db_write`` —
        # no writer or other checkpoint can race the C-level checkpoint
        # routine. Cadence 5min: bounds WAL-file growth without adding
        # noticeable steady-state IO. Lease-gated to one instance.
        supervisor.supervise(
            "wal-checkpoint-loop", lambda: _wal_checkpoint_loop(app),
        )
        # PR 9 / D3 — HIPAA boundary drift detector.
        supervisor.supervise(
            "hipaa-boundary-drift-detector",
            lambda: _hipaa_boundary_drift_detector(app),
        )
        #  Phase 4 — regulatory-clock escalation sweep (state derive +
        # breach chaining). Inert until a clock exists; lease-gated.
        supervisor.supervise(
            "regulatory-clock-escalator",
            lambda: _regulatory_clock_escalator(app),
        )
        #  — automated encrypted DB-snapshot backup. Disabled by default
        # (config backup.enabled); lease-gated; self-gates inert until the
        # operator enables it after the key-only export + SMB wiring.
        supervisor.supervise(
            "db-backup-sweeper",
            lambda: _db_backup_sweeper(app),
        )
        # Operator decision 2026-10-25 — the embedding runtime replaces itself
        # when the image's manifest moves past it (boot + every 10 min), through
        # the same update funnel as the admin's click. Inert when
        # embedding.auto_update is false. Lease-gated.
        supervisor.supervise(
            "embedding-auto-update-sweeper",
            lambda: _embedding_auto_update_sweeper(app),
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
        #  — scheduled Topic-digest sender (the output spine). Same
        # 60s lease-gated cadence; fires each Topic's named digests when
        # the clock crosses their schedule, rendering accumulated
        # topic_hits and delivering per the R1 HIPAA recipient routing.
        from email_triage.web.topic_digest_sender import _topic_digest_sender
        supervisor.supervise(
            "topic-digest-sender",
            lambda: _topic_digest_sender(app),
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
        # Punch 553 — hourly update check (GitHub release + security
        # marker). Makes no request when admin_email.release_check_url is
        # blank (OFF). Feeds the admin security banner + daily email.
        supervisor.supervise(
            "update-check-sweep",
            lambda: _update_check_sweeper(app),
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
        # rows on ``style_distill_queue`` / ``style_distill_queue_contacts``.
        # NOTE: nothing drains those rows — no queue worker exists at HEAD
        # and none ever has (N-474). Idempotent across ticks
        # (already-queued rows skip; no new sends → no work).
        supervisor.supervise(
            "style-distill-trigger-sweeper",
            lambda: _style_distill_trigger_sweeper(app),
        )

        #  V3 — Topic retention soft-expire + tombstone horizon-purge.
        # Daily tick: sets expired_at on topic_hits past their Topic's
        # retention_days (feedback/audit rows survive), and hard-deletes
        # Topics soft-tombstoned past the horizon + their child rows
        # (bounded batches; never the §164.312(b) audit chain — C-V3.2).
        # Lease-gated; idempotent + a no-op single-instance.
        supervisor.supervise(
            "topic-retention-purge-sweeper",
            lambda: _topic_retention_purge_sweeper(app),
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

        # N-192 R20_20: wire safe_audit_write's failure path into
        # app.state.audit_failures so /health can flip degraded on a
        # swallowed audit-write. Before N-192 the failure was WARNING-
        # logged only — invisible to the counter-based /health drift.
        from email_triage.web._audit import register_audit_failure_sink
        def _bump_app_state_audit_failures():
            current = getattr(app.state, "audit_failures", 0)
            app.state.audit_failures = int(current) + 1
        register_audit_failure_sink(_bump_app_state_audit_failures)

        # Punch 582: a durable chained row for audit writes lost without an
        # exception reaching the @db_write sentinel (cancelled, swallowed,
        # left in flight at shutdown). Unregistered just before conn.close().
        from email_triage.db.audit import make_audit_loss_sink
        from email_triage.web._audit import register_audit_loss_sink
        register_audit_loss_sink(make_audit_loss_sink(conn))
        # Panel B7 DB-2: a writer queue the last shutdown abandoned (L6)
        # left a sentinel next to the DB; record its row now, while the
        # write lock is free, then remove the file.
        from email_triage.db._live_app_gate import _resolve_dbdir
        from email_triage.web._audit import replay_writer_abandoned_sentinel
        _audit_data_dir = _resolve_dbdir(config.persistence.db_path)
        replay_writer_abandoned_sentinel(_audit_data_dir)

        # N-432 DA NTH-3 (2026-07-19) + DA-MF-1 fold (batched NTH-panel
        # same-day): stamp the two-layer "app is live" gate — in-process
        # bool + filesystem sentinel `<dbdir>/.app-alive.<pid>` — so raw-
        # connect migration primitives refuse to run against a live app
        # (including via `podman exec ... python -m et migrate` from a
        # separate interpreter). Passing db_path plants the sentinel
        # next to the DB so a cross-process invocation with the same
        # DB path can find it.
        from email_triage.db._live_app_gate import (
            mark_app_live, mark_app_stopped,
        )
        mark_app_live(db_path=config.persistence.db_path)

        try:
            yield
        finally:
            # Never leave the boot gate armed past this app (a shutdown or a test).
            from email_triage.embedding_bits import release_boot_update_gate

            release_boot_update_gate()

        # Shutdown: stop watchers first, then supervised tasks.
        await watcher_mgr.stop_all()
        await supervisor.stop_all()

        # Punch 582 (L4): wait, bounded, for the audit writes still in
        # flight (fire-and-forget access_log tasks and shielded inner
        # writes) while the writer and the connection are up. Whatever is
        # still running is recorded as one shutdown_undrained row. The
        # failure sink stays registered until the end of shutdown, so a loss
        # here can still degrade /health (before punch 582 it was the first
        # thing unregistered).
        try:
            from email_triage.web._audit import drain_inflight_audit_writes
            await drain_inflight_audit_writes(
                _AUDIT_SHUTDOWN_DRAIN_TIMEOUT_SECS,
                pending=list(getattr(app.state, "_audit_pending", None) or ()),
            )
        except Exception as _drain_exc:  # noqa: BLE001
            log.error(
                f"audit write shutdown drain FAILED "
                f"({type(_drain_exc).__name__}); in-flight audit writes may "
                f"be lost unrecorded (§164.312(b))",
            )

        # Drain long-lived httpx clients introduced by . Each
        # close() is best-effort + idempotent — surface any error in
        # the log but never block shutdown on a stuck pool.
        try:
            await app.state.event_dispatcher.aclose()
        except Exception as e:
            log.warning("event_dispatcher aclose failed",
                        error=fmt_exc(e))
        # N-276 R28: unregister the module-level accessor so a subsequent
        # webhook attempt fails-closed (no stale dispatcher after shutdown).
        try:
            from email_triage.web.events import register_event_dispatcher
            register_event_dispatcher(None)
        except Exception:
            pass
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

        #  Internet-Search HTTP pools — drain the module-level
        # LazyHttpClient holders (one long-lived pool each, ). Both
        # were unwired (SME 2026-06-08, fix-all-root-cause); best-effort.
        for _mod_name in (
            "email_triage.actions.web_search",
            "email_triage.actions.clinicaltrials",
        ):
            try:
                import importlib
                _m = importlib.import_module(_mod_name)
                if hasattr(_m, "aclose"):
                    await _m.aclose()
            except Exception as e:
                log.warning(
                    "internet-search client aclose failed",
                    module=_mod_name, error=fmt_exc(e),
                )

        # v0.1.2  Phase 2 — drain + stop the writer thread BEFORE the
        # connection closes, so any queued writes flush against a live
        # conn. Idempotent + best-effort; a stuck writer must not block
        # shutdown (10s join bound inside shutdown()).
        # Punch 636: False only when the writer outlived its join bound; the
        # final checkpoint below is then skipped (the wedged writer holds the
        #  write lock, so the checkpoint could not run and its worker
        # thread would hold process exit past the container StopTimeout).
        _writer_stopped = True
        try:
            from email_triage.db._writer import get_writer, set_writer

            _writer = get_writer()
            if _writer is not None:
                try:
                    # Panel B7 DB-2: at a join timeout, the next-boot sentinel
                    # is written before any lock wait.
                    import functools as _functools
                    from email_triage.web._audit import record_writer_abandoned
                    _writer_stopped = await _writer.shutdown(
                        on_abandoned=_functools.partial(
                            record_writer_abandoned, _audit_data_dir,
                        ),
                    ) is not False
                finally:
                    # Punch 636: uninstalled even when shutdown() raised, so
                    # the final checkpoint below takes db_call's  RLock
                    # path (no writer installed) instead of being refused by
                    # a stopping writer (WriterStopped).
                    set_writer(None)
        except Exception as e:
            log.warning("db-writer shutdown failed", error=fmt_exc(e))

        # Punch 636 fold (panel r1 DA-1, db-1): after a FAILED join the wedged
        # writer holds the write lock, so every further database write would
        # wait out SQLite's 30 s busy timeout, and two of them run past the
        # container StopTimeout into a SIGKILL. So write nothing more to the
        # database: the log lines go to the console from here, and the sweep
        # below records to its lock-free next-boot sentinel.
        if not _writer_stopped:
            try:
                from email_triage.triage_logging import remove_sqlite_handlers
                remove_sqlite_handlers()
            except Exception as e:
                log.error("audit log handler close failed", error=fmt_exc(e))

        # Punch 636: a second, zero-wait sweep of the in-flight audit writes.
        # The bounded drain above ran before the httpx drains and the writer
        # stop. A write launched after it, still running at loop close, would
        # be cancelled after the loss sink is gone and leave only a console
        # line. Whatever is still running now is recorded as
        # ``shutdown_undrained`` while the sink can still write the row.
        try:
            import functools as _sweep_functools
            from email_triage.web._audit import (
                drain_inflight_audit_writes, record_writer_abandoned,
            )
            await drain_inflight_audit_writes(
                _AUDIT_SHUTDOWN_SWEEP_TIMEOUT_SECS,
                pending=list(getattr(app.state, "_audit_pending", None) or ()),
                record=None if _writer_stopped else _sweep_functools.partial(
                    record_writer_abandoned, _audit_data_dir,
                    loss_class="shutdown_undrained", try_row=False,
                ),
            )
        except Exception as _sweep_exc:  # noqa: BLE001
            log.error(
                f"audit write shutdown sweep FAILED "
                f"({type(_sweep_exc).__name__}); in-flight audit writes may "
                f"be lost unrecorded (§164.312(b))",
            )

        # Punch 636: close every OTHER connection on the database file, so the
        # app connection's close below is the LAST close. SQLite's last close
        # checkpoints whatever frames remain and deletes the -wal
        # (sqlite.org/wal.html, sections 4 and 6). Before 636 these stayed open
        # until process exit, so the app connection was never the last and
        # every clean stop left WAL frames. The audit-chain log handler's
        # connection closes last of them, just before the app connection, so
        # the shutdown rows stay in the HMAC-chained log_entries.
        try:
            from email_triage.web import acme_job_state
            acme_job_state.set_db_handle(None)
        except Exception as e:
            log.error(
                "acme job-state connection close failed", error=fmt_exc(e),
            )
        from email_triage.single_flight import close_lock_conn
        close_lock_conn()

        # N-432 walresetbug — hipaa-sme NTH-2 (2026-07-19): fire ONE
        # final ``checkpoint_wal_truncate`` on the way down so no writes
        # sit stranded in the WAL when the container stops.
        #
        # Punch 636: it runs after the writer drained. Until 636 it ran before
        # the httpx drains and the writer stop, so the writer's queue and the
        # log rows after it stayed in the WAL. With no writer installed,
        # ``db_call`` runs it on the  RLock path. The log rows written
        # after it are folded by the app connection's last close below; this
        # checkpoint is the belt.
        #
        # db-sme NTH-1 (batched NTH-panel 2026-07-19): bound the wait by the
        # writer's own envelope (``WAL_SHUTDOWN_ENVELOPE_SECS``, one constant
        # for the join and this wait since punch 636). A wedged writer would
        # otherwise queue-and-wait indefinitely; try/except catches errors but
        # not hangs. Punch 636: after a failed join it is not attempted at all
        # (``_writer_stopped``); it is reported FAILED below without a wait.
        #
        # DA-SF-3 (batched NTH-panel 2026-07-19): a FAILURE to complete
        # this checkpoint has the same integrity effect as omitting it
        # (stranded WAL frames + walresetbug re-exposure on next boot),
        # so it's a §164.312(c)(1) integrity signal — bump
        # ``app.state.audit_failures`` (the counter the /health drift
        # surface reads) and log at ERROR, not WARN.
        try:
            if not _writer_stopped:
                raise TimeoutError(
                    "skipped: the db-writer outlived its join bound and holds "
                    "the write lock",
                )
            # Uses module-scope `asyncio` (imported at web/app.py top) — a
            # function-local `import asyncio` would LEGB-shadow it per
            # -followup-B (see test_no_legb_shadow_asyncio.py).
            from email_triage.web.db import checkpoint_wal_truncate
            from email_triage.web.db_threadpool import db_call

            _final = await asyncio.wait_for(
                db_call(checkpoint_wal_truncate, app.state.db),
                timeout=WAL_SHUTDOWN_ENVELOPE_SECS,
            )
            log.info(
                "WAL checkpoint (shutdown) fired",
                busy=_final.get("busy"),
                log=_final.get("log"),
                checkpointed=_final.get("checkpointed"),
            )
        except Exception as _shutdown_ckpt_exc:  # noqa: BLE001
            log.error(
                "WAL checkpoint (shutdown) FAILED — stranded WAL frames "
                "may re-open walresetbug window on next boot (§164.312(c)(1))",
                error=fmt_exc(_shutdown_ckpt_exc),
            )
            try:
                _current_af = getattr(app.state, "audit_failures", 0)
                app.state.audit_failures = int(_current_af) + 1
            except Exception:
                pass

        # N-432 DA NTH-3 + DA-SF-1 fold (batched NTH-panel 2026-07-19):
        # clear the app-live gate after the db-writer drain and the final
        # checkpoint, symmetric with mark_app_live being the last startup step
        # before yield. Keeps the gate SET for the entire serving+shutdown
        # window — any migration primitive invoked mid-shutdown (unlikely but
        # the point of the defensive gate is to defend against the unlikely)
        # still refuses.
        mark_app_stopped()

        # N-192 / punch 582: unregister both sinks only now, so every loss
        # recorded during shutdown reaches the chain and /health; a stray
        # call after this finds no sink and logs the gap-on-gap ERROR.
        register_audit_failure_sink(None)
        from email_triage.web._audit import register_audit_loss_sink
        register_audit_loss_sink(None)

        log.info("Web UI stopped")
        # Punch 636: the log handler's connection, then the app connection,
        # LAST. A line logged after this reaches the console only.
        try:
            from email_triage.triage_logging import remove_sqlite_handlers
            remove_sqlite_handlers()
        except Exception as e:
            log.error("audit log handler close failed", error=fmt_exc(e))
        try:
            conn.close()
        except Exception as e:
            log.error("database connection close failed", error=fmt_exc(e))
        # Punch 636: a SUCCESSFUL checkpoint that preceded a later write was
        # invisible to the DA-SF-3 signal above. The -wal itself is the
        # evidence: after the last close it is absent (or empty).
        _wal_left = _wal_bytes_left(db_path)
        if _wal_left:
            log.error(
                f"WAL file left after shutdown: {_wal_left} bytes. Another "
                f"process may hold the database open, or a close failed; "
                f"stranded frames re-open the walresetbug window on the next "
                f"boot (§164.312(c)(1))",
            )

    # Interactive API docs are OFF by default (N-next / §164.308(a)(1)(ii)(B)).
    # FastAPI's defaults serve /docs, /redoc and /openapi.json to ANY caller
    # that can reach the port. Observed 2026-08-18 on the publish candidate:
    # /openapi.json returned 200 unauthenticated with 288 routes enumerated,
    # /admin/security, /admin/tls and /accounts/api-keys among them, while
    # every other route correctly redirected to /login. The schema holds no
    # ePHI, so this is attack-surface reconnaissance rather than a PHI
    # access-control break — but a deployer inherits it silently, and there is
    # no reason to hand an unauthenticated caller the complete route and
    # parameter map. Explicit None on all three: openapi_url=None alone would
    # disable the others, and naming each one keeps the intent un-guessable.
    app = FastAPI(
        title="Email Triage",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
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
    # via ``tls: { csrf_enforce: false }`` in YAML or the live toggle
    # at /admin/security — one store, no env override (removed
    # 2026-09-12). When disabled, violations still log + bump
    # ``app.state.csrf_rejects`` so the operator can size + verify
    # before re-enabling.
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
    # Punch 553 — the update check's default address, from its one SSOT, for
    # the Config > General datalist/placeholder (no restated literal).
    from email_triage.update_check import DEFAULT_RELEASE_CHECK_URL
    templates.env.globals["default_release_check_url"] = DEFAULT_RELEASE_CHECK_URL
    # –301 pagination — rebuild the current URL's query string with one
    # param overridden, preserving every OTHER param (so paging one of the
    # 5 compliance tables doesn't reset the others). The `_pager.html` macro
    # calls this for its newer/older links.
    from email_triage.web._pagination import page_url as _page_url
    templates.env.globals["page_url"] = _page_url
    # N-229 R22 — expose the is_admin SSOT to Jinja under an UNDERSCORED
    # name (`_admin_of`) so it doesn't shadow the `is_admin` BOOL that
    # ~60 handlers pass in TemplateResponse ctx (`{"is_admin": is_admin}`).
    # Calling `is_admin(user)` from a template previously bombed with
    # `TypeError: 'bool' object is not callable` because the ctx bool
    # shadowed the global callable. `_admin_of(<user>)` is unique.
    from email_triage.web.dependencies import is_admin as _is_admin
    templates.env.globals["_admin_of"] = _is_admin
    # N-265 R27: Jinja globals for HIPAA folding — the R27 census
    # found `templates/profile/style_data.html:538` leaks reply
    # subjects under system-HIPAA when per-account flag is OFF because
    # it reads `entry.account.hipaa` (raw column) instead of the
    # effective verdict. Named `_hipaa_of` (mirror of `_admin_of`) to
    # avoid shadowing any handler-passed ctx bool. Callers use
    # `{% if _hipaa_of(entry.account) %}` (effective) OR
    # `{% if _hipaa_of(entry.account, strict=True) %}` (per-account
    # only, when only that axis matters).
    from email_triage.triage_logging import (
        account_hipaa_effective as _account_hipaa_effective,
        is_account_hipaa as _is_account_hipaa,
    )
    def _hipaa_of(account, *, strict=False):
        """Fold HIPAA gate for a Jinja template. Default: EFFECTIVE
        (system_hipaa OR per-account hipaa). `strict=True`: per-account
        only. Fail-closed on missing account."""
        if account is None:
            return True
        if strict:
            return _is_account_hipaa(account)
        return _account_hipaa_effective(account=account)
    templates.env.globals["_hipaa_of"] = _hipaa_of
    # run18  — the digest "Show matches" dry-run table formats its "When"
    # cell through the digest datetime SSOT (recipient_digest._format_datetime,
    # exposed as format_digest_datetime) so the preview matches the delivered
    # digest's space-separated "%Y-%m-%d %H:%M" form, instead of the inline ISO
    # "[:16]" slice that leaked the "T" separator (template-vs-Python drift).
    from email_triage.actions.recipient_digest import (
        format_digest_datetime as _format_digest_datetime,
    )
    templates.env.filters["format_digest_dt"] = (
        lambda entry: _format_digest_datetime(entry, "")
    )
    # 2026-07-13 — US-locale display filter (operator ask).
    # Renders '7/13/2026 9:12:33 AM EDT' from an ISO string or datetime.
    # Server-side; templates that want VIEWER-local rendering use the
    # `<time datetime='ISO' data-us-datetime>{{ ts | us_datetime }}</time>`
    # progressive-enhancement pattern — the JS helper in base.html walks
    # `[data-us-datetime]` elements after DOM load and rewrites text using
    # the viewer's browser timezone. See `_us_datetime.py` module docstring.
    from email_triage._us_datetime import install_filter as _install_us_datetime
    _install_us_datetime(templates.env)
    app.state.templates = templates

    # Register routers
    from email_triage.web.routers.ui import router as ui_router
    from email_triage.web.routers.api import router as api_router
    from email_triage.web.routers.webhooks import router as webhook_router
    from email_triage.web.routers.agent_api import (
        router as agent_api_router,
        legacy_openclaw_redirect_router,
    )
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
    #  — the external integration API is now mounted at the neutral
    # ``/api/v1`` (prefix lives on the router). The legacy ``/api/openclaw/*``
    # path 308-redirects to it (method/body-preserving) so existing
    # integrations keep working through the rename.
    app.include_router(agent_api_router)
    app.include_router(legacy_openclaw_redirect_router)
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
        # Punch 579: every HTTPException passes here, so its fixed error slug
        # (if any) reaches the request's access_log row.
        from email_triage.web.error_surface import stash_error_slug
        stash_error_slug(request, exc)
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

    #  — a `health_ro`-class principal tried to mint a web session.
    # `auth.create_session_token` is the ONE minting funnel and refuses there, so
    # every login surface is covered at one site; this handler is what makes the
    # refusal read as POLICY (403) rather than as a crash (500). No body detail
    # beyond the refusal: the route set a machine role may reach is not something
    # an unauthenticated login attempt gets told.
    from email_triage.web._route_scope import SessionMintRefused

    @app.exception_handler(SessionMintRefused)
    async def _session_mint_refused_handler(
        request: Request, exc: SessionMintRefused,
    ):
        return JSONResponse(
            {"detail": "This account may not sign in to the web interface."},
            status_code=403,
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
    """Detect an auth-revoked provider failure and persist the per-account
    ``auth_stale`` flag (the "Re-authenticate required" chip + daily-health
    call-out).

    This is the SET half of the ``auth_stale`` lifecycle; prefer the funnel
    ``record_provider_outcome(db, acct, exc)`` over calling this directly so
    set and clear stay symmetric across every credentialed surface (divergence
    census 2026-06-09, finding #1 — before then SET fired on the poll path
    only). The needle predicate is the SSOT in ``web/_auth_revoked.py`` (the
    Google ``invalid_grant`` / ``401 invalid_client`` and IMAP/Graph
    ``AUTHENTICATIONFAILED`` families, scanning both the exception class name
    and ``str(exc)``). Cleared by ``_clear_auth_stale`` on the next successful
    provider call on ANY path.
    """
    cls = type(err).__name__
    try:
        msg = str(err) or ""
    except Exception:  # noqa: BLE001 — an unprintable exc still has a class name
        msg = ""  # the class-name needle (OAuthRefreshFailed, …) still decides
    # The auth-revoked needle predicate is the SSOT in ``web/_auth_revoked.py``
    # — do NOT re-inline the list here. It drifted from the watcher-retry copy
    # before 2026-06-09 (the retry copy carried OAuthRefreshFailed/IMAPAuthError
    # and scanned the class name; this SET path did not — so a class-only auth
    # failure short-circuited retries but never flipped the chip). The shared
    # predicate scans BOTH the class name and ``str(exc)``. The lifecycle pin
    # (``tests/test_auth_stale_lifecycle_pin.py``) fails CI on a re-inlined list.
    from email_triage.web._auth_revoked import is_auth_revoked
    if not is_auth_revoked(cls, msg):
        return
    try:
        from email_triage.web.db import set_setting
        set_setting(db, _settings_keys.auth_stale(acct["id"]), {
            "at": now_utc_iso(),
            "reason": msg[:300],
        })
    except Exception as e:  # noqa: BLE001 — never mask the provider error
        # The credential IS revoked but the flag did not persist, so the
        # "Re-authenticate required" chip would read healthy. Log at ERROR
        # (the caller is already on a provider-failure path; raising here
        # would replace that error with this one).
        log.error(
            "Account auth revoked but the auth_stale flag failed to persist — "
            "the account will NOT show 'Re-authenticate required'",
            exc_info=e, **_acct_log_extras(acct), reason=msg[:200],
        )
    else:
        # db-sme r14 NIT: outside the try, so only a failed PERSIST reaches
        # the ERROR above (a raising log call cannot claim the flag was lost).
        log.warning(
            "Account auth flagged stale — re-authentication required",
            **_acct_log_extras(acct), reason=msg[:200],
        )


def _clear_auth_stale(db, account_id: int) -> None:
    """Clear the stale-auth flag on a successful provider call.

    Idempotent and cheap: reads the setting first and only issues the DB
    delete when the flag is actually set, so every provider-success path —
    including per-message loops (bulk re-triage, retry drain) — can call it
    without write-amplifying the settings table. The common case (account not
    stale) is a cache-backed read with no write.
    """
    try:
        # Use the public helpers so the in-process settings cache
        # is consulted on read and invalidated alongside the DB delete.
        from email_triage.web.db import delete_setting, get_setting
        key = _settings_keys.auth_stale(account_id)
        if get_setting(db, key) is None:
            return  # not stale → nothing to clear (no write)
        delete_setting(db, key)
    except Exception as e:
        log.error(
            "auth-stale flag clear failed; flag may remain set",
            exc_info=e,
            account_id=account_id,
        )


def _resurrect_auth_revoked_retries(db, account_id: int) -> None:
    """Symmetric CLEAR for ``watcher_retry_queue`` rows frozen by auth revocation.

    N-386 — ``mark_retry_dead(reason='auth_revoked')`` at
    ``watcher_retry.py:175`` SET the ``dead_reason`` but nothing on a
    provider-success path CLEARED it, so a mid-outage frozen retry row stayed
    dead forever after the account recovered. Sibling to
    ``_clear_auth_stale``: both fire on every provider-success path via
    ``record_provider_outcome``. Idempotent + cheap — the DB helper skips the
    WAL page write on the common (no-frozen-rows) case.
    """
    try:
        from email_triage.web.db import resurrect_auth_revoked_retries
        n = resurrect_auth_revoked_retries(db, int(account_id))
        if n > 0:
            log.info(
                "Auth restored — resurrected auth-revoked retry rows",
                account_id=int(account_id),
                resurrected=int(n),
            )
    except Exception as e:
        log.error(
            "auth-revoked retry resurrect failed; frozen rows may stay dead",
            exc_info=e,
            account_id=account_id,
        )


def record_provider_outcome(db, acct: dict, exc: BaseException | None) -> None:
    """SSOT for the per-account ``auth_stale`` lifecycle — the one funnel every
    credentialed provider surface routes its outcome through.

    Call after ANY credentialed provider operation (unified poll, Gmail/O365
    push delta, IMAP IDLE connect, Gmail-watch / O365-subscription renew,
    sent-mail capture, bulk re-fetch, topic backscan, the manual Test action):

      * ``exc is None``  → the call succeeded; the credential is alive → CLEAR
        any prior stale-auth flag (idempotent-cheap — see ``_clear_auth_stale``)
        AND resurrect any ``watcher_retry_queue`` rows this account froze with
        ``dead_reason='auth_revoked'`` (N-386 — see
        ``_resurrect_auth_revoked_retries``). Both CLEARs are per-account and
        idempotent; a fleet of provider-success calls collapses to a single
        write on the first success and no-ops after.
      * ``exc is not None`` → the call failed; SET the flag IFF the error is an
        auth-revoked signal (``_maybe_mark_auth_stale`` needle-filters via the
        ``_auth_revoked`` SSOT, so a transient network/5xx error is ignored).

    Routing every provider surface through this single funnel is what keeps the
    flag's set and clear edges symmetric across all ~11 credentialed call sites
    — the asymmetry the divergence census surfaced (2026-06-09, finding #1:
    SET on the poll path only; CLEAR on poll + OAuth re-auth only; push / IDLE /
    renewers / background jobs did neither → dead tokens invisible on those
    paths, and an account flagged by the poll path stayed stuck once it
    recovered via push). N-386 (2026-07-10) extends the same funnel discipline
    to the ``watcher_retry_queue`` auth_revoked lifecycle: the frozen rows were
    the SET-broad / CLEAR-narrow twin of the chip. Sync by design so the async
    loops invoke it as ``await db_call(record_provider_outcome, db, acct, exc)``
    (the  writer-thread serialisation), matching the existing
    ``db_call(_clear_auth_stale, …)`` / ``db_call(_maybe_mark_auth_stale, …)``
    call pattern it replaces.
    """
    try:
        if exc is None:
            _clear_auth_stale(db, acct["id"])
            _resurrect_auth_revoked_retries(db, acct["id"])  # N-386
        else:
            _maybe_mark_auth_stale(db, acct, exc)
    except Exception as e:
        log.error(
            "provider outcome auth-state update failed",
            account_id=(acct.get("id") if hasattr(acct, "get") else None),
            exc_info=e,
        )


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
    # Punch  / panel F8 — the WebAuthn challenge store had no caller for its
    # pruner, and the passkey begin route made that growth reachable WITHOUT
    # authentication. Expired rows already stop matching a consume; this is what
    # makes them leave.
    from email_triage.web.db_auth_helpers import (
        prune_expired_webauthn_challenges,
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
        # N-227c R22 — stamp with deletion count for /admin observability.
        app.state.log_entries_prune_loop_status = {
            "at": now_utc_iso(),
            "deleted": int(deleted or 0),
        }
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
        # Punch  / panel F8 — expired WebAuthn challenges (5-minute TTL).
        # The passkey begin step is unauthenticated, so anyone who can reach
        # /login can mint rows; they stop being consumable at their TTL, and
        # this is the only thing that removes them. Best-effort like its
        # siblings: a failed prune must not block the other four.
        try:
            wc_deleted = await db_call(
                prune_expired_webauthn_challenges, db,
            )
            if wc_deleted:
                log.info("Pruned expired webauthn_challenges rows",
                         deleted=wc_deleted)
        except Exception as e5:
            log.warning("webauthn_challenges prune failed", error=str(e5))

    #  — lease-gated: a global table prune; one instance per tick.
    await supervised_interval_loop(
        "log-entries-pruner", 30 * 60, _tick,
        warmup_secs=30,
        startup_jitter_secs=30.0,
        lease_name="log-entries-pruner",
        lease_conn=app.state.db,
    )


async def _wal_checkpoint_loop(app: FastAPI) -> None:
    """N-432 walresetbug P0 (2026-07-19) — periodic SERIALIZED WAL
    checkpoint.

    Runs ``checkpoint_wal_truncate`` (``@db_write``) via ``db_call``
    every 5 minutes. Paired with ``PRAGMA wal_autocheckpoint = 0`` at
    the opener SSOT so the ONLY WAL-checkpoint fire path in the
    process is this loop under the writer-lock. That serializes the
    checkpoint against every writer AND against every other
    checkpoint, closing the concurrent-race surface the walresetbug
    (SQLite < 3.51.3) exploits.

    Lease-gated: one instance per install per tick (matches the
    ``log-entries-pruner`` shape). ``PRAGMA wal_checkpoint(TRUNCATE)``
    is idempotent — a busy checkpoint just returns busy=1 and the
    next tick retries.
    """
    from email_triage.web.db import checkpoint_wal_truncate
    from email_triage.web.task_supervisor import supervised_interval_loop
    from email_triage.web.db_threadpool import db_call

    # db-sme NTH-1 (2026-07-19): busy-aware short retry. On busy=1 the
    # checkpoint couldn't truncate (a reader transaction outstanding); a
    # 5-min gap risks unbounded WAL growth under pathological long-read
    # + high-write mix. Schedule the next tick 30s out instead of the
    # normal 5min so the WAL trends bounded even under contention.
    _BUSY_RETRY_SECS = 30

    async def _tick() -> None:
        db = app.state.db
        try:
            result = await db_call(checkpoint_wal_truncate, db)
        except Exception as exc:
            log.warning("WAL checkpoint failed", error=str(exc))
            app.state.wal_checkpoint_loop_status = {
                "at": now_utc_iso(),
                "error": str(exc),
            }
            return
        # Log at debug for the happy path (5-min cadence would flood
        # info-level otherwise); at info when the checkpoint reported
        # busy=1 (reader contention prevented a full flush; benign but
        # worth surfacing for observability).
        if result.get("busy"):
            # db-sme NTH-2 (2026-07-19): under `@db_write` no writer CAN be
            # active during this checkpoint call — the busy=1 signal is a
            # READER holding an outstanding read-transaction on an older
            # frame (classic SQLite checkpoint-starvation shape). Wording
            # matches the actual cause so operator investigation of WAL
            # growth doesn't chase a phantom writer.
            log.info(
                "WAL checkpoint busy — reader transaction outstanding, "
                "scheduling short retry",
                busy=result["busy"], log=result["log"],
                checkpointed=result["checkpointed"],
                retry_secs=_BUSY_RETRY_SECS,
            )
            # Fire a short-retry tick outside the normal 5-min interval.
            # Best-effort; if it fails the next scheduled tick still
            # runs and the loop stays alive. Use module-scope `asyncio`
            # (imported at web/app.py top) — a function-local
            # `import asyncio` would LEGB-shadow it per -followup-B
            # (see test_no_legb_shadow_asyncio.py).
            try:
                await asyncio.sleep(_BUSY_RETRY_SECS)
                retry_result = await db_call(checkpoint_wal_truncate, db)
                app.state.wal_checkpoint_loop_status = {
                    "at": now_utc_iso(),
                    "retried": True,
                    **retry_result,
                }
                return
            except Exception as retry_exc:
                log.warning(
                    "WAL checkpoint short-retry failed",
                    error=str(retry_exc),
                )
        app.state.wal_checkpoint_loop_status = {
            "at": now_utc_iso(),
            **result,
        }

    # devils-advocate NTH-1 (2026-07-19): warmup_secs=60 previously
    # created a 60-75s boot window with no checkpoint fire path (auto-
    # checkpoint disabled AND periodic loop not ticking). Under a boot-
    # time ingestion catch-up the WAL could grow unbounded during that
    # window. warmup=5s + jitter=15s narrows the blind window to <=20s
    # while still deferring the first checkpoint past the initial
    # migration + seed run.
    await supervised_interval_loop(
        "wal-checkpoint-loop", 5 * 60, _tick,
        warmup_secs=5,
        startup_jitter_secs=15.0,
        lease_name="wal-checkpoint-loop",
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
    _update_check_once,
    _update_check_sweeper,
    _per_contact_style_gc_sweeper,
    _style_distill_trigger_sweeper,
    _recover_one_retry_row,
    _watcher_retry_sweeper,
    _hipaa_boundary_drift_detector,
    _regulatory_clock_escalator,
    _db_backup_sweeper,
    _embedding_auto_update_sweeper,
    _sent_mail_capture_loop,
    _resolve_capture_interval_hours,
    _seconds_until_next_capture_tick,
    _run_sent_mail_capture_sweep,
    _run_hipaa_counter_for_account,
    #  V3 — Topic retention soft-expire + tombstone horizon-purge sweep.
    _topic_retention_purge_once,
    _topic_retention_purge_sweeper,
)
