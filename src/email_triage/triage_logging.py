"""PHI-safe structured logging with HIPAA mode.

Two modes controlled by a single ``hipaa`` flag in config:

Standard (default):
    Logs include sender addresses, subject lines, classification reasons.
    Useful for troubleshooting in non-medical deployments.

HIPAA (hipaa=True):
    Strips all fields that could constitute PHI: subjects, senders,
    recipients, body content, attachment names, classification reasons.
    Only flow IDs, status transitions, categories, timing, and error
    types are logged.

Usage:
    from email_triage.triage_logging import setup_logging, get_logger
    setup_logging(config.logging)
    log = get_logger("engine.flow")
    log.info("classified", extra={"flow_id": "abc", "category": "invoices"})
"""

from __future__ import annotations

import contextvars
import json
import logging
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    from email_triage.config import LoggingConfig

# Module-level flag — set once at startup via setup_logging().
_hipaa_mode: bool = False


# Process-wide request correlation ID. ASGI middleware sets this on
# every inbound HTTP request; background tasks (watchers, schedulers,
# ACME issuance) set it via ``new_request_context`` so their log lines
# can be traced through the same field. The ContextVar default is
# empty so log lines emitted outside any request context don't get a
# stale ID from a previous one.
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="",
)


def get_request_id() -> str:
    """Return the current request_id, or empty string if outside a context."""
    return request_id_var.get()


def _new_id() -> str:
    """Mint a short request_id. UUID4 truncated to 12 hex chars —
    plenty of namespace for a single-instance install, short enough
    to grep comfortably in journalctl."""
    return uuid.uuid4().hex[:12]


@contextmanager
def new_request_context(name: str | None = None) -> Iterator[str]:
    """Context manager that sets a fresh request_id for the body.

    Use in background tasks / cron-style jobs that originate outside
    an HTTP request:

        with new_request_context("watcher.gmail.poll"):
            ...

    The ``name`` arg is decorative — the ID is just a UUID — but it's
    handy for the caller to log what kind of context it just opened.
    """
    rid = _new_id()
    token = request_id_var.set(rid)
    try:
        yield rid
    finally:
        request_id_var.reset(token)


def is_hipaa_mode() -> bool:
    return _hipaa_mode


def is_account_hipaa(account: Any) -> bool:
    """Resolved HIPAA state for a single email account.

    Returns True if either the system flag is on (global override) or
    the account's own ``hipaa`` column is set. Most-restrictive wins.
    Accepts any mapping-like object (dict, sqlite3.Row, dataclass) —
    looks up ``hipaa`` via ``__getitem__`` then falls back to
    ``getattr``, so callers don't need to normalise.
    """
    if _hipaa_mode:
        return True
    if account is None:
        return False
    try:
        val = account["hipaa"]
    except (KeyError, TypeError, IndexError):
        val = getattr(account, "hipaa", False)
    return bool(val)


def is_account_hipaa_locked(account: Any) -> bool:
    """True when an account's HIPAA flag cannot be unset right now.

    An account is locked if the system HIPAA flag is on AND the
    account was created while system HIPAA was on. Once system HIPAA
    is turned off, the account becomes unlockable (admin can then
    flip its per-account flag off if they wish, with a confirmation).
    """
    if not _hipaa_mode:
        return False
    if account is None:
        return False
    try:
        created_under = account["created_under_system_hipaa"]
    except (KeyError, TypeError, IndexError):
        created_under = getattr(account, "created_under_system_hipaa", False)
    return bool(created_under)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class _JsonFormatter(logging.Formatter):
    """Emits one JSON object per log line."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.now().astimezone().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Merge any extra keys the caller passed.
        if hasattr(record, "_extra"):
            entry.update(record._extra)
        if record.exc_info and record.exc_info[1] is not None:
            entry["error"] = str(record.exc_info[1])
            entry["error_type"] = type(record.exc_info[1]).__name__
        return json.dumps(entry, default=str)


class _TextFormatter(logging.Formatter):
    """Human-readable format: ``timestamp level logger msg key=value ...``"""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        parts = [ts, record.levelname.ljust(8), record.name, record.getMessage()]
        if hasattr(record, "_extra"):
            for k, v in record._extra.items():
                parts.append(f"{k}={v}")
        if record.exc_info and record.exc_info[1] is not None:
            parts.append(f"error={record.exc_info[1]}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# HIPAA-aware logger wrapper
# ---------------------------------------------------------------------------

class TriageLogger:
    """Thin wrapper that strips PHI from structured ``extra`` data in HIPAA mode."""

    # Fields that are ALWAYS stripped in HIPAA mode.
    _PHI_KEYS = frozenset({
        "sender", "senders", "recipients", "subject", "body",
        "body_text", "body_html", "links", "attachment", "attachments",
        "reason", "classification_reason", "headers",
    })

    # Fields that are ALWAYS stripped — both modes — because their
    # value is never a legitimate log payload regardless of HIPAA
    # state. Token leakage in hash-chained logs would survive
    # rotation and could not be expunged without breaking the
    # chain (HIPAA §164.312(b) audit controls + §164.312(e)(1)
    # transmission security — but the rule applies universally,
    # not only on HIPAA installs). Audit punch-list #111
    # (2026-05-08).
    #
    # Adding a key here propagates to every log row across the
    # install. Treat as a security-critical change; do not add
    # operator-debug fields to this set — only secret-shape
    # values that should never have been at the call site.
    _TOKEN_KEYS = frozenset({
        "authorization", "access_token", "refresh_token", "id_token",
        "code", "auth_code", "client_secret", "bearer_token",
        "api_key", "password", "smtp_password", "imap_password",
        "session_token",
    })

    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def _sanitise(self, extra: dict[str, Any] | None) -> dict[str, Any]:
        # Always inject the current request_id (if any) before stripping
        # PHI. The ID is an opaque UUID, never sensitive, so HIPAA mode
        # leaves it alone.
        rid = request_id_var.get()
        if extra is None:
            base: dict[str, Any] = {}
        elif _hipaa_mode:
            base = {
                k: v for k, v in extra.items()
                if k not in self._PHI_KEYS and k not in self._TOKEN_KEYS
            }
        else:
            base = {
                k: v for k, v in extra.items()
                if k not in self._TOKEN_KEYS
            }
        if rid and "request_id" not in base:
            base["request_id"] = rid
        return base

    def _log(
        self,
        level: int,
        msg: str,
        extra: dict[str, Any] | None = None,
        exc_info: Any = None,
    ) -> None:
        safe = self._sanitise(extra)
        # Resolve exc_info before passing to makeRecord.
        resolved_exc_info = None
        if exc_info:
            if isinstance(exc_info, BaseException):
                resolved_exc_info = (type(exc_info), exc_info, exc_info.__traceback__)
            elif exc_info is True:
                import sys
                resolved_exc_info = sys.exc_info()
            else:
                resolved_exc_info = exc_info
        record = self._logger.makeRecord(
            self._logger.name,
            level,
            "(triage)",
            0,
            msg,
            (),
            resolved_exc_info,
        )
        record._extra = safe  # type: ignore[attr-defined]
        self._logger.handle(record)

    def debug(self, msg: str, **extra: Any) -> None:
        self._log(logging.DEBUG, msg, extra)

    def info(self, msg: str, **extra: Any) -> None:
        self._log(logging.INFO, msg, extra)

    def warning(self, msg: str, **extra: Any) -> None:
        self._log(logging.WARNING, msg, extra)

    def error(self, msg: str, exc_info: Any = None, **extra: Any) -> None:
        self._log(logging.ERROR, msg, extra, exc_info=exc_info)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_logging(config: LoggingConfig) -> None:
    """Initialise logging for the whole process.  Call once at startup."""
    global _hipaa_mode
    _hipaa_mode = config.hipaa

    root = logging.getLogger("email_triage")
    root.setLevel(getattr(logging, config.level.upper(), logging.INFO))

    # Remove existing handlers (safe to call multiple times in tests).
    root.handlers.clear()

    fmt: logging.Formatter
    if config.format == "json":
        fmt = _JsonFormatter()
    else:
        fmt = _TextFormatter()

    # Console handler
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(fmt)
    root.addHandler(console)

    # Optional file handler
    if config.file:
        fh = logging.FileHandler(config.file)
        fh.setFormatter(fmt)
        root.addHandler(fh)

    if _hipaa_mode:
        root.info("HIPAA logging mode active -- PHI excluded from logs")


def get_logger(name: str) -> TriageLogger:
    """Return a PHI-aware logger under the ``email_triage`` namespace."""
    return TriageLogger(logging.getLogger(f"email_triage.{name}"))


# ---------------------------------------------------------------------------
# SQLite log handler (for admin web log viewer)
# ---------------------------------------------------------------------------

class SQLiteLogHandler(logging.Handler):
    """Write log entries to a SQLite ``log_entries`` table.

    Batches inserts — commits every *flush_interval* records or on flush().
    Designed to be added to the ``email_triage`` root logger alongside
    the console handler.

    #131 — keeps the last emitted ``row_hash`` in memory
    (``self._last_row_hash``) so the hot path no longer pays a SELECT
    per emit. ``logging.Handler.emit`` is serialised per-handler by
    ``self.lock`` and this handler is the only writer to ``log_entries``
    in the running process (the offline ``insert_log_entry`` helper is
    test/structured-event use only). The first emit primes the cache via
    one SELECT; subsequent emits chain off the in-memory tail.
    """

    def __init__(
        self,
        conn: "sqlite3.Connection",
        flush_interval: int = 10,
        level: int = logging.INFO,
    ) -> None:
        super().__init__(level)
        self._conn = conn
        self._flush_interval = flush_interval
        self._pending = 0
        # Sentinel ``None`` means "cache cold — read from DB on next
        # emit". After the first emit the cache holds the empty-string
        # genesis or the previous emit's row_hash.
        self._last_row_hash: str | None = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            import json as _json
            ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
            # Collect extra fields (anything the caller passed via **kwargs).
            #
            # The TriageLogger adapter packs the caller's keyword args into a
            # single ``record._extra`` dict (see ``_TriageLoggerAdapter`` /
            # ``_filter_phi_extra`` for the redaction step). Unpack that dict
            # into ``extra`` so the /logs page's pill renderer + Details
            # column can see ``error``, ``account``, ``account_id``,
            # ``flow_id``, etc. as top-level keys. Without this, the whole
            # caller dict landed under a single stringified ``_extra`` key
            # and the pill loop matched nothing — the operator-facing log
            # entry showed only the message with no actionable context.
            extra = {}
            for key in list(vars(record)):
                if key in _STANDARD_LOG_KEYS:
                    continue
                value = getattr(record, key)
                if key == "_extra" and isinstance(value, dict):
                    # Hoist nested keys to top-level so /logs sees them.
                    for inner_k, inner_v in value.items():
                        extra[inner_k] = str(inner_v)
                else:
                    extra[key] = str(value)

            # Preserve exception info when the caller used logger.error(...,
            # exc_info=e, ...). Mirrors _JsonFormatter / _TextFormatter so the
            # SQLite-backed /logs viewer shows the same `error` + `error_type`
            # fields the stdout sink already emits. Without this, every
            # exc_info-bearing log line landed in /logs without its exception
            # detail — making failures like "Failed to move message" opaque.
            if record.exc_info and record.exc_info[1] is not None:
                extra["error"] = str(record.exc_info[1])
                extra["error_type"] = type(record.exc_info[1]).__name__

            extra_json = _json.dumps(extra) if extra else "{}"

            # #42 — hash-chain. logging.Handler.emit is serialized
            # per-handler by self.lock, so the read-then-insert here
            # is race-free within one process.
            # #131 — the SELECT on the hot path was a per-emit cost on
            # an indexed-but-not-trivial table. Cache the last row_hash
            # on the instance; only hit the DB on the very first emit
            # (cold cache).
            from email_triage.web.db import (
                compute_log_row_hash, get_last_log_row_hash,
            )
            if self._last_row_hash is None:
                self._last_row_hash = get_last_log_row_hash(self._conn)
            prev_hash = self._last_row_hash
            row_hash = compute_log_row_hash(
                prev_hash, ts, record.levelname, record.name,
                record.getMessage(), extra_json,
            )

            self._conn.execute(
                "INSERT INTO log_entries "
                "(ts, level, logger, message, extra_json, created_at, "
                " prev_hash, row_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, record.levelname, record.name, record.getMessage(),
                 extra_json, ts, prev_hash, row_hash),
            )
            # Update in-memory tail BEFORE the commit decision — even
            # if the next handler operation crashes, the cache state
            # mirrors what's in the (uncommitted) connection.
            self._last_row_hash = row_hash
            self._pending += 1
            if self._pending >= self._flush_interval:
                self._conn.commit()
                self._pending = 0
        except sqlite3.ProgrammingError:
            # #148 — DB connection was closed (typically during
            # container shutdown after the audit-anchor flush). The
            # row would have been lost regardless; suppress the
            # user-visible traceback that ``handleError`` writes to
            # stderr and downgrade to ``logging.lastResort`` so the
            # message at least reaches stderr in the standard log
            # format. Reset ``_last_row_hash`` so any subsequent
            # emit (rare during shutdown but possible) re-syncs from
            # whatever connection is still alive — the chain anchor
            # at #131.1 covers the on-disk continuity, the in-memory
            # cache just needs to drop the stale tail.
            self._last_row_hash = None
            fallback = logging.lastResort
            if fallback is not None:
                try:
                    fallback.handle(record)
                except Exception:
                    # ``lastResort`` itself failed (stderr closed?) —
                    # nothing more we can safely do. Swallow.
                    pass
        except Exception:
            # Reset the cache on any failure so the next emit
            # re-syncs from the DB. Keeps the chain consistent if
            # an INSERT failed and was rolled back.
            self._last_row_hash = None
            self.handleError(record)

    def flush(self) -> None:
        if self._pending > 0:
            try:
                self._conn.commit()
                self._pending = 0
            except Exception:
                pass

    def close(self) -> None:
        self.flush()
        super().close()


# Standard LogRecord attributes to exclude from 'extra'.
_STANDARD_LOG_KEYS = frozenset({
    "name", "msg", "args", "created", "relativeCreated", "exc_info",
    "exc_text", "stack_info", "lineno", "funcName", "pathname",
    "filename", "module", "thread", "threadName", "process",
    "processName", "levelname", "levelno", "message", "msecs",
    "taskName",
})


def add_sqlite_handler(conn: "sqlite3.Connection") -> None:
    """Add a SQLite log handler to the email_triage root logger.

    Call after ``setup_logging()`` and after ``init_db()`` has created
    the ``log_entries`` table.
    """
    root = logging.getLogger("email_triage")
    handler = SQLiteLogHandler(conn, flush_interval=5)
    root.addHandler(handler)
