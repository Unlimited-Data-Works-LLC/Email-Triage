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
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from email_triage._isotime import NOW_UTC_ISO_RE, now_utc_iso

from email_triage._secret_scrub import SECRET_TOKEN_KEYS as _SECRET_TOKEN_KEYS
from email_triage._secret_scrub import redact_secret_tokens as _redact_secret_tokens
from email_triage._errfmt import redact_exc
from typing import Any, Iterator, TYPE_CHECKING
from email_triage._dbapi_errors import DB_ERRORS, DB_PROGRAMMING_ERRORS

if TYPE_CHECKING:
    from email_triage.config import LoggingConfig

# Module-level flag — set once at startup via setup_logging().
_hipaa_mode: bool = False


# Canonical PHI-redaction sentinel (A3, divergence census 2026-06-09). The
# same logical "this field was PHI-stripped" marker had drifted to TWO
# spellings — ``[redacted]`` (the PHI sites + the watcher reason-guard) and
# ``[REDACTED]`` (sent_mail_index's HIPAA-subject branch). They never crossed
# to leak (the guard checks a reason, the index writes a subject), but the
# divergence is a latent hazard: a future path routing the uppercase value to
# the lowercase guard would leak PHI. One spelling, enforced by
# tests/test_redaction_sentinel_pin.py.
# NOTE: this is the PHI sentinel. The SECRET-redaction marker used in
# web/db.py (passwords/keys scrubbed from error strings) is a DISTINCT concern
# with its own shape — NOT this constant.
REDACTED = "[redacted]"


# N-338 R31 (2026-07-04 hipaa-sme + DA follow-up on N-300 tranche  gap):
# ``Safe`` is the explicit caller-guaranteed non-PHI marker for the
# positional-args HIPAA gate. Wrap a string arg in ``Safe(...)`` when the
# caller GUARANTEES the value carries no §164.514(b) 18-identifier content
# (e.g. a compile-time literal, a well-known category name, a bounded
# provider constant). In HIPAA mode ``_gate_positional_args`` unwraps
# ``Safe`` to the underlying string; every OTHER string redacts to
# ``<redacted>`` (fail-CLOSED). N-300 previously allow-listed any
# ``len(s) <= 64 and "@" not in s and ":" not in s`` string — that
# predicate silently passes phone / SSN / DOB / MRN / patient-name / ZIP /
# ICD-10 shapes, i.e. the identifier set §164.514(b) targets.
#
# Usage:
#     from email_triage.triage_logging import Safe, get_logger
#     log = get_logger("engine.flow")
#     log.info("stage=%s reason=%s", Safe("classify"), Safe(reason_code))
class Safe:
    """Explicit non-PHI marker for TriageLogger positional string args.

    ``Safe(value)`` unwraps to ``value`` inside ``_gate_positional_args``
    when HIPAA mode is on. Constructor validates ``value`` is ``str`` so
    a stray ``Safe(patient_email)`` at least surfaces the caller's intent
    (the wrapper is DELIBERATE — a caller who wraps commits to the
    PHI-free claim).
    """
    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(
                f"Safe wraps str only; got {type(value).__name__}"
            )
        # Compile-time slip defence (hipaa-sme N-338 fix 2, 2026-07-04):
        # a stray ``Safe(patient_email)`` or ``Safe(subject_line)`` at a
        # call site would silently egress PHI into the msg body. The
        # constructor refuses the two coarsest PHI-shape smells so a
        # slip fails LOUD (TypeError) instead of quiet. Not exhaustive
        # — the caller is the enforceable owner; this is a cheap net.
        if "@" in value:
            raise TypeError(
                "Safe refuses email-shaped values ('@' present); "
                "this is a PHI-leak defence — pass an opaque scalar "
                "or wrap a known-safe literal"
            )
        if len(value) > 128:
            raise TypeError(
                f"Safe refuses long strings ({len(value)} > 128 chars); "
                "long strings are the PHI-body shape"
            )
        self.value = value

    def __repr__(self) -> str:
        return f"Safe({self.value!r})"

    def __reduce__(self) -> tuple[Any, tuple[str]]:
        """Cross-process pickle support (db-sme N-338 D1, 2026-07-04):
        ``__slots__`` blocks the default pickle __dict__ path. Without an
        explicit ``__reduce__`` a caller that submits ``Safe(...)`` args
        to a ``ProcessPoolExecutor`` sees a ``PicklingError`` at run
        time. No current caller crosses processes with a ``Safe``, but
        the round-trip is cheap defence.
        """
        return (self.__class__, (self.value,))


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
    """Mint a short request_id. 12 hex chars — plenty of namespace for
    a single-instance install, short enough to grep comfortably in
    journalctl.

    N-244b R25: SSOT `_ids.new_short_id("")` returns the bare hex tail.
    """
    from email_triage._ids import new_short_id
    return new_short_id("")


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


def account_hipaa_effective(
    *,
    account: Any = None,
    message: Any = None,
) -> bool:
    """SSOT: is THIS PHI operation subject to HIPAA handling right now?

    Most-restrictive-wins over three independent axes (PD#8 /
    feedback_most_restrictive_wins).  HIPAA applies if ANY of:

    * The **system flag** is on  (``is_hipaa_mode()`` — global install-wide
      override; covers every account whether per-account flag is set or not).
    * The **per-account flag** is set on the account in scope
      (``account.hipaa`` / ``account["hipaa"]`` — a non-HIPAA install may
      have individual HIPAA-flagged mailboxes).
    * The **message stamp** is True  (``message.hipaa`` — stamped at fetch
      time from ``system_hipaa OR account.hipaa``; accepted as a convenience
      so action-layer callers do not have to thread the account separately).

    Call sites in the per-account PHI layer MUST pass at least one of
    ``account=`` or ``message=``.  Passing *neither* returns the install-wide
    flag only — that branch exists for the genuinely install-wide fallback
    callers, NOT as a license to call this bare on a PHI path.  The invariant
    "no PHI-decision site invokes this context-free" is enforced
    STRUCTURALLY, not by convention: ``tests/test_account_hipaa_scope_pin.py``
    bans a bare/aliased ``is_hipaa_mode()`` in the per-account PHI layers, so a
    new PHI site that reaches for the global flag (or calls this with no
    context) is caught in CI.  Otherwise most-restrictive-wins: a ``message``
    stamped ``hipaa=True`` (or the system flag on) returns True even when
    ``account`` is None.

    This is the **only authorised answer** to "is this PHI subject to HIPAA
    handling right now?" for per-account PHI decisions (redaction, egress
    gating, audit triggers, per-message branches).  Install-wide decisions
    (boot enforcement, admin config display, BAA-ack, breach posture) stay
    on ``is_hipaa_mode()`` directly — they are correctly install-scoped.

    N-77 / class-fix: before this helper, ~54 per-account PHI decision sites
    called ``is_hipaa_mode()`` alone, silently skipping the per-account flag
    on non-HIPAA installs.  Route every category-B PHI-decision site through
    here; leave category-A (install-wide) sites on ``is_hipaa_mode()``.
    """
    # Axis 1: system-wide flag (cheapest check — short-circuit). Read the
    # module global ``_hipaa_mode`` DIRECTLY (not is_hipaa_mode()) — identical
    # value, but it keeps this SSOT out of its own bare-is_hipaa_mode() ban and
    # matches the tests that monkeypatch ``_tl._hipaa_mode``.
    if _hipaa_mode:
        return True
    # Axis 2: per-message stamp (stamped at fetch from system OR account flag)
    if message is not None and bool(getattr(message, "hipaa", False)):
        return True
    # Axis 3: per-account flag
    if account is not None:
        try:
            val = account["hipaa"]
        except (KeyError, TypeError, IndexError):
            val = getattr(account, "hipaa", False)
        if bool(val):
            return True
    return False


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
            # Punch 606: stderr/journald is retained too; same secret funnel
            # as the log_entries sink.
            "msg": scrub_persisted_log_text(record.getMessage()),
        }
        # Merge any extra keys the caller passed.
        if hasattr(record, "_extra"):
            entry.update({k: scrub_persisted_log_text(v)
                          for k, v in record._extra.items()})
        if record.exc_info and record.exc_info[1] is not None:
            # N-42: the exc_info exception text is the SEPARATE leak leg (a log
            # call with exc_info=True, not via fmt_exc) — value-scrub it too.
            entry["error"] = scrub_persisted_log_text(redact_exc(record.exc_info[1]))
            entry["error_type"] = type(record.exc_info[1]).__name__
        return json.dumps(entry, default=str)


class _TextFormatter(logging.Formatter):
    """Human-readable format: ``timestamp level logger msg key=value ...``"""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        # Punch 606: same secret funnel as the log_entries sink.
        parts = [ts, record.levelname.ljust(8), record.name,
                 scrub_persisted_log_text(record.getMessage())]
        if hasattr(record, "_extra"):
            for k, v in record._extra.items():
                parts.append(f"{k}={scrub_persisted_log_text(v)}")
        if record.exc_info and record.exc_info[1] is not None:
            parts.append(f"error={scrub_persisted_log_text(redact_exc(record.exc_info[1]))}")  # N-42 + 606
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
        # census run17 #1 — LLM-over-PHI output + free-text content keys. The
        # model's verbatim response (the classify debug logs) is the highest-
        # density PHI; these are stripped on the TriageLogger console/file leg.
        # The un-expungeable HMAC log_entries SINK is additionally guarded by
        # the fail-closed ALLOWLIST ``redact_persisted_extra`` (defence-in-depth
        # — a denylist alone is fail-OPEN: "raw" was absent from this set, which
        # is exactly how run17 #1 leaked).
        # Conservative: only UNAMBIGUOUS LLM-output keys (a key like "response"
        # /"content" collides with benign operator fields — e.g. invite.py logs
        # the calendar accept/decline as `response=` — so it stays OFF the
        # denylist; the sink ALLOWLIST is the fail-closed net for those).
        "raw", "prompt", "completion", "llm_response",
    })

    # Fields that are ALWAYS stripped — both modes — because their
    # value is never a legitimate log payload regardless of HIPAA
    # state. Token leakage in hash-chained logs would survive
    # rotation and could not be expunged without breaking the
    # chain (HIPAA §164.312(b) audit controls + §164.312(e)(1)
    # transmission security — but the rule applies universally,
    # not only on HIPAA installs). Audit the backlog 
    # (2026-05-08).
    #
    # Adding a key here propagates to every log row across the
    # install. Treat as a security-critical change; do not add
    # operator-debug fields to this set — only secret-shape
    # values that should never have been at the call site.
    #: Token-shaped extra-field keys stripped from every log record.
    #: SSOT-converged onto _secret_scrub.SECRET_TOKEN_KEYS (census #6) so the
    #: log-redaction key list and the persisted-error-text scrub key list
    #: can't drift apart.
    _TOKEN_KEYS = _SECRET_TOKEN_KEYS

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
            # Punch 547 (PD-8): the denylist above is fail-OPEN for any key
            # it does not name — ``raw_head_scrubbed`` passed it to the
            # console/journald leg while ``raw`` was listed. Apply the SAME
            # fail-closed allow-list the persisted sink uses (one funnel,
            # PD-5): a key not in _PERSIST_SAFE_KEYS keeps its name, loses
            # its value.
            base = redact_persisted_extra(base, hipaa=True)
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
        # N-208 R22 CI fix (2026-07-02): callers that pass `extra={"_extra":
        # {inner_fields}}` (a defense-in-depth double-wrap used by
        # `db_writelock.py` to survive stdlib's LogRecord dropping unknown
        # top-level fields) round-trip through `_merge_extra` as
        # `{"_extra": inner_fields}` at this point. The stored-record contract
        # is `rec._extra == inner_fields` (a flat dict of the emitted fields),
        # so unwrap the outer layer when we see the pattern. Preserves the
        # pre-fix behaviour for callers that pass a flat `extra={...}`.
        if isinstance(safe.get("_extra"), dict) and len(safe) <= 2:  # allow request_id alongside
            _unwrapped = dict(safe["_extra"])
            if "request_id" in safe and "request_id" not in _unwrapped:
                _unwrapped["request_id"] = safe["request_id"]
            safe = _unwrapped
        record._extra = safe  # type: ignore[attr-defined]
        # N-196b R21_4 (operator ruling 2026-07-02): ALSO promote the sanitised
        # extra kwargs onto the LogRecord as top-level attributes — mirrors
        # stdlib's `logging.Logger._log(extra=...)` semantics so tests that
        # assert on `record.<field>` (matching the stdlib contract) don't break
        # on the TriageLogger swap. Guard against clobbering LogRecord's own
        # attribute set.
        #
        # N-353 R31 (2026-07-05 trust-repair fix-forward per PHASE3 audit_hmac
        # d8df4a24 finding + the backlog  = TASK ): mirror stdlib's FULL
        # reserved-attr set explicitly. The `k in record.__dict__` clause below
        # catches the init-set attrs dynamically so no live PHI leak exists,
        # but defence-in-depth wants an explicit named set: (a) documents
        # intent; (b) survives a future Python release adding a new LogRecord
        # init-attr the codebase hasn't yet imported. Source: stdlib
        # `logging.LogRecord.__init__` — the enumerated attrs it sets, plus
        # `message` (set by `LogRecord.getMessage`) and `asctime` (set by the
        # formatter). Full set: 22 keys. Do NOT prune — every entry is a
        # LogRecord field a caller's `extra={key: v}` would clobber if the
        # dynamic check ever regressed.
        _reserved = {
            "name", "msg", "args", "levelname", "levelno",
            "pathname", "filename", "module", "exc_info", "exc_text",
            "stack_info", "lineno", "funcName", "created", "msecs",
            "relativeCreated", "thread", "threadName", "processName",
            "process", "message", "asctime",
            # Python 3.12+ added taskName (asyncio task context) —
            # `tests/test_n353_triage_logger_reserved_set_complete.py`'s
            # behavioural teeth caught this by probing `LogRecord.__init__`
            # directly. Do NOT drop this on a Python-version downgrade;
            # the guard is fail-open on absence.
            "taskName",
        }
        if safe:
            for k, v in safe.items():
                if k in _reserved or k in record.__dict__:
                    continue  # never clobber a LogRecord built-in
                record.__dict__[k] = v
        self._logger.handle(record)

    def _merge_extra(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """N-196b R21_4 (2026-07-02): also accept stdlib-style `extra=<dict>`
        alongside the TriageLogger `**extra` shape. Callers migrated from
        `logging.getLogger` typically write `.info("msg", extra={...})` and
        expect the dict's keys to appear as LogRecord attributes (stdlib
        semantics). Merge the `extra=` kwarg into the top-level `**extra`
        pack so both shapes populate the same sanitised extras dict."""
        merged = dict(kwargs)
        nested_extra = merged.pop("extra", None)
        if isinstance(nested_extra, dict):
            for k, v in nested_extra.items():
                merged.setdefault(k, v)
        return merged

    def _format_msg(self, msg: str, args: tuple[Any, ...]) -> str:
        """N-196b R21_4 (2026-07-02): accept stdlib-style `%`-formatted
        positional args so `log.info("foo %s bar", value)` works — matches
        stdlib's `logging.Logger.info(msg, *args)` semantics.

        N-300 R30 (2026-07-03 HIPAA-SME + DA follow-up on N-196b): in
        HIPAA mode, positional args are TYPE-GATED to bounded-scalar
        shapes (int / float / bool / None / short opaque strings) BEFORE
        interpolation. A caller writing `log.info("account %s",
        patient_email)` in a HIPAA-mode process previously interpolated
        the value into `record.msg` past `_sanitise` (which only
        filters the extras DICT, not positional args). The gate now
        redacts non-scalar / long-string positional args to
        `<redacted>` so the msg body stays PHI-safe.

        Silent on `msg % args` errors (preserve stdlib's "lazy
        formatting" fail-open behaviour). Errored fallback repr()s
        every arg — the same HIPAA-mode gate applies before repr() so
        the fail-open branch cannot egress PHI either.
        """
        if not args:
            return msg
        safe_args = self._gate_positional_args(args)
        try:
            return msg % safe_args
        except (TypeError, ValueError):  # pragma: no cover — bad format
            return msg + " " + " ".join(repr(a) for a in safe_args)

    def _gate_positional_args(self, args: tuple[Any, ...]) -> tuple[Any, ...]:
        """N-338 R31 (2026-07-04) — HIPAA gate on positional-args
        interpolation, fail-CLOSED on strings.

        Allow-list: ``None`` + numeric scalars (int / float / bool). String
        args require an explicit :class:`Safe` wrapper — bare strings
        redact to ``<redacted>``. Everything else redacts too. Effectively
        a no-op outside ``_hipaa_mode``.

        Supersedes N-300 R30 (rejected by hipaa-sme + DA panel 2026-07-03):
        the prior ``len<=64 and '@' not in a and ':' not in a`` predicate
        allow-listed the exact identifier shapes §164.514(b) targets —
        phone / SSN / DOB / MRN / patient-name / ZIP / ICD-10 codes /
        short clinical subject strings all sailed through. Fail-open on
        the 18-identifier set. Fix moves to an EXPLICIT-opt-in marker so
        every string in HIPAA mode either (a) carries a
        ``Safe(...)`` claim from the caller or (b) redacts.
        """
        if not _hipaa_mode:
            return args
        gated: list[Any] = []
        for a in args:
            if a is None or isinstance(a, (int, float, bool)):
                gated.append(a)
            elif isinstance(a, Safe):
                gated.append(a.value)
            else:
                gated.append("<redacted>")
        return tuple(gated)

    def debug(self, msg: str, *args: Any, **extra: Any) -> None:
        self._log(logging.DEBUG, self._format_msg(msg, args), self._merge_extra(extra))

    def info(self, msg: str, *args: Any, **extra: Any) -> None:
        self._log(logging.INFO, self._format_msg(msg, args), self._merge_extra(extra))

    def warning(self, msg: str, *args: Any, **extra: Any) -> None:
        self._log(logging.WARNING, self._format_msg(msg, args), self._merge_extra(extra))

    def error(self, msg: str, *args: Any, exc_info: Any = None, **extra: Any) -> None:
        self._log(logging.ERROR, self._format_msg(msg, args), self._merge_extra(extra), exc_info=exc_info)

    def exception(self, msg: str, *args: Any, **extra: Any) -> None:
        """N-196b R21_4 (2026-07-02 CI fix): stdlib `Logger.exception(msg)`
        parity — equivalent to `error(msg, exc_info=True)`. Called by code
        paths that catch an exception and want the traceback in the log
        without threading `exc_info=True` manually. Post-N-196b migration,
        `embedding_bits/__init__.py:1316` (and other pre-existing
        `logger.exception(...)` callers) broke CI without this."""
        self._log(logging.ERROR, self._format_msg(msg, args), self._merge_extra(extra), exc_info=True)

    def critical(self, msg: str, *args: Any, exc_info: Any = None, **extra: Any) -> None:
        """N-196b R21_4 (2026-07-02 CI fix): stdlib `Logger.critical(msg)`
        parity — same semantics as `error`, one severity higher."""
        self._log(logging.CRITICAL, self._format_msg(msg, args), self._merge_extra(extra), exc_info=exc_info)

    def log(self, level: int, msg: str, *args: Any, exc_info: Any = None, **extra: Any) -> None:
        """N-196b R21_4 (2026-07-02 CI fix): stdlib `Logger.log(level, msg)`
        parity — passthrough to `_log` with caller-chosen level. Used by
        code that dispatches severity dynamically."""
        self._log(level, self._format_msg(msg, args), self._merge_extra(extra), exc_info=exc_info)


# ---------------------------------------------------------------------------
# Persisted-log redaction SSOT (census run17 #1)
# ---------------------------------------------------------------------------
# The ``log_entries`` table is HMAC-hash-chained and write-once: a persisted PHI
# value can never be expunged without breaking the chain, which is both the
# §164.312(b) audit-controls record and the §164.312(c)(1) integrity witness
# (one property, one citation set, shared with ``_errfmt``; punch 462). The
# PHI field-strip used to live ONLY on the TriageLogger path
# (``_sanitise``), so a raw ``logging.getLogger`` bypassed it and free-text PHI
# rode into the chain (run17 #1). This is the FAIL-CLOSED chokepoint applied at
# EVERY persisted-log sink (``SQLiteLogHandler.emit`` + ``db.audit.insert_log_entry``)
# BEFORE the row is hashed+stored — so the strip is enforced regardless of how
# the logger was obtained, and the hash preimage == the stored value.
#
# It is an ALLOWLIST, not a denylist, per the 3-SME panel (hipaa-sme + db-sme +
# devils-advocate, 2026-06-27): on an un-expungeable table a denylist is
# fail-OPEN by construction (a new PHI-shaped key — "raw"/"prompt"/… — that
# nobody added to the denylist leaks). Only known-safe operator-debug + plumbing
# keys persist their value; every other key keeps its NAME (so the /logs viewer
# still shows the field existed) but its value is replaced with a placeholder.
# Secret-shaped (_TOKEN_KEYS) values are stripped in BOTH modes (a secret is
# never a legitimate log payload); the PHI allowlist applies in HIPAA mode.

#: Operator-debug + plumbing keys that may PERSIST their value into the HMAC
#: log_entries table. Curated for the /logs viewer's needs (the N-42 pill
#: renderer hoists error/account/account_id/flow_id). Add a key here only after
#: confirming it is never a PHI/free-text carrier. Guarded by a /logs render
#: round-trip test + the sink-redaction behavioural pin.
_PERSIST_SAFE_KEYS = frozenset({
    "request_id", "flow_id", "message_id", "subscription_id", "watch_id",
    "job_id", "task_id", "thread_id", "uid",
    "account_id", "account", "account_name", "owner", "owner_id", "user_id",
    "category", "status", "outcome", "state", "kind", "action", "event",
    "phase", "step", "provider", "folder_role",
    "error", "error_type", "error_kind", "error_code", "exc_type",
    "count", "counts", "n", "total", "num", "attempt", "retries", "limit",
    "elapsed_ms", "duration_ms", "ms", "seconds", "size", "bytes",
    "level", "logger", "name", "method", "status_code", "request_path", "route",
    # Added per the run17 #1 SME diff-review (db-sme + devils-advocate): the
    # /logs renderer's declared priority_keys + e.extra.* reads (logs.html) and
    # non-PHI surrogate IDs — confirmed live emitters, all opaque IDs/classes/
    # durations, never message content. The survival pin DERIVES the required
    # set from logs.html so this list can't silently fall behind the view.
    "run_id", "elapsed_secs", "error_class", "error_msg", "provider_type",
    "topic_id", "draft_id", "previous_external_id", "external_id",
    # Punch 547: the HIPAA-boot transmission-security attestation (an operator-
    # set config label + a bool; never message content). It is §164.312(e)
    # evidence, and the sink allow-list was silently blanking it in
    # log_entries; the console leg now shares this allow-list.
    "perimeter_tls_attestation", "perimeter_tls_attestation_known_shape",
    # Panel 547 hipaa F1: the rest of the SAME H-04 attestation row — two
    # config booleans, the configured bind host and a derived boolean. Pinned
    # by tests/test_h04_attestation_survives_redaction_pin.py (derived from the
    # call's own kwargs, so a key added there later must be allow-listed here).
    "require_https_app_layer", "tls_enabled", "bind_host",
    "bind_host_public_routable",
    # Punch 553 / N-556 (hipaa-b1 O5-H2, O5-H4): the egress-disclosure
    # acknowledgment id (``egress:<kind>:<host>``) and the update-check
    # before/after state (``off`` / ``on:<host>``). Admin-set config + a
    # fixed vocabulary, never mail content; without these the chained
    # §164.316(b)(1) record reads "[redacted]" on a HIPAA install.
    "disclosure_id", "update_check_before", "update_check_after",
})

#: Replaces a non-allowlisted value at the persisted-log sink. Keeps the field
#: NAME (operator sees the key existed) but never the value.
#:
#: N-217 R23 (2026-07-02): also the SSOT display-placeholder for every
#: caller-side redaction site (digest, digest_render, recipient_digest,
#: profile, email_watches, triage_classify, triage_one). Callers import as
#: `from email_triage.triage_logging import REDACTED_PLACEHOLDER` (public
#: alias) — the leading-underscore form is kept for backward-compat only.
_REDACTED_PLACEHOLDER = "[redacted]"
REDACTED_PLACEHOLDER = _REDACTED_PLACEHOLDER  # public alias for callers


def redact_persisted_extra(
    extra: dict[str, Any], *, hipaa: bool, phi_allowlist: bool = True
) -> dict[str, Any]:
    """Fail-CLOSED redaction for the un-expungeable HMAC ``log_entries`` sink.

    The ONE chokepoint both persisted-log sinks call BEFORE building/hashing
    ``extra_json`` (so the hash preimage == the stored value). Token-shaped
    keys (:data:`SECRET_TOKEN_KEYS`) are placeholdered in EVERY mode + regardless
    of ``phi_allowlist`` (a secret is never a legitimate log payload).

    ``phi_allowlist`` (default True) applies the full PHI ALLOWLIST for the
    UNCURATED raw-``logging.getLogger`` hot path (``SQLiteLogHandler.emit``): in
    HIPAA mode every key not in :data:`_PERSIST_SAFE_KEYS` is placeholdered
    (fail-closed on the write-once chain, per the run17 #1 SME panel).

    CURATED callers pass ``phi_allowlist=False`` → secret-strip ONLY. The sole
    production caller of ``insert_log_entry`` is the CLI admin-op audit, which
    already passes its own ``_SAFE_ARG_KEYS``-curated payload (no PHI). Applying
    the PHI allowlist THERE would (a) destroy the §164.312(b) audit-row CONTENT
    — the admin action name / flags / error_class → ``[redacted]`` — without
    removing any leak (a regression in the wrong OCR direction, asymmetric
    across the pre/post-``setup_logging`` boundary), and (b) fork a 2nd PHI
    allowlist that drifts from ``_SAFE_ARG_KEYS`` (PD#5). So curated callers get
    the secret strip only. (devils-advocate diff-review, 2026-06-27.)

    The field NAME is preserved; only the value is replaced.

    Punch 606: a value that survives the key rules is still value-scrubbed
    for secret SHAPES (:func:`scrub_persisted_log_text`) in every mode and
    regardless of ``phi_allowlist``. An allow-listed key (``error``) can carry
    exception text with ``access_token=...`` inside it; a key rule cannot see
    that.
    """
    if extra is None:
        return {}
    out: dict[str, Any] = {}
    for k, v in extra.items():
        if k in _SECRET_TOKEN_KEYS:
            out[k] = _REDACTED_PLACEHOLDER
        elif phi_allowlist and hipaa and k not in _PERSIST_SAFE_KEYS:
            out[k] = _REDACTED_PLACEHOLDER
        else:
            out[k] = scrub_persisted_log_text(v)
    return out


def scrub_persisted_log_text(value: Any) -> Any:
    """THE secret-value funnel for the HMAC ``log_entries`` chain (punch 606).

    Both chain writers (``SQLiteLogHandler.emit``, ``db/audit.insert_log_entry``)
    route the message and every surviving extra value through here BEFORE the
    hash preimage, so hash == store and ``verify_log_chain`` holds (PD-12).
    Before this, the sink stripped secrets by KEY only: a ``code=<otp>``
    formatted into the message, or ``access_token=...`` inside an allow-listed
    ``error`` value, persisted verbatim in both logging modes.

    The redaction is the ``_secret_scrub`` token-shape SSOT, called WITHOUT the
    persisted-error-column wrapper's whitespace collapse and 500-char cap:
    those would rewrite every multi-line or long row, and a row here must
    change only where a secret shape was found. Non-``str`` values pass
    through (``insert_log_entry`` callers pass ints/bools). Secrets only: PHI
    in message text is the N-475 ratchet's concern, not this funnel's.

    Containers (panel B3 hipaa-sme, N-338 allow-list ruling): a dict or list
    extra (``extra={"resp": {"access_token": ...}}``) is walked, applying the
    secret-KEY rule and the value scrub at every depth, so nothing inside a
    container reaches ``extra_json`` unscrubbed. Past ``_SCRUB_MAX_DEPTH`` the
    value is replaced whole (fail-closed; a log extra is never that deep).
    """
    return _scrub_persisted(value, 0)


_SCRUB_MAX_DEPTH = 8


def _scrub_persisted(value: Any, depth: int) -> Any:
    if isinstance(value, (dict, list, tuple)) and depth >= _SCRUB_MAX_DEPTH:
        return _REDACTED_PLACEHOLDER
    if isinstance(value, dict):
        return {k: (_REDACTED_PLACEHOLDER if k in _SECRET_TOKEN_KEYS
                    else _scrub_persisted(v, depth + 1))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_persisted(v, depth + 1) for v in value]
    if not isinstance(value, str) or not value:
        return value
    return _redact_secret_tokens(value)


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


_LOGGER_NAMESPACE = "email_triage"
_LOGGER_NAMESPACE_PREFIX = f"{_LOGGER_NAMESPACE}."


def _normalize_logger_name(name: str) -> str:
    """Canonicalize a logger name to single-prefix under the ``email_triage`` namespace.

    Idempotent: passing an already-fully-qualified name (``"email_triage.X"``)
    returns it unchanged; passing the short form (``"X"``) prepends the
    namespace; passing the bare namespace (``"email_triage"``) returns it
    verbatim. The prefix check requires the trailing dot, so a no-dot
    lookalike (``"email_triage_export"``) still gets the namespace prepended.

    This is the single source of truth for the logger-name transform. Both
    ``get_logger`` (runtime) and ``tests/test_no_double_prefix_get_logger_pin.py``
    (build-time structural pin) import and reuse this helper — PD-6 (pins
    obey the SSOT rule too).
    """
    if name == _LOGGER_NAMESPACE:
        return _LOGGER_NAMESPACE
    if name.startswith(_LOGGER_NAMESPACE_PREFIX):
        return name
    return f"{_LOGGER_NAMESPACE_PREFIX}{name}"


def effective_level_name() -> str:
    """Current effective level of the app logger, as a stdlib level NAME.

    Exists so callers that need to READ the level stop hand-rolling
    ``logging.getLogger("email_triage")``. The N-242 ratchet counts that call
    shape without distinguishing read from emit — correctly, because the shape
    is the SSOT bypass regardless of intent, and a reader is one edit away from
    becoming an emitter. Two N-464 folds (2026-09-12) added one hand-roll each
    and took the ratchet 2 -> 4; this helper is where that need belongs.

    Returns a NAME rather than an int because both callers round-trip the value
    through the ``runtime_settings`` store and the /config form, which speak
    names. A level with no stdlib name cannot round-trip, so it is not this
    function's job to invent one — see the form's own comment.
    """
    return logging.getLevelName(
        logging.getLogger(_LOGGER_NAMESPACE).getEffectiveLevel()
    )


def get_logger(name: str) -> TriageLogger:
    """Return a PHI-aware logger under the ``email_triage`` namespace.

    Idempotent via ``_normalize_logger_name``: a caller may pass either the
    short form (``"actions.move"``, the canonical style) OR an already-
    fully-qualified name (``"email_triage.actions.move"``) and the emitted
    logger name will be single-prefix in both cases. The un-idempotent
    version drifted in prod into ``email_triage.email_triage.X`` on ~24
    sites tagged ``# N-196b R21_4`` that passed the fully-qualified form;
    the pin ``tests/test_no_double_prefix_get_logger_pin.py`` enforces this
    contract at build time so the drift can't recur.
    """
    return TriageLogger(logging.getLogger(_normalize_logger_name(name)))


# ---------------------------------------------------------------------------
# SQLite log handler (for admin web log viewer)
# ---------------------------------------------------------------------------

# Panel P G1 (N-609): the ONE shape of the log-handler gap sentinel, the only
# legitimate writer of a blank-row_hash ``log_entries`` row. The writer below
# and ``verify_log_chain`` both read it, so the two cannot drift (PD-5).
GAP_SENTINEL_LEVEL = "ERROR"
GAP_SENTINEL_LOGGER = "email_triage.triage_logging"
GAP_SENTINEL_MESSAGE = (
    "SQLiteLogHandler write error — one or more audit log rows may have been "
    "dropped; this sentinel marks the gap for verify_log_chain"
)
GAP_SENTINEL_EXTRA = {"error_kind": "log_handler_drop"}
GAP_SENTINEL_HASH_ALG = "sha256"   # the log_entries column defaults
GAP_SENTINEL_KEY_VERSION = 0


def is_gap_sentinel_row(row: Any) -> bool:
    """True only for a row with the gap sentinel's EXACT shape: blank
    ``prev_hash`` and ``row_hash``, the writer's level, logger, message,
    ``extra_json``, alg and key version, ``created_at == ts``, and a ``ts`` in
    the exact shape ``now_utc_iso()`` returns (``NOW_UTC_ISO_RE``, the writer's
    own stamp; panel P fold 3). No free text field remains: ``id`` is an
    integer and ``ts`` is a pinned timestamp, so a forged sentinel can carry no
    content. It can only claim a false gap (fail-noisy). Any other blank-hash
    row is not the sentinel."""
    try:
        if row["row_hash"] != "" or row["prev_hash"] != "":
            return False
        # A timestamp SHAPE check, not a PHI classifier (N-338 gates PHI
        # decisions on bare str checks). A non-str ts raises TypeError in
        # fullmatch, which the except below turns into False.
        if NOW_UTC_ISO_RE.fullmatch(row["ts"]) is None:
            return False
        if (row["level"], row["logger"], row["message"]) != (
                GAP_SENTINEL_LEVEL, GAP_SENTINEL_LOGGER, GAP_SENTINEL_MESSAGE):
            return False
        if (row["hash_alg"], row["master_key_version"]) != (
                GAP_SENTINEL_HASH_ALG, GAP_SENTINEL_KEY_VERSION):
            return False
        if row["created_at"] != row["ts"]:
            return False
        from email_triage.db._helpers import load_json_col
        return load_json_col(row["extra_json"], default=None) == GAP_SENTINEL_EXTRA
    except (KeyError, IndexError, TypeError):
        return False


def _report_handler_fault(where: str) -> None:
    """Last-resort stderr report for a fault inside the SQLite audit handler.

    The handler cannot log through itself (a log line comes straight back into
    ``emit`` and would recurse), so a recovery-step fault goes to stderr.
    Must be called from inside an ``except`` block. It never raises.

    PHI: container stderr lands in the persistent host journal, which no
    redaction reaches afterwards. So the exception MESSAGE is never written:
    ``redact_exc`` scrubs only address and path shapes, and a free-text value
    (an MRN, a subject fragment) has no shape it could catch. Only the
    exception class, the ``where`` tag and the traceback FRAMES (file, line,
    function, source line: code, not data) are written.
    """
    import contextlib
    import traceback
    stream = sys.stderr
    if stream is None:
        return
    exc = sys.exc_info()[1]
    cls = type(exc).__name__ if exc is not None else "unknown"
    frames = (
        "".join(traceback.format_list(traceback.extract_tb(exc.__traceback__)))
        if exc is not None else ""
    )
    # A closed or broken stderr is the only thing tolerated (as before).
    with contextlib.suppress(OSError, ValueError):
        stream.write(
            f"--- audit log handler fault: {where}: {cls} "
            f"(message withheld: may carry PHI) ---\n{frames}"
        )


def _bump_chain_write_failure() -> None:
    """N-182b: count a failed ``log_entries`` chain-row write on the /health
    audit-failure counter, through the ``web._audit`` sink SSOT.

    Late import: ``web._audit`` imports this module at load time. No logging
    here (a log line would re-enter ``SQLiteLogHandler.emit``), and
    ``_bump_failure_counter`` never raises an ``Exception``. Without a
    registered sink (CLI, unit tests, after shutdown) it is a no-op, the same
    as every other ``safe_audit_write`` failure outside the web lifespan.
    Looked up in ``sys.modules``, not imported: the shutdown arm runs during
    teardown, where an import can fail, and an emit must not raise there. The
    sink is registered only by the web lifespan, which has already imported
    ``web._audit``; if the module is absent there is no sink to bump."""
    mod = sys.modules.get("email_triage.web._audit")
    if mod is not None:
        mod._bump_failure_counter()


class SQLiteLogHandler(logging.Handler):
    """Write log entries to a SQLite ``log_entries`` table.

    Batches inserts — commits every *flush_interval* records or on flush().
    Designed to be added to the ``email_triage`` root logger alongside
    the console handler.

     — keeps the last emitted ``row_hash`` in memory
    (``self._last_row_hash``) so the hot path no longer pays a SELECT
    per emit. ``logging.Handler.emit`` is serialised per-handler by
    ``self.lock`` and this handler is the only writer to ``log_entries``
    in the running process (the offline ``insert_log_entry`` helper is
    test/structured-event use only). The first emit primes the cache via
    one SELECT; subsequent emits chain off the in-memory tail.

     — ``shares_app_connection`` controls whether emit/flush acquire
    the process-wide DB write lock around their connection touches.
    Production (file-backed DB) follows the  design: ``add_sqlite_handler``
    hands the handler its OWN dedicated connection, so it owns its
    commit/rollback scope and the lock is needless overhead — pass
    ``False`` (default). The in-memory test fallback shares
    ``app.state.db`` with every other writer; on that path
    ``logging.Handler.lock`` does NOT protect against a concurrent
    ``db_call`` threadpool worker on the same connection, so emit/flush
    MUST acquire ``get_write_lock()`` — ``add_sqlite_handler`` passes
    ``True`` on that branch.
    """

    def __init__(
        self,
        conn: "sqlite3.Connection",
        flush_interval: int = 10,
        level: int = logging.INFO,
        *,
        shares_app_connection: bool = False,
        owns_connection: bool = False,
    ) -> None:
        super().__init__(level)
        self._conn = conn
        self._flush_interval = flush_interval
        self._pending = 0
        #  — see class docstring. Default False matches the production
        # (file-backed, dedicated-connection) path; tests / in-memory
        # callers pass True.
        self._shares_app_connection = bool(shares_app_connection)
        # Punch 636: ``close()`` closes the connection only when this handler
        # opened it (``add_sqlite_handler``'s dedicated branch). A caller's
        # connection is the caller's to close.
        self._owns_connection = bool(owns_connection)
        self._conn_closed = False
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
                    # N-42 (db-sme M1) — the COUNT-AGNOSTIC sink: every _extra
                    # value persists into the HMAC-chained log_entries HERE, so
                    # value-scrub each one. Any caller that put str(exc) (or a
                    # mailbox path) into _extra is covered at this single point,
                    # without chasing the ~239 individual render sites.
                    for inner_k, inner_v in value.items():
                        extra[inner_k] = redact_exc(str(scrub_persisted_log_text(inner_v)))  # DA D5b: walk before repr
                else:
                    extra[key] = redact_exc(str(scrub_persisted_log_text(value)))  # DA D5b: walk before repr

            # Preserve exception info when the caller used logger.error(...,
            # exc_info=e, ...). Mirrors _JsonFormatter / _TextFormatter so the
            # SQLite-backed /logs viewer shows the same `error` + `error_type`
            # fields the stdout sink already emits. Without this, every
            # exc_info-bearing log line landed in /logs without its exception
            # detail — making failures like "Failed to move message" opaque.
            if record.exc_info and record.exc_info[1] is not None:
                # N-42: this is the SQLite /logs + persisted log_entries leg —
                # the exc_info text lands in the HMAC-chained, un-expungeable
                # table, so value-scrub it (the str() render here was the real
                # leak the formatter-only fix missed).
                extra["error"] = redact_exc(record.exc_info[1])
                extra["error_type"] = type(record.exc_info[1]).__name__

            # census run17 #1 — FAIL-CLOSED PHI/secret strip at the persisted
            # sink, applied BEFORE the hash preimage (extra_json) is built so
            # hash == store and the chain stays intact. Catches any raw
            # ``logging.getLogger`` path that bypassed TriageLogger._sanitise
            # (the field-strip used to live ONLY there). _hipaa_mode is the
            # process-global set by setup_logging.
            extra = redact_persisted_extra(extra, hipaa=_hipaa_mode)
            extra_json = _json.dumps(extra) if extra else "{}"
            # Punch 606: the message rides the same secret-value funnel, ONCE,
            # and that one value is both hashed and stored (hash == store).
            message = scrub_persisted_log_text(record.getMessage())

            #  — hash-chain. logging.Handler.emit is serialized
            # per-handler by self.lock, so the read-then-insert here
            # is race-free between two emit() calls.
            #
            #  — conditional locking. On the production (file-backed)
            # path the handler owns its OWN dedicated connection
            # ( — add_sqlite_handler hands it a fresh one via
            # _open_dedicated_log_conn) and self.lock is sufficient: no
            # other writer touches that connection. On the in-memory
            # test path the handler shares app.state.db with db_call
            # threadpool workers — self.lock does NOT serialise against
            # those, so the read-then-insert chain invariant requires
            # the process-wide DB write lock. _maybe_lock() returns
            # the live lock on the shared path, nullcontext on the
            # dedicated path.
            #
            #  — the SELECT on the hot path was a per-emit cost on
            # an indexed-but-not-trivial table. Cache the last row_hash
            # on the instance; only hit the DB on the very first emit
            # (cold cache).
            # H-02a (Cycle 6, 2026-05-23): hash_alg + master_key_version
            # land on every new row. The web.db re-export shim covers
            # compute_log_row_hash + get_last_log_row_hash; we add
            # _get_current_hmac_version to the late-import so the hot
            # path can stamp the correct version for THIS row without
            # a separate registry lookup per insert.
            from email_triage.web.db import (
                CHAIN_HASH_ALG_CURRENT,
                compute_log_row_hash,
                get_last_log_row_hash,
                _get_current_hmac_version,
            )
            with self._maybe_lock():
                if self._last_row_hash is None:
                    self._last_row_hash = get_last_log_row_hash(self._conn)
                prev_hash = self._last_row_hash
                # Capture current HMAC version ONCE per emit. Rotation
                # requires an app-stop (per README's rotate ceremony),
                # so the version is stable for the lifetime of this
                # process; this still re-reads on every emit because
                # the registry lookup is a cheap dict-get under a
                # single threading.Lock acquisition.
                current_mkv = _get_current_hmac_version()
                hash_alg = CHAIN_HASH_ALG_CURRENT
                row_hash = compute_log_row_hash(
                    prev_hash, ts, record.levelname, record.name,
                    message, extra_json,
                    hash_alg=hash_alg,
                    master_key_version=current_mkv,
                )

                # async-db-ok: guarded by self._maybe_lock() — locks the shared-connection (in-memory/test) path per ; the file-backed path owns a dedicated connection and needs no lock
                self._conn.execute(
                    "INSERT INTO log_entries "
                    "(ts, level, logger, message, extra_json, created_at, "
                    " prev_hash, row_hash, hash_alg, master_key_version) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (ts, record.levelname, record.name,
                     message,
                     extra_json, ts, prev_hash, row_hash,
                     hash_alg, current_mkv or 0),
                )
                # Update in-memory tail BEFORE the commit decision —
                # even if the next handler operation crashes, the cache
                # state mirrors what's in the (uncommitted) connection.
                self._last_row_hash = row_hash
                self._pending += 1
                if self._pending >= self._flush_interval:
                    # async-db-ok: guarded by self._maybe_lock() — locks the shared-connection (in-memory/test) path per ; the file-backed path owns a dedicated connection and needs no lock
                    self._conn.commit()
                    self._pending = 0
        except DB_PROGRAMMING_ERRORS:
            #  — DB connection was closed (typically during
            # container shutdown after the audit-anchor flush). The
            # row would have been lost regardless; suppress the
            # user-visible traceback that ``handleError`` writes to
            # stderr and downgrade to ``logging.lastResort`` so the
            # message at least reaches stderr in the standard log
            # format. Reset ``_last_row_hash`` so any subsequent
            # emit (rare during shutdown but possible) re-syncs from
            # whatever connection is still alive — the chain anchor
            # at .1 covers the on-disk continuity, the in-memory
            # cache just needs to drop the stale tail.
            self._last_row_hash = None
            # N-182b (allow-list step 2, B2): this row is lost too; count it.
            _bump_chain_write_failure()
            fallback = logging.lastResort
            if fallback is not None:
                try:
                    fallback.handle(record)
                except Exception:
                    # ``lastResort`` itself failed (stderr closed?) —
                    # nothing more we can safely do; the helper tolerates a
                    # closed stderr and never raises.
                    _report_handler_fault("logging.lastResort")
        except Exception:
            # #239e — a transient write error here would otherwise
            # silently drop the whole uncommitted batch: with
            # flush_interval>1, up to flush_interval-1 emitted-but-
            # uncommitted rows plus this one are lost when the
            # connection rolls back. The next emit re-chains from the
            # last *committed* row, so verify_log_chain sees a CLEAN
            # chain with NO gap marker — an invisible audit-integrity
            # hole (HIPAA §164.312(c)(1)).
            #
            # Two-part mitigation, in order:
            #  1. Try once to commit the surviving batch. If the
            #     failure was on THIS row's INSERT, rows already in
            #     the pending transaction are intact and a commit
            #     salvages them (dropped batch -> not dropped).
            #  2. Insert a 'prechain' sentinel row (empty row_hash,
            #     empty prev_hash) and commit it. verify_log_chain
            #     counts empty-row_hash rows as prechain_count, so
            #     even a genuinely-lost batch leaves a visible marker
            #     at the gap (dropped batch -> visible). The sentinel
            #     is skipped by get_last_log_row_hash (WHERE
            #     row_hash != ''), so the chain re-anchors cleanly on
            #     the next real row.
            #
            #  — conditional locking, same shape as the happy path.
            # On the shared-connection (in-memory test) branch the lock
            # is required so a concurrent db_call worker can't
            # interleave a foreign commit/rollback mid-recovery. On the
            # dedicated-conn (production) branch _maybe_lock() is a
            # nullcontext — the handler owns its own commit scope.
            try:
                with self._maybe_lock():
                    # async-db-ok: guarded by self._maybe_lock() — locks the shared-connection (in-memory/test) path per ; the file-backed path owns a dedicated connection and needs no lock
                    self._conn.commit()
                    self._pending = 0
            except Exception:
                _report_handler_fault("pre-sentinel commit")
            try:
                import json as _json
                _sentinel_ts = now_utc_iso()
                with self._maybe_lock():
                    # async-db-ok: guarded by self._maybe_lock() — locks the shared-connection (in-memory/test) path per ; the file-backed path owns a dedicated connection and needs no lock
                    self._conn.execute(
                        "INSERT INTO log_entries "
                        "(ts, level, logger, message, extra_json, "
                        " created_at, prev_hash, row_hash, hash_alg, "
                        " master_key_version) "
                        "VALUES (?, ?, ?, ?, ?, ?, '', '', ?, ?)",
                        (
                            _sentinel_ts, GAP_SENTINEL_LEVEL,
                            GAP_SENTINEL_LOGGER,
                            GAP_SENTINEL_MESSAGE,
                            _json.dumps(GAP_SENTINEL_EXTRA),
                            _sentinel_ts,
                            GAP_SENTINEL_HASH_ALG,
                            GAP_SENTINEL_KEY_VERSION,
                        ),
                    )
                    # async-db-ok: guarded by self._maybe_lock() — locks the shared-connection (in-memory/test) path per ; the file-backed path owns a dedicated connection and needs no lock
                    self._conn.commit()
            except Exception:
                # Connection itself is broken — nothing more we can
                # safely do; handleError still surfaces it.
                _report_handler_fault("gap-sentinel write")
            # Reset the cache on any failure so the next emit
            # re-syncs from the DB. Keeps the chain consistent if
            # an INSERT failed and was rolled back.
            self._last_row_hash = None
            # N-182b (allow-list step 2, B2): a failed chain-row write must
            # not be visible only to handleError's stderr traceback. Bump the
            # /health audit-failure counter (app.state.audit_failures) through
            # the web._audit SSOT's sink. Deliberately NOT safe_audit_write /
            # record_audit_loss: both LOG, and a log line comes straight back
            # into this handler, so a persistent DB failure would recurse.
            # The counter bump does no logging and never raises.
            _bump_chain_write_failure()
            self.handleError(record)

    def flush(self) -> None:
        if self._pending > 0:
            #  — conditional locking. Shared-connection path (tests)
            # needs the process-wide DB write lock so a concurrent
            # db_call worker can't interleave; dedicated-conn path
            # (production) doesn't — _maybe_lock() picks the right
            # one based on shares_app_connection.
            try:
                with self._maybe_lock():
                    # async-db-ok: guarded by self._maybe_lock() — locks the shared-connection (in-memory/test) path per ; the file-backed path owns a dedicated connection and needs no lock
                    self._conn.commit()
                    self._pending = 0
            except Exception:
                # The pending audit rows were not committed: count the loss
                # on /health (no logging, never raises) and report to stderr.
                _bump_chain_write_failure()
                _report_handler_fault("flush commit")

    @contextmanager
    def _maybe_lock(self):
        """Conditional lock for each emit/flush DB touch.

         — only the in-memory (test) fallback shares the app
        connection; the file-backed handler owns a dedicated
        connection and must NOT take the process-wide write lock
        (that would couple isolated log writes to request-path
        db_call workers). Lock the shared-connection path only.
        """
        if self._shares_app_connection:
            from email_triage.web.db_writelock import get_write_lock
            with get_write_lock():
                yield
        else:
            yield

    def close(self) -> None:
        """Flush, then close the connection this handler owns (punch 636).

        Idempotent: ``logging.shutdown()`` at interpreter exit closes every
        handler again. Under the handler lock, so an emit in flight on another
        thread finishes before the connection goes."""
        self.acquire()
        try:
            if not self._conn_closed:
                self.flush()
                if self._owns_connection:
                    self._conn_closed = True
                    try:
                        self._conn.close()
                    except Exception as exc:
                        sys.stderr.write(
                            f"SQLiteLogHandler: closing its connection failed "
                            f"({type(exc).__name__}); the -wal may survive this stop\n"
                        )
        finally:
            self.release()
        super().close()


def remove_sqlite_handlers() -> int:
    """Detach every :class:`SQLiteLogHandler` from the ``email_triage`` logger
    and close it, which closes the connection ``add_sqlite_handler`` opened for
    it. Returns how many were removed.

    Punch 636: the web lifespan calls this at shutdown AFTER the explicit WAL
    TRUNCATE (so the "fired" and "Web UI stopped" rows stay in the chain) and
    BEFORE the app connection's close, which must be the LAST close: SQLite's
    last-close checkpoint then folds those rows and deletes the -wal
    (sqlite.org/wal.html, sections 4 and 6). Never move it after
    ``conn.close()``: the handler's open connection would keep that close from
    being the last one and strand the frames. On a failed writer join it runs
    right after the join instead (panel r1 DA-1). Lines logged after this
    reach the console handlers only."""
    root = logging.getLogger("email_triage")
    removed = 0
    for handler in list(root.handlers):
        if isinstance(handler, SQLiteLogHandler):
            root.removeHandler(handler)
            handler.close()
            removed += 1
    return removed


# Standard LogRecord attributes to exclude from 'extra'.
_STANDARD_LOG_KEYS = frozenset({
    "name", "msg", "args", "created", "relativeCreated", "exc_info",
    "exc_text", "stack_info", "lineno", "funcName", "pathname",
    "filename", "module", "thread", "threadName", "process",
    "processName", "levelname", "levelno", "message", "msecs",
    "taskName",
})


def _resolve_main_db_path(conn: "sqlite3.Connection") -> str | None:
    """Return the file path backing a connection's ``main`` database.

    ``PRAGMA database_list`` yields ``(seq, name, file)`` rows; the
    ``main`` row's ``file`` is the on-disk path (empty string for an
    in-memory or temp database). Returns None when the connection is
    in-memory — a second ``sqlite3.connect(":memory:")`` opens a
    *separate* empty database, so the dedicated-connection path must
    fall back to the shared connection in that case.
    """
    try:
        for row in conn.execute("PRAGMA database_list").fetchall():
            # Row is (seq, name, file) regardless of row_factory.
            name = row[1]
            path = row[2]
            if name == "main":
                return path or None
    except DB_ERRORS:
        return None
    return None


def _open_dedicated_log_conn(db_path: str) -> "sqlite3.Connection":
    """Open a dedicated SQLite connection on ``db_path`` for the log
    handler, mirroring the PRAGMAs ``init_db`` sets on the main one.

     — the SQLite log handler must NOT share the app's single
    connection: a foreign ``ROLLBACK`` from a concurrent write helper
    on a threadpool worker would orphan the handler's cached row tail
    and permanently break the audit hash-chain. Its own connection
    isolates its commit/rollback scope.
    """
    # N-17: route through the encrypted-aware shared opener so the
    # §164.312(b) audit-chain handler opens against an ENCRYPTED file on an
    # encrypted install (raw sqlite3.connect would hard-crash at the first
    # PRAGMA there). The opener self-selects encrypted-vs-plaintext from the
    # boot-stamped context + applies the same WAL/busy/FK PRAGMAs this site
    # set inline. Local imports keep this low-level logging module free of
    # an import-time package edge.
    from email_triage.db._engine import open_dedicated_conn
    from email_triage.db._helpers import apply_compatible_row_factory
    conn = open_dedicated_conn(db_path, check_same_thread=False)
    # N-16: factory from the conn's own dbapi module (sqlite3.Row vs
    # sqlcipher3.dbapi2.Row) — open_dedicated_conn may return either.
    apply_compatible_row_factory(conn)
    from email_triage.single_flight import set_cached_db_path

    set_cached_db_path(conn, db_path)
    return conn


def add_sqlite_handler(conn: "sqlite3.Connection") -> None:
    """Add a SQLite log handler to the email_triage root logger.

    Call after ``setup_logging()`` and after ``init_db()`` has created
    the ``log_entries`` table.

     — when the database is file-backed the handler is given its
    OWN connection (isolated commit/rollback scope, so the audit
    hash-chain can never be orphaned by a foreign ROLLBACK). For an
    in-memory database the handler falls back to the shared connection
    — a second ``:memory:`` connect would open an unrelated empty DB.
    """
    root = logging.getLogger("email_triage")
    db_path = _resolve_main_db_path(conn)
    if db_path:
        handler_conn = _open_dedicated_log_conn(db_path)
        shares_app_connection = False
    else:
        # In-memory database — cannot be reopened; share the connection.
        handler_conn = conn
        #  — flag the shared-connection branch so emit/flush take
        # the process-wide DB write lock (the dedicated-conn branch
        # above doesn't need it; see SQLiteLogHandler docstring).
        shares_app_connection = True
    handler = SQLiteLogHandler(
        handler_conn,
        # 2026-05-31 encrypted-cutover incident: on the file-backed
        # (production / dedicated-conn) path, commit EVERY emit so the
        # audit conn never holds the WAL write-lock across a multi-emit
        # batch. Under SQLCipher the per-page crypto widens every
        # write's lock-hold window; a batched hold (flush_interval=5)
        # parked the single WAL write-lock long enough that the main
        # app conn + the single_flight lease conn piled past the 30s
        # busy_timeout -> sustained "database is locked". Per-emit commit
        # keeps each hold to one row, and shrinks the lost-batch window
        # to zero (§164.312(c)(1) durability bonus). The in-memory test
        # path (shares_app_connection) keeps batching — no WAL there.
        flush_interval=1 if not shares_app_connection else 5,
        shares_app_connection=shares_app_connection,
        # Punch 636: the dedicated connection is the handler's to close.
        owns_connection=not shares_app_connection,
    )
    root.addHandler(handler)
