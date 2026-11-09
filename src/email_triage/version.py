"""Version + schema-compatibility introspection for the update banner.

 (Partial — shipped 2026-05-15). The @skip=tests/* deploy recovery
showed that `:previous` image rollback is a one-way trip once a
schema-bumping release lands: a v13 image can't open a v14 DB.
``deploy.sh`` blindly re-tags `:previous` -> `:latest` on `/health`
failure, leaving the install dead.

This module is the smallest concrete step toward the full update-UX
story: it answers three questions without doing anything
destructive.

  1. What version of the app is running?
  2. Where is the live DB schema relative to what this binary knows?
  3. If we DID re-tag `:previous` right now, would it still be able
     to open the live DB?

The answer drives a /config banner ("Up to date" / "Update available"
/ "Update available — schema-incompatible rollback") and a
``email-triage version-check`` CLI that prints the same status with
distinct exit codes for scripting.

No update mechanism, no auto-pull, no rollback automation lives here.
Those are  territory. This module is INTROSPECTION ONLY.

Naming note. The investigation memo (``internal documentation``)
referred to this hook as the "pre-update schema-compatibility check."
The helper here is the pure-function half; `scripts/deploy.sh` will
eventually call it as a pre-flight gate, but that wiring is out of
scope for this commit.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from email_triage import __version__ as APP_VERSION
from email_triage._int_utils import parse_int_or_none  # N-219b R23
from email_triage._dbapi_errors import DB_ERRORS, DB_OPERATIONAL_ERRORS


# ---------------------------------------------------------------------------
# Status enum (string-typed for template + JSON friendliness)
# ---------------------------------------------------------------------------

#: DB schema and target binary match exactly. Nothing to do.
STATUS_UP_TO_DATE = "up_to_date"

#: Target binary knows about migrations the live DB hasn't run yet.
#: Forward-compatible: applying the target binary will run those
#: migrations on first boot. Rollback to the previous image remains
#: safe (it would not have run the new migrations).
STATUS_UPDATE_AVAILABLE = "update_available"

#: Target binary has new migrations AND the previous image's known
#: schema cap is BELOW the current live DB schema. Applying the
#: target is fine (forward path is safe); the danger is the rollback
#: path — the `:previous` image cannot open the post-bump DB. The
#: @skip=tests/* incident. Operator should snapshot the DB before
#: applying, per the recommendation in
#: ``internal documentation`` § 5.
STATUS_INCOMPATIBLE_ROLLBACK = "incompatible_rollback"

#: Live DB schema is HIGHER than the target binary knows about. This
#: is the "rollback past a schema bump" case — refusing to load is
#: already enforced by ``migrations.run_migrations``. The banner / CLI
#: surface it so the operator gets a readable message instead of a
#: startup traceback.
STATUS_DOWNGRADE_NOT_SUPPORTED = "downgrade_not_supported"

#: The DB file exists but its applied schema version could not be read (the
#: open or the read failed). Only ``version-check`` reports it (the strict read);
#: it is never computed by :func:`compute_version_status`, because there is no
#: version to compare. 2026-10-18: the deploy pre-flight read a live DB it could
#: not open as schema 0, which is "older than every image", so the downgrade and
#: rollback gates could not fire on that read and the deploy proceeded.
STATUS_DB_UNREADABLE = "db_unreadable"


class DbSchemaUnreadableError(RuntimeError):
    """The strict schema read could not open or read an existing DB file.

    Raised only by ``read_db_schema_version(..., strict=True)``; the original
    driver error is chained as ``__cause__``. A decisional caller (the deploy's
    ``version-check``) must refuse on it; reporting 0 instead is the fail-open
    this type exists to prevent (PD-8)."""


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VersionStatus:
    """Snapshot returned by :func:`compute_version_status`.

    ``app_version`` is the running binary's :mod:`email_triage` version
    (``__version__``). ``db_schema_version`` is the highest migration
    version applied to the live DB (read via
    :func:`email_triage.web.migrations.schema_version`).
    ``target_schema_caps`` is what the running binary's source
    declares as its max-known migration version. ``previous_schema_caps``
    is the same thing for the ``:previous`` image when that information
    is available (it isn't, in the pure-function path — only when
    ``deploy.sh`` wires it in as a side input).

    ``status`` is one of the ``STATUS_*`` constants above. ``explanation``
    is a single plain-English line for the admin banner / CLI output,
    written to the audience rule in ``feedback_audience_per_page.md``
    (admin page; richer technical detail OK but no "v14 -> v15
    migration set" jargon — instead "Your install has a database newer
    than this binary knows about").
    """

    app_version: str
    db_schema_version: int
    target_schema_caps: int
    previous_schema_caps: Optional[int]
    status: str
    explanation: str

    def to_dict(self) -> dict:
        """JSON-friendly dict, for embedding in /health/detail later."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Pure helper — the testable core
# ---------------------------------------------------------------------------

def compute_version_status(
    *,
    db_schema_version: int,
    target_schema_caps: int,
    previous_schema_caps: Optional[int] = None,
    app_version: str = APP_VERSION,
) -> VersionStatus:
    """Decide which update-banner state applies, given three numbers.

    All inputs are integers ("highest migration version registered" /
    "highest migration version applied"); we never parse a semantic
    version string for the migration check. Semver lives in the app's
    ``__version__`` and is surfaced separately for display only — the
    schema-compat verdict turns on the integer migration counter.

    Forward-compat rule:

    * ``target == db`` -> ``up_to_date``.
    * ``target > db``  -> ``update_available`` (target knows everything
      the DB knows, plus more — first-boot will run the missing
      migrations).
    * ``target < db``  -> ``downgrade_not_supported`` (the DB has been
      written by a newer binary; this binary refuses to open it,
      matching the guard in ``migrations.run_migrations``).

    Rollback rule (only fires when forward-compat says
    ``update_available`` AND ``previous_schema_caps`` is provided):

    * ``previous_schema_caps < db_schema_version`` -> escalate to
      ``incompatible_rollback``. The @skip=tests/* case.
    * Otherwise ``update_available`` stays.

    The rollback rule deliberately reads ``db_schema_version`` (the
    LIVE DB right now), not ``target_schema_caps``. The danger window
    opens the moment the live DB is past what `:previous` can open;
    whether the new image goes higher still doesn't change that
    invariant.
    """

    if db_schema_version > target_schema_caps:
        status = STATUS_DOWNGRADE_NOT_SUPPORTED
    elif db_schema_version == target_schema_caps:
        status = STATUS_UP_TO_DATE
    else:
        # target > db: update available. Decide rollback safety.
        if (
            previous_schema_caps is not None
            and previous_schema_caps < db_schema_version
        ):
            status = STATUS_INCOMPATIBLE_ROLLBACK
        else:
            status = STATUS_UPDATE_AVAILABLE

    return VersionStatus(
        app_version=app_version,
        db_schema_version=db_schema_version,
        target_schema_caps=target_schema_caps,
        previous_schema_caps=previous_schema_caps,
        status=status,
        explanation=describe_status(
            status,
            db_schema_version=db_schema_version,
            target_schema_caps=target_schema_caps,
            previous_schema_caps=previous_schema_caps,
        ),
    )


# ---------------------------------------------------------------------------
# Plain-English explanations (audience: admin operator)
# ---------------------------------------------------------------------------

def describe_status(
    status: str,
    *,
    db_schema_version: int = 0,
    target_schema_caps: int = 0,
    previous_schema_caps: Optional[int] = None,
) -> str:
    """One-line operator-facing explanation for the given status.

    Audience: admin operator. The /config page is admin-only so this
    can name "database" and "rollback" directly; what it AVOIDS is
    raw migration version numbers in the user-facing prose ("v14 ->
    v15 migration set" is too jargony — the integers are kept as
    parenthetical detail for the operator who wants them).
    """

    if status == STATUS_UP_TO_DATE:
        return (
            "Your install is up to date. No database changes pending."
        )

    if status == STATUS_UPDATE_AVAILABLE:
        return (
            "An update is available. Applying it will add new "
            "database changes; rolling back to the previous image "
            "will still work if needed."
        )

    if status == STATUS_INCOMPATIBLE_ROLLBACK:
        return (
            "An update is available, but rolling back to the "
            "previous image WILL NOT WORK after this update. Your "
            "live database is already past what the previous image "
            "understands. Take a database snapshot before applying."
        )

    if status == STATUS_DOWNGRADE_NOT_SUPPORTED:
        return (
            "Your database is newer than this version of the "
            "software knows about. The application will refuse to "
            "start. Restore a backup or run a newer build."
        )

    return f"Unknown status: {status!r}."


# ---------------------------------------------------------------------------
# Source introspection — what schema cap does the running source declare?
# ---------------------------------------------------------------------------

def read_target_schema_caps() -> int:
    """Highest migration version registered in the running source tree.

    Reads the live ``MIGRATIONS`` registry in
    :mod:`email_triage.web.migrations`. This is the running binary's
    declaration: "I know how to take a DB up to version N."

    Returns 0 if no migrations are registered (fresh checkout, broken
    import). Caller should treat 0 as "I don't know" and not draw a
    confident banner from it.
    """

    try:
        from email_triage.web.migrations import MIGRATIONS
    except Exception:
        return 0
    return max((m.version for m in MIGRATIONS), default=0)


def read_db_schema_version(db_path: str | Path, *, strict: bool = False) -> int:
    """Highest migration version applied to the live DB.

    Opens ``db_path`` read-only so the helper is safe to call from a
    CLI / banner path that should not touch the live DB. By default returns
    0 on any error (missing file, locked, no ``schema_migrations`` table):
    the banner and health renders use that default, a non-decisional render
    degradation (R14's one allowed fail-open).

    ``strict=True`` is for a caller that DECIDES on the number (the deploy's
    ``version-check``): 0 then means only "the DB opened and has no applied
    migration"; a missing file, a failed open or a failed read raises
    :class:`DbSchemaUnreadableError`. 2026-10-18: a WAL-mode DB with no
    ``-wal``/``-shm`` in a read-only directory cannot be opened (SQLite cannot
    create its ``-wal`` sidecar, the first file it needs; sqlite.org/wal.html "Read-Only Databases"), the default
    read reported 0, and the deploy proceeded on it.
    """

    p = Path(db_path).expanduser()
    if strict:
        return _read_db_schema_version_strict(p)
    if not p.exists():
        return 0
    # N-17: on an encrypted install this read must go through the
    # SQLCipher opener — before N-17 it did a raw plaintext mode=ro open,
    # the SELECT raised (ciphertext is not valid SQLite), and the helper
    # silently returned 0 (a WRONG-version banner, not a crash). The
    # plaintext branch keeps the original read-only ``file:...?mode=ro``
    # open verbatim (no PRAGMAs — a read-only conn rejects PRAGMA
    # journal_mode, so it must NOT go through open_dedicated_conn, which
    # sets WAL). The encrypted branch uses _make_encrypted_conn directly
    # (PRAGMA key first). Punch 556 / N-559: the encrypted branch is now a
    # SQLCipher ``mode=ro`` handle too, not a read-write one.
    # the backlog  (Census v3 #8) — route through the SSOT
    # ``open_dedicated_conn_readish`` (boot-encryption-aware RO opener).
    # The pre-fix encrypted/plaintext hand-roll drifted vs init_db on
    # ``timeout=30.0`` + ``cached_statements=0``; the SSOT carries the
    # full argument set uniformly across the 7 census-flagged sites.
    from email_triage.db._engine import open_dedicated_conn_readish

    try:
        conn = open_dedicated_conn_readish(str(p))
    except DB_ERRORS:
        # Both drivers (punch 560: sqlcipher3's classes do not inherit
        # from sqlite3's, so the funnel carries both).
        return 0
    except Exception:
        # A non-DB open failure (e.g. no master key stamped) — keep the
        # helper's "return 0 on any open failure" contract rather than
        # crashing a banner render.
        return 0
    try:
        return read_schema_version(conn)
    finally:
        conn.close()


def _read_db_schema_version_strict(p: Path) -> int:
    """The ``strict=True`` arm of :func:`read_db_schema_version`: the same SSOT
    opener, but every failure raises :class:`DbSchemaUnreadableError` (chained)
    instead of reading as 0."""
    from email_triage.db._engine import open_dedicated_conn_readish

    if not p.exists():
        raise DbSchemaUnreadableError(f"database file not found: {p}")
    try:
        conn = open_dedicated_conn_readish(str(p))
    except Exception as e:  # noqa: BLE001 — every open failure is a refusal here
        raise DbSchemaUnreadableError(
            f"could not open {p} to read its schema version: {e}"
        ) from e
    try:
        return read_schema_version(conn, strict=True)
    except DbSchemaUnreadableError:
        raise
    except Exception as e:  # noqa: BLE001 — the plaintext open is lazy: it fails here
        raise DbSchemaUnreadableError(
            f"could not read the schema version of {p}: {e}"
        ) from e
    finally:
        conn.close()


def read_schema_version(conn: sqlite3.Connection, *, strict: bool = False) -> int:
    """Pure, side-effect-free schema-version read off an OPEN connection:
    ``MAX(version)`` from ``schema_migrations``, or 0 if the table is absent /
    empty.

    The SSOT for reading the applied schema version off a live connection
    WITHOUT the migration-framework's ``_ensure_bookkeeping`` side effect
    (``web.migrations.schema_version`` CREATEs the bookkeeping table on read —
    correct for the framework, WRONG for a read-only banner/health render that
    must never mutate). ``read_db_schema_version`` (path-based, above) and the
    daily-health banner both route through it (census run15  — the raw
    ``MAX(version)`` SELECT lived in two places). Does NOT close ``conn`` (the
    caller owns its lifecycle)."""
    if strict:
        # strict (version-check): "table absent" is decided by a catalog read,
        # never by an error, so a failed open (the plaintext ``mode=ro`` open is
        # lazy and fails HERE) or any other read error propagates to the caller
        # instead of reading as 0. The catalog read is also the forced open.
        present = conn.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if present is None:
            return 0
        row = conn.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()
    else:
        try:
            row = conn.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
        except DB_OPERATIONAL_ERRORS:
            # Table not created yet — pre-framework install, or truly fresh DB.
            return 0
    if row is None or row[0] is None:
        return 0
    return int(row[0])


def parse_previous_schema_caps(raw: str | None) -> Optional[int]:
    """Parse the `:previous` image's declared schema cap.

    The deploy host knows this number; the running container does not.
    ``scripts/deploy.sh`` reads it from the ``:previous`` image and passes it
    to ``email-triage version-check --previous-schema-caps N`` — the deploy's
    fail-closed rollback-safety compare (exit 2 → deploy aborts).

    Punch 547: this used to be read from the
    ``EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS`` env var, and an unset or inflated
    value silently OPENED that gate. It is now only ever an explicit argument.

    ``None`` / ``""`` / ``"0"`` / non-integer / < 1 -> ``None`` ("no value
    available" — never "schema 0", which would be misleading for an install
    with any registered migrations).
    """
    raw = (raw or "").strip()
    if not raw or raw == "0":
        return None
    v = parse_int_or_none(raw)  # N-219b R23: SSOT
    if v is None or v < 1:
        return None
    return v


# ---------------------------------------------------------------------------
# Top-level convenience — what the banner + CLI both call
# ---------------------------------------------------------------------------

def gather_version_status(
    db_path: str | Path | None,
    previous_schema_caps: Optional[int] = None,
    *,
    strict: bool = False,
) -> VersionStatus:
    """Build a :class:`VersionStatus` from live introspection.

    ``db_path`` is the path to the SQLite DB (typically
    ``config.persistence.db_path``). Pass ``None`` to skip the DB read
    and report a "we don't know" status; useful only in edge cases
    (CLI before init_db has ever run).

    Pure wrapper: it reads the three numbers, then defers to
    :func:`compute_version_status`. Tests exercise the wrapper sparingly;
    the bulk of the suite covers :func:`compute_version_status`
    directly because that's where the rules live.

    ``strict`` is passed to :func:`read_db_schema_version`: the deploy's
    ``version-check`` sets it, so an existing DB it cannot read raises
    :class:`DbSchemaUnreadableError` instead of reporting schema 0. The banner
    and /health callers keep the default.
    """

    target_caps = read_target_schema_caps()
    previous_caps = previous_schema_caps
    if db_path is None:
        db_schema = 0
    else:
        db_schema = read_db_schema_version(db_path, strict=strict)

    return compute_version_status(
        db_schema_version=db_schema,
        target_schema_caps=target_caps,
        previous_schema_caps=previous_caps,
    )
