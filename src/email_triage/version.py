"""Version + schema-compatibility introspection for the update banner.

#125 (Partial — shipped 2026-05-15). The 2026-05-09 deploy recovery
showed that `:previous` image rollback is a one-way trip once a
schema-bumping release lands: a v13 image can't open a v14 DB.
``deploy.sh`` blindly re-tags `:previous` -> `:latest` on `/health`
failure, leaving the install dead.

This module is the smallest concrete step toward the full update-UX
story (#166): it answers three questions without doing anything
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
Those are #166 territory. This module is INTROSPECTION ONLY.

Naming note. The investigation memo (``docs/update-strategy-investigation-2026-05-13.md``)
referred to this hook as the "pre-update schema-compatibility check."
The helper here is the pure-function half; `scripts/deploy.sh` will
eventually call it as a pre-flight gate, but that wiring is out of
scope for this commit.
"""

from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from email_triage import __version__ as APP_VERSION


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
#: 2026-05-09 incident. Operator should snapshot the DB before
#: applying, per the recommendation in
#: ``docs/update-strategy-investigation-2026-05-13.md`` § 5.
STATUS_INCOMPATIBLE_ROLLBACK = "incompatible_rollback"

#: Live DB schema is HIGHER than the target binary knows about. This
#: is the "rollback past a schema bump" case — refusing to load is
#: already enforced by ``migrations.run_migrations``. The banner / CLI
#: surface it so the operator gets a readable message instead of a
#: startup traceback.
STATUS_DOWNGRADE_NOT_SUPPORTED = "downgrade_not_supported"


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
      ``incompatible_rollback``. The 2026-05-09 case.
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


def read_db_schema_version(db_path: str | Path) -> int:
    """Highest migration version applied to the live DB.

    Opens ``db_path`` read-only so the helper is safe to call from a
    CLI / banner path that should not touch the live DB. Returns 0 on
    any error (missing file, locked, no ``schema_migrations`` table) —
    callers must distinguish "0 because fresh DB" from "0 because we
    couldn't read it" themselves if that matters.
    """

    p = Path(db_path).expanduser()
    if not p.exists():
        return 0
    try:
        conn = sqlite3.connect(
            f"file:{p}?mode=ro", uri=True, check_same_thread=False,
        )
    except sqlite3.Error:
        return 0
    try:
        try:
            row = conn.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
        except sqlite3.OperationalError:
            # Table not created yet — pre-framework install, or
            # truly fresh DB.
            return 0
        if row is None or row[0] is None:
            return 0
        return int(row[0])
    finally:
        conn.close()


_PREVIOUS_CAPS_ENV = "EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS"


def read_previous_schema_caps() -> Optional[int]:
    """Best-effort read of the `:previous` image's declared schema cap.

    The deploy host knows this number; the running container does not
    (the `:previous` image is on the host's local registry, not inside
    the running image). For this slice we expose a single env-var hook
    so ``scripts/deploy.sh`` can inject the value at container start:

        EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS=<int>

    When unset (the common case today), returns ``None``. The banner
    falls back to "update available" without the rollback-incompat
    escalation — strictly less alarming, never falsely loud. The
    full wiring (`deploy.sh` reads ``:previous`` image labels,
    injects the env var on each restart) is part of the #125 follow-up
    work, not this slice.

    Accepts strings ``"0"`` and ``""`` defensively; both are treated
    as "no value available" rather than "schema 0" since the latter
    would be misleading for an install with any registered
    migrations.
    """

    raw = os.environ.get(_PREVIOUS_CAPS_ENV, "").strip()
    if not raw or raw == "0":
        return None
    try:
        v = int(raw)
    except ValueError:
        return None
    if v < 1:
        return None
    return v


# ---------------------------------------------------------------------------
# Top-level convenience — what the banner + CLI both call
# ---------------------------------------------------------------------------

def gather_version_status(
    db_path: str | Path | None,
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
    """

    target_caps = read_target_schema_caps()
    previous_caps = read_previous_schema_caps()
    if db_path is None:
        db_schema = 0
    else:
        db_schema = read_db_schema_version(db_path)

    return compute_version_status(
        db_schema_version=db_schema,
        target_schema_caps=target_caps,
        previous_schema_caps=previous_caps,
    )
