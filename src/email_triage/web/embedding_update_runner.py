"""The ONE web-layer funnel for replacing the embedding runtime (punch 569 and
the 2026-10-25 operator decision that updates apply automatically).

``embedding_bits.update_runtime`` is the domain funnel: stage beside the live
prefix, verify every hash, swap, re-verify, roll back. It writes no audit rows
by design. Everything a CALLER must do around it lives HERE, once:

* the witness-first INTENT audit row (the update is REFUSED if it cannot be
  written),
* the in-flight guard (install-state row status plus ``update_in_progress``) and
  the row claim, in one DB hop,
* the OUTCOME audit row, and the release of the claimed row when the work raises,
* the removal-tombstone purge, off the DB writer,
* for the app's own (automatic) runs: the durable failure / success record that
  drives the retry backoff and the after-the-fact notice.

Two callers, one funnel (PD-5): the admin's click
(``routers/ui/embedding_install.embedding_update`` -> :func:`start_runtime_update`)
and the app's own sweeper (``background_sweepers._embedding_auto_update_sweeper``
-> :func:`auto_update_once` -> :func:`apply_runtime_update`). The pin
``tests/test_autoupd_single_funnel_pin.py`` fails CI on any other call of
``update_runtime`` in ``src/``.

Attribution (PD-3, §164.312(b)): an automatic run writes the same
``embedding_runtime_update`` rows as a click, under the typed SYSTEM actor
:data:`SYSTEM_ACTOR_EMAIL` (the ``system:<job>`` convention the automated backup
uses), never a blank or unknown actor.

Egress: unchanged. A click and an automatic run both reach
``update_runtime(source_dir=None)`` -> ``_install_common(method="auto")`` ->
``_http_download`` against the manifest's own URLs and publisher hashes; this
module adds no host and no client.
"""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from email_triage._errfmt import scrub_error_for_persist
from email_triage._isotime import now_utc_iso, parse_iso_aware
from email_triage.embedding_bits import (
    BOOT_GATE_TIMEOUT,
    DEFERRED_ERROR_CLASS,
    RESTART_MESSAGE,
    STATE_STALE_OK,
    RuntimeStatus,
    UpdateResult,
    _runtime_loaded_here,
    _update_state,
    auto_update_deferred,
    auto_update_enabled,
    get_install_status,
    keep_as_evidence,
    purge_removal_tombstones,
    resolve_manifest_path,
    release_boot_update_gate,
    restart_pending,
    runtime_status,
    set_auto_update_deferred,
    set_auto_update_failure,
    update_in_progress,
    update_runtime,
)
from email_triage.triage_logging import get_logger
from email_triage.web._audit import safe_audit_write
from email_triage.web.db import (
    get_setting,
    invalidate_setting_cache,
    record_auth_event,
    set_setting,
    set_setting_txn,
)
from email_triage.web.db_threadpool import db_call

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI

_log = get_logger("email_triage.web.embedding_update_runner")

#: The audit ``event_type`` of every attempt/outcome row, click or automatic.
EVENT_TYPE = "embedding_runtime_update"

#: Who an automatic run is, in ``auth_events.email``. The ``system:<job>``
#: convention is the automated backup's (``system:auto-backup``).
SYSTEM_ACTOR_EMAIL = "system:embedding-auto-update"

#: Who the boot recovery of an interrupted update is (``web/app.py`` lifespan). It
#: records a recovery, not an apply, so it is a different named actor, but it is
#: never blank (operator ruling R5, 2026-10-25).
BOOT_RECOVERY_ACTOR_EMAIL = "system:embedding-boot-recovery"

#: The one settings row that carries the automatic updater's durable state.
AUTO_STATE_KEY = "embedding_runtime:auto_update"

#: What a REFUSED update shows the admin. Static text only (N-179).
UPDATE_REFUSED_NO_WITNESS = (
    "Nothing was changed: the audit record of this update could not be "
    "written, and the runtime is never replaced without one. Try again; if it "
    "keeps failing, the application log names the cause."
)
#: An AUTOMATIC claim whose fresh status is no longer one the app may heal by itself
#: (an integrity refusal appeared, or the runtime became current) between the trigger's
#: read and the claim. Nothing is written (hipaa-sme SHOULD-1 / db S-A1).
UPDATE_REFUSED_NOT_AUTOMATIC = (
    "Nothing was changed: the runtime's state changed since the automatic check "
    "and it is no longer one the app replaces by itself."
)
UPDATE_REFUSED_IN_FLIGHT = (
    "Nothing was changed: an install or update is already in progress. Wait "
    "for it to finish."
)

_IN_FLIGHT = ("downloading", "verifying", "installing")

#: Bound on the integrity reason copied into an audit row.
_INTEGRITY_REASON_MAX = 400


@dataclass(frozen=True)
class UpdateActor:
    """Who asked for the update: an admin (click) or the app itself."""

    email: str
    user_id: int | None
    automatic: bool = False

    @classmethod
    def from_user(cls, user: dict) -> "UpdateActor":
        return cls(email=user.get("email", "") or "", user_id=user.get("id"))

    @classmethod
    def system(cls) -> "UpdateActor":
        return cls(email=SYSTEM_ACTOR_EMAIL, user_id=None, automatic=True)


@dataclass
class UpdateOutcome:
    """What one run of the funnel did. ``status`` is ``updated``, ``failed`` or
    ``refused`` (nothing was attempted; ``refusal`` is static text)."""

    status: str
    refusal: str = ""
    error_class: str = ""
    result: UpdateResult | None = None


@dataclass
class _Claim:
    before: RuntimeStatus
    method: str
    source_dir: Path | None
    manifest_path: Path
    #: The automatic caller's R1 guard for a NON-security (``stale_ok``) update:
    #: do not swap under a runtime this process has already loaded.
    defer_if_loaded: bool = False


def _audit(
    db: sqlite3.Connection, actor: UpdateActor, *, detail: str, outcome: str,
) -> None:
    """Best-effort OUTCOME row through the emitter SSOT (PD-3)."""
    safe_audit_write(
        lambda: record_auth_event(
            db,
            event_type=EVENT_TYPE,
            email=actor.email,
            user_id=actor.user_id,
            outcome=outcome,
            detail=detail,
        ),
        description=f"embedding_install_audit event={EVENT_TYPE} outcome={outcome}",
    )


def _progress_debug(payload: dict) -> None:
    """The installer writes the install-state row itself; this only logs."""
    _log.debug("embedding-update progress", extra={"_extra": {"payload": payload}})


def _track(app: "FastAPI", task: "asyncio.Task[Any]") -> None:
    """Hold a strong reference until the task ends."""
    pending = getattr(app.state, "_fire_and_forget_pending", None)
    if pending is None:
        pending = set()
        app.state._fire_and_forget_pending = pending
    pending.add(task)
    task.add_done_callback(pending.discard)


# ---------------------------------------------------------------------------
# Claim: INTENT row, in-flight guard, row flip (one DB hop)
# ---------------------------------------------------------------------------

async def _claim(
    app: "FastAPI",
    actor: UpdateActor,
    source_dir: Path | None,
    manifest_path: Path | None,
) -> tuple[_Claim | None, str]:
    db = app.state.db
    before = await asyncio.to_thread(runtime_status)
    if actor.automatic and not before.auto_updatable:
        # The R3 rule lives in the funnel, not only in the trigger: a prefix that turned
        # integrity-refused between the trigger's read and this one is NOT healed by the
        # app, and no INTENT row is written (the next tick records the detection).
        _log.warning(
            "automatic embedding update refused at the claim: the status changed",
            extra={"_extra": {"token": before.reason_token}},
        )
        return None, UPDATE_REFUSED_NOT_AUTOMATIC
    method = "sideload" if source_dir is not None else "auto"
    from_set = before.installed_set_version
    image_set = before.image_set_version

    # Every input is a PARAMETER, not a closure capture: the N-338c name-resolution pin
    # (new files must resolve every Name.Load) does not chain enclosing-function scopes.
    def _claim_db_work(
        db: sqlite3.Connection,
        actor: UpdateActor,
        method: str,
        source_dir: Path | None,
        before: RuntimeStatus,
        from_set: int | None,
        image_set: int | None,
    ) -> str:
        # N-543 / N-520: the INTENT row first, committed by the emitter before
        # anything else in this hop writes; a refusal below is then an attempt
        # followed by its failure row, the removal route's shape.
        detail = (
            f"update requested; method={method}; "
            + (
                f"trigger=automatic; reason={before.reason_token}; "
                if actor.automatic else ""
            )
            # Panel B3 hipaa F3 / DA F569-7: the sideload route already records
            # where the bundle came from; so does the update.
            + (f"source_dir={source_dir}; " if source_dir is not None else "")
            + f"from_state={before.state}; "
            f"from_set=v{from_set if from_set is not None else 'unknown'}; "
            f"image_set=v{image_set if image_set is not None else 'unknown'}; "
            f"security={before.security or 'n/a'}"
            # hipaa-sme SHOULD-R3-2: an update of a prefix refused for INTEGRITY
            # (possible tamper evidence, §164.312(c)(1)) records the FULL bounded
            # reason, which names the changed or duplicated distributions (package
            # names, not PHI), so the §164.312(b) record says what changed.
            + (
                f"; integrity_reason={before.reason[:_INTEGRITY_REASON_MAX]}"
                if before.integrity_refusal else ""
            )
            # Panel py314 (hipaa SHOULD-3 / db SHOULD-2): the replace of an
            # interpreter_mismatch prefix wipes another interpreter's orphan tree;
            # the chained row says whether that tree matched its marker first.
            + (
                f"; old_tree_verified={str(before.old_tree_verified).lower()}"
                if before.old_tree_verified is not None else ""
            )
        )
        witnessed = safe_audit_write(
            lambda: (record_auth_event(
                db,
                event_type=EVENT_TYPE,
                email=actor.email,
                user_id=actor.user_id,
                outcome="attempt",
                detail=detail,
            ), True)[1],
            description=f"embedding_install_audit event={EVENT_TYPE} outcome=attempt",
        )
        if witnessed is None:
            return UPDATE_REFUSED_NO_WITNESS
        state = get_install_status(db)
        if state["status"] in _IN_FLIGHT or update_in_progress():
            _audit(
                db, actor,
                detail="rejected — an install or update is already in flight",
                outcome="failure",
            )
            return UPDATE_REFUSED_IN_FLIGHT
        try:
            if actor.automatic:
                # db S-A2: an attempt the process dies in is never counted by _finish.
                # Mark it here; _finish, a failure, a deferral and a success all clear it,
                # and the next tick turns a marker left behind into a counted failure.
                # Panel T db R2-N1: the marker is written (uncommitted) BEFORE the flip,
                # whose commit then carries both. A marker write that raises flips
                # nothing, so the row is never stranded in ``downloading``.
                mark_auto_attempt(db, target=target_of(before))
            _update_state(
                db,
                status="downloading",
                install_method=method,
                current_file=None,
                progress_files_done=0,
                progress_bytes_done=0,
                bump_attempt=True,
                set_last_attempt_now=True,
                clear_error=True,
            )
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            # Panel U DA S1 / db S-U-A1: set_setting_txn leaves the settings cache to the
            # caller on every exit edge; without this a rolled-back marker can linger in
            # the cache and the next tick counts a phantom Interrupted failure.
            invalidate_setting_cache(AUTO_STATE_KEY)
        return ""

    refused = await db_call(
        _claim_db_work, db, actor, method, source_dir, before, from_set, image_set,
    )
    if refused:
        _log.warning(
            "embedding update refused",
            extra={"_extra": {"reason": refused}},
        )
        return None, refused
    return _Claim(
        before=before,
        method=method,
        source_dir=source_dir,
        manifest_path=(
            manifest_path if manifest_path is not None else resolve_manifest_path()
        ),
        defer_if_loaded=bool(actor.automatic and before.state == STATE_STALE_OK),
    ), ""


# ---------------------------------------------------------------------------
# Finish: the work, the OUTCOME row, the automatic run's durable record
# ---------------------------------------------------------------------------

async def _finish(
    app: "FastAPI", actor: UpdateActor, claim: _Claim,
) -> UpdateOutcome:
    app_db = app.state.db
    try:
        result = await asyncio.to_thread(
            update_runtime,
            conn=app_db,
            manifest_path=claim.manifest_path,
            source_dir=claim.source_dir,
            progress_callback=_progress_debug,
            defer_if_loaded=claim.defer_if_loaded,
        )
    except Exception as exc:  # noqa: BLE001
        _log.exception("embedding update task raised")
        err = type(exc).__name__
        # Panel B3 db F569-1(i): the claim flipped the row to "downloading"; an
        # escape past update_runtime's own failure funnel must release it, or
        # every later install/update/removal is refused as in flight.
        await db_call(
            _update_state, app_db,
            status="failed", current_file=None,
            last_error_class=err,
            last_error_msg=scrub_error_for_persist(exc),
        )
        await db_call(
            _audit, app_db, actor,
            detail=f"error — {scrub_error_for_persist(exc)}",
            outcome="failure",
        )
        if actor.automatic:
            await _note_failure(app_db, claim.before, err)
        return UpdateOutcome("failed", error_class=err)

    if result.status == "failed" and result.error_class == DEFERRED_ERROR_CLASS:
        # R1: the funnel found this process already running on the runtime and,
        # asked to defer, swapped nothing. The old set keeps serving; the row goes
        # back to ``installed``; the update waits for the next start. Not a failure.
        await db_call(
            _update_state, app_db,
            status="installed", current_file=None, clear_error=True,
        )
        await db_call(
            _audit, app_db, actor,
            detail=(
                "deferred — this process has already loaded the runtime; the "
                "previous set is unchanged and keeps serving; the update applies "
                "at the next start"
            ),
            # Its own outcome token (db NOTE): a deferral is not a failure, and nothing
            # that counts ``outcome='failure'`` rows may read it as one.
            outcome="deferred",
        )
        await _note_deferral(app, claim.before)
        if result.retired:
            schedule_tombstone_purge(app)  # the staged copy, never evidence
        return UpdateOutcome("deferred", error_class=result.error_class, result=result)
    evidence_kept = bool(claim.before.integrity_refusal)
    evidence_sets: list[str] = []
    if evidence_kept and result.retired:
        # hipaa-sme NOTE-1: the replaced files are renamed out of the tombstone family
        # so no routine purge (this update's or a later one's) can delete them; they stay
        # on the data volume beside the live prefix until an admin removes them.
        evidence_sets = await asyncio.to_thread(keep_as_evidence, list(result.retired))
    if result.status == "updated":
        to_set = result.to_set_version
        detail = (
            f"updated; to_set=v{to_set if to_set is not None else 'unknown'}; "
            f"retired={len(result.retired)}; "
            + (
                f"restart_required=True: {RESTART_MESSAGE}"
                if result.restart_required
                else "restart_required=False: no restart needed"
            )
            + (
                "; evidence_kept=True: the replaced files are kept for inspection on "
                "the data volume as "
                + (", ".join(evidence_sets) or "an evidence set")
                + " until an admin removes them; no routine update purges them"
                if evidence_kept else ""
            )
        )
        outcome = "success"
    else:
        detail = f"failed — {result.error_class}: the previous set is unchanged"
        outcome = "failure"
    await db_call(_audit, app_db, actor, detail=detail, outcome=outcome)
    if actor.automatic:
        if result.status == "updated":
            await db_call(
                record_auto_success, app_db,
                updated={
                    "at": now_utc_iso(),
                    "from_version": result.from_set_version,
                    "to_version": result.to_set_version,
                    "security": claim.before.security or "",
                    # WHY the runtime needed replacing, so a heal of an
                    # integrity refusal (disk_marker_mismatch, ...) is not
                    # reported as a routine manifest move.
                    "reason": claim.before.reason_token,
                    **(
                        {"old_tree_verified": claim.before.old_tree_verified}
                        if claim.before.old_tree_verified is not None else {}
                    ),
                    "advisories": [str(a) for a in claim.before.advisories],
                    "restart_required": bool(result.restart_required),
                },
            )
            set_auto_update_failure(None)
            set_auto_update_deferred(None)
        else:
            await _note_failure(
                app_db, claim.before, result.error_class or "UpdateFailed",
            )
    if result.retired and not evidence_kept:
        # The retired sets go now, off the writer (N-543). EXCEPT when the prefix
        # was refused for integrity (hipaa-sme SHOULD-R3-2): the replaced set is
        # the evidence of what changed (§164.312(b)), so it stays on the volume as
        # a removal tombstone until the next manifest-driven update or an explicit
        # admin removal purges tombstones.
        schedule_tombstone_purge(app)
    return UpdateOutcome(
        "updated" if result.status == "updated" else "failed",
        error_class=result.error_class,
        result=result,
    )


async def _note_deferral(app: "FastAPI", before: RuntimeStatus) -> None:
    target = target_of(before)
    counted = getattr(app.state, "embedding_deferral_counted", "") == target
    # DA NOTE-A5: the boot gate's cap timeout can only set the in-process mirror (it has
    # no db handle). The deferral that follows it is the first durable write, so it
    # carries the cause, with the real count and since.
    mirror = auto_update_deferred()
    timed_out = isinstance(mirror, dict) and mirror.get("target") == BOOT_GATE_TIMEOUT
    deferred = await db_call(
        record_auto_deferral, app.state.db,
        target=target, status=before, count_this_boot=not counted,
        cause=BOOT_GATE_TIMEOUT if timed_out else "",
    )
    app.state.embedding_deferral_counted = target
    set_auto_update_deferred(deferred)


async def _note_failure(
    db: sqlite3.Connection, before: RuntimeStatus, error_class: str,
) -> None:
    state = await db_call(
        record_auto_failure, db,
        error_class=error_class, target=target_of(before),
    )
    set_auto_update_failure(
        {"failures": state["failures"], "error_class": state["error_class"]},
    )


async def start_runtime_update(
    app: "FastAPI",
    *,
    actor: UpdateActor,
    source_dir: Path | None = None,
    manifest_path: Path | None = None,
) -> str:
    """Claim the update and run it in the background. Returns ``""`` once the
    work is under way, or the STATIC refusal text. The click's shape: the route
    answers at once and the install card polls the row."""
    claim, refused = await _claim(app, actor, source_dir, manifest_path)
    if claim is None:
        return refused
    _track(app, asyncio.create_task(_finish(app, actor, claim)))
    return ""


async def apply_runtime_update(
    app: "FastAPI",
    *,
    actor: UpdateActor,
    source_dir: Path | None = None,
    manifest_path: Path | None = None,
) -> UpdateOutcome:
    """Claim the update and run it to the end. The sweeper's shape."""
    claim, refused = await _claim(app, actor, source_dir, manifest_path)
    if claim is None:
        return UpdateOutcome("refused", refusal=refused)
    return await _finish(app, actor, claim)


def schedule_tombstone_purge(app: "FastAPI") -> None:
    """Delete the removal tombstone OFF the DB writer thread (N-543).

    ``remove_install`` and an update only RENAME the old prefix inside
    ``db_call`` (O(1)); the ~600 MB delete runs here, in a worker thread, so the
    single writer is never held by it and ``submit_write`` never sheds other
    users' audit rows while it runs. Fire-and-forget, tracked on ``app.state``
    like the installer task so it is not garbage-collected mid-run. A
    failure is logged; the next install or remove retries the purge.
    """
    async def _run() -> None:
        try:
            purged = await asyncio.to_thread(purge_removal_tombstones)
            if purged:
                _log.info(
                    "embedding runtime: purged the removal tombstone off the writer",
                    extra={"_extra": {"purged": len(purged)}},
                )
        except Exception:  # noqa: BLE001
            _log.exception("embedding runtime: tombstone purge failed")

    task = asyncio.create_task(_run())
    pending = getattr(app.state, "_fire_and_forget_pending", None)
    if pending is None:
        pending = set()
        app.state._fire_and_forget_pending = pending
    pending.add(task)
    task.add_done_callback(pending.discard)


# ---------------------------------------------------------------------------
# The automatic updater's durable state (ONE settings row, R7)
# ---------------------------------------------------------------------------

#: Retry ladder after a failed automatic attempt: 15 min, doubling, capped at 6 h.
#: The state is a settings row, so a restart does not reset it (a crash-looping
#: container cannot retry in a tight loop).
BACKOFF_BASE = timedelta(minutes=15)
BACKOFF_CAP = timedelta(hours=6)

#: How long the "it was updated" notice stays active: long enough for one daily
#: health email to carry it, short enough that it is not news a week later.
UPDATED_NOTICE_WINDOW = timedelta(hours=24)


def backoff_delay(failures: int) -> timedelta:
    if failures <= 0:
        return timedelta(0)
    return min(BACKOFF_CAP, BACKOFF_BASE * (2 ** min(failures - 1, 6)))


def target_of(status: RuntimeStatus) -> str:
    """Which change the failures belong to: a new image (another manifest set)
    is a fresh target, so its first attempt is not held back by the old one."""
    return f"{status.installed_set_version}->{status.image_set_version}"


def read_auto_state(conn: sqlite3.Connection) -> dict[str, Any]:
    """The automatic updater's state, normalized. A corrupt row reads as empty."""
    raw = get_setting(conn, AUTO_STATE_KEY)
    if not isinstance(raw, dict):
        raw = {}
    failures = raw.get("failures")
    if not isinstance(failures, int) or isinstance(failures, bool) or failures < 0:
        failures = 0
    updated = raw.get("updated")
    deferred = raw.get("deferred")
    last = raw.get("last_failure_at")
    return {
        "failures": failures,
        "last_failure_at": last if isinstance(last, str) and last else None,
        "error_class": str(raw.get("error_class") or "")[:64],
        "target": str(raw.get("target") or ""),
        "updated": updated if isinstance(updated, dict) else None,
        # R1: a non-security update waiting for the next restart (see
        # ``record_auto_deferral``); None when nothing waits.
        "deferred": deferred if isinstance(deferred, dict) else None,
        # db S-A2: an automatic attempt claimed but not yet finished (see
        # ``mark_auto_attempt``); a marker left behind means the process died in it.
        "in_flight": raw.get("in_flight") if isinstance(raw.get("in_flight"), dict) else None,
    }


def record_auto_failure(
    conn: sqlite3.Connection, *, error_class: str, target: str,
) -> dict[str, Any]:
    """Count one failed automatic attempt (a new target starts from zero)."""
    state = read_auto_state(conn)
    failures = state["failures"] if state["target"] == target else 0
    state.update(
        failures=failures + 1,
        last_failure_at=now_utc_iso(),
        error_class=error_class[:64],
        target=target,
        deferred=None,  # an attempt was made: nothing waits any more
        in_flight=None,  # and it ended (in failure) in a process that lived to say so
    )
    set_setting(conn, AUTO_STATE_KEY, state)
    return state


def mark_auto_attempt(conn: sqlite3.Connection, *, target: str) -> None:
    """Record that an automatic attempt is under way (written in the claim hop). Every
    way an attempt ends clears it; a marker found with no update running is an attempt
    the process died in, and the next tick counts it as a failure (``Interrupted``).

    Does NOT commit: the claim's commit makes it atomic with the flip to
    ``downloading`` (panel T db R2-N1)."""
    state = read_auto_state(conn)
    state["in_flight"] = {"target": target, "since": now_utc_iso()}
    set_setting_txn(conn, AUTO_STATE_KEY, state)


def record_auto_deferral(
    conn: sqlite3.Connection,
    *,
    target: str,
    status: RuntimeStatus,
    count_this_boot: bool = True,
    cause: str = "",
) -> dict[str, Any]:
    """Record that a NON-security update waits for the next restart because this
    process has already loaded the runtime (ruling R1), and return the durable
    record. ``count`` is the number of boots that deferred THIS target in a row
    (``count_this_boot`` is true once per process): at
    :data:`embedding_bits.DEFERRAL_ESCALATE_COUNT` boots, or after
    :data:`embedding_bits.DEFERRAL_ESCALATE_DAYS` days, the deferral is escalated (panel
    T DA SHOULD-A1). A success clears it, so the count is of CONSECUTIVE deferrals."""
    state = read_auto_state(conn)
    deferred = state["deferred"]
    if isinstance(deferred, dict) and deferred.get("target") == target:
        if not count_this_boot:
            return deferred
        deferred = {**deferred, "count": int(deferred.get("count") or 1) + 1,
                    "last_at": now_utc_iso()}
    else:
        deferred = {
            "since": now_utc_iso(),
            "target": target,
            "from_version": status.installed_set_version,
            "to_version": status.image_set_version,
            "count": 1,
        }
    # Panel T DA NOTE-A5: WHY this boot deferred. ``boot-gate-timeout`` means the boot
    # gate's cap ended the wait mid-download (a slow link), so the next boot downloads
    # again; a deferral for any other reason clears a stale cause.
    if cause:
        deferred["cause"] = cause
    else:
        deferred.pop("cause", None)
    state["deferred"] = deferred
    state["in_flight"] = None
    set_setting(conn, AUTO_STATE_KEY, state)
    return deferred


def record_auto_success(
    conn: sqlite3.Connection, *, updated: dict[str, Any],
) -> None:
    """Clear the failure record (the SET edge went through ``record_auto_failure``;
    this is the CLEAR edge, PD-18) and keep what changed, for the notice."""
    set_setting(conn, AUTO_STATE_KEY, {
        "failures": 0,
        "last_failure_at": None,
        "error_class": "",
        "target": "",
        "updated": updated,
        "deferred": None,
        "in_flight": None,  # the attempt that marked itself in the claim has finished
    })


def clear_auto_flags(conn: sqlite3.Connection) -> None:
    """The runtime is current again by some other route: forget the failures AND
    any deferral (PD-18: every flag SET on one path is CLEARED on every path that
    makes the runtime current)."""
    state = read_auto_state(conn)
    if not state["failures"] and not state["deferred"] and not state["in_flight"]:
        return
    state.update(
        failures=0, last_failure_at=None, error_class="", target="", deferred=None,
        in_flight=None,
    )
    set_setting(conn, AUTO_STATE_KEY, state)


def rehydrate_auto_failure(conn: sqlite3.Connection) -> None:
    """Boot: mirror the durable failure record into the notice's process-local
    state, so a restart does not hide a failure the admin was already told of."""
    state = read_auto_state(conn)
    set_auto_update_failure(
        {"failures": state["failures"], "error_class": state["error_class"]}
        if state["failures"] else None,
    )


def retry_due(
    state: dict[str, Any], *, target: str, now: datetime | None = None,
) -> bool:
    """May the next automatic attempt run? True when nothing failed against this
    target, or when the backoff since the last failure has elapsed."""
    if not state["failures"] or state["target"] != target:
        return True
    if not state["last_failure_at"]:
        return True
    last = parse_iso_aware(state["last_failure_at"])
    if last is None:  # an unreadable stamp must not stall the retries
        return True
    now = now or datetime.now(timezone.utc)
    return now >= last + backoff_delay(state["failures"])


def recent_auto_update(
    state: dict[str, Any], *, now: datetime | None = None,
) -> dict[str, Any] | None:
    """The ``updated`` record while it is inside :data:`UPDATED_NOTICE_WINDOW`."""
    updated = state.get("updated")
    if not isinstance(updated, dict) or not isinstance(updated.get("at"), str):
        return None
    at = parse_iso_aware(updated["at"])
    if at is None:
        return None
    now = now or datetime.now(timezone.utc)
    if timedelta(0) <= now - at < UPDATED_NOTICE_WINDOW:
        return updated
    return None


def describe_auto_update(updated: dict[str, Any]) -> dict[str, Any]:
    """The fields every after-the-fact surface (email, daily health) prints, from
    ONE place (PD-5): path-free and PHI-free."""
    from email_triage.embedding_bits import (
        SECURITY_FIX, SECURITY_NONE, SECURITY_UNKNOWN,
    )

    def _v(n: Any) -> str:
        return f"v{n}" if isinstance(n, int) and not isinstance(n, bool) else "unknown"

    security = str(updated.get("security") or "")
    security_label = {
        SECURITY_FIX: "yes: this release fixes a security problem",
        SECURITY_NONE: "no (not marked as a security fix at release)",
        SECURITY_UNKNOWN: "unknown: treated as a security fix",
    }.get(security, "not applicable")
    restart = bool(updated.get("restart_required"))
    return {
        "headline": "Embedding runtime updated automatically",
        "versions": f"{_v(updated.get('from_version'))} -> {_v(updated.get('to_version'))}",
        "security": security,
        "security_label": security_label,
        "reason": str(updated.get("reason") or "")[:64],
        "advisories": [str(a) for a in updated.get("advisories") or []],
        "at": str(updated.get("at") or ""),
        "restart_required": restart,
        "restart_message": (
            f"{RESTART_MESSAGE[0].upper()}{RESTART_MESSAGE[1:]}." if restart else ""
        ),
    }


# ---------------------------------------------------------------------------
# The automatic trigger (called by the sweeper; boot's first tick is the same)
# ---------------------------------------------------------------------------

async def auto_update_once(app: "FastAPI") -> str:
    """One tick of the automatic updater. Returns a short token (for tests and
    the log): ``disabled`` / ``current`` / ``integrity`` / ``deferred`` / ``busy`` /
    ``backoff`` / ``updated`` / ``failed`` / ``refused``.

    Runs the funnel only for MANIFEST-DRIVEN staleness: the installed runtime is
    stale or refused against this image's manifest and the refusal is not an
    integrity one (``RuntimeStatus.auto_updatable``). An absent runtime
    (``no_prefix``) is never installed from here: the first install stays an
    explicit admin action. A prefix whose INSTALLED.json was written by another
    interpreter (punch 732, ``interpreter_mismatch``) is not absent: it IS
    replaced here, after its orphan tree passed the integrity check against that
    marker (a tree that fails it is an integrity refusal). An INTEGRITY refusal (``INTEGRITY_TOKENS``: the volume
    no longer matches its record, possible tamper evidence) is never healed here:
    it claims nothing, writes no INTENT row and waits for an admin (hipaa-sme R3).
    """
    try:
        return await _auto_update_decision(app)
    finally:
        # The boot gate (panel T DA SHOULD-A1) holds the FIRST embedding load until
        # this first decision is made, whatever it is; every exit releases it.
        release_boot_update_gate()


def _record_integrity_detection(db: sqlite3.Connection, status: RuntimeStatus) -> bool:
    """Write ONE chained ``embedding_runtime_update`` row documenting the detection of
    an integrity refusal (hipaa-sme MUST-1, §164.308(a)(6)(ii) and §164.312(b)): the
    token, that it was NOT replaced automatically, and the bounded reason naming the
    changed distributions (package names, not PHI). ``outcome`` is ``denied:integrity``
    (the emitter's ``denied:`` family; it is not ``failure``, so no login-lockout counter
    reads it). Returns whether the row was written (a refused write is retried next tick)."""
    return safe_audit_write(
        lambda: record_auth_event(
            db,
            event_type=EVENT_TYPE,
            email=SYSTEM_ACTOR_EMAIL,
            user_id=None,
            outcome="denied:integrity",
            detail=(
                f"integrity refusal detected; not replaced automatically; "
                f"token={status.reason_token}; "
                f"reason={status.reason[:_INTEGRITY_REASON_MAX]}"
            ),
        ),
        description=f"embedding_install_audit event={EVENT_TYPE} outcome=denied:integrity",
    ) is not None


async def _auto_update_decision(app: "FastAPI") -> str:
    if not auto_update_enabled():
        return "disabled"
    db = app.state.db
    if update_in_progress():
        return "busy"
    status = await asyncio.to_thread(runtime_status)
    state = await db_call(read_auto_state, db)
    if not status.update_required or restart_pending():
        if state["failures"] or state["deferred"] or state["in_flight"]:
            # PD-18: the failure, deferral and in-flight flags are cleared on EVERY path
            # that makes the runtime current, not only our own success.
            await db_call(clear_auto_flags, db)
        set_auto_update_failure(None)
        set_auto_update_deferred(None)
        return "current"
    if state["in_flight"]:
        # db S-A2: a marker left by a claim whose process died before it finished. Nothing
        # is running now (update_in_progress was checked above) and the install row is not
        # in flight (boot recovery released it); a row that IS in flight is a live attempt.
        # Count the dead one, so the backoff holds across restarts instead of
        # re-downloading on every boot.
        if str((await db_call(get_install_status, db)).get("status") or "") in _IN_FLIGHT:
            return "busy"
        state = await db_call(
            record_auto_failure, db,
            error_class="Interrupted",
            target=str(state["in_flight"].get("target") or target_of(status)),
        )
        set_auto_update_failure(
            {"failures": state["failures"], "error_class": state["error_class"]},
        )
    if status.integrity_refusal:
        token = status.reason_token
        noted = getattr(app.state, "embedding_integrity_noted", None)
        if not isinstance(noted, set):
            noted = set()
            app.state.embedding_integrity_noted = noted
        if token not in noted:
            # Once per token per process: ONE durable chained row, then the WARNING. A
            # row that could not be written is retried on the next tick.
            if await db_call(_record_integrity_detection, db, status):
                noted.add(token)
            _log.warning(
                "embedding runtime refused for integrity; not replaced automatically",
                extra={"_extra": {
                    "token": token,
                    "reason": status.reason[:_INTEGRITY_REASON_MAX],
                }},
            )
        return "integrity"
    target = target_of(status)
    # R1 (operator ruling 2026-10-25): a NON-security update must not swap under a
    # runtime this process has already loaded: that pauses embedding until a human
    # restarts. Keep serving the old set, record the deferral (never silent), and
    # let the next boot's first tick apply it. The funnel re-checks at the swap
    # (``defer_if_loaded``) to close the race with a load after this point.
    if status.state == STATE_STALE_OK and _runtime_loaded_here():
        await _note_deferral(app, status)
        return "deferred"
    set_auto_update_deferred(None)
    if not retry_due(state, target=target):
        return "backoff"
    row = await db_call(get_install_status, db)
    if str(row.get("status") or "") in _IN_FLIGHT:
        return "busy"
    outcome = await apply_runtime_update(app, actor=UpdateActor.system())
    return outcome.status
