"""N-245 R24 — per-account on-disk artifact registry (2026-07-03).

Census R24 discovered MED (LATENT — ondisk-artifact-disposal V_C):
`msal_cache_path_for_account` was the only per-account file artifact
at HEAD, but adding a NEW artifact (say `oauth_state_<id>.json` or
`push_cursor_<id>.dat`) would re-fork the create/dispose/backup CIDI
shape run18 #1 already closed for msal_cache alone. No structural
registry existed to force a new artifact to register ONCE.

N-245 lands the registry SSOT even though there's no live drift YET —
the LATENT class becomes a MOVING drift shape the moment a second
per-account artifact ships. Registering-once-inherits-everything is
the anti-CIDI shape.

Contract:
  - `PER_ACCOUNT_ARTIFACT_BUILDERS: list[Callable[[Any], Path]]` — each
    entry is a builder that takes `account_id` and returns the
    absolute Path to that artifact's file.
  - `PER_ACCOUNT_ARTIFACT_GLOBS: list[str]` — glob patterns matching
    every artifact family, useful for backup + orphan-sweep.
  - `dispose_all_per_account_artifacts(account_id) -> int` — walks
    every builder, calls `.unlink(missing_ok=True)`, returns count
    deleted. Idempotent; fail-open on individual OSError (per-artifact
    logging left to the caller).

Adding a new per-account artifact = one row in `_BUILDERS` (and one
glob in `_GLOBS` if the disposal path also does a glob sweep). The
disposal actuator at `db/accounts.py::_delete_account_and_secrets`
already calls this registry after the msal-cache-specific dispose
(deprecating the per-artifact hard-coded unlink over time).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from email_triage._errfmt import fmt_exc
from email_triage.providers.factory import (
    msal_cache_path_for_account,
    msal_cache_path_for_cli,
)


# Type alias — each builder must take `account_id` (any type that
# str-formats — the factory's own signature takes Any) and return an
# absolute Path.
_ArtifactBuilder = Callable[[Any], Path]


# Registry of per-account artifact builders. Adding a new artifact
# family = one row here + one entry in `_GLOBS` if a wider sweep also
# needs it. Order doesn't matter — disposal walks all entries.
_BUILDERS: list[_ArtifactBuilder] = [
    msal_cache_path_for_account,
]


# Glob patterns for wider orphan-sweep + backup coverage. Kept
# separately so the disposal-side registry doesn't have to know the
# glob shape (a builder returns a specific Path; the glob catches any
# orphan created by an interrupted write).
PER_ACCOUNT_ARTIFACT_GLOBS: list[str] = [
    # N-259b R26: drop the underscore so this pattern also matches the
    # legacy singleton `msal_cache.json` (pre-#229 installs). The
    # n177_backup_msal_glob_pin explicitly requires the `msal_cache*.
    # json` (no underscore) shape for the backup collector.
    "./data/msal_cache*.json",
]


# Public alias — the registry name census recommended.
PER_ACCOUNT_ARTIFACT_BUILDERS: list[_ArtifactBuilder] = _BUILDERS


# N-252 R25: CLI (per-username) artifact registry — a sibling registry
# because `msal_cache_path_for_cli(username)` takes a username, not an
# account_id. Census R25 flagged this writer as missing from
# `_BUILDERS`, leaving an orphan `dispose_msal_cache_for_cli` (0
# non-def callers) — the CLI's plaintext OAuth refresh_token had no
# disposal contract.
_USER_ArtifactBuilder = Callable[[str], Path]

# NOTE (2026-07-09 hipaa-sme + db-sme V6 fold): this registry is
# retained for the backup-side glob companion (`PER_USER_ARTIFACT_GLOBS`
# feeds `backup.py` at `:1187` — the collector excludes these paths from
# the backup share). The disposer `dispose_all_per_user_artifacts` no
# longer iterates it; disposal routes through the SSOT
# `dispose_msal_cache_for_cli` which handles BOTH the post-N-307
# hash-suffixed shape AND the pre-N-307 raw-username OLD shape atomically.
# DO NOT re-inline the `for builder in _USER_BUILDERS` loop; that shape
# leaks the OLD-shape file (§164.310(d)(2)(i) LITERAL Disposal defect).
# The structural pin at `tests/test_ondisk_disposal_old_shape_pin.py`
# guards against this regression.
_USER_BUILDERS: list[_USER_ArtifactBuilder] = [
    msal_cache_path_for_cli,
]

PER_USER_ARTIFACT_BUILDERS: list[_USER_ArtifactBuilder] = _USER_BUILDERS

PER_USER_ARTIFACT_GLOBS: list[str] = [
    # Post-N-307 shape (hash-suffixed) + the pre-N-307 raw-username shape
    # (N-356 cleanup). Both are unlinked by `dispose_msal_cache_for_cli`;
    # both must also route into the backup-exclusion widening so a fresh
    # install upgraded across N-307 doesn't leak either shape into the
    # backup share.
    "./data/msal_cache_cli_*.json",
]


def dispose_all_per_user_artifacts(username: str) -> int:
    """N-252 R25: CLI-user sibling of
    `dispose_all_per_account_artifacts`. Routes every registered
    per-user artifact through its SSOT disposer.

    Census wf_56d1585d "Other findings" — ondisk-artifact-disposal V6
    (2026-07-09): the prior builder-loop shape called
    `msal_cache_path_for_cli(username).unlink(...)` which returns ONLY the
    post-N-307 hash-suffixed path — the pre-N-307 OLD-shape file
    `./data/msal_cache_cli_<username>.json` survived every operator
    `secrets purge-msal-cache` on an install upgraded across N-307 tranche
    . `dispose_msal_cache_for_cli` (N-356 R31) is the SSOT that
    unlinks BOTH shapes atomically; route through it so the registry
    walk cannot silently leak the OLD shape.

    The SSOT disposer returns True/False for a single artifact family;
    aggregate the boolean into the same "count deleted" contract that
    `dispose_all_per_account_artifacts` returns. Idempotent; OSError on
    the OLD-shape unlink propagates (fail-CLOSED, matching
    `dispose_msal_cache_for_cli`).
    """
    from email_triage.providers.factory import dispose_msal_cache_for_cli
    deleted = 0
    if dispose_msal_cache_for_cli(username):
        deleted += 1
    return deleted


def dispose_all_per_account_artifacts(account_id: Any) -> int:
    """N-245 R24: walk every registered per-account artifact builder,
    unlink the file (idempotent, **fail-CLOSED** on individual
    OSError — the body `except OSError: raise` re-raises).

    N-306 R30 (2026-07-03 DB-SME fix-forward): docstring corrected —
    the pre-fix version said "fail-open on individual OSError" which
    contradicted the actual code (`except OSError: raise` propagates
    to the caller). The BEHAVIOR was always correct (fail-CLOSED per
    the §164.310(d)(2)(i) pattern at `db/accounts.py:1469`); only the
    doc was misleading.

    Returns the count of files actually deleted (i.e. that existed
    pre-call). A fresh account with no artifacts yet returns 0.

    Callers MUST treat a pending OSError as fail-CLOSED per the
    §164.310(d)(2)(i) pattern at `db/accounts.py:1469` — if this
    function raises, the account-delete cascade must not report
    success.
    """
    # N-310 R30 (tranche  batch A DA + DB-SME fix-forward on N-245b):
    # per-artifact failure isolation — a raising builder must NOT skip
    # sibling disposals. Collect errors; dispose ALL; raise at the end
    # if any failed. Fail-CLOSED preserved (caller still sees an
    # exception with the aggregate), but every artifact gets a dispose
    # attempt so a broken new-artifact-#N doesn't silently orphan
    # msal_cache (§164.310(d)(2)(i) LITERAL Disposal).
    #
    # N-354 R31 (2026-07-05 trust-repair fix-forward per PHASE2 tranche 
    # DA + the backlog  = TASK ): closes two residual defects the
    # original N-310 shape left open:
    #   (a) `builder(account_id)` was OUTSIDE the try/except — a raising
    #       builder (broken registration, TypeError on unexpected
    #       account_id shape, path composition failure) skipped every
    #       sibling disposal + propagated an unwrapped exception. Now
    #       inside the try; a builder-error is aggregated with the same
    #       failure-isolation contract.
    #   (b) `errors[1:]` were silently DROPPED from the raised message —
    #       only the first error's path + type survived. On a partial-
    #       dispose incident the operator lost forensic detail on every
    #       error past the first. Now logged at WARNING before raising.
    from email_triage.triage_logging import get_logger
    _log = get_logger("email_triage.providers._ondisk_artifacts")
    deleted = 0
    errors: list[tuple[Any, Exception]] = []
    for builder in _BUILDERS:
        p: Any = None
        try:
            p = builder(account_id)
            if p.exists():
                p.unlink(missing_ok=True)
                deleted += 1
        except OSError as e:
            errors.append((p, e))
        except Exception as e:
            # N-354 fix (a): a raising builder must NOT skip siblings.
            # Aggregate + continue; caller sees fail-CLOSED at the end.
            errors.append((p, e))
    if errors:
        # N-354 fix (b): log every extra error (past the first) at
        # WARNING before raising — the raised message summarises the
        # first + count, but partial-dispose incidents need every error's
        # path + type for forensic detail on the §164.310(d)(2)(i)
        # disposal audit trail. `getMessage`-friendly kwargs; the
        # sanitised extras dict carries structured detail per persist.
        first_path, first_err = errors[0]
        for extra_path, extra_err in errors[1:]:
            _log.warning(
                "per-account artifact dispose: additional failure past first — "
                "detail lost from raised OSError message",
                artifact_path=str(extra_path) if extra_path is not None else "<builder-error>",
                error_type=type(extra_err).__name__,
                error_msg=str(extra_err),
                account_id=account_id,
            )
        if len(errors) > 1:
            raise OSError(
                f"per-account artifact dispose: {len(errors)} of "
                f"{len(_BUILDERS)} artifacts failed to unlink; first "
                f"at {first_path}: {first_err}"
            )
        # Preserve typed re-raise for single-error case only when the
        # single error was itself an OSError. A single non-OSError
        # (builder failure) wraps to OSError to keep the caller contract
        # stable (`callers MUST treat a pending OSError as fail-CLOSED`).
        if isinstance(first_err, OSError):
            raise first_err
        raise OSError(
            f"per-account artifact dispose: builder failed for "
            f"account_id={account_id}: {fmt_exc(first_err, with_class=True)}"
        )
    return deleted
