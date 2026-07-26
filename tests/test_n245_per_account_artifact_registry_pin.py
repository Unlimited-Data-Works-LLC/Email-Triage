"""N-245 R24 structural pin — per-account artifact registry anti-vacuity (2026-07-03).

Census R24 discovered MED (LATENT — ondisk-artifact-disposal V_C):
`msal_cache_path_for_account` was the only per-account file artifact,
but the class-level registry SSOT for "add a new artifact = one row +
dispose/backup inherited" was absent. N-245 lands the registry SSOT.

WHAT IT PINS (anti-vacuity + baseline):

The registry module + its 3 public symbols
(`PER_ACCOUNT_ARTIFACT_BUILDERS`, `PER_ACCOUNT_ARTIFACT_GLOBS`,
`dispose_all_per_account_artifacts`) must import + be non-empty
(the msal_cache builder must be registered).

If a new per-account artifact ships without a registry entry, this
pin should be extended with a structural check that the new artifact's
writer routes through a registered builder. Deferred until such an
artifact exists.
"""
from __future__ import annotations


def test_per_account_artifact_registry_present():
    """Anti-vacuity: the registry module imports + `_BUILDERS` is
    non-empty at HEAD (the msal_cache builder is registered)."""
    from email_triage.providers._ondisk_artifacts import (
        PER_ACCOUNT_ARTIFACT_BUILDERS,
        PER_ACCOUNT_ARTIFACT_GLOBS,
        dispose_all_per_account_artifacts,
    )
    from email_triage.providers.factory import msal_cache_path_for_account
    assert PER_ACCOUNT_ARTIFACT_BUILDERS, (
        "N-245 R24: `PER_ACCOUNT_ARTIFACT_BUILDERS` is empty. Each "
        "per-account file artifact must be registered so a new one "
        "inherits dispose + backup via the ONE registry funnel."
    )
    # msal_cache_path_for_account must be in the registry — anti-
    # vacuity for the SPECIFIC artifact that motivates the registry.
    assert msal_cache_path_for_account in PER_ACCOUNT_ARTIFACT_BUILDERS
    assert PER_ACCOUNT_ARTIFACT_GLOBS
    assert callable(dispose_all_per_account_artifacts)
    # Sanity: on a nonexistent account_id, dispose returns 0.
    assert dispose_all_per_account_artifacts(99999) == 0


def test_dispose_all_per_user_artifacts_has_non_test_caller():
    """N-267 R27 anti-vacuity: `dispose_all_per_user_artifacts` MUST
    have at least one non-test caller in `src/email_triage/`. R27
    census flagged the SSOT as ORPHAN — zero callers meant the
    §164.310(d)(2)(i) plaintext OAuth refresh_token in
    `./data/msal_cache_cli_*.json` had no production disposer. N-267
    landed the CLI `secrets purge-msal-cache --username` actuator to
    close the gap; this pin fires if a refactor drops it."""
    import ast
    from _pin_harness import SRC_ROOT, iter_files, parse_module
    caller_count = 0
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Name) and f.id == "dispose_all_per_user_artifacts":
                caller_count += 1
            if isinstance(f, ast.Attribute) and f.attr == "dispose_all_per_user_artifacts":
                caller_count += 1
    assert caller_count >= 1, (
        "N-267 R27 REGRESSION: `dispose_all_per_user_artifacts` has "
        f"only {caller_count} non-test callers under src/. R27 census "
        "caught this as V_B orphan — no production disposer for the "
        "§164.310(d)(2)(i) plaintext OAuth refresh_token. Wire the "
        "funnel at a natural actuator seam (see N-267 commit for the "
        "CLI `secrets purge-msal-cache` subcommand)."
    )


def test_per_user_cli_artifact_registry_present():
    """N-252 R25: anti-vacuity for the CLI (per-username) sibling
    registry. Census R25 flagged `msal_cache_path_for_cli` as the
    second per-account writer NOT in the registry."""
    from email_triage.providers._ondisk_artifacts import (
        PER_USER_ARTIFACT_BUILDERS,
        PER_USER_ARTIFACT_GLOBS,
        dispose_all_per_user_artifacts,
    )
    from email_triage.providers.factory import msal_cache_path_for_cli
    assert PER_USER_ARTIFACT_BUILDERS, (
        "N-252 R25: `PER_USER_ARTIFACT_BUILDERS` is empty. The CLI's "
        "per-username msal_cache_cli_<user>.json file has no dispose "
        "contract."
    )
    assert msal_cache_path_for_cli in PER_USER_ARTIFACT_BUILDERS
    assert PER_USER_ARTIFACT_GLOBS
    assert callable(dispose_all_per_user_artifacts)
    # Sanity: on a nonexistent username, dispose returns 0.
    assert dispose_all_per_user_artifacts("nonexistent_user_zzz") == 0
