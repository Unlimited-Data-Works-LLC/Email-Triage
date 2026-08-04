"""N-356 R31 — dispose_msal_cache_for_cli also cleans pre-N-307 OLD-shape files.

Trust-repair fix-forward per PHASE2 tranche  hipaa-sme + db-sme +
the backlog  (TASK ). Before N-307 (2026-07-03) the CLI MSAL cache
was named `msal_cache_cli_<username>.json`; N-307 switched to
`msal_cache_cli_<safe_stem>_<hash16>.json` to eliminate a cross-account
collision class (§164.310(d)(2)(i)). But `dispose_msal_cache_for_cli`
only unlinked the NEW-shape path, so any install upgraded across N-307
had OLD-shape files orphaned by every operator "clear my auth" call.
These teeth prove the OLD-shape cleanup lands too.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from email_triage.providers import factory as mod


@pytest.fixture
def tmp_data_dir(tmp_path, monkeypatch):
    """Redirect the on-disk `./data/` paths under a tmp_path via
    working-directory swap — the module builds paths as `./data/...`.
    """
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_old_shape_only_gets_disposed(tmp_data_dir):
    """OLD-shape file exists, NEW shape doesn't. Dispose returns True
    and unlinks the OLD file."""
    old = Path("./data/msal_cache_cli_alice.json")
    old.write_text('{"cached": "old-refresh-token"}')
    assert old.exists()

    result = mod.dispose_msal_cache_for_cli("alice")

    assert result is True, "N-356: OLD-shape file must count as a delete"
    assert not old.exists(), "N-356: OLD-shape file must be unlinked"


def test_new_shape_only_still_works(tmp_data_dir):
    """Backward compat: NEW-shape file exists, OLD shape doesn't. Same
    behaviour as before N-356."""
    new = mod.msal_cache_path_for_cli("bob")
    new.write_text('{"cached": "new-refresh-token"}')
    assert new.exists()

    result = mod.dispose_msal_cache_for_cli("bob")

    assert result is True, "N-356: NEW-shape file must count as a delete"
    assert not new.exists(), "N-356: NEW-shape file must be unlinked"


def test_both_shapes_disposed_together(tmp_data_dir):
    """The interesting upgraded-install case: both OLD + NEW shapes
    exist (operator re-authenticated post-N-307 but the OLD file was
    never cleaned). Both must go."""
    old = Path("./data/msal_cache_cli_charlie.json")
    old.write_text('{"cached": "old"}')
    new = mod.msal_cache_path_for_cli("charlie")
    new.write_text('{"cached": "new"}')
    assert old.exists() and new.exists()

    result = mod.dispose_msal_cache_for_cli("charlie")

    assert result is True, "N-356: at least one file must count as a delete"
    assert not old.exists(), "N-356: OLD-shape file must be unlinked"
    assert not new.exists(), "N-356: NEW-shape file must be unlinked"


def test_neither_shape_present_returns_false(tmp_data_dir):
    """Idempotency: absent = no-op = False."""
    result = mod.dispose_msal_cache_for_cli("nobody")
    assert result is False, "N-356: absent = no delete = False"


def test_empty_username_stays_fail_closed(tmp_data_dir):
    """Blank username: N-307's fail-CLOSED on empty username still
    fires (raises ValueError). OLD-shape cleanup MUST NOT circumvent it
    because the OLD shape used the raw username — blank there would
    target the same collision-prone sentinel path N-307 was landed to
    close."""
    # Even if some legacy file named `msal_cache_cli_.json` exists on
    # disk (it wouldn't in practice — the OLD scheme required a
    # username), dispose_msal_cache_for_cli MUST raise on blank input,
    # not silently unlink it.
    with pytest.raises(ValueError):
        mod.dispose_msal_cache_for_cli("")

    with pytest.raises(ValueError):
        mod.dispose_msal_cache_for_cli("   ")


def test_old_shape_unlink_oserror_propagates(tmp_data_dir, monkeypatch):
    """Fail-CLOSED contract: an OSError on the OLD-shape unlink must
    propagate (callers treat it as fail-CLOSED per the docstring)."""
    old = Path("./data/msal_cache_cli_dave.json")
    old.write_text('{"cached": "old"}')

    real_unlink = Path.unlink

    def fake_unlink(self, missing_ok: bool = False) -> None:
        if self.name == "msal_cache_cli_dave.json":
            raise OSError("simulated permission denied")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fake_unlink)

    with pytest.raises(OSError, match="simulated"):
        mod.dispose_msal_cache_for_cli("dave")
