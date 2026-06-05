"""Bundle E5  / Q4 — caller-intent gate for ``_hipaa_mode`` mutation.

Background
==========
``_apply_runtime_settings`` previously wrote ``triage_logging._hipaa_mode``
directly from a runtime-settings dict via ``settings.get("hipaa", False)``.
Any caller — including future contributors not aware of the HIPAA-safety
implications — could change the install-wide HIPAA predicate from a
post-boot request handler. The Q4 probe found this was reachable from
the admin UI via ``admin_security_save`` (canonical, intended) AND
copy-paste-able from there into any new handler that calls
``_apply_runtime_settings``.

The Bundle E5  fix (DESIGN-3, DA-signed-off 2026-05-23): gate the
HIPAA-flip on an explicit ``allow_hipaa_change=True`` keyword-only
kwarg. Only ``admin_security_save`` (the canonical HIPAA off-ramp)
passes it. Every other caller — present or future — that attempts to
flip HIPAA mode raises ``RuntimeError``.

Sub-check D defense (DA addition): even with the kwarg, a future
contributor could copy-paste the call from ``admin_security_save`` and
inherit the privilege. The
:class:`TestExactlyOneAllowHipaaChangeCallSite` test below greps the
source tree and asserts EXACTLY ONE source location passes the kwarg.
Copy-paste fires the test on the next CI run.

Boot-time exception
===================
The FastAPI lifespan path at ``web/app.py:~2139`` deliberately bypasses
the gate — it writes directly to ``triage_logging._hipaa_mode``. The
lifespan restore is the canonical "DB-as-source-of-truth across
restarts" replay; the gate is for POST-BOOT mutation attempts only.
The Sub-check D invariant therefore stays at "exactly one
``_apply_runtime_settings(...,
allow_hipaa_change=True)`` call site" — the lifespan does not call the
gated function for HIPAA.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from email_triage import triage_logging
from email_triage.web.routers.ui._shared import _apply_runtime_settings


# ---------------------------------------------------------------------------
# Functional tests — the gate's runtime behaviour
# ---------------------------------------------------------------------------


class _HipaaModeRestore:
    """Test helper: save the process-wide HIPAA flag, restore on exit.

    Mirrors the disciplined save-and-restore pattern at
    ``tests/test_log_no_token_leak.py:410-426`` — avoids the
    test-contamination class hipaa-sme flagged for Cycle 6 (undisciplined
    bare ``setup_logging(LoggingConfig(hipaa=...))`` calls without
    restore).
    """

    def __init__(self, target_value: bool):
        self._target = target_value
        self._prior: bool | None = None

    def __enter__(self) -> "_HipaaModeRestore":
        self._prior = triage_logging._hipaa_mode
        triage_logging._hipaa_mode = self._target
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        triage_logging._hipaa_mode = bool(self._prior)


class TestRuntimeSettingsHipaaGate:
    """Functional gate behaviour: kwarg required to flip; absent /
    unchanged HIPAA payload is a no-op; current value is preserved
    when ``hipaa`` is missing from the dict."""

    def test_apply_runtime_settings_raises_when_hipaa_flips_without_kwarg(self):
        """The structural-class invariant: an unaware caller cannot
        change HIPAA mode silently — bypass attempt raises immediately."""
        with _HipaaModeRestore(True):
            with pytest.raises(RuntimeError) as exc_info:
                _apply_runtime_settings({"hipaa": False, "log_level": "INFO"})
            msg = str(exc_info.value)
            assert "allow_hipaa_change=True" in msg, (
                f"RuntimeError must name the kwarg the caller missed; "
                f"got: {msg!r}"
            )
            assert "Bundle E5 " in msg, (
                f"RuntimeError must reference the ticket so the next "
                f"reader has a breadcrumb; got: {msg!r}"
            )
            # And the flag is unchanged after the raise.
            assert triage_logging._hipaa_mode is True

    def test_apply_runtime_settings_allows_hipaa_flip_with_kwarg(self):
        """The canonical off-ramp: with the explicit kwarg, the flip
        propagates to the module-global as expected."""
        with _HipaaModeRestore(True):
            _apply_runtime_settings(
                {"hipaa": False, "log_level": "INFO"},
                allow_hipaa_change=True,
            )
            assert triage_logging._hipaa_mode is False

        # Reverse direction: False → True.
        with _HipaaModeRestore(False):
            _apply_runtime_settings(
                {"hipaa": True, "log_level": "INFO"},
                allow_hipaa_change=True,
            )
            assert triage_logging._hipaa_mode is True

    def test_apply_runtime_settings_no_op_when_hipaa_unchanged(self):
        """The gate fires ONLY on actual change attempts — a payload
        whose ``hipaa`` value matches the current flag must not raise
        even without the kwarg. This keeps ``config_save`` (which
        preserves the existing value) working without the privilege."""
        with _HipaaModeRestore(True):
            # No raise — same value, no flip.
            _apply_runtime_settings(
                {"hipaa": True, "log_level": "INFO"},
            )
            assert triage_logging._hipaa_mode is True

        with _HipaaModeRestore(False):
            _apply_runtime_settings(
                {"hipaa": False, "log_level": "INFO"},
            )
            assert triage_logging._hipaa_mode is False

    def test_apply_runtime_settings_preserves_hipaa_when_absent_from_payload(self):
        """``.get("hipaa", <current>)`` default: if the key is missing
        from the dict, the value defaults to the CURRENT flag, not
        ``False``. Partial form-submit therefore can never silently
        downgrade HIPAA. No raise, no change."""
        with _HipaaModeRestore(True):
            _apply_runtime_settings({"log_level": "INFO"})
            assert triage_logging._hipaa_mode is True

        with _HipaaModeRestore(False):
            _apply_runtime_settings({"log_level": "INFO"})
            assert triage_logging._hipaa_mode is False


# ---------------------------------------------------------------------------
# Sub-check D — exactly one source location passes allow_hipaa_change=True
# ---------------------------------------------------------------------------


def _src_root() -> pathlib.Path:
    """Locate ``src/email_triage`` regardless of pytest invocation cwd."""
    here = pathlib.Path(__file__).resolve()
    # tests/test_web/<file> → repo root is parents[2]
    root = here.parents[2] / "src" / "email_triage"
    assert root.is_dir(), f"src tree not found at {root}"
    return root


def _find_call_sites_passing_kwarg() -> list[tuple[pathlib.Path, int, str]]:
    """Walk every ``.py`` under ``src/email_triage`` and return every
    line that calls ``_apply_runtime_settings(...)`` with the
    ``allow_hipaa_change=True`` kwarg.

    Returns ``(path, line_number, full_line)`` tuples.

    Uses a regex on the source text, not AST, because the call may span
    multiple lines but the kwarg appears on the same source line as
    either the call open-paren or the closing one in practice; a regex
    over the file content with re.DOTALL would over-match across
    function boundaries. Per-line check is precise enough for the
    "exactly one" invariant and trivially auditable.

    Prose mentions in docstrings and comments are EXCLUDED by the
    regex: it requires ``_apply_runtime_settings(`` (open paren),
    followed by content, then ``allow_hipaa_change=True``. A
    backtick-quoted reference like ````allow_hipaa_change=True````
    inside a docstring won't match because it lacks the call shape on
    the same line.
    """
    # The regex: `_apply_runtime_settings(` then anything but a newline,
    # then `allow_hipaa_change=True`. Anchored to be a call shape.
    pattern = re.compile(
        r"_apply_runtime_settings\([^\n]*allow_hipaa_change=True"
    )
    matches: list[tuple[pathlib.Path, int, str]] = []
    for path in sorted(_src_root().rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                matches.append((path, i, line.strip()))
    return matches


class TestExactlyOneAllowHipaaChangeCallSite:
    """Sub-check D: the structural defense against future copy-paste
    of the privileged kwarg.

    A future contributor adding a second ``_apply_runtime_settings(...,
    allow_hipaa_change=True)`` call site fires this test on the next
    CI run. If the new caller LEGITIMATELY needs to flip HIPAA mode,
    the contributor must update BOTH this test AND the Bundle E5 
    documentation block in
    ``src/email_triage/web/routers/ui/_shared.py:_apply_runtime_settings``.
    That's deliberate friction.
    """

    def test_exactly_one_call_site_passes_allow_hipaa_change(self):
        sites = _find_call_sites_passing_kwarg()
        assert len(sites) == 1, (
            f"Expected EXACTLY ONE `_apply_runtime_settings(..., "
            f"allow_hipaa_change=True)` call site; found "
            f"{len(sites)}:\n" +
            "\n".join(
                f"  {p}:{n}  {line}" for p, n, line in sites
            ) + (
                "\n\nIf a new caller legitimately needs to flip HIPAA "
                "mode, update this test AND the Bundle E5  "
                "documentation block in "
                "src/email_triage/web/routers/ui/_shared.py "
                "(_apply_runtime_settings) explaining why a second "
                "privileged surface exists. That friction is deliberate."
            )
        )

    def test_the_one_call_site_is_admin_security_save(self):
        """The lone privileged caller must be in
        ``web/routers/ui/admin.py`` — the canonical HIPAA off-ramp.
        Locks the privilege to a specific known module path."""
        sites = _find_call_sites_passing_kwarg()
        assert len(sites) == 1, (
            "test_exactly_one_call_site_passes_allow_hipaa_change "
            "should have already failed; this guard is the "
            "module-path check on top of that count."
        )
        path, lineno, line = sites[0]
        rel_str = str(path).replace("\\", "/")
        assert rel_str.endswith(
            "src/email_triage/web/routers/ui/admin.py"
        ), (
            f"The single privileged call site must be in admin.py "
            f"(canonical HIPAA off-ramp); got: {rel_str}:{lineno}  {line}"
        )
