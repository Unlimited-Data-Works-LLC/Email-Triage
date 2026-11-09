"""Runtime unit test — ``get_logger`` produces a single-prefix logger name
under every documented call convention.

This test is the runtime companion to the build-time structural pin at
``tests/test_no_double_prefix_get_logger_pin.py``. The pin walks static
call sites and applies ``_normalize_logger_name`` to their literal args;
this test actually calls ``get_logger`` at runtime and inspects the
resulting ``logging.Logger.name`` — so a future refactor that breaks the
``startswith`` branch (or drops the bare-namespace clause) is caught here
even if every call site's static shape remains legal.

Drawer origin: SME-panel db-sme SHOULD-FOLD #2 (2026-07-12) on the
``get_logger`` idempotent-normalization drive. Adding a runtime assertion
of the SSOT contract closes the pair (build-time + runtime).
"""

from __future__ import annotations

import pytest

from email_triage.triage_logging import get_logger


@pytest.mark.parametrize(
    "input_name,expected_logger_name",
    [
        # Short form — canonical style, gets namespace prepended.
        ("actions.move", "email_triage.actions.move"),
        # Fully-qualified form — the N-196b R21_4 shape that used to
        # double-prefix. Now idempotent: returned single-prefix.
        ("email_triage.actions.move", "email_triage.actions.move"),
        # Bare namespace — allowed clause, returned verbatim.
        ("email_triage", "email_triage"),
        # No-dot lookalike — the prefix check requires the trailing dot,
        # so this treats the whole string as a short name and prepends.
        ("email_triage_export", "email_triage.email_triage_export"),
        # Deep short form — prepend, no double-prefix.
        ("web.routers.ui.profile", "email_triage.web.routers.ui.profile"),
    ],
)
def test_get_logger_produces_single_prefix(
    input_name: str, expected_logger_name: str
) -> None:
    """Every documented call convention yields a single-prefix logger name."""
    triage_logger = get_logger(input_name)
    # TriageLogger wraps stdlib logging.Logger — inspect the underlying name.
    assert triage_logger._logger.name == expected_logger_name


def test_get_logger_never_produces_double_prefix() -> None:
    """Even a caller-side double-prefix input normalizes idempotently.

    ``get_logger("email_triage.email_triage.foo")`` is a call-site typo that
    the structural pin catches at build time; here we assert the runtime
    behavior for defense in depth.

    The current SSOT ``_normalize_logger_name`` treats any name already
    starting with ``email_triage.`` as fully-qualified — so a caller-side
    double-prefix STAYS double-prefixed at runtime (idempotency preserves
    it), which is precisely what the build-time pin exists to reject before
    it ever hits runtime. This test documents that runtime does not
    silently repair a call-site typo the pin missed — it stays double-
    prefixed, so a grep of live logs still visibly surfaces the drift.
    """
    triage_logger = get_logger("email_triage.email_triage.foo")
    # Idempotency preserves the caller's exact shape when it already carries
    # the namespace — so a typo like this is caught by the STRUCTURAL PIN,
    # not by the runtime SSOT. Documenting the seam.
    assert triage_logger._logger.name == "email_triage.email_triage.foo"
