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

import ast
import pathlib
import re

import pytest

from email_triage import triage_logging
from email_triage.web.routers.ui._shared import _apply_runtime_settings

from _pin_harness import (
    annotate_parents,
    enclosing_fn,
    iter_src_files,
    parse_module,  # N-178a
    relpath,
)


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
            assert "Bundle E5 #20" in msg, (
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
    for path in iter_src_files():
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
                "mode, update this test AND the Bundle E5 #20 "
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


# ---------------------------------------------------------------------------
# Sub-check E (2026-06-11, drift-prevention batch 5 — config store-boundary)
#
# The in-memory ``triage_logging._hipaa_mode`` global is a CACHE of the
# authoritative store ``runtime_settings.hipaa`` (DB). Sub-check D pins the
# DB-WRITE gate (the privileged ``allow_hipaa_change=True`` kwarg, exactly one
# caller). This pins the OTHER leg of the one-authoritative-store boundary (R7):
# the GLOBAL-WRITE. ``_hipaa_mode`` is written at exactly FOUR authorized sites —
# its module-level definition, ``setup_logging`` (boot config),
# ``web/app.py:lifespan`` (boot sync from the DB), and ``_apply_runtime_settings``
# (the admin-change funnel, itself gated by Sub-check D). A NEW handler that does
# ``triage_logging._hipaa_mode = X`` directly bypasses the funnel → the cache
# DIVERGES from the DB (reverts on the next boot/sync, or drives a per-account
# PHI decision off a stale in-memory flag). Count-agnostic (ast.walk over all of
# src); FUNCTION-keyed allow-list (R38 — line-stable, never (path, lineno)).
#
# RESIDUAL (documented, like every AST pin): catches an ASSIGNMENT target
# (``tl._hipaa_mode = X`` / a bare ``_hipaa_mode = X``). It does NOT catch a
# reflective write — ``setattr(triage_logging, "_hipaa_mode", X)`` — nor a write
# through an alias bound to the module object via a non-obvious path. No such
# reflective write exists in src today; a future one would need its own guard.
# The underlying _hipaa_mode funnel was SME-reviewed in Bundle E5  (the
# allow_hipaa_change gate); this pin adds CI enforcement of its global-write leg.
# ---------------------------------------------------------------------------

# (rel_path, enclosing_fn) — the ONLY sites authorized to write the _hipaa_mode
# global. Line-stable (R38). Verified against HEAD 2026-06-11 by an AST scan of
# the real write sites (not hand-guessed).
_HIPAA_MODE_WRITE_ALLOW = {
    ("triage_logging.py", "<module>"),       # the global's definition
    ("triage_logging.py", "setup_logging"),  # boot: _hipaa_mode = config.hipaa
    ("web/app.py", "lifespan"),              # boot sync from runtime_settings DB
    # the admin-change funnel — itself gated by Sub-check D (allow_hipaa_change):
    ("web/routers/ui/_shared.py", "_apply_runtime_settings"),
}


def _scan_hipaa_mode_writes(tree: ast.AST, rel: str) -> list[tuple[str, int, str]]:
    """Every assignment whose target writes ``_hipaa_mode`` (a bare ``Name`` in
    triage_logging.py, or an ``Attribute`` like ``triage_logging._hipaa_mode``),
    as (rel, lineno, enclosing_fn)."""
    annotate_parents(tree)
    out: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        else:
            continue
        for t in targets:
            nm = (
                t.attr if isinstance(t, ast.Attribute)
                else t.id if isinstance(t, ast.Name)
                else None
            )
            if nm == "_hipaa_mode":
                out.append((rel, node.lineno, enclosing_fn(node)))
    return out


def _hipaa_mode_write_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        rel = relpath(path)
        for rel_, lineno, fn in _scan_hipaa_mode_writes(tree, rel):
            if (rel_, fn) not in _HIPAA_MODE_WRITE_ALLOW:
                violations.append(f"{rel_}:{lineno} [{fn}]")
    return violations


def test_no_direct_hipaa_mode_write_outside_funnel():
    violations = _hipaa_mode_write_violations()
    assert violations == [], (
        "Direct write to the triage_logging._hipaa_mode global OUTSIDE the "
        "authorized sync funnel (the in-memory cache would diverge from the "
        "authoritative runtime_settings.hipaa DB store):\n  "
        + "\n  ".join(violations)
        + "\nRoute an admin HIPAA-flip through _apply_runtime_settings "
        "(gated by allow_hipaa_change — Sub-check D); never assign "
        "triage_logging._hipaa_mode directly. If a NEW authorized sync site is "
        "genuinely needed, add its (rel, fn) to _HIPAA_MODE_WRITE_ALLOW with a "
        "justification (and explain why the cache stays consistent with the DB)."
    )


def test_hipaa_mode_write_pin_has_teeth():
    # A new handler writing the global directly (qualified attr) is flagged...
    bad = ast.parse(
        "import email_triage.triage_logging as tl\n"
        "def evil_handler():\n"
        "    tl._hipaa_mode = True\n"
    )
    hits = [
        (ln, fn) for _, ln, fn in _scan_hipaa_mode_writes(bad, "x.py")
        if ("x.py", fn) not in _HIPAA_MODE_WRITE_ALLOW
    ]
    assert hits, "pin missed a direct _hipaa_mode global write"

    # ...and a bare-Name write in a non-authorized function is flagged...
    bad_bare = ast.parse(
        "def sneaky():\n"
        "    global _hipaa_mode\n"
        "    _hipaa_mode = True\n"
    )
    hits_bare = [
        (ln, fn) for _, ln, fn in _scan_hipaa_mode_writes(bad_bare, "triage_logging.py")
        if ("triage_logging.py", fn) not in _HIPAA_MODE_WRITE_ALLOW
    ]
    assert hits_bare, "pin missed a bare-Name _hipaa_mode write in a stray fn"

    # ...but an authorized site (setup_logging) is NOT flagged.
    ok = ast.parse(
        "def setup_logging(config):\n"
        "    global _hipaa_mode\n"
        "    _hipaa_mode = config.hipaa\n"
    )
    ok_hits = [
        (ln, fn) for _, ln, fn in _scan_hipaa_mode_writes(ok, "triage_logging.py")
        if ("triage_logging.py", fn) not in _HIPAA_MODE_WRITE_ALLOW
    ]
    assert not ok_hits, "an authorized _hipaa_mode write must NOT be flagged"
