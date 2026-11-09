"""N-332 R30 structural pin: `<logger>.debug/info/warning(..., exc_info=…)`
is a silent-swallow of the traceback on TriageLogger callers.

BACKGROUND
==========
`TriageLogger.debug/info/warning` (triage_logging.py, class `TriageLogger`)
are `(self, msg, *args, **extra)` — they DO NOT thread `exc_info`.
Passing `exc_info=<exception>` is silently swallowed into `**extra`
where nothing looks at it. Only `TriageLogger.error/.critical/.log`
declare `exc_info` as an explicit keyword parameter and thread it into
the underlying record. (`.exception()` also attaches a traceback, but it
hardcodes `exc_info=True` and takes no `exc_info` parameter of its own,
so it is neither a swallow site nor a route for a caller-supplied one.)

Deliberately SYMBOL refs, not line numbers: the earlier `:438-444` /
`:447/459/464` citations in this docstring had drifted 99 lines by
2026-09-17 and sent a reader to the wrong part of the file. A stale
pointer in a pin's own failure message is worse than none —
`file:symbol` is greppable and does not rot.

Trust-audit Phase 1 devils-advocate CONFIRMED live at HEAD: N-330's
migration from stdlib `logging.getLogger().debug(msg, exc_info=e)` to
`TriageLogger.debug(msg, exc_info=e)` silently dropped the OAuth push
traceback on `_dashboard_health_chips`. Pre-N-330 stdlib version honored
`exc_info`; post-N-330 sinks it.

WHY COUNT-AGNOSTIC + INTERPROCEDURAL
=====================================
The pin walks EVERY `.py` under `src/email_triage/` and flags any call
of the form `<any>.debug|info|warning(..., exc_info=…)`. It does NOT
require the receiver to be a specific TriageLogger binding — because
(a) at the point of writing, `get_logger` returns a TriageLogger project-
wide (`triage_logging` is the emitter SSOT per PD#3), (b) stdlib
`logging.Logger.debug/info/warning` DO thread `exc_info` but using them
is itself an SSOT bypass caught by the N-196b/N-242 STRICT-0 pins, so a
stdlib-logger caller of `.debug(exc_info=…)` is a DIFFERENT defect
(SSOT bypass) not covered here — and no stdlib-logger source that
survives those pins would land at HEAD anyway. There is no allow-list
(the empty one was removed 2026-11-05); a legitimate stdlib site needs
one added, with a written justification.

WHY `.error()` / `.critical()` / `.log()` ARE THE PERMITTED SET
===============================================================
Those three explicitly thread `exc_info` — they're the ONLY correct
targets for a traceback-carrying log. The intent of this pin is:
if you need `exc_info`, use `.error()` / `.critical()` / `.log()` — the
three methods that ACCEPT and thread an `exc_info` kwarg, stated
identically everywhere in this file.

To keep a WARNING at warning severity, reach for
`.log(logging.WARNING, ..., exc_info=e)`. `_BANNED_METHODS` is
{debug, info, warning}, so the modal site this pin flags is
`.warning(..., exc_info=e)`, and rewriting it to `.error()` mutates the
severity written into an HMAC-chained, un-expungeable `log_entries` row
that is surfaced at `/logs`.

KNOWN GAP, stated rather than implied: `.exception` is NOT in
`_BANNED_METHODS`. It takes `**extra` only and declares no `exc_info`
parameter, so `.exception(msg, exc_info=e)` swallows the kwarg into
`**extra` exactly as `.debug/.info/.warning` do — but it hardcodes
`exc_info=True` internally, so the traceback still attaches and nothing
is lost. That is why it is not banned, and why "permitted set" above is
scoped to what THREADS a caller-supplied `exc_info`, not to what is
safe to call.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


_BANNED_METHODS = {"debug", "info", "warning"}


def _emit_sites(tree: ast.Module) -> list[tuple[ast.Call, str]]:
    """Return (call, method_name) for every `<x>.debug|info|warning(..., exc_info=…)`."""
    out: list[tuple[ast.Call, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _BANNED_METHODS:
            continue
        if any(kw.arg == "exc_info" for kw in node.keywords):
            out.append((node, node.func.attr))
    return out


def test_no_exc_info_on_debug_info_warning():
    """Every log call in ``src/email_triage/`` that threads ``exc_info`` MUST
    target `.error()` / `.critical()` / `.log()` — never `.debug/.info/.warning`,
    which silently swallow `exc_info` on the TriageLogger SSOT."""
    import pytest
    violations: list[str] = []
    for fpath in iter_src_files():
        rel = relpath(fpath)
        text = fpath.read_text(encoding="utf-8")
        # Fast-path: nothing to scan if `exc_info` doesn't appear at all.
        if "exc_info" not in text:
            continue
        tree = parse_module(fpath)
        for call, method in _emit_sites(tree):
            violations.append(
                f"  {rel}:{call.lineno}  .{method}(..., exc_info=…) — "
                "use .error() / .critical(), or .log(logging.WARNING, …) "
                "to keep the severity"
            )
    if violations:
        listed = "\n".join(violations)
        pytest.fail(
            "TriageLogger .debug/info/warning silently swallow `exc_info` — "
            "their signature is (self, msg, *args, **extra), see class "
            "TriageLogger in triage_logging.py. Sites found:\n"
            f"{listed}\n"
            "Route through .error() / .critical() / .log() — those declare "
            "exc_info as an explicit keyword parameter and thread it."
        )
