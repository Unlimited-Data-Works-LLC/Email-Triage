"""the backlog  (Census v3 re-run — LIVE UX) — HH:MM labeling pin.

Structural + cross-module: any ``strftime("%H:%M")`` (or ``"%H:%M "`` with
NO ``UTC`` / timezone label following) that lands into user-facing text
(SMS body, template banner, notification) is a LIVE misread hazard —
the recipient reads a UTC wall-clock as their local time.

The census-recommended SSOT
(``_isotime.now_local_hm()`` + ``render_hm_for_audience(dt, *, audience_tz)``)
is a broader refactor tracked separately (task ). This pin
locks in the discipline that the LIVE UX regressions I closed
(``actions/escalate.py:221`` SMS URGENT prefix,
``web/routers/ui/_shared.py:929`` maintenance-window banner) don't
recur — every unlabeled ``strftime("%H:%M")`` format string in src
must either live inside ``_isotime.py`` (the SSOT the audience-tz
helper will build on) or carry an explicit timezone label in the
same format string (``"%H:%M UTC"``, ``"%H:%M %Z"``).

Prime Directive #6: routes through the shared ``_pin_harness``
walker.
"""
from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, iter_src_files, parse_module, relpath


_SSOT_RELPATH = "_isotime.py"

# Baseline ratchet — 7 pre-existing unlabeled ``%H:%M`` sites uncovered
# by the Census v3 re-run when the pin was authored (2026-07-11). The
# two LIVE reader-facing regressions (``actions/escalate.py:221`` SMS
# URGENT prefix + ``web/routers/ui/_shared.py:929`` banner value) were
# closed same-drive; the remaining 7 baseline entries below are on
# audience-tz SSOT adoption path (task ) — each needs a per-site
# audience decision (operator-local? sender-local? server-local?). The
# ratchet asserts (a) no NEW unlabeled site, (b) baseline never grows,
# so future edits force a labeled string OR a routing decision.
#  (2026-07-11): migrated from line-anchored `(rel, lineno)` to
# name-anchored `(rel, enclosing_fn)` per feedback_divergence_audit_and
# _ssot_pin. Session-third occurrence of the CIDI line-drift trap on
# baseline-allow-lists triggered the migration. The harness's
# `enclosing_fn` helper (`_pin_harness:164`, R38) is the SSOT for
# line-stable allow-list keys.
_BASELINE_ALLOW: frozenset[tuple[str, str]] = frozenset({
    ("actions/digest_filter.py", "digest_should_fire"),
    ("actions/recipient_digest.py", "_format_datetime"),
    ("actions/suggest_meeting_times.py", "_format_slot"),
    ("cli.py", "cmd_status"),
    ("web/digest.py", "_tick"),
    ("web/routers/ui/_shared.py", "_current_user_quiet_hours"),
    ("web/routers/ui/routes.py", "accounts_routes_save"),
})

_LABELED_SUFFIXES: tuple[str, ...] = (
    " UTC", "UTC",     # explicit UTC suffix (with or without leading space).
    " %Z", "%Z",       # tz-abbrev format code.
    " %z", "%z",       # tz-offset format code.
    " GMT", "GMT",
    " Z", "Z",         # ISO-Z suffix (used in Z-form timestamps).
)


def _is_hm_unlabeled(fmt: str) -> bool:
    """Return True if `fmt` contains ``%H:%M`` NOT followed by a
    recognised timezone label — the LIVE misread shape."""
    idx = fmt.find("%H:%M")
    if idx == -1:
        return False
    tail = fmt[idx + 5:]
    if not tail:
        return True
    for suf in _LABELED_SUFFIXES:
        if tail.startswith(suf):
            return False
    if "%H:%M:%S" in fmt:
        return _is_hm_unlabeled(fmt.replace("%H:%M:%S", "", 1))
    return True


def _scan_module(
    tree: ast.Module, rel: str, offenders: list[tuple[str, str, int, str]],
) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not isinstance(f, ast.Attribute) or f.attr != "strftime":
            continue
        if not node.args:
            continue
        arg0 = node.args[0]
        if not (isinstance(arg0, ast.Constant) and isinstance(arg0.value, str)):
            continue
        if _is_hm_unlabeled(arg0.value):
            # : tuple carries (rel, fn, lineno, fmt) — fn is the
            # name-anchored key against `_BASELINE_ALLOW`; lineno
            # + fmt stay for human-readable violation diagnostics.
            offenders.append(
                (rel, enclosing_fn(node), node.lineno, arg0.value)
            )


def _collect_offenders() -> list[tuple[str, str, int, str]]:
    out: list[tuple[str, str, int, str]] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith(_SSOT_RELPATH):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        _scan_module(tree, rel, out)
    return out


def test_no_new_unlabeled_hm_strftime_outside_ssot():
    """Baseline ratchet — bans NEW unlabeled ``%H:%M`` sites. Old
    baseline sites are allow-listed pending task  audience-tz
    SSOT sweep. Name-anchored per  (line-drift-resistant)."""
    fresh = [
        (rel, fn, ln, fmt) for rel, fn, ln, fmt in _collect_offenders()
        if (rel, fn) not in _BASELINE_ALLOW
    ]
    assert not fresh, (
        "Census  LIVE UX: NEW unlabeled `strftime('%H:%M')` site "
        "outside the `_isotime.py` SSOT (baseline-allow-list frozen at "
        "7 sites 2026-07-11). Either label the zone in the format "
        "string ('%H:%M UTC' / '%H:%M %Z') or route through the "
        "audience-tz SSOT (task ):\n\n" +
        "\n".join(
            f"  {rel}:{ln} ({fn})  strftime({fmt!r})"
            for rel, fn, ln, fmt in fresh
        )
    )


def test_baseline_allow_list_never_grows():
    """Strict-shrink invariant — the baseline set must not enumerate a
    site that no longer exists. If an entry drops off (site refactored /
    labeled / routed through SSOT) the allow-list MUST shrink so the
    ratchet actually ratchets. Name-anchored per ."""
    live = {(rel, fn) for rel, fn, _ln, _fmt in _collect_offenders()}
    stale = _BASELINE_ALLOW - live
    assert not stale, (
        "Census  baseline shrunk — prune the following entries "
        "from `_BASELINE_ALLOW` to keep the ratchet honest (the pin "
        "counts the population of hand-rolled `%H:%M` sites; the "
        "allow-list must reflect reality):\n\n" +
        "\n".join(f"  {rel}:{ln}" for rel, ln in sorted(stale))
    )
