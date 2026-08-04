""" v0.2.0 — audience-tz HH:MM rendering SSOT pin.

`_hm_render.render_hm_for_audience(dt, *, audience_tz=None)` is the
canonical HH:MM audience-tz-aware rendering entry point. Sites that
hand-roll `strftime("%H:%M UTC")` directly bypass the SSOT and would
drift if a future audience-tz refinement (e.g. rendering in a per-
recipient tz_preference) lands on ONE variant.

Grounding: census-live #5 (2026-07-11) row  fixed the LIVE
"name lied vs value" bug at `_shared.py:939` (`ends_at_local_hm` key
holding a UTC-formatted value). The three affected sites — escalate.py:228,
_shared.py:939, watcher.py:2008 — each independently rendered
`strftime("%H:%M UTC")`; a future audience-tz refinement WOULD drift
on 2 of them if updated one-at-a-time.

This pin ships as the same-change count-agnostic structural pin
(Prime Directive #1) for the `_hm_render` SSOT.
The check is grep-based because the offender shape is a `strftime`
LITERAL argument — an AST walker over `ast.Call` would see the
literal-string arg but the pattern-matching for `%H:%M UTC` is
simpler + faster as a raw text scan. Prime Directive #6: routes
through `_pin_harness.iter_src_files` + `relpath`, no hand-rolled
walker.

Allow-list: the SSOT module itself. The bare `strftime("%H:%M %Z")`
inside `_hm_render.py` is the ONE call this class permits.
"""
from __future__ import annotations

import re

from _pin_harness import iter_src_files, relpath


_SSOT_HOME = "_hm_render.py"

# Match `strftime("%H:%M UTC")` (any quotes / whitespace). Bounded to
# the exact "UTC" label — a future `strftime("%H:%M EDT")` would also
# be an offender under the same principle (the SSOT is the ONE place
# tz labeling belongs).
_STRFTIME_HM_UTC = re.compile(
    r'\.strftime\(\s*["\']%H:%M\s+[A-Z]+["\']\s*\)'
)


def test_no_bare_strftime_hm_tz_outside_hm_render_ssot():
    """No `.strftime("%H:%M <TZLABEL>")` outside `_hm_render.py`.

    The audience-tz-aware rendering entry point is
    `_hm_render.render_hm_for_audience`. A future refinement (e.g.
    rendering in a per-recipient tz) lands on ONE module post-SSOT
    instead of drifting across N hand-rolled sites.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith(_SSOT_HOME):
            continue
        text = path.read_text(encoding="utf-8")
        for match in _STRFTIME_HM_UTC.finditer(text):
            # Find the line number of the match.
            line = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{rel}:{line}  {match.group(0)}")
    assert not offenders, (
        " audience-tz SSOT: `.strftime(\"%H:%M <TZLABEL>\")` at a "
        "site outside `_hm_render.py`. Route through "
        "`email_triage._hm_render.render_hm_for_audience(dt, "
        "audience_tz=None)` — `audience_tz=None` preserves the "
        "UTC-labeled wire format from ; passing a `ZoneInfo` "
        "renders in the audience's tz.\n\n" + "\n".join(offenders)
    )
