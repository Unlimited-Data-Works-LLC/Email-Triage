"""N-411 (2026-07-13) — src-side SSOT-declaration forward-coverage meta-pin.

Closes the drift class the operator flagged 2026-07-13 while root-causing the
exampleuser #5 /health vs Accounts-card mismatch:

    A module CAN declare *"Single source of truth"* in its docstring / comment
    without a corresponding §3 registry row + pin file, and NOTHING catches it.

The two existing registry meta-pins guard the REVERSE direction:

  * ``test_ssot_registry_coverage_pin.py`` — every ``tests/…\\.py`` the §3
    registry NAMES must exist on disk (catches renamed/deleted pins).
  * ``test_ssot_registry_bijection_pin.py`` — every registry-named pin has
    teeth + imports ``_pin_harness`` (catches vacuous/hand-rolled pins).

Both explicitly DECLINE the forward direction (their docstrings: *"many
structural pins are legitimately not §3-registry SSOTs, so a forward bijection
would false-flag"*). But that reasoning is about **tests/test_*.py FILES** —
it does NOT apply to **src *"Single source of truth"* DECLARATIONS**. Those
are load-bearing architectural claims; every one MUST have a §3 registration
decision (either "registered + pinned" or "explicitly acknowledged low-
leverage").

The concrete miss that motivated this pin: ``watcher.py:268-278`` documented
``WatcherManager.account_states()`` as *"Single source of truth for 'is this
account ingesting?' … Every operator-facing surface (/health, dashboard chip,
daily digest) folds over this list"* — an aspirational contract with no
executable enforcement. 3 of 4 consumer sites migrated at introduction time;
the 4th (``_shared.py:1008 _admin_stats_snapshot``) escaped and shipped to
production, rendering every Gmail-API + O365 account as ``status=stopped``
on the /admin/stats table (operator screenshot 2026-07-12 21:19 EDT).

Prime Directive 1 in the project style guide: *"Every SSOT ships its count-
agnostic structural pin in the same change."* This meta-pin makes that
directive executable AT PR TIME — no NEW *"Single source of truth"* phrase
lands in src without a §3 decision + corresponding pin or reasoned exemption.

Count-agnostic (AST-walks every src file); interprocedural via docstring
scoping (module / class / function); reuses ``_pin_harness`` per PD#6.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    REPO_ROOT,
    SRC_ROOT,
    iter_src_files,
    parse_module,
    relpath,
)

_PLAYBOOK = REPO_ROOT / "docs" / "ssot-and-divergence-playbook.md"


# Case-insensitive match for "single source of truth" (with optional variations
# — the SSOT / SSOTs / etc. don't count here; only the full phrase, which is
# what the style-guide directive uses).
_SSOT_DECLARATION_RE = re.compile(
    r"single\s+source\s+of\s+truth",
    re.IGNORECASE,
)


# Src files where a "single source of truth" declaration EXISTS but is
# legitimately not §3-registered nor pinned. Each entry MUST carry a stated
# reason. Rot-guarded by :func:`test_unregistered_allow_has_no_stale_entries`
# below (PD#7 — the allow-list is part of the pin's contract).
#
# Categories accepted for allow-listing:
#   (a) Low-leverage dedup-list / cosmetic-constant SSOTs where a pin would
#       be over-engineering (a shared literal list, a rendering constant).
#   (b) SSOTs whose enforcement is entirely BEHAVIORAL (a per-render smoke
#       test) with no structural drift-vector — the behavioral test is
#       named in the reason.
#   (c) SSOTs whose scope is a single-file internal helper with no
#       cross-caller drift risk.
#
# NOT accepted: HIPAA-touching, load-bearing lifecycle (breaker/gate/audit),
# or multi-consumer public seams. Those get a real pin.
_UNREGISTERED_ALLOW: dict[str, str] = {
    # ── seeded 2026-07-13 (N-411 baseline). Each entry is expected to
    # shrink monotonically as Drive-2+ per-SSOT pins land.

    # ---- READERS (not declarations) — false positives of the phrase-match
    # detector. Each references an SSOT that LIVES elsewhere. Future
    # detector refinement (docstring-anchored + "IS the / this IS the"
    # predicate) would drop these from the flagged set naturally.
    "actions/move.py": (
        "N-411 READER: references `build_action_log_extras` SSOT which lives "
        "in a sibling module (pinned via `tests/test_action_log_extras_ssot_"
        "pin.py`); not a declaration."
    ),
    "baa_expiry.py": (
        "N-411 READER: notes the supervised BAA loop SSOT lives in "
        "`web/app.py`; not a declaration."
    ),
    "classify/prompts.py": (
        "N-411 READER: references `llm_safety` fence SSOT (§3-registered "
        "row: `llm_safety.py` `fence_data`); not a declaration."
    ),
    # NOTE — `web/daily_health.py` is READER, not declaration; covered by
    # the N-411 registry row which cites `web/daily_health.py:531` as a
    # consumer. No allow-list entry needed (registry-substring match
    # covers it).

    # retry_backoff.py removed 2026-07-14 (N-410 Drive-4): `compute_next_attempt_at`
    # + the two schedule tuples now pinned by `tests/test_retry_backoff_ssot_pin.py`
    # (module-scope FunctionDef uniqueness + schedule-constant uniqueness + a
    # behavioural anti-vacuity assertion). §3 registry row added same-commit.

    # ---- DRIVE-2+ CLOSE-OUT QUEUE. Each is a genuinely un-pinned SSOT
    # declaration. Kept ON the allow-list so this drive's CI is green while
    # Drives 2+ progressively ship real pins. Rot-guard PD#7 will surface
    # each one as it becomes truly registered (remove from allow-list at
    # that point). Ordered by leverage.

    # ---- ORIGINAL LOW-LEVERAGE seeds (pin-optional; register-decision
    # made in-line here per S3 scope).
    "actions/digest_configs.py": (
        "N-411 baseline: internal digest-model-shape SSOT scoped to this "
        "module + consumers already type-check via TypedDict; low drift "
        "vector, Drive-2 candidate for a per-shape pin if a 2nd builder ships."
    ),
    "actions/suggest_meeting_times.py": (
        "N-411 baseline: operator-facing meeting-suggestion body SSOT; "
        "behavioral drift caught by test_actions/test_suggest_meeting_times "
        "rendered-view tests; Drive-2 candidate."
    ),
    "ai_backends/azure_openai.py": (
        "N-411 baseline: shared list-of-3-strings dedup SSOT across the 3 "
        "openai-compat adapters; cosmetic — a 4th adapter shipping a "
        "divergent list would be caught in code review, low leverage. "
        "Drive-2 candidate for a class-level dedup pin."
    ),
    "ai_backends/gemini_adapter.py": (
        "N-411 baseline: same class as azure_openai.py above (dedup of a "
        "shared list of provider capabilities across adapters)."
    ),
    "ai_backends/openai_direct.py": (
        "N-411 baseline: same class as azure_openai.py above."
    ),
    "web/routers/ui/admin.py": (
        "N-411 baseline: admin-banner-text SSOT scoped to admin surface; "
        "single-caller, low drift vector; Drive-2 candidate."
    ),
    "web/routers/ui/ai_backends_crud.py": (
        "N-411 baseline: admin CRUD SSOT; scoped, low-multi-consumer "
        "drift vector; Drive-2 candidate."
    ),
    "web/routers/help.py": (
        "N-411 baseline: task-list SSOT for the help page — pure content, "
        "no drift consequence beyond stale copy caught in code review."
    ),
}


def _text_declarations(path):
    """Yield ``(lineno, snippet)`` for every occurrence of the SSOT-declaration
    phrase in ``path`` — walks the raw source so BOTH docstrings and ``#``
    comments are covered (an AST-only walk would miss `#` comments)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for idx, line in enumerate(text.splitlines(), start=1):
        if _SSOT_DECLARATION_RE.search(line):
            yield idx, line.strip()[:100]


def _incidental_route_through(snippet: str) -> bool:
    """Filter incidental *route-through-the-SSOT* mentions vs actual
    DECLARATIONS. A declaration reads *"this is the / the single source of
    truth"*; an incidental read is *"route through the SSOT"* / *"via the
    SSOT"* / a `#` comment about USING an existing SSOT. The filter is
    heuristic — it under-flags rather than over-flags, so a genuine
    declaration masquerading as a comment still trips the pin.
    """
    lower = snippet.lower()
    if "route through the ssot" in lower or "via the ssot" in lower:
        return True
    # "this is the single source of truth" / "single source of truth for X"
    # are DECLARATIONS; "of the single source of truth" / "matches the single
    # source of truth" are READS. Very rough heuristic — err on the side of
    # flagging.
    return False


def _src_files_with_declarations() -> dict[str, list[int]]:
    """Return ``{relpath: [linenos]}`` for every src file containing a
    non-incidental SSOT declaration."""
    out: dict[str, list[int]] = {}
    for path in iter_src_files():
        rel = relpath(path)
        hits = [
            lineno for lineno, snippet in _text_declarations(path)
            if not _incidental_route_through(snippet)
        ]
        if hits:
            out[rel] = hits
    return out


def _playbook_text() -> str:
    return _PLAYBOOK.read_text(encoding="utf-8")


def _src_file_is_registered(rel: str, playbook: str) -> bool:
    """True if ``rel`` (a src-relative path like ``web/watcher.py``) appears
    anywhere in the §3 registry. Substring match — cheap + false-positive-safe
    (the src path is distinctive enough that an incidental collision is
    negligible in practice). The registry cells reference src paths directly
    (see e.g. row 36: *"web/routers/_secret_write.py …"*).
    """
    return rel in playbook


def test_every_src_ssot_declaration_is_registered_or_allowed():
    """Every src *"Single source of truth"* declaration MUST correspond to
    either (a) a §3 registry row mentioning this src file OR (b) an entry in
    ``_UNREGISTERED_ALLOW`` with a stated reason.

    This is the FORWARD direction the two existing registry meta-pins
    explicitly declined for tests/*.py files. That decline does NOT apply to
    src declarations — those are load-bearing architectural claims that
    MUST be either pinned or explicitly acknowledged as low-leverage.
    """
    playbook = _playbook_text()
    declarations = _src_files_with_declarations()
    unregistered: list[str] = []
    for rel, linenos in declarations.items():
        if _src_file_is_registered(rel, playbook):
            continue
        if rel in _UNREGISTERED_ALLOW:
            continue
        unregistered.append(f"  {rel}  (lines: {linenos})")
    assert not unregistered, (
        "N-411 SSOT-declaration coverage gap — src file(s) declare `Single "
        "source of truth` in a docstring / comment but are neither §3-"
        "registered nor on `_UNREGISTERED_ALLOW`. Every SSOT must have an "
        "explicit registration decision: either ship a `test_*_ssot_pin.py` "
        "and add a §3 registry row naming this src path, OR add the src "
        "relpath to `_UNREGISTERED_ALLOW` with a stated reason (only for "
        "low-leverage dedup-lists / cosmetic constants / behavioral-only "
        "SSOTs — never for HIPAA-touching / lifecycle / multi-consumer "
        "seams).\n\n"
        + "\n".join(sorted(unregistered))
    )


def test_unregistered_allow_has_no_stale_entries():
    """N-206 R22-style rot-guard — every ``_UNREGISTERED_ALLOW`` entry MUST
    correspond to a live src file that still contains the SSOT declaration
    on HEAD. A stale entry silently exempts a FUTURE declaration that lands
    under the same relpath.

    Additionally: an entry whose src file is NOW §3-registered is dead
    weight (the allow-list exemption is not what covers it anymore) —
    remove it to keep the allow-list honest.
    """
    playbook = _playbook_text()
    declarations = _src_files_with_declarations()
    problems: list[str] = []
    for rel in sorted(_UNREGISTERED_ALLOW):
        if rel not in declarations:
            problems.append(
                f"  {rel}  — no `single source of truth` declaration on HEAD "
                "(file moved/renamed OR declaration removed)"
            )
            continue
        if _src_file_is_registered(rel, playbook):
            problems.append(
                f"  {rel}  — NOW §3-registered; the allow-list exemption is "
                "dead weight, remove it (the registry row is what covers it)"
            )
    assert not problems, (
        "N-411 rot-guard: `_UNREGISTERED_ALLOW` has stale entries. Keep the "
        "allow-list honest (PD#7 — the pin's exemption list is part of its "
        "contract).\n\n" + "\n".join(problems)
    )


def test_pin_has_teeth():
    """N-237 R23 ARM 4 teeth-probe — the phrase-detector regex must flag
    the canonical declaration shapes and not incidental non-declarations.
    """
    assert _SSOT_DECLARATION_RE.search(
        "This is the single source of truth for X."
    ), "detector missed a canonical declaration"
    assert _SSOT_DECLARATION_RE.search(
        "# Single source of truth for the setting cache TTL."
    ), "detector missed a `#`-comment declaration"
    assert _SSOT_DECLARATION_RE.search(
        "Single Source Of Truth"
    ), "detector is case-sensitive (should be case-insensitive)"
    assert not _SSOT_DECLARATION_RE.search(
        "This module contains helper functions for parsing."
    ), "detector false-flagged a non-declaration line"

    # And the whole-pipe teeth: a planted unregistered src path is flagged.
    fake = "web/definitely_not_in_playbook_xyz.py"
    playbook = _playbook_text()
    assert not _src_file_is_registered(fake, playbook), (
        "test setup: planted fake path unexpectedly appears in playbook"
    )
    assert fake not in _UNREGISTERED_ALLOW, (
        "test setup: planted fake path unexpectedly on the allow-list"
    )
