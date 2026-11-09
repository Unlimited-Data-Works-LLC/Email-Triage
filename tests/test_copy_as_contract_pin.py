"""COPY-AS-CONTRACT PIN — every user-visible imperative directive that names a
MECHANISM (verb + object shape: "turn it off", "click the X button", "instead
of deleting", "reconnect via", "manage in settings") MUST have a registry entry
in ``tests/copy_contract_registry.json`` mapping the phrase to a canonical
mechanism reference (route path, handler symbol, or explicit ``exempt``).

**Why this exists — D2 (2026-07-16 audit):**
The delete-refusal in ``src/email_triage/db/regulatory_clock.py:544-547`` says:

    "This template has been used (it has deadline history) — turn it off
    instead of deleting it, so past records stay intact."

...but NO route sets ``enabled=0`` on owned regulatory-clock templates and NO
UI toggle exists. The user-facing directive names a mechanism the code doesn't
deliver. Same class as the  cache-flush regression: shipped copy that
references a nonexistent feature. Prime Directive  ("test the rendered VIEW,
not just model/DB/auth") applies at the COPY layer too — a directive that
names a nonexistent verb+object is a defect even though py_compile + unit
tests + StrictUndefined all pass.

**The contract — COPY IS A CONTRACT WITH CODE.** A directive names a mechanism
→ that mechanism MUST exist AND the phrase→mechanism link MUST be filed in
the registry. The pin is COUNT-AGNOSTIC (PD#1): a property over every
user-visible string in ``src/**/*.py`` + ``src/email_triage/web/templates/
**/*.html``, never ``len(X)==N``. Fail-closed on any UNREGISTERED imperative
— adding rows to the registry is the whitelist step; enumerating the
imperatives IS the workflow. No pre-emptive size ratchet (unlike VALK): the
registry itself IS the ratchet — a NEW imperative in source with NO matching
key fires.

**Prior art:** the ``_FIRE_NOTIFICATION_KNOWN_CALLERS`` set in
``tests/test_webhook_ssot_pins.py`` (SME-panel 2026-07-15 DA-F1) is the same
allow-list shape at a different grain — a known-caller set that fails-closed
on a new caller. This pin does the same for user-facing copy: registered
phrases are the known-mechanism set; a new imperative fails-closed until
classified.

**String-filter strategy — the spec's fallback.** Filtering Python strings to
"user-facing only" would require whole-program analysis (which route serves
this string, is it flashed, is it a docstring vs raise arg vs log.info). This
pin does NOT: it scans EVERY string literal in every ``src/`` module (via the
harness ``parse_module`` + a JoinedStr-aware walker) and leans on the
registry to mark non-user-facing strings as ``exempt`` with a one-line reason.
That keeps the pin free of routing-layer assumptions (which drift) and
concentrates the semantic classification in the ONE registry file where a
reviewer can see it. Templates are strip-processed line-preservingly so a hit
reports the source .html file's lineno."""

from __future__ import annotations

import ast
import json
import pathlib
import re

from _pin_harness import (
    REPO_ROOT,
    iter_src_files,
    iter_template_files,
    parse_module,
    relpath,
)

_TESTS_ROOT = pathlib.Path(__file__).resolve().parent
_REGISTRY_PATH = _TESTS_ROOT / "copy_contract_registry.json"


# ---------------------------------------------------------------------------
# The imperative-phrase grammar. Case-insensitive; each pattern is a verb +
# mechanism-object shape naming a UI/routing affordance the user is directed
# to. Adding a pattern WIDENS the census — a new imperative class is now
# discoverable, then registered. Removing one is a NARROWING (a directive
# class is now uncensused) — do NOT remove without a hipaa-sme review.
# ---------------------------------------------------------------------------
_IMPERATIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bturn (it|them|this|that|[a-z]+) off\b", re.IGNORECASE),
    re.compile(r"\bturn (it|them|this|that|[a-z]+) on\b", re.IGNORECASE),
    re.compile(
        r"\bclick (the )?[a-z ]*?(button|link|toggle|switch|checkbox|option)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\buse (the )?[a-z ]*?(toggle|switch|button)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\btoggle (it|this|that|[a-z]+)\b", re.IGNORECASE),
    re.compile(r"\benable (it|them|this|that|[a-z]+)\b", re.IGNORECASE),
    re.compile(r"\bdisable (it|them|this|that|[a-z]+)\b", re.IGNORECASE),
    re.compile(
        r"\binstead of (deleting|removing|disabling|updating)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\breconnect (via|through|using|from)\b", re.IGNORECASE),
    re.compile(
        r"\bmanage (this|it|them|[a-z]+) in (the )?settings\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bgo to (the )?settings\b", re.IGNORECASE),
    re.compile(r"\bcheck the box\b", re.IGNORECASE),
)


def _matches_imperative(s: str) -> tuple[str, ...]:
    """Return every matched imperative phrase in ``s`` (lower-cased, stripped,
    de-duped in match order). Empty tuple when nothing matches."""
    seen: list[str] = []
    for pat in _IMPERATIVE_PATTERNS:
        for m in pat.finditer(s):
            phrase = m.group(0).strip().lower()
            if phrase not in seen:
                seen.append(phrase)
    return tuple(seen)


# ---------------------------------------------------------------------------
# Template-markup strip. Newline-preserving substitution so post-strip line
# numbers still match the source .html lineno (a Jinja block spanning lines
# 10..15 collapses to 5 blank lines, not 1 — else the reported lineno on a
# visible-text hit would drift silently). Perfect Jinja parsing is OUT OF
# SCOPE — this catches the dominant ``{% ... %}`` / ``{{ ... }}`` / ``{# #}``
# / ``<script>`` / ``<style>`` shapes. Residual false-positives (a phrase in
# an HTML attribute that survives the tag-strip) fall through to the registry
# as an ``exempt`` row with a one-line reason.
# ---------------------------------------------------------------------------
_JINJA_COMMENT = re.compile(r"\{#[\s\S]*?#\}")
_JINJA_STMT = re.compile(r"\{%[\s\S]*?%\}")
_JINJA_EXPR = re.compile(r"\{\{[\s\S]*?\}\}")
_SCRIPT_BODY = re.compile(r"<script[\s\S]*?</script>", re.IGNORECASE)
_STYLE_BODY = re.compile(r"<style[\s\S]*?</style>", re.IGNORECASE)
_HTML_TAG = re.compile(r"<[^>]+>")


def _blank_preserving_newlines(m: re.Match[str]) -> str:
    return "\n" * m.group(0).count("\n")


def _strip_template_markup(text: str) -> str:
    for pat in (_JINJA_COMMENT, _JINJA_STMT, _JINJA_EXPR, _SCRIPT_BODY, _STYLE_BODY):
        text = pat.sub(_blank_preserving_newlines, text)
    text = _HTML_TAG.sub(" ", text)
    return text


# ---------------------------------------------------------------------------
# Python string-literal walker — reuses the pin harness's ``parse_module``.
# Yields (string_value, lineno) for every ``ast.Constant(str)`` and every
# joined-string literal (f-string literal segments concatenated; formatted-
# value slots become empty string so a needle spanning literal segments still
# fires). Adjacent string literals like ``"a " "b"`` are Python-parsed into a
# SINGLE Constant, so a phrase spanning the concatenation naturally works.
# ---------------------------------------------------------------------------
def _iter_string_nodes_with_lineno(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value, node.lineno
        elif isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    parts.append("")
            joined = "".join(parts)
            if joined:
                yield joined, node.lineno


def _load_registry() -> dict:
    if not _REGISTRY_PATH.exists():
        return {"__schema": "v1"}
    data = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    assert data.get("__schema") == "v1", (
        "copy_contract_registry.json missing or wrong '__schema' — expected 'v1', "
        f"got {data.get('__schema')!r}. The schema key gates future format shifts."
    )
    return data


def _scan_repo() -> list[tuple[str, int, str]]:
    """Return every (repo-relpath, lineno, matched_phrase) triple across
    ``src/`` and the template tree. Relpath is REPO-ROOT-relative forward-
    slash (harness ``relpath(p, REPO_ROOT)``) so the registry key matches the
    SSOT-registry playbook §3 shape (``src/email_triage/…``)."""
    hits: list[tuple[str, int, str]] = []
    for path in iter_src_files():
        rel = relpath(path, REPO_ROOT)
        tree = parse_module(path)
        if tree is None:
            continue
        for s, lineno in _iter_string_nodes_with_lineno(tree):
            for phrase in _matches_imperative(s):
                hits.append((rel, lineno, phrase))
    for path in iter_template_files():
        rel = relpath(path, REPO_ROOT)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # pragma: no cover
            continue
        stripped = _strip_template_markup(text)
        for lineno, line in enumerate(stripped.splitlines(), start=1):
            for phrase in _matches_imperative(line):
                hits.append((rel, lineno, phrase))
    return hits


def _registry_key(rel: str, phrase: str) -> str:
    """The canonical composite key: ``<repo-relpath>::<phrase-normalized>``.
    Line-independent — a phrase moving lines within the same file preserves
    the key so a benign refactor doesn't churn the registry."""
    return f"{rel}::{phrase}"


def test_every_imperative_phrase_has_registry_entry():
    """PD#1 (count-agnostic) + PD#17 (test the rendered VIEW): every user-
    visible imperative phrase in ``src/*.py`` + ``templates/*.html`` MUST be
    registered mapping the phrase to a ``mechanism_ref`` (or an ``exempt``
    reason). D2 (2026-07-16): the delete-refusal string names a "turn it off"
    mechanism that doesn't exist — this pin fails-closed on that class of
    drift."""
    registry = _load_registry()
    hits = _scan_repo()
    missing_by_file: dict[str, list[tuple[int, str]]] = {}
    for rel, lineno, phrase in hits:
        key = _registry_key(rel, phrase)
        if key in registry:
            continue
        missing_by_file.setdefault(rel, []).append((lineno, phrase))
    if not missing_by_file:
        return
    total = sum(len(v) for v in missing_by_file.values())
    lines = [
        f"COPY-AS-CONTRACT PIN: {total} user-visible imperative phrase(s) in "
        f"{len(missing_by_file)} file(s) have NO tests/copy_contract_registry.json "
        "entry.",
        "",
        "Each phrase names a MECHANISM (a route, a UI toggle, a workflow) the user "
        "is directed to. The registry proves the phrase → mechanism link exists.",
        "Classify each as either:",
        '  {"mechanism_ref": "<verb+target>", "notes": "..."}  (real mechanism)',
        '  {"exempt": "<reason>"}                              (not user-facing, log/dev-only)',
        "",
        "Paste-ready registry additions (dedupe + merge into "
        "tests/copy_contract_registry.json):",
        "",
    ]
    for rel in sorted(missing_by_file):
        lines.append(f"# {rel}")
        seen_keys: set[str] = set()
        for lineno, phrase in sorted(missing_by_file[rel]):
            key = _registry_key(rel, phrase)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            lines.append(
                f'  "{key}": {{"mechanism_ref": "TODO", "notes": "line {lineno}"}},'
            )
        lines.append("")
    raise AssertionError("\n".join(lines))


def test_registry_entries_are_well_formed():
    """Every registry entry (except the ``__schema`` sentinel) must be a dict
    with either ``mechanism_ref`` OR ``exempt`` (non-empty string). A mistyped
    row would silently pass the phrase gate above (dict-membership check is
    truthy) so this is a structural belt to that suspenders."""
    registry = _load_registry()
    for key, entry in registry.items():
        if key == "__schema":
            continue
        assert isinstance(entry, dict), f"{key}: registry entry must be a dict"
        has_ref = (
            isinstance(entry.get("mechanism_ref"), str)
            and entry["mechanism_ref"].strip()
        )
        has_exempt = (
            isinstance(entry.get("exempt"), str)
            and entry["exempt"].strip()
        )
        assert has_ref or has_exempt, (
            f"{key}: registry entry needs either 'mechanism_ref' or 'exempt' "
            "(non-empty string)"
        )
        assert "::" in key, (
            f"{key}: registry key must be '<repo-relpath>::<phrase>'"
        )


def test_registry_entries_are_still_live():
    """A registry entry whose phrase no longer appears in the source is a
    STALE exemption — drop it (else a future re-introduction of the phrase
    silently inherits a green pin, exactly the R38-shape blind spot the
    harness exists to kill). Excludes the ``__schema`` sentinel."""
    registry = _load_registry()
    live_keys: set[str] = set()
    for rel, _lineno, phrase in _scan_repo():
        live_keys.add(_registry_key(rel, phrase))
    stale = [k for k in registry if k != "__schema" and k not in live_keys]
    assert not stale, (
        "Stale registry entries — the phrase no longer appears in the source. "
        "Drop them:\n  " + "\n  ".join(sorted(stale))
    )


def test_imperative_matcher_has_teeth():
    """PD#7 ("census the censusers") — the matcher fires on planted BAD shapes
    and stays quiet on planted GOOD shapes. A pin that silently matches
    nothing is worse than no pin."""
    # BAD — every core pattern class must fire on a planted string.
    assert "turn it off" in _matches_imperative("turn it off")
    assert any(
        "click" in p
        for p in _matches_imperative("click the disable button")
    )
    assert "toggle it" in _matches_imperative("please toggle it later")
    assert "instead of deleting" in _matches_imperative(
        "turn it off instead of deleting"
    )
    assert "reconnect via" in _matches_imperative(
        "please reconnect via the settings page"
    )
    assert "check the box" in _matches_imperative("check the box below")
    assert any(
        "go to" in p for p in _matches_imperative("go to settings to fix this")
    )
    # GOOD — plain confirmation / factual noun phrases must NOT match.
    assert _matches_imperative("The email was sent successfully.") == ()
    assert _matches_imperative("Regulatory clock templates") == ()
    assert _matches_imperative("Received 3 messages from 2 accounts.") == ()
    assert _matches_imperative("") == ()


def test_registry_file_exists():
    """The registry file MUST exist. A missing file is not "no violations" —
    it's a broken pin (``_load_registry`` would return the schema-only dict
    and every hit would fail-closed vacuously)."""
    assert _REGISTRY_PATH.is_file(), (
        f"Missing registry file: {_REGISTRY_PATH}. Create it with "
        '{"__schema": "v1"} as the starting content.'
    )


# ---------------------------------------------------------------------------
# BASELINE-EXEMPT RATCHET (DA panel-1 MF-1 fold + db-sme O5, 2026-07-16).
# The Drive-1 bootstrap auto-seeded the registry with "baseline-2026-07-16 —
# auto-seeded by VALK Drive-1 bootstrap. Classify..." exempts. That reason is
# BOILERPLATE — an unclassified holding-pattern, not a considered exempt.
# The DA panel raised the concern that shipping the pin with N boilerplate
# exempts creates a green-noise vacuous state where the pin structurally
# cannot catch a D2-shape defect (copy-referencing-nonexistent-mechanism)
# among the exempted entries.
#
# The RATCHET below caps the boilerplate-exempt count at the seed size (post
# the 22 template reclassifications). NEW boilerplate-exempts CANNOT accrue —
# a new imperative discovered in src/ must be classified with a SPECIFIC
# reason (real mechanism_ref, or a specific exempt reason naming why it's
# not-user-facing). Reclassifying an existing boilerplate entry with a
# specific reason SHRINKS the count; that is welcome. Growth fails-closed.
#
# The template reclassifications (22 rows, audit-batch 2026-07-16) are
# themselves marked with a specific reason so they no longer count as
# boilerplate; their spot-audit is deferred to Drive-4 retrofit e2e walks.
# ---------------------------------------------------------------------------

_BASELINE_BOILERPLATE_PREFIX = "baseline-2026-07-16"
_BASELINE_EXEMPT_CAP = 81  # punch 547: 82->81 (the _env_override docstring's "disable encryption" left with the env read); residual boilerplate at seed (src/*.py only,
# post template reclassifications). Shrink as entries are reclassified;
# a bump requires justification in the commit message.


def test_baseline_boilerplate_exempts_ratchet():
    """DA panel-1 MF-1 + db-sme O5 (2026-07-16): the boilerplate baseline-
    exempt count cannot grow. A new imperative flagged by the pin must be
    classified with a SPECIFIC reason (real ``mechanism_ref`` OR specific
    non-user-facing ``exempt``); a new copy of the "baseline-2026-07-16 —
    auto-seeded..." boilerplate is a green-noise hardening of the debt
    and fails-closed here.

    To SHRINK: reclassify an existing boilerplate entry with a specific
    reason (mechanism_ref OR specific exempt) AND bump the cap down. To
    grow: never — the pin has spoken. If the seed missed a legitimate
    baseline that surfaces later, add a NON-boilerplate reason like
    "internal log format" / "dev docstring" / "unreachable dead code" — the
    reason IS the audit trail."""
    registry = _load_registry()
    boilerplate_count = sum(
        1 for k, e in registry.items()
        if k != "__schema" and isinstance(e, dict)
        and e.get("exempt", "").startswith(_BASELINE_BOILERPLATE_PREFIX)
    )
    assert boilerplate_count <= _BASELINE_EXEMPT_CAP, (
        f"Boilerplate-exempt count {boilerplate_count} exceeds cap "
        f"{_BASELINE_EXEMPT_CAP}. New copy_contract_registry.json entries "
        "must carry a SPECIFIC exempt reason (not the 'baseline-2026-07-16 "
        "— auto-seeded...' boilerplate) OR be classified as mechanism_ref."
    )
    # Additionally: below the cap is GOOD (someone reclassified). Update
    # _BASELINE_EXEMPT_CAP downward in the same commit as the reclassification
    # to prevent silent debt regrowth (a future author reintroducing
    # boilerplate up to the old cap would slip through).
    if boilerplate_count < _BASELINE_EXEMPT_CAP:
        raise AssertionError(
            f"Boilerplate count {boilerplate_count} is BELOW cap "
            f"{_BASELINE_EXEMPT_CAP}. Great — reclassifications happened. "
            "Update _BASELINE_EXEMPT_CAP in this file to the new count "
            "(same commit) so the ratchet stays tight."
        )
