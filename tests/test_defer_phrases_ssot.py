"""Tests for _defer_phrases — the SSOT phrase library shared by defer_gate.py
(PreToolUse Edit/Write surface), scripts/git-hooks/commit-msg (git-hook surface),
and _scope_da.py (DA reasoning-prompt surface).

Pins the invariants that let the three surfaces stay in agreement:
  * ``find_defer_phrases`` matches every canonical idiom.
  * ``new_defer_phrases`` correctly SET-DIFFs (grandfathers before, flags after).
  * Whitelist substring-drop works.
  * PHI sniffer trips on obvious PII patterns; safe context passes.
  * ``write_event`` never raises (fail-open contract).

Self-referential note: this file is exempt from defer_gate's prose scan (see
``_PROSE_EXEMPT_RE``) — the test cannot exercise phrase detection without
carrying the phrases as string literals.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "scripts" / "hooks"
sys.path.insert(0, str(HOOKS))

from _defer_phrases import (  # noqa: E402
    DEFER_RE,
    context_window,
    find_defer_phrases,
    new_defer_phrases,
    write_event,
)


# ---------------------------------------------------------------------------
# Canonical-idiom detection
# ---------------------------------------------------------------------------

def test_finds_craig_real_example_2026_07_15():
    real = (
        "Pre-existing DA-F3b (WebhookTarget no account_id binding — "
        "cross-account fanning) documented in §4.35 as follow-on drive, "
        "NOT worsened by this feature."
    )
    hits = find_defer_phrases(real)
    assert "follow-on drive" in hits
    assert "not worsened by this feature" in hits


def test_finds_todo_defer():
    assert "todo: defer" in find_defer_phrases("TODO: defer to next drive")


def test_finds_next_drive():
    assert "next drive" in find_defer_phrases("Will address in the next drive.")


def test_finds_waiting_on_op():
    assert "waiting on op" in find_defer_phrases("Waiting on op input.")
    assert "waiting on operator" in find_defer_phrases("Waiting on operator input.")


def test_finds_out_of_scope_family():
    hits = find_defer_phrases("This is out of scope for this drive.")
    assert any("out of scope" in h for h in hits)


def test_empty_input_returns_empty_list():
    assert find_defer_phrases("") == []
    assert find_defer_phrases(None) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# SET-DIFF grandfathering
# ---------------------------------------------------------------------------

def test_grandfathered_phrase_not_flagged():
    before = "already contains follow-on drive as legacy prose"
    after = before + "\n\nNew unrelated line."
    assert new_defer_phrases(before, after) == []


def test_newly_introduced_phrase_flagged():
    before = "clean prose\n"
    after = "clean prose\n\nFollow-on drive item to handle later.\n"
    new = new_defer_phrases(before, after)
    assert "follow-on drive" in new


def test_multiple_new_phrases_sorted():
    before = ""
    after = "TODO: defer this. Also, waiting on operator."
    new = new_defer_phrases(before, after)
    assert new == sorted(new), "new_defer_phrases must return sorted for stable diffs"
    assert "todo: defer" in new
    assert "waiting on operator" in new


# ---------------------------------------------------------------------------
# Whitelist substring-drop
# ---------------------------------------------------------------------------

def test_whitelist_drops_matched_context(tmp_path, monkeypatch):
    wl = tmp_path / "wl.jsonl"
    wl.write_text(json.dumps({"pattern": "next drive shaft"}) + "\n",
                  encoding="utf-8")
    import _defer_phrases as dp
    monkeypatch.setattr(dp, "_WHITELIST_PATH_CANDIDATES", [wl])
    dp._load_whitelist.cache_clear()
    try:
        before = ""
        after = "the next drive shaft needs replacement"
        assert new_defer_phrases(before, after) == []
    finally:
        dp._load_whitelist.cache_clear()


def test_whitelist_does_not_drop_unmatched_context(tmp_path, monkeypatch):
    wl = tmp_path / "wl.jsonl"
    wl.write_text(json.dumps({"pattern": "next drive shaft"}) + "\n",
                  encoding="utf-8")
    import _defer_phrases as dp
    monkeypatch.setattr(dp, "_WHITELIST_PATH_CANDIDATES", [wl])
    dp._load_whitelist.cache_clear()
    try:
        before = ""
        after = "will handle in the next drive"
        assert "next drive" in new_defer_phrases(before, after)
    finally:
        dp._load_whitelist.cache_clear()


# ---------------------------------------------------------------------------
# PHI sniffer
# ---------------------------------------------------------------------------

def test_phi_sniffer_email_redacts_context():
    text = "contact user@example.com about defer"
    win = context_window(text, "defer", radius=40)
    assert "PHI sniffer tripped" in win


def test_phi_sniffer_safe_context_passes():
    text = "plain prose with defer in it and nothing sensitive"
    win = context_window(text, "defer", radius=40)
    assert "PHI sniffer tripped" not in win
    assert "defer" in win.lower()


def test_phi_sniffer_ssn_shape_redacts():
    text = "note 123-45-6789 defer this"
    win = context_window(text, "defer", radius=40)
    assert "PHI sniffer tripped" in win


# hipaa-sme F2 (11f991be batch panel): §164.514 defense-in-depth coverage —
# these shapes were UNCOVERED pre-fix and are now floor-redacted.
def test_phi_sniffer_iso8601_dob_redacts():
    text = "born 1970-01-15 defer this"
    assert "PHI sniffer tripped" in context_window(text, "defer", radius=40)


def test_phi_sniffer_parenthesized_phone_redacts():
    text = "call (555) 555-1234 defer this"
    assert "PHI sniffer tripped" in context_window(text, "defer", radius=40)


def test_phi_sniffer_dotted_phone_redacts():
    text = "phone 555.555.1234 defer this"
    assert "PHI sniffer tripped" in context_window(text, "defer", radius=40)


def test_phi_sniffer_labeled_patient_redacts():
    text = "Patient: John Doe defer this"
    assert "PHI sniffer tripped" in context_window(text, "defer", radius=40)


def test_phi_sniffer_ipv4_redacts():
    text = "host 10.0.0.1 defer this"
    assert "PHI sniffer tripped" in context_window(text, "defer", radius=40)


# hipaa-sme F1: `phrase` field is now PHI-sniffed too — a phrase captured
# from a match that includes MRN / patient labels gets redacted at write.
def test_write_event_phrase_field_phi_sniffed(tmp_path, monkeypatch):
    import _defer_phrases as dp
    log = tmp_path / "events.jsonl"
    monkeypatch.setattr(dp, "_EVENT_LOG", log)
    # A phrase value that itself contains PHI (as could happen with the
    # ~140-char-capture pre-existing regex hitting patient prose)
    dp.write_event(
        "pre-existing patient MRN-12345 documented as follow-on",
        "outer text",
        tool="Edit", path="foo.md", sha="abc", surface="prose",
    )
    row = json.loads(log.read_text(encoding="utf-8").strip().splitlines()[0])
    assert "MRN-12345" not in row["phrase"], (
        "phrase field must be PHI-sniffed (hipaa-sme F1 fix)"
    )
    assert "PHI sniffer tripped" in row["phrase"]


# ---------------------------------------------------------------------------
# write_event fail-open contract
# ---------------------------------------------------------------------------

def test_write_event_never_raises_on_missing_log_dir(tmp_path, monkeypatch):
    import _defer_phrases as dp
    fake = tmp_path / "does" / "not" / "exist" / "events.jsonl"
    monkeypatch.setattr(dp, "_EVENT_LOG", fake)
    write_event("defer", "some text with defer in it",
                tool="Edit", path="foo.md", sha="abc", surface="prose")
    assert fake.exists() or True


def test_write_event_appends(tmp_path, monkeypatch):
    import _defer_phrases as dp
    log = tmp_path / "events.jsonl"
    monkeypatch.setattr(dp, "_EVENT_LOG", log)
    write_event("defer", "prose with defer",
                tool="Edit", path="a.md", sha="abc", surface="prose")
    write_event("next drive", "next drive plan",
                tool="Write", path="b.md", sha="def", surface="prose")
    lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    row0 = json.loads(lines[0])
    assert row0["phrase"] == "defer"
    assert row0["surface"] == "prose"


# ---------------------------------------------------------------------------
# Compiled-regex sanity
# ---------------------------------------------------------------------------

def test_defer_re_compiles_and_is_case_insensitive():
    assert DEFER_RE.search("FOLLOW-ON DRIVE")
    assert DEFER_RE.search("follow-on drive")
