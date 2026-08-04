"""Tests for the M-1 + M-2 user-stated style knobs.

Covers ``format_style_knobs_for_prompt`` and ``build_style_prompt_prefix``
in isolation (no DB / no HTTP), plus the master / per-account / HIPAA
gate semantics. The Profile UI round-trip lives in
``tests/test_web/test_profile_writing.py``.
"""

from __future__ import annotations
from _db_tracking import track

import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.actions.style_profile import (
    StyleProfile,
    build_style_prompt_prefix,
    format_style_knobs_for_prompt,
)


def _defaults() -> dict:
    """Mirror of ``STYLE_KNOB_DEFAULTS`` — the "no preference" state."""
    return {
        "style_guide": "",
        "style_tone": "neutral",
        "style_length": "medium",
        "style_signature": "",
        "style_greeting": "first-name",
        "style_greeting_custom": "",
    }


# ---------------------------------------------------------------------------
# Empty / default returns empty string
# ---------------------------------------------------------------------------

class TestFormatStyleKnobsEmpty:
    def test_none_returns_empty(self):
        assert format_style_knobs_for_prompt(None) == ""

    def test_empty_dict_returns_empty(self):
        assert format_style_knobs_for_prompt({}) == ""

    def test_all_defaults_returns_empty(self):
        assert format_style_knobs_for_prompt(_defaults()) == ""


# ---------------------------------------------------------------------------
# Non-default values → block produced
# ---------------------------------------------------------------------------

class TestFormatStyleKnobsContent:
    def test_guide_non_empty_emits_user_notes(self):
        knobs = _defaults()
        knobs["style_guide"] = "I prefer concise replies and no emojis."
        out = format_style_knobs_for_prompt(knobs)
        assert "WRITING STYLE GUIDANCE:" in out
        assert "USER NOTES:" in out
        assert "I prefer concise replies" in out

    def test_tone_change_emits_block_with_example(self):
        knobs = _defaults()
        knobs["style_tone"] = "terse"
        out = format_style_knobs_for_prompt(knobs)
        assert "Tone: terse" in out
        # Tone example should be quoted and included.
        assert "Got it." in out

    def test_length_brief_emits_block(self):
        knobs = _defaults()
        knobs["style_length"] = "brief"
        out = format_style_knobs_for_prompt(knobs)
        assert "Length: brief" in out

    def test_greeting_none_emits_no_greeting_line(self):
        knobs = _defaults()
        knobs["style_greeting"] = "none"
        out = format_style_knobs_for_prompt(knobs)
        # We render a description that conveys "no greeting" without
        # using the phrase "no greeting" verbatim — assert on the
        # human-readable hint we ship.
        assert "no greeting line" in out.lower()

    def test_greeting_custom_uses_user_string(self):
        knobs = _defaults()
        knobs["style_greeting"] = "custom"
        knobs["style_greeting_custom"] = "Hey there,"
        out = format_style_knobs_for_prompt(knobs)
        assert "Hey there," in out

    def test_signature_emits_sign_with_line(self):
        knobs = _defaults()
        knobs["style_signature"] = "— Operator A"
        out = format_style_knobs_for_prompt(knobs)
        assert "Sign with:" in out
        assert "Operator A" in out


# ---------------------------------------------------------------------------
# Gate semantics: HIPAA, master toggle, per-account toggle
# ---------------------------------------------------------------------------

class TestFormatStyleKnobsGates:
    def _populated_knobs(self) -> dict:
        k = _defaults()
        k["style_tone"] = "casual"
        k["style_signature"] = "— Operator A"
        k["style_guide"] = "Keep it short."
        return k

    def test_hipaa_returns_empty_regardless_of_values(self):
        knobs = self._populated_knobs()
        out = format_style_knobs_for_prompt(knobs, hipaa=True)
        assert out == ""

    def test_master_off_returns_empty(self):
        knobs = self._populated_knobs()
        out = format_style_knobs_for_prompt(knobs, master_enabled=False)
        assert out == ""

    def test_account_off_returns_empty(self):
        knobs = self._populated_knobs()
        out = format_style_knobs_for_prompt(knobs, account_enabled=False)
        assert out == ""

    def test_all_gates_open_emits_block(self):
        knobs = self._populated_knobs()
        out = format_style_knobs_for_prompt(
            knobs, hipaa=False, master_enabled=True, account_enabled=True,
        )
        assert "WRITING STYLE GUIDANCE:" in out


# ---------------------------------------------------------------------------
# build_style_prompt_prefix — knob + profile stacking order
# ---------------------------------------------------------------------------

class TestBuildStylePromptPrefix:
    def test_knobs_appear_before_profile(self):
        knobs = _defaults()
        knobs["style_tone"] = "terse"
        knobs["style_guide"] = "Short replies only."

        # Manually-shaped profile so the assertion isn't dependent on
        # the LLM-distillation path.
        profile = StyleProfile(
            persona_summary="Direct, friendly.",
            greeting="Hi Person,",
            sample_count=5,
        )

        out = build_style_prompt_prefix(knobs, profile)
        knobs_at = out.find("WRITING STYLE GUIDANCE:")
        profile_at = out.find("[USER WRITING STYLE]")
        assert knobs_at != -1, out
        assert profile_at != -1, out
        # User-stated KNOBS first, system-inferred PROFILE second.
        assert knobs_at < profile_at

    def test_only_knobs_set_returns_just_knobs(self):
        knobs = _defaults()
        knobs["style_signature"] = "— Operator A"
        out = build_style_prompt_prefix(knobs, None)
        assert "WRITING STYLE GUIDANCE:" in out
        assert "[USER WRITING STYLE]" not in out

    def test_only_profile_set_returns_just_profile(self):
        profile = StyleProfile(
            persona_summary="Direct.", sample_count=3,
        )
        out = build_style_prompt_prefix(None, profile)
        assert "[USER WRITING STYLE]" in out
        assert "WRITING STYLE GUIDANCE:" not in out

    def test_neither_set_returns_empty(self):
        assert build_style_prompt_prefix(None, None) == ""
        assert build_style_prompt_prefix(_defaults(), StyleProfile()) == ""

    def test_hipaa_wipes_both_blocks(self):
        knobs = _defaults()
        knobs["style_tone"] = "casual"
        profile = StyleProfile(persona_summary="Direct.", sample_count=5)
        out = build_style_prompt_prefix(knobs, profile, hipaa=True)
        assert out == ""

    def test_master_off_wipes_both_blocks(self):
        knobs = _defaults()
        knobs["style_tone"] = "casual"
        profile = StyleProfile(persona_summary="Direct.", sample_count=5)
        out = build_style_prompt_prefix(knobs, profile, master_enabled=False)
        assert out == ""

    def test_dict_profile_is_coerced(self):
        # get_style_profile returns dict-shape; the helper must accept
        # both dict and StyleProfile uniformly.
        knobs = _defaults()
        knobs["style_tone"] = "terse"
        profile_dict = {
            "persona_summary": "Concise.",
            "sample_count": 7,
        }
        out = build_style_prompt_prefix(knobs, profile_dict)
        assert "WRITING STYLE GUIDANCE:" in out
        assert "[USER WRITING STYLE]" in out


# ---------------------------------------------------------------------------
# No-PII spot check — examples in the rendered block
# ---------------------------------------------------------------------------

class TestNoPiiInExamples:
    """The tone / greeting / length examples must not leak real names
    or domains. This isn't an exhaustive check; it's a guardrail
    against an accidental future edit that hard-codes 'bob' or
    similar into the example strings.
    """

    def test_greeting_examples_use_placeholders(self):
        for choice in ("first-name", "formal-name"):
            knobs = _defaults()
            knobs["style_greeting"] = choice
            out = format_style_knobs_for_prompt(knobs).lower()
            # No real-name leakage. Use a small forbidden list — these
            # are names that have appeared in the codebase historically
            # and would indicate a regression if they show up here.
            assert "bob" not in out
            assert "alice" not in out
            assert "@gmail.com" not in out
            assert "@example.com" not in out


# ---------------------------------------------------------------------------
# Migration v11 — schema extension applies cleanly
# ---------------------------------------------------------------------------

class TestMigrationV11:
    """The v11 migration adds five style-knob columns to ``users``.

    Run ``init_db`` against a fresh in-memory DB and confirm:
      * every documented column is present after the run
      * each column has the documented default
      * a re-run is a no-op (idempotent)
    """

    def test_columns_present_after_init(self):
        from email_triage.web.db import init_db
        conn = track(init_db(":memory:"))
        cols = {
            row[1] for row in conn.execute("PRAGMA table_info(users)")
        }
        for col in (
            "style_guide", "style_tone", "style_length",
            "style_signature", "style_greeting", "style_greeting_custom",
        ):
            assert col in cols, f"v11 migration did not add column {col!r}"
        conn.close()

    def test_documented_defaults(self):
        from email_triage.web.db import init_db, get_user_style_knobs
        conn = track(init_db(":memory:"))
        # Insert a user with no knob columns specified.
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("u@example.com", "U Person", "user", now),
        )
        user_id = cur.lastrowid
        conn.commit()
        knobs = get_user_style_knobs(conn, user_id)
        assert knobs["style_guide"] == ""
        assert knobs["style_tone"] == "neutral"
        assert knobs["style_length"] == "medium"
        assert knobs["style_signature"] == ""
        assert knobs["style_greeting"] == "first-name"
        assert knobs["style_greeting_custom"] == ""
        conn.close()

    def test_v11_is_idempotent_on_legacy_db(self):
        """Simulate the legacy-DB path: build a users table without the
        new columns, then run the v11 body directly against that
        connection. No errors and the columns appear.
        """
        from email_triage.web.migrations import MIGRATIONS
        v11 = next((m for m in MIGRATIONS if m.version == 11), None)
        assert v11 is not None, "v11 migration must be registered"

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        # Bare-minimum legacy-shape users table.
        conn.execute(
            "CREATE TABLE users ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " email TEXT NOT NULL UNIQUE,"
            " name TEXT NOT NULL,"
            " role TEXT NOT NULL DEFAULT 'user',"
            " created_at TEXT NOT NULL"
            ")"
        )
        conn.commit()

        # First run adds the columns.
        v11.body(conn)
        cols_after_first = {
            row[1] for row in conn.execute("PRAGMA table_info(users)")
        }
        assert "style_guide" in cols_after_first

        # Second run is a no-op (no exception, columns still there).
        v11.body(conn)
        cols_after_second = {
            row[1] for row in conn.execute("PRAGMA table_info(users)")
        }
        assert cols_after_first == cols_after_second
        conn.close()


# ---------------------------------------------------------------------------
# draft_reply integration — knobs + profile stack in the right order
# ---------------------------------------------------------------------------

class TestDraftReplyIntegration:
    """Verify the prompt-prefix order matches what draft_reply expects.

    When draft_reply's LLM-prompt build is wired up, it will call
    ``build_style_prompt_prefix(knobs, profile)``. The user-stated
    KNOBS block must come before the system-inferred PROFILE block in
    the rendered prompt — explicit user direction primes the LLM
    ahead of inferred context.
    """

    def test_full_stack_order_in_rendered_prompt(self):
        from email_triage.web.db import init_db, get_user_style_knobs
        from email_triage.actions.style_profile import (
            build_style_prompt_prefix, StyleProfile,
        )
        conn = track(init_db(":memory:"))
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("u@example.com", "U Person", "user", now),
        )
        user_id = cur.lastrowid
        conn.commit()

        # Customise knobs.
        from email_triage.web.db import set_user_style_knobs
        set_user_style_knobs(conn, user_id, {
            "style_guide": "Keep it short.",
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "— Operator A",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        })
        knobs = get_user_style_knobs(conn, user_id)

        profile = StyleProfile(
            persona_summary="Direct, friendly.",
            sample_count=10,
        )

        prefix = build_style_prompt_prefix(knobs, profile)
        # Order assertion — KNOBS first.
        knobs_at = prefix.find("WRITING STYLE GUIDANCE:")
        profile_at = prefix.find("[USER WRITING STYLE]")
        assert knobs_at != -1
        assert profile_at != -1
        assert knobs_at < profile_at

        # Both blocks carry their respective signal.
        assert "casual" in prefix
        assert "Operator A" in prefix
        assert "Direct, friendly" in prefix
        conn.close()
