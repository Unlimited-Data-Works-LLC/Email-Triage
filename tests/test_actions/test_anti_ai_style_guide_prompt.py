"""Tests for the anti-AI style guide prompt-build path.

Covers ``format_anti_ai_style_guide_for_prompt`` and the threaded
``build_style_prompt_prefix`` contract (stacking, disable-global,
HIPAA gate + opt-in). Pure in-memory; the DB round-trip lives in
``tests/test_web/test_anti_ai_style_guide_*.py`` and the
end-to-end prompt-build through ``build_prompt_messages`` lives
alongside the M-1+M-2 stitch coverage.
"""

from __future__ import annotations

from email_triage.actions.style_profile import (
    build_style_prompt_prefix,
    format_anti_ai_style_guide_for_prompt,
)


# ---------------------------------------------------------------------------
# format_anti_ai_style_guide_for_prompt — pure renderer
# ---------------------------------------------------------------------------

class TestFormatEmpty:
    def test_both_none_returns_empty(self):
        assert format_anti_ai_style_guide_for_prompt(None, None) == ""

    def test_both_empty_returns_empty(self):
        assert format_anti_ai_style_guide_for_prompt("", "") == ""

    def test_both_whitespace_returns_empty(self):
        assert format_anti_ai_style_guide_for_prompt("   ", "\n\t") == ""

    def test_disable_global_with_empty_user_returns_empty(self):
        # Global has content but disable-global zeroes it out; user
        # is empty → no block to render.
        out = format_anti_ai_style_guide_for_prompt(
            "ban Certainly!", "", disable_global=True,
        )
        assert out == ""


class TestFormatContent:
    def test_only_global_renders(self):
        out = format_anti_ai_style_guide_for_prompt(
            "Never say 'Certainly!'", "",
        )
        assert "Never say 'Certainly!'" in out
        assert "Avoid these AI-mannerisms" in out
        assert "End avoid" in out

    def test_only_user_renders(self):
        out = format_anti_ai_style_guide_for_prompt(
            "", "No em-dashes for narrative pause",
        )
        assert "No em-dashes" in out
        assert "Avoid these AI-mannerisms" in out

    def test_both_stack_by_default(self):
        out = format_anti_ai_style_guide_for_prompt(
            "GLOBAL_SENTINEL", "USER_SENTINEL",
        )
        # Both bodies appear; sections are concatenated under one
        # fenced block (not two separate fences).
        assert "GLOBAL_SENTINEL" in out
        assert "USER_SENTINEL" in out
        assert out.count("Avoid these AI-mannerisms") == 1
        assert out.count("End avoid") == 1

    def test_disable_global_drops_global_keeps_user(self):
        out = format_anti_ai_style_guide_for_prompt(
            "GLOBAL_SENTINEL", "USER_SENTINEL",
            disable_global=True,
        )
        assert "GLOBAL_SENTINEL" not in out
        assert "USER_SENTINEL" in out


# ---------------------------------------------------------------------------
# build_style_prompt_prefix — full stitch contract
# ---------------------------------------------------------------------------

class TestPrefixThreading:
    def test_anti_ai_only_renders_alone(self):
        """Knobs + profile both empty/None — anti-AI block still renders."""
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            anti_ai_global="GLOBAL_SENTINEL",
            anti_ai_user="",
        )
        assert "GLOBAL_SENTINEL" in pre

    def test_all_three_layers_render_in_order(self):
        """Knobs first, profile second, anti-AI last."""
        from email_triage.actions.style_profile import StyleProfile
        knobs = {
            "style_guide": "KNOB_SENTINEL_guide",
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        }
        profile = StyleProfile(
            persona_summary="PROFILE_SENTINEL_persona",
            sample_count=5,
        )
        pre = build_style_prompt_prefix(
            knobs=knobs, profile=profile,
            anti_ai_global="ANTI_SENTINEL_global",
            anti_ai_user="ANTI_SENTINEL_user",
        )
        assert "KNOB_SENTINEL_guide" in pre
        assert "PROFILE_SENTINEL_persona" in pre
        assert "ANTI_SENTINEL_global" in pre
        assert "ANTI_SENTINEL_user" in pre
        # Order pinning: knobs < profile < anti-AI.
        ki = pre.index("KNOB_SENTINEL_guide")
        pi = pre.index("PROFILE_SENTINEL_persona")
        ai = pre.index("ANTI_SENTINEL_global")
        assert ki < pi < ai, (
            f"Expected knobs<profile<anti-AI; got positions "
            f"{ki},{pi},{ai}"
        )


class TestPrefixHipaaGate:
    def test_hipaa_without_optin_collapses_anti_ai(self):
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            hipaa=True, m1m2_hipaa_allow=False,
            anti_ai_global="GLOBAL", anti_ai_user="USER",
        )
        assert pre == ""

    def test_hipaa_with_optin_renders_anti_ai(self):
        """Operator-typed anti-AI text is first-party data under
        §164.502(a) — the per-account ``style_knobs_hipaa_allow``
        opt-in lifts it the same way it lifts M-1+M-2."""
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            hipaa=True, m1m2_hipaa_allow=True,
            anti_ai_global="GLOBAL_SENTINEL", anti_ai_user="USER_SENTINEL",
        )
        assert "GLOBAL_SENTINEL" in pre
        assert "USER_SENTINEL" in pre

    def test_master_off_suppresses_anti_ai(self):
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            master_enabled=False,
            anti_ai_global="GLOBAL", anti_ai_user="USER",
        )
        assert pre == ""

    def test_account_off_suppresses_anti_ai(self):
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            account_enabled=False,
            anti_ai_global="GLOBAL", anti_ai_user="USER",
        )
        assert pre == ""


class TestPrefixStackBehaviour:
    """Build matrix from the punch-list spec."""

    def test_both_empty_no_section_injected(self):
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            anti_ai_global="", anti_ai_user="",
        )
        assert "Avoid these AI-mannerisms" not in pre

    def test_only_global_user_not_disabled(self):
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            anti_ai_global="GG", anti_ai_user="",
            anti_ai_disable_global=False,
        )
        assert "GG" in pre

    def test_only_user(self):
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            anti_ai_global="", anti_ai_user="UU",
        )
        assert "UU" in pre

    def test_both_set_user_not_disabled(self):
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            anti_ai_global="GG", anti_ai_user="UU",
            anti_ai_disable_global=False,
        )
        assert "GG" in pre
        assert "UU" in pre

    def test_both_set_user_disabled_global(self):
        pre = build_style_prompt_prefix(
            knobs=None, profile=None,
            anti_ai_global="GG", anti_ai_user="UU",
            anti_ai_disable_global=True,
        )
        assert "GG" not in pre
        assert "UU" in pre
