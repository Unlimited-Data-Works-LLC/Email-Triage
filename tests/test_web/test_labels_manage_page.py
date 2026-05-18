"""Tests for the /labels page copy + structure fixes (#159).

Covers:
  * The "Has label" filter doc claim is GONE — operator caught it
    surfacing a bullet that pointed at the wrong workflow.
  * The new "select one or more labels per rule" copy is present.
  * The "Rule-driven" copy doesn't have the hanging Rules link
    structure (the screenshot showed Rules orphaned on its own
    line; the rewrite keeps prose on one line + "Rules tab"
    inside the sentence).
  * The /labels page renders the My Settings tab strip (#158).
  * The /rules page renders the My Settings tab strip + the
    inner Rules cluster strip.
  * The Suggested-Category dropdown options on /rules are slug-
    only (the long-description blow-out is gone) but descriptions
    are still surfaced via the title= attribute.
  * The "Also adds labels" fieldset on /rules renders even with
    zero labels (#159.1 gate fix) and points users at the Labels
    tab.
"""

from __future__ import annotations

from email_triage.web.db import create_label


class TestLabelsManagePageCopy:
    def test_has_label_filter_bullet_removed(
        self, client, user_cookies,
    ):
        resp = client.get("/labels", cookies=user_cookies)
        assert resp.status_code == 200
        # OLD bullet — operator caught it; should not surface anymore.
        assert "\"Has label\" filter" not in resp.text
        assert "Has label" not in resp.text  # nothing references it now.

    def test_multiple_labels_per_rule_copy_present(
        self, client, user_cookies,
    ):
        """2026-05-12 third rewrite — the 'Multiple labels per rule'
        framing moved INSIDE the Rule-driven bullet (combined sentence)
        because operator caught the link-in-middle-of-bullet still
        wrapping awkwardly. The phrase 'Multiple labels per rule' is
        retained in body copy so existing copy can be located via
        operator search."""
        resp = client.get("/labels", cookies=user_cookies)
        assert resp.status_code == 200
        assert "Multiple labels per rule" in resp.text

    def test_rule_driven_copy_link_at_end(
        self, client, user_cookies,
    ):
        """2026-05-12 third rewrite — operator caught the same wrap
        breakage for the THIRD time. Even with link-at-end of
        sentence, Pico's <a> rendering pushed it onto its own line.
        Fix: dedicated bullet 'Where the rule editor lives — <link>'
        with the link as the entire trailing payload of a short
        sentence + period right after </a>. No prose AFTER the link.
        Even on a 320px viewport the break happens at the period."""
        resp = client.get("/labels", cookies=user_cookies)
        assert resp.status_code == 200
        # New shape: short bullet with link at the very end.
        assert "Where the rule editor lives" in resp.text
        assert 'href="/rules"' in resp.text
        # Old broken shapes should be gone — no prose after the link.
        assert "Rules editor</a>" not in resp.text
        # Old broken-wrap shape from earlier rewrite should be gone — link inline with
        # "tab," wording was the source of the mid-sentence wrap.
        assert "Rules</a> tab," not in resp.text

    def test_renders_my_settings_tab_strip(
        self, client, user_cookies,
    ):
        """#158 — /labels is now inside the My Settings cluster."""
        resp = client.get("/labels", cookies=user_cookies)
        assert resp.status_code == 200
        # The cluster header + the tab strip's Labels entry.
        assert "My Settings" in resp.text
        # Active-tab styling makes Labels bold (font-weight:600)
        # via the inline shared partial.
        assert ">Labels<" in resp.text


class TestRulesPageCopy:
    def test_renders_my_settings_tab_strip(
        self, client, user_cookies,
    ):
        """#158 — /rules is now inside the My Settings cluster too."""
        resp = client.get("/rules", cookies=user_cookies)
        assert resp.status_code == 200
        assert "My Settings" in resp.text
        # The settings-tabs partial has both Labels + Rules entries.
        # Confirm the Labels link points at /labels (sibling-tab).
        assert 'href="/labels"' in resp.text

    def test_suggested_category_options_slug_only(
        self, client, user_cookies,
    ):
        """#159.4 — dropdown options must be slug-only; descriptions
        ride along on title= so the native picker stays narrow."""
        resp = client.get("/rules", cookies=user_cookies)
        assert resp.status_code == 200
        # No "slug — description" pattern on options.
        # The em-dash separator between slug + description is the
        # tell. Confirm at least one <option ... title="..."> is
        # present (title is the new surface).
        assert 'title=' in resp.text
        # Em-dash inside option content was the prior shape;
        # confirm gone. (A stray em-dash elsewhere in the page is
        # fine — we just scope to within option tags.)
        import re
        bad = re.search(
            r'<option[^>]*>[^<]*&mdash;|<option[^>]*>[^<]*—',
            resp.text,
        )
        assert bad is None, (
            f"Found option-with-em-dash leak: {bad.group(0)!r}"
        )

    def test_also_adds_labels_fieldset_renders_with_zero_labels(
        self, client, user_cookies,
    ):
        """#159.1 — the fieldset must render even with no labels,
        with a hint pointing users at the Labels tab."""
        resp = client.get("/rules", cookies=user_cookies)
        assert resp.status_code == 200
        # Fieldset's legend.
        assert "Also adds labels" in resp.text
        # Empty-state hint copy.
        assert "No labels yet" in resp.text
        assert "Labels tab" in resp.text

    def test_also_adds_labels_fieldset_renders_with_labels(
        self, client, user_cookies, db,
    ):
        """Sanity — the catalog does render checkboxes when populated."""
        create_label(db, "urgent", "Urgent", "#cc0000")
        resp = client.get("/rules", cookies=user_cookies)
        assert resp.status_code == 200
        # Checkbox for the seeded label.
        assert 'value="urgent"' in resp.text
        # The "No labels yet" fallback should NOT render now.
        assert "No labels yet" not in resp.text


class TestNavTopLevelEntries:
    def test_top_nav_no_longer_carries_labels_link(
        self, client, user_cookies,
    ):
        """#158 — Labels is moved off the top-nav into My Settings."""
        resp = client.get("/dashboard", cookies=user_cookies)
        assert resp.status_code == 200
        # The top-nav <ul> uses class nav-items / nav-grouped or
        # nav-flat. Quick check: the nav-grouped block should NOT
        # contain a bare top-level Labels link. The page also
        # contains links to /labels inside the settings-tabs
        # partial on other pages, but /dashboard renders only
        # base.html nav. There must be no top-nav Labels link.
        import re
        # Grab the top-nav UL only.
        m = re.search(
            r'<ul class="nav-items nav-grouped">(.*?)</ul>',
            resp.text, re.DOTALL,
        )
        assert m, "nav-items nav-grouped block missing"
        top_nav = m.group(1)
        assert ">Labels<" not in top_nav
        assert ">Rules<" not in top_nav
        # Sanity — other clusters survive.
        assert ">Triage<" in top_nav
        assert ">My Settings<" in top_nav

    def test_top_nav_no_longer_carries_rules_link(
        self, client, user_cookies,
    ):
        """#158 — Rules is moved off the top-nav into My Settings."""
        # Same shape as the Labels test; covered above via top_nav.
        # Kept as a separate test name for grep + intent clarity.
        resp = client.get("/dashboard", cookies=user_cookies)
        assert resp.status_code == 200
        import re
        m = re.search(
            r'<ul class="nav-items nav-grouped">(.*?)</ul>',
            resp.text, re.DOTALL,
        )
        assert m
        assert ">Rules<" not in m.group(1)

    def test_labels_url_still_resolves(self, client, user_cookies):
        """#158 — moving Labels off the top-nav must not break the
        /labels URL. Deep links must still work."""
        resp = client.get("/labels", cookies=user_cookies)
        assert resp.status_code == 200

    def test_rules_url_still_resolves(self, client, user_cookies):
        """Same for /rules."""
        resp = client.get("/rules", cookies=user_cookies)
        assert resp.status_code == 200
