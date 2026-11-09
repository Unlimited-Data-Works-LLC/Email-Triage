"""Tests for /help/tasks.

The help page is anonymous-accessible (non-PHI). These tests pin
the contract end-users + medical-researchers depend on:

* GET returns 200, NOT a 303 redirect to /login.
* All six starter tasks render in the HTML body.
* The AUDIENCE comment header is present in the template source.
* m.help() tooltips render (data-tooltip span emitted by the macro).
* No admin-only path strings leak into the rendered HTML.
"""

from __future__ import annotations

from pathlib import Path


# ---------------------------------------------------------------------------
# Anonymous access
# ---------------------------------------------------------------------------

class TestAnonymousAccess:
    def test_help_tasks_returns_200(self, client):
        """GET /help/tasks succeeds without a session cookie."""
        resp = client.get("/help/tasks")
        assert resp.status_code == 200

    def test_help_tasks_is_not_303(self, client):
        """No redirect to /login — help is non-PHI public-facing copy."""
        resp = client.get("/help/tasks", follow_redirects=False)
        assert resp.status_code == 200
        assert resp.headers.get("location") is None

    def test_help_tasks_with_user_cookies_also_200(self, client, user_cookies):
        """Authenticated callers also see the page (same content)."""
        resp = client.get("/help/tasks", cookies=user_cookies)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Content contract — all six starter tasks land
# ---------------------------------------------------------------------------

class TestSixTasks:
    def test_all_six_task_titles_render(self, client):
        """The exact title strings from the backlog appear once each.

        We assert on the title strings (not anchor ids) because copy
        changes are easier to audit when the test reads like a TOC.
        """
        resp = client.get("/help/tasks")
        body = resp.text

        # Task 1 — route by sender
        assert "Route all mail from one sender to a category" in body
        # Task 2 — pause on vacation
        assert "Pause an account while you're on vacation" in body
        # Task 3 — add a delegate
        assert "Let someone else triage your mail (add a delegate)" in body
        # Task 4 — daily digest
        assert "Set up a daily digest" in body
        # Task 5 — disable AI drafts
        assert "Turn off AI draft replies for one account" in body
        # Task 6 — see captured training data
        assert "See what training data has been captured" in body

    def test_task_anchor_ids_present(self, client):
        """Each task has an anchor id so the table-of-contents links work."""
        body = client.get("/help/tasks").text
        for slug in (
            "route-by-sender",
            "pause-account",
            "add-delegate",
            "daily-digest",
            "disable-ai-drafts",
            "see-training-data",
        ):
            assert f'id="task-{slug}"' in body, f"missing anchor for {slug}"


# ---------------------------------------------------------------------------
# Audience-comment-header rule (per feedback_audience_per_page.md)
# ---------------------------------------------------------------------------

class TestAudienceHeader:
    def _template_path(self, name: str) -> Path:
        # Resolve via the package the same way Jinja does — walk up
        # from this test file to the repo root, then into the
        # template tree. Avoids importing the app.
        here = Path(__file__).resolve()
        # tests/test_web/test_help_tasks.py -> repo root is parents[2]
        root = here.parents[2]
        return root / "src" / "email_triage" / "web" / "templates" / name

    def test_tasks_template_has_audience_header(self):
        """tasks.html declares its AUDIENCE / TECH-SKILL / COPY RULES."""
        src = self._template_path("help/tasks.html").read_text(encoding="utf-8")
        assert "─── AUDIENCE ───" in src
        assert "AUDIENCE:" in src
        assert "TECH-SKILL:" in src
        assert "COPY RULES:" in src

    def test_task_partial_has_audience_header(self):
        """_task.html partial declares (or inherits) its audience."""
        src = self._template_path("help/_task.html").read_text(encoding="utf-8")
        assert "─── AUDIENCE ───" in src
        assert "AUDIENCE:" in src


# ---------------------------------------------------------------------------
# m.help() tooltip macro is invoked
# ---------------------------------------------------------------------------

class TestTooltipsRender:
    def test_data_tooltip_attribute_present(self, client):
        """The macro emits <span data-tooltip="..."> elements; without
        that the singleton tooltip engine has nothing to attach to."""
        body = client.get("/help/tasks").text
        assert "data-tooltip=" in body

    def test_at_least_one_tooltip_per_task(self, client):
        """Loose lower bound — six tasks, at least six tooltips. The
        actual count is higher (multiple m.help() calls per task) but
        this test pins the floor without locking in copy churn."""
        body = client.get("/help/tasks").text
        assert body.count("data-tooltip=") >= 6


# ---------------------------------------------------------------------------
# No-admin-path rule (per feedback_no_admin_path_in_user_copy.md)
# ---------------------------------------------------------------------------

def _content_block(body: str) -> str:
    """Slice the page's <main>...</main> block — the user-visible
    content area only. Skips base.html nav, JS shortcut maps, and
    stylesheet links so we test our page's copy, not the framework's
    plumbing. Lowercased for case-insensitive checks.
    """
    lo = body.lower()
    start = lo.find("<main")
    end = lo.find("</main>", start) if start != -1 else -1
    if start == -1 or end == -1:
        return lo
    return lo[start:end]


class TestNoAdminPaths:
    def test_no_admin_path_strings_in_content(self, client):
        """End-user copy must not reference admin-only routes or
        forbidden 'ask your administrator' phrasing.

        Scoped to <main>...</main> — the framework's keyboard-shortcut
        JS map in base.html references /admin/stats but that's wiring,
        not user-visible copy. The rule lives in
        ``feedback_no_admin_path_in_user_copy.md`` and is about prose
        the user reads.
        """
        content = _content_block(client.get("/help/tasks").text)
        assert "/admin/" not in content
        assert "/config" not in content
        assert "ask your administrator" not in content
        assert "ask an administrator" not in content

    def test_no_protocol_jargon_in_content(self, client):
        """Jargon-replacement table from the audience-comment header.

        Asserts the words we banned for end-user copy don't appear in
        the page's content area. Scoped to <main> for the same reason
        as the admin-path test.
        """
        content = _content_block(client.get("/help/tasks").text)
        # "language model" / "LLM" — replaced by "AI"
        assert "language model" not in content
        # "IMAP IDLE" — replaced by "watch folder"
        assert "imap idle" not in content
        # The strict feedback_no_anthropic rule — never name the API
        assert "anthropic" not in content


# ---------------------------------------------------------------------------
# Nav link integration
# ---------------------------------------------------------------------------

class TestNavLink:
    def test_help_link_in_nav(self, client, user_cookies):
        """Authenticated pages expose the Help link in the top nav."""
        resp = client.get("/dashboard", cookies=user_cookies)
        assert resp.status_code == 200
        assert 'href="/help/tasks"' in resp.text


# ---------------------------------------------------------------------------
# No repeated consecutive words in user-visible copy (punch P4b)
# ---------------------------------------------------------------------------

# The repeated-word rule of scripts/publish-proofread.py, inlined because this
# test ships to the public tree and the proofreader does not
# (publish_shipset.make_ships: test -> True, proofreader -> False). Where the
# proofreader exists (the dev tree), _proofread_rules() asserts these still
# equal its DUP / OK_DUP, so the copy cannot drift silently.
_DUP_PATTERN = r"\b([A-Za-z]{2,})\s+\1\b"
_OK_DUP = {"that", "had", "has", "is", "do", "so", "no", "ha", "very", "really"}


_PROOFREAD_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "publish-proofread.py"  # publish: absent-tolerant: the proofreader does not ship; absent, the test enforces its inlined copy of the DUP/OK_DUP rule, so the read can only add a drift check, never remove the typo check; pinned by test_the_proofread_rule_degrades_to_the_inlined_copy_without_the_script


def _proofread_rules(script: Path | None = None):
    import ast
    import re

    from _pin_harness import parse_module

    script = _PROOFREAD_SCRIPT if script is None else script
    if script.is_file():
        tree = parse_module(script)
        assert tree is not None, "scripts/publish-proofread.py does not parse"
        found = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name == "DUP":
                    found["DUP"] = ast.literal_eval(node.value.args[0])
                elif name == "OK_DUP":
                    found["OK_DUP"] = ast.literal_eval(node.value)
        assert found == {"DUP": _DUP_PATTERN, "OK_DUP": _OK_DUP}, (
            "scripts/publish-proofread.py's DUP/OK_DUP changed; update the "
            "inlined copy in this test to match: %r" % found)
    return re.compile(_DUP_PATTERN, re.I), _OK_DUP


def test_the_proofread_rule_degrades_to_the_inlined_copy_without_the_script(tmp_path):
    """On the public mirror scripts/publish-proofread.py is absent. The rule must
    then be the inlined copy, and it must still catch the stutter this file pins."""
    pattern, ok = _proofread_rules(tmp_path / "absent-publish-proofread.py")
    assert pattern.pattern == _DUP_PATTERN and ok == _OK_DUP
    assert pattern.search("a single email Email Triage sends")


class TestNoRepeatedWords:
    def test_no_repeated_consecutive_words_in_content(self, client):
        """User-visible copy (including m.help() tooltip text, which renders
        into data-tooltip attributes) has no "email Email"-class doubled
        word. Same rule as scripts/publish-proofread.py, applied to the
        rendered <main> block so a typo fails here, before publish."""
        import html

        body = client.get("/help/tasks").text
        lo = body.lower()
        start = lo.find("<main")
        end = lo.find("</main>", start)
        assert start != -1 and end != -1, "no <main> block in /help/tasks"
        content = html.unescape(body[start:end])

        dup, ok_dup = _proofread_rules()
        hits = []
        for m in dup.finditer(content):
            if m.group(1).lower() in ok_dup:
                continue
            pair = m.group(0).split()
            # the proofreader's CLI-placeholder / ALL-CAPS-emphasis skip
            if len(pair) == 2 and pair[1].isupper() and not pair[0].isupper():
                continue
            hits.append(content[max(0, m.start() - 40):m.end() + 40])
        assert not hits, "repeated word(s) in /help/tasks copy: %r" % hits
