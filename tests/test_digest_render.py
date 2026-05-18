"""Tests for digest render dispatch.

Covers all three formats:
- table (custom-digest variant; header text reflects digest name)
- grouped_list — section per group, group counts in heading
- plain_list — flat, same row-block shape as grouped_list

Plus dispatch behavior:
- Unknown render_as falls through to grouped_list (forward-compat)
- HIPAA mode collapses ``why`` to fixed phrases + redacts body
  preview; subject + sender stay verbatim
- ``include_body_preview=False`` omits the preview block
"""

from __future__ import annotations

import pytest


from email_triage.actions.digest_configs import (  # noqa: E402
    DigestColumn, DigestConfig, DigestFormat,
)
from email_triage.actions.digest_render import (  # noqa: E402
    render_digest,
    render_grouped_list,
    render_plain_list,
    render_table_generic,
)


def _row(
    *,
    category="newsletter",
    sender="Boss <boss@example.com>",
    subject="Q4 numbers",
    body_text="Lorem ipsum dolor sit amet — quarterly figures inside.",
    reason="Looks like a routine internal update",
    source="llm",
    date="2026-05-04T08:30:00+00:00",
    headers=None,
):
    return {
        "category": category,
        "sender": sender,
        "subject": subject,
        "body_text": body_text,
        "reason": reason,
        "source": source,
        "date": date,
        "headers": headers or {},
    }


def _all_columns():
    """Test helper: full column set so tests that check for
    category / reason / etc. content find what they assert.
    Production-default for new custom digests is the narrower
    [datetime, sender, headline, link] set."""
    return [
        DigestColumn(key="datetime", label="When"),
        DigestColumn(key="sender", label="Sender"),
        DigestColumn(key="category", label="Category"),
        DigestColumn(key="subject", label="Subject"),
        DigestColumn(key="reason", label="Why"),
    ]


def _cfg(**format_kw):
    fmt = DigestFormat(
        render_as=format_kw.get("render_as", "grouped_list"),
        group_by=format_kw.get("group_by", "category"),
        include_body_preview=format_kw.get("include_body_preview", True),
        max_rows=format_kw.get("max_rows", 50),
    )
    # Tests that exercise the full column palette (category /
    # reason / subject content) pass ``columns=_all_columns()``;
    # other tests rely on the production default
    # ``[datetime, sender, headline, link]``.
    if "columns" in format_kw:
        fmt.columns = format_kw["columns"]
    return DigestConfig(
        kind="custom",
        name=format_kw.get("name", "AI Newsletters"),
        format=fmt,
    )


# ---------------------------------------------------------------------------
# table_generic
# ---------------------------------------------------------------------------


def test_table_generic_uses_digest_name_in_heading():
    """Full-palette column set so the row assertions match
    columns that get rendered."""
    cfg = _cfg(
        render_as="table", name="AI Newsletters",
        columns=_all_columns(),
    )
    out = render_table_generic(
        cfg=cfg, rows=[_row()],
        account_name="user@example.local",
        account_email="Alex@example.com",
        hipaa=False,
    )
    assert "<h2>AI Newsletters — user@example.local</h2>" in out
    assert "<table" in out
    # Row content present + escaped.
    assert "Q4 numbers" in out
    assert "newsletter" in out
    assert "Looks like" in out  # standard-mode why


def test_table_generic_default_columns_render_link_column():
    """Production-default columns render Link as an <a>."""
    cfg = _cfg(render_as="table", name="Newsletters")
    row = _row()
    row["links"] = ["https://example.com/article-123"]
    out = render_table_generic(
        cfg=cfg, rows=[row],
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    assert '<th>When</th>' in out
    assert '<th>Sender</th>' in out
    assert '<th>Headline</th>' in out
    assert '<th>Link</th>' in out
    assert 'href="https://example.com/article-123"' in out
    # Default column set excludes category / reason — verify.
    assert '<th>Category</th>' not in out
    assert '<th>Why</th>' not in out


def test_table_generic_sort_by_priority_columns():
    """sort_priority on a column drives row order; secondary
    priority breaks ties."""
    rows = [
        _row(sender="ccc", subject="A", date="2026-05-04T10:00:00+00:00"),
        _row(sender="aaa", subject="B", date="2026-05-04T10:00:00+00:00"),
        _row(sender="bbb", subject="C", date="2026-05-05T10:00:00+00:00"),
    ]
    columns = [
        DigestColumn(key="datetime", label="When",
                     sort_priority=1, sort_direction="desc"),
        DigestColumn(key="sender", label="Sender",
                     sort_priority=2, sort_direction="asc"),
        DigestColumn(key="subject", label="Subject"),
    ]
    cfg = _cfg(render_as="table", columns=columns)
    out = render_table_generic(
        cfg=cfg, rows=rows,
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    # Newest date first: subject C (2026-05-05). Ties on the
    # 2026-05-04 day broken by sender ascending: aaa (B), then ccc (A).
    pos_c = out.index(">C<")
    pos_b = out.index(">B<")
    pos_a = out.index(">A<")
    assert pos_c < pos_b < pos_a


def test_table_generic_hipaa_redacts_why():
    cfg = _cfg(render_as="table", columns=_all_columns())
    out = render_table_generic(
        cfg=cfg,
        rows=[_row(reason="should not appear", source="llm")],
        account_name="x", account_email="y@z",
        hipaa=True,
    )
    assert "Classified by content analysis" in out
    assert "should not appear" not in out
    assert "HIPAA mode" in out  # banner present


# ---------------------------------------------------------------------------
# grouped_list
# ---------------------------------------------------------------------------


def test_grouped_list_emits_section_per_category():
    cfg = _cfg(render_as="grouped_list", group_by="category")
    rows = [
        _row(category="newsletter", subject="A"),
        _row(category="ai-news", subject="B"),
        _row(category="newsletter", subject="C"),
    ]
    out = render_grouped_list(
        cfg=cfg, rows=rows,
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    # Two sections.
    assert out.count("<section") == 2
    # Counts surface in section headings.
    assert "newsletter <small" in out
    assert "(2)" in out  # newsletter has 2 entries
    assert "(1)" in out  # ai-news has 1


def test_grouped_list_group_by_day():
    cfg = _cfg(render_as="grouped_list", group_by="day")
    rows = [
        _row(date="2026-05-04T10:00:00+00:00"),
        _row(date="2026-05-04T18:00:00+00:00"),
        _row(date="2026-05-05T08:00:00+00:00"),
    ]
    out = render_grouped_list(
        cfg=cfg, rows=rows,
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    assert "2026-05-04" in out
    assert "2026-05-05" in out


def test_grouped_list_no_grouping_falls_through_to_plain():
    """group_by=none → render via plain_list (flat output)."""
    cfg = _cfg(render_as="grouped_list", group_by="none")
    out = render_grouped_list(
        cfg=cfg, rows=[_row()],
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    assert "<section" not in out  # grouped_list shouldn't render sections


def test_grouped_list_group_by_sender():
    """One section per from-address; multi-message senders bucket
    together. The sender header is the raw `sender` field on the
    row (no display-name extraction so format-drift doesn't split
    a single sender across two sections)."""
    cfg = _cfg(render_as="grouped_list", group_by="sender")
    rows = [
        _row(sender="alice@x.com", subject="A1"),
        _row(sender="bob@y.com", subject="B1"),
        _row(sender="alice@x.com", subject="A2"),
    ]
    out = render_grouped_list(
        cfg=cfg, rows=rows,
        account_name="acct", account_email="me@here",
        hipaa=False,
    )
    # Both senders surface as section headings.
    assert "alice@x.com" in out
    assert "bob@y.com" in out
    # Two messages from alice + one from bob → 2 sections, 3 rows.
    assert out.count("alice@x.com") >= 1
    assert "A1" in out and "A2" in out and "B1" in out


def test_grouped_list_preview_can_be_disabled():
    cfg = _cfg(
        render_as="grouped_list", group_by="category",
        include_body_preview=False,
    )
    out = render_grouped_list(
        cfg=cfg, rows=[_row(body_text="LEAK PREVIEW CONTENT")],
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    assert "LEAK PREVIEW CONTENT" not in out


def test_grouped_list_drops_why_and_category_from_row_block():
    """Per-row meta line ``category · why`` was dropped 2026-05-07.

    Operator feedback: the ``why`` (LLM rationale) is noise the
    recipient doesn't need; the ``category`` is redundant with
    the digest's title (operator-set name carries what the
    digest covers).
    """
    cfg = _cfg(
        render_as="grouped_list", group_by="category",
        include_body_preview=False,
    )
    out = render_grouped_list(
        cfg=cfg,
        rows=[_row(
            category="some-category",
            reason="some rationale that should not appear",
        )],
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    # Subject + sender still in output.
    assert "Q4 numbers" in out
    assert "boss@example.com" in out
    # Category appears in the section heading (group_by=category)
    # but NOT as a per-row meta line under each row.
    # Reason / why is gone entirely.
    assert "some rationale that should not appear" not in out


def test_grouped_list_cheap_preview_pulls_lede_and_h1_h2():
    """include_body_preview=True with the new cheap preview:
    first non-empty line of body_text + up to 3 H1/H2 from
    body_html. No LLM."""
    from email_triage.actions.digest_render import render_grouped_list

    cfg = _cfg(
        render_as="grouped_list", group_by="category",
        include_body_preview=True,
    )
    row = _row(
        body_text=(
            "Top stories this week — here's what's hot in AI.\n\n"
            "More stuff below."
        ),
    )
    row["body_html"] = (
        "<html><body><h1>OpenAI announces o5</h1>"
        "<h2>Anthropic ships Sonnet 5</h2>"
        "<h2>Mistral raises 2B</h2>"
        "<p>filler...</p>"
        "<h2>SHOULD NOT APPEAR — fourth heading</h2></body></html>"
    )
    out = render_grouped_list(
        cfg=cfg, rows=[row],
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    # Lede surfaces.
    assert "Top stories this week" in out
    # First three H1/H2 surface; fourth dropped.
    assert "OpenAI announces o5" in out
    assert "Anthropic ships Sonnet 5" in out
    assert "Mistral raises 2B" in out
    assert "fourth heading" not in out


def test_grouped_list_section_heading_visually_distinct():
    """Section heading uses a left-border accent + background tint
    + bigger font so the operator can tell sections from rows at
    a glance."""
    from email_triage.actions.digest_render import render_grouped_list
    cfg = _cfg(render_as="grouped_list", group_by="category")
    out = render_grouped_list(
        cfg=cfg, rows=[_row(category="newsletter")],
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    # Three reinforcing visual signals that distinguish the
    # heading from a normal row.
    assert "border-left:4px solid" in out
    assert "background:#f1f5f9" in out
    assert "font-size:1.3em" in out


def test_grouped_list_hipaa_redacts_preview_no_why_line():
    """HIPAA contract under the 2026-05-07 render shape:

      - body preview redacts to '[redacted]' (was already true)
      - 'why' / 'reason' string never appears (was being rendered
        as a HIPAA-fixed phrase under category · why; both pieces
        of that meta line are now dropped — operator feedback,
        the rationale text + category are noise per row)
      - subject + sender pass through verbatim (already-in-mailbox
        carve-out)
    """
    cfg = _cfg(
        render_as="grouped_list", group_by="category",
        include_body_preview=True,
    )
    out = render_grouped_list(
        cfg=cfg,
        rows=[_row(
            body_text="PHI BODY MUST NOT LEAK",
            reason="LLM rationale should not leak",
            source="llm",
        )],
        account_name="x", account_email="y@z",
        hipaa=True,
    )
    assert "PHI BODY MUST NOT LEAK" not in out
    assert "LLM rationale should not leak" not in out
    # No "Classified by …" meta line — the entire category · why
    # row was dropped from the per-message block.
    assert "Classified by content analysis" not in out
    assert "[redacted]" in out  # preview redacted
    # Subject + sender stay verbatim per the contract.
    assert "Q4 numbers" in out
    assert "boss@example.com" in out


# ---------------------------------------------------------------------------
# plain_list
# ---------------------------------------------------------------------------


def test_plain_list_renders_all_rows_flat():
    cfg = _cfg(render_as="plain_list")
    rows = [_row(subject="A"), _row(subject="B"), _row(subject="C")]
    out = render_plain_list(
        cfg=cfg, rows=rows,
        account_name="x", account_email="y@z",
        hipaa=False,
    )
    assert "<section" not in out
    assert out.count("border-bottom:1px solid #eee") == 3


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_render_digest_dispatches_by_render_as():
    cfg_grouped = _cfg(render_as="grouped_list")
    cfg_plain = _cfg(render_as="plain_list")
    cfg_table = _cfg(render_as="table")
    rows = [_row()]
    out_grouped = render_digest(
        cfg=cfg_grouped, rows=rows,
        account_name="x", account_email="y@z", hipaa=False,
    )
    out_plain = render_digest(
        cfg=cfg_plain, rows=rows,
        account_name="x", account_email="y@z", hipaa=False,
    )
    out_table = render_digest(
        cfg=cfg_table, rows=rows,
        account_name="x", account_email="y@z", hipaa=False,
    )
    assert "<section" in out_grouped
    assert "<section" not in out_plain
    assert "<table" in out_table


def test_render_digest_unknown_renders_falls_through_to_grouped():
    cfg = _cfg(render_as="some-future-format")
    out = render_digest(
        cfg=cfg, rows=[_row()],
        account_name="x", account_email="y@z", hipaa=False,
    )
    assert "<section" in out  # grouped_list output shape
