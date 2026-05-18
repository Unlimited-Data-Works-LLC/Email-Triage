"""Tests for the HTML->text + link extraction helper."""

from email_triage.engine.html_text import (
    extract_links,
    html_to_text_with_links,
)


def test_plain_text_pass_through():
    assert html_to_text_with_links("") == ""


def test_anchor_inlines_url():
    html = '<p>Hello <a href="https://example.com/a">click here</a> today</p>'
    out = html_to_text_with_links(html)
    assert "click here" in out
    assert "https://example.com/a" in out


def test_anchor_link_list():
    html = """
    <ul>
      <li><a href="https://a.com/1">Headline A</a></li>
      <li><a href="https://b.com/2">Headline B</a></li>
    </ul>
    """
    links = extract_links(html)
    assert ("Headline A", "https://a.com/1") in links
    assert ("Headline B", "https://b.com/2") in links


def test_script_style_stripped():
    html = (
        "<html><head><style>body{color:red}</style>"
        "<script>alert('x')</script></head>"
        "<body><p>Real content</p></body></html>"
    )
    out = html_to_text_with_links(html)
    assert "color:red" not in out
    assert "alert" not in out
    assert "Real content" in out


def test_broken_html_does_not_raise():
    html = "<p>unclosed <a href='https://ok.com'>link"
    out = html_to_text_with_links(html)
    assert "ok.com" in out


def test_entities_decoded():
    html = "<p>AT&amp;T news &mdash; today</p>"
    out = html_to_text_with_links(html)
    assert "AT&T" in out
    assert "—" in out


def test_no_href_anchor_emits_text_only():
    html = '<p><a>text without href</a></p>'
    links = extract_links(html)
    out = html_to_text_with_links(html)
    assert links == []
    assert "text without href" in out


def test_empty_html_returns_empty():
    assert extract_links("") == []
    assert html_to_text_with_links("") == ""
