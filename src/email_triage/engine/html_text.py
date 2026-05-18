"""HTML -> text + link extraction for message bodies.

Shared between all providers that fetch HTML newsletter bodies.
Two responsibilities:

1. Render HTML as plain text with anchor URLs preserved inline, so
   downstream LLM extractors see ``headline (https://...)`` instead
   of losing the href when HTML is stripped.
2. Return the full ``(anchor_text, href)`` list so the digest
   extractor has a ground-truth URL set and can't hallucinate.
"""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser


_BLOCK_TAGS = {
    "p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "hr", "table", "section", "article", "header", "footer",
    "blockquote", "pre",
}


class _TextWithLinksParser(HTMLParser):
    """Streaming HTML parser that emits inline text with ``(url)`` after
    anchor text and collects all ``(text, href)`` pairs seen."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._anchor_stack: list[tuple[str, list[str]]] = []
        self._skip_depth = 0
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        t = tag.lower()
        if t in ("script", "style"):
            self._skip_depth += 1
            return
        if t in _BLOCK_TAGS:
            self._chunks.append("\n")
        if t == "a":
            href = ""
            for k, v in attrs:
                if k.lower() == "href" and v:
                    href = v.strip()
                    break
            self._anchor_stack.append((href, []))

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in ("script", "style"):
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if t == "a" and self._anchor_stack:
            href, parts = self._anchor_stack.pop()
            anchor_text = "".join(parts).strip()
            anchor_text = re.sub(r"\s+", " ", anchor_text)
            if href:
                if anchor_text:
                    self.links.append((anchor_text, href))
                    self._emit(f"{anchor_text} ({href})")
                else:
                    self.links.append(("", href))
                    self._emit(f"({href})")
            else:
                self._emit(anchor_text)
        if t in _BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        if self._anchor_stack:
            self._anchor_stack[-1][1].append(data)
        else:
            self._chunks.append(data)

    def _emit(self, s: str) -> None:
        if self._anchor_stack:
            self._anchor_stack[-1][1].append(s)
        else:
            self._chunks.append(s)

    def _flush_unclosed_anchors(self) -> None:
        # Broken HTML can leave <a> tags unclosed. Flush any stragglers
        # so their text + href still show up in the output + link list.
        while self._anchor_stack:
            href, parts = self._anchor_stack.pop()
            anchor_text = "".join(parts).strip()
            anchor_text = re.sub(r"\s+", " ", anchor_text)
            if href:
                if anchor_text:
                    self.links.append((anchor_text, href))
                    target = (
                        self._anchor_stack[-1][1] if self._anchor_stack
                        else self._chunks
                    )
                    target.append(f"{anchor_text} ({href})")
                else:
                    self.links.append(("", href))
                    target = (
                        self._anchor_stack[-1][1] if self._anchor_stack
                        else self._chunks
                    )
                    target.append(f"({href})")
            else:
                target = (
                    self._anchor_stack[-1][1] if self._anchor_stack
                    else self._chunks
                )
                target.append(anchor_text)

    def get_text(self) -> str:
        self._flush_unclosed_anchors()
        raw = "".join(self._chunks)
        decoded = html.unescape(raw)
        lines = [ln.strip() for ln in decoded.splitlines()]
        lines = [ln for ln in lines if ln]
        return "\n".join(lines) + ("\n" if lines else "")


def html_to_text_with_links(html_str: str) -> str:
    """Render HTML as text, inlining anchor URLs as ``text (href)``.

    Robust against broken HTML: the stdlib parser never raises on
    malformed input; it just does its best.
    """
    if not html_str:
        return ""
    parser = _TextWithLinksParser()
    try:
        parser.feed(html_str)
        parser.close()
    except Exception:
        return _regex_fallback(html_str)
    return parser.get_text()


def extract_links(html_str: str) -> list[tuple[str, str]]:
    """Return ``[(anchor_text, href), ...]`` in document order."""
    if not html_str:
        return []
    parser = _TextWithLinksParser()
    try:
        parser.feed(html_str)
        parser.close()
        parser._flush_unclosed_anchors()
    except Exception:
        return []
    return parser.links


def _regex_fallback(html_str: str) -> str:
    """Last-ditch tag stripper — used when the HTMLParser raises."""
    with_breaks = re.sub(
        r"</?(?:p|div|br|li|tr|h[1-6]|ul|ol|hr)[^>]*>", "\n", html_str,
        flags=re.IGNORECASE,
    )
    no_tags = re.sub(r"<[^>]+>", "", with_breaks)
    decoded = html.unescape(no_tags)
    lines = [ln.strip() for ln in decoded.splitlines()]
    lines = [ln for ln in lines if ln]
    return "\n".join(lines) + ("\n" if lines else "")
