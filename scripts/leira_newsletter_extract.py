#!/usr/bin/env python3
"""leira_newsletter_extract.py — Consumer #8 of the llm-host offload stack (2026-07-02).

Newsletter article extraction: given a raw newsletter email (HTML or plain text),
llm-host emits an array of {title, one_line_summary, url, category} per article.
Feeds the digest surfacing so the user reads titles+summaries instead of the
whole newsletter.

HIPAA note: PHI-safe by design — newsletters are marketing/news, not clinical
mail. Callers still gate on `hipaa` account flag AT THE CALLSITE (this consumer
does not enforce; enforcement is the caller's job).

Modes:
  html     — full HTML body; strip tags AT extraction time (do NOT pre-scrub).
  text     — plain-text body (already parsed).

Usage:
  cat newsletter.html | python scripts/leira_newsletter_extract.py html -
  python scripts/leira_newsletter_extract.py text --input body.txt

Prints JSON to stdout.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import OllamaCallError, call_leira, context_bytes, get_consumer_config

_cfg = get_consumer_config("newsletter_extract")
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.35)))
MAX_ARTICLES = int(_cfg.get("max_articles", 10))

EXTRACT_SCHEMA = {
    "type": "object",
    "required": ["articles"],
    "properties": {
        "articles": {
            "type": "array",
            "description": f"Up to {MAX_ARTICLES} articles. Each is a real story from the newsletter, NOT a duplicate.",
            "items": {
                "type": "object",
                "required": ["title", "one_line_summary"],
                "properties": {
                    "title": {"type": "string"},
                    "one_line_summary": {
                        "type": "string",
                        "description": "One sentence about the article's content. NOT the newsletter's promo copy.",
                    },
                    "url": {
                        "type": "string",
                        "description": "Article's canonical URL if present in the source. Empty string if unknown.",
                    },
                    "category": {
                        "type": "string",
                        "description": "Short topic label (e.g., 'clinical trial', 'policy', 'research', 'industry').",
                    },
                },
            },
        },
        "newsletter_name": {
            "type": "string",
            "description": "The newsletter's publication name if identifiable (e.g., 'STAT News', 'NEJM Weekly').",
        },
    },
}


def _strip_html(html: str) -> str:
    """Cheap HTML → text. Not a security boundary — enrichment only. Preserves
    URLs so llm-host can extract them into `url` fields."""
    # Preserve <a href=...>text</a> as `text (href)` before tag strip.
    def _anchor_repl(m: re.Match) -> str:
        return f"{m.group(2)} ({m.group(1)})"
    html = re.sub(
        r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*?>(.*?)</a>',
        _anchor_repl, html, flags=re.IGNORECASE | re.DOTALL,
    )
    # Drop style/script blocks entirely.
    html = re.sub(r"<(style|script)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
    # Strip remaining tags.
    text = re.sub(r"<[^>]+>", " ", html)
    # Normalise whitespace.
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract(body: str, mode: str) -> dict:
    if mode == "html":
        body = _strip_html(body)
    trimmed = False
    if len(body) > MAX_INPUT_BYTES:
        body = body[:MAX_INPUT_BYTES]
        trimmed = True
    result = call_leira(
        prompt=(
            f"You are extracting individual articles from a newsletter email body. "
            f"Return up to {MAX_ARTICLES} DISTINCT articles. Each article MUST be a "
            "real story with its own title + a one-sentence summary of the CONTENT "
            "(not the newsletter's promo copy about it). If a URL appears next to an "
            "article (e.g., '(https://...)' after the title), put it in `url`; else empty.\n\n"
            "Do NOT invent articles. Do NOT list boilerplate items (unsubscribe, "
            "'about this newsletter', ad units, 'view in browser'). If the body has "
            "no discernible articles (e.g., a receipt, a transactional email), return "
            "articles=[].\n\n"
            f"Body{' (trimmed)' if trimmed else ''}:\n{body}"
        ),
        schema=EXTRACT_SCHEMA,
    )
    result["trimmed"] = trimmed
    result["mode"] = mode
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["html", "text"])
    ap.add_argument("input", nargs="?", default="-", help="- for stdin, else a file path")
    args = ap.parse_args(argv)
    if args.input == "-":
        body = sys.stdin.read()
    else:
        body = Path(args.input).read_text(encoding="utf-8", errors="replace")
    if not body.strip():
        json.dump({"articles": [], "reason": "empty input"},
                  sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return
    try:
        out = extract(body, args.mode)
    except OllamaCallError as e:
        json.dump({"articles": [], "leira_error": str(e)},
                  sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
