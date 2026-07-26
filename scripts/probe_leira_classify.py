#!/usr/bin/env python3
"""Feed a raw .eml file through the production classify path and dump the
RAW LLM response BEFORE the parser sees it.

WHY
    When the retry-queue kills a message with
    ``No JSON object found in LLM response (len=N)`` we need to see what the
    Ollama backend (llm-host / qwen3.x) actually returned so we can decide
    whether it's a model bug (all-<think> reply, refusal, empty JSON) or a
    parser bug.

WHERE
    Run inside the ``email-triage`` container (has the app config + sqlcipher
    + httpx + the right Ollama base_url). Copy the .eml to a bind-mounted
    directory the container can read (e.g. /app/data/tmp) and:

        sudo podman cp fedex.eml email-triage:/tmp/msg.eml
        sudo podman exec email-triage python3 /app/scripts/probe_leira_classify.py \
            /tmp/msg.eml

    Optional flags:
        --topic-match   also fire the topic-match path (uses different
                        prompt + payload, larger num_predict)
        --raw-eml       treat argv[1] as raw MIME on stdin instead of a path
        --model NAME    override the resolved model (else uses whatever /api/ps
                        reports resident)
        --url URL       override base_url (else config's ollama base_url)

WHAT IT PRINTS
    1. Extracted (sender, subject, body_text[:200]) so you can confirm the
       parse.
    2. The exact system + user prompts sent (truncated).
    3. Ollama URL + model.
    4. The RAW response text (never touched by the JSON parser).
    5. Whether _parse_llm_json_tiered accepts it — and the tier it used
       (strict/lenient/salvage) — or the ValueError it raised.
    6. If topic-match was requested, same for that path.

NOT
    - Not touching the DB.
    - Not touching the retry queue (row 276 stays dead).
    - Not sending anywhere except the configured Ollama endpoint (llm-host).
"""
from __future__ import annotations

import argparse
import asyncio
import email
import json
import sys
from datetime import datetime, timezone
from email import policy
from email.message import Message as StdlibMessage
from pathlib import Path
from typing import Any


sys.path.insert(0, "/app/src")


def _extract_body_text(msg: StdlibMessage) -> str:
    """Prefer text/plain; fall back to a naive HTML → text strip."""
    plain_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        try:
            payload = part.get_content()
        except Exception:
            try:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or "utf-8"
                    payload = payload.decode(charset, errors="replace")
            except Exception:
                continue
        if not isinstance(payload, str):
            continue
        if ctype == "text/plain":
            plain_parts.append(payload)
        elif ctype == "text/html":
            html_parts.append(payload)
    if plain_parts:
        return "\n".join(plain_parts)
    if html_parts:
        try:
            import re
            text = "\n".join(html_parts)
            text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"\s+", " ", text)
            return text.strip()
        except Exception:
            return "\n".join(html_parts)
    return ""


def _load_eml(source: Path | None, raw_bytes: bytes | None) -> StdlibMessage:
    if raw_bytes is not None:
        return email.message_from_bytes(raw_bytes, policy=policy.default)
    assert source is not None
    with source.open("rb") as f:
        return email.message_from_bytes(f.read(), policy=policy.default)


def _build_app_message(std: StdlibMessage):
    from email_triage.engine.models import EmailMessage

    sender = std.get("From", "").strip() or "unknown@example.com"
    subject = std.get("Subject", "").strip() or "(no subject)"
    to = std.get("To", "").strip() or "unknown@example.com"
    date_hdr = std.get("Date", "")
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_hdr) if date_hdr else datetime.now(timezone.utc)
    except Exception:
        dt = datetime.now(timezone.utc)
    body_text = ""
    body_html = ""
    for part in std.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        try:
            payload = part.get_content()
        except Exception:
            continue
        if not isinstance(payload, str):
            continue
        if ctype == "text/plain" and not body_text:
            body_text = payload
        elif ctype == "text/html" and not body_html:
            body_html = payload
    # Prod path (providers/_normalize.build_email_message): if body_text is
    # empty and body_html is present, fall back to the APP's own
    # html_to_text_with_links so we exactly reproduce what classify sees.
    if not body_text and body_html:
        try:
            from email_triage.engine.html_text import html_to_text_with_links
            body_text = html_to_text_with_links(body_html)
        except Exception:
            body_text = _extract_body_text(std)  # last-resort naive strip
    return EmailMessage(
        message_id="probe:local",
        provider="probe",
        sender=sender,
        recipients=[r.strip() for r in to.split(",") if r.strip()],
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        date=dt,
    )


def _install_capture_hook() -> list[str]:
    """Monkey-patch classify.ollama._parse_llm_json_tiered to record every
    raw response text before it hits the parser. Returns a list that will
    be populated with each raw response seen."""
    import email_triage.classify.ollama as ollama_mod

    captured: list[str] = []
    real = ollama_mod._parse_llm_json_tiered

    def _spy(text: str, *a, **kw):
        captured.append(text)
        return real(text, *a, **kw)

    ollama_mod._parse_llm_json_tiered = _spy  # type: ignore[assignment]
    # `_parse_llm_json` is a thin wrapper that calls _parse_llm_json_tiered —
    # rebind it too so the classify() path uses the spied function.
    def _spy_plain(text: str):
        return _spy(text)[0]

    ollama_mod._parse_llm_json = _spy_plain  # type: ignore[assignment]
    return captured


def _load_categories(db) -> dict[str, str]:
    """Read the user's category slug → description map from the DB.
    Mirrors what the push consumer does before it calls classify()."""
    try:
        from email_triage.web.db import get_categories_dict
        return get_categories_dict(db)
    except Exception:
        return {"other": "anything that doesn't fit elsewhere"}


async def _run(msg, args) -> None:
    from email_triage.config import load_config
    from email_triage.secrets import read_bootstrap_master_key
    from email_triage.web.db import init_db_encrypted
    from email_triage.classify.ollama import OllamaClassifier

    cfg = load_config()
    key = read_bootstrap_master_key(cfg)
    db = init_db_encrypted(cfg.persistence.db_path, key)
    categories = _load_categories(db)

    clsf = getattr(cfg, "classifier", None)
    base_url = (
        args.url
        or getattr(clsf, "ollama_base_url", None)
        or getattr(clsf, "ollama_url", None)
        or getattr(clsf, "base_url", None)
        or "http://llm-host.example.com:11434"
    )
    model = (
        args.model
        or getattr(clsf, "ollama_model", None)
        or getattr(clsf, "model", None)
        or "qwen3.6:35b"
    )

    print(f"CLASSIFY_URL = {base_url}")
    print(f"MODEL        = {model}   (may be overridden by prefer_loaded)")
    print(f"SUBJECT      = {msg.subject!r}")
    print(f"SENDER       = {msg.sender!r}")
    print(f"BODY_LEN     = {len(msg.body_text or '')}")
    print(f"BODY_HEAD    = {(msg.body_text or '')[:400]!r}")
    print(f"CATEGORIES   = {list(categories.keys())}")
    print("-" * 70)

    captured = _install_capture_hook()
    classifier = OllamaClassifier(
        model=model,
        base_url=base_url,
        prefer_loaded=True,
        backup_models=[],
    )

    print("--- CLASSIFY (bare, _chat) ---")
    try:
        result = await classifier.classify(msg, categories)
        print("PARSED OK:")
        print(json.dumps(result.__dict__, default=str, indent=2))
    except Exception as e:
        print(f"CLASSIFY RAISED: {type(e).__name__}: {e}")

    if captured:
        print("\n--- RAW LLM RESPONSES (in order sent) ---")
        for i, raw in enumerate(captured):
            print(f"[response #{i}] len={len(raw)}")
            print(raw)
            print("-" * 40)
    else:
        print("(no raw response captured — the call may have failed before reaching Ollama)")

    if args.topic_match:
        print("\n--- TOPIC-MATCH (_chat_topics) ---")
        captured.clear()
        try:
            r = await classifier.classify_with_topics(
                msg, categories, list_hints=None, topic_block="",
            )
            print("PARSED OK:")
            print(json.dumps(getattr(r, "__dict__", {}), default=str, indent=2))
        except Exception as e:
            print(f"TOPIC-MATCH RAISED: {type(e).__name__}: {e}")
        for i, raw in enumerate(captured):
            print(f"[topic response #{i}] len={len(raw)}")
            print(raw)
            print("-" * 40)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("eml_path", nargs="?", type=Path,
                    help="Path to a .eml file inside the container.")
    ap.add_argument("--stdin", action="store_true",
                    help="Read raw MIME from stdin instead of a file.")
    ap.add_argument("--topic-match", action="store_true",
                    help="Also fire the topic-match path.")
    ap.add_argument("--model", type=str, default=None)
    ap.add_argument("--url", type=str, default=None)
    args = ap.parse_args()

    if args.stdin:
        std = _load_eml(None, sys.stdin.buffer.read())
    elif args.eml_path:
        std = _load_eml(args.eml_path, None)
    else:
        ap.error("Pass an eml_path or --stdin")

    msg = _build_app_message(std)
    asyncio.run(_run(msg, args))


if __name__ == "__main__":
    main()
