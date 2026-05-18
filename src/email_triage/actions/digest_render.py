"""Render dispatch for digest configs.

Originally three formats (Phase 3 of the multi-digest feature);
the dispatcher picks one based on ``cfg.format.render_as``:

- **table** — generic version of the legacy
  ``recipient_digest.render_html`` table. Used when an operator
  picks Render-as=Table on a custom digest. The preset
  (``preset_daily_activity``) keeps using
  ``recipient_digest.render_html`` directly (sender path
  dispatches there) so its wire output is byte-for-byte
  unchanged on the migration boundary.
- **grouped_list** — section per group (category / folder / day),
  per-row sender + subject + reason snippet + optional body
  preview. Default for custom digests.
- **plain_list** — flat ungrouped list, same per-row shape as
  grouped_list. Pick when there's no useful grouping (e.g.
  single-category digest).
- **newsletter** — article-card format produced by
  ``actions.digest.generate_digest``: re-fetches each row's
  body_html from the provider, runs LLM article extraction per
  message, groups by sender, renders compact Jinja template
  (per-source <strong> heading + <ul> of headline + summary +
  Read-more link). Restored 2026-05-06 — pre-digest_configs the
  scheduler called this rendering directly; the multi-digest
  migration silently mapped legacy schedules to grouped_list,
  which lost the article-extraction step.
- **newsletter_classic** — same article extraction + grouping,
  styled-HTML template (h2 title + date subtitle + per-sender
  h3 with bottom border + ul of bullets + footer). Older
  pre-8eaf959 visual treatment.

The two newsletter formats share the extraction step but the
sender path runs them ASYNC (LLM extract per source) — they
bypass this module's sync ``render_digest`` dispatcher and go
through ``render_newsletter_async`` instead. Sync dispatcher
only handles table / grouped_list / plain_list.

All formats honour the operator's HIPAA flag the same way the
preset table does: classifier reasoning collapses to a fixed
phrase per classifier source; subject + sender stay verbatim
(they already live in the recipient's own mailbox). Newsletter
formats inherit ``digest.generate_digest``'s HIPAA fail-closed
behaviour (commit aad59ad).
"""

from __future__ import annotations

import html
from collections import OrderedDict
from datetime import datetime
from typing import Any, Callable

from email_triage.actions.digest_configs import DigestConfig
from email_triage.actions.recipient_digest import (
    HIPAA_REASON_BY_SOURCE, HIPAA_REASON_DEFAULT, REASON_TRUNCATE,
)


# ---------------------------------------------------------------------------
# Shared row helpers (parity with recipient_digest)
# ---------------------------------------------------------------------------


def _render_reason(entry: dict[str, Any], hipaa: bool) -> str:
    """HIPAA mode: fixed phrase keyed on ``source``. Standard mode:
    verbatim, truncated. Mirrors recipient_digest._render_reason —
    duplicated here so we can ship phase 3 without an import-cycle
    refactor on the legacy module."""
    if hipaa:
        source = str(entry.get("source") or "")
        return HIPAA_REASON_BY_SOURCE.get(source, HIPAA_REASON_DEFAULT)
    raw = str(entry.get("reason") or "")
    if len(raw) > REASON_TRUNCATE:
        return raw[: REASON_TRUNCATE - 1] + "…"
    return raw


def _format_datetime(entry: dict[str, Any], fallback_iso: str) -> str:
    raw = entry.get("date") or fallback_iso or ""
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return str(raw)[:16]


def _preview(entry: dict[str, Any], hipaa: bool) -> str:
    """LEGACY: first 200-char preview of the body, HIPAA-redacted.

    Kept for back-compat with the old preset-table render path
    (recipient_digest.render_html still calls this) where the
    operator already accepted a 200-char body excerpt. The new
    custom-digest grouped/plain renders use ``_cheap_preview``
    instead — that returns first-line-of-body + first-3 H1/H2
    extracted from body_html, which is more useful for content
    aggregators (newsletter format) without paying any LLM cost.
    """
    if hipaa:
        return "[redacted]"
    raw = str(entry.get("body_text") or entry.get("snippet") or "")
    raw = " ".join(raw.split())  # collapse whitespace
    if len(raw) > 200:
        return raw[:199] + "…"
    return raw


def _cheap_preview(
    entry: dict[str, Any], hipaa: bool,
) -> tuple[str, list[str]]:
    """Return (lede, headings) — cheap content signals, no LLM.

    ``lede``: first non-empty line of body_text (~120 chars max).
    Newsletters typically open with a preheader/lede sentence
    designed for inbox previews; lifting it gives the reader a
    decent "what's this about" snippet at zero parse cost beyond
    a splitlines + length check. Skips lines under 5 chars to
    dodge "Hi," / single-word noise.

    ``headings``: up to 3 of the first ``<h1>``/``<h2>`` tags
    extracted from body_html via regex. For content aggregators
    these are usually the article titles — the same signal the
    LLM article extractor pulls, but raw + verbatim instead of
    paraphrased. Regex-only HTML scan is intentional; we don't
    need a full DOM walk for top-level headings, and avoiding
    BeautifulSoup keeps the cheap-preview path actually cheap.

    HIPAA mode returns ("[redacted]", []) — body content (text
    OR HTML) can carry PHI and is never quoted in the digest.
    """
    if hipaa:
        return ("[redacted]", [])

    body_text = str(entry.get("body_text") or entry.get("snippet") or "")
    body_html = str(entry.get("body_html") or "")

    # Lede — first non-trivial line.
    lede = ""
    for line in body_text.splitlines():
        line = line.strip()
        if len(line) >= 5:
            lede = line[:120] + ("…" if len(line) > 120 else "")
            break

    # Headings — regex-pull <h1>/<h2> content, strip inner tags,
    # collapse whitespace, take up to 3.
    headings: list[str] = []
    if body_html:
        import re as _re
        matches = _re.findall(
            r"<h[12][^>]*>(.*?)</h[12]>",
            body_html,
            _re.IGNORECASE | _re.DOTALL,
        )
        for m in matches:
            text = _re.sub(r"<[^>]+>", "", m)
            text = " ".join(text.split())
            if text:
                headings.append(text[:120])
            if len(headings) >= 3:
                break

    return (lede, headings)


# ---------------------------------------------------------------------------
# Group key extractors
# ---------------------------------------------------------------------------


def _group_key(entry: dict[str, Any], group_by: str, fallback_iso: str) -> str:
    """Pick the bucket label for one entry under the chosen grouping."""
    if group_by == "category":
        return str(entry.get("category") or "(uncategorised)")
    if group_by == "folder":
        # The folder of origin lives on the entry's headers when
        # the cross-folder search path was used; otherwise the
        # account's default mailbox is implied.
        headers = entry.get("headers") or {}
        return str(headers.get("X-Email-Triage-Folder") or "INBOX")
    if group_by == "day":
        raw = entry.get("date") or fallback_iso or ""
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d")
        except (TypeError, ValueError):
            return "unknown"
    if group_by == "sender":
        # Use the From header verbatim. Display-name extraction
        # (e.g. "Stratechery <ben@stratechery.com>" → "Stratechery")
        # is intentionally NOT applied here — the renderer keeps
        # the raw value so two messages from the same address
        # always group together regardless of display-name
        # variations between sends.
        return str(entry.get("sender") or "(unknown sender)")
    return ""  # 'none' or unknown — single bucket


def _group_rows(
    rows: list[dict[str, Any]], group_by: str, fallback_iso: str,
) -> "OrderedDict[str, list[dict[str, Any]]]":
    """Group ``rows`` by the chosen key. Preserves first-seen
    order so 'newest first' (rows arrive that way) flows through
    to bucket order."""
    buckets: OrderedDict[str, list] = OrderedDict()
    for entry in rows:
        key = _group_key(entry, group_by, fallback_iso)
        buckets.setdefault(key, []).append(entry)
    return buckets


# ---------------------------------------------------------------------------
# Format: table (generic — for custom digests that opt-in)
# ---------------------------------------------------------------------------


_DEFAULT_COLUMN_LABELS: dict[str, str] = {
    "datetime": "When",
    "sender": "Sender",
    "headline": "Headline",
    "subject": "Subject",
    "link": "Link",
    "category": "Category",
    "reason": "Why",
    "preview": "Preview",
    "unread": "Unread",
    "attachment": "📎",
    "folder": "Folder",
}


def _column_value(
    entry: dict[str, Any], key: str, *,
    hipaa: bool, fallback_dt_iso: str,
) -> str:
    """Resolve one column's cell value for one entry.

    Plain strings (already HTML-escaped at the caller). HIPAA
    redaction applies to ``reason`` + ``preview``; subject /
    sender / headline pass through verbatim per the design
    contract (those values already live in the recipient's
    mailbox via the original messages).
    """
    if key == "datetime":
        return _format_datetime(entry, fallback_dt_iso)
    if key == "sender":
        return str(entry.get("sender") or "—")
    if key in ("headline", "subject"):
        return str(entry.get("subject") or "—")
    if key == "link":
        # Provider-extracted URL list lives on the entry under
        # ``links``. Take the first; empty when no links found.
        links = entry.get("links") or []
        if isinstance(links, list) and links:
            return str(links[0])
        return ""
    if key == "category":
        return str(entry.get("category") or "—")
    if key == "reason":
        return _render_reason(entry, hipaa)
    if key == "preview":
        return _preview(entry, hipaa)
    if key == "unread":
        labels = entry.get("labels") or []
        return "✉" if "UNREAD" in labels else ""
    if key == "attachment":
        return "📎" if entry.get("attachments") else ""
    if key == "folder":
        headers = entry.get("headers") or {}
        return str(headers.get("X-Email-Triage-Folder") or "")
    return ""


def _sort_rows_by_columns(
    rows: list[dict[str, Any]],
    columns: list,
    *,
    hipaa: bool, fallback_dt_iso: str,
) -> list[dict[str, Any]]:
    """Apply per-column sort priorities + directions.

    Columns with ``sort_priority == 0`` don't participate.
    Columns with priority > 0 sort in ascending priority order
    (1 = primary, 2 = secondary, ...). Stable Python sort means
    we apply keys in REVERSE priority order — secondary first,
    primary last — so the primary key wins on the final pass.
    """
    sort_cols = [c for c in columns if c.sort_priority > 0]
    if not sort_cols:
        return rows
    sort_cols.sort(key=lambda c: c.sort_priority, reverse=True)
    out = list(rows)
    for col in sort_cols:
        reverse = (col.sort_direction == "desc")
        out.sort(
            key=lambda e, k=col.key: _column_value(
                e, k, hipaa=hipaa, fallback_dt_iso=fallback_dt_iso,
            ),
            reverse=reverse,
        )
    return out


def render_table_generic(
    *,
    cfg: DigestConfig,
    rows: list[dict[str, Any]],
    account_name: str,
    account_email: str,
    hipaa: bool,
    fallback_dt_iso: str = "",
) -> str:
    """Generic table render — per-digest variant of the preset's
    legacy table.

    Columns are operator-configurable via ``cfg.format.columns``
    (a list of ``DigestColumn`` carrying ``key`` + ``label`` +
    ``sort_priority`` + ``sort_direction``). Default column set
    for newly-created custom digests is
    ``[datetime, sender, headline, link]`` with datetime
    descending as the primary sort. Operators can pick from
    ``COLUMN_KEYS`` (datetime / sender / headline / subject /
    link / category / reason / preview / unread / attachment /
    folder) and reorder + relabel each column.

    Header text reflects the digest's ``name`` instead of "Daily
    Triage Digest". HIPAA mode + the per-column key picker
    interact via ``_column_value`` — ``reason`` and ``preview``
    redact in HIPAA mode; everything else passes through (the
    design contract documented at the top of
    ``recipient_digest`` allows this since the digest goes back
    to the same mailbox where the original messages live).
    """
    columns = cfg.format.columns or []
    if not columns:
        # Defensive — validator already rejects this case for
        # render_as=table, but if a caller bypasses validation
        # we still want a non-empty table.
        from email_triage.actions.digest_configs import _default_columns
        columns = _default_columns()

    sorted_rows = _sort_rows_by_columns(
        rows, columns, hipaa=hipaa, fallback_dt_iso=fallback_dt_iso,
    )

    header_cells = "".join(
        f"<th>{html.escape(col.label or _DEFAULT_COLUMN_LABELS.get(col.key, col.key))}</th>"
        for col in columns
    )

    body_rows: list[str] = []
    for entry in sorted_rows:
        cells: list[str] = []
        for col in columns:
            value = _column_value(
                entry, col.key,
                hipaa=hipaa, fallback_dt_iso=fallback_dt_iso,
            )
            # Link column: render as an <a> when the value looks
            # like a URL. Other columns are plain text. Cap link
            # display length so a giant tracker URL doesn't blow
            # the table layout.
            if col.key == "link" and value:
                shown = value if len(value) <= 60 else value[:57] + "…"
                cells.append(
                    f'<td><a href="{html.escape(value)}">'
                    f"{html.escape(shown)}</a></td>"
                )
            else:
                cells.append(f"<td>{html.escape(value)}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")

    hipaa_banner = _hipaa_banner_html() if hipaa else ""
    return (
        "<html><body>"
        f"<h2>{html.escape(cfg.name)} — {html.escape(account_name)}</h2>"
        f"<p>Activity for <code>{html.escape(account_email)}</code>: "
        f"<strong>{len(rows)}</strong> messages.</p>"
        f"{hipaa_banner}"
        '<table border="1" cellpadding="6" cellspacing="0" '
        'style="border-collapse:collapse;font-family:sans-serif;'
        'font-size:0.9em;">'
        f"<thead><tr>{header_cells}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
        "<p style=\"font-size:0.8em;color:#888;\">"
        "Sent by email-triage. Edit this digest via Accounts → "
        "Edit → Digests."
        "</p>"
        "</body></html>"
    )


# ---------------------------------------------------------------------------
# Format: grouped_list (default for custom)
# ---------------------------------------------------------------------------


def render_grouped_list(
    *,
    cfg: DigestConfig,
    rows: list[dict[str, Any]],
    account_name: str,
    account_email: str,
    hipaa: bool,
    fallback_dt_iso: str = "",
) -> str:
    """Default custom-digest format. One section per group.

    Per-row shape:

        Sender · Subject (When)
        category · why
        [200-char preview if format.include_body_preview]

    Empty groups are skipped (defensive — group_rows shouldn't
    emit them, but a future refactor that injects 'no rows'
    placeholder buckets shouldn't blow up here).
    """
    group_by = cfg.format.group_by
    include_preview = cfg.format.include_body_preview

    if group_by == "none":
        # Degenerate to plain list under the same render path so
        # operators get consistent visuals.
        return render_plain_list(
            cfg=cfg, rows=rows,
            account_name=account_name, account_email=account_email,
            hipaa=hipaa, fallback_dt_iso=fallback_dt_iso,
        )

    buckets = _group_rows(rows, group_by, fallback_dt_iso)
    sections: list[str] = []
    for label, bucket_rows in buckets.items():
        if not bucket_rows:
            continue
        item_html = "".join(
            _row_block_html(e, hipaa, fallback_dt_iso, include_preview)
            for e in bucket_rows
        )
        # Section heading: bigger font + left-border accent + light
        # background tint + indented rows underneath. Three
        # reinforcing signals so the heading reads as a section
        # marker, not "another row that printed weirdly with a (1)
        # tail" (operator feedback 2026-05-07).
        sections.append(
            "<section style=\"margin:1.5em 0;\">"
            "<h3 style=\"margin:0 0 0.5em;font-size:1.3em;"
            "border-left:4px solid #2563eb;"
            "background:#f1f5f9;"
            "padding:0.35em 0.7em;"
            "border-radius:4px;\">"
            f"{html.escape(label)} "
            "<small style=\"color:#888;font-weight:normal;"
            "font-size:0.75em;\">"
            f"({len(bucket_rows)})</small></h3>"
            "<div style=\"margin-left:1em;\">"
            f"{item_html}</div></section>"
        )
    hipaa_banner = _hipaa_banner_html() if hipaa else ""
    return (
        "<html><body style=\"font-family:sans-serif;font-size:0.95em;\">"
        f"<h2>{html.escape(cfg.name)} — {html.escape(account_name)}</h2>"
        f"<p>Activity for <code>{html.escape(account_email)}</code>: "
        f"<strong>{len(rows)}</strong> messages, "
        f"{len(buckets)} {group_by}{'s' if len(buckets) != 1 else ''}.</p>"
        f"{hipaa_banner}"
        f"{''.join(sections)}"
        "<p style=\"font-size:0.8em;color:#888;margin-top:1.5em;\">"
        "Sent by email-triage. Edit this digest via Accounts → "
        "Edit → Digests."
        "</p>"
        "</body></html>"
    )


# ---------------------------------------------------------------------------
# Format: plain_list
# ---------------------------------------------------------------------------


def render_plain_list(
    *,
    cfg: DigestConfig,
    rows: list[dict[str, Any]],
    account_name: str,
    account_email: str,
    hipaa: bool,
    fallback_dt_iso: str = "",
) -> str:
    """Flat ungrouped list. Same per-row block shape as
    grouped_list — just no section headers."""
    include_preview = cfg.format.include_body_preview
    items_html = "".join(
        _row_block_html(e, hipaa, fallback_dt_iso, include_preview)
        for e in rows
    )
    hipaa_banner = _hipaa_banner_html() if hipaa else ""
    return (
        "<html><body style=\"font-family:sans-serif;font-size:0.95em;\">"
        f"<h2>{html.escape(cfg.name)} — {html.escape(account_name)}</h2>"
        f"<p>Activity for <code>{html.escape(account_email)}</code>: "
        f"<strong>{len(rows)}</strong> messages.</p>"
        f"{hipaa_banner}"
        f"<div>{items_html}</div>"
        "<p style=\"font-size:0.8em;color:#888;margin-top:1.5em;\">"
        "Sent by email-triage. Edit this digest via Accounts → "
        "Edit → Digests."
        "</p>"
        "</body></html>"
    )


def _row_block_html(
    entry: dict[str, Any],
    hipaa: bool,
    fallback_dt_iso: str,
    include_preview: bool,
) -> str:
    """One entry rendered as a sender · subject (when) block.

    Per operator feedback (2026-05-07) the second meta line —
    ``category · why`` — was dropped: ``why`` is LLM-rationale
    noise the recipient doesn't need, and ``category`` is
    redundant with the digest title (the operator-set name at
    the top of the email already states what the digest covers,
    and most operators filter to one or two categories anyway).

    Preview block (when ``include_preview=True``) carries the
    cheap-preview pair: first line of body_text + up to 3
    extracted ``<h1>``/``<h2>`` headings from body_html. No LLM.
    HIPAA mode renders "[redacted]". Defaults to OFF on new
    digests; toggle stays available for operators who want the
    extra context per-row.
    """
    dt = html.escape(_format_datetime(entry, fallback_dt_iso))
    sender = html.escape(str(entry.get("sender") or "—"))
    subject = html.escape(str(entry.get("subject") or "—"))
    preview_block = ""
    if include_preview:
        if hipaa:
            preview_block = (
                "<div style=\"color:#555;font-size:0.9em;"
                "margin:0.15em 0 0 1em;\">[redacted]</div>"
            )
        else:
            lede, headings = _cheap_preview(entry, hipaa)
            bits = []
            if lede:
                bits.append(
                    "<div style=\"color:#555;font-size:0.9em;"
                    "margin:0.15em 0 0 1em;\">"
                    f"{html.escape(lede)}</div>"
                )
            if headings:
                items = "".join(
                    f"<li>{html.escape(h)}</li>" for h in headings
                )
                bits.append(
                    "<ul style=\"color:#555;font-size:0.85em;"
                    "margin:0.2em 0 0 2em;padding:0;\">"
                    f"{items}</ul>"
                )
            preview_block = "".join(bits)
    return (
        "<div style=\"margin:0.4em 0;padding:0.3em 0;"
        "border-bottom:1px solid #eee;\">"
        f"<div><strong>{sender}</strong> · {subject} "
        f"<small style=\"color:#888;\">({dt})</small></div>"
        f"{preview_block}"
        "</div>"
    )


def _hipaa_banner_html() -> str:
    return (
        '<p style="font-size:0.85em;color:#666;">'
        "HIPAA mode: classifier reasoning is redacted to a "
        "fixed phrase per classifier source; body previews are "
        "redacted. Subject + sender appear verbatim because they "
        "already live in this mailbox via the original messages."
        "</p>"
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


_RENDERERS: dict[str, Callable] = {
    "table": render_table_generic,
    "grouped_list": render_grouped_list,
    "plain_list": render_plain_list,
}


def render_digest(
    *,
    cfg: DigestConfig,
    rows: list[dict[str, Any]],
    account_name: str,
    account_email: str,
    hipaa: bool,
    fallback_dt_iso: str = "",
) -> str:
    """Format a digest as HTML based on ``cfg.format.render_as``.

    The preset (``cfg.kind == 'preset_daily_activity'``) is NOT
    routed through here — the sender keeps calling the legacy
    ``recipient_digest.render_html`` directly so the preset's
    wire output stays byte-for-byte identical across the
    migration boundary. This dispatcher is only for custom
    digests.

    Unknown render_as falls through to grouped_list (the default
    for custom) so a stored config from a future schema doesn't
    blow up an old reader.
    """
    fn = _RENDERERS.get(cfg.format.render_as, render_grouped_list)
    return fn(
        cfg=cfg, rows=rows,
        account_name=account_name, account_email=account_email,
        hipaa=hipaa, fallback_dt_iso=fallback_dt_iso,
    )


# ---------------------------------------------------------------------------
# Newsletter renderers (article extraction + grouped HTML)
# ---------------------------------------------------------------------------
#
# Two visual treatments share a single extraction step. The render
# functions below are NOT wired into the sync ``_RENDERERS`` dispatch
# — they're async (the article extraction calls the LLM per source
# message) and need a provider + classifier the sync dispatcher
# doesn't carry. The sender's per-digest dispatcher
# (``app._fire_one_digest``) detects ``render_as in {"newsletter",
# "newsletter_classic"}`` and routes to ``render_newsletter_async``
# below before reaching ``render_digest``.

# Pre-8eaf959 styled-HTML template, ported from the f-string shape
# in the original ``digest.build_digest_html`` (commit history,
# pre-Lindy). Translated to Jinja so it slots into the same
# ``digest.generate_digest(html_template=...)`` knob the compact
# template uses. Inline styles only — email clients don't honour
# external stylesheets or CSS variables.
_CLASSIC_NEWSLETTER_TEMPLATE = """\
<html>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:640px;margin:0 auto;padding:20px;color:#334155;line-height:1.6;">
<h2 style="color:#0f172a;margin-bottom:4px;font-size:24px;">{% if digest_name %}{{ digest_name | e }}{% else %}Newsletter Digest{% endif %}</h2>
<p style="color:#64748b;margin-top:0;font-size:14px;">
{{ date_str | e }} &mdash; {{ total_articles }} article{% if total_articles != 1 %}s{% endif %} from {{ groups|length }} source{% if groups|length != 1 %}s{% endif %}
</p>
<hr style="border:none;border-top:2px solid #e2e8f0;margin:16px 0;">
{% for g in groups %}
<div style="margin-bottom:24px;">
<h3 style="color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:6px;margin-bottom:10px;font-size:18px;">{{ g.sender_name | e }}</h3>
<ul style="margin:0;padding-left:20px;list-style-type:disc;">
{% for a in g.articles %}<li style="margin-bottom:8px;"><strong>{{ a.headline | e }}</strong>: {{ a.summary | e }}{% if a.url %} <a href="{{ a.url | e }}" style="color:#2563eb;text-decoration:underline;">Read more</a>{% endif %}</li>
{% endfor %}</ul>
</div>
{% endfor %}
<hr style="border:none;border-top:2px solid #e2e8f0;margin:16px 0;">
<p style="color:#94a3b8;font-size:12px;text-align:center;">Generated by Email Triage</p>
{% if signature %}<p style="font-size:0.85rem;color:gray;margin-top:1.5rem;text-align:center;">{{ signature | e }}</p>{% endif %}
</body>
</html>"""


async def render_newsletter_async(
    *,
    cfg: "DigestConfig",
    provider,
    classifier,
    messages: list,
    account_name: str,
    account_email: str,
    hipaa: bool,
    date_str: str = "",
    signature: str = "",
    digest_name: str = "",
    html_template: str = "",
) -> str:
    """Render a newsletter-shaped digest.

    Two visual treatments based on ``cfg.format.render_as``:
      - "newsletter" — compact Jinja default in
        ``digest.DEFAULT_DIGEST_TEMPLATE``.
      - "newsletter_classic" — older fuller styled-HTML template
        embedded in this module (``_CLASSIC_NEWSLETTER_TEMPLATE``).

    Both share the LLM article-extraction step from
    ``digest.generate_digest`` — re-fetches body_html via the
    provider (caller pre-fetches and passes ``messages``), runs
    ``extract_articles`` per source, groups by sender. The render
    function lives in ``digest.py``; this wrapper picks the
    template + threads the kwargs.

    HIPAA: the underlying ``digest.generate_digest`` already
    enforces HIPAA fail-closed (commit aad59ad). Caller must pass
    ``hipaa=True`` for HIPAA-flagged accounts; the extraction
    routine refuses to mine body content under that flag and
    falls back to subject-only headlines.
    """
    from email_triage.actions.digest import generate_digest

    # Template precedence: operator-supplied html_template (from
    # the editor textarea) wins, falls back to the built-in for
    # the chosen format. newsletter_classic builds use the
    # styled template, plain newsletter uses the compact default
    # (empty string -> generate_digest fills in
    # DEFAULT_DIGEST_TEMPLATE).
    if html_template:
        template = html_template
    elif cfg.format.render_as == "newsletter_classic":
        template = _CLASSIC_NEWSLETTER_TEMPLATE
    else:
        template = ""
    # generate_digest does the LLM extraction + grouping + render
    # in one shot. delete_originals stays False — newsletter render
    # via the per-digest send path is read-only; caller decides
    # archive separately if needed.
    html_body, _articles, _sources = await generate_digest(
        provider, classifier, messages,
        delete_originals=False,
        signature_template=signature,
        category=(
            (cfg.filter.categories or ["newsletters"])[0]
            if hasattr(cfg, "filter") else "newsletters"
        ),
        account=account_email,
        html_template=template,
        digest_name=digest_name or getattr(cfg, "name", "") or "",
    )
    return html_body
