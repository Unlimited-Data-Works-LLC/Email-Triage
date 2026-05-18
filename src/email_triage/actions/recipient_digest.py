"""Per-recipient per-account daily triage digest.

Delivers a daily summary of triage activity TO the account's own
mailbox so the user sees what email-triage has done with their mail
without leaving their inbox. Owner-only opt-in via the account-edit
form (``recipient_digest_enabled`` + ``recipient_digest_send_at`` in
``email_accounts.config_json``).

Scope decisions (locked at design time):

* **Locked to the account.** Delivery is to the account's own email
  address — never to the user's notify_email or any other surface.
  "What email-triage did to MY mail goes back into MY mailbox."
* **Owner-only initially.** Delegates of the account don't yet get
  their own opt-in. Per-(user, account) preferences will land later
  if delegate digests are wanted.
* **Hourly cadence with :10 offset.** Operator picks ``HH:10`` from
  a 24-option dropdown. The :10 offset dodges top-of-hour cron
  contention and gives a buffer for late-arriving classifications
  to settle before the digest fires.
* **Idempotent within 23h.** A ``settings.recipient_digest_state:<acct_id>``
  row carries the last-sent timestamp; the scheduler tick refuses
  to re-send within 23 hours regardless of how many tick fires
  fall inside the hour bucket.
* **Empty-day skip.** No triage rows in the last 24h => no email.
  Avoids daily empty-mail noise.

HIPAA exposure analysis (#post-recipient-digest design):

The digest contains datetime + sender + category + subject + reason.
The recipient is the SAME mailbox where the source mails already
live, so sender + subject are NOT new PHI exposure — the user has
those values already via their normal mail client. The only new
disclosure surface is the LLM-generated ``reason`` field, which can
quote body content ("Patient confirmed Tuesday appointment"). Two
postures:

* Standard mode: render ``reason`` verbatim, truncated to 120 char.
* HIPAA mode (system OR per-account): render a fixed phrase keyed
  on ``classification.source`` (Option B). Subject + sender pass
  through verbatim because they're already in the mailbox; only
  the new-PHI surface (reason) is redacted.

§164.312(b) Audit Controls satisfied via ``access_log`` row on
every send. §164.312(e) Transmission Security satisfied via
existing SMTP STARTTLS path.
"""

from __future__ import annotations

import html
import json
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from typing import Any

from email_triage._errfmt import fmt_exc
from email_triage.mail_headers import (
    X_EMAIL_TRIAGE_HEADER, build_triage_header,
)
from email_triage.triage_logging import get_logger
from email_triage.web.auth import format_from_header

log = get_logger("actions.recipient_digest")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: How far back the digest pulls. 24h matches the daily cadence with
#: a small overlap to absorb scheduler jitter — duplicate-suppression
#: is handled by the idempotence-window check on
#: ``last_recipient_digest_sent_at``, not the lookback length.
WINDOW_HOURS = 24

#: Idempotence guard: refuse to re-send within this window even if
#: the scheduler tick fires inside the configured hour bucket
#: multiple times.
MIN_RESEND_INTERVAL_HOURS = 23

#: Reason-redaction map for HIPAA mode (Option B). Keys match the
#: ``classification.source`` field; falls through to the generic
#: phrase when the source isn't recognized.
HIPAA_REASON_BY_SOURCE: dict[str, str] = {
    "llm":       "Classified by content analysis",
    "list_rule": "Classified by sender/subject rule match",
    "list_hint": "Classified by sender/subject hint match",
}
HIPAA_REASON_DEFAULT = "Classified by category routing"

#: Per-row reason truncation in standard mode. Long LLM rationales
#: bloat the digest; 120 chars covers the meaningful prefix.
REASON_TRUNCATE = 120

#: ``settings`` key prefix for the per-account idempotence state.
_STATE_KEY_PREFIX = "recipient_digest_state:"


def _state_key(account_id: int) -> str:
    return f"{_STATE_KEY_PREFIX}{account_id}"


# ---------------------------------------------------------------------------
# Should-fire decision
# ---------------------------------------------------------------------------

def parse_send_at_hour(raw: str | None) -> int | None:
    """Extract the hour from a ``HH:10`` send-time string.

    Returns None on missing / malformed input. The :10 offset is
    enforced by the UI dropdown but not validated here — the
    scheduler tick check is on the hour anyway.
    """
    if not raw:
        return None
    try:
        h, _, _ = str(raw).strip().partition(":")
        hour = int(h)
        if 0 <= hour <= 23:
            return hour
    except (TypeError, ValueError):
        pass
    return None


def should_fire(
    *,
    account_cfg: dict[str, Any],
    last_sent_iso: str | None,
    now: datetime,
) -> bool:
    """Decide whether the digest should fire RIGHT NOW for this account.

    Three gates: feature toggle, hour match, idempotence window.
    Empty-day skip is enforced separately by the caller (after
    collecting rows) so the should_fire decision can be made
    cheaply without a row read on accounts that aren't due yet.
    """
    if not bool(account_cfg.get("recipient_digest_enabled", False)):
        return False
    target_hour = parse_send_at_hour(
        account_cfg.get("recipient_digest_send_at"),
    )
    if target_hour is None:
        return False
    # Compare in account/user-local terms via the timestamp the
    # caller passed; the scheduler tick at app.py is responsible
    # for converting to the user's local time before invoking.
    if now.hour != target_hour:
        return False
    if last_sent_iso:
        try:
            last_dt = datetime.fromisoformat(last_sent_iso)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            last_dt = None
        if last_dt is not None:
            elapsed = (now - last_dt).total_seconds() / 3600.0
            if elapsed < MIN_RESEND_INTERVAL_HOURS:
                return False
    return True


# ---------------------------------------------------------------------------
# Row collection
# ---------------------------------------------------------------------------

def gather_digest_rows(
    db,
    *,
    account_id: int,
    since_iso: str,
) -> list[dict[str, Any]]:
    """Pull per-message classification rows from ``triage_runs.results_json``
    for ``account_id`` in the given window. Newest first.

    Filters out rows with status != "ok" (skipped, errored, header
    loop-prevention skips) since those weren't actually classified
    and would just confuse the digest.
    """
    rows = db.execute(
        "SELECT created_at, results_json FROM triage_runs "
        "WHERE account_id = ? AND created_at >= ? "
        "ORDER BY created_at DESC",
        (account_id, since_iso),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        try:
            results = json.loads(r["results_json"])
        except Exception:
            continue
        if not isinstance(results, list):
            continue
        for entry in results:
            if not isinstance(entry, dict):
                continue
            if entry.get("status") and entry["status"] != "ok":
                continue
            if not entry.get("category"):
                continue
            out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _render_reason(entry: dict[str, Any], hipaa: bool) -> str:
    """Pick the reason cell content for one row.

    HIPAA mode: fixed phrase keyed on ``source`` (Option B). The
    raw reason is replaced even though it was persisted as
    ``"[redacted]"`` already by triage_runner — defense in depth.
    Standard mode: verbatim, truncated.
    """
    if hipaa:
        source = str(entry.get("source") or "")
        return HIPAA_REASON_BY_SOURCE.get(source, HIPAA_REASON_DEFAULT)
    raw = str(entry.get("reason") or "")
    if len(raw) > REASON_TRUNCATE:
        return raw[: REASON_TRUNCATE - 1] + "…"
    return raw


def _format_datetime(entry: dict[str, Any], fallback_iso: str) -> str:
    """Pick the displayable datetime. Prefers the message's own Date
    header; falls back to the triage run's created_at when the
    provider's date wasn't carried through (legacy result rows
    pre-dating the writer's date persistence).
    """
    raw = entry.get("date") or fallback_iso or ""
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return str(raw)[:16]


def render_html(
    *,
    rows: list[dict[str, Any]],
    account_name: str,
    account_email: str,
    hipaa: bool,
    fallback_dt_iso: str = "",
) -> str:
    """Render the table as HTML."""
    body_rows: list[str] = []
    for entry in rows:
        dt = html.escape(_format_datetime(entry, fallback_dt_iso))
        sender = html.escape(str(entry.get("sender") or "—"))
        category = html.escape(str(entry.get("category") or "—"))
        subject = html.escape(str(entry.get("subject") or "—"))
        why = html.escape(_render_reason(entry, hipaa))
        body_rows.append(
            "<tr>"
            f"<td>{dt}</td><td>{sender}</td>"
            f"<td>{category}</td><td>{subject}</td>"
            f"<td>{why}</td>"
            "</tr>"
        )
    hipaa_banner = ""
    if hipaa:
        hipaa_banner = (
            '<p style="font-size:0.85em;color:#666;">'
            "HIPAA mode: classifier reasoning is redacted to a "
            "fixed phrase per classifier source. Subject + sender "
            "appear verbatim because they already live in this "
            "mailbox via the original messages."
            "</p>"
        )
    return (
        "<html><body>"
        f"<h2>Daily Triage Digest — {html.escape(account_name)}</h2>"
        f"<p>Activity for <code>{html.escape(account_email)}</code> "
        f"in the last {WINDOW_HOURS} hours: "
        f"<strong>{len(rows)}</strong> messages classified.</p>"
        f"{hipaa_banner}"
        '<table border="1" cellpadding="6" cellspacing="0" '
        'style="border-collapse:collapse;font-family:sans-serif;'
        'font-size:0.9em;">'
        "<thead><tr>"
        "<th>When</th><th>Sender</th><th>Category</th>"
        "<th>Subject</th><th>Why</th>"
        "</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
        "<p style=\"font-size:0.8em;color:#888;\">"
        "Sent by email-triage. Toggle off via Accounts → "
        "Edit → Daily Digest."
        "</p>"
        "</body></html>"
    )


def render_plain(
    *,
    rows: list[dict[str, Any]],
    account_name: str,
    account_email: str,
    hipaa: bool,
    fallback_dt_iso: str = "",
) -> str:
    """Render the same table as plaintext (fallback part)."""
    lines = [
        f"Daily Triage Digest — {account_name}",
        f"Activity for {account_email} in the last {WINDOW_HOURS} hours: "
        f"{len(rows)} messages classified.",
        "",
    ]
    if hipaa:
        lines.append(
            "HIPAA mode: classifier reasoning is redacted to a fixed "
            "phrase per classifier source. Subject + sender are "
            "verbatim (already in this mailbox).",
        )
        lines.append("")
    for entry in rows:
        dt = _format_datetime(entry, fallback_dt_iso)
        lines.append(
            f"  {dt} | {entry.get('sender', '—')} | "
            f"{entry.get('category', '—')} | "
            f"{entry.get('subject', '—')} | "
            f"{_render_reason(entry, hipaa)}"
        )
    lines.append("")
    lines.append("Toggle off via Accounts → Edit → Daily Digest.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Send
# ---------------------------------------------------------------------------

def build_custom_digest_subject(dcfg, now_local) -> str:
    """Subject line for a CUSTOM digest (not the legacy preset).

    Shape: ``Your <Cadence> <Body> Digest — <Weekday, Month DD, YYYY>``

    The ``<Cadence>`` token reflects the schedule selector
    (``daily`` → ``Daily``, ``weekly`` → ``Weekly``, ``monthly`` →
    ``Monthly``) so the subject matches the operator's chosen
    cadence rather than hard-coding "Daily".

    The ``<Body>`` token surfaces what the digest is filtering:

    * ``filter.categories`` is empty → fall back to ``dcfg.name``
      (the operator-typed digest name) so the subject still
      identifies the digest. Empty name itself falls back to
      "Email" so we never emit a stray "Your Daily  Digest".
    * Exactly one category → that category's display title
      (pluralized: ``newsletter`` → ``Newsletters``, ``alerts``
      stays ``Alerts``).
    * Two or more categories → first category's title + ``+N``
      where N = additional count. Example: filtering
      ``[newsletter, promotions, alerts]`` produces
      ``Newsletters +2``. Keeps the subject scannable while
      still telling the reader more is included.

    Preset (``preset_daily_activity``) is built elsewhere with the
    legacy ``Triage Digest — <account> (<N> classified)`` shape;
    this helper is only for custom digests.

    Local-time strftime keeps the date label aligned with the
    body's date_str. ``now_local`` is the caller's responsibility
    (pass ``now_utc.astimezone()`` from a UTC-tracking caller).
    """
    from email_triage.actions.digest import _category_title

    cadence = (
        getattr(getattr(dcfg, "schedule", None), "cadence", "")
        or "daily"
    ).strip().title()
    cats = list(getattr(getattr(dcfg, "filter", None), "categories", None) or [])
    if cats:
        first = _category_title(cats[0])
        # Pluralize naturally — _category_title returns the
        # title-cased slug as-is. "newsletter" → "Newsletter" needs
        # an "s"; "alerts" → "Alerts" already ends in s; "news"
        # ends in s but is uncountable (rare false-negative).
        if not first.lower().endswith("s"):
            first = first + "s"
        body = first
        if len(cats) > 1:
            body = f"{first} +{len(cats) - 1}"
    else:
        body = (getattr(dcfg, "name", "") or "Email").strip()
    date_str = now_local.strftime("%A, %B %d, %Y")
    # Em dash (U+2014) matches the legacy newsletter subject shape
    # the operator was used to seeing pre-multi-digest refactor.
    return f"Your {cadence} {body} Digest — {date_str}"


def send_recipient_digest(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_addr: str,
    from_name: str,
    to_addr: str,
    account_name: str,
    rows: list[dict[str, Any]],
    hipaa: bool,
    use_tls: bool = True,
    fallback_dt_iso: str = "",
    html_body_override: str | None = None,
    plain_body_override: str | None = None,
    subject_override: str | None = None,
) -> None:
    """Send the digest via SMTP.

    Synchronous; caller wraps in ``asyncio.to_thread`` from async.
    Stamps the loop-prevention header so the inbound watcher skips
    the digest itself when it lands in the recipient's INBOX.

    The ``*_override`` kwargs let the multi-digest sender (Phase 4)
    pass pre-rendered HTML / plain bodies — custom digests render
    via ``actions.digest_render.render_digest`` instead of the
    legacy ``render_html`` table. Without overrides the legacy
    table render fires (preset path).
    """
    subject = subject_override or (
        f"Triage Digest — {account_name} ({len(rows)} classified)"
    )
    html_body = (
        html_body_override
        if html_body_override is not None
        else render_html(
            rows=rows, account_name=account_name,
            account_email=to_addr, hipaa=hipaa,
            fallback_dt_iso=fallback_dt_iso,
        )
    )
    plain_body = (
        plain_body_override
        if plain_body_override is not None
        else render_plain(
            rows=rows, account_name=account_name,
            account_email=to_addr, hipaa=hipaa,
            fallback_dt_iso=fallback_dt_iso,
        )
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = format_from_header(from_addr, from_name)
    msg["To"] = to_addr
    msg["Date"] = formatdate(localtime=True)
    msg[X_EMAIL_TRIAGE_HEADER] = build_triage_header("recipient_digest")
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        if use_tls:
            server.starttls()
        if smtp_user:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)


# ---------------------------------------------------------------------------
# Idempotence helpers
# ---------------------------------------------------------------------------

def get_last_sent(db, account_id: int) -> str | None:
    """Pull the last-sent ISO timestamp from settings, or None."""
    from email_triage.web.db import get_setting
    state = get_setting(db, _state_key(account_id)) or {}
    return state.get("last_sent_at") if isinstance(state, dict) else None


def mark_sent(db, account_id: int, now: datetime, row_count: int) -> None:
    """Persist the last-sent timestamp + row count for the next
    idempotence check + audit-trail readback. Best-effort; an
    audit-write failure here doesn't roll back the actual SMTP
    send (the digest already left)."""
    from email_triage.web.db import set_setting
    try:
        set_setting(db, _state_key(account_id), {
            "last_sent_at": now.isoformat(),
            "row_count": int(row_count),
        })
    except Exception as e:
        log.warning(
            "recipient_digest: state write failed (idempotence "
            "guard may not engage on next tick)",
            account_id=account_id, error=fmt_exc(e),
        )
