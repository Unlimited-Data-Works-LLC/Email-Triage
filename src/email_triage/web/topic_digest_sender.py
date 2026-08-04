""" — the scheduled Topic-digest sender (the output spine).

This is the piece that turns accumulated ``topic_hits`` into a delivered
digest email. Before it,  had an editor, a matcher, a preview, and an
Internet-Search enrichment — but **nothing ever emailed a digest**: the
``render_as`` / ``mode`` config was stored with no consumer. This module is
that consumer.

It deliberately mirrors the per-account recipient-digest sender
(``web/digest.py``): a 60-second, lease-gated, DB-idempotent tick that fires
each Topic's named digests when the clock crosses their schedule.

What one fire does (``_fire_topic_digest``)
-------------------------------------------
1. **Recipient routing (design §8 R1 — DECIDED).** A Topic aggregates
   accounts. In **HIPAA mode** (system HIPAA OR any selected account is
   HIPAA — most-restrictive, §1a) the digest delivers ONLY **into a
   HIPAA-checked account in the Topic** (so the cross-account aggregate lands
   inside an already-protected mailbox the user manages — intra-entity
   §160.103 *use*, not a PHI egress). With NO eligible HIPAA recipient it
   **fail-closes** (does not send). Non-HIPAA: deliver into the first selected
   account. The deterministic default is the lowest-id eligible account; an
   operator-selectable multi-account dropdown is an additive editor refinement
   (NOT built here — noted, not silently dropped).
2. **Mode → hit set + watermark (design §2).** *Full* = all live hits in the
   retention window. *Differential* = live hits with ``first_seen_at >``
   the per-digest watermark. *Both* renders the Full window and still advances
   the watermark. The watermark advances **transactionally AFTER** a
   successful send (at-least-once, idempotent-by-watermark — a failed send
   re-includes, never silently drops).
3. **Ephemeral render (design §2/§3d).** Per-hit From/Subject/Date are pulled
   at render time via a Message-ID relocation fetch (the durable identity —
   ``provider_uid`` is not stored), **display-then-discard, never stored**,
   **fail-OPEN per hit** (one unreachable Subject degrades only that row). The
   header fetch is **injectable** so the whole sender is testable with no live
   IMAP. Rows render through ``digest_render.render_digest`` (consuming
   ``render_as`` / ``group_by``).
4. **Send** through ``recipient_digest.send_recipient_digest`` with the
   pre-rendered HTML; the recipient address is re-checked against the
   recipient account's own routable addresses (defense-in-depth).
5. **State** advances in ``study_digest_state`` after the send.

HIPAA: the digest body carries PHI-bearing message summaries, but it is
delivered into the user's OWN protected mailbox (R1), the matched "why" is the
user's OWN public Topic terms (R6), and a §164.312(b) access-audit row is
written per send.
"""

from __future__ import annotations

from email_triage.secrets import read_secret

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI

from email_triage._errfmt import fmt_exc
from email_triage.actions.topic_configs import MODES
from email_triage.triage_logging import get_logger
from email_triage.web._audit import safe_audit_write_async
from email_triage._secret_keys import SMTP_PASSWORD_KEY  # N-231 R22 stored-secret-key SSOT

log = get_logger("web.topic_digest_sender")


# ---------------------------------------------------------------------------
# Recipient routing (design §8 R1).
# ---------------------------------------------------------------------------

def _resolve_topic_recipient(
    candidates: list[dict],
    *,
    hipaa_topic: bool,
) -> tuple[dict | None, str]:
    """Pick the account a Topic digest delivers INTO, per R1.

    ``candidates`` are the Topic's selected accounts (already resolved + sorted
    by id for a deterministic default). In a HIPAA Topic the pool is the
    HIPAA-checked accounts only — **fail-closed** (returns ``(None, "")``) when
    none exists, so a protected aggregate is never delivered to an unprotected
    mailbox. Non-HIPAA: any selected account. The recipient address is the
    account's own primary address (so it routes into that mailbox — the
    recipient-mismatch guard the regular digest relies on holds by
    construction).
    """
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import account_addresses, account_email

    pool = (
        [a for a in candidates if is_account_hipaa(a)]
        if hipaa_topic else list(candidates)
    )
    for a in pool:
        addrs = [x for x in account_addresses(a) if x]
        # census run17  — account_email SSOT, not the open-coded key.
        to_addr = (account_email(a) or (addrs[0] if addrs else "")).strip()
        if to_addr:
            return a, to_addr
    return None, ""


# ---------------------------------------------------------------------------
# Ephemeral per-hit header fetch (display-then-discard, fail-OPEN, injectable).
# ---------------------------------------------------------------------------

#: ``async (app, secrets, account, hits) -> dict[rfc822_message_id, meta]``.
#: ``meta`` is ``{"sender": str, "subject": str}``. A hit absent from the
#: returned dict renders as "subject unavailable" (per-hit fail-open).
HeaderFetcher = Callable[[Any, Any, dict, list[dict]], Any]


def _msgid_search_query(provider_type: str, rfc_id: str) -> str:
    """The provider-native search query that locates a message by RFC
    Message-ID (used for the non-IMAP relocation path).

    * **gmail_api** — Gmail's documented ``rfc822msgid:`` operator (passes
      through ``_translate_imap_query`` as a Gmail-shape token).
    * **office365** — a Graph OData filter on ``internetMessageId`` (the
      O365 ``search()`` returns an ``eq``-bearing query verbatim as
      ``$filter``).

    NOTE: the Gmail/O365 branches are built to the documented provider APIs
    but are **not live-verified here** (this environment has no Gmail/O365
    credentials); the IMAP path is the one exercised in production. Per-hit
    fail-OPEN means a wrong/empty result degrades only that row.
    """
    rid = str(rfc_id).strip()
    pt = (provider_type or "").lower()
    if pt == "gmail_api":
        return f"rfc822msgid:{rid}"
    if pt == "office365":
        return "internetMessageId eq '%s'" % rid.replace("'", "")
    return ""


def _norm_msgid(mid: str) -> str:
    """Normalise an RFC 5322 Message-ID for identity comparison: strip
    whitespace + the surrounding angle brackets, casefold. Lets the
    relocated-message identity guard compare the FETCHED Message-ID against the
    matched hit's id without false mismatches on bracket/case/whitespace."""
    # Separate lstrip/rstrip (not strip("<>")) — Message-ID bracket normalization,
    # NOT bare-email-address extraction; matches the per_contact_hipaa idiom the
    # bare-address SSOT pin (test_bare_address_ssot_pin_a7) deliberately exempts.
    return str(mid or "").strip().lstrip("<").rstrip(">").strip().casefold()


async def _relocate_and_fetch_header(
    provider: Any, provider_type: str, rfc_id: str,
) -> dict | None:
    """Locate ONE message by its RFC Message-ID + return From/Subject.

    The hit row stores no usable ``provider_uid`` (the IMAP UID is only valid
    within ``(folder, uidvalidity)`` and is not captured at match time), so the
    durable RFC 5322 Message-ID is the identity. Relocation is provider-aware:

    * **IMAP** — cross-folder ``SEARCH HEADER Message-ID`` (design §2) → a
      ``(folder, uid)`` pair → a headers-ONLY fetch pinned to that folder.
    * **Gmail / O365** — a provider-native message-id ``search()`` →
      message-id → a headers-only fetch (no folder; the API id is global).

    Per-hit fail-OPEN: any miss returns ``None`` and that row degrades to
    "(subject unavailable)" alone — never raises into the batch.
    """
    if not rfc_id:
        return None

    fetch = getattr(provider, "fetch_message", None)
    if fetch is None:
        return None

    folder: str | None = None
    target_id: str | None = None
    via_imap_search = False
    try:
        saf = getattr(provider, "search_all_folders", None)
        if saf is not None:
            via_imap_search = True
            # IMAP — durable Message-ID across folders → (folder, uid).
            # Pass the criteria as the *query* with NO filter. A
            # ``MailFilter`` here is a trap: search_all_folders strips the
            # folder, then routes a non-None filter through
            # ``_translate_filter`` — which, with every other field empty,
            # yields no criteria and collapses to "ALL", returning an
            # ARBITRARY first message. That mis-attribution surfaced a
            # Netflix email under a "Lipodystrophy" topic hit
            # (operator 2026-06-15). search_all_folders is already
            # cross-folder, so no folder filter is needed; the query path
            # (`_translate_query`) passes the HEADER criterion through
            # unchanged.
            criteria = 'HEADER Message-ID "%s"' % str(rfc_id).replace('"', "")
            pairs = await saf(criteria, 1)
            if not pairs:
                return None
            folder, target_id = pairs[0][0], str(pairs[0][1])
        else:
            # Gmail / O365 — provider-native message-id search().
            search = getattr(provider, "search", None)
            query = _msgid_search_query(provider_type, rfc_id)
            if search is None or not query:
                return None
            ids = await search(query, 1)
            if not ids:
                return None
            target_id = str(ids[0])

        try:
            fetched = await fetch(target_id, headers_only=True, folder=folder)
        except TypeError:
            # A provider whose fetch_message lacks headers_only/folder kwargs.
            fetched = await fetch(target_id)
    except Exception:  # noqa: BLE001 — per-hit fail-open
        return None

    headers = getattr(fetched, "headers", None) or {}
    # Identity guard (defence-in-depth behind the query fix above) — assert the
    # relocated message IS the matched hit (incident_2026-06-12 provider_uid
    # trap, generalised: assert the rendered identity). The posture is
    # branch-asymmetric, fail-closed where the risk lives:
    #
    # * IMAP (``via_imap_search``): RFC 3501 ``SEARCH HEADER`` is a SUBSTRING
    #   match, so the relocation can return a *different* message whose
    #   Message-ID merely contains the id — and IMAP was the exact branch the
    #   "ALL"-collapse bug lived in. Require a POSITIVE id match: a relocated
    #   IMAP message that can't prove it's the requested one is dropped to
    #   "(subject unavailable)". Real IMAP fetches always carry a Message-ID, so
    #   this never wrongly drops a legitimate row; an empty-bytes fetch (deleted
    #   between SEARCH and FETCH) has empty subject/sender anyway.
    # * O365 / Gmail: located by a PRECISE server-side id query, and Graph omits
    #   headers unless ``internetMessageHeaders`` was $select-ed — so an ABSENT
    #   id is not evidence of mismatch. Only a POSITIVE mismatch rejects there.
    #
    # Dropping a row is a PD#8-sanctioned non-decisional render degradation,
    # never a security-control fail-open.
    fetched_mid = ""
    if isinstance(headers, dict):
        for _k, _v in headers.items():
            if str(_k).strip().lower() == "message-id":
                fetched_mid = str(_v or "")
                break
    id_matches = bool(fetched_mid) and _norm_msgid(fetched_mid) == _norm_msgid(rfc_id)
    if not id_matches and (fetched_mid or via_imap_search):
        return None
    subject = getattr(fetched, "subject", "") or ""
    sender = getattr(fetched, "sender", "") or ""
    if isinstance(headers, dict):
        subject = subject or headers.get("Subject") or headers.get("subject") or ""
        sender = sender or headers.get("From") or headers.get("from") or ""
    # Send-time backstop: flag email-triage's OWN generated content
    # (X-Email-Triage) so the row builder drops it — catches a hit persisted
    # before the generation-time skip landed (operator 2026-06-12).
    from email_triage.mail_headers import get_triage_header
    self_generated = bool(get_triage_header(headers))
    return {
        "sender": str(sender), "subject": str(subject),
        "self_generated": self_generated,
    }


async def _close_provider(provider: Any) -> None:
    try:
        close = getattr(provider, "close", None)
        if close is not None:
            result = close()
            if asyncio.iscoroutine(result):
                await result
    except Exception:  # noqa: BLE001 — best-effort close
        pass


async def _default_topic_header_fetcher(
    app: Any, secrets: Any, account: dict, hits: list[dict],
) -> dict[str, dict]:
    """Production header fetcher — one provider per account, per-hit fail-open.

    Builds the account's provider once, relocates + fetches each hit's header
    by Message-ID, and returns ``{rfc822_message_id: {sender, subject}}``. A
    build failure or a per-hit miss simply omits that hit (it then renders
    "subject unavailable"). IMAP is fully supported; a provider without
    ``search_all_folders`` yields an empty map (graceful degrade).
    """
    # web.routers.ui is the real export site (triage_runner_bulk only imports
    # this name function-locally — never a module-level attr; see
    # test_infunction_import_resolution_pin). The old triage_runner_bulk import
    # raised ImportError → every scheduled-digest header fetch degraded to
    # "subject unavailable".
    from email_triage.web.routers.ui import _create_provider_from_account

    out: dict[str, dict] = {}
    provider_type = str(account.get("provider_type") or "")
    try:
        provider = _create_provider_from_account(account, secrets)
    except Exception:  # noqa: BLE001 — degrade all this account's rows
        return out
    try:
        for h in hits:
            rfc_id = h.get("rfc822_message_id")
            if not rfc_id:
                continue
            meta = await _relocate_and_fetch_header(
                provider, provider_type, str(rfc_id),
            )
            if meta:
                out[str(rfc_id)] = meta
    finally:
        await _close_provider(provider)
    return out


async def _fetch_headers_for_topic(
    app: Any, secrets: Any, hits: list[dict],
    *, header_fetcher: HeaderFetcher | None,
) -> dict[str, dict]:
    """Resolve display headers for every hit, grouped by account.

    One provider serves all of an account's hits. Per-account fail-OPEN: a
    failure for one account degrades only that account's rows. Returns a merged
    ``{rfc822_message_id: meta}`` map; hits absent from it render degraded.
    """
    from email_triage.web.db import get_email_account
    from email_triage.web.db_threadpool import db_call

    fetcher = header_fetcher or _default_topic_header_fetcher
    by_acct: dict[int, list[dict]] = {}
    for h in hits:
        by_acct.setdefault(int(h["account_id"]), []).append(h)

    metas: dict[str, dict] = {}
    for acct_id, acct_hits in by_acct.items():
        try:
            account = await db_call(get_email_account, app.state.db, acct_id)
            if account is None:
                continue
            got = await fetcher(app, secrets, account, acct_hits)
            if got:
                metas.update(got)
        except Exception as e:  # noqa: BLE001 — degrade this account only
            log.warning(
                "Topic digest: header fetch failed for account",
                account_id=acct_id, error=fmt_exc(e),
            )
    return metas


# ---------------------------------------------------------------------------
# Row + body shaping.
# ---------------------------------------------------------------------------

def _topic_rows_from_hits(
    topic: Any, hits: list[dict], metas: dict[str, dict],
    *, new_since: str | None = None,
) -> list[dict[str, Any]]:
    """Shape live hits + ephemeral headers into ``render_digest`` rows.

    ``category`` = the Topic name (so ``group_by='category'`` groups under the
    Topic); ``reason`` = the matched Topic-terms (the user's OWN public
    Subject/Details words — R6, safe to show); ``date`` = ``first_seen_at`` (a
    reliable ISO stamp; the message's own Date header is not reliably ISO).
    A hit whose header fetch missed renders "(subject unavailable)".

    ``new_since`` (set only for ``mode='both'``) marks the rows whose
    ``first_seen_at`` is past the last-sent watermark — the "new since last"
    set — by prefixing their ``reason`` with ``(new)`` so a Both digest shows
    the full window AND which messages arrived since the previous send (the
    design's two-section value, within one render).
    """
    rows: list[dict[str, Any]] = []
    for h in hits:
        meta = metas.get(str(h.get("rfc822_message_id"))) or {}
        # Backstop (operator 2026-06-12): never render email-triage's OWN
        # generated content in a Topic digest, even if a stale hit row exists.
        if meta.get("self_generated"):
            continue
        terms = h.get("reason_terms") or []
        reason = ", ".join(str(t) for t in terms) if terms else "matched"
        if new_since and (h.get("first_seen_at") or "") > new_since:
            reason = f"(new) {reason}"
        rows.append({
            "sender": str(meta.get("sender") or ""),
            "subject": str(meta.get("subject") or "(subject unavailable)"),
            "date": h.get("first_seen_at") or "",
            "category": topic.name or "(topic)",
            "reason": reason,
            "source": "topic_match",
        })
    return rows


def _plain_body(topic: Any, rows: list[dict]) -> str:
    lines = [
        f"Topic Digest — {topic.name}",
        f"{len(rows)} matched message(s).",
        "",
    ]
    for r in rows:
        lines.append(
            f"- {r['subject']} — {r['sender'] or '(unknown sender)'} "
            f"(matched: {r['reason']})"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fire one Topic digest.
# ---------------------------------------------------------------------------

async def _fire_topic_digest(
    *,
    app: Any, db: Any, secrets: Any, smtp: Any, config: Any,
    topic: Any, digest: Any, now_utc: datetime,
    db_call: Any,
    header_fetcher: HeaderFetcher | None = None,
) -> int:
    """Render + send ONE Topic digest end-to-end; return the row count sent.

    Returns ``0`` when nothing went out — no eligible recipient (incl. the
    HIPAA fail-closed case), an empty window, or SMTP not configured. Raises
    only on a genuine send failure (SMTP), which the loop wraps per-digest so
    one bad fire never aborts the tick.
    """
    from email_triage.actions.digest_configs import DigestConfig
    from email_triage.actions.digest_render import render_digest
    from email_triage.actions.recipient_digest import send_recipient_digest
    from email_triage.actions.topic_configs import (
        TOPIC_MATCH_CONFIDENCE_FLOOR, count_topic_hits_below_floor,
        gather_live_topic_hits, get_topic_digest_state, mark_topic_digest_sent,
    )
    from email_triage.triage_logging import account_hipaa_effective
    from email_triage.web.db import account_addresses, get_email_account

    channel = digest.id or topic.name
    mode = digest.mode if getattr(digest, "mode", "full") in MODES else "full"

    # Resolve the Topic's accounts + HIPAA posture (most-restrictive: ANY
    # HIPAA account pulls the whole Topic to protected — §1a).
    #
    # §5/PD#9 — the SEND is the PHI-egress ACTUATOR. Intersect the Topic's saved
    # ids with the OWNER's CURRENT manageable set so a scheduled digest never
    # aggregates + emails an account the creator can no longer manage (e.g. a
    # delegate revoked AFTER the Topic was saved). Preview + Backscan already
    # intersect on each render; the un-gated send was the asymmetric leak (N-117,
    # devils-advocate). The system loop has no request ``user`` → scope to the
    # Topic owner (``topic.user_id``); fail-closed (owner manages nothing → no
    # candidates → no send).
    from email_triage.web.account_scope import (
        intersect_ids,
        manageable_account_ids,
    )
    _owner_manageable = await db_call(
        manageable_account_ids, db, {"id": topic.user_id},
    )
    _managed_ids = set(
        intersect_ids(topic.selected_account_ids, _owner_manageable)
    )
    candidates: list[dict] = []
    for aid in sorted(_managed_ids):
        a = await db_call(get_email_account, db, aid)
        if a is not None:
            candidates.append(a)
    if not candidates:
        return 0
    hipaa_topic = any(account_hipaa_effective(account=a) for a in candidates)

    recipient, to_addr = _resolve_topic_recipient(
        candidates, hipaa_topic=hipaa_topic,
    )
    if recipient is None or not to_addr:
        log.warning(
            "Topic digest: no eligible recipient; skipping",
            topic_id=topic.id, digest_id=channel, hipaa=hipaa_topic,
            candidates=len(candidates),
        )
        return 0

    # Mode → hit set. Differential restricts to first_seen_at > watermark.
    state = await db_call(get_topic_digest_state, db, topic.id, channel)
    watermark = (state or {}).get("last_sent_watermark")
    retention = int(getattr(topic, "retention_days", 0) or 0)
    since = watermark if mode == "differential" else None

    # Effective per-Topic floor (operator 2026-06-15): a Topic may override the
    # global default ``ET_TOPIC_MATCH_CONFIDENCE_FLOOR``; None inherits it.
    # Resolved ONCE and threaded LOCKSTEP into gather + count + the operator log
    # so the delivered set, the hidden-count, and the logged floor can never
    # disagree (PD#18). gather/count default to the global SSOT, so passing the
    # resolved value explicitly is what makes them per-Topic.
    _topic_floor = getattr(topic, "confidence_floor", None)
    effective_floor = (
        _topic_floor if _topic_floor is not None
        else TOPIC_MATCH_CONFIDENCE_FLOOR
    )

    hits = await db_call(
        gather_live_topic_hits, db, topic.id,
        retention_days=retention, since_watermark=since,
        confidence_floor=effective_floor,
    )
    # §5/PD#9 — the HITS are the PHI content: their headers get fetched from the
    # SOURCE mailbox (``_fetch_headers_for_topic``) and rendered into the emailed
    # digest. ``gather_live_topic_hits`` is TOPIC-wide, so the candidate-account
    # intersection above (which only gates recipient + HIPAA posture) is NOT
    # enough — also drop hits from accounts the OWNER no longer manages, or the
    # actual matched-message content of a now-unmanaged account still egresses.
    # (N-117 — the devils-advocate found the un-gated send; verify-don't-accept on
    # the proposed candidates-only fix found the hits/headers were the real leak.)
    hits = [h for h in hits if int(h["account_id"]) in _managed_ids]

    # Operator visibility for the confidence floor: the floor is reversible but
    # SILENT — surface a count of hits it hides so a genuine-but-weak clinical
    # match is visible. Goes to the operator LOG, never the recipient digest (no
    # admin/tuning copy in user-facing mail).
    suppressed = await db_call(
        count_topic_hits_below_floor, db, topic.id,
        retention_days=retention, since_watermark=since,
        confidence_floor=effective_floor,
    )
    if suppressed:
        log.info(
            "Topic digest: hits hidden below the confidence floor",
            topic_id=topic.id, digest_id=channel,
            suppressed_by_floor=suppressed,
            confidence_floor=effective_floor,
        )
    # Loosening visibility (hipaa/db SME 2026-06-15): a per-Topic floor BELOW the
    # global default SURFACES weak matches the default would hide — and at a low
    # floor ``suppressed`` is ~0, so the line above goes silent exactly when MORE
    # is surfaced. Report against the GLOBAL baseline so loosening a Topic below
    # the default stays visible (the privacy-posture-expanding direction).
    if effective_floor < TOPIC_MATCH_CONFIDENCE_FLOOR:
        would_hide_at_default = await db_call(
            count_topic_hits_below_floor, db, topic.id,
            retention_days=retention, since_watermark=since,
            confidence_floor=TOPIC_MATCH_CONFIDENCE_FLOOR,
        )
        surfaced_below_default = would_hide_at_default - suppressed
        if surfaced_below_default > 0:
            log.info(
                "Topic digest: per-Topic floor below the global default — "
                "surfacing matches the default would hide",
                topic_id=topic.id, digest_id=channel,
                confidence_floor=effective_floor,
                global_default=TOPIC_MATCH_CONFIDENCE_FLOOR,
                surfaced_below_default=surfaced_below_default,
            )

    if not hits:
        # Empty window: stamp last_sent_at (so the same minute-bucket doesn't
        # re-evaluate) but do NOT advance the watermark (nothing was sent).
        await db_call(
            mark_topic_digest_sent, db,
            topic_id=topic.id, channel=channel,
            last_sent_at=now_utc.isoformat(), watermark=None,
        )
        return 0

    if not getattr(smtp, "host", ""):
        log.warning(
            "Topic digest: SMTP not configured; skipping",
            topic_id=topic.id, digest_id=channel,
        )
        return 0

    # Defense-in-depth recipient guard (the address must route into the
    # recipient account — it does, by construction, but a future change to the
    # resolution must not be able to leak to a third party).
    # N-253 R25: canonical-email SSOT — a display-name-wrapped envelope
    # must not slip past the allow-list gate (§164.312(a)(1)).
    from email_triage.mail_headers import canonical_email
    valid = {canonical_email(x) for x in account_addresses(recipient) if x}
    if canonical_email(to_addr) not in valid:
        log.error(
            "Topic digest send refused: recipient mismatch",
            topic_id=topic.id, digest_id=channel, hipaa=hipaa_topic,
        )
        return 0

    # Ephemeral per-hit header fetch (display-then-discard, fail-open).
    metas = await _fetch_headers_for_topic(
        app, secrets, hits, header_fetcher=header_fetcher,
    )
    # Both renders the FULL window but marks the rows new since the watermark
    # (the design's "Full section + new-since-last section" value).
    new_since = watermark if mode == "both" else None
    rows = _topic_rows_from_hits(topic, hits, metas, new_since=new_since)

    cfg = DigestConfig(
        id=str(channel), name=getattr(digest, "name", "") or topic.name,
        enabled=True, schedule=digest.schedule, format=digest.format,
    )
    html_body = render_digest(
        cfg=cfg, rows=rows, account_name=topic.name,
        account_email=to_addr, hipaa=hipaa_topic,
        fallback_dt_iso=now_utc.isoformat(),
    )
    subject = f"Topic Digest — {topic.name} ({len(rows)} matched)"

    smtp_password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
    await asyncio.to_thread(
        send_recipient_digest,
        smtp_host=smtp.host, smtp_port=smtp.port, smtp_user=smtp.username,
        smtp_password=smtp_password, from_addr=smtp.from_addr,
        from_name=smtp.from_name, to_addr=to_addr,
        account_name=recipient.get("name", ""), rows=rows, hipaa=hipaa_topic,
        use_tls=smtp.use_tls, fallback_dt_iso=now_utc.isoformat(),
        html_body_override=html_body,
        plain_body_override=_plain_body(topic, rows),
        subject_override=subject,
    )

    # Advance state AFTER the successful send. For Full there is no content
    # watermark (it sends the whole window every time); Differential/Both
    # advance to the newest first_seen_at sent (hits are newest-first).
    new_watermark = None if mode == "full" else hits[0]["first_seen_at"]
    try:
        await db_call(
            mark_topic_digest_sent, db,
            topic_id=topic.id, channel=channel,
            last_sent_at=now_utc.isoformat(), watermark=new_watermark,
        )
    except Exception as e:  # noqa: BLE001 — a successful send must not look failed
        log.warning(
            "Topic digest: mark_sent failed",
            topic_id=topic.id, digest_id=channel, error=fmt_exc(e),
        )

    # §164.312(b) audit. The PHI-bearing aggregate spans several source
    # accounts (most-restrictive — feedback_most_restrictive_wins), so the
    # detail carries the contributing account ids for provenance.
    src_accts = sorted({int(h["account_id"]) for h in hits})

    # CANONICAL PHI-access control: a HIPAA delivery writes hipaa_access_events
    # (system actor), mirroring the recipient-digest path (actions/digest.py).
    # access_log alone is the route-shape sibling, NOT the PHI-access control
    # the §164.312(b) reconciliation reads. detail here is NEVER PHI and never
    # the recipient address (db/audit contract — account_id is the column).
    if hipaa_topic:
        try:
            from email_triage.db.audit import record_hipaa_access_event
            await safe_audit_write_async(
                lambda: db_call(
                    record_hipaa_access_event, db,
                    None,                                   # system-initiated send
                    int(recipient.get("id") or 0),
                    "topic_digest_sent", "ok",
                    (
                        f"topic_id={topic.id} digest={channel} mode={mode} "
                        f"rows={len(rows)} src_accts={src_accts}"
                    ),
                ),
                description=f"topic_digest_sent hipaa_access topic_id={topic.id} digest={channel}",
            )
        except Exception as e:  # noqa: BLE001 — audit failure must not fail send
            log.warning(
                "Topic digest: hipaa_access_events write failed",
                topic_id=topic.id, digest_id=channel, error=fmt_exc(e),
            )

    # Route-shape sibling (access_log) — written for every send, HIPAA or not.
    try:
        from email_triage.web.db import record_access_event
        await safe_audit_write_async(
            lambda: db_call(
                record_access_event, db,
                actor_user_id=None, method="POST", route="/internal/topic-digest",
                account_id=recipient.get("id"), message_id=None, status_code=200,
                outcome="topic_digest_sent",
                detail=(
                    f"topic_id={topic.id} digest={channel} mode={mode} "
                    f"rows={len(rows)} hipaa={hipaa_topic} src_accts={src_accts} "
                    f"to={to_addr}"
                ),
            ),
            description=f"topic_digest_sent access_log topic_id={topic.id} digest={channel}",
        )
    except Exception as e:  # noqa: BLE001 — audit failure must not fail the send
        log.warning(
            "Topic digest: access_log write failed",
            topic_id=topic.id, digest_id=channel, error=fmt_exc(e),
        )

    log.info(
        "Topic digest sent",
        topic_id=topic.id, digest_id=channel, mode=mode,
        rows=len(rows), hipaa=hipaa_topic,
    )
    return len(rows)


# ---------------------------------------------------------------------------
# The scheduler loop.
# ---------------------------------------------------------------------------

async def _topic_digest_sender(app: FastAPI) -> None:
    """Tick every 60s; fire each Topic's enabled digests on schedule.

    Lease-gated (one instance fires) with DB-backed per-digest idempotence
    (``study_digest_state`` keyed by the digest id), so correctness holds even
    if leadership moves between instances — the same shape the recipient-digest
    sender uses.
    """
    from email_triage.actions.digest_configs import DigestConfig
    from email_triage.actions.digest_filter import digest_should_fire
    from email_triage.actions.topic_configs import (
        get_topic_digest_state, list_all_active_topics,
    )
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.task_supervisor import supervised_interval_loop

    async def _tick() -> None:
        cfg = app.state.config
        db = app.state.db
        secrets = app.state.secrets
        smtp = cfg.smtp
        now_local = datetime.now().astimezone()
        now_utc = datetime.now(timezone.utc)
        # N-227c R22 — heartbeat stamp for /admin observability.
        app.state.topic_digest_sender_status = {"at": now_local.isoformat()}

        try:
            topics = await db_call(list_all_active_topics, db)
        except Exception as e:  # noqa: BLE001 — a bad read must not kill the loop
            log.warning("Topic digest sender: list topics failed", error=fmt_exc(e))
            return

        for topic in topics:
            for digest in (topic.digests or []):
                if not getattr(digest, "enabled", True):
                    continue
                channel = digest.id or topic.name
                state = await db_call(get_topic_digest_state, db, topic.id, channel)
                last_sent = (state or {}).get("last_sent_at")
                should_cfg = DigestConfig(
                    id=str(channel), name=getattr(digest, "name", "") or topic.name,
                    enabled=getattr(digest, "enabled", True),
                    schedule=digest.schedule, format=digest.format,
                )
                if not digest_should_fire(
                    should_cfg, last_sent_iso=last_sent, now_local=now_local,
                ):
                    continue
                try:
                    await _fire_topic_digest(
                        app=app, db=db, secrets=secrets, smtp=smtp, config=cfg,
                        topic=topic, digest=digest, now_utc=now_utc,
                        db_call=db_call,
                    )
                except Exception as e:
                    # Per-digest isolation: one bad fire never aborts the tick.
                    log.error(
                        "Topic digest fire failed",
                        topic_id=topic.id, digest_id=channel, error=fmt_exc(e),
                    )

    await supervised_interval_loop(
        "topic-digest-sender", 60, _tick,
        warmup_secs=15,
        startup_jitter_secs=30.0,
        lease_name="topic-digest-sender",
        lease_conn=app.state.db,
    )


__all__ = [
    "_topic_digest_sender",
    "_fire_topic_digest",
]
