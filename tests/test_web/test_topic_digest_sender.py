""" — the scheduled Topic-digest sender (the output spine).

Drives ``_fire_topic_digest`` end-to-end with the SMTP send + the ephemeral
header fetch injected/stubbed (no live IMAP, no live SMTP), asserting the
load-bearing behaviours:

* a Full digest sends every live hit and does NOT advance the watermark;
* a Differential digest sends only hits newer than the watermark and advances
  it (so the next fire is empty);
* an empty window does not send but stamps ``last_sent_at`` (schedule
  idempotence);
* **R1 HIPAA routing**: a HIPAA Topic delivers into its HIPAA account, and a
  HIPAA Topic whose only protected account has no routable address
  **fail-closes** (it must NOT fall through to a non-protected account);
* the send carries the matched terms as the why-matched, the recipient guard
  holds, and a §164.312(b) audit row is written.
"""

from __future__ import annotations
from _db_tracking import track

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from email_triage.actions import topic_configs as tc
from email_triage.web.db import init_db, get_email_account
from email_triage.web import topic_digest_sender as tds


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def conn() -> sqlite3.Connection:
    c = track(init_db(":memory:"))
    yield c
    c.close()


def _mk_user(conn) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('op@x.com','Op','user',?)", (now,),
    )
    conn.commit()
    return int(cur.lastrowid)


def _mk_account(conn, uid, *, email, hipaa=0) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cfg = json.dumps({"email_address": email}) if email else "{}"
    cur = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (uid, "Mailbox", "imap", cfg, int(hipaa), now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _mk_topic(conn, uid, account_ids, *, mode="full", retention_days=0):
    digest = tc.TopicDigest(
        id="tdig_abc", name="D", enabled=True, mode=mode,
        schedule=tc.DigestSchedule(), format=tc.DigestFormat(render_as="plain_list"),
    )
    return tc.upsert_topic(conn, tc.TopicConfig(
        user_id=uid, name="Lupus", subjects=["lupus"],
        details="Safety of Estrogens in Lupus",
        selected_account_ids=[int(a) for a in account_ids],
        retention_days=retention_days, enabled=True, digests=[digest],
    ))


def _add_hit(conn, topic_id, account_id, rfc_id, *, seen_at, terms=("lupus",)):
    tc.insert_topic_hit(
        conn, topic_id=int(topic_id), account_id=int(account_id),
        rfc822_message_id=rfc_id, reason_terms=list(terms),
        confidence=0.9, source="live", seen_at=seen_at,
    )


async def _passthrough_db_call(fn, *a, **k):
    return fn(*a, **k)


def _fake_app(conn):
    return SimpleNamespace(state=SimpleNamespace(
        db=conn, secrets=_FakeSecrets(), config=_fake_config(),
    ))


class _FakeSecrets:
    def get(self, key, default=None):
        return "pw" if key == "SMTP_PASSWORD" else default


def _fake_config():
    return SimpleNamespace(smtp=_fake_smtp())


def _fake_smtp():
    return SimpleNamespace(
        host="smtp.invalid", port=25, username="u", from_addr="triage@x.com",
        from_name="Triage", use_tls=False,
    )


async def _stub_header_fetcher(app, secrets, account, hits):
    """Return a subject/sender per hit — no IMAP."""
    return {
        h["rfc822_message_id"]: {
            "sender": "alice@example.com",
            "subject": f"re {h['rfc822_message_id']}",
        }
        for h in hits
    }


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@pytest.fixture
def captured_send(monkeypatch):
    """Capture send_recipient_digest calls instead of hitting SMTP."""
    sent: list[dict] = []

    def _fake_send(**kw):
        sent.append(kw)

    monkeypatch.setattr(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        _fake_send,
    )
    return sent


async def _fire(conn, topic, *, header_fetcher=_stub_header_fetcher):
    digest = topic.digests[0]
    app = _fake_app(conn)
    return await tds._fire_topic_digest(
        app=app, db=conn, secrets=app.state.secrets, smtp=_fake_smtp(),
        config=app.state.config, topic=topic, digest=digest,
        now_utc=datetime.now(timezone.utc), db_call=_passthrough_db_call,
        header_fetcher=header_fetcher,
    )


# ---------------------------------------------------------------------------
# Full mode
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_sends_all_and_keeps_watermark(conn, captured_send):
    uid = _mk_user(conn)
    acct = _mk_account(conn, uid, email="clinic@x.com")
    topic = _mk_topic(conn, uid, [acct], mode="full")
    base = datetime.now(timezone.utc) - timedelta(hours=2)
    _add_hit(conn, topic.id, acct, "<a@x>", seen_at=_iso(base))
    _add_hit(conn, topic.id, acct, "<b@x>", seen_at=_iso(base + timedelta(minutes=5)))

    n = await _fire(conn, topic)

    assert n == 2
    assert len(captured_send) == 1
    call = captured_send[0]
    assert call["to_addr"] == "clinic@x.com"
    assert call["hipaa"] is False
    assert call["html_body_override"]                      # rendered HTML
    assert len(call["rows"]) == 2
    # matched terms surface as the why-matched.
    assert any("lupus" in (r.get("reason") or "") for r in call["rows"])

    # Full does NOT advance the differential watermark; last_sent_at IS set.
    state = tc.get_topic_digest_state(conn, topic.id, "tdig_abc")
    assert state["last_sent_watermark"] is None
    assert state["last_sent_at"]

    # §164.312(b) audit row written (access_log).
    row = conn.execute(
        "SELECT outcome FROM access_log WHERE outcome='topic_digest_sent'"
    ).fetchone()
    assert row is not None


# ---------------------------------------------------------------------------
# Differential mode
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_differential_sends_only_new_then_advances(conn, captured_send):
    uid = _mk_user(conn)
    acct = _mk_account(conn, uid, email="clinic@x.com")
    topic = _mk_topic(conn, uid, [acct], mode="differential")
    t0 = datetime.now(timezone.utc) - timedelta(hours=3)
    _add_hit(conn, topic.id, acct, "<old@x>", seen_at=_iso(t0))
    # Pretend a prior send already covered <old@x>: watermark = t0.
    tc.mark_topic_digest_sent(
        conn, topic_id=topic.id, channel="tdig_abc",
        last_sent_at=_iso(t0), watermark=_iso(t0),
    )
    # A new hit arrives AFTER the watermark.
    t1 = t0 + timedelta(hours=1)
    _add_hit(conn, topic.id, acct, "<new@x>", seen_at=_iso(t1))

    n = await _fire(conn, topic)

    assert n == 1                                  # only the new hit
    assert len(captured_send) == 1
    rfcs = {r["subject"] for r in captured_send[0]["rows"]}
    assert "re <new@x>" in rfcs and "re <old@x>" not in rfcs
    # Watermark advanced to the newest sent hit.
    state = tc.get_topic_digest_state(conn, topic.id, "tdig_abc")
    assert state["last_sent_watermark"] == _iso(t1)

    # A second fire immediately has nothing new → no send.
    captured_send.clear()
    n2 = await _fire(conn, topic)
    assert n2 == 0
    assert captured_send == []


# ---------------------------------------------------------------------------
# Both mode — full window, new-since-watermark rows marked
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_both_renders_full_and_marks_new(conn, captured_send):
    uid = _mk_user(conn)
    acct = _mk_account(conn, uid, email="clinic@x.com")
    topic = _mk_topic(conn, uid, [acct], mode="both")
    t0 = datetime.now(timezone.utc) - timedelta(hours=3)
    _add_hit(conn, topic.id, acct, "<old@x>", seen_at=_iso(t0))
    tc.mark_topic_digest_sent(
        conn, topic_id=topic.id, channel="tdig_abc",
        last_sent_at=_iso(t0), watermark=_iso(t0),
    )
    t1 = t0 + timedelta(hours=1)
    _add_hit(conn, topic.id, acct, "<new@x>", seen_at=_iso(t1))

    n = await _fire(conn, topic)

    assert n == 2                                  # FULL window (both hits)
    rows = {r["subject"]: r["reason"] for r in captured_send[0]["rows"]}
    assert rows["re <new@x>"].startswith("(new)")  # new since watermark, marked
    assert not rows["re <old@x>"].startswith("(new)")
    # Both advances the watermark to the newest.
    state = tc.get_topic_digest_state(conn, topic.id, "tdig_abc")
    assert state["last_sent_watermark"] == _iso(t1)


# ---------------------------------------------------------------------------
# Empty window
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_empty_window_no_send_but_stamps(conn, captured_send):
    uid = _mk_user(conn)
    acct = _mk_account(conn, uid, email="clinic@x.com")
    topic = _mk_topic(conn, uid, [acct], mode="full")
    # No hits.
    n = await _fire(conn, topic)
    assert n == 0
    assert captured_send == []
    state = tc.get_topic_digest_state(conn, topic.id, "tdig_abc")
    assert state is not None and state["last_sent_at"]   # schedule marker stamped


# ---------------------------------------------------------------------------
# R1 HIPAA routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hipaa_topic_delivers_into_hipaa_account(conn, captured_send):
    uid = _mk_user(conn)
    plain = _mk_account(conn, uid, email="open@x.com", hipaa=0)
    protected = _mk_account(conn, uid, email="clinic@x.com", hipaa=1)
    topic = _mk_topic(conn, uid, [plain, protected], mode="full")
    base = datetime.now(timezone.utc) - timedelta(hours=1)
    _add_hit(conn, topic.id, plain, "<a@x>", seen_at=_iso(base))

    n = await _fire(conn, topic)

    assert n == 1
    assert len(captured_send) == 1
    # R1: delivered INTO the HIPAA account, not the open one.
    assert captured_send[0]["to_addr"] == "clinic@x.com"
    assert captured_send[0]["hipaa"] is True
    # B-1: the canonical §164.312(b) PHI-access row is written for a HIPAA send.
    hev = conn.execute(
        "SELECT account_id, operation FROM hipaa_access_events "
        "WHERE operation='topic_digest_sent'"
    ).fetchone()
    assert hev is not None
    assert hev["account_id"] == protected        # audited against the recipient


@pytest.mark.asyncio
async def test_hipaa_topic_no_addressable_protected_recipient_fail_closed(
    conn, captured_send,
):
    """A HIPAA Topic whose only protected account has NO routable address must
    fail-closed — it must NOT fall through and deliver the protected aggregate
    to the non-protected account."""
    uid = _mk_user(conn)
    protected = _mk_account(conn, uid, email="", hipaa=1)      # no address
    plain = _mk_account(conn, uid, email="open@x.com", hipaa=0)
    topic = _mk_topic(conn, uid, [protected, plain], mode="full")
    base = datetime.now(timezone.utc) - timedelta(hours=1)
    _add_hit(conn, topic.id, plain, "<a@x>", seen_at=_iso(base))

    n = await _fire(conn, topic)

    assert n == 0
    assert captured_send == []        # nothing delivered — not to the open acct


# ---------------------------------------------------------------------------
# Header-fetch fail-open
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_header_fetch_failure_degrades_rows_not_send(conn, captured_send):
    """When the ephemeral header fetch yields nothing, rows degrade to
    'subject unavailable' but the digest still sends (fail-open)."""
    uid = _mk_user(conn)
    acct = _mk_account(conn, uid, email="clinic@x.com")
    topic = _mk_topic(conn, uid, [acct], mode="full")
    base = datetime.now(timezone.utc) - timedelta(hours=1)
    _add_hit(conn, topic.id, acct, "<a@x>", seen_at=_iso(base))

    async def _empty_fetcher(app, secrets, account, hits):
        return {}

    n = await _fire(conn, topic, header_fetcher=_empty_fetcher)

    assert n == 1
    assert len(captured_send) == 1
    assert captured_send[0]["rows"][0]["subject"] == "(subject unavailable)"


@pytest.mark.asyncio
async def test_send_excludes_account_owner_no_longer_manages(conn, captured_send):
    """N-117 — the SEND is the PHI-egress ACTUATOR (devils-advocate finding).

    A Topic whose saved ``selected_account_ids`` includes an account the OWNER no
    longer manages (e.g. a delegate revoked AFTER the Topic was saved) must NOT
    have that account's matched-message PHI fetched + emailed. Preview + Backscan
    already intersect; the un-gated send was the asymmetric leak. The fix filters
    BOTH the candidate accounts (recipient + HIPAA posture) AND the rendered hits
    to the owner's CURRENT manageable set — ``gather_live_topic_hits`` is
    topic-wide, so the candidate filter ALONE would still egress the content
    (verify-don't-accept on the proposed candidates-only fix caught this).
    """
    uid = _mk_user(conn)
    owned = _mk_account(conn, uid, email="mine@x.com")
    # A 2nd user's account: uid is neither owner nor delegate → NOT in uid's
    # manageable set (the post-revocation state). Flag it HIPAA so that, were it
    # NOT excluded, the whole Topic would go protected — an observable tell.
    other = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('other@x.com','Other','user',?)",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.commit()
    unmanaged = _mk_account(
        conn, int(other.lastrowid), email="theirs@x.com", hipaa=1,
    )
    topic = _mk_topic(conn, uid, [owned, unmanaged], mode="full")
    base = datetime.now(timezone.utc) - timedelta(hours=2)
    _add_hit(conn, topic.id, owned, "<a@x>", seen_at=_iso(base))
    _add_hit(
        conn, topic.id, unmanaged, "<b@x>",
        seen_at=_iso(base + timedelta(minutes=1)),
    )

    n = await _fire(conn, topic)

    assert len(captured_send) == 1
    call = captured_send[0]
    # Recipient is the owner's managed account, never the unmanaged one.
    assert call["to_addr"] == "mine@x.com"
    # The unmanaged account is HIPAA — were it not excluded from candidates the
    # digest would be protected. Excluded → non-protected.
    assert call["hipaa"] is False
    # The hits filter dropped the unmanaged account's matched message: only the
    # owned account's single hit is rendered + counted, and the unmanaged rfc
    # (<b@x>) never reaches a rendered row (no mailbox header fetch from it).
    assert n == 1
    assert len(call["rows"]) == 1
    assert all(
        "<b@x>" not in str(r.get("subject") or "") for r in call["rows"]
    ), "an unmanaged account's matched message leaked into the digest"


# ---------------------------------------------------------------------------
# State + gather helpers (unit)
# ---------------------------------------------------------------------------

def test_gather_respects_retention_and_watermark(conn):
    uid = _mk_user(conn)
    acct = _mk_account(conn, uid, email="clinic@x.com")
    topic = _mk_topic(conn, uid, [acct], mode="full", retention_days=30)
    now = datetime.now(timezone.utc)
    _add_hit(conn, topic.id, acct, "<old@x>", seen_at=_iso(now - timedelta(days=60)))
    _add_hit(conn, topic.id, acct, "<recent@x>", seen_at=_iso(now - timedelta(days=1)))

    # Retention=30 drops the 60-day-old hit.
    rows = tc.gather_live_topic_hits(conn, topic.id, retention_days=30)
    assert {r["rfc822_message_id"] for r in rows} == {"<recent@x>"}

    # No retention bound → both.
    rows_all = tc.gather_live_topic_hits(conn, topic.id, retention_days=0)
    assert len(rows_all) == 2

    # Watermark excludes hits at/older than the cursor.
    wm = _iso(now - timedelta(days=2))
    rows_wm = tc.gather_live_topic_hits(conn, topic.id, since_watermark=wm)
    assert {r["rfc822_message_id"] for r in rows_wm} == {"<recent@x>"}


# ---------------------------------------------------------------------------
# The PRODUCTION header-fetch seam (driven for real, not the injected stub)
# ---------------------------------------------------------------------------

class _FakeImapProvider:
    """IMAP-shape provider: has search_all_folders → (folder, uid).

    Echoes a Message-ID in the fetched headers (every real IMAP message carries
    one) so the IMAP fail-closed identity guard can positively confirm identity;
    ``msgid`` defaults to the id the relocate tests query."""
    def __init__(self, *, subject="re lupus", sender="a@x.com", found=True,
                 msgid="<m@x>"):
        self.searched: list[str] = []
        self._subject, self._sender, self._found = subject, sender, found
        self._msgid = msgid

    async def search_all_folders(self, criteria, limit, *, filter=None):
        self.searched.append(criteria)
        return [("INBOX", "42")] if self._found else []

    async def fetch_message(self, uid, *, headers_only=False, folder=None):
        return SimpleNamespace(
            headers={"Message-ID": self._msgid},
            subject=self._subject, sender=self._sender,
        )


class _FakeApiProvider:
    """Gmail/O365-shape provider: search() returns ids, NO search_all_folders."""
    def __init__(self, *, subject="re hi", sender="a@x.com", found=True):
        self.queries: list[str] = []
        self._subject, self._sender, self._found = subject, sender, found

    async def search(self, query, limit=50):
        self.queries.append(query)
        return ["api-msgid-1"] if self._found else []

    async def fetch_message(self, mid, *, headers_only=False, folder=None):
        return SimpleNamespace(headers={}, subject=self._subject, sender=self._sender)


@pytest.mark.asyncio
async def test_relocate_imap_resolves_subject():
    p = _FakeImapProvider(subject="re lupus", sender="a@x.com")
    meta = await tds._relocate_and_fetch_header(p, "imap", "<m@x>")
    # meta now also carries ``self_generated`` (the X-Email-Triage backstop);
    # this fixture's message isn't email-triage-generated, so it's False.
    assert meta == {
        "sender": "a@x.com", "subject": "re lupus", "self_generated": False,
    }
    assert 'HEADER Message-ID "<m@x>"' in p.searched[0]


@pytest.mark.asyncio
async def test_relocate_gmail_uses_rfc822msgid():
    p = _FakeApiProvider(subject="re g")
    meta = await tds._relocate_and_fetch_header(p, "gmail_api", "<m@x>")
    assert meta["subject"] == "re g"
    assert p.queries == ["rfc822msgid:<m@x>"]      # Gmail's documented operator


@pytest.mark.asyncio
async def test_relocate_o365_uses_internetmessageid():
    p = _FakeApiProvider(subject="re o")
    meta = await tds._relocate_and_fetch_header(p, "office365", "<m@x>")
    assert meta["subject"] == "re o"
    assert p.queries == ["internetMessageId eq '<m@x>'"]   # Graph OData filter


@pytest.mark.asyncio
async def test_relocate_unknown_provider_degrades_without_searching():
    p = _FakeApiProvider()
    meta = await tds._relocate_and_fetch_header(p, "weirdmail", "<m@x>")
    assert meta is None
    assert p.queries == []           # no recognized query → never searched


@pytest.mark.asyncio
async def test_relocate_no_match_degrades_to_none():
    p = _FakeApiProvider(found=False)
    meta = await tds._relocate_and_fetch_header(p, "gmail_api", "<m@x>")
    assert meta is None              # per-hit fail-open: this row degrades


# ---------------------------------------------------------------------------
# Fix #1 (operator 2026-06-15): the relocation must use the Message-ID QUERY,
# never a folder filter — a folder filter collapses the real search_all_folders
# to "ALL" and returns an ARBITRARY message (the Netflix-on-Lipodystrophy
# mis-attribution). Plus a fail-soft identity guard: a relocated message whose
# Message-ID does not match the matched hit's id is dropped, never rendered with
# a foreign sender/subject.
# ---------------------------------------------------------------------------

class _RealContractImapProvider:
    """IMAP fake that MODELS the real search_all_folders contract: a non-None
    folder filter OVERRIDES the query → an arbitrary first message (prod's
    collapse-to-ALL). Only a query-driven call (filter=None) resolves the
    requested Message-ID. fetch_message echoes the resolved uid's Message-ID so
    the identity guard has a real id to compare — mocking the boundary's
    BEHAVIOUR, not just recording the call (the trap the old fake fell into)."""

    def __init__(self, requested_mid: str):
        self._req = requested_mid
        self.filter_seen = "UNSET"

    async def search_all_folders(self, criteria, limit, *, filter=None):
        self.filter_seen = filter
        if filter is not None and getattr(filter, "folder", None):
            return [("INBOX", "999")]          # query dropped → arbitrary msg
        return [("INBOX", "42")]               # query honoured → requested msg

    async def fetch_message(self, uid, *, headers_only=False, folder=None):
        if uid == "42":
            return SimpleNamespace(
                headers={"Message-ID": self._req},
                subject="right subject", sender="pi@trial.org",
            )
        return SimpleNamespace(
            headers={"Message-ID": "<arbitrary-netflix@x>"},
            subject="WRONG netflix promo", sender="info@netflix.com",
        )


@pytest.mark.asyncio
async def test_relocate_imap_uses_query_no_filter_resolves_requested():
    """Regression pin for the primary Fix #1: the caller passes NO folder filter,
    so the real seam honours the Message-ID query and resolves the REQUESTED
    message (re-adding a filter would return the arbitrary one, which the guard
    then rejects to None → this assertion fails either way)."""
    p = _RealContractImapProvider("<m@x>")
    meta = await tds._relocate_and_fetch_header(p, "imap", "<m@x>")
    assert meta is not None and meta["subject"] == "right subject"
    assert p.filter_seen is None        # the call carried NO folder filter


@pytest.mark.asyncio
async def test_relocate_imap_identity_mismatch_degrades_to_none():
    """The fail-soft guard: a relocated message whose Message-ID differs from the
    matched hit's id is dropped (None), never rendered with a foreign identity."""
    class _WrongMsg(_FakeImapProvider):
        async def fetch_message(self, uid, *, headers_only=False, folder=None):
            return SimpleNamespace(
                headers={"Message-ID": "<someone-else@x>"},
                subject="not yours", sender="evil@x",
            )

    p = _WrongMsg()
    meta = await tds._relocate_and_fetch_header(p, "imap", "<m@x>")
    assert meta is None


@pytest.mark.asyncio
async def test_relocate_imap_identity_match_tolerates_brackets_and_case():
    """A genuine match differing only in angle brackets / case / whitespace is
    NOT a mismatch — the guard normalises before comparing."""
    class _BracketCaseMsg(_FakeImapProvider):
        async def fetch_message(self, uid, *, headers_only=False, folder=None):
            return SimpleNamespace(
                headers={"Message-Id": "  M@X  "},   # no brackets, upper, spaces
                subject="re lupus", sender="a@x.com",
            )

    p = _BracketCaseMsg()
    meta = await tds._relocate_and_fetch_header(p, "imap", "<m@x>")
    assert meta is not None and meta["subject"] == "re lupus"


@pytest.mark.asyncio
async def test_relocate_imap_absent_message_id_fails_closed():
    """IMAP branch is FAIL-CLOSED: a relocated message with NO Message-ID in its
    headers can't prove identity (RFC 3501 HEADER search is a substring match,
    and IMAP is the branch the ALL-collapse bug lived in) → dropped to None."""
    class _NoMsgId(_FakeImapProvider):
        async def fetch_message(self, uid, *, headers_only=False, folder=None):
            return SimpleNamespace(headers={}, subject="ambiguous", sender="a@x")

    p = _NoMsgId()
    meta = await tds._relocate_and_fetch_header(p, "imap", "<m@x>")
    assert meta is None


@pytest.mark.asyncio
async def test_relocate_o365_absent_message_id_fails_open():
    """O365/Gmail branch is FAIL-OPEN on an absent Message-ID: it located the
    message by a precise server-side id query, and Graph omits headers unless
    internetMessageHeaders was $select-ed — so absence is not a mismatch."""
    p = _FakeApiProvider(subject="re o")          # fetch returns headers={}
    meta = await tds._relocate_and_fetch_header(p, "office365", "<m@x>")
    assert meta is not None and meta["subject"] == "re o"


def test_norm_msgid_normalises_brackets_case_whitespace():
    assert tds._norm_msgid("<M@X>") == tds._norm_msgid("  m@x ")
    assert tds._norm_msgid("<a@b>") != tds._norm_msgid("<c@d>")
    assert tds._norm_msgid("") == ""
    assert tds._norm_msgid(None) == ""


@pytest.mark.asyncio
async def test_differential_watermark_boundary_no_duplicate(conn, captured_send):
    """A hit whose first_seen_at == the watermark is NOT re-sent (strict >),
    so the newest-sent hit never duplicates on the next fire. (Distinct
    per-hit `_now_iso()` stamps make exact ties across messages a non-issue;
    a composite (first_seen, id) cursor is a noted future enhancement.)"""
    uid = _mk_user(conn)
    acct = _mk_account(conn, uid, email="clinic@x.com")
    topic = _mk_topic(conn, uid, [acct], mode="differential")
    t = datetime.now(timezone.utc) - timedelta(hours=1)
    _add_hit(conn, topic.id, acct, "<m@x>", seen_at=_iso(t))

    assert await _fire(conn, topic) == 1
    state = tc.get_topic_digest_state(conn, topic.id, "tdig_abc")
    assert state["last_sent_watermark"] == _iso(t)

    captured_send.clear()
    assert await _fire(conn, topic) == 0     # boundary hit not re-sent
    assert captured_send == []


def test_mark_sent_full_preserves_watermark(conn):
    uid = _mk_user(conn)
    acct = _mk_account(conn, uid, email="clinic@x.com")
    topic = _mk_topic(conn, uid, [acct])
    # First, a differential send sets a watermark.
    tc.mark_topic_digest_sent(
        conn, topic_id=topic.id, channel="tdig_abc",
        last_sent_at="2026-01-01T00:00:00+00:00",
        watermark="2026-01-01T00:00:00+00:00",
    )
    # A later Full send passes watermark=None — it must NOT clobber the cursor.
    tc.mark_topic_digest_sent(
        conn, topic_id=topic.id, channel="tdig_abc",
        last_sent_at="2026-02-01T00:00:00+00:00", watermark=None,
    )
    state = tc.get_topic_digest_state(conn, topic.id, "tdig_abc")
    assert state["last_sent_watermark"] == "2026-01-01T00:00:00+00:00"
    assert state["last_sent_at"] == "2026-02-01T00:00:00+00:00"
