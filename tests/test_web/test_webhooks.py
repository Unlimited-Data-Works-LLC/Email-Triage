"""Tests for webhook receiver endpoints.

Gmail Pub/Sub deliveries must carry a Google-signed JWT in the
Authorization header.  The happy-path tests mint their own RS256
tokens with a local RSA keypair, then stub the cert cache's
``get_key`` so the webhook accepts our test-only public key.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from email_triage.web.db import upsert_gmail_watch


# ---------------------------------------------------------------------------
# JWT helpers (test-only)
# ---------------------------------------------------------------------------

_KEY_CACHE: dict[str, object] = {}


def _rsa_keypair():
    if "priv" not in _KEY_CACHE:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _KEY_CACHE["priv"] = priv
        _KEY_CACHE["pub"] = priv.public_key()
    return _KEY_CACHE["priv"], _KEY_CACHE["pub"]


def _make_jwt(
    *,
    audience: str = "https://test.example.invalid/webhooks/gmail",
    issuer: str = "https://accounts.google.com",
    email: str = "pubsub-push@project.iam.gserviceaccount.com",
    email_verified: bool = True,
    kid: str = "test-kid",
    expires_in: int = 600,
    now: int | None = None,
) -> str:
    priv, _ = _rsa_keypair()
    now = int(now if now is not None else time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "email": email,
        "email_verified": email_verified,
        "iat": now,
        "exp": now + expires_in,
        "sub": "1234567890",
    }
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def stub_cert_cache():
    """Replace the cert cache on the app with one that hands out our public key."""
    from email_triage.web.gmail_push_auth import _CertCache

    _, pub = _rsa_keypair()

    class _StubCache(_CertCache):
        async def get_key(self, kid: str):
            return pub

        async def _refresh(self):
            pass

    return _StubCache()


@pytest.fixture
def push_app(client, stub_cert_cache):
    """Configure push config on the shared test app and seed cert cache."""
    app = client.app
    app.state.config.push.gmail_subscription_sa_email = (
        "pubsub-push@project.iam.gserviceaccount.com"
    )
    app.state.config.push.gmail_audience = "https://test.example.invalid/webhooks/gmail"
    app.state.config.push.public_url = "https://test.example.invalid"
    app.state._gmail_cert_cache = stub_cert_cache
    app.state.push_queue = asyncio.Queue(maxsize=4)
    app.state.metrics = {}
    yield app


def _push_payload(email: str, history_id: int) -> dict:
    data = base64.b64encode(
        json.dumps({"emailAddress": email, "historyId": history_id}).encode()
    ).decode()
    return {
        "message": {"data": data, "messageId": "msg-1"},
        "subscription": "projects/test/subscriptions/gmail-push",
    }


def _seed_watch(db, email="user@gmail.com", account_id=1, history_id="10"):
    # We bypass email_accounts FK by inserting a parent row first.
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT OR IGNORE INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
        "VALUES (?, 1, 'Test Gmail', 'gmail_api', ?, ?, ?)",
        (account_id, json.dumps({"account": email}), now, now),
    )
    db.commit()
    upsert_gmail_watch(
        db,
        account_id=account_id,
        email_address=email,
        topic_name="projects/test/topics/gmail-push",
        history_id=history_id,
        expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    )


# ---------------------------------------------------------------------------
# Gmail push endpoint
# ---------------------------------------------------------------------------


class TestGmailPushVerification:
    def test_happy_path_queues(self, push_app, client, db, admin_user):
        _seed_watch(db, email="user@gmail.com", account_id=1)
        token = _make_jwt()
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("user@gmail.com", 12345),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "queued"
        assert push_app.state.push_queue.qsize() == 1
        item = push_app.state.push_queue.get_nowait()
        assert item["email"] == "user@gmail.com"
        assert item["history_id"] == "12345"
        assert item["account_id"] == 1

    def test_missing_authorization_401(self, push_app, client, db, admin_user):
        _seed_watch(db)
        resp = client.post("/webhooks/gmail", json=_push_payload("user@gmail.com", 1))
        assert resp.status_code == 401
        assert push_app.state.metrics.get("gmail_push.auth_missing") == 1

    def test_wrong_audience_401(self, push_app, client, db, admin_user):
        _seed_watch(db)
        token = _make_jwt(audience="https://not-our-host/webhooks/gmail")
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("user@gmail.com", 1),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401
        assert push_app.state.metrics.get("gmail_push.auth_failed") == 1

    def test_wrong_issuer_401(self, push_app, client, db, admin_user):
        _seed_watch(db)
        token = _make_jwt(issuer="https://evil.example.com")
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("user@gmail.com", 1),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_wrong_sa_email_401(self, push_app, client, db, admin_user):
        _seed_watch(db)
        token = _make_jwt(email="someone-else@project.iam.gserviceaccount.com")
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("user@gmail.com", 1),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_expired_jwt_401(self, push_app, client, db, admin_user):
        _seed_watch(db)
        token = _make_jwt(expires_in=-300, now=int(time.time()) - 600)
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("user@gmail.com", 1),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_unknown_email_dropped(self, push_app, client, db, admin_user):
        # No watch row for this address.
        token = _make_jwt()
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("stranger@gmail.com", 1),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "dropped"
        assert push_app.state.push_queue.qsize() == 0

    def test_email_address_case_insensitive(
        self, push_app, client, db, admin_user,
    ):
        """Operator stores 'User@Gmail.COM' (mixed case). Pub/Sub
        delivers 'user@gmail.com' (lowercase per Gmail API contract).
        Lookup must match — observed regression on prod (#post-#92)
        manifested as repeating 'no active watch for address'
        warnings on every push delivery for accounts whose stored
        email was anything but all-lowercase."""
        # Force the row's stored email to mixed case bypassing the
        # upsert helper's normalization to simulate legacy rows that
        # pre-date the normalization fix.
        _seed_watch(db, email="User@Gmail.COM", account_id=10)
        db.execute(
            "UPDATE gmail_watches SET email_address = ? WHERE account_id = ?",
            ("User@Gmail.COM", 10),
        )
        db.commit()
        token = _make_jwt()
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("user@gmail.com", 99),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "queued"
        item = push_app.state.push_queue.get_nowait()
        assert item["account_id"] == 10
        assert item["history_id"] == "99"

    def test_email_address_normalized_on_upsert(
        self, push_app, client, db, admin_user,
    ):
        """upsert_gmail_watch normalizes mixed-case input to lowercase
        on write so the post-fix path is robust regardless of
        operator-typed casing in the source config."""
        from email_triage.web.db import (
            upsert_gmail_watch, get_gmail_watch_by_email,
        )
        # Insert via the public helper with mixed case.
        from datetime import datetime, timedelta, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        db.execute(
            "INSERT OR IGNORE INTO email_accounts "
            "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (20, 1, 'CaseTest', 'gmail_api', '{}', ?, ?)",
            (now_iso, now_iso),
        )
        db.commit()
        upsert_gmail_watch(
            db, account_id=20, email_address="MIXED@Case.Test",
            topic_name="projects/test/topics/gmail-push",
            history_id="1", expires_at=future,
        )
        row = db.execute(
            "SELECT email_address FROM gmail_watches WHERE account_id = 20"
        ).fetchone()
        assert row["email_address"] == "mixed@case.test"
        # And lookup with any casing variant resolves the row.
        assert get_gmail_watch_by_email(db, "MIXED@Case.Test") is not None
        assert get_gmail_watch_by_email(db, "mixed@case.test") is not None
        assert get_gmail_watch_by_email(db, "  Mixed@CASE.test  ") is not None
        # Empty / None input returns None safely.
        assert get_gmail_watch_by_email(db, "") is None
        assert get_gmail_watch_by_email(db, None) is None

    def test_upsert_writes_canonical_shape_and_legacy_rows_still_found(
        self, push_app, client, db, admin_user,
    ):
        """upsert_gmail_watch writes the canonical_email() shape (bare,
        lower-cased, IDNA A-label domain), so either envelope form of an
        IDN address finds the row. A row still holding the legacy
        strip().lower() shape is found through the dual-shape probe, and
        the next upsert rewrites it canonical: no backfill is needed."""
        from email_triage.web.db import (
            upsert_gmail_watch, get_gmail_watch_by_email,
        )
        from datetime import datetime, timedelta, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        for acct in (21, 22):
            db.execute(
                "INSERT OR IGNORE INTO email_accounts "
                "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
                "VALUES (?, 1, 'IdnTest', 'gmail_api', '{}', ?, ?)",
                (acct, now_iso, now_iso),
            )
        db.commit()

        def upsert(acct, addr):
            upsert_gmail_watch(
                db, account_id=acct, email_address=addr,
                topic_name="projects/test/topics/gmail-push",
                history_id="1", expires_at=future,
            )

        def stored(acct):
            return db.execute(
                "SELECT email_address FROM gmail_watches WHERE account_id = ?",
                (acct,),
            ).fetchone()["email_address"]

        upsert(21, "Alice <Alice@München.Test>")
        assert stored(21) == "alice@xn--mnchen-3ya.test"
        for needle in ("alice@münchen.test", "ALICE@xn--mnchen-3ya.test"):
            row = get_gmail_watch_by_email(db, needle)
            assert row is not None and row["account_id"] == 21, needle

        # A row written before the canonical write keeps the legacy shape.
        upsert(22, "carol@münchen.test")
        db.execute(
            "UPDATE gmail_watches SET email_address = ? WHERE account_id = 22",
            ("carol@münchen.test",),
        )
        db.commit()
        # Found from BOTH shapes. The A-label lookup collapses both string
        # probes to the A-label form, so only the canonical-compare probe
        # reaches the U-label row.
        for needle in ("Carol@München.test", "carol@xn--mnchen-3ya.test"):
            row = get_gmail_watch_by_email(db, needle)
            assert row is not None and row["account_id"] == 22, needle
        # The next re-register rewrites it canonical, and both forms find it.
        upsert(22, "carol@münchen.test")
        assert stored(22) == "carol@xn--mnchen-3ya.test"
        for needle in ("carol@münchen.test", "carol@xn--mnchen-3ya.test"):
            row = get_gmail_watch_by_email(db, needle)
            assert row is not None and row["account_id"] == 22, needle

    def test_one_mailbox_one_watch_row_across_shapes(
        self, push_app, client, db, admin_user,
    ):
        """The UNIQUE index on gmail_watches.email_address compares one
        string. With canonical writes beside legacy rows, a second account
        must still be refused the same mailbox in EITHER shape, in both
        directions, as the index refused a same-shape duplicate before."""
        import sqlite3
        from email_triage.web.db import upsert_gmail_watch
        from datetime import datetime, timedelta, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        for acct in (31, 32, 33, 34):
            db.execute(
                "INSERT OR IGNORE INTO email_accounts "
                "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
                "VALUES (?, 1, 'UniqTest', 'gmail_api', '{}', ?, ?)",
                (acct, now_iso, now_iso),
            )
        db.commit()

        def upsert(acct, addr):
            upsert_gmail_watch(
                db, account_id=acct, email_address=addr,
                topic_name="projects/test/topics/gmail-push",
                history_id="1", expires_at=future,
            )

        def count(addr_like):
            return db.execute(
                "SELECT COUNT(*) FROM gmail_watches WHERE email_address LIKE ?",
                (addr_like,),
            ).fetchone()[0]

        # Legacy U-label row on account 31; account 32 writes the same
        # mailbox (it would be stored canonical, a different string).
        upsert(31, "dave@münchen.test")
        db.execute(
            "UPDATE gmail_watches SET email_address = ? WHERE account_id = 31",
            ("dave@münchen.test",),
        )
        db.commit()
        with pytest.raises(sqlite3.IntegrityError):
            upsert(32, "Dave@xn--mnchen-3ya.test")
        assert count("dave@%") == 1
        # The holder itself may still re-register (rewritten canonical).
        upsert(31, "dave@münchen.test")
        assert count("dave@%") == 1

        # Reverse: canonical row on account 33; account 34 writes the
        # U-label form of the same mailbox.
        upsert(33, "erin@xn--mnchen-3ya.test")
        with pytest.raises(sqlite3.IntegrityError):
            upsert(34, "erin@münchen.test")
        assert count("erin@%") == 1

    @staticmethod
    def _plant_legacy_pair(db, accounts, local):
        """Two legacy rows on different accounts that canonicalize to one
        mailbox: an NFC U-label and an NFD U-label form. The old writer
        allowed this pair; upsert_gmail_watch now refuses a new one, so it
        is planted by rewriting the stored strings directly."""
        import unicodedata
        from email_triage.web.db import upsert_gmail_watch
        from datetime import datetime, timedelta, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        nfc = f"{local}@münchen.test"
        nfd = unicodedata.normalize("NFD", nfc)
        assert nfc != nfd
        for i, (acct, addr) in enumerate(zip(accounts, (nfc, nfd))):
            db.execute(
                "INSERT OR IGNORE INTO email_accounts "
                "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
                "VALUES (?, 1, 'PairTest', 'gmail_api', '{}', ?, ?)",
                (acct, now_iso, now_iso),
            )
            db.commit()
            upsert_gmail_watch(
                db, account_id=acct,
                email_address=f"{local}{i}@placeholder.test",
                topic_name="projects/test/topics/gmail-push",
                history_id="1",
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(days=7)
                ).isoformat(),
            )
            db.execute(
                "UPDATE gmail_watches SET email_address = ? WHERE account_id = ?",
                (addr, acct),
            )
            db.commit()
        return nfc, nfd

    def test_two_legacy_holders_fail_closed_on_lookup(
        self, push_app, client, db, admin_user, caplog,
    ):
        """F1 (pgw panel, all three seats): when two accounts' legacy rows
        canonicalize to one mailbox, the lookup must not pick one. It
        returns None, the webhook drops the push as no_watch, and one WARN
        names only the account ids and the count, never the address."""
        import logging
        from email_triage.web.db import get_gmail_watch_by_email
        self._plant_legacy_pair(db, (41, 42), "gina")
        with caplog.at_level(logging.WARNING, logger="email_triage.web.db"):
            assert get_gmail_watch_by_email(db, "gina@xn--mnchen-3ya.test") is None
        warns = [
            r for r in caplog.records
            if "gmail_watch_mailbox_ambiguous" in r.getMessage()
        ]
        assert len(warns) == 1, [r.getMessage() for r in caplog.records]
        rec = warns[0]
        assert rec.levelno == logging.WARNING
        rendered = rec.getMessage() + " " + repr(rec.__dict__)
        assert "41" in rendered and "42" in rendered
        for leak in ("gina", "münchen", "mnchen"):
            assert leak not in rendered, leak

        token = _make_jwt()
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("gina@xn--mnchen-3ya.test", 1),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "dropped", "reason": "no_watch"}
        assert push_app.state.push_queue.qsize() == 0

    @pytest.mark.parametrize("first,second", [(51, 52), (52, 51)])
    def test_legacy_pair_collapses_to_one_watch_on_renewal(
        self, push_app, client, db, admin_user, first, second,
    ):
        """F2 (pgw panel, sme-db SHOULD-2 and sme-da SHOULD-1): a holder of
        the mailbox may renew. With a pre-existing legacy pair, the first
        account to renew is rewritten canonical; the second is refused by
        the UNIQUE index and its row is left as it was. Both renewal orders
        run. A third account that holds no row is still refused."""
        import sqlite3
        from email_triage.web.db import upsert_gmail_watch, get_gmail_watch
        from datetime import datetime, timedelta, timezone
        self._plant_legacy_pair(db, (51, 52), "hank")
        canonical = "hank@xn--mnchen-3ya.test"

        def renew(acct, addr="hank@münchen.test", history_id="2"):
            upsert_gmail_watch(
                db, account_id=acct, email_address=addr,
                topic_name="projects/test/topics/gmail-push",
                history_id=history_id,
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(days=7)
                ).isoformat(),
            )

        def rows():
            return db.execute(
                "SELECT account_id, email_address, history_id "
                "FROM gmail_watches WHERE account_id IN (51, 52, 53) "
                "ORDER BY account_id"
            ).fetchall()

        db.execute(
            "INSERT OR IGNORE INTO email_accounts "
            "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (53, 1, 'PairTest', 'gmail_api', '{}', ?, ?)",
            (datetime.now(timezone.utc).isoformat(),) * 2,
        )
        db.commit()
        # While both rows are still legacy, the canonical string collides
        # with neither, so only the app-level check refuses a non-holder.
        with pytest.raises(sqlite3.IntegrityError):
            renew(53, addr=canonical)
        assert len(rows()) == 2

        loser_before = dict(get_gmail_watch(db, second))
        renew(first)
        assert get_gmail_watch(db, first)["email_address"] == canonical

        with pytest.raises(sqlite3.IntegrityError):
            renew(second, history_id="3")
        assert dict(get_gmail_watch(db, second)) == loser_before
        assert len(rows()) == 2

        # The survivor keeps renewing.
        renew(first, history_id="4")
        assert get_gmail_watch(db, first)["history_id"] == "4"
        assert get_gmail_watch(db, first)["email_address"] == canonical

        # After the collapse, a non-holder is still refused in either shape.
        for addr in (canonical, "hank@münchen.test"):
            with pytest.raises(sqlite3.IntegrityError):
                renew(53, addr=addr)
        assert len(rows()) == 2

    def test_legacy_pair_where_one_row_is_already_canonical(
        self, push_app, client, db, admin_user,
    ):
        """sme-da round 2: the row whose canonical write lands first keeps
        the mailbox. When the other row already holds the canonical string,
        the earliest renewer is the one refused, and the canonical row keeps
        renewing."""
        import sqlite3
        from email_triage.web.db import upsert_gmail_watch, get_gmail_watch
        from datetime import datetime, timedelta, timezone
        nfc, _ = self._plant_legacy_pair(db, (61, 62), "ivy")
        canonical = "ivy@xn--mnchen-3ya.test"
        # The old writer stored an A-label input as given, so a legacy row
        # can already be the canonical string.
        db.execute(
            "UPDATE gmail_watches SET email_address = ? WHERE account_id = 62",
            (canonical,),
        )
        db.commit()

        def renew(acct, history_id):
            upsert_gmail_watch(
                db, account_id=acct, email_address=nfc,
                topic_name="projects/test/topics/gmail-push",
                history_id=history_id,
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(days=7)
                ).isoformat(),
            )

        early_before = dict(get_gmail_watch(db, 61))
        with pytest.raises(sqlite3.IntegrityError):
            renew(61, "2")
        assert dict(get_gmail_watch(db, 61)) == early_before
        renew(62, "3")
        survivor = get_gmail_watch(db, 62)
        assert survivor["email_address"] == canonical
        assert survivor["history_id"] == "3"
        assert db.execute(
            "SELECT COUNT(*) FROM gmail_watches WHERE account_id IN (61, 62)"
        ).fetchone()[0] == 2

    def test_garbage_base64_ignored(self, push_app, client, db, admin_user):
        _seed_watch(db)
        token = _make_jwt()
        resp = client.post(
            "/webhooks/gmail",
            json={"message": {"data": "not-valid-base64!!!"}},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_missing_data_ignored(self, push_app, client, db, admin_user):
        _seed_watch(db)
        token = _make_jwt()
        resp = client.post(
            "/webhooks/gmail",
            json={"message": {"data": ""}},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_queue_full_503(self, push_app, client, db, admin_user):
        _seed_watch(db)
        # Fill the queue (maxsize=4 in fixture).
        for _ in range(4):
            push_app.state.push_queue.put_nowait({"filler": True})
        token = _make_jwt()
        resp = client.post(
            "/webhooks/gmail",
            json=_push_payload("user@gmail.com", 99),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 503
        assert push_app.state.metrics.get("gmail_push.queue_full") == 1


# ---------------------------------------------------------------------------
# Graph push (unchanged behaviour)
# ---------------------------------------------------------------------------


class TestGraphPush:
    def test_validation_request(self, client, db):
        resp = client.post("/webhooks/graph?validationToken=abc123", json={})
        assert resp.status_code == 200
        assert resp.text == "abc123"

    def test_change_notification(self, client, db):
        resp = client.post(
            "/webhooks/graph",
            json={"value": [
                {"resource": "me/mailFolders('Inbox')/messages", "changeType": "created"},
            ]},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_empty_notification(self, client, db):
        resp = client.post("/webhooks/graph", json={"value": []})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestGmailApiWatchRegistration:
    @pytest.mark.asyncio
    async def test_register_watch(self):
        from unittest.mock import AsyncMock, patch
        from email_triage.providers.gmail_api import GmailApiProvider

        provider = GmailApiProvider(client_id="cid", refresh_token="rt")
        with patch.object(provider, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"historyId": "99999", "expiration": "1700000000000"}
            result = await provider.register_watch("projects/test/topics/gmail-push")
            assert result["historyId"] == "99999"
            mock_req.assert_called_once_with(
                "POST",
                "/users/me/watch",
                json_data={"topicName": "projects/test/topics/gmail-push", "labelIds": ["INBOX"]},
            )

    @pytest.mark.asyncio
    async def test_stop_watch(self):
        from unittest.mock import AsyncMock, patch
        from email_triage.providers.gmail_api import GmailApiProvider

        provider = GmailApiProvider(client_id="cid", refresh_token="rt")
        with patch.object(provider, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = None
            await provider.stop_watch()
            mock_req.assert_called_once_with("POST", "/users/me/stop")

    @pytest.mark.asyncio
    async def test_watch_generator_raises(self):
        # The generator path is not how Gmail delivers push; callers
        # must go through register_watch + /webhooks/gmail instead.
        # The error message itself was scrubbed of API-contract jargon
        # so it reads cleanly in operator-facing UIs.
        from email_triage.providers.gmail_api import GmailApiProvider

        provider = GmailApiProvider(client_id="cid", refresh_token="rt")
        with pytest.raises(NotImplementedError, match="not supported"):
            async for _ in provider.watch():
                pass


class TestCLIPushFlag:
    def test_watch_push_flag(self):
        from email_triage.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["watch", "--push"])
        assert args.push is True

    def test_watch_no_push_default(self):
        from email_triage.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["watch"])
        assert args.push is False
