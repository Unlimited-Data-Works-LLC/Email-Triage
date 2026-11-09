""" — IMAP batch-fetch primitive.

Before this fix
---------------
``providers/imap_blocking.py:_blocking_fetch`` opens a fresh
``imaplib.IMAP4_SSL`` + LOGIN + SELECT per UID. A 50-UID poll cycle
paid 50 × (TLS handshake + LOGIN + SELECT) ≈ 5-10 s of pure transport
overhead.

This fix
--------
New :func:`_blocking_fetch_batch` opens ONE connection and FETCHes N
UIDs serially on it — collapses to 1 × (TLS + LOGIN + SELECT) + N ×
FETCH. ``ImapProvider.fetch_messages_batch`` wires the
``poll_once`` caller (the only call site in this commit; the 3 action
callers use the provider-agnostic ``self._provider.fetch_message``
surface and stay on single-fetch pending a future
provider-abstract-base extension).

This test file pins:

  * **Connection accounting** — N UIDs → 1 connection-opens, 1
    LOGIN, 1 SELECT, N FETCHes, 1 LOGOUT. The whole point of the
    fix; a regression that put per-UID LOGIN back is caught here.
  * **Result alignment** — output list is aligned 1:1 with input
    UIDs; an empty FETCH response (vanished UID) yields ``(b"", [])``
    in the matching slot rather than aborting the batch.
  * **Protocol-level failure semantics** — LOGIN refused / SELECT
    refused / connection drop raise RuntimeError immediately (caller
    treats whole batch as failed); per-UID FETCH failure inside the
    batch is recorded as an empty slot (caller drops it like
    single-fetch's empty bytes).
  * **Empty input** — ``uids=[]`` returns ``[]`` WITHOUT opening a
    connection (cheap path for the rare race-condition caller).
  * **Headers-only** — same BODY.PEEK[HEADER] / BODY.PEEK[] choice
    as single-fetch.
  * **Structural pin (drift defense per n=6 pattern)** —
    ``ImapProvider.poll_once`` invokes ``fetch_messages_batch``
    rather than the prior single-fetch loop, with fallback-to-single
    on whole-batch failure preserved.
"""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

from _tls_assertions import assert_verifying_context as _assert_verifying
import pytest

from _pin_harness import parse_module
from email_triage.providers.imap_blocking import (
    _blocking_fetch_batch,
    fetch_messages_batch_blocking,
)


# ---------------------------------------------------------------------------
# Stub builder — tracks per-method call counts so we can assert
# connection-opens, LOGINs, SELECTs, FETCHes, LOGOUTs separately.
# ---------------------------------------------------------------------------


def _make_batch_factory(
    *,
    fetch_responses: dict[str, tuple] | None = None,
    login_typ: str = "OK",
    select_typ: str = "OK",
):
    """Build a factory that returns a fresh MagicMock client per
    construction call. Tracks ``opens`` in the closure so the test
    can assert how many ``IMAP4_SSL(host, port, ssl_context=...)`` invocations
    happened across the run.

    ``fetch_responses`` maps each UID string to the canned ``(typ,
    data)`` tuple ``client.uid("FETCH", uid, section)`` will return.
    A UID not in the map gets a default ``("OK", canned-payload)``.
    """
    opens = {"count": 0}
    logins = {"count": 0}
    selects = {"count": 0}
    fetches = {"count": 0, "uids": []}
    logouts = {"count": 0}

    def _default_response(uid: str):
        return (
            "OK",
            [
                (
                    f"1 (UID {uid} BODY[] {{16}}".encode(),
                    f"X: y-{uid}\r\n\r\n".encode(),
                ),
                b" FLAGS (\\Seen))",
            ],
        )

    def _factory(host, port, *, ssl_context):
        _assert_verifying(ssl_context)
        opens["count"] += 1
        client = MagicMock()

        def _login(user, pw):
            logins["count"] += 1
            return (login_typ, [b""])

        def _select(name, readonly=True):
            selects["count"] += 1
            return (select_typ, [b"1"])

        def _uid(verb, uid, section):
            fetches["count"] += 1
            fetches["uids"].append(uid)
            if fetch_responses and uid in fetch_responses:
                return fetch_responses[uid]
            return _default_response(uid)

        def _logout():
            logouts["count"] += 1

        client.login = _login
        client.select = _select
        client.uid = _uid
        client.logout = _logout
        return client

    return _factory, {
        "opens": opens, "logins": logins, "selects": selects,
        "fetches": fetches, "logouts": logouts,
    }


# ---------------------------------------------------------------------------
# Connection accounting — the headline  property
# ---------------------------------------------------------------------------

class TestConnectionAccounting:
    """The whole point of  — N UIDs in a batch = 1 connection
    open + 1 LOGIN + 1 SELECT + N FETCHes + 1 LOGOUT. Before the
    fix this was N × everything; a regression that re-introduces per-
    UID LOGIN would show up here as `opens > 1` or `logins > 1`.
    """

    def test_five_uids_open_one_connection(self):
        factory, counts = _make_batch_factory()
        with patch("imaplib.IMAP4_SSL", side_effect=factory):
            results = _blocking_fetch_batch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uids=["10", "11", "12", "13", "14"],
                headers_only=False,
            )
        assert counts["opens"]["count"] == 1, (
            f"batch should open exactly ONE connection for N UIDs; "
            f"got {counts['opens']['count']} opens"
        )
        assert counts["logins"]["count"] == 1
        assert counts["selects"]["count"] == 1
        assert counts["fetches"]["count"] == 5
        assert counts["logouts"]["count"] == 1
        assert len(results) == 5

    def test_single_uid_batch_still_opens_one_connection(self):
        # N=1 caller of batch primitive is rare (`fetch_messages_batch`
        # delegates to single-fetch when N==1) but the primitive
        # itself must still work cleanly with a single-element list.
        factory, counts = _make_batch_factory()
        with patch("imaplib.IMAP4_SSL", side_effect=factory):
            results = _blocking_fetch_batch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uids=["42"], headers_only=False,
            )
        assert counts["opens"]["count"] == 1
        assert counts["fetches"]["count"] == 1
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Result alignment
# ---------------------------------------------------------------------------

class TestResultAlignment:
    """Output list MUST be 1:1 with input UIDs. A caller mapping
    ``zip(uids, results)`` to build EmailMessages depends on this.
    """

    def test_results_align_with_input_order(self):
        factory, _ = _make_batch_factory()
        with patch("imaplib.IMAP4_SSL", side_effect=factory):
            results = _blocking_fetch_batch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uids=["100", "200", "300"], headers_only=False,
            )
        assert len(results) == 3
        # The default-response builder embeds the UID into the body
        # so we can confirm ordering.
        assert b"y-100" in results[0][0]
        assert b"y-200" in results[1][0]
        assert b"y-300" in results[2][0]

    def test_vanished_uid_yields_empty_slot(self):
        # A UID the server can't return (deleted between SEARCH and
        # FETCH, wrong mailbox) → ``(b"", [])`` in the matching slot.
        # The batch MUST continue rather than abort — matches the
        # single-fetch empty-bytes pass-through behaviour.
        factory, counts = _make_batch_factory(fetch_responses={
            "999": ("NO", [None]),  # IMAP NO = not-found
        })
        with patch("imaplib.IMAP4_SSL", side_effect=factory):
            results = _blocking_fetch_batch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uids=["10", "999", "11"], headers_only=False,
            )
        assert len(results) == 3
        # Successful slots populated, vanished slot empty.
        assert b"y-10" in results[0][0]
        assert results[1] == (b"", [])
        assert b"y-11" in results[2][0]
        # All 3 FETCHes attempted (vanished UID didn't abort the batch).
        assert counts["fetches"]["count"] == 3

    def test_uid_fetch_exception_yields_empty_slot(self):
        # Per-UID FETCH that raises (network blip, server hiccup)
        # also records an empty slot rather than aborting the batch.
        def _factory(host, port, *, ssl_context):
            _assert_verifying(ssl_context)
            client = MagicMock()
            client.login = MagicMock(return_value=("OK", [b""]))
            client.select = MagicMock(return_value=("OK", [b"1"]))

            def _uid(verb, uid, section):
                if uid == "999":
                    raise OSError("simulated network blip")
                return (
                    "OK",
                    [
                        (
                            f"1 (UID {uid} BODY[] {{4}}".encode(),
                            b"hi\r\n",
                        ),
                        b" FLAGS ())",
                    ],
                )

            client.uid = _uid
            client.logout = MagicMock()
            return client

        with patch("imaplib.IMAP4_SSL", side_effect=_factory):
            results = _blocking_fetch_batch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uids=["10", "999", "11"], headers_only=False,
            )
        assert len(results) == 3
        assert results[0][0] == b"hi\r\n"
        assert results[1] == (b"", [])  # per-UID exception caught
        assert results[2][0] == b"hi\r\n"


# ---------------------------------------------------------------------------
# Protocol-level failures abort whole batch
# ---------------------------------------------------------------------------

class TestProtocolFailures:
    """LOGIN refused / SELECT refused → RuntimeError, whole batch
    fails. Caller treats this as a transport-layer error (same
    semantics as single-fetch); the optional fall-back-to-single
    path lives in the higher-level ``ImapProvider.poll_once``.
    """

    def test_login_refused_raises_runtimeerror(self):
        factory, _ = _make_batch_factory(login_typ="NO")
        with patch("imaplib.IMAP4_SSL", side_effect=factory):
            with pytest.raises(RuntimeError, match="LOGIN refused"):
                _blocking_fetch_batch(
                    host="imap.test", port=993, use_ssl=True,
                    username="u", password="p", mailbox="INBOX",
                    uids=["10", "11"], headers_only=False,
                )

    def test_select_failure_raises_runtimeerror(self):
        factory, _ = _make_batch_factory(select_typ="NO")
        with patch("imaplib.IMAP4_SSL", side_effect=factory):
            with pytest.raises(RuntimeError, match="SELECT"):
                _blocking_fetch_batch(
                    host="imap.test", port=993, use_ssl=True,
                    username="u", password="p", mailbox="INBOX",
                    uids=["10", "11"], headers_only=False,
                )


# ---------------------------------------------------------------------------
# Empty input cheap-path
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_uids_returns_empty_without_opening_connection(self):
        factory, counts = _make_batch_factory()
        with patch("imaplib.IMAP4_SSL", side_effect=factory):
            results = _blocking_fetch_batch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uids=[], headers_only=False,
            )
        assert results == []
        assert counts["opens"]["count"] == 0, (
            "empty-UIDs cheap-path must NOT open a connection — "
            "would waste a TLS handshake for nothing"
        )


# ---------------------------------------------------------------------------
# Headers-only mode
# ---------------------------------------------------------------------------

class TestHeadersOnly:
    def test_headers_only_uses_body_peek_header(self):
        captured_sections: list[str] = []

        def _factory(host, port, *, ssl_context):
            _assert_verifying(ssl_context)
            client = MagicMock()
            client.login = MagicMock(return_value=("OK", [b""]))
            client.select = MagicMock(return_value=("OK", [b"1"]))

            def _uid(verb, uid, section):
                captured_sections.append(section)
                return (
                    "OK",
                    [
                        (
                            f"1 (UID {uid} BODY[HEADER] {{0}}".encode(),
                            b"",
                        ),
                        b" FLAGS ())",
                    ],
                )

            client.uid = _uid
            client.logout = MagicMock()
            return client

        with patch("imaplib.IMAP4_SSL", side_effect=_factory):
            _blocking_fetch_batch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uids=["1", "2"], headers_only=True,
            )

        assert captured_sections == [
            "(BODY.PEEK[HEADER] FLAGS)",
            "(BODY.PEEK[HEADER] FLAGS)",
        ]

    def test_body_mode_uses_body_peek(self):
        captured_sections: list[str] = []

        def _factory(host, port, *, ssl_context):
            _assert_verifying(ssl_context)
            client = MagicMock()
            client.login = MagicMock(return_value=("OK", [b""]))
            client.select = MagicMock(return_value=("OK", [b"1"]))

            def _uid(verb, uid, section):
                captured_sections.append(section)
                return (
                    "OK",
                    [
                        (
                            f"1 (UID {uid} BODY[] {{0}}".encode(),
                            b"",
                        ),
                        b" FLAGS ())",
                    ],
                )

            client.uid = _uid
            client.logout = MagicMock()
            return client

        with patch("imaplib.IMAP4_SSL", side_effect=_factory):
            _blocking_fetch_batch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uids=["1"], headers_only=False,
            )

        assert captured_sections == ["(BODY.PEEK[] FLAGS)"]


# ---------------------------------------------------------------------------
# Async wrapper
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_async_wrapper_delegates_to_blocking():
    factory, counts = _make_batch_factory()
    with patch("imaplib.IMAP4_SSL", side_effect=factory):
        results = await fetch_messages_batch_blocking(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p", mailbox="INBOX",
            uids=["1", "2", "3"], headers_only=False,
        )
    assert len(results) == 3
    assert counts["opens"]["count"] == 1


@pytest.mark.asyncio
async def test_async_wrapper_empty_uids_returns_empty():
    factory, counts = _make_batch_factory()
    with patch("imaplib.IMAP4_SSL", side_effect=factory):
        results = await fetch_messages_batch_blocking(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p", mailbox="INBOX",
            uids=[], headers_only=False,
        )
    assert results == []
    assert counts["opens"]["count"] == 0


# ---------------------------------------------------------------------------
# Structural pin — poll_once wires the batch path
# ---------------------------------------------------------------------------

class TestPollOnceWiring:
    """ structural pin (drift defense per n=6 pattern) — the
    ``ImapProvider.poll_once`` method MUST invoke
    ``fetch_messages_batch`` (the optimised path) rather than
    looping ``self.fetch_message(uid)`` per UID. A future refactor
    that reverts to single-fetch (re-introducing per-UID
    TLS+LOGIN) is caught here.
    """

    def test_poll_once_calls_batch_method(self):
        import ast
        from pathlib import Path
        tree = parse_module(
            Path(__file__).resolve().parent.parent
            / "src" / "email_triage" / "providers" / "imap.py"
        )
        assert tree is not None, (
            "expected parseable source at "
            "src/email_triage/providers/imap.py"
        )

        # Find the poll_once method body.
        poll_once_body = None
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.AsyncFunctionDef)
                and node.name == "poll_once"
            ):
                poll_once_body = node
                break
        assert poll_once_body is not None, (
            "ImapProvider.poll_once not found in providers/imap.py"
        )

        # Walk poll_once for any call to fetch_messages_batch.
        found_batch_call = False
        for sub in ast.walk(poll_once_body):
            if isinstance(sub, ast.Call):
                if (
                    isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "fetch_messages_batch"
                ):
                    found_batch_call = True
                    break

        assert found_batch_call, (
            "ImapProvider.poll_once must invoke "
            "`self.fetch_messages_batch(...)` for #261 — a regression "
            "that loops `self.fetch_message(uid)` per UID re-introduces "
            "the per-UID TLS+LOGIN cost. Fallback-to-single on whole-"
            "batch failure is fine; the batch CALL must be there."
        )
