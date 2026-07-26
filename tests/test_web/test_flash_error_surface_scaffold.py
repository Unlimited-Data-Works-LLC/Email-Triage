"""R20_1 / N-179 scaffold — scrub_exc + flash SSOTs baseline behavior.

Tests the SCAFFOLD contract (not the 126-site adoption; that's next-window).
Locks in the SSOT's behavioral invariants so the adoption sweep has a stable
target.
"""
from __future__ import annotations

import pytest

from email_triage.web._flash import (
    scrub_exc, flash_redirect, flash_context, flash_htmx, FLASH_KEYS, FLASH_PURPOSES,
)
from email_triage.web.error_surface import api_error_response, raise_api_error


class TestScrubExc:
    def test_sensitive_purpose_generic_message(self):
        for purpose in ("auth", "config", "backup"):
            got = scrub_exc(ValueError("secret key material 0x1234abcd" * 5), purpose=purpose)
            assert got == f"{purpose} operation failed"
            assert "0x1234abcd" not in got

    def test_informational_purpose_scrubs_shapes(self):
        got = scrub_exc(ValueError("user alice@example.com hit token deadbeef1234cafebabe"), purpose="form")
        assert "alice@example.com" not in got
        assert "deadbeef1234cafebabe" not in got
        assert "<email>" in got
        assert "<token>" in got

    def test_length_cap(self):
        got = scrub_exc("x" * 500, purpose="misc")
        assert len(got) <= 200

    def test_str_input_direct(self):
        assert scrub_exc("simple message", purpose="form") == "simple message"

    def test_unknown_purpose_falls_to_misc(self):
        got = scrub_exc(ValueError("noise"), purpose="not-a-real-purpose")
        assert got == "noise"  # misc = informational

    def test_flash_keys_constants(self):
        assert FLASH_KEYS == frozenset({"err", "ok", "warn", "info"})
        assert "misc" in FLASH_PURPOSES and "auth" in FLASH_PURPOSES


class TestFlashRedirect:
    def test_err_only(self):
        r = flash_redirect("/x", err=ValueError("bad"), purpose="form")
        assert r.status_code == 303
        assert "err=bad" in r.headers["location"]

    def test_sensitive_purpose_scrubs_url(self):
        r = flash_redirect("/x", err=ValueError("secret material"), purpose="auth")
        loc = r.headers["location"]
        assert "secret" not in loc
        # err_qs uses quote(safe='') -> space as %20
        assert "auth%20operation%20failed" in loc

    def test_msg_and_existing_qs(self):
        r = flash_redirect("/x?a=1", ok="saved")
        loc = r.headers["location"]
        assert loc.startswith("/x?a=1&")
        # ok= is delivered as msg= (aligned with _redirect.py::msg_qs SSOT)
        assert "msg=saved" in loc


class TestFlashContext:
    def test_mutates_ctx(self):
        ctx = {"user": "u1"}
        out = flash_context(ctx, err="bad", purpose="form")
        assert out is ctx
        assert ctx["err"] == "bad"
        assert ctx["user"] == "u1"

    def test_no_flash_no_change(self):
        ctx = {"user": "u1"}
        flash_context(ctx)
        assert "err" not in ctx and "ok" not in ctx


class TestFlashHtmx:
    def test_err_fragment(self):
        r = flash_htmx(err="bad")
        assert r.status_code == 200
        assert b'flash-err' in r.body
        assert b'bad' in r.body

    def test_no_input_returns_empty_flash(self):
        r = flash_htmx()
        assert r.status_code == 200


class TestApiErrorResponse:
    def test_basic(self):
        r = api_error_response(ValueError("form bad"), status_code=422, purpose="form")
        import json
        assert r.status_code == 422
        body = json.loads(r.body)
        assert body == {"error": "form bad"}

    def test_sensitive_scrubbed(self):
        r = api_error_response(ValueError("secret material"), status_code=500, purpose="config")
        import json
        body = json.loads(r.body)
        assert body["error"] == "config operation failed"

    def test_extra_merged(self):
        r = api_error_response("nope", extra={"field": "email"})
        import json
        body = json.loads(r.body)
        assert body["error"] == "nope"
        assert body["field"] == "email"


class TestRaiseApiError:
    def test_returns_httpexception_with_scrubbed_detail(self):
        e = raise_api_error(ValueError("form bad"), status_code=422, purpose="form")
        from fastapi import HTTPException
        assert isinstance(e, HTTPException)
        assert e.status_code == 422
        assert e.detail == "form bad"

    def test_sensitive_purpose(self):
        e = raise_api_error(ValueError("token abc"), status_code=401, purpose="auth")
        assert e.detail == "auth operation failed"
