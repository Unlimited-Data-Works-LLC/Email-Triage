""" -- unit tests for `email_triage._base64url` SSOT.

The SSOT ships pins that ban DIRECT stdlib calls outside its home,
but until  the SSOT's OWN behavior had no unit test. This file
covers the contract: `b64decode_permissive(s, *, urlsafe, validate)`
+ `b64encode_urlsafe(data, *, strip_padding)` -- the exact shapes
callers rely on.
"""
from __future__ import annotations

import pytest

from email_triage._base64url import b64decode_permissive, b64encode_urlsafe


class TestB64DecodePermissive:
    """`b64decode_permissive(s, *, urlsafe=True, validate=False)`."""

    def test_padded_urlsafe_roundtrip(self):
        data = b"hello world 12345"
        encoded = b64encode_urlsafe(data, strip_padding=False)
        # encoded is bytes; decoder accepts bytes-or-str.
        assert b64decode_permissive(encoded, urlsafe=True) == data

    def test_unpadded_urlsafe_decodes(self):
        # Gmail-push / RFC 4648 sec.5 shape -- no `=` padding.
        data = b"hi"
        encoded = b64encode_urlsafe(data, strip_padding=True)
        assert b"=" not in encoded
        assert b64decode_permissive(encoded, urlsafe=True) == data

    def test_urlsafe_hyphen_underscore(self):
        # RFC 4648 sec.5 URL-safe alphabet: `-` for `+`, `_` for `/`.
        data = bytes([0xfb, 0xff])
        encoded = b64encode_urlsafe(data, strip_padding=True)
        assert b"+" not in encoded
        assert b"/" not in encoded
        assert b64decode_permissive(encoded, urlsafe=True) == data

    def test_plain_padded_decodes_with_urlsafe_false(self):
        # Legacy plain base64 (with `+` / `/`).
        data = b"payload"
        # stdlib's plain b64encode:
        import base64
        plain = base64.b64encode(data).decode("ascii")
        assert b64decode_permissive(plain, urlsafe=False) == data

    def test_validate_true_rejects_garbage(self):
        # `test_decode_garbage_returns_empty` contract in mail_headers
        # depended on validate=True raising or returning empty.
        with pytest.raises(Exception):
            b64decode_permissive("not@valid!base64", urlsafe=False, validate=True)

    def test_empty_string_returns_empty_bytes(self):
        assert b64decode_permissive("", urlsafe=True) == b""

    def test_short_input_pad_fixup(self):
        # A 1-char base64 input like "a" is invalid on stdlib but
        # b64decode_permissive should pad-fix or fail cleanly.
        # This is a boundary test — the SSOT's contract says
        # unpadded URL-safe decodes correctly, so 3-char and 4-char
        # inputs are the normal shapes.
        data = b"x"  # 1 byte -> "eA==" plain / "eA" URL-safe unpadded
        encoded = b64encode_urlsafe(data, strip_padding=True)
        assert len(encoded) == 2
        assert b64decode_permissive(encoded, urlsafe=True) == data


class TestB64EncodeUrlsafe:
    """`b64encode_urlsafe(data, *, strip_padding=True)`."""

    def test_strip_padding_true_removes_equals(self):
        data = b"ab"  # forces padding
        encoded = b64encode_urlsafe(data, strip_padding=True)
        assert b"=" not in encoded

    def test_strip_padding_false_keeps_equals(self):
        data = b"ab"  # forces padding
        encoded = b64encode_urlsafe(data, strip_padding=False)
        assert encoded.endswith(b"=")

    def test_urlsafe_alphabet_uses_hyphen_underscore(self):
        # bytes chosen to produce +/ in stdlib alphabet.
        data = bytes([0xfb, 0xff, 0xff])
        encoded = b64encode_urlsafe(data, strip_padding=False)
        assert b"+" not in encoded
        assert b"/" not in encoded

    def test_roundtrip_random_ish_bytes(self):
        data = bytes(range(256))
        encoded = b64encode_urlsafe(data, strip_padding=True)
        assert b64decode_permissive(encoded, urlsafe=True) == data
