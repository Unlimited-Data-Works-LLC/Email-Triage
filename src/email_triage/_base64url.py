""" census-live tail — base64 padding SSOT (retrieved 2026-07-11).

External URL-safe base64 producers (WebAuthn, JWT, Gmail push
notifications, WebPush, Office365 push data blobs) routinely STRIP the
trailing ``=`` characters to keep tokens URL-safe. Standard-library
:func:`base64.b64decode` (and :func:`base64.urlsafe_b64decode`) RAISE
``binascii.Error`` when the input length is not a multiple of 4 —
i.e., they refuse unpadded input.

Consequence at HEAD before this SSOT: 4 call sites in the codebase were
calling ``base64.b64decode(<external-input>)`` directly:

  * ``mail_headers.py:541`` — decodes a header field with unknown
    padding shape (RFC 2047 encoded-word body).
  * ``providers/office365.py:865`` — decodes ``contentBytes`` from an
    O365 push calendar attachment (M365 sender may strip padding
    depending on client).
  * ``web/dev_keypair.py:101`` — decodes an SSH ed25519 public-key
    blob typed by the operator (paste MAY be trimmed).
  * ``web/routers/webhooks.py:112`` — decodes a Gmail push notification
    payload's ``data`` field (Gmail base64url-encodes without padding
    per RFC 4648 §5).

All four SILENTLY FAILED (either raising ``binascii.Error``, or, in the
``webhooks.py`` case, being swallowed by a broad ``except: JSONResponse
{ignored}``) on any unpadded input. On the O365 push path this meant
silent calendar-attachment loss on affected messages. On the Gmail push
path this meant the ingestion loop treated the notification as a
decoding failure and dropped the push.

This SSOT owns the ONE conversion between "strict-length" input and
correctly-decoded bytes so callers can't drift. Convention: use
``b64decode_permissive`` for ANY external URL-safe base64 input;
standard-library ``base64.b64decode`` / ``base64.urlsafe_b64decode``
outside this module (except for the SSOT's own body + the trusted
allow-list) is the drift shape ``tests/test_base64url_ssot_pin.py``
forbids.

Prime Directive #1: SSOT ships with count-agnostic structural pin same
change. See ``tests/test_base64url_ssot_pin.py``.
"""
from __future__ import annotations

import base64


def _pad_to_multiple_of_four(s: bytes | str) -> bytes | str:
    """Return ``s`` extended with ``=`` (or ``b"="``) so its length is
    a multiple of 4 — the input shape :func:`base64.b64decode` requires.

    ``-len(s) % 4`` computes exactly the number of pad characters
    needed (0 when already aligned, 1/2/3 otherwise). Guaranteed
    length-only widening — no character replacement — so the
    URL-safe / standard alphabet distinction is preserved.
    """
    if isinstance(s, bytes):
        return s + b"=" * (-len(s) % 4)
    return s + "=" * (-len(s) % 4)


def b64decode_permissive(
    s: bytes | str,
    *,
    urlsafe: bool = True,
    validate: bool = False,
) -> bytes:
    """Decode ``s`` as base64, re-padding first so unpadded URL-safe
    input decodes correctly.

    - ``urlsafe=True`` (default): accept the ``-`` / ``_`` alphabet
      (RFC 4648 §5). Callers with strict RFC 4648 §4 input (rare —
      typically internal-only) pass ``urlsafe=False``.
    - ``validate=True``: reject characters outside the chosen alphabet
      (matches stdlib's ``b64decode(..., validate=True)`` contract).
      DEFAULT is ``False`` so legit padded-but-slightly-noisy external
      inputs (whitespace stripped upstream, embedded newlines) don't
      hard-fail — matches how existing hand-rolled sites behaved.

    Raises the SAME exceptions the stdlib would raise on a hard-decode
    failure (``binascii.Error`` on non-alphabet chars with
    ``validate=True``, ``UnicodeDecodeError`` upstream if the caller
    decodes the returned bytes with wrong codec, etc.). The padding
    fix does NOT paper over structural corruption — it only fixes the
    "length not a multiple of 4" class the stdlib rejects.
    """
    padded = _pad_to_multiple_of_four(s)
    # DA F4 (2026-07-11 batched panel on N-395): collapse the hand-rolled
    # URL-safe alphabet check onto the stdlib idiom via ``altchars`` +
    # native ``validate`` kwarg. Eliminates the duplicate-of-stdlib
    # alphabet surface + preserves the URL-safe / standard alphabet
    # distinction inside stdlib's own validated path.
    altchars = b"-_" if urlsafe else None
    return base64.b64decode(padded, altchars=altchars, validate=validate)


def b64encode_urlsafe(
    data: bytes,
    *,
    strip_padding: bool = True,
) -> bytes:
    """Encode ``data`` as URL-safe base64, optionally stripping the
    trailing ``=`` padding (RFC 4648 §5 URL-safe convention used by
    WebAuthn / JWT / Gmail push).

    Callers producing strict-padded output (rare) pass
    ``strip_padding=False``. Callers producing WebAuthn / JWT / URL-
    embedded tokens leave the default so the encoded string is a
    valid URL segment.
    """
    encoded = base64.urlsafe_b64encode(data)
    if strip_padding:
        return encoded.rstrip(b"=")
    return encoded
