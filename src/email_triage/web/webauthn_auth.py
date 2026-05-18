"""WebAuthn / FIDO2 hardware-key auth.

Wraps Duo's ``webauthn`` Python library to implement registration +
authentication ceremonies for the per-user self-service hardware-key
flow at ``/profile/hardware-keys`` and the email-then-touch login at
``/login``.

Two ceremonies, both two-step (begin / finish):

1. **Registration** — ``begin_registration`` returns options the
   browser passes to ``navigator.credentials.create()``.
   ``finish_registration`` verifies the attestation, inserts a
   ``hardware_keys`` row.
2. **Authentication** — ``begin_authentication`` returns options
   for ``navigator.credentials.get()``. ``finish_authentication``
   verifies the assertion, updates ``sign_count``, returns the
   resolved user.

Sign-count regression detection is built into
``verify_authentication_response`` — passing ``credential_current_sign_count``
catches cloned-authenticator attacks. The library raises on regression;
we surface a generic auth-fail to the caller.

This module is the only place that imports the ``webauthn`` package
in the app — all callers go through these helpers.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from typing import Any

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.helpers.exceptions import (
    InvalidRegistrationResponse,
    InvalidAuthenticationResponse,
)

from email_triage.web.db_auth_helpers import (
    add_hardware_key,
    consume_webauthn_challenge,
    find_hardware_key_by_credential_id,
    find_user_by_webauthn_handle,
    get_or_create_webauthn_user_handle,
    list_hardware_keys,
    store_webauthn_challenge,
    update_hardware_key_sign_count,
    user_has_active_hardware_key as _user_has_active_hardware_key,
)


# Note (2026-04-29): the webauthn library's ``verify_registration_response``
# and ``verify_authentication_response`` both accept ``Union[str, dict,
# RegistrationCredential|AuthenticationCredential]`` for the ``credential``
# kwarg. Earlier versions of this module went through a ``RegistrationCredential
# .parse_obj()`` step (pydantic v1 → v2 migration tripped that up), then through
# a ``model_validate()`` shim. The library has since reshaped the
# ``*Credential`` classes into plain dataclasses with no pydantic methods at
# all. Right path is to skip the parse step and hand the dict straight to the
# verify call -- the library does its own internal coercion. We use the raw
# response dict for the credential-id lookup at finish time too.


class WebAuthnConfigError(RuntimeError):
    """Raised when ``rp_id`` / ``origin`` aren't configured.

    Hardware-key auth has no sensible default; the operator must
    supply the canonical hostname before this code path can run.
    """


class WebAuthnAuthError(RuntimeError):
    """Generic authentication / registration failure.

    Raised from the ``finish_*`` paths to give the caller a single
    exception type to render. Detail goes to the structured log,
    not the response body.
    """


def _require_config(rp_id: str, origin: str | list[str]) -> None:
    has_origin = bool(origin) and (
        any(origin) if isinstance(origin, list) else True
    )
    if not rp_id or not has_origin:
        raise WebAuthnConfigError(
            "WebAuthn rp_id and origin must be set in config.webauthn "
            "before hardware-key flows are available."
        )


# ---------------------------------------------------------------------------
# Public API used by the web routes
# ---------------------------------------------------------------------------

def user_has_active_hardware_key(
    conn: sqlite3.Connection, user_id: int,
) -> bool:
    """Re-export of the DB helper for symmetry — keeps callers from
    needing to import both modules."""
    return _user_has_active_hardware_key(conn, user_id)


def begin_registration(
    conn: sqlite3.Connection,
    *,
    user: dict[str, Any],
    rp_id: str,
    rp_name: str,
    require_user_verification: bool = False,
    discoverable: bool = True,
    attachment: str | None = None,
) -> str:
    """Generate registration options for a self-service ``Add hardware
    key`` flow. Stores the challenge in ``webauthn_challenges`` keyed
    on user_id; ``finish_registration`` consumes it.

    Returns a JSON string ready to be embedded in the page (the
    browser's ``navigator.credentials.create()`` accepts the parsed
    JSON). Lazily seeds ``users.webauthn_user_handle`` on first call.

    Excludes already-registered credentials so the user can't double-
    register the same authenticator (browser shows an "already
    registered" UX instead of going through the touch ceremony).
    """
    _require_config(rp_id, rp_name)
    user_handle = get_or_create_webauthn_user_handle(conn, user["id"])
    existing = list_hardware_keys(conn, user["id"])
    exclude = [
        PublicKeyCredentialDescriptor(id=bytes(k["credential_id"]))
        for k in existing
    ]
    uv = (
        UserVerificationRequirement.REQUIRED
        if require_user_verification
        else UserVerificationRequirement.PREFERRED
    )
    # Passkey support (2026-04-29). residentKey="preferred" makes the
    # credential discoverable -- the OS / password manager can find it
    # without the user typing an email first (powers conditional UI on
    # login). attachment lets the operator nudge toward platform
    # authenticators (Touch ID / Windows Hello / Android passkey)
    # versus cross-platform (USB / NFC security keys).
    sel_kwargs: dict[str, Any] = {
        "user_verification": uv,
    }
    if discoverable:
        sel_kwargs["resident_key"] = ResidentKeyRequirement.PREFERRED
    if attachment in ("platform", "cross-platform"):
        sel_kwargs["authenticator_attachment"] = AuthenticatorAttachment(
            attachment,
        )
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_handle,
        user_name=user.get("email", ""),
        user_display_name=user.get("name") or user.get("email", ""),
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(**sel_kwargs),
    )
    store_webauthn_challenge(
        conn,
        user_id=user["id"],
        email=None,
        kind="register",
        challenge=opts.challenge,
    )
    return options_to_json(opts)


def finish_registration(
    conn: sqlite3.Connection,
    *,
    user: dict[str, Any],
    rp_id: str,
    origin: str | list[str],
    response_json: str | dict,
    nickname: str,
) -> int:
    """Verify the browser's attestation response and insert a
    ``hardware_keys`` row.

    ``response_json`` is whatever the browser POSTed back from the
    ``navigator.credentials.create()`` resolution — a dict-like
    structure with ``id`` / ``rawId`` / ``response`` / ``type``.
    ``nickname`` is the operator-supplied label (e.g.
    "YubiKey blue").

    Returns the new ``hardware_keys.id``. Raises
    ``WebAuthnAuthError`` on any verify failure.
    """
    _require_config(rp_id, origin)
    challenge = consume_webauthn_challenge(
        conn, user_id=user["id"], email=None, kind="register",
    )
    if challenge is None:
        raise WebAuthnAuthError(
            "No active registration challenge for this user "
            "(expired or already consumed)."
        )
    if isinstance(response_json, str):
        try:
            response_data = json.loads(response_json)
        except json.JSONDecodeError as e:
            raise WebAuthnAuthError(f"Bad response JSON: {e}") from e
    else:
        response_data = response_json
    try:
        verified = verify_registration_response(
            credential=response_data,
            expected_challenge=challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
        )
    except (InvalidRegistrationResponse, ValueError, KeyError) as e:
        raise WebAuthnAuthError(f"Registration verify failed: {e}") from e

    transports_raw = response_data.get("response", {}).get("transports") or []
    if not isinstance(transports_raw, list):
        transports_raw = []

    # Library shape change (2026-04-29): VerifiedRegistration.aaguid is now
    # a UUID-formatted string (e.g. "abcd1234-...-...") instead of raw
    # bytes. Convert to the canonical 16-byte form so the DB column shape
    # stays consistent with rows written by earlier versions. Tolerate
    # bytes too in case the library bumps back.
    raw_aaguid = getattr(verified, "aaguid", None)
    aaguid_b: bytes | None
    if raw_aaguid is None or raw_aaguid == "":
        aaguid_b = None
    elif isinstance(raw_aaguid, (bytes, bytearray)):
        aaguid_b = bytes(raw_aaguid)
    else:
        import uuid as _uuid
        try:
            aaguid_b = _uuid.UUID(str(raw_aaguid)).bytes
        except (ValueError, AttributeError):
            aaguid_b = None

    return add_hardware_key(
        conn,
        user_id=user["id"],
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        transports=[str(t) for t in transports_raw],
        aaguid=aaguid_b,
        nickname=nickname,
    )


def begin_authentication(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    email: str,
    rp_id: str,
    require_user_verification: bool = False,
) -> str:
    """Generate authentication options for a login attempt.

    Lists only the user's currently-active credentials in
    ``allowCredentials`` so the browser can hint the right
    authenticator. Stores the challenge keyed on email so the
    ``finish_authentication`` call can find it without trusting
    client-supplied user-id mid-ceremony.
    """
    _require_config(rp_id, "any")  # origin checked at finish
    keys = list_hardware_keys(conn, user_id)
    if not keys:
        raise WebAuthnAuthError(
            "User has no active hardware keys; OTP path applies."
        )
    descriptors = []
    for k in keys:
        ts = k.get("transports") or []
        wt = []
        for t in ts:
            try:
                wt.append(AuthenticatorTransport(t))
            except ValueError:
                continue
        descriptors.append(
            PublicKeyCredentialDescriptor(
                id=bytes(k["credential_id"]),
                transports=wt or None,
            )
        )
    uv = (
        UserVerificationRequirement.REQUIRED
        if require_user_verification
        else UserVerificationRequirement.PREFERRED
    )
    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=descriptors,
        user_verification=uv,
    )
    store_webauthn_challenge(
        conn,
        user_id=user_id,
        email=email,
        kind="authenticate",
        challenge=opts.challenge,
    )
    return options_to_json(opts)


def finish_authentication(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    rp_id: str,
    origin: str | list[str],
    response_json: str | dict,
) -> int:
    """Verify the browser's assertion and update sign_count.

    Returns the ``hardware_keys.id`` that authenticated. Caller
    mints the session with that id stamped into the cookie payload
    so the access_log shows ``auth_source='webauthn',
    auth_key_id=<n>`` per request.
    """
    _require_config(rp_id, origin)
    challenge = consume_webauthn_challenge(
        conn, user_id=user_id, email=None, kind="authenticate",
    )
    if challenge is None:
        raise WebAuthnAuthError(
            "No active authentication challenge for this user "
            "(expired or already consumed)."
        )
    if isinstance(response_json, str):
        try:
            response_data = json.loads(response_json)
        except json.JSONDecodeError as e:
            raise WebAuthnAuthError(f"Bad response JSON: {e}") from e
    else:
        response_data = response_json

    # Pull the credential id straight from the response dict (it's a
    # base64url string per WebAuthn spec). No pydantic parse needed.
    cred_id_str = response_data.get("id")
    if not cred_id_str or not isinstance(cred_id_str, str):
        raise WebAuthnAuthError("Assertion missing credential id.")
    try:
        cred_id_b = base64url_to_bytes(cred_id_str)
    except Exception as e:
        raise WebAuthnAuthError(f"Bad credential id: {e}") from e

    # Look up the registered credential.
    row = find_hardware_key_by_credential_id(conn, cred_id_b)
    if row is None:
        raise WebAuthnAuthError(
            "Unknown credential id (revoked, never registered, or "
            "wrong user)."
        )
    if row["user_id"] != user_id:
        raise WebAuthnAuthError(
            "Credential belongs to a different user."
        )

    try:
        verified = verify_authentication_response(
            credential=response_data,
            expected_challenge=challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"]),
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError) as e:
        raise WebAuthnAuthError(f"Assertion verify failed: {e}") from e

    update_hardware_key_sign_count(conn, row["id"], verified.new_sign_count)
    return int(row["id"])


# ---------------------------------------------------------------------------
# Passkey / discoverable-credential login (2026-04-29)
# ---------------------------------------------------------------------------
#
# A "passkey" in WebAuthn terms is just a discoverable (resident) credential
# with userVerification. The crypto + protocol are the same as the existing
# hardware-key flow; the difference is the *user experience*:
#
#   * Browser autofill ("conditional UI") suggests a passkey at the email
#     field. User picks one without typing.
#   * No email needs to be known at the begin step. The browser returns the
#     credential plus a userHandle that the server uses to look up the
#     account.
#
# These two helpers are an additional path alongside the existing
# begin_authentication / finish_authentication. The original "email -> touch"
# flow stays for hardware keys that aren't discoverable.
#
# Challenge storage: we don't have a user_id at begin time. The caller
# (login route) holds the challenge bytes in a short-lived signed cookie
# (same shape as the existing dev-keypair challenge cookie); finish reads
# it back. No DB row needed -- a single-use challenge that lives only for
# the duration of one login attempt.


def begin_passkey_authentication(
    rp_id: str,
    *,
    require_user_verification: bool = True,
) -> tuple[str, bytes]:
    """Generate authentication options for a discoverable-credential
    (passkey) login. Returns ``(options_json, challenge_bytes)``.

    The caller is responsible for stashing ``challenge_bytes`` so
    ``finish_passkey_authentication`` can verify (typically a
    short-lived signed cookie). No user_id / email needed at begin
    time -- the browser surfaces a credential picker via conditional
    UI; the picked credential's ``userHandle`` resolves the user at
    finish time.
    """
    _require_config(rp_id, "any")
    uv = (
        UserVerificationRequirement.REQUIRED
        if require_user_verification
        else UserVerificationRequirement.PREFERRED
    )
    opts = generate_authentication_options(
        rp_id=rp_id,
        # Empty allow_credentials => discoverable. Browser shows
        # the OS-level passkey picker / autofill instead of a
        # narrow "touch this specific key" prompt.
        allow_credentials=[],
        user_verification=uv,
    )
    return options_to_json(opts), opts.challenge


def finish_passkey_authentication(
    conn: sqlite3.Connection,
    *,
    rp_id: str,
    origin: str | list[str],
    response_json: str | dict,
    challenge: bytes,
) -> tuple[int, int]:
    """Verify the assertion + resolve the user from the credential's
    ``userHandle``. Returns ``(user_id, hardware_key_id)``.

    Caller hands ``challenge`` back from wherever it stashed it at
    begin time (signed cookie, etc.). The credential's ``userHandle``
    is the server-issued ``users.webauthn_user_handle`` -- the
    browser echoes it back in the assertion for discoverable
    credentials. We use it to look up the user without trusting any
    client-supplied email.
    """
    _require_config(rp_id, origin)

    if isinstance(response_json, str):
        try:
            response_data = json.loads(response_json)
        except json.JSONDecodeError as e:
            raise WebAuthnAuthError(f"Bad response JSON: {e}") from e
    else:
        response_data = response_json

    # Credential id straight from the response (base64url string).
    cred_id_str = response_data.get("id")
    if not cred_id_str or not isinstance(cred_id_str, str):
        raise WebAuthnAuthError("Assertion missing credential id.")
    try:
        cred_id_b = base64url_to_bytes(cred_id_str)
    except Exception as e:
        raise WebAuthnAuthError(f"Bad credential id: {e}") from e

    # Look up the registered credential by id (no user_id known yet).
    row = find_hardware_key_by_credential_id(conn, cred_id_b)
    if row is None:
        raise WebAuthnAuthError(
            "Unknown credential id (revoked, never registered)."
        )

    # Cross-check: the assertion's userHandle (when present for
    # discoverable credentials) must match the credential row's
    # owner's webauthn_user_handle. Defense-in-depth -- prevents a
    # caller from claiming a credential they couldn't have signed.
    user_handle_b64 = (
        response_data.get("response", {}).get("userHandle")
    )
    if user_handle_b64:
        try:
            user_handle_bytes = base64url_to_bytes(user_handle_b64)
        except Exception:
            user_handle_bytes = None
        if user_handle_bytes is not None:
            owner = find_user_by_webauthn_handle(conn, user_handle_bytes)
            if owner is None or owner["id"] != row["user_id"]:
                raise WebAuthnAuthError(
                    "userHandle does not match credential owner."
                )

    try:
        verified = verify_authentication_response(
            credential=response_data,
            expected_challenge=challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"]),
            require_user_verification=True,  # passkeys carry UV
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError) as e:
        raise WebAuthnAuthError(f"Assertion verify failed: {e}") from e

    update_hardware_key_sign_count(conn, row["id"], verified.new_sign_count)
    return int(row["user_id"]), int(row["id"])
