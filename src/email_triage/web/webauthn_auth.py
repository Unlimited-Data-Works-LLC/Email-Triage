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
# Punch 484: the verify sites catch the library's BASE exception. py_webauthn
# 3.0.0 rejects CBOR with duplicate map keys (InvalidCBORData). It wraps the
# client-supplied CBOR in Invalid*Response itself, but decodes the STORED
# credential public key in verify_authentication_response outside that wrap
# (only InvalidSignature is caught there), so a bare InvalidCBORData reached
# our narrower (Invalid*Response, ValueError, KeyError) catch, escaped it, and
# became a 500 with no login-failure row. ValueError/KeyError stay listed: the
# library's dict coercion raises them for a malformed credential dict.
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, WebAuthnException

from email_triage.db.audit import record_hardware_key_registration
from email_triage.web.db_writelock import db_write
from email_triage.db.users import (
    consume_webauthn_challenge_txn,
    update_hardware_key_sign_count_txn,
)
from email_triage.web.db_auth_helpers import (
    consume_webauthn_challenge,
    find_hardware_key_by_credential_id,
    find_user_by_webauthn_handle,
    get_or_create_webauthn_user_handle,
    list_hardware_keys,
    store_webauthn_challenge,
    user_has_active_hardware_key as _user_has_active_hardware_key,
    WebAuthnChallenge,
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


class WebAuthnSignCountError(WebAuthnAuthError):
    """The assertion's signature counter did not advance past the stored one.

    Punch 444: a correctly signed assertion with a counter at or below the stored
    count is a cloned authenticator or a replay. It is a subclass so every caller of
    :class:`WebAuthnAuthError` is unchanged, and a caller (or a test) can tell it
    from a malformed payload or a bad signature. The library skips this check when
    both counters are 0 (synced passkeys report 0); replay of those rests on the
    single-use server-side challenge, not on this error.
    """


# The library words a counter refusal "Response sign count of N was not greater than
# current count of M" (py_webauthn 2.7.1 and 3.0.0; read from both wheels). The real-library
# test (tests/test_webauthn_real_library_counter_replay.py) fails if a bump rewords it.
_SIGN_COUNT_MARKER = "sign count"


def _assertion_verify_error(exc: BaseException) -> WebAuthnAuthError:
    """The single mapping from a failed ``verify_authentication_response`` to our
    error type: :class:`WebAuthnSignCountError` for a counter refusal, the generic
    :class:`WebAuthnAuthError` for everything else."""
    text = f"Assertion verify failed: {exc}"
    if isinstance(exc, InvalidAuthenticationResponse) and _SIGN_COUNT_MARKER in str(exc).lower():
        return WebAuthnSignCountError(text)
    return WebAuthnAuthError(text)


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

class WebAuthnStaleChallengeError(WebAuthnAuthError):
    """A challenge written by a pre-v53 image: no stored UV requirement.

    Raised ONLY from :func:`_stored_uv_requirement`'s NULL branch. Routes catch
    it ahead of the generic handler and do NOT count it as a failed login: no
    client can author such a row, and it exists for at most one challenge TTL
    after the v53 upgrade. An absent or expired challenge is NOT this class —
    that is attacker-reachable and keeps counting toward the login guard.
    """


class WebAuthnNoChallengeError(WebAuthnAuthError):
    """No server-side challenge row could be consumed: it expired, or an
    earlier presentation already consumed it (punch ).

    A REPLAY of a previously-used assertion lands here, which is why this is
    a named class: it lets a route record the refusal under its own reason
    slug instead of the generic verify failure. Unlike
    :class:`WebAuthnStaleChallengeError` it IS attacker-reachable, so a route
    that distinguishes it must still COUNT it toward the login guard.

    SCOPE: the class (and so the audit row) cannot tell a replay from an
    expiry -- both are 'the row is not there'. Distinguishing them would need
    a consumed-challenge tombstone, i.e. a schema change.
    """


# The ``webauthn_challenges.kind`` value for the discoverable-credential
# (passkey) login ceremony. ONE spelling, shared by begin + finish, so the
# kind guard in ``consume_webauthn_challenge`` cannot drift between them.
_PASSKEY_CHALLENGE_KIND = "passkey"


def _require_user_verified(verified: Any, require_uv: bool) -> None:
    """Refuse a response whose authenticator did not verify the user when UV
    was required (punch  panel).

    py_webauthn already enforces this when passed ``require_user_verification``;
    this is the layer that does not depend on the library's internals, and the
    one the suite can observe (its tests replace the library call). A result
    with no ``user_verified`` attribute is refused, not waved through.
    """
    if require_uv and not getattr(verified, "user_verified", False):
        raise WebAuthnAuthError(
            "User verification was required and was not performed."
        )


def _stored_uv_requirement(stored: WebAuthnChallenge) -> bool:
    """The user-verification requirement to ENFORCE at a finish step: the one
    its begin step stored with the challenge (punch ).

    A None comes from a challenge written before migration v53. Refuse it:
    reading it as "not required" would re-open the gap for the one ceremony
    that straddles the deploy, and the user only has to start again.
    """
    if stored.require_user_verification is None:
        raise WebAuthnStaleChallengeError(
            "This sign-in challenge predates a server update. "
            "Start the ceremony again."
        )
    return stored.require_user_verification


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
        require_user_verification=require_user_verification,
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
    ip: str | None = None,
    user_agent: str | None = None,
) -> int:
    """Verify the browser's attestation response and insert a
    ``hardware_keys`` row.

    ``response_json`` is whatever the browser POSTed back from the
    ``navigator.credentials.create()`` resolution — a dict-like
    structure with ``id`` / ``rawId`` / ``response`` / ``type``.
    ``nickname`` is the operator-supplied label (e.g.
    "YubiKey blue").

    Punch : the insert goes through
    ``db.audit.record_hardware_key_registration``, which writes the key AND its
    ``hardware_key_registered`` audit row in one transaction. ``ip`` /
    ``user_agent`` are the request's audit context for that row.

    Returns the new ``hardware_keys.id``. Raises
    ``WebAuthnAuthError`` on any verify failure.
    """
    _require_config(rp_id, origin)
    stored = consume_webauthn_challenge(
        conn, user_id=user["id"], email=None, kind="register",
    )
    if stored is None:
        raise WebAuthnNoChallengeError(
            "No active registration challenge for this user "
            "(expired or already consumed)."
        )
    require_uv = _stored_uv_requirement(stored)
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
            expected_challenge=stored.challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            # Punch : enforce what begin_registration asked for. The
            # library's default is False, so omitting this enforced nothing.
            require_user_verification=require_uv,
        )
    except (WebAuthnException, ValueError, KeyError) as e:
        raise WebAuthnAuthError(f"Registration verify failed: {e}") from e
    _require_user_verified(verified, require_uv)

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

    return record_hardware_key_registration(
        conn,
        user_id=user["id"],
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        transports=[str(t) for t in transports_raw],
        aaguid=aaguid_b,
        nickname=nickname,
        email=user.get("email") or "",
        ip=ip,
        user_agent=user_agent,
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
            "User has no active passkeys; OTP path applies."
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
        require_user_verification=require_user_verification,
    )
    return options_to_json(opts)


@db_write
def finish_authentication(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    rp_id: str,
    origin: str | list[str],
    response_json: str | dict,
) -> int:
    """Committing form of :func:`finish_authentication_txn`. Returns the
    ``hardware_keys.id`` that authenticated.

    Commits in ``finally``: the challenge burn is durable on EVERY edge (a
    refused ceremony stays burned, punch 449), and the sign_count bump with it
    on success. The commit runs before ``@db_write`` sees a raise, so its
    rollback has nothing left to undo.
    """
    try:
        return finish_authentication_txn(
            conn, user_id=user_id, rp_id=rp_id, origin=origin,
            response_json=response_json,
        )
    finally:
        conn.commit()


def finish_authentication_txn(
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

    Does NOT commit (N-520 step 2, s2 panel credential-burn ruling): the
    caller owns the transaction. The login route runs this inside
    ``record_witnessed_state_change`` so the challenge burn, the sign_count
    bump, the last_login stamp and the success row commit together; on a
    refusal the route commits the TIGHTENING burn with no success row. The
    committing form wraps this one, so the two cannot drift.
    """
    _require_config(rp_id, origin)
    stored = consume_webauthn_challenge_txn(
        conn, user_id=user_id, email=None, kind="authenticate",
    )
    if stored is None:
        raise WebAuthnNoChallengeError(
            "No active authentication challenge for this user "
            "(expired or already consumed)."
        )
    require_uv = _stored_uv_requirement(stored)
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
            expected_challenge=stored.challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"]),
            # Punch : enforce what begin_authentication asked for.
            require_user_verification=require_uv,
        )
    except (WebAuthnException, ValueError, KeyError) as e:
        raise _assertion_verify_error(e) from e
    _require_user_verified(verified, require_uv)

    update_hardware_key_sign_count_txn(conn, row["id"], verified.new_sign_count)
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
# flow stays for passkeys that aren't discoverable.
#
# Challenge storage (punch ): server-side, single-use, exactly as the
# hardware-key path does it. We don't have a user_id at begin time, so the
# row is owned by neither user_id nor email and is named by its primary key;
# begin returns that id and finish consumes the row by it (delete-on-read).
#
# This used to be a signed cookie holding the challenge BYTES, with nothing
# consumed anywhere: the finish step took the challenge as a parameter and
# deleted the cookie only on the success path. Neither the cookie's
# ``max_age`` nor ``delete_cookie`` binds an attacker replaying with a script
# -- both are instructions to a compliant browser -- and the library's
# sign_count guard is skipped entirely at 0/0, which is what every synced
# passkey (iCloud Keychain, Google Password Manager) reports. So a captured
# assertion + cookie pair was replayable for as long as the signature held.
# The server-side row is the control: the second presentation finds nothing
# to consume and is refused before the library runs, regardless of signature
# validity and regardless of sign_count.


def begin_passkey_authentication(
    conn: sqlite3.Connection, *, rp_id: str,
) -> tuple[str, int]:
    """Generate authentication options for a discoverable-credential
    (passkey) login. Returns ``(options_json, challenge_id)``.

    Punch : the challenge is STORED server-side here and deleted on read
    at finish, so the caller carries only ``challenge_id`` -- an opaque handle
    to a single-use row -- and never the challenge bytes. No user_id / email
    is needed at begin time: the browser surfaces a credential picker via
    conditional UI, and the picked credential's ``userHandle`` resolves the
    user at finish time.

    Passkeys always require user verification, and
    ``finish_passkey_authentication`` enforces what is stored here. There used
    to be a parameter here that could ask for less; nothing passed it, and
    finish ignored it (punch  panel).
    """
    _require_config(rp_id, "any")
    uv = UserVerificationRequirement.REQUIRED
    opts = generate_authentication_options(
        rp_id=rp_id,
        # Empty allow_credentials => discoverable. Browser shows
        # the OS-level passkey picker / autofill instead of a
        # narrow "touch this specific key" prompt.
        allow_credentials=[],
        user_verification=uv,
    )
    challenge_id = store_webauthn_challenge(
        conn,
        user_id=None,
        email=None,
        kind=_PASSKEY_CHALLENGE_KIND,
        challenge=opts.challenge,
        # Punch : the finish step enforces what begin asked for, and
        # begin asked for REQUIRED two statements above.
        require_user_verification=True,
    )
    return options_to_json(opts), int(challenge_id)


@db_write
def finish_passkey_authentication(
    conn: sqlite3.Connection,
    *,
    rp_id: str,
    origin: str | list[str],
    response_json: str | dict,
    challenge_id: int,
) -> tuple[int, int]:
    """Committing form of :func:`finish_passkey_authentication_txn`. Returns
    ``(user_id, hardware_key_id)``. Commits in ``finally`` for the same reason
    as :func:`finish_authentication`: a refused ceremony burns its challenge.
    """
    try:
        return finish_passkey_authentication_txn(
            conn, rp_id=rp_id, origin=origin, response_json=response_json,
            challenge_id=challenge_id,
        )
    finally:
        conn.commit()


def finish_passkey_authentication_txn(
    conn: sqlite3.Connection,
    *,
    rp_id: str,
    origin: str | list[str],
    response_json: str | dict,
    challenge_id: int,
) -> tuple[int, int]:
    """Verify the assertion + resolve the user from the credential's
    ``userHandle``. Returns ``(user_id, hardware_key_id)``.

    ``challenge_id`` is the handle ``begin_passkey_authentication`` returned.
    The challenge itself is read out of the server-side row and the row is
    DELETED in the same call (punch ), so a second presentation of the
    same assertion finds nothing to consume and is refused before the library
    runs -- regardless of signature validity and regardless of ``sign_count``,
    which the library skips entirely when both counters are 0 (every synced
    passkey reports 0). The consume happens FIRST: a refused ceremony burns
    its challenge, so a failed attempt must begin again rather than retry.

    The credential's ``userHandle`` is the server-issued
    ``users.webauthn_user_handle`` -- the browser echoes it back in the
    assertion for discoverable credentials. We use it to look up the user
    without trusting any client-supplied email.

    Does NOT commit (N-520 step 2, s2 panel credential-burn ruling): the
    caller owns the transaction. The login route runs this inside
    ``record_witnessed_state_change`` so the challenge burn, the sign_count
    bump, the last_login stamp and the success row commit together; on a
    refusal the route commits the TIGHTENING burn with no success row. The
    committing form wraps this one, so the two cannot drift.
    """
    _require_config(rp_id, origin)
    stored = consume_webauthn_challenge_txn(
        conn,
        user_id=None,
        email=None,
        kind=_PASSKEY_CHALLENGE_KIND,
        challenge_id=challenge_id,
    )
    if stored is None:
        raise WebAuthnNoChallengeError(
            "No active passkey challenge for this handle (expired, or "
            "already consumed by an earlier attempt)."
        )
    require_uv = _stored_uv_requirement(stored)
    if not require_uv:
        # Fail CLOSED rather than enforce less than a passkey ceremony means:
        # begin stores True unconditionally, so a False here could only come
        # from a future begin that asked for less than this finish enforces.
        raise WebAuthnAuthError(
            "Passkey login requires user verification; the stored challenge "
            "does not."
        )

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
            expected_challenge=stored.challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"]),
            # Punch : what the begin step stored (always True here).
            require_user_verification=require_uv,
        )
    except (WebAuthnException, ValueError, KeyError) as e:
        raise _assertion_verify_error(e) from e
    _require_user_verified(verified, require_uv)

    update_hardware_key_sign_count_txn(conn, row["id"], verified.new_sign_count)
    return int(row["user_id"]), int(row["id"])
