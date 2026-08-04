"""N-151 — MSAL cache encryption behaviour (2026-07-08).

Three-legged coverage matching the fail-CLOSED contract in
``providers._msal_cache_crypto``:

1. Round-trip: ``encrypt_cache`` → ``decrypt_cache`` is identity for
   any UTF-8 plaintext + returns Fernet ciphertext (starts with
   ``b"gAAAAA"``).
2. Legacy migration: a plaintext MSAL cache file on disk is read on
   ``_init_cache`` + re-written as ciphertext on ``_save_cache``.
3. Corrupt / wrong-key file: ``_init_cache`` returns an EMPTY cache
   without falling back to a plaintext read — the process re-auths.

Master-key resolution is monkeypatched to a fixed Fernet key per test
(``_get_master_key`` is process-cached via lru_cache; the tests call
``_reset_master_key_cache_for_tests`` in the fixture).
"""
from __future__ import annotations

import importlib.util
import json

import pytest
from cryptography.fernet import Fernet

# N-151 db-sme fold #5: skip the behaviour tests on any CI leg that
# lacks the optional `msal` extra — `Office365Provider.__init__` raises
# ImportError when `HAS_MSAL=False`.  `find_spec` avoids paying the
# import cost during collection.
pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("msal") is None,
    reason="N-151: msal optional extra not installed on this CI leg",
)


@pytest.fixture()
def fake_master_key(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """Install a fixed Fernet key as the master-key accessor's result."""
    from email_triage.providers import _msal_cache_crypto

    key = Fernet.generate_key()
    # Clear the real accessor's lru_cache BEFORE monkeypatching (the
    # monkeypatch replaces the callable with a plain lambda that has no
    # `.cache_clear` attr; clearing after would raise AttributeError).
    _msal_cache_crypto._reset_master_key_cache_for_tests()
    monkeypatch.setattr(
        _msal_cache_crypto, "_get_master_key", lambda: key
    )
    yield key


def test_round_trip_identity(fake_master_key: bytes) -> None:
    from email_triage.providers._msal_cache_crypto import (
        decrypt_cache, encrypt_cache,
    )
    plaintext = json.dumps({
        "AccessToken": {"foo": "bar"},
        "RefreshToken": {"baz": "qux"},
    })
    ct = encrypt_cache(plaintext)
    assert ct.startswith(b"gAAAAA"), (
        "Fernet ciphertext must start with the version-byte + timestamp "
        "b64 marker; a leading `{` would indicate a plaintext write."
    )
    assert decrypt_cache(ct) == plaintext


def test_decrypt_returns_none_on_wrong_key(fake_master_key: bytes) -> None:
    """Wrong master key → None; MUST NOT fall back to plaintext read."""
    from email_triage.providers import _msal_cache_crypto
    from email_triage.providers._msal_cache_crypto import (
        decrypt_cache, encrypt_cache,
    )

    ct = encrypt_cache('{"AccessToken": {}}')
    # Rotate the master key mid-test
    wrong_key = Fernet.generate_key()
    _msal_cache_crypto._get_master_key = lambda: wrong_key
    assert decrypt_cache(ct) is None


def test_decrypt_returns_none_on_corrupt(fake_master_key: bytes) -> None:
    from email_triage.providers._msal_cache_crypto import decrypt_cache

    assert decrypt_cache(b"not-fernet-at-all") is None
    assert decrypt_cache(b"") is None
    # Truncated ciphertext
    from email_triage.providers._msal_cache_crypto import encrypt_cache
    good = encrypt_cache("{}")
    assert decrypt_cache(good[:20]) is None


def test_looks_like_legacy_plaintext_predicate() -> None:
    from email_triage.providers._msal_cache_crypto import (
        looks_like_legacy_plaintext,
    )
    # Legacy plaintext MSAL cache
    assert looks_like_legacy_plaintext(b'{"AccessToken": {}}')
    assert looks_like_legacy_plaintext(b"{}")
    # Leading whitespace tolerated
    assert looks_like_legacy_plaintext(b"  {}")
    # Fernet ciphertext (starts with `gAAAAA`) is NOT plaintext-shaped
    assert not looks_like_legacy_plaintext(b"gAAAAA-not-json-body")
    # Random bytes not JSON
    assert not looks_like_legacy_plaintext(b"garbage")
    assert not looks_like_legacy_plaintext(b"")


def test_provider_init_cache_reads_encrypted(
    tmp_path, fake_master_key: bytes,
) -> None:
    """``Office365Provider._init_cache`` decrypts a Fernet-shaped file."""
    from email_triage.providers._msal_cache_crypto import encrypt_cache
    from email_triage.providers.office365 import Office365Provider

    cache_path = tmp_path / "msal_cache.json"
    # Pre-seed the disk with a Fernet-encrypted MSAL-shaped payload
    payload = '{"AccessToken": {"tok": {"secret": "x"}}}'
    cache_path.write_bytes(encrypt_cache(payload))

    p = Office365Provider(
        client_id="cid", tenant_id="tid",
        token_cache_path=str(cache_path),
        username="u@example.com",
    )
    cache = p._init_cache()
    assert json.loads(cache.serialize()) == json.loads(payload)


def test_provider_init_cache_reads_legacy_plaintext(
    tmp_path, fake_master_key: bytes,
) -> None:
    """Legacy plaintext file on disk is read one-shot (migration)."""
    from email_triage.providers.office365 import Office365Provider

    cache_path = tmp_path / "msal_cache.json"
    payload = '{"AccessToken": {"tok": {"secret": "x"}}}'
    cache_path.write_bytes(payload.encode("utf-8"))

    p = Office365Provider(
        client_id="cid", tenant_id="tid",
        token_cache_path=str(cache_path),
        username="u@example.com",
    )
    cache = p._init_cache()
    assert json.loads(cache.serialize()) == json.loads(payload)


def test_provider_init_cache_fails_closed_on_corrupt(
    tmp_path, fake_master_key: bytes,
) -> None:
    """Corrupt file → empty in-memory cache, NO plaintext fallback."""
    from email_triage.providers.office365 import Office365Provider

    cache_path = tmp_path / "msal_cache.json"
    # Not Fernet, not JSON → both decrypt AND legacy-shaped detect fail
    cache_path.write_bytes(b"\x00\x01\x02not-fernet-not-json")

    p = Office365Provider(
        client_id="cid", tenant_id="tid",
        token_cache_path=str(cache_path),
        username="u@example.com",
    )
    cache = p._init_cache()
    # An empty MSAL cache serialises to "{}" — nothing was loaded from
    # the corrupt file.  The next silent-acquire will fail + trigger
    # re-auth, which is the fail-CLOSED contract.
    assert cache.serialize() == "{}"


def test_provider_save_cache_writes_ciphertext(
    tmp_path, fake_master_key: bytes,
) -> None:
    """``_save_cache`` writes Fernet ciphertext (never plaintext)."""
    import msal  # noqa: F401  # provider optional-import guard

    from email_triage.providers._msal_cache_crypto import decrypt_cache
    from email_triage.providers.office365 import Office365Provider

    cache_path = tmp_path / "msal_cache.json"
    p = Office365Provider(
        client_id="cid", tenant_id="tid",
        token_cache_path=str(cache_path),
        username="u@example.com",
    )
    cache = p._init_cache()
    # Simulate state change so _save_cache actually writes.  Real
    # cache mutation happens via msal internal machinery; here we
    # directly deserialize a payload + toggle the state flag.
    cache.deserialize('{"AccessToken": {"tok": {"secret": "y"}}}')
    cache.has_state_changed = True

    p._save_cache()

    raw = cache_path.read_bytes()
    assert raw.startswith(b"gAAAAA"), (
        "N-151 fail-CLOSED contract broken: _save_cache wrote non-Fernet "
        "bytes.  A leading `{` here means the plaintext-write regression "
        "landed."
    )
    # Round-trip through decrypt to confirm the payload preserved
    assert json.loads(decrypt_cache(raw)) == {
        "AccessToken": {"tok": {"secret": "y"}}
    }
    # Permission mode preserved from atomic_write_bytes contract
    # (skip on Windows where POSIX mode is not enforced)
    import os
    if os.name == "posix":
        import stat
        assert stat.S_IMODE(cache_path.stat().st_mode) == 0o600


def test_provider_legacy_to_encrypted_migration(
    tmp_path, fake_master_key: bytes,
) -> None:
    """Full migration cycle: legacy plaintext in → ciphertext out."""
    from email_triage.providers._msal_cache_crypto import (
        decrypt_cache, looks_like_legacy_plaintext,
    )
    from email_triage.providers.office365 import Office365Provider

    cache_path = tmp_path / "msal_cache.json"
    legacy = '{"AccessToken": {"legacy": {"foo": "bar"}}}'
    cache_path.write_bytes(legacy.encode("utf-8"))
    assert looks_like_legacy_plaintext(cache_path.read_bytes())

    p = Office365Provider(
        client_id="cid", tenant_id="tid",
        token_cache_path=str(cache_path),
        username="u@example.com",
    )
    cache = p._init_cache()
    assert json.loads(cache.serialize()) == json.loads(legacy)

    # Trigger a save — cache is loaded fresh, `has_state_changed` is
    # False until we toggle it (msal only sets it on real mutation).
    cache.has_state_changed = True
    p._save_cache()

    raw = cache_path.read_bytes()
    assert not looks_like_legacy_plaintext(raw), (
        "After migration write, file MUST be Fernet ciphertext — a still-"
        "plaintext-shaped file means _save_cache took a plaintext path."
    )
    assert raw.startswith(b"gAAAAA")
    assert json.loads(decrypt_cache(raw)) == json.loads(legacy)


@pytest.mark.no_master_key
def test_provider_save_cache_refuses_write_when_master_key_unavailable(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N-151-tail fail-CLOSED refuse-write path — DA fold N-151-tail2 (2026-07-09).

    Anchors the SOFT variant of DA fold P4 (`_master_key_available`
    boot-time probe + `_save_cache` refuse-on-False) against the
    N-151-tail2 root-cause promotion of the fake-master-key autouse to
    repo-root scope.  Without this positive assertion the widened
    autouse would silently mask a regression that removed the
    refuse-write branch: every existing test would still pass, and
    `_save_cache` could quietly write ciphertext (or worse, plaintext)
    without a master key.

    Uses `@pytest.mark.no_master_key` to opt OUT of the repo-root
    `_n151_msal_master_key_autouse` fixture so the fail-CLOSED path is
    actually reachable.
    """
    import msal  # noqa: F401  # provider optional-import guard

    from email_triage.providers import _msal_cache_crypto
    from email_triage.providers.office365 import Office365Provider

    # Force `_get_master_key()` to raise — simulating a bootstrap-config
    # regression on a host that lost its master-key backing.
    _msal_cache_crypto._reset_master_key_cache_for_tests()

    def _raise_no_key() -> bytes:
        raise RuntimeError("test: master key unavailable")

    monkeypatch.setattr(
        _msal_cache_crypto, "_get_master_key", _raise_no_key,
    )

    cache_path = tmp_path / "msal_cache.json"
    p = Office365Provider(
        client_id="cid", tenant_id="tid",
        token_cache_path=str(cache_path),
        username="u@example.com",
    )
    # `__init__` probes _get_master_key + records unavailable.  Construction
    # NEVER raises (SOFT P4 contract — the raise-at-boot variant would
    # break >10 existing tests, so unavailable is recorded and enforced
    # AT THE ACTUATOR (_save_cache), per Prime Directive #8.)
    assert p._master_key_available is False, (
        "N-151-tail SOFT P4: __init__ MUST record master-key unavailable "
        "when _get_master_key() raises — the actuator gate at _save_cache "
        "depends on this flag being False to refuse the write."
    )

    # Drive the writer — has_state_changed must be True or _save_cache
    # no-ops for the wrong reason (state-unchanged, not refuse).
    cache = p._init_cache()
    cache.has_state_changed = True

    p._save_cache()

    # Fail-CLOSED contract — writer REFUSED because the master key was
    # unavailable.  NO file on disk (not plaintext, not ciphertext).
    assert not cache_path.exists(), (
        "N-151-tail fail-CLOSED contract broken: _save_cache created a "
        "file on disk while `_master_key_available=False`.  Either the "
        "actuator gate was removed OR the flag was set True on init "
        "despite `_get_master_key` raising."
    )
