"""Punch 429 / 430 / 432: the per-account MSAL token cache survives a backup and a
restore, wherever the config puts the data dir, and an unencrypted legacy cache
is reported on the READ path, not only during a backup.

* 432: the collector searched ``Path(persistence.db_path).parent`` while the
  writer (``providers.factory``) writes CWD-relative ``./data``. With a db_path
  elsewhere, every cache was silently left out of the bundle.
* 429: inclusion and byte round-trip were proven, restorability was not. Here a
  bundled cache, Fernet AND legacy plaintext, is restored to disk and loaded by
  the provider's own loader (``Office365Provider._init_cache``, the code a running
  install uses), and MSAL returns the refresh token from it. The legacy branch is
  driven through ``build_full_bundle``, not the predicate alone. Offline limit:
  whether Entra ACCEPTS the token is a network fact no unit test can show; what is
  proven is that the restored file yields the same refresh token to MSAL.
* 430: the loader raises the at-rest WARNING (naming the file) for a legacy
  plaintext cache; only ``_msal_cache_crypto`` may test the legacy shape.
"""
from __future__ import annotations

import ast
import json
import logging
from pathlib import Path

import msal
import pytest

from _pin_harness import iter_src_files, parse_module, relpath
from test_backup import _FakeSecrets, _seed_test_config, _seed_test_db

from email_triage.backup import build_full_bundle, unbundle
from email_triage.providers import _msal_cache_crypto
from email_triage.providers.factory import msal_cache_path_for_account

_PASS = "operator-bundle-passphrase-32"
_RT = "rt-punch429-secret"


def _cache_json() -> str:
    """A minimal MSAL cache holding one refresh token, in MSAL's own schema."""
    return json.dumps({
        "RefreshToken": {
            "uid.utid-login.microsoftonline.com-refreshtoken-cid--": {
                "credential_type": "RefreshToken", "secret": _RT,
                "home_account_id": "uid.utid", "environment": "login.microsoftonline.com",
                "client_id": "cid", "target": "",
            },
        },
        "Account": {}, "IdToken": {}, "AccessToken": {}, "AppMetadata": {},
    })


@pytest.fixture
def fernet_key(monkeypatch):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    _msal_cache_crypto._reset_master_key_cache_for_tests()
    monkeypatch.setattr(_msal_cache_crypto, "_get_master_key", lambda: key)
    yield key
    _msal_cache_crypto._reset_master_key_cache_for_tests()


def _bundle(tmp_path: Path, data_dir: Path) -> dict:
    conn = _seed_test_db(tmp_path / "triage.db")
    cfg = _seed_test_config(tmp_path / "email-triage.yaml")
    try:
        blob = build_full_bundle(
            db_conn=conn, config_path=cfg, data_dir=data_dir, cert_dir=None,
            secrets_provider=_FakeSecrets({"ET_MASTER_KEY": "k" * 32}),
            master_key_name="ET_MASTER_KEY", passphrase=_PASS,
            include_master_key=False, include_tls_certs=False, include_logs=False,
            operator_email="op@example.com", hostname="h.invalid", schema_version=1,
        )
    finally:
        conn.close()
    return unbundle(blob, passphrase=_PASS).files


def _refresh_tokens_after_restore(tmp_path: Path, name: str, data: bytes) -> list[str]:
    """Restore one bundled cache file to a fresh dir and load it with the
    provider's own loader; return the refresh-token secrets MSAL finds."""
    from email_triage.providers.office365 import Office365Provider

    restored = tmp_path / "restored" / name
    restored.parent.mkdir(parents=True, exist_ok=True)
    restored.write_bytes(data)
    prov = Office365Provider(client_id="cid", token_cache_path=str(restored))
    cache = prov._init_cache()
    return [rt["secret"]
            for rt in list(cache.search(msal.TokenCache.CredentialType.REFRESH_TOKEN))]


def test_432_a_cache_is_bundled_when_db_path_is_not_under_the_cwd(
        tmp_path, monkeypatch, fernet_key):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.chdir(run)
    cache = msal_cache_path_for_account(5)          # ./data/msal_cache_5.json (CWD)
    cache.parent.mkdir(parents=True)
    cache.write_bytes(_msal_cache_crypto.encrypt_cache(_cache_json()))
    cfg_data = tmp_path / "elsewhere"               # Path(db_path).parent
    cfg_data.mkdir()
    files = _bundle(tmp_path, cfg_data)
    assert "data/msal_cache_5.json" in files, (
        "the collector searched only the config data dir; the writer's cache "
        "under the CWD was left out of the bundle")
    assert files["data/msal_cache_5.json"].data == cache.read_bytes()


def _two_dirs_one_name(tmp_path, monkeypatch, cwd_bytes: bytes, cfg_bytes: bytes):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.chdir(run)
    cwd_copy = msal_cache_path_for_account(5)       # ./data/msal_cache_5.json (CWD)
    cwd_copy.parent.mkdir(parents=True)
    cwd_copy.write_bytes(cwd_bytes)
    cfg_data = tmp_path / "elsewhere"
    cfg_data.mkdir()
    (cfg_data / "msal_cache_5.json").write_bytes(cfg_bytes)
    return cwd_copy.resolve(), cfg_data


def test_432_a_same_name_clash_with_identical_bytes_is_bundled_once(
        tmp_path, monkeypatch, fernet_key):
    blob = _msal_cache_crypto.encrypt_cache(_cache_json())
    _cwd, cfg_data = _two_dirs_one_name(tmp_path, monkeypatch, blob, blob)
    files = _bundle(tmp_path, cfg_data)
    assert files["data/msal_cache_5.json"].data == blob
    assert sum(1 for k in files if k.endswith("msal_cache_5.json")) == 1


def test_432_a_same_name_clash_with_different_bytes_refuses_the_bundle(
        tmp_path, monkeypatch, fernet_key):
    # Panel Z SHOULD-Z1-3: a backup run from a CWD whose ./data belongs to another
    # install would bundle that install's token under this install's account id.
    # Which file is the real one cannot be known here, so refuse (fail closed).
    from email_triage.backup import ArtifactClashError

    cwd_copy, cfg_data = _two_dirs_one_name(
        tmp_path, monkeypatch, _msal_cache_crypto.encrypt_cache(_cache_json()),
        _msal_cache_crypto.encrypt_cache(_cache_json().replace(_RT, "rt-other")))
    with pytest.raises(ArtifactClashError) as exc:
        _bundle(tmp_path, cfg_data)
    msg = str(exc.value)
    assert str(cwd_copy) in msg and str((cfg_data / "msal_cache_5.json").resolve()) in msg


@pytest.mark.parametrize("shape", ["fernet", "legacy_plaintext"])
def test_429_a_bundled_cache_restores_to_a_usable_refresh_token(
        tmp_path, monkeypatch, fernet_key, shape):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    raw = (_msal_cache_crypto.encrypt_cache(_cache_json()) if shape == "fernet"
           else _cache_json().encode("utf-8"))
    (data_dir / "msal_cache_7.json").write_bytes(raw)
    files = _bundle(tmp_path, data_dir)
    assert "data/msal_cache_7.json" in files, f"{shape} cache dropped from the bundle"
    bundled = files["data/msal_cache_7.json"].data
    assert bundled == raw
    assert _refresh_tokens_after_restore(tmp_path, "msal_cache_7.json", bundled) == [_RT]


def test_430_the_loader_warns_on_a_legacy_plaintext_cache(tmp_path, caplog, fernet_key):
    path = tmp_path / "msal_cache_9.json"
    path.write_bytes(_cache_json().encode("utf-8"))
    with caplog.at_level(logging.WARNING):
        assert _refresh_tokens_after_restore(tmp_path, path.name, path.read_bytes()) == [_RT]
    legacy = [r for r in caplog.records if "LEGACY PLAINTEXT" in r.getMessage()]
    assert legacy, "the read path loaded an unencrypted refresh token without the WARNING"
    assert any(str(getattr(r, "source", "")).endswith("msal_cache_9.json") for r in legacy)


def _legacy_shape_callers(trees) -> list[str]:
    out = []
    for rel, tree in trees:
        if rel == "providers/_msal_cache_crypto.py":
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                f = n.func
                name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                if name == "looks_like_legacy_plaintext":
                    out.append(f"{rel}:{n.lineno}")
    return out


def test_430_only_the_crypto_module_tests_the_legacy_shape():
    """A reader that tests the legacy shape itself skips the at-rest WARNING (the
    pre-430 loader did, logging INFO). Readers call ``read_legacy_plaintext`` /
    ``is_valid_cache_payload``, which own the shape AND the warning."""
    trees = [(relpath(p), t) for p in iter_src_files() for t in [parse_module(p)] if t]
    assert not _legacy_shape_callers(trees)
    bad = ast.parse("def f(raw):\n    return looks_like_legacy_plaintext(raw)\n")
    assert _legacy_shape_callers([("providers/office365.py", bad)]) == [
        "providers/office365.py:2"]
