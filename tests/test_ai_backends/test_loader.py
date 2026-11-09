"""Tests for :func:`email_triage.ai_backends.loader.load_backend`."""

from __future__ import annotations

import asyncio

import pytest

from email_triage.ai_backends import (
    BackendAdapter,
    BackendBAARequiredError,
    BackendDisabledError,
    BackendError,
    BackendNotFoundError,
    load_backend,
)
from email_triage.ai_backends.ollama_adapter import OllamaAdapter
from email_triage.ai_backends.base import NotImplementedAdapter


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class _FakeSecrets:
    """In-memory stand-in for :class:`DbSecrets`. Mirrors the
    ``.get(key)`` surface the loader uses; supports ``.set(key, val)``
    for fixture setup."""

    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self._data = dict(mapping or {})

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value


def _fresh_db():
    """init_db backed by :memory: — already includes the v26 schema."""
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _insert_backend(
    conn,
    *,
    name="Test Backend",
    type_="openai",
    endpoint="https://api.openai.invalid/v1",
    api_key_secret_ref=None,
    model=None,
    baa_certified=0,
    baa_expires_at=None,
    enabled=1,
) -> int:
    cur = conn.execute(
        "INSERT INTO ai_backends "
        "(name, type, endpoint, api_key_secret_ref, model, "
        " baa_certified, baa_expires_at, enabled) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (name, type_, endpoint, api_key_secret_ref, model,
         baa_certified, baa_expires_at, enabled),
    )
    conn.commit()
    return int(cur.lastrowid)


# ---------------------------------------------------------------------------
# None → install default (Ollama)
# ---------------------------------------------------------------------------

def test_load_backend_none_returns_install_default_ollama():
    """Passing ``backend_id=None`` returns an OllamaAdapter with the
    install default endpoint+model."""
    conn = _fresh_db()
    try:
        adapter = load_backend(None, db_conn=conn, secrets=None)
        assert isinstance(adapter, OllamaAdapter)
        # The adapter wraps an OllamaClassifier — pull its base_url to
        # confirm the default applied.
        assert adapter._client._base_url == "http://localhost:11434"  # type: ignore[attr-defined]
    finally:
        conn.close()


def test_load_backend_none_with_config_uses_config_values():
    """When ``config`` is supplied, the install default mirrors
    ``config.classifier.ollama_url`` + ``.model``."""

    class FakeClassifierCfg:
        ollama_url = "http://homelab.invalid:11434"
        model = "qwen3.8:50b"

    class FakeTlsCfg:
        local_url_suffixes = [".home.lan"]

    class FakeConfig:
        classifier = FakeClassifierCfg()
        tls = FakeTlsCfg()

    conn = _fresh_db()
    try:
        adapter = load_backend(
            None, db_conn=conn, secrets=None, config=FakeConfig(),
        )
        assert isinstance(adapter, OllamaAdapter)
        assert adapter._client._base_url == "http://homelab.invalid:11434"  # type: ignore[attr-defined]
        assert adapter._client._model == "qwen3.8:50b"  # type: ignore[attr-defined]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  — backup_models threaded onto the style-learning complete() path
# ---------------------------------------------------------------------------

def test_decode_backup_models_value_is_tolerant():
    from email_triage.web.db import decode_backup_models_value
    assert decode_backup_models_value('["a:8b", "b:4b"]') == ["a:8b", "b:4b"]
    assert decode_backup_models_value(None) == []
    assert decode_backup_models_value("not json") == []
    assert decode_backup_models_value("{}") == []            # non-list -> []
    assert decode_backup_models_value('["x", "", "  "]') == ["x"]  # blanks dropped


def test_ollama_adapter_threads_backup_models_to_classifier():
    adapter = OllamaAdapter(
        endpoint="http://localhost:11434", model="primary:8b",
        backup_models=["b1:8b", "b2:4b"],
    )
    assert adapter._client._backup_models == ["b1:8b", "b2:4b"]  # type: ignore[attr-defined]


def test_ollama_adapter_default_has_no_backups():
    adapter = OllamaAdapter(endpoint="http://localhost:11434", model="primary:8b")
    assert adapter._client._backup_models == []  # type: ignore[attr-defined]


def test_load_backend_threads_ollama_row_backup_models():
    conn = _fresh_db()
    try:
        bid = _insert_backend(
            conn, type_="ollama", endpoint="http://localhost:11434",
            model="primary:8b",
        )
        conn.execute(
            "UPDATE ai_backends SET backup_models_json = ? WHERE id = ?",
            ('["backup:8b", "backup:4b"]', bid),
        )
        conn.commit()
        adapter = load_backend(bid, db_conn=conn, secrets=_FakeSecrets())
        assert isinstance(adapter, OllamaAdapter)
        assert adapter._client._backup_models == ["backup:8b", "backup:4b"]  # type: ignore[attr-defined]
    finally:
        conn.close()


def test_backup_models_threaded_to_adapter_only_for_ollama(monkeypatch):
    """ seam pin (PD#2): backup_models reaches an adapter constructor ONLY
    for type=='ollama'. If a future edit un-scopes it (passes it
    unconditionally), a non-ollama adapter that rejects the kwarg hits the
    TypeError fallback in load_backend — which drops EVERY kwarg
    (endpoint/model/api_key) and silently half-configures the backend. A spy
    adapter captures the kwargs load_backend actually passes, asserting the
    scoping holds for BOTH branches."""
    from email_triage.ai_backends import loader as loader_mod

    captured: dict = {}

    class _SpyAdapter:
        is_local = True
        backend_type = "spy"

        def __init__(self, **kw):
            captured.clear()
            captured.update(kw)

    conn = _fresh_db()
    try:
        for type_, endpoint, expect_backups in (
            ("ollama", "http://localhost:11434", True),
            ("openai", "https://api.openai.invalid/v1", False),
        ):
            bid = _insert_backend(
                conn, name=f"spy-{type_}", type_=type_,
                endpoint=endpoint, model="m",
            )
            conn.execute(
                "UPDATE ai_backends SET backup_models_json=? WHERE id=?",
                ('["b:8b"]', bid),
            )
            conn.commit()
            monkeypatch.setitem(loader_mod.BACKEND_TYPES, type_, _SpyAdapter)
            loader_mod.load_backend(bid, db_conn=conn, secrets=_FakeSecrets())
            assert ("backup_models" in captured) is expect_backups, (
                f"type={type_!r}: backup_models scoping wrong "
                f"(captured keys: {sorted(captured)})"
            )
    finally:
        conn.close()


def test_load_backend_install_default_threads_config_backup_models():
    class FakeClassifierCfg:
        ollama_url = "http://localhost:11434"
        model = "primary:8b"
        backup_models = ["cfg-backup:8b"]

    class FakeTlsCfg:
        local_url_suffixes = []

    class FakeConfig:
        classifier = FakeClassifierCfg()
        tls = FakeTlsCfg()

    conn = _fresh_db()
    try:
        adapter = load_backend(None, db_conn=conn, secrets=None, config=FakeConfig())
        assert isinstance(adapter, OllamaAdapter)
        assert adapter._client._backup_models == ["cfg-backup:8b"]  # type: ignore[attr-defined]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# id-driven loads
# ---------------------------------------------------------------------------

def test_load_backend_by_id_returns_correct_adapter_type():
    """The loader instantiates the adapter class registered for the
    row's ``type``."""
    conn = _fresh_db()
    try:
        local_id = _insert_backend(
            conn,
            name="Local Ollama",
            type_="ollama",
            endpoint="http://localhost:11434",
        )
        adapter = load_backend(local_id, db_conn=conn, secrets=None)
        assert isinstance(adapter, OllamaAdapter)
    finally:
        conn.close()


def test_load_backend_by_id_missing_raises_not_found():
    conn = _fresh_db()
    try:
        with pytest.raises(BackendNotFoundError):
            load_backend(99999, db_conn=conn, secrets=None)
    finally:
        conn.close()


def test_load_backend_disabled_row_raises():
    conn = _fresh_db()
    try:
        bid = _insert_backend(
            conn, name="Old", type_="ollama",
            endpoint="http://localhost:11434", enabled=0,
        )
        with pytest.raises(BackendDisabledError, match="disabled"):
            load_backend(bid, db_conn=conn, secrets=None)
    finally:
        conn.close()


def test_load_backend_unknown_type_raises_clearly(monkeypatch):
    """A row whose ``type`` is somehow not in BACKEND_TYPES (the CHECK
    constraint should prevent this, but be belt-and-braces) raises
    :class:`BackendError`, not :class:`KeyError`."""
    conn = _fresh_db()
    try:
        bid = _insert_backend(
            conn, name="Local", type_="ollama",
            endpoint="http://localhost:11434",
        )
        # Patch the registry to make this row's type unknown.
        from email_triage.ai_backends import registry as reg
        saved = reg.BACKEND_TYPES["ollama"]
        try:
            del reg.BACKEND_TYPES["ollama"]
            with pytest.raises(BackendError, match="unknown type"):
                load_backend(bid, db_conn=conn, secrets=None)
        finally:
            reg.BACKEND_TYPES["ollama"] = saved
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Secret resolution
# ---------------------------------------------------------------------------

def test_load_backend_resolves_api_key_via_secrets():
    """When ``api_key_secret_ref`` is set, the loader fetches the
    plaintext via the secrets store and hands it to the adapter."""
    conn = _fresh_db()
    secrets = _FakeSecrets({"openai_key": "sk-secret-XXX"})
    try:
        bid = _insert_backend(
            conn,
            name="OpenAI",
            type_="openai",  # placeholder adapter, but loader still resolves the key
            endpoint="https://api.openai.invalid/v1",
            api_key_secret_ref="openai_key",
        )
        # Capture what gets passed to the adapter constructor.
        captured: dict = {}

        class _Capture(NotImplementedAdapter):
            backend_type = "openai"

            def __init__(self, *args, **kwargs) -> None:
                captured.update(kwargs)
                super().__init__(**kwargs)

        from email_triage.ai_backends import registry as reg
        saved = reg.BACKEND_TYPES["openai"]
        try:
            reg.BACKEND_TYPES["openai"] = _Capture
            adapter = load_backend(bid, db_conn=conn, secrets=secrets)
            assert isinstance(adapter, _Capture)
            assert captured["api_key"] == "sk-secret-XXX"
            # Adapter does NOT expose the key publicly.
            assert "sk-secret-XXX" not in repr(adapter)
        finally:
            reg.BACKEND_TYPES["openai"] = saved
    finally:
        conn.close()


def test_load_backend_missing_secrets_provider_raises():
    """A row with ``api_key_secret_ref`` set but no secrets provider
    passed in raises a clear error rather than silently constructing
    the adapter without a key."""
    conn = _fresh_db()
    try:
        bid = _insert_backend(
            conn,
            name="OpenAI",
            type_="openai",
            endpoint="https://api.openai.invalid/v1",
            api_key_secret_ref="openai_key",
        )
        with pytest.raises(BackendError, match="no secrets provider"):
            load_backend(bid, db_conn=conn, secrets=None)
    finally:
        conn.close()


def test_load_backend_secret_missing_in_store_raises():
    """When the ``api_key_secret_ref`` points at a key that the
    secrets store doesn't know, raise rather than instantiate with
    an empty key (which would silently 401 on every call)."""
    conn = _fresh_db()
    secrets = _FakeSecrets()
    try:
        bid = _insert_backend(
            conn,
            name="OpenAI",
            type_="openai",
            endpoint="https://api.openai.invalid/v1",
            api_key_secret_ref="missing_key",
        )
        with pytest.raises(BackendError, match="not present in secrets"):
            load_backend(bid, db_conn=conn, secrets=secrets)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Key-less Ollama rows
# ---------------------------------------------------------------------------

def test_load_backend_ollama_row_with_no_secret_ref_works():
    """An ``ollama`` row with NULL ``api_key_secret_ref`` and no
    secrets provider must still load — Ollama doesn't need a key."""
    conn = _fresh_db()
    try:
        bid = _insert_backend(
            conn, name="LAN Ollama", type_="ollama",
            endpoint="http://homelab.invalid:11434",
            api_key_secret_ref=None,
        )
        adapter = load_backend(bid, db_conn=conn, secrets=None)
        assert isinstance(adapter, OllamaAdapter)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Placeholder adapter fail-fast
# ---------------------------------------------------------------------------

def test_placeholder_adapter_raises_on_chat_complete():
    """:class:`NotImplementedAdapter` is the contract for future
    migrations that add a new enum value before the concrete adapter
    lands. Pin that the first :meth:`chat_complete` call raises a
    clear :class:`NotImplementedError` with the backend type in the
    message.

    As of -A every enum value (``ollama`` / ``openai`` /
    ``azure_openai`` / ``gemini``) has a concrete adapter — so this
    test injects a placeholder via :func:`register_backend` rather
    than relying on a still-placeholder enum value. The invariant
    being pinned is the placeholder's behaviour, not which enum
    value happens to still need an adapter."""
    conn = _fresh_db()
    try:
        # Swap in a placeholder for an existing enum value, drive the
        # loader through that row, confirm the first chat_complete
        # call raises with the type in the message.
        class _Placeholder(NotImplementedAdapter):
            backend_type = "gemini"

        from email_triage.ai_backends import registry as reg
        saved = reg.BACKEND_TYPES["gemini"]
        try:
            reg.BACKEND_TYPES["gemini"] = _Placeholder
            bid = _insert_backend(
                conn,
                name="Future Backend",
                type_="gemini",
                endpoint="https://example.invalid/v1",
            )
            adapter = load_backend(bid, db_conn=conn, secrets=None)
            with pytest.raises(NotImplementedError, match="gemini"):
                asyncio.run(adapter.chat_complete(
                    [{"role": "user", "content": "x"}]
                ))
        finally:
            reg.BACKEND_TYPES["gemini"] = saved
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Adapter contract
# ---------------------------------------------------------------------------

def test_ollama_adapter_implements_chat_complete_shape(monkeypatch):
    """The OllamaAdapter delegates to OllamaClassifier.complete().
    Verify the messages list gets stitched into a single prompt that
    preserves system+user turns."""
    conn = _fresh_db()
    try:
        adapter = load_backend(None, db_conn=conn, secrets=None)

        captured_prompts: list[str] = []

        async def _fake_complete(prompt: str) -> str:
            captured_prompts.append(prompt)
            return "stitched-ok"

        monkeypatch.setattr(adapter._client, "complete", _fake_complete)

        out = asyncio.run(adapter.chat_complete([
            {"role": "system", "content": "you are a triage assistant"},
            {"role": "user", "content": "classify this"},
        ]))

        assert out == "stitched-ok"
        assert len(captured_prompts) == 1
        # System content is marked and user content is preserved.
        assert "[SYSTEM]" in captured_prompts[0]
        assert "you are a triage assistant" in captured_prompts[0]
        assert "classify this" in captured_prompts[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# require_baa_certified — the runtime BAA chokepoint (census N-63).
# A HIPAA account's PHI-egress path passes require_baa_certified=True; the
# loader must refuse an uncertified / expired backend so PHI never reaches a
# non-BAA subprocessor (§164.502(a)(1) / §164.308(b)(1)). The selector gate
# only fires at selection time — this covers the lapsed-AFTER-selection case.
# ---------------------------------------------------------------------------

_FUTURE = "2099-01-01"
_PAST = "2000-01-01"


def test_require_baa_uncertified_backend_raises():
    """An external backend with baa_certified=0 is refused for a HIPAA
    PHI caller (the live N-63 defect: PHI to an uncertified vendor)."""
    conn = _fresh_db()
    try:
        bid = _insert_backend(conn, baa_certified=0, baa_expires_at=None)
        with pytest.raises(BackendBAARequiredError):
            load_backend(bid, db_conn=conn, secrets=None,
                         require_baa_certified=True)
    finally:
        conn.close()


def test_require_baa_expired_backend_raises():
    """A once-certified backend whose BAA expiry has passed is refused."""
    conn = _fresh_db()
    try:
        bid = _insert_backend(conn, baa_certified=1, baa_expires_at=_PAST)
        with pytest.raises(BackendBAARequiredError):
            load_backend(bid, db_conn=conn, secrets=None,
                         require_baa_certified=True)
    finally:
        conn.close()


def test_require_baa_certified_future_backend_loads():
    """A BAA-certified, non-expired backend loads normally for a HIPAA
    caller — the gate must not block a valid BAA."""
    conn = _fresh_db()
    try:
        bid = _insert_backend(conn, baa_certified=1, baa_expires_at=_FUTURE)
        adapter = load_backend(bid, db_conn=conn, secrets=None,
                               require_baa_certified=True)
        assert isinstance(adapter, BackendAdapter)
    finally:
        conn.close()


def test_require_baa_false_does_not_gate_uncertified():
    """The default (require_baa_certified=False, non-HIPAA path) must NOT
    impose a BAA requirement — an uncertified backend still loads."""
    conn = _fresh_db()
    try:
        bid = _insert_backend(conn, baa_certified=0, baa_expires_at=None)
        adapter = load_backend(bid, db_conn=conn, secrets=None)
        assert isinstance(adapter, BackendAdapter)
    finally:
        conn.close()


def test_require_baa_install_default_is_exempt():
    """backend_id=None → the local install-default Ollama, which is BAA-
    exempt (no egress) even when require_baa_certified=True."""
    conn = _fresh_db()
    try:
        adapter = load_backend(None, db_conn=conn, secrets=None,
                               require_baa_certified=True)
        assert isinstance(adapter, OllamaAdapter)
    finally:
        conn.close()


def test_baa_required_error_is_a_backend_error():
    """BackendBAARequiredError subclasses BackendError so the distill
    paths' existing `except BackendError` still catches it as a backstop
    even if the dedicated handler is ever removed."""
    assert issubclass(BackendBAARequiredError, BackendError)
