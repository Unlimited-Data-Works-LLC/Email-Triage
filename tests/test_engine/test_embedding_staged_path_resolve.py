"""Backend resolves the embedding-bits-staged model dir by EXPLICIT PATH.

The offline installer stages at $HF_HOME/<hf_cache_dir_for_model(name)>/; the
backend must load THAT path (air-gap-safe) when it exists, else fall back to the
bare name (online hub-download)."""
from __future__ import annotations

from email_triage.engine.embedding_backend import SentenceTransformersBackend
from email_triage.embedding_bits import hf_cache_dir_for_model


def test_resolves_staged_dir_when_present(tmp_path, monkeypatch):
    hf_home = tmp_path / "hf-cache"
    staged = hf_home / hf_cache_dir_for_model("intfloat/multilingual-e5-base")
    staged.mkdir(parents=True)
    (staged / "config.json").write_text("{}", encoding="utf-8")
    # Punch 547: the staged dir is DERIVED from the runtime-deps prefix; the
    # environment's HF_HOME must not choose which model files load.
    import email_triage.embedding_bits as _eb
    monkeypatch.setattr(_eb, "get_runtime_deps_path", lambda: tmp_path)
    monkeypatch.setenv("HF_HOME", str(tmp_path / "elsewhere"))

    be = SentenceTransformersBackend(model="intfloat/multilingual-e5-base")
    assert be._resolve_staged_model_path() == str(staged)


def test_returns_none_when_not_staged(tmp_path, monkeypatch):
    monkeypatch.setenv("HF_HOME", str(tmp_path / "empty"))
    be = SentenceTransformersBackend(model="all-MiniLM-L6-v2")
    assert be._resolve_staged_model_path() is None


def test_returns_none_when_no_hf_home(monkeypatch):
    monkeypatch.delenv("HF_HOME", raising=False)
    be = SentenceTransformersBackend(model="all-MiniLM-L6-v2")
    assert be._resolve_staged_model_path() is None
