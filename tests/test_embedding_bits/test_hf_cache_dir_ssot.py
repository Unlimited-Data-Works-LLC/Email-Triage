"""Pin: the embedding-bits hf-cache-dir naming is ONE SSOT.

The offline installer stages each model at ``$HF_HOME/<hf_cache_dir>/`` and the
backend (``engine.embedding_backend._resolve_staged_model_path``) loads it from
there BY EXPLICIT PATH — both choose the dir via
``embedding_bits.hf_cache_dir_for_model``. The manifest also carries an explicit
``hf_cache_dir`` per model. If the manifest's value drifts from the derivation,
the backend looks in the wrong dir, silently misses the staged model, and a true
air-gap reaches for the network (the exact  failure). Pin them equal.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from email_triage.embedding_bits import hf_cache_dir_for_model

_MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "scripts" / "embedding-bits-manifest.json"
)


def test_derivation_examples():
    # Bare name → implicit sentence-transformers/ org; slash name → as-is.
    assert (hf_cache_dir_for_model("all-MiniLM-L6-v2")
            == "sentence-transformers_all-MiniLM-L6-v2")
    assert (hf_cache_dir_for_model("sentence-transformers/all-MiniLM-L6-v2")
            == "sentence-transformers_all-MiniLM-L6-v2")  # same dir either way
    assert (hf_cache_dir_for_model("intfloat/multilingual-e5-base")
            == "intfloat_multilingual-e5-base")


def test_manifest_hf_cache_dir_equals_derivation_from_repo_id():
    """Every shipped manifest model's explicit ``hf_cache_dir`` must equal the
    derivation from its HF repo id (parsed from the model ``url``) — so the
    installer-staged dir and the backend's explicit-path load can't diverge."""
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    models = manifest.get("models", [])
    assert models, "manifest carries no models"
    for m in models:
        hcd = m.get("hf_cache_dir")
        assert hcd, f"model {m.get('name')!r} is missing hf_cache_dir"
        rid = re.search(r"huggingface\.co/([^/]+/[^/]+)/resolve", m.get("url", ""))
        assert rid, f"model {m.get('name')!r} url has no parseable repo id"
        repo_id = rid.group(1)
        assert hcd == hf_cache_dir_for_model(repo_id), (
            f"{m['name']}: manifest hf_cache_dir {hcd!r} != "
            f"derived {hf_cache_dir_for_model(repo_id)!r} (from repo {repo_id!r})"
        )
        # And the raw repo-id transform agrees (belt + suspenders).
        assert hcd == repo_id.replace("/", "_")


def test_every_model_stages_the_config_json_the_backend_probes_for():
    """The backend's air-gap resolver
    (``engine.embedding_backend.SentenceTransformersBackend._resolve_staged_model_path``)
    returns the staged dir ONLY when ``<staged>/config.json`` exists — that
    file is the marker it treats as "a real staged model is here." So EVERY
    shipped model MUST list ``config.json`` among its staged ``files``; if a
    future model is added without it, the installer stages the weights, the
    backend's ``(staged / "config.json").is_file()`` probe returns False, and a
    true air-gap silently reaches for the network (the exact  failure this
    SSOT exists to prevent). Pin the manifest to the backend's probe.
    """
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    models = manifest.get("models", [])
    assert models, "manifest carries no models"
    for m in models:
        names = {f.get("name") for f in m.get("files", [])}
        assert "config.json" in names, (
            f"model {m.get('name')!r} stages no config.json — the backend's "
            f"_resolve_staged_model_path probe gates on it, so an air-gap load "
            f"would silently miss this model and reach for the network. "
            f"Staged files: {sorted(names)}"
        )
