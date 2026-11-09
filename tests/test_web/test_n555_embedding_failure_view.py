"""N-555 / punch 552: an embedder failure is VISIBLE in the rendered views (PD-17).

With the fallback chain gone, a failing embedder has three operator-facing
surfaces and one user-facing one. Each is rendered here under StrictUndefined,
so a template still reading a removed key (``fallback_backend``,
``_m.primary``, ``_life_fb``) fails as a 500 instead of rendering blank:

* the AI Backends tab: the backend's Errors count and Last error, and no
  fallback form;
* /admin/stats: the embedding card's error row (lenient render; see that
  test for the pre-existing StrictUndefined gaps in stats.html);
* /profile/style-data: the gate's "requires the local embedding backend"
  reason when the runtime is refused, which a configured fallback used to hide.
"""

from __future__ import annotations

import email_triage.embedding_bits as embedding_bits
from email_triage.config import EmbeddingConfig
from email_triage.engine.embedding_backend import SentenceTransformersBackend


def _configure_failing_embedder(app, monkeypatch) -> None:
    backend = SentenceTransformersBackend(model="all-MiniLM-L6-v2")
    backend._metrics.record_failure(RuntimeError("runtime refused"))
    monkeypatch.setattr(
        app.state.config, "embedding",
        EmbeddingConfig(backend="sentence_transformers", model_name="all-MiniLM-L6-v2"),
    )
    monkeypatch.setattr(app.state, "embedding_backend", backend, raising=False)
    monkeypatch.setattr(app.state, "embedding_model", "all-MiniLM-L6-v2", raising=False)


def test_the_ai_backends_tab_shows_the_error_and_no_fallback_form(
    client, app, admin_cookies, strict_undefined_templates, monkeypatch,
):
    _configure_failing_embedder(app, monkeypatch)
    resp = client.get("/config?tab=ai_backends", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:800]
    flat = " ".join(resp.text.split())
    assert "Last error: <code>RuntimeError</code>" in flat
    assert 'name="fallback_backend"' not in resp.text
    assert "Embedding fallback" not in resp.text
    assert "Fallback activations" not in resp.text


def test_admin_stats_renders_the_embedders_error_row(
    client, app, admin_cookies, monkeypatch,
):
    """Lenient render, the production mode. stats.html is NOT StrictUndefined-
    clean at base 09363ca7, independent of this change: ``_emb.lifetime`` on
    the unconfigured ``{"configured": False}`` block (stats.html:164) and
    ``{% if _single_life.calls %}`` on an empty lifetime slice (:201) both
    raise under StrictUndefined with no embedder and with one. The content
    assertions below carry the check instead."""
    _configure_failing_embedder(app, monkeypatch)
    resp = client.get("/admin/stats", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:800]
    flat = " ".join(resp.text.split())
    assert "<td><code>errors</code></td>" in flat
    assert '<strong style="color:var(--pico-del-color);">1</strong>' in flat
    assert "fallback_fires" not in resp.text
    assert "primary.errors" not in resp.text


def test_style_data_names_a_refused_runtime_instead_of_hiding_it(
    client, app, user_cookies, strict_undefined_templates, monkeypatch,
):
    _configure_failing_embedder(app, monkeypatch)
    monkeypatch.setattr(embedding_bits, "is_runtime_ready", lambda: False)
    resp = client.get("/profile/style-data", cookies=user_cookies)
    assert resp.status_code == 200, resp.text[:800]
    flat = " ".join(resp.text.split())
    assert "This feature requires the local embedding backend." in flat
