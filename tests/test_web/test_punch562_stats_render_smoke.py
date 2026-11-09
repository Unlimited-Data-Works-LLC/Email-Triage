"""Punch 562 — /admin/stats renders StrictUndefined-clean on every embedding shape.

``admin/stats.html`` read ``health.embedding.lifetime.<ns>`` unconditionally,
branched on ``metrics.backend_type``, and tested counters bare (``errors``
and the lifetime ``calls`` guard). The producer
(``routers/health.py::_compute_health_detail``) returned only
``{"configured": False}`` when no embedder is configured and ``{}`` metrics when
``metrics()`` raised. Production's lenient Undefined rendered blanks;
StrictUndefined 500'd (PD-17 / R39).

Every case drives the REAL producer; only the backend on ``app.state`` varies.
(Punch 552 / N-555 removed the fallback embedder, so there is no fallback case.)
"""

from __future__ import annotations

import pytest


class _MetricsRaise:
    backend_type = "ollama"

    def metrics(self):
        raise RuntimeError("punch 562: metrics() failed")


def _backend(kind):
    if kind == "none":
        return None
    if kind == "metrics-raise":
        return _MetricsRaise()
    raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["none", "metrics-raise"])
def test_admin_stats_renders_strict_clean(
    kind, app, client, admin_cookies, monkeypatch, strict_undefined_templates,
):
    monkeypatch.setattr(app.state, "embedding_backend", _backend(kind), raising=False)
    resp = client.get("/admin/stats", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[-2000:]


def test_admin_stats_renders_when_health_snapshot_fails(
    client, admin_cookies, monkeypatch, strict_undefined_templates,
):
    """The handler degrades to ``health = {}`` when the snapshot raises."""
    import email_triage.web.routers.health as health_mod

    async def _boom(request):
        raise RuntimeError("punch 562: health snapshot failed")

    monkeypatch.setattr(health_mod, "_compute_health_detail", _boom)
    resp = client.get("/admin/stats", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[-2000:]


def test_embedding_block_has_one_shape(app, monkeypatch):
    """The producer half: configured or not, the block carries every key the
    template reads unconditionally."""
    import asyncio

    from starlette.requests import Request

    from email_triage.web.routers.health import _compute_health_detail

    for kind in ("none", "metrics-raise"):
        monkeypatch.setattr(app.state, "embedding_backend", _backend(kind), raising=False)
        req = Request({"type": "http", "app": app, "headers": [], "method": "GET", "path": "/"})
        payload, _ = asyncio.run(_compute_health_detail(req))
        emb = payload["embedding"]
        assert set(emb["lifetime"]) == {"ollama", "sentence_transformers"}, kind
        assert "backend_type" in emb["metrics"] or not emb["configured"], kind
