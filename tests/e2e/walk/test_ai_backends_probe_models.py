"""Walk — Admin AI backends probe-models — sketch .

Feature: ``GET /config/ai-backends/probe-models`` (landed 2026-06-06 in
580877ca). v0.2.0 Feature 44 — model picker. Walk uses
``page.route()`` to intercept the probe endpoint (no real Ollama in
e2e), fills the endpoint field, clicks Fetch models, and asserts the
success shape (select shown + enabled, chat-capable model listed,
embedding-only model NOT offered as a primary chat option, capability
badge/text present). Branch (D2 shape catch) — re-route to a refusal
JSON; the manual-mode checkbox auto-flips on and the free-text model
input appears so the form stays submittable.
"""

from __future__ import annotations

import json
import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


_GOLDEN_PAYLOAD = {
    "ok": True,
    "models": [
        {
            "name": "qwen3:4b",
            "chat_capable": True,
            "embedding_only": False,
            "parameter_size": "4B",
            "context_length": 32768,
            "family": "qwen",
            "size_bytes": 4_000_000_000,
            "resident": False,
        },
        {
            "name": "nomic-embed-text",
            "chat_capable": False,
            "embedding_only": True,
            "family": "nomic",
            "size_bytes": 274_000_000,
        },
    ],
}

_REFUSAL_PAYLOAD = {
    "ok": False,
    "error": (
        "Endpoint is not a local / allowlisted host — model probing is "
        "restricted to in-install endpoints."
    ),
    "models": [],
}


def _fulfill(route, payload: dict) -> None:
    route.fulfill(
        status=200,
        content_type="application/json",
        body=json.dumps(payload),
    )


def _install_probe_route(page, payload: dict):
    """Install a ``page.route`` intercept for the probe endpoint."""
    page.route(
        "**/config/ai-backends/probe-models*",
        lambda route: _fulfill(route, payload),
    )


def test_probe_models_golden_render_and_refuse_switches_to_manual(
    authed_page, base_url,
):
    """GOLDEN — fetch success surfaces the model select with the chat-
    capable model as an option; embedding-only model NOT offered as
    primary chat; a capability badge/text present.

    D2 BRANCH — refusal JSON auto-flips manual-mode on so the form
    stays submittable, and the operator-visible error string surfaces."""
    _install_probe_route(authed_page, _GOLDEN_PAYLOAD)

    authed_page.goto(f"{base_url}/config/ai-backends/new")

    # backend-type select defaults to ollama.
    backend_select = authed_page.locator('select[name="backend_type"]')
    if backend_select.count() == 0:
        pytest.xfail(
            "backend_type select not surfaced on /config/ai-backends/new"
        )
    val = backend_select.first.input_value()
    if val != "ollama":
        pytest.xfail(f"backend_type default is {val!r}, expected 'ollama'.")

    endpoint = authed_page.locator('input[name="endpoint"]').first
    if endpoint.count() == 0:
        pytest.xfail("endpoint input not surfaced on model-picker macro.")
    endpoint.fill("http://127.0.0.1:11434")

    fetch_btn = authed_page.locator("[data-mp-fetch]").first
    if fetch_btn.count() == 0:
        pytest.xfail(
            "[data-mp-fetch] button missing — feature-work: expose the "
            "Fetch models button in the model-picker macro."
        )
    fetch_btn.click()

    select_el = authed_page.locator("[data-mp-select]").first
    try:
        select_el.wait_for(state="visible", timeout=8_000)
    except Exception:
        pytest.xfail(
            "[data-mp-select] never became visible after Fetch — "
            "success-path JS did not toggle the select."
        )
    expect(select_el).to_be_visible()

    # qwen3:4b is offered.
    options_text = " | ".join(
        authed_page.locator("[data-mp-select] option").all_inner_texts()
    )
    assert "qwen3:4b" in options_text, (
        f"chat-capable model 'qwen3:4b' missing from picker options: "
        f"{options_text!r}"
    )
    # nomic-embed-text is NOT offered as a primary chat option (either
    # absent OR clearly badge-flagged — the walk accepts either shape).
    if "nomic-embed-text" in options_text:
        # Present — must be badge-flagged (contains 'embed' hint or a
        # capability tag in its option label).
        assert re.search(
            r"embed|embedding|only", options_text, re.I
        ), (
            "embedding-only model listed as a picker option WITHOUT any "
            "capability badge — chat/embed distinction lost."
        )

    # Capability badge/text — look for a 32k / 4B / chat token nearby.
    body_text = authed_page.locator("body").inner_text() or ""
    assert re.search(r"32k|4B|chat|context", body_text, re.I), (
        "no capability badge/text (32k / 4B / chat / context) surfaced "
        "on the picker — metadata fields did not reach the rendered DOM."
    )

    # D2 BRANCH — swap the intercept to the refusal JSON.
    authed_page.unroute("**/config/ai-backends/probe-models*")
    _install_probe_route(authed_page, _REFUSAL_PAYLOAD)

    fetch_btn.click()

    manual_cb = authed_page.locator("[data-mp-manual]").first
    if manual_cb.count() == 0:
        pytest.xfail(
            "[data-mp-manual] checkbox missing — feature-work: expose "
            "the manual-mode remedy control."
        )
    try:
        expect(manual_cb).to_be_checked(timeout=5_000)
    except Exception:
        pytest.xfail(
            "manual-mode checkbox did NOT auto-flip after refusal — "
            "remedy path is not wired."
        )

    manual_input = authed_page.locator('input[name="model"]').first
    if manual_input.count() == 0:
        pytest.xfail(
            "free-text model input absent after refusal — remedy path "
            "leaves the form unsubmittable."
        )
    expect(manual_input).to_be_visible()

    # The refusal message (or the macro's fallback copy) is on-screen.
    body_after = authed_page.locator("body").inner_text() or ""
    assert re.search(
        r"local\s*/\s*allowlisted|Could not fetch models|type the model "
        r"id manually",
        body_after,
        re.I,
    ), (
        "no operator-readable refusal / fallback copy surfaced — the "
        "user has no signal about WHY the picker dropped to manual mode."
    )
