"""Render the install card partial in each state.

Tests Jinja-template rendering with a synthesised install_state row
+ asserts the expected buttons / progress bars / error chips render.
Doesn't spin up the full FastAPI app — just the template engine.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

PKG_TEMPLATES = (
    Path(__file__).resolve().parent.parent.parent
    / "src" / "email_triage" / "web" / "templates"
)


@pytest.fixture
def jinja_env():
    env = Environment(
        loader=FileSystemLoader(str(PKG_TEMPLATES)),
        autoescape=select_autoescape(["html"]),
    )
    # Stub the csrf_input macro the template references
    env.globals["csrf_input"] = lambda req: ""
    env.globals["request"] = object()
    return env


def _render_card(env, state_row, runtime_ready=True, sha_short=""):
    tmpl = env.get_template("admin/config_tabs/_embedding_install_card.html")
    return tmpl.render(
        request=object(),
        install_state=state_row,
        install_manifest_sha_short=sha_short,
        install_runtime_ready=runtime_ready,
    )


def _base_row(status: str, **overrides) -> dict:
    base = {
        "status": status,
        "install_method": None,
        "manifest_sha256": None,
        "runtime_deps_path": None,
        "progress_files_done": 0,
        "progress_files_total": 0,
        "progress_bytes_done": 0,
        "progress_bytes_total": 0,
        "current_file": None,
        "attempt_count": 0,
        "last_attempt_at": None,
        "installed_at": None,
        "last_error_class": None,
        "last_error_msg": None,
        "last_error_at": None,
    }
    base.update(overrides)
    return base


def test_card_not_installed_state(jinja_env):
    html = _render_card(jinja_env, _base_row("not_installed"))
    assert "Install now" in html
    assert "Sideload pre-staged bits" in html
    assert "not installed" in html
    # No progress bar / cancel button in this state
    assert "Cancel" not in html
    # Always-visible hash-verification disclosure (normalize whitespace)
    flat = " ".join(html.split())
    assert "manifest baked into this image" in flat


def test_card_downloading_state_shows_progress_and_cancel(jinja_env):
    html = _render_card(jinja_env, _base_row(
        "downloading",
        install_method="auto",
        progress_files_done=3,
        progress_files_total=18,
        progress_bytes_done=10_000_000,
        progress_bytes_total=600_000_000,
        current_file="torch-2.5.1+cpu-cp312-cp312-linux_x86_64.whl",
    ))
    assert "Downloading files" in html
    assert "3 of 18 files" in html
    assert "torch-2.5.1+cpu" in html
    assert "Cancel" in html
    # The hx-poll wrapper is in the PARENT template, not this partial,
    # so we only confirm the cancel form here.


def test_card_verifying_state(jinja_env):
    html = _render_card(jinja_env, _base_row(
        "verifying", install_method="auto",
        progress_files_done=18, progress_files_total=18,
    ))
    assert "Verifying hashes" in html
    assert "Cancel" in html


def test_card_failed_state_surfaces_error(jinja_env):
    html = _render_card(jinja_env, _base_row(
        "failed",
        install_method="auto",
        last_error_class="HashMismatch",
        last_error_msg=(
            "SHA-256 mismatch on torch-2.5.1+cpu-cp312-cp312-linux_x86_64.whl"
        ),
        attempt_count=3,
    ))
    assert "Install failed" in html
    assert "HashMismatch" in html
    assert "torch-2.5.1+cpu" in html
    # Retry button
    assert "Retry" in html
    # 3 attempts surface
    assert "3 attempts" in html


def test_card_installed_state_shows_summary(jinja_env):
    html = _render_card(
        jinja_env,
        _base_row(
            "installed",
            install_method="auto",
            installed_at="2026-05-17T12:34:56+00:00",
            runtime_deps_path="/app/data/runtime-deps",
        ),
        sha_short="abcdef012345",
    )
    assert "Installed" in html
    assert "2026-05-17T12:34:56" in html
    assert "/app/data/runtime-deps" in html
    assert "abcdef012345" in html
    assert "Re-verify" in html
    # Re-install is in a <details> collapsible
    assert "Re-install" in html


def test_card_installed_but_runtime_not_ready_shows_warning(jinja_env):
    html = _render_card(
        jinja_env,
        _base_row("installed", install_method="auto",
                  installed_at="2026-05-17T12:34:56+00:00",
                  runtime_deps_path="/app/data/runtime-deps"),
        runtime_ready=False,
    )
    assert "does not import" in html
    assert "Restart the container" in html


def test_card_routes_match_spec(jinja_env):
    """Every state surfaces the right POST endpoint(s)."""
    for state in ("not_installed", "failed"):
        html = _render_card(jinja_env, _base_row(
            state,
            last_error_class="HashMismatch" if state == "failed" else None,
            last_error_msg="x" if state == "failed" else None,
        ))
        assert "/config/ai-backends/embedding-install" in html
        assert "/config/ai-backends/embedding-sideload" in html

    html_dl = _render_card(jinja_env, _base_row(
        "downloading", install_method="auto",
        progress_files_total=18,
    ))
    assert "/config/ai-backends/embedding-install-cancel" in html_dl

    html_ok = _render_card(
        jinja_env,
        _base_row("installed", install_method="auto",
                  installed_at="2026-05-17T12:34:56+00:00"),
    )
    assert "/config/ai-backends/embedding-reverify" in html_ok
