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
    # Register the us_datetime filter (SSOT — same call as web/app.py).
    from email_triage._us_datetime import install_filter as _install_us_datetime
    _install_us_datetime(env)
    return env


def _render_card(
    env,
    state_row,
    runtime_ready=True,
    sha_short="",
    *,
    verified=True,
    verify_reason="ok",
    runtime_present=None,
    image_sha_short="",
):
    """Render the partial with the full context the ONE builder supplies.

    Keyword defaults mirror ``embedding_install.build_install_card_context`` for
    a healthy verified install, so an existing test reads unchanged; the N-525
    branches are exercised by passing ``verified=False``. ``runtime_present``
    defaults to "a prefix exists iff the row names one", which is what the
    builder derives from disk.
    """
    tmpl = env.get_template("admin/config_tabs/_embedding_install_card.html")
    if runtime_present is None:
        runtime_present = bool(state_row.get("runtime_deps_path"))
    return tmpl.render(
        request=object(),
        install_state=state_row,
        install_manifest_sha_short=sha_short,
        install_runtime_ready=runtime_ready,
        install_verified=verified,
        install_verify_reason=verify_reason,
        install_runtime_present=runtime_present,
        install_image_manifest_sha_short=image_sha_short,
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


def test_card_installing_state_names_the_running_interpreters_site_packages(jinja_env):
    """Punch 732: the path is derived from the running interpreter through the ONE
    context builder, never a literal ``python3.12`` that a base-image bump strands.
    Rendered under StrictUndefined so a builder that drops the key fails here."""
    import re
    import sys

    from jinja2 import StrictUndefined

    from email_triage.web.routers.ui.embedding_install import (
        build_install_card_context,
    )

    jinja_env.undefined = StrictUndefined
    ctx = build_install_card_context(_base_row("installing", install_method="auto"))
    html = jinja_env.get_template(
        "admin/config_tabs/_embedding_install_card.html",
    ).render(request=object(), **ctx)
    flat = " ".join(html.split())
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    assert f"{pyver}" in flat and "site-packages" in flat
    assert set(re.findall(r"python\d+\.\d+", flat)) == {pyver}


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
    # N-525: the old copy said "Restart the container to pick up the runtime
    # path". No startup caller has ever added the path, so a restart never
    # helped — it is added when the backend loads. Advice that does nothing is
    # worse than none, because the operator spends a restart to learn nothing.
    flat = " ".join(html.split())
    assert "A container restart alone will not fix this" in flat
    assert "Restart the container to pick up" not in flat


def test_card_installed_but_unverified_says_it_will_not_load(jinja_env):
    """N-525 / punch 540 — the wording follows the marker check.

    THE defect this pins: in the installed state the card printed "Files
    verified against the pinned manifest baked into this image" with nothing
    having checked the installed package set. An operator reading it on the
    2026-05-18 install — 18 stale distributions, 104 OSV records — was told the
    thing was verified. The claim may now appear ONLY under install_verified.
    """
    html = _render_card(
        jinja_env,
        _base_row("installed", install_method="auto",
                  installed_at="2026-05-17T12:34:56+00:00",
                  runtime_deps_path="/app/data/runtime-deps"),
        runtime_ready=False,
        verified=False,
        verify_reason="set_mismatch: not installed: torch, transformers",
    )
    flat = " ".join(html.split())
    assert "NOT verified against the manifest in the current image" in flat
    assert "set_mismatch: not installed: torch, transformers" in flat
    # The load-bearing negative: no "verified" claim about the INSTALLED set.
    assert "installed packages match this image's pinned manifest" not in flat


def test_card_offers_remove_whenever_a_prefix_exists(jinja_env):
    """N-526 / punch 541 — keyed on the DISK, not on the row's status.

    The case with no supported fix before this was a volume still holding
    packages while the row said something else. So [Remove] is offered on
    presence of the prefix, including from a ``not_installed`` row.
    """
    html = _render_card(
        jinja_env,
        _base_row("not_installed"),
        runtime_present=True,
    )
    assert "/config/ai-backends/embedding-remove" in html

    # ...and never mid-install, where it would race a running pip.
    html_dl = _render_card(
        jinja_env,
        _base_row("downloading", install_method="auto",
                  progress_files_total=18),
        runtime_present=True,
    )
    assert "/config/ai-backends/embedding-remove" not in html_dl

    # ...and not at all when there is nothing on disk to remove.
    html_none = _render_card(
        jinja_env, _base_row("not_installed"), runtime_present=False,
    )
    assert "/config/ai-backends/embedding-remove" not in html_none


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
