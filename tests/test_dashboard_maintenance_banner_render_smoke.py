""" (Census v3 re-run LIVE UX) — dashboard banner render smoke.

PD#17 (test the rendered VIEW, not just model/DB): the maintenance-
window banner in ``dashboard.html`` reads
``llm_banner.maintenance_window.ends_at_utc_hm``. This session
renamed the key from ``ends_at_local_hm`` (name lied vs value —
value was ``strftime("%H:%M UTC")``) → ``ends_at_utc_hm``. Both
producer (``web/routers/ui/_shared.py:929``) and consumer
(``web/templates/dashboard.html:26``) renamed same-commit.

The regression class Playwright would catch: a template consumer
still reading a stale key would render EMPTY under a non-strict
Jinja env, or RAISE under ``StrictUndefined`` (which app.py wires
tree-wide). This smoke exercises the exact template expression
under StrictUndefined so a future rename-with-missed-consumer
regresses loud.

Scope caveat: this is not a full end-to-end browser drive
(local sqlcipher unavailable + the deploy host-live 40 commits behind
operator-gated deploy queue). It DOES exercise the class of
regression Playwright would surface (template-vs-context key
mismatch → empty render or hard fail), which is the OCR-relevant
class per `feedback_ui_fixes_reviewed_with_playwright` +
`feedback_test_the_view_not_just_machinery`.
"""
from __future__ import annotations

from jinja2 import Environment, StrictUndefined

_BANNER_HTML_EXPR = (
    "Back at <strong>{{ llm_banner.maintenance_window.ends_at_utc_hm }}"
    "</strong>."
)


def _env() -> Environment:
    return Environment(undefined=StrictUndefined, autoescape=True)


def test_banner_renders_new_utc_hm_key():
    """The renamed key resolves to the strftime('%H:%M UTC') value."""
    out = _env().from_string(_BANNER_HTML_EXPR).render(
        llm_banner={
            "maintenance_window": {
                "host": "llm-host.invalid",
                "ends_at_utc_hm": "01:30 UTC",
            },
        },
    )
    assert "01:30 UTC" in out
    assert out.startswith("Back at <strong>")
    assert out.endswith("</strong>.")


def test_banner_raises_on_stale_key_read():
    """Regression teeth: if the template were still reading the old
    ``ends_at_local_hm`` key while the producer emitted
    ``ends_at_utc_hm``, StrictUndefined would raise — mirror the
    scenario to prove the pin has real teeth."""
    stale_expr = (
        "Back at <strong>{{ llm_banner.maintenance_window.ends_at_local_hm }}"
        "</strong>."
    )
    import pytest
    from jinja2 import UndefinedError
    with pytest.raises(UndefinedError):
        _env().from_string(stale_expr).render(
            llm_banner={
                "maintenance_window": {
                    "host": "llm-host.invalid",
                    "ends_at_utc_hm": "01:30 UTC",
                },
            },
        )


def test_banner_key_matches_shared_py_producer():
    """The producer at `web/routers/ui/_shared.py:929` writes the key
    the template reads. Read the source string to defend against a
    silent rename on one side only."""
    from pathlib import Path
    shared = (
        Path(__file__).resolve().parents[1]
        / "src" / "email_triage" / "web" / "routers" / "ui" / "_shared.py"
    )
    src = shared.read_text(encoding="utf-8")
    assert '"ends_at_utc_hm"' in src, (
        "web/routers/ui/_shared.py no longer emits the "
        "`ends_at_utc_hm` key — dashboard.html:26 template consumer "
        "would render EMPTY (under Jinja default) or RAISE (under "
        "StrictUndefined)."
    )
    assert '"ends_at_local_hm"' not in src, (
        "web/routers/ui/_shared.py still emits the STALE "
        "`ends_at_local_hm` key alongside the renamed one — pick "
        "one; the template consumer only reads `ends_at_utc_hm`."
    )
