"""run18  — the digest-candidates "When" cell renders via the datetime SSOT.

PD#17 (test the rendered VIEW): the inline ``[:16]`` ISO slice leaked a "T"
separator into the "Show matches" dry-run table while the delivered digest used
"%Y-%m-%d %H:%M". The template now pipes the row through the ``format_digest_dt``
Jinja filter (→ ``recipient_digest._format_datetime``). This smoke renders the
cell expression through an env wired the SAME way ``web/app.py`` wires it, under
``StrictUndefined``, and asserts the space-separated form (no "T") + the "—"
empty fallback.
"""
from __future__ import annotations

from jinja2 import Environment, StrictUndefined

from email_triage.actions.recipient_digest import format_digest_datetime

# The exact cell expression from accounts/_digest_candidates.html.
_CELL = "{{ (r | format_digest_dt) or '—' }}"


def _env() -> Environment:
    env = Environment(undefined=StrictUndefined, autoescape=True)
    # Mirror web/app.py's filter registration (run18 ).
    env.filters["format_digest_dt"] = (
        lambda entry: format_digest_datetime(entry, "")
    )
    return env


def test_when_cell_uses_space_separated_ssot_form():
    out = _env().from_string(_CELL).render(
        r={"date": "2026-06-27T14:30:00+00:00"},
    )
    assert out == "2026-06-27 14:30"
    assert "T" not in out  # the ISO separator the [:16] slice leaked is gone


def test_when_cell_empty_date_falls_back_to_dash():
    tmpl = _env().from_string(_CELL)
    assert tmpl.render(r={}) == "—"
    assert tmpl.render(r={"date": None}) == "—"


def test_format_digest_datetime_alias_is_the_ssot():
    """The public alias the filter imports IS the SSOT impl — not a fork."""
    from email_triage.actions.recipient_digest import _format_datetime
    assert format_digest_datetime is _format_datetime
    assert (
        format_digest_datetime({"date": "2026-06-27T14:30:00+00:00"}, "")
        == "2026-06-27 14:30"
    )
