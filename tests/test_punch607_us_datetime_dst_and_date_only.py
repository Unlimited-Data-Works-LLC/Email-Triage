"""Punch 607 — the US datetime display was DST-frozen and shifted date-only values a day early.

Two defects, one display surface (`_us_datetime.py` server filter + the
`base.html` browser walker):

1. FROZEN OFFSET. The server default zone was
   ``datetime.now().astimezone().tzinfo`` captured once at import: a
   fixed-offset ``timezone``, not a zone. A process started in July
   rendered 17:00Z on Jan 15 as ``1:00 PM EDT`` (correct: ``12:00 PM EST``).
2. DATE-ONLY SHIFT. A ``YYYY-MM-DD`` value (BAA expiry) was parsed as UTC
   midnight and shifted west, so ``2026-12-31`` showed as
   ``12/30/2026 7:00 PM EST`` at all 7 BAA expiry sites, server AND browser.

Direction of failure before the fix: a silent wrong compliance record (a
BAA shown a day early; every cross-DST timestamp an hour off). After: the
right day / the right offset, or ``—`` for an unparseable value.

The DST tests run the formatter in a SUBPROCESS with ``TZ=EST5EDT`` so the
default (no ``tz=``) path is exercised against a known zone on any host:
POSIX ``TZ`` strings are honoured by both glibc and the Windows CRT.

The rendered-view (PD-17) test for the 7 BAA sites lives in
``tests/test_web/test_punch607_baa_expiry_date_render.py`` (it needs the
``test_web`` app fixtures).

SCOPE CAVEAT (what a green run does NOT prove): the census pin keys on the
column name ``baa_expires_at``. A BAA expiry carried into a template under
another variable name is not seen by it; the server filter and the walker
both route a date-only value to the date path regardless of the call site,
which is the backstop for that case.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import date, datetime

import pytest

from _pin_harness import TEMPLATES_ROOT, iter_template_files, relpath, tree_src_env

from email_triage._us_datetime import format_us_date, format_us_datetime


def _run_in_zone(tz: str, values: list[str]) -> list[str]:
    """Format each value with the DEFAULT (server-local) zone in a child
    process whose local zone is ``tz``."""
    code = (
        "import json, sys\n"
        "from email_triage._us_datetime import format_us_datetime\n"
        "print(json.dumps([format_us_datetime(v) for v in json.loads(sys.argv[1])]))\n"
    )
    env = tree_src_env({"TZ": tz})
    out = subprocess.run(
        [sys.executable, "-c", code, json.dumps(values)],
        env=env, capture_output=True, text=True, timeout=60, check=True,
    )
    return json.loads(out.stdout)


# --------------------------------------------------------------------------
# 1. Frozen offset: the default zone's offset is computed per instant.
# --------------------------------------------------------------------------

_DST_CASES = [
    # (UTC instant, expected render in America/New_York rules)
    ("2026-01-15T17:00:00Z", "1/15/2026 12:00:00 PM EST"),   # winter
    ("2026-07-15T17:00:00Z", "7/15/2026 1:00:00 PM EDT"),    # summer
    ("2026-03-08T06:59:59Z", "3/8/2026 1:59:59 AM EST"),     # last second of EST
    ("2026-03-08T07:00:00Z", "3/8/2026 3:00:00 AM EDT"),     # spring forward
    ("2026-11-01T05:59:59Z", "11/1/2026 1:59:59 AM EDT"),    # last second of EDT
    ("2026-11-01T06:00:00Z", "11/1/2026 1:00:00 AM EST"),    # fall back
]


# The Windows CRT applies US rules to a bare ``EST5EDT`` and rejects a rule
# suffix; glibc honours an explicit suffix even with no zoneinfo files
# installed, so the transitions do not depend on the runner's tzdata.
_US_EASTERN_POSIX = "EST5EDT" if sys.platform == "win32" else "EST5EDT,M3.2.0,M11.1.0"


def test_default_zone_offset_is_computed_per_instant_across_dst():
    """RED before the fix: whichever half of the year the process started
    in, the other half rendered with the wrong offset and label."""
    got = _run_in_zone(_US_EASTERN_POSIX, [c[0] for c in _DST_CASES])
    assert got == [c[1] for c in _DST_CASES]


def test_explicit_tz_is_still_honoured():
    from datetime import timedelta, timezone
    jst = timezone(timedelta(hours=9), name="JST")
    assert format_us_datetime("2026-01-15T17:00:00Z", tz=jst) == "1/16/2026 2:00:00 AM JST"


def test_windows_long_zone_names_reduce_to_initials():
    from email_triage._us_datetime import _zone_abbrev
    from datetime import timedelta, timezone
    long_name = timezone(timedelta(hours=-5), name="Eastern Standard Time")
    assert _zone_abbrev(datetime(2026, 1, 15, 12, tzinfo=long_name)) == "EST"
    short = timezone(timedelta(hours=-5), name="EST")
    assert _zone_abbrev(datetime(2026, 1, 15, 12, tzinfo=short)) == "EST"


# --------------------------------------------------------------------------
# 2. Date-only values are calendar dates: no time, no zone shift.
# --------------------------------------------------------------------------

def test_date_only_string_is_not_shifted_in_a_zone_west_of_utc():
    """RED before the fix: ``12/30/2026 7:00 PM EST`` (a day early)."""
    got = _run_in_zone(_US_EASTERN_POSIX, ["2026-12-31", "2026-01-01", " 2026-07-04 "])
    assert got == ["12/31/2026", "1/1/2026", "7/4/2026"]


def test_date_only_string_is_not_shifted_in_a_zone_east_of_utc():
    got = _run_in_zone("JST-9", ["2026-12-31"])
    assert got == ["12/31/2026"]


def test_date_object_and_filter_take_the_date_path():
    assert format_us_datetime(date(2026, 12, 31)) == "12/31/2026"
    assert format_us_date(date(2026, 12, 31)) == "12/31/2026"
    assert format_us_date("2026-12-31") == "12/31/2026"


def test_full_iso_datetime_is_not_mistaken_for_a_date():
    """The date-only path is chosen by SHAPE. A datetime string still
    renders as an instant (``parse_iso_date`` alone would have truncated
    it to its first ten characters)."""
    got = _run_in_zone(_US_EASTERN_POSIX, ["2026-12-31T23:30:00Z", "2026-12-31T00:00:00"])
    assert got == ["12/31/2026 6:30:00 PM EST", "12/30/2026 7:00:00 PM EST"]


def test_us_date_shows_the_day_the_baa_gate_acts_on():
    """The displayed day and the BAA gate's day come from one parser
    (``_isotime.parse_iso_date``), so they cannot disagree."""
    from email_triage.baa_expiry import _parse_expiry
    for raw in ("2026-12-31", "2026-12-31T00:00:00", "2026-12-31T23:59:59Z", "2027-02-28"):
        gate_day = _parse_expiry(raw)
        assert format_us_date(raw) == f"{gate_day.month}/{gate_day.day}/{gate_day.year}"


@pytest.mark.parametrize("bad", [None, "", "not a date", "2026-13-45", 12345])
def test_us_date_unparseable_renders_em_dash(bad):
    assert format_us_date(bad) == "—"


def test_install_filter_registers_us_date():
    import jinja2
    from email_triage._us_datetime import install_filter
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    install_filter(env)
    assert env.from_string("{{ d | us_date }}").render(d="2026-12-31") == "12/31/2026"
    assert env.from_string("{{ d | us_datetime }}").render(d="2026-12-31") == "12/31/2026"


# --------------------------------------------------------------------------
# 3. The browser walker (base.html).
# --------------------------------------------------------------------------

_WALKER_MARKER = "window.applyUsDatetimes"


def _walker_source() -> str:
    html = (TEMPLATES_ROOT / "base.html").read_text(encoding="utf-8")
    blocks = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
    hits = [b for b in blocks if _WALKER_MARKER in b]
    assert len(hits) == 1, f"expected exactly one walker script in base.html, found {len(hits)}"
    return hits[0]


_WALKER_CASES = [
    # (attributes, expected text after the walker runs)
    ({"datetime": "2026-12-31", "data-us-date": ""}, "12/31/2026"),
    # An unmigrated site that hands a date-only value to the datetime
    # path still gets the right day.
    ({"datetime": "2026-12-31", "data-us-datetime": ""}, "12/31/2026"),
    ({"datetime": "2026-01-15T17:00:00Z", "data-us-datetime": ""}, "1/15/2026 12:00:00 PM EST"),
    ({"datetime": "2026-07-15T17:00:00Z", "data-us-datetime": ""}, "7/15/2026 1:00:00 PM EDT"),
    ({"datetime": "2026-03-08T07:00:00Z", "data-us-datetime": ""}, "3/8/2026 3:00:00 AM EDT"),
    ({"datetime": "2026-11-01T06:00:00Z", "data-us-datetime": ""}, "11/1/2026 1:00:00 AM EST"),
    # Malformed input leaves the server-rendered text alone.
    ({"datetime": "garbage", "data-us-datetime": ""}, "server"),
    ({"datetime": "garbage", "data-us-date": ""}, "server"),
]

_NODE_HARNESS = r"""
const cases = JSON.parse(process.argv[2]);
const els = cases.map(function (attrs) {
  return {
    attrs: attrs,
    textContent: 'server',
    getAttribute: function (n) { return Object.prototype.hasOwnProperty.call(this.attrs, n) ? this.attrs[n] : null; },
  };
});
global.window = {};
global.document = {
  readyState: 'complete',
  addEventListener: function () {},
  querySelectorAll: function (sel) {
    const wanted = (sel.match(/\[([a-z-]+)\]/g) || []).map(function (s) { return s.slice(1, -1); });
    return els.filter(function (e) { return wanted.some(function (w) { return w in e.attrs; }); });
  },
};
const src = require('fs').readFileSync(process.argv[3], 'utf8');
eval(src);
process.stdout.write(JSON.stringify(els.map(function (e) { return e.textContent; })));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed; the source pin below still runs")
def test_walker_renders_dates_and_dst_correct_instants(tmp_path):
    """Executes the real walker script from base.html under node with the
    viewer in America/New_York. RED before the fix: the ``data-us-date``
    element was never selected and the date-only ``data-us-datetime``
    element rendered ``12/30/2026 7:00:00 PM EST``."""
    script = tmp_path / "walker.js"
    script.write_text(_walker_source(), encoding="utf-8")
    harness = tmp_path / "harness.js"
    harness.write_text(_NODE_HARNESS, encoding="utf-8")
    env = dict(os.environ)
    env["TZ"] = "America/New_York"
    out = subprocess.run(
        ["node", str(harness), json.dumps([c[0] for c in _WALKER_CASES]), str(script)],
        env=env, capture_output=True, text=True, timeout=60, check=True,
    )
    assert json.loads(out.stdout) == [c[1] for c in _WALKER_CASES]


def test_walker_source_routes_date_only_before_constructing_a_date():
    """Structural backstop for hosts without node: the walker selects
    ``[data-us-date]``, and tests the ``YYYY-MM-DD`` shape BEFORE any
    ``new Date(`` (``new Date('2026-12-31')`` is UTC midnight, the bug)."""
    src = _walker_source()
    assert "[data-us-date]" in src, "walker does not select data-us-date elements"
    m_def = re.search(
        r"var\s+(\w+)\s*=\s*/[^/\n]*\\d\{4\}\)?-\(?\\d\{2\}\)?-\(?\\d\{2\}[^/\n]*/", src,
    )
    assert m_def, "walker defines no YYYY-MM-DD date-only pattern"
    pattern_name = m_def.group(1)
    start = src.find("function apply(")
    end = src.find("document.readyState", start)
    assert start != -1 and end != -1, "walker `apply` function not found"
    body = src[start:end]
    first_test = body.find(pattern_name + ".test(")
    first_new_date = body.find("new Date(")
    assert first_test != -1, f"`apply` never tests {pattern_name} (the date-only shape)"
    assert first_new_date == -1 or first_test < first_new_date, (
        "inside `apply`, the date-only shape test must come before the first `new Date(`"
    )


# --------------------------------------------------------------------------
# 4. Census pin: every template that renders a BAA expiry uses the date path.
# --------------------------------------------------------------------------

_BAA_FIELD = "baa_expires_at"
_FILTERED_RE = re.compile(r"\{\{[^}]*?\b" + _BAA_FIELD + r"\b[^}]*?\|\s*(\w+)[^}]*\}\}")
_TIME_TAG_RE = re.compile(r"<time\b[^>]*>", re.S)


def _baa_render_violations(text: str) -> tuple[list[str], int]:
    """Return (violations, number of BAA render sites seen) for one template.

    A render site is a ``{{ … baa_expires_at … | filter }}`` expression or a
    ``<time>`` tag whose attributes reference ``baa_expires_at``. A form
    ``value="{{ row.baa_expires_at }}"`` (no filter, not a ``<time>``) is the
    raw ISO value an ``<input type=date>`` needs and is not a render site.
    """
    violations: list[str] = []
    sites = 0
    for m in _FILTERED_RE.finditer(text):
        sites += 1
        if m.group(1) != "us_date":
            violations.append(f"filter `{m.group(1)}` on {_BAA_FIELD}: {m.group(0)!r}")
    for m in _TIME_TAG_RE.finditer(text):
        tag = m.group(0)
        if _BAA_FIELD not in tag:
            continue
        sites += 1
        if "data-us-date" not in re.findall(r"data-us-[a-z]+", tag):
            violations.append(f"<time> for {_BAA_FIELD} without data-us-date: {tag!r}")
    return violations, sites


def test_every_baa_expiry_render_uses_the_date_only_path():
    offenders: list[str] = []
    total_sites = 0
    for path in iter_template_files():
        violations, sites = _baa_render_violations(path.read_text(encoding="utf-8"))
        total_sites += sites
        offenders.extend(f"{relpath(path, TEMPLATES_ROOT)}: {v}" for v in violations)
    assert total_sites > 0, "census found no BAA expiry render site: the pin would be vacuous"
    assert not offenders, "BAA expiry rendered through the datetime path:\n" + "\n".join(offenders)


def test_baa_census_pin_has_teeth():
    bad = '<time datetime="{{ row.baa_expires_at }}" data-us-datetime>{{ row.baa_expires_at | us_datetime }}</time>'
    violations, sites = _baa_render_violations(bad)
    assert sites == 2 and len(violations) == 2
    good = '<time datetime="{{ row.baa_expires_at }}" data-us-date>{{ row.baa_expires_at | us_date }}</time>'
    assert _baa_render_violations(good) == ([], 2)
    form = '<input type="date" name="baa_expires_at" value="{{ row.baa_expires_at or \'\' }}">'
    assert _baa_render_violations(form) == ([], 0)
