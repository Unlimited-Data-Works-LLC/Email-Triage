"""Punch 553 / N-556 — behaviour of the update-check SSOT (pure functions).

Covers the off-switch (design doc section 4), the release-metadata convention
and its fail-closed parse (section 5), and the disclosure registry (section 3).
The web-facing halves (banners, dismiss route, sweeper, daily email) are in
``tests/test_web/test_update_check_553_web.py``.
"""

from __future__ import annotations

import json

import pytest
import yaml

from email_triage import update_check as uc
from email_triage.config import AdminEmailConfig, TriageConfig, _parse_raw


# ---------------------------------------------------------------------------
# (d) the off-switch: blank means OFF
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "yaml_body, expected",
    [
        ("{}\n", uc.DEFAULT_RELEASE_CHECK_URL),               # block absent
        ("admin_email: {}\n", uc.DEFAULT_RELEASE_CHECK_URL),  # key absent
        ("admin_email:\n  release_check_url: ''\n", ""),
        ("admin_email:\n  release_check_url: '   '\n", ""),
        ("admin_email:\n  release_check_url: null\n", ""),
        ("admin_email:\n  release_check_url: 42\n", ""),
        ("admin_email:\n  release_check_url: ftp://mirror/r\n", ""),
        ("admin_email:\n  release_check_url: 'https://'\n", ""),
        # hipaa-b1 O5-H3: plain http is refused (a MITM could forge or
        # suppress the security notice) -> OFF, like any invalid value.
        ("admin_email:\n  release_check_url: http://mirror.example/r\n", ""),
        (
            "admin_email:\n  release_check_url: https://mirror.example/r\n",
            "https://mirror.example/r",
        ),
    ],
)
def test_yaml_release_check_url_resolution(yaml_body, expected):
    cfg = _parse_raw(yaml.safe_load(yaml_body))
    assert cfg.admin_email.release_check_url == expected


def test_blank_no_longer_falls_back_to_github():
    """The N-556 defect, named: a blank value used to become the GitHub URL."""
    cfg = _parse_raw({"admin_email": {"release_check_url": ""}})
    assert cfg.admin_email.release_check_url == ""
    assert "github" not in cfg.admin_email.release_check_url


def test_dataclass_default_is_the_ssot_constant():
    assert AdminEmailConfig().release_check_url == uc.DEFAULT_RELEASE_CHECK_URL
    assert TriageConfig().admin_email.release_check_url == uc.DEFAULT_RELEASE_CHECK_URL


_CUR = "https://mirror.example/r"


@pytest.mark.parametrize(
    "form, current, expected, rejected",
    [
        # Section not on the posted form: unchanged, whatever else is there.
        ({"admin_email_release_check_url": ""}, _CUR, _CUR, False),
        ({}, "", "", False),
        # Unticked: OFF.
        ({uc.FORM_SECTION_MARKER: "1"}, _CUR, "", False),
        ({uc.FORM_SECTION_MARKER: "1", uc.FORM_URL_FIELD: _CUR}, _CUR, "", False),
        # Ticked + blank address: preserve; from OFF -> the default.
        ({uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
          uc.FORM_URL_FIELD: ""}, _CUR, _CUR, False),
        ({uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
          uc.FORM_URL_FIELD: "  "}, "", uc.DEFAULT_RELEASE_CHECK_URL, False),
        # Ticked + valid address.
        ({uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
          uc.FORM_URL_FIELD: "https://other.example/x"}, _CUR,
         "https://other.example/x", False),
        # Ticked + invalid address: unchanged + a visible rejection.
        ({uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
          uc.FORM_URL_FIELD: "javascript:alert(1)"}, _CUR, _CUR, True),
        ({uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
          uc.FORM_URL_FIELD: "not a url"}, "", "", True),
        ({uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
          uc.FORM_URL_FIELD: "http://mirror.example/r"}, _CUR, _CUR, True),
    ],
)
def test_form_resolution(form, current, expected, rejected):
    value, rejection = uc.resolve_release_check_form(form, current)
    assert value == expected
    assert bool(rejection) is rejected


# ---------------------------------------------------------------------------
# (c) release-metadata convention + fail-closed parse
# ---------------------------------------------------------------------------

def _marker(meta: dict | str) -> str:
    raw = meta if isinstance(meta, str) else json.dumps(meta)
    return f"<!-- email-triage-release-meta: {raw} -->"


def _payload(tag: str, body: str) -> dict:
    return {"tag_name": tag, "html_url": f"https://example.invalid/{tag}",
            "body": body}


def _facts(tag: str, body: str) -> uc.ReleaseFacts:
    return uc.parse_release_payload(_payload(tag, body), checked_at="2026-10-01T00:00:00Z")


_SEC_HIGH = {"schema": 1, "security": True, "severity": "high",
             "min_secure_version": "0.2.1", "advisories": ["GHSA-aaaa-bbbb-cccc"]}
_NOT_SEC = {"schema": 1, "security": False}
_NOT_SEC_FLOOR = {"schema": 1, "security": False, "severity": "critical",
                  "min_secure_version": "0.2.1"}

#: Markers that are present but must NOT parse. Every one of them, on a newer
#: release, must surface as a security update of unknown severity — the
#: property the next test asserts over the whole set (not a count).
_UNPARSEABLE_BODIES = [
    _marker("{not json"),
    _marker({"schema": 2, "security": False}),
    _marker({"security": False}),                                 # no schema
    _marker({"schema": 1, "security": "no"}),                     # not a bool
    _marker({"schema": 1, "security": True}),                     # no severity
    _marker({"schema": 1, "security": True, "severity": "severe"}),
    _marker({"schema": 1, "security": False, "min_secure_version": "abc",
             "severity": "low"}),
    _marker({"schema": 1, "security": False, "min_secure_version": "0.2.1"}),
    _marker({"schema": 1, "security": True, "severity": "low",
             "advisories": "GHSA-x"}),
    _marker(_NOT_SEC) + "\n" + _marker(_NOT_SEC),                  # two markers
    _marker("[]"),
    "<!-- EMAIL-TRIAGE-RELEASE-META:{\"schema\":1} -->",           # case variant
]


@pytest.mark.parametrize("body", _UNPARSEABLE_BODIES)
def test_unparseable_marker_never_hides_a_security_flag(body):
    facts = _facts("v0.2.1", body)
    assert facts.meta_status == uc.META_UNPARSEABLE
    pending = uc.security_update_pending(facts, "0.2.0")
    assert pending is not None
    assert pending["severity"] == uc.SEVERITY_UNKNOWN
    assert pending["reason"] == "marker_unparseable"


def test_absent_marker_on_newer_release_is_a_security_update():
    facts = _facts("v0.2.1", "## Changes\n- things")
    assert facts.meta_status == uc.META_ABSENT
    pending = uc.security_update_pending(facts, "0.2.0")
    assert pending["reason"] == "marker_absent"
    assert pending["severity"] == uc.SEVERITY_UNKNOWN


@pytest.mark.parametrize("body", ["", _marker("{bad"), _marker(_SEC_HIGH)])
def test_nothing_shows_when_not_behind(body):
    """Whatever the marker says, an install at/after the release sees nothing."""
    assert uc.security_update_pending(_facts("v0.2.1", body), "0.2.1") is None
    assert uc.security_update_pending(_facts("v0.2.1", body), "0.3.0") is None


def test_valid_security_release():
    pending = uc.security_update_pending(_facts("v0.2.1", _marker(_SEC_HIGH)), "0.2.0")
    assert pending["reason"] == "security_release"
    assert pending["severity"] == "high"
    assert pending["target_version"] == "v0.2.1"
    assert pending["advisories"] == ["GHSA-aaaa-bbbb-cccc"]


def test_valid_non_security_release_is_an_ordinary_update():
    assert uc.security_update_pending(_facts("v0.2.2", _marker(_NOT_SEC)), "0.2.0") is None


def test_carried_floor_reaches_installs_below_it():
    """A non-security v0.2.2 carrying floor 0.2.1 still flags a 0.2.0 install,
    and stops flagging once the install reaches the floor."""
    facts = _facts("v0.2.2", _marker(_NOT_SEC_FLOOR))
    below = uc.security_update_pending(facts, "0.2.0")
    assert below["reason"] == "below_secure_floor"
    assert below["target_version"] == "0.2.1"
    assert below["severity"] == "critical"
    assert uc.security_update_pending(facts, "0.2.1") is None


def test_unparseable_tag_counts_as_newer():
    pending = uc.security_update_pending(_facts("release-candidate", ""), "0.2.0")
    assert pending is not None


def test_no_facts_no_banner():
    assert uc.security_update_pending(None, "0.2.0") is None


def test_facts_round_trip_through_their_persisted_shape():
    facts = _facts("v0.2.1", _marker(_SEC_HIGH))
    again = uc.ReleaseFacts.from_dict(json.loads(json.dumps(facts.to_dict())))
    assert again == facts
    assert uc.ReleaseFacts.from_dict({"meta_status": "bogus"}) is None
    assert uc.ReleaseFacts.from_dict("not a dict") is None


# ---------------------------------------------------------------------------
# (b) disclosure registry
# ---------------------------------------------------------------------------

def test_update_check_disclosure_tracks_the_switch():
    cfg = TriageConfig()
    rows = {d.kind: d for d in uc.egress_disclosures(cfg)}
    assert rows["update_check"].enabled
    assert rows["update_check"].host == "api.github.com"
    assert rows["update_check"].dismissal_id == "egress:update_check:api.github.com"

    cfg.admin_email.release_check_url = ""
    rows = {d.kind: d for d in uc.egress_disclosures(cfg)}
    assert not rows["update_check"].enabled
    assert uc.dismissable_disclosure_ids(cfg) == frozenset()


def test_beacon_is_declared_but_off_in_v020():
    """ CR-4 builds the poster; until then nothing is sent, so nothing
    is disclosed (a banner for a flow that does not happen would be false)."""
    rows = {d.kind: d for d in uc.egress_disclosures(TriageConfig())}
    assert "telemetry_beacon" in rows
    assert rows["telemetry_beacon"].enabled is False
    assert uc.TELEMETRY_BEACON_BUILT is False


def test_dismissal_id_changes_with_host():
    cfg = TriageConfig()
    first = uc.dismissable_disclosure_ids(cfg)
    cfg.admin_email.release_check_url = "https://mirror.example/r"
    assert uc.dismissable_disclosure_ids(cfg) != first


def test_active_banners_drop_dismissed_ids():
    cfg = TriageConfig()
    (only,) = uc.active_disclosure_banners(cfg, [])
    assert uc.active_disclosure_banners(cfg, [only["id"]]) == []


def test_state_label_records_host_only():
    """O5-H4: the change record carries on/off + HOST, never the full URL."""
    assert uc.update_check_state_label("") == "off"
    assert uc.update_check_state_label(
        "https://mirror.example/private/path?token=x",
    ) == "on:mirror.example"


# ---------------------------------------------------------------------------
# DA O5-F1 / db F-O5-2: the release link is https-only
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("html_url", [
    "javascript:fetch('/admin/x')",
    "JavaScript:alert(1)",
    "data:text/html,<script>x</script>",
    "http://github.invalid/c-laforest/email-triage/releases/tag/v9",
    "",
    42,
])
def test_unsafe_release_link_is_dropped(html_url):
    facts = uc.parse_release_payload(
        {"tag_name": "v99.0.0", "html_url": html_url, "body": ""},
        checked_at="2026-10-01T00:00:00Z",
    )
    assert facts.release_url is None
    assert uc.security_update_pending(facts, "0.2.0")["release_url"] is None


def test_https_release_link_is_kept():
    url = "https://github.invalid/c-laforest/email-triage/releases/tag/v99.0.0"
    facts = uc.parse_release_payload(
        {"tag_name": "v99.0.0", "html_url": url, "body": ""}, checked_at="x",
    )
    assert facts.release_url == url


# ---------------------------------------------------------------------------
# DA O5-F2: an unknown running version compares to nothing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("running", ["0.0.0+unknown", "not-a-version", ""])
def test_unknown_running_version_raises_no_banner(running):
    facts = uc.parse_release_payload(
        {"tag_name": "v99.0.0", "html_url": "", "body": ""}, checked_at="x",
    )
    assert uc.running_version_unknown(running)
    assert uc.security_update_pending(facts, running) is None


def test_known_running_version_is_not_unknown():
    assert not uc.running_version_unknown("0.2.0")
    assert not uc.running_version_unknown("0.2.0+local.build")


# ---------------------------------------------------------------------------
# db F-O5-1: staleness (pure half; the funnel is tested against a DB in the
# web file)
# ---------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

_NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
_URL = uc.DEFAULT_RELEASE_CHECK_URL


def _h(last_ok_hours_ago=None, failures=0):
    last = (None if last_ok_hours_ago is None
            else (_NOW - timedelta(hours=last_ok_hours_ago)).isoformat())
    return {"last_success_at": last, "consecutive_failures": failures,
            "last_failure_at": None}


@pytest.mark.parametrize("health, stale", [
    (_h(), False),                                          # never ran
    (_h(1), False),
    (_h(uc.STALE_AFTER_HOURS - 1), False),
    (_h(uc.STALE_AFTER_HOURS + 1), True),                   # too old
    (_h(1, failures=uc.STALE_AFTER_FAILURES - 1), False),
    (_h(1, failures=uc.STALE_AFTER_FAILURES), True),        # too many failures
    (_h(None, failures=uc.STALE_AFTER_FAILURES), True),     # never succeeded
    ({"last_success_at": "garbage", "consecutive_failures": 0}, True),
])
def test_staleness_rule(health, stale):
    got = uc.update_check_stale(health, _URL, now=_NOW)
    assert (got is not None) is stale
    if got:
        assert got["host"] == "api.github.com"


@pytest.mark.parametrize("health, reason", [
    (_h(uc.STALE_AFTER_HOURS + 1), uc.STALE_REASON_NOT_RUNNING),      # aged, 0 failures
    (_h(uc.STALE_AFTER_HOURS + 1, failures=3), uc.STALE_REASON_FAILING),
    (_h(1, failures=uc.STALE_AFTER_FAILURES), uc.STALE_REASON_FAILING),
    (_h(None, failures=uc.STALE_AFTER_FAILURES), uc.STALE_REASON_FAILING),
])
def test_staleness_reason_picks_the_copy(health, reason):
    """Punch 574: the notice names WHY it fired, and its title/cause/advice
    come from that reason. Only the failing arm sends the operator to the
    network; the not-running arm never does."""
    got = uc.update_check_stale(health, _URL, now=_NOW)
    assert got["reason"] == reason
    assert {"title", "cause", "advice"} <= set(got)
    if reason == uc.STALE_REASON_FAILING:
        assert got["cause"] == f"{health['consecutive_failures']} failed attempts in a row"
        assert "internet access" in got["advice"]
    else:
        assert "internet access" not in got["advice"]
        assert "failed attempts" not in got["cause"]


def _hf(kind, status=None):
    h = _h(None, failures=uc.STALE_AFTER_FAILURES)
    h["last_failure_kind"], h["last_failure_status"] = kind, status
    return h


@pytest.mark.parametrize("health, reason", [
    (_hf(uc.FAILURE_HTTP_STATUS, 404), uc.STALE_REASON_BAD_ADDRESS),
    (_hf(uc.FAILURE_HTTP_STATUS, 410), uc.STALE_REASON_BAD_ADDRESS),
    (_hf(uc.FAILURE_HTTP_STATUS, 401), uc.STALE_REASON_BAD_ADDRESS),
    # Rate limits (403/429) and a timeout (408) do not prove a bad address.
    (_hf(uc.FAILURE_HTTP_STATUS, 403), uc.STALE_REASON_FAILING),
    (_hf(uc.FAILURE_HTTP_STATUS, 408), uc.STALE_REASON_FAILING),
    (_hf(uc.FAILURE_HTTP_STATUS, 429), uc.STALE_REASON_FAILING),
    (_hf(uc.FAILURE_HTTP_STATUS, 503), uc.STALE_REASON_FAILING),
    (_hf(uc.FAILURE_TRANSPORT), uc.STALE_REASON_FAILING),
    (_hf(uc.FAILURE_BAD_RESPONSE), uc.STALE_REASON_FAILING),
    (_hf(None), uc.STALE_REASON_FAILING),                   # pre-584 record
    (_hf(uc.FAILURE_TRANSPORT, 404), uc.STALE_REASON_FAILING),  # status w/o http kind
    (_hf("made_up", 404), uc.STALE_REASON_FAILING),
    (_hf(uc.FAILURE_HTTP_STATUS, True), uc.STALE_REASON_FAILING),
    (_hf(uc.FAILURE_HTTP_STATUS, "404"), uc.STALE_REASON_FAILING),
])
def test_a_refused_address_gets_its_own_notice(health, reason):
    """Punch 584: a 4xx answer (bar rate limits and timeouts) proves the
    network works, so the notice names the address and the status instead of
    sending the admin to the network. Anything else keeps the failing arm."""
    got = uc.update_check_stale(health, _URL, now=_NOW)
    assert got["reason"] == reason
    if reason == uc.STALE_REASON_BAD_ADDRESS:
        status = health["last_failure_status"]
        assert got["cause"] == (
            f"{uc.STALE_AFTER_FAILURES} failed attempts in a row; "
            f"api.github.com answered HTTP {status}"
        )
        assert "reached api.github.com" in got["advice"]
        assert "General settings tab" in got["advice"]
        assert "Check this server" not in got["advice"]
    else:
        assert "internet access" in got["advice"]
        assert "answered HTTP" not in got["cause"]


def test_a_policy_refusal_gets_its_own_notice():
    """Panel H584-2: the egress funnel refusing the address is neither a
    network nor a far-server problem; the notice says this server blocked it."""
    got = uc.update_check_stale(_hf(uc.FAILURE_REFUSED), _URL, now=_NOW)
    assert got["reason"] == uc.STALE_REASON_REFUSED
    assert got["cause"] == (
        f"{uc.STALE_AFTER_FAILURES} failed attempts in a row; "
        "this server will not contact api.github.com"
    )
    assert "internet access" not in got["advice"]
    assert "General settings tab" in got["advice"]


def test_every_notice_arm_formats_with_the_documented_keys():
    """Cross-route from the panel: the notice is formatted inside the render
    surfaces' broad ``except``, so a stray placeholder would raise there and
    drop the banner (fail OPEN). Property over EVERY arm, count-agnostic."""
    for reason, notice in uc._STALE_NOTICE.items():
        assert set(notice) == {"title", "cause", "advice"}, reason
        notice["cause"].format(n=1, status=404, host="h.example")
        notice["advice"].format(host="h.example")
        assert "{" not in notice["title"] and "}" not in notice["title"], reason


def test_bad_address_arm_needs_failures():
    """An AGE-stale record (no failure since the last success) is the
    not-running arm even if an old failure detail lingers."""
    h = _h(uc.STALE_AFTER_HOURS + 1)
    h["last_failure_kind"], h["last_failure_status"] = uc.FAILURE_HTTP_STATUS, 404
    assert uc.update_check_stale(h, _URL, now=_NOW)["reason"] == (
        uc.STALE_REASON_NOT_RUNNING
    )


@pytest.mark.parametrize("url, expected", [
    (uc.DEFAULT_RELEASE_CHECK_URL, {}),
    ("", {"release_check_url": ""}),
    ("https://mirror.example/r", {"release_check_url": "https://mirror.example/r"}),
])
def test_yaml_fields_leave_the_default_out(url, expected):
    assert uc.release_check_yaml_fields(url) == expected


@pytest.mark.parametrize("retired", sorted(uc._RETIRED_DEFAULT_RELEASE_CHECK_URLS))
def test_a_retired_default_reads_as_the_current_default(retired):
    for value in (retired, retired.upper(), f"  {retired}  "):
        assert uc.parse_release_check_url({"release_check_url": value}) == (
            uc.DEFAULT_RELEASE_CHECK_URL
        )


def test_default_names_a_public_repository():
    """Punch 584: the default must be answerable without credentials. The
    development repository is private (GitHub answers 404), so the default
    names the public mirror. Checked by name, not by the network."""
    assert "/repos/unlimited-data-works-llc/email-triage/" in (
        uc.DEFAULT_RELEASE_CHECK_URL.lower()
    )


def test_stale_copy_lives_only_in_update_check():
    """Punch 574 SSOT: no render surface writes its own stale-notice sentence.
    Property over every file under src/ (count-agnostic): the copy's
    distinctive phrases appear in update_check.py and nowhere else."""
    from pathlib import Path

    from _pin_harness import SRC_ROOT, iter_files, relpath

    home = Path(uc.__file__).resolve()
    phrases = ("failed attempts in a row", "update check is failing",
               "has stopped running", "address does not work",
               "does not lead to a public release feed",
               "blocked by this server", "will not contact")
    scanned = [p for p in iter_files(SRC_ROOT, "*")
               if p.is_file() and p.suffix in {".py", ".html", ".txt", ".j2"}]
    assert home in {p.resolve() for p in scanned}, "the walk never reached update_check.py"
    offenders = sorted(
        f"{relpath(p)}: {ph}"
        for p in scanned
        if p.resolve() != home
        for ph in phrases
        if ph in p.read_text(encoding="utf-8", errors="replace").lower()
    )
    assert offenders == [], offenders


def test_no_staleness_notice_while_off():
    assert uc.update_check_stale(
        _h(None, failures=10 * uc.STALE_AFTER_FAILURES), "", now=_NOW,
    ) is None


# ---------------------------------------------------------------------------
# panel b1 round 3: no control / line-break character in any admitted URL
# ---------------------------------------------------------------------------

_INJECTED = [
    "https://github.invalid/x/releases/tag/v9\nBcc: victim@example.com",
    "https://github.invalid/x/releases/tag/v9\r\nX-Injected: 1",
    "https://github.invalid/x/\rrelease",
    "https://github.invalid/x/\trelease",
    "https://github.invalid/x/\x00release",
    "https://github.invalid/x/\x7frelease",
    "https://github.invalid/x/\x85release",          # C1 NEL
    "https://github.invalid/x/\u2028release",        # line separator
    "https://github.invalid/x/\u2029release",        # paragraph separator
    "https://api.git\nhub.com/repos/x/releases/latest",
]


@pytest.mark.parametrize("value", _INJECTED)
def test_control_characters_are_refused_everywhere(value):
    assert uc.is_https_url(value) is False
    # release page link (banner + email)
    facts = uc.parse_release_payload(
        {"tag_name": "v99.0.0", "html_url": value, "body": ""}, checked_at="x",
    )
    assert facts.release_url is None
    # the check URL from YAML -> OFF, from the form -> rejected
    assert uc.parse_release_check_url({"release_check_url": value}) == ""
    _, rejection = uc.resolve_release_check_form(
        {uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
         uc.FORM_URL_FIELD: value},
        _CUR,
    )
    assert rejection


def test_clean_https_url_still_admitted():
    assert uc.is_https_url("https://github.invalid/c-laforest/email-triage/releases/tag/v1")


@pytest.mark.parametrize("stored", [
    "javascript:alert(1)",
    "data:text/html,<script>x</script>",
    "http://github.invalid/x",
    "https://github.invalid/x\nBcc: y",
    42,
])
def test_stored_release_link_is_rechecked_on_load(stored):
    """hipaa round 3: a persisted facts row carrying an unsafe link (written
    before a rule change, or edited at rest) loads with no link."""
    facts = uc.ReleaseFacts.from_dict({
        "checked_at": "x", "latest_tag": "v99.0.0", "release_url": stored,
        "meta_status": uc.META_ABSENT,
    })
    assert facts is not None
    assert facts.release_url is None


def test_stored_safe_link_survives_load():
    url = "https://github.invalid/c-laforest/email-triage/releases/tag/v99.0.0"
    facts = uc.ReleaseFacts.from_dict({
        "checked_at": "x", "latest_tag": "v99.0.0", "release_url": url,
        "meta_status": uc.META_ABSENT,
    })
    assert facts.release_url == url


# ---------------------------------------------------------------------------
# panel b1 round 4: tag / advisory / floor text, and Cf characters
# ---------------------------------------------------------------------------

_SEC_HIGH_ADV = {"schema": 1, "security": True, "severity": "high",
                 "min_secure_version": "99.0.0", "advisories": ["GHSA-ok"]}


@pytest.mark.parametrize("tag", [
    "v9.9.9\nNo security update is pending.",       # DA measured fixture
    "v9.9.9\r\nX: y",
    "v9.9.9\u202e",                                  # RLO
    "v9.\u200b9.9",                                  # ZWSP
    "v9.9\u20289",    # embedded (a trailing one is stripped, harmlessly)
])
def test_unsafe_tag_is_dropped_and_fails_closed(tag):
    facts = uc.parse_release_payload(
        {"tag_name": tag, "html_url": "", "body": _marker(_NOT_SEC)},
        checked_at="x",
    )
    assert facts.latest_tag is None
    assert facts.meta_status == uc.META_UNPARSEABLE
    pending = uc.security_update_pending(facts, "0.2.0")
    assert pending is not None and pending["severity"] == uc.SEVERITY_UNKNOWN
    assert "\n" not in repr(pending.get("latest_tag"))


@pytest.mark.parametrize("bad_adv", [
    "GHSA-x\nSecurity: none",                       # DA measured fixture
    "CVE-2026-1\r",
    "GHSA-\u202ex",
    "GHSA-\u200bx",
])
def test_unsafe_advisory_rejects_the_marker(bad_adv):
    meta = dict(_SEC_HIGH_ADV, advisories=["GHSA-ok", bad_adv])
    facts = _facts("v99.0.0", _marker(meta))
    assert facts.meta_status == uc.META_UNPARSEABLE
    assert facts.advisories == ()
    pending = uc.security_update_pending(facts, "0.2.0")
    assert pending is not None and pending["advisories"] == []
    assert pending["reason"] == "marker_unparseable"


def test_unsafe_floor_rejects_the_marker():
    meta = dict(_NOT_SEC_FLOOR, min_secure_version="0.2.1\n")
    assert _facts("v0.2.2", _marker(meta)).meta_status == uc.META_UNPARSEABLE


@pytest.mark.parametrize("ch", ["\u202e", "\u200b", "\ufeff", "\u00ad"])
def test_format_characters_are_refused_in_urls(ch):
    assert uc.is_https_url(f"https://github.invalid/x{ch}/releases") is False
    assert uc.has_unsafe_text_char(f"a{ch}b")


def test_clean_text_is_admitted():
    assert not uc.has_unsafe_text_char("GHSA-aaaa-bbbb-cccc")
    assert uc.release_tag({"tag_name": " v1.2.3 "}) == ("v1.2.3", True)
    assert uc.release_tag({}) == (None, True)


@pytest.mark.parametrize("field, value", [
    ("latest_tag", "v9.9.9\nNo security update is pending."),
    ("advisories", ["GHSA-x\nSecurity: none"]),
    ("min_secure_version", "0.2.1\u202e"),
])
def test_stored_unsafe_text_loads_as_unparseable(field, value):
    row = {"checked_at": "x", "latest_tag": "v99.0.0", "release_url": None,
           "meta_status": uc.META_OK, "security": False,
           "severity": None, "min_secure_version": None, "advisories": []}
    row[field] = value
    facts = uc.ReleaseFacts.from_dict(row)
    assert facts.meta_status == uc.META_UNPARSEABLE
    assert facts.latest_tag is None and facts.advisories == ()
    assert uc.security_update_pending(facts, "0.2.0") is not None
