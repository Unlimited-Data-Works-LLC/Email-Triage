"""Update check, security-release flag and egress disclosures (punch 553).

The single source of truth for four things the managed-install design
(``internal documentation``) specifies, so no caller re-derives them:

* **The off-switch.** ``admin_email.release_check_url`` is parsed ONLY by
  :func:`parse_release_check_url` (YAML load); the Config > General save
  decides the value ONLY via :func:`resolve_release_check_form` and writes it
  ONLY via :func:`release_check_yaml_fields` (punch 584). Key absent ->
  the GitHub default (on by default, operator decision 553-1); blank / null ->
  OFF with no request made; anything that is not an http(s) URL -> OFF plus a
  WARNING (fail-closed for egress, PD-8). Before 553 the loader did
  ``a.get(key, default) or default``, so a blank value fell back to GitHub and
  the check could not be turned off.
* **The release-metadata convention.** :func:`parse_release_payload` reads the
  one ``<!-- email-triage-release-meta: {...} -->`` marker in a GitHub release
  body into :class:`ReleaseFacts`. It is fail-CLOSED: an absent or unreadable
  marker on a newer release is reported as a security update of unknown
  severity, never as "not security".
* **Pending-ness.** :func:`security_update_pending` derives, at render time,
  whether the RUNNING version is missing a security fix. Facts are persisted;
  the pending flag never is (PD-18), so an update + restart clears it at once.
* **Egress disclosures.** :func:`egress_disclosures` is the one registry of
  optional outbound flows that admins must be told about (the update check, and
  the telemetry beacon once  CR-4 builds it). The admin-login banner, its
  dismiss route and the design doc all read this list.

This module makes no network call. The fetch stays in
``web.daily_health.fetch_latest_release`` (egress funnel, ``Intent.PUBLIC_FETCH``,
1-hour cache); the hourly ``update-check-sweep`` loop calls it and hands the
payload here.
"""

from __future__ import annotations

import json as _json
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version



def _warn(msg: str, **extra: Any) -> None:
    """Lazy TriageLogger warning. ``config`` imports this module at load, and
    config keeps ``triage_logging`` out of its module-level import graph
    (N-378), so the logger import is deferred to the rare warning path."""
    from email_triage.triage_logging import get_logger

    get_logger("email_triage.update_check").warning(msg, **extra)

#: The public mirror's "newest release" endpoint. The ONE copy of this literal;
#: ``config.AdminEmailConfig`` and the Config > General datalist import it.
#: Punch 584: until then this named the PRIVATE development repository, which
#: GitHub answers with 404 to every request without credentials, so no check
#: could succeed on a development-tree build. The v0.1.x public builds were
#: unaffected only because the publish sanitizer then rewrote whole files;
#: since d0154bd1 (2026-08-10) it rewrites Python comments and docstrings
#: only, so a public build curated after that date would have shipped the
#: private address and failed every check on every install.
DEFAULT_RELEASE_CHECK_URL = (
    "https://api.github.com/repos/unlimited-data-works-llc/email-triage/"
    "releases/latest"
)

#: The public mirror's web address, for links in operator email (issues, docs).
#: The ONE copy of this literal; ``web.admin_alerts`` and ``web.daily_health``
#: import it. Punch 585: both linked the PRIVATE development repository, which
#: a public install's operator cannot open (GitHub answers 404), and the
#: publish sanitizer no longer rewrites code literals (d0154bd1).
#: tests/test_n585_no_private_repo_link_pin.py holds every shipped literal to it.
PUBLIC_REPO_URL = "https://github.com/unlimited-data-works-llc/email-triage"

#: Built-in defaults that have since been replaced (punch 584). Before 584 the
#: Config > General save wrote the in-force default into the YAML, so an
#: install that ever saved its config carries the old default as if an admin
#: had typed it, and a later change of the default never reached it. A stored
#: value equal to one of these is read as "the default". NEVER delete an entry:
#: an install keeps the old value in its YAML until its next Config Save, and
#: dropping the entry would bring its failing address back.
_RETIRED_DEFAULT_RELEASE_CHECK_URLS = frozenset({
    "https://api.github.com/repos/c-laforest/email-triage/releases/latest",
})

#: YAML key (under ``admin_email``) and form field names.
RELEASE_CHECK_URL_KEY = "release_check_url"
FORM_URL_FIELD = "admin_email_release_check_url"
FORM_ENABLED_FIELD = "update_check_enabled"
#: Hidden marker the Config > General template always posts with the update
#: check section, so "checkbox unticked" is distinguishable from "section not on
#: this form" (the ``__ingestion_fields_present`` idiom).
FORM_SECTION_MARKER = "__update_check_fields_present"

#: Settings-table key holding the last successfully parsed release facts.
FACTS_SETTING_KEY = "update_check:release_facts"


# ---------------------------------------------------------------------------
# The off-switch
# ---------------------------------------------------------------------------

def is_https_url(value: str) -> bool:
    """True for an ``https://`` URL that names a host.

    HTTPS only (hipaa-b1 O5-H3): over plain http a network attacker could
    forge "not newer" and suppress a security notice, or plant a false one.
    A plain-http address is therefore treated like any other invalid value
    (OFF from YAML, rejected from the form) — fail-closed.

    No control or line-break character anywhere (panel b1 round 3, DA):
    ``urlsplit`` silently drops an embedded CR/LF/tab while parsing, so a
    value like ``https://h/x\nBcc: y`` would pass the scheme check yet be
    returned and written verbatim into the plain-text email (line
    injection). Any Unicode control (Cc), line separator (Zl) or paragraph
    separator (Zp) rejects the whole value.
    """
    if not isinstance(value, str) or has_unsafe_text_char(value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme.lower() == "https" and bool(parts.hostname)


#: Unicode categories no release-derived string may contain: controls (Cc:
#: CR, LF, tab, NUL, DEL, C1 incl. NEL), format characters (Cf: U+202E
#: RIGHT-TO-LEFT OVERRIDE, U+200B ZERO WIDTH SPACE, BOM; display spoofing),
#: line separator (Zl) and paragraph separator (Zp).
_UNSAFE_TEXT_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def has_unsafe_text_char(value: str) -> bool:
    """THE one predicate (panel b1 rounds 3-4): True when ``value`` holds any
    character a displayed or e-mailed release string must not carry. Used by
    :func:`is_https_url` and for the release tag, the secure floor and every
    advisory id, because each is printed in the admin banner and the
    plain-text email, where an embedded line break is line injection."""
    return any(
        unicodedata.category(ch) in _UNSAFE_TEXT_CATEGORIES for ch in value
    )


def parse_release_check_url(block: Mapping[str, Any] | None) -> str:
    """Resolve ``admin_email.release_check_url`` from a loaded YAML block.

    Returns the URL to check, or ``""`` for OFF. Key absent (or no block) ->
    :data:`DEFAULT_RELEASE_CHECK_URL`. Present and blank / ``null`` -> OFF.
    Present and not an https URL with a host (plain http included, O5-H3) ->
    OFF plus a WARNING: a typo must not leak (fail-closed for egress); the
    cost is a silent loss of update notices, which the WARNING and the
    missing disclosure banner surface. Present and equal to a retired built-in
    default -> the current default (punch 584; the host is the same, so the
    egress disclosure an admin acknowledged still describes it).
    """
    if block is None or RELEASE_CHECK_URL_KEY not in block:
        return DEFAULT_RELEASE_CHECK_URL
    raw = block[RELEASE_CHECK_URL_KEY]
    if raw is None:
        return ""
    if not isinstance(raw, str):
        _warn(
            "admin_email.release_check_url is not a string; update check OFF",
            value_type=type(raw).__name__,
        )
        return ""
    value = raw.strip()
    if not value:
        return ""
    if not is_https_url(value):
        _warn(
            "admin_email.release_check_url is not an https URL; "
            "update check OFF",
        )
        return ""
    if value.lower() in _RETIRED_DEFAULT_RELEASE_CHECK_URLS:
        _warn(
            "admin_email.release_check_url holds a retired built-in default; "
            "using the current default address. Save Config > General once "
            "to remove the old value from the config file",
        )
        return DEFAULT_RELEASE_CHECK_URL
    return value


def release_check_yaml_fields(url: str) -> dict[str, str]:
    """The ``admin_email`` YAML entries that record the update-check address.

    THE one rule for writing it (punch 584): the default is NOT written, so an
    install that never chose an address follows the default when it changes;
    OFF (``""``) and an admin-chosen address are written as they are. Before
    584 the Save wrote the in-force default, which froze it into the file.
    """
    if url == DEFAULT_RELEASE_CHECK_URL:
        return {}
    return {RELEASE_CHECK_URL_KEY: url}


def resolve_release_check_form(
    form: Mapping[str, Any], current: str,
) -> tuple[str, str | None]:
    """Resolve the Config > General update-check controls into the new value.

    Intent comes from declared controls only (PD-13), never from field
    presence: the section marker says the controls were on the posted form, the
    checkbox says on/off, and a blank URL field PRESERVES (the current URL, or
    the default when the check was off). Returns ``(new_value, rejection)``;
    ``rejection`` is a user-facing sentence when a non-blank URL was refused
    (the value is then unchanged).
    """
    if FORM_SECTION_MARKER not in form:
        return current, None
    if FORM_ENABLED_FIELD not in form:
        return "", None
    raw = str(form.get(FORM_URL_FIELD) or "").strip()
    if not raw:
        return (current or DEFAULT_RELEASE_CHECK_URL), None
    if not is_https_url(raw):
        return current, (
            "The update-check address was not saved: it must start with "
            "https:// and name a server."
        )
    return raw, None


#: Messages of the two chained INFO records this feature writes. Their kwarg
#: keys must all be in ``triage_logging._PERSIST_SAFE_KEYS`` so they survive
#: HIPAA-mode redaction (hipaa-b1 O5-H2/H4; pinned by the survival arm of
#: ``tests/test_n556_update_check_ssot_pin.py``). The acknowledgment row is the
#: retained §164.316(b)(1) evidence that an admin received the egress notice.
DISCLOSURE_ACK_LOG_MSG = "Egress disclosure acknowledged"
UPDATE_CHECK_CHANGED_LOG_MSG = "Update check setting changed"


def update_check_state_label(url: str) -> str:
    """``"off"`` or ``"on:<host>"`` — the non-PHI record of the setting (the
    host only, never the full URL) for the change log (O5-H4)."""
    host = update_check_host(url)
    return f"on:{host}" if host else "off"


def update_check_host(url: str) -> str:
    """The host the update check contacts (``""`` when OFF)."""
    if not url:
        return ""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Release metadata convention
# ---------------------------------------------------------------------------

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
SEVERITY_UNKNOWN = "unknown"

#: The marker is an HTML comment so it is invisible on the GitHub release page.
#: Matched leniently (any whitespace, any case of the tag) so a near-miss is
#: counted as a marker and then FAILS the strict parse, rather than being
#: treated as absent.
_MARKER_RE = re.compile(
    r"<!--\s*email-triage-release-meta\s*:(.*?)-->", re.IGNORECASE | re.DOTALL,
)

META_OK = "ok"
META_ABSENT = "absent"
META_UNPARSEABLE = "unparseable"


@dataclass(frozen=True)
class ReleaseFacts:
    """What the last successful check learned about the newest release.

    Facts only. Whether the running install is missing a security fix is
    derived at render time by :func:`security_update_pending`.
    """

    checked_at: str
    latest_tag: str | None
    release_url: str | None
    meta_status: str
    security: bool = False
    severity: str | None = None
    min_secure_version: str | None = None
    advisories: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["advisories"] = list(self.advisories)
        return d

    @classmethod
    def from_dict(cls, raw: Any) -> "ReleaseFacts | None":
        """Rebuild persisted facts; ``None`` when the row is not facts-shaped."""
        if not isinstance(raw, dict):
            return None
        try:
            status = raw.get("meta_status")
            if status not in (META_OK, META_ABSENT, META_UNPARSEABLE):
                return None
            advisories = raw.get("advisories") or []
            tag, tag_ok = release_tag({"tag_name": raw.get("latest_tag")})
            floor = raw.get("min_secure_version") or None
            if (not tag_ok
                    or (floor is not None and (not isinstance(floor, str)
                                               or has_unsafe_text_char(floor)))
                    or any(not isinstance(a, str) or has_unsafe_text_char(a)
                           for a in advisories)):
                # Round 4: a stored row that fails the admission rules loads
                # as unparseable (fail-closed), with no unsafe text kept.
                return cls(
                    checked_at=str(raw.get("checked_at") or ""),
                    latest_tag=None,
                    release_url=release_page_url(
                        {"html_url": raw.get("release_url")},
                    ),
                    meta_status=META_UNPARSEABLE,
                )
            return cls(
                checked_at=str(raw.get("checked_at") or ""),
                latest_tag=tag,
                # panel b1 round 3 (db F-R3-3, hipaa): the stored link is
                # re-admitted on LOAD through the SAME funnel as on store
                # (https-only, no control character), so a settings row
                # written before a rule change, or edited at rest, cannot
                # carry an unsafe href into the banner or the email.
                release_url=release_page_url(
                    {"html_url": raw.get("release_url")},
                ),
                meta_status=status,
                security=bool(raw.get("security")),
                severity=raw.get("severity") or None,
                min_secure_version=raw.get("min_secure_version") or None,
                advisories=tuple(str(a) for a in advisories),
            )
        except (TypeError, ValueError):
            return None


def _parse_marker(raw_json: str) -> dict[str, Any] | None:
    """Strictly parse one marker's JSON. ``None`` = unparseable."""
    try:
        meta = _json.loads(raw_json.strip())
    except ValueError:
        return None
    if not isinstance(meta, dict) or meta.get("schema") != 1:
        return None
    security = meta.get("security")
    if not isinstance(security, bool):
        return None
    severity = meta.get("severity")
    floor = meta.get("min_secure_version")
    if floor is not None:
        if (not isinstance(floor, str) or has_unsafe_text_char(floor)
                or _version(floor) is None):
            return None
    if security or floor is not None:
        if severity not in SEVERITIES:
            return None
    elif severity is not None and severity not in SEVERITIES:
        return None
    advisories = meta.get("advisories", [])
    # Round 4 (DA): an advisory id with a line break or format character
    # rejects the WHOLE marker (unparseable -> the urgent banner of unknown
    # severity), so tampered metadata stays loud rather than being trimmed.
    if not isinstance(advisories, list) or not all(
        isinstance(a, str) and not has_unsafe_text_char(a) for a in advisories
    ):
        return None
    return {
        "security": security,
        "severity": severity,
        "min_secure_version": floor,
        "advisories": tuple(advisories),
    }


def parse_release_payload(
    payload: Mapping[str, Any], *, checked_at: str,
) -> ReleaseFacts:
    """Turn a GitHub ``/releases/latest`` payload into :class:`ReleaseFacts`.

    Exactly one marker must be present and must parse strictly; zero markers is
    ``absent``; two or more, or any parse failure, is ``unparseable``. Both
    non-ok statuses are read by :func:`security_update_pending` as "security
    update, severity unknown" on a newer release (fail-closed).
    """
    tag, tag_ok = release_tag(payload)
    # DA O5-F1 / db F-O5-2: the link becomes an <a href> in the admin banner
    # and the daily email; admit only an https URL (a ``javascript:`` or
    # ``data:`` value from a mirror or a compromised source is dropped).
    url = release_page_url(payload)
    body = payload.get("body")
    body = body if isinstance(body, str) else ""
    markers = _MARKER_RE.findall(body)
    base = {"checked_at": checked_at, "latest_tag": tag, "release_url": url}
    if not tag_ok:
        # Round 4 (DA): a tag carrying a line break or format character is
        # dropped from display and the release counts as unparseable; with no
        # tag it also counts as newer, so the urgent banner shows (fail-closed).
        return ReleaseFacts(meta_status=META_UNPARSEABLE, **base)
    if not markers:
        return ReleaseFacts(meta_status=META_ABSENT, **base)
    if len(markers) > 1:
        return ReleaseFacts(meta_status=META_UNPARSEABLE, **base)
    meta = _parse_marker(markers[0])
    if meta is None:
        return ReleaseFacts(meta_status=META_UNPARSEABLE, **base)
    return ReleaseFacts(meta_status=META_OK, **base, **meta)


def release_tag(payload: Mapping[str, Any]) -> tuple[str | None, bool]:
    """The release tag from a GitHub payload, and whether it conforms.

    The ONE place a payload's ``tag_name`` is admitted (the tag is printed in
    the banner and the plain-text email). Returns ``(tag, True)`` for a clean
    non-empty tag, ``(None, True)`` when there is none, and ``(None, False)``
    when it carries an unsafe character (:func:`has_unsafe_text_char`).
    """
    raw = payload.get("tag_name")
    if not isinstance(raw, str) or not raw.strip():
        return None, True
    if has_unsafe_text_char(raw.strip()):
        return None, False
    return raw.strip(), True


def release_page_url(payload: Mapping[str, Any]) -> str | None:
    """The release's page link from a GitHub payload, or ``None``.

    The ONE place a payload's ``html_url`` is admitted: https with a host
    only (same rule as the check URL, hipaa O5-H3), because it is rendered
    as a link in the admin banner and the daily email.
    """
    raw = payload.get("html_url")
    if isinstance(raw, str) and is_https_url(raw.strip()):
        return raw.strip()
    return None


#: The ``__version__`` fallback in ``email_triage/__init__.py`` when package
#: metadata is missing (a source checkout). Its local segment marks it.
_UNKNOWN_VERSION_LOCAL = "unknown"


def running_version_unknown(running_version: str) -> bool:
    """True when the running version cannot be compared (DA O5-F2)."""
    v = _version(running_version)
    return v is None or (v.local or "") == _UNKNOWN_VERSION_LOCAL


def _version(raw: str | None) -> Version | None:
    if not raw:
        return None
    text = raw.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    try:
        return Version(text)
    except InvalidVersion:
        return None


def security_update_pending(
    facts: ReleaseFacts | None, running_version: str,
) -> dict[str, Any] | None:
    """The security-banner context, or ``None`` when no security update is due.

    Derived every time from persisted facts and the RUNNING version, never
    stored. Rules (design section 5.1):

    * no facts, or the newest release is not newer than the running version ->
      ``None`` (an unparseable tag counts as newer: it cannot be proven older);
    * valid marker, ``security: true`` -> pending, the release is the target;
    * valid marker, running version below the carried ``min_secure_version`` ->
      pending, the floor is the target;
    * valid marker, neither -> ``None`` (an ordinary update);
    * marker absent or unparseable -> pending with severity ``unknown``.
    """
    if facts is None:
        return None
    running = _version(running_version)
    if running_version_unknown(running_version):
        # DA O5-F2: a source checkout without package metadata reports
        # ``0.0.0+unknown``; comparing against it would make EVERY release
        # "newer" and raise the urgent banner. No comparison is possible, so
        # no banner; the sweeper logs a WARNING each tick instead.
        return None
    latest = _version(facts.latest_tag)
    if running is not None and latest is not None and latest <= running:
        return None

    reason: str
    severity: str
    target = facts.latest_tag
    if facts.meta_status == META_OK:
        floor = _version(facts.min_secure_version)
        below_floor = (
            floor is not None and (running is None or running < floor)
        )
        if facts.security:
            reason = "security_release"
        elif below_floor:
            reason = "below_secure_floor"
            target = facts.min_secure_version
        else:
            return None
        severity = facts.severity or SEVERITY_UNKNOWN
    elif facts.meta_status == META_ABSENT:
        reason = "marker_absent"
        severity = SEVERITY_UNKNOWN
    else:
        reason = "marker_unparseable"
        severity = SEVERITY_UNKNOWN

    return {
        "reason": reason,
        "severity": severity,
        "running_version": running_version,
        "target_version": target,
        "latest_tag": facts.latest_tag,
        "release_url": facts.release_url,
        "advisories": list(facts.advisories),
        "checked_at": facts.checked_at,
    }


# ---------------------------------------------------------------------------
# Check health: a failing check must not be silent (db F-O5-1)
# ---------------------------------------------------------------------------

#: Settings key for the check's own health record.
HEALTH_SETTING_KEY = "update_check:health"
#: An ON check whose last success is older than this is reported stale.
STALE_AFTER_HOURS = 48
#: ...or after this many consecutive failed ticks (hourly: about a day),
#: which also covers an install whose check has never succeeded.
STALE_AFTER_FAILURES = 24

OUTCOME_OK = "ok"
OUTCOME_FAILED = "fetch_failed"
OUTCOME_OFF = "off"

#: Punch 605: wall-clock time this module was first imported, which is boot
#: (``web/app.py`` imports it during startup). The last-resort anchor for a
#: record with no attempt and no stamp (a pre-605 record, or a failed arm).
#: A restart moves it, which is why ``armed_at`` is the primary anchor.
_PROCESS_STARTED_AT = datetime.now(timezone.utc)

#: How a failed fetch failed (punch 584), recorded with the failure so the
#: notice names the right fix. ``http_status``: the server ANSWERED with an
#: HTTP error status, so this install's internet access works;
#: ``transport``: no answer at all (name lookup, connect, TLS, timeout);
#: ``bad_response``: an answer that is not a JSON object; ``refused``: this
#: server's own egress policy refused the address (a private or reserved
#: destination), so no request left the install.
FAILURE_HTTP_STATUS = "http_status"
FAILURE_TRANSPORT = "transport"
FAILURE_BAD_RESPONSE = "bad_response"
FAILURE_REFUSED = "refused"
_FAILURE_KINDS = frozenset({
    FAILURE_HTTP_STATUS, FAILURE_TRANSPORT, FAILURE_BAD_RESPONSE,
    FAILURE_REFUSED,
})


def fetch_failure(kind: str, status: int | None = None) -> dict[str, Any]:
    """The failure detail a release fetch reports. The ONE builder of its
    shape; :func:`record_check_outcome` validates it again on the way in."""
    return {"kind": kind, "status": status}


def _clean_failure(raw: Any) -> tuple[str | None, int | None]:
    """``(kind, status)`` from a failure detail, each ``None`` when absent or
    not well-formed. ``status`` survives only beside ``http_status``."""
    if not isinstance(raw, Mapping):
        return None, None
    kind = raw.get("kind")
    if kind not in _FAILURE_KINDS:
        return None, None
    status = raw.get("status")
    if (
        kind != FAILURE_HTTP_STATUS
        or not isinstance(status, int) or isinstance(status, bool)
        or not 100 <= status <= 599
    ):
        status = None
    return kind, status


def _empty_health() -> dict[str, Any]:
    return {"last_success_at": None, "consecutive_failures": 0,
            "last_failure_at": None, "last_failure_kind": None,
            "last_failure_status": None,
            # Punch 605: anchors for a record with no attempt yet. armed_at =
            # first seen ON with nothing recorded (stamped at boot, outside
            # the tick); last_off_at = the last tick that found the check OFF.
            "armed_at": None, "last_off_at": None}


def load_check_health(conn) -> dict[str, Any]:
    """The persisted check-health record (an empty one when absent/bad)."""
    from email_triage.web.db import get_setting

    raw = get_setting(conn, HEALTH_SETTING_KEY)
    health = _empty_health()
    if isinstance(raw, dict):
        if isinstance(raw.get("last_success_at"), str):
            health["last_success_at"] = raw["last_success_at"]
        if isinstance(raw.get("last_failure_at"), str):
            health["last_failure_at"] = raw["last_failure_at"]
        for anchor in ("armed_at", "last_off_at"):
            if isinstance(raw.get(anchor), str):
                health[anchor] = raw[anchor]
        n = raw.get("consecutive_failures")
        if isinstance(n, int) and not isinstance(n, bool) and n >= 0:
            health["consecutive_failures"] = n
        health["last_failure_kind"], health["last_failure_status"] = (
            _clean_failure({"kind": raw.get("last_failure_kind"),
                            "status": raw.get("last_failure_status")})
        )
    return health


def record_check_outcome(
    conn, outcome: str, *, now_iso: str,
    failure: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """THE one funnel for both edges of the staleness flag (PD-18).

    ``ok`` clears it (failures -> 0, last success -> now, failure detail ->
    none); ``fetch_failed`` sets it (failures + 1, and the failure detail from
    :func:`fetch_failure`, or none when the caller has no detail); ``off``
    resets the record, so re-enabling the check does not start with a stale
    alarm from before it was turned off, and stamps ``last_off_at`` (punch
    605: a check enabled at runtime is measured from the last tick that saw
    it off). Returns the record written.
    """
    from email_triage.web.db import set_setting

    if outcome == OUTCOME_OFF:
        health = _empty_health()
        health["last_off_at"] = now_iso
    else:
        health = load_check_health(conn)
        if outcome == OUTCOME_OK:
            health["last_success_at"] = now_iso
            health["consecutive_failures"] = 0
            health["last_failure_kind"] = None
            health["last_failure_status"] = None
        elif outcome == OUTCOME_FAILED:
            health["consecutive_failures"] += 1
            health["last_failure_at"] = now_iso
            health["last_failure_kind"], health["last_failure_status"] = (
                _clean_failure(failure)
            )
        else:
            raise ValueError(f"unknown update-check outcome {outcome!r}")
    set_setting(conn, HEALTH_SETTING_KEY, health)
    return health


def _no_attempt_recorded(health: Mapping[str, Any]) -> bool:
    return not health.get("last_success_at") and not int(
        health.get("consecutive_failures") or 0)


def arm_check_health(conn, url: str, *, now_iso: str) -> dict[str, Any] | None:
    """Stamp ``armed_at`` when the check is ON and nothing is recorded yet.

    Punch 605: called at BOOT, not from the hourly tick, because the case it
    exists for is a ticker that never runs (then nothing in the tick runs
    either). Idempotent: an existing stamp is kept, so a ticker that is dead
    at every boot is still reported STALE_AFTER_HOURS after the first one.
    OFF clears it (:func:`record_check_outcome`). Returns the record, or
    ``None`` when the check is off.
    """
    from email_triage.web.db import set_setting

    if not url:
        return None
    health = load_check_health(conn)
    if _no_attempt_recorded(health) and not health.get("armed_at"):
        health["armed_at"] = now_iso
        set_setting(conn, HEALTH_SETTING_KEY, health)
    return health


def _never_ran_too_long(health: Mapping[str, Any], *, now) -> bool:
    """A record with no attempt whose anchor is older than STALE_AFTER_HOURS.

    Anchor order: ``armed_at``, else ``last_off_at``, else the process start.
    An unreadable stamp cannot prove freshness (stale), as with
    ``last_success_at``."""
    from email_triage._isotime import parse_iso_aware

    stamp = health.get("armed_at") or health.get("last_off_at")
    anchor = parse_iso_aware(stamp) if stamp else _PROCESS_STARTED_AT
    if anchor is None:
        return True
    return (now - anchor).total_seconds() > STALE_AFTER_HOURS * 3600


def _answered_but_refused(health: Mapping[str, Any]) -> int | None:
    """The HTTP status when the last failure was the server REFUSING the
    address (a 4xx), else ``None``. 403, 408 and 429 are left out: GitHub
    answers its rate limit with 403 or 429, and 408 is a timeout, so none of
    them proves the address is wrong."""
    kind, status = _clean_failure({"kind": health.get("last_failure_kind"),
                                   "status": health.get("last_failure_status")})
    if (
        kind == FAILURE_HTTP_STATUS and status is not None
        and 400 <= status <= 499 and status not in (403, 408, 429)
    ):
        return status
    return None


def update_check_stale(
    health: Mapping[str, Any] | None, url: str, *, now,
) -> dict[str, Any] | None:
    """The staleness notice, or ``None``. Derived, never stored.

    Only while the check is ON: stale when the last success is older than
    :data:`STALE_AFTER_HOURS`, or after :data:`STALE_AFTER_FAILURES`
    consecutive failures, or (punch 605) when NO attempt has been recorded
    :data:`STALE_AFTER_HOURS` after the check was armed (the ticker never
    ran). ``now`` is a timezone-aware ``datetime``.
    """
    if not url or not health:
        return None
    from email_triage._isotime import parse_iso_aware

    failures = int(health.get("consecutive_failures") or 0)
    last_ok = health.get("last_success_at")
    too_old = False
    if last_ok:
        last_dt = parse_iso_aware(last_ok)
        if last_dt is None:
            too_old = True       # an unreadable timestamp cannot prove freshness
        else:
            too_old = (now - last_dt).total_seconds() > STALE_AFTER_HOURS * 3600
    elif not failures:
        too_old = _never_ran_too_long(health, now=now)
    if not too_old and failures < STALE_AFTER_FAILURES:
        return None
    status = _answered_but_refused(health) if failures else None
    if status is not None:
        reason = STALE_REASON_BAD_ADDRESS
    elif failures and health.get("last_failure_kind") == FAILURE_REFUSED:
        reason = STALE_REASON_REFUSED
    else:
        reason = STALE_REASON_FAILING if failures else STALE_REASON_NOT_RUNNING
    notice = _STALE_NOTICE[reason]
    host = update_check_host(url)
    return {
        "since": last_ok,
        "consecutive_failures": failures,
        "last_failure_at": health.get("last_failure_at"),
        "host": host,
        "reason": reason,
        "title": notice["title"],
        "cause": notice["cause"].format(n=failures, status=status, host=host),
        "advice": notice["advice"].format(host=host),
    }


#: Why a stale notice fires, derived from the health record (punch 574).
#: ``failing``: attempts are being made and failing. ``not_running``: the last
#: success is older than :data:`STALE_AFTER_HOURS` and NO attempt has failed
#: since, so no attempt is being recorded at all (the checker stopped ticking).
#: Telling that operator to check internet access sends them to the wrong fix.
#: ``bad_address`` (punch 584): attempts fail because the server ANSWERS with
#: a 4xx refusal (see :func:`_answered_but_refused`), which proves the
#: internet access works and the address is the problem. A private GitHub
#: repository answers 404, which is how the arm was found. ``refused``
#: (punch 584, panel H584-2): this server's egress policy refused the address,
#: so nothing was sent and neither the network nor the far server is at fault.
STALE_REASON_FAILING = "failing"
STALE_REASON_NOT_RUNNING = "not_running"
STALE_REASON_BAD_ADDRESS = "bad_address"
STALE_REASON_REFUSED = "refused"

#: The one copy for every arm. Every surface (admin banner, daily-health
#: attention line, HTML and text email) reads these fields from the notice
#: rather than writing its own sentence. ``cause`` may use ``{n}``,
#: ``{status}`` and ``{host}``; ``advice`` may use ``{host}``.
_STALE_NOTICE: dict[str, dict[str, str]] = {
    STALE_REASON_FAILING: {
        "title": "The update check is failing",
        "cause": "{n} failed attempts in a row",
        "advice": ("Check this server's internet access and the "
                   "update-check address on the General settings tab."),
    },
    STALE_REASON_BAD_ADDRESS: {
        "title": "The update-check address does not work",
        "cause": "{n} failed attempts in a row; {host} answered HTTP {status}",
        "advice": ("This server reached {host}, so its internet access "
                   "works. The update-check address on the General settings "
                   "tab does not lead to a public release feed (a private "
                   "GitHub repository, or one with no published release yet, "
                   "answers HTTP 404). Correct the address. Unticking "
                   "\"Check for updates\" also clears this notice, but then "
                   "this install is not told about security updates."),
    },
    STALE_REASON_REFUSED: {
        "title": "The update-check address is blocked by this server",
        "cause": "{n} failed attempts in a row; this server will not contact {host}",
        "advice": ("This server never contacts private or reserved network "
                   "addresses, and the update-check address on the General "
                   "settings tab leads to one (directly or by a redirect). "
                   "Correct the address to a public release feed."),
    },
    STALE_REASON_NOT_RUNNING: {
        "title": "The update check has stopped running",
        "cause": "no check attempt has been recorded since then",
        "advice": ("The background update checker may have stopped. Restart "
                   "the service; if this notice stays, look in the logs for "
                   "update-check messages."),
    },
}


def load_release_facts(conn) -> ReleaseFacts | None:
    """Read the persisted facts (``None`` when absent or malformed)."""
    from email_triage.web.db import get_setting

    return ReleaseFacts.from_dict(get_setting(conn, FACTS_SETTING_KEY))


def save_release_facts(conn, facts: ReleaseFacts) -> None:
    """Persist facts, overwriting the previous check's."""
    from email_triage.web.db import set_setting

    set_setting(conn, FACTS_SETTING_KEY, facts.to_dict())


# ---------------------------------------------------------------------------
# Egress disclosures
# ---------------------------------------------------------------------------

#: The telemetry beacon poster is  CR-4 (next release, decision 553-5).
#: Until it exists there is no beacon config key and nothing to disclose, so
#: the entry is declared with ``enabled`` fixed False; CR-4 replaces this with
#: the real setting read.
TELEMETRY_BEACON_BUILT = False

DISCLOSURE_UPDATE_CHECK = "update_check"
DISCLOSURE_TELEMETRY_BEACON = "telemetry_beacon"


@dataclass(frozen=True)
class EgressDisclosure:
    """One optional outbound flow every admin is told about."""

    kind: str
    title: str
    enabled: bool
    host: str
    sends: str
    turn_off: str

    @property
    def dismissal_id(self) -> str:
        """Per-host id, so pointing the flow at a new host re-shows it."""
        return f"egress:{self.kind}:{self.host}"


def egress_disclosures(config: Any) -> list[EgressDisclosure]:
    """Every optional outbound flow, enabled or not (design section 3)."""
    url = getattr(getattr(config, "admin_email", None), "release_check_url", "")
    url = url if isinstance(url, str) else ""
    return [
        EgressDisclosure(
            kind=DISCLOSURE_UPDATE_CHECK,
            title="Update check is on",
            enabled=bool(url),
            host=update_check_host(url),
            sends=(
                "Once an hour this install asks that server for the newest "
                "release. The request carries this server's internet address "
                "and nothing else: no account, no mail, no patient data."
            ),
            turn_off=(
                "Untick \"Check for updates\" on the General settings tab. "
                "With the check off you will not be told about security "
                "updates here."
            ),
        ),
        EgressDisclosure(
            kind=DISCLOSURE_TELEMETRY_BEACON,
            title="Usage report to your support provider is on",
            enabled=TELEMETRY_BEACON_BUILT,
            host="",
            sends=(
                "A random install number, the app and database versions, the "
                "operating system, and when updates last ran. No patient data, "
                "no message counts, no user names."
            ),
            turn_off="Turn off the usage report on the General settings tab.",
        ),
    ]


def dismissable_disclosure_ids(config: Any) -> frozenset[str]:
    """Ids the dismiss route accepts: enabled disclosures only.

    The security banner has no id here by construction, so it cannot be
    dismissed through the route.
    """
    return frozenset(
        d.dismissal_id for d in egress_disclosures(config) if d.enabled
    )


def active_disclosure_banners(
    config: Any, dismissed: set[str] | frozenset[str] | list[str],
) -> list[dict[str, Any]]:
    """Banner rows for enabled disclosures this admin has not dismissed."""
    gone = set(dismissed)
    return [
        {
            "id": d.dismissal_id,
            "kind": d.kind,
            "title": d.title,
            "host": d.host,
            "sends": d.sends,
            "turn_off": d.turn_off,
        }
        for d in egress_disclosures(config)
        if d.enabled and d.dismissal_id not in gone
    ]


__all__ = [
    "DEFAULT_RELEASE_CHECK_URL",
    "FACTS_SETTING_KEY",
    "FORM_ENABLED_FIELD",
    "FORM_SECTION_MARKER",
    "FORM_URL_FIELD",
    "EgressDisclosure",
    "ReleaseFacts",
    "active_disclosure_banners",
    "dismissable_disclosure_ids",
    "egress_disclosures",
    "is_https_url",
    "has_unsafe_text_char",
    "release_tag",
    "release_page_url",
    "running_version_unknown",
    "HEALTH_SETTING_KEY",
    "FAILURE_BAD_RESPONSE",
    "FAILURE_HTTP_STATUS",
    "FAILURE_REFUSED",
    "FAILURE_TRANSPORT",
    "STALE_REASON_BAD_ADDRESS",
    "STALE_REASON_REFUSED",
    "fetch_failure",
    "load_check_health",
    "record_check_outcome",
    "release_check_yaml_fields",
    "update_check_stale",
    "update_check_state_label",
    "DISCLOSURE_ACK_LOG_MSG",
    "UPDATE_CHECK_CHANGED_LOG_MSG",
    "load_release_facts",
    "parse_release_check_url",
    "parse_release_payload",
    "resolve_release_check_form",
    "save_release_facts",
    "security_update_pending",
    "update_check_host",
]
