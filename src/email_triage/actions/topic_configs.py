"""Topic / Study Digest configuration storage + CRUD.

A **Topic** is a user-defined subject (a study, a project, a thread of
interest) that the app watches for across one or more of the user's
mailboxes, surfaced as a special-case digest. See
``internal documentation`` §2 for the full data
model; this module owns the **DB layer** for it.

Storage shape
-------------
Unlike :mod:`email_triage.actions.digest_configs` (which stores its
configs as a JSON blob under a ``settings`` key, account-scoped),
Topics get **first-class tables** (migration v40): ``topics``,
``topic_hits``, ``study_match_cache``, ``study_digest_state``. A Topic
is **user-scoped** — the account multi-select lives *inside* the Topic
as ``selected_account_ids`` — so it cannot hang off a per-account
settings key the way a digest config does.

The :class:`TopicConfig` dataclass **composes** (does not fork) the
existing :class:`DigestSchedule` / :class:`DigestWindow` /
:class:`DigestFormat` from ``digest_configs`` — those three are stored
as JSON blobs (``schedule_json`` / ``window_json`` / ``format_json``)
on the ``topics`` row and hydrated back via the same tolerant
``digest_configs`` coercers.

This module owns
----------------
* The :class:`TopicConfig` dataclass + (de)serialization helpers.
* Topic CRUD keyed by ``user_id``: :func:`list_topics`,
  :func:`get_topic`, :func:`upsert_topic`, :func:`soft_delete_topic`,
  :func:`bump_topic_version`.
* :func:`insert_topic_hit` — the back-scan/live-classify UPSERT that
  pins ``first_seen_at = MIN(...)`` (design §8 B3).

Single-writer contract
-----------------------
Every write helper is ``@db_write``-decorated (conn-first, ends in
``conn.commit()``), so when the web router dispatches it via
``db_call`` it routes to the **existing single-writer thread** — NO new
SQLCipher connection (a 4th connection re-opens the encrypted
lock-storm; design §4.4 / v0.1.2 INCIDENT-1). Read helpers are plain
(undecorated) functions: a reader on its own statement sees a
consistent WAL snapshot.

What this layer does NOT do
---------------------------
No classify, no render, no router, no template — those are later 
stages. No mail body is ever stored here (only message *identity* +
the user's own public matched-terms). No embedding signal (the
pre-filter is config-keyword/IDF only;  deliberately uses no vector
— design N17).
"""

from __future__ import annotations

from email_triage.db.columns import TOPICS_COLUMNS
import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any

import sqlite3

from email_triage._int_utils import parse_int_or_none  # N-219c/8 R23
from email_triage.db._helpers import dump_json_col
from email_triage.actions.digest_configs import (
    CADENCES,
    GROUP_BYS,
    RENDER_AS,
    DigestFormat,
    DigestSchedule,
    DigestWindow,
    _coerce,
    _coerce_format,
)
from email_triage.web.db_writelock import db_write
from email_triage.mail_headers import extract_bare_address


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Allowed Topic digest modes (design §2). ``full`` = all live hits in
#: window; ``differential`` = new-since-last-send; ``both`` = a Full
#: section + a "new since last" section with independent watermarks.
MODES = ("full", "differential", "both")


def _resolve_confidence_floor(default: float = 0.5) -> float:
    """Resolve the digest confidence floor: env-override then ``default``.

    Operator-tunable without a code edit via ``ET_TOPIC_MATCH_CONFIDENCE_FLOOR``
    (a float in ``[0, 1]``); an unset / blank / unparseable / out-of-range value
    falls back to ``default``. Resolved once at import (the service restarts on
    deploy), so a test pins behaviour by passing ``confidence_floor=`` to
    :func:`gather_live_topic_hits` rather than mutating the environment."""
    raw = os.environ.get("ET_TOPIC_MATCH_CONFIDENCE_FLOOR")
    if raw is None or not str(raw).strip():
        return default
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return default
    if val < 0.0 or val > 1.0:
        return default
    return val


#:  digest confidence floor (operator 2026-06-15). A persisted Topic hit is
#: SURFACED in a digest only when its stored ``confidence`` is at or above this
#: floor — closing the "surface on the matched boolean alone" gap, where a
#: low-confidence ``matched: true`` still reached a recipient's digest (a weak
#: PHI-adjacent association). Applied at SURFACE time in
#: :func:`gather_live_topic_hits` (NOT at match time), reading the persisted
#: ``topic_hits.confidence`` — so the floor stays REVERSIBLE: every match is
#: still persisted, and LOWERING the floor instantly re-surfaces previously
#: hidden hits (a match-time drop would cache ``matched=0`` and make the drop
#: permanent for already-scanned mail). Default 0.5 (raise/lower via the env
#: var). This is the SINGLE source for the floor — import it, never restate it.
TOPIC_MATCH_CONFIDENCE_FLOOR = _resolve_confidence_floor()


# ---------------------------------------------------------------------------
#  C-V1.1 / C-V1.2 — V1 PHI scrubber gate (fail-CLOSED).
#
# The Topic **Details** + **Subject(s)** are operator-typed free text. The
# design (§9 V1) treats them as "public only AFTER a sound scrub" — the
# scrubber is the *sole technical control*. Before this text can be
# persisted (and later flow into a cloud Topic-block as DATA), it MUST pass
# the SAME pre-egress HIPAA-18 catalogue the m-series describe-and-discard
# pipeline uses (``phi_scrubber.PHI_REGEX_PATTERNS`` via
# ``_layer2_scan_string`` — the "m-series catalogue").
#
# **Fail-CLOSED (C-V1.2):** a save is BLOCKED when EITHER
#   (a) any free-text field trips a PHI pattern, OR
#   (b) the scrubber itself RAISES.
# A scrubber that errors must never be read as "clean" — a raise blocks the
# save exactly as a positive hit does. The caller surfaces this as a clear
# user-facing error; nothing PHI-shaped lands at rest.
# ---------------------------------------------------------------------------

import re as _re

#: A **canonical public study identifier** — ClinicalTrials.gov ``NCT`` +
#: exactly 8 digits (mirrors ``actions.clinicaltrials._NCT_RE``). Such an id
#: is a PUBLIC registry number, NOT one of the 18 HIPAA identifiers, and the
#: §9 egress rule explicitly sanctions "public study identifier/name ONLY"
#: as an allowed egress. The raw m-series ``alphanumeric_id`` catch-all
#: would over-match it, so canonical NCT tokens are MASKED OUT before the
#: PHI scan — a bare NCT id passes, while a surname/date/contact riding
#: alongside it (e.g. "Smith relapse re NCT00000419") still trips on the
#: surname. Only the *canonical* shape is allow-listed; a malformed
#: NCT-like token (wrong digit count) is NOT masked and still scans.
_NCT_TOKEN_RE = _re.compile(r"\bNCT\d{8}\b")

#: m-series catalogue labels that are NOT applied to Topic free-text.
#:
#: The m-series ``PHI_REGEX_PATTERNS`` were tuned for a *writing-style
#: descriptor* — a closed-enum profile where ANY medical word, any Title-Case
#: pair, any bare year, any 5-digit run, or any letter+digit token is
#: anomalous and signals a leak. Topic config text is the OPPOSITE surface: a
#: Topic is, by design, a Title-Case study NAME built from medical vocabulary
#: and ordinary study shorthand — the design's own canonical legitimate
#: examples are "Lupus HRT SELENA", "SELENA Lupus Study", "Phase 3
#: hormone-therapy safety in lupus", "diabetes study", "covid19 cohort",
#: "study 2024 arm". For Topic text the PHI risk is the **18 HIPAA
#: *identifiers*** (names with honorifics, dates, phone/fax, email, SSN,
#: MRN/long-digit runs, addresses, account/license/device ids, URLs, IPs,
#: image filenames) — NOT the disease/therapy vocabulary, NOT a generic
#: Title-Case pair, and NOT every numeric token that happens to look
#: identifier-shaped. Per the  Stage-5 hipaa-sme scrubber-scoping ruling,
#: FOUR catch-all labels are excluded from the Topic gate, and one
#: (``alphanumeric_id``) is REFINED rather than excluded (see
#: :func:`_scan_topic_phi`):
#:
#:   * ``medical_term`` — the disease/therapy/treatment/medication vocabulary
#:     catch-all. Excluding it lets a Topic name its own condition (the core
#:     use case) instead of blocking it.
#:   * ``name_two_caps`` — "two consecutive capitalised tokens = possible full
#:     name". This cannot tell "John Smith" (a person) from "Lupus Study" (a
#:     study title), so on Title-Case Topic names it is almost all false
#:     positives. The design EXPLICITLY accepts a measured free-text-name
#:     false-negative rate here (C-V1.3) and defaults cloud egress OFF for
#:     HIPAA Topics until that recall is measured — the scrubber is a
#:     best-effort identifier gate, not a perfect name detector. The
#:     higher-precision ``name_honorific`` ("Dr. Smith") still fires, so an
#:     honorific-prefixed name is still blocked.
#:   * ``year_four_digit`` — a bare 4-digit year (e.g. "study 2024 cohort") is
#:     NOT a §164.514(b)(2) identifier: Safe Harbor explicitly keeps the YEAR
#:     element of a date. A real date-of-birth rides the still-active
#:     ``date_slash_dash`` ("04/12/1965") or ``date_month_day`` ("April 12")
#:     patterns, which STAY fail-closed. A lone year in study text is
#:     legitimate cohort/phase shorthand, so it is excluded here.
#:   * ``zip_code`` — a bare 5-digit run ("Topic 90210 arm") is far too
#:     ambiguous on free study text (cohort sizes, arm numbers, lab values all
#:     read as 5 digits) to treat as a geographic identifier. A genuine
#:     street address still trips the still-active ``street_address`` pattern,
#:     which STAYS; only the standalone 5-digit ZIP heuristic is dropped.
#:
#: ``alphanumeric_id`` is NOT excluded — excluding it would LEAK genuine
#: license/account/device IDs (A1234567B, XJ4521098, SN4452310) that rely
#: SOLELY on that label. Instead it is Topic-locally REFINED in
#: :func:`_scan_topic_phi`: a fired span is re-tested against a stricter
#: pattern requiring a 4+ contiguous-digit run, so genuine IDs still BLOCK
#: while ordinary study shorthand (covid19, iPhone15, aspirin81, Phase3)
#: passes. (A pure 8-digit run like 99204812 is still caught by the
#: still-active ``mrn_or_id_long_digits`` ``\d{6,}`` rule.)
#:
#: EVERY OTHER catalogue label (the real, high-precision identifier shapes)
#: still fires. This is the documented C-V1.3 precision/recall calibration as
#: amended by the  Stage-5 ruling, not a relaxation of the identifier gate.
_TOPIC_SCRUB_EXCLUDED_LABELS = frozenset(
    {"medical_term", "name_two_caps", "year_four_digit", "zip_code"}
)

#: Topic-local refinement of the m-series ``alphanumeric_id`` catch-all (
#: Stage-5 ruling). When ``alphanumeric_id`` fires on a Topic surface, the
#: matched span is re-tested against THIS stricter pattern, which additionally
#: requires a run of 4+ contiguous digits. Only spans matching it are treated
#: as PHI and block; spans that fire the loose catch-all but lack a 4-digit
#: run (covid19, iPhone15, aspirin81, Phase3, keyword0) are treated as clean.
#: Genuine license/account/device IDs (A1234567B → "1234567"; XJ4521098 →
#: "4521098"; SN4452310 → "4452310") carry such a run and stay blocked.
_TOPIC_ALPHANUMERIC_ID_STRICT_RE = _re.compile(
    r"\b(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9-]*\d{4,}[A-Za-z0-9-]*\b"
)


def _scan_topic_phi(value: str) -> list[str]:
    """Scan ONE Topic free-text string for PHI-identifier patterns.

    Reuses the m-series HIPAA-18 catalogue (``phi_scrubber.PHI_REGEX_PATTERNS``)
    — the SAME pattern set the describe-and-discard distill gate uses — with
    the  Stage-5 hipaa-sme scrubber-scoping adjustments, all grounded in
    the design:

      * canonical public study identifiers (``NCT`` + 8 digits) are masked
        out first (sanctioned public id, not PHI; §9 egress rule);
      * the catch-all labels in :data:`_TOPIC_SCRUB_EXCLUDED_LABELS`
        (``medical_term`` / ``name_two_caps`` / ``year_four_digit`` /
        ``zip_code``) are skipped — none is a §164.514(b)(2) identifier on
        free study text (see that frozenset's rationale); and
      * the loose ``alphanumeric_id`` catch-all is Topic-locally REFINED
        rather than excluded: it only counts as PHI when the matched span ALSO
        carries a run of 4+ contiguous digits (re-tested here against
        :data:`_TOPIC_ALPHANUMERIC_ID_STRICT_RE`). This keeps genuine
        license/account/device IDs (A1234567B, XJ4521098) blocked while
        letting ordinary study shorthand (covid19, iPhone15, Phase3) pass. A
        pure long digit run (99204812) is unaffected — it is still caught by
        the always-on ``mrn_or_id_long_digits`` ``\\d{6,}`` rule.

    Returns the list of fired pattern labels (never the matched text — the
    label is the audit-safe surface). Empty list ⇒ clean. Raises only if the
    catalogue detector itself fails — the caller turns that into a fail-CLOSED
    block (C-V1.2).

    The scan goes through ``phi_scrubber._layer2_scan_string`` (the
    catalogue's documented detector entry point) so there is ONE detector for
    every PHI surface; the Topic-specific label exclusions + the
    ``alphanumeric_id`` refinement are applied to its result. Routing through
    that single entry point also means a forced detector failure propagates
    here (and the caller fails closed), exactly as the describe-and-discard
    gate relies on.
    """
    from email_triage.style_learning.phi_scrubber import _layer2_scan_string

    scannable = _NCT_TOKEN_RE.sub(" ", str(value))
    fired: list[str] = []
    for label in _layer2_scan_string(scannable):
        if label in _TOPIC_SCRUB_EXCLUDED_LABELS:
            continue
        if label == "alphanumeric_id" and not _TOPIC_ALPHANUMERIC_ID_STRICT_RE.search(
            scannable
        ):
            # The loose catch-all fired but no span carries a 4+ digit run on
            # this surface — ordinary study shorthand (covid19, iPhone15),
            # not a genuine license/account/device ID. Treat as clean.
            continue
        fired.append(label)
    return fired


class TopicScrubBlocked(ValueError):
    """Raised by :func:`scrub_topic_free_text` when the V1 PHI gate blocks a save.

    Carries the list of fired pattern *labels* (never the matched text —
    the label is the audit-safe surface). ``raised`` is True when the block
    is the fail-closed-on-internal-error path (the scrubber itself raised),
    distinguishing a genuine PHI trip from a defensive block (C-V1.2).
    """

    def __init__(self, labels: list[str], *, raised: bool = False) -> None:
        self.labels = list(labels)
        self.raised = raised
        if raised:
            msg = (
                "Could not verify the Topic text is free of personal "
                "information — save blocked for safety. Please try again."
            )
        else:
            msg = (
                "This Topic's Subjects/Details look like they contain personal "
                "or health information (names, dates, IDs, contact info, or "
                "medical terms). Topic text must stay free of patient/personal "
                "details — edit it and save again."
            )
        super().__init__(msg)


def scrub_topic_free_text(*fields: str) -> None:
    """Fail-CLOSED PHI gate over the Topic's free-text fields (C-V1.1/.2).

    Runs every non-empty string in ``fields`` through :func:`_scan_topic_phi`
    (the m-series HIPAA-18 identifier catalogue, NCT-masked, medical-vocab
    excluded). Raises :class:`TopicScrubBlocked` when ANY pattern fires
    (``raised=False``) OR when the scrubber import/scan itself raises
    (``raised=True``) — both are fail-closed: a save proceeds ONLY on a
    clean, completed scan. Returns ``None`` on the clean path.

    Reuses the existing pre-egress scrubber catalogue (the same
    ``PHI_REGEX_PATTERNS`` the describe-and-discard distill gate uses) rather
    than forking a second pattern list — one PHI catalogue, audited once.
    """
    fired: list[str] = []
    try:
        for value in fields:
            if not value:
                continue
            fired.extend(_scan_topic_phi(str(value)))
    except Exception as exc:  # noqa: BLE001 — fail-closed on internal error
        # The catalogue could not be loaded/scanned — treat as a block, never
        # as "clean" (C-V1.2: a scrubber that can't run must BLOCK).
        raise TopicScrubBlocked(fired, raised=True) from exc

    if fired:
        raise TopicScrubBlocked(fired)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

@dataclass
class TopicDigest:
    """One named delivery schedule for a Topic.

    A Topic can carry SEVERAL — e.g. a daily incremental on weekdays at
    22:00 plus a weekly full on Monday at 07:00 (the operator's own
    example). Each digest owns its own cadence / time / days-of-week
    (``schedule``), its full / new-since-last / both ``mode``, and the
    rich render ``format`` — the SAME :class:`DigestFormat` the regular
    per-account digests use (render_as + group_by + columns + sort).

    Retention is **Topic-level** (the ``topic_hits`` store is shared
    across a Topic's digests), so it is NOT a per-digest field — it
    lives on :class:`TopicConfig`.

    ``id`` is an opaque stable handle so the editor can add/remove/edit
    individual digests without reordering churn; :func:`_coerce_topic_digest`
    mints one when a stored/POSTed digest lacks it.
    """
    id: str = ""
    name: str = ""
    enabled: bool = True
    mode: str = "full"
    schedule: DigestSchedule = field(default_factory=DigestSchedule)
    format: DigestFormat = field(default_factory=DigestFormat)


def _new_digest_id() -> str:
    """Mint an opaque id for a Topic digest (mirrors digest_configs._new_id).

    N-244 R24: routed through the short-id SSOT. Byte-identical wire
    shape (`tdig_<12-hex>`); entropy source flipped from uuid4 to
    secrets.token_hex (matches ACME + session conventions).
    """
    from email_triage._ids import new_short_id
    return new_short_id("tdig")


def _coerce_topic_digest(raw: Any) -> TopicDigest:
    """Hydrate one stored/POSTed digest dict into a :class:`TopicDigest`.

    Tolerant: unknown keys ignored, nested schedule/format go through the
    same ``digest_configs`` coercers, a missing id is minted, a bad mode
    falls back to ``full`` (validate surfaces it; never a 500)."""
    if isinstance(raw, TopicDigest):
        return raw
    if not isinstance(raw, dict):
        return TopicDigest(id=_new_digest_id())
    mode = str(raw.get("mode") or "full")
    if mode not in MODES:
        mode = "full"
    return TopicDigest(
        id=str(raw.get("id") or "") or _new_digest_id(),
        name=str(raw.get("name") or ""),
        enabled=bool(raw.get("enabled", True)),
        mode=mode,
        schedule=_coerce(DigestSchedule, raw.get("schedule")),
        format=_coerce_format(raw.get("format")),
    )


def _coerce_topic_digests(raw: Any) -> list[TopicDigest]:
    """Hydrate a JSON-or-list value into ``list[TopicDigest]``; tolerant."""
    src: Any = raw
    if isinstance(raw, str) and raw:
        try:
            src = json.loads(raw)
        except (TypeError, ValueError):
            return []
    if not isinstance(src, list):
        return []
    return [_coerce_topic_digest(d) for d in src]


@dataclass
class TopicConfig:
    """One user-scoped Topic.

    Composes (does not fork) the existing digest schedule / format
    dataclasses. ``subjects`` is a repeatable chip-list (a study has a
    name + acronym + sponsor; the matcher ORs across them).
    ``selected_account_ids`` is the in-Topic account multi-select that
    makes a Topic user-scoped rather than account-scoped.

    ``digests`` is the list of named delivery schedules ( v2 —
    multiple digests per Topic). Retention (``retention_days``) is
    Topic-level (shared hit store). The legacy single
    ``mode``/``schedule``/``window``/``format`` fields are RETAINED for
    rollback/back-compat: :func:`row_to_topic` synthesizes a one-element
    ``digests`` list from them when a Topic predates ``digests_json``,
    and :func:`upsert_topic` mirrors the first digest back into them so a
    rollback to the single-digest code still renders.

    ``id`` is the autoincrement DB id (0 for a not-yet-persisted Topic;
    :func:`upsert_topic` stamps the real id on insert). ``topic_version``
    is a monotonic int that bumps on any change to
    name/subjects/details/accounts (cache-invalidate + back-scan
    trigger) — see :func:`bump_topic_version`.
    """
    id: int = 0
    user_id: int = 0
    name: str = ""
    subjects: list[str] = field(default_factory=list)
    details: str = ""
    details_source: str = "manual"
    selected_account_ids: list[int] = field(default_factory=list)
    retention_days: int = 90
    #: Per-Topic digest confidence floor (operator 2026-06-15). ``None`` =
    #: inherit the global default :data:`TOPIC_MATCH_CONFIDENCE_FLOOR`
    #: (env ``ET_TOPIC_MATCH_CONFIDENCE_FLOOR``). A float in ``[0, 1]`` overrides
    #: it for THIS Topic's digests. NULL is load-bearing — distinct from 0.0
    #: (0.0 = surface everything); never coerce a missing column to 0.0.
    confidence_floor: float | None = None
    digests: list[TopicDigest] = field(default_factory=list)
    # Legacy single-digest fields — kept for rollback/back-compat only.
    # New code reads/writes ``digests``; these mirror digest[0].
    mode: str = "full"
    schedule: DigestSchedule = field(default_factory=DigestSchedule)
    window: DigestWindow = field(default_factory=DigestWindow)
    format: DigestFormat = field(default_factory=DigestFormat)
    topic_version: int = 1
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""
    deleted_at: str | None = None


def _now_iso() -> str:
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


def _coerce_str_list(raw: Any) -> list[str]:
    """Hydrate a JSON-or-list value into a ``list[str]``; tolerant."""
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, str) and raw:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return []
        return [str(x) for x in data] if isinstance(data, list) else []
    return []


def _coerce_int_list(raw: Any) -> list[int]:
    """Hydrate a JSON-or-list value into a ``list[int]``; drops junk."""
    out: list[int] = []
    src: Any
    if isinstance(raw, list):
        src = raw
    elif isinstance(raw, str) and raw:
        try:
            src = json.loads(raw)
        except (TypeError, ValueError):
            return []
    else:
        return []
    if not isinstance(src, list):
        return []
    for x in src:
        v = parse_int_or_none(x)  # N-219c/8 R23: SSOT
        if v is not None:
            out.append(v)
    return out


def row_to_topic(row: Any) -> TopicConfig:
    """Hydrate a ``topics`` DB row (sqlite3.Row or tuple-dict) into a
    :class:`TopicConfig`.

    Tolerant of partial / legacy JSON blobs — the nested digest
    dataclasses go through the same ``digest_configs`` coercers
    (``_coerce`` / ``_coerce_format``) so a malformed ``schedule_json``
    degrades to a default rather than raising.
    """
    def g(key: str, default: Any = None) -> Any:
        if hasattr(row, "keys"):
            return row[key] if key in row.keys() else default
        return row.get(key, default) if isinstance(row, dict) else default

    def _load_json_obj(raw: Any) -> Any:
        if isinstance(raw, (dict, list)):
            return raw
        if isinstance(raw, str) and raw:
            try:
                return json.loads(raw)
            except (TypeError, ValueError):
                return {}
        return {}

    legacy_mode = str(g("mode") or "full")
    legacy_schedule = _coerce(DigestSchedule, _load_json_obj(g("schedule_json")))
    legacy_format = _coerce_format(_load_json_obj(g("format_json")))

    #  v2 — prefer the multi-digest ``digests_json``. A Topic that
    # predates the column (or has an empty list) synthesizes a single
    # digest from the legacy mode/schedule/format so its existing
    # delivery config survives the schema bump untouched.
    digests = _coerce_topic_digests(g("digests_json"))
    if not digests:
        digests = [TopicDigest(
            id=_new_digest_id(),
            name="Digest",
            enabled=True,
            mode=legacy_mode if legacy_mode in MODES else "full",
            schedule=legacy_schedule,
            format=legacy_format,
        )]

    return TopicConfig(
        id=int(g("id") or 0),
        user_id=int(g("user_id") or 0),
        name=str(g("name") or ""),
        subjects=_coerce_str_list(g("subjects_json")),
        details=str(g("details") or ""),
        details_source=str(g("details_source") or "manual"),
        selected_account_ids=_coerce_int_list(g("selected_account_ids_json")),
        retention_days=int(g("retention_days") or 0),
        # NULL (legacy / pre-migration / "use the default") stays None — do NOT
        # coerce to 0.0 (0.0 would surface every weak match for this Topic).
        confidence_floor=(
            float(_cf) if (_cf := g("confidence_floor")) is not None else None
        ),
        digests=digests,
        mode=legacy_mode,
        schedule=legacy_schedule,
        window=_coerce(DigestWindow, _load_json_obj(g("window_json"))),
        format=legacy_format,
        topic_version=int(g("topic_version") or 1),
        enabled=bool(g("enabled")),
        created_at=str(g("created_at") or ""),
        updated_at=str(g("updated_at") or ""),
        deleted_at=(g("deleted_at") or None),
    )


def to_dict(cfg: TopicConfig) -> dict[str, Any]:
    """Plain-dict round-trip (nested dataclasses → dicts) for API /
    template surfaces. Mirrors ``digest_configs.to_dict``."""
    return asdict(cfg)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate(cfg: TopicConfig) -> list[str]:
    """Return human-readable validation errors, empty when ok.

    Bounces malformed configs at the save boundary with actionable
    messages instead of letting a typo break the digest builder.
    """
    errors: list[str] = []
    if cfg.user_id <= 0:
        errors.append("user_id is required")
    if not cfg.name.strip():
        errors.append("name is required")
    if cfg.retention_days < 0:
        errors.append("retention_days must be >= 0")
    # Per-Topic floor: blank (None) inherits the default; a set value must be in
    # [0, 1] (same range the env SSOT _resolve_confidence_floor enforces — ONE
    # range definition). An out-of-range value bounces here BEFORE persist so a
    # typo re-renders the editor with this message rather than silently reverting.
    if cfg.confidence_floor is not None and not (
        0.0 <= float(cfg.confidence_floor) <= 1.0
    ):
        errors.append("Match strictness must be between 0 and 1.")

    #  v2 — per-digest validation. A Topic with zero digests is
    # allowed (it just collects hits with no scheduled delivery yet);
    # each digest that IS present must be well-formed so the scheduler
    # loop never trips on a typo.
    for i, d in enumerate(cfg.digests or []):
        tag = f"Digest {i + 1}" + (f" ({d.name})" if d.name else "")
        if d.mode not in MODES:
            errors.append(f"{tag}: what-to-include must be one of {MODES}")
        if d.schedule.cadence not in CADENCES:
            errors.append(f"{tag}: cadence must be one of {CADENCES}")
        # ``t or ""`` guards a None time_local (a malformed digests_json /
        # direct-API write) — len(None) would 500 instead of validating.
        t = d.schedule.time_local or ""
        if not (
            len(t) == 5 and t[2] == ":"
            and t[:2].isdigit() and t[3:].isdigit()
            and 0 <= int(t[:2]) <= 23 and 0 <= int(t[3:]) <= 59
        ):
            errors.append(f"{tag}: send time must be HH:MM (24-hour)")
        if d.schedule.cadence == "weekly" and not d.schedule.days_of_week:
            errors.append(f"{tag}: weekly cadence needs at least one day")
        if d.format.render_as not in RENDER_AS:
            errors.append(f"{tag}: render style is not recognised")
        # group_by + max_rows mirror the DigestConfig.validate bounds so a
        # hand-crafted / typo'd POST is bounced at SAVE time with an
        # actionable message, not at render time with a stack trace.
        if d.format.group_by not in GROUP_BYS:
            errors.append(f"{tag}: group-by is not recognised")
        if d.format.max_rows < 1 or d.format.max_rows > 1000:
            errors.append(f"{tag}: max rows must be between 1 and 1000")
    return errors


# ---------------------------------------------------------------------------
# Read CRUD (plain helpers — consistent WAL snapshot, no write lock)
# ---------------------------------------------------------------------------

def list_topics(
    conn: sqlite3.Connection,
    user_id: int,
    *,
    include_deleted: bool = False,
) -> list[TopicConfig]:
    """Return a user's Topics, newest first. Excludes soft-deleted by
    default (``deleted_at IS NULL``).
    """
    sql = f"SELECT {TOPICS_COLUMNS} FROM topics WHERE user_id = ?"
    params: list[Any] = [int(user_id)]
    if not include_deleted:
        sql += " AND deleted_at IS NULL"
    sql += " ORDER BY created_at DESC, id DESC"
    rows = conn.execute(sql, params).fetchall()
    return [row_to_topic(r) for r in rows]


def get_topic(
    conn: sqlite3.Connection,
    topic_id: int,
    *,
    include_deleted: bool = False,
) -> TopicConfig | None:
    """Return one Topic by id, or ``None`` when absent.

    Keyed by ``id`` (the global surrogate), NOT scoped to a user here —
    the web layer is responsible for the per-user authorization check
    before handing an id in. Excludes soft-deleted by default.
    """
    sql = f"SELECT {TOPICS_COLUMNS} FROM topics WHERE id = ?"
    params: list[Any] = [int(topic_id)]
    if not include_deleted:
        sql += " AND deleted_at IS NULL"
    row = conn.execute(sql, params).fetchone()
    return row_to_topic(row) if row is not None else None


def list_active_topics_for_account(
    conn: sqlite3.Connection,
    account_id: int,
) -> list[TopicConfig]:
    """Return every ENABLED, non-deleted Topic that watches ``account_id``.

    The live classify path matches each just-classified message
    against the Topics whose ``selected_account_ids`` include the message's
    account. Topics are **user-scoped**, but a single account can be watched
    by several users' Topics, so this is keyed on the **account** (NOT a
    user): the per-account authorization was already enforced when each
    Topic was saved (the editor intersects submitted account ids with the
    author's manageable set — design §5), so membership in
    ``selected_account_ids`` is itself the authorization record.

    The account-membership filter runs in Python over the JSON-array column
    (``selected_account_ids`` is a JSON blob, not a relational column): the
    ``topics`` table is small (user-defined), and the matcher's per-message
    LLM call dominates this read, so a bounded scan of enabled Topics is
    cheaper to keep correct than a JSON1 sub-query. Disabled + soft-deleted
    Topics are excluded — they neither match live mail nor collect hits.
    """
    rows = conn.execute(
        f"SELECT {TOPICS_COLUMNS} FROM topics WHERE enabled = 1 AND deleted_at IS NULL",
    ).fetchall()
    aid = int(account_id)
    out: list[TopicConfig] = []
    for r in rows:
        cfg = row_to_topic(r)
        if aid in (cfg.selected_account_ids or []):
            out.append(cfg)
    return out


def list_all_active_topics(conn: sqlite3.Connection) -> list[TopicConfig]:
    """Return every ENABLED, non-deleted Topic across ALL users.

    The scheduled Topic-digest sender iterates every Topic install-wide
    (Topics are user-scoped, but the single sender loop fires them all),
    checking each Topic's named digests against their schedules. Disabled +
    soft-deleted Topics are excluded — they neither collect hits nor deliver.
    """
    rows = conn.execute(
        f"SELECT {TOPICS_COLUMNS} FROM topics WHERE enabled = 1 AND deleted_at IS NULL "
        "ORDER BY id",
    ).fetchall()
    return [row_to_topic(r) for r in rows]


# ---------------------------------------------------------------------------
# Write CRUD (@db_write — routes through the single-writer thread)
# ---------------------------------------------------------------------------

@db_write
def upsert_topic(conn: sqlite3.Connection, cfg: TopicConfig) -> TopicConfig:
    """Insert or update a Topic, keyed by ``cfg.id``.

    ``cfg.id == 0`` (or falsy) inserts a new row and stamps the
    autoincrement id back onto the returned config. A non-zero id
    updates the existing row in place.

    The composed digest schedule / window / format are serialized to
    their JSON-blob columns; the subject chip-list + account multi-select
    to their JSON-array columns. ``created_at`` is preserved on update
    (never clobbered); ``updated_at`` is stamped every write.

    Does NOT auto-bump ``topic_version`` — that is the caller's explicit
    decision (a name/accounts/details change bumps it via
    :func:`bump_topic_version`; an enable-toggle does not). Returns the
    persisted config (id-stamped).

    **#33 C-V1.1 / C-V1.2 — V1 PHI gate (fail-CLOSED).** The operator-typed
    Details + every Subject chip are scrubbed through the m-series HIPAA-18
    catalogue BEFORE the row is written. A PHI-pattern trip — OR a scrubber
    that raises — raises :class:`TopicScrubBlocked` and the save NEVER
    reaches the INSERT/UPDATE (no PHI-shaped free text lands at rest, and
    the cloud Topic-block egress that later reads ``details`` stays inert
    until the text is clean). The gate runs first so an enable-toggle
    re-save of an already-clean Topic also re-verifies on every write path.
    """
    # C-V1.1 / C-V1.2 — scrub every operator free-text surface fail-closed
    # before any write: Details, each Subject chip, AND each digest NAME
    # ( v2 added per-digest names — also operator free text that lands at
    # rest in digests_json, so it MUST pass the same HIPAA-18 gate or a
    # PHI-shaped digest name ("MRN 12345678") would persist unscanned).
    scrub_topic_free_text(
        cfg.details,
        *(cfg.subjects or []),
        *[d.name for d in (cfg.digests or []) if d.name],
    )

    now = _now_iso()
    subjects_json = dump_json_col(list(cfg.subjects or []))
    accounts_json = dump_json_col([int(a) for a in (cfg.selected_account_ids or [])])

    #  v2 — ``digests`` is the source of truth. Ensure each carries an id
    # so edit/remove stays stable, then serialize to ``digests_json``.
    digests = list(cfg.digests or [])
    for d in digests:
        if not d.id:
            d.id = _new_digest_id()
    digests_json = dump_json_col([asdict(d) for d in digests])

    # Mirror the FIRST digest into the legacy single-digest columns so a
    # rollback to pre-v41 code still renders this Topic's primary digest
    # (the columns stay populated; new code ignores them on read when
    # ``digests_json`` is present).
    if digests:
        first = digests[0]
        legacy_mode = first.mode if first.mode in MODES else "full"
        schedule_json = dump_json_col(asdict(first.schedule))
        format_json = dump_json_col(asdict(first.format))
    else:
        legacy_mode = cfg.mode if cfg.mode in MODES else "full"
        schedule_json = dump_json_col(asdict(cfg.schedule))
        format_json = dump_json_col(asdict(cfg.format))
    window_json = dump_json_col(asdict(cfg.window))

    if cfg.id and int(cfg.id) > 0:
        conn.execute(
            "UPDATE topics SET "
            "  user_id = ?, name = ?, subjects_json = ?, details = ?, "
            "  details_source = ?, selected_account_ids_json = ?, mode = ?, "
            "  retention_days = ?, confidence_floor = ?, digests_json = ?, "
            "  schedule_json = ?, window_json = ?, format_json = ?, "
            "  topic_version = ?, enabled = ?, updated_at = ? "
            "WHERE id = ?",
            (
                int(cfg.user_id), cfg.name, subjects_json, cfg.details,
                cfg.details_source, accounts_json, legacy_mode,
                int(cfg.retention_days), cfg.confidence_floor, digests_json,
                schedule_json, window_json, format_json, int(cfg.topic_version),
                int(bool(cfg.enabled)), now, int(cfg.id),
            ),
        )
        conn.commit()
        cfg.updated_at = now
        return cfg

    cur = conn.execute(
        "INSERT INTO topics ("
        "  user_id, name, subjects_json, details, details_source, "
        "  selected_account_ids_json, mode, retention_days, confidence_floor, "
        "  digests_json, schedule_json, window_json, format_json, topic_version, "
        "  enabled, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            int(cfg.user_id), cfg.name, subjects_json, cfg.details,
            cfg.details_source, accounts_json, legacy_mode,
            int(cfg.retention_days), cfg.confidence_floor, digests_json,
            schedule_json, window_json, format_json, int(cfg.topic_version),
            int(bool(cfg.enabled)), now, now,
        ),
    )
    conn.commit()
    cfg.id = int(cur.lastrowid)
    cfg.created_at = now
    cfg.updated_at = now
    return cfg


@db_write
def soft_delete_topic(conn: sqlite3.Connection, topic_id: int) -> bool:
    """Soft-delete a Topic (set ``deleted_at``). Returns True on hit.

    A soft delete (tombstone, not a row removal) keeps the Topic +
    its hit history queryable for audit/teaching while removing it from
    the user-facing list. A *hard* delete is a separate, deliberate
    operation (the design's B2 ``ON DELETE CASCADE`` only fires on a real
    ``DELETE FROM topics`` — not exercised by this helper). Idempotent:
    re-deleting an already-deleted Topic does not flip ``deleted_at``
    forward (the ``WHERE deleted_at IS NULL`` guard makes it a no-op).
    """
    cur = conn.execute(
        "UPDATE topics SET deleted_at = ?, updated_at = ? "
        "WHERE id = ? AND deleted_at IS NULL",
        (_now_iso(), _now_iso(), int(topic_id)),
    )
    conn.commit()
    return cur.rowcount > 0


@db_write
def bump_topic_version(conn: sqlite3.Connection, topic_id: int) -> int:
    """Increment a Topic's ``topic_version`` and return the new value.

    Called on any change to name/subjects/details/accounts (design §2):
    a version bump invalidates the back-scan match cache (rows are keyed
    by ``(topic_id, topic_version, …)``) and triggers a fresh back-scan.
    Returns the new ``topic_version`` (or 0 if the Topic does not exist).
    """
    conn.execute(
        "UPDATE topics SET topic_version = topic_version + 1, "
        "  updated_at = ? WHERE id = ?",
        (_now_iso(), int(topic_id)),
    )
    conn.commit()
    row = conn.execute(
        "SELECT topic_version FROM topics WHERE id = ?", (int(topic_id),),
    ).fetchone()
    if row is None:
        return 0
    return int(row["topic_version"] if hasattr(row, "keys") else row[0])


@db_write
def insert_topic_hit(
    conn: sqlite3.Connection,
    *,
    topic_id: int,
    account_id: int,
    rfc822_message_id: str,
    folder: str = "",
    provider_uid: str | None = None,
    uidvalidity: int = 0,
    reason_terms: list[str] | None = None,
    confidence: float = 0.0,
    source: str = "live",
    seen_at: str | None = None,
) -> None:
    """Record a Topic hit, UPSERT-keyed on
    ``(topic_id, account_id, rfc822_message_id)``.

    **The MIN/MAX pin (design §8 B3).** The same message can be
    discovered twice: once by the live classify pass and once by an
    explicit back-scan over history. Single-writer serialization does
    NOT resolve this *logical* race — a second insert must keep the
    EARLIER ``first_seen_at`` (a wrong, later ``first_seen_at`` would
    make the message look "new" and corrupt the Differential digest).
    The conflict clause therefore sets:

        first_seen_at     = MIN(existing, incoming)
        last_confirmed_at = MAX(existing, incoming)

    using SQLite's two-arg ``MIN``/``MAX`` scalar functions over the
    stored row value and ``excluded`` (the rejected insert). A re-insert
    also re-confirms the hit (advances ``last_confirmed_at``) and
    refreshes the fetch key (folder/uid/uidvalidity) + matched terms +
    ``confidence`` + ``source``, but never moves ``first_seen_at``
    forward.

    ``reason_terms`` is the JSON list of matched Topic-terms (the user's
    own public Subject/Details terms — never a body quote). ``confidence``
    is the match strength [0.0..1.0]; ``source`` records where the hit was
    discovered (``'live'`` | ``'backscan'`` | ``'included'``).

    Inserting a hit does NOT clear a prior ``removed_at`` / ``expired_at``
    — a re-confirmation of a soft-removed hit is left for the caller /
    feedback layer to decide, so a per-hit "this was wrong" removal is
    not silently undone by the next classify pass.
    """
    now = seen_at or _now_iso()
    terms_json = dump_json_col(list(reason_terms or []))
    conn.execute(
        "INSERT INTO topic_hits ("
        "  topic_id, account_id, folder, provider_uid, uidvalidity, "
        "  rfc822_message_id, reason_terms_json, confidence, source, "
        "  first_seen_at, last_confirmed_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(topic_id, account_id, rfc822_message_id) DO UPDATE SET "
        "  first_seen_at     = MIN(topic_hits.first_seen_at, "
        "                          excluded.first_seen_at), "
        "  last_confirmed_at = MAX(topic_hits.last_confirmed_at, "
        "                          excluded.last_confirmed_at), "
        "  folder            = excluded.folder, "
        "  provider_uid      = excluded.provider_uid, "
        "  uidvalidity       = excluded.uidvalidity, "
        "  reason_terms_json = excluded.reason_terms_json, "
        "  confidence        = excluded.confidence, "
        "  source            = excluded.source",
        (
            int(topic_id), int(account_id), folder, provider_uid,
            int(uidvalidity), rfc822_message_id, terms_json,
            float(confidence), str(source), now, now,
        ),
    )
    conn.commit()


# ---------------------------------------------------------------------------
#  v3 — operator feedback (thumbs up/down) + learned reinforcement signal.
#
# A vote carries TWO effects (operator 2026-06-12 "curation + reinforcement"):
#   * message-level curation  — flips that message's topic_hits.source to
#                               'included' (up) / 'excluded' (down);
#   * sender-level learning    — a per-Topic signal the matcher honors on FUTURE
#                               matches (down sender ⇒ auto-drop, up ⇒ always-keep).
# The sender key is the operator's own curation, SAME category as the shipped
# list_rules sender patterns — SQLCipher-at-rest, cascade-deleted with the Topic.
# ---------------------------------------------------------------------------

def normalize_feedback_sender(sender: str) -> str:
    """A stable, lowercased sender key from a From header.

    ``"Fred <fred@x.com>"`` -> ``"fred@x.com"``; bare ``"fred@x.com"`` ->
    ``"fred@x.com"``. Empty/None -> ``""``. Pure string work.

    Delegates to the bare-address SSOT ``mail_headers.extract_bare_address``
    (A7). The previous hand-rolled ``<([^>]+)>`` regex was byte-identical to
    the SSOT (same regex + same lower/strip fallback — verified over the edge
    cases), so the persisted ``topic_feedback`` dedup key is UNCHANGED by this
    convergence. Census run12 #9: a re-rolled copy of the SSOT's own regex —
    REFUTED-as-live (no key split) but real PD#5 drift; the A7 pin now bans a
    re-rolled angle-bracket-capture regex so it can't diverge later."""
    return extract_bare_address(sender)


@db_write
def record_topic_feedback(
    conn: sqlite3.Connection,
    *,
    topic_id: int,
    account_id: int | None,
    vote: int,
    sender: str | None = None,
    rfc822_message_id: str | None = None,
    now: str | None = None,
) -> dict:
    """Record an operator thumbs vote (``+1`` up / ``-1`` down) on a Topic match.

    Writes (a) the SENDER-level learned signal when ``sender`` is given and
    resolves to a non-empty key, and (b) the MESSAGE-level signal when
    ``rfc822_message_id`` is given — the latter ALSO flips that hit's
    ``topic_hits.source`` to ``'included'`` / ``'excluded'`` so the digest
    honors the curation immediately. Each is an UPSERT on
    ``(topic_id, signal_type, signal_value)`` so a re-vote flips the sign.
    Returns ``{"sender_key": str|None, "vote": int}`` for the caller's UI echo.
    """
    now = now or _now_iso()
    v = 1 if int(vote) >= 0 else -1
    aid = int(account_id) if account_id is not None else None

    def _upsert(signal_type: str, signal_value: str) -> None:
        conn.execute(
            "INSERT INTO topic_feedback ("
            "  topic_id, account_id, signal_type, signal_value, vote, "
            "  rfc822_message_id, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(topic_id, signal_type, signal_value) DO UPDATE SET "
            "  vote = excluded.vote, account_id = excluded.account_id, "
            "  rfc822_message_id = excluded.rfc822_message_id, "
            "  updated_at = excluded.updated_at",
            (int(topic_id), aid, signal_type, signal_value, v,
             rfc822_message_id, now, now),
        )

    sender_key = normalize_feedback_sender(sender or "")
    if sender_key:
        _upsert("sender", sender_key)
    if rfc822_message_id and aid is not None:
        _upsert("message", str(rfc822_message_id))
        # Message-level curation on any STORED hit (the ephemeral Preview row
        # may not be persisted yet — then only the sender signal lands, which is
        # the durable learning). Reuse the existing topic_hits curation columns:
        #   up   -> source='included' + clear any prior soft-remove;
        #   down -> removed_at = now (the existing "this was wrong" soft-remove).
        if v > 0:
            # N-184 R20_16: upvote-restore MUST clear both soft-lifecycle
            # cols. Clearing removed_at only left an expired-then-restored
            # hit hidden by the expired filter; both cols set-by-1-path but
            # cleared-by-0-paths was the bug.
            conn.execute(
                "UPDATE topic_hits "
                "SET source = 'included', removed_at = NULL, expired_at = NULL "
                "WHERE topic_id = ? AND account_id = ? AND rfc822_message_id = ?",
                (int(topic_id), aid, str(rfc822_message_id)),
            )
        else:
            conn.execute(
                "UPDATE topic_hits SET removed_at = ? "
                "WHERE topic_id = ? AND account_id = ? AND rfc822_message_id = ?",
                (now, int(topic_id), aid, str(rfc822_message_id)),
            )
    elif rfc822_message_id:
        # Sender-less message vote with an account is the normal case; a vote
        # carrying neither account nor sender is a no-op guard.
        _upsert("message", str(rfc822_message_id))
    conn.commit()
    return {"sender_key": sender_key or None, "vote": v}


def get_topic_sender_signals(conn: sqlite3.Connection, topic_id: int) -> dict[str, int]:
    """``{normalized_sender: vote(+1/-1)}`` — the Topic's learned allow/deny set.

    Read-only; the matcher loads this once per Preview / back-scan / live match
    and drops a -1 sender's mail (auto-exclude) / force-keeps a +1 sender's."""
    rows = conn.execute(
        "SELECT signal_value, vote FROM topic_feedback "
        "WHERE topic_id = ? AND signal_type = 'sender'",
        (int(topic_id),),
    ).fetchall()
    out: dict[str, int] = {}
    for r in rows:
        sv = r["signal_value"] if hasattr(r, "keys") else r[0]
        vt = r["vote"] if hasattr(r, "keys") else r[1]
        out[str(sv)] = int(vt)
    return out


@db_write
def clear_topic_feedback(
    conn: sqlite3.Connection, *, topic_id: int, signal_type: str, signal_value: str,
) -> None:
    """Undo a vote — the operator un-thumbs a sender or message."""
    conn.execute(
        "DELETE FROM topic_feedback "
        "WHERE topic_id = ? AND signal_type = ? AND signal_value = ?",
        (int(topic_id), str(signal_type), str(signal_value)),
    )
    conn.commit()


# ---------------------------------------------------------------------------
#  scheduled-digest send-state + live-hit gather.
#
# Consumed by the scheduled Topic-digest sender (``web/topic_digest_sender``).
# State is keyed ``(topic_id, channel)`` where ``channel`` is the per-digest
# stable key (the ``TopicDigest.id``) — a Topic carries SEVERAL named digests,
# each with its own schedule, so each owns ONE ``study_digest_state`` row
# carrying its Differential ``last_sent_watermark`` (the new-since cursor) and
# its ``last_sent_at`` (the schedule idempotence marker the sender's
# ``digest_should_fire`` reads).
# ---------------------------------------------------------------------------

def get_topic_digest_state(
    conn: sqlite3.Connection,
    topic_id: int,
    channel: str,
) -> dict[str, Any] | None:
    """Return the ``study_digest_state`` row for ``(topic_id, channel)``.

    ``None`` before the first send. The row carries ``last_sent_watermark``
    (the Differential cursor) + ``last_sent_at`` (the schedule marker).
    """
    row = conn.execute(
        "SELECT last_sent_watermark, last_sent_at FROM study_digest_state "
        "WHERE topic_id = ? AND format = ?",
        (int(topic_id), str(channel)),
    ).fetchone()
    if row is None:
        return None
    if hasattr(row, "keys"):
        return {
            "last_sent_watermark": row["last_sent_watermark"],
            "last_sent_at": row["last_sent_at"],
        }
    return {"last_sent_watermark": row[0], "last_sent_at": row[1]}


@db_write
def mark_topic_digest_sent(
    conn: sqlite3.Connection,
    *,
    topic_id: int,
    channel: str,
    last_sent_at: str,
    watermark: str | None = None,
) -> None:
    """UPSERT the send-state for ``(topic_id, channel)`` after a fire.

    Advances ``last_sent_at`` (always) and ``last_sent_watermark`` (only when
    ``watermark`` is non-None — a Full-only send passes ``None`` and the
    stored cursor is preserved). The watermark advance commits in the SAME
    write as ``last_sent_at`` so a crash cannot record the send without
    advancing the cursor (at-least-once, idempotent-by-watermark: a failed
    send simply re-includes those hits next time, never silently drops —
    design §2). Keyed on ``UNIQUE(topic_id, format)``.
    """
    conn.execute(
        "INSERT INTO study_digest_state ("
        "  topic_id, format, last_sent_watermark, last_sent_at"
        ") VALUES (?, ?, ?, ?) "
        "ON CONFLICT(topic_id, format) DO UPDATE SET "
        "  last_sent_watermark = COALESCE("
        "      excluded.last_sent_watermark, "
        "      study_digest_state.last_sent_watermark), "
        "  last_sent_at = excluded.last_sent_at",
        (int(topic_id), str(channel), watermark, str(last_sent_at)),
    )
    conn.commit()


def _live_topic_hits_where(
    topic_id: int, *, retention_days: int, since_watermark: str | None,
) -> tuple[str, list[Any]]:
    """The shared WHERE for a Topic's LIVE hits in a digest window — live +
    retention + watermark, WITHOUT the confidence floor.

    Both the surface gather (``>= floor``) and the suppressed-count (``< floor``)
    build on this ONE predicate list so they can't drift in the window
    definition (PD#5). Returns ``(where_sql, params)``; the caller appends its
    own ``confidence`` comparison + its param AFTER these (param order stays
    lockstep with the ``?`` order)."""
    where = "topic_id = ? AND removed_at IS NULL AND expired_at IS NULL"
    params: list[Any] = [int(topic_id)]
    if retention_days and int(retention_days) > 0:
        from email_triage._isotime import to_utc_iso
        cutoff = to_utc_iso(
            datetime.now(timezone.utc) - timedelta(days=int(retention_days))
        )
        where += " AND first_seen_at >= ?"
        params.append(cutoff)
    if since_watermark:
        where += " AND first_seen_at > ?"
        params.append(str(since_watermark))
    return where, params


def gather_live_topic_hits(
    conn: sqlite3.Connection,
    topic_id: int,
    *,
    retention_days: int = 0,
    since_watermark: str | None = None,
    confidence_floor: float | None = None,
) -> list[dict[str, Any]]:
    """Return a Topic's LIVE hits (newest first) for a digest render.

    Live = ``removed_at IS NULL AND expired_at IS NULL``. ``retention_days``
    (> 0) bounds by ``first_seen_at >= now - retention_days`` (0 = no lower
    bound). ``since_watermark`` (the Differential cursor) additionally
    restricts to ``first_seen_at > watermark`` — the new-since-last-send set;
    pass ``None`` for the Full set.

    ``confidence_floor`` (default the module SSOT
    :data:`TOPIC_MATCH_CONFIDENCE_FLOOR`, env-tunable via
    ``ET_TOPIC_MATCH_CONFIDENCE_FLOOR``) suppresses hits whose stored
    ``confidence`` is below it — the SURFACE-time topic-match floor (operator
    2026-06-15). Applied here (not at match time) so it stays REVERSIBLE: every
    match is persisted, and lowering the floor re-surfaces hidden hits on the
    next render. Pass ``0.0`` to disable (e.g. a diagnostic that wants the full
    set). ``topic_hits.confidence`` is NOT NULL (default 0.0), so an unquantified
    match lands at 0.0 and is suppressed by any positive floor — fail-closed.

    Returns plain dicts: durable identity (``rfc822_message_id`` + fetch key)
    + matched terms + confidence + ``first_seen_at``. **No subject/body** —
    those are PHI, fetched ephemerally at render time (design §2); the caller
    resolves From/Subject/Date per hit out-of-band.
    """
    floor = (
        confidence_floor if confidence_floor is not None
        else TOPIC_MATCH_CONFIDENCE_FLOOR
    )
    where, params = _live_topic_hits_where(
        topic_id, retention_days=retention_days, since_watermark=since_watermark,
    )
    sql = (
        "SELECT topic_id, account_id, rfc822_message_id, folder, "
        "       provider_uid, uidvalidity, reason_terms_json, confidence, "
        "       first_seen_at FROM topic_hits WHERE " + where
    )
    if floor and float(floor) > 0.0:
        # COALESCE is defensive only — the column is NOT NULL (default 0.0) — but
        # keeps the floor fail-closed if that constraint is ever relaxed.
        sql += " AND COALESCE(confidence, 0.0) >= ?"
        params.append(float(floor))
    sql += " ORDER BY first_seen_at DESC"

    out: list[dict[str, Any]] = []
    for r in conn.execute(sql, params).fetchall():
        out.append({
            "topic_id": r["topic_id"],
            "account_id": r["account_id"],
            "rfc822_message_id": r["rfc822_message_id"],
            "folder": r["folder"],
            "provider_uid": r["provider_uid"],
            "uidvalidity": r["uidvalidity"],
            "reason_terms": _coerce_str_list(r["reason_terms_json"]),
            "confidence": r["confidence"],
            "first_seen_at": r["first_seen_at"],
        })
    return out


def count_topic_hits_below_floor(
    conn: sqlite3.Connection,
    topic_id: int,
    *,
    retention_days: int = 0,
    since_watermark: str | None = None,
    confidence_floor: float | None = None,
) -> int:
    """Count the LIVE hits in the same digest window that the confidence floor
    SUPPRESSES (``confidence < floor``) — operator visibility for the floor.

    The digest delivers only ``>= floor`` hits; this surfaces "N weak matches
    hidden" so a silently-suppressed genuine match is visible (the operator can
    then lower ``ET_TOPIC_MATCH_CONFIDENCE_FLOOR`` — every suppressed hit is still
    persisted and re-surfaces, operator 2026-06-15). Shares the live-window
    predicate with :func:`gather_live_topic_hits` so the two can never drift
    (PD#5). Returns 0 when the floor is disabled (``<= 0``)."""
    floor = (
        confidence_floor if confidence_floor is not None
        else TOPIC_MATCH_CONFIDENCE_FLOOR
    )
    if not floor or float(floor) <= 0.0:
        return 0
    where, params = _live_topic_hits_where(
        topic_id, retention_days=retention_days, since_watermark=since_watermark,
    )
    sql = (
        "SELECT COUNT(*) FROM topic_hits WHERE " + where
        + " AND COALESCE(confidence, 0.0) < ?"
    )
    params.append(float(floor))
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row else 0


__all__ = [
    "MODES",
    "TOPIC_MATCH_CONFIDENCE_FLOOR",
    "count_topic_hits_below_floor",
    "TopicScrubBlocked",
    "scrub_topic_free_text",
    "_scan_topic_phi",
    "TopicConfig",
    "TopicDigest",
    "_coerce_topic_digest",
    "_coerce_topic_digests",
    "_new_digest_id",
    "row_to_topic",
    "to_dict",
    "validate",
    "list_topics",
    "get_topic",
    "list_active_topics_for_account",
    "list_all_active_topics",
    "upsert_topic",
    "soft_delete_topic",
    "bump_topic_version",
    "insert_topic_hit",
    "get_topic_digest_state",
    "mark_topic_digest_sent",
    "gather_live_topic_hits",
]
