""" Topic / Study-Digest HIPAA privacy gates — the CI guard.

This module pins the four make-or-break privacy contracts for the Topic
digest feature (design ``internal documentation``
§0 / §4.7 / §5 / §8). Each assert site pins a contract that, if a future
commit loosens it, should fail this test rather than silently relax the
privacy posture.

The four gates (one ``Test*`` class each):

  (a) **SCRUBBER FAIL-CLOSED** — a Topic Details/Subject string carrying a
      PHI pattern (an MRN, a DOB, a bare surname near an NCT, an email …)
      BLOCKS the persisted save; AND a scrubber that *raises* also BLOCKS
      (fail-closed on error, not only on trip). Reuses the M-series PHI
      catalogue (``hipaa_style_distill._PHI_PATTERNS``) + the HIPAA-18
      regex detector (``phi_scrubber._layer2_scan_string``).
  (b) **PRIVACY-INVARIANT** — the stored ``reason_terms_json`` contains
      ONLY the user's own public Topic-terms, never a body quote. A
      synthetic match is driven through the matcher → the persisted hit;
      no body text may leak into the stored row.
  (c) **C-V3.2** — NO foreign key from the audit / ``log_entries`` (HMAC)
      chain reaches ``topics`` / ``topic_hits``, and the topic tables
      never reference the audit chain. A topics/topic_hits delete can
      therefore NEVER cascade-reach the audit chain. Proven by schema
      introspection over the live v40 migration.
  (d) **ACTOR≠OWNER** — a non-owner preview of a HIPAA-account hit fires
      ``record_hipaa_access_event``; owner self-access does NOT
      (§164.502(a) self-disclosure carve-out — ``feedback_hipaa_actor_
      owner_gate.md``).

No real PHI anywhere — clearly-fictional synthetic strings only
(``user@example.com`` / ``Operator A`` / digit runs / ``Dr. Jones``),
mirroring the ``test_privacy_invariants_m_series`` catalogue convention.

CI vs manual
------------
Every test in this module is **deterministic + runs in CI** — no live
matcher, no network, no Ollama. The recall *measurement* against a live
LLM lives in the sibling ``tests/test_topic_recall_harness.py`` (the
``≥0.95`` gate, env-gated skip). The privacy gates here have no live
dependency by design (the whole point is that the gate is enforced in
deterministic code, not by the LLM).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.actions.topic_configs import (
    TopicConfig,
    insert_topic_hit,
    upsert_topic,
)


# ---------------------------------------------------------------------------
# Synthetic PHI catalogue — reused from the M-series invariant suite
# (``test_privacy_invariants_m_series._SYNTHETIC_PHI_CATALOGUE``). Every
# entry is fictional + designed to match a specific PHI rule. These appear
# in TEST source only; the ``test_privacy_invariants_no_customer_names``
# sibling scans ``src/`` only, so synthetic names here don't trip it.
# ---------------------------------------------------------------------------

_SYNTHETIC_PHI_CATALOGUE: dict[str, str] = {
    "mrn_long_digit_run": "follow-up on 1234567 chart review",
    "date_dob_slash": "DOB 04/12/1965 noted",
    "ssn_format": "SSN 123-45-6789 on file",
    "phone_us_dashed": "call 555-123-4567",
    "phone_parens": "ring (555) 123-4567",
    "email_address": "loop in nurse@clinic.example",
    "street_address": "see 123 Main Street",
    "honorific_name": "follow up with Dr. Jones",
}

# A bare surname adjacent to an NCT id — the design's §0 "no identifier +
# study id" leak shape. Both the surname (honorific_name) and the NCT are
# things a Topic Details box must never persist as a study marker.
_SURNAME_NEAR_NCT = "Dr. Jones re NCT00000419 enrollment"


# ---------------------------------------------------------------------------
# DB helpers (mirror the M-series module's full-schema bring-up).
# ---------------------------------------------------------------------------

def _make_db_full() -> sqlite3.Connection:
    """Full schema via init_db — runs every migration incl. v40 (topics)."""
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_user(conn: sqlite3.Connection, email: str = "owner@example.com") -> int:
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (email, "Operator A", "user", _now()),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_account(
    conn: sqlite3.Connection, *, user_id: int, hipaa: bool = False,
) -> int:
    now = _now()
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "  user_id, name, provider_type, config_json, hipaa, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Operator A Mailbox", "imap", "{}", int(bool(hipaa)), now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_topic(
    conn: sqlite3.Connection, *, user_id: int, account_id: int,
    name: str = "Farm Animals", subjects=("goats", "alpacas"),
    details: str = "",
) -> TopicConfig:
    cfg = TopicConfig(
        user_id=user_id,
        name=name,
        subjects=list(subjects),
        details=details,
        selected_account_ids=[account_id],
    )
    return upsert_topic(conn, cfg)


# ===========================================================================
# (a) SCRUBBER FAIL-CLOSED  —  the REAL production gate in upsert_topic
# ===========================================================================
#
# The Topic Details/Subject boxes take operator-typed free text. Production
# ships a fail-closed PHI gate (``topic_configs.scrub_topic_free_text``, wired
# into ``upsert_topic`` ahead of any write; design C-V1.1 / C-V1.2):
#
#   * a PHI-pattern TRIP raises ``TopicScrubBlocked(raised=False)`` — the row
#     never reaches the INSERT/UPDATE;
#   * a scrubber that RAISES (or fails to even import) raises
#     ``TopicScrubBlocked(raised=True)`` — fail-closed on error, NOT only on
#     trip; a scrubber that can't run BLOCKS, never "assume clean".
#
# The gate scans Details + every Subject chip through the m-series HIPAA-18
# regex catalogue (``phi_scrubber._layer2_scan_string`` over
# ``PHI_REGEX_PATTERNS``). The Topic *name* is the operator's own short public
# label and is intentionally NOT gated here (per the labels-are-not-PHI
# ruling) — PHI leaks into the free-text Details/Subjects, which IS gated.
#
# We test the real symbols directly: no test-side re-implementation.
# ===========================================================================


def _detect_topic_phi(text: str) -> list[str]:
    """The production HIPAA-18 detector's labels for one string (sanity use).

    Mirrors exactly what ``scrub_topic_free_text`` runs over each field —
    ``phi_scrubber._layer2_scan_string`` (the 45 CFR §164.514(b)(2) set).
    Used only to assert a synthetic string genuinely trips the gate, so a
    "blocks save" test can never pass for the wrong reason.
    """
    from email_triage.style_learning.phi_scrubber import _layer2_scan_string

    return list(_layer2_scan_string(text)) if text else []


class TestScrubberFailClosed:
    """A PHI-bearing Topic save raises ``TopicScrubBlocked`` and never persists;
    a scrubber that raises also blocks (fail-closed on error)."""

    def _topic_count(self, conn) -> int:
        return int(conn.execute("SELECT COUNT(*) FROM topics").fetchone()[0])

    @pytest.mark.parametrize(
        "label,phi", sorted(_SYNTHETIC_PHI_CATALOGUE.items()),
    )
    def test_phi_in_details_blocks_save(self, label, phi):
        """Every catalogue PHI shape in the Details box BLOCKS the real save."""
        from email_triage.actions.topic_configs import TopicScrubBlocked

        conn = _make_db_full()
        uid = _seed_user(conn)
        acct = _seed_account(conn, user_id=uid)
        cfg = TopicConfig(
            user_id=uid, name="Goat Notes", subjects=["goats"],
            details=phi, selected_account_ids=[acct],
        )
        before = self._topic_count(conn)
        with pytest.raises(TopicScrubBlocked) as ei:
            upsert_topic(conn, cfg)
        assert ei.value.raised is False, "a PHI trip is not the raised-error path"
        assert ei.value.labels, "the block must carry the fired pattern label(s)"
        # The row never landed — fail-closed means no partial persist.
        assert self._topic_count(conn) == before, (
            f"PHI shape {label!r} ({phi!r}) reached the topics table; the "
            f"save must be blocked BEFORE the write"
        )

    def test_surname_near_nct_in_details_blocks_save(self):
        """A bare surname adjacent to an NCT id (design §0 leak shape) blocks."""
        from email_triage.actions.topic_configs import TopicScrubBlocked

        conn = _make_db_full()
        uid = _seed_user(conn)
        acct = _seed_account(conn, user_id=uid)
        cfg = TopicConfig(
            user_id=uid, name="Cohort notes", subjects=["lupus"],
            details=_SURNAME_NEAR_NCT, selected_account_ids=[acct],
        )
        # Sanity: the detector actually fires on the honorific surname here.
        assert _detect_topic_phi(_SURNAME_NEAR_NCT), (
            "detector should flag the honorific surname in the NCT line"
        )
        with pytest.raises(TopicScrubBlocked):
            upsert_topic(conn, cfg)
        assert self._topic_count(conn) == 0

    def test_phi_in_a_subject_chip_blocks_save(self):
        """PHI in a Subject chip (not just Details) also blocks the save."""
        from email_triage.actions.topic_configs import TopicScrubBlocked

        conn = _make_db_full()
        uid = _seed_user(conn)
        acct = _seed_account(conn, user_id=uid)
        cfg = TopicConfig(
            user_id=uid, name="Goat Notes",
            subjects=["goats", "DOB 04/12/1965"],  # poisoned chip
            details="", selected_account_ids=[acct],
        )
        with pytest.raises(TopicScrubBlocked):
            upsert_topic(conn, cfg)
        assert self._topic_count(conn) == 0

    def test_clean_topic_persists(self):
        """Negative control: a clean non-medical Topic DOES persist — the
        gate filters PHI, it does not nuke every save. (Details/Subjects are
        single-word + lower-case so the broad two-caps name heuristic — which
        runs at egress, not at save — is not even in play here.)"""
        conn = _make_db_full()
        uid = _seed_user(conn)
        acct = _seed_account(conn, user_id=uid)
        cfg = TopicConfig(
            user_id=uid, name="dirt bikes",
            subjects=["motocross", "enduro"],
            details="trail riding and weekend racing",
            selected_account_ids=[acct],
        )
        saved = upsert_topic(conn, cfg)
        assert saved.id > 0
        assert self._topic_count(conn) == 1

    def test_raising_scrubber_fails_closed(self):
        """A scrubber that RAISES blocks the save (fail-closed on error, not
        only on trip). We force the real gate's detector
        (``_layer2_scan_string``) to raise — a clean Topic that would
        otherwise persist must still be blocked with ``raised=True``."""
        from email_triage.actions import topic_configs as tc
        from email_triage.actions.topic_configs import TopicScrubBlocked

        conn = _make_db_full()
        uid = _seed_user(conn)
        acct = _seed_account(conn, user_id=uid)
        # A Topic with zero PHI — would persist under the real detector.
        cfg = TopicConfig(
            user_id=uid, name="dirt bikes", subjects=["enduro"],
            details="weekend racing", selected_account_ids=[acct],
        )

        import email_triage.style_learning.phi_scrubber as phi_mod
        orig = phi_mod._layer2_scan_string

        def _boom(_text):
            raise ValueError("synthetic scrubber failure")

        phi_mod._layer2_scan_string = _boom
        try:
            with pytest.raises(TopicScrubBlocked) as ei:
                upsert_topic(conn, cfg)
        finally:
            phi_mod._layer2_scan_string = orig

        assert ei.value.raised is True, (
            "a scrubber that RAISES must take the fail-closed-on-error path "
            "(raised=True), distinct from a genuine PHI trip"
        )
        # Nothing persisted — a broken scrubber is treated as "PHI may be present".
        assert self._topic_count(conn) == 0

    def test_scrub_topic_free_text_clean_returns_none(self):
        """The gate primitive returns ``None`` on a clean scan (so the save
        proceeds) — pins the clean path so a future tightening that raises on
        clean text is caught."""
        from email_triage.actions.topic_configs import scrub_topic_free_text

        assert scrub_topic_free_text("goats", "alpacas", "pasture rotation") is None

    def test_detector_catalogue_is_exhaustive(self):
        """Belt-and-braces: every catalogue entry actually trips the real
        gate detector. A pattern silently dropped from ``PHI_REGEX_PATTERNS``
        would make a 'blocks save' test pass for the wrong reason (the gate
        never tripped). This pins the detector."""
        missed = [
            label for label, phi in _SYNTHETIC_PHI_CATALOGUE.items()
            if not _detect_topic_phi(phi)
        ]
        assert not missed, (
            "The real HIPAA-18 detector missed catalogue shapes "
            f"{missed}; a 'blocks save' test could pass for the wrong "
            "reason. Restore the pattern in phi_scrubber.PHI_REGEX_PATTERNS."
        )


# ===========================================================================
# (a2) TOPIC-SCRUBBER PRECISION/RECALL PIN — the  Stage-5 scoping ruling
# ===========================================================================
#
# The  Stage-5 hipaa-sme scrubber-scoping ruling narrowed the Topic-surface
# PHI gate (``topic_configs._scan_topic_phi`` + ``_TOPIC_SCRUB_EXCLUDED_LABELS``)
# WITHOUT touching the shared ``phi_scrubber.PHI_REGEX_PATTERNS`` (those keep
# the strict versions for the describe-and-discard distill gate). Three
# adjustments, Topic-surface ONLY:
#
#   1. exclude ``year_four_digit`` (bare year is not a §164.514(b)(2) id — the
#      YEAR element of a date is Safe-Harbor-retained; a real DOB rides
#      date_slash_dash / date_month_day, which STAY), and
#   2. exclude ``zip_code`` (a bare 5-digit run is too ambiguous on study text;
#      a genuine street_address STAYS), and
#   3. REFINE ``alphanumeric_id`` (don't exclude it — re-test the fired span
#      against a stricter 4+ contiguous-digit-run pattern; block only on a
#      match, so genuine license/account/device IDs stay blocked while
#      study shorthand like covid19/iPhone15/Phase3 passes).
#
# This class is the precision/recall PROOF: realistic study shorthand must PASS
# (no PHI fired) and genuine identifiers must still BLOCK. It drives the REAL
# production primitive ``scrub_topic_free_text`` (which raises
# ``TopicScrubBlocked`` on a trip and returns None when clean) — no test-side
# re-implementation.
# ===========================================================================

#: Realistic operator-typed Topic shorthand that MUST pass the narrowed gate.
#: After the ruling none of these is a §164.514(b)(2) identifier on study
#: text: bare years (year_four_digit excluded), a bare 5-digit run (zip_code
#: excluded), and letter+digit tokens with NO 4-digit run (alphanumeric_id
#: refined). ``medical_term`` / ``name_two_caps`` were already excluded.
_TOPIC_SCRUB_MUST_PASS: tuple[str, ...] = (
    "covid19",
    "iPhone15",
    "study 2024 cohort",     # bare year — year_four_digit excluded
    "Topic 90210 arm",       # bare 5-digit — zip_code excluded
    "aspirin81",
    "omega3",
    "Phase3",
    "keyword0",              # the realistic test-discriminator shape
    "acronym1",
    "condition2",
)

#: Genuine HIPAA identifiers that MUST still block on the Topic surface. The
#: first three rely on the alphanumeric_id 4-digit-run refinement (license /
#: account / device ids); 99204812 falls to the always-on mrn_or_id_long_digits
#: \d{6,} rule; the rest are unambiguous identifier shapes that the ruling left
#: fully fail-closed.
_TOPIC_SCRUB_MUST_BLOCK: tuple[str, ...] = (
    "A1234567B",             # license/account id — 4+ digit run
    "XJ4521098",             # device/serial id — 4+ digit run
    "99204812",              # pure 8-digit run — mrn_or_id_long_digits
    "MRN 1234567",           # explicit MRN long-digit run
    "DOB 04/12/1965",        # date_slash_dash STAYS fail-closed
    "123-45-6789",           # SSN
    "555-123-4567",          # US phone
    "nurse@clinic.example",  # email
)


class TestTopicScrubberPrecisionRecall:
    """The  Stage-5 scoping ruling's precision/recall pin: realistic study
    shorthand passes; genuine identifiers still block. Drives the REAL
    ``scrub_topic_free_text`` primitive end-to-end."""

    @pytest.mark.parametrize("text", _TOPIC_SCRUB_MUST_PASS)
    def test_realistic_shorthand_passes_clean(self, text):
        """Realistic operator shorthand must NOT trip the narrowed gate — a
        clean scan returns ``None`` (the save would proceed)."""
        from email_triage.actions.topic_configs import (
            TopicScrubBlocked,
            _scan_topic_phi,
            scrub_topic_free_text,
        )

        # No label fires Topic-locally...
        fired = _scan_topic_phi(text)
        assert fired == [], (
            f"{text!r} unexpectedly tripped the Topic gate (labels {fired}); "
            f"the  Stage-5 ruling requires realistic study shorthand to pass"
        )
        # ...and the full primitive returns None (clean path).
        try:
            assert scrub_topic_free_text(text) is None
        except TopicScrubBlocked as exc:  # pragma: no cover - failure detail
            pytest.fail(
                f"{text!r} was BLOCKED (labels {exc.labels}); it must pass the "
                f"narrowed Topic scrubber per the  Stage-5 ruling"
            )

    @pytest.mark.parametrize("text", _TOPIC_SCRUB_MUST_BLOCK)
    def test_genuine_identifiers_still_block(self, text):
        """Genuine HIPAA identifiers must STILL block — the ruling narrowed
        precision, it did NOT open a hole for real license/account/device ids,
        MRNs, DOBs, SSNs, phones, or emails."""
        from email_triage.actions.topic_configs import (
            TopicScrubBlocked,
            _scan_topic_phi,
            scrub_topic_free_text,
        )

        # At least one label fires Topic-locally...
        fired = _scan_topic_phi(text)
        assert fired, (
            f"{text!r} did NOT trip the Topic gate; the narrowed scrubber must "
            f"still block genuine HIPAA identifiers"
        )
        # ...and the full primitive fails closed (a genuine trip, not the
        # raised-on-error path).
        with pytest.raises(TopicScrubBlocked) as ei:
            scrub_topic_free_text(text)
        assert ei.value.raised is False, (
            f"{text!r} should block on a PHI trip, not the fail-on-error path"
        )
        assert ei.value.labels, "the block must carry the fired pattern label(s)"


# ===========================================================================
# (b) PRIVACY-INVARIANT — stored reason_terms = own public terms only
# ===========================================================================
#
# A persisted ``topic_hits`` row stores the matched Topic-TERMS (the user's
# OWN public Subject/Details terms the email hit) — NEVER an email-body quote
# and NEVER generative prose. We drive a synthetic match end-to-end through
# the matcher into a persisted hit, then assert the stored
# ``reason_terms_json`` is a subset of the operator's own public config terms
# and that NO body text leaked into the row.
# ===========================================================================


class _StubVerdict:
    """A classify-layer-shaped TopicVerdict the mock classifier returns.

    ``reason_terms`` is what the classifier reports matched. The CONTRACT
    (design §0 / R6, ``classify/prompts.py``) is that these MUST be drawn
    from the Topic's OWN listed terms — the prompt instructs it and the
    persist layer stores exactly what it gets. A correct classifier never
    echoes a body quote here; this test proves the *stored* row carries only
    the operator's public terms by feeding the contract-correct shape and
    asserting no body text survives into the DB.
    """

    def __init__(self, topic_id, reason_terms, confidence=0.9):
        self.topic_id = topic_id
        self.matched = True
        self.reason_terms = tuple(reason_terms)
        self.confidence = confidence


class _MockClassifier:
    """Minimal classifier exposing the matcher's async seam.

    Returns a fixed verdict carrying ONLY the operator's public terms — it
    deliberately does NOT read the message body (proving the persisted row
    can carry only public config text)."""

    categories: dict = {}

    def __init__(self, verdict):
        self._verdict = verdict
        self.seen_messages: list = []

    async def classify_with_topics_safe(
        self, message, categories, list_hints, *, topic_block, model=None,
    ):
        self.seen_messages.append(message)
        return type("R", (), {"topic_verdicts": [self._verdict]})()


class _Msg:
    """An EmailMessage-shaped object with a SECRET body marker — if any byte
    of the body reaches the stored hit row, the privacy invariant is broken."""

    BODY_SECRET = "PATIENT_BODY_SECRET_should_never_persist_8675309"

    def __init__(self, rfc_id="<m1@example.com>"):
        self.headers = {
            "Message-ID": rfc_id,
            "From": "alerts@farm.example",
            "Subject": "Weekly goats and alpacas update",
        }
        self.message_id = rfc_id
        self.body_text = f"Body about goats. {self.BODY_SECRET}. Regards."
        self.folder = "INBOX"
        self.provider_uid = "42"
        self.uidvalidity = 7


@pytest.mark.asyncio
class TestPrivacyInvariantReasonTerms:
    """Stored ``reason_terms_json`` carries only the user's own public
    Topic-terms; no email body ever leaks into the row."""

    async def test_persisted_reason_terms_are_own_public_terms_only(self):
        from email_triage.actions.topic_matcher import match_topics_for_message

        conn = _make_db_full()
        uid = _seed_user(conn)
        acct = _seed_account(conn, user_id=uid)
        # Single-word Topic name + lower-case subjects so the Detail passes
        # the matcher's egress PHI scrub (the broad two-caps name heuristic
        # would otherwise drop a "Farm Animals"-style Detail before the seam
        # is even reached — that gate is covered by the topic_matcher tests).
        topic = _seed_topic(
            conn, user_id=uid, account_id=acct,
            name="livestock", subjects=["goats", "alpacas"],
            details="goats alpacas pasture rotation",
        )

        # The operator's OWN public vocabulary — the only thing allowed in
        # the stored reason_terms.
        own_terms = {"goats", "alpacas", "pasture", "rotation"}
        verdict = _StubVerdict(topic.id, reason_terms=["goats", "alpacas"])
        classifier = _MockClassifier(verdict)
        msg = _Msg()

        verdicts = await match_topics_for_message(msg, [topic], classifier)
        assert verdicts, "the mock classifier should yield a matched verdict"

        # Persist the hit exactly as the back-scan / live path does.
        reason_terms = list(verdicts[0].reason_terms)
        insert_topic_hit(
            conn,
            topic_id=topic.id,
            account_id=acct,
            rfc822_message_id=msg.message_id,
            folder=msg.folder,
            provider_uid=msg.provider_uid,
            uidvalidity=msg.uidvalidity,
            reason_terms=reason_terms,
            confidence=verdicts[0].confidence,
            source="live",
        )

        row = conn.execute(
            "SELECT reason_terms_json FROM topic_hits WHERE topic_id = ?",
            (topic.id,),
        ).fetchone()
        stored = json.loads(row["reason_terms_json"])

        # 1) Every stored term is one of the operator's own public terms.
        assert set(stored), "expected stored reason terms"
        assert set(stored) <= own_terms, (
            f"stored reason_terms {stored} must be a subset of the "
            f"operator's own public Topic terms {sorted(own_terms)}"
        )
        # 2) The email body secret never reached the stored row.
        blob = json.dumps(stored)
        assert _Msg.BODY_SECRET not in blob, (
            "email-body text leaked into the persisted reason_terms_json"
        )
        # 3) No raw header text (sender/subject) leaked either — only terms.
        assert "alerts@farm.example" not in blob
        assert "Weekly goats and alpacas update" not in blob

    async def test_no_message_body_column_exists_on_topic_hits(self):
        """Structural pin: ``topic_hits`` has NO column that could hold a
        body/subject/sender quote — message IDENTITY + own-terms only.
        A future migration adding a 'snippet'/'body'/'subject' column would
        fail this test (design §2: 'No mail bodies are stored')."""
        conn = _make_db_full()
        cols = {
            r[1].lower()
            for r in conn.execute("PRAGMA table_info('topic_hits')").fetchall()
        }
        forbidden = {
            "body", "body_text", "snippet", "subject", "sender", "from_addr",
            "preview", "raw", "content", "headers", "summary",
        }
        leak = forbidden & cols
        assert leak == set(), (
            f"topic_hits gained body/quote-shaped column(s) {leak}; the "
            f"hit row must store message IDENTITY + own public terms only"
        )


# ===========================================================================
# (c) C-V3.2 — no FK from the audit/HMAC chain to topics/topic_hits
# ===========================================================================
#
# A delete of a Topic (or a topic_hit) must NEVER be able to cascade into the
# tamper-evident audit chain. We prove it structurally: introspect the live
# v40 schema and assert the FK graph has no edge connecting the topic tables
# to the audit/log_entries chain in EITHER direction.
# ===========================================================================

_AUDIT_CHAIN_TABLES = frozenset({
    "log_entries",        # the HMAC hash-chain itself
    "hipaa_access_events",
    "auth_events",
    "audit_gap_events",
    "discover_runs",
})

_TOPIC_TABLES = frozenset({
    "topics",
    "topic_hits",
    "study_match_cache",
    "study_digest_state",
})


def _fk_parents(conn: sqlite3.Connection, table: str) -> set[str]:
    """The set of parent tables ``table`` has a FOREIGN KEY into."""
    return {
        row[2]  # PRAGMA foreign_key_list: col 2 = referenced ("table")
        for row in conn.execute(
            f"PRAGMA foreign_key_list('{table}')"
        ).fetchall()
    }


class TestCV32NoAuditCascadeFromTopics:
    """No FK edge connects the topic tables and the audit/HMAC chain."""

    def test_audit_chain_has_no_fk_into_topic_tables(self):
        """No audit-chain table references a topic table — so a topic delete
        cannot cascade INTO the audit chain via a child FK."""
        conn = _make_db_full()
        present = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        offenders: dict[str, set[str]] = {}
        for t in sorted(_AUDIT_CHAIN_TABLES & present):
            parents = _fk_parents(conn, t)
            reaches = parents & _TOPIC_TABLES
            if reaches:
                offenders[t] = reaches
        assert not offenders, (
            f"audit-chain table(s) gained a FK into topic tables {offenders}; "
            f"a topics/topic_hits delete could now cascade-reach the audit "
            f"chain (C-V3.2 violation)"
        )

    def test_topic_tables_do_not_reference_audit_chain(self):
        """No topic table references an audit-chain table — belt-and-braces
        on the other direction (the topic FKs go to users/accounts/topics
        only)."""
        conn = _make_db_full()
        offenders: dict[str, set[str]] = {}
        for t in sorted(_TOPIC_TABLES):
            parents = _fk_parents(conn, t)
            reaches = parents & _AUDIT_CHAIN_TABLES
            if reaches:
                offenders[t] = reaches
        assert not offenders, (
            f"topic table(s) gained a FK into the audit chain {offenders}"
        )

    def test_topic_fks_are_only_users_accounts_topics(self):
        """Pin the exact FK parents of each topic table — the only legitimate
        cascade roots are users / email_accounts / topics. Anything else (esp.
        an audit table) fails here first."""
        conn = _make_db_full()
        allowed = {"users", "email_accounts", "topics"}
        for t in sorted(_TOPIC_TABLES):
            parents = _fk_parents(conn, t)
            assert parents <= allowed, (
                f"{t} references unexpected parent(s) {parents - allowed}; "
                f"only {sorted(allowed)} are legitimate topic-FK roots"
            )

    def test_log_entries_has_zero_foreign_keys(self):
        """The HMAC chain table itself carries NO foreign keys at all — it is
        an append-only ledger, structurally unreachable by any cascade."""
        conn = _make_db_full()
        assert _fk_parents(conn, "log_entries") == set(), (
            "log_entries gained a foreign key; the HMAC ledger must stay "
            "FK-free so no cascade can ever touch it"
        )

    def test_deleting_a_topic_does_not_touch_audit_rows(self):
        """Behavioural proof: with FKs enforced, deleting a Topic that has a
        hit + an unrelated audit row leaves the audit rows intact."""
        conn = _make_db_full()
        conn.execute("PRAGMA foreign_keys = ON")
        uid = _seed_user(conn)
        acct = _seed_account(conn, user_id=uid, hipaa=True)
        topic = _seed_topic(conn, user_id=uid, account_id=acct)
        insert_topic_hit(
            conn, topic_id=topic.id, account_id=acct,
            rfc822_message_id="<x@example.com>", reason_terms=["goats"],
        )
        # An audit row referencing the SAME account (the realistic overlap).
        from email_triage.db.audit import record_hipaa_access_event
        record_hipaa_access_event(conn, uid, acct, "preview")
        audit_before = conn.execute(
            "SELECT COUNT(*) FROM hipaa_access_events"
        ).fetchone()[0]

        # Hard-delete the topic — its hit cascades away (topic_hits child),
        # the audit row must NOT.
        conn.execute("DELETE FROM topics WHERE id = ?", (topic.id,))
        conn.commit()

        hits_after = conn.execute(
            "SELECT COUNT(*) FROM topic_hits WHERE topic_id = ?", (topic.id,)
        ).fetchone()[0]
        audit_after = conn.execute(
            "SELECT COUNT(*) FROM hipaa_access_events"
        ).fetchone()[0]
        assert hits_after == 0, "the topic_hit should cascade-delete with its topic"
        assert audit_after == audit_before, (
            "deleting a topic must NOT remove any audit-chain row"
        )


# ===========================================================================
# (d) ACTOR≠OWNER — non-owner preview of a HIPAA-account hit audits
# ===========================================================================
#
# The Topic preview surfaces a HIPAA-flagged account's matched mail metadata.
# Per ``feedback_hipaa_actor_owner_gate.md`` / §164.502(a): when the actor is
# NOT the account owner, a ``hipaa_access_events`` row must fire; owner
# self-access is a self-disclosure carve-out and is NOT recorded.
#
# This is the canonical actor≠owner gate (``audit_phi_access``
# in ``web/routers/ui/_shared.py``) — the same SSOT the Topic preview path
# must use. We exercise it directly with a topic-preview operation name and
# assert both directions over the real ``hipaa_access_events`` table.
# ===========================================================================


class TestActorOwnerGate:
    """Non-owner preview of a HIPAA account audits; owner self-access does not."""

    def _account_dict(self, conn, account_id) -> dict:
        row = conn.execute(
            "SELECT id, user_id, hipaa FROM email_accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "hipaa": bool(row["hipaa"]),
        }

    def _events(self, conn) -> list[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM hipaa_access_events ORDER BY id"
        ).fetchall()

    def test_non_owner_preview_of_hipaa_account_fires_event(self):
        from email_triage.web.routers.ui._shared import (
            audit_phi_access,
        )

        conn = _make_db_full()
        owner = _seed_user(conn, email="owner@example.com")
        actor = _seed_user(conn, email="manager@example.com")  # a DIFFERENT user
        acct = _seed_account(conn, user_id=owner, hipaa=True)
        account = self._account_dict(conn, acct)

        assert self._events(conn) == []
        audit_phi_access(
            conn, actor_user_id=actor, account=account,
            operation="topic_preview",
        )
        events = self._events(conn)
        assert len(events) == 1, "a non-owner HIPAA preview must audit"
        ev = events[0]
        assert ev["actor_user_id"] == actor
        assert ev["account_id"] == acct
        assert ev["operation"] == "topic_preview"

    def test_owner_self_access_does_not_fire_event(self):
        """Owner previewing their OWN HIPAA account → §164.502(a) carve-out,
        NO hipaa_access_events row."""
        from email_triage.web.routers.ui._shared import (
            audit_phi_access,
        )

        conn = _make_db_full()
        owner = _seed_user(conn, email="owner@example.com")
        acct = _seed_account(conn, user_id=owner, hipaa=True)
        account = self._account_dict(conn, acct)

        audit_phi_access(
            conn, actor_user_id=owner, account=account,
            operation="topic_preview",
        )
        assert self._events(conn) == [], (
            "owner self-access on a HIPAA account must NOT write a "
            "hipaa_access_events row (self-disclosure carve-out)"
        )

    def test_non_owner_preview_of_non_hipaa_account_does_not_fire(self):
        """The gate is HIPAA-scoped: a non-owner preview of a NON-HIPAA
        account writes no hipaa_access_events row (that table is HIPAA-only;
        the auth_events lens covers non-HIPAA cross-user actions)."""
        from email_triage.web.routers.ui._shared import (
            audit_phi_access,
        )

        conn = _make_db_full()
        owner = _seed_user(conn, email="owner@example.com")
        actor = _seed_user(conn, email="manager@example.com")
        acct = _seed_account(conn, user_id=owner, hipaa=False)  # NOT hipaa
        account = self._account_dict(conn, acct)

        audit_phi_access(
            conn, actor_user_id=actor, account=account,
            operation="topic_preview",
        )
        assert self._events(conn) == []
