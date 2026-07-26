""" Phase 4d-iii — the per-recipient "Regulatory deadlines" digest section.

Covers the ACCOUNT-scoped reader (no cross-account leak into a per-account
digest), the SSOT deadline wording shared with the escalation email, and the
rendered HTML/plain section builders. HIPAA-minimal: no case_ref /
raw_deadline_phrase reaches the digest.
"""
from __future__ import annotations

from email_triage.db.regulatory_clock import (
    clock_deadline_phrase,
    create_clock_candidate,
    list_compliance_clocks_for_account,
)
from email_triage.web.db import create_email_account
from email_triage.web.digest import (
    _build_compliance_clocks_section_html,
    _build_compliance_clocks_section_plain,
)


def _seed_clock(db, user_id, *, name="Lupus study mailbox", deadline_at=None):
    aid = create_email_account(
        db, user_id=user_id, name=name,
        provider_type="imap", config={"account": "pi@site.example"},
        hipaa=True,
    )
    did = db.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS'"
    ).fetchone()[0]
    iid = create_clock_candidate(
        db, def_id=did, account_id=aid, case_ref="SECRET-CASE-REF-001",
        responsibility="i_submit",
    )
    if deadline_at is not None:
        db.execute(
            "UPDATE regulatory_clock_instance SET deadline_at=? WHERE id=?",
            (deadline_at, iid),
        )
    return aid, iid


def test_reader_is_account_scoped(db, regular_user):
    # two OWNED accounts; the reader scoped to account A must NOT surface
    # account B's clock — a per-account digest must not leak other accounts'
    # deadlines (the cross-account over-share the user-scoped reader would cause)
    aid_a, _ = _seed_clock(db, regular_user["id"], name="Account A")
    _seed_clock(db, regular_user["id"], name="Account B")
    a_clocks = list_compliance_clocks_for_account(
        db, account_id=aid_a, account_name="Account A",
    )
    assert len(a_clocks) == 1
    assert all(c["account_name"] == "Account A" for c in a_clocks)


def test_reader_is_hipaa_minimal(db, regular_user):
    aid, _ = _seed_clock(db, regular_user["id"])
    clocks = list_compliance_clocks_for_account(db, account_id=aid)
    assert len(clocks) == 1
    c = clocks[0]
    assert "case_ref" not in c
    assert "raw_deadline_phrase" not in c
    assert "SECRET-CASE-REF-001" not in str(c)
    assert c["account_name"] == "(unnamed account)"  # name not passed → safe default


def test_deadline_phrase_due_overdue_none():
    # the SSOT wording shared by the escalation email + the digest section
    assert clock_deadline_phrase(3) == "due in 3 day(s)"
    assert clock_deadline_phrase(0) == "due in 0 day(s)"
    assert clock_deadline_phrase(-1) == "OVERDUE by 1 day(s)"
    assert clock_deadline_phrase(-2) == "OVERDUE by 2 day(s)"
    assert clock_deadline_phrase(None) == "deadline not set"


def test_section_html_phi_free_and_advisory():
    clocks = [
        {"label": "IRB report", "days_left": 2, "account_name": "A"},
        {"label": "FDA 15-day", "days_left": -1, "account_name": "A"},
    ]
    html = _build_compliance_clocks_section_html(clocks)
    assert "Regulatory deadlines" in html
    assert "IRB report" in html and "due in 2 day(s)" in html
    assert "OVERDUE by 1 day(s)" in html
    assert "verify against your SOP" in html          # advisory copy
    assert "#b00020" in html                            # overdue alert color


def test_section_empty_is_empty_string():
    assert _build_compliance_clocks_section_html([]) == ""
    assert _build_compliance_clocks_section_plain([]) == ""


def test_section_html_escapes_label():
    html = _build_compliance_clocks_section_html(
        [{"label": "<script>x</script>", "days_left": 1}]
    )
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_section_plain_lists_each_clock():
    plain = _build_compliance_clocks_section_plain([
        {"label": "IRB report", "days_left": 2},
        {"label": "FDA 15-day", "days_left": None},
    ])
    assert "Regulatory deadlines" in plain
    assert "IRB report: due in 2 day(s)" in plain
    assert "FDA 15-day: deadline not set" in plain


def _digest_row(subject="s"):
    return {
        "category": "newsletter", "sender": "x@y", "subject": subject,
        "date": "2026-05-05T08:00:00+00:00", "labels": [], "actions": [],
        "attachments": [], "headers": {}, "source": "llm", "reason": "r",
    }


async def test_digest_render_injects_section_execution_path():
    """EXECUTION coverage of the PROD injection in ``_render_digest_payload``
    (not just the builders). The section is fail-OPEN, so a path that NEVER
    renders would pass silently — the incident_2026-06-11 'dead in prod' shape.
    This drives the real fetch→build→inject block and asserts the section lands
    in BOTH bodies. The reader is mocked (its account-scoping is covered by
    test_reader_is_account_scoped); the boundary under test is the injection.
    asyncio_mode=auto collects this bare ``async def`` without a marker."""
    from datetime import datetime, timezone
    from unittest.mock import patch

    from email_triage.actions.digest_configs import DigestConfig, DigestFormat
    from email_triage.web.app import _render_digest_payload

    acct = {
        "id": 7, "name": "Lupus mailbox", "email_address": "u@test",
        "user_id": 1, "is_active": True, "hipaa": True,
        "provider_type": "imap", "config": {},
    }
    dcfg = DigestConfig(
        id="d1", kind="custom", name="x", enabled=True,
        format=DigestFormat(render_as="grouped_list"),
    )
    fake_clocks = [
        {"label": "IRB report", "days_left": 2, "account_name": "Lupus mailbox"},
    ]

    def _fake_reader(*_a, **_k):
        return fake_clocks

    with patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=[_digest_row("A"), _digest_row("B")],
    ), patch(
        "email_triage.db.regulatory_clock.list_compliance_clocks_for_account",
        _fake_reader,
    ):
        _subj, html_body, plain_body, _rows, _total = (
            await _render_digest_payload(
                db=object(),
                secrets=type("S", (), {"get": lambda *a, **k: ""})(),
                acct=acct, dcfg=dcfg, hipaa=True,
                now_utc=datetime.now(timezone.utc), last_sent=None,
            )
        )
    assert "Regulatory deadlines" in html_body
    assert "IRB report" in html_body and "due in 2 day(s)" in html_body
    assert "Regulatory deadlines" in plain_body
    assert "IRB report: due in 2 day(s)" in plain_body


def test_deadline_wording_literals_are_ssot_only():
    """PD#1 structural pin for the clock_deadline_phrase SSOT (shipped in the
    SAME change as the SSOT): the FORMATTED deadline-wording code literals
    (``due in {`` / ``OVERDUE by {``) live ONLY inside that one funnel. A future
    caller that hand-rolls the wording instead of routing through
    clock_deadline_phrase trips this. Count-agnostic (walk every src module +
    AST-scope the allowed site), NOT a len()==N check. Routes through the shared
    ``_pin_harness`` source walk (R5b) — never a hand-rolled rglob."""
    import ast

    from _pin_harness import walk_src

    needles = ("due in {", "OVERDUE by {")
    offenders = []
    for path, rel, tree in walk_src():
        text = path.read_text(encoding="utf-8")
        if not any(n in text for n in needles):
            continue
        # Allowed ONLY inside clock_deadline_phrase: blank that function's source
        # span, then any surviving needle is a hand-rolled drift copy.
        spans = [
            (node.lineno, node.end_lineno)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "clock_deadline_phrase"
        ]
        residue = "\n".join(
            ln for i, ln in enumerate(text.splitlines(), start=1)
            if not any(a <= i <= b for (a, b) in spans)
        )
        offenders += [
            f"{rel}: hand-rolled '{n}'"
            for n in needles if n in residue
        ]
    assert not offenders, (
        "deadline-wording literal hand-rolled outside the clock_deadline_phrase "
        "SSOT (route it through clock_deadline_phrase): " + "; ".join(offenders)
    )
