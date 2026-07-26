"""N-175 — COMPLETE the digest-preview redact_pii render-net.

Sibling of N-174 (which fixed ONLY the preset branch:
``recipient_digest.render_html`` / ``render_plain``). The digest_preview
seam (``OwnedAccount`` → ``can_manage_account`` = reachable by a managing
NON-OWNER) flows through ``web.digest._render_digest_payload``, which
dispatches to THREE render branches — preset, custom (``render_digest`` →
table / grouped_list / plain_list), and newsletter
(``render_newsletter_async`` → ``generate_digest`` → ``build_digest_html``).
N-174 left the custom + newsletter branches rendering ``sender`` /
``subject`` VERBATIM under ``hipaa`` — a §164.502(b) min-necessary /
§164.514(d)(1) display-min leak of the SAME class, reachable by the SAME
preview seam.

This module pins the COMPLETED net:

  1. ``test_net_complete_*`` — the count-agnostic, interprocedural
     net-completeness pin (PD#1/#2/#4). It AST-walks
     ``_render_digest_payload`` and asserts that EVERY source-render call
     (one that BUILDS ``html_body`` / ``plain_body`` rather than
     transforms an already-rendered body) threads ``redact_pii``. A
     future 4th preview-reachable render branch that forgets the flag →
     RED. Transforms (``html_to_text`` / ``_inject_before_body_close``,
     which take an already-rendered body as an argument) are correctly
     excluded — they cannot leak what the source render already redacted.

  2. ``test_renderer_accepts_redact_pii`` — every renderer in the net
     carries the ``redact_pii`` parameter (signature pin).

  3. Rendered-view tests per branch — custom table / grouped_list /
     plain_list (incl. the group-by-sender heading, which IS the verbatim
     sender) AND newsletter — assert ``redact_pii=True`` drops sender +
     subject and ``redact_pii=False`` (the DELIVERED path) keeps them
     verbatim, byte-unchanged.

Teeth: the AST net pin flags any source-render assignment to html_body /
plain_body lacking ``redact_pii=`` — a planted branch that ignores the
flag goes RED. The per-branch view tests RED against HEAD~1 (custom +
newsletter renderers had no ``redact_pii`` parameter and emitted sender +
subject verbatim).

CRITICAL CONSTRAINT (shared with N-174): the DELIVERED digest
(``_fire_one_digest`` / ``topic_digest_sender`` → ``render_digest`` /
``render_newsletter_async`` with ``redact_pii`` omitted) is BYTE-UNCHANGED
— the recipient is the account's own authorized mailbox.
"""

from __future__ import annotations

import ast
import inspect
import textwrap

import pytest

from email_triage.actions import digest as digest_mod
from email_triage.actions import digest_render as dr
from email_triage.actions import recipient_digest as rd
from email_triage.actions.digest import Article, SenderGroup, build_digest_html
from email_triage.actions.digest_configs import (
    DigestColumn, DigestConfig, DigestFormat,
)
from email_triage.web import digest as web_digest

# Shared PHI sentinels — match the N-174 pin's sender/subject surface.
_SENDER = "alice@clinic.example.com"
_SUBJECT = "Lab results: glucose panel"
_REASON = "Patient confirmed Tuesday appointment"  # hipaa-gated, separate
# The link column is a body-extracted URL — for a HIPAA medical email it can
# be a patient-portal link (PHI). The production-default custom-table column
# set is [datetime, sender, headline, link], so the table preview renders it.
# (DA catch: the original fixture EXCLUDED the link column → the leak slipped.)
_PHI_URL = "https://portal.example.com/patient/abc123"


def _row(*, sender=_SENDER, subject=_SUBJECT, category="newsletter"):
    return {
        "message_id": "m1",
        "sender": sender,
        "subject": subject,
        "category": category,
        "reason": _REASON,
        "source": "llm",
        "status": "ok",
        "date": "2026-05-02T08:14:00+00:00",
        "body_text": "body sentinel",
        "links": [_PHI_URL],
        "headers": {},
    }


def _cfg(render_as: str, *, group_by: str = "category", columns=None):
    fmt = DigestFormat(
        render_as=render_as, group_by=group_by,
        include_body_preview=True, max_rows=50,
    )
    if columns is not None:
        fmt.columns = columns
    return DigestConfig(kind="custom", name="Clinic Digest", format=fmt)


def _sender_subject_columns():
    # FULL production-shaped palette: the default [datetime, sender, headline,
    # link] PLUS subject + category + reason, so EVERY matched-message PHI
    # column key the table can render (sender / headline / subject / link) is
    # exercised by the pin — the DA-caught link column included. Non-PHI keys
    # (datetime / category) ride along to prove they pass through untouched.
    return [
        DigestColumn(key="datetime", label="When"),
        DigestColumn(key="sender", label="Sender"),
        DigestColumn(key="headline", label="Headline"),
        DigestColumn(key="subject", label="Subject"),
        DigestColumn(key="link", label="Link"),
        DigestColumn(key="category", label="Category"),
        DigestColumn(key="reason", label="Why"),
    ]


# ---------------------------------------------------------------------------
# 1. Net-completeness — count-agnostic AST pin over _render_digest_payload
# ---------------------------------------------------------------------------


_BODY_TARGETS = {"html_body", "plain_body"}


def _source_render_calls() -> list[ast.Call]:
    """Every Call that BUILDS html_body/plain_body in
    ``_render_digest_payload`` (a SOURCE render), excluding calls that
    merely TRANSFORM an already-rendered body (html_to_text /
    _inject_before_body_close — identified structurally by their taking
    html_body/plain_body as an argument)."""
    src = textwrap.dedent(inspect.getsource(web_digest._render_digest_payload))
    tree = ast.parse(src)
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
        if not (targets & _BODY_TARGETS):
            continue
        value = node.value
        if isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call):
            continue
        # Names referenced as positional or keyword args.
        arg_names: set[str] = set()
        for a in value.args:
            if isinstance(a, ast.Name):
                arg_names.add(a.id)
        for kw in value.keywords:
            if isinstance(kw.value, ast.Name):
                arg_names.add(kw.value.id)
        # A render that consumes an already-built body is a transform,
        # not a source render — it cannot leak what was already redacted.
        if arg_names & _BODY_TARGETS:
            continue
        calls.append(value)
    return calls


def _call_name(call: ast.Call) -> str:
    return getattr(call.func, "id", None) or getattr(call.func, "attr", "?")


def test_net_complete_every_source_render_threads_redact_pii():
    """PD#4 net-completeness: every preview-reachable SOURCE render in
    ``_render_digest_payload`` threads ``redact_pii``. Count-agnostic —
    a future 4th branch that forgets it goes RED."""
    calls = _source_render_calls()
    # Non-vacuous guard: the dispatch has preset html + preset plain +
    # newsletter html + custom html = 4 source renders (the newsletter /
    # custom plain bodies are derived via html_to_text and excluded).
    assert len(calls) >= 3, (
        f"AST net saw too few source renders ({len(calls)}) — the scanner "
        f"is blind; refusing to pass vacuously"
    )
    for call in calls:
        kwargs = {kw.arg for kw in call.keywords}
        assert "redact_pii" in kwargs, (
            f"_render_digest_payload source-render branch "
            f"{_call_name(call)}(...) does NOT thread redact_pii — a "
            f"preview-reachable verbatim sender/subject leak (N-175)"
        )


def test_net_includes_all_three_dispatch_branches():
    """Sanity/teeth: the AST classifier sees each of the three dispatch
    branches by name, so a refactor that drops one is visible."""
    names = {_call_name(c) for c in _source_render_calls()}
    assert "render_newsletter_async" in names, names
    assert "render_digest" in names, names
    # The preset render is imported under render_preset_html/_plain aliases.
    assert any("preset" in n for n in names), names


# ---------------------------------------------------------------------------
# 2. Signature pin — every renderer in the net accepts redact_pii
# ---------------------------------------------------------------------------


_RENDERERS_WITH_REDACT = [
    rd.render_html,
    rd.render_plain,
    dr.render_digest,
    dr.render_table_generic,
    dr.render_grouped_list,
    dr.render_plain_list,
    dr.render_newsletter_async,
    digest_mod.generate_digest,
    digest_mod.build_digest_html,
]


@pytest.mark.parametrize(
    "fn", _RENDERERS_WITH_REDACT, ids=lambda f: f.__name__,
)
def test_renderer_accepts_redact_pii(fn):
    assert "redact_pii" in inspect.signature(fn).parameters, (
        f"{fn.__module__}.{fn.__name__} missing redact_pii — net incomplete"
    )


# ---------------------------------------------------------------------------
# 3a. Custom branch — table / grouped_list / plain_list rendered views
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("render_as", ["table", "grouped_list", "plain_list"])
def test_custom_preview_redacts_sender_subject(render_as):
    """redact_pii=True (the preview seam) → sender + subject gone from
    every custom render format."""
    columns = _sender_subject_columns() if render_as == "table" else None
    cfg = _cfg(render_as, columns=columns)
    out = dr.render_digest(
        cfg=cfg, rows=[_row()], account_name="Clinic",
        account_email="x@y.com", hipaa=True, redact_pii=True,
    )
    assert _SENDER not in out, f"{render_as}: sender leaked in preview"
    assert _SUBJECT not in out, f"{render_as}: subject leaked in preview"
    assert "[redacted]" in out
    if render_as == "table":
        # The full-palette table fixture renders the link column, whose
        # value is a PHI patient-portal URL (DA catch) — it must be gone.
        assert _PHI_URL not in out, "table: link (PHI URL) leaked in preview"


@pytest.mark.parametrize("render_as", ["table", "grouped_list", "plain_list"])
def test_custom_delivered_keeps_verbatim(render_as):
    """redact_pii=False (delivered, the default) → verbatim to the OWN
    mailbox; byte-unchanged from omitting the flag entirely."""
    columns = _sender_subject_columns() if render_as == "table" else None
    cfg = _cfg(render_as, columns=columns)
    kwargs = dict(
        cfg=cfg, rows=[_row()], account_name="Clinic",
        account_email="x@y.com", hipaa=True,
    )
    out = dr.render_digest(**kwargs, redact_pii=False)
    assert _SENDER in out, f"{render_as}: delivered must keep sender"
    assert _SUBJECT in out, f"{render_as}: delivered must keep subject"
    if render_as == "table":
        # Delivered table keeps the link cell verbatim (it goes to the
        # account's OWN mailbox) — proves redact is preview-only.
        assert _PHI_URL in out, "table: delivered must keep link verbatim"
    # Delivered byte-identical whether redact_pii is omitted or False.
    assert dr.render_digest(**kwargs) == out


def test_grouped_by_sender_heading_is_redacted():
    """When grouping BY sender the section heading IS the verbatim
    sender — the preview must redact the heading too, not just the row."""
    cfg = _cfg("grouped_list", group_by="sender")
    preview = dr.render_grouped_list(
        cfg=cfg, rows=[_row()], account_name="C",
        account_email="x@y.com", hipaa=True, redact_pii=True,
    )
    assert _SENDER not in preview
    delivered = dr.render_grouped_list(
        cfg=cfg, rows=[_row()], account_name="C",
        account_email="x@y.com", hipaa=True, redact_pii=False,
    )
    assert _SENDER in delivered  # heading carries it verbatim when delivered


def test_table_sort_order_preserved_under_redaction():
    """The sort pass keys on UNREDACTED values, so a redacted preview
    keeps the SAME row order as the delivered digest (only the displayed
    cell is redacted)."""
    cfg = _cfg(
        "table",
        columns=[
            DigestColumn(key="sender", label="Sender", sort_priority=1),
        ],
    )
    rows = [_row(sender="zeta@clinic.example.com"),
            _row(sender="alpha@clinic.example.com")]
    out = dr.render_digest(
        cfg=cfg, rows=rows, account_name="C", account_email="x@y.com",
        hipaa=True, redact_pii=True,
    )
    # Both senders redacted; the render must not crash and must redact all.
    assert "zeta@clinic.example.com" not in out
    assert "alpha@clinic.example.com" not in out
    assert out.count("[redacted]") >= 2


def test_table_link_column_redacts_url_on_default_columns():
    """DA catch — the PRODUCTION-DEFAULT custom-table column set
    ``[datetime, sender, headline, link]`` (used when an operator hasn't
    customised columns) renders the body-extracted ``link`` URL. For a
    HIPAA medical email that URL can be a patient-portal link (PHI), so
    the preview must redact it; the delivered table keeps it verbatim and
    as a real anchor."""
    from email_triage.actions.digest_configs import _default_columns

    cfg = _cfg("table", columns=_default_columns())
    common = dict(
        cfg=cfg, rows=[_row()], account_name="Clinic",
        account_email="x@y.com", hipaa=True,
    )

    # PREVIEW (managing non-owner) — URL gone, no anchor to it, sentinel shown.
    preview = dr.render_digest(**common, redact_pii=True)
    assert _PHI_URL not in preview, "link URL leaked in table preview"
    assert "portal.example.com" not in preview
    assert f'href="{_PHI_URL}"' not in preview  # not even an <a href> shell
    assert "[redacted]" in preview

    # DELIVERED — verbatim URL, rendered as a clickable anchor.
    delivered = dr.render_digest(**common, redact_pii=False)
    assert _PHI_URL in delivered, "delivered table must keep link verbatim"
    assert f'href="{_PHI_URL}"' in delivered
    # Byte-unchanged whether the flag is omitted or explicitly False.
    assert dr.render_digest(**common) == delivered


# ---------------------------------------------------------------------------
# 3c. Banner disambiguation — the custom banner must NOT claim "verbatim"
# in a redacted preview (DA follow-on; the preset banner was already
# context-aware via N-174, the custom one was not).
# ---------------------------------------------------------------------------


# The exact delivered-context banner string — frozen so a future edit that
# accidentally reshapes the DELIVERED wording (byte boundary to the
# authorized recipient) trips this pin.
_DELIVERED_BANNER = (
    '<p style="font-size:0.85em;color:#666;">'
    "HIPAA mode: classifier reasoning is redacted to a "
    "fixed phrase per classifier source; body previews are "
    "redacted. Subject + sender appear verbatim because they "
    "already live in this mailbox via the original messages."
    "</p>"
)


def test_custom_banner_delivered_byte_unchanged():
    """redact_pii=False (and omitted) → the pre-N-175 banner, byte-identical."""
    assert dr._hipaa_banner_html() == _DELIVERED_BANNER
    assert dr._hipaa_banner_html(False) == _DELIVERED_BANNER


def test_custom_banner_preview_drops_verbatim_claim():
    """redact_pii=True → the banner states sender+subject are REDACTED and
    does NOT carry the delivered-only "verbatim because" claim."""
    preview = dr._hipaa_banner_html(True)
    assert "redacted" in preview.lower()
    assert "preview" in preview.lower()
    # The misleading delivered-only phrase must be absent in the preview.
    assert "verbatim because they" not in preview
    assert "appear verbatim" not in preview


@pytest.mark.parametrize("render_as", ["table", "grouped_list", "plain_list"])
def test_custom_render_banner_matches_redaction_state(render_as):
    """End-to-end through the renderers: a redacted PREVIEW must not tell a
    managing non-owner the cells are verbatim; the DELIVERED render keeps
    the verbatim wording."""
    columns = _sender_subject_columns() if render_as == "table" else None
    cfg = _cfg(render_as, columns=columns)
    common = dict(
        cfg=cfg, rows=[_row()], account_name="Clinic",
        account_email="x@y.com", hipaa=True,
    )
    preview = dr.render_digest(**common, redact_pii=True)
    delivered = dr.render_digest(**common, redact_pii=False)

    # Preview: no verbatim claim; the redacted-preview banner present.
    assert "appear verbatim" not in preview, f"{render_as}: stale verbatim claim"
    assert "HIPAA mode (preview)" in preview
    # Delivered: the verbatim contract wording is present + byte-unchanged.
    assert "appear verbatim because they" in delivered
    assert dr.render_digest(**common) == delivered


# ---------------------------------------------------------------------------
# 3b. Newsletter branch — build_digest_html rendered view + no-mutation
# ---------------------------------------------------------------------------


def _newsletter_groups():
    """Groups carrying every per-message PHI surface the newsletter
    template renders: sender_name (=sender), headline (=subject under the
    HIPAA fail-closed path), summary (=body), url."""
    return {
        _SENDER.lower(): SenderGroup(
            sender_name="Alice Clinic",
            sender_email=_SENDER,
            articles=[Article(
                headline=_SUBJECT,
                summary="patient body content sentinel",
                url="https://portal.example.com/patient/abc123",
            )],
        )
    }


def test_newsletter_preview_redacts_all_phi_surfaces():
    out = build_digest_html(
        _newsletter_groups(), "Tuesday, May 12, 2026", redact_pii=True,
    )
    assert "Alice Clinic" not in out, "sender_name (sender) leaked"
    assert _SUBJECT not in out, "headline (subject) leaked"
    assert "patient body content sentinel" not in out, "summary (body) leaked"
    assert "portal.example.com" not in out, "article url leaked"
    assert "[redacted]" in out


def test_newsletter_delivered_keeps_verbatim():
    out = build_digest_html(
        _newsletter_groups(), "Tuesday, May 12, 2026", redact_pii=False,
    )
    assert "Alice Clinic" in out
    assert _SUBJECT in out


def test_newsletter_delivered_byte_identical_default_vs_false():
    groups = _newsletter_groups()
    assert (
        build_digest_html(groups, "today")
        == build_digest_html(groups, "today", redact_pii=False)
    )


def test_build_digest_html_does_not_mutate_caller_groups():
    """Redaction operates on COPIES — the caller's SenderGroup / Article
    objects (and any delivered-path re-render) must be untouched."""
    groups = _newsletter_groups()
    _ = build_digest_html(groups, "today", redact_pii=True)
    g = groups[_SENDER.lower()]
    assert g.sender_name == "Alice Clinic"
    assert g.articles[0].headline == _SUBJECT
    assert g.articles[0].summary == "patient body content sentinel"
    assert g.articles[0].url == "https://portal.example.com/patient/abc123"


@pytest.mark.asyncio
async def test_generate_digest_seam_redacts_local_classifier_body():
    """End-to-end newsletter seam: a LOCAL classifier (hipaa does NOT
    suppress its summary) still must not leak sender/subject/body into a
    preview when redact_pii=True; redact_pii=False keeps them verbatim."""
    import json
    from datetime import datetime, timezone
    from unittest.mock import AsyncMock
    from email_triage.engine.models import EmailMessage

    classifier = AsyncMock()
    classifier.is_local = True
    classifier.complete.return_value = json.dumps([
        {"headline": _SUBJECT, "summary": "patient body content sentinel",
         "url": None},
    ])
    msg = EmailMessage(
        message_id="100", provider="imap",
        sender=f"Alice Clinic <{_SENDER}>",
        recipients=["u@test.com"], subject=_SUBJECT,
        body_text="patient body content sentinel",
        date=datetime.now(timezone.utc), links=[],
    )
    provider = AsyncMock()

    preview_html, _a, _s = await digest_mod.generate_digest(
        provider, classifier, [msg], redact_pii=True,
    )
    assert _SENDER not in preview_html
    assert _SUBJECT not in preview_html
    assert "patient body content sentinel" not in preview_html
    assert "[redacted]" in preview_html

    delivered_html, _a2, _s2 = await digest_mod.generate_digest(
        provider, classifier, [msg], redact_pii=False,
    )
    assert _SUBJECT in delivered_html
