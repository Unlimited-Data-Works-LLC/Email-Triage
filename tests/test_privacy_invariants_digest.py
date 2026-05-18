"""Privacy invariants for digest body-preview HIPAA redaction (#167).

Filed against the 2026-05-14 weekly HIPAA / NERC-CIP audit
recommendation #4: "Verify digest ``include_body_preview``
respects HIPAA mode at runtime (template evidence at
``digest_render.py:88-105`` shows ``[redacted]`` return for HIPAA;
verify via test)." The audit's posture was that the code path
exists but no explicit runtime test was pinning it — a future
refactor that accidentally removes or weakens the gate would
ship green.

This module is the privacy-invariant pin. It belongs in
``tests/test_privacy_invariants_*.py`` so the cross-cutting batch
runner (and any future "run only privacy tests" sweep) finds it
alongside the sibling M-series, log-scrub, dep-review, and
no-customer-names invariant modules.

Surfaces pinned:

* ``actions.digest_render._cheap_preview`` — the lede + headings
  extractor; returns ``("[redacted]", [])`` for HIPAA.
* ``actions.digest_render._preview`` — the legacy 200-char body
  preview helper used by the table renderer's ``preview`` column.
* ``actions.digest_render.render_grouped_list`` — end-to-end
  default custom-digest render path.
* ``actions.digest_render.render_plain_list`` — the flat-list
  variant; previously NOT pinned (sibling
  ``tests/test_actions/test_digest_hipaa_body_preview.py`` covers
  grouped_list + table but not plain_list).
* ``actions.digest_render.render_table_generic`` — the operator-
  configurable table format's ``preview`` column.
* ``actions.digest_render.render_digest`` (dispatcher) — verifies
  the gate fires through the dispatcher for every supported
  ``render_as`` value AND for an unknown value (which the
  dispatcher falls back to grouped_list — that fallback path
  must STILL honour the HIPAA flag).
* **System-HIPAA mode** (``triage_logging._hipaa_mode = True``) —
  the install-wide flag must force redaction regardless of the
  per-account ``hipaa`` column. The ``_render_digest_payload``
  caller (web/app.py:3994) resolves
  ``hipaa = is_hipaa_mode() or bool(acct.get("hipaa", False))``;
  this module pins that the renderer honours both inputs.

Compliance angle (audit cross-ref): HIPAA §164.502(a)(1) — the
digest is an outbound disclosure of PHI to the operator's
mailbox. Body preview that bypasses HIPAA mode at any of the
above surfaces is a §164.502 issue even when recipient = data
subject (the digest travels via SMTP + sits at rest in the
recipient's mailbox; the gate is the only thing keeping body
fragments off the wire).

Companion modules:
  * tests/test_actions/test_digest_hipaa_body_preview.py — the
    feature-level coverage (newsletter async + provider-fetch
    stamp + extract_articles fallback). This module focuses on
    the SYNC sync-renderer + dispatcher + system-flag invariants;
    overlap with the feature module is intentional (defense in
    depth) — the two test files index different keywords for
    different audit / search workflows.
  * tests/test_privacy_invariants_m_series.py — the M-series
    style-learning invariants. Same shape (sentinel-string +
    raising fixture pattern).

See ``docs/privacy-audit-runbook.md`` for the full operator
contract.
"""

from __future__ import annotations

import pytest

from email_triage.actions.digest_configs import (
    DigestColumn, DigestConfig, DigestFormat,
)
from email_triage.actions.digest_render import (
    _cheap_preview,
    _preview,
    render_digest,
    render_grouped_list,
    render_plain_list,
    render_table_generic,
)


# ---------------------------------------------------------------------------
# Sentinel + fixture helpers
# ---------------------------------------------------------------------------


# Long enough to be visually distinct in failure messages, not
# token-shaped so it doesn't trip the static-grep guards in the
# log-scrub / no-customer-names sibling tests.
SENTINEL_BODY = "DIGEST_BODY_SENTINEL_77_must_never_appear"
SENTINEL_HEADING_1 = "DIGEST_HEADING_SENTINEL_A_must_never_appear"
SENTINEL_HEADING_2 = "DIGEST_HEADING_SENTINEL_B_must_never_appear"


# The redaction marker the gate emits in place of body content.
# Pinned here so a future commit that flips the marker (e.g. to
# "[PHI redacted]") fails this test rather than silently shipping
# a string the operator's eyes were trained to ignore.
REDACTED_MARKER = "[redacted]"


def _poisoned_entry() -> dict:
    """A row dict carrying every body surface the renderers read.

    ``body_text`` feeds ``_cheap_preview``'s lede + the legacy
    ``_preview``'s 200-char dump. ``body_html`` feeds
    ``_cheap_preview``'s H1/H2 extraction. ``snippet`` is the
    fallback ``_preview`` reads when ``body_text`` is empty —
    pinned with the sentinel so a future refactor that swaps
    sources still catches the gate.
    """
    return {
        "category": "newsletter",
        "sender": "alice@example.com",
        "subject": "Update",
        "body_text": (
            f"{SENTINEL_BODY} lede sentence with PHI-looking content. "
            f"Second paragraph."
        ),
        "body_html": (
            f"<h1>{SENTINEL_HEADING_1}</h1>"
            f"<h2>{SENTINEL_HEADING_2}</h2>"
            f"<p>{SENTINEL_BODY}</p>"
        ),
        "snippet": f"{SENTINEL_BODY} snippet fallback",
        "reason": "matched newsletters route",
        "source": "llm",
        "date": "2026-05-08T08:00:00+00:00",
        "links": [],
        "labels": [],
        "attachments": [],
        "headers": {},
    }


def _assert_no_sentinel(out: str, *, surface: str) -> None:
    """One-line invariant: none of the three body sentinels may
    appear in the rendered output. ``surface`` is the renderer name
    for the failure message so a missed gate points at the right
    layer."""
    for sentinel in (SENTINEL_BODY, SENTINEL_HEADING_1, SENTINEL_HEADING_2):
        assert sentinel not in out, (
            f"HIPAA gate failed at {surface}: body sentinel "
            f"{sentinel!r} appeared in rendered output. The renderer "
            f"must redact body_text + body_html + snippet for HIPAA "
            f"accounts per §164.502(a)(1)."
        )


# ---------------------------------------------------------------------------
# Invariant 1: _cheap_preview returns ("[redacted]", []) for HIPAA
# ---------------------------------------------------------------------------


class TestCheapPreviewHipaaGate:
    """The grouped_list / plain_list per-row content extractor.
    Returns a (lede, headings) tuple — HIPAA collapses both."""

    def test_returns_redacted_marker_and_empty_headings(self):
        """Direct unit on the helper. body_text + body_html both
        populated; HIPAA returns the redacted-marker + empty list."""
        lede, headings = _cheap_preview(_poisoned_entry(), hipaa=True)
        assert lede == REDACTED_MARKER
        assert headings == []

    def test_no_sentinel_in_output(self):
        """Sanity: every sentinel-carrying input field is in the
        entry, none of them reach the output."""
        entry = _poisoned_entry()
        lede, headings = _cheap_preview(entry, hipaa=True)
        # Combine the return tuple into one string + check.
        combined = lede + " ".join(headings)
        _assert_no_sentinel(combined, surface="_cheap_preview")

    def test_non_hipaa_extracts_content(self):
        """Affirmative baseline: with hipaa=False the helper DOES
        produce content. Without this, a test that silently became
        a no-op (e.g. _cheap_preview started always returning empty
        because of an unrelated bug) would still pass the HIPAA
        assertion above. The pair pins the gate behaviour, not the
        function-always-returns-empty behaviour."""
        lede, headings = _cheap_preview(_poisoned_entry(), hipaa=False)
        # The lede comes from the first non-trivial body_text line.
        assert SENTINEL_BODY in lede
        # The two H-tag sentinels come from body_html.
        joined_headings = " ".join(headings)
        assert SENTINEL_HEADING_1 in joined_headings
        assert SENTINEL_HEADING_2 in joined_headings

    def test_snippet_fallback_also_redacts(self):
        """body_text empty but ``snippet`` populated — the gate
        must still fire before _cheap_preview falls back to the
        snippet field. Defense against a future refactor that adds
        a new fallback source without re-reading the gate."""
        entry = _poisoned_entry()
        entry["body_text"] = ""
        lede, headings = _cheap_preview(entry, hipaa=True)
        assert lede == REDACTED_MARKER
        assert headings == []
        _assert_no_sentinel(
            lede + " ".join(headings),
            surface="_cheap_preview (snippet fallback)",
        )


# ---------------------------------------------------------------------------
# Invariant 2: _preview returns "[redacted]" for HIPAA (legacy path)
# ---------------------------------------------------------------------------


class TestLegacyPreviewHipaaGate:
    """The legacy 200-char preview helper used by the table render's
    ``preview`` column. Kept for back-compat with the preset path
    (recipient_digest still uses it indirectly) + custom table
    digests that opt into the preview column."""

    def test_returns_redacted_marker(self):
        out = _preview(_poisoned_entry(), hipaa=True)
        assert out == REDACTED_MARKER

    def test_no_sentinel_in_output(self):
        out = _preview(_poisoned_entry(), hipaa=True)
        _assert_no_sentinel(out, surface="_preview")

    def test_non_hipaa_extracts_content(self):
        """Affirmative baseline: non-HIPAA produces body content."""
        out = _preview(_poisoned_entry(), hipaa=False)
        assert SENTINEL_BODY in out

    def test_snippet_fallback_also_redacts(self):
        """body_text empty but ``snippet`` populated — same gate
        fires before the legacy preview reads the snippet."""
        entry = _poisoned_entry()
        entry["body_text"] = ""
        out = _preview(entry, hipaa=True)
        assert out == REDACTED_MARKER


# ---------------------------------------------------------------------------
# Invariant 3: every sync renderer surface honours the gate
# ---------------------------------------------------------------------------


def _grouped_cfg() -> DigestConfig:
    return DigestConfig(
        kind="custom",
        name="Test Grouped",
        format=DigestFormat(
            render_as="grouped_list",
            group_by="category",
            include_body_preview=True,
            max_rows=10,
        ),
    )


def _plain_cfg() -> DigestConfig:
    return DigestConfig(
        kind="custom",
        name="Test Plain",
        format=DigestFormat(
            render_as="plain_list",
            group_by="none",
            include_body_preview=True,
            max_rows=10,
        ),
    )


def _table_cfg() -> DigestConfig:
    return DigestConfig(
        kind="custom",
        name="Test Table",
        format=DigestFormat(
            render_as="table",
            include_body_preview=True,
            max_rows=10,
            columns=[
                DigestColumn(key="datetime", label="When"),
                DigestColumn(key="sender", label="Sender"),
                DigestColumn(key="subject", label="Subject"),
                DigestColumn(key="preview", label="Preview"),
            ],
        ),
    )


class TestSyncRendererSurfaceCoverage:
    """End-to-end on every sync render path that ships in
    ``_RENDERERS``. Each path passes through ``_row_block_html``
    or ``_column_value`` which calls the preview helpers — the
    invariant here is that the rendered HTML never carries a body
    sentinel for a HIPAA account."""

    def test_render_grouped_list_redacts(self):
        out = render_grouped_list(
            cfg=_grouped_cfg(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=True,
        )
        _assert_no_sentinel(out, surface="render_grouped_list")
        assert REDACTED_MARKER in out, (
            "render_grouped_list under HIPAA should emit the "
            "[redacted] marker in the preview block."
        )

    def test_render_plain_list_redacts(self):
        """render_plain_list was NOT covered by the existing
        feature-level test file — pin it here so the third sync
        renderer can't ship a regression silently."""
        out = render_plain_list(
            cfg=_plain_cfg(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=True,
        )
        _assert_no_sentinel(out, surface="render_plain_list")
        assert REDACTED_MARKER in out, (
            "render_plain_list under HIPAA should emit the "
            "[redacted] marker in the preview block."
        )

    def test_render_table_generic_redacts(self):
        out = render_table_generic(
            cfg=_table_cfg(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=True,
        )
        _assert_no_sentinel(out, surface="render_table_generic")
        assert REDACTED_MARKER in out, (
            "render_table_generic under HIPAA should emit the "
            "[redacted] marker in the preview column."
        )


# ---------------------------------------------------------------------------
# Invariant 4: render_digest dispatcher honours the gate for every
# ``render_as`` value AND the unknown-value fallback
# ---------------------------------------------------------------------------


class TestRenderDigestDispatcherGate:
    """The dispatcher's job is to route ``cfg.format.render_as`` to
    the right renderer. Each registered renderer carries its own
    HIPAA gate, but the dispatcher itself could in principle short-
    circuit the gate (it doesn't, today). Pin every
    ``render_as`` value AND the unknown-value fallback to be sure
    the dispatcher never bypasses the gate."""

    @pytest.mark.parametrize("render_as,cfg_factory", [
        ("grouped_list", _grouped_cfg),
        ("plain_list", _plain_cfg),
        ("table", _table_cfg),
    ])
    def test_dispatcher_redacts_known_render_as(self, render_as, cfg_factory):
        cfg = cfg_factory()
        # Belt-and-braces: confirm the factory-built cfg actually
        # has the render_as we're testing.
        assert cfg.format.render_as == render_as
        out = render_digest(
            cfg=cfg, rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=True,
        )
        _assert_no_sentinel(
            out, surface=f"render_digest(render_as={render_as!r})",
        )
        assert REDACTED_MARKER in out

    def test_dispatcher_unknown_render_as_falls_back_with_gate_intact(self):
        """The dispatcher falls back to render_grouped_list when
        ``render_as`` isn't in the _RENDERERS dict (defensive — a
        stored config from a future schema shouldn't blow up an
        old reader). The fallback path must STILL honour HIPAA."""
        # Build a config whose render_as is not in _RENDERERS. We
        # bypass the validator by mutating the field directly post-
        # construction (the validator would reject this on a real
        # save, but the dispatcher's defensive branch fires in
        # production on stored configs that pre-date a renamed
        # render_as value).
        cfg = _grouped_cfg()
        cfg.format.render_as = "future_unknown_format"
        out = render_digest(
            cfg=cfg, rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=True,
        )
        _assert_no_sentinel(
            out, surface="render_digest(render_as=unknown_fallback)",
        )
        assert REDACTED_MARKER in out, (
            "Unknown render_as falls back to grouped_list — the "
            "fallback path must still honour HIPAA. A future commit "
            "that changes the fallback target should not weaken the "
            "gate."
        )


# ---------------------------------------------------------------------------
# Invariant 5: include_body_preview=False suppresses the surface entirely
#
# The include_body_preview flag is the operator-facing toggle. When False,
# the preview block isn't rendered at all — the HIPAA gate is then moot
# for that surface, but a defensive test pins the contract anyway: under
# the OFF-toggle, no body content can leak even for non-HIPAA accounts.
# This catches a hypothetical future regression where the toggle is
# ignored.
# ---------------------------------------------------------------------------


class TestIncludeBodyPreviewToggleSuppression:
    """The operator-facing ``include_body_preview`` toggle is the
    first line of defence (no preview surface = no gate to bypass).
    Pin that the toggle is honoured on every sync renderer."""

    def _no_preview_grouped(self) -> DigestConfig:
        cfg = _grouped_cfg()
        cfg.format.include_body_preview = False
        return cfg

    def _no_preview_plain(self) -> DigestConfig:
        cfg = _plain_cfg()
        cfg.format.include_body_preview = False
        return cfg

    def _no_preview_table(self) -> DigestConfig:
        """Table renderer's preview surface is the ``preview``
        column — dropping the column from ``columns`` is the toggle
        equivalent for the table format."""
        cfg = _table_cfg()
        cfg.format.include_body_preview = False
        cfg.format.columns = [
            c for c in cfg.format.columns if c.key != "preview"
        ]
        return cfg

    def test_grouped_list_no_preview_drops_body_even_non_hipaa(self):
        out = render_grouped_list(
            cfg=self._no_preview_grouped(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=False,  # critical: non-HIPAA, gate is the toggle alone
        )
        _assert_no_sentinel(
            out,
            surface=(
                "render_grouped_list(include_body_preview=False, "
                "hipaa=False)"
            ),
        )

    def test_plain_list_no_preview_drops_body_even_non_hipaa(self):
        out = render_plain_list(
            cfg=self._no_preview_plain(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=False,
        )
        _assert_no_sentinel(
            out,
            surface=(
                "render_plain_list(include_body_preview=False, "
                "hipaa=False)"
            ),
        )

    def test_table_no_preview_column_drops_body_even_non_hipaa(self):
        out = render_table_generic(
            cfg=self._no_preview_table(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=False,
        )
        _assert_no_sentinel(
            out,
            surface="render_table_generic(no preview column, hipaa=False)",
        )


# ---------------------------------------------------------------------------
# Invariant 6: system-HIPAA flag forces redaction at the caller level
#
# The renderer takes a single ``hipaa`` flag — it doesn't read the system
# flag itself. The CALLER (web/app.py:3994 in ``_dispatch_digests``)
# resolves ``hipaa = is_hipaa_mode() or bool(acct.get("hipaa", False))``,
# threading both inputs through one parameter. Pinning the caller's
# resolution shape is the test that proves: even on a non-HIPAA-flagged
# account, system-HIPAA mode (whole-install flag) forces redaction.
#
# We simulate the caller's resolution by toggling
# ``triage_logging._hipaa_mode`` and calling ``is_hipaa_mode()`` ourselves
# to compute the renderer input — mirroring exactly what app.py does.
# ---------------------------------------------------------------------------


class TestSystemHipaaModeForcesRedaction:
    """System-wide ``_hipaa_mode = True`` must force the digest
    renderer to redact body content regardless of the per-account
    flag. This is the gate that protects an operator who flipped
    the install-wide flag but forgot to update every account row."""

    def _resolve_hipaa(self, acct: dict) -> bool:
        """Mirror of the caller in ``web/app.py:3994``."""
        from email_triage.triage_logging import is_hipaa_mode
        return is_hipaa_mode() or bool(acct.get("hipaa", False))

    def test_system_hipaa_on_account_hipaa_off_still_redacts(self):
        """The (system=ON, account=OFF) cell — the case that the
        per-account-only gate would MISS if the renderer pulled
        directly from ``acct["hipaa"]``. The caller's resolution
        shape catches it; this test pins that contract."""
        from email_triage import triage_logging
        # Save + clear state so a leaked toggle from another test
        # doesn't false-positive this assertion.
        prior = triage_logging._hipaa_mode
        triage_logging._hipaa_mode = True
        try:
            acct = {"hipaa": False, "id": 1}  # account-level OFF
            hipaa = self._resolve_hipaa(acct)
            assert hipaa is True, (
                "Caller resolution should return True when system "
                "flag is on, even with per-account flag off"
            )
            out = render_grouped_list(
                cfg=_grouped_cfg(),
                rows=[_poisoned_entry()],
                account_name="acct", account_email="me@example.com",
                hipaa=hipaa,
            )
            _assert_no_sentinel(
                out, surface="system_hipaa=ON, account_hipaa=OFF",
            )
            assert REDACTED_MARKER in out
        finally:
            triage_logging._hipaa_mode = prior

    def test_system_hipaa_off_account_hipaa_on_still_redacts(self):
        """The (system=OFF, account=ON) cell — the common case.
        The per-account flag alone must drive redaction."""
        from email_triage import triage_logging
        prior = triage_logging._hipaa_mode
        triage_logging._hipaa_mode = False
        try:
            acct = {"hipaa": True, "id": 1}
            hipaa = self._resolve_hipaa(acct)
            assert hipaa is True
            out = render_grouped_list(
                cfg=_grouped_cfg(),
                rows=[_poisoned_entry()],
                account_name="acct", account_email="me@example.com",
                hipaa=hipaa,
            )
            _assert_no_sentinel(
                out, surface="system_hipaa=OFF, account_hipaa=ON",
            )
            assert REDACTED_MARKER in out
        finally:
            triage_logging._hipaa_mode = prior

    def test_both_flags_on_redacts(self):
        """Belt-and-braces: both ON behaves the same as either ON.
        Pinned so a future ``if`` that subtly inverted to AND
        instead of OR fires here."""
        from email_triage import triage_logging
        prior = triage_logging._hipaa_mode
        triage_logging._hipaa_mode = True
        try:
            acct = {"hipaa": True, "id": 1}
            hipaa = self._resolve_hipaa(acct)
            assert hipaa is True
            out = render_plain_list(
                cfg=_plain_cfg(),
                rows=[_poisoned_entry()],
                account_name="acct", account_email="me@example.com",
                hipaa=hipaa,
            )
            _assert_no_sentinel(
                out, surface="system_hipaa=ON, account_hipaa=ON",
            )
        finally:
            triage_logging._hipaa_mode = prior

    def test_both_flags_off_does_not_redact(self):
        """Affirmative baseline: with both off, the renderer DOES
        produce body content. Without this we couldn't tell a
        gate-always-fires regression apart from a working gate."""
        from email_triage import triage_logging
        prior = triage_logging._hipaa_mode
        triage_logging._hipaa_mode = False
        try:
            acct = {"hipaa": False, "id": 1}
            hipaa = self._resolve_hipaa(acct)
            assert hipaa is False
            out = render_grouped_list(
                cfg=_grouped_cfg(),
                rows=[_poisoned_entry()],
                account_name="acct", account_email="me@example.com",
                hipaa=hipaa,
            )
            # Non-HIPAA: at least one of the sentinels survives
            # (the cheap_preview lede or one of the headings).
            present = sum(
                int(s in out) for s in (
                    SENTINEL_BODY, SENTINEL_HEADING_1, SENTINEL_HEADING_2,
                )
            )
            assert present >= 1, (
                "Non-HIPAA render should surface at least one body "
                "sentinel; got zero. The gate-always-fires "
                "regression would land here."
            )
            assert REDACTED_MARKER not in out, (
                "Non-HIPAA render must NOT emit the redacted marker"
            )
        finally:
            triage_logging._hipaa_mode = prior


# ---------------------------------------------------------------------------
# Invariant 7: HIPAA banner copy is present on every redacted render
#
# The recipient should be able to TELL the render was redacted — a
# silent redaction looks like a bug ("why is every preview empty?").
# Pin the banner-copy presence so a future refactor that drops the
# explanatory paragraph fires here.
# ---------------------------------------------------------------------------


class TestHipaaBannerCopy:
    """Operator-facing copy on the redacted render. The banner is
    one line in ``_hipaa_banner_html`` that explains why previews
    are blank. Pin that the banner ships on every sync renderer
    when ``hipaa=True``."""

    def test_grouped_list_carries_banner(self):
        out = render_grouped_list(
            cfg=_grouped_cfg(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=True,
        )
        assert "HIPAA mode" in out, (
            "Redacted grouped_list should carry the explanatory "
            "HIPAA banner copy so the recipient understands why "
            "the previews are empty."
        )

    def test_plain_list_carries_banner(self):
        out = render_plain_list(
            cfg=_plain_cfg(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=True,
        )
        assert "HIPAA mode" in out

    def test_table_generic_carries_banner(self):
        out = render_table_generic(
            cfg=_table_cfg(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=True,
        )
        assert "HIPAA mode" in out

    def test_non_hipaa_does_not_carry_banner(self):
        """Affirmative baseline: the banner is HIPAA-only."""
        out = render_grouped_list(
            cfg=_grouped_cfg(),
            rows=[_poisoned_entry()],
            account_name="acct", account_email="me@example.com",
            hipaa=False,
        )
        assert "HIPAA mode" not in out
