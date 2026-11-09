"""Count-agnostic pin — Drive-7 defensive-xfail SSOT.

Anchors ``feedback_dont_over_defer`` (recurrence class) + DA-batch3 HIGH
finding (Drive-6 close-out): a walk that does ``authed_page.goto(url)``
followed by ``if x.count() == 0: pytest.xfail(...)`` silently converts a
5xx REGRESSION into an xfail SKIPPED, voiding the walk's coverage claim.
Fold SSOT lives in ``tests/e2e/walk/_helpers.py::goto_or_fail`` (LOUD
2xx-3xx guard; 4xx/5xx = ``pytest.fail``). Drive-6 folded the HIPAA-critical
instance; Drive-7 sweeps the 5 non-HIPAA sites called out in the Drive-6
trailer + the fold-reference walk.

Pin shape (per PD#1 — count-agnostic structural pin, same-change as the SSOT):

* Walk ``tests/e2e/walk/*.py`` via ``ast.walk``; for each ``Expr(...)``
  whose expression (unwrapping ``ast.Await`` for future ``async def`` walks
  per DA-batch4 Drive-7 must-fix) is a ``Call`` whose callable is
  ``<Name>.goto`` and the receiver name is ``authed_page`` or ``page``,
  count as a "bare-goto" site.
* Enforce the "goto_or_fail-only" rule per FILE via a legacy allow-list
  (``_LEGACY_BARE_GOTO_ALLOW``). A NEW walk file (not in the allow-list)
  with ANY bare ``.goto()`` FAILS the pin.
* PD#7 rot-guard: every allow-list entry must still exist AND still hold
  ≥1 bare ``.goto()`` (a rotted entry silently exempts a future twin).
* Teeth: SSOT still exports ``goto_or_fail`` + the 6 Drive-7-swept files
  hold ZERO bare ``.goto()`` + a RUNTIME teeth-probe (per db-sme Drive-7
  NTH#2) drives ``goto_or_fail`` with a fake status=500 response and
  confirms the LOUD ``pytest.fail`` fires (static AST teeth aren't enough
  to prove the fail-path).

Reuses ``_pin_harness.REPO_ROOT`` per PD#6 (harness convergence — the pin
cannot drift in its scoping).

Known-and-accepted escapes (db-sme Drive-7 NTH#4 + DA Drive-7 NTH):
* **Assignment-form goto** (``resp = page.goto(url)``) is intentionally
  NOT scanned — the pin's ``Expr``-only shape skips ``Assign``. Callers
  that capture the response are expected to inspect ``.status`` inline
  (``assert resp.status == 200``), same shape Drive-6 used for the
  HIPAA-critical ``.request.post`` fold and preserved in
  ``test_topic_digest_new.py::test_new_editor_blank_renders``. A future
  reader adding assignment-form goto in a non-swept file must apply
  that inline check by hand.
* **Receiver aliasing** (``p = authed_page; p.goto(...)``) escapes:
  the receiver's ``ast.Name.id`` is ``p``, not ``authed_page``. Not
  a pattern any walk uses today; add a name-flow analysis pass if
  a future walk lands one.
* **Reflective call** (``getattr(page, 'goto')(url)``) escapes for
  the same reason — the callable isn't an ``Attribute`` node.
  Stylistically foreign; not worth extra scanner complexity.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests._pin_harness import REPO_ROOT, parse_module

WALKS_ROOT: Path = REPO_ROOT / "tests" / "e2e" / "walk"

# The 6 files that Drive-6 + Drive-7 have swept clean of bare ``.goto()``.
# A pin failure here means a regression introduced a bare ``.goto()`` in one
# of these files — un-do it (use ``goto_or_fail(page, url)`` instead).
_DRIVE7_SWEPT: frozenset[str] = frozenset({
    "test_admin_webhook_preview.py",
    "test_backfill_capped_dismiss.py",
    "test_provider_labels_apply.py",  # Drive-6 fold reference (HIPAA-critical)
    "test_topic_digest_new.py",
    "test_topic_digest_preview.py",
    "test_topic_digest_test_details.py",
})

# Legacy walks that pre-date Drive-7 and still contain bare ``.goto()``.
# NEW walk files MUST NOT appear in this set — they must use ``goto_or_fail``
# from day 1. Future drives (Drive-8+) SHRINK this set as they sweep more
# walks; when the set is empty, promote the pin to global-enforce mode
# (drop the allow-list entirely).
_LEGACY_BARE_GOTO_ALLOW: frozenset[str] = frozenset({
    "test_accounts_api_keys_page.py",
    "test_ai_backends_probe_models.py",
    "test_backup_config_save.py",
    "test_clock_disposition_actions.py",
    "test_help_me.py",
    "test_help_me_ask.py",
    "test_profile_hardware_keys.py",
    "test_profile_security_walk.py",
    "test_regulatory_clocks_create.py",
    "test_regulatory_clocks_dashboard.py",
    "test_regulatory_clocks_delete.py",
    "test_regulatory_clocks_editor.py",
    "test_regulatory_clocks_update.py",
    "test_reindex_jobs_aggregate_progress_fragment.py",
    "test_topic_backscan_worker.py",
    "test_topic_digest_delete.py",
    "test_topic_digest_delete_hit.py",
    "test_topic_digest_edit.py",
    "test_topic_digest_feedback_unmute.py",
    "test_topic_digest_hit_feedback.py",
    "test_topic_digest_include_hit.py",
    "test_topic_digest_retriage_cancel.py",
    "test_topic_digest_save.py",
})

_RECEIVERS: frozenset[str] = frozenset({"authed_page", "page"})


def _walk_files() -> list[Path]:
    return sorted(p for p in WALKS_ROOT.rglob("test_*.py"))


def _collect_bare_goto(path: Path) -> list[int]:
    """Return line numbers of bare ``Expr(Call(<receiver>.goto(...)))`` sites.

    Unwraps ``ast.Await`` (per DA Drive-7 must-fix) so a future ``async def
    test_...`` walk with ``await authed_page.goto(url)`` — shape
    ``Expr(Await(Call(...)))`` — is still caught. Playwright's SYNC API
    doesn't need this today; keeps the pin robust against a future
    async-only Playwright migration or a mixed ``pytest-asyncio`` walk.
    """
    tree = parse_module(path)
    if tree is None:  # pragma: no cover - a syntax error will fail elsewhere
        return []
    hits: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr):
            continue
        call = node.value
        # Unwrap `await <call>` — Expr(Await(Call(...))).
        if isinstance(call, ast.Await):
            call = call.value
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
            continue
        if call.func.attr != "goto":
            continue
        recv = call.func.value
        if isinstance(recv, ast.Name) and recv.id in _RECEIVERS:
            hits.append(node.lineno)
    return hits


def test_no_new_bare_goto_outside_legacy_allow_list() -> None:
    """PD#1 — a NEW walk file (or a swept file that regressed) with any bare
    ``authed_page.goto(...)`` / ``page.goto(...)`` expression statement FAILS.

    Fold SSOT: import ``goto_or_fail`` from ``tests.e2e.walk._helpers`` and
    use it in place of the bare ``.goto()``. It captures the response and
    asserts the status is in the 200-399 window; a 5xx/4xx is ``pytest.fail``,
    NOT ``pytest.xfail``, so a route regression surfaces as CI-red rather
    than silently converting a downstream ``.count() == 0`` xfail into a
    pass.
    """
    offenders: list[str] = []
    for p in _walk_files():
        if p.name in _LEGACY_BARE_GOTO_ALLOW:
            continue
        hits = _collect_bare_goto(p)
        if hits:
            for ln in hits:
                offenders.append(f"{p.name}:{ln}")
    assert not offenders, (
        f"Drive-7 defensive-xfail SSOT — {len(offenders)} bare "
        f"authed_page.goto(...) / page.goto(...) site(s) outside the "
        f"legacy allow-list:\n"
        + "\n".join(f"  {o}" for o in offenders)
        + "\n\nFix: import goto_or_fail from tests.e2e.walk._helpers and "
        "replace 'authed_page.goto(url)' with 'goto_or_fail(authed_page, url)'."
    )


def test_legacy_allow_list_has_no_stale_entries() -> None:
    """PD#7 rot-guard — every legacy allow-list entry must (a) still exist
    on disk AND (b) still contain ≥1 bare ``.goto()`` site.

    A rotted allow-list entry (file removed OR fully swept) silently
    exempts a future twin under the same name, hiding a regression.
    Drop it from ``_LEGACY_BARE_GOTO_ALLOW`` in the same change that
    completes the file's sweep.
    """
    rotten: list[str] = []
    for name in sorted(_LEGACY_BARE_GOTO_ALLOW):
        p = WALKS_ROOT / name
        if not p.exists():
            rotten.append(f"{name} (file removed — drop from allow-list)")
            continue
        if not _collect_bare_goto(p):
            rotten.append(
                f"{name} (0 bare .goto() sites — sweep complete, "
                f"drop from allow-list)"
            )
    assert not rotten, (
        "Legacy allow-list has stale entries — drop them:\n"
        + "\n".join(f"  {r}" for r in rotten)
    )


def test_drive7_swept_files_hold_no_bare_goto() -> None:
    """Teeth-probe — each Drive-7-swept file must have ZERO bare
    ``.goto()``. If any of the 6 swept files regains a bare ``.goto()``,
    Drive-7's fold has been silently reverted; fail LOUD."""
    regressed: list[str] = []
    for name in sorted(_DRIVE7_SWEPT):
        p = WALKS_ROOT / name
        if not p.exists():
            pytest.fail(
                f"Drive-7 swept file {name!r} missing — was the walk "
                "renamed or deleted? Update _DRIVE7_SWEPT to match."
            )
        hits = _collect_bare_goto(p)
        if hits:
            regressed.append(f"{name}:{hits}")
    assert not regressed, (
        "Drive-7 sweep regressed — the following swept files regained "
        "bare .goto():\n" + "\n".join(f"  {r}" for r in regressed)
        + "\n\nFix: use goto_or_fail(page, url) — see "
        "tests/e2e/walk/_helpers.py."
    )


def test_ssot_still_exports_goto_or_fail() -> None:
    """Teeth-probe — the fold SSOT still exports ``goto_or_fail``. If a
    refactor drops the export, the pin's "use goto_or_fail" advice is
    stale; fail LOUD so this pin is updated in the same change."""
    from tests.e2e.walk import _helpers  # noqa: WPS433 — teeth-probe

    assert hasattr(_helpers, "goto_or_fail"), (
        "goto_or_fail vanished from tests/e2e/walk/_helpers.py — this "
        "pin's advice is now stale. Restore the export OR update the pin "
        "to reference the new SSOT name."
    )
    assert hasattr(_helpers, "start_5xx_watch"), (
        "start_5xx_watch vanished — the HTMX-wait 5xx-guard SSOT is gone."
    )
    assert hasattr(_helpers, "assert_no_regression_or_xfail"), (
        "assert_no_regression_or_xfail vanished — the wait-timeout dispatch "
        "SSOT is gone."
    )


def test_pin_planted_fake_catches_bare_goto(tmp_path: Path) -> None:
    """Teeth-probe — a planted-fake AST containing a bare ``.goto()`` in a
    NOT-allow-listed name MUST be caught by ``_collect_bare_goto``. Also
    covers the DA Drive-7 must-fix: ``await authed_page.goto(...)``
    (Expr(Await(Call))) must be caught after the ``ast.Await`` unwrap."""
    sync_shape = tmp_path / "sync_fake.py"
    sync_shape.write_text(
        "def test_synthetic(authed_page, base_url):\n"
        "    authed_page.goto(f'{base_url}/whatever')\n",
        encoding="utf-8",
    )
    async_shape = tmp_path / "async_fake.py"
    async_shape.write_text(
        "async def test_synthetic(authed_page, base_url):\n"
        "    await authed_page.goto(f'{base_url}/whatever')\n",
        encoding="utf-8",
    )
    assert _collect_bare_goto(sync_shape), (
        "Teeth-probe FAILED (sync shape): the AST walker did not catch a "
        "synthetic bare authed_page.goto(...) expression. The pin is blind."
    )
    assert _collect_bare_goto(async_shape), (
        "Teeth-probe FAILED (async shape): the AST walker did not catch a "
        "synthetic bare 'await authed_page.goto(...)' expression. "
        "DA Drive-7 must-fix regressed — restore the ast.Await unwrap in "
        "_collect_bare_goto."
    )


def test_goto_or_fail_runtime_fails_loud_on_5xx() -> None:
    """RUNTIME teeth-probe (db-sme Drive-7 NTH#2) — drive ``goto_or_fail``
    with a fake status=500 response and confirm ``pytest.fail`` fires.
    Static AST teeth prove the shape; this proves the fail-path is not
    silently a ``pass`` under a coding regression. Uses a fake ``page``
    ($goto returns SimpleNamespace) — no real Playwright fixture needed.
    """
    from tests.e2e.walk._helpers import goto_or_fail

    fake_response = SimpleNamespace(
        status=500,
        url="http://example.invalid/whatever",
        body=lambda: b"boom",
    )
    fake_page = SimpleNamespace(goto=lambda _url: fake_response)

    with pytest.raises(pytest.fail.Exception) as exc:
        goto_or_fail(fake_page, "http://example.invalid/whatever")
    msg = str(exc.value)
    assert "500" in msg, (
        f"goto_or_fail failed but its message did not name the status: {msg!r}"
    )
    assert "regression" in msg.lower(), (
        f"goto_or_fail failed but the message did not name the class: {msg!r}"
    )


def test_goto_or_fail_runtime_passes_on_2xx() -> None:
    """RUNTIME teeth-probe (db-sme Drive-7 NTH#2 companion) — a fake
    status=200 response passes ``goto_or_fail`` cleanly (no fail, no raise).
    Guards against a coding regression that would fail-loud on 2xx too."""
    from tests.e2e.walk._helpers import goto_or_fail

    fake_response = SimpleNamespace(
        status=200,
        url="http://example.invalid/ok",
        body=lambda: b"",
    )
    fake_page = SimpleNamespace(goto=lambda _url: fake_response)
    result = goto_or_fail(fake_page, "http://example.invalid/ok")
    assert result is fake_response, (
        "goto_or_fail did not return the underlying Response — the "
        "response-inspection contract is broken."
    )
