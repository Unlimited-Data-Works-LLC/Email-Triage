""" / N-03 — EmailMessage in-memory PHI residency narrowing.

Background
----------
``EmailMessage`` dataclass holds ``Attachment`` rows, each with an
optional ``data: bytes`` field. Before this fix the providers that
populate attachments (Gmail, IMAP, O365) all set ``data=blob`` on
``text/calendar`` parts — the only attachment shape this codebase
currently processes. The bytes blob is needed transiently inside
``_extract_attachments`` to call ``parse_ics(blob)`` → ``parsed: dict``,
but ``actions/invite.py`` (the SINGLE downstream consumer) only ever
reads ``att.parsed``, never ``att.data``. Grep of ``src/`` for
``att.data`` / ``attachment.data`` reads returns ZERO results outside
the providers themselves.

Carrying the bytes blob on the Attachment for the rest of the flow
lifetime widens §164.308(a)(1)(ii)(B) Risk Management (availability
axis of CIA-triad) PHI-residency surface for no consumer benefit. The
fix is the narrowest possible mitigation: drop the blob at the
``Attachment(...)`` constructor call in each provider — the parse has
already consumed it; the ``parsed`` dict carries the only field any
consumer reads.

This test file pins:

  * **Structural pin (drift defense per n=6 pattern)** — AST-walk every
    ``Attachment(...)`` constructor in ``providers/{gmail_api,imap,
    office365}.py`` and assert each one passes ``data=None``. A future
    refactor that re-introduces ``data=blob`` is caught at test-time
    and forces a paired §164.316 register entry documenting the
    residency-window extension.
  * **HIPAA log-scrub regression** — `_PHI_KEYS` continues to strip
    ``attachments`` under HIPAA mode (sanity that the fix doesn't bump
    the log-leak surface).
  * **Documentation pin** — the ``Attachment`` docstring carries the
    N-03 closure rationale so a future contributor reading the model
    finds the constraint at the type level, not buried in commit
    history.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from _pin_harness import parse_module
from email_triage.engine.models import Attachment
from _pin_harness import _FULL_DEV_TREE  # the one dev-tree detector (PD-5)


# ---------------------------------------------------------------------------
# Structural pin — every provider Attachment(...) constructor passes data=None
# ---------------------------------------------------------------------------

_PROVIDER_FILES = (
    "src/email_triage/providers/gmail_api.py",
    "src/email_triage/providers/imap.py",
    "src/email_triage/providers/office365.py",
)


def _attachment_constructor_calls(path: Path) -> list[ast.Call]:
    """Every ``Attachment(...)`` Call node in the file at ``path``."""
    tree = parse_module(path)
    assert tree is not None, f"expected parseable source at {path}"
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Attachment"
    ]


def _kwarg(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


@pytest.mark.parametrize("provider_path", _PROVIDER_FILES)
def test_provider_attachment_constructor_passes_data_none(
    provider_path: str,
):
    """Every ``Attachment(...)`` call in a provider must pass
    ``data=None`` (or omit ``data`` entirely — the dataclass default is
    None). Passing ``data=blob`` (or any non-None expression) would
    extend in-memory PHI residency past the parse step for no consumer
    benefit and re-opens the  / N-03 finding. A new provider that
    needs the bytes for a legitimate reason (e.g. attachment
    forwarding) MUST land a paired §164.316 register entry and update
    this guard to scope the exemption.
    """
    repo_root = Path(__file__).resolve().parents[2]
    calls = _attachment_constructor_calls(repo_root / provider_path)
    assert calls, (
        f"expected at least one Attachment(...) constructor in "
        f"{provider_path}; AST walk found none"
    )

    offenders: list[str] = []
    for call in calls:
        data_kw = _kwarg(call, "data")
        if data_kw is None:
            # Omitted — dataclass default is None, also fine.
            continue
        if isinstance(data_kw, ast.Constant) and data_kw.value is None:
            continue
        # Anything else (a Name like `blob`, a BoolOp like
        # `blob or None`, or any other expression) is a regression.
        offenders.append(
            f"{provider_path}:{call.lineno}  Attachment(..., "
            f"data={ast.unparse(data_kw)})"
        )

    if offenders:
        joined = "\n  ".join(offenders)
        pytest.fail(
            f"{len(offenders)} Attachment(...) constructor(s) pass a "
            f"non-None `data=` — extends in-memory PHI residency past "
            f"the parse step (#266 / N-03 §164.308(a)(1)(ii)(B) Risk "
            f"Management):\n  {joined}\n\n"
            "If a new consumer legitimately needs the raw bytes, add a "
            "paired §164.316 register entry documenting the residency-"
            "window extension and update this guard to scope the "
            "exemption."
        )


# ---------------------------------------------------------------------------
# Documentation pin — Attachment docstring carries the N-03 rationale
# ---------------------------------------------------------------------------

def test_attachment_docstring_documents_n03_constraint():
    """The Attachment dataclass docstring must carry the N-03 rationale
    so a contributor reading the type finds the constraint at the type
    level, not buried in commit history (per medical-scope drawer §2.6
    rationale-travels-with-code).
    """
    doc = inspect.getdoc(Attachment) or ""
    # The publish sanitizer strips internal tracking ids from the public tree by design,
    # so the id half holds on the full dev tree only; the regulatory anchor below is the
    # rationale itself and holds on every tree.
    if _FULL_DEV_TREE:
        assert "#266" in doc or "N-03" in doc, (
            "Attachment docstring must reference #266 / N-03 — the "
            "residency-narrowing rationale is type-level, not a "
            "commit-history detail"
        )
    assert "§164.308(a)(1)(ii)(B)" in doc, (
        "Attachment docstring must name §164.308(a)(1)(ii)(B) Risk "
        "Management as the regulatory anchor — the constraint is a "
        "HIPAA-finding closure, not a generic memory optimisation"
    )


# ---------------------------------------------------------------------------
# Dataclass shape pin — data field still exists for future re-enable
# ---------------------------------------------------------------------------

def test_attachment_data_field_still_exists_with_default_none():
    """The ``data`` field is preserved on the dataclass (not removed)
    so a future feature that genuinely needs raw bytes can re-enable
    it deliberately. Removing the field would be a breaking API change
    with no current upside; the fix is to drop the value at the
    constructor call sites, not the field on the model.
    """
    fields = Attachment.__dataclass_fields__
    assert "data" in fields, (
        "Attachment.data field must be preserved on the dataclass — "
        "removing it would be a breaking change. The N-03 fix drops "
        "the value at the provider constructor call sites, not the "
        "field itself."
    )
    # Default is None — set explicitly in the dataclass declaration.
    assert fields["data"].default is None, (
        "Attachment.data default must be None so constructor calls "
        "that omit it implicitly get the residency-narrowed shape"
    )


# ---------------------------------------------------------------------------
# HIPAA log-scrub regression — `_PHI_KEYS` still strips attachments
# ---------------------------------------------------------------------------

def test_phi_keys_still_strips_attachments_field():
    """Sanity that the existing HIPAA log strip surface is unchanged by
    the fix. The N-03 mitigation is at the data-residency layer; if
    `_PHI_KEYS` regressed (e.g. someone removed `attachments` from the
    strip set in a refactor), an audit-row that included an
    `attachments` field in its `extra` dict would land in logs.
    """
    from email_triage.triage_logging import TriageLogger
    keys = TriageLogger._PHI_KEYS
    assert "attachments" in keys, (
        "_PHI_KEYS must continue to strip `attachments` from log extras "
        "in HIPAA mode — the N-03 fix doesn't change the log strip "
        "surface but a contributor refactoring _PHI_KEYS could "
        "accidentally remove the entry. This guard catches that."
    )
    assert "attachment" in keys, (
        "Singular `attachment` also in the strip set — covers per-row "
        "log emissions that name a single attachment"
    )
