"""SSOT for writing provider-native labels (§164.502(e) egress gate).

Writing a label/category up to the upstream mailbox (Gmail label, O365
category) is a **disclosure to the mail provider** — a §164.502(e)
egress of a PHI-adjacent string. The established posture
(``reference_labels_phi_use_vs_disclosure_2026-06-06``) is: the *read*
side (discovering a user's own labels to show an authorized manager) is
an intra-entity USE gated on the access boundary, but the *write* side
(pushing a label up to the provider) is the egress and is gated on the
**HIPAA flag** — in HIPAA mode the provider portion is skipped so a
PHI-adjacent label string never leaves the perimeter to a mailbox that
may not be under a BAA.

This module is the **single** path to ``provider.apply_label`` across
the codebase (divergence census 2026-06-09 class #5). Before this, the
gate was implemented once correctly (``AddLabelAction``) and was
**missing** on two automated triage paths — ``LabelAction`` and
``web/triage_one._apply_rule_provider_labels`` — which pushed labels on
every HIPAA triage run with no gate. Routing every sink through here
makes the gate count-agnostic: a new label-apply site cannot forget the
gate, because calling ``provider.apply_label`` directly is pinned out
(``tests/test_provider_label_egress_ssot_pin.py``).

The caller owns logging + side-effects (idempotency stamps, entry
dicts, ``ActionOutput``/``BulkItemResult`` mapping); this helper owns
only the gated egress and returns the ``(applied, skipped, errors)``
triple so every caller maps the same three outcome lists its own way.
"""

from __future__ import annotations

from typing import Any

from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import account_hipaa_effective


def resolve_label_hipaa(message: Any = None, account: Any = None) -> bool:
    """The single resolver for the provider-label §164.502(e) gate input.

    Most-restrictive-wins over the per-message stamp, the system flag,
    and the per-account flag — collapsed into ONE funnel so the gate's
    own input cannot drift across call sites (the automated actions pass
    a ``message``; the operator/agent paths pass an ``account``). A
    falsy/absent argument simply does not contribute. ``message.hipaa``
    is already stamped ``system_hipaa OR account.hipaa`` at fetch, so for
    the message paths the ``account`` arg is belt-and-suspenders.

    Delegates to ``account_hipaa_effective`` (the SSOT) so there is one
    axis-combination implementation, not two (N-77 class-fix).
    """
    return account_hipaa_effective(account=account, message=message)


async def push_provider_labels(
    provider: Any,
    message_id: str,
    names: Any,
    *,
    hipaa: bool,
) -> tuple[list[str], list[str], list[tuple[str, str, BaseException]]]:
    """Apply provider-native labels to ``message_id``, HIPAA-gated.

    Args:
        provider: the email provider (``apply_label`` coroutine).
        message_id: the provider message id to label.
        names: an iterable of label/category names (falsy entries
            dropped); order preserved.
        hipaa: when ``True`` the whole provider portion is **skipped**
            (the §164.502(e) egress gate) — every name lands in
            ``skipped`` and nothing is written upstream.

    Returns:
        ``(applied, skipped, errors)``. ``applied`` is the names written
        to the provider; ``skipped`` the names not written (HIPAA gate,
        or whole-provider ``NotImplementedError``); ``errors`` a list of
        ``(label, detail, exc)`` triples for individual failures (the
        apply loop continues past a single failure). ``detail`` is the
        PHI-free ``fmt_exc`` string for the operator-facing outcome;
        ``exc`` is the live exception so a caller can preserve
        ``exc_info=`` (a full traceback) in its log — only reached on
        NON-HIPAA accounts (HIPAA skips before any apply), so the
        traceback carries no redaction obligation.

    Note on PHI: a label *slug* / classification *category* is a category
    name, not a Safe-Harbor §164.514(b) identifier, so it is not PHI on
    its own — but an operator MAY embed an identifier in a label name, so
    the slugs are treated as PHI-adjacent and kept off the upstream
    mailbox in HIPAA mode (and out of any non-redacted log field).
    """
    applied: list[str] = []
    skipped: list[str] = []
    errors: list[tuple[str, str, BaseException]] = []

    clean = [str(n) for n in (names or []) if n]
    if not clean:
        return applied, skipped, errors

    # §164.502(e) gate — keep PHI-adjacent label strings off the
    # upstream mailbox in HIPAA mode. Internal/DB-only labels are the
    # caller's concern and stay on regardless; this helper governs ONLY
    # the provider-perimeter write.
    if hipaa:
        skipped = list(clean)
        return applied, skipped, errors

    for label in clean:
        try:
            await provider.apply_label(message_id, label)
            applied.append(label)
        except NotImplementedError:
            # Whole-provider lack of label support — the remaining
            # names would raise identically, so skip them all and stop.
            skipped.extend(n for n in clean if n not in applied and n not in skipped)
            break
        except Exception as e:  # noqa: BLE001 — per-label isolation
            errors.append((label, fmt_exc(e), e))

    return applied, skipped, errors
