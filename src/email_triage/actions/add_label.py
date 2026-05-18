"""Add-label action — attach one or more labels when a route fires.

Companion to :class:`LabelAction` (which applies the classification
category as a single provider-native label). ``AddLabelAction`` is the
explicit, multi-target route-level cousin: when a route's category
matches, attach the operator-picked internal labels (via the
``labels`` catalog + ``message_labels`` junction table) AND/OR the
operator-picked provider-native labels (Gmail labels / IMAP keywords /
Office 365 categories).

Shape parity with the list-rule editor
======================================

The list-rule editor stores an ``adds_labels`` JSON array of internal
slugs on ``list_rules`` (see migration v18). When a list rule matches,
the engine attaches those internal labels to the message. ``AddLabelAction``
runs the same internal-label apply path — same DB helper
(:func:`apply_labels_to_message`), same forward-only INSERT-OR-IGNORE
semantics — keyed off the route's action config instead of the rule.

Action config shape
===================

``add-label`` accepts a ``config`` dict with two optional keys:

    {
      "labels":          ["receipts", "tax-2026", ...],     # internal slugs
      "provider_labels": ["Receipts/2026", "Tax", ...],     # provider native
    }

Either may be empty. Empty + empty is a no-op (the action runs and
returns SKIPPED with a "nothing configured" reason). Internal labels
that no longer exist in the catalog are silently dropped at the DB
helper layer — the action records what it attempted, the helper
records what it persisted.

HIPAA gate
==========

When the message's resolved HIPAA state is on (per ``message.hipaa``,
which carries the per-account flag stamped at fetch time, or the
install-wide HIPAA mode), the PROVIDER-native portion is skipped.
Internal labels stay — they live in the install's own DB under
operator-controlled labels and never leave the perimeter, so the
HIPAA boundary doesn't apply. Provider-native labels would write a
human-readable label string back to the upstream provider, which IS
PHI-adjacent on a HIPAA mailbox (a label like "Patient Smith — Lab
Results" leaks the subject by naming convention). The asymmetry
mirrors the rule editor's behaviour.

Idempotency
===========

Internal-label apply is idempotent at the DB layer (INSERT OR IGNORE
on the (message_id, label_slug) primary key). Provider-native apply
is idempotent on every supported provider (Gmail labels are a set;
IMAP STORE +FLAGS is set-union; O365 categories are deduped server-
side). No state_bag record is required.
"""

from __future__ import annotations

import logging
from typing import Any

from email_triage.actions.base import Action, build_action_log_extras
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
)
from email_triage.providers.base import EmailProvider
from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import is_hipaa_mode

logger = logging.getLogger("email_triage.actions.add_label")


class AddLabelAction(Action):
    """Attach operator-picked labels when this route fires.

    Distinct from :class:`LabelAction`, which derives a single label
    from ``classification.category`` and a prefix. ``AddLabelAction``
    pulls the labels from its own ``config`` so a single route can
    tag a message with several internal + several provider-native
    labels at once — the route-level equivalent of the list-rule
    editor's "Also adds labels" / "Also apply provider labels".
    """

    @property
    def name(self) -> str:
        return "add-label"

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        config = config or {}
        raw_internal = config.get("labels") or []
        raw_provider = config.get("provider_labels") or []

        # Normalise to lists of clean strings. Form posts can hand us
        # mixed shapes (list, comma-string from a free-text field, or
        # None); be lenient on input + strict on output.
        internal_slugs = _normalise_string_list(raw_internal, lower=True)
        provider_names = _normalise_string_list(raw_provider, lower=False)

        # Resolve HIPAA on the SAME basis ``build_action_log_extras``
        # uses — message.hipaa is stamped at fetch time from the
        # per-account flag and is the canonical signal. is_hipaa_mode()
        # backstops against an install where the message-level flag
        # wasn't set but the install is HIPAA-mode globally (digest
        # render / future surfaces).
        hipaa = bool(getattr(message, "hipaa", False)) or is_hipaa_mode()

        def _extras(**more: Any) -> dict[str, Any]:
            return build_action_log_extras(
                flow, message, classification, provider,
                internal_count=len(internal_slugs),
                provider_count=len(provider_names),
                hipaa=hipaa,
                **more,
            )

        if not internal_slugs and not provider_names:
            logger.info(
                "add-label: nothing configured, skipping",
                extra=_extras(),
            )
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "no labels configured"},
            )

        internal_applied: list[str] = []
        provider_applied: list[str] = []
        provider_skipped: list[str] = []
        errors: list[str] = []

        # ── Internal labels ────────────────────────────────────────
        # Stays on regardless of HIPAA — these are install-local DB
        # rows, never crossing the perimeter.
        if internal_slugs:
            db = (flow.state_bag or {}).get("db") if flow.state_bag else None
            account_id = (
                (flow.state_bag or {}).get("account_id") if flow.state_bag else None
            )
            actor_user_id = (
                (flow.state_bag or {}).get("actor_user_id") if flow.state_bag else None
            )
            if db is not None and account_id is not None:
                try:
                    from email_triage.web.db import apply_labels_to_message
                    inserted = apply_labels_to_message(
                        db, message.message_id, account_id,
                        internal_slugs,
                        applied_by_actor=actor_user_id,
                    )
                    # ``apply_labels_to_message`` returns rows-inserted;
                    # we report the *attempted* slug list because the
                    # helper silently drops unknown slugs (forward-only
                    # validation). The count is useful for log
                    # correlation but the slug list is what operators
                    # want to see when answering "did this route tag
                    # this message?".
                    internal_applied = list(internal_slugs)
                    logger.info(
                        "add-label: internal labels applied",
                        extra=_extras(
                            applied=internal_applied,
                            inserted=inserted,
                        ),
                    )
                except Exception as e:
                    errors.append(f"internal: {fmt_exc(e)}")
                    logger.warning(
                        "add-label: internal label apply failed",
                        exc_info=e,
                        extra=_extras(),
                    )
            else:
                # CLI / engine path without web-DB plumbing — internal
                # labels live in the web DB only, so skip silently
                # rather than crash. Operators wiring add-label into a
                # non-web caller would only use provider_labels.
                logger.info(
                    "add-label: internal labels skipped (no DB in flow context)",
                    extra=_extras(skipped_slugs=internal_slugs),
                )

        # ── Provider-native labels ────────────────────────────────
        # HIPAA gate: skip the provider portion to keep PHI-adjacent
        # label strings off the upstream mailbox. Internal labels
        # stayed above (DB-only, perimeter-safe).
        if provider_names:
            if hipaa:
                provider_skipped = list(provider_names)
                logger.info(
                    "add-label: provider labels skipped (HIPAA mode)",
                    extra=_extras(skipped=provider_skipped),
                )
            else:
                for label in provider_names:
                    try:
                        await provider.apply_label(message.message_id, label)
                        provider_applied.append(label)
                    except NotImplementedError:
                        # Whole-provider lack of support → skip the
                        # remaining label list too, log once.
                        provider_skipped.extend(
                            n for n in provider_names if n not in provider_applied
                        )
                        logger.info(
                            "add-label: provider does not support labels, "
                            "skipping remainder",
                            extra=_extras(skipped=provider_skipped),
                        )
                        break
                    except Exception as e:
                        errors.append(f"provider:{label}: {fmt_exc(e)}")
                        logger.warning(
                            "add-label: provider label apply failed for %r",
                            label,
                            exc_info=e,
                            extra=_extras(label=label),
                        )

        # Decide the outcome. COMPLETED if anything was applied,
        # SKIPPED if nothing applied but no errors (e.g. HIPAA + no
        # internals), FAILED if every attempt errored.
        any_applied = bool(internal_applied) or bool(provider_applied)
        if any_applied:
            return ActionOutput(
                result=ActionResult.COMPLETED,
                data={
                    "internal_applied": internal_applied,
                    "provider_applied": provider_applied,
                    "provider_skipped": provider_skipped,
                    "errors": errors,
                },
            )
        if errors and not provider_skipped and not internal_slugs and not provider_applied:
            return ActionOutput(
                result=ActionResult.FAILED,
                error="; ".join(errors),
            )
        return ActionOutput(
            result=ActionResult.SKIPPED,
            data={
                "internal_applied": internal_applied,
                "provider_applied": provider_applied,
                "provider_skipped": provider_skipped,
                "errors": errors,
                "reason": (
                    "hipaa_mode" if hipaa and provider_names and not internal_slugs
                    else "nothing applied"
                ),
            },
        )


def _normalise_string_list(raw: Any, *, lower: bool) -> list[str]:
    """Coerce a mixed-shape form value into a clean string list.

    Accepts:
      * ``list`` / ``tuple`` — iterate, strip each entry, drop empties.
      * ``str`` — split on commas (operator typed a free-text field),
        strip each, drop empties.
      * anything else — return ``[]``.

    Order is preserved; duplicates are de-duped (first occurrence wins)
    so an operator can paste a list with accidental repeats without
    seeing every label applied twice in the result data.
    """
    if isinstance(raw, str):
        candidates = raw.split(",")
    elif isinstance(raw, (list, tuple)):
        candidates = list(raw)
    else:
        return []

    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c is None:
            continue
        s = str(c).strip()
        if not s:
            continue
        if lower:
            s = s.lower()
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out
