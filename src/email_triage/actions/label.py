"""Label action — apply a label/category/tag to the email."""

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

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.actions.label")  # N-196b R21_4


class LabelAction(Action):
    """Apply the classification category as a label on the email."""

    #  — provider-level idempotency contract. ``apply_label`` is a
    # no-op on every supported provider (Gmail/O365 attach the label
    # only if not already present), so re-running this action on a
    # crash-recovery rerun produces no duplicate side effect. The class
    # does not gate on ``check_idempotent_already_done``; only
    # ``record_idempotent_done`` is called so the /flows surface answers
    # "did this run?" consistently with helper-based actions.
    _naturally_idempotent: bool = True
    _idempotency_rationale: str = (
        "provider.apply_label is provider-level idempotent (Gmail/O365 "
        "no-op when the label is already attached); a crash-recovery "
        "rerun re-issues the same apply with no duplicate effect"
    )

    @property
    def name(self) -> str:
        return "label"

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        #  follow-up — config["labels"] is a list of operator-
        # picked provider-native labels (Gmail labels, O365
        # categories). When set + non-empty, apply each one. When
        # empty / missing, fall back to the legacy behaviour:
        # classification.category as the label name (with optional
        # ``label_prefix`` prefix).
        cfg = config or {}
        explicit = cfg.get("labels") or []
        labels_to_apply: list[str] = []
        if isinstance(explicit, list):
            labels_to_apply = [str(s) for s in explicit if s]
        if not labels_to_apply:
            fallback = classification.category
            if "label_prefix" in cfg:
                fallback = f"{cfg['label_prefix']}/{fallback}"
            labels_to_apply = [fallback]

        from email_triage.actions.base import record_idempotent_done
        from email_triage.actions.provider_labels import (
            push_provider_labels,
            resolve_label_hipaa,
        )

        # §164.502(e) egress gate (via the provider-label SSOT): in
        # HIPAA mode the classification category is NOT pushed up to the
        # provider mailbox — a PHI-adjacent label string stays inside the
        # perimeter. Same gate AddLabelAction has always had; this action
        # was missing it (divergence census 2026-06-09 #5). The gate
        # input goes through the one resolver so it can't drift.
        hipaa = resolve_label_hipaa(message=message)

        applied, skipped, errors = await push_provider_labels(
            provider, message.message_id, labels_to_apply, hipaa=hipaa,
        )

        def _extras(**more: Any) -> dict[str, Any]:
            return build_action_log_extras(
                flow, message, classification, provider, **more,
            )

        # apply_label is provider-level idempotent, so a crash-recovery
        # rerun re-issues the same apply with no duplicate effect;
        # record_idempotent_done stamps action_results so /flows surfaces
        # the outcome with the same shape other actions use.
        for label in applied:
            logger.info("Label applied", extra=_extras(label=label))
            await record_idempotent_done(
                flow, message, self.name, external_id=label,
            )
        if hipaa and skipped:
            logger.info(
                "Provider labels skipped (HIPAA mode)",
                extra=_extras(skipped=skipped),
            )
        elif skipped:
            logger.info(
                f"Provider {provider.name} does not support labels, skipping",
                **_extras(skipped=skipped),
            )
        for lbl, detail, exc in errors:
            logger.error(
                "Failed to apply label",
                exc_info=exc, extra=_extras(label=lbl, error=detail),
            )
        err_str = "; ".join(f"{lbl}: {detail}" for lbl, detail, _ in errors)

        # Outcome aggregation across the (one or many) label apply
        # attempts. Mirror the single-label behaviour when only one
        # label is in play; surface partial outcomes when multiple.
        if applied and not errors:
            return ActionOutput(
                result=ActionResult.COMPLETED,
                data={
                    "label": applied[0] if len(applied) == 1 else None,
                    "labels": applied,
                },
            )
        if applied and errors:
            # Partial success — count as FAILED so the operator
            # surface flags it, but carry the applied list for audit.
            return ActionOutput(
                result=ActionResult.FAILED,
                error=err_str,
                data={"labels_applied": applied},
            )
        if hipaa and skipped and not applied and not errors:
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "hipaa_mode"},
            )
        if skipped and not applied and not errors:
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": f"Provider '{provider.name}' does not support labels"},
            )
        if errors:
            return ActionOutput(
                result=ActionResult.FAILED,
                error=err_str,
            )
        # All labels skipped + no error + no apply (shouldn't reach
        # here since the fallback always supplies at least one
        # label name).
        return ActionOutput(
            result=ActionResult.SKIPPED,
            data={"reason": "no labels resolved"},
        )
