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
from email_triage._errfmt import fmt_exc

logger = logging.getLogger("email_triage.actions.label")


class LabelAction(Action):
    """Apply the classification category as a label on the email."""

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
        # #163 follow-up — config["labels"] is a list of operator-
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

        applied: list[str] = []
        skipped_unsupported = False
        last_error: Exception | None = None

        from email_triage.actions.base import record_idempotent_done

        for label in labels_to_apply:
            # Per-call closure pins the per-iteration label into
            # every log emission.
            def _extras(**more: Any) -> dict[str, Any]:
                return build_action_log_extras(
                    flow, message, classification, provider,
                    label=label, **more,
                )
            try:
                # apply_label is idempotent on every provider, so
                # we don't gate on prior-run state. record_idempotent
                # _done stamps action_results so /flows surfaces the
                # outcome with the same shape other actions use.
                await provider.apply_label(message.message_id, label)
                logger.info("Label applied", extra=_extras())
                record_idempotent_done(
                    flow, message, self.name, external_id=label,
                )
                applied.append(label)
            except NotImplementedError:
                logger.info(
                    "Provider %s does not support labels, skipping",
                    provider.name,
                    extra=_extras(),
                )
                skipped_unsupported = True
            except Exception as e:
                logger.error(
                    "Failed to apply label",
                    exc_info=e,
                    extra=_extras(),
                )
                last_error = e

        # Outcome aggregation across the (one or many) label apply
        # attempts. Mirror the single-label behaviour when only one
        # label is in play; surface partial outcomes when multiple.
        if applied and last_error is None:
            return ActionOutput(
                result=ActionResult.COMPLETED,
                data={
                    "label": applied[0] if len(applied) == 1 else None,
                    "labels": applied,
                },
            )
        if applied and last_error is not None:
            # Partial success — count as FAILED so the operator
            # surface flags it, but carry the applied list for audit.
            return ActionOutput(
                result=ActionResult.FAILED,
                error=fmt_exc(last_error),
                data={"labels_applied": applied},
            )
        if skipped_unsupported and not applied and last_error is None:
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": f"Provider '{provider.name}' does not support labels"},
            )
        if last_error is not None:
            return ActionOutput(
                result=ActionResult.FAILED,
                error=fmt_exc(last_error),
            )
        # All labels skipped + no error + no apply (shouldn't reach
        # here since the fallback always supplies at least one
        # label name).
        return ActionOutput(
            result=ActionResult.SKIPPED,
            data={"reason": "no labels resolved"},
        )
