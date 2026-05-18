"""Move action — move an email to a folder based on its classification.

The target folder is resolved from the action config's ``folder_map``,
which maps category slugs to folder names.  If no mapping exists for the
category, the action is skipped.

Example config (in routes):

    routes:
      invoices:
        actions: [label, move]
        move:
          folder_map:
            invoices: "INBOX.Triage.Invoices"
            to-respond: "INBOX.Triage.To Respond"
          auto_create: true
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

logger = logging.getLogger("email_triage.actions.move")


class MoveAction(Action):
    """Move an email to a folder determined by its classification category."""

    @property
    def name(self) -> str:
        return "move"

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        # PR 6 / C2 — move is *mostly* idempotent (a second
        # ``move_message`` to the same folder is a no-op on most
        # providers), but Gmail-via-IMAP can synthesize a duplicate
        # message in the destination folder if the SOURCE was
        # already removed. Guard.
        from email_triage.actions.base import (
            check_idempotent_already_done, record_idempotent_done,
        )
        prior = check_idempotent_already_done(
            flow, message, self.name,
        )
        if prior is not None:
            return prior

        config = config or {}
        folder_map: dict[str, str] = config.get("folder_map", {})
        auto_create: bool = config.get("auto_create", True)

        folder = folder_map.get(classification.category)

        # Per-call closure: pins the action-specific ``folder`` field
        # into every emission. Delegates the canonical extras shape
        # to ``build_action_log_extras`` (single source of truth at
        # base.py per item #137-adjacent) so the same fields surface
        # on every action log line — owner + account_name + flow id —
        # without each action open-coding the redaction + account-
        # identifier logic.
        def _extras(**more: Any) -> dict[str, Any]:
            return build_action_log_extras(
                flow, message, classification, provider,
                folder=folder, **more,
            )

        if not folder:
            logger.info(
                "No folder mapping for category '%s', skipping move",
                classification.category,
                extra=_extras(),
            )
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": f"No folder mapped for category '{classification.category}'"},
            )

        try:
            # Auto-create folder if enabled AND the folder isn't already
            # visible via list_folders(). Skipping CREATE when the folder
            # already exists avoids the blanket-swallow pattern below that
            # was silently hiding real "can't create" errors (permission,
            # namespace prefix mismatch, server refusal) and letting the
            # subsequent COPY fail with a cryptic "COPY to 'X' failed".
            if auto_create:
                exists = False
                try:
                    folders = await provider.list_folders()
                    exists = folder in folders or folder.lower() in {
                        f.lower() for f in folders
                    }
                except Exception:
                    # list_folders not supported / transient error — fall
                    # through to create-attempt below. Best-effort.
                    pass

                if not exists:
                    try:
                        await provider.create_folder(folder)
                    except NotImplementedError:
                        pass
                    except RuntimeError as create_err:
                        # Only swallow "already exists"-shaped messages.
                        # Everything else (permission, namespace, quota)
                        # is a real problem — log it so the cause is
                        # visible instead of surfacing as an opaque
                        # downstream COPY failure.
                        msg = str(create_err).lower()
                        if "exist" in msg or "duplicate" in msg:
                            pass
                        else:
                            logger.warning(
                                "Folder create failed; continuing to move anyway",
                                extra=_extras(create_error=str(create_err)),
                            )

            await provider.move_message(message.message_id, folder)
            logger.info("Message moved to folder", extra=_extras())
            record_idempotent_done(
                flow, message, self.name, external_id=folder,
            )
            return ActionOutput(
                result=ActionResult.COMPLETED,
                data={"folder": folder},
            )
        except NotImplementedError:
            logger.info(
                "Provider %s does not support move, skipping",
                provider.name,
                extra=_extras(),
            )
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": f"Provider '{provider.name}' does not support moving messages"},
            )
        except Exception as e:
            logger.error("Failed to move message", exc_info=e, extra=_extras())
            return ActionOutput(
                result=ActionResult.FAILED,
                error=fmt_exc(e),
            )
