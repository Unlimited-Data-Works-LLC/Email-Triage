"""Draft reply action — creates an LLM-generated reply draft.

The draft is created via the email provider (never sent automatically).
This is a safety feature: drafts require human review before sending.

Prompt-prefix order (highest precedence first)
==============================================

The prompt for the draft-reply LLM call is assembled in this canonical
order (wired live in ``DraftReplyAction._generate_body`` ->
``build_prompt_messages``):

    1. M-1+M-2: user-stated style knobs (explicit operator preference)
    2. M-3:     system-derived profile (general voice from past sent mail)
    3. M-7:     HIPAA-safe per-contact overlay (-C; merges the
                per-recipient descriptor on top of the account-level
                direction for HIPAA-flagged accounts only)
    4. M-4:     retrieved few-shot examples (specific examples for THIS draft)
    ───
    5.          The actual draft-reply task message

Knobs come first because the LLM treats later text as a refinement of
earlier text -- explicit user direction is the primary signal, the
inferred profile fills in gaps, the per-contact overlay (HIPAA path)
specialises the direction for the recurring correspondent, and the
few-shot examples ground every abstraction in concrete past replies
that match this incoming email's topic.

A future commit that reorders these layers without intent will break
the order-pinning test in
``tests/test_actions/test_draft_reply_m5_stitch.py`` -- treat that
test as the canonical contract.

Gating
======

Every layer respects three independent toggles:

  * **HIPAA** -- if ``message.hipaa`` or the resolved account is
    HIPAA-flagged, every layer is suppressed and the prompt collapses
    to the bare task message. The toggles are UX surface; the HIPAA
    gate is the privacy guarantee. Defence in depth: M-3 + M-4 each
    re-check this, so a misconfigured caller can't bypass it.
  * **Master toggle** -- ``style_learning:master`` setting. When
    OFF, every layer is suppressed install-wide.
  * **Per-account toggles** -- ``style_learning_enabled`` (M-1+M-2,
    M-3) and ``rag_sent_index_enabled`` (M-4) gate the matching
    layers without affecting the others.
  * **Per-contact sub-toggle (M-7)** --
    ``style_learning_per_contact_enabled`` is a refinement INSIDE the
    M-4 path: when on (default), retrieval narrows to past replies to
    THIS sender first and tops up from the global pool only if fewer
    than top_k matches were found. Has NO effect when M-4 is off.
"""

from __future__ import annotations

import logging
import types
from typing import Any

from email_triage.actions.base import Action
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
)
from email_triage.providers.base import EmailProvider
from email_triage.llm_safety import DATA_FENCE_SECURITY_RULE, fence_data
from email_triage._errfmt import fmt_exc
from email_triage._int_utils import parse_int_or_none  # N-219c/36 R23

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.actions.draft_reply")  # N-196b R21_4


# ---------------------------------------------------------------------------
# RAG gate + prompt builder (M-5)
# ---------------------------------------------------------------------------

# Module-level set used by ``_should_use_rag`` to log the
# "embedding backend missing" warning at most once per (account_id,
# process). The full surface fires on every triage; without this
# guard a misconfigured install would log thousands of identical
# lines per day.
_RAG_BACKEND_WARNED: set[int] = set()


def _should_use_rag(
    db: Any, account: dict | None, app: Any,
) -> bool:
    """Decide whether the M-4 retrieval block should fire.

    Returns False when ANY of the following holds:

      * ``account`` is None (no account context to gate on)
      * the account is HIPAA-flagged (defence in depth -- the
        ``SentMailIndex`` short-circuits HIPAA at every public
        method, but the gate here means we don't even build the
        index instance)
      * the install-wide style-learning master toggle is off
      * the per-account RAG-over-sent-mail toggle is off
      * no embedding backend is configured on ``app.state``
        (operator hasn't set up ``embedding:`` in YAML)

    A missing embedding backend is logged once per (account_id,
    process) at INFO level -- subsequent calls return False
    silently.
    """
    if account is None:
        return False

    # Defence in depth: HIPAA gate first. The toggles below are an
    # operator UX surface; the HIPAA gate is the privacy guarantee.
    from email_triage.triage_logging import is_account_hipaa
    if is_account_hipaa(account):
        return False

    account_id_raw = account.get("id") if isinstance(account, dict) else None
    account_id = parse_int_or_none(account_id_raw)  # N-219c/36 R23: SSOT (None input → None; non-numeric → None)
    if account_id is None:
        return False

    # Toggle gates.
    try:
        from email_triage.web.db import (
            is_rag_sent_index_enabled,
            is_style_learning_master_enabled,
        )
    except Exception:
        # Imports failing means the web layer isn't loaded; treat
        # as toggles off so non-web callers (CLI / tests) get the
        # safe default.
        return False

    try:
        if not is_style_learning_master_enabled(db):
            return False
        if not is_rag_sent_index_enabled(db, account_id):
            return False
    except Exception:
        # DB error during the gate read = fail closed.
        return False

    # Embedding backend wired?
    backend = getattr(app, "state", None)
    backend = getattr(backend, "embedding_backend", None) if backend else None
    if backend is None:
        if account_id not in _RAG_BACKEND_WARNED:
            _RAG_BACKEND_WARNED.add(account_id)
            logger.info(
                "RAG enabled but no embedding backend configured "
                "-- skipping retrieval",
                extra={"account_id": account_id},
            )
        return False

    return True


def _query_text_for_retrieval(message: EmailMessage) -> str:
    """Build the embedding query string for similar-reply retrieval.

    Concatenates subject + first paragraph of the incoming body. We
    deliberately avoid sending the full body -- the first paragraph
    captures the topic well enough for cosine matching against past
    replies, and short query texts mean fewer tokens spent on the
    embedder.
    """
    subject = (message.subject or "").strip()
    body = (message.body_text or "").strip()
    # First paragraph = up to first blank line, max ~500 chars.
    first_para = body.split("\n\n", 1)[0] if body else ""
    if len(first_para) > 500:
        first_para = first_para[:500]
    parts = [p for p in (subject, first_para) if p]
    return "\n\n".join(parts).strip()


async def build_prompt_messages(
    *,
    db: Any,
    app: Any,
    account: dict | None,
    user_id: int | None,
    message: EmailMessage,
    classification: Classification,
    from_address: str | None = None,
) -> list[dict]:
    """Assemble the LLM-message list for a draft-reply call.

    Returns a list of ``{"role": "...", "content": "..."}`` dicts in
    the canonical M-1+M-2 / M-3 / M-4 / user-task order.

    Layer 1 (M-1+M-2): a single ``system`` message with the user-
    stated style knobs prefix.
    Layer 2 (M-3): appended to the same ``system`` message when the
    derived profile is present (the helper already stacks them via
    :func:`build_style_prompt_prefix`).
    Layer 3 (M-4): zero or more ``user`` / ``assistant`` turn pairs
    representing past similar replies. Each pair is one example.
    Layer 4: a final ``user`` message asking the LLM to draft a
    reply to this incoming email.

    Each layer is independently gateable -- HIPAA suppresses every
    layer; the master toggle does the same; per-account toggles
    affect only their matching layer.
    """
    from email_triage.actions.style_profile import (
        build_style_prompt_prefix,
    )
    from email_triage.web.db import (
        get_global_anti_ai_style_guide,
        get_style_profile,
        get_user_anti_ai_style_guide,
        get_user_style_knobs,
        is_style_knobs_hipaa_allow,
        is_style_learning_account_enabled,
        is_style_learning_master_enabled,
    )
    from email_triage.web.db_threadpool import db_call
    from email_triage.triage_logging import is_account_hipaa

    #  — build_prompt_messages is awaited from DraftReplyAction.
    # execute, which runs on the event-loop thread. Every shared-
    # connection read below hops to the threadpool via db_call.
    hipaa = bool(getattr(message, "hipaa", False)) or (
        account is not None and is_account_hipaa(account)
    )
    try:
        master_enabled = await db_call(is_style_learning_master_enabled, db)
    except Exception:
        master_enabled = False
    try:
        account_enabled = is_style_learning_account_enabled(account)
    except Exception:
        account_enabled = False

    # ---- Layers 1 + 2: M-1+M-2 knobs and M-3 profile ------------------
    knobs = None
    profile = None
    account_id = None
    if account is not None and isinstance(account, dict):
        account_id = parse_int_or_none(account.get("id"))  # N-219c/36 R23: SSOT
    try:
        knobs = (
            await db_call(get_user_style_knobs, db, user_id)
            if user_id else None
        )
    except Exception:
        knobs = None
    try:
        profile = (
            await db_call(get_style_profile, db, account_id)
            if account_id else None
        )
    except Exception:
        profile = None

    # Punch list  — when alias-aware learning is on for this
    # account, swap the account-wide descriptor for the one matching
    # the From-address the reply will use. Fallback chain:
    # alias-specific → primary → account-wide → no prefix.
    if account_id is not None:
        try:
            from email_triage.web.db import (
                account_email,
                is_alias_mode_enabled_for_account,
                list_account_style_per_alias,
                normalise_from_address,
            )
            if await db_call(is_alias_mode_enabled_for_account, db, account_id):
                from email_triage.actions.style_profile import (
                    StyleProfile as _SP,
                    resolve_alias_profile,
                )
                rows = await db_call(
                    list_account_style_per_alias, db, account_id,
                )
                alias_profiles: dict[str, _SP] = {}
                for r in rows:
                    try:
                        alias_profiles[r["from_address"]] = (
                            _SP.from_dict(r["descriptor"])
                        )
                    except Exception:
                        continue
                primary_norm = normalise_from_address(
                    account_email(account) if account else None,
                )
                effective_from = normalise_from_address(
                    from_address if from_address else (
                        account_email(account) if account else ""
                    ),
                )
                profile = resolve_alias_profile(
                    from_address=effective_from,
                    alias_profiles=alias_profiles,
                    primary_address=primary_norm,
                    account_profile=profile,
                )
        except Exception as exc:
            # Any failure on the alias-resolution path falls through
            # to the account-wide descriptor we already loaded; the
            # alias feature is additive and must never break drafting.
            logger.warning(
                "draft_reply: alias profile resolution failed; using account descriptor",
                error=fmt_exc(exc),
            )

    #  Phase 2: per-account opt-in to render M-1+M-2 (operator-
    # typed style knobs) on HIPAA-flagged accounts. Default False —
    # operator must explicitly tick the "Allow my own writing-style
    # preferences for this HIPAA-flagged account" checkbox on
    # /accounts/<id>/edit. M-3 / M-4 / M-7 stay hard-off regardless.
    m1m2_hipaa_allow = False
    if hipaa and account_id is not None:
        try:
            m1m2_hipaa_allow = await db_call(
                is_style_knobs_hipaa_allow, db, account_id,
            )
        except Exception:
            # Read failure = fall back to hard-off; the privacy bias is
            # "more redaction, never less" per internal documentation.
            m1m2_hipaa_allow = False

    # Anti-AI style guide (install-wide + per-user). Same shape as the
    # M-1+M-2 knobs — operator-typed text, no PHI inputs by
    # construction. The HIPAA gate inside ``build_style_prompt_prefix``
    # piggybacks on the M-1+M-2 ``m1m2_hipaa_allow`` opt-in so a
    # HIPAA-flagged account without the opt-in continues to see an
    # empty prefix.
    anti_ai_global = ""
    anti_ai_user = ""
    anti_ai_disable_global = False
    try:
        anti_ai_global = await db_call(get_global_anti_ai_style_guide, db)
    except Exception:
        anti_ai_global = ""
    try:
        anti_ai_user, anti_ai_disable_global = await db_call(
            get_user_anti_ai_style_guide, db, user_id,
        )
    except Exception:
        anti_ai_user, anti_ai_disable_global = ("", False)

    # ---- M-7 per-contact HIPAA overlay -----------------------
    # The M-7 draft-time consumer merges per-recipient HIPAA-safe
    # overlay descriptors on top of the account-level direction. Gate:
    # only fire for HIPAA-flagged accounts AND when the style-learning
    # master toggle + per-account toggle are both on. Non-HIPAA
    # accounts have a separate (plaintext-recipient) per-contact path
    # via the M-4 RAG layer; the HIPAA path is the describe-and-discard
    # pipeline whose overlay lives in ``per_contact_style_hipaa``.
    hipaa_contact_overlay: dict | None = None
    if (
        hipaa
        and master_enabled
        and account_enabled
        and account_id is not None
    ):
        try:
            from email_triage.style_learning.per_contact_hipaa import (
                merge_overlays_for_recipients,
            )
            from email_triage.mail_headers import _extract_addr
            secrets_provider = getattr(
                getattr(app, "state", None), "secrets", None,
            )
            # Reply To: addresses = the From: of the inbound message.
            # CC handling is not in scope for the overlay layer (the
            # per-contact descriptor was trained on a single
            # recipient corpus). We use the bare ``sender`` as the
            # canonical address to look up.
            recipient_addrs: list[str] = []
            sender_bare = _extract_addr(message.sender or "")
            if sender_bare:
                recipient_addrs.append(sender_bare)
            if secrets_provider is not None and recipient_addrs:
                #  — merge_overlays_for_recipients reads the shared
                # connection; dispatch it off the event loop via
                # db_call (consistent with every other DB read in this
                # async builder).
                merged_overlay, recipient_hashes = (
                    await db_call(
                        merge_overlays_for_recipients,
                        db, account_id, recipient_addrs,
                        secrets=secrets_provider,
                    )
                )
                if merged_overlay is not None and recipient_hashes:
                    hipaa_contact_overlay = merged_overlay
                    # Audit log — HASH only, never plaintext. The
                    # event name is the canonical handle for grep +
                    # log-search ("did the M-7 overlay actually fire
                    # for this draft?").
                    logger.info(
                        "m7_overlay_applied",
                        extra={
                            "account_id": account_id,
                            "recipient_hashes": list(recipient_hashes),
                            "recipient_count": len(recipient_hashes),
                            "overlay_fields": sorted(
                                merged_overlay.keys()
                            ),
                        },
                    )
        except Exception as exc:
            # M-7 is additive. Any failure on the overlay path falls
            # back to the no-overlay default; never let it break a
            # draft. Captured in INFO (not ERROR) because the layer
            # is best-effort.
            logger.info(
                "m7_overlay_skipped",
                extra={
                    "account_id": account_id,
                    "error_type": type(exc).__name__,
                },
            )
            hipaa_contact_overlay = None

    style_prefix = build_style_prompt_prefix(
        knobs, profile,
        hipaa=hipaa,
        master_enabled=master_enabled,
        account_enabled=account_enabled,
        m1m2_hipaa_allow=m1m2_hipaa_allow,
        anti_ai_global=anti_ai_global,
        anti_ai_user=anti_ai_user,
        anti_ai_disable_global=anti_ai_disable_global,
        hipaa_contact_overlay=hipaa_contact_overlay,
    )

    messages: list[dict] = []
    if style_prefix:
        messages.append({"role": "system", "content": style_prefix})

    # ---- Layer 3: M-4 retrieval ---------------------------------------
    # The gate inside ``_should_use_rag`` re-checks HIPAA + the master
    # + per-account toggle + the presence of an embedding backend on
    # app.state. A False here means we cleanly skip the layer.
    #  — _should_use_rag reads the shared connection (the toggle
    # gates); dispatch it through db_call so the read runs off the
    # event loop under the process-wide DB lock.
    if await db_call(_should_use_rag, db, account, app):
        try:
            from email_triage.actions.sent_mail_index import SentMailIndex
        except Exception:
            SentMailIndex = None  # type: ignore

        if SentMailIndex is not None and account_id is not None:
            try:
                index = SentMailIndex(
                    db, account_id,
                    embedding_backend=app.state.embedding_backend,
                    embedding_model=getattr(
                        app.state, "embedding_model", "",
                    ),
                    sqlite_vec_available=bool(
                        getattr(app.state, "sqlite_vec_available", False)
                    ),
                )
                query_text = _query_text_for_retrieval(message)
                # M-7: if the per-contact sub-toggle is on, pass the
                # incoming sender's bare address (display-name stripped,
                # case-folded) so retrieval prefers past replies to
                # THIS person. The helper falls back to the global
                # pool when fewer than top_k per-contact rows match.
                contact_address: str | None = None
                try:
                    from email_triage.web.db import (
                        is_style_learning_per_contact_enabled,
                    )
                    if is_style_learning_per_contact_enabled(account):
                        from email_triage.mail_headers import _extract_addr
                        addr = _extract_addr(message.sender or "")
                        contact_address = addr or None
                except Exception:
                    # Per-contact filter is a refinement; on any error
                    # we fall through to the legacy global path so the
                    # operator still gets RAG-ranked examples.
                    contact_address = None
                examples = await index.retrieve_similar(
                    query_text=query_text,
                    top_k=5,
                    contact_address=contact_address,
                )
            except Exception as exc:
                logger.warning(
                    "M-4 retrieval failed; continuing without examples",
                    extra={
                        "error_type": type(exc).__name__,
                        "account_id": account_id,
                    },
                )
                examples = []

            # Each retrieved example becomes a user/assistant turn
            # pair: the past inbound (we don't have it, so we pass a
            # short context line built from subject) and the user's
            # past sent reply (the body excerpt).
            for ex in examples:
                # Skip empty / malformed entries defensively.
                excerpt = (ex.get("excerpt") or "").strip()
                if not excerpt:
                    continue
                past_subject = (ex.get("subject") or "").strip()
                # The "user turn" stub names the past topic; the
                # "assistant turn" is the actual past reply body.
                # Keep the user turn short -- the LLM cares mostly
                # about the assistant turn (the user's voice).
                user_stub = (
                    f"Previous incoming email (subject: {past_subject})"
                    if past_subject else
                    "Previous incoming email"
                )
                messages.append({"role": "user", "content": user_stub})
                messages.append({"role": "assistant", "content": excerpt})

    # ---- Layer 4: the actual task message ----------------------------
    # The whole incoming email — subject, sender AND body — is
    # attacker-controlled, so it is wrapped in ONE closed, sanitized DATA
    # fence (mirrors classify.prompts.build_email_block). Only our own
    # framing and the classifier's closed-vocab category slug sit outside
    # the fence. The RAG few-shot turns (Layer 3) are the operator's own past
    # sent mail rendered as assistant-role voice examples — deliberately NOT
    # fenced (fencing them would defeat their few-shot purpose, and an
    # assistant-role turn can't carry a data fence). Note the residual: the
    # excerpt is quoted-inbound-stripped at index time (``_strip_quoted`` in
    # sent_mail_index.py), a heuristic — an imperfect strip could leave a
    # sliver of inbound text in the high-trust assistant position. Bounded
    # (self-poisoning of one's own corpus, not live inbound injection) and
    # accepted, since fencing is structurally impossible here.
    # The treat-as-data security rule rides INSIDE this task message, right
    # before the fenced email — so it travels with the data it governs and
    # is present on EVERY path, including the HIPAA path where the style
    # system prefix is suppressed and this user message is the only one. The
    # HIPAA contract ("prompt collapses to a single user task message") is
    # preserved precisely because the rule lives here, not in a separate
    # system turn.
    email_block = "\n".join([
        f"Subject: {message.subject or '(no subject)'}",
        f"From: {message.sender}",
        "",
        message.body_text or "(no body)",
    ])
    task = (
        DATA_FENCE_SECURITY_RULE
        + "\n\n"
        + f"Draft a reply to the following email. "
        + f"Classification: {classification.category}.\n\n"
        + fence_data(email_block)
    )
    messages.append({"role": "user", "content": task})
    return messages


# ---------------------------------------------------------------------------
# Draft runtime (process-singleton fallback)
# ---------------------------------------------------------------------------
# build_prompt_messages needs an ``app`` (for app.state.embedding_backend on
# the non-HIPAA RAG path) and load_backend needs the install ``config`` -- but
# the action layer reaches neither directly (it only gets ``flow.state_bag``).
# Rather than thread app.state through all 8 TriageContext constructors + both
# dispatch paths, register these process-singletons ONCE at web-app startup
# (web/app.py) and resolve them here. state_bag values take precedence, so the
# triage_one path (which carries the per-run config) still wins.
_DRAFT_RUNTIME: dict[str, Any] = {}


def register_draft_runtime(
    *,
    config: Any = None,
    embedding_backend: Any = None,
    embedding_model: str = "",
    sqlite_vec_available: bool = False,
) -> None:
    """Stash the process-wide draft runtime (called once at app startup)."""
    _DRAFT_RUNTIME["config"] = config
    _DRAFT_RUNTIME["embedding_backend"] = embedding_backend
    _DRAFT_RUNTIME["embedding_model"] = embedding_model or ""
    _DRAFT_RUNTIME["sqlite_vec_available"] = bool(sqlite_vec_available)


def _resolve_draft_runtime(state_bag: dict) -> tuple[Any, Any]:
    """Return ``(config, app_like)`` for body generation.

    ``config`` comes from ``state_bag['config']`` (the per-run config on the
    triage_one path), falling back to the process singleton. ``app_like``
    exposes ``.state.embedding_backend`` etc. -- the real ``app`` if state_bag
    carries one, else a shim from the registered singletons (HIPAA accounts
    skip RAG, so the embedding backend is only consulted for non-HIPAA).
    """
    sb = state_bag or {}
    config = sb.get("config") or _DRAFT_RUNTIME.get("config")
    app = sb.get("app")
    if app is None:
        app = types.SimpleNamespace(
            state=types.SimpleNamespace(
                embedding_backend=_DRAFT_RUNTIME.get("embedding_backend"),
                embedding_model=_DRAFT_RUNTIME.get("embedding_model", ""),
                sqlite_vec_available=_DRAFT_RUNTIME.get(
                    "sqlite_vec_available", False,
                ),
            ),
        )
    return config, app


# ---------------------------------------------------------------------------
# DraftReplyAction
# ---------------------------------------------------------------------------

class DraftReplyAction(Action):
    """Create a draft reply to the email via the provider.

    Generates the reply body with the local LLM -- the M-1..M-7 style
    prompt (:func:`build_prompt_messages`) through the install-default
    backend (:func:`load_backend`) -- threaded back into the original
    conversation, never sent. Fails CLOSED (no draft) on a BAA/secret
    error; degrades to a safe static placeholder only on a non-security
    generation failure (the one permitted, non-decisional fail-open).
    """

    @property
    def name(self) -> str:
        return "draft_reply"

    _DRAFT_MAX_TOKENS = 1024

    @staticmethod
    def _placeholder_body(classification: Classification) -> str:
        """The pre-LLM safe fallback -- non-PHI, only the category slug."""
        return (
            f"[Auto-drafted reply for {classification.category} email]\n\n"
            f"This is a draft reply. Please review and edit before sending."
        )

    @staticmethod
    def _acct_field(account: Any, key: str) -> Any:
        """Read ``key`` from an account dict OR sqlite3.Row OR object."""
        if account is None:
            return None
        if isinstance(account, dict):
            return account.get(key)
        try:
            return account[key]
        except (KeyError, IndexError, TypeError):
            return getattr(account, key, None)

    async def _generate_body(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
    ) -> str:
        """Generate the reply body with the local LLM.

        Fail-CLOSED on a BAA / secret error (re-raise -> the action FAILs, no
        draft). Degrade to the safe placeholder on a non-security generation
        failure (timeout / empty / unwired runtime) -- the one permitted fail-
        OPEN (non-decisional render degradation; every draft is human-reviewed).
        """
        from email_triage.triage_logging import account_hipaa_effective
        from email_triage.web.db_threadpool import db_call
        from email_triage.ai_backends.base import (
            BackendBAARequiredError,
            BackendError,
        )
        from email_triage.ai_backends.loader import load_backend

        sb = flow.state_bag or {}
        db = sb.get("db")
        account = sb.get("account")
        secrets = sb.get("secrets")
        actor_user_id = sb.get("actor_user_id")
        config, app = _resolve_draft_runtime(sb)

        if db is None or config is None:
            logger.info(
                "draft_reply: runtime unwired; using placeholder body",
                extra={
                    "flow_id": flow.flow_id,
                    "have_db": db is not None,
                    "have_config": config is not None,
                },
            )
            return self._placeholder_body(classification)

        # SSOT HIPAA verdict (account_hipaa_effective, PD#8 / N-77) — drives
        # BOTH the PHI-egress gate and the audit trigger, so it must be the SSOT
        # (covers the message.hipaa axis + the account-None edge), not the
        # weaker is_account_hipaa. Prefer the verdict already resolved upstream
        # (triage_one plants it in state_bag); fall back to recomputing it.
        hipaa = sb.get("account_hipaa")
        if hipaa is None:
            hipaa = account_hipaa_effective(account=account, message=message)
        hipaa = bool(hipaa)
        owner_id = self._acct_field(account, "user_id")
        account_id = self._acct_field(account, "id")
        from_address = sb.get("self_email") or None

        # Build the style-aware prompt. On HIPAA this collapses to the single
        # DATA-fenced task message (style prefix suppressed, M-4 RAG hard-off);
        # non-HIPAA layers M-1..M-4.
        messages = await build_prompt_messages(
            db=db,
            app=app,
            account=account,
            user_id=owner_id,
            message=message,
            classification=classification,
            from_address=from_address,
        )

        # Resolve the install-default (local Ollama) adapter. require_baa_
        # certified=hipaa so a HIPAA account whose default endpoint is non-
        # local + unacked REFUSES rather than egress PHI.
        try:
            adapter = await db_call(
                load_backend,
                None,
                db_conn=db,
                secrets=secrets,
                config=config,
                require_baa_certified=hipaa,
            )
        except BackendBAARequiredError:
            logger.error(
                "draft_reply: refusing draft -- backend BAA not satisfied for "
                "a HIPAA account (fail-closed; no draft created)",
                extra={"flow_id": flow.flow_id},
            )
            raise
        except BackendError as be:
            # Non-BAA backend-resolution failure: the adapter was never built,
            # so NO PHI egressed. Degrade to the safe non-PHI placeholder (the
            # permitted non-decisional fail-open) on HIPAA and non-HIPAA alike —
            # refusing here would block drafting on a transient/config error for
            # zero PHI-safety gain. The genuine egress boundary is
            # BackendBAARequiredError above (refused, not degraded).
            logger.warning(
                "draft_reply: backend resolution failed; placeholder body",
                extra={
                    "flow_id": flow.flow_id,
                    "error_type": type(be).__name__,
                },
            )
            return self._placeholder_body(classification)

        # HIPAA PHI-access audit: the draft-gen reads inbound PHI. The
        # actor!=owner predicate is the shared SSOT (phi_access_audit_required:
        # owner self-draft exempt, NOT actor!=null — PD-5/PD-14). Routed through
        # the emitter SSOT (HMAC chain), body-text-free, emitted BEFORE the LLM
        # hop so the access is recorded even if generation then fails. A failure
        # here propagates (fail-closed: no audit -> no draft).
        from email_triage.db.audit import (
            phi_access_audit_required,
            record_hipaa_access_event,
        )
        if account_id is not None and phi_access_audit_required(
            account_hipaa=hipaa,
            actor_user_id=actor_user_id,
            owner_id=owner_id,
        ):
            await db_call(
                record_hipaa_access_event,
                db,
                actor_user_id,
                int(account_id),
                "draft_reply_generate",
                outcome="ok",
            )

        try:
            body_text = await adapter.chat_complete(
                messages, max_tokens=self._DRAFT_MAX_TOKENS,
            )
        except Exception as ce:
            # NOTE (hipaa-sme 2026-06-19): this broad catch -> placeholder is
            # the ONE permitted fail-OPEN, and it is SAFE only because the
            # install-default backend is LOCAL + keyless (no secret/key error
            # is reachable inside chat_complete here). If a KEYED / non-local
            # backend is ever wired for HIPAA draft-gen, NARROW this catch to
            # let a typed secret/key error PROPAGATE (fail-closed) rather than
            # degrade to a placeholder.
            logger.warning(
                "draft_reply: LLM generation failed; placeholder body",
                extra={
                    "flow_id": flow.flow_id,
                    "error_type": type(ce).__name__,
                },
            )
            return self._placeholder_body(classification)

        body_text = (body_text or "").strip()
        if not body_text:
            return self._placeholder_body(classification)
        return body_text

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        # PR 6 / C2 — guard the provider mutation. Without this, a
        # /flows/<id>/retry of a flow that already drafted a reply
        # creates a SECOND draft in the user's mailbox (Gmail
        # users.messages.send is happily non-idempotent at the API
        # surface). The skip path leaves the prior draft intact.
        from email_triage.actions.base import (
            check_idempotent_already_done, record_idempotent_done,
        )
        prior = await check_idempotent_already_done(
            flow, message, self.name,
        )
        if prior is not None:
            logger.info(
                "Draft already created for this flow + message; skipping",
                extra={
                    "flow_id": flow.flow_id,
                    "previous_draft_id": prior.data.get(
                        "previous_external_id",
                    ),
                },
            )
            return prior

        try:
            from email_triage.mail_headers import (
                X_EMAIL_TRIAGE_DRAFT_BODY_HEADER,
                X_EMAIL_TRIAGE_HEADER,
                build_triage_header,
                encode_draft_body_header,
            )
            # N-01 REOPENED at the LLM-draft landing (hipaa-sme RULING 2,
            # 2026-06-19; internal documentation CR-01 7.4). The
            # draft body below is now LLM-GENERATED (no longer static): PHI
            # flows incoming-message -> prompt -> local Ollama -> generated
            # body -> state_bag['action_results']. Disposition (re-walked,
            # hipaa-sme): reply-drafting is a 164.502 USE within the owner's
            # existing authorization (the owner holds the inbound message;
            # the draft returns to the same correspondent; the LLM hop is
            # local-only) -- NOT a new disclosure. Controls in _generate_body:
            # encrypt-at-rest EM affirmed for action_results (SQLCipher/
            # EQM-08); actor!=owner PHI-access audit; fail-CLOSED on BAA/
            # secret error. HIPAA prompts carry NO verbatim few-shot (the M-4
            # index is HIPAA-hard-off); the M-3/M-7 signal is the closed-
            # vocab, Safe-Harbor-scrubbed descriptor only.
            draft_body = await self._generate_body(
                flow, message, classification,
            )
            # Account name isn't threaded to actions; pull from state_bag
            # when the runner plants it, otherwise leave empty (the
            # header is still required for the inbound skip to fire).
            account_name = ""
            try:
                account_name = str(flow.state_bag.get("account_name", "") or "")
            except Exception:
                account_name = ""
            stamp = build_triage_header(
                "draft-reply",
                category=classification.category,
                account=account_name,
                hipaa=bool(getattr(message, "hipaa", False)),
            )
            # M-6 edit-feedback capture loop: stamp a base64-encoded
            # snapshot of the AI-drafted body so that when the user
            # edits + sends, the M-6 scanner can compare draft vs sent.
            extra: dict[str, str] = {X_EMAIL_TRIAGE_HEADER: stamp}
            # MUST-FIX (hipaa-sme 2026-06-19, CR-02): the draft body is now
            # LLM-GENERATED, so the M-6 base64 snapshot is a PHI duplicate in
            # message metadata. The M-6 scanner is hard-OFF for HIPAA, so on a
            # HIPAA account this header would carry PHI with ZERO consumer
            # benefit -- a 164.502(b) minimum-necessary violation (and X-*
            # headers travel / log / raw-source-view differently than the
            # body). SUPPRESS it on HIPAA; the non-PHI X-Email-Triage
            # loop-prevention stamp above still rides so the inbound skip fires.
            from email_triage.triage_logging import is_account_hipaa
            _hdr_hipaa = is_account_hipaa(
                flow.state_bag.get("account")
            ) or bool(getattr(message, "hipaa", False))
            if not _hdr_hipaa:
                try:
                    draft_body_header = encode_draft_body_header(draft_body)
                    if draft_body_header:
                        extra[X_EMAIL_TRIAGE_DRAFT_BODY_HEADER] = draft_body_header
                except Exception as enc_exc:
                    # Encoding failure should never poison draft creation.
                    # Log + continue without the M-6 capture header; the
                    # outbound draft still ships with X-Email-Triage so
                    # the loop-prevention skip still fires.
                    logger.warning(
                        "M-6 draft-body header encode failed; continuing",
                        extra={
                            "flow_id": flow.flow_id,
                            "error_type": type(enc_exc).__name__,
                        },
                    )
            # 2026-05-13 — In-Reply-To must be the RFC 5322
            # Message-Id; IMAP UID would silently break threading.
            # A6 (census 2026-06-09): header-then-provider-id = SSOT.
            from email_triage.mail_headers import get_message_rfc_id
            _rfc_id = get_message_rfc_id(message)
            draft_id = await provider.create_draft(
                to=[message.sender],
                subject=f"Re: {message.subject}",
                body=draft_body,
                in_reply_to=_rfc_id,
                thread_id=message.thread_id,
                extra_headers=extra,
            )
            logger.info(
                "Draft created",
                extra={"flow_id": flow.flow_id, "draft_id": draft_id},
            )
            await record_idempotent_done(
                flow, message, self.name,
                external_id=str(draft_id) if draft_id is not None else None,
            )
            return ActionOutput(
                result=ActionResult.COMPLETED,
                data={"draft_id": draft_id},
            )
        except NotImplementedError:
            logger.info(
                "Provider does not support drafts, skipping",
                extra={"flow_id": flow.flow_id, "provider": provider.name},
            )
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": f"Provider '{provider.name}' does not support drafts"},
            )
        except Exception as e:
            logger.error(
                "Failed to create draft",
                exc_info=e,
                extra={"flow_id": flow.flow_id},
            )
            return ActionOutput(
                result=ActionResult.FAILED,
                error=fmt_exc(e),
            )


__all__ = [
    "DraftReplyAction",
    "build_prompt_messages",
    "_should_use_rag",
]
