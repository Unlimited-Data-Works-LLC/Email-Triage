"""Per-account vector index of sent mail (M-4 scaffold).

Indexes the user's own sent messages so the draft-reply path can pull
the most-similar past replies as few-shot examples for the AI prompt
builder. This module ships ONLY the storage + helpers + privacy
invariants -- the wiring into ``actions/draft_reply.py`` lives in
M-5 (the next the backlog item) and is intentionally not done here.

Design choices captured here so M-5 doesn't have to re-derive them:

* **Schema lives in ``sent_mail_index`` (migration v12).** Keys are
  ``(account_id, rfc_message_id)`` so re-indexing the same logical
  message is a no-op even when the provider re-emits a new
  ``message_id`` (Gmail can re-shape ids across folder moves).
* **Vectors are packed float32 BLOBs.** ``struct.pack("Nf", ...)`` is
  ~3-4x smaller than json-as-text and avoids JSON parsing overhead
  on the hot retrieval path.
* **HIPAA short-circuits at every public method.** Retrieval over
  PHI requires a BAA + an external-vector-search audit story we
  don't have; the cleanest gate is "M-4 is hard-off on HIPAA-flagged
  accounts, full stop". Defence-in-depth: the migration redacts
  subject + body_excerpt at write time too, so the rebuild path
  on a flipped account leaves no reconstructable PHI.
* **Embedding backend is local-only.** Sending the user's sent mail
  to a remote embedding service is a privacy regression vs M-3
  (which sends one summary only). The ``__init__`` allowlist
  refuses non-local backends with a clear error -- future remote
  backends require an explicit BAA-gate review.
* **sqlite-vec is opt-in.** When the extension fails to load
  (Python sqlite3 built without ``--enable-loadable-sqlite-extensions``
  on most distros), retrieval falls back to in-memory cosine over
  the rows in ``sent_mail_index`` for this account. Performance
  matters less in the fallback path because the corpus is one
  user's sent mail, capped by the operator-tunable index size.

Privacy contract reaffirmed
===========================

The corpus is the user's own sent mail. The only thing that
crosses the trust boundary in this module is:

1. Plaintext bodies -> local embedding backend (Ollama).
2. Vectors stored at rest in the install's SQLite DB.
3. A small dict (sender / to / subject / excerpt / score) returned
   to the M-5 prompt builder for in-process use.

No outbound network call beyond the embedding step. No fan-out to
external vector stores. No remote embedding backend.
"""

from __future__ import annotations

from email_triage._int_utils import parse_int_or_none  # N-219c/31 R23
from email_triage.db._helpers import dump_json_col, load_json_col  # N-186 R20_10

import json
import math
import sqlite3
import struct
from typing import Any, Iterable, Protocol

import numpy as np

from email_triage.engine.models import EmailMessage
from email_triage.triage_logging import REDACTED, get_logger, is_account_hipaa
from email_triage.web.db_writelock import get_write_lock
from email_triage._dbapi_errors import DB_ERRORS

log = get_logger("actions.sent_mail_index")


# ---------------------------------------------------------------------------
# Embedding backend protocol
# ---------------------------------------------------------------------------

class EmbeddingBackend(Protocol):
    """Minimum surface this module needs from an LLM-side backend.

    The existing :class:`email_triage.classify.base.Classifier`
    protocol does NOT include an ``embed_text`` method (its remit is
    classification + raw completion). Rather than bolt embeddings
    onto every classifier subclass, we declare a tiny Protocol here
    so backends that DO speak embeddings (Ollama via
    ``/api/embeddings``) can be passed in directly and the rest of
    the codebase doesn't need to change.

    M-4 ships the contract; M-5 picks the concrete backend at draft
    time via the existing classifier-config plumbing.
    """

    backend_type: str
    """Short string identifier used by the local-only allowlist
    check. Concrete backends set this to one of ``_LOCAL_BACKENDS``
    (currently just ``"ollama"``)."""

    async def embed_text(self, text: str) -> list[float]:
        """Embed ``text`` and return a list of floats."""


# Backends that may receive sent-mail bodies. Adding a non-local
# backend here is a privacy decision and requires a separate review.
# Keeping this as a module-level constant (not a config flag) is
# deliberate: an operator who flips a "send my sent mail to
# OpenAI" toggle in the YAML shouldn't be able to bypass the
# allowlist by editing config.
_LOCAL_BACKENDS: tuple[str, ...] = (
    "ollama",
    # In-process CPU embedder. No network hop, no GPU contention.
    # Added 2026-05-13 — needed when the install's primary chat
    # model overflows GPU VRAM and a co-resident embedder would
    # thrash. See engine/embedding_backend.py:SentenceTransformersBackend.
    "sentence_transformers",
    # No composite "fallback" type (punch 552 / N-555): the chain that
    # embedded with a second model when the first failed was removed,
    # so a failed embed reaches this module's callers instead.
)

# M-6 ranking multiplier for captured edit-feedback pairs (AI drafted,
# user edited + sent). Captured rows multiply their cosine by this
# value at ranking time so they surface ahead of equivalent general
# sent-mail rows. 1.3 is intentionally modest -- a captured pair on
# a different topic still loses to a general row that's a tighter
# topical match.
_CAPTURED_PAIR_BOOST: float = 1.3


class NonLocalBackendError(ValueError):
    """Raised when SentMailIndex is constructed with a non-local backend.

    M-4 ships local-only by design (see module docstring). The error
    text names the rule + the rejected backend so the operator's log
    surface tells them what to do.
    """


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def _pack_vec(vec: list[float]) -> bytes:
    """Pack a float vector to a compact little-endian float32 blob.

    Empty vector -> empty bytes (helper sites treat empty as
    "embedding not available", same as a NULL row).
    """
    if not vec:
        return b""
    return struct.pack(f"<{len(vec)}f", *vec)


def _unpack_vec(blob: bytes | None) -> list[float]:
    """Inverse of :func:`_pack_vec`. Tolerant of None / empty."""
    if not blob:
        return []
    n, rem = divmod(len(blob), 4)
    if rem:
        # Corrupt row -- treat as missing rather than crashing the
        # whole retrieval path.
        log.warning(
            "sent_mail_index: unaligned vec blob, skipping",
            blob_len=len(blob),
        )
        return []
    return list(struct.unpack(f"<{n}f", blob))


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity. Returns 0.0 on empty or zero-length inputs."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    denom = math.sqrt(na) * math.sqrt(nb)
    if denom <= 0.0:
        return 0.0
    return dot / denom


def _now_iso() -> str:
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


def _strip_quoted(body: str) -> str:
    """Reuse the quote-stripper from the M-3 module to keep a single
    source of truth for "what is the user's own writing in this body".
    """
    from email_triage.actions.style_profile import _strip_quoted as _sp_strip
    return _sp_strip(body)


# ---------------------------------------------------------------------------
# SentMailIndex
# ---------------------------------------------------------------------------

class SentMailIndex:
    """Per-account index of the user's sent mail for RAG retrieval.

    Construction is cheap (no IO). The first call to a public method
    short-circuits when the account is HIPAA-flagged. The provider
    + concrete embedding-backend wiring is supplied by the caller --
    this class stays a pure storage + similarity primitive.
    """

    def __init__(
        self,
        db: sqlite3.Connection,
        account_id: int,
        *,
        embedding_backend: EmbeddingBackend,
        embedding_model: str,
        provider: Any | None = None,
        sqlite_vec_available: bool = False,
        sent_folders: list[str] | None = None,
    ) -> None:
        backend_type = getattr(embedding_backend, "backend_type", "")
        if backend_type not in _LOCAL_BACKENDS:
            raise NonLocalBackendError(
                f"M-4 sent-mail index is local-only by design; "
                f"backend_type={backend_type!r} is not in the "
                f"allowlist {_LOCAL_BACKENDS!r}. Configure a local "
                f"embedding backend (Ollama) for this account, or "
                f"leave the per-account RAG toggle off.",
            )
        self._db = db
        self._account_id = int(account_id)
        self._backend = embedding_backend
        self._model = embedding_model
        #  — the value written to + filtered on embedding_model.
        # Encodes the E5 prefix scheme (no-op for non-E5 models, so
        # existing rows are unchanged). Write + both retrieve filters use
        # self._stamp so they always match.
        from email_triage.engine.embedding_backend import embedding_stamp
        self._stamp = embedding_stamp(embedding_model)
        self._provider = provider
        self._vec_available = bool(sqlite_vec_available)
        # 2026-05-11 — multi-folder override mirroring SentMailCaptureLoop.
        # When non-empty, index_recent runs one search() per folder via
        # MailFilter and merges the result so IMAP SELECTs each mailbox
        # in turn. Empty list falls through to the provider's default
        # mailbox + "in:sent" query (Gmail / O365 path).
        # run18  (PD#5): coerce through the
        # normalize_sent_folder_override SSOT — the strip/drop-blank/
        # legacy-scalar contract lives in ONE place, so a future caller
        # that does NOT pre-normalize stays safe (the old inline loop
        # iterated a bare str into its characters).
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        self._sent_folders: tuple[str, ...] = tuple(
            normalize_sent_folder_override(sent_folders)
        )

    # -- account-state helpers ---------------------------------------------

    def _account_row(self) -> dict | None:
        #  — hold the process-wide DB write lock for the shared-
        # connection read. Callers reach this via db_call (which already
        # holds the reentrant lock); the in-method acquire makes the
        # method correct regardless of caller and clears the  ratchet.
        with get_write_lock():
            cur = self._db.execute(
                "SELECT id, hipaa, created_under_system_hipaa "
                "FROM email_accounts WHERE id = ?",
                (self._account_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        if hasattr(row, "keys"):
            return {k: row[k] for k in row.keys()}
        return {
            "id": row[0],
            "hipaa": row[1],
            "created_under_system_hipaa": row[2],
        }

    def _hipaa_short_circuit(self, op: str) -> bool:
        """Return True when the operation should NOT proceed.

        Logs a single line so an operator who's debugging "why is
        this empty?" gets a readable answer in the log rather than
        a silent return.
        """
        acct = self._account_row()
        if acct is None:
            log.info(
                "sent_mail_index: account not found",
                op=op, account_id=self._account_id,
            )
            return True
        if is_account_hipaa(acct):
            log.info(
                "sent_mail_index: HIPAA-flagged account, skipping",
                op=op, account_id=self._account_id,
            )
            return True
        return False

    # -- index_message -----------------------------------------------------

    async def index_message(
        self, message: EmailMessage, *, is_captured_pair: bool = False,
    ) -> None:
        """Index a single sent message.

        Idempotent: a message whose ``(account_id, rfc_message_id)``
        already has a row is left alone (no re-embed, no row update).
        Empty / quote-only bodies are skipped -- there is nothing to
        embed.

        ``is_captured_pair=True`` (M-6) flags this row as a captured
        edit-feedback pair: AI drafted, the user edited, the sent
        version is the gold standard. Captured rows get a retrieval
        ranking boost in :meth:`retrieve_similar`. The flag is stored
        on the row, not derived at retrieval time, so the boost is
        deterministic across model rebuilds.
        """
        from email_triage.web.db_threadpool import db_call

        #  — _hipaa_short_circuit does a shared-connection read
        # (_account_row); index_message is awaited from the sent-mail-
        # capture loop on the event-loop thread, so dispatch it off-loop.
        if await db_call(self._hipaa_short_circuit, "index_message"):
            return

        # A6 (census 2026-06-09): message-level SSOT. Was Message-ID /
        # message-id only — an IMAP ``Message-Id``-cased sent message
        # resolved to "" → the dedup lookup below was skipped → a fresh
        # row was inserted on EVERY re-scan (the census double-count). The
        # SSOT covers all casings AND falls back to the provider-native id
        # so a header-less sent message still dedups.
        from email_triage.mail_headers import get_message_rfc_id
        rfc_id = get_message_rfc_id(message)
        # Skip rows we already have. Index look-up is on the unique
        # constraint -- O(log n) and avoids the embedding round-trip.
        #  — index_message is awaited from the sent-mail-capture
        # path on the event-loop thread; route the shared-connection
        # read through db_call so it runs on the threadpool.
        if rfc_id:
            def _existing_row_lookup():
                return self._db.execute(
                    "SELECT 1 FROM sent_mail_index "
                    "WHERE account_id = ? AND rfc_message_id = ?",
                    (self._account_id, rfc_id),
                ).fetchone()

            existing = await db_call(_existing_row_lookup)
            if existing is not None:
                return

        body = _strip_quoted(message.body_text or "")
        if not body.strip():
            # Use the underlying logger directly here -- the
            # TriageLogger wrapper is structured-only (no fmt args).
            return

        # Embed the (subject + body) so retrieval matches both topical
        # and semantic similarity. Subject alone misses paraphrases;
        # body alone misses extreme-short replies ("yes please").
        text_for_embedding = (
            (message.subject or "").strip() + "\n\n" + body
        ).strip()
        #  — E5 models need a "passage: " prefix on indexed docs,
        # symmetric with the "query: " prefix at retrieve. No-op for
        # non-E5 models (the helper returns "").
        from email_triage.engine.embedding_backend import e5_prefix
        try:
            vec = await self._backend.embed_text(
                e5_prefix(self._model, "passage") + text_for_embedding
            )
        except Exception as exc:
            log.warning(
                "sent_mail_index: embed_text failed",
                message_id=message.message_id,
                error_type=type(exc).__name__,
            )
            return

        excerpt = body[:1000]
        # The migration's docstring promises HIPAA redaction at index
        # time. We've already short-circuited HIPAA accounts above
        # (so this branch is dead in normal operation); leaving the
        # guard here in case a future caller bypasses the gate.
        if message.hipaa:
            excerpt = REDACTED

        # Precompute the L2 norm at write time so retrieval never has
        # to recompute it ( -- on a 10k-row corpus that recompute
        # was seconds of pure-Python multiplications + sqrts on the
        # event loop). We use math.sqrt over the original list rather
        # than numpy here because index_message is on the SLOW write
        # path (one-shot per sent message); the win lives on the read
        # path. Empty vec -> norm 0.0; retrieval treats norm == 0 as
        # "skip this row".
        norm = math.sqrt(sum(x * x for x in vec)) if vec else 0.0

        now = _now_iso()

        #  — the INSERT + commit run as one unit off the event-loop
        # thread; db_call holds the process-wide DB lock for the hop.
        def _insert_index_row():
            self._db.execute(
                "INSERT OR IGNORE INTO sent_mail_index ("
                "account_id, message_id, rfc_message_id, sent_at, "
                "to_addresses, subject, body_excerpt, embedding_vec, "
                "embedding_model, indexed_at, is_captured_pair, "
                "embedding_norm, embedding_dimension"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self._account_id,
                    message.message_id,
                    rfc_id or None,
                    message.date.isoformat() if message.date else now,
                    dump_json_col(message.recipients or []),  # N-186 R20_10 SSOT (ensure_ascii=False)
                    REDACTED if message.hipaa else (message.subject or ""),
                    excerpt,
                    _pack_vec(vec),
                    self._stamp,
                    now,
                    1 if is_captured_pair else 0,
                    float(norm),
                    #  — stamp the per-row dimension at index time. The
                    # v32 migration's "new rows backfill via index_message"
                    # promise was never kept (this INSERT omitted the
                    # column → NULL). Needed so needs_reindex()'s
                    # dimension trigger is reliable on fresh corpora.
                    len(vec),
                ),
            )
            self._db.commit()

        try:
            await db_call(_insert_index_row)
        except DB_ERRORS as exc:
            log.warning(
                "sent_mail_index: insert failed",
                message_id=message.message_id,
                error_type=type(exc).__name__,
            )

    # -- index_recent ------------------------------------------------------

    async def index_recent(self, *, limit: int = 200) -> int:
        """Pull the last ``limit`` sent messages and index any not yet
        present.

        Returns the count of newly-indexed rows. A re-run on the same
        Sent-folder snapshot returns 0 (idempotency invariant tested
        in test_sent_mail_index.py).
        """
        from email_triage.web.db_threadpool import db_call
        #  — _hipaa_short_circuit does a shared-connection read;
        # index_recent is an async def, so dispatch it off-loop.
        if await db_call(self._hipaa_short_circuit, "index_recent"):
            return 0
        if self._provider is None:
            log.warning(
                "sent_mail_index: no provider supplied to index_recent; "
                "caller must pre-fetch messages and call index_message",
                account_id=self._account_id,
            )
            return 0

        # Multi-folder fan-out: run one search per overridden folder,
        # merging ids in first-seen order so the same message indexed
        # under two folders only embeds once per tick. Errors on one
        # folder don't abort the others — log + continue.
        #
        # 2026-05-13 root cause — UIDs are mailbox-scoped per RFC 3501
        # § 2.3.1.1, so each UID must be fetched against the folder it
        # came from. Pair each UID with its source folder + thread the
        # folder through fetch_message below. Before this fix, IMAP
        # fetches defaulted to the provider's INBOX, looked up the
        # Sent-folder UIDs there, got data=[None] back, and produced
        # empty-body EmailMessages for every result.
        seen: set[str] = set()
        merged_pairs: list[tuple[str, str]] = []  # (folder, uid)
        try:
            if self._sent_folders:
                from email_triage.engine.models import MailFilter
                for folder in self._sent_folders:
                    try:
                        part = await self._provider.search(
                            "in:sent", limit,
                            filter=MailFilter(folder=folder),
                        )
                    except Exception as exc:
                        log.warning(
                            "sent_mail_index: provider search failed "
                            "(continuing with other folders)",
                            folder=folder,
                            error_type=type(exc).__name__,
                        )
                        continue
                    for mid in part or ():
                        if mid not in seen:
                            seen.add(mid)
                            merged_pairs.append((folder, mid))
            else:
                fallback_ids = await self._provider.search(
                    "in:sent", limit,
                )
                # No folder override = default mailbox; fetch path uses
                # its own default. Empty-string folder sentinel skips
                # the kwarg.
                merged_pairs = [("", mid) for mid in (fallback_ids or [])]
        except Exception as exc:
            log.warning(
                "sent_mail_index: provider search failed",
                error_type=type(exc).__name__,
            )
            return 0

        # Pre-filter against the existing index so we don't waste
        # fetch round-trips on messages we already have. We can't do
        # this on (account_id, message_id) because re-indexing across
        # provider id changes is part of the design; we DO check
        # (account_id, rfc_message_id) inside index_message itself.
        new_count = 0
        #  — _row_count does a raw self._db.execute on the shared
        # connection; dispatch it through db_call so the read runs off
        # the event loop under the process-wide DB lock.
        before = await db_call(self._row_count)
        for folder, mid in merged_pairs:
            try:
                if folder:
                    msg = await self._provider.fetch_message(
                        mid, folder=folder,
                    )
                else:
                    msg = await self._provider.fetch_message(mid)
            except Exception as exc:
                log.warning(
                    "sent_mail_index: fetch failed; continuing",
                    message_id=mid,
                    folder=folder,
                    error_type=type(exc).__name__,
                )
                continue
            await self.index_message(msg)
        #  — same as above: the closing count goes through db_call.
        new_count = await db_call(self._row_count) - before
        return max(0, new_count)

    def _row_count(self) -> int:
        #  — hold the process-wide DB write lock for the shared-
        # connection read. db_call (the dispatching caller) already
        # holds the reentrant lock; the in-method acquire makes the
        # method correct regardless of caller and clears the  ratchet.
        with get_write_lock():
            cur = self._db.execute(
                "SELECT COUNT(*) AS n FROM sent_mail_index "
                "WHERE account_id = ?",
                (self._account_id,),
            )
            row = cur.fetchone()
        if row is None:
            return 0
        return int(row["n"] if hasattr(row, "keys") else row[0])

    # -- retrieve_similar --------------------------------------------------

    def _row_to_entry(
        self,
        row: Any,
        qvec_np: "np.ndarray",
        qvec_norm: float,
    ) -> tuple[float, dict, int]:
        """Helper: extract (ranking_score, entry-dict, row-id) from a SQLite row.

        Centralised so the per-contact filter path and the global
        path stay in lockstep on dict shape + cosine math.

        Cosine math is numpy-backed. The candidate vector is
        materialised via ``np.frombuffer`` (zero-copy view of the
        BLOB) and dotted against the precomputed ``qvec_np``; the
        candidate's L2 norm comes from the ``embedding_norm`` column
        (computed at write time by :meth:`index_message` and back-
        filled by migration v15) so retrieval never recomputes it.
        ``qvec_norm`` is computed once by the caller, outside the
        per-row loop.
        """
        row_dict = (
            {k: row[k] for k in row.keys()}
            if hasattr(row, "keys")
            else {
                "id": row[0],
                "message_id": row[1],
                "rfc_message_id": row[2],
                "sent_at": row[3],
                "to_addresses": row[4],
                "subject": row[5],
                "body_excerpt": row[6],
                "embedding_vec": row[7],
                "embedding_model": row[8],
                "is_captured_pair": row[9] if len(row) > 9 else 0,
                "embedding_norm": row[10] if len(row) > 10 else 0.0,
            }
        )
        # Cosine via numpy. Empty / corrupt blob -> raw_sim = 0.0.
        # Precomputed norm of 0.0 also -> 0.0 (the migration / writer
        # leave norm at 0 for empty/corrupt rows on purpose).
        blob = row_dict["embedding_vec"]
        try:
            stored_norm = float(row_dict.get("embedding_norm") or 0.0)
        except (TypeError, ValueError):
            stored_norm = 0.0
        raw_sim = 0.0
        if blob and stored_norm > 0.0 and qvec_norm > 0.0:
            n, rem = divmod(len(blob), 4)
            if rem == 0 and n == qvec_np.shape[0]:
                # np.frombuffer is a zero-copy view; we don't write
                # to it so the read-only flag is fine.
                cand = np.frombuffer(blob, dtype="<f4")
                dot = float(cand @ qvec_np)
                raw_sim = dot / (stored_norm * qvec_norm)
        # M-6 ranking boost: captured edit-feedback pairs (AI drafted,
        # user edited + sent) carry a stronger style signal than
        # general sent mail. Multiply cosine by ``_CAPTURED_PAIR_BOOST``
        # at ranking time so captured rows surface ahead of equivalent
        # general rows. Boost is intentionally modest (1.3) -- captured
        # pair on different topic still loses to general row that's a
        # tighter match.
        is_captured = bool(row_dict.get("is_captured_pair") or 0)
        ranking_score = (
            raw_sim * _CAPTURED_PAIR_BOOST if is_captured else raw_sim
        )
        try:
            to_list = load_json_col(row_dict["to_addresses"], default=[])
            if not isinstance(to_list, list):
                to_list = []
        except (TypeError, ValueError):
            to_list = []
        entry = {
            "message_id": row_dict["message_id"],
            "rfc_message_id": row_dict["rfc_message_id"],
            "sent_at": row_dict["sent_at"],
            "to_addresses": to_list,
            "subject": row_dict["subject"] or "",
            "excerpt": row_dict["body_excerpt"] or "",
            # Surface unboosted cosine; boost is a ranking detail,
            # not the canonical similarity.
            "similarity": float(raw_sim),
            "is_captured_pair": is_captured,
        }
        # N-219c/31 R23: dict.get + parse_int_or_none handles all 3 shapes
        # (missing key, None value, non-numeric) with -1 sentinel.
        row_id = parse_int_or_none(row_dict.get("id"))
        if row_id is None:
            row_id = -1
        return ranking_score, entry, row_id

    async def retrieve_similar(
        self,
        query_text: str,
        *,
        top_k: int = 5,
        contact_address: str | None = None,
    ) -> list[dict]:
        """Return up to ``top_k`` most-similar indexed sent messages.

        Each entry: ``{message_id, rfc_message_id, sent_at,
        to_addresses (list), subject, excerpt, similarity (0..1)}``.

        Returns ``[]`` for HIPAA-flagged accounts (defence in depth:
        ``index_message`` already short-circuits HIPAA, so the index
        SHOULD be empty -- but if a non-HIPAA account was rebuilt
        and then flipped to HIPAA, this gate stops the pre-flip rows
        from being surfaced post-flip).

        M-7: when ``contact_address`` is supplied AND the per-contact
        toggle is enabled at the call site, the candidate pool is
        narrowed to rows whose ``to_addresses`` JSON blob contains
        the address (case-fold substring match -- cheap; SQL LIKE).
        If fewer than ``top_k`` per-contact rows match, the helper
        tops up from the unfiltered pool so the LLM still receives
        enough examples. Per-contact rows take priority; global rows
        fill the remainder. Dedup is by primary-key id.

        The per-contact toggle decision lives at the CALLER; this
        method just executes the contract -- pass ``contact_address``
        when you want the filter applied, leave it ``None`` for the
        legacy global-pool behaviour.
        """
        from email_triage.web.db_threadpool import db_call
        #  — _hipaa_short_circuit does a shared-connection read;
        # retrieve_similar is an async def, so dispatch it off-loop.
        if await db_call(self._hipaa_short_circuit, "retrieve_similar"):
            return []
        if not query_text or not query_text.strip():
            return []
        # Panel T db S-R2-A1: while the boot update gate is armed (auto mode, a stale_ok
        # runtime, first auto-update decision not made yet) an embed waits up to
        # BOOT_UPDATE_GATE_CAP_SECS. Draft enrichment is optional, so fail fast to no
        # examples instead of holding the draft; the indexers keep the wait. The check is
        # backend-agnostic: an Ollama-backed index also skips examples during the gate (a
        # non-decisional degradation, PD-8).
        from email_triage.embedding_bits import boot_update_gate_pending
        if boot_update_gate_pending():
            log.info("sent_mail_index: boot update gate armed; retrieval skipped")
            return []

        #  — E5 models need a "query: " prefix on search queries,
        # symmetric with the "passage: " prefix at index. No-op for
        # non-E5 models.
        from email_triage.engine.embedding_backend import e5_prefix
        try:
            qvec = await self._backend.embed_text(
                e5_prefix(self._model, "query") + query_text
            )
        except Exception as exc:
            log.warning(
                "sent_mail_index: embed_text failed on query",
                error_type=type(exc).__name__,
            )
            return []

        cap = max(0, int(top_k))
        if cap == 0:
            return []

        # Materialise the query vector once + compute its L2 norm
        # once, outside the per-row loop. This is the half of 's
        # win that lives on the read path: the candidate norm comes
        # from the row (precomputed at write time) and the query
        # norm is amortised across every candidate in this call.
        qvec_np = np.asarray(qvec, dtype="<f4") if qvec else np.zeros(
            0, dtype="<f4",
        )
        qvec_norm = float(np.linalg.norm(qvec_np)) if qvec_np.size else 0.0
        if qvec_norm <= 0.0:
            # Zero query vector -- every cosine is 0/0; cheaper to
            # short-circuit than to scan rows that all score 0.0.
            return []

        # the backlog  (Census v3 #2 wider follow-up) — this site
        # is on the wider providers/actions/style_learning pin's
        # allow-list because the SQL below LIKE-matches against the
        # RAW ``to_addresses`` column (display form, e.g.
        # ``"Alice <alice@münchen.de>, bob@x.com"``). Canonicalizing
        # the filter side (which IDNA-normalizes + strips display-
        # wrap) would produce ``alice@xn--mnchen-3ya.de`` — a
        # substring the raw ``to_addresses`` never contains — so
        # every LIKE match would drop to zero. A proper fix requires
        # canonicalizing BOTH sides (index column migration + write-
        # path normalize), which is a separate scope. For now: strip
        # + case-fold to match the SQL's ``LOWER(to_addresses)``
        # side. Allow-listed in
        # ``tests/test_canonical_email_ssot_providers_pin.py::
        # _ALLOWED_PROVIDERS_BYPASSES`` — the SSOT bypass is
        # RATIONALIZED, not silent.
        contact_norm = (contact_address or "").strip().lower() or None

        # In-memory cosine over candidate rows. The vec0 virtual-
        # table path is intentionally NOT implemented in this scaffold
        # (it would couple the helper to the extension's API surface
        # before we know which version sticks). When the extension
        # is loaded, the helper still walks rows in this table; the
        # virtual-table fast path lands as a separate change once we
        # have a measured benchmark showing it's worth the complexity.

        per_contact_entries: list[tuple[float, dict, int]] = []
        seen_ids: set[int] = set()

        if contact_norm is not None:
            # Filter at SQL: rows whose to_addresses JSON contains the
            # contact substring. Case-fold via LOWER() on the column;
            # the contact is already lower-cased above. Cheap match
            # because the column is indexed on (account_id) and the
            # filter narrows further by the LIKE predicate.
            #  — retrieve_similar is awaited from the draft-reply
            # path on the event-loop thread; route the read off-loop.
            def _per_contact_rows():
                return self._db.execute(
                    "SELECT id, message_id, rfc_message_id, sent_at, "
                    "to_addresses, subject, body_excerpt, embedding_vec, "
                    "embedding_model, is_captured_pair, embedding_norm "
                    "FROM sent_mail_index "
                    "WHERE account_id = ? "
                    "AND embedding_model = ? "
                    "AND LOWER(to_addresses) LIKE '%' || ? || '%'",
                    (self._account_id, self._stamp, contact_norm),
                ).fetchall()

            rows = await db_call(_per_contact_rows)
            for row in rows:
                sim, entry, row_id = self._row_to_entry(
                    row, qvec_np, qvec_norm,
                )
                if row_id >= 0:
                    seen_ids.add(row_id)
                per_contact_entries.append((sim, entry, row_id))
            per_contact_entries.sort(key=lambda t: t[0], reverse=True)
            # Trim to cap so the order stays stable when we later
            # interleave global top-up rows.
            if len(per_contact_entries) > cap:
                per_contact_entries = per_contact_entries[:cap]

        # Decide whether the global top-up query is needed:
        #   * per-contact filter not requested -> always run global
        #   * per-contact filter requested and we got >= cap rows -> done
        #   * per-contact filter requested but sparse -> top up
        need_global = (
            contact_norm is None
            or len(per_contact_entries) < cap
        )

        global_entries: list[tuple[float, dict, int]] = []
        if need_global:
            #  — route the global candidate read off the loop.
            def _global_rows():
                return self._db.execute(
                    "SELECT id, message_id, rfc_message_id, sent_at, "
                    "to_addresses, subject, body_excerpt, embedding_vec, "
                    "embedding_model, is_captured_pair, embedding_norm "
                    "FROM sent_mail_index "
                    "WHERE account_id = ? AND embedding_model = ?",
                    (self._account_id, self._stamp),
                ).fetchall()

            rows = await db_call(_global_rows)
            for row in rows:
                sim, entry, row_id = self._row_to_entry(
                    row, qvec_np, qvec_norm,
                )
                # Skip rows already returned in the per-contact pool.
                if row_id >= 0 and row_id in seen_ids:
                    continue
                global_entries.append((sim, entry, row_id))
            global_entries.sort(key=lambda t: t[0], reverse=True)

        # Compose the final list: per-contact rows first (already sim-
        # sorted), then global rows fill until cap. The per-contact
        # priority is the M-7 contract -- when replying to THIS
        # person, prefer past replies to THIS person.
        out: list[dict] = []
        for _sim, entry, _rid in per_contact_entries:
            out.append(entry)
            if len(out) >= cap:
                return out
        for _sim, entry, _rid in global_entries:
            out.append(entry)
            if len(out) >= cap:
                break
        return out

    # -- delete_account_index ----------------------------------------------

    def delete_account_index(self) -> int:
        """Remove every indexed row for this account.

        Used by the per-account toggle Off path AND by the M-8
        "Delete everything" sweep. NOT gated on HIPAA -- if anything
        the HIPAA path NEEDS to delete in case rows snuck in pre-
        flip. Returns the number of rows deleted.
        """
        #  — this is a plain sync method called DIRECTLY (CLI,
        # /profile delete path, tests) with no db_call dispatch, so it
        # genuinely touched the shared connection off the write lock.
        # The DELETE + commit must run as ONE atomic unit under the
        # lock: a foreign commit between them would flush a half-built
        # transaction. Hold get_write_lock() across both statements.
        with get_write_lock():
            cur = self._db.execute(
                "DELETE FROM sent_mail_index WHERE account_id = ?",
                (self._account_id,),
            )
            self._db.commit()
        try:
            return int(cur.rowcount or 0)
        except Exception:
            return 0


__all__ = [
    "SentMailIndex",
    "EmbeddingBackend",
    "NonLocalBackendError",
    "_CAPTURED_PAIR_BOOST",
]
