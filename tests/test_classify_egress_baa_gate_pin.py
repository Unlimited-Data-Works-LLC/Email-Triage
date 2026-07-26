"""Class-wide count-agnostic pin for the PHI→LLM classify/complete/embed egress
class (N-113 residual; DA R2). The N-113-specific pin
(``test_n113_topic_backscan_baa_gate``) covers only ``match_topics_for_message``;
THIS pin covers the WHOLE egress class — every site that ships a message's PHI to
a classifier / LLM / embedder — so a NEW ungated ``.classify(`` / ``.complete(`` /
``chat_complete(`` / ``embed_text(`` site cannot appear green.

A HIPAA account's message content may reach an external subprocessor only behind a
HIPAA-egress control (§164.308(b)(1)). The codebase uses several VALID controls
(this is managed divergence, not one-true-SSOT — some controls are STRONGER than a
BAA gate and must not be "converged" away):

* ``baa_block_status`` / ``is_safe_for_hipaa`` — the BAA gate SSOT (preferred).
* ``BackendBAARequiredError`` / ``require_baa`` — the ai_backends loader BAA gate.
* ``_hipaa_short_circuit`` — SKIPS HIPAA accounts entirely (stronger: HIPAA mail is
  never embedded, even locally — the RAG-index design choice).
* the describe-and-discard de-identification scrubber (EQM-12) — egresses
  Safe-Harbor-scrubbed (de-identified) content, which is not PHI.

This pin asserts every egress call site's enclosing function references one of
those control markers, OR is on a justified allow-list. A site with NO recognized
control turns it RED — that is the enumeration proof (PD#4): the pin IS the
complete-net check. Built on the shared ``_pin_harness`` (PD#6).
"""
from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, walk_src

# The PHI→LLM egress call names (a message's content crosses to a model here).
_EGRESS_CALLS = frozenset({
    "match_topics_for_message", "classify", "complete", "chat_complete",
    "embed_text",
})

# Any of these names in the enclosing function = a recognized HIPAA-egress control.
_CONTROL_MARKERS = frozenset({
    "baa_block_status",          # the BAA gate SSOT
    "is_safe_for_hipaa",         # the BAA gate SSOT (run-level)
    "BackendBAARequiredError",   # the ai_backends loader BAA gate
    "require_baa_certified",     # load_backend BAA arg
    "_hipaa_short_circuit",      # SKIP HIPAA entirely (stronger than a BAA gate)
})

# (relpath, fn): an egress call whose HIPAA-egress control is provided some other
# justified way (upstream caller, de-identification, or genuinely out of scope).
_ALLOW = {
    ("web/triage_one.py", "_match_topics_live"):
        "gated by its caller triage_single_message — the §164.308(b)(1) chokepoint "
        "(baa_block_status before classify) returns a fail-closed skip before this "
        "Topic-match egress is reached, for all 7 ingestion/runner paths",
    ("actions/hipaa_style_distill.py", "distill_hipaa_style"):
        "EQM-12 describe-and-discard de-identification — the prompt is Safe-Harbor "
        "scrubbed before classifier.complete(), so the egress is de-identified "
        "(not PHI); flag-gated OFF by default",
    ("web/routers/ui/triage_classify.py", "classify_run"):
        "N-113 NOT-A-FINDING — the manual classify-PASTE route is account-UNSCOPED "
        "(no account_id → no HIPAA flag to evaluate); operator-initiated ad-hoc "
        "disclosure, not system auto-disclosure of a flagged account",
    ("actions/digest.py", "extract_articles"):
        "is_local-only conservative gate (digest.py:200 — `message.hipaa and not "
        "classifier.is_local` degrades to a subject-only article): blocks ALL "
        "external classifiers, STRICTER than the BAA gate. Converging to "
        "baa_block_status (to permit a BAA-acked external) needs conn-threading + "
        "is a feature not a leak-fix — tracked PD#5 convergence residual",
    ("actions/sent_mail_index.py", "index_message"):
        "_hipaa_short_circuit (sent_mail_index.py:278/292) — SKIPS HIPAA accounts "
        "entirely; HIPAA mail is never embedded (stronger than a BAA gate)",
    ("actions/sent_mail_index.py", "retrieve_similar"):
        "_hipaa_short_circuit — SKIPS HIPAA accounts (no HIPAA embedding egress)",
    ("jobs/embedding_reindex.py", "run_embedding_reindex_job"):
        "skips HIPAA accounts entirely (embedding_reindex.py:458 — `if "
        "is_account_hipaa(acct): finish done; return`); no embedding of HIPAA mail",
}


def _is_egress_call(node: ast.AST) -> str | None:
    """The egress call name if ``node`` is a non-internal egress Call, else None.
    Excludes ``self.classify(...)`` (a classifier/engine calling its OWN method —
    not an egress decision site) and the method DEFINITIONS."""
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    if isinstance(f, ast.Name) and f.id in _EGRESS_CALLS:
        return f.id
    if isinstance(f, ast.Attribute) and f.attr in _EGRESS_CALLS:
        # skip self.<call>( — internal self-dispatch, not an egress decision
        if isinstance(f.value, ast.Name) and f.value.id == "self":
            return None
        return f.attr
    return None


# The TRANSPORT / implementation layer — these modules IMPLEMENT classify/complete/
# chat_complete/embed_text (the HTTP call itself); they don't see ``account_hipaa``,
# so they aren't egress-DECISION sites. The HIPAA-egress decision is made by their
# CALLERS (actions/jobs/web), which this pin scans. Excluding them keeps the pin on
# the decision layer (engine/embedding_backend gates at CONSTRUCTION — non-local
# base_url reject — verified under N-113; its callers carry the per-account gate).
def _is_transport_layer(rel: str) -> bool:
    return (rel.startswith("ai_backends/") or rel.startswith("classify/")
            or rel == "engine/embedding_backend.py")


def _collect_sites():
    """relpath -> {fn_name: set(egress_call_names)} for every egress call site."""
    out: dict[str, dict[str, set[str]]] = {}
    for _path, rel, tree in walk_src():
        if _is_transport_layer(rel):
            continue
        for node in ast.walk(tree):
            name = _is_egress_call(node)
            if name is None:
                continue
            # walk_src() already annotated parents (parse_module) → harness
            # enclosing_fn (no re-rolled parent dict / walk, R5c).
            fn_name = enclosing_fn(node)
            if fn_name == "<module>":
                continue
            # the method DEFINITION itself (async def classify) is not a call site —
            # but we matched a Call, so this is a real call. Record it.
            out.setdefault(rel, {}).setdefault(fn_name, set()).add(name)
    return out


def _fn_references_control(rel: str, fn_name: str) -> bool:
    """True if the named function's body references any control marker."""
    for _path, r, tree in walk_src():
        if r != rel:
            continue
        for fn in ast.walk(tree):
            if (isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and fn.name == fn_name):
                # markers may be bare Names (imported funcs / raised errors) OR
                # Attribute attrs (e.g. self._hipaa_short_circuit(...)).
                refs = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
                refs |= {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
                if refs & _CONTROL_MARKERS:
                    return True
        return False
    return False


def test_every_phi_llm_egress_site_has_a_hipaa_control():
    """Enumeration proof (PD#4) + prevention: every classify/complete/embed egress
    site routes through a recognized HIPAA-egress control, or is allow-listed with
    a justification. A new ungated site (a HIPAA account's PHI to an external model
    with no gate) turns this RED — §164.308(b)(1)."""
    sites = _collect_sites()
    offenders = []
    for rel, fns in sites.items():
        for fn_name, calls in fns.items():
            if (rel, fn_name) in _ALLOW:
                continue
            if _fn_references_control(rel, fn_name):
                continue
            offenders.append(f"{rel}::{fn_name} (egress: {sorted(calls)})")
    assert not offenders, (
        "PHI→LLM egress site(s) with NO recognized HIPAA-egress control "
        f"({sorted(_CONTROL_MARKERS)}) and not allow-listed: {sorted(offenders)}. "
        "A HIPAA account's PHI could egress to an external model un-gated "
        "(§164.308(b)(1)). Route through classify.baa_gate.baa_block_status (the "
        "SSOT), or add a justified _ALLOW entry if the control is provided another "
        "documented way (upstream gate / de-identification)."
    )


def test_allow_entries_are_live():
    """The allow-list can't rot: every _ALLOW entry must name a function that still
    makes an egress call (a removed/renamed site = a stale exemption to delete)."""
    sites = _collect_sites()
    stale = [
        f"{rel}::{fn}" for (rel, fn) in _ALLOW
        if fn not in sites.get(rel, {})
    ]
    assert not stale, (
        f"_ALLOW names egress sites that no longer exist: {stale}. Delete the "
        "stale exemptions so the allow-list shrinks and can't mask a regression."
    )
