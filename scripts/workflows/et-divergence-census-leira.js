export const meta = {
  name: 'divergence-census-llm-host',
  description: 'FORK of divergence-census wired to a llm-host pre-pass (Consumer #1 of the llm-host offload stack): each Census subagent runs `scripts/leira_census_prepass.py` as its FIRST tool call and treats the returned candidate site list as a STARTING HINT, then widens with its own AST walk (llm-host output = PROBE, not verdict). Goal: cut Phase-1 enumeration tokens vs the original workflow while preserving the AI assistant judgment for Steps 2-6 + AST completeness.',
  phases: [
    { title: 'Warm', detail: 'single low-effort probe to hot-load qwen3.6:35b on llm-host BEFORE the Census fan-out. HARD GATE: if llm-host does not serve, HALT the workflow (do not fan out) and surface a troubleshooting bundle (ollama-ps + ollama-list + nagios_tail) for operator review. Fallback to AI provider-only census is OPERATOR-GATED, never automatic.' },
    { title: 'Census', detail: 'one agent per seeded operation-class: enumerate, cluster variants, rank weakest-first, recommend SSOT + pin' },
    { title: 'Verify', detail: 'adversarially verify each enumeration was COMPLETE + the canonical claim holds' },
    { title: 'Discover', detail: 'open-ended: find NEW divergent classes beyond the seeded set (un-primed)' },
    { title: 'Synthesize', detail: 'merge seeded + discovered into a ranked harmonization backlog' },
  ],
}

// ---------------------------------------------------------------------------
// ★ Per-drive learnings mirror — kept parallel to the sibling
// `et-divergence-census.js` script (2026-07-09 drive). Two NEW
// discoverable classes seeded for the Discover phase:
//   * INPUT-PARSE-SET COMPLETENESS — a function that filters an input
//     dict against a hardcoded key-set OR parses a command-line with a
//     regex/glob is a CIDI-shape when the set/pattern misses a class of
//     legitimate inputs (grounded in N-380 `_FORBIDDEN_KEYS` widen +
//     N-381 `_extract_msg_from_command` widen).
//   * FAIL-LOUD ACTUATOR GATE — a typed exception at an actuator + a
//     clean-error wrapper at the top-level entry (grounded in N-157
//     `CliAuditGateClosed` + `main()` try/except + rc=3 discriminator).
// the backlog  (audit_hmac categorizer over-flags on file-name
// adjacency) is queued for both scripts — refinement direction:
// require AST-visible surface touch before admitting the file to the
// audit_hmac category.
//
// ★ RUN21 LEARNINGS (2026-07-18) — folded per BINDING
// feedback_after_every_run_evaluate_census_and_leira_offload:
//   * NEW STALE TRAP #4 — VERIFIER-HALLUCINATED-SSOT. Run21 D2 verifier
//     asserted a per-message SSOT (`record_message_result` at
//     `web/_watch_status_recorder`) that DID NOT EXIST at HEAD; the actual
//     seam is a differently-named aggregate (`record_triage_run`) that
//     BOTH IMAP+O365 poll paths already route through. Fix builder caught
//     it (refused to fabricate). Verify prompt now instructs: for any SSOT
//     named by exact identifier, FIRST tool call is a repo-wide grep for
//     BOTH the identifier AND the containing module — verify presence at
//     HEAD before comparing sibling shapes.
//   * NEW STALE TRAP #5 — BLANKET-EXEMPTION-HIDES-SECOND-TARGET. Run21 D1
//     verifier missed a fn-body blanket exemption in the atomic-write pin
//     (`_fn_calls_atomic_ssot`) that let a fn with ANY use of the SSOT
//     bypass detection on an UNRELATED tmp+rename target. DA caught it as
//     MF-1 same-drive. Verify prompt now instructs: walk the pin code for
//     fn-body blanket-exemption patterns + flag as NTH; propose dropping
//     the exemption if the SSOT's OWN file is already exempted by the
//     outer file-name allow-list.
//   * NEW STALE TRAP #6 — DOCUMENTED-WAITING-ON-OP. Run21 D3 pin scope
//     widen (web/routers → web) caught a REAL 3rd-site drift at
//     `web/db.py::upsert_gmail_watch` — but the site was documented
//     WAITING-ON-OP in a same-fn comment block (safe migration requires a
//     backfill or dual-shape lookup). When a widened pin catches a
//     documented-defer site, EXEMPT it in the pin's allow-list WITH the
//     WAITING-ON-OP citation, NOT re-open the deferred question. Verify
//     prompt should note: if the site's own docstring/comment block
//     explains why the divergence is a compat concern, verdict=STALE-w-
//     doc-cite; the fix is allow-list-entry-with-citation, not immediate
//     migration.
//   * COST-CALIBRATION — actuals 39 agents / 4.27M subagent tok / 53 min /
//     826 tool uses. Prior estimate ~30 agents / ~3M tok / ~25 min was
//     under by ~2× wall-clock, ~40% tokens. Discover-widen (2 → 7 seeded
//     classes) + llm-host-prepass Census subagents extending their AST walks
//     past probe list are the drivers. Update: budget 5–7M output tok +
//     ~50 min for the full census phase alone (was 4–6M + ~25 min).
//     Ledger row landed in `procedure_census_loop.md` §Cost.
//
// ★ RUN22 LEARNINGS (2026-07-18) — folded per BINDING
// feedback_after_every_run_evaluate_census_and_leira_offload:
//   * NEW STALE TRAP #7 — FORK-CLAIM-WITHOUT-COMPARISON. Run22 D3 verifier
//     flagged `.lower()` in `per_contact_hipaa.py:413` vs `.casefold()` in
//     `_norm_msgid` as a HIPAA HMAC-key fork. Verify-don't-accept caught it:
//     BOTH sites are internally symmetric — the .lower() writer's output is
//     the ONLY consumer via a PRIMARY-KEY conflict on the same-transform
//     column, and the .casefold() site's output is consumed ONLY by an
//     in-memory `==` on both sides. No single value is produced by one and
//     consumed by the other. Verify prompt now instructs: two normalization
//     sites in different modules are NOT a fork unless a single value flows
//     from one normalizer's output into another's comparison. Trace ALL
//     callers of each side and confirm the cross-produce/consume path exists
//     before calling it a fork. Per-feature internally-symmetric normal-
//     ization is design symmetry, not drift.
//   * NEW STALE TRAP #8 — HIPAA-DELIBERATE-RETENTION. Run22 D1 verifier
//     proposed a `record_account_deactivation_outcome` funnel to clear
//     `gmail_watches.status='errored'` / `o365_subs.status='errored'` on
//     account soft-deactivate. Verify caught it: the docstring at
//     `web/watcher.py:1264-1274` EXPLICITLY documents the N-62 posture —
//     soft-deactivate deliberately does NOT clear these because they reflect
//     real provider-side state during the 3-7 day expiry window (§164.502
//     (a)(1) receive-but-discard, fail-closed at the actuator). "Chips
//     stuck" was the wrong framing; the retention IS the compliance posture.
//     Verify prompt now instructs: before proposing a lifecycle-flag CLEAR
//     funnel, grep the SET-site's file for an in-source docstring naming a
//     deliberate-retention posture; if present, verdict=STALE-w-doc-cite,
//     do NOT propose a clear funnel.
//   * NEW OPERATIONAL SIGNAL — llm-host PREPASS CLIENT-SIDE HANG. Run22 had
//     13/14 seeded classes HALT at the llm-host prepass with 0 bytes stdout
//     AND 0 bytes stderr across multiple attempts (180s / 60s / 60s / 280s).
//     Model loaded + warm + serving per ollama-ps; prepass CLIENT hangs
//     silently. `feedback_leira_silent_fallback_wastes_offload` discipline
//     HELD (no subagent silently AST-only-walked and mislabeled `served`);
//     each honored the BINDING + refused to fall to AI provider-only. But
//     verify agents did burn real AI provider tokens re-enumerating what a
//     Phase-0 structural pre-check would have skipped. Fold candidates for
//     next revision: (a) Phase-0 structural pre-check for CLOSED-AT-HEAD
//     classes — if the class has an existing `test_*_ssot_pin.py` whose
//     docstring names a prior widening AND the pin passes AND a 30-second
//     AST re-derive returns 0 defects, mark `STALE-preverified` and SKIP
//     llm-host offload entirely; (b) enrich signature-hints with concrete
//     SSOT symbol names (parse-int-request's 3-width discipline — the ONE
//     class that produced real llm-host-served data this run); (c) bake a
//     distinct `HALTED` sentinel severity so downstream consumers don't
//     auto-accept a halted class as `sites:0 / canonical:false / LOW`.
//   * NEW SEEDED CLASS CANDIDATE — LIFECYCLE-COLUMN-RESET-COMPLETENESS.
//     The N-427 fix (this run's only surviving live defect) is exactly the
//     shape of N-240 R24, one column later. PD#18 direct pattern with a
//     mechanical enumeration signature: for each `web/db.py` UPDATE funnel
//     keyed on `WHERE status='running' AND ended_at IS NULL` (the requeue
//     shape), cross-check the SET clause against every column on the target
//     table added after the funnel's last edit. Seed as class `lifecycle-
//     column-reset-completeness` in the Discover-lens hint set.
//   * NEW SEEDED CLASS CANDIDATE — PIN-SCANS-TREE (anti-vacuity). Discover
//     completeness surfaced that the N-244 short-id pin exists but does NOT
//     walk the tree (anti-vacuity only). Invisible to `pinned-verify`
//     (which asks "does a pin exist for this SSOT?"). Seed a new class
//     `pin-scans-tree` whose predicate is: for every `tests/test_*_ssot_
//     pin.py`, assert the pin body contains at least one of `iter_src_
//     files`, `iter_files`, `rglob(`, `walk(` OR imports `_pin_harness`.
//     Failing pins are anti-vacuity conversion candidates.
//   * COST-CALIBRATION — actuals 41 agents / 3.87M subagent tok / 61 min /
//     838 tool uses / 8 discovered / 24 newly-found via completeness /
//     0 seeded live defects (all 14 STALE-CLOSED-at-HEAD). Ledger: run22
//     was ~10% cheaper on tokens than run21 (3.87M vs 4.27M) but ~15%
//     LONGER wall-clock (61 vs 53 min) — the llm-host prepass hang chewed up
//     silent-timeout minutes across 13 classes with zero token yield.
//     AI provider vs llm-host split: ESSENTIALLY 100% AI provider this run — the
//     prepass hang defeated the offload intent; only 1/14 (`parse-int-
//     request`) served real llm-host-derived candidate sites. Verify-don't-
//     accept ran 12 agents / ~1.0M tok / 7.6 min (adjudicator included).
//     Fix workflow: inline (this fix was ≤6 edits), no fix workflow spent.
//     3-SME panel: 3 agents / ~200k tok / ~2 min parallel. Total run22
//     loop: ~5.1M subagent tokens end-to-end (vs run21 ~5.5M).
//
// RUN23 (2026-07-18, post-`think:false` fix commit 8b37ce2a) FOLD:
//   * NEW STALE TRAP #9 — REDISCOVERS-REFUTED-PRIOR-RUN-FINDING. Run23 C2
//     (Action.execute log-extras hand-rolled in notify/escalate/draft_reply/
//     self_sent_event) is EXACTLY the class run14 #8 raised and REFUTED as
//     too-broad. The existing pin at `tests/test_action_log_extras_ssot_pin.
//     py` docstring L11-31 explicitly documents the refusal: "the un-migrated
//     sites are legitimately DIFFERENT log lines — a 'skipping; already
//     applied' notice, a placeholder/error-path diagnostic, a per-escalation-
//     step log — that carry their own minimal context ({flow_id} / {flow_id,
//     error_type} / {account_id})". Run23 verifier VERIFIED HIGH but did not
//     surface the run14 pin refutation. Verify prompt now instructs: BEFORE
//     marking a shape-adoption finding VERIFIED, `Read` the primary SSOT
//     pin's docstring (`tests/test_<ssot_target>_ssot_pin.py`) and search
//     for phrases naming the refusal ("CENSUS <NNNN> REFUTED", "RESHAPED",
//     "too-broad", "un-migrated sites are legitimately DIFFERENT"). If
//     present, verdict=STALE-w-doc-cite pointing to the pin's refusal
//     paragraph; the fix is NO CODE CHANGE + census script trap update, not
//     re-open the refuted class.
//   * NEW STALE TRAP  — SSOT-DOCSTRING-DELIBERATE-SCOPE-EXCLUSION. Run23
//     C6 (canonical_json cache-fingerprint fork) was VERIFIED as a fork but
//     the SSOT `src/email_triage/_signing.py::canonical_json` docstring L11-
//     13 EXPLICITLY excludes both frozen-audit-chain + cache-fingerprint
//     from SSOT scope: "The frozen audit-chain forms in `db/audit.py`
//     deliberately use their own recipes (checksummed migration bodies,
//     backwards-compat) and are EXCLUDED from the SSOT — this module owns
//     ONLY the non-frozen family." Routing cache-fingerprint sites through
//     `canonical_json` would CHANGE BYTES for non-ASCII taxonomy values and
//     invalidate all existing cache rows — a real regression. Verifier
//     surfaced the exclusion (its `ssot_target` field literally said "No
//     expansion of SSOT scope recommended") but still marked the class
//     CONFIRMED. Verify prompt now instructs: BEFORE proposing a fork-to-
//     SSOT convergence, `Read` the SSOT module's own docstring and search
//     for phrases like "EXCLUDED", "scope explicitly", "own recipes", "not
//     covered by this SSOT". If the drift shape is inside the excluded
//     scope, verdict=STALE-w-doc-cite; propose either (a) no-fix +
//     documentation, or (b) a SEPARATE sibling SSOT (e.g. a
//     `canonical_cache_json` alongside `canonical_json`), not convergence.
//   * NEW STALE TRAP  — CANDIDATE-COMPLETENESS-CROSS-CONTAMINATION.
//     Run23 C1 (watcher.py per-message LLM_UNREACHABLE) had its
//     `true_live_sites` list POLLUTED with C0's Gmail/O365 push-lifecycle
//     sites because the heuristic that merged discovered candidates with
//     completeness enumeration output matched on file-overlap. Verifier
//     agents received a mixed prompt (title from C1, sites from C0) and
//     returned mixed verdicts. Verify prompt now REJECTS the merge: pass
//     candidate + completeness data as SEPARATE raw fields, and instruct
//     the verifier to re-enumerate the class-signature INDEPENDENTLY from
//     the completeness enumeration signature — do NOT trust the merged
//     sites list. Additionally: post-verify, sanity-check that a
//     candidate's true_live_sites intersect its ORIGINAL cited files;
//     zero-intersection means the verifier locked onto a different class
//     and the verdict should be re-run in isolation.
//   * OPERATIONAL WIN — `think:false` FIX VALIDATED AT SCALE. Run23 served
//     14/14 seeded classes via llm-host (`leira_status="served"` verified
//     programmatically in raw JSON — no halted, no fallback), vs run22's
//     1/14 and run21's 0/14 effective. Wall-clock ↓23% (47 vs 61 min)
//     despite MORE real AI provider work (subagent tokens +7% because verify
//     agents actually enumerated instead of returning halt-artifacts).
//     Recalibrate expected llm-host-served ratio to ~100% baseline for a
//     well-formed prepass (`think:false` + valid config); anything <90%
//     served is a config / Ollama / llm-host health regression, not a normal
//     baseline shift.
//   * COST-CALIBRATION — actuals 40 agents / 4.14M subagent tok / 47 min /
//     753 tool uses / 7 discovered classes / 16 newly-found via
//     completeness / 3 seeded live defects (C0 gmail/o365 lifecycle SET-
//     narrow — MED; C1 watcher LLM-down — LOW-MED; C3 URL-query API-key
//     leak — HIGH). Verify-don't-accept: 21 agents / 1.78M tok / ~14 min.
//     3-SME batched panel: 3 agents / 265k tok / ~6 min. Fix workflow:
//     inline sequential (all 3 landings ≤15 edits total incl. pins), no
//     fix workflow spent. Total run23 loop: ~6.2M subagent tokens end-to-
//     end (vs run22 ~5.1M) — the +22% cost bought 3 real defects landed
//     (including 1 HIGH-sev API-key leak surface) vs run22's 0 seeded
//     live. Ratio flips: run23 is the FIRST census loop where the offload
//     paid off end-to-end (verify surfacing real defects that AI provider
//     halt-mode would have hidden).
//
// ADDITIONAL 2026-07-09 discoverable classes (from N-380/N-381 SME panels):
//   * SHALLOW-CHECK LIMITATION — a `set(...) & payload.keys()` intersection
//     inspects only top-level keys; nested-dict PHI slips past the guard.
//     Refinement: recursive `_leaks` walk with depth-cap.
//   * REGEX-OVER-FULL-STRING PARSING FRAGILITY — hooks that regex a full
//     command-line are boundary-blind (char classes terminate at first
//     quote; wrong-branch order under adversarial shapes). Refinement:
//     shlex.split-based tokenization.  Applies to any hook / command-line
//     parser under `scripts/hooks/`.
//   * SENSITIVE-PURPOSE SLUG DESTRUCTION (2026-07-09 post-batch-6, from
//     db-fast-review MF-1) — `raise_api_error(<slug>, purpose='auth'|
//     'provider'|'config'|'backup'|'digest')` routes the `<slug>` first
//     arg through `scrub_exc` which REPLACES the input with
//     `f'{purpose} operation failed'` for _SENSITIVE_PURPOSES per
//     `web/_flash.py:58-88`. Dict-detail sites setting
//     `detail={"error": "<slug>", "message": "..."}` where `<slug>` is
//     a machine-readable identifier (`hipaa_blocked`, `calendar_not_
//     enabled`, etc.) LOSE the slug — tests asserting on
//     `body.detail.error == "<slug>"` fail. Fix: use `purpose='misc'`
//     for literal-str slug args (curated identifier, not leak vector);
//     reserve `purpose='auth'|'provider'|...` for calls passing a real
//     Exception whose `str()` could carry secrets. Detection recipe:
//     grep `raise_api_error("<literal_slug>", ..., purpose="<sensitive>")`.
//     Grounded in this drive's MF-1 fix at `a3cf46d8` (5 sites in
//     agent_api.py).
//     UPGRADE 2026-07-09 (MF-1 tail landing `240a9dda`): STRUCTURAL PIN
//     `tests/test_no_sensitive_purpose_literal_slug_pin.py` now enforces
//     this class going forward (count-agnostic AST walker via
//     `_pin_harness`; covers BOTH `raise_api_error` + `api_error_response`
//     sinks). On first run the pin caught 10 MORE pre-existing sibling
//     sites in the shared auth-gate SSOTs (`web/dependencies.py`×6,
//     `web/routers/agent_api.py`×1, `web/routers/api.py`×3). The pin is
//     now the SSOT for this class; the census grep is a discovery-tier
//     redundancy for when the pin's `_ALLOWED_SLUG_DESTRUCTIONS` set
//     grows or a caller wraps the SSOT in a helper (interprocedural-hop).
//   * ENUMERATION-SCOPE UNDERCOUNT ON SHARED-MODULE SIBLINGS (2026-07-09
//     late-session  tranches 1-5 drive) — a class whose census hint
//     phrases scope as "concentrated in `<router-A>`, `<router-B>`,
//     `<router-C>`, scattered small counts elsewhere" is CIDI-shaped:
//     the analyst named the top-3 and hand-waved the tail. The 
//     drive found the count roughly DOUBLED once verify-against-HEAD
//     widened scope from `web/routers/**/*.py` to include the sibling
//     shared-dependency module `web/dependencies.py` (+8 sites) AND
//     `web/routers/api.py` (+30 sites — the JSON REST module silently
//     OUT-OF-scope of the "concentrated in ..." phrasing). Total drift:
//     68→108 sites. Refinement direction: for any class whose
//     enumeration lens is `web/routers/**`, ALSO scope
//     `web/dependencies.py`, `web/auth.py`, and `web/*.py` shared
//     modules. Reject "scattered small counts elsewhere" phrasing at
//     census-authoring time; require the tail-list enumerated with a
//     specific number.
//   * REGEX-BASED MIGRATION SCRIPTS BREAK MULTI-LINE IMPORTS — the
//     tranche 4 batch-migration script inserted an `import` line after
//     the "last-seen `from email_triage.`" line WITHOUT accounting for
//     that line being the OPEN of a multi-line import block. Syntax
//     error at py_compile. Fixed by relocating. Refinement direction:
//     AST-based migration (find TOP-LEVEL Import/ImportFrom nodes +
//     insert AFTER the last one). Applies to any bulk-edit script
//     under `scripts/`.
//
// ADDITIONAL 2026-07-09 drive-end classes (parallel fold to sibling
// `et-divergence-census.js` — post-99fc5b67 mirror per this script's
// stated "kept parallel" convention):
//   * OBSERVABILITY-BUCKET COMPENSATING CONTROL — a SOFT-variant of a
//     strict-required-spec closure ships via a fixed-enum-shape
//     `/health/detail` sibling bucket + rate-limited on-transition WARN.
//     Fold cite: N-316b `f2b9b214` + CI-red fix-forward `101b00c9`.
//   * MODULE-LEVEL PRIMITIVE ALIAS in AST detectors — pre-walk per-module
//     `alias = primitive` Assign + `from x import primitive as alias`
//     ImportFrom, union into gate-name set for THAT module only. Fold
//     cite: N-286b `29a3f199`.
//   * VERIFY-AGAINST-HEAD PARTIAL CLOSE POSTURE — category-sample
//     (10 SHAs / 7 categories) with uniform-pattern observation as
//     defensible PARTIAL close per BINDING  7-label. Fold cite:
//     `STATE_2026-07-09_meta_triage_115_118_partial_closed`.
//   * TIMESTAMP-STRING SSOT ROUTE — inline
//     `datetime.now(<tz>).isoformat().replace("+00:00", "Z")` trips both
//     A10 SSOT ratchet AND N-335b shadow-import pin. Always route
//     through `_isotime.now_utc_iso_z()`. Fold cite: N-316b CI-red
//     fix-forward `101b00c9`.
//   * NEW PIN AUTHORED WITHOUT HARNESS ADOPTION (pin-harness-drift RE-FIRED
//     on a fresh pin, not a legacy one) — `test_drain_audit_row_count_arm_
//     pin.py` landed at `da40ebd8` with a hand-rolled
//     `str(path).replace('\\', '/')` relpath instead of routing through
//     `_pin_harness.relpath`. `feedback_meta_pins_gate_new_pin_pushes`
//     REQUIRES a local `test_pin_harness_adoption.py` sweep before pushing
//     any new pin — meta-pin caught it in CI (Unit+Pin RED on `46dd4433`),
//     forcing same-drive fix-forward `5423c633` (harness route) +
//     `864bee86` (`test_pin_has_teeth` symmetric teeth). Refinement:
//     pin-harness-drift signature_hint should promote the pre-push
//     local-sweep requirement — census flags any new `*_pin.py` whose
//     ADD-commit doesn't touch `_pin_harness` OR `test_pin_harness_
//     adoption.py`'s `_ALLOW` list in the SAME commit.
// ---------------------------------------------------------------------------

// The catalog of operation-classes to census. Each is a "convergent intent,
// divergent implementation" candidate — the same logical operation plausibly
// done several ways. `why` cites prior evidence the drift is real where known.
// R23 workflow enhancement (2026-07-02): 1 pipeline agent failed on both
// R22 and R23 with "StructuredOutput retry cap exceeded" (the subagent
// finished its investigation but never emitted the schema-shaped result).
// Appending an explicit schema-final-call reminder to the prompt reduces
// that failure mode. Kept short — the schema itself carries the field list.
const SCHEMA_REMINDER =
    '\n\n=== FINAL STEP (do this before you stop): call the StructuredOutput ' +
    'tool with your findings shaped to the JSON schema. This is NOT a ' +
    'narrative response — the schema fields ARE the deliverable. If you ' +
    'have no findings, still emit the schema with an empty array + a note. ' +
    'The pipeline drops your output entirely if you skip the schema-call step.';

// R27 enhancement (post-R26 verify-don't-accept refutation of the ' +
// "494-site error-surface adoption debt" claim). Two failure modes ' +
// R26 revealed:
//   1. Over-counting: lumped literal-content safe operator-copy sites into ' +
//      an "adoption debt" bucket alongside actual PHI/exception injection ' +
//      shapes. HIGH severity applied wrongly to a class that was actually ' +
//      converged at HEAD.
//   2. Stale path citations: cited `actions/topic_digest_sender.py:568` ' +
//      when the actual path at HEAD is `web/topic_digest_sender.py:568`.
// Append this reminder to Discover + Verify prompts so subsequent runs ' +
// self-check the enumeration net against HEAD before framing a claim.
const VERIFY_AT_HEAD_REMINDER =
    '\n\n=== VERIFY-AT-HEAD DISCIPLINE (R27 enhancement, grounded in R26 ' +
    'refutation): before you frame a claim as HIGH severity or cite a ' +
    'per-file count, (a) ENUMERATE STRUCTURALLY via AST at HEAD — every ' +
    'site your claim depends on must be re-locatable via a paste-ready ' +
    'ast.walk detector, not just an LLM-grep sense; (b) VERIFY THE PATH ' +
    'EXISTS — a `path.exists()` check on every cited file:line before ' +
    'framing; a citation of `foo/bar.py:568` that does not exist at HEAD is ' +
    'a REFUTED claim, not a MED/HIGH one; (c) DIFFERENTIATE LIVE-DEFECT ' +
    'from ADOPTION-DEBT — a site running a literal-content safe operator ' +
    'string through the SSOT-adjacent shape is NOT a "V2 XSS/PHI leak"; ' +
    'differentiate the "carries user/exception content" shape (real risk) ' +
    'from the "carries a literal SSOT-safe template" shape (not a defect); ' +
    '(d) MASS-COUNT SANITY — a claim of "N sites" where N > 100 needs a ' +
    'paste-ready structural detector that returns exactly N, not an LLM-' +
    'estimate. R26 flagged 494 sites for error-surface; the structural ' +
    'scan at HEAD found 0-3 depending on the shape. Overcounting misroutes ' +
    'SME + operator effort.';

const CLASSES = [
  {
    key: 'audit-emit',
    title: 'HIPAA / audit-event emission',
    operation: 'recording an auditable event (PHI access, credential change, admin action) — AND its failure DISPOSITION',
    signature_hint: 'record_hipaa_access_event / record_access_event / record_auth_event (direct OR via a db_call(EMITTER,...) await-seam); inserts into hipaa_access_events / access_log / auth_events / log_entries; direct audit-row INSERTs; AND the swallow-disposition: an emit inside a try whose handler catches-all (Exception/BaseException/bare/tuple) WITHOUT re-raising (a /health-invisible best-effort write) vs one routed through the web._audit.safe_audit_write / safe_audit_write_async SSOT',
    why: 'KNOWN drift: finding N-33-B (a HIPAA send wrote access_log not the canonical hipaa_access_events → invisible to §164.312(b) reconciliation) + run17 #3/N-135 (the swallow-disposition: ~60 emits across 27 files swallowed in hand-rolled try/except, converged onto safe_audit_write[_async], pinned by tests/test_audit_emit_swallow_pin.py). LESSON (PD#4): an LLM-grep enumeration of this class UNDERCOUNTS badly — the #3 re-census hand-counted 3 swallows; the AST swallow-detector found 60. ENUMERATE STRUCTURALLY (see step 1b). FRAMING TRAP (run18 #7/N-164): an emission-pairing class of the form "every X must pair with an emit/event Y" must NOT be stated as "every record/call site pairs with Y" — that over-broad framing webhook-STORMS (one event per item in a batch) and false-flags deferred-emit callers; distinguish TERMINAL completion (emit ONCE) from PER-ITEM record (no emit), and key the pin on the TERMINAL seam. HIGH value (HIPAA-load-bearing).',
  },
  {
    key: 'permission-check',
    title: 'Authorization / access-scope gate',
    operation: 'gating a handler/action on who may access which account or resource',
    signature_hint: 'can_manage_account, _manageable_account_ids, _require_admin, _gate_account_ids, get_email_account (unscoped by-id), account-scope intersections in routers; the RAW by-id SQL fetch must be matched ALIAS-TOLERANTLY over a function\'s JOINED string-constant corpus — both /from\\s+email_accounts(\\s+\\w+)?\\b/ AND /where\\s+(\\w+\\.)?id\\s*=/ (run18 #8): the literal substring "from email_accounts where id" EVADES aliased SQL ("FROM email_accounts ea ... WHERE ea.id = ?") and a per-ast.Constant test inherits a split-FROM/WHERE blind spot; the \\b rejects email_accounts_archive and the id= form excludes WHERE ea.user_id = ? (by-user, not by-id)',
    why: 'KNOWN drift: finding N-28 — a handler skipped the §5 manageable-set intersection and opened an is-HIPAA enumeration oracle. HIGH value (HIPAA-load-bearing). run18 #8 widened the by-id pin (tests/test_authz_by_id_fetch_pin.py) raw-SQL net from a literal substring to the alias-tolerant FROM/WHERE pair over the joined corpus (drift-prevention; no live IDOR — all 4 aliased by-id fetches are gated db-helpers / the named get_email_account SSOT, zero ungated @router handlers).',
  },
  {
    key: 'egress',
    title: 'Outbound network call (PHI-egress surface)',
    operation: 'making an outbound HTTP/network request to a host outside the install',
    signature_hint: 'httpx, requests, urllib, aiohttp clients; .get(/.post( to external URLs; the egress allowlist; SSRF guards',
    why: 'project_no_external_data_flow enumerates allowed egress. Is every external call funneled through ONE allowlisted client, or scattered? HIGH value (PHI-egress).',
  },
  {
    key: 'secret-read',
    title: 'Credential / secret READ + config hydration',
    operation: 'reading a stored secret/credential and hydrating it into config',
    signature_hint: 'secrets.get(...), app.py startup hydration of config.*_oauth.*, providers/factory.py credential reads, _secret_key_for_account reads',
    why: 'Complement to the _secret_write SSOT just built (commit 1cbfe6e). Are reads + the config-hydration path consistent, or does each consumer re-derive? MED.',
  },
  {
    key: 'config-persist',
    title: 'Config / settings persistence (3 stores)',
    operation: 'persisting a configuration value',
    signature_hint: '_write_config_yaml(config), set_setting / set_bool_setting (settings table), secrets.set (secrets store) — and the BOUNDARY rules for which store a value belongs in',
    why: 'Three stores (YAML / settings-table / secrets) with fuzzy boundaries; a value written to the wrong store, or to two, drifts silently. MED.',
  },
  {
    key: 'provider-fetch',
    title: 'IMAP / provider message fetch',
    operation: 'fetching messages/headers/folders from a mailbox provider',
    // N-284 R30: signature widened after the R30 verifier proved this hint
    // missed 11 `list_folders` / `search_all_folders` call sites (a 36% V0
    // undercount on `fetch_message` too). The class covers ALL provider read
    // paths that could bypass the imap_blocking safe transport, not just the
    // headline `fetch_message`.
    signature_hint: 'imap_blocking.py (stdlib parser), aioimaplib usage, provider .search/.fetch/.list_history paths, headers_only fetch, .list_folders / .search_all_folders / .fetch_message call sites (interprocedural — count callers too, not just the definitions)',
    why: 'bug_aioimaplib_recursion: aioimaplib has a parens/recursion bug; imap_blocking is the safe path for header fetch. Is the safe path used consistently or bypassed? Widened R30 to include all folder/search paths since a bypass on ANY of them re-enters the aioimaplib recursion. MED.',
  },
  {
    key: 'error-surface',
    title: 'User-facing error / result surfacing from a handler',
    operation: 'reporting a save/action failure or result back to the operator',
    signature_hint: 'redirect ?err= / ?saved= querystring, inline HTMLResponse error fragments, flash messages, form_error context keys',
    why: 'Consistency of how handlers report failure to the operator — a silently-swallowed error is the failure mode behind several incidents. MED/LOW.',
  },
  {
    key: 'pinned-verify',
    title: 'Already-harmonized SSOTs — does each have a SOUND structural pin?',
    operation: 'verifying the existing SSOTs are enforced by a count-agnostic structural test whose net is complete',
    signature_hint: '@db_write + tests/test_db_write_coverage_pin.py; _secret_write.py + tests/test_no_unguarded_secret_write.py (interprocedural); llm_safety.py fence SSOT (NOTE: believed to have NO AST pin yet); m.secret_input + tests/test_credential_inputs_hardened.py',
    why: 'Harmonization DECAYS without a pin. Confirm each SSOT has a real pin AND the pin\'s enumeration is complete (interprocedural where the codebase hops values through db_call(helper,...)). llm_safety.py is the suspected gap. META value.',
  },
  {
    key: 'pin-harness-drift',
    title: 'The structural pins THEMSELVES — do they share the harness, or re-roll the walk/relpath/teeth?',
    operation: 'every count-agnostic structural pin (tests/*_pin.py + friends that walk src/email_triage) routes its file-walk, repo-relative path, AST parse, and enclosing-fn key through the shared harness tests/_pin_harness.py — never a hand-rolled SRC_ROOT/rglob/relative_to/parent-annotation copy',
    signature_hint: 'grep tests/ for rglob("*.py") + parents[N]/"src"/"email_triage" + relative_to(SRC) + .replace("\\\\","/")/.as_posix() in a file NOT importing _pin_harness; the canonical drifts are the relpath BASE divergence (relative_to(SRC)=\"web/db.py\" vs SRC.parent vs parents[1]) and the basename-vs-relpath allow-list bug (R38). The live guard is tests/test_pin_harness_adoption.py.',
    why: 'R5b/R5c — "census the censusers". The anti-drift layer drifts too: ~40 pins each hand-rolled the SRC-root + rglob + relpath boilerplate and DIVERGED in it (3 relpath bases; the auth_stale basename allow-list bug). They were converged onto tests/_pin_harness.py + the meta-pin test_pin_harness_adoption.py on 2026-06-11. A true-up must re-measure whether a NEW pin re-rolled the walk or a migrated pin drifted back off the harness — a census that never censuses its own anti-drift mechanism has a recursive blind spot. META value.',
  },
  {
    key: 'json-col-write',
    title: 'DB-column JSON encode (write twin of load_json_col)',
    operation: 'serializing a Python value to JSON for storage in a *_json DB column',
    signature_hint: 'json.dumps / JSONEncoder whose result is bound into a *_json column write (INSERT/UPDATE param); the bare json.dumps(x) vs compact separators=(",",":") vs canonical sort_keys/ensure_ascii=False option-split; the HMAC hash-preimage forms (triage_logging.py) that MUST stay byte-stable. The pinned READER is load_json_col (db/_helpers.py); the WRITER SSOT was never built. MEMBERSHIP PREDICATE: a json.dumps call whose value FLOWS to a *_json column param — AST-enumerate the flow, NOT a grep of json.dumps (95 hits vs ~66 true writers).',
    why: 'run18 #4 (discovered): ~66 unharmonized json.dumps writers into *_json columns vs the 1 pinned reader; 3-way option split → a hash-preimage fork risk in the audit chain + multilingual ensure_ascii bloat. WRITE TWIN of load_json_col (run17 #7/N-140). Build dump_json_col() next to load_json_col; ban bare json.dumps into a *_json column outside it (allow-list the hashed forms). MED.',
  },
  {
    key: 'ondisk-artifact-disposal',
    title: 'Per-account on-disk credential/state file — create vs dispose vs backup parity',
    operation: 'an account-scoped file written to disk OUTSIDE the SQLCipher DB (credential/token cache, state file) whose CREATE, DISPOSE-on-delete, and BACKUP sides must agree on the path set',
    signature_hint: 'a per-account file path (f"...{account_id}..." under a data dir) CREATED by a writer but NOT unlinked in the §164.310(d)(2)(i) disposal funnel (db/accounts.py purge_account_local_state / watcher.apply_account_deleted) AND/OR not collected by the backup bundle (backup.py). The CREATE side is typically broad (several writers); the DISPOSE + BACKUP sides narrow → drift. Exemplar: msal_cache_<id>.json (run18 #1/N-150). MEMBERSHIP PREDICATE: a write to a per-account on-disk path literal — AST-enumerate writers, then check each has a matching disposal unlink + a backup decision (bidirectional file-artifact invariant), NOT just DB-row purges (the old pin was file-BLIND).',
    why: 'run18 #1 (discovered, HIGH/LIVE): plaintext O365 OAuth tokens in ./data/msal_cache_<id>.json survived account purge — §164.310(d)(2)(i)+§164.312(a)(2)(iv). A NEW lens: "account-scoped on-disk artifact, CREATE broad but DISPOSE/BACKUP narrow." Also flags plaintext-at-rest (encrypt-at-rest Directive ) + the §164.308(a)(7) backup-completeness twin. HIGH value (HIPAA disposal + at-rest). UPGRADE 2026-07-09 (wf_56d1585d V6 fix at `de050c40`): SECONDARY drift shape — when a per-user artifact PATH-SHAPE MIGRATES (N-307 rename), a registry-driven disposer iterating `_USER_BUILDERS` + inline `builder(username).unlink(...)` unlinks ONLY the current-shape path; installs upgraded across the rename leak the PRIOR-SHAPE plaintext OAuth refresh_token file. Fix: aggregate disposer MUST ROUTE THROUGH the SSOT disposer (`dispose_<stem>_for_<scope>`) which knows both shape epochs — never re-inline the unlink loop. Discover-phase enumeration lens: for each `_ARTIFACT_BUILDERS` entry, assert a matching `dispose_<stem>_for_<scope>` SSOT exists AND is CALLED by the aggregate disposer (interprocedural symmetry at the seam per PD#2).',
  },
  {
    key: 'parse-int-request',
    title: 'Parse-int of a request value (the _safe_int SSOT)',
    operation: 'converting an attacker-controllable request value (form/query/path param) to int',
    signature_hint: 'int(<request-accessor>) — int(form.get(...)) / int(query_params...) / int(path_params...) / int(request.*) — OUTSIDE the _safe_int SSOT (web/routers/ui/_shared.py:104, swallows TypeError/ValueError→default). A bare int() OR int(x or 0) (which does NOT cover non-numeric) → an uncaught ValueError → HTTP 500 on a tampered value; vs a hand-rolled try/except (TypeError,ValueError) wrapper (correct-but-divergent CIDI drift). MEMBERSHIP PREDICATE: int(<call to a request accessor>) AST-enumerated — NOT a grep of int( (census hand-count ~72; AST net = 29 request-derived, 2 unguarded).',
    why: 'run18  (discovered, LOW-MED with 2 LIVE 500s): profile.py:1559/1564 int(form.get("def_id") or 0) → reachable 500 on non-numeric def_id today. _safe_int is the SSOT but ~29 sites bypass it. Route all through _safe_int; ban bare int(<request-accessor>) outside it. §164.308(a)(7) availability (a reachable 500), not PHI. MED.',
  },
  {
    key: 'canonical-email-bypass',
    title: 'canonical_email SSOT bypass on address vars',
    operation: 'normalising an email address for storage / allow-list lookup / display',
    signature_hint: 'inline `.strip().lower()` on a variable whose identifier matches /email|addr|recipient|sender|user_email|owner/ OUTSIDE `mail_headers.canonical_email` (the SSOT that also strips display-name wrapping + IDNA-normalises the domain). MEMBERSHIP PREDICATE: `ast.Attribute(attr="lower").parent.func == ast.Attribute(attr="strip")` on the same expr where the base receiver is a Name whose id matches the email-ident regex — NOT a text-grep for `.strip().lower()`.',
    why: 'DISCOVERED by census run wf_1296c6ba-9b8 (2026-07-04): 25 sites drift, several feeding §164.312(a)(1) HIPAA recipient allow-list gates. Display-name-wrapped (`"Alice" <alice@x.com>`) or IDN (`patient@Café.example`) inputs silently miss the allow-list because `.strip().lower()` alone drops neither the display wrapping nor IDNA-normalises the domain. mail_headers.canonical_email exists + is the SSOT; 25 callers open-code the shape. Seeded here per operator directive 2026-07-04 ("after EVERY census run, evaluate + enhance ... a class that should be seeded"). HIGH. Fix-forward tracker: N-346.',
  },
  {
    key: 'lifecycle-triple-clear-asymmetry',
    title: 'Lifecycle triple (status/error_count/error_last) UPSERT-side CLEAR omission',
    operation: 'UPSERTing a row whose schema carries a lifecycle triple (status TEXT, error_count INTEGER, error_last TEXT/TIMESTAMP), where a "fresh" write must reset the triple',
    signature_hint: 'an `INSERT ... ON CONFLICT(...) DO UPDATE SET ...` string constant that lists the operational columns (email/topic/history/id/updated_at) but omits `status = ...` / `error_count = ...` / `error_last = ...` in the SET list, while the same table\'s column set (via `PRAGMA table_info`) DOES include status/error_count/error_last. Sibling table (e.g. office365_subscriptions vs gmail_watches) provides the exemplar shape. MEMBERSHIP PREDICATE: AST-scan for `ast.Constant(value=str)` matching `/ON\\s+CONFLICT[^)]+DO\\s+UPDATE\\s+SET/i` AND the SET list does NOT contain status/error_count/error_last, PROVIDED the target table has those columns declared elsewhere in the module.',
    why: 'DISCOVERED by census run wf_1296c6ba-9b8 (2026-07-04): gmail_watches upsert omitted the lifecycle-triple CLEAR (4 of 5 callers relied on a follow-up `record_gmail_watch_outcome(None)` — the OAuth-recovery path silently skipped it, leaving the stale `errored` chip stuck). Fix-forward N-347 (80ad278d) extended the UPSERT SSOT itself to reset the triple inline; a future sibling table (topic_watches, ical_watches, …) growing the same triple will hit the same class. Seeded here so next census run catches it at DDL/SSOT landing. HIGH. §164.312(b) audit-visibility + operator-UX reliability.',
  },
]

const CENSUS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['class_key', 'signature', 'sites', 'variants', 'canonical_exists',
             'recommended_ssot', 'recommended_pin', 'weakest_variant',
             'severity', 'est_effort', 'notes', 'leira_status'],
  properties: {
    class_key: { type: 'string' },
    signature: { type: 'string', description: 'the exact grep/AST signature(s) used to enumerate — so completeness is auditable' },
    leira_status: {
      type: 'string',
      enum: ['served', 'timeout', 'empty', 'error', 'unavailable', 'unavailable_awaiting_op_confirm'],
      description: 'REQUIRED per 2026-07-18 sharpening + operator directive "fallback to AI provider only after confirming with me". "served" = prepass returned non-empty JSON on 1st or 2nd attempt. "timeout"/"empty"/"error"/"unavailable" = both attempts failed; MUST run the troubleshooting suite AND set status to "unavailable_awaiting_op_confirm" (do NOT silently AST-only-walk). The Phase-0 warm-up SHOULD have caught this before you got here; if you see this in a Census subagent it means the warm gate slipped.',
    },
    troubleshooting: {
      type: 'string',
      description: 'REQUIRED when leira_status != "served". Verbatim ollama-ps + ollama-list + the monitoring system-log-tail 20 llm-host output + first stderr line from the prepass. Operator inspects this to determine whether to authorize an AI provider-only fallback re-fire.',
    },
    sites: {
      type: 'array',
      description: 'every implementation site found',
      items: {
        type: 'object', additionalProperties: false,
        required: ['file', 'line', 'variant_label'],
        properties: {
          file: { type: 'string' }, line: { type: 'integer' },
          variant_label: { type: 'string' },
        },
      },
    },
    variants: {
      type: 'array',
      description: 'the distinct implementation variants, clustered',
      items: {
        type: 'object', additionalProperties: false,
        required: ['label', 'count', 'description', 'risk'],
        properties: {
          label: { type: 'string' }, count: { type: 'integer' },
          description: { type: 'string' },
          risk: { type: 'string', description: 'concrete risk this variant carries' },
        },
      },
    },
    canonical_exists: { type: 'boolean', description: 'does a canonical/safest variant or SSOT already exist?' },
    canonical: { type: 'string', description: 'the existing canonical SSOT/variant, or "none"' },
    recommended_ssot: { type: 'string', description: 'the single source of truth all sites should route through' },
    recommended_pin: { type: 'string', description: 'the count-agnostic structural test that would fail CI on a future off-SSOT variant' },
    weakest_variant: { type: 'string' },
    severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
    est_effort: { type: 'string', enum: ['S', 'M', 'L', 'XL'] },
    notes: { type: 'string' },
  },
}

const VERIFY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['class_key', 'enumeration_complete', 'missed_sites',
             'canonical_claim_holds', 'severity_verdict', 'notes'],
  properties: {
    class_key: { type: 'string' },
    enumeration_complete: { type: 'boolean', description: 'did the census agent find ALL sites? (the show-me-your-net discipline)' },
    missed_sites: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['file', 'line', 'why_missed'],
        properties: {
          file: { type: 'string' }, line: { type: 'integer' }, why_missed: { type: 'string' },
        },
      },
    },
    canonical_claim_holds: { type: 'boolean' },
    severity_verdict: { type: 'string', description: 'agree with the census severity, or adjust (with reason)' },
    notes: { type: 'string' },
  },
}

// Open-ended discovery lenses — find CIDI cases BEYOND the seeded classes.
// Deliberately general + un-primed (no specific bug named) so a hit is a real
// validation of the audit, not a plant. The "lifecycle-flags" lens covers the
// classic set-broad / clear-narrow asymmetry; the others cover cross-cutting
// concerns + same-effect-different-mechanism.
const DISCOVERY_LENSES = [
  {
    key: 'lifecycle-flags',
    prompt:
      'Find a LIFECYCLE FLAG / status-state pattern handled ASYMMETRICALLY across code paths — a flag, ' +
      'setting, or piece of state that is SET (or invalidated) on one condition but whose corresponding ' +
      'CLEAR / reset / refresh is wired into only SOME of the paths that should trigger it. The classic ' +
      'shape: the set-side has a broad set of triggers while the clear-side is wired into one narrow path, ' +
      'so the state goes STALE on the other paths. For each candidate give the set-sites and the clear-sites ' +
      '(file:line) and name the paths where the clear is MISSING.',
  },
  {
    key: 'cross-cutting',
    prompt:
      'Find a CROSS-CUTTING concern — structured logging, audit emission, cache invalidation, metric/counter ' +
      'update, status-flag maintenance, error handling — applied in SOME code paths handling the same logical ' +
      'operation but inconsistently or entirely MISSING in sibling paths. Give the paths that DO and DO NOT ' +
      'apply it (file:line).',
  },
  {
    key: 'same-effect-diff-mechanism',
    prompt:
      'Find the SAME logical effect achieved via DIFFERENT mechanisms/helpers/inline code across the codebase — ' +
      'multiple implementations of one operation where consolidating to a single source of truth would prevent ' +
      'future drift. Give the divergent implementations (file:line) and the unifying SSOT.',
  },
]

const DISCOVERY_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['lens', 'candidates'],
  properties: {
    lens: { type: 'string' },
    candidates: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['title', 'operation', 'consistent_sites',
                   'divergent_or_missing_sites', 'why', 'severity',
                   'recommended_ssot_or_fix'],
        properties: {
          title: { type: 'string' },
          operation: { type: 'string' },
          consistent_sites: {
            type: 'array',
            items: {
              type: 'object', additionalProperties: false,
              required: ['file', 'line'],
              properties: { file: { type: 'string' }, line: { type: 'integer' } },
            },
          },
          divergent_or_missing_sites: {
            type: 'array',
            items: {
              type: 'object', additionalProperties: false,
              required: ['file', 'line', 'note'],
              properties: {
                file: { type: 'string' }, line: { type: 'integer' },
                note: { type: 'string' },
              },
            },
          },
          why: { type: 'string' },
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
          recommended_ssot_or_fix: { type: 'string' },
        },
      },
    },
  },
}

// Completeness-verify schema for the Discover phase (added 2026-06-09 after
// the auth_stale canary slipped past: each lens surfaced SALIENT instances,
// not ALL — there was no enumerate-the-full-population check).
const COMPLETENESS_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['pattern', 'enumeration_signature', 'all_instances', 'newly_found_beyond_original'],
  properties: {
    pattern: { type: 'string' },
    enumeration_signature: { type: 'string', description: 'how the FULL population of this shape was enumerated (the grep/AST net)' },
    all_instances: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['file', 'line', 'note'],
        properties: { file: { type: 'string' }, line: { type: 'integer' }, note: { type: 'string' } },
      },
    },
    newly_found_beyond_original: {
      type: 'array',
      description: 'instances of this shape the ORIGINAL finding did not cite (the completeness payoff)',
      items: {
        type: 'object', additionalProperties: false,
        required: ['file', 'line', 'note'],
        properties: { file: { type: 'string' }, line: { type: 'integer' }, note: { type: 'string' } },
      },
    },
  },
}

phase('Warm')

// Phase-0 warm-up + fail-fast llm-host gate (2026-07-18 sharpening — run21
// lesson + operator directive "always utilize llm-host offload for a census
// loop. Fallback to AI provider only after confirming with me. Attempt to
// troubleshoot llm-host connection"). Fire a single low-effort probe against
// `scripts/leira_census_prepass.py`. Purpose:
//   (a) hot-load qwen3.6:35b on llm-host so the first real Census subagent's
//       prepass finds a warm model;
//   (b) if llm-host is unreachable, HALT the workflow BEFORE fanning out 39
//       Census subagents that would each pay a 100k+ AI provider-token
//       tax to enumerate their class from scratch (run21 shape).
// Fallback to AI provider-only enumeration is OPERATOR-GATED, never
// automatic — see feedback_leira_silent_fallback_wastes_offload.
const _warmResult = await agent(
  `Warm-up probe for the llm-host census prepass — hot-load qwen3.6:35b on llm-host BEFORE the Census fan-out.\n\n` +
  `STEP 1: Run this ONCE, foreground, with a shell-level 180s timeout:\n\n` +
  `  timeout 180 python scripts/leira_census_prepass.py \\\n` +
  `    --class-key warmup \\\n` +
  `    --class-title "warmup" \\\n` +
  `    --class-operation "hot-load qwen3.6:35b" \\\n` +
  `    --signature-hint "any function"\n\n` +
  `If the output is a non-empty JSON candidate list (or JSON \`{"sites":[]}\` with exit 0), llm-host served — return ` +
  `\`{"leira_status":"served"}\` and stop.\n\n` +
  `STEP 2 (only if STEP 1 failed — empty output / non-zero exit / timeout): before returning any failure status, ` +
  `RUN THE TROUBLESHOOTING SUITE (per BINDING feedback_leira_silent_fallback_wastes_offload):\n` +
  `  ssh the gateway host "python3 <your monitoring tool> llm-host ollama-ps"\n` +
  `  ssh the gateway host "python3 <your monitoring tool> llm-host ollama-list"\n` +
  `  ssh the gateway host "python3 <your monitoring tool> the monitoring host the monitoring system-log-tail 20 llm-host"\n\n` +
  `Return \`{"leira_status":"unavailable_awaiting_op_confirm","stderr":"<first-line-of-prepass-stderr>","ollama_ps":"<verbatim>","ollama_list":"<verbatim>","nagios_tail":"<verbatim>"}\` — do NOT silently proceed; do NOT invent a candidate list; do NOT run the Census enumeration. Fallback to AI provider-only census is OPERATOR-GATED per the drawer above.`,
  {
    label: 'warm:qwen3.6:35b', phase: 'Warm', effort: 'low',
    schema: {
      type: 'object',
      additionalProperties: false,
      required: ['leira_status'],
      properties: {
        leira_status: {
          type: 'string',
          enum: ['served', 'timeout', 'empty', 'error', 'unavailable', 'unavailable_awaiting_op_confirm'],
        },
        stderr: { type: 'string' },
        ollama_ps: { type: 'string' },
        ollama_list: { type: 'string' },
        nagios_tail: { type: 'string' },
      },
    },
  },
)

// HARD GATE — halt the whole workflow if the warm-up says llm-host is
// unreachable. Prevents run21-style 4M AI provider-token silent-fallback.
if (_warmResult && typeof _warmResult === 'object' && _warmResult.leira_status && _warmResult.leira_status !== 'served') {
  log(`Phase-0 warm-up returned leira_status=${_warmResult.leira_status} — HALTING workflow. Operator confirmation required before AI provider-only fallback.`)
  return {
    halted: true,
    reason: 'llm-host-unavailable',
    warm_result: _warmResult,
    operator_action: 'Review the troubleshooting evidence in warm_result. If llm-host is fixable (cold model, network blip, keepalive dropped), warm it and re-fire this workflow. If llm-host is genuinely unavailable and you want to proceed on AI provider tokens anyway, explicitly authorize (~4-5M subagent-token cost) then re-invoke.',
  }
}

phase('Census')

const results = await pipeline(
  CLASSES,
  // Stage 1 — census one operation-class.
  (cls) => agent(
    `You are auditing the email-triage codebase (HIPAA-class FastAPI/Jinja/SQLite app at ` +
    `the repo root = your current working directory, source under src/email_triage/) for ` +
    `"convergent intent, divergent implementation" — the SAME logical operation implemented several ways.\n\n` +
    `OPERATION CLASS: ${cls.title}\n` +
    `The operation: ${cls.operation}\n` +
    `Where to look (signature hint, NOT exhaustive — widen it): ${cls.signature_hint}\n` +
    `Why this class matters: ${cls.why}\n\n` +
    `Do this, REPORT don't fix:\n` +
    `0. llm-host PRE-PASS (starting hint, NOT the answer). Run FOREGROUND, wait for the JSON, DO NOT bg-and-continue:\n` +
    `   python scripts/leira_census_prepass.py \\\n` +
    `     --class-key ${JSON.stringify(cls.key)} \\\n` +
    `     --class-title ${JSON.stringify(cls.title)} \\\n` +
    `     --class-operation ${JSON.stringify(cls.operation)} \\\n` +
    `     --signature-hint ${JSON.stringify(cls.signature_hint)}\n` +
    `   The output is a JSON candidate site list (file:line + one-line note per site) from a ` +
    `llm-host (qwen3.6:35b) pre-scan. Treat it as a PROBE, NOT the answer: (a) llm-host's context is bounded so ` +
    `raw grep past a cap is DROPPED — the enumeration is knowingly INCOMPLETE; (b) llm-host does NO AST ` +
    `resolution and cannot see helper-hops / dynamic dispatch. You MUST still run the structural AST ` +
    `walk in step 1b — the pre-pass is a starting hint that saves you the raw grep pass, nothing more.\n\n` +
    `llm-host-STATUS DISCIPLINE (SHARPENED 2026-07-18 after operator directive "Always utilize llm-host offload for a ` +
    `census loop. Fallback to AI provider only after confirming with me. Attempt to troubleshoot llm-host connection." ` +
    `+ run21 silent-fallback lesson):\n` +
    `   * Reaching this subagent means the Phase-0 warm-up ALREADY confirmed llm-host is served + qwen3.6:35b is loaded. ` +
    `If your prepass call still fails here, retry ONCE with a shell timeout of 180s.\n` +
    `   * If EITHER attempt succeeds: populate \`leira_status="served"\` + cite the pre-pass in your 'signature' ` +
    `field (e.g. "llm-host pre-pass + AST walk") + proceed to step 1 with the candidate list.\n` +
    `   * If BOTH attempts fail: DO NOT silently AST-only-walk. RUN THE TROUBLESHOOTING SUITE and return early ` +
    `WITHOUT enumerating your class. Per BINDING feedback_leira_silent_fallback_wastes_offload, fallback to ` +
    `AI provider-only enumeration is OPERATOR-GATED, never automatic. Fill the required schema fields as follows:\n` +
    `       ssh the gateway host "python3 <your monitoring tool> llm-host ollama-ps"\n` +
    `       ssh the gateway host "python3 <your monitoring tool> llm-host ollama-list"\n` +
    `       ssh the gateway host "python3 <your monitoring tool> the monitoring host the monitoring system-log-tail 20 llm-host"\n` +
    `     Then return \`leira_status="unavailable_awaiting_op_confirm"\` + \`troubleshooting\` = verbatim ollama-ps + ` +
    `ollama-list + nagios_tail + first stderr line, and set every enumeration field to a MINIMAL early-return ` +
    `stub (sites=[], variants=[{"label":"leira_unavailable","count":0,"description":"census aborted awaiting op ` +
    `confirm","risk":"none"}], canonical_exists=false, canonical="", recommended_ssot="halted", recommended_pin="halted", ` +
    `weakest_variant="halted", severity="LOW", est_effort="S", notes="llm-host UNAVAILABLE — awaiting operator ` +
    `confirmation before AI provider-only fallback per feedback_leira_silent_fallback_wastes_offload"). ` +
    `The parent workflow aggregates these + surfaces the bundle for operator review.\n` +
    `   * NEVER return \`leira_status="served"\` or a "llm-host pre-pass + AST walk" signature when llm-host did not ` +
    `serve — the run21 silent fallback burned 4.27M AI provider tokens exactly because subagents mis-labelled ` +
    `their failure as success.\n` +
    `1. ENUMERATE every site that performs this operation. Use Grep/Glob/Read. State the EXACT ` +
    `signature(s) you searched (so completeness is auditable) and widen beyond the hint — find the sites the ` +
    `obvious grep misses (values passed through a db_call(helper,...) threadpool hop, re-exports, aliases).\n` +
    `1b. IF the divergence is STRUCTURALLY EXPRESSIBLE — an AST-checkable property over call sites (e.g. ` +
    `"emitter call inside a try whose handler swallows", "by-id fetch with no gate in the same handler", ` +
    `"INSERT outside the @decorator", "raw sqlite3.connect not the encryption-aware opener") — you MUST write a ` +
    `throwaway AST detector (python -c with ast.walk over src/email_triage, reusing tests/_pin_harness.py's ` +
    `iter_src_files/relpath) and report ITS site list as authoritative in the 'signature' + 'sites' fields. An LLM ` +
    `grep UNDERCOUNTS structurally-detectable classes: in run17 #3 a grep enumerated 3 audit-emit swallows while ` +
    `the AST detector found 60 across 27 files (a 20x miss the grep-based verify ALSO passed). The grep is the ` +
    `hint; the AST walk is the net. This detector is also the seed for the recommended_pin in step 5.\n` +
    `1c. MEMBERSHIP-PREDICATE DISCIPLINE (PD#4 — the run18 recurring failure mode). DECLARE the EXACT membership ` +
    `predicate your net keyed on (the decorator / receiver-TYPE / call-name / SQL-shape) AND assert it is a SUPERSET of ` +
    `the operation class you were asked to enumerate, not a narrower proxy. FOUR nets this audit shipped GREEN-AND-WRONG ` +
    `because the predicate was narrower than the class: (i) audit-emit keyed on a HARDCODED 3-emitter name-list when an ` +
    `@audit_emitter AST-walk yields 11 (and even that missed db_call-as-_db_call seam aliases + conditional 'if env: raise' ` +
    `swallows); (ii) authz keyed on the literal substring "from email_accounts where id" which misses aliased SQL ` +
    `("FROM email_accounts ea ... WHERE ea.id ="); (iii) config/secret-read keyed on a receiver-NAME substring ` +
    `(secret|provider) instead of the receiver TYPE (isinstance SecretsProvider/DbSecrets) so bootstrap.set / renamed ` +
    `handles escaped; (iv) the pin-harness meta-pin exempts by the import-SUBSTRING '"_pin_harness" in text', so a file ` +
    `that imports the harness yet ALSO hand-rolls a SECOND raw walk stays invisible. The receiver-NAME trap RECURRED ` +
    `AGAIN at finer grains in run18: (v) a pin keyed on a receiver variable-NAME substring (secret|provider) was BLIND ` +
    `to a factory-bound secrets receiver — fix = resolve the receiver by its SecretsProvider TYPE, not its name ` +
    `(N-161 #5); and (vi) a credential read keyed on a literal env-var KEY was only caught for the ".get" spelling — ` +
    `fix = ban ALL spellings (os.environ.get / os.getenv / environ[KEY] subscript / a bare environ walk), not one ` +
    `(N-163 #6). RULE: if your predicate is a name-list / literal-substring / receiver-NAME / single-SPELLING match it ` +
    `is blind BY CONSTRUCTION — widen it STRUCTURALLY: a receiver predicate → TYPE-resolution (isinstance/annotation), ` +
    `a literal-KEY predicate → an ALL-SPELLINGS ban, an SQL/decorator predicate → an alias-tolerant regex / ` +
    `decorator-walk — then re-enumerate; set enumeration_complete=false unless you proved predicate ⊇ class. Be ` +
    `especially skeptical when a class claims its OWN prior closure ("0 unrouted / converged" / "no live debt") — ` +
    `re-derive from scratch; run18 caught audit-emit, pin-harness, AND secret-read over-reporting their closure.\n` +
    `1d. RUN20 §7#1 PREDICATE-WIDTH CHECK. If your class has a NAME-LIST membership predicate (a specific set ` +
    `of decorators / function-names / table-names), you MUST ALSO declare a STRUCTURAL predicate that ` +
    `SUPERSETS the name-list, run both, and REPORT BOTH COUNTS in the census output. Refuse ` +
    `enumeration_complete=true if the two counts differ by more than 20%. run20 §7 documented SIX classes ` +
    `where the AST-structural predicate materially outperformed the initial hint's name-list — pinned-verify ` +
    `4→65 (16x), error-surface 55→411 (7.5x), pin-harness-drift 41→93 (2.3x), secret-read 6→15 (2.5x), ` +
    `audit-emit 2→3 + insert_log_entry missed entirely, permission-check V3 chain. When counts diverge that ` +
    `far, the name-list is the WRONG predicate for the class — widen it structurally BEFORE reporting a site set.\n` +
    `2. CLUSTER the sites into distinct VARIANTS by HOW each handles the contract around the operation ` +
    `(the guard, the ordering, the error-handling, the intent-declaration, which store/table). Name each variant + count.\n` +
    `3. For each variant state the CONCRETE risk it carries (what breaks, when).\n` +
    `4. Say whether a canonical/safest variant or SSOT ALREADY exists.\n` +
    `5. Recommend the ONE SSOT to route all sites through, AND the count-agnostic structural test ` +
    `(AST/grep pin, per the project's pattern_count_agnostic_structural_drift_catch — assert a PROPERTY over every ` +
    `site, never a count) that would fail CI on a future off-SSOT variant. If the codebase hops values through ` +
    `helpers, the pin must be interprocedural. Where the class is a render-redaction / view-leak class (PHI scrubbed ` +
    `before a template render), the pin is a RENDERED-VIEW test that MUST exercise the COUNT-GATED multi-item branch ` +
    `with a fixture of ≥2 items: run18 N-162 was a multi-folder PHI render leak that escaped the suite because every ` +
    `existing test used a SINGLE item and never hit the "|length > 1" gate guarding the leaking render sites (PD#17 — ` +
    `test the rendered view, AND the count-gated branch of it).\n` +
    `6. Rate overall severity (weakest variant's blast radius, weighted by HIPAA-load-bearing) + effort to harmonize.\n` +
    `Reference exemplars already in-tree: @db_write + tests/test_db_write_coverage_pin.py, ` +
    `_secret_write.py + tests/test_no_unguarded_secret_write.py.` + SCHEMA_REMINDER,
    { label: `census:${cls.key}`, phase: 'Census', schema: CENSUS_SCHEMA },
  ),
  // Stage 2 — adversarially verify the census was COMPLETE.
  (census, cls) => agent(
    `Adversarially verify a divergence-census finding for operation-class "${cls.title}" in email-triage ` +
    `(repo root = your current working directory; source under src/email_triage/). The census agent reported:\n\n` +
    `Signature searched: ${census ? census.signature : '(census failed)'}\n` +
    `Sites found: ${census ? census.sites.length : 0}\n` +
    `Variants: ${census ? JSON.stringify(census.variants.map(v => ({label: v.label, count: v.count}))) : '[]'}\n` +
    `Claims canonical exists: ${census ? census.canonical_exists : 'n/a'} (${census ? census.canonical : ''})\n` +
    `Severity: ${census ? census.severity : 'n/a'}\n\n` +
    `Your job — find what it MISSED (the "show me your net was complete" discipline). Re-run your OWN ` +
    `enumeration with broader signatures (aliases, re-exports, helper-hops, dynamic dispatch). WHERE the class is ` +
    `structurally expressible, RE-ENUMERATE with your OWN AST detector (python -c + ast.walk over src/email_triage), ` +
    `NOT just a broader grep — a structural count exceeding the census's site list is the run17 #3 failure mode (3 ` +
    `reported, 60 real, and a grep-based verify rubber-stamped it).\n\n` +
    `RUN19 LESSONS — three STALE-detection traps that rubber-stamped false-live findings when Consumer #2 caught them:\n` +
    `(1) PIN-ALREADY-WIDENED: if the census claims a pin's net is incomplete, READ that pin file's DOCSTRING at HEAD ` +
    `— it often self-documents recent widenings (e.g. run19 F1 permission-check: the pin's docstring said "the old ` +
    `_GATE_NAMES net was incomplete (6 names)" — meaning it had already been widened; a live re-read revealed STALE, ` +
    `not incomplete). A docstring that names a prior fix is STRONG evidence the class is closed at HEAD.\n` +
    `(2) EQUIVALENT-PIN-DIFFERENT-NAME: if the census claims a guard pin is missing, GREP for equivalently-purposed pins ` +
    `with alternate naming (e.g. run19 F3 config-persist: census claimed no test_no_unguarded_settings_write; HEAD had ` +
    `test_settings_key_catalog_pin.py which IS the guard, just named around the catalog SSOT). "Guard exists under a ` +
    `different filename" = STALE, not missing.\n` +
    `(3) LATENT-BUT-BOUNDED: distinguish real-live drift from latent-but-bounded shapes (e.g. run19 D2 bijection sites ` +
    `looked real but were structurally bounded — no live leak). If the mechanism is real but the trigger is guarded ` +
    `elsewhere in the same handler / SSOT, DOWNGRADE to LATENT with the specific guard cited, don't rubber-stamp LIVE.\n` +
    `(4) VERIFIER-HALLUCINATED-SSOT (added run21 D2 2026-07-18): when the census/claim NAMES an SSOT function or module ` +
    `by exact identifier (e.g. "route through record_message_result at web/_watch_status_recorder"), your FIRST tool ` +
    `call MUST be a repo-wide grep for BOTH the identifier AND the containing module — verify they exist at HEAD ` +
    `before comparing sibling shapes. Run21 D2 claim asserted a per-message SSOT that never existed; the actual seam ` +
    `is a DIFFERENTLY-NAMED aggregate (record_triage_run) that BOTH IMAP+O365 poll paths already route through. ` +
    `Missing-SSOT = the CLASS is CLOSED at HEAD under a different shape than the claim named. Verdict=STALE + cite ` +
    `the actually-present seam; do NOT fabricate the missing SSOT to make the claim true.\n` +
    `(5) BLANKET-EXEMPTION-HIDES-SECOND-TARGET (added run21 D1 2026-07-18): a pin that exempts an ENTIRE fn body when ` +
    `it detects ANY use of the SSOT (e.g. "if _fn_calls_atomic_ssot(fn): continue") is a false-negative surface — a fn ` +
    `can legitimately route ONE write through the SSOT while still hand-rolling a divergence on a SECOND, unrelated ` +
    `target. When VERIFY-ing a pin the census cites, walk the pin code for a fn-body blanket-exemption pattern and ` +
    `flag it as a NTH ("pin has fn-body blanket exemption; over-broad"). DA route: propose dropping the exemption ` +
    `same-drive if the SSOT's OWN file is already exempted by the outer file-name allow-list.\n` +
    `(6) DOCUMENTED-WAITING-ON-OP (added run21 D3 2026-07-18): when a widened pin catches a site whose OWN in-source ` +
    `docstring/comment block explains the divergence is a compat concern (e.g. safe migration requires a backfill or ` +
    `dual-shape lookup), verdict=STALE-w-doc-cite; the fix is allow-list-entry-with-citation, not re-open the deferred ` +
    `question. Grep the site's containing fn AND the nearest preceding comment block for tokens like "WAITING-ON-OP" / ` +
    `"deferred" / "backfill required" / "compat" before proposing an immediate migration. Run21 D3 caught web/db.py:: ` +
    `upsert_gmail_watch this way — was correctly exempted with citation, not re-migrated.\n` +
    `(7) FORK-CLAIM-WITHOUT-COMPARISON (added run22 D3 2026-07-18): when the census/claim asserts two normalization ` +
    `sites (e.g. .lower() vs .casefold(), .strip() vs .lstrip()) constitute a FORK on a shared value, your FIRST tool ` +
    `call MUST be a caller-trace on BOTH sides — does a single value flow from one normalizer's output into another's ` +
    `comparison, hash, or persisted store? If BOTH sides are internally symmetric (each writer's output is consumed ` +
    `only by an equivalently-normalized reader on the same code path), there is NO fork — it is design symmetry, not ` +
    `drift. Run22 D3 claimed a Message-ID .lower() vs .casefold() fork; both sites had one caller each on internally ` +
    `symmetric paths (PRIMARY-KEY conflict on same-transform column; in-memory == on both sides) so no cross-produce/` +
    `consume path existed. Two independent normalizations are NOT a fork unless the write of one is the read of the ` +
    `other. Verdict=STALE + cite the symmetric caller pair; do NOT propose a shared-SSOT unless a real cross-flow ` +
    `exists.\n` +
    `(8) HIPAA-DELIBERATE-RETENTION (added run22 D1 2026-07-18): before proposing a lifecycle-flag CLEAR funnel ` +
    `(e.g. "chips stuck on paused account", "status='errored' never resets"), grep the SET-site's OWN file for an ` +
    `in-source docstring/comment naming a deliberate-retention posture (regulatory anchor citations like §164.502, ` +
    `N-* posture names, "fail-closed at the actuator", "reflects real provider-side state during expiry window"). ` +
    `If present, the retention IS the compliance posture — "chips stuck" is the wrong framing. Verdict=STALE-w-doc- ` +
    `cite; do NOT propose a clear funnel. Run22 D1 verifier missed that web/watcher.py:1264-1274 explicitly documents ` +
    `the N-62 posture (soft-deactivate deliberately preserves gmail_watches.status / o365_subs.status during the 3-7 ` +
    `day expiry window). Trace also to the reader (verify the flag is not rendered on the paused-account row) — a ` +
    `retained flag that does not render is not user-visible drift either.\n\n` +
    `RUN20 §7#4 COUNT-DISCREPANCY CHECK — the census counts SSOT sites-registered (function-body); ` +
    `you must ALSO count call-site usages (grep for each SSOT function-name across the codebase) and flag any ` +
    `discrepancy ≥30% as a "counting-convention gap" — run20 provider-fetch had 23 registered vs ~55 real call ` +
    `sites and the verify agent didn't notice. When they diverge you may still accept enumeration_complete=true ` +
    `IF the census explicitly names which count it used, but SEVERITY must reflect the wider one.\n\n` +
    `RUN20 §7#6c CANONICAL-CLAIM SKEPTICISM WHEN HISTORY EXISTS — REJECT canonical_claim_holds=true when the class has ` +
    `a documented prior-unsoundness track record. Known-drifty classes: audit-emit (run17 #3), pin-harness (run15/17/18 ` +
    `widenings), pinned-verify (run20 §7). For those, treat "canonical exists" as a HYPOTHESIS and re-derive its site ` +
    `set structurally BEFORE agreeing.\n\n` +
    `Report: (a) was the ` +
    `enumeration complete, and any sites it missed with file:line; (b) does the canonical/SSOT claim actually hold ` +
    `(or is the "canonical" itself one of several variants); (c) is the severity right; (d) ONE of the three run19 ` +
    `STALE traps apply → verdict=STALE with the specific docstring/pin/guard citation, NOT enumeration_complete=false. ` +
    `Default to enumeration_complete=false if you find ANY missed site AND none of the three STALE traps apply.` +
    VERIFY_AT_HEAD_REMINDER + SCHEMA_REMINDER,
    { label: `verify:${cls.key}`, phase: 'Verify', schema: VERIFY_SCHEMA },
  ).then(v => ({ census, verify: v, cls: cls.key })),
)

phase('Discover')

// Open-ended, un-primed discovery (3 lenses in parallel). A hit here that
// matches no seeded class is a genuine validation that the audit finds drift
// it was NOT told about (the operator's canary). No specific bug is named.
const discovered = (await parallel(DISCOVERY_LENSES.map(L => () =>
  agent(
    `You are doing OPEN-ENDED divergence discovery on the email-triage codebase (HIPAA-class FastAPI/Jinja/SQLite ` +
    `app; source under src/email_triage/ in your current working directory). The seeded ` +
    `census already covers these — do NOT re-report them: audit-event emission, authz/permission checks, ` +
    `outbound egress, secret reads, config persistence, provider/IMAP fetch, user-facing error surfacing.\n\n` +
    `Find OTHER "convergent intent, divergent implementation" cases (the same logical operation handled several ` +
    `ways, or a concern applied to some code paths but not its sibling paths). Specifically:\n${L.prompt}\n\n` +
    `Use Grep/Glob/Read across src/email_triage (include web/, web/routers/, actions/, classify/, db/). Report ` +
    `concrete candidates with file:line evidence; rate each severity + name the unifying SSOT/fix. Be specific — ` +
    `a maintainer must be able to act on each. An empty list is a fine answer if you find nothing real.` +
    VERIFY_AT_HEAD_REMINDER + SCHEMA_REMINDER,
    { label: `discover:${L.key}`, phase: 'Discover', schema: DISCOVERY_SCHEMA },
  )
))).filter(Boolean)
const discoveredCount = discovered.reduce(
  (n, d) => n + (d.candidates ? d.candidates.length : 0), 0,
)
log(`Discovery surfaced ${discoveredCount} candidate new class(es) beyond the seeded set`)

// Discover COMPLETENESS-VERIFY — the 2026-06-09 canary fix. Each lens finds
// SALIENT instances, not ALL (that's how the known auth_stale set-broad/
// clear-narrow defect slipped past — the lifecycle lens found ONE flag and
// stopped). For each discovered pattern, enumerate the FULL population of that
// exact shape and check every member, surfacing the sites the original finding
// did NOT cite.
const _allCands = discovered.flatMap(
  g => (g.candidates || []).map(c => ({ lens: g.lens, c })),
)
const completeness = (await parallel(_allCands.map(({ c }) => () =>
  agent(
    `A divergence pattern was found in email-triage (source under ` +
    `src/email_triage/ in your current working directory).\n` +
    `PATTERN: "${c.title}"\nOperation: ${c.operation}\nWhy divergent: ${c.why}\n\n` +
    `That finding cites only a few sites. Your job is COMPLETENESS for this exact shape — be exhaustive. ` +
    `FIRST enumerate the FULL POPULATION (e.g. if it is a status-flag set/clear asymmetry, list EVERY status ` +
    `flag / setting the app writes, then check each one's clear-side coverage; if it is an inline idiom, grep ` +
    `EVERY occurrence). THEN check each member. Report ALL instances of this shape, and SEPARATELY the ones ` +
    `the original finding did NOT cite. Show the enumeration signature you used so the net is auditable.` + SCHEMA_REMINDER,
    { label: `complete:${(c.title || '').slice(0, 22)}`, phase: 'Discover', schema: COMPLETENESS_SCHEMA },
  ),
))).filter(Boolean)
const newlyFound = completeness.reduce(
  (n, r) => n + (r.newly_found_beyond_original ? r.newly_found_beyond_original.length : 0), 0,
)
log(`Completeness-verify found ${newlyFound} additional instance(s) the lenses missed`)

phase('Synthesize')

const clean = results.filter(Boolean).filter(r => r.census)
log(`Censused ${clean.length}/${CLASSES.length} seeded + ${discoveredCount} discovered; synthesizing`)

const backlog = await agent(
  `You are the synthesizer for a "divergence census" of the email-triage codebase. Below is (1) the structured ` +
  `census + adversarial-verification for ${clean.length} SEEDED operation-classes, and (2) ${discoveredCount} ` +
  `DISCOVERED candidate classes from an open-ended sweep. Produce a CONCISE ranked harmonization backlog in markdown.\n\n` +
  `SEEDED (JSON):\n${JSON.stringify(clean, null, 1)}\n\n` +
  `DISCOVERED (JSON):\n${JSON.stringify(discovered, null, 1)}\n\n` +
  `DISCOVER-COMPLETENESS (full-population enumeration per discovered pattern; ` +
  `'newly_found_beyond_original' = sites the lenses missed):\n${JSON.stringify(completeness, null, 1)}\n\n` +
  `Output a markdown doc with:\n` +
  `1. A one-paragraph executive summary: how many classes are already pinned vs divergent, the top-3 to ` +
  `harmonize next (HIPAA-load-bearing + widest spread + weakest-variant severity), and whether the open-ended ` +
  `Discover phase surfaced anything the seeded set missed.\n` +
  `2. A ranked table of ALL classes (seeded + the credible discovered ones, deduped): Class | #sites | #variants | ` +
  `weakest variant + its risk | canonical exists? | recommended SSOT | recommended pin | severity | effort.\n` +
  `3. For the top-3, a short per-class "harmonization plan" (the SSOT to build + the count-agnostic pin to write, ` +
  `naming whether the pin must be interprocedural).\n` +
  `4. A "discovered classes" section: list the open-ended candidates, mark each real / spurious with a one-line ` +
  `reason, and fold the real ones into the ranked table.\n` +
  `5. A "completeness caveats" section: any class where the verifier found the enumeration was INCOMPLETE (list ` +
  `the missed sites) — flag "re-census before trusting."\n` +
  `6. A short "prevention" note: the iron rule (every SSOT ships with its structural pin; harmonization without a ` +
  `pin decays), and that llm_safety.py reportedly lacks an AST pin (confirm/deny from the data).\n` +
  `7. A "census methodology self-eval" section (the standing post-run step): from THIS run's data, what should ` +
  `scripts/workflows/et-divergence-census.js itself LEARN? Flag any class where a structural AST detector (step 1b) ` +
  `found materially MORE sites than an initial grep would (the run17 #3 3-vs-60 failure mode); any seeded class that ` +
  `should be split or added; any verify stage that rubber-stamped an incomplete net; any signature_hint that proved ` +
  `too narrow. Be concrete — name the class, the count delta, and the exact signature/detector that should be baked ` +
  `into the class hint. This section is the INPUT to folding learnings back into the census script + procedure_census_loop.\n` +
  `Be decisive and specific. This is a backlog the operator will act on.`,
  { label: 'synthesize:backlog', phase: 'Synthesize' },
)

// Standing post-run step (productized reminder — the anti-drift tooling drifts
// too, PD#6/#7 "census the censusers"). The backlog's "census methodology
// self-eval" section (synthesizer point 7) is the data; act on it.
log('POST-RUN STEP — evaluate THIS census script against this run and fold in learnings: read the ' +
    'backlog\'s "census methodology self-eval" section, then update scripts/workflows/et-divergence-census.js ' +
    '(class signature_hints, step-1b AST detectors, new/split seeded classes) + sharpen procedure_census_loop, ' +
    'grounded in this run\'s concrete evidence. Do NOT skip — an un-sharpened census undercounts the next run.')

return {
  censusedClasses: clean.length, totalClasses: CLASSES.length,
  discoveredCount, newlyFound, backlogMarkdown: backlog,
  raw: clean, discovered, completeness,
}
