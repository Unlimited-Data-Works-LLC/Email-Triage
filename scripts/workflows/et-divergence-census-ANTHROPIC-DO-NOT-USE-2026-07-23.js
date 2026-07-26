export const meta = {
  name: 'divergence-census',
  description: 'Census convergent-intent / divergent-implementation operation-classes across email-triage; rank a harmonization backlog (SSOT + structural pin per class)',
  phases: [
    { title: 'Census', detail: 'one agent per seeded operation-class: enumerate, cluster variants, rank weakest-first, recommend SSOT + pin' },
    { title: 'Verify', detail: 'adversarially verify each enumeration was COMPLETE + the canonical claim holds' },
    { title: 'Discover', detail: 'open-ended: find NEW divergent classes beyond the seeded set (un-primed)' },
    { title: 'Synthesize', detail: 'merge seeded + discovered into a ranked harmonization backlog' },
  ],
}

// ---------------------------------------------------------------------------
// * Per-drive learnings -- folded per `feedback_after_every_run_evaluate_
// census_and_leira_offload.md` standing rule (operator 2026-07-08).
//
// 2026-07-09 drive (N-380 + N-381 landings):
//   * NEW discoverable class -- INPUT-PARSE-SET COMPLETENESS. A function
//     that filters an input dict against a hardcoded key-set (e.g.
//     `web/events.py::fire_notification._FORBIDDEN_KEYS`) or parses a
//     command-line with a regex/glob (e.g.
//     `scripts/hooks/evidence_bound_claim_gate.py::_extract_msg_from_command`)
//     is a CIDI-shape when the SET/PATTERN misses a class of legitimate
//     inputs -- the intent is "block/parse everything in the class", the
//     divergent implementation is "the actual set is a subset of the
//     class". Seed the Discover phase for future runs with a lens
//     searching for `frozenset({...})` / `set(...)` / any re.search on
//     command-shape strings inside gate/refusal/parse functions.
//   * NEW discoverable class -- FAIL-LOUD ACTUATOR GATE. `cli.py`'s N-157
//     landing added a typed exception (`CliAuditGateClosed`) + a top-
//     level try/except in `main()` that catches it + prints clean stderr
//     + returns a dedicated exit code. Discover phase should look for
//     any other actuator with a similar "raise on gate-close, but no
//     clean-error wrapper at the top-level entry" shape -- those surface
//     as raw Python tracebacks that break-glass operators can't read.
//     Seed lens: grep for `class.*Closed\|class.*Gate\|raise RuntimeError`
//     in `cli.py` + any `main()` catch-block absence pattern.
//
// the backlog  (audit_hmac categorizer over-flags on file-name
// adjacency) is queued as a follow-up refinement -- the current
// categorizer fires on path adjacency, not on the actual surface touch
// (`_chain_insert` / chained-table INSERT / `@audit_emitter` /
// canonical-tuple). Wastes SME review budget on false positives.
// Refinement direction: require an AST-visible surface touch before
// admitting the file to the audit_hmac category.
//
// ADDITIONAL 2026-07-09 drive learnings (post-99fc5b67 audit_hmac fold, from
// N-316b + N-286b + -STALE + meta-triage -#118 verify-against-HEAD
// walks):
//   * NEW discoverable class -- OBSERVABILITY-BUCKET COMPENSATING CONTROL. When
//     a strict-required-spec ships as SOFT (e.g. N-151 boot-time hard raise
//     -> WARN-log-plus-fail-CLOSED), the compensating control is an
//     `/health/detail` sibling bucket in the fixed enum shape
//     `{available: bool | None, reason: <fixed-enum>, error_type: <class-name>,
//     last_probed_at: <utc-iso-z>}`. Key traps to censusing this class:
//     (a) `reason` MUST be a fixed enum (not `str(exc)` -- sec.164.502 min-necessary
//     leak class); (b) `error_type` carries class name ONLY (no message text);
//     (c) WARN-log rate-limited to once-per-boot + on-transition via
//     `app.state._<name>_last_reason` (the monitoring system-30s-poll = 2880 WARN/day disaster);
//     (d) fail-safe path returns `available=None` on probe-error/import-error,
//     never propagates. Discover-phase lens: any `/health/detail` compute helper
//     whose docstring/name mentions "compensating control" / "SOFT variant" /
//     the accessor lru_cache pattern.
//   * NEW discoverable class -- MODULE-LEVEL PRIMITIVE ALIAS in AST detectors.
//     A structural detector (like `_structural_resolver_names` at
//     `test_authz_by_id_fetch_pin.py:116`) that walks `ast.Call.func` against a
//     canonical name-set is BLIND to `alias = primitive` module-Assign +
//     `from x import primitive as alias` ImportFrom. Widen every canonical-set
//     structural pin to compute per-module aliases FIRST + union into the
//     gate-name set for that module only. Discover-phase lens: any pin importing
//     a `_CANONICAL_*_SET` frozenset and checking `fname in <set>` without
//     pre-walking module aliases. Fold cite: N-286b R32 `_module_level_
//     primitive_aliases(tree)` shape.
//   * NEW discoverable class -- VERIFY-AGAINST-HEAD PARTIAL CLOSE POSTURE. When
//     an audit-artefact class carries >100 per-item findings but the drive that
//     produced it has already landed most fix-forwards (like the trust-audit
//     2026-07-03 -> r22-r30 census-driven N-XXX chain), a SAMPLE across
//     categories (10 SHAs / 7 categories) with uniform-pattern observation is a
//     defensible PARTIAL close -- NOT a shortcut, but explicit per BINDING 
//     7-label. Discover-phase lens: the backlog rows with `Read + triage` in the
//     Action cell over an audit-artefact list -- sample first, then decide
//     full-walk vs PARTIAL. Cite: `STATE_2026-07-09_meta_triage_115_118_
//     partial_closed.md` for the sample-evidence shape.
//   * NEW discoverable class -- TIMESTAMP-STRING SSOT ROUTE (N-357). Any
//     `datetime.now(<tz>).isoformat().replace("+00:00", "Z")` inline chain in
//     `src/**` bypasses `_isotime.now_utc_iso_z()`. TWO pins fire on the same
//     inline shape: `test_now_iso_utc_pin_a10` (A10 SSOT ratchet) + the
//     `test_n335b_function_scope_shadow_import_pin` when the module already
//     imports `datetime`/`timezone`. Fold cite: N-316b CI-red fix-forward
//     `101b00c9` -- one inline shim = 2 defect events per site. Discover-phase
//     lens: grep `datetime.now(.*).isoformat().replace` under `src/`.
// ADDITIONAL 2026-07-09 discoverable classes (from N-380/N-381 SME panels):
//   * SHALLOW-CHECK LIMITATION -- a `set(...) & payload.keys()` intersection
//     inspects only top-level keys; a caller wrapping PHI in a nested
//     dict (`{"meta": {"body": "..."}}`) slips past the guard regardless
//     of set widening.  Refinement direction: recursive `_leaks` walk
//     with a depth-cap or a JSON-Pointer-style key-path check.
//   * REGEX-OVER-FULL-STRING PARSING FRAGILITY -- extractors that
//     `re.search` against a full command-line (evidence_bound_claim_gate
//     `_extract_msg_from_command` pre-N-381-F1) are boundary-blind:
//     `[^\s'\"]+` char classes terminate at the first quote, and a
//     legal `--message="msg with -F embedded"` shape fires the wrong
//     branch order.  Refinement direction: shlex.split-based
//     tokenization + token-boundary-aware parse.  Applies to any
//     hook / command-line parser under `scripts/hooks/`.
// ADDITIONAL 2026-07-09 post-batch-6 (from db-fast-review MF-1 discovery):
//   * SENSITIVE-PURPOSE SLUG DESTRUCTION -- `raise_api_error(<slug>,
//     purpose='auth'|'provider'|'config'|'backup'|'digest')` routes the
//     `<slug>` first arg through `scrub_exc` which -- per
//     `web/_flash.py:58-88` -- REPLACES the input with
//     `f'{purpose} operation failed'` for _SENSITIVE_PURPOSES. Dict-detail
//     sites setting `detail={"error": "<slug>", "message": "..."}` where
//     the slug is a machine-readable identifier (`hipaa_blocked`,
//     `calendar_not_enabled`, etc.) LOSE the slug -- tests asserting on
//     `body.detail.error == "<slug>"` fail. Fix: use `purpose='misc'` for
//     literal-str slug args (developer committed to a curated identifier,
//     not a leak vector); reserve `purpose='auth'|'provider'|...` for
//     calls that pass a real Exception whose `str()` could carry secrets.
//     Detection recipe (add to census discover-phase): grep for
//     `raise_api_error("<literal_slug>", ..., purpose="<sensitive>")` +
//     match against `_SENSITIVE_PURPOSES` set. Grounded in this drive's
//     MF-1 fix at `a3cf46d8` (5 sites in agent_api.py).
//     UPGRADE 2026-07-09 (MF-1 tail landing `240a9dda`): STRUCTURAL PIN
//     `tests/test_no_sensitive_purpose_literal_slug_pin.py` now enforces
//     this class going forward (count-agnostic AST walker via
//     `_pin_harness`; covers BOTH `raise_api_error` + `api_error_response`
//     sinks). On first run the pin caught 10 MORE pre-existing sibling
//     sites in the shared auth-gate SSOTs (`web/dependencies.py`x6,
//     `web/routers/agent_api.py`x1, `web/routers/api.py`x3) -- sites the
//     initial MF-1 fix at `a3cf46d8` (batch 2+3+6 CI red evidence) did
//     NOT enumerate. The pin is now the SSOT for this class; the census
//     grep is a discovery-tier redundancy for when the pin's
//     `_ALLOWED_SLUG_DESTRUCTIONS` set grows or a caller wraps the SSOT
//     in a helper (interprocedural-hop shape).
// ADDITIONAL 2026-07-09 late-session (from  tranches 1-5 drive):
//   * ENUMERATION-SCOPE UNDERCOUNT ON SHARED-MODULE SIBLINGS -- the
//     error-surface class was flagged as "concentrated in agent_api.py
//     (~30), auth_keys.py (~15), integrations.py (~2), scattered small
//     counts elsewhere" (the backlog ). Reality at HEAD found the
//     count roughly DOUBLED once verify-against-HEAD widened scope from
//     `web/routers/**/*.py` to include the sibling shared-dependency
//     module `web/dependencies.py` (+8 sites) AND `web/routers/api.py`
//     (+30 sites -- the JSON REST module that was silently OUT-OF-scope
//     of the "concentrated in ..." phrasing). integrations.py itself
//     was 8 not 2 (undercount by 4x). Total drift: 68->108.
//     Refinement direction: for any class whose enumeration lens is
//     `web/routers/**`, ALSO scope `web/dependencies.py`,
//     `web/auth.py`, and `web/*.py` shared modules. A shared-module
//     class hint MUST enumerate the shared-module tree, not the routers
//     tree alone. Grounding cite: this drive's tranche 4/5 CI-red-free
//     landings verified this scope widening was safe (raise_api_error
//     is a pure wrapper, no dep cycle).
//   * REGEX-BASED MIGRATION SCRIPTS BREAK MULTI-LINE IMPORTS -- the
//     tranche 4 batch-migration script inserted an `import` line after
//     the last-seen `from email_triage.` line WITHOUT accounting for
//     that line being the OPEN of a multi-line import block. Result:
//     syntax error (`from ... import (` with `from ...` interleaved).
//     Fixed inline by relocating the inserted import outside the block.
//     Refinement direction: an AST-based migration (find TOP-LEVEL
//     Import/ImportFrom nodes + insert AFTER the last one, not "after
//     the last line starting with `from`"). Applies to any bulk-edit
//     script under `scripts/`.
//   * CI/CD CENSUS UNDERCOUNT PATTERN -- when a census flags a class
//     with a HEADLINE count + "scattered small counts elsewhere"
//     phrasing, that phrasing is CIDI-shaped: the analyst named the
//     top-3 and hand-waved the tail. Refinement direction: reject the
//     phrasing at census-review time; require the tail-list enumerated
//     with a specific number, even if "0 sites in file X" is the
//     entry. A verify-against-HEAD label is not a substitute -- it
//     labels post-hoc, whereas the enumeration should be complete at
//     census-authoring time.
// ADDITIONAL 2026-07-09 post-census (drain-audit pin drift -- pin-harness-drift
// class RE-FIRED on a NEW pin, not a legacy one):
//   * NEW PIN AUTHORED WITHOUT HARNESS ADOPTION -- the  tail-2 structural
//     pin `test_drain_audit_row_count_arm_pin.py` landed at `da40ebd8` with a
//     hand-rolled `str(path).replace('\\', '/')` relpath, bypassing the shared
//     `_pin_harness.relpath` SSOT. `feedback_meta_pins_gate_new_pin_pushes`
//     REQUIRES a local `test_pin_harness_adoption.py` sweep before any new
//     pin push -- that meta-pin caught it in CI (Unit+Pin RED on `46dd4433`),
//     forcing a same-drive fix-forward `5423c633` (route through
//     `_pin_harness.relpath`) + `864bee86` (`test_pin_has_teeth` symmetric
//     teeth). Evidence: the anti-drift layer's ENFORCEMENT (the meta-pin) is
//     load-bearing -- but the PROCEDURE (meta-pin as pre-push gate) drifted:
//     the drive shipped the pin without running the meta-pin locally first.
//     Refinement direction: the pin-harness-drift class hint should
//     PROMOTE the pre-push local-sweep requirement into the signature_hint
//     itself, so the census flags any new `*_pin.py` file whose ADD-commit
//     doesn't touch `_pin_harness` OR the `_ALLOW` list of the meta-pin.
//     Cite: pin-harness-drift entry (line ~304) -- signature_hint should add
//     "new pin file adds MUST touch tests/_pin_harness.py import block OR
//     the test_pin_harness_adoption.py allow-list in the SAME commit".
// ADDITIONAL 2026-07-10 (post-deploy census wf_69674c7e-c67 close drive --
// N-383-tail `6d44e067` + N-387 `917c03a6` landings, 3-SME panel wf sme-
// {hipaa,db,da}-n387@session-3a3b9a1e):
//   * APPLICATION OF EXISTING CLASS (N-286b module-level primitive alias) --
//     N-383-tail closed the LOW ImportFrom-alias + same-file 1-line wrapper
//     shapes on the N-200 cookie-Secure SSOT pin via `_module_ssot_aliases
//     (tree)` (mirroring `_module_level_primitive_aliases` shape from N-286b).
//     Both an ImportFrom-alias (`from _cookies import is_request_https as ir_
//     https`) AND a same-file 1-line wrapper (`def _is_https(r, c): return
//     is_request_https(r, c)`) resolve to the SSOT; the pre-tail pin's
//     `fname == SSOT_NAME` check false-positived both. Confirms N-286b class
//     is REAL and applies to ANY structural pin gating a canonical call --
//     not just AST resolver-name pins. Refinement direction: the N-286b
//     class hint should NAME the 1-line-wrapper variant explicitly (was
//     Alias + Assign but NOT wrapper); expand the discover-lens to include
//     `def X(...): return <canonical>(...)` 1-line forwards as an alias
//     source in addition to Import/Assign.
//   * NEW discoverable class -- SQL-LITERAL UPSERT-SCANNER COMPLETENESS
//     (N-387). A structural pin scanning `INSERT INTO T ... ON CONFLICT
//     (...) DO UPDATE SET body` SQL literals is BLIND to at least four
//     variant shapes unless explicitly handled:
//       (a) `INSERT OR IGNORE INTO T` -- SQLite drops the write on
//           conflict, ON CONFLICT SET body never fires; a lifecycle-status
//           table using this shape PRESERVES the stale `errored` chip
//           (N-347's exact defect via a different SQL route). Auto-flag on
//           any triple-carrying table.
//       (b) `INSERT OR REPLACE INTO T` -- delete-then-insert takes column
//           DEFAULTs on fresh row; usually safe if the triple isn't
//           explicitly non-clear-set. Not auto-flagged; queue as a separate
//           class if a caller EXPLICITLY sets the triple to non-clear.
//       (c) `DO UPDATE SET x=? WHERE status='active'` -- SQLite permits a
//           trailing WHERE on the SET payload. A `\bstatus\s*=` presence
//           check would FALSELY see the WHERE-clause `status =` and mask
//           an omitted SET assignment. `_RE_UPSERT_SET` terminator lookahead
//           MUST include `\bWHERE\b` alongside `INSERT INTO` / `RETURNING` /
//           `;` / `\Z`.
//       (d) Python implicit-concat across newlines -- `"INSERT INTO T "
//           "ON CONFLICT ... DO UPDATE SET ..."` fuses into ONE
//           `ast.Constant`. Text-regex on raw file bytes sees per-quote
//           breaks; walk `ast.parse(source)` + `ast.Constant`(str) +
//           `ast.JoinedStr` (elide interpolation slots with a placeholder)
//           to catch multi-line SQL literals whole. F-string dynamic-table
//           names (`f"INSERT INTO {tbl} ..."`) lose the identifier to the
//           scanner -- queue as an interprocedural/dynamic follow-up class.
//     Cite: `tests/test_lifecycle_triple_upsert_clear_pin.py` -- 10 pin arms
//     (2 pin + 3 omit-each + 1 clean + 1 scope + 2 OR-IGNORE + 1 discovery-
//     liveness + 1 extractor-liveness). Grounding: divergence-census-
//     2026-07-10-wf_69674c7e-c67 sec.2 rank 6.
//   * NEW methodology bake-in -- POSITIVE-LIVENESS ON THE EXTRACTOR
//     (complementary to anti-vacuity on discovery). Any pin with a
//     discover-then-scan pipeline MUST assert BOTH: (i) discovery returns
//     non-empty at HEAD (already common); (ii) the extractor yields ACTUAL
//     known-live items with expected payload shape -- read a specific
//     known-live target file (e.g. `src/email_triage/web/db.py`) + assert
//     `_iter_<extractor>(<file>)` produces the expected tuple(s). Guards
//     against extractor regression that would leave the main test passing
//     vacuously (zero-yield extractor + `offenders=[]` = silent pass). Cite:
//     `test_teeth_extractor_liveness_on_web_db` in N-387; folded from db-sme
//     panel verdict at wf sme-db-n387@session-3a3b9a1e. Refinement
//     direction: promote to a required arm-class in the census
//     signature_hint for discover+scan pins.
// ---------------------------------------------------------------------------
//
// ADDITIONAL 2026-07-11 ultracode fan-out drive learnings (the backlog
//  /  /  /  landed;  flaky-drain root-cause fix
// same drive):
//   * NEW discoverable class -- SSOT-ORPHAN CLEAR PATH (PD#18 sub-class).
//     A status flag SET on a specific failure prefix
//     (``pause_style_distill_(account|contact)`` with
//     ``last_error='baa_required:...'`` or ``'scrubber_fail:...'``,
//     ``mark_retry_dead(reason='auth_revoked')``, ``failing_since``
//     watcher marker) whose CLEAR SSOT exists in ``db/*.py`` but has
//     ZERO non-test callers in src/. Seed lens: for every
//     ``def pause_*`` / ``def mark_*_dead`` / ``def set_*_status``
//     helper, check whether the sibling ``def unpause_*`` / ``def
//     resurrect_*`` / ``def clear_*_status`` is called by anything
//     under ``src/email_triage/`` (not just tests). Grounding: 
//     BAA + scrubber_fail sub-shapes landed at 9b1509c7 + f314abe1;
//     wider gap likely exists in retry-queue lifecycle.
//   * NEW discoverable class -- ENCRYPTION-AWARE OPENER ARG-DRIFT
//     (the backlog ). A hand-rolled ``if dedicated_conn_is_encrypted():
//     open_dedicated_conn else: sqlite3.connect(...)`` branch where
//     the plaintext arm drops one or more of the init_db argument
//     profile (``timeout=30.0``, ``cached_statements=0``,
//     ``check_same_thread=False``). Seed lens: any ``ast.If`` whose
//     ``test`` is a Call to ``dedicated_conn_is_encrypted`` and whose
//     branches contain a call to ``sqlite3.connect`` -- flag missing
//     arg names against the init_db profile. Grounding: 7 sites
//     converged onto ``open_dedicated_conn_readish`` at this drive's
//      fold, each dropping a different subset of args.
//   * NEW discoverable class -- CANONICAL-EMAIL BYPASS BEYOND
//     web/routers/** (the backlog  + follow-up ). Raw
//     ``.lower()`` / ``.strip().lower()`` on email-shape receivers in
//     ``providers/*.py`` / ``style_learning/*.py`` / ``actions/*.py``
//     that gate an equality compare OR compose a memoization
//     cache-key. Seed lens: extend the ``_EMAIL_SHAPE_MARKERS`` set +
//     scope to whole tree (Discover-phase; the current pin is
//     ``web/routers/**`` only per its own docstring hole #3).
//     Grounding: gmail_calendar.py:518+522 (attendee-match) +
//     per_contact_hipaa.py:1326 (cache_key) folded at f314abe1.
//   * NEW discoverable class -- TERMINAL-EXIT LIFECYCLE FUNNEL (PD#18
//     sub-class, the backlog ). Every ``async def`` coroutine that
//     writes a sticky ``status`` / ``last_error`` / ``failing_since``
//     marker via a SET helper MUST route EVERY terminal exit
//     (``Return`` / ``Break`` / ``raise``) through the corresponding
//     CLEAR / update funnel -- otherwise ``/health *_failing_for()``
//     reports a permanently-exited task as active-failing. Seed lens:
//     for each ``async def X`` with >=1 sticky-marker write and >=1
//     ``record_*_outcome`` funnel call, prove every reachable
//     terminal has a preceding funnel call. Grounding:
//     ``_watch_account`` at watcher.py had 3 exits bypass
//     ``record_mailbox_outcome``; landed d423f837.
//   * NEW discoverable class -- FIRE-AND-FORGET TASK BASE-EXCEPTION
//     SWALLOW (the backlog ). Any ``try: return await X() except
//     Exception:`` inside a wrapper that catches audit-write failures.
//     Python 3.8+ ``asyncio.CancelledError`` inherits ``BaseException``
//     (not ``Exception``), so cancellation transitions the task to
//     ``done()==True`` WITHOUT the wrapper's stash/counter firing.
//     Seed lens: grep for ``except Exception`` within an
//     ``async def safe_*_write*`` sibling; pair with
//     ``asyncio.create_task`` argument sites downstream.
//     Grounding: safe_audit_write* fixed at 48cf61b6 with
//     ``except BaseException`` + ``add_done_callback`` on the
//     create_task site.
// ---------------------------------------------------------------------------
//
// ADDITIONAL 2026-07-11 late-session drive learnings ( SECRETS_SSOT_HOME
// hoist + meta-pin contract #9 landed `98fddb33`;  counter-emit SSOT
// convergence + trigger-vocab pin landed `1508d3d0`;  base64 decode
// SSOT + 4 HIGH decode-fail migrations staged):
//   * NEW discoverable class -- HAND-ROLLED-TERMINAL COMPLETION SHAPE. For
//     any completion SSOT (``complete_triage_run`` at ``web/events.py:573``)
//     that internally chains N sub-steps (record + emit + fire-webhook),
//     ANY caller that hand-rolls the sub-step calls SEPARATELY --
//     ``await db_call(record_X, ...); ...; await fire_X_completed(...)``
//     -- silently bypasses the counter/emit sub-step. Seed lens: for every
//     ``async def complete_<X>`` SSOT that wraps a ``record_<X>`` + a
//     ``fire_<X>_completed`` + a metric emit, enumerate ALL
//     ``record_<X>`` call sites and flag those NOT enclosed by the
//     SSOT's body. Grounding:  tail found 4 sites (watcher.py:1913
//     IMAP-watch, ingestion_push.py:685 Gmail-push, :1258 O365-push,
//     poll_ingestion.py:377 O365-poll -- the 4th surfaced by DA panel
//     verification via git-grep AFTER my llm-host scope enumerated 3).
//     Enforcement: recommend a cross-module pin restricting
//     ``record_<X>`` + emit-SSOT call sites to the completion SSOT's
//     body (task  filed). Refinement direction: extend the census's
//     "audit-emit" class lens (line 34) to walk ANY completion-SSOT
//     class with the same shape.
//   * NEW methodology bake-in -- llm-host-QWEN3.6:35B PREPASS SCOPE-DRIFT.
//     llm-host offloads succeed at CLASSIFYING sites within a named file
//     scope but MISS SIBLING sites in DIFFERENT files that share the
//     shape. Two concrete miss-events this session: (a)  initial
//     enumeration fed 4 named files (imap-watch, gmail-push, o365-push,
//     topic-backscan) and correctly classified 3 as HAND_ROLLED; the
//     4th UNFOLDED site was in a DIFFERENT file (poll_ingestion.py) not
//     in the initial scope -- DA F6 caught via broader git-grep. (b)
//      llm-host classified 14 sites correctly BUT the pin walker
//     surfaced 2 additional PAD_HAND_ROLLED sites off-by-5-lines from
//     llm-host's cited coords (gmail_api.py:1132 pad-restore vs :1137
//     actual decode; auth_keys.py:509 pad-restore vs :516 actual
//     decode). Learning: (i) the enumeration signature for a class
//     should be a STRUCTURAL AST walker fed to llm-host for classification
//     -- not a hand-picked file list handed to llm-host for enumeration;
//     (ii) the count-agnostic pin's walker is the AUTHORITATIVE site
//     list, llm-host is a HINT that fills in classification/reasoning.
//     Refinement direction for future census offloads: fire the pin
//     walker FIRST (returns exhaustive site list), then llm-host for
//     per-site classification (PAD_HANDLED_SAFELY vs
//     PAD_HAND_ROLLED vs PAD_MISSING_CAUSES_DECODE_FAIL etc.). Grounding:
//      grounding at 1508d3d0 commit body;  grounding at
//     ``scratchpad_leira_123_enum.json`` + pin walker output at
//     ``tests/test_base64url_ssot_pin.py::_ALLOW_STDLIB_DECODE_SITES``
//     which captures 2 additional real sites beyond llm-host's cited
//     line numbers.
//   * NEW discoverable class -- EXTERNAL-INPUT URL-SAFE BASE64 DECODE
//     WITHOUT RE-PADDING. Any ``base64.b64decode(<external-
//     source>)`` or ``base64.urlsafe_b64decode(<external-source>)``
//     call where the source is a Gmail push notification body, an
//     O365 push contentBytes attachment, an RFC 2047 encoded-word,
//     a WebAuthn client-side blob, a JWT signature -- all of which
//     strip trailing ``=`` per RFC 4648 sec.5 -- raises ``binascii.Error``
//     on non-multiple-of-4 length input. Seed lens: ast.Call to
//     ``base64.b64decode`` / ``base64.urlsafe_b64decode`` whose first
//     positional arg is an ast.Name (variable, not constant) inside
//     a function under ``src/email_triage/web/routers/**.py`` OR
//     ``src/email_triage/providers/**.py``, without a preceding
//     ``+= "=" * (-len(x) % 4)`` shape in the ~5 lines above. Grounding:
//      4 HIGH-severity decode-fail bugs (mail_headers.py:541,
//     office365.py:865, dev_keypair.py:101, webhooks.py:112) folded
//     onto ``email_triage._base64url.b64decode_permissive``.
//     Enforcement: ``tests/test_base64url_ssot_pin.py`` + seeded
//     allow-list; task  tracks the 10 PAD_HAND_ROLLED siblings.
//   * NEW methodology bake-in -- MIRROR-WITH-CHECK vs DIRECT-IMPORT
//     for pin-vs-runtime vocab SSOTs. When a pin ENFORCES that
//     callers use a bounded vocab (trigger set, allowed-file set,
//     etc.), the pin's local copy of the vocab MUST be a direct-
//     import of the runtime SSOT (``from ... import _X as _Y``) --
//     NOT a mirror-with-check pattern (local ``frozenset`` literal
//     + ``test_pin_mirrors_runtime`` drift-detector). The mirror
//     pattern re-introduces the class the shared-constant hoist
//     eliminates. Grounding: DA F4 on  batched panel called
//     this out; the fix (direct-import) took ~5 min, dropped the
//     mirror-check test entirely. Pattern precedent from 
//     ``SECRETS_SSOT_HOME`` hoist landed at 98fddb33. Enforcement:
//     ``test_pin_harness_adoption.py`` contract #9 walks tests/**
//     and bans re-inlining a harness-hoisted shared frozenset --
//     extend to also detect and flag ``local_vocab: frozenset[str]
//     = frozenset({...})`` + ``test_pin_mirrors_runtime_ssot``
//     pairs OUTSIDE the SSOT home, as a stronger structural check.
//     Refinement direction: promote to a required arm-class in the
//     census signature_hint for any vocab-set SSOT.
//   * NEW methodology bake-in -- llm-host CENSUS-LOOP VERDICT SCHEMA
//     HALLUCINATION. The naive census-loop offload shape ("give
//     llm-host a diff and a categorical verdict enum
//     ``[CONVERGED, NEW_DRIFT_INTRODUCED, UNCERTAIN_NEEDS_HUMAN_REVIEW]``")
//     causes qwen3.6:35b to default to ``NEW_DRIFT_INTRODUCED``
//     even when the ``findings`` array is empty. Two consecutive
//     runs same-session (2026-07-11 session census-loops 1 + 2)
//     both showed this pattern: 32s / 30 tokens and 23s / 28
//     tokens respectively, both returning the drift verdict with
//     zero findings. Per verify-don't-accept: empty evidence
//     cannot support a drift claim. Refinement direction for
//     future census offload scripts: post-hoc override the
//     verdict to ``CONVERGED`` when ``findings`` is empty, and
//     record the original llm-host verdict in a
//     ``_verdict_override_note`` field so the schema-constraint
//     shape is documented in the artifact. Grounding:
//     ``scratchpad/leira_census_session.py`` post-hoc override
//     block; grounded on 2026-07-11 session runs 1 + 2 empirical
//     evidence + broader 18/22 pin sweep GREEN independently
//     rebutting the drift verdict. Also add a similar
//     "return-schema-permits-honest-CONVERGED" review to any
//     future llm-host offload with a categorical verdict enum --
//     force the model to justify the non-CONVERGED verdict via
//     a required findings array, and post-hoc override when the
//     findings array is empty.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ADDITIONAL 2026-07-11 post-#120 drive learnings (workflow
// `wf_bbfca658-a38` AST class hunt discovered 2 new AST-expressible
// classes worth seeding into the census + a reinforcement of the
// verify-don't-accept discipline):
//
//   * NEW discoverable class -- FERNET-CONSTRUCTION-OUTSIDE-TRUST-ENVELOPE-MAP.
//     Cryptography primitives `Fernet(x)` should not be constructed at
//     arbitrary sites -- each construction is a trust envelope whose key
//     material must trace to a documented source (master key, per-record
//     derived key, or passphrase KDF). Enumeration lens: `ast.Call`
//     with `func.id == "Fernet"` OR `func.attr == "Fernet"`. The
//     PATH-anchored allow-list is the SSOT (learn from
//     `test_new_run_id_ssot_pin.py` line-drift trap 5082->5086 -- line-
//     anchored allow-lists CIDI-drift). Grounding: 2026-07-11 workflow
//     found 8 sites, VERIFIED as 5 legitimate envelopes across 3 files
//     (secrets.py SSOT + backup.py passphrase-KDF + _msal_cache_crypto.py
//     MSAL cache) via verify-don't-accept. Pin landed as
//     `tests/test_fernet_construction_allowlist_pin.py`. sec.164.312(a)(2)(iv)
//     encryption-of-record anchor.
//
//   * NEW methodology bake-in -- VERIFY-DON'T-ACCEPT REJECTS THE
//     `asyncio.create_task`-UNTRACKED CLAIM AT HEAD (2026-07-11). Workflow
//     AST hunt flagged 8 sites as "GC-loss footgun" (`task = asyncio.
//     create_task(...)` bound to local, allegedly untracked). Reading
//     the surrounding lines: ALL 8 are actually tracked -- 3 via a
//     `_BG_TASKS.add(task)` + `add_done_callback` pattern (backup.py:725,
//     embedding_install.py:294+407), 1 via `self._tasks[key] = task`
//     instance-dict storage (watcher.py:881), 2 via list-comp
//     immediately consumed by `asyncio.gather(*tasks)` (triage_runner_
//     bulk.py:1092), 1 via `task_supervisor.py:414` SSOT, 1 via
//     access_audit.py:270 with `add_done_callback`. The AST hunt was
//     line-anchored; it saw the assignment but missed the tracking
//     call 1-3 lines below. Lesson: any "untracked X" class MUST verify
//     the +5 line window before flagging. Refinement: a proper
//     `create_task` untracked pin needs FLOW ANALYSIS (bind-then-
//     never-used-in-tracking-set-within-function-scope) -- bounded
//     complex; skip until a real HEAD defect surfaces. Pin NOT filed
//     (task  dispositioned CLOSED -- no HEAD defect).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ADDITIONAL 2026-07-11 post-#137 drive learnings (RATCHET PIN pattern
// for large-baseline classes):
//
//   * NEW methodology bake-in -- RATCHET PIN with `(rel, enclosing_fn)`
//     grandfathered baseline is the correct pattern for large latent
//     classes discovered via broad AST walk. Rather than migrate N
//     sites in one drive (which risks breaking hot paths), grandfather
//     the current site set + strict-shrink test forces reduction as
//     migrations land. This session shipped THREE such ratchet pins
//     with baselines auto-generated by committed
//     `scratchpad/generate_*_baseline.py` scripts:
//       -  silent-swallow (`except X: pass` / `except X: return
//         None`) -- 309 sites in 193 (rel, fn) pairs; sec.164.312(b) audit
//         controls anchor.
//       -  SELECT-* over-fetch -- 51 sites; sec.164.502(b) minimum-
//         necessary anchor.
//       -  sync-sqlite in async -- 116 sites in 46 (rel, async_fn)
//         pairs; sec.164.312(e)(1) availability anchor.
//     Each ratchet has: (a) auto-generator script (committed for
//     reproducibility), (b) the pin file with grandfathered baseline
//     embedded via placeholder-replace, (c) strict-shrink
//     `test_baseline_never_grows` companion that forces baseline
//     reduction as sites migrate.
//
//   * NEW discoverable class -- EXCEPTION-CHAIN LOSS. 15 sites
//     of `except X as e: raise Y(...)` without `from e`. Mechanical AST
//     rewrite via end_col_offset splice appended ` from <name>` at the
//     closing paren of exc Call. Fix WAS committed same-drive (class
//     was small enough for full migration). sec.164.312(b) audit-controls
//     anchor (traceback __cause__ integrity for incident response).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ADDITIONAL 2026-07-11 post-#141 drive learnings (llm-host-FIRST binding
// rule + schema-enum retrofit):
//
//   * NEW BINDING RULE -- llm-host-FIRST + BUILD-llm-host-TWINS. Filed as
//     `memory/feedback_leira_first_and_build_leira_versions.md`
//     (2026-07-11): always invoke the llm-host version when one exists,
//     and BUILD a llm-host twin whenever only non-llm-host exists. Session
//     spent 6 census iterations running llm-host-based audits BUT the
//     formal `et-divergence-census.js` workflow (this file, which
//     dispatches llm-host internally per phase) went un-invoked all
//     session. Operator caught the gap. Fix: (a) filed the binding
//     rule, (b) fired the formal workflow with `scriptPath:`, (c)
//     had to strip 9 non-ASCII glyphs + normalize LF line endings
//     so the permission handler accepts the invocation (committed
//     `dbb2a6e4`). The economic argument: AI provider-spend scales
//     with turn count, llm-host spend is fixed-cost per host-second
//     on the RTX 3090. Committing llm-host audit scripts (via the
//     `scratchpad/leira_*_audit.py` pattern) yields REGRESSION
//     CHECKS for every future drive.
//
//   * NEW methodology bake-in -- LEIRA_CENSUS_SESSION.PY ENUM RETROFIT
//     AT EVERY CLASS-CLOSURE. When a session ships a NEW ratchet-pin
//     or SSOT-fold that closes a class, the class enum in
//     `scratchpad/leira_census_session.py` MUST be retrofitted
//     same-drive so subsequent census runs classify NEW code against
//     the current session's discoveries. This session retrofitted
//     the enum with 5 new categories (LINE_ANCHORED_ALLOW_LIST_LITERAL,
//     SILENT_SWALLOW_ACCRETION, SELECT_STAR_OVERFETCH,
//     SYNC_SQLITE_IN_ASYNC, EXCEPTION_CHAIN_MISSING_FROM) at commit
//     `ac54e1f2`. Post-retrofit run at HEAD `ac54e1f2` returned
//     verdict CONVERGED, 0 findings (llm-host native, no override).
//     Ongoing: when THIS census workflow ships a new class discovery
//     via the Discover phase, the leira_census_session.py enum MUST
//     get the corresponding entry in the same drive.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ADDITIONAL 2026-07-11 post-#121 drive learnings ( name-anchoring
// migration -- the LINE-DRIFT TRAP finally structurally closed):
//
//   * NEW methodology bake-in -- LINE-ANCHORED BASELINE ALLOW-LISTS
//     CIDI-DRIFT ON THIRD SESSION OCCURRENCE. Structural pins that key
//     `_BASELINE_ALLOW` or `_NAMED_DEVIATIONS` on ``(rel, lineno)`` fail
//     silently across unrelated code changes -- the target site drifts
//     lines while the allow-list holds. This session hit the trap on
//     three separate pins in a row:
//       (1) ``test_new_run_id_ssot_pin.py`` -- `_shared.py:5082->5086`
//           (first drift caught by CI on `bb110843`, then `5086->5084`
//           after  fold).
//       (2) ``test_wall_clock_hm_labeling_pin.py`` -- `_shared.py:703->704`
//           after  fold (same session, same downstream drift).
//       (3) Both migrated same-drive in  to `(rel, enclosing_fn)`
//           shape via `_pin_harness.enclosing_fn` (R38 SSOT explicitly
//           documents this: "an allow-list keyed on (relpath,
//           enclosing_fn, payload) survives an unrelated line shift").
//     Reinforcement: any NEW `_BASELINE_ALLOW` / `_NAMED_DEVIATIONS`
//     that a census-follow-up ships MUST key on `enclosing_fn` (or
//     `enclosing_qualified_name` for class-scoped disambiguation).
//     Line-anchored NEVER; the trap has now bitten three times in
//     one session and structurally closed for two pins. Refinement:
//     add a meta-pin that AST-detects `frozenset({("...", <int>)})`
//     literals in `tests/**/*.py` and refuses new ones outside a
//     small documented allow-list of legitimate line-anchored pins.
//     Filed as CENSUS_METAPIN_CANDIDATE (not gate-blocking).
//
//   * NEW discoverable class -- DOCSTRING TEXT-MENTIONS OF BANNED
//     SHAPES TRIP LITERAL REGEX PINS. My `test_js_base64url_ssot_pin.py`
//     docstring at first push (`7ed370d7`) rephrased my rationale in
//     prose that literally mentioned `.replace("\\", "/")` -- the V5
//     meta-pin's regex hit that literal-string mention as an offender.
//     Refinement: writing a NEW pin's docstring, describe the banned
//     shape ABSTRACTLY (e.g. "hand-rolled path-separator normalisation")
//     not by embedding the literal. This is a documentation discipline
//     lesson, not a defect -- recorded here so future pin-authors
//     don't re-hit it.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// N-369 R31 (2026-07-05 trust-repair fix-forward per Census run22 sec.7 self-
// eval + the backlog  = TASK ) -- CENSUS METHODOLOGY BAKE-IN.
//
// The 7 self-eval learnings from run22 sec.7. Each is prescriptive for future
// runs; the SME agents dispatched by this workflow MUST honor them.
// ---------------------------------------------------------------------------
//
// 1. **Signature-derivation-from-protocol** (run22 sec.7#1): a class whose sites
//    are all attribute-calls on a Protocol/ABC MUST derive its attr-set from
//    that Protocol's abstract methods (via ast), not a hardcoded name-list.
//    Provider-fetch is the exemplar; see class hint below.
//
// 2. **counting_convention field on class hint** (run22 sec.7#2): each class hint
//    declares the counting convention it uses. Values:
//    'ssot-routed' -- count only sites already-routed through the SSOT.
//    'super-set' -- count ALL sites via ast.walk (def-sites + call-sites).
//    'adoption-debt-included' -- include un-migrated sites the SSOT wants to
//    absorb.
//    A class-level breakdown (e.g. '36 headline / 167 super-set') MUST NOT be
//    reported without naming the convention.
//
// 3. **def-vs-call site counting distinction** (run22 sec.7#3): every SSOT
//    enumeration counts `ast.Call` nodes-to-the-SSOT-name across the tree, and
//    reports both `def_sites` and `call_sites` separately. 3x under-report on
//    the SSOT itself has been observed (secret-read run22 sec.5).
//
// 4. **Prelude verify on "no AST pin yet" claims** (run22 sec.7#4): before
//    instructing an analyst to build a pin the hint claims is missing, the
//    workflow MUST grep tests/ for `test_*<class>*pin` or `test_*<class>*
//    coverage`. If a match exists, mark the hint STALE and require the analyst
//    to verify. Same pattern for any "believed to have NO AST pin yet"
//    phrasing.
//
// 5. **Structural-superset check** (run22 sec.7#5): a companion script
//    `structural_superset_check.py` (queued as N-369b follow-up) derives the
//    enumeration net INDEPENDENTLY from the class-hint (e.g. "every abstract
//    method on the named protocol class", "every `@decorator`-marked callable")
//    and asserts the census's enumeration is superset-of this independent set. Census-
//    the-censusers with a SECOND census (PD #7).
//
// 6. **Discover-phase inversion probes** (run22 sec.7#6): each run rotates in
//    two new inversion probes: (a) walk `internal documentation
//    sec.3` for any SSOT-registry entry NOT tied to a seeded class-key this run;
//    (b) walk `internal documentation` sec.4.9 for the last three N-xx
//    finding classes and check whether their class-key is in the seed set; if
//    not, promote to seeded. Prevents Discover from returning [] as a
//    tautology of the seeded lenses.
//
// 7. **census_status enum on verify block** (run22 sec.7#7): every verify result
//    surfaces a `census_status` enum value:
//    'CLOSED' -- canonical exists + enumeration complete.
//    'NET-INCOMPLETE' -- canonical exists + enumeration missed sites (name them).
//    'LIVE-DRIFT' -- canonical missing OR variants failing.
//    'STALE-VERDICT' -- verify contradicts census-side claim.
//    A NET-INCOMPLETE class is NOT reported as CLOSED -- the operator sees the
//    net-gap distinctly.
// ---------------------------------------------------------------------------

// The catalog of operation-classes to census. Each is a "convergent intent,
// divergent implementation" candidate -- the same logical operation plausibly
// done several ways. `why` cites prior evidence the drift is real where known.
const CLASSES = [
  {
    key: 'audit-emit',
    title: 'HIPAA / audit-event emission',
    operation: 'recording an auditable event (PHI access, credential change, admin action) -- AND its failure DISPOSITION',
    signature_hint: 'record_hipaa_access_event / record_access_event / record_auth_event (direct OR via a db_call(EMITTER,...) await-seam); inserts into hipaa_access_events / access_log / auth_events / log_entries; direct audit-row INSERTs; AND the swallow-disposition: an emit inside a try whose handler catches-all (Exception/BaseException/bare/tuple) WITHOUT re-raising (a /health-invisible best-effort write) vs one routed through the web._audit.safe_audit_write / safe_audit_write_async SSOT',
    why: 'KNOWN drift: finding N-33-B (a HIPAA send wrote access_log not the canonical hipaa_access_events -> invisible to sec.164.312(b) reconciliation) + run17 #3/N-135 (the swallow-disposition: ~60 emits across 27 files swallowed in hand-rolled try/except, converged onto safe_audit_write[_async], pinned by tests/test_audit_emit_swallow_pin.py). LESSON (PD#4): an LLM-grep enumeration of this class UNDERCOUNTS badly -- the #3 re-census hand-counted 3 swallows; the AST swallow-detector found 60. ENUMERATE STRUCTURALLY (see step 1b). FRAMING TRAP (run18 #7/N-164): an emission-pairing class of the form "every X must pair with an emit/event Y" must NOT be stated as "every record/call site pairs with Y" -- that over-broad framing webhook-STORMS (one event per item in a batch) and false-flags deferred-emit callers; distinguish TERMINAL completion (emit ONCE) from PER-ITEM record (no emit), and key the pin on the TERMINAL seam. HIGH value (HIPAA-load-bearing).',
  },
  {
    key: 'permission-check',
    title: 'Authorization / access-scope gate',
    operation: 'gating a handler/action on who may access which account or resource',
    signature_hint: 'can_manage_account, _manageable_account_ids, _require_admin, _gate_account_ids, get_email_account (unscoped by-id), account-scope intersections in routers; the RAW by-id SQL fetch must be matched ALIAS-TOLERANTLY over a function\'s JOINED string-constant corpus -- both /from\\s+email_accounts(\\s+\\w+)?\\b/ AND /where\\s+(\\w+\\.)?id\\s*=/ (run18 #8): the literal substring "from email_accounts where id" EVADES aliased SQL ("FROM email_accounts ea ... WHERE ea.id = ?") and a per-ast.Constant test inherits a split-FROM/WHERE blind spot; the \\b rejects email_accounts_archive and the id= form excludes WHERE ea.user_id = ? (by-user, not by-id)',
    why: 'KNOWN drift: finding N-28 -- a handler skipped the sec.5 manageable-set intersection and opened an is-HIPAA enumeration oracle. HIGH value (HIPAA-load-bearing). run18 #8 widened the by-id pin (tests/test_authz_by_id_fetch_pin.py) raw-SQL net from a literal substring to the alias-tolerant FROM/WHERE pair over the joined corpus (drift-prevention; no live IDOR -- all 4 aliased by-id fetches are gated db-helpers / the named get_email_account SSOT, zero ungated @router handlers).',
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
    signature_hint: '_write_config_yaml(config), set_setting / set_bool_setting (settings table), secrets.set (secrets store) -- and the BOUNDARY rules for which store a value belongs in',
    why: 'Three stores (YAML / settings-table / secrets) with fuzzy boundaries; a value written to the wrong store, or to two, drifts silently. MED.',
  },
  {
    key: 'provider-fetch',
    title: 'IMAP / provider message fetch',
    operation: 'fetching messages/headers from a mailbox provider',
    // N-368 R31 (2026-07-05 trust-repair fix-forward per Census run22 sec.3(c) +
    // the backlog  = TASK ): signature widened per the run22 verifier
    // finding -- the prior narrow attr-set {fetch_message, fetch_messages_batch,
    // fetch_history, list_history} missed 11 sites (EmailProvider.list_folders()
    // x 9 + ImapProvider.search_all_folders() x 2). Broader hint below derives
    // the full attribute set from the EmailProvider protocol's public API +
    // adds the aioimaplib INV1 scope-caveat (fetch/search args must be
    // ast.Constant, not JoinedStr / variable -- the "async-transport criteria
    // stay literal" convention run22 sec.5 named).
    signature_hint: 'imap_blocking.py (stdlib parser), aioimaplib usage, provider .search/.fetch/.list_history paths, headers_only fetch, EmailProvider.list_folders / ImapProvider.search_all_folders / list_special_use_folders / discover_special_use_folder -- DERIVE the full attr-set from the EmailProvider protocol\'s public API (providers/base.py) rather than a hardcoded name-list; a new abstract method added there MUST expand the signature automatically. INV1 aioimaplib scope-caveat: every .fetch/.search/.uid("fetch",...) argument in the aioimaplib allow-set is ast.Constant (not JoinedStr / variable) -- this is the "async-transport criteria stay literal" convention.',
    counting_convention: 'super-set -- count both def-sites AND ast.Call sites via ast.walk; report both distinctly (run22 sec.7#3 def-vs-call convention).',
    why: 'bug_aioimaplib_recursion: aioimaplib has a parens/recursion bug; imap_blocking is the safe path for header fetch. Is the safe path used consistently or bypassed? MED. N-368 note: signature widening + counting-convention refinement + INV1 literal-arg caveat close the run22 verifier gaps.',
  },
  {
    key: 'error-surface',
    title: 'User-facing error / result surfacing from a handler',
    operation: 'reporting a save/action failure or result back to the operator',
    signature_hint: 'redirect ?err= / ?saved= querystring, inline HTMLResponse error fragments, flash messages, form_error context keys',
    why: 'Consistency of how handlers report failure to the operator -- a silently-swallowed error is the failure mode behind several incidents. MED/LOW.',
  },
  {
    key: 'pinned-verify',
    title: 'Already-harmonized SSOTs -- does each have a SOUND structural pin?',
    operation: 'verifying the existing SSOTs are enforced by a count-agnostic structural test whose net is complete',
    signature_hint: '@db_write + tests/test_db_write_coverage_pin.py; _secret_write.py + tests/test_no_unguarded_secret_write.py (interprocedural); llm_safety.py fence SSOT (NOTE: believed to have NO AST pin yet); m.secret_input + tests/test_credential_inputs_hardened.py',
    why: 'Harmonization DECAYS without a pin. Confirm each SSOT has a real pin AND the pin\'s enumeration is complete (interprocedural where the codebase hops values through db_call(helper,...)). llm_safety.py is the suspected gap. META value.',
  },
  {
    key: 'pin-harness-drift',
    title: 'The structural pins THEMSELVES -- do they share the harness, or re-roll the walk/relpath/teeth?',
    operation: 'every count-agnostic structural pin (tests/*_pin.py + friends that walk src/email_triage) routes its file-walk, repo-relative path, AST parse, and enclosing-fn key through the shared harness tests/_pin_harness.py -- never a hand-rolled SRC_ROOT/rglob/relative_to/parent-annotation copy',
    signature_hint: 'grep tests/ for rglob("*.py") + parents[N]/"src"/"email_triage" + relative_to(SRC) + .replace("\\\\","/")/.as_posix() in a file NOT importing _pin_harness; the canonical drifts are the relpath BASE divergence (relative_to(SRC)=\"web/db.py\" vs SRC.parent vs parents[1]) and the basename-vs-relpath allow-list bug (R38). The live guard is tests/test_pin_harness_adoption.py.',
    why: 'R5b/R5c -- "census the censusers". The anti-drift layer drifts too: ~40 pins each hand-rolled the SRC-root + rglob + relpath boilerplate and DIVERGED in it (3 relpath bases; the auth_stale basename allow-list bug). They were converged onto tests/_pin_harness.py + the meta-pin test_pin_harness_adoption.py on 2026-06-11. A true-up must re-measure whether a NEW pin re-rolled the walk or a migrated pin drifted back off the harness -- a census that never censuses its own anti-drift mechanism has a recursive blind spot. META value.',
  },
  {
    key: 'json-col-write',
    title: 'DB-column JSON encode (write twin of load_json_col)',
    operation: 'serializing a Python value to JSON for storage in a *_json DB column',
    signature_hint: 'json.dumps / JSONEncoder whose result is bound into a *_json column write (INSERT/UPDATE param); the bare json.dumps(x) vs compact separators=(",",":") vs canonical sort_keys/ensure_ascii=False option-split; the HMAC hash-preimage forms (triage_logging.py) that MUST stay byte-stable. The pinned READER is load_json_col (db/_helpers.py); the WRITER SSOT was never built. MEMBERSHIP PREDICATE: a json.dumps call whose value FLOWS to a *_json column param -- AST-enumerate the flow, NOT a grep of json.dumps (95 hits vs ~66 true writers).',
    why: 'run18 #4 (discovered): ~66 unharmonized json.dumps writers into *_json columns vs the 1 pinned reader; 3-way option split -> a hash-preimage fork risk in the audit chain + multilingual ensure_ascii bloat. WRITE TWIN of load_json_col (run17 #7/N-140). Build dump_json_col() next to load_json_col; ban bare json.dumps into a *_json column outside it (allow-list the hashed forms). MED.',
  },
  {
    key: 'ondisk-artifact-disposal',
    title: 'Per-account on-disk credential/state file -- create vs dispose vs backup parity',
    operation: 'an account-scoped file written to disk OUTSIDE the SQLCipher DB (credential/token cache, state file) whose CREATE, DISPOSE-on-delete, and BACKUP sides must agree on the path set',
    signature_hint: 'a per-account file path (f"...{account_id}..." under a data dir) CREATED by a writer but NOT unlinked in the sec.164.310(d)(2)(i) disposal funnel (db/accounts.py purge_account_local_state / watcher.apply_account_deleted) AND/OR not collected by the backup bundle (backup.py). The CREATE side is typically broad (several writers); the DISPOSE + BACKUP sides narrow -> drift. Exemplar: msal_cache_<id>.json (run18 #1/N-150). MEMBERSHIP PREDICATE: a write to a per-account on-disk path literal -- AST-enumerate writers, then check each has a matching disposal unlink + a backup decision (bidirectional file-artifact invariant), NOT just DB-row purges (the old pin was file-BLIND).',
    why: 'run18 #1 (discovered, HIGH/LIVE): plaintext O365 OAuth tokens in ./data/msal_cache_<id>.json survived account purge -- sec.164.310(d)(2)(i)+sec.164.312(a)(2)(iv). A NEW lens: "account-scoped on-disk artifact, CREATE broad but DISPOSE/BACKUP narrow." Also flags plaintext-at-rest (encrypt-at-rest Directive ) + the sec.164.308(a)(7) backup-completeness twin. HIGH value (HIPAA disposal + at-rest). UPGRADE 2026-07-09 (wf_56d1585d V6 fix at `de050c40`): a SECONDARY drift shape landed -- when a per-user artifact PATH-SHAPE MIGRATES over time (e.g. N-307 rename `msal_cache_cli_<user>.json` -> `msal_cache_cli_<safe_stem>_<hash16>.json`), a registry-driven disposer that iterates `_USER_BUILDERS` + calls `builder(username).unlink(missing_ok=True)` unlinks ONLY the CURRENT-SHAPE path -- installs upgraded across the rename leak the PRIOR-SHAPE file (still contains a plaintext OAuth refresh_token). The SSOT-disposer (`dispose_msal_cache_for_cli` N-356 R31) knows both shape epochs; the registry-driven `dispose_all_per_user_artifacts` MUST ROUTE THROUGH the SSOT disposer, NOT re-inline the unlink loop. Add to census discover-phase: for every `_ARTIFACT_BUILDERS` entry, check that the corresponding `dispose_<stem>_for_<scope>` SSOT exists AND is CALLED by the aggregate disposer. Grounded evidence: `de050c40` fix (route through SSOT) + `tests/test_ondisk_disposal_old_shape_pin.py` (3 tests including a structural sibling that enforces per-builder SSOT-call symmetry).',
  },
  {
    key: 'parse-int-request',
    title: 'Parse-int of a request value (the _safe_int SSOT)',
    operation: 'converting an attacker-controllable request value (form/query/path param) to int',
    signature_hint: 'int(<request-accessor>) -- int(form.get(...)) / int(query_params...) / int(path_params...) / int(request.*) -- OUTSIDE the _safe_int SSOT (web/routers/ui/_shared.py:104, swallows TypeError/ValueError->default). A bare int() OR int(x or 0) (which does NOT cover non-numeric) -> an uncaught ValueError -> HTTP 500 on a tampered value; vs a hand-rolled try/except (TypeError,ValueError) wrapper (correct-but-divergent CIDI drift). MEMBERSHIP PREDICATE: int(<call to a request accessor>) AST-enumerated -- NOT a grep of int( (census hand-count ~72; AST net = 29 request-derived, 2 unguarded).',
    why: 'run18  (discovered, LOW-MED with 2 LIVE 500s): profile.py:1559/1564 int(form.get("def_id") or 0) -> reachable 500 on non-numeric def_id today. _safe_int is the SSOT but ~29 sites bypass it. Route all through _safe_int; ban bare int(<request-accessor>) outside it. sec.164.308(a)(7) availability (a reachable 500), not PHI. MED.',
  },
  {
    key: 'audit_hmac',
    title: 'HMAC-chained audit-row writer (log_entries chain integrity)',
    operation: 'inserting a row into a chained/audit table whose linkage is HMAC-secured via canonical-tuple hashing',
    signature_hint: 'MEMBERSHIP PREDICATE (strict -- do NOT admit on file-name adjacency; the backlog  R31 refinement): a file qualifies only when AST-walk finds >=1 of (a) a call named `_chain_insert` or `chain_insert`; (b) a `@audit_emitter` decorator application; (c) an `INSERT INTO log_entries` / `INSERT INTO audit_events` / `INSERT INTO hipaa_access_events` / `INSERT INTO auth_events` SQL literal (case-insensitive); (d) a call touching the canonical HMAC-preimage tuple `(prev_hash, actor_id, action, resource, ts, payload_json)` (bind-order agnostic). A file whose PATH merely contains `audit/` or `db/` but AST-walks EMPTY of the above is NOT audit_hmac -- file-name adjacency alone over-flagged run22 and wasted SME review budget on false positives.',
    counting_convention: 'super-set -- count both the emitter def-sites AND every ast.Call that satisfies the membership predicate; report both distinctly.',
    why: 'run22 sec.meta hipaa-sme + db-sme + DA (the backlog ): the audit_hmac census category previously fired on file-name adjacency (path contains `audit` / `db/`), NOT on the actual surface touch. Over-flags real HMAC-chain risk exposure. This refined membership predicate requires an AST-visible surface touch -- reuses `test_no_unguarded_secret_write._scan` scoping style (Prime Directive #6). Category-signal quality; the HMAC chain itself is HIPAA-load-bearing sec.164.312(b) so a mis-categorized finding wastes both directions -- silent-drop of real ones + wasted panel time on false ones. MED.',
  },
  {
    key: 'hardcoded-timeout',
    title: 'Hardcoded network / DBAPI / regex timeout literal (config-item drift)',
    operation: 'passing a float or int LITERAL as timeout= to a network client (httpx / smtplib / imaplib / requests) or a DBAPI opener (sqlite3.connect / sqlcipher3.dbapi2.connect) or a regex safety budget (regex.search timeout=)',
    signature_hint: 'MEMBERSHIP PREDICATE (AST-walk): a Call whose keyword arg `timeout=` is an ast.Constant (int/float) -- NOT an ast.Name / ast.Attribute / ast.Call reference to a module SSOT constant or accessor. Scope: `sqlite3.connect(...)`, `sqlcipher3.dbapi2.connect(...)`, `httpx.AsyncClient(...)`, `LazyHttpClient(intent=..., timeout=...)`, `smtplib.SMTP(...)`, `client.get/post(...)` with timeout kwarg, `asyncio.wait_for(..., timeout=...)`, `regex.search(..., timeout=...)`. Allow-list: the SSOT declaration file that HOLDS the module-level constant defaults (`db/_engine.py` for sqlite; `classify/hints.py` for the ReDoS budget; `classify/ollama.py` __init__ default for Ollama probes; `web/smtp_send.py` fall-through for SMTP). Every OTHER call site must dereference a name / accessor.',
    counting_convention: 'per-domain -- count sqlite openers, httpx clients, LazyHttpClient constructions, smtplib.SMTP, imaplib.IDLE waits, and regex.search timeouts as DISTINCT sub-tallies (each has a different SSOT + config surface); AST-enumerate ALL sub-domains via ast.walk, not a grep of `timeout=`.',
    why: 'operator flag 2026-07-11 ("hardcoding timeouts? thats not good. timeouts should be an exposed config item").  (SMTP smtp_send_message hardcoded 30.0 default) + -a/b/c/d/e batched fix converged the whole class in ONE drive after operator called out my initial defer: 4 ollama.py + 9 sqlite (db/_engine.py + db/_migrate.py + web/db.py) + 1 classify/hints.py + 5 HTTP-client sub-class (watch_runner + gmail_push_auth + acme_renewer + office365 + imap.py) + 3 census-loop-caught (embedding_bits + watcher×2) = 22+ sites across 14 files, migrated to 13 new config fields spanning ClassifierConfig(5) / PersistenceConfig(2) / PushConfig(2) / AcmeConfig(1) / IngestionConfig(3), with 8 module-level SSOTs + configure_* setters + get_* accessors; watch_runner refactored from module-level `LazyHttpClient` to lazy-factory pattern; boot wire via config._wire_module_singletons; always-emit round-trip; preventative pin `tests/test_no_hardcoded_sqlite_timeout_pin.py` closes the sqlite sub-class. Bound to `feedback_dynamic_over_hardcoding` order 10 + `feedback_default_to_complete` (operator flagged my initial defer of the HTTP-client sub-class as "deferring again"; convergence check via AST-scan caught 3 more sites HAND-COUNT MISSED). LESSONS TO BAKE IN: (1) hand-count MISSES sites — a broad AST-walk over the tree is the only complete enumeration; my initial hand-count was ~14 sqlite sites but the widened AST-net check found 3 more classes I had not thought of (subprocess timeout in embedding_bits, asyncio.wait_for shutdown grace in watcher). (2) The "expose all" convergence signal is `count_of_offenders == 0 after excluding SSOT decl files` — the census script for THIS class should assert that count-agnostic invariant, not a list. (3) Config-item plumbing has 4 costs: dataclass field, YAML parser, boot wire, and admin-form round-trip — the round-trip pin catches the drift; without it a full-rebuild writer silently drops any field the config-form save handler doesn\'t emit. (4) When operator says "expose ALL" and I catch myself filing something as "follow-up drive", that is the default-to-easier violation the guide names; the correct response is to KEEP GOING same-drive even if it means invalidating an in-flight SME panel and firing a new one. MED value (reliability tuning + auditability, not HIPAA-load-bearing).',
  },
]

const CENSUS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['class_key', 'signature', 'sites', 'variants', 'canonical_exists',
             'recommended_ssot', 'recommended_pin', 'weakest_variant',
             'severity', 'est_effort', 'notes'],
  properties: {
    class_key: { type: 'string' },
    signature: { type: 'string', description: 'the exact grep/AST signature(s) used to enumerate -- so completeness is auditable' },
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

// Open-ended discovery lenses -- find CIDI cases BEYOND the seeded classes.
// Deliberately general + un-primed (no specific bug named) so a hit is a real
// validation of the audit, not a plant. The "lifecycle-flags" lens covers the
// classic set-broad / clear-narrow asymmetry; the others cover cross-cutting
// concerns + same-effect-different-mechanism.
const DISCOVERY_LENSES = [
  {
    key: 'lifecycle-flags',
    prompt:
      'Find a LIFECYCLE FLAG / status-state pattern handled ASYMMETRICALLY across code paths -- a flag, ' +
      'setting, or piece of state that is SET (or invalidated) on one condition but whose corresponding ' +
      'CLEAR / reset / refresh is wired into only SOME of the paths that should trigger it. The classic ' +
      'shape: the set-side has a broad set of triggers while the clear-side is wired into one narrow path, ' +
      'so the state goes STALE on the other paths. For each candidate give the set-sites and the clear-sites ' +
      '(file:line) and name the paths where the clear is MISSING.',
  },
  {
    key: 'cross-cutting',
    prompt:
      'Find a CROSS-CUTTING concern -- structured logging, audit emission, cache invalidation, metric/counter ' +
      'update, status-flag maintenance, error handling -- applied in SOME code paths handling the same logical ' +
      'operation but inconsistently or entirely MISSING in sibling paths. Give the paths that DO and DO NOT ' +
      'apply it (file:line).',
  },
  {
    key: 'same-effect-diff-mechanism',
    prompt:
      'Find the SAME logical effect achieved via DIFFERENT mechanisms/helpers/inline code across the codebase -- ' +
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
// not ALL -- there was no enumerate-the-full-population check).
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

phase('Census')

const results = await pipeline(
  CLASSES,
  // Stage 1 -- census one operation-class.
  (cls) => agent(
    `You are auditing the email-triage codebase (HIPAA-class FastAPI/Jinja/SQLite app at ` +
    `the repo root = your current working directory, source under src/email_triage/) for ` +
    `"convergent intent, divergent implementation" -- the SAME logical operation implemented several ways.\n\n` +
    `OPERATION CLASS: ${cls.title}\n` +
    `The operation: ${cls.operation}\n` +
    `Where to look (signature hint, NOT exhaustive -- widen it): ${cls.signature_hint}\n` +
    `Why this class matters: ${cls.why}\n\n` +
    `Do this, REPORT don't fix:\n` +
    `1. ENUMERATE every site that performs this operation. Use Grep/Glob/Read. State the EXACT ` +
    `signature(s) you searched (so completeness is auditable) and widen beyond the hint -- find the sites the ` +
    `obvious grep misses (values passed through a db_call(helper,...) threadpool hop, re-exports, aliases).\n` +
    `1b. IF the divergence is STRUCTURALLY EXPRESSIBLE -- an AST-checkable property over call sites (e.g. ` +
    `"emitter call inside a try whose handler swallows", "by-id fetch with no gate in the same handler", ` +
    `"INSERT outside the @decorator", "raw sqlite3.connect not the encryption-aware opener") -- you MUST write a ` +
    `throwaway AST detector (python -c with ast.walk over src/email_triage, reusing tests/_pin_harness.py's ` +
    `iter_src_files/relpath) and report ITS site list as authoritative in the 'signature' + 'sites' fields. An LLM ` +
    `grep UNDERCOUNTS structurally-detectable classes: in run17 #3 a grep enumerated 3 audit-emit swallows while ` +
    `the AST detector found 60 across 27 files (a 20x miss the grep-based verify ALSO passed). The grep is the ` +
    `hint; the AST walk is the net. This detector is also the seed for the recommended_pin in step 5.\n` +
    `1c. MEMBERSHIP-PREDICATE DISCIPLINE (PD#4 -- the run18 recurring failure mode). DECLARE the EXACT membership ` +
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
    `to a factory-bound secrets receiver -- fix = resolve the receiver by its SecretsProvider TYPE, not its name ` +
    `(N-161 #5); and (vi) a credential read keyed on a literal env-var KEY was only caught for the ".get" spelling -- ` +
    `fix = ban ALL spellings (os.environ.get / os.getenv / environ[KEY] subscript / a bare environ walk), not one ` +
    `(N-163 #6). RULE: if your predicate is a name-list / literal-substring / receiver-NAME / single-SPELLING match it ` +
    `is blind BY CONSTRUCTION -- widen it STRUCTURALLY: a receiver predicate -> TYPE-resolution (isinstance/annotation), ` +
    `a literal-KEY predicate -> an ALL-SPELLINGS ban, an SQL/decorator predicate -> an alias-tolerant regex / ` +
    `decorator-walk -- then re-enumerate; set enumeration_complete=false unless you proved predicate superset-of class. Be ` +
    `especially skeptical when a class claims its OWN prior closure ("0 unrouted / converged" / "no live debt") -- ` +
    `re-derive from scratch; run18 caught audit-emit, pin-harness, AND secret-read over-reporting their closure.\n` +
    `2. CLUSTER the sites into distinct VARIANTS by HOW each handles the contract around the operation ` +
    `(the guard, the ordering, the error-handling, the intent-declaration, which store/table). Name each variant + count.\n` +
    `3. For each variant state the CONCRETE risk it carries (what breaks, when).\n` +
    `4. Say whether a canonical/safest variant or SSOT ALREADY exists.\n` +
    `5. Recommend the ONE SSOT to route all sites through, AND the count-agnostic structural test ` +
    `(AST/grep pin, per the project's pattern_count_agnostic_structural_drift_catch -- assert a PROPERTY over every ` +
    `site, never a count) that would fail CI on a future off-SSOT variant. If the codebase hops values through ` +
    `helpers, the pin must be interprocedural. Where the class is a render-redaction / view-leak class (PHI scrubbed ` +
    `before a template render), the pin is a RENDERED-VIEW test that MUST exercise the COUNT-GATED multi-item branch ` +
    `with a fixture of >=2 items: run18 N-162 was a multi-folder PHI render leak that escaped the suite because every ` +
    `existing test used a SINGLE item and never hit the "|length > 1" gate guarding the leaking render sites (PD#17 -- ` +
    `test the rendered view, AND the count-gated branch of it).\n` +
    `6. Rate overall severity (weakest variant's blast radius, weighted by HIPAA-load-bearing) + effort to harmonize.\n` +
    `Reference exemplars already in-tree: @db_write + tests/test_db_write_coverage_pin.py, ` +
    `_secret_write.py + tests/test_no_unguarded_secret_write.py.`,
    { label: `census:${cls.key}`, phase: 'Census', schema: CENSUS_SCHEMA },
  ),
  // Stage 2 -- adversarially verify the census was COMPLETE.
  (census, cls) => agent(
    `Adversarially verify a divergence-census finding for operation-class "${cls.title}" in email-triage ` +
    `(repo root = your current working directory; source under src/email_triage/). The census agent reported:\n\n` +
    `Signature searched: ${census ? census.signature : '(census failed)'}\n` +
    `Sites found: ${census ? census.sites.length : 0}\n` +
    `Variants: ${census ? JSON.stringify(census.variants.map(v => ({label: v.label, count: v.count}))) : '[]'}\n` +
    `Claims canonical exists: ${census ? census.canonical_exists : 'n/a'} (${census ? census.canonical : ''})\n` +
    `Severity: ${census ? census.severity : 'n/a'}\n\n` +
    `Your job -- find what it MISSED (the "show me your net was complete" discipline). Re-run your OWN ` +
    `enumeration with broader signatures (aliases, re-exports, helper-hops, dynamic dispatch). WHERE the class is ` +
    `structurally expressible, RE-ENUMERATE with your OWN AST detector (python -c + ast.walk over src/email_triage), ` +
    `NOT just a broader grep -- a structural count exceeding the census's site list is the run17 #3 failure mode (3 ` +
    `reported, 60 real, and a grep-based verify rubber-stamped it). Report: (a) was the ` +
    `enumeration complete, and any sites it missed with file:line; (b) does the canonical/SSOT claim actually hold ` +
    `(or is the "canonical" itself one of several variants); (c) is the severity right. Default to enumeration_complete=false ` +
    `if you find ANY missed site.`,
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
    `census already covers these -- do NOT re-report them: audit-event emission, authz/permission checks, ` +
    `outbound egress, secret reads, config persistence, provider/IMAP fetch, user-facing error surfacing.\n\n` +
    `Find OTHER "convergent intent, divergent implementation" cases (the same logical operation handled several ` +
    `ways, or a concern applied to some code paths but not its sibling paths). Specifically:\n${L.prompt}\n\n` +
    `Use Grep/Glob/Read across src/email_triage (include web/, web/routers/, actions/, classify/, db/). Report ` +
    `concrete candidates with file:line evidence; rate each severity + name the unifying SSOT/fix. Be specific -- ` +
    `a maintainer must be able to act on each. An empty list is a fine answer if you find nothing real.`,
    { label: `discover:${L.key}`, phase: 'Discover', schema: DISCOVERY_SCHEMA },
  )
))).filter(Boolean)
const discoveredCount = discovered.reduce(
  (n, d) => n + (d.candidates ? d.candidates.length : 0), 0,
)
log(`Discovery surfaced ${discoveredCount} candidate new class(es) beyond the seeded set`)

// Discover COMPLETENESS-VERIFY -- the 2026-06-09 canary fix. Each lens finds
// SALIENT instances, not ALL (that's how the known auth_stale set-broad/
// clear-narrow defect slipped past -- the lifecycle lens found ONE flag and
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
    `That finding cites only a few sites. Your job is COMPLETENESS for this exact shape -- be exhaustive. ` +
    `FIRST enumerate the FULL POPULATION (e.g. if it is a status-flag set/clear asymmetry, list EVERY status ` +
    `flag / setting the app writes, then check each one's clear-side coverage; if it is an inline idiom, grep ` +
    `EVERY occurrence). THEN check each member. Report ALL instances of this shape, and SEPARATELY the ones ` +
    `the original finding did NOT cite. Show the enumeration signature you used so the net is auditable.`,
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
  `the missed sites) -- flag "re-census before trusting."\n` +
  `6. A short "prevention" note: the iron rule (every SSOT ships with its structural pin; harmonization without a ` +
  `pin decays), and that llm_safety.py reportedly lacks an AST pin (confirm/deny from the data).\n` +
  `7. A "census methodology self-eval" section (the standing post-run step): from THIS run's data, what should ` +
  `scripts/workflows/et-divergence-census.js itself LEARN? Flag any class where a structural AST detector (step 1b) ` +
  `found materially MORE sites than an initial grep would (the run17 #3 3-vs-60 failure mode); any seeded class that ` +
  `should be split or added; any verify stage that rubber-stamped an incomplete net; any signature_hint that proved ` +
  `too narrow. Be concrete -- name the class, the count delta, and the exact signature/detector that should be baked ` +
  `into the class hint. This section is the INPUT to folding learnings back into the census script + procedure_census_loop.\n` +
  `*** Run20 remediation-cycle lessons (baked in for run21+ discipline; validate/refresh from run21 data):**\n` +
  `- **Consumer #2 semantic-filter blind-spot** -- a class where the SSOT/harness EXISTS but is only PARTIALLY adopted ` +
  `(pre-existing sites bypass it) can be wrongly STALE'd by Consumer #2 (harness present != every site adopted). ` +
  `Run20 R20_3: harness had 197 fork-sites vs the 93 the census claimed (2x under-count). Rule: any Consumer #2 STALE ` +
  `verdict on an "SSOT present but wide adoption" shape MUST be paired with a structural adoption-count walker before ` +
  `trusting the downgrade.\n` +
  `- **Actuator-check > name-check for interproc SSOT verification** -- a pin that verifies KEY_CONST NAMES appear in ` +
  `a handler catches spelling drift but not a silent bypass write (secrets[K]=v instead of set_secret_if_changed(...)). ` +
  `Rule: for any interproc SSOT pin, prefer "KEY_CONST is the K-th arg of a call to one of the SSOT actuators" over ` +
  `"KEY_CONST appears somewhere in the function body". Run20 example: N-181 hipaa-sme + db-sme + DA convergent must-fix.\n` +
  `- **Hardcoded name lists inside _pin_harness reintroduce the N-135 pattern at a smaller grain.** A helper like ` +
  `chain_writer_names()={"insert_log_entry"} is the same "hardcoded name list" trap the guide warns against. Rule: any ` +
  `new hardcoded name set inside _pin_harness MUST be paired with a companion drift-guard test (structural discovery ` +
  `walker + assert declared == discovered - ALLOW). N-182 example: DA must-fix.\n` +
  `- **SSOT composition (extend A5/A8) often beats new files.** For the "options a=new file / b=one file / c=extend ` +
  `existing" pattern, if an existing hardened SSOT already owns half the invariant, prefer COMPOSITION (add a purpose= ` +
  `arg / delegate to the existing seam) over a parallel new SSOT. N-179 example: error_html.py extended to auto-scrub ` +
  `Exception input via scrub_exc, avoiding a 2nd html-escape seam.\n` +
  `- **Verify-don't-accept can REFUTE a census class.** Run20 R20_15 (permission-check "6 V3 resolvers"): I couldn't ` +
  `map the class to real tree code -- no _scope_from / _resolve_*_scope / V3 resolver pattern exists at HEAD. Rule: ` +
  `census language that names specific pattern names ("V3 resolvers", "6 sites") MUST be grep-verifiable before ` +
  `the class is seeded. If Consumer #1 pre-pass can't locate the named seams, seed as UNCERTAIN + require the operator ` +
  `to confirm the class exists.\n` +
  `*** Run21 remediation lessons (baked in for run22+):**\n` +
  `- **Detector-refinement often outperforms migration.** Run21 R21_2 (error-surface sub-2/sub-3): baselines went ` +
  `116+20 -> 0+0 mostly through detector TIGHTENING, not migration. False-positive rate was 85% because: (a) common ` +
  `variable names like \`err\` in DEFAULT_EXC_NAMES caught non-exception values (authz-error return values, pre-scrubbed ` +
  `strings from db_call tuples); (b) \`str(x)\` / \`repr(x)\` fired on scalars (\`str(fp)\`, \`str(backend)\`, \`str(payload)\`) ` +
  `in html.escape safety chains, not exceptions; (c) log/audit-helper descendants (\`log.error("msg", extra={"error": ` +
  `fmt_exc(e)}})\`, \`_record_*_audit(detail=fmt_exc(e))\`) are LEGIT server-side sinks; (d) \`type(exc).__name__\` is the ` +
  `class-name extraction idiom, no PHI. Rule: when a detector's site count is materially higher than the census's, ` +
  `TIGHTEN the detector before demanding migration -- false-positive sites are noise the operator must review one-by-one.\n` +
  `- **REFUTE-via-verify-don't-accept for aspirational/registry classes.** Run21 R21_5 ondisk-artifact-disposal ` +
  `recommended a \`providers/on_disk_artifacts.py::ACCOUNT_ARTIFACTS\` registry, but ONLY 1 per-account artifact exists ` +
  `at HEAD (msal_cache -- already SSOT'd via msal_cache_path_for_account + backup glob). Registry is aspirational until a ` +
  `second artifact type is added. Rule: if a census recommends a registry+bidirectional-pin for a CURRENT count of 1, ` +
  `seed as REVISIT-WHEN -- the operator confirms when the second type is under active development.\n` +
  `- **Census-vs-detector count deltas MUST be reported both ways.** Run21 R20_9/N-196 module-logger-init: census ` +
  `claimed 118, my structural walker found 72 (35% over-count, not under-count). Both directions matter -- an over-count ` +
  `wastes SME review, an under-count misses drift. Rule: always report ABS(census - detector) count delta with sign ` +
  `so the operator sees over/under-counts in the same view.\n` +
  `- **Verify-don't-accept also applies to REMEDIATION recommendations.** Run21 R21_8 config-persist V7 claimed ` +
  `10 raw \`secrets.set\` sites are N-130-recurrence surface, but reading each one showed: 5 are one-shot MIGRATION seeds ` +
  `(providers/factory.py::hydrate_and_register_install_oauth), 2 are ACME account key store, 1 is session_secret at ` +
  `lifespan startup -- legit init paths, NOT form-driven writes. The N-181 SSOT actuator-check pin ALREADY covers the ` +
  `highest-risk INSTALL_OAUTH_FIELDS keys. Rule: before recommending a broad \`_secret_write\` funnel migration for ` +
  `a whole class, walk each site's call context -- init/migration paths intentionally bypass never-clobber (they DO write, ` +
  `unconditionally, on first-run seed).\n` +
  `*** Run22 remediation lessons (baked in for run23+):**\n` +
  `- **A REFUTE can be WRONG -- census can re-flag with better framing.** Run22 R22_3 ondisk-artifact-disposal was ` +
  `REFUTED in run21 R21_5 with "only 1 per-account artifact exists -> registry premature". Run22 re-flagged HIGH because ` +
  `the ctor DEFAULTS still hardcoded the singleton path -- 5 callers were correct but the ctor was a fail-open back-door. ` +
  `Rule: a "premature abstraction" REFUTE must ALSO verify the seam DOES NOT have a fail-OPEN default. If the class has ` +
  `a ctor kwarg with a shared-singleton default, that IS the defect -- kill the default even if only 1 artifact type exists.\n` +
  `- **Detector-widening (BoolOp) reveals sites the census missed.** Run22 R22_5 claimed "5 utc-iso-boolop bypasses"; ` +
  `after widening the A10 pin to walk BoolOp shapes + fixpoint-propagating aware-now taint through OR-fallback ` +
  `assignments, the AST-precise walk found 6 sites (1 literal-BoolOp + 5 downstream Name-tracked via base-BoolOp seed). ` +
  `Rule: when the census claims "N sites of shape X" and the AST walker finds N-1 of X but M of shape Y that CAUSED X, ` +
  `report BOTH counts -- the census's line-count is a hint, the AST census-of-classes is authoritative.\n` +
  `- **Stale-guard sibling MUST be applied to every _ALLOW list you land.** Run22 R22_4 pinned-verify: ` +
  `\`_HARNESS_IMPORT_ALLOW\` at test_ssot_registry_bijection_pin.py:150-157 had 5 stale entries -- 3 GHOSTS + 2 MIGRATED -- ` +
  `because the pin lacked the sibling stale-guard \`test_covered_elsewhere_entries_exist\` pattern. PD#7 not propagated. ` +
  `Rule: every \`_ALLOW\`/\`_EXEMPT\`/\`_COVERED_ELSEWHERE\` list SHIPS with its own stale-guard test in the same commit. ` +
  `A list without a rot-guard is a policy that has drift baked in.\n` +
  `- **Detector aliasing gaps are structural -- check ImportFrom aliases before claiming coverage.** Run22 R22_9 ` +
  `permission-check: a handler that imported \`manageable_account_ids as _manageable_account_ids\` used the aliased name; ` +
  `the detector's \`_GATE_NAMES\` set didn't include the alias, so the handler looked un-gated. ` +
  `Rule: any detector that name-matches a canonical SSOT symbol MUST also walk the module's ImportFrom nodes and add ` +
  `\`alias.asname\` for every \`alias.name in _CANONICAL_SET\` to its effective set. Pass as \`extra_gate_names\` to the ` +
  `per-function check.\n` +
  `- **A same-tick SET-then-CLEAR wipe is a LIFECYCLE class, not a naming/count class.** Run22 R22_2 backfill_capped: ` +
  `SET at line X + CLEAR at line Y in the SAME function is a defect if both fire on the same execution tick. ` +
  `The N-198 FILE-symmetry pin was too coarse -- it required BOTH set/clear in the file, but not their mutual exclusion. ` +
  `Rule: for any operator-visible chip that carries a HIPAA sec.-anchored signal (sec.164.502(a)(1) un-triaged-PHI-in-gap, ` +
  `sec.164.312(b) audit-emit failure, etc.), the pin MUST assert the SET and CLEAR are mutually exclusive per execution ` +
  `path -- via if/else branches, an early continue/return between them, or a \`_set_this_tick\` guard variable. ` +
  `File-level co-existence is necessary but not sufficient.\n` +
  `*** Run23 remediation lessons (baked in for run24+):**\n` +
  `- **A REFUTE of a "premature abstraction" must ALSO verify no fail-open default remains in the seam.** ` +
  `Run23 R23_2 re-flagged ondisk-artifact-disposal (which R21_5 had REFUTED as "1 per-account artifact -> premature"): ` +
  `cli.py:483 still carried the fail-open default \`.get("token_cache_path", "./data/msal_cache.json")\` -- the abstraction ` +
  `WAS premature, but the DEFAULT was the live sec.164.310(d)(2)(i) defect. Rule: when synthesizer REFUTEs a class as ` +
  `"abstraction aspirational / registry premature," it MUST also check for a fail-open default at the seam ` +
  `(ctor kwarg, config fallback, caller-side .get() literal) -- kill the default even if the registry is premature. ` +
  `See feedback_verify_dont_accept sharpening 2026-07-02.\n` +
  `- **Cross-scope keying widens a lifecycle pin scope.** Run23 R23_3 backfill_capped: N-201's same-tick pin (R22 lesson) ` +
  `was still gappable -- a PEER mailbox on the SAME account could wipe the chip because storage keyed on account_id ` +
  `alone. The lifecycle scope isn't just per-tick; it's per (account, source_mailbox). Rule: for any operator-visible ` +
  `chip that scopes below account (per-mailbox, per-folder, per-provider), the pin MUST assert the CLEAR side accepts ` +
  `the sub-scope key + refuses to wipe when the stored sub-scope differs.\n` +
  `- **SSOT-consolidation is NOT "technical debt" -- the duplicated safe pattern IS the defect.** Run23 R23_1 ` +
  `backup.py had 8 SSOT-drift sites; 2 were live world-readable defects, 6 were "correct-by-construction TODAY" ` +
  `(chmod-before-swap correctly ordered). Filing the 6 as "N-Xb technical debt cleanup" is the anti-pattern the ` +
  `operator called out. Rule: when the census flags SSOT-drift, fix ALL sites in the same session -- not just the ` +
  `live-defect subset. A duplicated safe pattern is a landmine for the next editor. Extend the SSOT API if needed ` +
  `(e.g. add a \`pre_replace\` callback for verify-before-swap sites) rather than leaving them un-migrated. See ` +
  `feedback_dont_over_defer 2026-07-02 sharpening.\n` +
  `- **Enumeration under-count on a "N prod + M test/spike" split.** Run23 R23_8 said "5 prod + 14 test/spike" ` +
  `openers of the standard PRAGMA sequence; structural AST scan found 4 prod openers (correct on the split-side, ` +
  `under-count on the count-side by 1). Rule: any "N prod + M test" claim in a signature_hint MUST be structurally ` +
  `verified against a whole-repo AST walk -- trust the walker's count, use the census count as the LEAD only.\n` +
  `Be decisive and specific. This is a backlog the operator will act on.`,
  { label: 'synthesize:backlog', phase: 'Synthesize' },
)

// Standing post-run step (productized reminder -- the anti-drift tooling drifts
// too, PD#6/#7 "census the censusers"). The backlog's "census methodology
// self-eval" section (synthesizer point 7) is the data; act on it.
//
// * EXTENDED STANDING RULE (2026-07-02, operator directive): after EVERY
// census run, evaluate BOTH the census script AND the llm-host offload scripts
// (scripts/leira_census_prepass.py, scripts/leira_class_hints.py, scripts/
// leira_cache.py, scripts/leira_verify_fix.py, scripts/leira_discover.py,
// scripts/leira_prepass.py) with what this run taught. Did a Consumer #1
// pre-pass miss a decorator-SSOT surface? Add its name to the class-hint
// REGISTRY entry's `decorator_ssots`. Did the discover-phase pre-scan miss
// a drift shape a class flagged? Add a new scanner to `leira_discover.py`.
// Was a cache entry stale (a fix landed but the cached candidate list didn't
// reflect it)? Invalidate + adjust cache-key. The llm-host offload stack is
// itself subject to the "anti-drift tooling drifts too" PD#6/#7 discipline.
log('POST-RUN STEP -- evaluate THIS census script against this run and fold in learnings: read the ' +
    'backlog\'s "census methodology self-eval" section, then update scripts/workflows/et-divergence-census.js ' +
    '(class signature_hints, step-1b AST detectors, new/split seeded classes) + sharpen procedure_census_loop, ' +
    'grounded in this run\'s concrete evidence. Do NOT skip -- an un-sharpened census undercounts the next run.')

return {
  censusedClasses: clean.length, totalClasses: CLASSES.length,
  discoveredCount, newlyFound, backlogMarkdown: backlog,
  raw: clean, discovered, completeness,
}
