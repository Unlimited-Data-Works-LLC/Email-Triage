#!/usr/bin/env python3
"""leira_class_hints.py — per-class structural hint registry (2026-07-02).

Improvement #1 of the llm-host offload stack sharpening: map a divergence-census
class name to a curated `ClassHint` with (a) high-signal keyword lists, (b)
banned false-positive keywords, (c) decorator SSOT names to pre-scan for
(Improvement #2 — decorator-aware wrapper), and (d) a compact per-class
"what to look for" note for the llm-host prompt.

Callers (`leira_census_prepass.py` primarily) read this registry via
`get_class_hint(name)` and pass its fields into the prompt + optional
decorator pre-scan.

Adding a new class: append a `ClassHint(...)` entry. Zero-configuration —
the registry is a plain dict keyed on canonical class name (matching the
census script's class keys).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClassHint:
    name: str
    keywords: tuple[str, ...]
    ban_keywords: tuple[str, ...] = ()
    decorator_ssots: tuple[str, ...] = ()
    probe_shapes: tuple[str, ...] = ()  # short human-readable shape descriptors
    prompt_note: str = ""


REGISTRY: dict[str, ClassHint] = {
    "audit-emit": ClassHint(
        name="audit-emit",
        keywords=("record_hipaa_access_event", "record_auth_event",
                  "audit_emitter", "_chain_insert"),
        ban_keywords=("test_",),
        decorator_ssots=("audit_emitter", "db_write"),
        probe_shapes=(
            "@audit_emitter decorator on a fn that writes to log_entries / hipaa_access_events",
            "record_hipaa_access_event(actor≠owner) call sites",
            "raw INSERT INTO log_entries (BANNED — must route through emitter)",
        ),
        prompt_note=(
            "Every audit-event write MUST go through the @audit_emitter decorator + "
            "record_hipaa_access_event / record_auth_event helpers — a raw INSERT to "
            "the audit table forks the HMAC chain."
        ),
    ),
    "config-persist": ClassHint(
        name="config-persist",
        keywords=("set_setting", "set_secret", "_write_config_yaml",
                  "_secret_write"),
        ban_keywords=("test_",),
        decorator_ssots=("db_write",),
        probe_shapes=(
            "3-store SSOT (`_write_config_yaml` for YAML, `set_setting` for db-settings, "
            "`SecretsProvider.set` / `_secret_write` for secrets)",
            "db_call(set_setting, conn, KEY, ...) seam form",
        ),
        prompt_note=(
            "The config surface has 3 disjoint stores (YAML / settings table / secrets). "
            "A key must live in exactly ONE. The `_write_config_yaml` full-rebuild writer "
            "silently drops a section it doesn't emit — census R23 R23_6 hunts for db_call "
            "seam misses at the settings-store side."
        ),
    ),
    "ondisk-artifact-disposal": ClassHint(
        name="ondisk-artifact-disposal",
        keywords=("msal_cache", "token_cache_path", "purge_account_local_state",
                  "msal_cache_path_for_account"),
        ban_keywords=("test_",),
        decorator_ssots=(),
        probe_shapes=(
            "Office365(Calendar)?Provider(token_cache_path=<value>) — value MUST resolve to "
            "msal_cache_path_for_account(account_id) OR a per-account derived path",
            "shared singleton literal `./data/msal_cache.json` (BANNED as ctor default AND "
            "as caller kwarg AND as .get() fallback)",
        ),
        prompt_note=(
            "Per-account credential material (MSAL token cache) MUST NOT co-mingle. "
            "N-202 killed the ctor default; N-209 killed the CLI's explicit fallback. "
            "Any new caller that resurrects the singleton literal is a §164.310(d)(2)(i) "
            "cross-account credential-pool defect."
        ),
    ),
    "backfill-capped-lifecycle": ClassHint(
        name="backfill-capped-lifecycle",
        keywords=("mark_backfill_capped", "clear_backfill_capped", "backfill_capped"),
        ban_keywords=("test_",),
        decorator_ssots=(),
        probe_shapes=(
            "SET and CLEAR of the operator chip must be mutually exclusive per execution tick "
            "(if/else, continue/return in the SET path, or a `_set_this_tick` guard var)",
            "cross-mailbox scope: CLEAR by mailbox B on account A must NOT wipe SET by "
            "mailbox A on account A (source_mailbox= scope; N-211)",
        ),
        prompt_note=(
            "The chip is the ONLY §164.502(a)(1) un-triaged-PHI-in-gap operator signal. A "
            "same-tick or cross-mailbox CLEAR silently defeats it. Look for straight-line "
            "SET-then-CLEAR paths that lack a guard, AND for CLEAR sites that don't pass "
            "source_mailbox= when the caller has per-mailbox context."
        ),
    ),
    "utc-iso-boolop": ClassHint(
        name="utc-iso-boolop",
        keywords=("isoformat", "now_utc_iso", "to_utc_iso", "datetime.now"),
        ban_keywords=("test_",),
        decorator_ssots=(),
        probe_shapes=(
            "`(a or b).isoformat()` BoolOp shape where a or b is aware-now-rooted",
            "`(datetime.now(tz) - td).isoformat()` inline arith",
            "`now = X or datetime.now(tz); now.isoformat()` — var seed via BoolOp",
        ),
        prompt_note=(
            "The A10 stored-ISO SSOT (`to_utc_iso` / `now_utc_iso`) MUST own the format "
            "of every persisted / compared timestamp. BoolOp fallbacks are the shape N-203 "
            "widened the pin to catch."
        ),
    ),
    "permission-check": ClassHint(
        name="permission-check",
        keywords=("can_manage_account", "manageable_account_ids",
                  "_gate_provider_labels", "can_modify_owned_resource",
                  "is_account_owner"),
        ban_keywords=("test_",),
        decorator_ssots=(),
        probe_shapes=(
            "handler that fetches an account by client-submitted id MUST gate with a "
            "manageable-set intersection (can_manage_account OR manageable_account_ids OR "
            "an Owned* DI dep) BEFORE reading/writing",
            "aliased ImportFrom of the gate name (`import ... as _z`) — N-207 widened the "
            "detector for this",
        ),
        prompt_note=(
            "Every by-id handler must gate at the actuator (write path), not just the reader. "
            "Verify the ImportFrom-alias case (N-207) — a `from X import gate as _gate` is "
            "invisible to a name-match detector without alias resolution."
        ),
    ),
    "atomic-marker-writes": ClassHint(
        name="atomic-marker-writes",
        keywords=("atomic_write_text", "atomic_write_bytes", "write_bytes",
                  "os.chmod", "os.replace"),
        ban_keywords=("test_",),
        decorator_ssots=(),
        probe_shapes=(
            "`path.write_bytes(data)` followed by `os.chmod(path, 0o600)` on the FINAL "
            "path (WORLD-READABLE WINDOW) — route through _atomicio.atomic_write_bytes(mode=)",
            "`os.chmod(tmp, mode); os.replace(tmp, out)` — SAFE, but duplicates _atomicio's "
            "logic (SSOT drift)",
        ),
        prompt_note=(
            "Master-key material integrity (§164.312(a)(1)) — atomic_write_bytes chmods the "
            "TMP file BEFORE the atomic rename, so the visible target NEVER has a broader "
            "mode. Non-atomic write+chmod on a final path is a live defect."
        ),
    ),
    "request-meta": ClassHint(
        name="request-meta",
        keywords=("request.client.host", "request.headers.get",
                  "request_meta", "user-agent"),
        ban_keywords=("test_",),
        decorator_ssots=(),
        probe_shapes=(
            "`request.client.host if request.client else None/\"\"` — the N-187 hand-rolled "
            "shape (route through request_meta(request).host)",
            "`request.headers.get(\"user-agent\")` at authz-adjacent site — same",
        ),
        prompt_note=(
            "N-187 SSOT unifies client host + user-agent reads with a fallback-safe chain. "
            "Every raw read at an audit-event or authz-boundary site is a §164.312(b) "
            "identity-consistency defect."
        ),
    ),
}


def get_class_hint(name: str) -> ClassHint | None:
    """Return the hint for `name`, or None when the class isn't in the registry.
    Callers should degrade gracefully (fall back to the generic prompt) when
    None — an unhinted class still works, just without the class-specific note
    and decorator pre-scan."""
    return REGISTRY.get(name)


def all_class_names() -> list[str]:
    return sorted(REGISTRY.keys())
