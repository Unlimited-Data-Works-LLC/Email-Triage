"""llm-host-offloaded defer-sweep for the email-triage project (Consumer of the llm-host offload stack).

Reads every session JSONL, memory drawer, audit-report file, commit
message, and the backlog row; extracts every defer-shaped occurrence;
batches to the llm-host offload stack (`leira_prepass.call_leira`) for
semantic classification; emits two markdown tables:

  (a) phrase-frequency: phrase | frequency | example_context
  (b) items: item_normalized | shapes | source_types | hits |
             current_status (shipped/tracked/deferred/unknown)

Per `pattern_leira_offload_stack` — a Consumer of the offload stack
follows five non-negotiable pillars:

  1. NO hardcoded model / context / limits — every knob comes from
     `leira_config.json` (via `get_consumer_config('defer_sweep')`)
     or is derived from the runtime-discovered context window
     (`context_bytes(ratio)`).
  2. DYNAMIC discovery of model + context + lifetime — the wrapper
     owns `/api/show`; Consumer never touches it.
  3. Congestion backoff + persistent cooldown lives in `call_leira`;
     Consumer never rolls its own retry loop.
  4. Structured output schema per Consumer — passed to `call_leira`
     as the `schema` kwarg; the wrapper enforces server-side format
     compliance.
  5. HIPAA gate at the CALLSITE — this script processes local
     project artifacts (session JSONL, memory drawers, commits,
     the backlog). No PHI paths. Callers wanting a corpus that
     COULD include PHI (e.g. clinical mail) must gate at their end
     BEFORE invoking this script; this script does not enforce.

USAGE (local — this-machine tool; not designed to run on other hosts):

    python scripts/llm-host-defer-sweep.py

Output lands in `defer_sweep/` at repo root (created on import):
  * `verdicts.jsonl` — per-candidate verdicts (streamed, append-mode
    SSOT across runs).
  * `tables.md` — the two markdown tables (final).
  * `extract-manifest.json` — per-source stat manifest
    (mtime_ns + size_bytes for files; git HEAD sha for commits).
  * `extract-cache.jsonl` — all-runs candidate rows, rewritten whole
    at end-of-extract-phase; fail-open loader skips any malformed
    line. Set `LEIRA_EXTRACT_FORCE=1` to bypass both the manifest
    and the cache (escape hatch for regex edits / corpus changes
    made outside normal channels).
  * `.pause` — filesystem sentinel; `touch` it to trigger a
    clean-exit at the next batch boundary with a resume hint.

Environment overrides:
  * OLLAMA_HOST — pick a different host entry in leira_config.json.
  * OLLAMA_MODEL / OLLAMA_URL / OLLAMA_TIMEOUT_S — per-call overrides.

Corpus sizes (2026-07-15):
  * 48 session JSONL (~612 MB)
  * 375 memory drawer .md files
  * 2137 commit messages
  * 188 audit-report files
  * 233 the backlog rows (44 active + 189 completed)

First built 2026-07-15 for the operator-directed all-history defer-
language census that surfaced during task  close-out (defer-gate
recurrence #8). Pattern-conformant per operator instruction:
"mempalace search pattern_leira_offload_stack and apply it to that
script".
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

# Pillar 1 / 2 / 3 — the wrapper owns runtime discovery, backoff,
# cooldown, schema enforcement. Consumers ONLY call `call_leira`.
sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import (  # type: ignore[import]
    OllamaCallError,
    LeiraUnavailable,
    call_leira,
    context_bytes,
    get_consumer_config,
    active_host_name,
    _in_cooldown as leira_in_cooldown,           # backward-compat (pre-Drive-D tests)
    _in_cooldown_for as leira_in_cooldown_for,   # Drive-D per-host
    _cooldown_path_for as leira_cooldown_path_for,
    _COOLDOWN_PATH as LEIRA_COOLDOWN_PATH,
)


# ---------------------------------------------------------------------------
# Consumer config — every knob comes from leira_config.json.
# ---------------------------------------------------------------------------

_CFG = get_consumer_config("defer_sweep")
_CONTEXT_RATIO = float(_CFG.get("context_usage_ratio", 0.30))
BATCH_SIZE = int(_CFG.get("batch_size", 25))

# Max characters we'll ship in a single call_leira invocation. Derived
# from the model's actual context window — a bigger-context model gets
# a bigger cap automatically (Pillar 1 forbids "MAX_INPUT_BYTES = 200_000").
_MAX_INPUT_CHARS = context_bytes(_CONTEXT_RATIO)


# ---------------------------------------------------------------------------
# Resumability + session-cap dials (opt-in via env; 0 = unbounded / off).
# LEIRA_MAX_BATCHES caps the number of judge batches per session (mid-session
# clean stop). LEIRA_SWEEP_LIMIT truncates the deduped candidate stream (the
# operator-specified smoke-test dial). Pause-file semaphore mirrors the
# email-mine `llm-dial.sh` pattern — presence ⇒ clean exit at next batch
# boundary. Verdicts JSONL is the durable SSOT (append mode) — replaces the
# prior `defer-sweep-checkpoint.jsonl` which opened in 'w' and truncated every
# rerun.
# ---------------------------------------------------------------------------
import os

_MAX_BATCHES = int(os.environ.get("LEIRA_MAX_BATCHES", "0") or 0)
_SWEEP_LIMIT = int(os.environ.get("LEIRA_SWEEP_LIMIT", "0") or 0)

# Runtime-artifact directory — verdicts, extract cache/manifest, tables,
# pause-sentinel all live here. Kept out of `scripts/` (source-only) at the
# operator's direction 2026-07-15 so multi-GB cache files don't pollute the
# script folder and appear in dev tooling that walks scripts/. Created on
# import so first-run does not need a manual mkdir.
_DATA_DIR = Path(__file__).resolve().parents[1] / "defer_sweep"
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_VERDICTS_PATH = _DATA_DIR / "verdicts.jsonl"
_PAUSE_PATH = _DATA_DIR / ".pause"

# Extract-cache — per-source stat manifest + all-runs candidate cache; the
# extract phase skips fresh disk/git work when nothing changed since the last
# run. Fail-open on missing/malformed (helpers below re-extract on any doubt).
# LEIRA_EXTRACT_FORCE=1 is the always-available escape hatch when the operator
# suspects manifest drift (regex change, extractor edit, corpus edit outside
# normal channels): both structures are ignored and rebuilt from source.
_EXTRACT_MANIFEST_PATH = _DATA_DIR / "extract-manifest.json"
_EXTRACT_CACHE_PATH = _DATA_DIR / "extract-cache.jsonl"
_EXTRACT_FORCE = os.environ.get("LEIRA_EXTRACT_FORCE", "") not in ("", "0", "false", "False")


# ---------------------------------------------------------------------------
# Paths — local-machine tool; hardcoded to Alex's Windows layout.
# ---------------------------------------------------------------------------

REPO = Path("C:/Users/ExampleUser/Documents/the AI assistant/Projects/email-triage")
SESSION_DIR = Path(
    "C:/Users/ExampleUser/.the AI assistant/projects/"
    "C--Users-ExampleUser-Documents-the AI assistant-Projects-email-triage"
)


# ---------------------------------------------------------------------------
# Defer-shaped seed patterns.
# ---------------------------------------------------------------------------

# SSOT wire (Prime Directive #5, Drive-2 of bridge arc): the broad census
# patterns live in ``scripts/hooks/_defer_phrases.py`` alongside the tight
# GATE patterns used by defer_gate. This module re-exports as ``DEFER_PATTERNS``
# for backwards compatibility with any external caller / historical shape.
_HOOKS_DIR = Path(__file__).resolve().parent / "hooks"
sys.path.insert(0, str(_HOOKS_DIR))
from _defer_phrases import SWEEP_PATTERNS as DEFER_PATTERNS  # noqa: E402

_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), name) for p, name in DEFER_PATTERNS]


# Perf: compile ONE combined regex so extract does a single pass over
# each file instead of 37 separate scans. Named group `pN` identifies
# which subpattern matched.
_UNION_RE = re.compile(
    "|".join(
        f"(?P<p{i}>{regex})"
        for i, (regex, _) in enumerate(DEFER_PATTERNS)
    ),
    re.IGNORECASE,
)
_NAME_BY_GROUP = {
    f"p{i}": name for i, (_, name) in enumerate(DEFER_PATTERNS)
}


def _elog(*args) -> None:
    """Flush-through stderr print — the default block-buffers when stderr
    is redirected to a file and swallows live progress."""
    print(*args, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _snippet_around(text: str, start: int, end: int, radius: int = 160) -> str:
    """Return a short context snippet around a match, whitespace-collapsed."""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].replace("\n", " ").replace("\r", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    return snippet[:400]


def extract_from_file(path: Path, source_type: str) -> list[dict]:
    """Yield defer-candidate records from a file. ONE pass via union regex."""
    candidates: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _elog(f"[skip] {path}: {exc}")
        return candidates
    for m in _UNION_RE.finditer(text):
        gd = m.groupdict()
        name = "?"
        for g, v in gd.items():
            if v is not None:
                name = _NAME_BY_GROUP.get(g, "?")
                break
        snippet = _snippet_around(text, m.start(), m.end())
        candidates.append({
            "phrase": m.group(0),
            "phrase_canon": name,
            "snippet": snippet,
            "file": str(path),
            "offset": m.start(),
            "source_type": source_type,
        })
    return candidates


def _parse_commit_log_stdout(stdout: str) -> list[dict]:
    """Parse `git log --format=%H%x00%s%x00%b%x1e` stdout → candidate rows.

    Shared by extract_from_commits() (full log) and _cached_extract_commits()
    (delta log `<prior>..HEAD`) — the row shape is identical either way.
    """
    candidates: list[dict] = []
    for rec in stdout.split("\x1e"):
        rec = rec.strip()
        if not rec:
            continue
        parts = rec.split("\x00", 2)
        if len(parts) < 2:
            continue
        sha, subj = parts[0], parts[1]
        body = parts[2] if len(parts) > 2 else ""
        text = subj + "\n" + body
        for m in _UNION_RE.finditer(text):
            gd = m.groupdict()
            name = "?"
            for g, v in gd.items():
                if v is not None:
                    name = _NAME_BY_GROUP.get(g, "?")
                    break
            snippet = _snippet_around(text, m.start(), m.end())
            candidates.append({
                "phrase": m.group(0),
                "phrase_canon": name,
                "snippet": snippet,
                "file": f"commit:{sha[:12]}",
                "offset": m.start(),
                "source_type": "commit",
            })
    return candidates


def extract_from_commits() -> list[dict]:
    """Every `git log --all` message body → candidate records."""
    proc = subprocess.run(
        ["git", "log", "--all", "--format=%H%x00%s%x00%b%x1e"],
        cwd=REPO, capture_output=True, text=True, encoding="utf-8",
        errors="replace",
    )
    return _parse_commit_log_stdout(proc.stdout)


def dedupe_candidates(candidates: list[dict]) -> list[dict]:
    """Fold candidates whose (phrase_canon, snippet_head) match — same
    conversation typically repeats identical phrasing. Keep first hit."""
    seen: set[str] = set()
    out: list[dict] = []
    for c in candidates:
        key = c["phrase_canon"] + "|" + c["snippet"][:120].lower()
        h = hashlib.sha1(key.encode("utf-8", errors="replace")).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append(c)
    return out


# ---------------------------------------------------------------------------
# Resumability helpers — verdict key + prior-verdict loader + pause probe.
# ---------------------------------------------------------------------------

def _verdict_key(c: dict) -> str:
    """Stable per-candidate resume key: sha1(phrase_canon|file|offset).
    Orthogonal to `dedupe_candidates` (which keys on phrase_canon|snippet[:120]
    and drops file+offset intentionally) — dedup collapses noise BEFORE the
    resume filter runs, so the surviving representative always keeps the
    FIRST-seen (file, offset) and this key is stable across runs unless the
    underlying corpus is edited between runs.
    """
    raw = f"{c.get('phrase_canon', '')}|{c.get('file', '')}|{c.get('offset', 0)}"
    return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()


def _load_prior_verdicts(path: Path) -> tuple[set[str], list[dict]]:
    """Stream the verdicts JSONL if present; return (set_of_keys, merged_rows).

    Malformed lines are skipped with a stderr warning (fail-open guard for a
    partial-write tail from an abrupt exit — a truncated last line must not
    wipe the entire resume state). Returns ((), []) when the file is missing.
    """
    if not path.exists():
        return set(), []
    keys: set[str] = set()
    rows: list[dict] = []
    for lineno, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            _elog(f"[resume] {path.name} line {lineno} malformed, skipping ({e})")
            continue
        rows.append(row)
        keys.add(_verdict_key(row))
    return keys, rows


def _pause_requested(path: Path) -> bool:
    """Filesystem semaphore: presence of the pause file ⇒ clean-exit at next
    batch boundary. Mirrors the email-mine `llm-dial.sh` pattern."""
    return path.exists()


# ---------------------------------------------------------------------------
# Extract-cache helpers — per-source stat manifest + all-runs candidate cache.
# Cache/manifest live UPSTREAM of dedupe → resume-skip → LEIRA_SWEEP_LIMIT →
# judge; downstream contract is byte-identical (`all_candidates` list of the
# same-shaped dicts). All writers stderr `[extract-cache] …` lines for
# operator visibility.
# ---------------------------------------------------------------------------

def _file_stat_key(path: Path) -> tuple[int, int] | None:
    """Return (mtime_ns, size_bytes) for cache-key comparison; None on OSError.

    Both fields are checked because mtime alone is spoofable by `touch` and
    size alone misses same-length in-place edits.
    """
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _git_head_sha() -> str | None:
    """`git rev-parse HEAD` in REPO; None on any failure (fail-open)."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO, capture_output=True, text=True, encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    sha = (proc.stdout or "").strip()
    return sha or None


def _load_extract_manifest() -> dict:
    """Read the per-source stat manifest; fail-open to empty dict on missing /
    unreadable / JSONDecodeError. LEIRA_EXTRACT_FORCE=1 short-circuits to
    empty (full re-extract; manifest gets rewritten at end-of-phase)."""
    if _EXTRACT_FORCE:
        _elog("[extract-cache] LEIRA_EXTRACT_FORCE=1 — ignoring manifest")
        return {}
    if not _EXTRACT_MANIFEST_PATH.exists():
        return {}
    try:
        return json.loads(_EXTRACT_MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _elog(
            f"[extract-cache] manifest unreadable ({exc}) — treating as empty; "
            f"full re-extract this run"
        )
        return {}


def _save_extract_manifest(manifest: dict) -> None:
    """Atomic tmp+rename write so a mid-write crash leaves the OLD manifest
    intact — next run treats every source as changed and re-extracts (correct
    but slow), never fails to load."""
    tmp = _EXTRACT_MANIFEST_PATH.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tmp.replace(_EXTRACT_MANIFEST_PATH)


def _load_extract_cache() -> dict[str, list[dict]]:
    """Stream the cache JSONL and bucket rows by their `file` field. Commit
    rows (file == 'commit:<sha>') are collapsed into the reserved
    '__commit_log__' bucket so `_cached_extract_commits` can find them by a
    single key. Fail-open per rule 6 — malformed lines skip w/ stderr warn."""
    if _EXTRACT_FORCE:
        _elog("[extract-cache] LEIRA_EXTRACT_FORCE=1 — ignoring cache")
        return {}
    if not _EXTRACT_CACHE_PATH.exists():
        return {}
    buckets: dict[str, list[dict]] = {}
    try:
        text = _EXTRACT_CACHE_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _elog(f"[extract-cache] cache unreadable ({exc}) — treating as empty")
        return {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            _elog(f"[extract-cache] cache line {lineno} malformed, skipping ({exc})")
            continue
        f = row.get("file", "")
        key = "__commit_log__" if isinstance(f, str) and f.startswith("commit:") else f
        buckets.setdefault(key, []).append(row)
    total = sum(len(v) for v in buckets.values())
    _elog(f"[extract-cache] loaded {total} rows across {len(buckets)} sources")
    return buckets


def _save_extract_cache(buckets: dict[str, list[dict]]) -> None:
    """Rewrite the cache JSONL WHOLE at end-of-extract-phase (open 'w'), one
    JSON object per line. Consumers must NOT assume append-only. Row order
    within a source is preserved; row order across sources follows dict
    iteration order (insertion order in CPython)."""
    with open(_EXTRACT_CACHE_PATH, "w", encoding="utf-8") as fh:
        for rows in buckets.values():
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _append_extract_cache_rows(
    buckets: dict[str, list[dict]], key: str, rows: list[dict]
) -> None:
    """Append rows to a source's in-memory bucket. The on-disk cache is
    rewritten whole at end-of-phase — this is purely a bucket-mutation
    convenience (used by _cached_extract_commits delta path)."""
    buckets.setdefault(key, []).extend(rows)


def _purge_extract_cache_by_source(
    buckets: dict[str, list[dict]], key: str
) -> None:
    """Drop a source's bucket in place — called on a stat-mismatch before
    re-extraction so stale rows don't leak into the flattened output."""
    buckets.pop(key, None)


def _cached_extract_file(
    path: Path,
    source_type: str,
    manifest: dict,
    buckets: dict[str, list[dict]],
) -> tuple[list[dict], bool]:
    """Cache-aware wrapper around extract_from_file. Stat-compares against the
    manifest; on match returns the cached bucket without touching disk; on
    mismatch (or missing entry) purges the stale bucket, re-runs
    extract_from_file, and refreshes both structures. Returns
    (rows, cache_hit) so the caller can suppress its per-file timing log
    when the helper hit."""
    key = str(path)
    stat = _file_stat_key(path)
    entry = manifest.get(key)
    if (
        stat is not None
        and isinstance(entry, dict)
        and entry.get("mtime_ns") == stat[0]
        and entry.get("size_bytes") == stat[1]
        and key in buckets
    ):
        rows = buckets[key]
        _elog(f"[extract-cache] hit {path.name} {len(rows)} rows cached")
        return rows, True
    # Miss: purge any stale bucket, re-extract, refresh manifest.
    _purge_extract_cache_by_source(buckets, key)
    rows = extract_from_file(path, source_type)
    buckets[key] = rows
    if stat is not None:
        manifest[key] = {
            "mtime_ns": stat[0],
            "size_bytes": stat[1],
            "rows": len(rows),
            "extracted_at_iso": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            ),
        }
    return rows, False


def _cached_extract_commits(
    manifest: dict,
    buckets: dict[str, list[dict]],
) -> list[dict]:
    """Cache-aware wrapper around extract_from_commits. HEAD-SHA compare:
      * head == prior_sha → return the cached '__commit_log__' bucket verbatim.
      * head != prior_sha AND prior_sha is a valid object → `git log
        <prior>..HEAD --all` delta, APPEND to bucket (existing rows retained;
        history-rewrite tolerance = old refs stay stale until
        LEIRA_EXTRACT_FORCE=1).
      * missing prior / unknown-object / git failure → full re-extract via
        extract_from_commits().
    Manifest is always refreshed with the new HEAD."""
    head = _git_head_sha()
    entry = manifest.get("__commit_log__")
    prior_sha = entry.get("head_sha") if isinstance(entry, dict) else None
    existing = buckets.get("__commit_log__", [])

    if head and prior_sha and head == prior_sha and "__commit_log__" in buckets:
        _elog(
            f"[extract-cache] hit __commit_log__ {len(existing)} rows cached "
            f"(HEAD={head[:12]})"
        )
        return existing

    delta_rows: list[dict] = []
    used_delta = False
    if head and prior_sha and prior_sha != head:
        try:
            proc = subprocess.run(
                [
                    "git", "log", f"{prior_sha}..HEAD", "--all",
                    "--format=%H%x00%s%x00%b%x1e",
                ],
                cwd=REPO, capture_output=True, text=True, encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            _elog(
                f"[extract-cache] delta git log OSError ({exc}) — "
                f"falling back to full re-extract"
            )
            proc = None
        if proc is not None and proc.returncode == 0:
            delta_rows = _parse_commit_log_stdout(proc.stdout or "")
            used_delta = True
            _elog(
                f"[extract-cache] delta __commit_log__ "
                f"{prior_sha[:12]}..{head[:12]} +{len(delta_rows)} rows"
            )
        elif proc is not None:
            # Non-zero rc typically means unknown-object (deleted branch,
            # GC'd commit) — fall through to full re-extract below.
            _elog(
                f"[extract-cache] delta git log rc={proc.returncode} "
                f"(prior {prior_sha[:12]} unknown?) — full re-extract"
            )

    if used_delta:
        _append_extract_cache_rows(buckets, "__commit_log__", delta_rows)
        combined = buckets["__commit_log__"]
    else:
        _purge_extract_cache_by_source(buckets, "__commit_log__")
        combined = extract_from_commits()
        buckets["__commit_log__"] = combined
        _elog(
            f"[extract-cache] miss __commit_log__ {len(combined)} rows "
            f"extracted (full)"
        )

    manifest["__commit_log__"] = {
        "head_sha": head or "",
        "rows": len(combined),
        "extracted_at_iso": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        ),
    }
    return combined


# ---------------------------------------------------------------------------
# Pillar 4 — structured output schema.
# ---------------------------------------------------------------------------

_JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "description": (
                f"One verdict object per input candidate, in the SAME order "
                f"as input. Up to {BATCH_SIZE} entries per call."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "is_defer": {
                        "type": "boolean",
                        "description": (
                            "True iff the surrounding text expresses a "
                            "DECISION to postpone / not-do / hold / track-"
                            "for-later actual work. False if the defer-"
                            "word is used in another sense (documentation "
                            "ABOUT deferring, variable name, unrelated "
                            "context, negation like 'don't defer', quoting "
                            "a rule, etc.)."
                        ),
                    },
                    "item": {
                        "type": "string",
                        "description": (
                            "Short normalized description of WHAT the defer "
                            "is about (<=100 chars). Empty string when "
                            "is_defer=false."
                        ),
                    },
                    "shape": {
                        "type": "string",
                        "description": (
                            "One of the canonical shapes: hard-defer / "
                            "tracked-work / waiting-op / todo-marker / "
                            "blocked-on / wip / meta-doc / false-positive."
                        ),
                    },
                },
                "required": ["is_defer", "item", "shape"],
            },
        }
    },
    "required": ["verdicts"],
}


_JUDGE_SYSTEM = (
    "You are a defer-language classifier for a software project. "
    "For each candidate, decide whether the surrounding text expresses "
    "a DECISION to postpone actual work. Return a JSON object with a "
    "`verdicts` array — one entry per candidate, in the SAME order as "
    "input. Each verdict entry MUST be an object with EXACTLY these three "
    "keys: `is_defer` (boolean), `item` (string, <=100 chars, empty when "
    "is_defer=false), `shape` (string, one of: hard-defer / tracked-work / "
    "waiting-op / todo-marker / blocked-on / wip / meta-doc / false-positive). "
    "Do NOT emit bare booleans as array elements. Do NOT rename `is_defer` "
    "to `verdict` or `defer` — the exact key names are required. Do not "
    "add markdown fences."
)


_JUDGE_EXAMPLE = (
    "Example output shape (values illustrative):\n"
    "{\n"
    "  \"verdicts\": [\n"
    "    {\"is_defer\": true,  \"item\": \"add Redis auth to prod broker\", \"shape\": \"hard-defer\"},\n"
    "    {\"is_defer\": false, \"item\": \"\", \"shape\": \"meta-doc\"},\n"
    "    {\"is_defer\": true,  \"item\": \"migrate schema v42 → v43\",      \"shape\": \"tracked-work\"}\n"
    "  ]\n"
    "}"
)


def build_task_prompt(batch: list[dict]) -> str:
    """Compose the per-batch user prompt."""
    items = [
        {"id": i, "phrase": c["phrase"], "snippet": c["snippet"]}
        for i, c in enumerate(batch)
    ]
    payload = json.dumps(items, ensure_ascii=False, indent=2)
    # Enforce Pillar 1 — cap the payload against the runtime-derived
    # byte budget. A batch that exceeds the cap is fatal (means the
    # snippets are too big); halve BATCH_SIZE or lower context_usage_ratio.
    if len(payload) > _MAX_INPUT_CHARS:
        raise OllamaCallError(
            f"batch payload {len(payload)} bytes exceeds context-derived "
            f"cap {_MAX_INPUT_CHARS} bytes — reduce BATCH_SIZE or shorten "
            f"snippets"
        )
    # Ollama `format=schema` does NOT enforce nested `items` sub-schema
    # (ollama/ollama #10091, #15540) — qwen3.6 has been observed to emit
    # `{"verdicts": [true, false, ...]}` (bare bools) or `{"verdicts":
    # [{"verdict": false}, ...]}` (wrong key names) when only the schema
    # is passed. Prompt-level defense: system prompt states the required
    # key names; the user prompt shows an explicit worked example.
    return (
        "Classify these defer-candidate snippets. Return "
        "`{\"verdicts\": [...]}` with one entry per input in order — "
        "each entry MUST be an object with keys `is_defer`, `item`, "
        "`shape` (never a bare boolean).\n\n"
        f"{_JUDGE_EXAMPLE}\n\n"
        f"Candidates:\n{payload}"
    )


def judge_batch(batch: list[dict]) -> list[dict]:
    """Send a batch of candidates to llm-host via the wrapper's `call_leira`.
    Pillar 3 — no consumer-side retry loop; the wrapper owns backoff +
    cooldown. `LeiraUnavailable` is NOT caught here (per operator directive
    3): it propagates so `main()` can flush partial verdicts and exit clean
    with a resume hint. `OllamaCallError` (per-batch transient) DOES degrade
    this batch to a no-op — that's a batch-level defect, not a wrapper
    unavailability signal.

    `think=False` — Ollama /api/chat top-level field. Thinking mode adds
    latency and per Ollama issue #14645 can interact badly with schema-json
    (silent stalls). Disabled per operator directive.
    """
    try:
        task_prompt = build_task_prompt(batch)
        result = call_leira(
            task_prompt=task_prompt,
            schema=_JUDGE_SCHEMA,
            system=_JUDGE_SYSTEM,
            think=False,
        )
        # `call_leira` returns the parsed dict when a schema is passed.
        if isinstance(result, str):
            result = json.loads(result)
        verdicts = result.get("verdicts") if isinstance(result, dict) else result
        if not isinstance(verdicts, list):
            raise OllamaCallError(f"expected list, got {type(verdicts)}")
        if len(verdicts) != len(batch):
            if len(verdicts) < len(batch):
                verdicts = verdicts + [
                    {"is_defer": False, "item": "", "shape": "false-positive"}
                ] * (len(batch) - len(verdicts))
            else:
                verdicts = verdicts[: len(batch)]
        # Per-element shape guard — the top-level `format=schema` in
        # `call_leira` enforces the top-level {"verdicts": [...]} shape but
        # Ollama has been observed to emit array elements as bare `bool`
        # (or other primitives) rather than the full verdict dict. That
        # crashes the downstream `{**c, **v}` merge with TypeError. Coerce
        # any non-dict element to the fallback dict so the merge, JSONL
        # write, and downstream aggregation all stay well-typed.
        coerced: list[dict] = []
        for v in verdicts:
            if isinstance(v, dict):
                coerced.append(v)
            elif isinstance(v, bool):
                coerced.append({
                    "is_defer": bool(v),
                    "item": "",
                    "shape": "malformed-verdict-bool",
                })
            else:
                coerced.append({
                    "is_defer": False,
                    "item": "",
                    "shape": "malformed-verdict-other",
                })
        return coerced
    except LeiraUnavailable:
        # Wrapper-level unavailability — must propagate so `main()` can
        # flush partial verdicts and exit clean with a resume hint (per
        # operator directive 3). LeiraUnavailable subclasses OllamaCallError,
        # so this re-raise MUST come first — otherwise the OllamaCallError
        # handler below silently degrades the batch and the outer resume
        # semantics collapse.
        raise
    except OllamaCallError as exc:
        _elog(f"[judge] batch failed: {exc}")
        return [
            {"is_defer": False, "item": "", "shape": "error"}
        ] * len(batch)


# ---------------------------------------------------------------------------
# Status resolution — the backlog row cross-reference
# ---------------------------------------------------------------------------

_PUNCH_ROWS: list[dict] | None = None


def _load_punch_rows() -> list[dict]:
    global _PUNCH_ROWS
    if _PUNCH_ROWS is not None:
        return _PUNCH_ROWS
    rows: list[dict] = []
    for path in [REPO / "the backlog", REPO / "the backlog archive"]:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(
                r"^\|\s*(\d+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*"
                r"([^|]+)\|\s*([^|]+)\|",
                line,
            )
            if m:
                rows.append({
                    "id": int(m.group(1)),
                    "sev": m.group(2),
                    "status": m.group(3),
                    "release": m.group(4).strip(),
                    "feature": m.group(5).strip(),
                    "item": m.group(6).strip(),
                    "source_file": str(path),
                })
    _PUNCH_ROWS = rows
    return rows


def resolve_current_status(item_desc: str) -> str:
    """Look up item in the backlog; return shipped/tracked/deferred/unknown."""
    if not item_desc:
        return "unknown"
    rows = _load_punch_rows()
    item_lo = item_desc.lower()
    for r in rows:
        if r["item"].lower()[:80] in item_lo or item_lo[:60] in r["item"].lower():
            status = r["status"].lower()
            if status in ("closed", "done", "shipped"):
                return "shipped"
            if status in ("tracked", "queued", "next", "open"):
                return "tracked"
            if status in ("deferred", "parked", "wip", "in-progress", "blocked"):
                return "deferred"
            return status
    return "unknown"


# ---------------------------------------------------------------------------
# Aggregation + main
# ---------------------------------------------------------------------------

def _write_tables(judged: list[dict], out: Path) -> None:
    """Build the two markdown tables."""
    defers = [j for j in judged if j.get("is_defer")]
    phrase_counts: collections.Counter[str] = collections.Counter()
    phrase_examples: dict[str, str] = {}
    for j in defers:
        p = j.get("phrase_canon") or j.get("phrase") or "?"
        phrase_counts[p] += 1
        phrase_examples.setdefault(p, j["snippet"])
    item_records: dict[str, dict] = {}
    for j in defers:
        item = (j.get("item") or "").strip()
        if not item or item.lower() in ("null", "none"):
            continue
        key = item.lower()[:80]
        rec = item_records.setdefault(key, {
            "item": item,
            "shapes": set(),
            "sources": set(),
            "count": 0,
        })
        rec["shapes"].add(j.get("shape") or "?")
        rec["sources"].add(j.get("source_type") or "?")
        rec["count"] += 1
    for rec in item_records.values():
        rec["status"] = resolve_current_status(rec["item"])
    lines = [
        "# Defer-sweep tables (llm-host-judged, all-history)",
        "",
        (
            f"Corpus: {len(judged)} candidates classified; "
            f"{len(defers)} identified as defer-shaped."
        ),
        "",
        "## Table A — defer phrases (frequency)",
        "",
        "| Phrase | Freq | Example context |",
        "|---|---:|---|",
    ]
    for phrase, freq in phrase_counts.most_common():
        example = phrase_examples.get(phrase, "").replace("|", "/")[:200]
        lines.append(f"| `{phrase}` | {freq} | {example} |")
    lines.extend([
        "",
        f"Total distinct phrases: {len(phrase_counts)}",
        "",
        "## Table B — deferred items + current status",
        "",
        "| Item | Shapes | Source types | Hits | Status |",
        "|---|---|---|---:|---|",
    ])
    for rec in sorted(item_records.values(), key=lambda r: -r["count"]):
        shapes = ",".join(sorted(rec["shapes"]))
        sources = ",".join(sorted(rec["sources"]))
        item_esc = rec["item"].replace("|", "/")[:200]
        lines.append(
            f"| {item_esc} | {shapes} | {sources} | {rec['count']} | "
            f"{rec['status']} |"
        )
    lines.extend([
        "",
        f"Total unique items: {len(item_records)}",
    ])
    out.write_text("\n".join(lines), encoding="utf-8")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Argparse hookup so `--help` works and the drift-guard scaffold
    test can prove the CLI surface exists. No runtime knobs — every
    dial is env-var-driven (LEIRA_SWEEP_LIMIT / LEIRA_MAX_BATCHES /
    LEIRA_EXTRACT_FORCE / OLLAMA_HOST / OLLAMA_MODEL / OLLAMA_URL /
    OLLAMA_TIMEOUT_S) so cron / task-scheduler invocations stay
    argument-free."""
    ap = argparse.ArgumentParser(
        prog="leira_defer_sweep",
        description=(
            "llm-host-offloaded defer-language sweep over session JSONL, "
            "memory drawers, audit reports, commit log, and the backlog. "
            "Writes verdicts + tables to defer_sweep/ at repo root. "
            "All runtime dials come from environment variables — see "
            "the module docstring for the full list."
        ),
        epilog=(
            "Environment dials: LEIRA_SWEEP_LIMIT (truncate candidate "
            "stream); LEIRA_MAX_BATCHES (cap batches per session, 0 = "
            "unbounded); LEIRA_EXTRACT_FORCE=1 (bypass extract cache/"
            "manifest); OLLAMA_HOST / OLLAMA_MODEL / OLLAMA_URL / "
            "OLLAMA_TIMEOUT_S (per-call llm-host wrapper overrides)."
        ),
    )
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    _parse_args(argv)
    verdicts_path = _VERDICTS_PATH
    tables_path = _DATA_DIR / "tables.md"

    # (1) PRE-LOOP cooldown gate — short-circuit BEFORE the extract phase
    # (minutes of local file I/O + git log) when the wrapper's persistent
    # cooldown file is present. The judge phase would just crash immediately;
    # exit clean with a resume hint pointing at the cooldown-file path.
    #
    # Batch-2 DA NTH#3 fold (2026-07-17): the legacy `leira_in_cooldown()`
    # is checked FIRST for backward-compat (pre-Drive-D tests monkey-patch
    # this name); THEN `leira_in_cooldown_for(active_host)` covers the
    # post-Drive-D per-host cooldowns. Either flag short-circuits.
    _active_host = active_host_name()
    _legacy_in_cd, _legacy_remaining = leira_in_cooldown()
    _per_host_in_cd, _per_host_remaining = leira_in_cooldown_for(_active_host)
    if _legacy_in_cd or _per_host_in_cd:
        in_cd = True
        remaining = max(_legacy_remaining, _per_host_remaining)
        _per_host_path = leira_cooldown_path_for(_active_host)
        _elog(
            f"[main] llm-host host={_active_host} in cooldown for {remaining:.0f}s "
            f"more — clean exit. rm {_per_host_path} (per-host) or "
            f"{LEIRA_COOLDOWN_PATH} (legacy global) to clear, then re-run."
        )
        return 0

    start = time.time()
    _elog(
        f"[main] extract phase — {time.strftime('%H:%M:%S')} — "
        f"batch_size={BATCH_SIZE} max_input_chars={_MAX_INPUT_CHARS}"
    )

    # Extract-cache: load manifest + prior-run buckets. LEIRA_EXTRACT_FORCE=1
    # short-circuits both to empty inside the loaders. Cache/manifest live
    # UPSTREAM of dedupe → resume-skip → LEIRA_SWEEP_LIMIT → judge; downstream
    # contract is byte-identical.
    manifest = _load_extract_manifest()
    cache_by_source = _load_extract_cache()

    jsonl_files = sorted(SESSION_DIR.glob("*.jsonl"))
    for i, f in enumerate(jsonl_files, 1):
        t0 = time.time()
        rows, hit = _cached_extract_file(f, "session", manifest, cache_by_source)
        if not hit:
            _elog(
                f"[extract] {i}/{len(jsonl_files)} JSONL {f.name} "
                f"(+{len(rows)} hits, {time.time() - t0:.1f}s)"
            )

    memory_dir = SESSION_DIR / "memory"
    if memory_dir.exists():
        md_files = sorted(memory_dir.glob("*.md"))
        for f in md_files:
            _cached_extract_file(f, "memory", manifest, cache_by_source)
        _elog(f"[extract] memory drawers: {len(md_files)} scanned")

    audit_dir = REPO / "audit-reports"
    if audit_dir.exists():
        n = 0
        for f in sorted(audit_dir.rglob("*")):
            if f.is_file() and f.suffix in {".md", ".json", ".txt"}:
                _cached_extract_file(f, "audit", manifest, cache_by_source)
                n += 1
        _elog(f"[extract] audit-reports: {n} files scanned")

    _elog("[extract] commit log scanning...")
    _cached_extract_commits(manifest, cache_by_source)
    _elog("[extract] commit log done")

    # the backlog rows are re-derived every run (cheap; never cached) — the
    # the backlog files are small and re-parse in milliseconds, and their
    # status column mutates on almost every commit so caching would be a
    # near-permanent miss anyway.
    punch_rows: list[dict] = []
    for row in _load_punch_rows():
        punch_rows.append({
            "phrase": row["status"],
            "phrase_canon": row["status"].lower(),
            "snippet": (
                f"the backlog row {row['id']} [{row['sev']}/{row['status']}/"
                f"{row['release']}]: {row['item'][:200]}"
            ),
            "file": row["source_file"],
            "offset": 0,
            "source_type": "the backlog",
        })

    # Persist cache + manifest at end-of-extract-phase (whole rewrite for the
    # cache; atomic tmp+rename for the manifest). A crash mid-write loses at
    # most this phase's fresh work; next run re-extracts (idempotent — the
    # extractor is a pure function of the file bytes).
    _save_extract_cache(cache_by_source)
    _save_extract_manifest(manifest)

    # Flatten buckets + append re-derived the backlog rows. Bucket iteration
    # order preserves insertion order (CPython dict) but downstream dedup is
    # order-tolerant so this doesn't matter for correctness.
    all_candidates: list[dict] = [
        row for bucket in cache_by_source.values() for row in bucket
    ] + punch_rows

    _elog(
        f"[main] extracted {len(all_candidates)} raw candidates — "
        f"{time.strftime('%H:%M:%S')}"
    )

    deduped = dedupe_candidates(all_candidates)
    _elog(f"[main] deduped to {len(deduped)} unique candidates")

    # (2) Resume-skip: filter out anything already judged in a prior session.
    # The verdicts JSONL is the durable SSOT; keys are stable across runs
    # (see `_verdict_key` docstring for the file+offset stability rule).
    prior_keys, _ = _load_prior_verdicts(verdicts_path)
    if prior_keys:
        before = len(deduped)
        deduped = [c for c in deduped if _verdict_key(c) not in prior_keys]
        skipped = before - len(deduped)
        if skipped:
            _elog(
                f"[main] resuming — {len(prior_keys)} verdicts already on disk, "
                f"skipping {skipped} already-judged keys"
            )
        if not deduped:
            _elog(
                f"[main] all {before} candidates already judged — nothing to do; "
                f"regenerating tables from {verdicts_path.name}"
            )

    # (3) Smoke-test dial: LEIRA_SWEEP_LIMIT truncates the candidate stream
    # after dedupe + resume-skip. 0 = unbounded (process all).
    if _SWEEP_LIMIT > 0 and len(deduped) > _SWEEP_LIMIT:
        _elog(f"[main] limit={_SWEEP_LIMIT} (LEIRA_SWEEP_LIMIT) — truncating from {len(deduped)}")
        deduped = deduped[:_SWEEP_LIMIT]

    _elog(f"[main] judge phase — {time.strftime('%H:%M:%S')} — {len(deduped)} candidates to judge")

    # (4) Verdicts JSONL opened in APPEND mode so streamed rows accumulate
    # across sessions — replaces the prior 'w' checkpoint which truncated
    # every rerun. Each row completes before the next call_leira starts so
    # Ctrl-C / cooldown / pause / max-batches / LeiraUnavailable all leave
    # the file well-formed.
    batches_run = 0
    stop_reason: str | None = None
    try:
        with open(verdicts_path, "a", encoding="utf-8") as verdicts_fh:
            for i in range(0, len(deduped), BATCH_SIZE):
                # (6) Pause dial: filesystem semaphore polled per batch. With
                # think=False + BATCH_SIZE=25, typical llm-host latency is well
                # under 30s per batch, meeting the operator's response spec.
                if _pause_requested(_PAUSE_PATH):
                    stop_reason = (
                        f"pause file detected — clean-exit at batch boundary; "
                        f"rm {_PAUSE_PATH} to resume"
                    )
                    _elog(f"[main] {stop_reason}")
                    break

                batch = deduped[i : i + BATCH_SIZE]
                verdicts = judge_batch(batch)
                for c, v in zip(batch, verdicts):
                    merged = {**c, **v}
                    verdicts_fh.write(json.dumps(merged, ensure_ascii=False) + "\n")
                verdicts_fh.flush()
                batches_run += 1
                done = i + len(batch)
                elapsed = time.time() - start
                eta = ((len(deduped) - done) / max(1, done)) * elapsed
                _elog(
                    f"[judge] {done}/{len(deduped)} — "
                    f"eta {int(eta // 60)}m — "
                    f"batches_run={batches_run} — "
                    f"{time.strftime('%H:%M:%S')}"
                )

                # (7) Session-cap dial: LEIRA_MAX_BATCHES caps batches per
                # session. 0 = unbounded (run to completion).
                if _MAX_BATCHES > 0 and batches_run >= _MAX_BATCHES:
                    stop_reason = (
                        f"LEIRA_MAX_BATCHES={_MAX_BATCHES} reached — clean exit; "
                        f"re-run to resume from {verdicts_path.name}"
                    )
                    _elog(f"[main] {stop_reason}")
                    break
    except LeiraUnavailable as exc:
        # (5) LeiraUnavailable propagates from judge_batch — flush already
        # happened per-batch; log a resume hint and exit clean. The verdicts
        # JSONL is well-formed; the next run's prior_keys set picks up from
        # here.
        stop_reason = (
            f"llm-host went unavailable ({exc}) — flushed {batches_run} batches "
            f"before stop. Re-run to resume from {verdicts_path.name}"
        )
        _elog(f"[main] {stop_reason}")

    # (8) Tables are ALWAYS rebuilt from the FULL verdicts file so a paused-
    # then-resumed sweep yields the same tables as a single continuous run,
    # and each partial-completion run also gets fresh cumulative tables.
    _elog(f"[main] aggregate phase — {time.strftime('%H:%M:%S')}")
    _, judged = _load_prior_verdicts(verdicts_path)
    _write_tables(judged, tables_path)
    _elog(
        f"[main] done — {len(judged)} verdicts on disk — tables at {tables_path}"
        + (f" — stopped: {stop_reason}" if stop_reason else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
