#!/usr/bin/env python3
"""leira_census_prepass.py — Consumer #1 of the llm-host offload stack.

Purpose: replace Phase-1 STEP 1 (enumeration) of the divergence census — currently a
the AI assistant subagent doing broad grep + AST walks + candidate site listing across ~200 files —
with a llm-host pre-pass. the AI assistant keeps STEPS 2-6 (variant clustering, canonical/SSOT judgment,
pin design, severity). This is the biggest run19 token sink (~3.4M tokens / 36 agents).

Pipeline per class:
  1. Locally grep src/email_triage for the class's signature_hint keywords (mechanical,
     no LLM). Cap total raw matches to keep the llm-host context window manageable.
  2. Feed the class description + raw grep output to llm-host (qwen3.6:35b) with a strict
     schema: return a filtered candidate site list, one entry per genuine site with
     file:line + a one-line note on how the site handles the contract.
  3. Emit the candidate list as JSON. llm-host output = PROBE, never verdict. the AI assistant reads
     it in Phase-1 Step-2 (variant clustering).

Contract with the census workflow (wire-in is a SEPARATE next-window change): the JSON
output is meant to be dropped into the census subagent's prompt as "pre-scanned candidate
sites; verify + widen with your own AST walk before clustering".
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import call_leira, OllamaCallError, get_consumer_config, DEFAULT_CONTEXT_TOKENS

_cfg = get_consumer_config("census_prepass")
# Derive MAX_RAW_HITS from the model's ACTUAL context (learned at import time) so a
# bigger-context model automatically gets a bigger cap. Heuristic: each hit ~= 25 tokens
# (100 chars); reserve `usage_ratio` fraction of context for hit lines (leave the rest
# for the static prompt + llm-host's response). Config can override with an absolute cap
# via `max_raw_hits_override` (rarely needed).
_hit_tokens = 25
_usage_ratio = float(_cfg.get("context_usage_ratio", 0.4))
MAX_RAW_HITS = int(_cfg.get("max_raw_hits_override") or (DEFAULT_CONTEXT_TOKENS * _usage_ratio / _hit_tokens))
CLUSTER_WINDOW = int(_cfg.get("cluster_window", 5))     # within-file line-cluster dedup window
_IMPORT_RE = re.compile(r"^\s*(from\s+\S+\s+import|import\s+\S+)")
_COMMENT_RE = re.compile(r"^\s*#")
_BLANK_RE = re.compile(r"^\s*$")

CANDIDATE_SCHEMA = {
    "type": "object",
    "required": ["signature_searched", "candidate_sites", "notes", "enumeration_caveats"],
    "properties": {
        "signature_searched": {
            "type": "string",
            "description": "The exact grep/keyword patterns you used to select the shown raw matches (echo them so completeness is auditable).",
        },
        "candidate_sites": {
            "type": "array",
            "description": "Filtered list of sites that genuinely implement the operation class. One entry per site.",
            "items": {
                "type": "object",
                "required": ["file", "line", "note"],
                "properties": {
                    "file": {"type": "string", "description": "Path relative to repo root, e.g. src/email_triage/web/routers/ui/accounts.py"},
                    "line": {"type": "integer"},
                    "note": {"type": "string", "description": "One line: what this site does + which variant / how it handles the contract"},
                },
            },
        },
        "notes": {
            "type": "string",
            "description": "One paragraph: what patterns of sites you kept vs discarded and why. Do NOT do variant clustering or severity here.",
        },
        "enumeration_caveats": {
            "type": "string",
            "description": "Honest gaps: aliases you couldn't resolve, dynamic-dispatch paths, or file types you didn't scan. Empty string if none.",
        },
    },
}


def _grep_signature(keywords: list[str], repo_root: Path) -> list[str]:
    """Ripgrep the source tree for the keywords. Returns file:line: content lines."""
    src = repo_root / "src" / "email_triage"
    if not src.is_dir():
        raise SystemExit(f"src dir not found: {src}")
    # Bash tool's rg is available under Git-Bash; call ripgrep via shell to keep
    # a single dependency surface. Fall back to python-grep on failure.
    pattern = "|".join(re.escape(k) for k in keywords)
    try:
        proc = subprocess.run(
            ["rg", "-n", "--no-heading", "-e", pattern, "--type", "py", str(src)],
            capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace",
        )
        if proc.returncode not in (0, 1):  # 1 = no matches, still valid
            raise RuntimeError(f"rg exit {proc.returncode}: {proc.stderr[:200]}")
        return proc.stdout.splitlines()
    except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired):
        # Fallback: python walk
        rx = re.compile(pattern)
        hits = []
        for p in src.rglob("*.py"):
            try:
                for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{p}:{i}:{line}")
            except OSError:
                continue
        return hits


def _dedupe_and_filter(raw: list[str]) -> tuple[list[str], dict]:
    """Reduce the raw ripgrep hits into a de-noised, per-file line-clustered representative list.

    Cap-loss fix (2026-07-01): the original 200-cap dropped 54-71% of raw hits pre-llm-host; the raw
    was inflated by (a) imports, (b) comments/docstrings, (c) multiple adjacent hits in the same
    file (a def + its call + the module's re-export land on 3 lines that all match). This function
    drops imports/comments/blank + collapses within-file consecutive hits into one representative,
    then the caller caps the result. Returns (filtered, stats)."""
    dropped_import = dropped_comment = 0
    per_file: dict[str, list[tuple[int, str]]] = {}
    for line in raw:
        # rg -n --no-heading yields "path:line:content" (Windows paths may contain ':' after drive
        # letter — rsplit twice handles that safely).
        parts = line.rsplit(":", 2)
        if len(parts) != 3:
            continue
        path, ln, content = parts
        try:
            ln_i = int(ln)
        except ValueError:
            continue
        if _IMPORT_RE.match(content):
            dropped_import += 1
            continue
        if _COMMENT_RE.match(content) or _BLANK_RE.match(content):
            dropped_comment += 1
            continue
        per_file.setdefault(path, []).append((ln_i, content))

    filtered: list[str] = []
    dropped_cluster = 0
    for path, hits in per_file.items():
        hits.sort()
        last_kept_line = -CLUSTER_WINDOW - 1
        for ln_i, content in hits:
            if ln_i - last_kept_line <= CLUSTER_WINDOW:
                dropped_cluster += 1
                continue
            filtered.append(f"{path}:{ln_i}:{content}")
            last_kept_line = ln_i

    stats = {
        "raw_total": len(raw),
        "dropped_imports": dropped_import,
        "dropped_comments": dropped_comment,
        "dropped_cluster": dropped_cluster,
        "filtered_total": len(filtered),
        "unique_files": len(per_file),
    }
    return filtered, stats


def _extract_keywords(signature_hint: str) -> list[str]:
    """Pull grep-worthy tokens from a natural-language signature_hint. Identifiers are
    the load-bearing signal — snake_case names, dotted paths, module.function refs."""
    # Match: snake_case idents (>=4 chars), dotted access, decorator refs
    toks = set(re.findall(r"[A-Za-z_][A-Za-z_0-9]{3,}(?:\.[A-Za-z_][A-Za-z_0-9]+)*", signature_hint))
    # Drop generic English filler
    stop = {"through", "canonical", "helper", "into", "record", "with", "which", "operation",
            "class", "insert", "inserts", "direct", "OR", "AND", "via", "await", "seam",
            "table", "tables", "path", "paths", "and", "the", "for", "each", "over",
            "session", "context", "value", "values", "return", "handler", "action", "file",
            "line", "boundary", "config", "settings", "content", "encoded", "decoded"}
    return sorted(k for k in toks if k not in stop and not k[0].isdigit())[:12]


def run_prepass(class_key: str, class_title: str, class_operation: str,
                signature_hint: str, repo_root: Path) -> dict:
    keywords = _extract_keywords(signature_hint)
    raw = _grep_signature(keywords, repo_root)
    filtered, filter_stats = _dedupe_and_filter(raw)
    capped = filtered[:MAX_RAW_HITS]

    # Trim file paths to repo-relative for smaller prompt.
    def _rel(line: str) -> str:
        # Windows and posix separators both appear; strip repo root
        s = str(repo_root).replace("\\", "/")
        return line.replace(str(repo_root), "").replace(s, "").lstrip("/\\")

    raw_blob = "\n".join(_rel(l) for l in capped)

    prompt = (
        f"You are pre-scanning the email-triage codebase (HIPAA-class FastAPI/Jinja/SQLite) "
        f"for one operation-class in a divergence census. You are the WIDE pass; a the AI assistant "
        f"agent will do variant-clustering + SSOT judgment after you. Do NOT cluster, do NOT "
        f"design pins, do NOT rate severity — just filter raw grep hits into a candidate site list.\n\n"
        f"OPERATION CLASS: {class_title}\n"
        f"The operation: {class_operation}\n"
        f"Signature hint (what to keep): {signature_hint}\n\n"
        f"I ran a broad ripgrep for these keywords: {keywords}\n"
        f"Raw hits (up to {MAX_RAW_HITS}, format `path:line:content`):\n"
        f"----\n{raw_blob}\n----\n\n"
        f"Return JSON per the schema. For candidate_sites: keep only lines that genuinely "
        f"implement the operation-class (definitions AND real use-sites); DISCARD test files "
        f"(tests/), comments-only hits, string literals mentioning the name, and unrelated "
        f"same-name identifiers. For each kept site write ONE short 'note' line explaining "
        f"what the site does — not judgment, not severity, just the mechanism. Be honest in "
        f"'enumeration_caveats' about aliases / dynamic-dispatch / helper-hop paths you can't "
        f"see from the raw hits alone (the AI assistant will do the AST walk for those)."
    )

    result = call_leira(prompt, schema=CANDIDATE_SCHEMA)

    # Deterministic keyword-anchor pass: guarantee every keyword with >=1 filtered hit gets AT
    # LEAST ONE representative site. llm-host's semantic filter sometimes picks other sites in the
    # same file, hiding a load-bearing keyword. This closes that gap without asking llm-host nicely.
    # Insert anchors only for keywords not already covered.
    flagged_files_by_line = {(s["file"].replace("\\", "/"), s["line"]) for s in result.get("candidate_sites", [])}
    def _line_has_kw(entry: str, kw: str) -> bool:
        parts = entry.rsplit(":", 2)
        return len(parts) == 3 and kw in parts[2]

    kw_anchors_added = 0
    for kw in keywords:
        # Already covered? Check if any flagged site's actual source line at file:line contains kw.
        covered = False
        for s in result.get("candidate_sites", []):
            f = _normalize_path(s["file"])
            if not f.is_file():
                continue
            try:
                src_line = f.read_text(encoding="utf-8", errors="replace").splitlines()[s["line"] - 1]
            except (OSError, IndexError):
                continue
            if kw in src_line:
                covered = True
                break
        if covered:
            continue
        # Not covered. Insert the FIRST filtered entry that contains this keyword as an anchor.
        for entry in filtered:
            if _line_has_kw(entry, kw):
                parts = entry.rsplit(":", 2)
                path, ln = parts[0].replace("\\", "/"), int(parts[1])
                # Normalize absolute -> repo-relative "src/email_triage/..." form so downstream
                # consumers (verify harness, census subagent) can find the file.
                if "src/email_triage/" in path:
                    path = "src/email_triage/" + path.split("src/email_triage/", 1)[1]
                if (path, ln) in flagged_files_by_line:
                    continue
                result.setdefault("candidate_sites", []).append({
                    "file": path, "line": ln,
                    "note": f"keyword-anchor: {kw} (deterministic post-llm-host; the AI assistant still AST-widens)",
                })
                flagged_files_by_line.add((path, ln))
                kw_anchors_added += 1
                break

    def _normalize_path_local(p: str) -> Path:
        p = p.replace("\\", "/").lstrip("/")
        if not p.startswith("src/email_triage/"):
            p = "src/email_triage/" + p.lstrip("./")
        return repo_root / p

    # Attach mechanical metadata
    result["_prepass_meta"] = {
        "class_key": class_key,
        "raw_hits": len(raw),
        "filter_stats": filter_stats,
        "capped_to": len(capped),
        "keywords": keywords,
        "kw_anchors_added": kw_anchors_added,
    }
    return result


def _normalize_path(p) -> Path:
    """Resolve a llm-host-reported path to the repo file. Handles bare paths and
    'src/email_triage/'-prefixed ones."""
    s = str(p).replace("\\", "/").lstrip("./")
    if not s.startswith("src/email_triage/"):
        s = "src/email_triage/" + s.lstrip("/")
    # Repo root discovered from cwd (the CLI passes it into run_prepass — reuse via Path.cwd fallback)
    return Path.cwd() / s


def _decorator_scan(repo_root: Path, decorator_names: tuple[str, ...]) -> list[str]:
    """Improvement #2 (2026-07-02): decorator-aware wrapper. AST-walk src/ for
    `@<name>` decorator uses so decorator-SSOT sites (invisible to a keyword-
    only llm-host semantic filter) are unioned into the candidate site list.
    Format: `path:line:content` matching the existing candidate_sites shape."""
    import ast as _ast
    hits: list[str] = []
    src_root = repo_root / "src" / "email_triage"
    if not src_root.is_dir():
        return hits
    for p in src_root.rglob("*.py"):
        if "__pycache__" in str(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            tree = _ast.parse(text)
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in _ast.walk(tree):
            if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                name = None
                if isinstance(dec, _ast.Name):
                    name = dec.id
                elif isinstance(dec, _ast.Attribute):
                    name = dec.attr
                elif isinstance(dec, _ast.Call):
                    f = dec.func
                    name = (f.id if isinstance(f, _ast.Name) else
                            f.attr if isinstance(f, _ast.Attribute) else None)
                if name and name in decorator_names:
                    rel = str(p.relative_to(repo_root)).replace("\\", "/")
                    hits.append(f"{rel}:{dec.lineno}:@{name} on {node.name}(...)")
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--class-key", required=True)
    ap.add_argument("--class-title", required=True)
    ap.add_argument("--class-operation", required=True)
    ap.add_argument("--signature-hint", required=True)
    ap.add_argument("--repo-root", default=".", type=Path)
    # Improvement #1 (2026-07-02): class-specific structural hint (looks up
    # `leira_class_hints.REGISTRY[<name>]` and folds it into the prompt).
    ap.add_argument("--class-hint", default=None,
                    help="canonical class name in leira_class_hints.REGISTRY (adds "
                         "probe-shapes + decorator SSOTs to the pre-pass)")
    # Improvement #4: response cache keyed on (consumer, class, head-sha).
    ap.add_argument("--head-sha", default=None,
                    help="git HEAD sha; combined with --use-cache to hit "
                         "~/.llm-host-cache and skip fresh llm-host calls on unchanged HEADs")
    ap.add_argument("--use-cache", action="store_true")
    args = ap.parse_args()

    # Improvement #4 cache lookup — fast-path a cached response.
    if args.use_cache and args.head_sha:
        try:
            from leira_cache import cache_get  # type: ignore
            cached = cache_get("census_prepass", args.class_key, args.head_sha)
            if cached is not None:
                cached["_from_cache"] = True
                print(json.dumps(cached, ensure_ascii=False, indent=2))
                return
        except ImportError:
            pass

    try:
        out = run_prepass(args.class_key, args.class_title, args.class_operation,
                          args.signature_hint, args.repo_root.resolve())
    except OllamaCallError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Improvement #1: fold in the class hint's probe shapes + prompt note as
    # metadata for the caller (the AI assistant reads them BEFORE the AST walk).
    if args.class_hint:
        try:
            from leira_class_hints import get_class_hint  # type: ignore
            hint = get_class_hint(args.class_hint)
            if hint is not None:
                out["class_hint"] = {
                    "probe_shapes": list(hint.probe_shapes),
                    "prompt_note": hint.prompt_note,
                    "decorator_ssots": list(hint.decorator_ssots),
                }
                # Improvement #2: decorator-aware pre-scan.
                if hint.decorator_ssots:
                    dec_hits = _decorator_scan(
                        args.repo_root.resolve(), hint.decorator_ssots,
                    )
                    if dec_hits:
                        out["decorator_scan_sites"] = dec_hits[:60]
        except ImportError:
            pass

    # Improvement #4 cache write — store the fresh response for the next run.
    if args.use_cache and args.head_sha:
        try:
            from leira_cache import cache_put  # type: ignore
            cache_put("census_prepass", args.class_key, args.head_sha, out)
        except ImportError:
            pass

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
