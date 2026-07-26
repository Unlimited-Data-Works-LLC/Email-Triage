#!/usr/bin/env python3
"""leira_hardcode_scanner.py — Consumer  of the llm-host offload stack (2026-07-02).

Scope-aware hardcode-literal scanner. Addresses the ~90% false-positive rate
of the 2026-07-02 hardcode audit (see `audit-reports/2026-07-02-hardcode-
audit-triage-note.md`): the prior heuristic classifier couldn't distinguish
a dataclass field default from an operational literal at a call site.

This consumer walks the AST with **scope classification** — every candidate
literal is tagged with:
- `is_dataclass_field_default` — the literal sits at a class-body assignment
  or `field(default_factory=lambda: ...)` inside a `@dataclass`-annotated
  class. These are CONFIG SSOT defaults, not hardcodes.
- `is_function_kwarg_default` — the literal sits at a `def f(x: T = "...")`
  position. Callers override; not a hardcode.
- `is_fallback_literal` — the literal sits at `x or "default"` /
  `x if x else "default"` where the LHS is a config-driven name.
- `is_operational` — the literal is at a call site, comparison, or
  assignment inside operational code without config-lookup indirection.

Only `is_operational` literals get flagged as candidates.

Then llm-host classifies each operational hit into:
- `real_hardcode` — a value that varies by deploy but isn't config-tunable.
- `well_known_constant` — a protocol/algorithm/spec-fixed value (HTTP
  status, `/run/secrets`, MS Graph endpoint, LE ACME URL).
- `internal_sentinel` — 0/1/-1/None-adjacent values.

Usage:
  python scripts/leira_hardcode_scanner.py --src src/email_triage \
      --output audit-reports/YYYY-MM-DD-hardcode-scoped.json

Prints a JSON with per-site verdicts.
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from leira_prepass import OllamaCallError, call_leira, context_bytes, get_consumer_config

_cfg = get_consumer_config("hardcode_scanner")
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.40)))
MAX_HITS_PER_BATCH = int(_cfg.get("max_hits_per_batch", 20))


# ---------------------------------------------------------------------------
# Scope-aware AST walker
# ---------------------------------------------------------------------------

def _get_parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _is_dataclass_decorated(cls: ast.ClassDef) -> bool:
    for dec in cls.decorator_list:
        name = None
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        elif isinstance(dec, ast.Call):
            f = dec.func
            name = (f.id if isinstance(f, ast.Name) else
                    f.attr if isinstance(f, ast.Attribute) else None)
        if name == "dataclass":
            return True
    return False


def _in_dataclass_field_default(node: ast.Constant, parents: dict) -> bool:
    """True if `node` sits at the value position of a class-body AnnAssign or
    Assign inside a @dataclass class, OR inside a `field(default_factory=
    lambda: [...])` call."""
    cur = parents.get(node)
    steps = 0
    while cur is not None and steps < 12:
        # AnnAssign / Assign whose target is inside a ClassDef with @dataclass
        if isinstance(cur, (ast.AnnAssign, ast.Assign)):
            grand = parents.get(cur)
            if isinstance(grand, ast.ClassDef) and _is_dataclass_decorated(grand):
                return True
        # Inside a field(default_factory=lambda: ...) call
        if isinstance(cur, ast.Call):
            f = cur.func
            name = (f.id if isinstance(f, ast.Name) else
                    f.attr if isinstance(f, ast.Attribute) else None)
            if name == "field":
                return True
        # Inside a lambda that is the default_factory arg of field(...)
        if isinstance(cur, ast.Lambda):
            outer = parents.get(cur)
            if isinstance(outer, ast.keyword) and outer.arg == "default_factory":
                return True
        cur = parents.get(cur)
        steps += 1
    return False


def _in_function_kwarg_default(node: ast.Constant, parents: dict) -> bool:
    """True if `node` sits at the default-value position of a function/method
    keyword argument (`def f(x: T = "literal")`)."""
    cur = parents.get(node)
    steps = 0
    while cur is not None and steps < 6:
        if isinstance(cur, ast.arguments):
            # Are we in `defaults` or `kw_defaults`?
            if node in cur.defaults or node in cur.kw_defaults:
                return True
            return False
        cur = parents.get(cur)
        steps += 1
    return False


_FALLBACK_KWARGS = {"default", "fallback", "if_missing", "or_"}


def _in_module_level_const(node: ast.Constant, parents: dict) -> bool:
    """True if `node` sits at the value position of a module-level assignment
    whose target is an ALL_CAPS name (possibly leading-underscore). These are
    the Python config-SSOT pattern for module-level defaults —
    `_MANUAL_REDIRECT_URI = "..."`, `DEFAULT_OLLAMA_BASE_URL = "..."`."""
    cur = parents.get(node)
    steps = 0
    while cur is not None and steps < 6:
        if isinstance(cur, (ast.Assign, ast.AnnAssign)):
            grand = parents.get(cur)
            if isinstance(grand, ast.Module):
                # Extract targets
                targets = cur.targets if isinstance(cur, ast.Assign) else [cur.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        n = t.id.lstrip("_")
                        if n and n.isupper() and any(c.isalpha() for c in n):
                            return True
            return False
        cur = parents.get(cur)
        steps += 1
    return False


def _in_fallback_literal(node: ast.Constant, parents: dict) -> bool:
    """True if `node` sits at a fallback position: BoolOp(`or`), IfExp orelse,
    or a `keyword(arg="default"|"fallback")` on a call. Also walks up through
    an enclosing List/Tuple so `foo(default=["8.8.8.8"])` is caught."""
    cur = parents.get(node)
    steps = 0
    while cur is not None and steps < 4:
        if isinstance(cur, ast.BoolOp) and isinstance(cur.op, ast.Or):
            return True
        if isinstance(cur, ast.IfExp) and cur.orelse is node:
            return True
        if isinstance(cur, ast.keyword) and cur.arg in _FALLBACK_KWARGS:
            return True
        if isinstance(cur, (ast.List, ast.Tuple, ast.Set)):
            cur = parents.get(cur)
            steps += 1
            continue
        break
    return False


# ---------------------------------------------------------------------------
# Candidate collection
# ---------------------------------------------------------------------------

import re

# TIGHT candidate filters — an int/float/string qualifies as a hardcode
# candidate ONLY if it matches one of these patterns (else we get 23k FPs).
_URL_RE = re.compile(r"^https?://[^ \n]{3,}")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
_HOSTPORT_RE = re.compile(
    r"^(?=.*[a-zA-Z])[a-zA-Z0-9.-]+:\d{2,5}$"
)  # Require ≥1 letter in host portion — excludes HH:MM time strings.

# Well-known constants — protocol/standard/RFC-fixed values that vary per
# NOTHING. Pre-filtered so llm-host doesn't waste tokens on them.
_WELL_KNOWN_STRINGS = {
    # Loopback / any-addr
    "127.0.0.1", "::1", "0.0.0.0", "::",
    # RFC1918 / CGN / link-local / multicast / doc / test-net CIDRs
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    "0.0.0.0/8", "100.64.0.0/10", "240.0.0.0/4",
    "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    "255.255.255.255/32", "192.88.99.0/24",
    "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
    # Well-known public DNS resolvers (operator-overrideable via config;
    # scan_scope filter catches the config-default cases; this catches
    # inline literals used as fallbacks)
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    # Google / Microsoft / GitHub well-known endpoints (protocol-fixed)
    "https://gmail.googleapis.com/gmail/v1",
    "https://oauth2.googleapis.com/token",
    "https://accounts.google.com/o/oauth2/v2/auth",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.metadata",
    "https://graph.microsoft.com/v1.0",
    "https://graph.microsoft.com/.default",
    "https://login.microsoftonline.com",
    "https://login.microsoftonline.com/common",
    "https://login.microsoftonline.com/organizations",
}

_WELL_KNOWN_PORTS = {
    # (int, string form both possible)
    22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
}
_ABS_PATH_RE = re.compile(
    r"^/(?:etc|var|usr|opt|run|home|root|mnt|srv|boot|lib)"
    r"(?:/[a-zA-Z0-9_.-]+){1,}$"
)  # Restricted to known FS roots — excludes URL-path fragments like `/api/foo`.


def _is_candidate_string(val: str) -> str | None:
    """Return a category tag or None if `val` doesn't qualify as a candidate.
    Well-known constants (loopback, RFC1918, Google/Microsoft endpoints) are
    pre-filtered so they don't reach llm-host."""
    if val in _WELL_KNOWN_STRINGS:
        return None
    if _URL_RE.match(val):
        return "url"
    if _IPV4_RE.match(val):
        return "ipv4"
    if _HOSTPORT_RE.match(val):
        return "hostport"
    if _ABS_PATH_RE.match(val):
        return "abs_path"
    return None


def _numeric_call_context(node: ast.Constant, parents: dict) -> str | None:
    """Return a category tag if `node` sits at a keyword-arg or positional
    slot of a call whose function name suggests timeout / limit / threshold /
    port / retry / interval semantics."""
    _KW_HINT = {
        "timeout": "timeout", "timeout_s": "timeout", "timeout_sec": "timeout",
        "timeout_secs": "timeout", "timeout_seconds": "timeout",
        "port": "port", "listen_port": "port", "bind_port": "port",
        "max_retries": "retry", "retry_count": "retry", "retries": "retry",
        "interval": "interval", "interval_s": "interval",
        "poll_interval": "interval", "backoff": "backoff",
        "limit": "limit", "max_items": "limit", "max_size": "limit",
        "threshold": "threshold",
    }
    par = parents.get(node)
    if isinstance(par, ast.keyword) and par.arg in _KW_HINT:
        # Well-known port pre-filter
        if _KW_HINT[par.arg] == "port" and isinstance(node.value, int) and node.value in _WELL_KNOWN_PORTS:
            return None
        return _KW_HINT[par.arg]
    return None


def collect_candidates(src: pathlib.Path) -> list[dict]:
    """Walk `src` and return one dict per QUALIFYING literal (URLs, IPs,
    host:port, abs-paths for strings; numeric literals only when they sit at
    a hint kwarg like `timeout=`/`port=`)."""
    out: list[dict] = []
    for p in src.rglob("*.py"):
        if "__pycache__" in str(p):
            continue
        try:
            source = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        parents = _get_parents(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue
            val = node.value
            if isinstance(val, bool):
                continue
            category = None
            literal_kind = None
            if isinstance(val, str):
                if not (4 <= len(val) <= 200):
                    continue
                category = _is_candidate_string(val)
                if not category:
                    continue
                literal_kind = "str"
            elif isinstance(val, (int, float)):
                if val in (0, 1, -1) or (isinstance(val, float) and val in (0.0, 1.0, -1.0)):
                    continue
                category = _numeric_call_context(node, parents)
                if not category:
                    continue
                literal_kind = "int" if isinstance(val, int) else "float"
            else:
                continue
            # Skip docstring position
            par = parents.get(node)
            if isinstance(par, ast.Expr):
                grand = parents.get(par)
                if isinstance(grand, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    if grand.body and grand.body[0] is par:
                        continue
            in_df = _in_dataclass_field_default(node, parents)
            in_kw = _in_function_kwarg_default(node, parents)
            in_fb = _in_fallback_literal(node, parents)
            in_mc = _in_module_level_const(node, parents)
            out.append({
                "path": str(p.relative_to(src.parent)).replace("\\", "/"),
                "line": node.lineno,
                "value": repr(val)[:80],
                "kind": literal_kind,
                "category": category,
                "in_dataclass_field_default": in_df,
                "in_function_kwarg_default": in_kw,
                "in_fallback_literal": in_fb,
                "in_module_level_const": in_mc,
                "is_operational": not (in_df or in_kw or in_fb or in_mc),
            })
    return out


# ---------------------------------------------------------------------------
# llm-host classification (per-batch)
# ---------------------------------------------------------------------------

CLASSIFY_SCHEMA = {
    "type": "object",
    "required": ["verdicts"],
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["path", "verdict"],
                "properties": {
                    "path": {"type": "string",
                             "description": "path:line as passed in"},
                    "verdict": {
                        "type": "string",
                        "enum": ["real_hardcode", "well_known_constant",
                                 "internal_sentinel", "unclear"],
                    },
                    "reasoning": {"type": "string",
                                  "description": "one-line justification"},
                    "suggested_config_key": {
                        "type": "string",
                        "description": "only when verdict=real_hardcode; snake.case",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                },
            },
        },
    },
}


def leira_classify(operational_hits: list[dict]) -> list[dict]:
    """Batch-classify operational hits via llm-host. Returns per-site verdict."""
    verdicts: list[dict] = []
    for i in range(0, len(operational_hits), MAX_HITS_PER_BATCH):
        batch = operational_hits[i:i + MAX_HITS_PER_BATCH]
        compact = "\n".join(
            f"  {h['path']}:{h['line']} = {h['value']} (kind={h['kind']})"
            for h in batch
        )
        try:
            result = call_leira(
                task_prompt=(
                    "You are classifying source-code literals that our scope-aware "
                    "AST walker has already filtered to OPERATIONAL positions "
                    "(NOT dataclass field defaults, NOT function-kwarg defaults, "
                    "NOT fallback literals). For each, decide:\n"
                    "- `real_hardcode`: a value that varies per deploy or per "
                    "operator preference and should move to config. Provide a "
                    "`suggested_config_key` (snake.case).\n"
                    "- `well_known_constant`: protocol/algorithm/spec constant "
                    "that doesn't vary (HTTP status, `/run/secrets` Docker "
                    "convention, MS Graph endpoint, well-known DNS resolver).\n"
                    "- `internal_sentinel`: 0/1/-1/None-adjacent, algorithm "
                    "internal (key size, buffer size fixed by spec).\n"
                    "- `unclear`: needs human review.\n\n"
                    "Assign severity high|medium|low for real_hardcode findings.\n"
                    f"Hits (path:line = literal):\n{compact}"
                ),
                schema=CLASSIFY_SCHEMA,
            )
            verdicts.extend(result.get("verdicts", []))
        except OllamaCallError as e:
            verdicts.append({"leira_error": str(e), "batch_start": i})
    return verdicts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", type=pathlib.Path, default=pathlib.Path("src/email_triage"))
    ap.add_argument("--output", type=pathlib.Path,
                    default=pathlib.Path("audit-reports/hardcode-scoped.json"))
    ap.add_argument("--skip-llm-host", action="store_true",
                    help="output candidates + scope tags without llm-host classification")
    args = ap.parse_args(argv)

    candidates = collect_candidates(args.src)
    operational = [c for c in candidates if c["is_operational"]]
    print(f"total candidates: {len(candidates)}", file=sys.stderr)
    print(f"operational (post scope-filter): {len(operational)}", file=sys.stderr)

    payload = {
        "src": str(args.src),
        "totals": {
            "all_candidates": len(candidates),
            "operational_after_scope_filter": len(operational),
            "in_dataclass_field_default": sum(1 for c in candidates if c["in_dataclass_field_default"]),
            "in_function_kwarg_default": sum(1 for c in candidates if c["in_function_kwarg_default"]),
            "in_fallback_literal": sum(1 for c in candidates if c["in_fallback_literal"]),
            "in_module_level_const": sum(1 for c in candidates if c["in_module_level_const"]),
        },
        "operational_hits": operational,
    }
    if not args.skip_leira:
        payload["verdicts"] = leira_classify(operational)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                           encoding="utf-8")
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
