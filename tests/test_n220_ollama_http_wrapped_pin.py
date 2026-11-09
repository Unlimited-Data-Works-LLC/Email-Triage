"""N-220 R22 structural pin — Ollama HTTP POST is breaker+timer wrapped (2026-07-02).

Census R22 (run22 backlog HIGH #3): `engine/embedding_backend.py:265`
`OllamaEmbeddingBackend.embed_text` issued a raw `client.post("/api/embeddings")`
with NEITHER `llm_health.translate_unreachable` NOR `metrics.timer` wrapping.
Consequence: a dead Ollama on the M-4 sent-mail-index or draft-reply retrieval
path raises a raw `httpx.ConnectError`, the fallback backend catches it
silently, the `ollama` circuit breaker never trips, AND `/metrics` carries
zero embedding latency for the Ollama path.

WHAT IT PINS (count-agnostic, interprocedural via function name — a property
over every site, never `len(X)==N`):

Every function that issues an httpx call (`.post`/`.get`/`.put`/`.delete`) to
an Ollama API URL (path starts with `/api/`) must reference BOTH
`translate_unreachable(` AND `metrics.timer(` in the SAME top-level function
(including nested closures). Waives: SSOT files that DEFINE the helpers
themselves (`llm_health.py`, `metrics.py`) and test files.

SCOPE CAVEAT (honest): asserts BOTH strings are referenced in the same
top-level function as the httpx call — does NOT prove the wrapper textually
encloses the call on every code path. Sibling refs count. Anti-vacuity:
`test_ollama_http_call_site_exists` fails if the census's target site
disappears (a refactor that hoists the call into a helper must keep the
wrapper co-located OR add an allow-list entry + document why).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


# The endpoint substring that identifies an Ollama API URL we care about.
# Scoped to `/api/embeddings` (the retrieval hot path) at N-220. `/api/chat`
# is covered by test_metrics_adoption_pin.py at the outer classify() seam,
# and `/api/ps` / `/api/tags` / `/api/show` are health probes that don't
# carry classify semantics. Widen this set only when a new hot-path
# endpoint is added.
_OLLAMA_ENDPOINT_MARK = "/api/embeddings"

_HTTPX_METHODS = {"post", "get", "put", "delete"}


def _fn_of(node: ast.AST, tree: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return the innermost enclosing top-level fn (walks up through nested)."""
    # ast doesn't give parent pointers - annotate on demand.
    stack: list[ast.AST] = [tree]
    parents: dict[int, ast.AST] = {}
    while stack:
        cur = stack.pop()
        for child in ast.iter_child_nodes(cur):
            parents[id(child)] = cur
            stack.append(child)
    cur = node
    top_fn = None
    while cur is not tree:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            top_fn = cur
        parent = parents.get(id(cur))
        if parent is None:
            break
        cur = parent
    return top_fn


def _fn_source_refs(fn: ast.AST, tree: ast.AST, needle: str) -> bool:
    """True if `needle` appears as an attribute / name / call substring in fn."""
    for node in ast.walk(fn):
        # Function calls: check for `translate_unreachable(...)` and
        # `metrics.timer(...)` shapes.
        if isinstance(node, ast.Call):
            f = node.func
            name = None
            if isinstance(f, ast.Name):
                name = f.id
            elif isinstance(f, ast.Attribute):
                name = f.attr
            if name and needle.rstrip("(") in name:
                return True
        # Also match Attribute lookups without call (e.g. imports referenced)
        if isinstance(node, ast.Attribute) and needle.rstrip("(") == node.attr:
            return True
        if isinstance(node, ast.Name) and needle.rstrip("(") == node.id:
            return True
    return False


def _find_ollama_httpx_call_sites(tree: ast.AST) -> list[tuple[ast.FunctionDef, ast.Call]]:
    """Return (fn, call) pairs for every httpx `.post/.get/...` to an Ollama URL."""
    hits: list[tuple[ast.FunctionDef, ast.Call]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        # Match `<something>.post(...)` shape
        if not isinstance(f, ast.Attribute):
            continue
        if f.attr not in _HTTPX_METHODS:
            continue
        # Look for the URL arg (positional 0 or kwarg `url`)
        url_arg = None
        if node.args:
            url_arg = node.args[0]
        for kw in node.keywords:
            if kw.arg == "url":
                url_arg = kw.value
                break
        if url_arg is None:
            continue
        # Extract text: JoinedStr (f-string), Constant str, or ignore
        text = ""
        if isinstance(url_arg, ast.Constant) and isinstance(url_arg.value, str):
            text = url_arg.value
        elif isinstance(url_arg, ast.JoinedStr):
            for v in url_arg.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    text += v.value
        if _OLLAMA_ENDPOINT_MARK not in text:
            continue
        fn = _fn_of(node, tree)
        if fn is None:
            continue
        hits.append((fn, node))
    return hits


def test_ollama_http_call_site_exists():
    """Anti-vacuity: at least one call site MUST exist tree-wide. If this
    fails, a refactor removed the target of the pin - update the allow-list
    or the pin design deliberately."""
    total = 0
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        total += len(_find_ollama_httpx_call_sites(tree))
    assert total >= 1, (
        "N-220 R22 anti-vacuity: no Ollama httpx call sites found tree-wide. "
        "If a refactor removed them all, this pin has nothing to guard - "
        "delete the pin OR update the endpoint mark."
    )


def test_ollama_http_calls_are_breaker_and_timer_wrapped():
    """Every Ollama /api/... POST/GET/... must reference BOTH
    `translate_unreachable` AND `metrics.timer` in the same top-level fn."""
    unwrapped: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for fn, call in _find_ollama_httpx_call_sites(tree):
            has_breaker = _fn_source_refs(fn, tree, "translate_unreachable")
            has_timer = _fn_source_refs(fn, tree, "timer")
            if not (has_breaker and has_timer):
                missing = []
                if not has_breaker:
                    missing.append("translate_unreachable")
                if not has_timer:
                    missing.append("metrics.timer")
                unwrapped.append(
                    f"{rel}:{call.lineno} in `{fn.name}` missing {'+'.join(missing)}"
                )
    assert not unwrapped, (
        "N-220 R22: Ollama httpx call site not wrapped in breaker + timer. "
        "Every `.post/.get/... /api/...` must sit inside "
        "`translate_unreachable('ollama', self._base_url, default_port=11434)` "
        "AND `metrics.timer('et_llm_<label>_seconds', backend='ollama')`. "
        "See `classify/ollama.py:_chat` for the canonical pattern.\n\n"
        + "\n".join(unwrapped)
    )
