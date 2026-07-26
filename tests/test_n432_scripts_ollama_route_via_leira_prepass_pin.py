"""N-432 (2026-07-21) count-agnostic structural pin — every Ollama /api/(chat
|generate|embeddings) call site in ``scripts/**`` MUST route through the SSOT
``leira_prepass.call_leira`` wrapper. Hand-rolled ``urllib.request.Request`` /
``urlopen`` POSTs to those endpoints are forbidden outside the SSOT module
itself.

Story: 2026-07-21 defer_gate v3.1 landed with three hooks (``_scope_da.py``,
``_defer_da.py``, ``learn_defer_phrases.py``) each hand-rolling stdlib urllib
to POST ``/api/chat`` on llm-host with a hardcoded model + hardcoded
``keep_alive`` + no ``think`` field. The hardcoded ``think`` default (True on
qwen3.6:35b) added a 12s per-call stall; the hardcoded ``keep_alive:"30m"``
violated ``feedback_dont_manually_repin_ollama``; the hardcoded model +
endpoint violated ``pattern_leira_offload_stack`` Pillar 1 + Rule 3 in
``feedback_leira_first_and_build_leira_versions``. The correct funnel already
existed — ``scripts/leira_prepass.py:call_leira`` — with model discovery, host
failover, per-host cooldown, exponential backoff, schema validation, and
per-call ``think`` support. The three hooks bypassed it.

Recurrence class: ``feedback_leira_first_and_build_leira_versions`` Rule 3
("ALWAYS route through the wrapper; NEVER curl :11434 with a hardcoded
model") + ``pattern_leira_offload_stack`` Pillar 1 (no hardcoded model /
context / keep_alive). The N-431 pin covers ``src/email_triage/`` (in-app
httpx path, SSOT = ``_ollama_reuse.merge_reuse_options``); this pin covers
``scripts/`` (offline/CLI path, SSOT = ``leira_prepass.call_leira``). Two
Ollama SSOTs for two boundaries, one pin each.

WHAT IT PINS (count-agnostic, structural):

Every ``.py`` file under ``scripts/`` (excluding ``leira_prepass.py`` — that
IS the SSOT — and ``__pycache__``) that BOTH:

  (a) references an Ollama endpoint string (``/api/chat``, ``/api/generate``,
      or ``/api/embeddings``) in a code-level string literal, AND
  (b) contains a call to ``urlopen(...)`` or ``Request(...)`` (bare-name or
      attribute shape)

fires the pin. The combination IS the hand-rolled-POST recurrence shape.
Files that reference the endpoint only in a docstring (documentation) but
do not urlopen it are fine. Files that urlopen unrelated URLs (a git-hook
health-check) are fine. The AND-of-both is what the pin closes.

No enumeration floor: post-refactor the correct answer is ZERO offenders,
and the pin fires exactly when a future consumer re-introduces the
recurrence.
"""
from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import REPO_ROOT, iter_files, parse_module, parse_source, relpath

SCRIPTS_ROOT: Path = REPO_ROOT / "scripts"

# The SSOT module itself is exempt (it IS the funnel).
_SSOT_RELPATH = "leira_prepass.py"

# Endpoint needles — the substrings that mark a call site as an Ollama POST.
_OLLAMA_ENDPOINT_NEEDLES = ("/api/chat", "/api/generate", "/api/embeddings")


def _iter_scripts_py():
    """Yield every ``*.py`` under ``scripts/`` via the shared harness walker
    (R5b: NEVER hand-roll ``rglob`` — the harness owns the walk +
    ``__pycache__`` skip), excluding the SSOT module."""
    for path in iter_files(SCRIPTS_ROOT, "*.py"):
        if path.name == _SSOT_RELPATH:
            continue
        yield path


def _collect_docstring_nodes(tree: ast.AST) -> set[int]:
    """Return the ``id(...)`` of every ``ast.Constant`` that is a module /
    class / function docstring. Used to skip docstring-only endpoint mentions
    when scanning for LIVE endpoint references."""
    docs: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = getattr(node, "body", None) or []
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            docs.add(id(first.value))
    return docs


def _module_has_live_ollama_endpoint_reference(tree: ast.AST) -> bool:
    """True if any code-level (non-docstring) string literal in ``tree``
    contains an Ollama endpoint needle. Docstrings are excluded — a script
    documenting talking to Ollama in prose is not the recurrence shape."""
    doc_ids = _collect_docstring_nodes(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in doc_ids:
                continue
            if any(n in node.value for n in _OLLAMA_ENDPOINT_NEEDLES):
                return True
        elif isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    if any(n in v.value for n in _OLLAMA_ENDPOINT_NEEDLES):
                        return True
    return False


def _module_calls_urllib_post(tree: ast.AST) -> bool:
    """True if ``tree`` contains a call to ``urlopen(...)`` OR
    ``urllib.request.urlopen(...)`` OR ``Request(...)`` OR
    ``urllib.request.Request(...)`` — either bare-name (via
    ``from urllib.request import urlopen``) or attribute shape."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in ("urlopen", "Request"):
            return True
        if isinstance(func, ast.Attribute) and func.attr in ("urlopen", "Request"):
            return True
    return False


def test_no_hand_rolled_ollama_post_in_scripts():
    """No ``scripts/**/*.py`` file (except the SSOT ``leira_prepass.py``) may
    both reference an Ollama endpoint in a code-level string literal AND
    hand-roll ``urlopen(...)`` / ``Request(...)``. The AND-of-both is the
    2026-07-21 recurrence shape."""
    offenders: list[str] = []
    for path in _iter_scripts_py():
        tree = parse_module(path)
        if tree is None:
            continue
        if not _module_has_live_ollama_endpoint_reference(tree):
            continue
        if _module_calls_urllib_post(tree):
            offenders.append(relpath(path, base=REPO_ROOT))
    assert not offenders, (
        "N-432: scripts/**/*.py files hand-roll an Ollama POST (endpoint "
        "string + urllib.request call in the same module): "
        + ", ".join(offenders) + ". Delete the hand-rolled POST and route "
        "through `leira_prepass.call_leira(prompt, schema=..., think=..., "
        "timeout_s=...)`. Per pattern_leira_offload_stack Pillar 1 + "
        "feedback_leira_first_and_build_leira_versions Rule 3, every llm-host "
        "call from scripts/ MUST route through the wrapper — it owns model "
        "resolution, host failover, cooldown, backoff, and schema "
        "validation."
    )


def test_pin_detects_planted_hand_rolled_post():
    """Teeth — the detector flags a planted hand-rolled POST shape."""
    bad = (
        "from urllib.request import Request, urlopen\n"
        "req = Request('http://llm-host:11434/api/chat', data=b'{}')\n"
        "urlopen(req, timeout=15)\n"
    )
    tree = parse_source(bad)
    assert _module_has_live_ollama_endpoint_reference(tree), (
        "detector missed a planted /api/chat string literal"
    )
    assert _module_calls_urllib_post(tree), (
        "detector missed a planted urlopen(...) call"
    )


def test_pin_ignores_docstring_only_mention():
    """Teeth — a file mentioning ``/api/chat`` only in a docstring, with no
    urllib call, does NOT fire the pin."""
    good = (
        '"""Consumer that talks to llm-host /api/chat via call_leira."""\n'
        "from leira_prepass import call_leira\n"
        "def do():\n"
        "    return call_leira('hi')\n"
    )
    tree = parse_source(good)
    # Docstring-only mention should not count as a LIVE reference.
    assert not _module_has_live_ollama_endpoint_reference(tree), (
        "docstring mention wrongly counted as live endpoint reference"
    )
