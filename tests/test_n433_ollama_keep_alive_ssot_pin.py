"""N-433 (2026-07-22) count-agnostic structural pin — the ``scripts/`` SSOT
(``leira_prepass.py``) MUST set the Ollama ``keep_alive`` top-level field in
every body dict it POSTs to ``/api/chat`` / ``/api/generate`` /
``/api/embeddings``. Every other ``scripts/**/*.py`` file that reaches Ollama
directly (hand-rolled POST) MUST also carry a ``keep_alive`` key in its body.

Story: 2026-07-22 batch SME panel (workflow ``wf_0947dcd0-906``) found that
``leira_prepass.call_leira`` — the funnel N-432 requires every ``scripts/``
consumer to route through — did NOT set ``keep_alive`` on its own body dict.
The three defer-gate hooks had just been refactored to route through the
wrapper on the claim that "the wrapper picks up ... keep_alive" (commit
``7da21900``). The wrapper's body dict at the time contained only ``model``,
``messages``, ``stream``, ``options``, ``format``, ``think`` — verified by
``grep -c keep_alive scripts/leira_prepass.py → 0``. The three hooks routing
through the wrapper therefore inherited the SSOT hole silently — every llm-host
call was still applying Ollama's per-call default ``"5m"`` model TTL, which
silently overrides operator TTL pins per BINDING
``feedback_always_set_ollama_keep_alive_explicitly``.

This pin makes the recurrence structurally impossible on the SSOT owner.
The peer N-432 pin (``test_n432_scripts_ollama_route_via_leira_prepass_pin``)
forces every OTHER script to route through this SSOT; the two pins together
mean every llm-host call from ``scripts/`` provably sets ``keep_alive``.

WHAT IT PINS (count-agnostic, structural):

  1. ``scripts/leira_prepass.py`` — SSOT owner — MUST define a
     module-level ``_DEFAULT_KEEP_ALIVE`` constant AND its
     ``_call_leira_once`` body dict must contain ``"keep_alive"`` as a
     key (verified via AST walk of the module).

  2. Every ``scripts/**/*.py`` file that hand-rolls an Ollama endpoint
     POST (per the N-432 detector shape — an ``/api/chat|generate|
     embeddings`` string literal in the same module as an
     ``urlopen(...)``/``Request(...)`` call) MUST carry a
     ``"keep_alive"`` key in a dict-literal within that module. The
     SSOT ``leira_prepass.py`` counts under rule (1); it is exempt from
     rule (2).

No enumeration floor — the correct answer is that rule (1) always passes and
rule (2) fires ONLY when a future consumer re-introduces the recurrence.
"""
from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import REPO_ROOT, iter_files, parse_module, parse_source, relpath

SCRIPTS_ROOT: Path = REPO_ROOT / "scripts"
_SSOT_RELPATH = "leira_prepass.py"
_OLLAMA_ENDPOINT_NEEDLES = ("/api/chat", "/api/generate", "/api/embeddings")


def _iter_scripts_py():
    """Yield every ``*.py`` under ``scripts/`` via the shared harness walker."""
    for path in iter_files(SCRIPTS_ROOT, "*.py"):
        yield path


def _module_has_live_ollama_endpoint_reference(tree: ast.AST) -> bool:
    """Same detector as N-432: any non-docstring string literal contains
    an Ollama endpoint needle."""
    # Collect docstring node ids.
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
    # Scan for live references.
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docs:
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
    """Same detector as N-432: any ``urlopen(...)``/``Request(...)`` call."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in ("urlopen", "Request"):
            return True
        if isinstance(func, ast.Attribute) and func.attr in ("urlopen", "Request"):
            return True
    return False


def _module_defines_default_keep_alive(tree: ast.AST) -> bool:
    """True if the module top-level defines a name matching
    ``*_KEEP_ALIVE`` or ``KEEP_ALIVE`` — case-sensitive, module scope."""
    for node in tree.body if isinstance(tree, ast.Module) else []:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for tgt in targets:
            if isinstance(tgt, ast.Name) and tgt.id.endswith("KEEP_ALIVE"):
                return True
    return False


def _module_dict_literals_include_key(tree: ast.AST, key: str) -> bool:
    """True if the module structurally sets ``key`` as a dict key. Matches
    either:

      * an ``ast.Dict`` literal whose ``.keys`` contain a string constant
        equal to ``key`` (e.g. ``{"keep_alive": "-1"}``), OR
      * an ``ast.Subscript`` assignment target whose ``.slice`` is a string
        constant equal to ``key`` (e.g. ``body["keep_alive"] = x``) — the
        idiomatic guarded-set pattern the SSOT uses for ``body["think"]``.

    Dict-comprehension literals with dynamic keys are ignored (no static key
    to match)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and k.value == key:
                    return True
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    slc = target.slice
                    if isinstance(slc, ast.Constant) and slc.value == key:
                        return True
        elif isinstance(node, ast.AugAssign) or isinstance(node, ast.AnnAssign):
            target = getattr(node, "target", None)
            if isinstance(target, ast.Subscript):
                slc = target.slice
                if isinstance(slc, ast.Constant) and slc.value == key:
                    return True
    return False


def test_ssot_leira_prepass_defines_keep_alive_default_and_body_key():
    """Rule 1: the SSOT owner ``scripts/leira_prepass.py`` MUST:
    (a) define a module-level ``*_KEEP_ALIVE`` constant, AND
    (b) include ``"keep_alive"`` as a key in at least one dict literal
        (the body dict of ``_call_leira_once``).
    Both together mean the SSOT owns the model-lifetime contract."""
    ssot_path = SCRIPTS_ROOT / _SSOT_RELPATH
    assert ssot_path.exists(), f"SSOT file missing: {ssot_path}"
    tree = parse_module(ssot_path)
    assert tree is not None, f"SSOT file did not parse: {ssot_path}"
    assert _module_defines_default_keep_alive(tree), (
        "N-433 rule 1a: scripts/leira_prepass.py is expected to define a "
        "module-level `*_KEEP_ALIVE` constant so the SSOT owns the Ollama "
        "model-lifetime default. Add `_DEFAULT_KEEP_ALIVE: str | None = "
        "_resolve_default_keep_alive()` alongside the existing "
        "`_DEFAULT_THINK` sibling."
    )
    assert _module_dict_literals_include_key(tree, "keep_alive"), (
        "N-433 rule 1b: scripts/leira_prepass.py is expected to include "
        "`\"keep_alive\"` as a key in the body dict of `_call_leira_once`. "
        "Add `body[\"keep_alive\"] = _effective_keep_alive` guarded by "
        "`is not None`, mirroring the `body[\"think\"]` block."
    )


def test_no_hand_rolled_ollama_post_missing_keep_alive():
    """Rule 2: every ``scripts/**/*.py`` file that hand-rolls an Ollama
    POST (per N-432 detector shape) MUST also include ``"keep_alive"`` as
    a key in at least one dict literal. The SSOT owner is exempt (its own
    body dict is checked by rule 1b)."""
    offenders: list[str] = []
    for path in _iter_scripts_py():
        if path.name == _SSOT_RELPATH:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        if not _module_has_live_ollama_endpoint_reference(tree):
            continue
        if not _module_calls_urllib_post(tree):
            continue
        if not _module_dict_literals_include_key(tree, "keep_alive"):
            offenders.append(relpath(path, base=REPO_ROOT))
    assert not offenders, (
        "N-433 rule 2: scripts/**/*.py files hand-roll an Ollama POST "
        "(endpoint string + urllib call in the same module) but the module "
        "carries no `\"keep_alive\"` dict-key. Per BINDING "
        "`feedback_always_set_ollama_keep_alive_explicitly`, every direct "
        "Ollama /api/chat|generate|embeddings call MUST set `keep_alive` "
        "explicitly (absence lets Ollama apply its 5m default and silently "
        "override operator TTL pins). Offenders: " + ", ".join(offenders)
        + ". Either route through `leira_prepass.call_leira` (which now "
        "sets keep_alive by construction — rule 1) or add "
        "`\"keep_alive\": \"-1\"` (or a bounded value) to the body dict."
    )


def test_pin_detects_planted_hand_rolled_post_missing_keep_alive():
    """Teeth — the detector flags a planted hand-rolled POST without
    ``keep_alive`` in its body dict."""
    bad = (
        "from urllib.request import Request, urlopen\n"
        "import json\n"
        "body = {'model': 'qwen', 'messages': [], 'stream': False}\n"
        "req = Request('http://llm-host:11434/api/chat', data=json.dumps(body).encode())\n"
        "urlopen(req, timeout=15)\n"
    )
    tree = parse_source(bad)
    assert _module_has_live_ollama_endpoint_reference(tree), (
        "detector missed the planted /api/chat string literal"
    )
    assert _module_calls_urllib_post(tree), (
        "detector missed the planted urlopen(...) call"
    )
    assert not _module_dict_literals_include_key(tree, "keep_alive"), (
        "detector wrongly saw keep_alive in a body dict without it"
    )


def test_pin_accepts_hand_rolled_post_with_keep_alive():
    """Teeth — the detector accepts a planted hand-rolled POST that DOES
    include ``keep_alive`` in its body dict (rule 2 rejects only the
    absence)."""
    good = (
        "from urllib.request import Request, urlopen\n"
        "import json\n"
        "body = {'model': 'qwen', 'messages': [], 'stream': False, 'keep_alive': '-1'}\n"
        "req = Request('http://llm-host:11434/api/chat', data=json.dumps(body).encode())\n"
        "urlopen(req, timeout=15)\n"
    )
    tree = parse_source(good)
    assert _module_dict_literals_include_key(tree, "keep_alive"), (
        "detector missed keep_alive present in body dict"
    )
