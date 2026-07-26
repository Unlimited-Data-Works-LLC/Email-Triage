"""test_leira_no_hardcode_pin.py — Structural pin (2026-07-02) for the llm-host
offload stack's "NO HARDCODING" pillar.

Anchors `pattern_leira_offload_stack.md`'s Pillar 1: every Consumer must
read its knobs via `get_consumer_config(...)`, its byte-budget via
`context_bytes(ratio, ...)`, and its llm-host endpoint via `call_leira(...)`.
Direct hardcoded model names, hardcoded context windows > 8192, or
hardcoded timeouts > 60s in a `leira_*.py` script are banned.

Waived per line via `# llm-host-hardcode-allowed: <reason>` end-of-line
comment when a value genuinely can't be config-derived (e.g. a subprocess
timeout for the Python interpreter itself, not the LLM).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from _pin_harness import parse_source

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
_MODEL_STRING_RE = re.compile(r"^(qwen|llama|mistral|gemma|phi|codellama|deepseek|nomic)", re.I)
_ALLOWED_MARKER = "llm-host-hardcode-allowed"


def _leira_consumer_scripts():
    _NON_CONSUMERS = {
        "leira_prepass.py",       # wrapper (IS the config-reader)
        "leira_config.py",        # config helper
        # 2026-07-02 sharpening helpers (Improvements #1, #4) — NOT consumers.
        "leira_class_hints.py",   # per-class structural hint registry
        "leira_cache.py",         # response cache
    }
    for p in sorted(_SCRIPTS_DIR.glob("leira_*.py")):
        if p.name in _NON_CONSUMERS:
            continue
        yield p


def _read_source_lines(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    return text, text.splitlines()


def _line_is_waived(lines, lineno) -> bool:
    if lineno < 1 or lineno > len(lines):
        return False
    return _ALLOWED_MARKER in lines[lineno - 1]


@pytest.mark.parametrize("script_path", list(_leira_consumer_scripts()),
                         ids=lambda p: p.name)
def test_no_hardcoded_model_string(script_path):
    """Ban `= "qwen3.6:35b"` style hardcoded model literals in consumers.
    The wrapper's `_discover_model()` is the SSOT."""
    text, lines = _read_source_lines(script_path)
    tree = parse_source(text)
    hardcodes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        v = node.value
        if not (isinstance(v, ast.Constant) and isinstance(v.value, str)):
            continue
        if not _MODEL_STRING_RE.match(v.value):
            continue
        if _line_is_waived(lines, node.lineno):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        hardcodes.append(f"{script_path.name}:{node.lineno} {targets} = {v.value!r}")
    assert not hardcodes, (
        "Hardcoded model name in Consumer — the wrapper's `_discover_model()` "
        "is the SSOT. Read the running model from `call_leira`'s response, "
        "not from a string literal. Waive per line with "
        f"`# {_ALLOWED_MARKER}: <reason>` if genuinely unavoidable.\n"
        + "\n".join(hardcodes)
    )


@pytest.mark.parametrize("script_path", list(_leira_consumer_scripts()),
                         ids=lambda p: p.name)
def test_no_hardcoded_context_or_large_timeout(script_path):
    """Ban integer literals in Assign nodes that look like a context window
    (> 8192 tokens) or a large timeout (> 60s not from config). This catches
    the "= 98304" / "= 200_000" / "timeout=1800" mistakes.

    Waived per line with `# llm-host-hardcode-allowed: <reason>`."""
    text, lines = _read_source_lines(script_path)
    tree = parse_source(text)
    hardcodes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        v = node.value
        # Skip if the value is a call — that's a config-derived derivation.
        if isinstance(v, ast.Call):
            continue
        if not (isinstance(v, ast.Constant) and isinstance(v.value, int)):
            continue
        val = v.value
        if val <= 8192:  # small ints are fine (list caps, retries, ratios)
            continue
        if _line_is_waived(lines, node.lineno):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        hardcodes.append(f"{script_path.name}:{node.lineno} {targets} = {val}")
    # Same guard for KEYWORD args in Call nodes (e.g. `timeout=1800`).
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg is None:
                continue
            if kw.arg not in {"timeout", "num_ctx", "context", "max_tokens", "max_input_bytes"}:
                continue
            v = kw.value
            if not (isinstance(v, ast.Constant) and isinstance(v.value, int)):
                continue
            if v.value <= 60:  # small timeouts are fine
                continue
            if _line_is_waived(lines, kw.value.lineno):
                continue
            hardcodes.append(f"{script_path.name}:{kw.value.lineno} kwarg {kw.arg}={v.value}")

    assert not hardcodes, (
        "Hardcoded context-window / timeout in Consumer. Read via "
        "`get_consumer_config(<consumer_name>)` or `context_bytes(ratio)`; "
        f"waive per line with `# {_ALLOWED_MARKER}: <reason>`.\n"
        + "\n".join(hardcodes)
    )


@pytest.mark.parametrize("script_path", list(_leira_consumer_scripts()),
                         ids=lambda p: p.name)
def test_consumer_imports_wrapper_helpers(script_path):
    """A consumer MUST import at least one of `call_leira`, `context_bytes`,
    `get_consumer_config` from `leira_prepass`. A leira_*.py that talks
    directly to llm-host via urllib is bypassing the SSOT."""
    text = script_path.read_text(encoding="utf-8", errors="replace")
    tree = parse_source(text)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "leira_prepass":
            for a in node.names:
                imports.add(a.name)
    required_at_least_one = {"call_leira", "context_bytes", "get_consumer_config"}
    assert imports & required_at_least_one, (
        f"{script_path.name} does not import any of {required_at_least_one} "
        f"from leira_prepass. Got imports: {imports}. A Consumer bypassing "
        "the wrapper is a Pillar violation — the wrapper owns the backoff, "
        "the discovery, the cooldown."
    )
