"""N-338 R31 — structural pin against re-widening the positional-args HIPAA
gate back to a bare-string allow-list, MODULE-WIDE per PD#2 interprocedural.

N-300 R30 (2026-07-03) shipped ``_gate_positional_args`` with an
allow-list ``isinstance(a, str) and len(a) <= 64 and "@" not in a and
":" not in a`` — which passes phone / SSN / DOB / MRN / patient-name /
ZIP / ICD-10 codes / short clinical subjects. Any regression that
re-introduces a branch appending an unmodified ``str`` value to the
gated tuple recreates the LIVE §164.514(b) leak.

**Interprocedural** (db-sme + DA N-338 review 2026-07-04): the pin walks
the ENTIRE ``triage_logging`` module (not just ``_gate_positional_args``)
and forbids ``isinstance(_, str)`` outside a small allow-list of
functions whose docstrings + names make their string-check purpose
explicit and non-gate (``_sanitise`` / ``redact_persisted_extra`` /
``_persist_row`` / ``Safe.__init__`` / ``_stringy_extra_key`` etc.). A
refactor that hoists the gate's string check into a helper the pin
doesn't allow-list will fail immediately.

Companion behavioural coverage lives in
``test_n300_positional_args_hipaa_gate.py`` (parametrized over 17
identifier shapes hipaa-sme flagged).
"""
from __future__ import annotations

import ast

import pytest

from _pin_harness import SRC_ROOT, parse_module


# N-341 R31 (2026-07-04 CI-red fix-forward on 7f108327): route through
# the shared ``_pin_harness`` per the pin-harness-adoption meta-pin
# (census run15 #3 — a per-file ``Path(__file__).resolve().parent.parent``
# is fragile against file MOVEs). SRC_ROOT is computed ONCE in the
# harness; parse_module is the shared parse+annotate-parents entry point.
TARGET = SRC_ROOT / "triage_logging.py"


# Functions whose ``isinstance(_, str)`` calls are semantically legitimate
# (dict-key sanitisation, error-message shape checks, config parsing, the
# Safe ctor itself). Every OTHER FunctionDef in triage_logging.py must NOT
# do a bare-str check — the gate's fail-CLOSED promise depends on it.
_ALLOW_LISTED_FUNCTIONS = frozenset({
    "__init__",            # Safe.__init__ — validates the wrapper's value shape.
    "_sanitise",           # extras-dict sanitiser (denylist path, out-of-scope for N-338).
    "redact_persisted_extra",  # persisted-log sink allowlist.
    "_merge_extra",        # kwargs merge — checks for dict shape via isinstance(dict).
    "_JsonFormatter",      # formatter type coercion (renders values, does not gate them).
    "format",              # _JsonFormatter.format — LogRecord serialisation.
    "emit",                # SQLiteLogHandler.emit — persisted-sink row build.
    "_stringify",          # LogRecord field coercion.
    "_persist_row",        # sink row shaping.
    "_coerce_key",         # normalise extras key names.
    "setup_logging",       # boot-time config validation.
    "_setup_root",         # root logger config.
    "_normalise_level",    # log-level string→int coercion.
})


def _iter_isinstance_str_sites() -> list[tuple[int, str, str]]:
    """Return every ``isinstance(_, str)`` call site as
    (lineno, enclosing_function_name, second_arg_source).
    Walks the whole module and remembers the enclosing FunctionDef.
    """
    tree = parse_module(TARGET)
    if tree is None:
        pytest.fail(f"parse_module returned None for {TARGET}")
    sites: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == "isinstance"
                and len(sub.args) == 2
            ):
                type_src = ast.unparse(sub.args[1])
                # Match ``str`` bare AND ``(str, …)`` tuples.
                type_names = {t.strip() for t in type_src.strip("()").split(",")}
                if "str" in type_names or type_src == "str":
                    sites.append((sub.lineno, node.name, type_src))
    return sites


def _gate_fn() -> ast.FunctionDef:
    tree = parse_module(TARGET)
    if tree is None:
        pytest.fail(f"parse_module returned None for {TARGET}")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_gate_positional_args":
            return node
    pytest.fail("_gate_positional_args not found in triage_logging.py — moved or renamed?")


def _fn_by_name(name: str) -> ast.FunctionDef | None:
    tree = parse_module(TARGET)
    if tree is None:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


# ---------------------------------------------------------------------------
# Interprocedural: every ``isinstance(_, str)`` in triage_logging must be
# inside an allow-listed function.
# ---------------------------------------------------------------------------

def test_no_bare_str_isinstance_outside_allow_list():
    """N-338 PD#2 interprocedural pin: bare-str allow-list can only live
    in curated functions. A future refactor that extracts the gate's
    string check to a helper `_string_ok(a)` (or a class predicate) trips
    this immediately — the helper's FunctionDef name is not on the list.
    Add to `_ALLOW_LISTED_FUNCTIONS` only after a hipaa-sme review that
    the new site is NOT the gate's fail-CLOSED path.
    """
    violations: list[str] = []
    for lineno, fn_name, type_src in _iter_isinstance_str_sites():
        if fn_name not in _ALLOW_LISTED_FUNCTIONS:
            violations.append(
                f"triage_logging.py:{lineno} — {fn_name}() calls "
                f"``isinstance(_, {type_src})``. Not in the N-338 "
                f"allow-list. Bare-str checks outside these functions "
                f"are the exact shape N-300 leaked (phone/SSN/DOB/MRN/"
                f"name/ZIP/ICD-10). Either wire the check through "
                f"``Safe`` or add the enclosing function to "
                f"``_ALLOW_LISTED_FUNCTIONS`` after hipaa-sme review."
            )
    if violations:
        pytest.fail("N-338 interprocedural violations:\n" + "\n".join(violations))


# ---------------------------------------------------------------------------
# Positive shape checks on the gate itself.
# ---------------------------------------------------------------------------

def test_gate_function_still_uses_isinstance_safe():
    """N-338: the ``Safe`` unwrap is the ONE explicit string-typed opt-in.
    A refactor that drops it silently redacts every caller — the
    behavioural tests would flag it, this pin surfaces it earlier.
    """
    fn = _gate_fn()
    for sub in ast.walk(fn):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Name)
            and sub.func.id == "isinstance"
            and len(sub.args) == 2
            and ast.unparse(sub.args[1]) == "Safe"
        ):
            return
    pytest.fail(
        "_gate_positional_args lost its ``isinstance(_, Safe)`` check — "
        "the Safe(...) opt-in path is gone. Restore it or callers that "
        "wrapped literals in Safe() silently redact."
    )


def test_gate_function_contains_redacted_literal():
    """N-338: fail-CLOSED default must still emit a redaction sentinel.
    A regression that drops the ``<redacted>`` literal leaves the
    fall-through arm passing un-gated values.
    """
    fn = _gate_fn()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Constant) and sub.value == "<redacted>":
            return
    pytest.fail(
        "_gate_positional_args no longer contains the ``<redacted>`` "
        "literal. Non-scalar / non-Safe args may pass un-redacted."
    )


def test_gate_function_forbids_bare_str_isinstance_locally():
    """N-338 anti-regression pin — narrow scope for a clear error at the
    exact leak site. `_gate_positional_args` MUST NOT itself call
    ``isinstance(_, str)`` — that is the direct N-300 shape. The
    interprocedural pin above widens the guarantee; this one names the
    leak site precisely.
    """
    fn = _gate_fn()
    for sub in ast.walk(fn):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Name)
            and sub.func.id == "isinstance"
            and len(sub.args) == 2
        ):
            type_src = ast.unparse(sub.args[1])
            type_names = {t.strip() for t in type_src.strip("()").split(",")}
            if "str" in type_names or type_src == "str":
                pytest.fail(
                    f"triage_logging.py:{sub.lineno} — "
                    f"_gate_positional_args reintroduced "
                    f"``isinstance(_, {type_src})``. This is the exact "
                    f"N-300 R30 shape hipaa-sme rejected. Route strings "
                    f"through Safe(...) or redact."
                )
