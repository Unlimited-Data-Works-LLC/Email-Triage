#!/usr/bin/env python3
"""leira_discover.py — Consumer  of the llm-host offload stack (2026-07-02).

Improvement #6 of the sharpening: run a set of drift-shape scanners across
src/ + emit candidate NEW divergence classes. Instead of the AI assistant doing open-
ended discovery (expensive), llm-host takes structural hints from the scanner
output + names + brief-describes candidate new classes.

Scanners baked in (extensible via a JSON config):
- `boolop_isoformat`: `(a or b).isoformat()` shape where a operand is aware-now
- `try_int_valueerror`: `try: int(x) except (TypeError, ValueError)` (parse-int)
- `write_bytes_then_chmod`: `.write_bytes(x); os.chmod(p, m)` non-atomic pair
- `raw_getattr_client`: `request.client.host if request.client` request-meta bypass
- `aliased_import_asname`: `from X import Y as _Y` (potential ImportFrom-alias detector-bypass)
- `pin_harness_adoption`: `tests/*_pin.py` file that hand-rolls `.rglob`/
  `.relative_to`/`.replace('\\','/')` WITHOUT importing `_pin_harness`
  (grounded 2026-07-09 drain-audit pin drift: `da40ebd8` shipped without
  harness route, CI RED on `46dd4433`, fix-forward `5423c633` + teeth
  `864bee86`; `feedback_meta_pins_gate_new_pin_pushes` promotes the
  meta-pin from a CI-only gate into a discover-tier pre-flag)

Usage:
  python scripts/leira_discover.py --src src/email_triage
  python scripts/leira_discover.py --src src/email_triage --scanners boolop_isoformat,try_int_valueerror

Prints JSON to stdout with per-scanner hit lists + llm-host's candidate-class summary.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import OllamaCallError, call_leira, context_bytes, get_consumer_config

_cfg = get_consumer_config("discover")
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.40)))
MAX_HITS_PER_SCANNER = int(_cfg.get("max_hits_per_scanner", 25))


# ---------------------------------------------------------------------------
# Scanners — each returns a list of (relpath, lineno, snippet) tuples.
# ---------------------------------------------------------------------------

def _iter_python(src: Path):
    for p in src.rglob("*.py"):
        if "__pycache__" in str(p):
            continue
        yield p


def _read_tree(p: Path) -> tuple[str, ast.AST] | None:
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text)
        return text, tree
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None


def scan_boolop_isoformat(src: Path) -> list[tuple[str, int, str]]:
    hits = []
    for p in _iter_python(src):
        got = _read_tree(p)
        if got is None:
            continue
        _, tree = got
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "isoformat"):
                continue
            rcv = node.func.value
            if not isinstance(rcv, ast.BoolOp) or not isinstance(rcv.op, ast.Or):
                continue
            has_now = any(
                isinstance(op, ast.Call) and isinstance(op.func, ast.Attribute)
                and op.func.attr == "now"
                for op in rcv.values
            )
            if has_now:
                hits.append((str(p.relative_to(src.parent)), node.lineno,
                             "(a or b).isoformat() with aware-now"))
    return hits[:MAX_HITS_PER_SCANNER]


def scan_try_int_valueerror(src: Path) -> list[tuple[str, int, str]]:
    hits = []
    for p in _iter_python(src):
        got = _read_tree(p)
        if got is None:
            continue
        _, tree = got
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            has_int_call = any(
                isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                and sub.func.id == "int"
                for stmt in node.body for sub in ast.walk(stmt)
            )
            if not has_int_call:
                continue
            for handler in node.handlers:
                exc = handler.type
                names = []
                if isinstance(exc, ast.Name):
                    names = [exc.id]
                elif isinstance(exc, ast.Tuple):
                    names = [e.id for e in exc.elts if isinstance(e, ast.Name)]
                if "ValueError" in names or "TypeError" in names:
                    hits.append((str(p.relative_to(src.parent)), node.lineno,
                                 "try: int(x) except (ValueError, ...)"))
                    break
    return hits[:MAX_HITS_PER_SCANNER]


def scan_write_bytes_then_chmod(src: Path) -> list[tuple[str, int, str]]:
    hits = []
    for p in _iter_python(src):
        got = _read_tree(p)
        if got is None:
            continue
        text, tree = got
        # Simple pairing: within any function, if a write_bytes call is followed
        # in the same block by an os.chmod on the same receiver, flag it.
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = list(ast.walk(fn))
            for i, node in enumerate(body):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "write_bytes"):
                    continue
                # Look for os.chmod call within +6 nodes forward.
                for later in body[i + 1: i + 20]:
                    if (isinstance(later, ast.Call)
                            and isinstance(later.func, ast.Attribute)
                            and later.func.attr == "chmod"):
                        hits.append((str(p.relative_to(src.parent)), node.lineno,
                                     "write_bytes(...) + os.chmod(...) nearby"))
                        break
    return hits[:MAX_HITS_PER_SCANNER]


def scan_raw_getattr_client(src: Path) -> list[tuple[str, int, str]]:
    """`request.client.host if request.client else <fallback>` — request_meta bypass."""
    hits = []
    _pat = re.compile(r"request\.client\.host\s+if\s+request\.client")
    for p in _iter_python(src):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if _pat.search(line):
                hits.append((str(p.relative_to(src.parent)), lineno,
                             "request.client.host if request.client (N-187)"))
    return hits[:MAX_HITS_PER_SCANNER]


def scan_aliased_import_asname(src: Path) -> list[tuple[str, int, str]]:
    """`from X import Y as _Y` — potential detector-bypass. Flag only when the
    aliased name matches a known SSOT-y pattern (`_ssot`, `_manageable`, `_gate`)."""
    hits = []
    known_prefixes = ("_manageable_", "_gate_", "_ssot_", "_can_manage")
    for p in _iter_python(src):
        got = _read_tree(p)
        if got is None:
            continue
        _, tree = got
        for node in tree.body:
            if not isinstance(node, ast.ImportFrom):
                continue
            for alias in node.names:
                if alias.asname is None:
                    continue
                if any(alias.asname.startswith(pfx) for pfx in known_prefixes):
                    hits.append((str(p.relative_to(src.parent)), node.lineno,
                                 f"{alias.name} as {alias.asname}"))
    return hits[:MAX_HITS_PER_SCANNER]


def scan_pin_harness_adoption(
    src: Path, tests_dir: Path | None = None
) -> list[tuple[str, int, str]]:
    """New-pin harness drift — grounded 2026-07-09 drain-audit pin.

    Walks `tests/*_pin.py` for files that hand-roll the walk/relpath
    boilerplate — `.rglob("*.py")`, `.relative_to(...)`, or
    `.replace("\\", "/")` — patterns the shared `tests/_pin_harness.py`
    module SSOTs (`iter_py_files`, `relpath`). PARTIAL adoption is
    ALSO a drift class: the drain-audit pin at `da40ebd8` imported
    `_pin_harness` for `SRC_ROOT` but still hand-rolled `.relative_to()`,
    forcing fix-forward `5423c633` + teeth `864bee86` after CI-RED on
    `46dd4433`. So the scanner does NOT gate on "imports harness";
    every drift-shape is emitted with `imports_harness=T|F` in the
    snippet so the synthesizer can rank (F = never adopted, urgent;
    T = partial adoption, review).

    `feedback_meta_pins_gate_new_pin_pushes` REQUIRES the meta-pin
    `test_pin_harness_adoption.py` as a pre-push sweep; this scanner
    promotes that gate into a discover-tier pre-flag so a NEW pin's
    drift surfaces before the push, not after CI-RED.
    """
    if tests_dir is None:
        repo_root = Path(__file__).resolve().parent.parent
        tests_dir = repo_root / "tests"
    else:
        repo_root = tests_dir.parent
    if not tests_dir.is_dir():
        return []
    hits: list[tuple[str, int, str]] = []
    # RECURSIVE — walk tests/test_web/*_pin.py too. The panel's devils-advocate
    # caught a non-recursive `glob` here that was structurally BLIND to the
    # tests/test_web/ subtree, hiding 2 hand-rolled sites (PD#7 census-the-
    # censusers failure — the scanner IS this class's census, itself un-scoped).
    for p in tests_dir.rglob("*_pin.py"):
        if p.name == "_pin_harness.py":
            continue
        if "__pycache__" in p.parts:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        imports_harness = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "_pin_harness" in node.module:
                imports_harness = True
                break
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "_pin_harness" in (alias.name or ""):
                        imports_harness = True
                        break
                if imports_harness:
                    break
        harness_tag = "PARTIAL-adopt" if imports_harness else "NON-adopt"
        for node in ast.walk(tree):
            snippet = None
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr == "rglob":
                    snippet = f"[{harness_tag}] hand-rolled .rglob() — use _pin_harness.iter_py_files"
                elif attr == "relative_to":
                    snippet = f"[{harness_tag}] hand-rolled .relative_to() — use _pin_harness.relpath"
                elif attr == "replace" and len(node.args) == 2:
                    arg0 = node.args[0]
                    if (isinstance(arg0, ast.Constant) and isinstance(arg0.value, str)
                            and arg0.value in ("\\", "\\\\")):
                        snippet = f"[{harness_tag}] hand-rolled .replace('\\','/') — use _pin_harness.relpath"
            if snippet:
                try:
                    rel = p.relative_to(repo_root).as_posix()
                except ValueError:
                    rel = str(p)
                hits.append((rel, node.lineno, snippet))
                # N.B.: NO break. A single file can have several sites; a
                # per-file break silently masked 3 secondary sites during
                # the initial N-382 migration (test_account_hipaa_scope_pin
                # line 267 + 779, test_n157_cli_admin_op_via_emitter_ssot
                # line 66 + 97, test_ssot_registry_bijection_pin line 92 +
                # 232). Emit every site; the synthesizer clusters by file.
    return hits[:MAX_HITS_PER_SCANNER]


SCANNERS = {
    "boolop_isoformat": scan_boolop_isoformat,
    "try_int_valueerror": scan_try_int_valueerror,
    "write_bytes_then_chmod": scan_write_bytes_then_chmod,
    "raw_getattr_client": scan_raw_getattr_client,
    "aliased_import_asname": scan_aliased_import_asname,
    "pin_harness_adoption": scan_pin_harness_adoption,
}


DISCOVER_SCHEMA = {
    "type": "object",
    "required": ["candidate_classes"],
    "properties": {
        "candidate_classes": {
            "type": "array",
            "description": "Up to 6 NEW divergence-class candidates the scanner hits suggest.",
            "items": {
                "type": "object",
                "required": ["name", "shape", "why_worth_seeding"],
                "properties": {
                    "name": {"type": "string",
                             "description": "Short kebab-case class name."},
                    "shape": {"type": "string",
                              "description": "The AST shape or grep signature."},
                    "why_worth_seeding": {"type": "string",
                                          "description": "One line: what defect it hunts for."},
                    "sample_sites": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", type=Path, default=Path("src/email_triage"))
    ap.add_argument("--scanners", default="",
                    help="comma-list of scanners to run (default: all)")
    args = ap.parse_args(argv)
    chosen = ([s.strip() for s in args.scanners.split(",") if s.strip()]
              if args.scanners else list(SCANNERS.keys()))
    per_scanner: dict[str, list] = {}
    for name in chosen:
        fn = SCANNERS.get(name)
        if fn is None:
            per_scanner[name] = [{"error": f"unknown scanner: {name}"}]
            continue
        hits = fn(args.src)
        per_scanner[name] = [
            {"file": f, "line": ln, "snippet": s} for f, ln, s in hits
        ]
    compact = "\n".join(
        f"[{name}] {len(rows)} hits: "
        + ", ".join(f"{r.get('file')}:{r.get('line')}" for r in rows[:6])
        for name, rows in per_scanner.items()
    )
    if len(compact) > MAX_INPUT_BYTES:
        compact = compact[:MAX_INPUT_BYTES]
    try:
        summary = call_leira(
            prompt=(
                "You are proposing NEW divergence-census candidate classes from AST-scanner "
                "hits. For each candidate: (1) shortName (kebab), (2) AST shape or grep "
                "signature, (3) one-line 'why worth seeding'. Cap at 6. Skip a scanner if its "
                "hit count is 0 or ≤2 (not a class-worth of drift).\n\n"
                f"Scanner hits:\n{compact}"
            ),
            schema=DISCOVER_SCHEMA,
        )
        # Enrich each candidate with the raw hits.
        for cand in summary.get("candidate_classes", []):
            cand["sample_sites"] = [
                f"{r['file']}:{r['line']}" for name, rows in per_scanner.items()
                if any(cand["name"].split("-")[0] in n for n in name.split("_"))
                for r in rows[:6]
            ]
    except OllamaCallError as e:
        summary = {"candidate_classes": [], "leira_error": str(e)}
    out = {"scanners": per_scanner, "candidate_classes":
           summary.get("candidate_classes", [])}
    if summary.get("leira_error"):
        out["leira_error"] = summary["leira_error"]
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
