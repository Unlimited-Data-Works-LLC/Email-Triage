"""N-369b — Structural-superset check for the divergence census (PD #7).

Per Census run22 §7#5 methodology bake-in
(`scripts/workflows/et-divergence-census-llm-host.js:46-51`):

    A companion script `structural_superset_check.py` derives the
    enumeration net INDEPENDENTLY from the class-hint (e.g. "every
    abstract method on the named protocol class", "every
    `@decorator`-marked callable") and asserts the census's
    enumeration is ⊇ this independent set. Census-the-censusers
    with a SECOND census.

CONTRACT.  For every seeded divergence-census class key registered
here, this script re-derives the enumeration net STRUCTURALLY from
the codebase — not from the census's class-hint attr-set. When a
census run's hit-list is passed in via `--census`, the script prints
the (derived − census) gap: sites the STRUCTURAL walk found that the
census enumeration did NOT surface. A non-empty gap is a
`NET-INCOMPLETE` census (per methodology §7#7) and MUST be reported
to the operator before the census's class-level count is trusted.

WHY THIS EXISTS.  The census workflow's SME agents each carry their
own attr-set / hint / grep pattern in the class hint. When the hint's
seed-set is under-derived (the pre-N-368 provider-fetch class hint
missed `list_folders` × 9 sites — a 36% V0 undercount), the census's
enumeration is silently short. The structural walk here is
DELIBERATELY INDEPENDENT — it does not read the census's class hint
at all; it derives from the source-of-truth surface (an ABC's
abstract methods, a decorator's applied sites, an SSOT's callees).
Two independent walks agreeing is the closed-loop proof PD #7 asks
for; disagreement is the drift signal.

STRATEGY REGISTRY.  Two strategies land in this initial N-369b
tranche (proof-of-concept; the registry grows per new class):

    provider-fetch — walk `providers/base.py::EmailProvider` ABC,
        collect every `async def` NAME (abstract + concrete methods
        the ABC exposes); union with subclass NAMES from every
        `providers/*.py` module (so a subclass-only widening like
        `ImapProvider.search_all_folders` still enters the derived
        set). The census's `provider-fetch` class hint MUST cover
        every returned name, else NET-INCOMPLETE.

    audit-emit — reuse `_pin_harness.audit_emitter_names` +
        `discover_audit_emitter_modules` to enumerate every
        `@audit_emitter`-decorated callable across src. The census's
        `audit-emit` enumeration MUST include every returned name.

USAGE:
    python scripts/structural_superset_check.py --class provider-fetch
    python scripts/structural_superset_check.py --class audit-emit
    python scripts/structural_superset_check.py --class provider-fetch \\
        --census census_hits.txt   # one member per line
    python scripts/structural_superset_check.py --list

Exits non-zero when a census-hits file is supplied AND the derived
set is NOT a subset of it (methodology §7#7 NET-INCOMPLETE). Without
`--census`, prints the derived set and exits 0 — a discovery /
priming call before a census run.

RESIDUAL (honest).  This script is a companion, NOT a CI-gated pin.
The census workflow does not import it. It IS an operator-runnable
tool the census SME agents can call INSIDE a Discover-phase probe
(methodology §7#6 inversion probe class) as an independent second
census. That composition is deferred to a follow-up: today the
script is a standalone CLI + the two proof-of-concept strategies.
Adding a strategy per new class is a one-function change against the
`_STRATEGIES` registry below.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

# The package root (mirrors `_pin_harness.SRC_ROOT` — kept local so a
# missing test-tree in a slim checkout does not sink the script).
_HERE = Path(__file__).resolve()
_SRC_ROOT = _HERE.parents[1] / "src" / "email_triage"


def _parse(path: Path) -> ast.AST | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None


def _iter_src(subdir: str = ""):
    base = _SRC_ROOT if not subdir else _SRC_ROOT / subdir
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        yield path


# ---------------------------------------------------------------------------
# provider-fetch strategy
# ---------------------------------------------------------------------------


def _derive_provider_fetch() -> set[str]:
    """Union of every `async def` NAME on `EmailProvider` (the ABC at
    `providers/base.py`) plus every `async def` NAME on any subclass
    across `providers/*.py`. The class-hint's public-API attr-set
    MUST cover this union. A future abstract method added to the ABC
    or a subclass-only widening (e.g. `ImapProvider.search_all_folders`)
    lands here automatically — no hardcode."""
    names: set[str] = set()
    for path in _iter_src("providers"):
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # Detect EmailProvider ABC + any subclass. A conservative
            # detector: the class inherits from `EmailProvider` or `ABC`
            # OR names one of them in its bases chain. The census cares
            # about the concrete PROVIDER surface — narrow to classes
            # that resemble a provider (name ends in `Provider` OR the
            # ABC itself).
            base_names = {
                b.id for b in node.bases if isinstance(b, ast.Name)
            } | {
                b.attr for b in node.bases if isinstance(b, ast.Attribute)
            }
            is_provider = (
                node.name == "EmailProvider"
                or node.name.endswith("Provider")
                or bool(base_names & {"EmailProvider", "ABC"})
            )
            if not is_provider:
                continue
            for member in node.body:
                if isinstance(member, (ast.AsyncFunctionDef, ast.FunctionDef)):
                    # dunder init / abstract-only helpers stay in — the
                    # census's V0 undercount was on real method NAMES,
                    # not on `__init__` shape.
                    if member.name.startswith("_") and member.name != "__init__":
                        continue
                    names.add(member.name)
    return names


# ---------------------------------------------------------------------------
# audit-emit strategy
# ---------------------------------------------------------------------------


def _derive_audit_emit() -> set[str]:
    """Union of every `@audit_emitter`-decorated def across src.
    Reuses the harness idiom (tests/_pin_harness.py::audit_emitter_names
    is the pin-side companion; the script here inlines the same walk
    so the companion is standalone — a slim checkout with tests/
    stripped still runs it). Includes `chain_writer_names()` — the
    log_entries chain-primitive helpers that are NOT `@audit_emitter`
    decorated but ARE part of the audit-emit class per N-182 R20_7
    (`insert_log_entry`, `_chain_insert`)."""
    names: set[str] = set()
    for path in _iter_src():
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                dname = (
                    dec.id if isinstance(dec, ast.Name)
                    else dec.attr if isinstance(dec, ast.Attribute) else None
                )
                if dname == "audit_emitter":
                    names.add(node.name)
                    break
    # N-182 R20_7 chain-primitive union.
    names |= {"insert_log_entry", "_chain_insert"}
    return names


# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------


_STRATEGIES = {
    "provider-fetch": (
        _derive_provider_fetch,
        "Every `async def` on `EmailProvider` ABC + every subclass "
        "override across `providers/*.py`. Class-hint at "
        "`scripts/workflows/et-divergence-census-llm-host.js` under key "
        "`provider-fetch` MUST cover this union (N-368 baseline).",
    ),
    "audit-emit": (
        _derive_audit_emit,
        "Every `@audit_emitter`-decorated callable across src + the "
        "chain-primitive union `{insert_log_entry, _chain_insert}` "
        "(N-182 R20_7). Census `audit-emit` class MUST cover this.",
    ),
}


def _list_strategies() -> int:
    for key, (_, description) in sorted(_STRATEGIES.items()):
        print(f"{key}:\n  {description}\n")
    return 0


def _load_census(path: Path) -> set[str]:
    return {
        line.strip() for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def _run(class_key: str, census_path: Path | None) -> int:
    if class_key not in _STRATEGIES:
        print(f"ERROR: unknown class key '{class_key}'", file=sys.stderr)
        print("Known keys:", ", ".join(sorted(_STRATEGIES)), file=sys.stderr)
        return 2
    derive, _description = _STRATEGIES[class_key]
    derived = derive()
    print(f"[{class_key}] DERIVED SUPERSET ({len(derived)} members):")
    for name in sorted(derived):
        print(f"  {name}")
    if census_path is None:
        return 0
    census = _load_census(census_path)
    missing = derived - census
    extra = census - derived
    print()
    print(f"[{class_key}] CENSUS INPUT: {len(census)} members from {census_path}")
    if missing:
        print(f"[{class_key}] NET-INCOMPLETE — census MISSED "
              f"{len(missing)} members:")
        for name in sorted(missing):
            print(f"  - {name}")
    if extra:
        print(f"[{class_key}] CENSUS EXTRA (not in derived — likely OK, "
              f"census may be wider than the structural walk): "
              f"{len(extra)} members")
        for name in sorted(extra):
            print(f"  + {name}")
    if missing:
        print(f"[{class_key}] STATUS = NET-INCOMPLETE (per methodology "
              "§7#7). Fix the census class-hint before trusting the "
              "class-level count.")
        return 1
    print(f"[{class_key}] STATUS = CLOSED (structural walk ⊆ census).")
    return 0


def _cli() -> int:
    ap = argparse.ArgumentParser(
        prog="structural_superset_check.py",
        description=("N-369b: derive the structural-superset enumeration "
                     "net INDEPENDENTLY from a census class-hint."),
    )
    ap.add_argument(
        "--class", dest="class_key", metavar="KEY",
        help="Census class key to check (e.g. provider-fetch). "
             "Run with --list for a full registry.",
    )
    ap.add_argument(
        "--census", metavar="PATH", type=Path,
        help="Optional census-hits file (one member per line, "
             "'#' comments allowed). Non-zero exit when the derived "
             "set is NOT a subset of the census.",
    )
    ap.add_argument(
        "--list", action="store_true",
        help="List known class keys + strategy descriptions.",
    )
    args = ap.parse_args()
    if args.list:
        return _list_strategies()
    if not args.class_key:
        ap.print_help()
        return 2
    return _run(args.class_key, args.census)


if __name__ == "__main__":
    sys.exit(_cli())
