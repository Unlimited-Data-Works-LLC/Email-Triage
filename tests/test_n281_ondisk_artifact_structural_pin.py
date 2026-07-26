"""N-281 R29 structural pin — ondisk-artifact builder registry (2026-07-03).

R29 census MED #2 (ondisk-artifact-disposal): the existing N-245 pin
tests registry-MEMBERSHIP via a K=1 name-list check
(`msal_cache_path_for_account in PER_ACCOUNT_ARTIFACT_BUILDERS`). A
THIRD per-id Path-returning builder function could ship without a
registry row + the pin would stay green — the N-150 recurrence shape.

N-281 lands a STRUCTURAL AST-walk pin: any `FunctionDef` in the
providers/ subtree that:
  - has a name matching `*_path*` OR `*_cache_path*` OR `*_artifact_path*`
    OR `dispose_*`
  - AND takes an `account_id` OR `username` positional/kw arg
  - AND its body imports `pathlib.Path` OR returns a `Path(...)` /
    `Path` name expression
must be either IN the registry name-list OR in a narrow ALLOW-list
of intentional non-registry cases.

This catches a NEW builder shipping without a registry row — the
K=1 name-list membership can't.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_REGISTRY_NAMES: set[str] = set()


def _load_registry():
    """Pull all registered builder function NAMES from the SSOT so
    the pin follows the registry — never hand-copied."""
    global _REGISTRY_NAMES
    if _REGISTRY_NAMES:
        return _REGISTRY_NAMES
    from email_triage.providers._ondisk_artifacts import (
        PER_ACCOUNT_ARTIFACT_BUILDERS,
        PER_USER_ARTIFACT_BUILDERS,
    )
    for fn in list(PER_ACCOUNT_ARTIFACT_BUILDERS) + list(PER_USER_ARTIFACT_BUILDERS):
        name = getattr(fn, "__name__", "")
        if name:
            _REGISTRY_NAMES.add(name)
    return _REGISTRY_NAMES


# Narrow ALLOW-list for intentional non-registry builders. Empty by
# default — a new entry should be a deliberate operator/SME decision.
_ALLOW_UNREGISTERED: set[str] = {
    # N-356 R31 (2026-07-05): CLI-scoped disposer, not a per-id (account_id)
    # Path builder. Trips the heuristic (name starts with `dispose_`, takes
    # `username`, body constructs a Path) but is intentionally not in
    # `PER_*_ARTIFACT_BUILDERS` — the CLI cache path is username-keyed,
    # not account_id-keyed, and is invoked by the CLI logout flow rather
    # than the per-account §164.310(d)(2)(i) disposal sweep. See
    # `providers/factory.py::dispose_msal_cache_for_cli` docstring for
    # full grounding.
    "dispose_msal_cache_for_cli",
}


def _fn_signature_takes_account_id_or_username(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    args = node.args
    all_args = list(args.args) + list(args.posonlyargs) + list(args.kwonlyargs)
    return any(a.arg in ("account_id", "username") for a in all_args)


def _fn_returns_path(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Body contains a `Path(...)` call OR a `return <expr>` where
    <expr> textually references Path."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name) and f.id == "Path":
                return True
            if isinstance(f, ast.Attribute) and f.attr == "Path":
                return True
        # A return-annotation of Path is also a signal.
    ret = node.returns
    if isinstance(ret, ast.Name) and ret.id == "Path":
        return True
    if isinstance(ret, ast.Attribute) and ret.attr == "Path":
        return True
    return False


def test_per_id_path_builders_are_in_registry():
    """Any Path-returning function with an `account_id` or `username`
    parameter in the `providers/` subtree must be in the registry name-
    list (or an intentional allow-list entry). Catches a new builder
    that ships without a registry row."""
    reg = _load_registry()
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if not rel.startswith("providers/"):
            continue
        # The SSOT itself defines the builders it registers.
        if rel.endswith("/_ondisk_artifacts.py"):
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name
            # Naming heuristic — filter to shapes that could plausibly
            # be per-id Path builders.
            if not (
                "cache_path" in name
                or "artifact_path" in name
                or name.startswith("dispose_")
                or name.endswith("_path_for_account")
                or name.endswith("_path_for_user")
            ):
                continue
            if not _fn_signature_takes_account_id_or_username(node):
                continue
            if not _fn_returns_path(node):
                continue
            if name in reg or name in _ALLOW_UNREGISTERED:
                continue
            offenders.append(f"{rel}:{node.lineno} ({name})")
    assert not offenders, (
        "N-281 R29 ondisk-artifact structural pin: per-id Path-"
        "returning builder(s) not in `PER_*_ARTIFACT_BUILDERS`. Add "
        "them to the registry in `providers/_ondisk_artifacts.py` "
        "so `dispose_all_per_account_artifacts` +\n"
        "`dispose_all_per_user_artifacts` fold them into the "
        "§164.310(d)(2)(i) disposal sweep. Recurrence shape from "
        "N-150.\n\n"
        + "\n".join(offenders)
    )
