"""N-226 R22 structural pin — effective-HIPAA fold: forbid raw `bool(<x>.get('hipaa'))` (2026-07-02).

Census R22 (run22 discovered class — MED, HIPAA-load-bearing) flagged 3
sites in `web/routers/ui/profile.py` (:1059 style-data export payload;
:4404 `_hit_from_verdict` topic-preview hit; :4449 `_hit_from_keyword`
topic-preview hit) that computed the per-hit HIPAA flag as bare
`bool(acct.get("hipaa"))` — bypassing the fold SSOT
`triage_logging.is_account_hipaa(account)` which returns
`system_hipaa OR account.hipaa` (most-restrictive-wins).

CONSEQUENCE: on a `system_hipaa=True` install with `acct.hipaa=0`, these
sites emit `hipaa: false` — the template redaction gate then reads
`hit.hipaa` as False and presents PHI-in-clear, contradicting the
install-wide compliance flag.

ADOPTION: N-226 landed 3 profile.py migrations to `is_account_hipaa`.

WHAT IT PINS (count-agnostic, tree-wide):

Every `bool(<x>.get("hipaa"))` and `bool(<x>["hipaa"])` call outside the
SSOT (`triage_logging.py`) and its 2 documented flag-diff sites
(`accounts.py::_maybe_upgrade_hipaa` "was_hipaa" diff) fires the pin.
Scoped to the `hipaa` key — a different key (say `is_admin`) has its own
SSOT + pin (N-222).

The 2 documented allow-list entries are the flag-DIFF sites: they need
to compare the ACCOUNT COLUMN alone (not the folded state) so a system-
hipaa-OFF-but-account-hipaa-ON transition is detected. Those explicitly
read `.get("hipaa")` and are correct.

SCOPE CAVEAT: matches `bool(<Name>.get("hipaa"))` /
`bool(<Name>["hipaa"])` shapes only. A future indirection (helper var,
`.pop("hipaa")`, `.get("hipaa", 0)` with a default) sneaks past — extend
the detector when a new shape surfaces.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_FILES = {"triage_logging.py"}

# Allow-list: sites that legitimately need the ACCOUNT COLUMN alone (not
# the fold), so a system-hipaa-OFF-but-account-hipaa-ON transition is
# detectable. All entries carry a comment explaining WHY the raw read is
# intentional at that seam.
_ALLOW = frozenset({
    # `accounts.py::_maybe_upgrade_hipaa` — was-hipaa flag-diff must read
    # the account column alone (fold would collapse system_hipaa-on
    # accounts into "always was", missing the transition edge).
    ("web/routers/ui/accounts.py", "was_hipaa"),
    # `db/accounts.py::set_account_hipaa` — flag-flip guard "already in
    # requested state" must read the column alone.
    ("db/accounts.py", "current"),
    # `_shared.py` HIPAA-mode flip gate — reads settings/runtime config
    # (not an account), fold isn't applicable.
    ("web/routers/ui/_shared.py", "new_hipaa"),
    # `admin.py` runtime-config assemble — this is the DB-locked-section
    # write shape (see comment at site); reads runtime, not an account.
    # No assign target (it's a Dict value), so allow-list by (path, None).
    ("web/routers/ui/admin.py", None),
    # `web/app.py` lifespan restore (N-471 fold) — reads the SYSTEM
    # runtime-settings row to set the process-global HIPAA flag. There is
    # no account in scope at boot, so `is_account_hipaa(account)` has no
    # argument to take and the fold is not applicable; this IS the write
    # that establishes the system half the fold would later read. Keyed on
    # the named local deliberately: the assignment's real target is the
    # Attribute `triage_logging._hipaa_mode`, which resolves to None and
    # would exempt the whole file.
    ("web/app.py", "system_hipaa_from_row"),
})


def _has_hipaa_bool_read(call: ast.Call) -> tuple[bool, str | None]:
    """True if `call` is `bool(<x>.get("hipaa"))` or `bool(<x>["hipaa"])`.
    Returns (matched, target_var_name) for allow-list keying."""
    if not (isinstance(call.func, ast.Name) and call.func.id == "bool"):
        return False, None
    if len(call.args) != 1:
        return False, None
    inner = call.args[0]
    # `<x>.get("hipaa")` — check arg[0] Constant
    if (isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Attribute)
            and inner.func.attr == "get"
            and inner.args
            and isinstance(inner.args[0], ast.Constant)
            and inner.args[0].value == "hipaa"):
        name = (inner.func.value.id
                if isinstance(inner.func.value, ast.Name) else None)
        return True, name
    # `<x>["hipaa"]` subscript
    if isinstance(inner, ast.Subscript):
        sl = inner.slice
        if isinstance(sl, ast.Constant) and sl.value == "hipaa":
            name = inner.value.id if isinstance(inner.value, ast.Name) else None
            return True, name
    return False, None


def _find_enclosing_assign_target(node: ast.AST, tree: ast.AST) -> str | None:
    """Return the ast.Name target if `node` sits at the value of an
    Assign/AnnAssign whose LHS is a bare Name (used for allow-list key)."""
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            if child is node and isinstance(parent, (ast.Assign, ast.AnnAssign)):
                if isinstance(parent, ast.Assign):
                    for tgt in parent.targets:
                        if isinstance(tgt, ast.Name):
                            return tgt.id
                elif isinstance(parent.target, ast.Name):
                    return parent.target.id
    return None


def test_no_raw_bool_hipaa_read_outside_ssot():
    """Every `bool(<x>.get("hipaa"))` / `bool(<x>["hipaa"])` tree-wide
    (outside `triage_logging.py` + 2 documented flag-diff sites) fires."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            matched, _ = _has_hipaa_bool_read(node)
            if not matched:
                continue
            # Check allow-list: (relpath, assign-target-name) OR
            # (relpath, None) as a file-level fallback for shapes without a
            # bare-Name assign target (Dict values, tuple returns, etc.).
            target = _find_enclosing_assign_target(node, tree)
            if (rel, target) in _ALLOW or (rel, None) in _ALLOW:
                continue
            offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "N-226 R22 effective-HIPAA fold: raw `bool(<x>.get('hipaa'))` "
        "or `bool(<x>['hipaa'])` outside `triage_logging.py`. Route through "
        "`triage_logging.is_account_hipaa(account)` which folds the system "
        "flag (`system_hipaa`) OR the account column — most-restrictive-wins. "
        "The raw read leaks PHI-in-clear on a system_hipaa install with an "
        "acct.hipaa=0 account (template redaction gate reads the wrong bit).\n\n"
        "If a NEW site legitimately needs the account column ALONE (a "
        "flag-diff seam), add it to `_ALLOW` with a comment explaining why.\n\n"
        + "\n".join(offenders)
    )


def test_ssot_is_reachable():
    """Anti-vacuity: `triage_logging.is_account_hipaa` must exist. If it
    was renamed, downstream migrations shouldn't build on a stale name."""
    from email_triage.triage_logging import is_account_hipaa
    assert callable(is_account_hipaa)
    # Sanity: fold semantics — with system_hipaa off, empty dict → False.
    assert is_account_hipaa({}) is False
