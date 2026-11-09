"""Structural pin (census wf_56d1585d 2026-07-09 HIGH  — canonical-email
bypass): a `.strip().lower()` chain in `web/routers/**` outside a fn that
also references `canonical_email` is a §164.312(a)(1) permission-actuator /
authenticator input-normalisation defect by shape.

What this defends
-----------------
The class the census caught at `web/routers/ui/accounts.py:2317` and
extended to `web/routers/auth_keys.py:772 / 1274 / 575`:

- One side of an email compare goes through `canonical_email` (stdlib
  IDNA-2003 (RFC 3490) + lowercase; the SSOT — see mail_headers.py:249-268
  which self-corrects an earlier UTS-46 docstring claim), the other side
  goes through `.strip().lower()` (basic lowercase only).
- The two normalisations DIVERGE on IDN aliases (`Name <a@münchen.de>`)
  and display-wrapped aliases (`Name <john@x.com>`).
- The actuator either fails FORWARD-OPEN (revoke silently no-ops → aliases
  keep their access;  accounts.py exact class) OR fails FORWARD-CLOSED
  (legit IDN user can't log in; auth_keys.py class).

Both classes are §164.312(a)(1) permission-actuator defects by shape. This
pin makes the shape a build-failure.

Count-agnostic
--------------
Per ``pattern_count_agnostic_structural_drift_catch.md`` — asserts a
PROPERTY (no `.strip().lower()` outside `canonical_email` context inside
`web/routers/**`), not a count. A new site added tomorrow trips the same
shape.

Scope
-----
`web/routers/**` only — where email actuators / authenticators live. A
`.strip().lower()` in `db/`, `providers/`, `actions/`, `style_learning/`
is often a legitimate hash-index / display-lowercase / sort-key
normalisation, not an email compare — those are outside scope.

Allow-list
----------
`_ALLOWED_CANONICAL_BYPASSES` is the explicit, documented set of
`(relpath, funcname)` exemptions for legit `.strip().lower()` chains
inside `web/routers/**` that are provably NOT email-compares (CLI-ident
construction, code / token normalisation that ships a hex string, etc.).
Each entry carries a one-line justification.

SCOPE CAVEAT — known false-negative surface (DA-fold R2 2026-07-09)
-------------------------------------------------------------------
This pin is AST-receiver-substring based and inherits three residuals
the docstring MUST disclose (Prime Directive #7 — census the censusers):

1. **Aliased dataflow bypass.** A trivial variable rename hides the
   receiver from the marker match: ``e = form.get('email');
   e.strip().lower()`` — the ``.strip().lower()`` receiver is bare ``e``,
   which contains no email-shape marker → MISSED. The pin only sees the
   IMMEDIATE receiver expression; it does not chase name-bindings back
   to their source. A dedicated dataflow pin would be a distinct build.

2. **Lambda / helper wrapper bypass.** ``_norm = lambda s:
   s.strip().lower()`` applied downstream to an email is invisible: the
   ``.strip().lower()`` chain lives inside the lambda body whose receiver
   is bare ``s``. Same class as #1 (interprocedural bypass).

3. **Out-of-scope siblings.** The pin scopes to ``web/routers/**`` (the
   HTTP surface). ``.strip().lower()`` chains inside
   ``web/{login_guard,topic_digest_sender,email_watches,db,digest}.py``
   / ``providers/`` / ``actions/`` / ``style_learning/`` are NOT
   audited by this pin. Many of those are legitimate (hash-key
   normalisation, sort keys, prefilter needles) but a real email compare
   in one would slip. Census  scoped only the HTTP surface; a
   sibling-tree drive would extend.

These are DECLARED holes; a future census re-audits with a wider net
(interprocedural + tree-wide) as its own drive.

Meta-drift guarantee (PD#7)
---------------------------
Routes the walk through `_pin_harness.iter_src_files` + `parse_module` +
`relpath` so the pin cannot drift in its scoping.
"""
from __future__ import annotations

import ast

from _canonical_email_pin_predicates import (
    fn_calls_canonical_email,
    is_email_shape,
    is_strip_lower_chain,
)
from _pin_harness import (
    annotate_parents,
    enclosing_fn,
    innermost_fn_at_lineno,
    iter_src_files,
    parse_module,
    relpath,
    parse_source,
)


# (relpath, funcname) exemptions. Each MUST have a same-line comment
# documenting WHY the .strip().lower() is provably NOT an email compare.
_ALLOWED_CANONICAL_BYPASSES: set[tuple[str, str]] = {
    # profile.py:api_keys_create — `alias_raw` is a CLI-ident (`--as me`),
    # not an email compare; it's downstream stripped to alnum + `_-` for
    # shell safety. Wrapping in canonical_email would break the CLI-ident
    # semantics.
    ("web/routers/ui/profile.py", "api_keys_create"),
    # (web/db.py, upsert_gmail_watch) removed 2026-11-05: it writes
    # canonical_email() now, and get_gmail_watch_by_email's dual-shape
    # probe still finds rows written in the legacy shape.
}


# the backlog  — email-shape / .lower() / .strip().lower() /
# canonical_email predicates share ONE source of truth in
# tests/_canonical_email_pin_predicates.py. Sibling pin
# ``test_canonical_email_ssot_providers_pin.py`` imports the same
# predicates. A tightening at N-317 or similar lands in ONE file;
# both pins pick it up (PD#6 pins obey SSOT).


def _fn_containing(tree: ast.AST, node: ast.AST):
    """Return the enclosing ``FunctionDef``/``AsyncFunctionDef`` node via
    the shared harness (:func:`innermost_fn_at_lineno`) — the ONE SSOT for
    "resolve node → enclosing fn node" (harness contract #8; the meta-pin
    ``test_no_v6_handrolled_enclosing_fn_outside_harness`` guards against
    a re-rolled ``_ph_parent`` climb). ``None`` at module scope."""
    return innermost_fn_at_lineno(tree, node.lineno)


def _scan() -> list[tuple[str, int, str]]:
    """Repo-wide scan under ``web/`` (widened from ``web/routers/`` per
    DA-scope-widen census run21 D3 fold, 2026-07-18 — email_watches.py
    at web/ was previously invisible to the pin's file-walk). Returns
    ``[(relpath, lineno, funcname), ...]`` for every non-allowed
    ``.strip().lower()`` chain in a fn that does NOT also call
    ``canonical_email``."""
    offenders: list[tuple[str, int, str]] = []
    for path in iter_src_files("web"):
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        for node in ast.walk(tree):
            if not is_strip_lower_chain(node):
                continue
            # Only flag email/address-shape receivers — a `.strip().lower()`
            # on a category name / label / rule slug is a legit non-email
            # normalisation, not the census-flagged class.
            receiver = node.func.value.func.value  # type: ignore[union-attr]
            if not is_email_shape(receiver):
                continue
            fn = _fn_containing(tree, node)
            if fn is None:
                continue  # module-scope chain — rare, skip
            fn_name = fn.name
            if (rp, fn_name) in _ALLOWED_CANONICAL_BYPASSES:
                continue
            if fn_calls_canonical_email(fn):
                continue
            offenders.append((rp, node.lineno, fn_name))
    return offenders


def test_no_canonical_email_bypass_in_routers():
    """No `.strip().lower()` chain in `web/routers/**` outside a fn that
    references `canonical_email`.

    Failure prints `relpath:lineno in <fn_name>` per violation.
    """
    offenders = _scan()
    if offenders:
        lines = [
            f"  {rp}:{ln} in `{fn}`"
            for rp, ln, fn in offenders
        ]
        raise AssertionError(
            "canonical-email bypass — `.strip().lower()` chain in "
            "`web/routers/**` inside a fn that does NOT also call "
            "`canonical_email(...)`. §164.312(a)(1) shape defect (census "
            "wf_56d1585d 2026-07-09 #319). Route the receiver through "
            "`canonical_email(...)` (stdlib IDNA-2003 + lowercase; see "
            "mail_headers.py:249) so an IDN "
            "or display-wrapped alias matches its stored canonical form.\n\n"
            + "\n".join(lines)
        )


def test_pin_has_teeth():
    """Detector flags a planted bad shape and passes a clean shape."""
    bad = (
        "def revoke_alias(form):\n"
        "    target = (form.get('address') or '').strip().lower()\n"
        "    return target\n"
    )
    good = (
        "def revoke_alias(form):\n"
        "    from x import canonical_email\n"
        "    target = canonical_email(form.get('address') or '')\n"
        "    return target\n"
    )
    good_with_belt = (
        "def revoke_alias(form):\n"
        "    from x import canonical_email\n"
        "    target = canonical_email(form.get('address') or '')\n"
        "    # Defensive belt on already-canonical data — legal.\n"
        "    normalized = target.strip().lower()\n"
        "    return normalized\n"
    )
    bad_tree = parse_source(bad)
    annotate_parents(bad_tree)
    bad_fn = next(
        n for n in ast.walk(bad_tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    bad_hit = any(
        is_strip_lower_chain(n) for n in ast.walk(bad_fn)
    ) and not fn_calls_canonical_email(bad_fn)
    assert bad_hit, "pin missed a planted bad shape (no teeth)"

    for src in (good, good_with_belt):
        tree = parse_source(src)
        annotate_parents(tree)
        fn = next(
            n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        # Either no chain, OR chain in a canonical_email fn (both legal).
        assert fn_calls_canonical_email(fn), \
            "clean fixture must reference canonical_email"


def test_allow_list_is_grounded():
    """Every allow-list entry must correspond to a real `.strip().lower()`
    chain at HEAD in the SAME fn — a stale exemption silently widens the
    net."""
    live: set[tuple[str, str]] = set()
    for path in iter_src_files("web"):
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        for node in ast.walk(tree):
            if not is_strip_lower_chain(node):
                continue
            fn = _fn_containing(tree, node)
            if fn is not None:
                live.add((rp, fn.name))
    stale = _ALLOWED_CANONICAL_BYPASSES - live
    assert not stale, (
        f"Stale _ALLOWED_CANONICAL_BYPASSES entries (no matching HEAD "
        f"chain — delete): {sorted(stale)}"
    )


def test_ssot_is_reachable():
    """Anti-vacuity: `canonical_email` must import + be a callable."""
    from email_triage.mail_headers import canonical_email
    assert callable(canonical_email)
