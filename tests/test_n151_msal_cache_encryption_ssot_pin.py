"""N-151 SSOT structural pin (2026-07-08).

Enforces: any I/O on an ``msal_cache_path_for_{account,cli}(...)``-derived
Path MUST route through the ``providers._msal_cache_crypto`` envelope —
NEVER raw ``.read_text()`` / ``.write_text()`` / ``atomic_write_text`` on
the plaintext.

Two legal I/O sites in the tree:

* ``providers/office365.py::Office365Provider._init_cache`` — reads via
  ``.read_bytes()`` and hands to ``decrypt_cache`` (fail-CLOSED).
* ``providers/office365.py::Office365Provider._save_cache`` — encrypts
  via ``encrypt_cache`` then writes via ``atomic_write_bytes``.

Anything else is drift.  A future dispose call site is EXEMPT because it
only ``.unlink()``s the file — that's covered by N-236's dispose SSOT
pin, not this one.

WHAT IT PINS (count-agnostic, interprocedural on the same enclosing fn):

For every ``*.py`` under ``src/email_triage`` (harness `iter_src_files`):

  1. Locate assignments ``X = msal_cache_path_for_{account,cli}(...)``.
  2. In the same enclosing function, if ANY of
     ``X.read_text() / X.read_bytes() / X.write_text(...) / X.write_bytes(...)``
     or ``atomic_write_text(X, ...) / atomic_write_bytes(X, ...)`` appears,
     the enclosing (relpath, fn_name) pair MUST be one of:

        (providers/office365.py, _init_cache)
        (providers/office365.py, _save_cache)

     — anything else fires.

Anti-vacuity: BOTH allow-listed sites MUST exist in the tree (guarantees
the pin sees real I/O, not just an empty forest).

Documented scope-boundary (N-151 DA fold P5) — evasion classes this pin
does NOT catch, complementary to N-335b's function-scope SHADOW-import
walker (which does catch them at the import layer):

  * Module-level import ALIAS: ``from providers.factory import
    msal_cache_path_for_account as _mcpa`` — CAUGHT here via
    ``_module_alias_map``.
  * Bound-attribute rename: ``mcpa = factory.msal_cache_path_for_account;
    mcpa(id)`` — NOT caught; a future edit would evade this pin but
    still trip N-335b if it introduced a new import surface.
  * getattr shape: ``getattr(factory, "msal_cache_path_for_account")(id)``
    — NOT caught; no realistic call site today.

Widening to close both residual shapes is queued as N-151-fu and depends
on landing an interprocedural Name → helper resolver (either extending
N-335b or reusing its harness per PD #6 — one shared harness for pin
scoping).
"""
from __future__ import annotations

import ast
from typing import Iterable

from _pin_harness import iter_src_files, parse_module, relpath


_PATH_BUILDER_NAMES = frozenset({
    "msal_cache_path_for_account",
    "msal_cache_path_for_cli",
})
_LEGAL_SITES = frozenset({
    ("providers/office365.py", "_init_cache"),
    ("providers/office365.py", "_save_cache"),
})
_IO_ATTRS = frozenset({"read_text", "read_bytes", "write_text", "write_bytes"})
_IO_FUNCS = frozenset({"atomic_write_text", "atomic_write_bytes"})


def _module_alias_map(tree: ast.AST) -> set[str]:
    """N-151 db-sme fold #3: collect module-level ``from providers.factory
    import msal_cache_path_for_account [as X]`` aliases.  Without this,
    a future rename (``from providers.factory import
    msal_cache_path_for_account as _mcpa``) would bind a Name the raw
    ``f.id in _PATH_BUILDER_NAMES`` check misses — exactly the class of
    SHADOW-import evasion N-335b was landed to close."""
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        # Only care about the two builders; module path doesn't matter
        # (a relative or absolute import equally binds the name locally).
        for alias in node.names:
            if alias.name in _PATH_BUILDER_NAMES:
                aliases.add(alias.asname or alias.name)
    return aliases | _PATH_BUILDER_NAMES


def _is_path_builder_call(node: ast.AST, allowed_names: set[str]) -> bool:
    """True if ``node`` is a call to one of the ``msal_cache_path_for_*``
    helpers — bare Name (possibly under a module-level import alias) or
    ``factory.msal_cache_path_for_*`` attribute access."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name):
        return f.id in allowed_names
    if isinstance(f, ast.Attribute):
        return f.attr in _PATH_BUILDER_NAMES
    return False


def _collect_msal_path_bindings(fn: ast.AST, allowed_names: set[str]) -> set[str]:
    """Return the set of local Name identifiers in ``fn`` that were
    assigned from a ``msal_cache_path_for_*(...)`` call in ``fn``'s body.

    Handles ``X = f(...)``, ``X = Path(str(f(...)))``,
    ``self._token_cache_path = f(...)`` (records attribute name too),
    and ``X: str = str(f(...))`` — the common wrappers.  Missed shapes
    are conservative (would fail-open on that site); future extensions
    add via the ``ast.walk`` pass at construction, not here.
    """
    names: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        value = node.value
        if value is None:
            continue
        # Unwrap common wrappers: str(...), Path(...), str(Path(...))
        v = value
        while isinstance(v, ast.Call) and isinstance(v.func, ast.Name) \
                and v.func.id in {"str", "Path"} and v.args:
            v = v.args[0]
        if not _is_path_builder_call(v, allowed_names):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            if isinstance(t, ast.Name):
                names.add(t.id)
            elif isinstance(t, ast.Attribute) and t.attr:
                # e.g. `self._token_cache_path = ...` — record the attr
                names.add(t.attr)
    return names


def _find_illegal_io(
    fn: ast.AST, path_names: set[str],
) -> Iterable[ast.AST]:
    """Yield each I/O call node within ``fn`` that operates on a name in
    ``path_names`` — i.e., an unencrypted read/write of the MSAL cache
    file that ISN'T routed through ``_msal_cache_crypto``."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        # X.read_text() / X.write_bytes(...) / self._token_cache_path.read_bytes()
        if isinstance(f, ast.Attribute) and f.attr in _IO_ATTRS:
            recv = f.value
            recv_name = None
            if isinstance(recv, ast.Name):
                recv_name = recv.id
            elif isinstance(recv, ast.Attribute):
                recv_name = recv.attr
            if recv_name in path_names:
                yield node
        # atomic_write_text(X, ...) / atomic_write_bytes(self._token_cache_path, ...)
        elif isinstance(f, ast.Name) and f.id in _IO_FUNCS:
            if not node.args:
                continue
            arg0 = node.args[0]
            arg_name = None
            if isinstance(arg0, ast.Name):
                arg_name = arg0.id
            elif isinstance(arg0, ast.Attribute):
                arg_name = arg0.attr
            if arg_name in path_names:
                yield node


def test_no_unencrypted_msal_cache_io_outside_crypto_ssot() -> None:
    """Any I/O on a `msal_cache_path_for_*` path outside the two
    `office365.py::_init_cache/_save_cache` seams is drift."""
    offenders: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        # Skip the crypto module itself + the path-SSOT that DEFINES
        # the helpers (no I/O there — but future edits could add).
        if rp in {"providers/_msal_cache_crypto.py"}:
            continue
        allowed_names = _module_alias_map(tree)
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            path_names = _collect_msal_path_bindings(fn, allowed_names)
            # Also propagate `self._token_cache_path` — the ctor stores
            # the builder result on `self`, and methods use `self._token_cache_path`.
            # The bindings pass above already records the `attr` name on
            # a `self.<attr> = <builder>(...)` assignment.
            if not path_names:
                # No local binding — but if THIS fn is one of the two
                # legal sites, `self._token_cache_path` may be inherited
                # from __init__.  Add it defensively.
                if isinstance(fn.name, str) and fn.name in {"_init_cache", "_save_cache"}:
                    path_names = {"_token_cache_path"}
                else:
                    # Search all callers in the file for the attribute
                    # binding — a Path-typed attribute assigned in the
                    # module's __init__ is still a MSAL cache path.
                    for other in ast.walk(tree):
                        if isinstance(other, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            path_names |= _collect_msal_path_bindings(other, allowed_names)
                    if not path_names:
                        continue
            for io in _find_illegal_io(fn, path_names):
                site = (rp, fn.name)
                if site in _LEGAL_SITES:
                    continue
                offenders.append(f"{rp}:{io.lineno} in {fn.name}()")
    assert not offenders, (
        "N-151 DRIFT: raw MSAL cache I/O outside the "
        "`_msal_cache_crypto` SSOT:\n  " + "\n  ".join(offenders) +
        "\n\nRoute reads through `decrypt_cache`, writes through "
        "`encrypt_cache` + `atomic_write_bytes`.  Fail-CLOSED: NEVER "
        "fall back to a plaintext read/write."
    )


def test_pin_has_teeth() -> None:
    """Anti-vacuity — both allow-listed seams MUST exist in the tree.
    A rename or deletion of `_init_cache`/`_save_cache` would silently
    turn this pin vacuous otherwise."""
    from email_triage.providers.office365 import Office365Provider
    assert hasattr(Office365Provider, "_init_cache"), (
        "N-151 pin vacuity: `Office365Provider._init_cache` absent.  "
        "Either the seam moved (update `_LEGAL_SITES`) or the encryption "
        "SSOT was gutted."
    )
    assert hasattr(Office365Provider, "_save_cache"), (
        "N-151 pin vacuity: `Office365Provider._save_cache` absent."
    )
    # And the crypto SSOT itself
    from email_triage.providers import _msal_cache_crypto  # noqa: F401
    from email_triage.providers._msal_cache_crypto import (  # noqa: F401
        decrypt_cache, encrypt_cache, looks_like_legacy_plaintext,
    )


def test_pin_scans_real_files() -> None:
    """Meta-anti-vacuity: the walker must actually visit `office365.py`
    (guards against an SRC_ROOT regression)."""
    seen = False
    for path in iter_src_files():
        if relpath(path) == "providers/office365.py":
            seen = True
            break
    assert seen, (
        "N-151 harness regression: `iter_src_files` did not yield "
        "`providers/office365.py` — SRC_ROOT drift."
    )
