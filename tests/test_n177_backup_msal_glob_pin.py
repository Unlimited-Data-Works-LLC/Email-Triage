"""N-177 + N-351 structural pin — backup collector iterates the ondisk-artifact registry, not a bare literal.

Original N-177 (2026-06-27) checked that `backup.py::build_full_bundle` calls
`.glob("msal_cache*.json")` at least once — a LITERAL shape check that failed
to catch a future artifact family added to `providers/_ondisk_artifacts.py`
but forgotten in the backup collector.

N-351 rewrite (2026-07-04, census DISCOVERED MED wf_1296c6ba-9b8): the pin now
walks the registry as a membership check. It asserts:

  (a) `build_full_bundle` imports (or receives via module-scope import) the
      `PER_ACCOUNT_ARTIFACT_GLOBS` name from `_ondisk_artifacts`.
  (b) `PER_ACCOUNT_ARTIFACT_GLOBS` is referenced INSIDE the fn body — the
      registry is actually iterated, not just imported for decoration.
  (c) The registry is non-empty at import time — a future refactor that
      empties it would silently drop every per-account artifact from every
      backup.
  (d) LEGACY: at least one `.glob("msal_cache*.json")` call remains for the
      transitional literal-shim documented in `backup.py:1197-1204` (kept
      only until the shim is removed in a follow-up commit).

The teeth-test plants a `build_full_bundle` shape that BOTH lacks the
registry reference AND has the bare literal — the new pin's (b) check must
fire.
"""
from __future__ import annotations

import ast

from tests._pin_harness import SRC_ROOT, is_bare_json_loads, parse_module, parse_source


BACKUP = SRC_ROOT / "backup.py"


def _find_fn(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _names_referenced(fn: ast.AST) -> set[str]:
    """Every Name.id + Attribute.attr referenced anywhere in `fn`'s body."""
    seen: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Name):
            seen.add(n.id)
        elif isinstance(n, ast.Attribute):
            seen.add(n.attr)
        elif isinstance(n, ast.ImportFrom):
            for alias in n.names:
                seen.add(alias.name)
                if alias.asname:
                    seen.add(alias.asname)
    return seen


def test_backup_iterates_ondisk_artifact_registry():
    """N-351 — the collector MUST route per-account artifact enumeration
    through the `PER_ACCOUNT_ARTIFACT_GLOBS` registry, so a NEW artifact
    added to `_ondisk_artifacts.py` is picked up automatically."""
    tree = parse_module(BACKUP)
    assert tree is not None, "backup.py failed to parse"
    fn = _find_fn(tree, "build_full_bundle")
    assert fn is not None, "build_full_bundle not found in backup.py"

    referenced = _names_referenced(fn)
    assert "PER_ACCOUNT_ARTIFACT_GLOBS" in referenced, (
        "N-351 regression: build_full_bundle no longer references the "
        "PER_ACCOUNT_ARTIFACT_GLOBS registry — a new per-account artifact "
        "added to _ondisk_artifacts.py would silently drop from every backup"
    )


def test_registry_is_non_empty_at_import_time():
    """N-351 — an empty registry silently drops every artifact from every
    backup, even with the pin above green."""
    from email_triage.providers._ondisk_artifacts import PER_ACCOUNT_ARTIFACT_GLOBS
    assert len(PER_ACCOUNT_ARTIFACT_GLOBS) >= 1, (
        "PER_ACCOUNT_ARTIFACT_GLOBS is empty — the collector iterates it "
        "but there is nothing to iterate. Restore at least the msal_cache "
        "glob or explain in a comment why the registry is legitimately empty."
    )


def test_backup_no_bare_msal_cache_literal():
    """N-351 R31 (2026-07-05) — replaces LEGACY N-177 literal-glob check.
    The `test_backup_uses_glob_not_bare_singleton_LEGACY` test was removed
    together with the `data_dir.glob('msal_cache*.json')` shim at
    backup.py:1204. This pin retains the bare-literal ban so a future
    edit reverting to `msal_cache.json` string constants in
    `build_full_bundle` still fires."""
    tree = parse_module(BACKUP)
    assert tree is not None, "backup.py failed to parse"
    fn = _find_fn(tree, "build_full_bundle")
    assert fn is not None

    for n in ast.walk(fn):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if n.value in ("data/msal_cache.json", "msal_cache.json"):
                raise AssertionError(
                    f"bare '{n.value}' literal in build_full_bundle at line "
                    f"{getattr(n, 'lineno', '?')} — N-177 regression: should "
                    f"route via registry PER_ACCOUNT_ARTIFACT_GLOBS + glob"
                )


def test_pin_has_teeth():
    """N-351 teeth — a bad shape that references neither the registry NOR
    routes through a glob call MUST fail the registry-reference check
    (a) + the bare-literal-ban check (c)."""
    bad = """
def build_full_bundle(**kw):
    files = []
    msal_path = data_dir / "msal_cache.json"  # bare literal — N-177 regression
    if msal_path.is_file():
        files.append(_BundleFile(path="data/msal_cache.json", data=msal_path.read_bytes(), mode=0o600))
    return files
"""
    tree = ast.parse(bad)
    fn = _find_fn(tree, "build_full_bundle")
    assert fn is not None

    # (a) N-351 registry reference must be ABSENT in bad shape
    referenced = _names_referenced(fn)
    assert "PER_ACCOUNT_ARTIFACT_GLOBS" not in referenced, (
        "teeth: bad shape must not reference the registry"
    )

    # (c) bare literal must be PRESENT in bad shape
    bare_hits = [n for n in ast.walk(fn)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.value in ("data/msal_cache.json", "msal_cache.json")]
    assert bare_hits, "teeth: bad shape must contain a bare singleton literal"


# ---------------------------------------------------------------------------
# N-472 (2026-09-12) — the collector must ASK the writer whether a payload is
# valid, never decide the shape itself.
#
# The defect this pins: `build_full_bundle` validated MSAL caches with a
# hardcoded `json.loads`, and N-151's 2026-07-08 plaintext-to-Fernet cutover
# turned that into a reject of every cache the writer produces. Every bundle
# for two months silently omitted every per-account token cache.
#
# The fix routes the decision through `_msal_cache_crypto.is_valid_cache_payload`
# — the predicate owned by the module that WRITES the bytes — so the next format
# migration propagates by construction. A comment in the collector asking future
# authors not to re-inline a shape check is not enforcement; this is (PD-1: the
# SSOT ships its count-agnostic structural pin in the same change).
#
# Count-agnostic by construction: both arms are properties over the function's
# AST (a name must be referenced; a call/shape must be absent anywhere in the
# body), never `len(X) == N`. PD-6: reuses this file's existing `_find_fn` /
# `_names_referenced` walkers and the shared harness's `is_bare_json_loads`
# rather than hand-rolling a second scanner.
# ---------------------------------------------------------------------------

def test_backup_delegates_payload_validity_to_the_writer():
    """N-472 arm A — `build_full_bundle` references the writer's predicate."""
    tree = parse_module(BACKUP)
    assert tree is not None, "backup.py failed to parse"
    fn = _find_fn(tree, "build_full_bundle")
    assert fn is not None, "build_full_bundle not found in backup.py"

    # N-472 N1 — the CALL must carry `source=`, not merely exist.
    #
    # The behavioural test calls `is_valid_cache_payload` directly and passes
    # `source=` itself, so it structurally cannot observe whether the COLLECTOR
    # threads it. Measured: deleting `source=str(p)` from `build_full_bundle`
    # leaves the suite fully GREEN at `37 passed`, and every legacy-plaintext
    # warning silently degrades to "<unspecified>" — an operator told a token is
    # unencrypted on disk and not told whose. The `or "<unspecified>"` default is
    # what makes that regression silent rather than a TypeError, so the kwarg
    # needs a pin rather than relying on the signature to enforce it.
    # `pattern_teeth_test_on_a_helper_does_not_pin_the_caller`.
    calls = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "is_valid_cache_payload"
    ]
    assert calls, (
        "N-472: `build_full_bundle` does not CALL `is_valid_cache_payload` — "
        "a name reference alone (an import) is not the guard"
    )
    for call in calls:
        assert any(kw.arg == "source" for kw in call.keywords), (
            "N-472: `is_valid_cache_payload` is called at "
            f"`build_full_bundle` line {call.lineno} WITHOUT `source=`. The "
            "predicate receives bytes and cannot know which file produced "
            "them; without the caller's path every legacy-plaintext warning "
            "degrades to '<unspecified>' and the operator cannot tell which "
            "account has an unencrypted refresh token on disk. Pass "
            "`source=str(p)`."
        )

    referenced = _names_referenced(fn)
    assert "is_valid_cache_payload" in referenced, (
        "N-472: `build_full_bundle` must route on-disk artifact validity "
        "through `_msal_cache_crypto.is_valid_cache_payload` — the predicate "
        "owned by the module that writes the bytes. A validity check the "
        "collector decides for itself goes stale the next time the payload "
        "format moves, which is exactly how every MSAL cache fell out of "
        "every backup between 2026-07-08 and 2026-09-12."
    )


def test_backup_does_not_re_inline_a_payload_shape_check():
    """N-472 arm B — no hand-rolled shape check anywhere in the collector.

    The arm that actually prevents the regression. Arm A stays green if
    someone adds a second, parallel validator beside the delegated one; this
    arm is what makes that red.
    """
    tree = parse_module(BACKUP)
    assert tree is not None, "backup.py failed to parse"
    fn = _find_fn(tree, "build_full_bundle")
    assert fn is not None, "build_full_bundle not found in backup.py"

    offenders: list[str] = []
    for node in ast.walk(fn):
        if is_bare_json_loads(node):
            offenders.append(f"json.loads at line {node.lineno}")
        # `<bytes>.startswith(b"{")` / `.lstrip().startswith(...)` — the
        # legacy-plaintext shape check, which belongs to the crypto module.
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "startswith"):
            offenders.append(f".startswith() shape check at line {node.lineno}")

    assert not offenders, (
        "N-472: `build_full_bundle` is deciding an artifact's payload shape "
        "itself instead of asking `_msal_cache_crypto`. Call "
        "`is_valid_cache_payload(raw, source=str(p))` rather than re-inlining "
        "the check here — a shape check in the reader is invisible to the "
        "writer and goes stale on the next format change.\n\n"
        "Do NOT call `looks_like_legacy_plaintext` here to report the legacy "
        "case: that function's own docstring forbids using it as an "
        "is-this-encrypted check, and the warning already fires inside "
        "`is_valid_cache_payload`. Pass `source=` so it can name the file. "
        "(This message used to recommend the opposite; it was contradicting "
        "the comment at the call site, and THIS ARM CANNOT SEE that shape "
        "anyway — it matches `json.loads` and `.startswith`, while "
        "`looks_like_legacy_plaintext(raw)` is an `ast.Name` call.)\n  "
        + "\n  ".join(offenders)
    )


def test_n472_pin_has_teeth():
    """Both N-472 arms must FIRE on a planted bad shape (PD-6 teeth)."""
    bad = parse_source(
        "def build_full_bundle(data_dir):\n"
        "    for p in data_dir.glob('msal_cache*.json'):\n"
        "        raw = p.read_bytes()\n"
        "        try:\n"
        "            json.loads(raw.decode('utf-8'))\n"
        "        except ValueError:\n"
        "            continue\n"
        "        if raw.lstrip().startswith(b'{'):\n"
        "            pass\n"
    )
    fn = _find_fn(bad, "build_full_bundle")
    assert fn is not None

    # Arm A must fire: the delegated predicate is absent.
    assert "is_valid_cache_payload" not in _names_referenced(fn), (
        "teeth: bad shape must not reference the writer's predicate"
    )

    # Arm B must fire: both hand-rolled shapes are present.
    assert any(is_bare_json_loads(n) for n in ast.walk(fn)), (
        "teeth: bad shape must contain a bare json.loads"
    )
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "startswith" for n in ast.walk(fn)), (
        "teeth: bad shape must contain a .startswith() shape check"
    )

    # And the GOOD shape must NOT trip arm B — a pin that flags the fix is
    # worse than no pin.
    good = parse_source(
        "def build_full_bundle(data_dir):\n"
        "    for p in data_dir.glob('msal_cache*.json'):\n"
        "        raw = p.read_bytes()\n"
        "        if not is_valid_cache_payload(raw):\n"
        "            continue\n"
    )
    good_fn = _find_fn(good, "build_full_bundle")
    assert good_fn is not None
    assert "is_valid_cache_payload" in _names_referenced(good_fn)
    assert not any(is_bare_json_loads(n) for n in ast.walk(good_fn)), (
        "teeth: the correct shape must not be flagged"
    )
