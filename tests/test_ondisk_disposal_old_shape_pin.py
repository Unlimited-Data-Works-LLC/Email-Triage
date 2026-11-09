"""Structural + behavioral pin (post-drive-full-census 2026-07-09 V6):
`dispose_all_per_user_artifacts` MUST route through the SSOT
`dispose_msal_cache_for_cli`, which handles BOTH the post-N-307
hash-suffixed shape AND the pre-N-307 raw-username OLD shape.

What this defends
-----------------
The census wf_56d1585d "Other findings" item ondisk-artifact-disposal V6
flagged: the CLI's `secrets purge-msal-cache` handler in `cli.py:1047`
routes through `dispose_all_per_user_artifacts(username)`, which BEFORE
this pin/fix iterated `_USER_BUILDERS = [msal_cache_path_for_cli]` and
unlinked ONLY the post-N-307 hash-suffixed file. On an install upgraded
across the N-307 shape change (2026-07-03 tranche  rename to
`msal_cache_cli_<safe_stem>_<hash16>.json`), the pre-N-307 OLD-shape
file `./data/msal_cache_cli_<username>.json` survived every operator
`secrets purge-msal-cache` — a §164.310(d)(2)(i) LITERAL Disposal defect
because a plaintext OAuth refresh_token (`msal_cache_cli_<user>.json`
carries the msal token cache, refresh_token included) could survive the
purge operator flow.

`dispose_msal_cache_for_cli` (factory.py, N-356 R31) is the SSOT that
unlinks BOTH shapes atomically. This pin behaviorally verifies that a
per-user disposal removes BOTH files when both are present, and
STRUCTURALLY asserts that `dispose_all_per_user_artifacts` calls the
SSOT rather than re-inlining the unlink.

Count-agnostic + interprocedural
--------------------------------
The behavioral test is not count-based; the structural test verifies a
property over the disposer body (a Call to `dispose_msal_cache_for_cli`
must be present).

Grounded in this drive's fix at `_ondisk_artifacts.py::
dispose_all_per_user_artifacts` (routed through the SSOT).
"""
from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import parse_module, SRC_ROOT


def test_dispose_all_per_user_artifacts_removes_both_shapes(tmp_path, monkeypatch):
    """Behavioral: with BOTH the post-N-307 hash-suffixed file AND the
    pre-N-307 raw-username file present, `dispose_all_per_user_artifacts`
    must delete BOTH (returns 1 = one artifact family disposed; the
    SSOT reports success once for the msal_cache family regardless of
    how many shape-variants it unlinked)."""
    from email_triage.providers import _ondisk_artifacts
    from email_triage.providers import factory

    username = "test_user_ondisk_disposal"
    # Redirect the ./data prefix into tmp_path so we don't touch a real
    # install. Both factory helpers build paths relative to ./data.
    monkeypatch.chdir(tmp_path)
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)

    new_path = factory.msal_cache_path_for_cli(username)
    old_path = Path(f"./data/msal_cache_cli_{username}.json").resolve()
    # Ensure the paths differ (the N-307 shape MUST differ from the OLD
    # shape or the pin is testing nothing meaningful).
    assert new_path.resolve() != old_path, (
        f"N-307 rename appears to be a no-op — new_path {new_path!r} "
        f"resolves to the same file as OLD-shape {old_path!r}. If the "
        f"factory helper was reverted, this pin's assumption is void."
    )
    new_path.parent.mkdir(parents=True, exist_ok=True)
    new_path.write_text('{"placeholder": "new"}')
    old_path.parent.mkdir(parents=True, exist_ok=True)
    old_path.write_text('{"placeholder": "old"}')

    assert new_path.exists(), "test setup: new-shape file not created"
    assert old_path.exists(), "test setup: old-shape file not created"

    deleted = _ondisk_artifacts.dispose_all_per_user_artifacts(username)

    assert not new_path.exists(), (
        "dispose_all_per_user_artifacts did NOT unlink the post-N-307 "
        "new-shape file — the SSOT route may be broken."
    )
    assert not old_path.exists(), (
        "dispose_all_per_user_artifacts did NOT unlink the pre-N-307 "
        "OLD-shape file — the SSOT route (via dispose_msal_cache_for_cli) "
        "must handle both shapes. This is the §164.310(d)(2)(i) LITERAL "
        "Disposal defect the census V6 finding flagged."
    )
    assert deleted == 1, (
        f"expected deleted==1 (one artifact family disposed by the SSOT); "
        f"got {deleted}. The disposer aggregates by artifact family, not "
        f"per-file — a change here indicates the route now double-counts."
    )


def test_dispose_all_per_user_artifacts_routes_through_ssot():
    """Structural: the body of `dispose_all_per_user_artifacts` in
    `_ondisk_artifacts.py` MUST include a Call to
    `dispose_msal_cache_for_cli`. Guards against a well-meaning
    "simplification" that re-inlines the unlink loop and re-opens the
    OLD-shape gap the census V6 finding closed."""
    path = SRC_ROOT / "providers" / "_ondisk_artifacts.py"
    tree = parse_module(path)
    assert tree is not None, f"could not parse {path}"

    target_fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "dispose_all_per_user_artifacts":
                target_fn = node
                break
    assert target_fn is not None, (
        "dispose_all_per_user_artifacts function not found in "
        "_ondisk_artifacts.py — a rename/removal is a REGRESSION shape "
        "the census flagged; re-review before proceeding."
    )

    calls_ssot = False
    for node in ast.walk(target_fn):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id == "dispose_msal_cache_for_cli":
                calls_ssot = True
                break
            if isinstance(f, ast.Attribute) and f.attr == "dispose_msal_cache_for_cli":
                calls_ssot = True
                break

    assert calls_ssot, (
        "N-407 / census V6 REGRESSION: "
        "`dispose_all_per_user_artifacts` no longer calls "
        "`dispose_msal_cache_for_cli` — the SSOT that unlinks BOTH the "
        "post-N-307 hash-suffixed shape and the pre-N-307 raw-username "
        "OLD shape. Do not re-inline the unlink loop; the SSOT is the "
        "only path that closes the §164.310(d)(2)(i) LITERAL Disposal "
        "defect for installs upgraded across N-307."
    )


def test_every_user_builder_has_a_matching_ssot_disposer_call():
    """Structural (DA fold, 2026-07-09): every builder registered in
    `_USER_BUILDERS` MUST have a corresponding `dispose_<stem>_for_cli`
    SSOT that is called by `dispose_all_per_user_artifacts`. Guards
    against a future maintainer adding a builder row (say
    `push_cursor_path_for_cli`) without the matching SSOT disposer +
    dispatch — that shape silently DOES NOT DISPOSE the new artifact
    family, re-opening the same LITERAL Disposal class the V6 fix
    closed.

    Convention: builder `<stem>_path_for_cli` → SSOT `dispose_<stem>_for_cli`.
    """
    from email_triage.providers._ondisk_artifacts import _USER_BUILDERS

    path = SRC_ROOT / "providers" / "_ondisk_artifacts.py"
    tree = parse_module(path)
    assert tree is not None

    target_fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "dispose_all_per_user_artifacts":
                target_fn = node
                break
    assert target_fn is not None

    called_names: set[str] = set()
    for node in ast.walk(target_fn):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                called_names.add(f.id)
            elif isinstance(f, ast.Attribute):
                called_names.add(f.attr)

    unmatched: list[str] = []
    for builder in _USER_BUILDERS:
        bname = builder.__name__
        # `<stem>_path_for_cli` -> `dispose_<stem>_for_cli`
        if bname.endswith("_path_for_cli"):
            stem = bname[: -len("_path_for_cli")]
            expected = f"dispose_{stem}_for_cli"
        else:
            expected = None
        if expected is None or expected not in called_names:
            unmatched.append(f"{bname} -> expected {expected!r}")

    assert not unmatched, (
        "Census V6 REGRESSION class: a per-user artifact was added to "
        "`_USER_BUILDERS` without a matching SSOT disposer + explicit "
        "call in `dispose_all_per_user_artifacts`. Silent under-disposal "
        "re-opens §164.310(d)(2)(i) LITERAL Disposal for the missed "
        "family. For builder `<stem>_path_for_cli` add "
        "`dispose_<stem>_for_cli` (patterned on N-356 R31) and call it "
        "in `dispose_all_per_user_artifacts`. Missing:\n  "
        + "\n  ".join(unmatched)
    )
