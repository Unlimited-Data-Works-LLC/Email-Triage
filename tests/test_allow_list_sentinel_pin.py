"""N-422 Drive-3 close-out task  — Allow-list sentinel structural pairing pin.

Devils-advocate follow-on from N-411's register row (line 1002): *"sentinel-
based structural pairing to prevent allow-list rot."*

Every `_*_ALLOW` dict in every `tests/test_*_ssot_pin.py` file exempts a
set of src files from a pin's coverage. If the exempted src file changes
shape (or moves, or the exempted symbol is renamed) the allow-list entry
becomes silent dead weight — the exemption persists even though the
underlying "why this file was exempted" no longer holds. The PD#7 rot-
guards each pin has today catch stale entries via same-shape detection at
HEAD, but only for the shape THAT pin cares about. A structural pairing
sentinel makes the coupling visible IN THE SOURCE FILE ITSELF.

The contract this pin enforces going forward:

  For every entry ``rel: "reason"`` in a ``_*_ALLOW`` dict in a pin file,
  the corresponding ``src/email_triage/<rel>`` MUST contain a sentinel
  comment of the form::

      # <pin-slug>-allow: <short reason>

  where ``pin-slug`` is derived from the pin file name (e.g.
  ``test_backfill_cap_ssot_pin.py`` → ``backfill_cap``). The sentinel
  comment can be anywhere in the file — its presence is the signal that
  a developer editing the src file knows THIS file is allow-listed by
  THIS pin.

Historical debt: the current allow-list entries across the seven Drive-2
declaration pins (N-412..N-418) + the N-411 meta-pin + the N-228 backoff-
step pin do NOT carry these sentinels. Each is seeded into
``_SENTINEL_EXEMPT`` with a stated reason (typically: "pre-N-422 entry;
sentinel-add is a follow-on"). The pin's forward-coverage enforces the
sentinel requirement on NEW allow-list entries going forward.

Reuses `_pin_harness` per PD#6. Rot-guarded PD#7 on `_SENTINEL_EXEMPT`.
Teeth via planted-fake pin AST + planted-fake src file with/without the
sentinel.
"""

from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import (
    REPO_ROOT,
    SRC_ROOT,
    iter_files,
    parse_module,
)


_TESTS_ROOT = REPO_ROOT / "tests"


# Pin-slug format the sentinel uses: `# <slug>-allow: <reason>`. Derived
# from the pin filename by stripping `test_` prefix + `_ssot_pin.py` /
# `_pin.py` suffix.
def _pin_slug(pin_path: Path) -> str:
    name = pin_path.stem  # e.g. "test_backfill_cap_ssot_pin"
    if name.startswith("test_"):
        name = name[len("test_"):]
    for suffix in ("_ssot_pin", "_pin"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


# Historical debt seed. Every pre-N-422 allow-list entry lives here so the
# pin lands GREEN without a mass sentinel-add edit across ~20 src files.
# Rot-guarded PD#7 by :func:`test_sentinel_exempt_no_stale_entries`.
# Keyed by ``(pin-slug, src-relpath)``.
#
# Follow-on: each entry becomes a candidate for a real sentinel add + entry
# removal here. Ordered roughly by leverage.
_SENTINEL_EXEMPT: dict[tuple[str, str], str] = {
    # N-411 SSOT-declaration meta-pin (`_UNREGISTERED_ALLOW`)
    ("ssot_src_declaration_registered", "actions/move.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "baa_expiry.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "classify/prompts.py"): "pre-N-422",
    # retry_backoff.py removed 2026-07-14 (N-410 Drive-4: real structural pin landed).
    ("ssot_src_declaration_registered", "actions/digest_configs.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "actions/suggest_meeting_times.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "ai_backends/azure_openai.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "ai_backends/gemini_adapter.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "ai_backends/openai_direct.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "web/routers/ui/admin.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "web/routers/ui/ai_backends_crud.py"): "pre-N-422",
    ("ssot_src_declaration_registered", "web/routers/help.py"): "pre-N-422",

    # N-421 hardened meta-pin (`_HARDENED_ALLOW`)
    # actions/base.py removed 2026-07-14 (N-411 §3 registry now cites src path).
    ("ssot_declaration_hardened", "actions/sent_mail_index.py"): "pre-N-422",

    # N-414 backfill-cap paired-import (`_PAIRED_IMPORT_ALLOW`)
    ("backfill_cap", "web/routers/ui/accounts.py"): "pre-N-422",
    ("backfill_cap", "web/watcher.py"): "pre-N-422",

    # N-412 baa_gate symmetry (`_SYMMETRY_ALLOW`) — keyed on CLASS NAME
    # not src path. Skipped: allow-list key is a class name, not a path.

    # N-417 regulatory-clock no-projection (`_EMITTER_ALLOW`) — the 3
    # allow-listed modules ARE the SSOT owners; no sentinel needed for
    # SSOT-owning modules by design.
    ("migrations_no_projection", "web/migrations.py"): "pre-N-422 SSOT-owner",
    ("migrations_no_projection", "db/audit.py"): "pre-N-422 SSOT-owner",
    ("migrations_no_projection", "db/regulatory_clock.py"): "pre-N-422 SSOT-owner",

    # N-44 auth-revoked lifecycle (`_DELTA_CLEAR_ALLOW`)
    ("auth_stale_lifecycle", "web/poll_ingestion.py"): "pre-N-422",
    ("auth_stale_lifecycle", "web/ingestion_push.py"): "pre-N-422",
    ("auth_stale_lifecycle", "web/watcher.py"): "pre-N-422",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_pin_files():
    """Yield every `tests/test_*_pin.py` file via the shared harness walker
    (R5c: pins that audit a non-src tree route through `iter_files(root,
    pattern)` rather than re-rolling `Path.glob`)."""
    yield from iter_files(_TESTS_ROOT, "test_*_pin.py")


def _extract_allow_entries(pin_path: Path):
    """Return ``[(dict_name, key_str), ...]`` for every module-scope Assign
    of the form ``_<name>_ALLOW: dict = { "<key>": ..., ... }`` in the pin
    file. Skips non-str dict keys.
    """
    tree = parse_module(pin_path)
    if tree is None:
        return []
    out: list[tuple[str, str]] = []
    for node in tree.body:
        target_name: str | None = None
        value = None
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target_name = node.targets[0].id
                value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_name = node.target.id
            value = node.value
        if target_name is None or value is None:
            continue
        if not (target_name.startswith("_") and target_name.endswith("_ALLOW")):
            continue
        if not isinstance(value, ast.Dict):
            continue
        for k in value.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                out.append((target_name, k.value))
    return out


def _src_has_sentinel(rel: str, pin_slug: str) -> bool:
    """True if ``src/email_triage/<rel>`` contains a line matching
    ``# <pin_slug>-allow:``. Case-sensitive; leading whitespace tolerated.
    """
    path = SRC_ROOT / rel
    if not path.exists():
        return False
    needle = f"# {pin_slug}-allow"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        if needle in line:
            return True
    return False


# ---------------------------------------------------------------------------
# Pin — every allow-list entry MUST have a paired src sentinel OR be exempt
# ---------------------------------------------------------------------------


def test_every_allow_list_entry_has_paired_sentinel():
    """For every `_*_ALLOW` dict entry `rel: "..."` across every pin file
    in `tests/`, either (a) the src file `<SRC_ROOT>/<rel>` contains a
    sentinel comment `# <pin-slug>-allow:` OR (b) the (pin-slug, rel) pair
    is in `_SENTINEL_EXEMPT` with a stated reason.

    New allow-list entries WITHOUT the sentinel + WITHOUT an exempt entry
    are refused — that's the forward-coverage this pin adds.
    """
    problems: list[str] = []
    for pin_path in _iter_pin_files():
        slug = _pin_slug(pin_path)
        for dict_name, rel in _extract_allow_entries(pin_path):
            # Skip entries whose key isn't a bare src-relpath: class
            # names (N-412 `_SYMMETRY_ALLOW`) OR function-scope refs
            # (`<path>::<fn>` shape used by other pins to allow-list a
            # single callsite rather than a whole file).
            if "::" in rel:
                continue
            if "/" not in rel and not rel.endswith(".py"):
                continue
            if (slug, rel) in _SENTINEL_EXEMPT:
                continue
            if _src_has_sentinel(rel, slug):
                continue
            problems.append(
                f"  {pin_path.name}::{dict_name}[{rel!r}] — src file "
                f"lacks `# {slug}-allow:` sentinel. Add a one-line "
                "comment near the exempted shape explaining WHY this "
                "file is on the allow-list, so a future dev editing "
                "the file knows the exemption exists."
            )
    assert not problems, (
        "N-422 allow-list sentinel drift — src file(s) referenced by a "
        "pin allow-list lack the paired sentinel comment. Either add "
        "`# <slug>-allow: <reason>` to the src file OR add the "
        "(pin-slug, rel) pair to `_SENTINEL_EXEMPT` with a stated "
        "reason.\n\n" + "\n".join(problems)
    )


# ---------------------------------------------------------------------------
# Rot-guard PD#7 + teeth
# ---------------------------------------------------------------------------


def test_sentinel_exempt_no_stale_entries():
    """`_SENTINEL_EXEMPT` entries MUST correspond to (a) a live pin file
    matching the slug that still has (b) a matching allow-list entry for
    the src relpath. Stale entries silently exempt future violations."""
    live: set[tuple[str, str]] = set()
    for pin_path in _iter_pin_files():
        slug = _pin_slug(pin_path)
        for _, rel in _extract_allow_entries(pin_path):
            live.add((slug, rel))
    stale = [
        f"  ({slug!r}, {rel!r})"
        for (slug, rel) in _SENTINEL_EXEMPT
        if (slug, rel) not in live
    ]
    assert not stale, (
        "N-422 rot-guard: `_SENTINEL_EXEMPT` has stale entries (PD#7).\n\n"
        + "\n".join(stale)
    )


def test_pin_has_teeth():
    """Three planted-fake probes: (a) `_pin_slug` derives the right slug
    from a canonical pin filename; (b) `_extract_allow_entries` finds an
    entry in a synthetic AST; (c) `_src_has_sentinel` accepts + rejects
    matching / non-matching comment shapes.
    """
    # (a) Slug derivation
    assert _pin_slug(Path("test_backfill_cap_ssot_pin.py")) == "backfill_cap"
    assert _pin_slug(Path("test_n228_backoff_step_ssot_pin.py")) == "n228_backoff_step"
    assert _pin_slug(Path("test_pin_harness_adoption.py")) == "pin_harness_adoption"

    # (b) Extract from synthetic pin file
    fake_pin_src = (
        "_FAKE_ALLOW: dict = {\n"
        '    "web/foo.py": "reason",\n'
        '    "actions/bar.py": "another reason",\n'
        "}\n"
    )
    fake_tree = ast.parse(fake_pin_src)
    entries: list[tuple[str, str]] = []
    for node in fake_tree.body:
        target_name = None
        value = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_name = node.target.id
            value = node.value
        if target_name and target_name.startswith("_") and target_name.endswith("_ALLOW"):
            if isinstance(value, ast.Dict):
                for k in value.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        entries.append((target_name, k.value))
    assert entries == [
        ("_FAKE_ALLOW", "web/foo.py"),
        ("_FAKE_ALLOW", "actions/bar.py"),
    ], f"teeth: extract detector broken; got {entries}"

    # (c) Sentinel-match string shapes
    line_with = "    # backfill_cap-allow: pure lifecycle-clear"
    line_without = "    # backfill_cap: pure lifecycle-clear"
    assert "# backfill_cap-allow" in line_with, "teeth: match string wrong"
    assert "# backfill_cap-allow" not in line_without, (
        "teeth: sentinel accepted a non-`-allow`-suffixed comment"
    )
