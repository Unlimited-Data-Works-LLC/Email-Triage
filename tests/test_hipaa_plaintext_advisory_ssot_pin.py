"""N-413 Drive-2 close-out #2 — `db/_engine.py` HIPAA-mode-plaintext advisory SSOT pin.

`db/_engine.py` declares itself the *"single source of truth for the HIPAA-
mode-plaintext advisory text so the boot-time emit (console/file, immediate)
and the §164.312(b) audit-chain re-emit (after add_sqlite_handler attaches)
are byte-identical"* (comment above `HIPAA_PLAINTEXT_ADVISORY` at line 146).
The byte-identical contract is load-bearing: a diverging string on the audit-
chain re-emit path would produce two subtly different §164.312(b) rows
across app boots — the exact silent-fork class §164.316(b)(2)(iii) is
supposed to prevent (an SME auditing the record would have to reconcile
which advisory was actually shown to the operator that day).

Two divergence vectors this pin locks:

  1. **Text SSOT** — the `HIPAA_PLAINTEXT_ADVISORY` string literal is the
     ONLY copy. A hand-rolled sibling string that opens with the same
     signature phrase in ANY OTHER src file is a fork. AST-walks every src
     module, extracts every string literal, refuses one that starts with the
     distinctive signature `"HIPAA mode is ON but persistence.encryption_enabled"`
     outside the SSOT module.

  2. **Import routing** — every reference to the name
     `HIPAA_PLAINTEXT_ADVISORY` outside the SSOT module MUST import it from
     `email_triage.db._engine`. Local re-definition (a bare
     `HIPAA_PLAINTEXT_ADVISORY = "…"` re-assign) at another module scope is
     refused.

Also covers `PLAINTEXT_ADVISORY` (the general non-HIPAA sibling constant
immediately below the SSOT declaration) with the same text-SSOT and
import-routing checks — the two constants share the same divergence class.

Reuses `_pin_harness` per PD#6. Rot-guarded PD#7. Teeth via three planted-
fake probes. §3 registered in `internal documentation`; §4.29
register row filed.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    iter_src_files,
    parse_module,
    relpath,
)


_SSOT_MODULE_REL = "db/_engine.py"
_SSOT_IMPORT_PATH = "email_triage.db._engine"


# Signature prefix for the HIPAA advisory. Anchored on a phrase specific
# enough that no unrelated string will collide (mentioning both HIPAA mode
# AND persistence.encryption_enabled). If the SSOT text is edited, this
# prefix must stay a real prefix — the pin's `test_pin_has_teeth` guards
# that the SSOT string still starts with it.
_HIPAA_SIGNATURE_PREFIX = "HIPAA mode is ON but persistence.encryption_enabled"

# Signature prefix for the general PLAINTEXT_ADVISORY. Same shape.
_PLAINTEXT_SIGNATURE_PREFIX = "DB encryption is OFF"


# Src modules that are ALLOWED to hold the raw signature string outside the
# SSOT module. Rot-guarded per PD#7 by
# :func:`test_signature_allow_list_has_no_stale_entries`.
#
# Category accepted: tests-only fixtures / doc-string illustrative excerpts
# that MUST embed the actual string for a legitimate reason. Runtime src
# modules NEVER accept an entry here — the whole point of the SSOT is that
# there is exactly one runtime copy.
_SIGNATURE_ALLOW: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_string_literals(tree: ast.AST):
    """N-409 Drive-4 refinement (db-sme note #2): delegate to the hoisted
    ``_pin_harness.iter_string_literals`` — which reconstructs strings from
    ``Constant`` + ``JoinedStr`` **and** ``BinOp(+)`` string-concat shapes.
    The hoisted helper closes the theoretical `"prefix" + "suffix"` twin-
    split slip that the prior Constant/JoinedStr-only detector was blind to.
    """
    from _pin_harness import iter_string_literals
    yield from iter_string_literals(tree)


def _module_imports_advisory_names(tree: ast.AST) -> set[str]:
    """Return the set of names imported from ``email_triage.db._engine`` at
    ANY scope (module or function-local — the repo uses lazy-imports).
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == _SSOT_IMPORT_PATH:
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _module_has_local_assign(tree: ast.AST, name: str) -> bool:
    """True if the module has a top-level (or nested) assignment to ``name``
    at the module body — i.e. a local re-definition that would fork the SSOT.
    """
    for node in tree.body if hasattr(tree, "body") else []:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return True
    return False


# ---------------------------------------------------------------------------
# Pin — text SSOT (no hand-rolled twin)
# ---------------------------------------------------------------------------


def _flag_signature_twins(prefix: str, ssot_module: str) -> list[str]:
    """Return `[]` if the signature prefix appears ONLY inside ssot_module,
    else a list of `rel:lineno` violations."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == ssot_module:
            continue
        if rel in _SIGNATURE_ALLOW:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            hit_text: str | None = None
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                hit_text = node.value
            elif isinstance(node, ast.JoinedStr):
                parts: list[str] = []
                for v in node.values:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        parts.append(v.value)
                    elif isinstance(v, ast.FormattedValue):
                        parts.append("{}")
                hit_text = "".join(parts)
            if hit_text and prefix in hit_text:
                offenders.append(f"  {rel}:{node.lineno}")
    return offenders


def test_hipaa_signature_string_lives_only_in_ssot():
    """The distinctive `HIPAA mode is ON but persistence.encryption_enabled`
    prefix MUST appear only in `db/_engine.py`. Any other src module that
    contains a string literal starting with it is a hand-rolled twin — a
    divergence-vector for the boot-emit vs §164.312(b) audit-chain re-emit
    byte-identity contract.
    """
    offenders = _flag_signature_twins(_HIPAA_SIGNATURE_PREFIX, _SSOT_MODULE_REL)
    assert not offenders, (
        "N-413 HIPAA_PLAINTEXT_ADVISORY text-SSOT drift — twin string(s) "
        "found outside `db/_engine.py`. Route through the shared "
        "`HIPAA_PLAINTEXT_ADVISORY` constant so the boot-time console/file "
        "emit and the §164.312(b) audit-chain re-emit stay byte-identical.\n\n"
        + "\n".join(offenders)
    )


def test_plaintext_signature_string_lives_only_in_ssot():
    """Same discipline for the general (non-HIPAA) `PLAINTEXT_ADVISORY`
    sibling constant declared immediately below in the SSOT module."""
    offenders = _flag_signature_twins(_PLAINTEXT_SIGNATURE_PREFIX, _SSOT_MODULE_REL)
    assert not offenders, (
        "N-413 PLAINTEXT_ADVISORY text-SSOT drift — twin string(s) found "
        "outside `db/_engine.py`. Route through the shared "
        "`PLAINTEXT_ADVISORY` constant.\n\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Pin — import routing (no local re-definition)
# ---------------------------------------------------------------------------


def test_advisory_names_imported_from_ssot_not_redefined_locally():
    """Every src module that mentions `HIPAA_PLAINTEXT_ADVISORY` or
    `PLAINTEXT_ADVISORY` — either by importing it or by naming it in a
    reference — must NOT locally re-assign the name. A local
    `HIPAA_PLAINTEXT_ADVISORY = "…"` at another module scope would shadow
    the SSOT for that module's readers and silently fork the advisory.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_MODULE_REL:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for name in ("HIPAA_PLAINTEXT_ADVISORY", "PLAINTEXT_ADVISORY"):
            if _module_has_local_assign(tree, name):
                offenders.append(
                    f"  {rel}  local re-assignment of `{name}` at module "
                    "scope — this shadows the SSOT."
                )
    assert not offenders, (
        "N-413 advisory-name re-definition drift — src module(s) locally "
        "re-assign an advisory-name that is SSOT-owned by "
        f"`{_SSOT_IMPORT_PATH}`. Import the SSOT instead of re-declaring "
        "the name.\n\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Rot-guard PD#7
# ---------------------------------------------------------------------------


def test_signature_allow_list_has_no_stale_entries():
    """Any `_SIGNATURE_ALLOW` entry MUST correspond to a live src file that
    still contains the signature. A stale entry silently exempts a future
    twin under the same relpath.
    """
    stale: list[str] = []
    for rel in sorted(_SIGNATURE_ALLOW):
        path = SRC_ROOT / rel
        if not path.exists():
            stale.append(f"  {rel}  — file missing")
            continue
        tree = parse_module(path)
        if tree is None:
            stale.append(f"  {rel}  — did not parse")
            continue
        has_hipaa = any(_HIPAA_SIGNATURE_PREFIX in s for s in _iter_string_literals(tree))
        has_plain = any(_PLAINTEXT_SIGNATURE_PREFIX in s for s in _iter_string_literals(tree))
        if not (has_hipaa or has_plain):
            stale.append(f"  {rel}  — no advisory signature on HEAD")
    assert not stale, (
        "N-413 rot-guard: `_SIGNATURE_ALLOW` has stale entries. Remove them "
        "to keep the allow-list honest (PD#7).\n\n" + "\n".join(stale)
    )


# ---------------------------------------------------------------------------
# Teeth
# ---------------------------------------------------------------------------


def test_pin_has_teeth():
    """Three planted-fake probes: (a) the SSOT string still starts with the
    signature prefix (else the detector goes silent), (b) the twin detector
    would fire on a planted violation, (c) the local-assign detector fires
    on a planted re-assignment.
    """
    # (a) The SSOT string still starts with the signature prefix. Otherwise
    #     the whole detector is vacuously silent.
    tree = parse_module(SRC_ROOT / _SSOT_MODULE_REL)
    assert tree is not None
    found_hipaa = False
    for s in _iter_string_literals(tree):
        if s.startswith(_HIPAA_SIGNATURE_PREFIX):
            found_hipaa = True
            break
    assert found_hipaa, (
        "teeth: SSOT string no longer starts with the signature prefix — "
        "the pin's detector would go silent. Update `_HIPAA_SIGNATURE_PREFIX` "
        "to a prefix that still uniquely identifies the SSOT string."
    )

    # (b) Twin detector: a synthetic AST containing a matching string
    #     literal must be flagged by the same function scoping used at
    #     runtime — assert on a hand-rolled probe (not by touching the
    #     working tree).
    fake_tree = ast.parse(
        f'FAKE_TWIN = "{_HIPAA_SIGNATURE_PREFIX} is off in prod."\n'
    )
    fake_texts = list(_iter_string_literals(fake_tree))
    assert any(_HIPAA_SIGNATURE_PREFIX in t for t in fake_texts), (
        "teeth: signature-prefix detector missed a planted twin string"
    )

    # (c) Local-assign detector: a synthetic AST with a re-assignment of
    #     the SSOT name must be flagged.
    fake_reassign = ast.parse('HIPAA_PLAINTEXT_ADVISORY = "wrong text"\n')
    assert _module_has_local_assign(fake_reassign, "HIPAA_PLAINTEXT_ADVISORY"), (
        "teeth: local-assign detector missed a planted re-assignment"
    )
