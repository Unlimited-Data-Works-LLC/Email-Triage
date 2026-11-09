"""N-412 Drive-2 close-out #1 — `classify/baa_gate.py` BAA-gate SSOT declaration pin.

`classify/baa_gate.py` declares itself *"the single source of truth for the
gate"* in the module docstring (line 11). The N-411 src-declaration meta-pin
(`test_ssot_src_declaration_registered_pin.py`) currently allow-lists the
module as a `Drive-2 close-out required` entry. This pin is what removes it
from that allow-list.

The BAA gate has three DIVERGENCE VECTORS this pin locks:

  1. **`_backend_for_classifier` ↔ `_endpoint_info_from_config` symmetry**.
     Two entry points compute the ``(backend, host)`` tuple used in
     `baa_ack_key`:

       - `classifier_baa_status(conn, classifier)` — uses `type(cls).__name__`
         via `_backend_for_classifier` (a live classifier is on hand).
       - `classifier_baa_status_from_config(conn, config)` — uses
         `_endpoint_info_from_config` (avoids instantiating a classifier for
         the admin Config / Security snapshots;  leak-risk driver).

     If a NEW concrete `JsonChatClassifier` subclass ships without an
     accompanying `_endpoint_info_from_config` branch, the two entry points
     silently disagree: the live gate resolves and (correctly) blocks or
     acks, while the config snapshot raises `ValueError("Unknown classifier
     backend")` — a UX regression AND a distinct baa_ack_key (so an
     operator ack against one shape does not cover the other). Count-agnostic:
     walk every `class *Classifier(...)` in `src/email_triage/classify/`, map
     to its `_backend_for_classifier` id, assert the id is in the branch set
     the config-side reader recognises.

  2. **`baa_ack_key` format literal invariance**. The persisted-settings key
     shape ``baa_ack:{backend}:{host}`` is contractual — a second string
     formatter with different separators would silently fork the ack keys
     (unacked despite ack on file). Pin the SSOT string literal.

  3. **Consumer routing SSOT** (PD#5). Every call to the gate primitives
     (`is_safe_for_hipaa`, `baa_block_status`, `classifier_baa_status`,
     `classifier_baa_status_from_config`, `baa_ack_key`, `get_baa_ack`,
     `set_baa_ack`, `revoke_baa_ack`) MUST import from
     ``email_triage.classify.baa_gate`` — never a hand-rolled twin. Walk src
     imports + call-site names; refuse a matching call name whose module
     path is not the SSOT.

Reuses ``_pin_harness`` per PD#6 (single shared AST walker + relpath). Rot-
guard PD#7 on the symmetry allow-list. `test_pin_has_teeth`. §3 registered
in `internal documentation`; §4.28 register row filed.
"""

from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import (
    SRC_ROOT,
    iter_src_files,
    parse_module,
    relpath,
)


_BAA_GATE_MODULE_REL = "classify/baa_gate.py"
_BAA_GATE_IMPORT_PATH = "email_triage.classify.baa_gate"


# Names the gate exports. A call to any of these OUTSIDE the SSOT that does
# NOT import from `email_triage.classify.baa_gate` is a fork.
_GATE_PRIMITIVES = frozenset({
    "is_safe_for_hipaa",
    "baa_block_status",
    "classifier_baa_status",
    "classifier_baa_status_from_config",
    "baa_ack_key",
    "get_baa_ack",
    "set_baa_ack",
    "revoke_baa_ack",
    "_backend_for_classifier",
    "_vendor_host_for_classifier",
    "_endpoint_info_from_config",
})


# Concrete subclasses INTENTIONALLY exempt from the symmetry pin. Each entry
# MUST carry a stated reason. Rot-guarded per PD#7 by
# :func:`test_symmetry_allow_list_has_no_stale_entries`.
#
# Category accepted: an abstract intermediate subclass that itself is not
# meant to be instantiated as an endpoint (e.g. `JsonChatClassifier` — the
# shared JSON-chat scaffold that the 3 concrete adapters inherit from).
_SYMMETRY_ALLOW: dict[str, str] = {
    "JsonChatClassifier": (
        "abstract intermediate — shared JSON-chat scaffold in classify/base.py; "
        "concrete adapters (Ollama/OpenAICompat/Gemini) inherit; itself never "
        "instantiated as an endpoint."
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify_dir() -> Path:
    return SRC_ROOT / "classify"


def _is_direct_abc(node: ast.ClassDef) -> bool:
    """True only for an abstract root: ``node`` directly subclasses ``ABC``
    AND declares at least one ``@abstractmethod``.  A concrete adapter that
    happens to subclass ``ABC`` directly is still checked (fail closed)."""
    direct = any(
        (isinstance(b, ast.Name) and b.id == "ABC")
        or (isinstance(b, ast.Attribute) and b.attr == "ABC")
        for b in node.bases
    )
    if not direct:
        return False
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in item.decorator_list:
                name = d.attr if isinstance(d, ast.Attribute) else getattr(d, "id", "")
                if name == "abstractmethod":
                    return True
    return False


def _iter_classifier_subclasses() -> dict[str, str]:
    """Return ``{ClassName: relpath}`` for every ``class *Classifier(...)`` in
    the classify/ package (excluding direct ``ABC`` root bases). Count-agnostic
    — any future adapter is picked up without editing this pin.
    """
    out: dict[str, str] = {}
    for path in iter_src_files("classify"):
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ClassDef)
                and node.name.endswith("Classifier")
                and not _is_direct_abc(node)
            ):
                out[node.name] = relpath(path)
    return out


def _endpoint_info_branches() -> set[str]:
    """Parse `_endpoint_info_from_config` and return the set of ``cls_id``
    string literals it recognises — one per resolved ``backend`` branch.
    Count-agnostic: walks the assignment `cls_id = "…"` per branch inside the
    function body.
    """
    tree = parse_module(SRC_ROOT / _BAA_GATE_MODULE_REL)
    assert tree is not None, "baa_gate.py did not parse"
    branches: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef)
                and node.name == "_endpoint_info_from_config"):
            continue
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Assign):
                continue
            targets = [t for t in sub.targets if isinstance(t, ast.Name)
                       and t.id == "cls_id"]
            if not targets:
                continue
            if isinstance(sub.value, ast.Constant) and isinstance(sub.value.value, str):
                branches.add(sub.value.value)
    return branches


def _backend_id_of(cls_name: str) -> str:
    """Replay `_backend_for_classifier`'s formula in test-space: strip the
    ``Classifier`` suffix and lowercase. (Kept in-test so any refactor of the
    formula in src surfaces via the symmetry check failing loudly.)"""
    return cls_name.replace("Classifier", "").lower()


# ---------------------------------------------------------------------------
# Pin — symmetry
# ---------------------------------------------------------------------------


def test_backend_symmetry_between_live_and_config_readers():
    """Every concrete `*Classifier` subclass MUST have a matching branch in
    `_endpoint_info_from_config`. Otherwise a new backend shipping via the
    live path silently mismatches the config-snapshot path — distinct
    `baa_ack_key`, `ValueError` on the admin Config panel, per-shape ack
    divergence.
    """
    subclasses = _iter_classifier_subclasses()
    branches = _endpoint_info_branches()
    unmatched: list[str] = []
    for cls_name, src_rel in sorted(subclasses.items()):
        if cls_name in _SYMMETRY_ALLOW:
            continue
        bid = _backend_id_of(cls_name)
        if bid not in branches:
            unmatched.append(
                f"  {cls_name} @ {src_rel}  → backend id "
                f"`{bid}` not in `_endpoint_info_from_config` branches "
                f"({sorted(branches)})"
            )
    assert not unmatched, (
        "N-412 BAA-gate symmetry drift: `*Classifier` subclass(es) present "
        "with no matching branch in `classify/baa_gate.py::"
        "_endpoint_info_from_config`. The two BAA-status readers "
        "(`classifier_baa_status` via `_backend_for_classifier`; "
        "`classifier_baa_status_from_config` via `_endpoint_info_from_config`) "
        "would resolve DISTINCT `(backend, host)` tuples — distinct "
        "`baa_ack_key` values → per-shape ack divergence + `ValueError` on "
        "the admin Config snapshot. Add a branch to "
        "`_endpoint_info_from_config` returning the same `cls_id` that "
        "`_backend_for_classifier` produces for this subclass "
        "(`ClassName.replace('Classifier','').lower()`), OR add an entry "
        "to `_SYMMETRY_ALLOW` justifying the exemption.\n\n"
        + "\n".join(unmatched)
    )


def test_symmetry_allow_list_has_no_stale_entries():
    """PD#7 rot-guard: every `_SYMMETRY_ALLOW` entry MUST correspond to a
    live `*Classifier` class still present in src. A stale entry silently
    exempts a FUTURE class of the same name.
    """
    subclasses = _iter_classifier_subclasses()
    stale = [name for name in _SYMMETRY_ALLOW if name not in subclasses]
    assert not stale, (
        "N-412 rot-guard: `_SYMMETRY_ALLOW` has stale entries (class no "
        "longer in classify/): " + ", ".join(sorted(stale))
    )


# ---------------------------------------------------------------------------
# Pin — baa_ack_key format literal invariance
# ---------------------------------------------------------------------------


def test_baa_ack_key_format_literal_locked():
    """The persisted-settings key shape ``baa_ack:{backend}:{host}`` is
    contractual. A second formatter with different separators would silently
    fork the ack keys (an ack on file goes un-recognised, PHI would be
    blocked or — worse — a distinct new key is silently accepted). Locks
    the f-string constants at the SSOT.
    """
    tree = parse_module(SRC_ROOT / _BAA_GATE_MODULE_REL)
    assert tree is not None
    fmts: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "baa_ack_key":
            for sub in ast.walk(node):
                if isinstance(sub, ast.JoinedStr):
                    parts: list[str] = []
                    for v in sub.values:
                        if isinstance(v, ast.Constant) and isinstance(v.value, str):
                            parts.append(v.value)
                        elif isinstance(v, ast.FormattedValue):
                            parts.append("{}")
                    fmts.append("".join(parts))
    assert fmts == ["baa_ack:{}:{}"], (
        "N-412 BAA-gate key-format drift: `baa_ack_key` must format as "
        "`baa_ack:{backend}:{host}` (a single f-string of that exact shape). "
        f"Found: {fmts!r}. A separator / prefix change silently forks the "
        "persisted-ack namespace — an existing ack on file will fail to "
        "match and PHI egress will be either unnecessarily blocked or "
        "(worse) permitted under a distinct un-acked key."
    )


# ---------------------------------------------------------------------------
# Pin — consumer routing SSOT (PD#5)
# ---------------------------------------------------------------------------


def _module_imports_from_baa_gate(tree: ast.AST) -> set[str]:
    """Return the set of names imported from `email_triage.classify.baa_gate`
    at module scope. Handles both `from ...baa_gate import X` and function-
    local imports of the same shape (a common lazy-import pattern in this
    repo — `baa_gate.py` itself lazy-imports `email_triage.web.db.get_setting`).

    N-409 Drive-4 refinement (db-sme note #1): also delegate to the hoisted
    ``_pin_harness.module_ssot_imports`` which resolves ``import ... as bg``
    module aliases → so a call site using ``bg.baa_ack_key(...)`` resolves
    to the SSOT even though the attribute receiver is ``bg`` (or any
    operator-chosen alias), not the literal name ``baa_gate``. The result
    is a superset of the prior behavior (the raw ImportFrom walk stays for
    lazy-imports which the hoisted helper covers too, but the harness helper
    only walks module-scope imports)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == _BAA_GATE_IMPORT_PATH:
            for alias in node.names:
                names.add(alias.asname or alias.name)
    from _pin_harness import module_ssot_imports
    names |= module_ssot_imports(tree, _BAA_GATE_IMPORT_PATH)
    return names


def _module_alias_receivers_of_baa_gate(tree: ast.AST) -> set[str]:
    """N-409 Drive-4 refinement (db-sme note #1): return every module-alias
    name that resolves to `email_triage.classify.baa_gate` (or a descendant).
    A call site `bg.baa_ack_key(...)` where `bg` is in this set resolves to
    the SSOT even though the attribute receiver is not the literal name
    `baa_gate`. Covers both ``import ... as bg`` and (rare) ``from X import
    baa_gate as bg`` where X is `email_triage.classify` — such an alias
    would bind the module object itself under a receiver name.

    **Residual (documented per DA hedge da-fix-2):** a runtime dynamic
    import like ``bg = importlib.import_module(
    "email_triage.classify.baa_gate")`` is invisible to this AST resolver
    — the module reference materializes only at runtime, and the bound
    name ``bg`` is not linked to the SSOT module in any AST node. Zero
    known offenders at HEAD; a future dynamic-import shape would require
    a text-scan complement or an additional AST pattern."""
    receivers: set[str] = set()
    ssot = _BAA_GATE_IMPORT_PATH
    prefix = ssot + "."
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                if mod == ssot or mod.startswith(prefix):
                    receivers.add(alias.asname or mod.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            # ``from email_triage.classify import baa_gate as bg`` binds
            # the module object to ``bg`` — that name is a receiver too.
            parent = (node.module or "")
            if ssot.startswith(parent + "."):
                trailing = ssot[len(parent) + 1:]  # e.g. "baa_gate"
                for alias in node.names:
                    if alias.name == trailing:
                        receivers.add(alias.asname or alias.name)
    return receivers


def test_gate_primitive_callers_import_from_ssot():
    """Every src call to a gate primitive (`is_safe_for_hipaa`,
    `baa_block_status`, `classifier_baa_status[_from_config]`, `baa_ack_key`,
    `{get,set,revoke}_baa_ack`, and the three helpers) MUST resolve to
    `email_triage.classify.baa_gate` — never a hand-rolled twin. The check
    is scoped to the module containing each call; a call whose module does
    not import the same name from the SSOT is flagged.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _BAA_GATE_MODULE_REL:
            continue  # the SSOT defines them
        tree = parse_module(path)
        if tree is None:
            continue
        imported = _module_imports_from_baa_gate(tree)
        # N-409 Drive-4 refinement (db-sme note #1): resolved-import-path
        # receiver alias set — a call `bg.baa_ack_key(...)` where `bg` is
        # aliased from the SSOT module resolves to the SSOT.
        alias_receivers = _module_alias_receivers_of_baa_gate(tree) | {"baa_gate"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name: str | None = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id in alias_receivers:
                    name = func.attr
            if name in _GATE_PRIMITIVES:
                if isinstance(func, ast.Name) and name not in imported:
                    offenders.append(
                        f"  {rel}:{node.lineno}  calls `{name}(...)` but this "
                        f"module does not `from {_BAA_GATE_IMPORT_PATH} import "
                        f"{name}` — likely a hand-rolled fork."
                    )
    assert not offenders, (
        "N-412 BAA-gate consumer-routing drift: gate primitive(s) called "
        "outside the SSOT without importing the SSOT primitive. This is "
        "how per-account BAA acks diverge: two callers with two "
        f"predicates. Route every call through `{_BAA_GATE_IMPORT_PATH}`.\n\n"
        + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Teeth
# ---------------------------------------------------------------------------


def test_pin_has_teeth():
    """N-237 R23 ARM 4 teeth-probe — plant a fake subclass name, a fake
    format, and a fake un-imported call site; each must be caught by the
    respective helper.
    """
    # Symmetry teeth — a hypothetical class name that would NOT be in the
    # branch set unless someone extended _endpoint_info_from_config.
    fake_cls = "MadeUpProviderXyzClassifier"
    fake_bid = _backend_id_of(fake_cls)
    branches = _endpoint_info_branches()
    assert fake_bid not in branches, (
        "teeth: planted fake backend id unexpectedly present"
    )

    # Format-lock teeth — the constructor of `ast.JoinedStr` from the actual
    # source is exact; a different shape must be recognisably distinct.
    fake_shape = "baa-ack/{}/{}"
    assert fake_shape != "baa_ack:{}:{}", (
        "teeth: planted fake key shape collides with the real shape"
    )

    # Routing teeth — the ImportFrom detector must not match a nearby
    # non-SSOT module path.
    tree = ast.parse(
        "from email_triage.classify.other_module import baa_ack_key\n"
    )
    imported = _module_imports_from_baa_gate(tree)
    assert "baa_ack_key" not in imported, (
        "teeth: routing detector accepted an import from a non-SSOT module"
    )


def test_direct_abc_exemption_has_teeth():
    """``_is_direct_abc`` exempts ONLY an abstract root (direct ``ABC`` base AND
    its own ``@abstractmethod``). A concrete direct-ABC adapter, or a subclass
    of the root, stays checked by the symmetry pin (fail closed)."""

    def cls(src: str) -> ast.ClassDef:
        return next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ClassDef))

    root = cls(
        "class Classifier(ABC):\n"
        "    @abstractmethod\n"
        "    def classify(self): ...\n"
    )
    root_attr = cls(
        "class Classifier(abc.ABC):\n"
        "    @abc.abstractmethod\n"
        "    def classify(self): ...\n"
    )
    concrete = cls("class RogueClassifier(ABC):\n    def classify(self): return 1\n")
    sub = cls(
        "class FooClassifier(Classifier):\n"
        "    @abstractmethod\n"
        "    def classify(self): ...\n"
    )
    meta = cls(
        "class MetaClassifier(metaclass=ABCMeta):\n"
        "    @abstractmethod\n"
        "    def classify(self): ...\n"
    )
    assert _is_direct_abc(root) and _is_direct_abc(root_attr)
    assert not _is_direct_abc(concrete), "teeth: concrete direct-ABC adapter exempted"
    assert not _is_direct_abc(sub), "teeth: subclass of the root exempted"
    assert not _is_direct_abc(meta), "teeth: metaclass=ABCMeta class exempted"
