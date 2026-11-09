"""Action-log ``extra=`` shape SSOT uniqueness pin (divergence census run14 #8).

``actions/base.build_action_log_extras(flow, message, classification, provider,
**more)`` is the ONE assembler of the structured action-log ``extra`` dict —
``flow_id`` + ``message_id`` + ``provider`` + ``category`` + the workforce-identity
cluster (``owner`` / ``account_name`` / ``account_id`` from ``flow.state_bag``) +
the PHI-gated ``sender`` / ``subject``. Operators triage "did this flow run, on
whose account?" by grepping those fields, so the shape must stay consistent across
every action that emits it.

CENSUS run14 #8 RESHAPED (verify-don't-accept). The census read "8 of 12 actions
hand-roll ``extra={flow_id}`` → non-adopters" and proposed "ban bare
``extra=<dict-literal>`` in ``Action.execute``". That remedy is REFUTED as
too-broad: the un-migrated sites are legitimately DIFFERENT log lines — a
"skipping; already applied" notice, a placeholder/error-path diagnostic, a
per-escalation-step log — that carry their own minimal context (``{flow_id}`` /
``{flow_id, error_type}`` / ``{account_id}``), and the structured action RESULT is
recorded via ``record_idempotent_done`` / ``ActionOutput`` (not the log line). They
are NOT impoverished result lines and forcing the rich shape on a "skipping" log
would be noise. The label/move/add_label/regulatory_clock per-item action lines
(the ones with the rich shape) DO route through the SSOT.

So there is no live ADOPTION divergence to migrate. What the SSOT lacked is its
PD#1 pin. THIS is it — a UNIQUENESS pin (PD#5 "two mirrored copies WILL drift"):
no function OTHER than ``build_action_log_extras`` may ASSEMBLE the workforce-
identity cluster (write BOTH ``owner`` and ``account_name`` as dict keys — a Dict
literal key OR a subscript-assignment target ``d["owner"] = …``). A future action
that hand-rolls ``{… "owner": …, "account_name": …}`` instead of calling the SSOT
is the real drift, and it is RED here. Scoped to ``actions/`` (the action-log
shape; an unrelated ``owner``/``account_name`` dict elsewhere — an API payload, a
template context — is not this concern).

Anti-vacuity is built in: the detector FIRES on the SSOT itself (it assembles the
cluster via subscript), and the SSOT is the SOLE allow-listed site — so a green
result proves the detector has teeth AND that nothing else assembles the cluster.
"""

from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, iter_src_files, parse_module, relpath

_SSOT_FN = "build_action_log_extras"
# The workforce-identity cluster the SSOT assembles from flow.state_bag. BOTH keys
# present = an action-log identity dict (only the SSOT legitimately builds it).
_CLUSTER = frozenset({"owner", "account_name"})


def _dict_str_keys(node: ast.Dict) -> set[str]:
    return {
        k.value for k in node.keys
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }


def _subscript_assign_key(node: ast.AST) -> str | None:
    """``d["owner"] = …`` → ``"owner"`` (a STRING subscript that is an assignment
    TARGET — the assemble idiom the SSOT uses); else None."""
    if not isinstance(node, ast.Assign):
        return None
    for tgt in node.targets:
        if (
            isinstance(tgt, ast.Subscript)
            and isinstance(tgt.slice, ast.Constant)
            and isinstance(tgt.slice.value, str)
        ):
            return tgt.slice.value
    return None


def _cluster_assemblers(tree: ast.AST) -> set[str]:
    """Enclosing-function names that ASSEMBLE the cluster — reference BOTH cluster
    keys as a dict-literal key or a subscript-assignment target, AND in the SAME
    function (so two unrelated single-key dicts don't conspire)."""
    keys_by_fn: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        fn = None
        keys: set[str] = set()
        if isinstance(node, ast.Dict):
            keys = _dict_str_keys(node) & _CLUSTER
            if keys:
                fn = enclosing_fn(node)
        else:
            k = _subscript_assign_key(node)
            if k in _CLUSTER:
                keys = {k}
                fn = enclosing_fn(node)
        if fn is not None and keys:
            keys_by_fn.setdefault(fn, set()).update(keys)
    return {fn for fn, ks in keys_by_fn.items() if _CLUSTER <= ks}


def test_only_the_ssot_assembles_the_action_log_identity_cluster():
    offenders = []
    ssot_seen = False
    for p in iter_src_files("actions"):
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        for fn in _cluster_assemblers(tree):
            if fn == _SSOT_FN:
                ssot_seen = True
            else:
                offenders.append(f"{relpath(p)}::{fn}")
    assert not offenders, (
        "A function OTHER than actions/base.build_action_log_extras assembles the "
        "action-log workforce-identity cluster (owner + account_name) — a second "
        "mirrored copy of the action-log extra shape that WILL drift from the SSOT "
        f"(PD#5/census run14 #8):\n  " + "\n  ".join(offenders)
        + "\nCall build_action_log_extras(flow, message, classification, provider, "
        "**more) instead of hand-rolling the dict."
    )
    # Anti-vacuity: the detector MUST fire on the SSOT (proving it has teeth and the
    # cluster is the real assemble signature). If the SSOT stopped assembling the
    # cluster, the whole pin would be vacuously green.
    assert ssot_seen, (
        "build_action_log_extras no longer assembles owner+account_name — the pin "
        "is now vacuous. Re-anchor _CLUSTER to the SSOT's current identity fields."
    )


def test_pin_has_teeth():
    # A dict-literal hand-roll of the cluster outside the SSOT IS flagged.
    bad_literal = parse_source_module(
        'def _extras():\n'
        '    return {"flow_id": fid, "owner": o, "account_name": an}\n'
    )
    assert _cluster_assemblers(bad_literal) == {"_extras"}
    # The subscript-assembly idiom (what the SSOT itself uses) IS flagged too.
    bad_subscript = parse_source_module(
        'def _extras():\n'
        '    d = {}\n'
        '    d["owner"] = o\n'
        '    d["account_name"] = an\n'
        '    return d\n'
    )
    assert _cluster_assemblers(bad_subscript) == {"_extras"}
    # A dict with only ONE cluster key is NOT flagged (a minimal/diagnostic extra,
    # e.g. the legitimately-un-migrated `extra={"account_id": ...}` lines).
    one_key = parse_source_module(
        'def _log():\n'
        '    return {"flow_id": fid, "account_id": aid}\n'
    )
    assert _cluster_assemblers(one_key) == set()
    # Two SEPARATE single-key dicts in one function do NOT conspire to a false hit.
    split = parse_source_module(
        'def _two():\n'
        '    a = {"owner": o}\n'
        '    b = {"account_name": an}\n'
        '    return a, b\n'
    )
    # owner (in dict a) + account_name (in dict b) are in the SAME function, so this
    # WOULD be flagged by the function-level union — which is correct: a function
    # building both keys IS assembling the cluster, even across two dicts.
    assert _cluster_assemblers(split) == {"_two"}


def parse_source_module(src: str) -> ast.AST:
    import ast as _ast
    from _pin_harness import annotate_parents
    tree = _ast.parse(src)
    annotate_parents(tree)
    return tree
