"""run17 #4 — secret-read funnel pin (PD#1/#2).

Reading a stored secret/credential must route through the ``secrets.py`` read
SSOTs — never a raw ``.require()`` / ``.get()`` on a ``SecretsProvider`` /
bootstrap receiver outside the SSOT module:

  - ``read_secret(provider, key)``            — soft read (None if absent)
  - ``read_secret_required(provider, key)``   — raise-on-missing read (the
    ``.require`` twin; run17 #4)
  - ``read_bootstrap_master_key(cfg)``        — the master-key SSOT (constructs
    a fresh bootstrap provider, then ``read_secret_required``)

WHY pinned: the master key unlocks every ciphertext in ``secrets_store`` AND
derives the ``log_entries`` HMAC audit-chain key, so a master-key read is the
highest-privilege secret read. The census run17 #4 flagged it the "only unpinned
read surface" — ``backup.py`` (DR-bundle export) reads it via raw
``secrets_provider.require(master_key_name)``, bypassing the SSOT. The structural
enumeration (this pin) found the FULL divergent set is 5 raw-provider reads
(2 master-key in ``backup.py`` + 3 bootstrap reads in ``cli.py``); the 46
per-account reads already funnel through ``read_secret`` (converged). The
census's "~43 sites" over-counted by lumping the converged funnel in.

``secrets.py`` (the SSOT home) is EXEMPT — its read SSOTs are the ONE place a raw
``provider.require``/``.get`` is legitimate.

SCOPE CAVEAT (honest, like the by-id pin): the ``.get`` receiver is matched by a
receiver-TYPE predicate (run18 #6, §7d) — a ``.get`` whose receiver STATIC type
resolves to the ``SecretsProvider`` family (see
``_pin_harness.secret_receiver_type_table``) — UNION the legacy receiver-NAME set
(retained as the residual for receivers the static resolver can't type, AND kept
deliberately NARROW so ``.get`` does not false-positive on a dict / a
``_provider_labels.get``). ``.require`` is flagged on ANY receiver (it is a
SecretsProvider-only method — a dict has none), so an aliased master-key read via
``.require`` is caught regardless of receiver name. The residual: a ``.get``
secret-read through a receiver that is NEITHER type-resolvable NOR name-listed.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SECRETS_SSOT_HOME,
    is_secrets_provider_typed_receiver,
    iter_src_files,
    parse_module,  # N-350 R31
    relpath,
    secret_receiver_type_table,
)

# ``.get`` is ambiguous (dicts have it too — ``_provider_labels.get`` etc. are
# NOT secret reads), so only flag ``.get`` on a receiver whose resolved TYPE is a
# SecretsProvider (run18 #6, §7d — PRIMARY) OR a KNOWN secrets-provider name (the
# residual fallback). ``provider`` is in the name set because it is THIS
# codebase's live runtime-DbSecrets alias (cli.py ``cmd_secrets`` binds the
# DbSecrets to ``provider``; cli.py:870 ``provider.rotate_master_key`` / :928
# ``provider.set`` / secrets.py:1282 ``provider.get``) — the single most-probable
# place a future secret read lands, so leaving it out is the run17 #2 "incomplete
# net" trap (DA, run17 #4). The name set is kept NARROW (exact names, not a
# substring) precisely so the ``.get`` arm doesn't re-introduce the dict-``.get``
# false positive the type predicate is careful to avoid.
_SECRET_GET_RECEIVERS = frozenset({"bootstrap", "secrets_provider", "secrets", "_secrets", "provider"})

# The SSOT module — a raw provider read here IS the funnel.
# Sourced from ``_pin_harness.SECRETS_SSOT_HOME`` so this pin and the collapse
# pin (``test_web/test_secret_read_collapse_pin_a5.py``) can't drift out of
# sync — census wf_69674c7e-c67 recommended widening B (2026-07-11).
_EXEMPT_FILES = SECRETS_SSOT_HOME

# (relpath:lineno) sanctioned raw reads, each with a reason. Empty until a real
# exemption is justified; the 5 known offenders are TO BE ROUTED, not allow-listed.
_ALLOW: frozenset[str] = frozenset()


def _receiver_name(func: ast.Attribute) -> str | None:
    v = func.value
    if isinstance(v, ast.Name):
        return v.id
    if isinstance(v, ast.Attribute):
        return v.attr
    return None


def _raw_secret_reads(tree: ast.AST, type_table=frozenset()) -> list[tuple[int, str]]:
    """(lineno, spelling) for raw provider secret-reads in this module.
    ``type_table`` is the §7d resolved-receiver-TYPE set (empty for the in-memory
    teeth, which fall back to the receiver-NAME set)."""
    out: list[tuple[int, str]] = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
            continue
        attr = n.func.attr
        recv = _receiver_name(n.func)
        if attr == "require":
            # SecretsProvider-only method → any receiver is a secrets provider.
            out.append((n.lineno, f"{recv}.require(...)"))
        elif attr == "get" and (
            is_secrets_provider_typed_receiver(n.func, type_table)
            or recv in _SECRET_GET_RECEIVERS
        ):
            out.append((n.lineno, f"{recv}.get(...)"))
    return out


def _find_violations() -> list[str]:
    bad: list[str] = []
    for f in iter_src_files():
        rel = relpath(f)
        if rel in _EXEMPT_FILES:
            continue
        tree = parse_module(f); assert tree is not None, f"parse failed: {f}"  # N-350 R31
        type_table = secret_receiver_type_table(tree)
        for lineno, spelling in _raw_secret_reads(tree, type_table):
            if f"{rel}:{lineno}" in _ALLOW:
                continue
            bad.append(f"{rel}:{lineno}  {spelling}")
    return bad


def test_no_raw_provider_secret_read_outside_secrets_module():
    offenders = _find_violations()
    assert offenders == [], (
        "Raw SecretsProvider read outside secrets.py — route through the read "
        f"SSOT (read_secret / read_secret_required / read_bootstrap_master_key): {offenders}"
    )


def test_pin_has_teeth():
    # .require outside secrets.py → flagged (master-key read bypass)
    bad = ast.parse("def f(secrets_provider, n):\n    return secrets_provider.require(n)\n")
    assert _raw_secret_reads(bad) == [(2, "secrets_provider.require(...)")]
    # bootstrap.get → flagged
    g = ast.parse("def f(bootstrap, k):\n    return bootstrap.get(k)\n")
    assert _raw_secret_reads(g) == [(2, "bootstrap.get(...)")]
    # dict-ish .get on a non-secret receiver → NOT flagged (the FP class)
    ok = ast.parse("def f():\n    return _provider_labels.get('x')\n")
    assert _raw_secret_reads(ok) == []
    # routed through the SSOT → no Attribute .require/.get → NOT flagged
    routed = ast.parse("def f(p, k):\n    return read_secret_required(p, k)\n")
    assert _raw_secret_reads(routed) == []
