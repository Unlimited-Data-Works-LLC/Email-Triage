""" v0.2.0 — ``Fernet(x)`` construction trust-envelope allow-list pin.

Discovered by the census-convergence workflow `wf_bbfca658-a38`
(2026-07-11). Cryptography primitives ``Fernet(x)`` should not be
constructed at arbitrary sites — each construction is a trust envelope
whose key material must trace to a documented source (master key,
per-record derived key, or passphrase KDF).

Enumeration (`grep -rn "Fernet(" src/email_triage --include="*.py"`):

- ``secrets.py:481``, ``:585``, ``:793`` — the secrets-store SSOT (Keyfile
  + Db backends + rotation). Master key from
  ``read_bootstrap_master_key`` / ``master_key_from_env``. §164.312(a)(2)(iv)
  encryption-of-record.
- ``backup.py:174``, ``:201`` — bundle envelope encryption. Key material
  is a PASSPHRASE-DERIVED (scrypt/PBKDF) per-bundle key + fresh random
  salt (`_secrets.token_bytes`) — a DIFFERENT trust envelope from the
  secrets-store master key. Backup archives are separately-recoverable
  under a user-typed passphrase; folding them into the secrets SSOT
  would break the recovery-without-master-key invariant.
- ``providers/_msal_cache_crypto.py:80``, ``:112`` — MSAL token cache
  envelope. Key material is ``_get_master_key()`` (same master key
  family as secrets.py) but the storage domain is separate: MSAL cache
  files on disk vs the ``secrets_store`` DB table. Folding them would
  couple two orthogonal storage lifecycles.

All 5 non-SSOT sites are LEGITIMATELY separate crypto envelopes —
verified-don't-accepted against the census's HAND_ROLLED_SSOT_DUP
initial classification.

Prime Directive #1 down-payment: the trust-envelope map ships its
count-agnostic structural pin same-change. Prime Directive #6:
routes through the shared ``_pin_harness`` walker.

The pin is PATH-anchored (not line-anchored) — learn from the
``test_new_run_id_ssot_pin.py`` line-drift trap (5082→5086 caught
by CI 2026-07-11) documented in
``feedback_divergence_audit_and_ssot_pin``.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


# Path-anchored allow-list. Each entry is the repo-relative posix path
# of a module where ``Fernet(x)`` MAY be constructed. New sites require
# a documented trust envelope + a comment justification + adding here.
_ALLOWED_FERNET_HOMES: frozenset[str] = frozenset({
    "secrets.py",  # secrets-store SSOT (KeyfileSecrets / DbSecrets / rotate_master_key)
    "backup.py",  # passphrase-KDF-derived per-bundle envelope
    "providers/_msal_cache_crypto.py",  # MSAL token cache separate storage domain
})


def _is_fernet_construction(node: ast.AST) -> bool:
    """Return True if ``node`` is a ``Fernet(...)`` call.

    Accepts either the bare ``Fernet(x)`` (import via ``from
    cryptography.fernet import Fernet``) or the attribute-access
    ``fernet.Fernet(x)`` / ``cryptography.fernet.Fernet(x)`` forms.
    """
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    if isinstance(fn, ast.Name) and fn.id == "Fernet":
        return True
    if isinstance(fn, ast.Attribute) and fn.attr == "Fernet":
        return True
    return False


def test_fernet_construction_only_at_allowed_homes():
    """Ban ``Fernet(x)`` construction outside the trust-envelope map.

    A new Fernet construction site should be a DELIBERATE decision to
    introduce a new crypto envelope — surface it in review by requiring
    the pin author to think about the key-material provenance + storage
    lifecycle, and to add the file to :data:`_ALLOWED_FERNET_HOMES`
    with a comment explaining the envelope.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        # Path suffix match — allow-list stores repo-relative posix
        # paths under ``src/email_triage/`` (e.g. ``secrets.py``
        # matches ``src/email_triage/secrets.py``; the sub-package
        # entry ``providers/_msal_cache_crypto.py`` matches
        # ``src/email_triage/providers/_msal_cache_crypto.py``).
        if any(rel.endswith(home) for home in _ALLOWED_FERNET_HOMES):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if _is_fernet_construction(node):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        " trust-envelope map: ``Fernet(x)`` construction at a site "
        "not in the documented allow-list. Each Fernet construction is "
        "a NEW crypto envelope whose key material must trace to a "
        "documented source. If this site really needs its own envelope "
        "(new storage domain + distinct key material vs the secrets "
        f"SSOT), justify it and add its path to _ALLOWED_FERNET_HOMES "
        f"in `tests/test_fernet_construction_allowlist_pin.py`. Current "
        f"allow-list: {sorted(_ALLOWED_FERNET_HOMES)}.\n\n" +
        "\n".join(offenders)
    )
