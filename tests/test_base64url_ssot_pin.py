""" census-live tail — base64 decode SSOT structural pin (PD#1).

Ships with the ``email_triage._base64url`` SSOT (2026-07-11) same
change. Enforces: no call to ``base64.b64decode(...)`` or
``base64.urlsafe_b64decode(...)`` inside ``src/email_triage/`` outside
the SSOT home OR the allow-list below. New code lands through
``email_triage._base64url.b64decode_permissive`` — the SSOT handles
the pad-to-multiple-of-4 re-padding so unpadded URL-safe input decodes
correctly instead of raising ``binascii.Error``.

The allow-list is seeded with EVERY pre-SSOT ``base64.b64decode`` site
in the codebase at 1508d3d0 that llm-host ``qwen3.6:35b`` prepass
classified as PAD_HANDLED_SAFELY — sites that decode trusted-internal
roundtrip data (bundle export, signed-blob roundtrip, cache-key hash
prefix, etc.) where padding is guaranteed by an in-repo encoder.
These sites are DRIFT-STABLE at HEAD, not correctness gaps; each is a
conscious ``(rel, lineno)`` entry so a future edit at that seam is a
CI-visible decision (allow-list entries are audited by
``feedback_dont_over_defer`` — each stays as long as its rationale
does, and if the surrounding code moves the entry MUST be re-verified,
not just re-shifted).

Migration path: the four HIGH-severity decode-fail sites the SSOT was
built for — ``mail_headers.py:541``, ``providers/office365.py:865``,
``web/dev_keypair.py:101``, ``web/routers/webhooks.py:112`` — are NOT
allow-listed; they route through ``b64decode_permissive`` in this
same commit. Follow-up drives converging the 10 remaining
PAD_HAND_ROLLED sites (per llm-host ``scratchpad_leira_123_enum.json``)
DELETE their allow-list entries as they migrate.
"""
from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, iter_src_files, parse_module, relpath


_STDLIB_DECODE_ATTRS: frozenset[str] = frozenset({
    "b64decode", "urlsafe_b64decode",
})

# Seeded allow-list of the pre-SSOT trusted-internal decoder sites at
# 1508d3d0. Each entry is a ``(rel, lineno)`` pair — the shape used by
# other structural pins in this project (see `test_new_run_id_ssot_pin.py`
# `_NAMED_DEVIATIONS`). Follow-up drives DELETE entries as they migrate.
#  (2026-07-11) name-anchored migration: `(rel, enclosing_fn)` shape
# survives unrelated line shifts. Trade-off: a function-scope allow-list
# means all decode calls in a listed function are trusted, which is a
# controlled loosening — the semantic-review rationale below still
# governs each listed function.
_ALLOW_STDLIB_DECODE_SITES: frozenset[tuple[str, str]] = frozenset({
    # backup.py — DR-bundle export roundtrip; encoder ships padding.
    ("backup.py", "_derive_key"),
    ("backup.py", "derive_etbk_passphrase"),
    # cli.py — bootstrap master-key roundtrip via SSOT encoder that ships
    # padding. (cli.py :3407/:3409 migrated onto SSOT under .)
    ("cli.py", "cmd_auth_dev_login"),
    # mail_headers.py — pre-check that swallows exceptions and returns "";
    # the decode-fail arm was migrated onto SSOT under . This encoder
    # ships padding.
    ("mail_headers.py", "encode_draft_body_header"),
    # secrets.py — Fernet envelope roundtrip; encoder ships padding.
    ("secrets.py", "_fernet_master_key_bytes"),
    # web/background_sweepers.py — trusted-internal roundtrip.
    ("web/background_sweepers.py", "run_backup_once"),
    # web/dev_keypair.py — one-way SHA256 fingerprint display; not part
    # of a binary roundtrip.
    ("web/dev_keypair.py", "fingerprint"),
    # web/webauthn_auth.py — llm-host PAD_HANDLED_SAFELY; uses
    # `webauthn.helpers.base64url_to_bytes` which internally handles padding.
    ("web/webauthn_auth.py", "finish_passkey_authentication"),
    # web/routers/auth_keys.py — `import base64 as _b64` convenience alias
    # + URLSafeSerializer roundtrip; the serializer handles padding
    # transparently. Two functions in the WebAuthn login pair.
    # (auth_keys.py :396 + :509 + :516 + :525 migrated onto SSOT .)
    ("web/routers/auth_keys.py", "login_passkey_begin"),
    ("web/routers/auth_keys.py", "login_passkey_finish"),
    # web/routers/ui/profile.py — trusted-internal roundtrip across 5
    # sites; llm-host classified all PAD_HANDLED_SAFELY. 5 unique functions.
    ("web/routers/ui/profile.py", "_topic_editor_snapshot"),
    ("web/routers/ui/profile.py", "_hit_from_verdict"),
    ("web/routers/ui/profile.py", "_hit_from_keyword"),
    ("web/routers/ui/profile.py", "profile_topic_digest_hit_feedback"),
    ("web/routers/ui/profile.py", "profile_topic_digest_feedback_unmute"),
})


def _is_stdlib_decode_call(node: ast.AST) -> bool:
    """Match ``base64.<b64decode|urlsafe_b64decode>(...)`` — a stdlib
    decode via the module attribute."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr not in _STDLIB_DECODE_ATTRS:
        return False
    v = f.value
    return isinstance(v, ast.Name) and v.id == "base64"


def _is_stdlib_decode_importfrom(node: ast.AST) -> bool:
    """Match ``from base64 import b64decode`` / ``urlsafe_b64decode``
    (with or without ``as _alias``). DA F2 on the 2026-07-11 batched
    panel: the local-name shadow evasion was originally documented as
    an out-of-scope residual — but that IS the drift-shape the pin is
    meant to close per PD#2 (make the pin interprocedural) + PD#6
    (pins obey the SSOT rule). Ban it outright at the ImportFrom
    node — a shadow-alias that never gets called still means the
    stdlib decoder is now bound to a project-local name; the drift-
    class is closed at the import, not at the call."""
    if not isinstance(node, ast.ImportFrom):
        return False
    if node.module != "base64":
        return False
    for alias in node.names:
        if alias.name in _STDLIB_DECODE_ATTRS:
            return True
    return False


def _is_stdlib_alias_import(node: ast.AST) -> bool:
    """Match ``import base64 as <alias>`` — the module-alias evasion
    of the standard `import base64` idiom.  tail (2026-07-11):
    task  filed for the broader ImportFrom-alias interprocedural
    walker. This arm closes the module-alias half of that class: a
    caller `import base64 as _b64; _b64.b64decode(x)` would use the
    aliased-module attribute shape, which the current
    `_is_stdlib_decode_call` walker (matching `base64.<attr>`) would
    NOT catch. Banning the aliased-module import outright is cheaper
    than tracking asname bindings through the tree — and matches the
    project convention of module-qualified stdlib calls using the
    literal name `base64`."""
    if not isinstance(node, ast.Import):
        return False
    for alias in node.names:
        if alias.name == "base64" and alias.asname is not None:
            return True
    return False


def test_no_stdlib_b64decode_outside_ssot_home_or_allow_list():
    """No caller may invoke ``base64.b64decode(...)`` /
    ``base64.urlsafe_b64decode(...)`` outside ``_base64url.py`` (the
    SSOT home) or the seeded allow-list. Route via
    ``email_triage._base64url.b64decode_permissive`` instead — it
    re-pads before decoding so unpadded URL-safe input works."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        # SSOT home is EXEMPT — its body defines the funnel.
        if rel.endswith("_base64url.py"):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if _is_stdlib_alias_import(node):
                #  tail — ban aliased-module import shape
                # ``import base64 as _b64`` outside the SSOT home.
                key = (rel, enclosing_fn(node))
                if key in _ALLOW_STDLIB_DECODE_SITES:
                    continue
                offenders.append(
                    f"{rel}:{node.lineno}  import base64 as <alias>"
                )
                continue
            if _is_stdlib_decode_importfrom(node):
                # DA F2 (2026-07-11 batched panel) — ban local-name
                # shadow imports of the stdlib decoders, since the
                # module-attribute check below would not catch a
                # subsequent bare call to the aliased name. A single
                # ``from base64 import b64decode`` outside the SSOT
                # home + allow-list is enough to trip.
                key = (rel, enclosing_fn(node))
                if key in _ALLOW_STDLIB_DECODE_SITES:
                    continue
                offenders.append(
                    f"{rel}:{node.lineno}  from base64 import "
                    f"{[a.name for a in node.names if a.name in _STDLIB_DECODE_ATTRS]}"
                )
                continue
            if not _is_stdlib_decode_call(node):
                continue
            key = (rel, enclosing_fn(node))
            # DB-SME nit fold (2026-07-11 batched panel): dropped the
            # basename fallback that was dead code at HEAD — a nested
            # ``web/backup.py`` would silently share the same
            # ``("backup.py", 166)`` slot as ``src/email_triage/backup.py``
            # under the fallback shape. Every allow-list entry now uses
            # its full relpath key.
            if key in _ALLOW_STDLIB_DECODE_SITES:
                continue
            offenders.append(f"{rel}:{node.lineno}  base64.{node.func.attr}(...)")
    assert not offenders, (
        " base64 decode SSOT: route via "
        "`email_triage._base64url.b64decode_permissive(s)` (or `.b64encode_"
        "urlsafe(data)` for the write arm) instead of `base64.b64decode`. "
        "The SSOT re-pads before decoding so unpadded URL-safe input "
        "(WebAuthn / JWT / Gmail push / O365 push) decodes correctly "
        "instead of raising `binascii.Error`. "
        "Add the site to `_ALLOW_STDLIB_DECODE_SITES` ONLY if the caller "
        "receives trusted-internal data with guaranteed-padded encoder.\n\n"
        + "\n".join(offenders)
    )
