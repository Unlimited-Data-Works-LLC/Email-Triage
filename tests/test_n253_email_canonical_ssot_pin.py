"""N-253 R25 structural pin — email-address canonicalization SSOT (2026-07-03).

Census R25 discovered HIGH #1 (email-address canonicalization,
§164.312(a)(1) recipient-allow-list gate): 30+ inline `.strip().lower()`
sites re-derive the canonical form on address-shaped variables. Weakest
variant: recipient-allow-list gates at `web/digest.py:622`,
`web/email_watches.py:839`, `topic_digest_sender.py:568` — a write/read
recipe drift = unauthorized-recipient send.

N-253 fix (staged):
  - `mail_headers.canonical_email(x)` — new SSOT (wraps
    `extract_bare_address` which already handles bare + display-name
    shapes and lowercases).
  - Migrated 2 recipient-allow-list gates (`web/digest.py:622`,
    `web/email_watches.py:839`). `topic_digest_sender.py:568` —
    verify-don't-accept: does not exist at HEAD (census cited a stale
    path; actual file is `actions/topic_digest_sender.py` — deferred to
    a follow-up sweep if the class re-fires).

WHAT IT PINS (structural, STRICT):

Any `<name>.strip().lower()` OR `(<name> or "").strip().lower()`
where the receiver-name matches an address-shaped identifier
(sender/from/to/recipient/email/address/etc.) OUTSIDE the SSOT module
`mail_headers.py` fires.

Migration is per-file: run this pin, migrate the flagged site to
`canonical_email(<name>)`, re-run.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_ADDR_NAMES = frozenset({
    "sender", "sender_email", "from_addr", "from_address",
    "to_addr", "to_address", "recipient", "recipient_email",
    "email", "address", "contact_address", "primary_address",
    "target_email", "notify_email", "envelope_from", "envelope_to",
})

_SSOT_FILES = {"mail_headers.py"}

# Existing sites that ALREADY drift but are lower-priority per census
# (subject/keyword/domain filters — not address-shaped). Also
# non-recipient uses of address-shaped names that don't need the
# display-name canonical form.
_ALLOW: frozenset[str] = frozenset({
    # 2026-07-03 N-253 R25 baseline. Migration is per-file follow-up.
    # These are TREE-WIDE seen sites that use an address-shaped var
    # name but don't gate a §164.312(a)(1) recipient allow-list.
    "actions/hipaa_style_distill.py",
    "actions/sent_mail_index.py",
    "actions/style_profile.py",
    "db/accounts.py",
    "engine/embedding_backend.py",
})


def _receiver_name(node: ast.AST) -> str | None:
    """Return the address-shaped identifier name if this expression
    ultimately resolves to `<name>.strip().lower()` OR
    `(<name> or "").strip().lower()`, else None."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "lower" and not node.args):
        return None
    # .lower() on a .strip() call
    strip_call = node.func.value
    if not (isinstance(strip_call, ast.Call) and isinstance(strip_call.func, ast.Attribute)
            and strip_call.func.attr == "strip"):
        return None
    recv = strip_call.func.value
    # Direct Name receiver: `foo.strip().lower()`
    if isinstance(recv, ast.Name):
        return recv.id
    # `(foo or "").strip().lower()` — BoolOp Or with a Name.
    if isinstance(recv, ast.BoolOp) and isinstance(recv.op, ast.Or):
        for v in recv.values:
            if isinstance(v, ast.Name):
                return v.id
    return None


def test_no_raw_strip_lower_on_address_shaped_var():
    """STRICT tree-wide: `<name>.strip().lower()` where <name> is an
    address-shaped identifier outside `mail_headers.py` OR the
    allow-list must route through `canonical_email(<name>)`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] in _SSOT_FILES:
            continue
        if rel in _ALLOW:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            name = _receiver_name(node)
            if name in _ADDR_NAMES:
                offenders.append(f"{rel}:{node.lineno}  {name}.strip().lower()")
    assert not offenders, (
        "N-253 R25 §164.312(a)(1) canonical-email SSOT: raw "
        "`<address-var>.strip().lower()` outside `mail_headers.py`. "
        "Route through `canonical_email(<var>)` — a display-name-wrapped "
        "envelope shape (`Alice <a@x>`) and the bare form (`a@x`) MUST "
        "compare identically in recipient allow-list gates.\n\n"
        + "\n".join(offenders)
    )


def test_canonical_email_ssot_shape():
    """Anti-vacuity: `canonical_email` handles the 4 wire shapes +
    empty."""
    from email_triage.mail_headers import canonical_email
    assert canonical_email("Alice <a@x.com>") == "a@x.com"
    assert canonical_email("a@x.com") == "a@x.com"
    assert canonical_email("A@X.COM") == "a@x.com"
    assert canonical_email("  Bob <B@Y.COM>  ") == "b@y.com"
    assert canonical_email("") == ""
    assert canonical_email(None) == ""
