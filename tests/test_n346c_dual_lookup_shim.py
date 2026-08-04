"""N-346c (2026-07-08) — dual-lookup shim for the persisted-HMAC drift
class the WAITING-ON-OP default named.

Behaviour tests (functional, not structural pins — the surface is a
call-shape SSOT that the AST-structural pin `test_n346c_read_paths_use_
all_shapes` (below) covers separately):

1. `hash_recipient_for_install(addr, shape='legacy')` reproduces the
   pre-N-346c hash exactly (byte-identical) — a persisted row keyed on
   the pre-N-346c shape MUST still hash to the same key. Regression on
   this = the very orphaning class WAITING-ON-OP asked me to prevent.

2. `hash_recipient_for_install(addr, shape='canonical')` uses
   `canonical_email()`'s normalization (IDNA A-label + display-name
   strip + strip().lower()) — the future-target shape a backfill would
   rewrite persisted rows to.

3. For ASCII-domain / bare-address inputs the two shapes COLLIDE (same
   hash) — dual-lookup is a no-op cost in the common case.

4. For IDN inputs the two shapes DIVERGE — the canonical shape closes
   the A-label/U-label envelope collision class the register row named.

5. `hash_recipient_for_install_all_shapes(addr, secrets)` returns
   `[canonical_hash, legacy_hash]` in that order — canonical first (the
   future-target); order is stable so a read caller iterating first-
   match-wins gets deterministic behaviour.

6. `_normalize_recipient_for_hash(addr, shape)` — the extracted
   normalizer covers the two shapes; an unknown shape raises ValueError
   (fail-CLOSED — a typo can't silently pick a shape).

7. `get_gmail_watch_by_email` READ path tries BOTH shapes — a row
   persisted with the legacy shape is still found by an IDN-envelope
   canonical-shape lookup.

Not covered by this file (deliberate scope): the audit-trail hash in
`merge_overlays_for_recipients` (line ~1301) still uses legacy shape to
preserve audit-trail continuity with existing rows — that's a data-
migration decision separate from the read-shim. If operator opts to
backfill, that call flips to canonical alongside the backfill script.
"""
from __future__ import annotations

import ast
import hashlib
import hmac
import pytest

from email_triage.style_learning.per_contact_hipaa import (
    _HASH_SHAPES,
    _normalize_recipient_for_hash,
    hash_recipient_for_install,
    hash_recipient_for_install_all_shapes,
)
from _pin_harness import SRC_ROOT, parse_module


# A stub secrets backend that returns a fixed per-install salt so the
# hash is deterministic across the test suite. `read_secret(secrets,
# key)` returns `str | None`; the salt is stored as a hex string per
# `get_or_init_recipient_salt` (line 215: `secrets.set(KEY, salt.hex())`).
from email_triage.style_learning.per_contact_hipaa import (
    HIPAA_RECIPIENT_SALT_SECRET_KEY,
)


class _StubSecrets:
    def __init__(self, salt: bytes = b"test-install-salt-32-bytes-long!") -> None:
        self._salt = salt

    def get(self, key: str) -> str | None:
        if key == HIPAA_RECIPIENT_SALT_SECRET_KEY:
            return self._salt.hex()
        return None

    def set(self, key: str, value: str) -> None:  # pragma: no cover
        pass


_SECRETS = _StubSecrets()


def _legacy_hash_manually(addr: str, salt: bytes) -> str:
    """Recompute the pre-N-346c legacy hash from scratch, independent of
    the module under test, so the regression test can catch a subtle
    shape drift in the extracted `_normalize_recipient_for_hash` helper.
    """
    from email_triage.mail_headers import _extract_addr
    bare = _extract_addr(addr)
    normalised = bare.strip().lower()
    return hmac.new(
        salt, normalised.encode("utf-8"), hashlib.sha256,
    ).hexdigest()


def test_legacy_shape_reproduces_pre_n346c_hash():
    """Fail-loud on shape drift: the legacy shape's hash must equal the
    from-scratch pre-N-346c computation to the byte."""
    addr = "Alice <alice@example.com>"
    expected = _legacy_hash_manually(addr, _SECRETS._salt)
    got = hash_recipient_for_install(addr, secrets=_SECRETS, shape="legacy")
    assert got == expected, (
        "Legacy hash shape drifted — every persisted per_contact_hipaa_v2 "
        "row is now orphaned. This is the exact regression class N-346c "
        "was written to prevent."
    )


def test_default_shape_is_legacy():
    """Backward-compat: the default shape MUST be legacy so an
    unmigrated caller (WRITE path) keeps producing the current
    persisted-row hash."""
    addr = "bob@example.com"
    default_hash = hash_recipient_for_install(addr, secrets=_SECRETS)
    legacy_hash = hash_recipient_for_install(
        addr, secrets=_SECRETS, shape="legacy",
    )
    assert default_hash == legacy_hash


def test_ascii_inputs_collide_across_shapes():
    """ASCII-domain, bare-address inputs — the two shapes hash-collide.
    Dual-lookup is a no-op cost for the common case."""
    for addr in (
        "alice@example.com",
        "carol@sub.example.co.uk",
        "Alice <alice@example.com>",
    ):
        legacy = hash_recipient_for_install(
            addr, secrets=_SECRETS, shape="legacy",
        )
        canonical = hash_recipient_for_install(
            addr, secrets=_SECRETS, shape="canonical",
        )
        assert legacy == canonical, (
            f"ASCII input {addr!r} produced divergent shapes — either "
            "the legacy strip().lower() is wrong or canonical_email() "
            "does more than IDNA-encode on ASCII."
        )


def test_idn_inputs_diverge_across_shapes():
    """IDN inputs — legacy strip().lower() keeps the U-label domain,
    canonical IDNA-encodes it to A-label. The two hashes MUST differ,
    which is what closes the A-label / U-label envelope collision
    class the register row named."""
    # Munich in German + IDNA A-label form. `.strip().lower()` keeps
    # Unicode; `canonical_email()` idna-encodes.
    idn_addr = "alice@münchen.de"
    legacy = hash_recipient_for_install(
        idn_addr, secrets=_SECRETS, shape="legacy",
    )
    canonical = hash_recipient_for_install(
        idn_addr, secrets=_SECRETS, shape="canonical",
    )
    assert legacy != canonical, (
        "IDN input hashed identically across shapes — canonical_email() "
        "didn't IDNA-encode the domain. The dual-lookup shim is a no-op "
        "for IDN installs; that's the class N-346c was written to close."
    )


def test_all_shapes_returns_canonical_first_then_legacy():
    """Iteration order is stable + canonical is first so a first-match-
    wins reader migrates naturally as soon as a canonical-shape write
    lands. Legacy-shape rows are still findable via the second probe."""
    addr = "alice@münchen.de"
    shapes = hash_recipient_for_install_all_shapes(
        addr, secrets=_SECRETS,
    )
    assert len(shapes) == 2
    assert shapes[0] == hash_recipient_for_install(
        addr, secrets=_SECRETS, shape="canonical",
    )
    assert shapes[1] == hash_recipient_for_install(
        addr, secrets=_SECRETS, shape="legacy",
    )
    # And the constant tuple carries the shapes in the same order (a
    # future new shape MUST land here first as the SSOT).
    assert _HASH_SHAPES == ("canonical", "legacy")


def test_normalize_unknown_shape_raises_valueerror():
    """Fail-CLOSED on typo. A stray shape like `"canonicl"` MUST raise —
    not silently degrade to `legacy`."""
    with pytest.raises(ValueError, match="unknown hash shape"):
        _normalize_recipient_for_hash("alice@example.com", "canonicl")


def test_hash_unknown_shape_raises_valueerror():
    """The typed API also fail-CLOSED. A caller passing shape='typo'
    MUST raise so the typo surfaces at first call, not silently write
    a third-shape hash into the persisted store."""
    with pytest.raises(ValueError, match="unknown hash shape"):
        hash_recipient_for_install(
            "alice@example.com", secrets=_SECRETS, shape="typo",
        )


def test_all_shapes_covers_every_declared_shape():
    """`hash_recipient_for_install_all_shapes` covers EVERY shape in
    _HASH_SHAPES — a new shape added to the enum without extending the
    dual-lookup SSOT would silently drop future-migration coverage.
    Count-agnostic: assert equality of the returned length to the
    enum's arity, and that every declared shape's hash is present in
    the returned list."""
    addr = "alice@münchen.de"  # IDN so shapes diverge, all distinct
    got = hash_recipient_for_install_all_shapes(addr, secrets=_SECRETS)
    for s in _HASH_SHAPES:
        expected = hash_recipient_for_install(
            addr, secrets=_SECRETS, shape=s,
        )
        assert expected in got, (
            f"Shape {s!r} declared in _HASH_SHAPES but its hash is not "
            "included in the dual-lookup all-shapes result. A new shape "
            "was added to the enum without extending the SSOT."
        )
    assert len(got) == len(_HASH_SHAPES)


def test_read_call_at_overlay_lookup_iterates_all_shapes():
    """Structural pin — the OVERLAY read path in per_contact_hipaa.py
    MUST route its address→hash lookup through
    `hash_recipient_for_install_all_shapes()` (not the single-shape
    variant). Catches a future regression that reverts the read path.

    N-346c-tail-B refactor: `get_contact_style_overlay` is now a thin
    wrapper on `get_contact_style_overlay_with_hash`; the dual-lookup
    call moved to `_with_hash`. Either function containing the SSOT
    call satisfies the pin — the invariant is "SOMEWHERE in the
    overlay-lookup call chain the `_all_shapes` SSOT fires", not "the
    single top-level entry point calls it".
    """
    src = SRC_ROOT / "style_learning" / "per_contact_hipaa.py"
    tree = parse_module(src)
    assert tree is not None
    OVERLAY_LOOKUP_FN_NAMES = {
        "get_contact_style_overlay",
        "get_contact_style_overlay_with_hash",
    }
    found = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in OVERLAY_LOOKUP_FN_NAMES:
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            func = inner.func
            if isinstance(func, ast.Name) and func.id == "hash_recipient_for_install_all_shapes":
                found = True
                break
            if isinstance(func, ast.Attribute) and func.attr == "hash_recipient_for_install_all_shapes":
                found = True
                break
        if found:
            break
    assert found, (
        "N-346c: the overlay-lookup call chain "
        f"({sorted(OVERLAY_LOOKUP_FN_NAMES)!r}) must call "
        "`hash_recipient_for_install_all_shapes()` — the SSOT for the "
        "dual-lookup read shim. Single-shape reads reopen the "
        "A-label/U-label IDN envelope collision the shim closed."
    )


def test_get_gmail_watch_by_email_uses_dual_lookup():
    """Structural pin — the gmail_watches read path
    `get_gmail_watch_by_email` MUST reference `canonical_email` in its
    body (the second shape's normalizer). Catches a future regression
    that reverts the read to single-shape."""
    src = SRC_ROOT / "web" / "db.py"
    tree = parse_module(src)
    assert tree is not None
    found = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name != "get_gmail_watch_by_email":
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name) and inner.id == "canonical_email":
                found = True
                break
            if isinstance(inner, ast.Attribute) and inner.attr == "canonical_email":
                found = True
                break
    assert found, (
        "N-346c: `get_gmail_watch_by_email` must reference "
        "`canonical_email` in its body — the dual-lookup shim tries "
        "the canonical shape before the legacy shape so IDN-envelope "
        "webhooks find their persisted watch row. Removing this call "
        "reopens the collision class the shim was written to close."
    )
