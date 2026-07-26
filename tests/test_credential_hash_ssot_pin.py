"""Credential-hash SSOT pin (divergence census run14 #1).

A STORED bearer secret — an OTP code, an API key, a recovery code, an
operator-recovery token — must be hashed (and verify-compared) through the ONE
SSOT ``email_triage.web._credhash.hash_credential``. The idiom
``hashlib.sha256(<secret>.encode()).hexdigest()`` was hand-rolled in three
byte-identical credential-hash functions; three forks of a security primitive
are a partial-fix hazard (a KDF/work-factor migration done in two of three
desyncs hash from verify and locks out every credential of that class).

COUNT-AGNOSTIC PROPERTY (over every ``*.py`` in ``src/email_triage`` except the
SSOT module): no ``sha256(<X>.encode(...))`` call may have ``X`` a
credential-named identifier (``code`` / ``key`` / ``token`` / ``secret`` /
``recovery`` / ``otp`` / ``passcode`` / ``password`` / ``api_key``) — that is the
credential-hash idiom and must route through ``hash_credential`` instead. A
``len(...)==N`` count is never used; the AST self-enumerates, so a fourth
credential class is covered the moment it is written.

DOCUMENTED EXCEPTIONS (not stored bearer secrets — must NOT route through the
credential SSOT):
* ``web/csrf.py::_hash_session`` — a CSRF-token-to-session BINDING derivation
  (``sha256(session_token.encode()).hexdigest()[:16]``), not a stored secret
  compared on an auth path. It hashes the session token to derive a CSRF value;
  routing it through the credential SSOT would be a category error.
Content/integrity hashing (cache keys, the HMAC audit chain, file checksums,
SSH-key fingerprints) is NOT matched at all — those hash non-credential-named
values (``canonical`` / ``payload`` / ``blob`` / ``data``).
"""

from __future__ import annotations

import ast
import re

from _pin_harness import enclosing_fn, iter_src_files, parse_module, parse_source, relpath

_ALLOWED_FILE = {"_credhash.py"}
# (relpath, function-name) sites that hash a credential-named var for a NON-credential
# purpose — see module docstring. Keyed on the line-stable (relpath, fn) form.
_ALLOWED_SITES = {
    ("web/csrf.py", "_hash_session"),
}

# A credential-named identifier: the stored-secret vars. ``key`` matches as an
# exact word or a ``*_key`` suffix (NOT "keyword"/"monkey"); ``code``/``token``/etc.
# match as a word component.
#
# NB (DA should-fix B, run14 #1): _CRED_RE is deliberately BROAD — it also
# matches non-credential ``*_key`` / ``*_token`` (``master_key``, ``cache_key``,
# ``public_key``, ``tsig_key``, ``idempotency_key``). Those don't fire today only
# because they're hashed over already-bytes (no ``.encode()``); a future
# ``sha256(master_key.encode())`` WOULD match and must be resolved by adding its
# (relpath, fn) to ``_ALLOWED_SITES`` with a justification (it is not a stored
# bearer secret), NOT by narrowing the regex (which would reopen the cred hole).
_CRED_RE = re.compile(
    r"(?i)(^|_)(code|key|token|secret|recovery|otp|passcode|password|apikey|cred)($|_)"
)


def _final_name(node: ast.AST) -> str | None:
    """The trailing identifier of a Name or attribute chain (``code`` ->
    ``code``; ``self.api_key`` -> ``api_key``), else None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_cred_named(node: ast.AST) -> bool:
    name = _final_name(node)
    return bool(name and _CRED_RE.search(name))


def _credential_in_expr(node: ast.AST) -> bool:
    """True if a credential-named Name/Attribute appears ANYWHERE in ``node`` —
    bare (``code``), attribute (``self.api_key``), concatenated
    (``code + salt``), or interpolated (``f"{otp}{pepper}"``). This is what
    makes the pin catch the KDF-migration re-fork shapes (salt-concat, f-string)
    the SSOT exists to prevent, not just the bare ``sha256(code.encode())``."""
    if _is_cred_named(node):
        return True
    if isinstance(node, ast.BinOp):
        return _credential_in_expr(node.left) or _credential_in_expr(node.right)
    if isinstance(node, ast.JoinedStr):
        return any(
            _credential_in_expr(v.value)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"str", "repr"}
        and node.args
    ):
        return _credential_in_expr(node.args[0])
    return False


def _is_hash_sink(call: ast.Call) -> bool:
    """True if ``call`` constructs or feeds a hash: ``sha256(...)`` (hashlib or
    bare), ``hashlib.new(...)``, or ``<obj>.update(...)``. Covering ``.update``
    and ``hashlib.new`` closes the migration idioms (chained update, new())
    a future re-fork would use (DA should-fix A, census run14 #1)."""
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id == "sha256"
    if isinstance(fn, ast.Attribute):
        if fn.attr == "sha256":
            return True
        if fn.attr == "new" and isinstance(fn.value, ast.Name) and fn.value.id == "hashlib":
            return True
        if fn.attr == "update":  # a hash object's .update(<bytes>)
            return True
    return False


def _feeds_credential(call: ast.Call) -> bool:
    """True if any positional arg of a hash sink is ``<expr>.encode(...)`` where
    ``<expr>`` contains a credential var. The ``.encode()`` is the tell that the
    hashed value is a (string) credential, not already-bytes content."""
    for a in call.args:
        if (
            isinstance(a, ast.Call)
            and isinstance(a.func, ast.Attribute)
            and a.func.attr == "encode"
            and _credential_in_expr(a.func.value)
        ):
            return True
    return False


def _offenders(tree: ast.AST, rel: str) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_hash_sink(node):
            continue
        if not _feeds_credential(node):
            continue
        fn = enclosing_fn(node)
        if (rel, fn) in _ALLOWED_SITES:
            continue
        out.append(f"{rel}:{getattr(node, 'lineno', -1)} ({fn})")
    return out


def test_credential_hash_routes_through_ssot():
    offenders: list[str] = []
    for p in iter_src_files():
        if p.name in _ALLOWED_FILE:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        offenders.extend(_offenders(tree, relpath(p)))
    assert not offenders, (
        "A stored bearer secret is hashed with a hand-rolled "
        "`sha256(<secret>.encode()).hexdigest()` instead of the credential-hash "
        f"SSOT (census run14 #1): {offenders}. Route it through "
        "`email_triage.web._credhash.hash_credential` (both the store side AND "
        "the verify/compare side), so a future KDF migration is a one-line "
        "change. If this is genuinely NOT a stored credential (a derivation like "
        "the CSRF session binding), add (relpath, fn) to _ALLOWED_SITES with a "
        "justification."
    )


def test_pin_has_teeth():
    # The credential idiom IS flagged — bare/attr subjects AND the KDF-migration
    # re-fork shapes (hashlib.new, salt-concat BinOp, f-string, chained .update)
    # that the SSOT exists to prevent (DA should-fix A, census run14 #1).
    for bad in (
        'x = hashlib.sha256(code.encode()).hexdigest()\n',
        'y = sha256(api_key.encode()).hexdigest()\n',
        'z = hashlib.sha256(self.token.encode()).digest()\n',
        'w = hashlib.sha256(recovery_code.encode("utf-8")).hexdigest()\n',
        'p = hashlib.new("sha256", api_key.encode()).hexdigest()\n',
        'q = hashlib.sha256((code + salt).encode()).hexdigest()\n',
        'r = hashlib.sha256(f"{recovery_code}{pepper}".encode()).hexdigest()\n',
        'def h():\n    d = hashlib.sha256()\n    d.update(token.encode())\n',
    ):
        assert _offenders(parse_source(bad), "web/x.py"), f"missed a cred-hash: {bad!r}"
    # The SSOT call + content hashing are NOT flagged
    for ok in (
        'a = hash_credential(code)\n',                                   # SSOT call
        'b = hashlib.sha256(canonical).hexdigest()\n',                   # bytes, no .encode
        'c = hashlib.sha256(payload.encode("utf-8")).hexdigest()\n',     # payload, not cred
        'd = hashlib.sha256(blob).digest()\n',                           # blob fingerprint
        'e = hashlib.sha256(b"literal").hexdigest()\n',                  # literal bytes
    ):
        assert not _offenders(parse_source(ok), "web/x.py"), f"false-flagged: {ok!r}"
    # The csrf session-binding shape DOES match the credential idiom (it hashes
    # `session_token`), so it is excluded by (relpath, fn) allow-list, NOT by the
    # detector shape: flagged at an arbitrary site, NOT at csrf._hash_session.
    csrf = (
        'def _hash_session(session_token):\n'
        '    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()[:16]\n'
    )
    assert _offenders(parse_source(csrf), "web/other.py"), (
        "the session-token shape should match the credential idiom in general"
    )
    assert not _offenders(parse_source(csrf), "web/csrf.py"), (
        "csrf._hash_session must be allow-listed by (relpath, fn)"
    )


def test_ssot_is_byte_identical_to_the_replaced_idiom():
    """The SSOT must produce the SAME hash the three forks did (a behaviour-
    preserving convergence — existing stored credential hashes still verify)."""
    import hashlib

    from email_triage.web._credhash import hash_credential

    for secret in ("123456", "et_live_abcDEF", "recovery-XYZ", ""):
        assert hash_credential(secret) == hashlib.sha256(secret.encode()).hexdigest()
