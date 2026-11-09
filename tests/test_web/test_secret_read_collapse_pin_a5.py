"""A5 (divergence census 2026-06-09) — secret-read silent-collapse pin.

The  typed :class:`email_triage.secrets.SecretsDecryptError` exists to
keep two conditions APART: a secret that was never configured (``get``
returns ``None``) versus a secret row that exists but is unreadable —
a corrupt ciphertext or, far more likely, an install-wide master-key
mismatch. Folding the latter back into the former silently degrades a
security control: a webhook ships UNSIGNED, an O365 push is mis-rejected
as "clientstate unset", a configured account reports "needs re-auth".

The divergence census found ~14 call sites that each wrapped their secret
read in a broad ``except Exception:``/bare ``except:`` that returned a
falsy default — every one collapsing *unreadable* into *absent*. The fix
(A5) introduced a single sanctioned reader, ``secrets.read_secret``, which
propagates ``SecretsDecryptError``, and rewrote every collapse site to
either let it propagate or catch it *explicitly* and fail closed.

This pin is **count-agnostic** — it does not assert "N sites"; it asserts
the STRUCTURAL invariant over every site: no function under
``src/email_triage`` may wrap a secret read in a broad ``except`` that
swallows the error (does not re-raise). Intentional handling must name
``SecretsDecryptError`` (or another specific type) explicitly. New code
that reintroduces the broad-swallow pattern fails here regardless of how
many sites exist.
"""

from __future__ import annotations

import ast

import pytest

# Shared structural-pin harness (R5b): the ONE home for the src walk, relpath,
# and AST parse so this pin cannot drift in its scoping. ``relpath(p)`` here is
# the canonical ``web/db.py`` form (relative to ``SRC_ROOT``); this pin's relpath
# is used ONLY in violation/offender MESSAGES (never an allow-list key or an
# equality/needle check — the SSOT allow-list ``_SECRET_GET_SSOT_FILES`` is keyed
# on ``path.name``), so the base change from the old ``src/email_triage/web/db.py``
# form to ``web/db.py`` is harmless.
from _pin_harness import SECRETS_SSOT_HOME, iter_src_files, parse_module, relpath

# Broad handler types that swallow indiscriminately. A bare ``except:``
# (handler.type is None) is also broad.
_BROAD_NAMES = {"Exception", "BaseException"}


def _is_secret_read(call: ast.Call) -> bool:
    """True if ``call`` reads a secret: ``read_secret(...)`` (the sanctioned
    SSOT) or a provider ``.get(...)`` / ``.require(...)`` on a ``*secret*`` /
    ``*bootstrap*`` receiver.

    CAVEAT (heuristic scope, per SME N-1): the attribute arm matches only when
    the receiver's rendered name contains "secret" (e.g. ``secrets``,
    ``self._secrets``, ``secrets_provider``) or "bootstrap" (the master-key
    provider). A secret read aliased to a non-matching name — ``sp =
    get_secrets(req); sp.get(k)`` — is NOT matched here, so wrapping THAT in a
    broad swallow would slip past this pin. The mitigation is the SSOT itself:
    new reads go through ``read_secret`` (always matched).

    The ``.require`` arm + the ``bootstrap`` receiver (census run12 #4) close
    the bootstrap MASTER-KEY provider read — the highest-blast-radius secret (it
    unlocks DbSecrets AND the HMAC audit chain) — which the original ``.get``-
    on-``secret``-only arm matched by NEITHER (``secrets_provider.require(...)``
    / ``bootstrap.require(...)``). A future broad-swallow around a ``.require``
    master-key read is now caught.

    DELIBERATELY NOT matched: the ``read_bootstrap_master_key(config)`` SSOT
    function. verify-don't-accept (census run12 #4): its callers
    (``web/app.py`` boot, the ``cmd_db_encrypt/decrypt`` CLI cutover helpers)
    LEGITIMATELY fold ``except Exception: key = None`` — but that None is the
    boot contract's input, NOT a silent degradation: ``enforce_db_encryption_
    boot_contract`` converts a missing-OR-unreadable key into a hard
    RuntimeError (never plaintext), and the cutover helpers are "wrong-key
    brick-impossible" by design. Matching the function would false-positive on
    that fail-closed-downstream pattern; the ``.require`` provider arm covers
    the actual unguarded-read risk without it."""
    func = call.func
    if isinstance(func, ast.Name) and func.id == "read_secret":
        return True
    if isinstance(func, ast.Attribute) and func.attr in {"get", "require"}:
        try:
            recv = ast.unparse(func.value)
        except Exception:  # pragma: no cover - ast.unparse always present 3.9+
            return False
        recv_l = recv.lower()
        return "secret" in recv_l or "bootstrap" in recv_l
    return False


def _try_body_reads_secret(node: ast.Try) -> bool:
    for stmt in node.body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call) and _is_secret_read(sub):
                return True
    return False


def _handler_is_broad(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:  # bare ``except:``
        return True
    if isinstance(handler.type, ast.Name):
        return handler.type.id in _BROAD_NAMES
    if isinstance(handler.type, ast.Tuple):
        return any(
            isinstance(e, ast.Name) and e.id in _BROAD_NAMES
            for e in handler.type.elts
        )
    return False


def _handler_reraises(handler: ast.ExceptHandler) -> bool:
    return any(isinstance(sub, ast.Raise) for sub in ast.walk(handler))


def _handler_names_decrypt_error(handler: ast.ExceptHandler) -> bool:
    """True if the handler explicitly catches ``SecretsDecryptError``."""
    t = handler.type
    if t is None:
        return False
    candidates = t.elts if isinstance(t, ast.Tuple) else [t]
    for c in candidates:
        if isinstance(c, ast.Name) and c.id == "SecretsDecryptError":
            return True
        if isinstance(c, ast.Attribute) and c.attr == "SecretsDecryptError":
            return True
    return False


def _handler_is_meaningful(handler: ast.ExceptHandler) -> bool:
    """A handler does *something* with the caught decrypt error — logs,
    re-raises, returns, or sets a sentinel consumed downstream (e.g.
    ``secret_unreadable = True`` → a later fail-closed drop). Only a body
    that is SOLELY ``pass`` / ``...`` / a docstring is "swallow to nothing"
    — the one shape that silently discards the typed error."""
    for stmt in handler.body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue  # bare ``...`` or a docstring string-literal
        return True
    return False


def _find_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:  # pragma: no cover - unparseable file skipped
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            if not _try_body_reads_secret(node):
                continue
            rel = relpath(path)
            decrypt_handlers = [
                h for h in node.handlers if _handler_names_decrypt_error(h)
            ]
            has_explicit_decrypt = bool(decrypt_handlers)
            # Loophole guard: an explicit ``except SecretsDecryptError`` that
            # swallows to nothing (bare pass) re-creates the A5 defect.
            for h in decrypt_handlers:
                if not _handler_is_meaningful(h):
                    violations.append(
                        f"{rel}:{h.lineno} (SecretsDecryptError swallowed "
                        f"to nothing)"
                    )
            # The core invariant: the *decrypt* case must be distinctly
            # handled. A broad swallow is the A5 defect ONLY when no explicit
            # SecretsDecryptError handler distinguishes the unreadable case —
            # a broad fallback for genuinely-transient errors (alongside an
            # explicit decrypt handler) is fine.
            if has_explicit_decrypt:
                continue
            for handler in node.handlers:
                if _handler_is_broad(handler) and not _handler_reraises(handler):
                    violations.append(f"{rel}:{handler.lineno}")
    return violations


def test_no_broad_except_swallows_a_secret_read():
    """No secret read may sit under a broad ``except`` that swallows the
    error. Catch ``SecretsDecryptError`` explicitly (or re-raise) instead.

    If this fails, the offending ``file:line`` collapses an UNREADABLE
    secret (master-key mismatch / corrupt row) into the ABSENT path —
    exactly the A5 divergence. Fix: route the read through
    ``secrets.read_secret`` and handle ``SecretsDecryptError`` explicitly,
    failing closed.
    """
    violations = _find_violations()
    assert violations == [], (
        "Broad except swallowing a secret read (A5 silent-collapse) at:\n  "
        + "\n  ".join(violations)
        + "\nUse `except SecretsDecryptError:` (fail closed + log) or let it "
        "propagate; never fold an unreadable secret into the absent path."
    )


def test_pin_has_teeth_detects_a_planted_collapse(tmp_path):
    """Guard against the pin silently passing because its matcher broke:
    a synthetic collapse site MUST be detected."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "def f(secrets, k):\n"
        "    try:\n"
        "        return secrets.get(k) or ''\n"
        "    except Exception:\n"
        "        return ''\n",
        encoding="utf-8",
    )
    tree = parse_module(planted); assert tree is not None
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and _try_body_reads_secret(node):
            for h in node.handlers:
                if _handler_is_broad(h) and not _handler_reraises(h):
                    hits.append(h.lineno)
    assert hits, "pin matcher failed to flag a planted silent-collapse site"


def _violations_in_source(src: str, tmp_path) -> list[str]:
    p = tmp_path / "snippet.py"
    p.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and _try_body_reads_secret(node):
            decrypt = [h for h in node.handlers if _handler_names_decrypt_error(h)]
            for h in decrypt:
                if not _handler_is_meaningful(h):
                    out.append(("pass-loophole", h.lineno))
            if decrypt:
                continue
            for h in node.handlers:
                if _handler_is_broad(h) and not _handler_reraises(h):
                    out.append(("broad-swallow", h.lineno))
    return out


def test_two_tier_handler_is_exempt(tmp_path):
    """An explicit SecretsDecryptError handler ALONGSIDE a broad fallback
    (the is_authenticated shape) is NOT a violation — the unreadable case
    is distinctly handled; the broad arm is for transient backend errors."""
    src = (
        "def f(secrets, k):\n"
        "    try:\n"
        "        return bool(read_secret(secrets, k))\n"
        "    except SecretsDecryptError:\n"
        "        log.error('unreadable'); return False\n"
        "    except Exception:\n"
        "        return False\n"
    )
    assert _violations_in_source(src, tmp_path) == []


def test_pass_only_decrypt_handler_is_flagged(tmp_path):
    """`except SecretsDecryptError: pass` swallows the typed error to
    nothing — it re-creates the A5 defect and must be flagged."""
    src = (
        "def f(secrets, k):\n"
        "    try:\n"
        "        return read_secret(secrets, k)\n"
        "    except SecretsDecryptError:\n"
        "        pass\n"
    )
    kinds = [k for k, _ in _violations_in_source(src, tmp_path)]
    assert "pass-loophole" in kinds


def test_require_arm_and_bootstrap_receiver_have_teeth(tmp_path):
    """census run12 #4 — the ``.require`` arm + the ``bootstrap`` receiver catch
    a swallowed MASTER-KEY provider read; the ``read_bootstrap_master_key`` SSOT
    is deliberately NOT matched (its fold-to-None is the fail-closed boot
    contract enforced downstream, not a silent collapse)."""
    src_secret = (
        "def f(secrets_provider, k):\n"
        "    try:\n"
        "        return secrets_provider.require(k)\n"
        "    except Exception:\n"
        "        return None\n"
    )
    assert _violations_in_source(src_secret, tmp_path), \
        ".require on a secret receiver in a broad swallow must be flagged"
    src_bootstrap = (
        "def g(bootstrap, k):\n"
        "    try:\n"
        "        return bootstrap.require(k)\n"
        "    except Exception:\n"
        "        return None\n"
    )
    assert _violations_in_source(src_bootstrap, tmp_path), \
        ".require on a bootstrap receiver in a broad swallow must be flagged"
    src_ssot = (
        "def h(config):\n"
        "    try:\n"
        "        return read_bootstrap_master_key(config)\n"
        "    except Exception:\n"
        "        return None\n"
    )
    assert _violations_in_source(src_ssot, tmp_path) == [], \
        "read_bootstrap_master_key fold-to-None (fail-closed boot contract) must NOT be flagged"


def test_read_secret_propagates_decrypt_error():
    """The SSOT itself must NOT swallow — it propagates SecretsDecryptError
    and returns None only for the genuinely-absent / no-provider cases."""
    from email_triage.secrets import SecretsDecryptError, read_secret

    class _Raises:
        def get(self, key):
            raise SecretsDecryptError(key)

    class _Absent:
        def get(self, key):
            return None

    assert read_secret(None, "X") is None  # no provider -> absent
    assert read_secret(_Absent(), "X") is None  # key absent -> None
    with pytest.raises(SecretsDecryptError):
        read_secret(_Raises(), "X")  # unreadable -> propagates, never None


# ---------------------------------------------------------------------------
# #9 (divergence census 2026-06-10) — secret reads route through the SSOT.
#
# A5 (above) bans the broad-swallow-AROUND a secret read. #9 enforces the
# funnel itself: a raw provider read ``<secrets>.get(key)`` must go through
# ``read_secret`` instead. A5's own SCOPE CAVEAT notes that the broad-swallow
# guard's `.get` arm only matches a "secret"-named receiver, so a read aliased
# to a non-"secret" name slips past it — the mitigation is "prefer read_secret".
# This pin makes that mitigation MANDATORY: the raw provider ``.get`` lives in
# exactly ONE place, the SSOT home ``secrets.py`` (``read_secret`` +
# ``SecretsProvider`` impls). Everywhere else, route through ``read_secret`` so
# the A5 broad-swallow guard keeps full structural coverage + a master-key
# mismatch fails closed uniformly.
# ---------------------------------------------------------------------------

# The SSOT home — the ONLY module where a raw ``<secrets>.get`` is sanctioned
# (read_secret's own body + the provider backends it dispatches to).
# Sourced from ``_pin_harness.SECRETS_SSOT_HOME`` so this pin and the funnel pin
# (``test_secret_read_funnel_pin.py``) can't drift out of sync — census
# wf_69674c7e-c67 recommended widening B (2026-07-11). A future ``secrets.py``
# → ``secrets/`` package split updates the constant in ONE place, both pins
# widen at once.
_SECRET_GET_SSOT_FILES = SECRETS_SSOT_HOME


def _is_provider_receiver(recv: str) -> bool:
    """True when the rendered receiver is a secrets PROVIDER — the local
    ``secrets`` / ``secrets_provider`` or an attribute ``*.secrets`` /
    ``*._secrets`` (e.g. ``self.secrets``, ``self._secrets``). Tighter than the
    A5 broad-swallow heuristic precisely so this BAN doesn't false-positive on
    a config collection that merely ends in ``_secrets``: a BARE ``_secrets``
    suffix (``valid_secrets``, ``account_secrets`` — both real config names,
    not providers) is deliberately NOT matched; only the exact provider locals
    + dotted ``.secrets``/``._secrets`` attribute accesses are.

    SCOPE CAVEAT (R38, inherited from A5): this is BLIND to a provider aliased
    to a receiver name outside this set — e.g. ``prov = get_secrets(req);
    prov.get(k)`` or ``store = app.state.secrets; store.get(k)``. HEAD
    enumeration confirms no such alias exists (every ``get_secrets(...)`` result
    is bound to ``secrets``/``secrets_provider``, both matched). Re-census on any
    new ``x = get_secrets(...)`` / ``x = *.state.secrets`` binding to a
    non-conventional name; the convention to enforce is "name the local
    ``secrets``." A5 disclosed this gap; #9 keeps that disclosure honest."""
    low = recv.lower()
    return (
        low == "secrets"
        or low == "secrets_provider"
        or low.endswith(".secrets")
        or low.endswith("._secrets")
    )


def _raw_provider_get_lines(tree: ast.AST) -> list[int]:
    out: list[int] = []
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "get" and n.args):
            try:
                recv = ast.unparse(n.func.value)
            except Exception:  # pragma: no cover
                continue
            if _is_provider_receiver(recv):
                out.append(n.lineno)
    return out


def test_secret_reads_route_through_read_secret_ssot():
    """No module outside the SSOT home may read a secret via a raw provider
    ``<secrets>.get(key)`` — route it through ``email_triage.secrets.read_secret``
    so the A5 broad-swallow guard keeps full coverage and a master-key mismatch
    fails closed uniformly. A genuinely-needed raw get may carry an inline
    ``# secret-read-ok`` marker with a one-line justification."""
    offenders: list[str] = []
    for path in iter_src_files():
        if path.name in _SECRET_GET_SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        try:
            source_text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # pragma: no cover
            continue
        src = source_text.splitlines()
        rel = relpath(path)
        for ln in _raw_provider_get_lines(tree):
            line = src[ln - 1] if 0 < ln <= len(src) else ""
            if "secret-read-ok" in line:
                continue
            offenders.append(f"{rel}:{ln}")
    assert offenders == [], (
        "Raw provider secret read outside the read_secret SSOT (#9):\n  "
        + "\n  ".join(offenders)
        + "\nUse read_secret(secrets, key) instead (or mark a justified raw "
        "get with an inline `# secret-read-ok` comment)."
    )


def test_route_ssot_pin_has_teeth(tmp_path):
    """The #9 ban must flag a planted raw provider get + ignore read_secret."""
    bad = (
        "def f(secrets, self_):\n"
        "    a = secrets.get('SMTP_PASSWORD')\n"      # raw provider get -> flagged
        "    b = self.secrets.get('k')\n"             # raw provider get -> flagged
        "    return a, b\n"
    )
    assert len(_raw_provider_get_lines(ast.parse(bad))) == 2
    ok = (
        "def f(secrets, d):\n"
        "    a = read_secret(secrets, 'SMTP_PASSWORD')\n"   # SSOT -> not a raw get
        "    b = d.get('not_a_secret')\n"                   # plain dict -> not provider
        "    c = my_cache.get('x')\n"                       # non-secret receiver
        # Config collections that merely END in '_secrets' (real names:
        # config.valid_secrets is a set, account_secrets a dict) are NOT
        # providers and must NOT be flagged — the false-positive boundary.
        "    e = valid_secrets.get('x')\n"
        "    g = account_secrets.get('x')\n"
        "    return a, b, c, e, g\n"
    )
    assert _raw_provider_get_lines(ast.parse(ok)) == []
