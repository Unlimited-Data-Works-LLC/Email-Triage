"""punch 548 / N-544 — structural pins over the Gmail push JWKS fetch.

Three properties, each a PROPERTY over every matching site rather than a count
(PD-1), each with a teeth arm that plants the bad shape and the good one
(PD-2/PD-7), and all three routed through the shared `_pin_harness` walk so
the pin cannot drift in its own scoping (PD-6).

* **Arm A — every `raise` out of `_CertCache` is one of the two typed errors.**
  This is the enumeration half of panel546 H-6 and it is deliberately stated
  as the WEAKER of the two: an `ast.Raise` node is the only thing it can see,
  so an UNGUARDED call that propagates somebody else's exception type
  (`resp.json()`, `RSAAlgorithm.from_jwk`) produces no `Raise` node and is
  INVISIBLE to this arm. Arm B is what carries "complete by construction".
* **Arm B — every external `get_key` call sits in a guard with the right
  handler ORDER.** Keyed on the SEAM, not on the source (PD-2): whatever
  `_CertCache` grows later, a caller of `get_key` must re-raise the two typed
  errors FIRST and convert anything else to `GmailPushVerificationError`.
  The order matters and is asserted: a catch-all placed first would eat
  `GmailPushTransientFetchError` and silently turn the 503/retry arm into a
  401.
* **Arm C — no JWKS fetch bypasses the refresh gate.** Any function in
  `gmail_push_auth.py` that obtains the HTTP client must consult
  `_refresh_allowed()`. This is the anti-drift half of H-5: the gate lives
  inside the one function that fetches, and a SECOND fetcher added later
  would be a fresh amplification arm.

What these pins do NOT claim: they say nothing about the interval's VALUE, the
negative cache's bounds, or whether a redirect is followed. Those are
behavioural and live in `tests/test_web/test_punch548_jwks_fetch_hardening.py`.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth,
    enclosing_qualified_name,
    parse_module,
    relpath,
    walk_src,
)

_MODULE = "web/gmail_push_auth.py"
_TYPED = frozenset({"GmailPushVerificationError", "GmailPushTransientFetchError"})
_CACHE_CLASS = "_CertCache"
_GATE = "_refresh_allowed"
_LOCK = "_get_refresh_lock"


# ---------------------------------------------------------------------------
# shared node predicates
# ---------------------------------------------------------------------------


def _raised_name(node: ast.Raise) -> str | None:
    """The exception TYPE name a `raise` names, or None for a bare re-raise."""
    exc = node.exc
    if exc is None:
        return None
    if isinstance(exc, ast.Call):
        exc = exc.func
    if isinstance(exc, ast.Name):
        return exc.id
    if isinstance(exc, ast.Attribute):
        return exc.attr
    return None


def _handler_names(handler: ast.ExceptHandler) -> set[str]:
    t = handler.type
    if t is None:
        return {"<bare>"}
    parts = t.elts if isinstance(t, ast.Tuple) else [t]
    out: set[str] = set()
    for p in parts:
        if isinstance(p, ast.Name):
            out.add(p.id)
        elif isinstance(p, ast.Attribute):
            out.add(p.attr)
    return out


def _body_reraises_bare(handler: ast.ExceptHandler) -> bool:
    return any(isinstance(s, ast.Raise) and s.exc is None
               for s in ast.walk(ast.Module(body=handler.body, type_ignores=[])))


def _body_raises(handler: ast.ExceptHandler, name: str) -> bool:
    mod = ast.Module(body=handler.body, type_ignores=[])
    return any(isinstance(s, ast.Raise) and _raised_name(s) == name
               for s in ast.walk(mod))


def _is_client_get(node: ast.AST) -> bool:
    """`self._http.get()` — the ONE way this module obtains an HTTP client."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr != "get":
        return False
    recv = node.func.value
    return (isinstance(recv, ast.Attribute) and recv.attr == "_http"
            and isinstance(recv.value, ast.Name) and recv.value.id == "self")


def _calls_named(fn: ast.AST, name: str) -> bool:
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute) and f.attr == name:
                return True
            if isinstance(f, ast.Name) and f.id == name:
                return True
    return False


# ---------------------------------------------------------------------------
# Arm A — every raise inside _CertCache is typed
# ---------------------------------------------------------------------------


def _detect_untyped_raise_in_cache(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Raise):
            continue
        qual = enclosing_qualified_name(node)
        if not qual.startswith(f"{_CACHE_CLASS}."):
            continue
        name = _raised_name(node)
        if name is None:          # bare re-raise: the type is unchanged
            continue
        if name not in _TYPED:
            out.append(f"{qual} raises {name}")
    return out


def test_every_raise_out_of_the_cert_cache_is_typed():
    """No `raise` inside `_CertCache` names a type outside the two the
    webhook handler catches. A third type would reach the route as a 500 and
    Pub/Sub would retry hard on it (the 2026-06-25 shape, N-288)."""
    seen = 0
    violations: list[str] = []
    for _path, rel, tree in walk_src():
        hits = _detect_untyped_raise_in_cache(tree)
        if rel == _MODULE:
            seen += 1
        violations += [f"{rel}: {h}" for h in hits]
    assert seen == 1, (
        f"punch 548 arm A never saw {_MODULE} — the pin is mis-scoped and "
        "would read green over an empty set"
    )
    assert not violations, (
        "punch 548 / H-6: an untyped `raise` inside _CertCache:\n  "
        + "\n  ".join(violations)
    )


def test_arm_a_has_teeth():
    assert_pin_has_teeth(
        _detect_untyped_raise_in_cache,
        bad_source=(
            "class _CertCache:\n"
            "    async def _refresh(self):\n"
            "        raise ValueError('untyped')\n"
        ),
        good_source=(
            "class _CertCache:\n"
            "    async def _refresh(self):\n"
            "        raise GmailPushTransientFetchError('typed')\n"
        ),
    )


# ---------------------------------------------------------------------------
# Arm B — the seam: every external get_key call is guarded, in the right order
# ---------------------------------------------------------------------------


def _is_get_key_call(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get_key")


def _external_get_key_calls(tree: ast.AST) -> list[ast.Call]:
    """Every `x.get_key(...)` call outside `_CertCache` itself. Enclosure is
    resolved by the harness (`enclosing_qualified_name`), never by a
    hand-rolled parent climb — harness contract #8."""
    return [n for n in ast.walk(tree)
            if _is_get_key_call(n)
            and not enclosing_qualified_name(n).startswith(f"{_CACHE_CLASS}.")]


def _guard_defects(guard: ast.Try) -> list[str]:
    """What is wrong with this `try` as a typed-net guard, if anything."""
    typed_at = catchall_at = None
    for i, h in enumerate(guard.handlers):
        names = _handler_names(h)
        if _TYPED <= names and _body_reraises_bare(h) and typed_at is None:
            typed_at = i
        elif ({"Exception", "<bare>"} & names
              and _body_raises(h, "GmailPushVerificationError")
              and catchall_at is None):
            catchall_at = i
    out: list[str] = []
    if typed_at is None:
        out.append("no handler re-raises BOTH typed errors bare")
    if catchall_at is None:
        out.append("no catch-all handler converts to "
                   "GmailPushVerificationError")
    if typed_at is not None and catchall_at is not None \
            and typed_at > catchall_at:
        out.append("the catch-all precedes the typed re-raise, so "
                   "GmailPushTransientFetchError is flattened into a 401")
    return out


def _detect_unguarded_get_key_seam(tree: ast.AST) -> list[str]:
    """Top-down (no parent climb): a call is guarded when some `try` IN THE
    SAME function has the call inside its `body` and no guard defect."""
    tries = [n for n in ast.walk(tree) if isinstance(n, ast.Try)]
    out: list[str] = []
    for call in _external_get_key_calls(tree):
        qual = enclosing_qualified_name(call)
        candidates = []
        for t in tries:
            if enclosing_qualified_name(t) != qual:
                continue
            if any(id(x) == id(call)
                   for stmt in t.body for x in ast.walk(stmt)):
                candidates.append(t)
        if not candidates:
            out.append(f"{qual}: get_key call is not inside a try")
            continue
        per_try = [_guard_defects(t) for t in candidates]
        if all(defects for defects in per_try):
            # No candidate guard is clean — report the least-broken one.
            out += [f"{qual}: {d}" for d in min(per_try, key=len)]
    return out


def test_every_external_get_key_call_is_guarded():
    """Every caller of `_CertCache.get_key` outside the class wraps it so that
    the two typed errors re-raise unchanged and FIRST, and anything else
    becomes `GmailPushVerificationError`. The net is then complete by
    construction rather than by enumerating `_refresh`'s failure modes."""
    seen = 0
    violations: list[str] = []
    for _path, rel, tree in walk_src():
        # ONE predicate for "an external get_key call", shared with the
        # detector — a second copy here is exactly the drift PD-5 forbids.
        seen += len(_external_get_key_calls(tree))
        violations += [f"{rel}: {h}" for h in _detect_unguarded_get_key_seam(tree)]
    assert seen >= 1, (
        "punch 548 arm B found NO external get_key call anywhere in src — "
        "the seam was renamed and this pin is now blind"
    )
    assert not violations, (
        "punch 548 / H-6 (PD-2, at the seam):\n  " + "\n  ".join(violations)
    )


_GOOD_SEAM = (
    "async def verify(cache, kid):\n"
    "    try:\n"
    "        key = await cache.get_key(kid)\n"
    "    except (GmailPushVerificationError, GmailPushTransientFetchError):\n"
    "        raise\n"
    "    except Exception as e:\n"
    "        raise GmailPushVerificationError('x') from e\n"
    "    return key\n"
)


def test_arm_b_has_teeth_against_an_unguarded_call():
    assert_pin_has_teeth(
        _detect_unguarded_get_key_seam,
        bad_source=(
            "async def verify(cache, kid):\n"
            "    key = await cache.get_key(kid)\n"
            "    return key\n"
        ),
        good_source=_GOOD_SEAM,
    )


def test_arm_b_has_teeth_against_a_reversed_handler_order():
    """The order arm, planted separately: a catch-all FIRST swallows the
    transient error, so the 503/retry arm silently becomes a 401."""
    assert_pin_has_teeth(
        _detect_unguarded_get_key_seam,
        bad_source=(
            "async def verify(cache, kid):\n"
            "    try:\n"
            "        key = await cache.get_key(kid)\n"
            "    except Exception as e:\n"
            "        raise GmailPushVerificationError('x') from e\n"
            "    except (GmailPushVerificationError, "
            "GmailPushTransientFetchError):\n"
            "        raise\n"
            "    return key\n"
        ),
        good_source=_GOOD_SEAM,
    )


def test_arm_b_has_teeth_against_a_missing_typed_reraise():
    assert_pin_has_teeth(
        _detect_unguarded_get_key_seam,
        bad_source=(
            "async def verify(cache, kid):\n"
            "    try:\n"
            "        key = await cache.get_key(kid)\n"
            "    except Exception as e:\n"
            "        raise GmailPushVerificationError('x') from e\n"
            "    return key\n"
        ),
        good_source=_GOOD_SEAM,
    )


# ---------------------------------------------------------------------------
# Arm C — no fetch bypasses the refresh gate
# ---------------------------------------------------------------------------


def _holds_the_gate(fn: ast.AST) -> bool:
    """A function that consults the floor AND takes the single-flight lock."""
    return _calls_named(fn, _GATE) and _calls_named(fn, _LOCK)


def _detect_ungated_fetch(tree: ast.AST) -> list[str]:
    """Interprocedural (PD-2): the fetch moved behind a helper when the
    DB-546-3 lock landed, and a pin keyed on the fetching function alone
    would have gone blind at exactly that refactor. So a fetcher is gated
    either directly, or because EVERY in-module caller of it holds both the
    floor and the lock."""
    fns = [n for n in ast.walk(tree)
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    fetchers = [fn for fn in fns if any(_is_client_get(n) for n in ast.walk(fn))]
    holders = {fn.name for fn in fns if _holds_the_gate(fn)}
    out: list[str] = []
    for fn in fetchers:
        if _holds_the_gate(fn):
            continue
        callers = {
            enclosing_qualified_name(c).split(".")[-1]
            for c in ast.walk(tree)
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
            and c.func.attr == fn.name
        }
        if not callers:
            out.append(
                f"{fn.name} obtains the HTTP client, holds neither "
                f"{_GATE}() nor the lock, and nothing in this module calls it"
            )
        elif not callers <= holders:
            out.append(
                f"{fn.name} obtains the HTTP client and is reached from "
                f"{sorted(callers - holders)}, which do not hold both "
                f"{_GATE}() and the single-flight lock"
            )
    return out


def test_no_jwks_fetch_bypasses_the_refresh_gate():
    """Every function in `gmail_push_auth.py` that obtains the HTTP client
    consults `_refresh_allowed()`. A second fetcher added later without the
    gate would be a fresh copy of the N-544 amplification arm."""
    tree = parse_module(
        [p for p, rel, _t in walk_src() if rel == _MODULE][0]
    )
    assert tree is not None, f"punch 548 arm C could not parse {_MODULE}"
    fetchers = [
        fn.name for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(_is_client_get(n) for n in ast.walk(fn))
    ]
    assert fetchers, (
        "punch 548 arm C found NO `self._http.get()` in "
        f"{_MODULE} — the fetch was respelled and this pin is now blind"
    )
    violations = _detect_ungated_fetch(tree)
    assert not violations, (
        "punch 548 / H-5: an ungated JWKS fetch:\n  " + "\n  ".join(violations)
    )


_GOOD_FETCH = (
    "class _CertCache:\n"
    "    async def _refresh(self):\n"
    "        async with self._get_refresh_lock():\n"
    "            if not self._refresh_allowed():\n"
    "                raise GmailPushTransientFetchError('gated')\n"
    "            await self._fetch_and_install()\n"
    "    async def _fetch_and_install(self):\n"
    "        client = await self._http.get()\n"
    "        await client.get(URL)\n"
)


def test_arm_c_has_teeth():
    """A fetcher with no gate at all."""
    assert_pin_has_teeth(
        _detect_ungated_fetch,
        bad_source=(
            "class _CertCache:\n"
            "    async def _refresh(self):\n"
            "        client = await self._http.get()\n"
            "        await client.get(URL)\n"
        ),
        good_source=_GOOD_FETCH,
    )


def test_arm_c_has_teeth_against_an_ungated_second_caller():
    """The interprocedural arm: the helper is gated through `_refresh`, and a
    SECOND caller that skips the gate is the drift this pin exists for."""
    assert_pin_has_teeth(
        _detect_ungated_fetch,
        bad_source=_GOOD_FETCH + (
            "    async def warm(self):\n"
            "        await self._fetch_and_install()\n"
        ),
        good_source=_GOOD_FETCH,
    )


def test_arm_c_has_teeth_against_a_gate_without_the_lock():
    """DB-546-3: the floor alone refuses concurrent waiters instead of
    coalescing them, so the lock is part of the property."""
    assert_pin_has_teeth(
        _detect_ungated_fetch,
        bad_source=(
            "class _CertCache:\n"
            "    async def _refresh(self):\n"
            "        if not self._refresh_allowed():\n"
            "            raise GmailPushTransientFetchError('gated')\n"
            "        await self._fetch_and_install()\n"
            "    async def _fetch_and_install(self):\n"
            "        client = await self._http.get()\n"
            "        await client.get(URL)\n"
        ),
        good_source=_GOOD_FETCH,
    )


# ---------------------------------------------------------------------------
# the gate predicate is ONE predicate (PD-5)
# ---------------------------------------------------------------------------


def test_the_refresh_floor_is_spelled_once():
    """`_JWKS_MIN_REFRESH_INTERVAL_SECS` is compared against a clock in
    exactly ONE place — `_refresh_allowed`. Two copies of the comparison would
    be the duplicated-predicate drift PD-5 forbids, and the second copy is
    where the floor would silently differ."""
    path = [p for p, rel, _t in walk_src() if rel == _MODULE][0]
    tree = parse_module(path)
    sites = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(
            isinstance(n, ast.Name)
            and n.id == "_JWKS_MIN_REFRESH_INTERVAL_SECS"
            for n in ast.walk(node)
        ):
            sites.add(enclosing_qualified_name(node))
    assert sites == {f"{_CACHE_CLASS}.{_GATE}"}, (
        "punch 548: the refresh floor is compared in "
        f"{sorted(sites)} — it belongs only in {_CACHE_CLASS}.{_GATE}"
    )
    assert relpath(path) == _MODULE
