"""run17 #8 — ``fetch_message`` honors ``headers_only`` (§164.502(b)
minimum-necessary) per-provider interprocedural pin (drift-prevention).

The provider contract (:meth:`providers.base.EmailProvider.fetch_message`)
declares ``headers_only: bool = False`` — an opt-in metadata-only fast-path so a
caller that needs ONLY the headers (sender / subject / recipients / date /
labels) never pulls the PHI body or attachment bytes. Honoring it is the
§164.502(b) minimum-necessary control; IGNORING it (``_ = headers_only`` then a
full-body fetch) ships the entire PHI body — incl. attachments — on a request
that asked for none, a min-necessary violation.

Verify-don't-accept (run17 #8, 2026-06-27) at HEAD:
  * ``providers/imap.py``       — HONORS (forwards ``headers_only=headers_only``
                                  to ``fetch_message_blocking`` →
                                  ``BODY.PEEK[HEADER]`` and to
                                  ``_raw_to_email_message`` which empties the
                                  body — the narrowing is INTERPROCEDURAL).
  * ``providers/gmail_api.py``  — now HONORS (``format=metadata`` vs ``full``).
  * ``providers/office365.py``  — now HONORS (header-only ``$select`` + no
                                  ``$expand=attachments``).

This pin guards against a FUTURE regression: a new provider (or an edit to an
existing one) whose ``fetch_message`` override discards ``headers_only`` and
fetches the full body anyway. Count-agnostic + interprocedural: a property over
EVERY concrete ``fetch_message`` method (``ast.walk`` over the provider
subclasses, never ``len(X)==N``). Each concrete override must EITHER reference
``headers_only`` in a narrowing branch / forward it to a helper, OR be declared
in :data:`_FULL_FETCH_ONLY` with a written reason — so a full-body fetch is an
EXPLICIT, reviewed capability gap, never a silent discard.

HONORS is defined INTERPROCEDURALLY (PD#2): ``headers_only`` referenced in an
``if`` / ternary test (direct narrowing) OR forwarded as an arg/kwarg to a call
(the value flows to a helper that narrows — IMAP's shape). ``ast.walk`` over the
method descends into nested closures, so IMAP's ``_fetch_via_stdlib`` forward is
in scope.

SCOPE CAVEAT (honest, R55): this asserts ``headers_only`` DRIVES a branch or is
FORWARDED inside the method — it does NOT prove the narrow branch actually omits
the body on every path, nor does it follow the value across a module boundary to
confirm the callee narrows. The behavioural coverage (a headers_only fetch
returns empty body / attachments while keeping metadata) lives in the per-
provider tests in ``tests/test_providers/``. This pin is the structural
backstop against the ``_ = headers_only`` discard regression specifically.
"""

from __future__ import annotations

import ast

from _pin_harness import parse_source, walk_src


# ``relpath::ClassName`` of a concrete ``fetch_message`` that legitimately CANNOT
# project headers-only (a written §164.502(b) reason required). EMPTY: all three
# live providers (IMAP / Gmail API / Graph) honor headers_only. This is the
# DECLARED escape hatch (run17 #8 fallback) — a future provider whose API
# genuinely cannot fetch headers-only without a large refactor registers HERE
# with a reason, so the full-body fetch is reviewed + pinned, never a silent
# ``_ = headers_only`` discard.
_FULL_FETCH_ONLY: dict[str, str] = {}


def _is_abstract(method: ast.AST) -> bool:
    """True if the method is decorated ``@abstractmethod`` / ``@abc.abstractmethod``
    — the base-contract declaration, NOT a concrete override."""
    for dec in getattr(method, "decorator_list", []):
        d = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(d, ast.Name) and d.id == "abstractmethod":
            return True
        if isinstance(d, ast.Attribute) and d.attr == "abstractmethod":
            return True
    return False


def _concrete_fetch_message_methods(tree: ast.AST):
    """Yield ``(classname, method_node)`` for every CONCRETE (non-abstract)
    method named ``fetch_message`` defined directly on a class in ``tree`` — the
    provider override surface. The abstract base declaration is skipped."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if (isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name == "fetch_message"
                    and not _is_abstract(item)):
                yield node.name, item


def _iter_src_fetch_methods():
    """Yield ``(relpath, classname, method_node)`` for every concrete
    ``fetch_message`` override under ``src/email_triage`` (interprocedural over
    the provider subclasses)."""
    for _path, rel, tree in walk_src():
        for classname, method in _concrete_fetch_message_methods(tree):
            yield rel, classname, method


def _name_referenced(subtree: ast.AST, name: str) -> bool:
    """True if ``name`` appears as an ``ast.Name`` anywhere in ``subtree``."""
    for n in ast.walk(subtree):
        if isinstance(n, ast.Name) and n.id == name:
            return True
    return False


def _honors_headers_only(method: ast.AST) -> bool:
    """True if ``headers_only`` DRIVES a narrowing within the method (incl.
    nested closures): referenced in an ``if`` / ternary test (direct narrowing)
    OR forwarded as a positional / starred / keyword arg to a call
    (interprocedural narrowing — the value flows to a helper that narrows, as
    IMAP forwards it to ``fetch_message_blocking`` / ``_raw_to_email_message``).

    A bare ``_ = headers_only`` discard is NOT a meaningful use — the whole
    point of the pin. ``ast.walk`` descends into nested ``def``/``async def`` so
    a forward inside a closure (IMAP's ``_fetch_via_stdlib``) is seen."""
    for n in ast.walk(method):
        if isinstance(n, (ast.If, ast.IfExp)) and _name_referenced(n.test, "headers_only"):
            return True
        if isinstance(n, ast.Call):
            for a in n.args:
                if isinstance(a, ast.Name) and a.id == "headers_only":
                    return True
                if (isinstance(a, ast.Starred) and isinstance(a.value, ast.Name)
                        and a.value.id == "headers_only"):
                    return True
            for kw in n.keywords:
                if isinstance(kw.value, ast.Name) and kw.value.id == "headers_only":
                    return True
    return False


def test_every_concrete_fetch_message_honors_or_is_declared_full_fetch():
    """Every concrete provider ``fetch_message`` either HONORS ``headers_only``
    (narrows on it / forwards it) OR is declared in ``_FULL_FETCH_ONLY`` with a
    reason. A discard (``_ = headers_only`` then a full fetch) is a §164.502(b)
    minimum-necessary violation. Count-agnostic + interprocedural."""
    offenders: list[str] = []
    for rel, cls, method in _iter_src_fetch_methods():
        if f"{rel}::{cls}" in _FULL_FETCH_ONLY:
            continue
        if not _honors_headers_only(method):
            offenders.append(f"{rel}:{method.lineno} ({cls}.fetch_message)")
    assert offenders == [], (
        "A concrete provider fetch_message IGNORES headers_only (fetches the "
        "full PHI body — incl. attachments — even on a headers_only=True "
        "request) = §164.502(b) minimum-necessary violation:\n  "
        + "\n  ".join(offenders)
        + "\nHonor it (narrow on headers_only, or forward it to a header-only "
        "fetch), OR register the provider in _FULL_FETCH_ONLY with a written "
        "reason if its API genuinely cannot project headers-only."
    )


def test_live_providers_present_and_honor():
    """Anti-vacuity guard (the pin guards itself): the three live providers each
    appear as a concrete fetch_message (so a broken walk fails LOUD, not green),
    and — since none are in _FULL_FETCH_ONLY — each must HONOR headers_only."""
    found = {rel: cls for rel, cls, _m in _iter_src_fetch_methods()}
    for rel in (
        "providers/gmail_api.py",
        "providers/office365.py",
        "providers/imap.py",
    ):
        assert rel in found, (
            f"expected a concrete fetch_message override in {rel} — the AST "
            "walk found none (harness/glob regression?)"
        )
    for rel, cls, method in _iter_src_fetch_methods():
        if f"{rel}::{cls}" in _FULL_FETCH_ONLY:
            continue
        assert _honors_headers_only(method), (
            f"{rel}::{cls}.fetch_message no longer honors headers_only"
        )


def test_full_fetch_only_entries_are_real_and_still_ignore():
    """PD#7 non-staleness: every ``_FULL_FETCH_ONLY`` key must still name a live
    concrete fetch_message that does NOT honor headers_only (else it was honored
    / refactored / removed and the exemption is dead), and carry a reason."""
    live = {f"{rel}::{cls}": m for rel, cls, m in _iter_src_fetch_methods()}
    for key, reason in _FULL_FETCH_ONLY.items():
        assert reason and reason.strip(), f"_FULL_FETCH_ONLY[{key!r}] needs a reason"
        assert key in live, (
            f"_FULL_FETCH_ONLY {key} no longer exists as a concrete "
            "fetch_message — drop the stale exemption"
        )
        assert not _honors_headers_only(live[key]), (
            f"_FULL_FETCH_ONLY {key} now HONORS headers_only — drop the exemption"
        )


def test_pin_has_teeth():
    """The detector FLAGS a planted discard shape and PASSES the three honoring
    shapes (direct ``if``, ternary, interprocedural forward); the abstract base
    declaration is excluded from scope."""
    # BAD — a concrete override that discards the flag then fetches full.
    bad = parse_source(
        "class BadProvider:\n"
        "    async def fetch_message(self, mid, *, headers_only=False, folder=None):\n"
        "        _ = headers_only\n"
        "        _ = folder\n"
        "        return await self._get(mid, full=True)\n"
    )
    bad_methods = list(_concrete_fetch_message_methods(bad))
    assert bad_methods, "teeth: planted concrete fetch_message not found"
    assert not _honors_headers_only(bad_methods[0][1]), (
        "teeth: a `_ = headers_only` discard must NOT count as honoring"
    )

    # GOOD-1 — direct narrowing via `if headers_only:` (the Graph shape).
    good_if = parse_source(
        "class G1:\n"
        "    async def fetch_message(self, mid, *, headers_only=False, folder=None):\n"
        "        if headers_only:\n"
        "            return await self._get(mid, fields='headers')\n"
        "        return await self._get(mid, fields='full')\n"
    )
    assert _honors_headers_only(list(_concrete_fetch_message_methods(good_if))[0][1])

    # GOOD-2 — ternary narrowing (the Gmail shape).
    good_ternary = parse_source(
        "class G2:\n"
        "    async def fetch_message(self, mid, *, headers_only=False, folder=None):\n"
        "        fmt = 'metadata' if headers_only else 'full'\n"
        "        return await self._get(mid, format=fmt)\n"
    )
    assert _honors_headers_only(list(_concrete_fetch_message_methods(good_ternary))[0][1])

    # GOOD-3 — interprocedural FORWARD to a helper (the IMAP shape).
    good_fwd = parse_source(
        "class G3:\n"
        "    async def fetch_message(self, mid, *, headers_only=False, folder=None):\n"
        "        async def _inner():\n"
        "            return await fetch_blocking(mid, headers_only=headers_only)\n"
        "        return await _inner()\n"
    )
    assert _honors_headers_only(list(_concrete_fetch_message_methods(good_fwd))[0][1])

    # ABSTRACT base declaration is out of scope (not a concrete override).
    base = parse_source(
        "class Base:\n"
        "    @abstractmethod\n"
        "    async def fetch_message(self, mid, *, headers_only=False, folder=None):\n"
        "        ...\n"
    )
    assert not list(_concrete_fetch_message_methods(base)), (
        "teeth: an @abstractmethod fetch_message must be excluded from scope"
    )
