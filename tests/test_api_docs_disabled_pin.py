"""Pin: no ASGI app may serve interactive API docs unauthenticated.

Grounding — observed 2026-08-18 on the v0.2.0 publish candidate, running as a
real container built from the curated public tree: ``GET /openapi.json``
returned 200 with **288 routes** to an unauthenticated caller — ``/admin/security``,
``/admin/tls``, ``/admin/compliance-security``, ``/accounts/api-keys`` and the
whole account-creation wizard among them — while every other route correctly
redirected to ``/login``.  Nothing in ``src/`` passed ``docs_url``/``openapi_url``
to the constructor, so the app simply inherited FastAPI's open defaults.  The
3-SME panel (hipaa-sme MEDIUM §164.308(a)(1)(ii)(B) elevated to fix-in-batch on
cost, db-sme, devils-advocate must-fix #4) asked for the fix plus this pin.

The pin is a PROPERTY over EVERY constructor site (Prime Directive 1), not an
assertion about one line number: walk every ``*.py`` under ``src/`` and require
that each ``FastAPI(...)`` / ``APIRouter``-app construction explicitly pins the
three doc routes to ``None``.  A new app object added later is covered the day
it is written, and a count is never hard-coded.

It is deliberately AST-based rather than a substring scan: a comment saying
``docs_url=None`` must not be able to satisfy it.
"""

from __future__ import annotations

import ast

from _pin_harness import walk_src

# The kwargs that must be pinned to None on every ASGI-app construction.
_REQUIRED_NONE_KWARGS = ("docs_url", "redoc_url", "openapi_url")

# Constructors that serve interactive docs when left at their defaults.
_DOC_SERVING_CTORS = {"FastAPI"}


def _app_constructions() -> list[tuple[str, ast.Call]]:
    """Every FastAPI(...) call in the shipped source tree.

    Walks via the shared ``_pin_harness`` (Prime Directive 6: the pins obey the
    SSOT rule too) so this pin cannot drift in its own scoping — a hand-rolled
    ``rglob`` + ``ast.parse`` here is what ``test_pin_harness_adoption`` refuses,
    and it refused this file on first write.
    """
    found: list[tuple[str, ast.Call]] = []
    for _path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            if name in _DOC_SERVING_CTORS:
                found.append((rel, node))
    return found


def test_every_app_construction_disables_interactive_docs() -> None:
    constructions = _app_constructions()
    offenders: list[str] = []

    for rel, call in constructions:
        pinned = {
            kw.arg: kw.value
            for kw in call.keywords
            if kw.arg in _REQUIRED_NONE_KWARGS
        }
        for kwarg in _REQUIRED_NONE_KWARGS:
            value = pinned.get(kwarg)
            if value is None:
                offenders.append(
                    f"{rel}:{call.lineno} does not pass {kwarg}"
                )
            elif not (isinstance(value, ast.Constant) and value.value is None):
                offenders.append(
                    f"{rel}:{call.lineno} passes {kwarg} "
                    f"but not as a literal None"
                )

    assert not offenders, (
        "Interactive API docs would be served unauthenticated. Every FastAPI() "
        "construction must pass docs_url=None, redoc_url=None and "
        "openapi_url=None explicitly:\n  " + "\n  ".join(offenders)
    )


def test_the_pin_has_teeth() -> None:
    """Floor the walker so it cannot silently degrade into a no-op.

    If a refactor moves the app construction somewhere this walk cannot see,
    the pin above would pass vacuously — green because it found nothing, which
    is the failure mode the census-the-censusers directive exists to catch.
    """
    assert _app_constructions(), (
        "found ZERO FastAPI() constructions under src/ — the walker is blind, "
        "so test_every_app_construction_disables_interactive_docs is vacuous"
    )
