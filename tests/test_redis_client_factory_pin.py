"""Count-agnostic pin for the Redis-client factory SSOT (divergence census run17 ).

Every optional Redis consumer (the classification cache, the topic-feedback
mirror, the persistent-counter backend) MUST build its client through
``email_triage.cache._redis.build_redis_client`` — the ONE owner of the canonical
``redis.Redis.from_url`` connection params (``decode_responses`` + the short
LAN socket/connect timeouts). Before run17 the params were hand-rolled at THREE
src sites, and a 4th copy had ALREADY DRIFTED in a test reachability probe
(``test_classification_redis.py`` used ``socket_timeout=5`` with no
connect-timeout / decode) — the predicted fork, realised.

This pin is a PROPERTY over EVERY ``*.py`` under ``src/email_triage`` AND
``tests/`` (the realised fork was test-side, so the net spans both), never
``len(sites) == N``. It bans any ``redis.Redis.from_url`` /
``redis.asyncio...from_url`` CALL outside the factory module — including a
``from redis import Redis`` / ``from redis.asyncio import Redis`` bare-alias
evasion (per-module import scan). Interprocedural by construction: it keys on the
construction SITE wherever it sits, not on who calls it.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    REPO_ROOT,
    SRC_ROOT,
    assert_pin_has_teeth,
    enclosing_fn,
    iter_files,
    parse_module,
    parse_source,
    relpath,
)

# The REPO-relative path of the ONE sanctioned ``redis.Redis.from_url`` call
# site — the factory SSOT. Every other site is an offender.
_FACTORY = "src/email_triage/cache/_redis.py"


def _attr_root_name(node: ast.AST) -> str | None:
    """The root ``Name`` id of an attribute/name chain (``redis.asyncio.Redis``
    → ``"redis"``), or ``None`` when the chain doesn't bottom out at a Name."""
    cur = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


def _redis_import_aliases(tree: ast.AST) -> set[str]:
    """Names bound to a ``redis`` / ``redis.asyncio`` symbol — so a bare
    ``Redis.from_url(...)`` (from ``from redis import Redis [as X]``) is caught
    even though it isn't written ``redis.Redis.from_url``."""
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("redis", "redis.asyncio"):
            for a in node.names:
                aliases.add(a.asname or a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "redis" or a.name.startswith("redis."):
                    aliases.add(a.asname or a.name.split(".")[0])
    return aliases


def _from_url_calls(tree: ast.AST) -> list[ast.Call]:
    """Every ``<...>.from_url(...)`` call whose receiver chain roots at ``redis``
    (covering ``redis.Redis.from_url`` / ``redis.asyncio.Redis.from_url`` /
    ``redis.asyncio.from_url``) OR at a ``from redis[.asyncio] import …`` alias.

    A ``from_url`` on an unrelated object (some ORM's ``Model.from_url``) is NOT
    flagged — the receiver root must resolve to ``redis`` or a redis import alias,
    so there are no false positives on the common method name."""
    aliases = _redis_import_aliases(tree)
    hits: list[ast.Call] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "from_url"
        ):
            continue
        root = _attr_root_name(node.func.value)
        if root == "redis" or (root is not None and root in aliases):
            hits.append(node)
    return hits


def _sites_with_from_url() -> dict[str, list[str]]:
    """REPO-relative path -> [enclosing_fn, ...] for every ``*.py`` under
    ``src/email_triage`` or ``tests/`` that calls ``redis.Redis.from_url``."""
    out: dict[str, list[str]] = {}
    paths = list(iter_files(SRC_ROOT, "*.py")) + list(iter_files(REPO_ROOT / "tests", "*.py"))
    for path in paths:
        tree = parse_module(path)
        if tree is None:
            continue
        hits = _from_url_calls(tree)
        if hits:
            out[relpath(path, base=REPO_ROOT)] = [enclosing_fn(h) for h in hits]
    return out


def test_no_redis_from_url_outside_factory():
    """``redis.Redis.from_url`` is called ONLY in the factory SSOT — every other
    Redis consumer routes through ``build_redis_client`` so the connection params
    can't fork into a (5th) drifted copy."""
    offenders = {rel: fns for rel, fns in _sites_with_from_url().items() if rel != _FACTORY}
    assert not offenders, (
        "redis.Redis.from_url / redis.asyncio...from_url is called outside the "
        f"factory SSOT ({_FACTORY}): {offenders}. Build the client through "
        "email_triage.cache._redis.build_redis_client(url, **overrides) so the "
        "canonical connection params (decode_responses + the short LAN socket/"
        "connect timeouts) live in ONE place. Pass an intentional override (e.g. "
        "a more tolerant socket_timeout on a reachability probe) as a kwarg — "
        "never re-fork the param set."
    )


def test_factory_is_the_sole_from_url_site():
    """Non-vacuity guard: the factory SSOT really DOES call from_url (so the pin
    can't pass green merely because the call was renamed/removed everywhere)."""
    found = _sites_with_from_url()
    assert _FACTORY in found, (
        f"{_FACTORY} no longer calls redis.Redis.from_url — the factory SSOT is "
        "missing/renamed; this pin would be vacuously green. Restore the factory."
    )


def test_detector_catches_every_from_url_shape():
    """Teeth: each real ``from_url`` construction shape is detected; an unrelated
    ``from_url`` on a non-redis object is NOT (no false positive)."""
    for src in (
        "import redis\nc = redis.Redis.from_url('redis://x')\n",                 # qualified sync
        "import redis.asyncio\nc = redis.asyncio.Redis.from_url('redis://x')\n",  # qualified async
        "import redis.asyncio\nc = redis.asyncio.from_url('redis://x')\n",        # module helper
        "from redis import Redis\nc = Redis.from_url('redis://x')\n",             # bare alias
        "from redis.asyncio import Redis as AR\nc = AR.from_url('redis://x')\n",  # aliased async
    ):
        assert _from_url_calls(ast.parse(src)), f"detector missed: {src!r}"
    # Unrelated ``.from_url`` (not rooted at redis / a redis alias) is clean.
    assert not _from_url_calls(ast.parse("c = Model.from_url('postgres://x')\n"))
    assert not _from_url_calls(ast.parse("from sqlalchemy import URL\nu = URL.from_url('x')\n"))
    # The factory call itself is NOT a from_url construction (it wraps it).
    assert not _from_url_calls(ast.parse(
        "from email_triage.cache._redis import build_redis_client\n"
        "c = build_redis_client('redis://x', socket_timeout=5)\n"
    ))


def test_pin_has_teeth():
    """``assert_pin_has_teeth`` — flags a planted raw from_url, passes the factory call."""
    assert_pin_has_teeth(
        lambda tree: bool(_from_url_calls(tree)),
        bad_source="import redis\ndef f():\n    return redis.Redis.from_url('redis://x')\n",
        good_source=(
            "from email_triage.cache._redis import build_redis_client\n"
            "def f():\n    return build_redis_client('redis://x')\n"
        ),
    )
    # bare-alias evasion is caught too.
    bare = parse_source("from redis import Redis\ndef f():\n    return Redis.from_url('redis://x')\n")
    assert _from_url_calls(bare), "bare-import alias evaded the detector"
