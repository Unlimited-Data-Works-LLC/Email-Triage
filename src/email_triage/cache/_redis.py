"""SSOT for the optional Redis subsystem — client construction + fallback breaker.

run17  +  (the Redis subsystem). The three optional Redis consumers —
``cache/classification.py`` (the LLM classification-result cache),
``cache/topic_feedback.py`` (the Topic learned-sender mirror) and
``engine/persistent_counters.py`` (lifetime counter persistence) — each
hand-rolled (a) the ``redis.Redis.from_url`` connection params and (b) a
per-module circuit-breaker. The params had ALREADY drifted (a realised 4th copy
in a test fixture used ``socket_timeout=5`` with no connect-timeout / decode),
and ``persistent_counters`` carried NO breaker at all — so a dead Redis re-paid
the full 2 s socket timeout on every counter bump, with no backoff. This module
is the ONE home for both halves:

* :func:`build_redis_client` — the ONLY place ``redis.Redis.from_url`` is called
  (pinned by ``tests/test_redis_client_factory_pin.py``). Owns the canonical
  client params; callers pass only an intentional override.
* :class:`RedisFallbackBreaker` — the ONE fallback circuit-breaker class under
  ``cache/`` (pinned by ``tests/test_redis_fallback_breaker_pin.py``). Extracted
  from the two byte-identical ``_BreakerState`` copies; the policy (trip → open
  for ``ttl_secs`` monotonic seconds; recover purely by TTL) is PRESERVED
  exactly — this is reliability code, de-duplicated, not re-policied.

Optional-by-design contract (unchanged): ``redis`` is imported LAZILY so an
install without the ``cache`` extra doesn't error at import time, and
:func:`build_redis_client` lets ``ImportError`` propagate so each caller keeps
its own "package not installed" log + breaker handling. At import time this
module imports nothing from ``email_triage`` (stdlib + the lazy ``redis`` only),
so it is a leaf in the import graph — the classification cache's existing
``cache → engine.persistent_counters`` edge cannot cycle through it. The one
in-package import, ``email_triage.tls`` for a ``rediss://`` URL, is lazy, inside
:func:`_guarded_ssl_connection_class`.
"""

from __future__ import annotations

import functools
import time
from dataclasses import dataclass
from typing import Any


#: Canonical ``redis.Redis.from_url`` parameters — the SUPERSET-correct set that
#: the three live src consumers all used IDENTICALLY:
#:   * ``decode_responses=True`` — str in/out, so ``json.dumps``/``loads`` round-
#:     trips cleanly (every consumer relies on this);
#:   * a SHORT 2.0 s ``socket_timeout`` + ``socket_connect_timeout`` — Redis is
#:     LAN-only by policy, and a stuck server must never block the classifier
#:     (or, via the ``a*`` mirrors, the event loop) for longer than that.
#: This is NOT the drifted test-fixture shape (``socket_timeout=5``, no
#: connect-timeout / decode) — that reachability probe now passes an EXPLICIT
#: override through the factory instead of re-forking the params.
_DEFAULT_CLIENT_KWARGS: dict[str, Any] = {
    "decode_responses": True,
    "socket_timeout": 2.0,
    "socket_connect_timeout": 2.0,
}


def build_redis_client(url: str, **overrides: Any) -> Any:
    """Construct a synchronous ``redis.Redis`` from ``url`` (run17  SSOT).

    The ONE sanctioned ``redis.Redis.from_url`` call site — every optional Redis
    consumer (classification cache, topic-feedback mirror, persistent counters)
    builds its client HERE so the connection params can't fork into a 4th
    drifted copy. ``overrides`` layer on top of :data:`_DEFAULT_CLIENT_KWARGS`
    for an intentional per-caller tweak (e.g. a more tolerant ``socket_timeout``
    on a reachability probe).

    Imports ``redis`` lazily and lets ``ImportError`` PROPAGATE: each caller
    distinguishes "package not installed" from a connection-build error with its
    own log message + breaker handling, so the factory swallows neither.
    ``redis.Redis.from_url`` does not connect eagerly — a dead server first
    surfaces on a command, where the caller's breaker backs off.

    ``rediss://`` (TLS): redis-py builds its own ``SSLContext``, which the punch 776
    distrusted-key check never saw (cycle P DA P4-2). The connection class is forced to
    :func:`_guarded_ssl_connection_class` (a caller override cannot replace it), which
    judges the verified chain once the handshake is done and closes the socket on a
    refusal: redis-py reports a ``ConnectionError`` and the caller's breaker trips.
    """
    import redis  # type: ignore[import-not-found]  # lazy: optional `cache` extra

    kwargs = {**_DEFAULT_CLIENT_KWARGS, **overrides}
    if url.split(":", 1)[0].strip().lower() == "rediss":
        kwargs["connection_class"] = _guarded_ssl_connection_class()
    return redis.Redis.from_url(url, **kwargs)


@functools.lru_cache(maxsize=1)
def _guarded_ssl_connection_class() -> type:
    """``redis.connection.SSLConnection`` whose every new socket is judged by
    ``tls.enforce_chain_not_distrusted`` after redis-py's own handshake (``_connect``
    returns the wrapped socket). A ``CERT_NONE`` socket (``ssl_cert_reqs=none``)
    verified nothing and is not judged, as everywhere else."""
    from redis.connection import SSLConnection  # type: ignore[import-not-found]

    class GuardedSSLConnection(SSLConnection):
        def _connect(self):
            from email_triage.tls import enforce_chain_not_distrusted

            sock = super()._connect()
            try:
                enforce_chain_not_distrusted(sock)
            except BaseException:
                sock.close()
                raise
            return sock

    return GuardedSSLConnection


@dataclass
class RedisFallbackBreaker:
    """The ONE fallback circuit-breaker for the optional Redis consumers (run17 ).

    Extracted from the two byte-identical ``_BreakerState`` copies in
    ``cache/classification.py`` and ``cache/topic_feedback.py`` and additionally
    composed into the previously-breaker-less ``engine/persistent_counters.py``.
    Behaviour is PRESERVED exactly — de-duplication, not a policy change:

    * :meth:`is_open` — True while the monotonic ``open_until`` deadline is in the
      future. Every Redis-touching method checks this FIRST and short-circuits to
      its safe fallback (cache miss / DB read / counter no-op) WITHOUT a round-trip.
    * :meth:`trip` — on a Redis-unreachable error, open the breaker for
      ``ttl_secs`` monotonic seconds and record the (truncated) reason.

    Recovery is TTL-only BY DESIGN (run17  — see
    ``tests/test_redis_fallback_breaker_pin.py``): while the breaker is open NO
    Redis I/O is attempted, so there is no in-window success edge to "clear" from
    (unlike a sticky flag set on one surface and cleared on another). The breaker
    self-heals when the SHORT (60 s default) TTL elapses and the next call
    retries — succeed → stays closed, fail → re-trips. Callers still drop their
    own cached client on a trip so the post-recovery attempt rebuilds it.
    """

    ttl_secs: float = 60.0
    open_until: float = 0.0  # monotonic deadline; 0 = closed
    last_reason: str = ""

    def is_open(self) -> bool:
        """True while the breaker's monotonic deadline is still in the future."""
        return self.open_until > time.monotonic()

    def trip(self, reason: str = "") -> None:
        """Open the breaker for ``ttl_secs`` seconds and store the truncated reason."""
        self.open_until = time.monotonic() + self.ttl_secs
        self.last_reason = reason[:200]
