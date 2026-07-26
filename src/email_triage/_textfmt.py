"""Display-text formatting SSOT (run18 ).

One ``truncate`` helper for "cap a string to N display chars, appending an
ellipsis when it was cut". Before this, the digest family (``actions/digest.py``,
``actions/digest_render.py``, ``actions/recipient_digest.py``) carried ~half a
dozen ad-hoc ``text[:n] + "…"`` slice-arithmetic truncations that had ALREADY
drifted in two ways:

* the ELLIPSIS CHARACTER — ``actions/digest.py`` used the ASCII ``"..."`` while
  ``digest_render`` used the Unicode ``"…"`` (the run18  finding); and
* the LENGTH CONVENTION — some sites meant "n is the total width including the
  ellipsis" (``text[:n-1] + "…"``), others "n content chars plus an ellipsis"
  (``text[:n] + "…"``), and the table link-cap had silently become
  ``value[:57] + "…"`` (a stale ``-3`` left over from when the ellipsis was the
  3-char ``"..."``), producing a 58-char cap where 60 was intended.

``truncate`` fixes the SSOT to ONE convention — the result is **at most ``n``
characters, ellipsis included** (the dominant existing convention) — so every
routed call site is ellipsis-consistent and width-consistent. This module has
NO project imports, so the digest-family modules (and any future caller) can
import it without an import cycle.

NOT a token/LLM-budget truncator — that is ``llm_truncation`` (finish-reason
detection) and the per-backend input caps, which stay separate by design.
"""

from __future__ import annotations

#: The canonical single-glyph ellipsis. ASCII "..." is deliberately NOT the
#: default — keeping one glyph is the whole point of the SSOT (run18 ).
ELLIPSIS = "…"


def truncate(text: object, n: int, *, ellipsis: str = ELLIPSIS) -> str:
    """Cap ``text`` to at most ``n`` characters, appending ``ellipsis`` when cut.

    Contract (the ONE convention the digest family now shares):

    * ``len(str(text)) <= n`` → the text is returned unchanged (no ellipsis).
    * otherwise → ``text`` is cut so the returned string is **exactly ``n``
      characters including the ``ellipsis``** (``text[: n - len(ellipsis)] +
      ellipsis``).

    ``n <= 0`` returns ``""``; an ``n`` smaller than the ellipsis returns the
    ellipsis clipped to ``n`` (degenerate, but total length still honoured).
    Non-``str`` input is coerced via ``str()`` so a caller can pass a value that
    is "almost always a string" without a guard (matches the old ad-hoc sites,
    several of which wrapped in ``str(...)`` first).
    """
    if n <= 0:
        return ""
    s = text if isinstance(text, str) else str(text)
    if len(s) <= n:
        return s
    cut = n - len(ellipsis)
    if cut <= 0:
        return ellipsis[:n]
    return s[:cut] + ellipsis
