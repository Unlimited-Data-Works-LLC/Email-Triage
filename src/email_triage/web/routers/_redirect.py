"""Redirect query-string SSOT (divergence census run12 #5 — flash-redirect).

Handlers signal success/failure to the next page via a ``?err=…`` / ``?msg=…``
query param on a 303 ``RedirectResponse``. Several hand-rolled the value into an
f-string RAW — ``f"/x?err={save_error}"`` — so an exception text containing ``&``
/ ``=`` / a space SPLITS or breaks the redirect URL (a YAML/backup error is the
common case), and an unescaped ``<`` would only be saved by the target template's
Jinja autoescape (defence-in-depth, not by the URL). The fix is ONE encoder all
``?err=`` / ``?msg=`` redirect values route through.

``err_qs`` / ``msg_qs`` URL-encode via :func:`urllib.parse.quote` (encodes ``&``
``=`` space AND ``<`` ``>`` ``"`` → ``%XX``), so the value is URL-safe and
HTML-context-hardened regardless of the target page's escaping. Pinned by
``tests/test_redirect_qs_ssot_pin.py`` (no raw variable interpolated into a
``RedirectResponse`` ``?err=``/``?msg=`` URL outside this module).
"""

from __future__ import annotations

from urllib.parse import quote


def err_qs(message: str) -> str:
    """``err=<url-encoded message>`` — the SSOT for an error redirect query
    param. URL-encodes the (operator-facing, often exception-derived) message so
    it cannot split the URL or carry raw markup into the target page."""
    return f"err={quote(str(message), safe='')}"


def msg_qs(message: str) -> str:
    """``msg=<url-encoded message>`` — the success/notice twin of :func:`err_qs`."""
    return f"msg={quote(str(message), safe='')}"


def qs(**params: str) -> str:
    """Build a full ``k=v&k=v`` query string with every value URL-encoded — for a
    redirect that carries more than one param (e.g. ``saved`` + ``err``)."""
    return "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())


def read_flash(request) -> tuple[str | None, str | None]:
    """Read the ``(msg, err)`` flash a sibling POST wrote via :func:`msg_qs` /
    :func:`err_qs` on its 303 redirect — the READER twin of those encoders, so a
    post-redirect-get (PRG) flash is decoded in ONE place. Every ``?err=`` reader
    routes here (backup / integrations / tls_csr / profile-watches), so the
    ``msg`` / ``err`` decode cannot drift. The BESPOKE single-flash params
    (``saved`` / ``save_msg`` / ``renewed`` / ``flushed`` / ``flush_err`` …) keep
    their raw ``query_params.get(...)`` reads — they have no encoder twin (mirroring
    the write side, where they ride literal ``?saved=1`` / :func:`qs`, not
    :func:`err_qs`); the flash-COUPLING pin
    (``tests/test_flash_param_coupling_pin.py``) is what guarantees each of THOSE
    is still read by its target route.

    Returns ``(msg, err)``; either is ``None`` when absent. ``urllib`` already
    percent-decoded the values into ``request.query_params``. The bug this closes
    (census run14 #7): a watch-save built a notice — a COUNT of the PHI accounts
    it skipped from the fan-out (never their names) — but redirected with a bare
    ``?saved=1`` while the target GET hard-coded ``save_msg=None``, so the notice
    (and the HIPAA-skip count) was silently dropped on every save.
    """
    qp = request.query_params
    return qp.get("msg"), qp.get("err")
