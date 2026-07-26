"""Exception-to-string formatting helper.

``str(exc)`` returns the empty string for some bare exceptions
(``ValueError()`` with no args, ``sqlite3.IntegrityError`` before
``.args`` is populated, third-party libs that raise blank exceptions
in error paths). Logging that produces ``error=`` (empty value) tells
the operator nothing actionable.

``fmt_exc(e)`` returns ``str(e)`` when non-empty, otherwise ``repr(e)``
which always carries the exception class + any args. Use this anywhere
an exception is rendered for an operator-facing log line, error dict,
or audit detail.
"""

from __future__ import annotations

import re

# N-42 — PHI value-scrub for exception text before it enters a persisted log
# field (the HMAC-chained ``log_entries`` table, where it cannot be expunged
# without breaking the §164.312(b) chain). An exception string routinely echoes
# a recipient/sender ADDRESS ("SMTP refused rcpt jane.doe@hosp.org") or a
# MAILBOX PATH whose folder can be named after a patient
# ("[Errno 2] .../Maildir/.INBOX.Smith-Labs/cur/1.eml"). These are PHI shapes.
#
# Safe-Harbor email/address shape — mirrors ``style_learning.phi_scrubber`` so
# the two address regexes can't drift in what counts as an address.
_ADDR_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Filesystem / mailbox path shape: POSIX 2+ segments or a Windows drive path.
# HIPAA-conservative direction — redact the path, keep the error class + errno
# (a config path is over-redacted; that is the safe miss for a §164.502(b)
# minimum-necessary log field). The ``(?<![\w/])`` lookbehind carves out URL
# PATHS (``https://host/a/b`` — the ``/a/b`` is preceded by the host word-char
# or by ``//``), so an OAuth/API endpoint stays intact for debuggability
# (db-sme: those carry no PHI). A leading-slash absolute path (preceded by
# space/quote/start) still matches. KNOWN RESIDUAL: a RELATIVE mailbox/folder
# name with no leading slash (an IMAP "INBOX.Smith-Labs") is not path-shaped and
# is not redacted — a documented, AI-assessed LOW residual (N-42 register row).
_PATH_RE = re.compile(r"(?<![\w/])(?:/[\w.+\-]+){2,}/?|[A-Za-z]:\\[\w.\\+\-]+")

_REDACTED_ADDR = "[redacted-addr]"
_REDACTED_PATH = "[redacted-path]"


def redact_exc(value: BaseException | str) -> str:
    """Value-scrub an exception (or its already-rendered text) of PHI-shaped
    substrings before it enters a persisted or operator-facing field.

    The SINGLE place exception text is PHI-scrubbed (N-42). ``fmt_exc`` routes
    through it, and the structured-logging formatters call it on the
    ``exc_info`` exception so the ``error`` log field is scrubbed regardless of
    how it was produced. Scrubs email addresses and filesystem/mailbox paths;
    a free-form subject FRAGMENT embedded in arbitrary error prose is not
    generically detectable and remains a documented residual.

    Examples:
        >>> redact_exc(ValueError("rcpt jane.doe@hosp.org refused"))
        'rcpt [redacted-addr] refused'
        >>> redact_exc("[Errno 2] open '/var/mail/.INBOX.Smith/cur/1.eml'")
        "[Errno 2] open '[redacted-path]'"
    """
    try:
        s = value if isinstance(value, str) else (str(value) or repr(value))
    except Exception:
        # An exception whose __str__/__repr__ ITSELF raises must NOT escape —
        # fmt_exc's contract is "the operator always sees something" and it is on
        # 353 sites (db-sme edge-case). Fall back to the class name.
        s = f"<unrenderable {type(value).__name__}>"
    try:
        s = _ADDR_RE.sub(_REDACTED_ADDR, s)
        s = _PATH_RE.sub(_REDACTED_PATH, s)
    except Exception:
        # A scrub failure must never lose the operator's error signal; return
        # the unscrubbed text (already a string) rather than raise.
        pass
    return s


def fmt_exc(e: BaseException, *, with_class: bool = False) -> str:
    """Render an exception so the operator always sees something, PHI-scrubbed.

    Returns ``str(e)`` when non-empty, else ``repr(e)`` (which always includes
    the exception class name) — then routed through :func:`redact_exc` so a
    leaked address/path can't reach a log/audit/error field (N-42).

    ``with_class=True`` prefixes the exception class name — the SSOT for the
    ``f"{type(e).__name__}: {e}"`` twin idiom (census run13 #8). The rendered
    output is still PHI-scrubbed AND ``__str__``-bomb-safe (an exception whose
    ``__str__`` raises during the prefix render degrades to
    ``"<ClassName>: <unrenderable>"`` rather than propagating).

    NOTE (db-sme/DA, census run13 #8): scrub-vs-classifier safety rests on TWO
    distinct grounds — do NOT collapse them into a blanket "classifiers key on
    raw input" (that claim is FALSE for office365 and misleads a future editor):
    * Most error-classifiers (``is_auth_revoked_exc``, the acme retry classifier
      ``_classify_acme_error``, ``load_backend`` failover) key on the RAW live
      exception (``str(exc)`` or structured attrs like ``exc.typ``) UPSTREAM of
      every ``fmt_exc`` render, so the scrub is downstream and cannot change a
      branch decision.
    * The office365 ``list_folders`` auth-shape demotion is the EXCEPTION: it
      token-matches the ALREADY-SCRUBBED ``fmt_exc(...)`` output. That is safe
      only by token/regex disjointness — the auth tokens (AADSTS / 401 /
      Unauthorized / invalid_grant / device code) are not address- or
      path-shaped, so ``redact_exc`` provably cannot strip them. A future editor
      adding a path-shaped or ``@``-bearing classifier token WOULD silently
      break that DEBUG demotion (regression-guarded in test_o365_probe_ui).

    Examples:
        >>> fmt_exc(ValueError("bad input"))
        'bad input'
        >>> fmt_exc(ValueError())     # str() would be ""
        'ValueError()'
        >>> fmt_exc(OSError(2, "no such file"))
        '[Errno 2] no such file'
        >>> fmt_exc(ValueError("rcpt a@b.com"), with_class=True)
        'ValueError: rcpt [redacted-addr]'
    """
    if with_class:
        # Render the class-prefixed form, hardened the same way redact_exc
        # hardens a bare exception: an exception whose ``__str__`` itself raises
        # must NOT escape (the twin idiom this replaces had no such guard).
        try:
            rendered = f"{type(e).__name__}: {e}"
        except Exception:
            rendered = f"{type(e).__name__}: <unrenderable>"
        return redact_exc(rendered)
    # Pass the exception (not str(e)) so redact_exc's hardened render handles an
    # exception whose __str__ itself raises (db-sme edge-case) — str()/repr()
    # there are inside try/except, so fmt_exc never propagates a __str__ bomb.
    return redact_exc(e)


def scrub_error_for_persist(
    value: BaseException | str | None, *, max_len: int | None = None,
) -> str | None:
    """SSOT for any exception/error text written to a PERSISTED or operator-
    facing ``*error*`` field (``triage_jobs.error_text`` / ``flows.error`` /
    ``*.last_error`` / a chained audit ``detail`` …) — census run13 #2.

    Composes BOTH scrub legs (which no site but ``embedding_bits._scrub_error``
    previously did): PHI (:func:`redact_exc` — email addresses + mailbox/
    filesystem paths, N-42) AND secrets (``scrub_secrets_from_text`` — token-
    shaped values), then whitespace-collapse + length-cap (via the secret-scrub
    SSOT; ``max_len`` overrides the default cap — e.g. the watcher-retry 500).
    ``None``/empty in → ``None`` out.

    A mail-path exception can echo a recipient address or mailbox path (PHI);
    an index/pip/backend error can echo a token (secret). ``fmt_exc`` scrubs
    only PHI and is the operator-LOG funnel; THIS is the persisted-field funnel
    that scrubs both. As with ``fmt_exc`` the scrub sits DOWNSTREAM of any
    retry/branch classifier (which key on the raw ``str(exc)``), so it never
    changes a decision."""
    from email_triage._secret_scrub import scrub_secrets_from_text
    if value is None:
        return None
    kw = {} if max_len is None else {"max_len": max_len}
    return scrub_secrets_from_text(redact_exc(value), **kw)


def scrub_class_error_for_persist(
    e: BaseException, *, max_len: int | None = None,
) -> str | None:
    """SSOT for the class-prefixed persisted-exception idiom (census run13 #8 F4).

    Collapses the previously-duplicated
    ``scrub_error_for_persist(f"{type(e).__name__}: {e}")`` shape into ONE call.
    Composes :func:`fmt_exc` (``with_class=True``, so ``ClassName:`` prefix +
    ``__str__``-bomb safety + PHI scrub) then routes the rendered string
    through :func:`scrub_error_for_persist` for the secret-scrub + length-cap
    legs. Twenty-plus repo sites replicated the literal twin as the direct
    argument to :func:`scrub_error_for_persist`; each duplicate could drift
    (``:`` vs ``-``, order flip, missing prefix), and the exc-render twin pin
    exempted the routed-through form specifically because the scrub neutralised
    the leak — it never guarded consistency across sites. This SSOT closes that
    gap: every persisted class-prefixed error routes here.
    """
    if e is None:  # type: ignore[unreachable]
        return None
    return scrub_error_for_persist(fmt_exc(e, with_class=True), max_len=max_len)
