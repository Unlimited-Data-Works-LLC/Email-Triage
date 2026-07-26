"""User-facing error surfacing SSOT (R20_1 sub-classes 1-3, N-179 scaffold).

The census run20 R20_1 finding: ~411 sites (my strict enumeration = 126 sites
across 4 sub-classes) surface user-facing errors ad-hoc — `err_msg=str(e)` into
ctx, `?err=<raw exception>` into a RedirectResponse URL, `HTMLResponse("<pre>"+
str(e)+"</pre>")` bodies, `raise HTTPException(detail=str(e))`. Raw exception
strings can carry PHI (mail-body fragments in a parser error), credentials
(key material in a decryption error), or session tokens (HTTP client errors).

This module = the SSOT for sub-classes 1 (redirect-flash-key), 2
(HTMLResponse-error-body), 3 (context-key-err-msg). Sub-class 4 (JSONResponse
/ HTTPException) lives in the sibling ``error_surface.py``.

Contract:
- `flash_redirect(request, url, err=..., ok=...)` — return a RedirectResponse
  whose URL carries a scrubbed error / ok flash param. Never lets a raw
  exception string reach the URL.
- `flash_context(ctx, err=..., ok=...)` — mutate a template context dict to
  include a scrubbed flash pair under conventional keys.
- `flash_htmx(err=..., ok=...) -> HTMLResponse` — return an HTMX-friendly
  inline error/ok fragment.
- `scrub_exc(exc, *, purpose)` — the SHARED SCRUBBER. Maps a raw exception to
  a user-facing string. Purpose-labeled so hipaa-sme + db-sme can audit which
  paths surface what shape of message.

Every helper takes str-or-Exception; when handed an Exception, `scrub_exc`
runs (drops chained context, kills stack traces, replaces PHI/secret-shape
tokens with placeholders per an ALLOW-LIST of safe shapes).

NOT DONE (next-window build):
- 126-site adoption sweep (see audit-reports/r20_1_error_surface_full_enumeration.json).
- 3-arm interprocedural AST pin (redirect QS allowlist + HTMLResponse-in-router
  routing + context-key ban list).
- 3-SME panel + §164.316 register row N-179.
"""
from __future__ import annotations

from typing import Any

from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.web.routers._redirect import err_qs, msg_qs

# The known-safe context/redirect keys the flash SSOT emits. Anything outside
# this set that carries an error string is a leak candidate (the census's
# strict interprocedural pin will enforce that new keys must join this set).
FLASH_KEYS: frozenset[str] = frozenset({"err", "ok", "warn", "info"})

# Purpose labels for `scrub_exc(purpose=...)`. Naming the purpose lets the pin +
# SME audit which caller-classes surface which shape (e.g. "auth" is more
# sensitive than "form-validation").
FLASH_PURPOSES: frozenset[str] = frozenset({
    "auth", "config", "backup", "digest", "triage", "provider",
    "form", "search", "admin", "misc",
})


_SENSITIVE_PURPOSES: frozenset[str] = frozenset({
    "auth",       # session tokens, key material
    "config",     # secret config values
    "backup",     # bundle passphrases, master keys
    "provider",   # hipaa-sme N-179 must-fix: OAuth error_description /
                  # WWW-Authenticate leaks client-secret fragments + tokens
    "digest",     # hipaa-sme N-179 must-fix: Jinja UndefinedError echoes
                  # attribute paths that name a subject
})


def scrub_exc(exc: Exception | str, *, purpose: str = "misc") -> str:
    """Map a raw exception (or already-string) to a user-facing message.

    Per hipaa-sme N-179 (2026-07-02):
    - Sensitive purposes (auth / config / backup / provider / digest) → generic
      "<purpose> operation failed" message. Callers wanting detail log the raw
      exception via `_log` (privileged sink) + surface only the scrubbed string.
    - Informational purposes (form / search / triage / admin / misc) → preserve
      message but strip PHI + secret shapes: email, hex token ≥12 chars,
      base64 blob ≥16 chars, US SSN, US phone, IPv4/v6, MRN-shape, DOB (ISO
      or slash), JWT, UUID, Bearer/Basic tokens.

    Length cap AFTER scrubbing so a huge exception doesn't blow the template.
    Cap-before-scrub would leave partial shapes intact.
    """
    if purpose not in FLASH_PURPOSES:
        purpose = "misc"
    raw = exc if isinstance(exc, str) else str(exc)
    if purpose in _SENSITIVE_PURPOSES:
        return f"{purpose} operation failed"
    # DA N-179 must-fix (DoS): slice BEFORE regex so a 10MB str(e) from a
    # runaway parser can't pin CPU on backtracking. 2048-char window is well
    # over the 200-char final cap yet cheap to regex.
    s = raw[:2048]
    import re
    # Order matters: JWT + UUID first (they'd also match hex-token / base64).
    s = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "<jwt>", s)
    s = re.sub(r"\b(?:Bearer|Basic)\s+\S+", "<auth-header>", s)
    s = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<uuid>", s)
    # PHI shapes (SSN / phone / DOB / MRN) — matter most for medical-researcher reuse.
    s = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "<ssn>", s)
    s = re.sub(r"\b\d{9}\b", "<ssn>", s)  # 9-consecutive variant
    s = re.sub(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b", "<phone>", s)
    s = re.sub(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b", "<dob>", s)
    s = re.sub(r"\b\d{2}/\d{2}/(?:19|20)\d{2}\b", "<dob>", s)
    s = re.sub(r"\b(?:MRN|mrn)[:\s#-]*\w{4,}\b", "<mrn>", s)
    # Network shapes.
    s = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<ipv4>", s)
    s = re.sub(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", "<ipv6>", s)
    # Generic shapes (last — least specific).
    s = re.sub(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+", "<email>", s)
    s = re.sub(r"\b[0-9a-fA-F]{12,}\b", "<token>", s)
    s = re.sub(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", "<blob>", s)
    return s[:200] or f"{purpose} operation failed"


def flash_redirect(url: str, *, err: Exception | str | None = None,
                   ok: Exception | str | None = None,
                   purpose: str = "misc") -> RedirectResponse:
    """Redirect to `url` with a scrubbed err= / msg= query param.

    Two SSOT layers — never regresses the census run12 #5 flash-redirect SSOT:
    - `scrub_exc()` (this module) does the exception→user-safe-string mapping
      (drops PHI/secret shapes, generic message for sensitive purposes).
    - `err_qs()` / `msg_qs()` (`web/routers/_redirect.py`) does the URL encoding
      (via `urllib.parse.quote(safe='')`, HTML-context-hardened). Pinned by
      `test_redirect_qs_ssot_pin.py` — do NOT re-implement here.

    Sub-class 1 SSOT.
    """
    frags: list[str] = []
    if err is not None:
        frags.append(err_qs(scrub_exc(err, purpose=purpose)))
    if ok is not None:
        frags.append(msg_qs(scrub_exc(ok, purpose=purpose)))
    if frags:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{'&'.join(frags)}"
    return RedirectResponse(url=url, status_code=303)


def flash_context(ctx: dict[str, Any], *, err: Exception | str | None = None,
                  ok: Exception | str | None = None,
                  purpose: str = "misc") -> dict[str, Any]:
    """Mutate `ctx` in place to add scrubbed err/ok flash strings, return it.

    Sub-class 3 SSOT — every template context that surfaces an error routes
    through this call so the interprocedural pin has a single seam.
    """
    if err is not None:
        ctx["err"] = scrub_exc(err, purpose=purpose)
    if ok is not None:
        ctx["ok"] = scrub_exc(ok, purpose=purpose)
    return ctx


def flash_htmx(*, err: Exception | str | None = None,
               ok: Exception | str | None = None,
               purpose: str = "misc") -> HTMLResponse:
    """Return an HTMX-friendly inline flash fragment. Sub-class 2 SSOT."""
    msg = scrub_exc(err, purpose=purpose) if err is not None else (
        scrub_exc(ok, purpose=purpose) if ok is not None else "")
    cls = "err" if err is not None else "ok"
    body = f'<small class="flash-{cls}">{msg}</small>'
    return HTMLResponse(body)
