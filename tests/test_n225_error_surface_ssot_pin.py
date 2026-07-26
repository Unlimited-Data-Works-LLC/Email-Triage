"""N-225 R22 structural pin — error-surface SSOT anti-vacuity + strict Arm-B (2026-07-02).

Census R22 (run22 backlog HIGH #1) flagged `error-surface` — 4 SSOT modules
(`_flash.py`, `error_surface.py`, `error_html.py`, `_redirect.py`) exist
in-tree but the census verifier found 57-95 off-SSOT sites and reported
"SSOT DEFINED, ENFORCEMENT INCOMPLETE."

Verify-don't-accept at HEAD (2026-07-02):
- Arm B strict (`HTMLResponse(f"...{e|exc|err|error}...")` — the literal
  PHI-leak-via-str(e) shape the census called out): **0 sites tree-wide**.
  Either the census-observed sites were remediated between census-time and
  HEAD, OR the census's arm-B claim reflected a broader shape (any f-string
  body) that includes many legit local render helpers.

This pin is a MINIMUM-VIABLE anti-vacuity + strict-Arm-B guard. It does
NOT yet enforce the full 4-arm interprocedural contract the census
recommended (that requires a SME panel — hipaa-sme + db-sme + devils-
advocate — and a bigger interprocedural walker for Arm C's TemplateResponse
ctx-var subscript assigns). Recorded as follow-up.

WHAT IT PINS (count-agnostic):

1. **Arm B STRICT-0** (`test_no_htmlresponse_fstring_with_raw_exc`) — every
   `HTMLResponse(...)` call whose first arg is an f-string interpolating a
   bare exception name (`{e}` / `{exc}` / `{err}` / `{error}` / `{str(e)}`
   as a nested Call) fires the pin. Baseline 0 tree-wide.

2. **SSOT existence anti-vacuity** (`test_error_surface_ssots_exist`) —
   asserts the 4 SSOT modules import and expose their documented callables
   (`_flash.scrub_exc/flash_htmx/flash_redirect/flash_context`,
   `error_surface.api_error_response/raise_api_error`,
   `error_html.error_chip/error_article`, `_redirect.err_qs/read_flash`).
   If a rename removes an SSOT, this fires — the pin's targets vanished and
   downstream migrations shouldn't blindly proceed on stale drawer text.

FOLLOW-UP (deferred pending SME panel):
- Arm A flash-key redirects → allow-list appears in reader coupling
- Arm C TemplateResponse FLASH_CTX_KEYS → interprocedural walk of
  `<name> = {...}` / `<name>[<key>] = <value>` → follow Name to consumer
- Arm D JSONResponse['error'|'detail'] / HTTPException detail scrub
- Widen this pin per SME panel review.
"""
from __future__ import annotations

import ast
import importlib

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_EXC_NAMES = {"e", "exc", "err", "error"}


def _fstring_interpolates_bare_exc(joined: ast.JoinedStr) -> bool:
    """True if any FormattedValue inside `joined` is a bare exception Name
    (or `str(<exc>)` — an equally-unscrubbed form)."""
    for v in joined.values:
        if not isinstance(v, ast.FormattedValue):
            continue
        expr = v.value
        if isinstance(expr, ast.Name) and expr.id in _EXC_NAMES:
            return True
        if isinstance(expr, ast.Call):
            f = expr.func
            fname = (f.id if isinstance(f, ast.Name)
                     else f.attr if isinstance(f, ast.Attribute) else None)
            if fname == "str":
                for a in expr.args:
                    if isinstance(a, ast.Name) and a.id in _EXC_NAMES:
                        return True
    return False


def test_no_htmlresponse_fstring_with_raw_exc():
    """STRICT-0: no `HTMLResponse(f"...{e|exc|err|error}...")` or
    `HTMLResponse(f"...{str(e)}...")` tree-wide. Route through
    `_flash.flash_htmx(purpose=..., msg=scrub_exc(e))` or
    `error_html.error_chip/error_article(...)`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = (f.id if isinstance(f, ast.Name)
                    else f.attr if isinstance(f, ast.Attribute) else None)
            if name != "HTMLResponse" or not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.JoinedStr) and _fstring_interpolates_bare_exc(arg):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "N-225 R22 error-surface Arm B STRICT-0: `HTMLResponse(f\"...{e}...\")` "
        "or `HTMLResponse(f\"...{str(e)}...\")` reflects an unscrubbed "
        "exception body — a PHI-leak-in-authenticated-admin-fragment + "
        "reflected-XSS vector.\n\n"
        "Route through `web/_flash.py::flash_htmx(purpose=<label>, "
        "msg=scrub_exc(e))` (returns the same-shape HTMLResponse) or "
        "`web/error_html.py::error_chip(msg=scrub_exc(e))` / "
        "`error_article(...)` for a richer fragment.\n\n"
        + "\n".join(offenders)
    )


def test_error_surface_ssots_exist():
    """Anti-vacuity: the 4 error-surface SSOTs must import and expose their
    documented callables. If any goes missing, downstream migrations are
    building on stale drawer text."""
    ssot_contracts = {
        "email_triage.web._flash": [
            "scrub_exc", "flash_htmx", "flash_redirect", "flash_context",
        ],
        "email_triage.web.error_surface": [
            "api_error_response", "raise_api_error",
        ],
        "email_triage.web.error_html": [
            "error_chip", "error_article",
        ],
        "email_triage.web.routers._redirect": [
            "err_qs", "read_flash",
        ],
    }
    missing: list[str] = []
    for mod_name, callables in ssot_contracts.items():
        try:
            mod = importlib.import_module(mod_name)
        except ImportError as e:
            missing.append(f"{mod_name} (import failed: {e})")
            continue
        for name in callables:
            if not hasattr(mod, name):
                missing.append(f"{mod_name}.{name}")
    assert not missing, (
        "N-225 R22 anti-vacuity: error-surface SSOT contract broken — the "
        "documented callables are the target of downstream adoption. If a "
        "callable was intentionally removed, update the census drawer + this "
        "test in the SAME change so migrations don't build on stale scaffolding.\n\n"
        + "\n".join(missing)
    )
