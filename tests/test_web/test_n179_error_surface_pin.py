"""N-179 structural pin — R20_1 error-surface SSOT enforcement.

Three-arm interprocedural AST pin (per run20 §7#2 splits):

Arm 1 (redirect-flash-key): every RedirectResponse in a router MUST route
through `web/_flash.py::flash_redirect` — no raw exception in the URL.

Arm 2 (HTMLResponse-error-body): HTMLResponse whose body includes a raw
exception ref MUST route through `web/error_html.py::error_chip` or
`error_article` (the composed A8+N-179 SSOT that html-escapes + scrubs).

Arm 3 (context-key-err-msg): a subscript-assign / dict-key / kwarg of the
form `{"err_msg": str(e)}` (or `err_msg=str(e)`) into a template ctx MUST
route through `web/_flash.py::flash_context` — no raw exception in ctx.

Composition SSOT: exception-string sanitization lives in `web/_flash.py::scrub_exc`;
the two rendering SSOTs (`error_chip`/`error_article` for HTML, `flash_redirect`
for URLs) compose it. That's a single scrub seam and a single escape/URL-encode
seam per surface.

Ratchet: partial adoption baselines from R20_1a enumeration
(audit-reports/r20_1_error_surface_full_enumeration.json). Migrations
DECREMENT the baseline in the SAME commit that removes sites.
"""
from __future__ import annotations

import ast
from pathlib import Path

from tests._pin_harness import SRC_ROOT, iter_files, parse_module, relpath

ROUTERS = SRC_ROOT / "web" / "routers"

# Ratchet baselines (2026-07-02 — R20_1 close). Decrement in the SAME commit
# that removes sites (commit-coupled per N-178 pattern).
_MAX_SUB1_RAW_REDIRECT = 0     # sub1 (redirect-flash-key) — STRICT-0 after sub-1 sweep landed
_MAX_SUB2_RAW_HTML     = 0     # sub2 (HTMLResponse-error-body) — STRICT-0 after R21_2 sweep (2026-07-02)
_MAX_SUB3_RAW_CTX      = 0     # sub3 (context-key-err-msg) — STRICT-0 achieved 2026-07-02 (detector narrowed + `type(exc).__name__` safe-idiom exempted + scrub_error_for_persist added to _SSOT_NAMES + 10 real sites migrated to scrub_exc SSOT); scrub_class_error_for_persist added to _SSOT_NAMES 2026-07-06 (N-375 SSOT collapse — the new wrapper composes fmt_exc + scrub_error_for_persist so it IS an adopted wrapper)

# HIPAA-load-bearing files — strict-0 carve-out for sub-1 (redirect) only.
# Sub-2 and sub-3 have pre-existing debt in these files that pre-dates N-179;
# a full migration is tracked as N-179a follow-up. New sub-2/sub-3 drift is
# still blocked by the general ratchet (baseline never grows).
_HIPAA_STRICT_FILES_SUB1 = {
    "web/routers/auth_keys.py",  # §164.312(d) authentication surface
    "web/routers/backup.py",     # §164.308(a)(7) backup surface
}
_HIPAA_STRICT_FILES = _HIPAA_STRICT_FILES_SUB1  # kept for downstream references

# Existing scrub-SSOT names. A call to one of these WRAPPING the exception is
# considered adopted; the composition delegates to scrub_exc.
_SSOT_NAMES = {"flash_redirect", "flash_context", "flash_htmx",
               "error_chip", "error_article", "scrub_exc",
               "raise_api_error", "api_error_response",
               "err_qs", "msg_qs",
               # N-179 R21_2 (2026-07-02): existing scrub SSOTs the pin
               # recognises as adopted wrappers.
               "scrub_error_for_persist",
               # N-375 (2026-07-06): the class-prefixed persist SSOT —
               # composes fmt_exc(with_class=True) + scrub_error_for_persist,
               # so a call wrapping the exception IS adopted.
               "scrub_class_error_for_persist"}


_DEFAULT_EXC_NAMES = frozenset({"e", "exc", "exception"})
# N-179 R21_2 refinement (2026-07-02): `err` REMOVED from the default
# exception-name set. It's a common non-exception variable (authz-error
# return values, pre-scrubbed error strings from db_call tuples) — the
# broad default caused ~85% false-positive rate on sub-2 ratchet (14 of
# 20 profile.py `HTMLResponse(err or ...)` sites are pre-scrubbed authz
# returns, not raw exceptions). Real `err` exception-bindings from
# `except X as err` still get picked up via `_collect_except_bindings`
# per-file.


def _collect_except_bindings(tree: ast.AST) -> set[str]:
    """db-sme N-179 must-fix (b): widen _is_exception_ref name-set to include
    every `except X as <name>:` binding in the module — catches `err_var`,
    `oauth_err`, `parse_e`, etc. that the hard-coded {e,exc,err,exception}
    set was blind to (Prime Directive #2: interproc pin key on the bind
    site, not a fixed name-set)."""
    names = set(_DEFAULT_EXC_NAMES)
    for sub in ast.walk(tree):
        if isinstance(sub, ast.ExceptHandler) and sub.name:
            names.add(sub.name)
    return names


def _is_exception_ref(node: ast.AST, exc_names: frozenset[str] | set[str] | None = None) -> bool:
    """Walk `node`; return True if it contains a bare exception-variable
    reference (Name in `exc_names`, defaulting to the common four)
    NOT already inside a SSOT wrapper call."""
    if exc_names is None:
        exc_names = _DEFAULT_EXC_NAMES
    # N-179 R21_2 (2026-07-02): pre-collect all Name IDs that appear ONLY
    # inside `type(<exc>)...` — the class-name extraction idiom is safe
    # (no PHI in a Python class name).
    safe_type_wrapped: set[int] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                and sub.func.id == "type":
            for arg in sub.args:
                for sn in ast.walk(arg):
                    if isinstance(sn, ast.Name) and sn.id in exc_names:
                        safe_type_wrapped.add(id(sn))
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            called = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else None)
            if called in _SSOT_NAMES:
                return False  # ssot wraps the arg; adopted
        if isinstance(sub, ast.Name) and sub.id in exc_names \
                and id(sub) not in safe_type_wrapped:
            return True
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
            # fmt_exc / format_exc are intrinsically exception-adjacent.
            if sub.func.id in {"format_exc", "fmt_exc"}:
                return True
            # str(x) / repr(x): only counts if x is a Name in exc_names —
            # `str(fp)`/`str(backend)`/`str(payload)` (a form value or config
            # scalar) is NOT an exception ref. N-179 R21_2 refinement:
            # tightened over-broad detector on 2026-07-02 after run21 backlog
            # showed the pin over-reported sub-2 ratchet by ~85% (14 of 20
            # sites were `err`-shaped auth-error returns or `str(<scalar>)`
            # in pre-existing html.escape safety chains, not real leaks).
            if sub.func.id in {"str", "repr"} and sub.args:
                arg0 = sub.args[0]
                if isinstance(arg0, ast.Name) and arg0.id in exc_names:
                    return True
    return False


def _walk_routers(check):
    """Iter (rel, offenders) for router files. `check(tree)` returns lineno list."""
    reports = []
    for py in iter_files(ROUTERS):
        tree = parse_module(py)
        if tree is None:
            continue
        rel = relpath(py)
        lines = check(tree)
        for ln in lines:
            reports.append((rel, ln))
    return reports


def _sub1_check(tree: ast.AST) -> list[int]:
    """Raw RedirectResponse in a router body that carries an exception."""
    exc_names = _collect_except_bindings(tree)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "RedirectResponse":
            for a in node.args + [kw.value for kw in node.keywords if kw.arg == "url"]:
                if _is_exception_ref(a, exc_names):
                    hits.append(node.lineno)
                    break
    return hits


def _sub2_check(tree: ast.AST) -> list[int]:
    """HTMLResponse whose first arg contains an exception ref NOT wrapped
    in a SSOT (error_chip / error_article)."""
    exc_names = _collect_except_bindings(tree)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "HTMLResponse" and node.args:
            if _is_exception_ref(node.args[0], exc_names):
                hits.append(node.lineno)
    return hits


def _sub3_check(tree: ast.AST) -> list[int]:
    """A dict-key / kwarg / subscript-assign of a known error key carrying
    a raw exception ref."""
    # N-179 R21_2 refinement (2026-07-02): NARROWED to template-context-
    # specific keys. `detail`, `exc`, `reason`, `msg`, `message` are common
    # kwargs in audit/log helpers (`_record_*_audit(detail=fmt_exc(e))`,
    # `logger.error(msg=..., reason=...)`) where a raw exception is the
    # LEGITIMATE server-side sink. `err_msg` / `error_msg` are the specific
    # Jinja template-context conventions the census originally flagged;
    # `error` is common enough to keep as a template key too.
    ERR_KEYS = {"err_msg", "error_msg", "error", "parse_error"}  # punch 426: + parse_error
    # N-179 R21_2 refinement (2026-07-02): kwargs to LOG methods
    # (log.warning/.error/.info/.debug + logger.*) are SERVER-SIDE
    # sinks and legit — skip them. `log.warning("msg", error=fmt_exc(e))`
    # is a structured-log call, not a user-facing render.
    _LOG_ATTRS = {"warning", "error", "info", "debug", "exception", "critical"}
    _AUDIT_CALL_PREFIXES = ("record_", "_record_", "_audit_", "audit_")
    # Excluded-nodes set: EVERY descendant of a log/audit call is a
    # server-side sink, not user-facing. Nested `extra={"_extra":
    # {"error": ...}}` under log.error() must not fire.
    excluded_ids: set[int] = set()
    for node in ast.walk(tree):
        is_log = (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in _LOG_ATTRS
        )
        is_audit_call = (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and any(node.func.id.startswith(p) for p in _AUDIT_CALL_PREFIXES)
        )
        if is_log or is_audit_call:
            for sub in ast.walk(node):
                excluded_ids.add(id(sub))
    log_kwargs = excluded_ids  # keep the historical name for the kwargs check
    exc_names = _collect_except_bindings(tree)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in ERR_KEYS \
                and id(node) not in log_kwargs \
                and _is_exception_ref(node.value, exc_names):
            hits.append(getattr(node.value, "lineno", 0))
        if isinstance(node, ast.Dict) and id(node) not in excluded_ids:
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value in ERR_KEYS and _is_exception_ref(v, exc_names):
                    hits.append(getattr(v, "lineno", 0))
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Subscript) and isinstance(tgt.slice, ast.Constant) \
                        and tgt.slice.value in ERR_KEYS and _is_exception_ref(node.value, exc_names):
                    hits.append(node.lineno)
    return hits


def _sub4_check(tree: ast.AST) -> list[int]:
    """DA N-179 arm 4: forbid the manual-str(e) regression pattern
    `error_chip(str(e), ...)` / `error_article(str(e), ...)` — callers
    MUST pass the Exception object so the SSOT owns chain-context
    flattening (str(e) at the caller flattens `__cause__` / traceback
    formatter output that regex can't fully catch)."""
    exc_names = _collect_except_bindings(tree)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in {"error_chip", "error_article"} and node.args:
            first = node.args[0]
            if isinstance(first, ast.Call) and isinstance(first.func, ast.Name) \
                    and first.func.id in {"str", "repr", "format_exc", "fmt_exc"}:
                # Peek: was the arg to str/repr an exception name?
                for sub in ast.walk(first):
                    if isinstance(sub, ast.Name) and sub.id in exc_names:
                        hits.append(node.lineno)
                        break
    return hits


def _classify(reports):
    """Split (rel, ln) tuples into strict-0-carve-out vs ratchet-eligible.

    `rel` arrives already-normalised forward-slash (see line 141 —
    `rel = relpath(py)` via `_pin_harness.relpath`), so the prior local
    `.replace("\\\\", "/")` was pure double-work — dropped per DA
    panel review of N-382 (scanner scope-widening tail).
    """
    hipaa, ratchet = [], []
    for rel, ln in reports:
        if any(rel.endswith(h) or h in rel for h in _HIPAA_STRICT_FILES):
            hipaa.append(f"{rel}:{ln}")
        else:
            ratchet.append(f"{rel}:{ln}")
    return hipaa, ratchet


# ---------------------------------------------------------------------------
# Pin arms
# ---------------------------------------------------------------------------

def test_sub1_no_raw_exc_in_redirectresponse():
    """Arm 1 — router-side RedirectResponse must route through flash_redirect
    (strict-0 after the sub-1 sweep)."""
    reports = _walk_routers(_sub1_check)
    hipaa, ratchet = _classify(reports)
    assert not hipaa, (
        "N-179 STRICT-0 CARVE-OUT — HIPAA-load-bearing router still uses raw "
        "RedirectResponse+exception: " + ", ".join(hipaa)
    )
    assert len(ratchet) <= _MAX_SUB1_RAW_REDIRECT, (
        f"N-179 sub-1 raw redirect count {len(ratchet)} > baseline "
        f"{_MAX_SUB1_RAW_REDIRECT}: " + ", ".join(ratchet[:10])
    )


def test_sub2_htmlresponse_error_body_ratchet():
    """Arm 2 — HTMLResponse w/ raw exception body must route through error_chip/
    error_article. Ratchet baseline while sub-2 sweep completes; HIPAA strict-0
    is deferred to N-179a follow-up (existing debt exists)."""
    reports = _walk_routers(_sub2_check)
    all_sites = [f"{rel}:{ln}" for rel, ln in reports]
    assert len(all_sites) <= _MAX_SUB2_RAW_HTML, (
        f"N-179 sub-2 raw HTMLResponse count {len(all_sites)} > baseline "
        f"{_MAX_SUB2_RAW_HTML}: " + ", ".join(all_sites[:10])
    )


def test_sub3_context_key_err_msg_ratchet():
    """Arm 3 — raw exception in error-shaped ctx keys must route through
    flash_context. Ratchet baseline while sub-3 sweep completes; HIPAA strict-0
    is deferred to N-179a follow-up (existing debt exists)."""
    reports = _walk_routers(_sub3_check)
    all_sites = [f"{rel}:{ln}" for rel, ln in reports]
    assert len(all_sites) <= _MAX_SUB3_RAW_CTX, (
        f"N-179 sub-3 raw ctx-key count {len(all_sites)} > baseline "
        f"{_MAX_SUB3_RAW_CTX}: " + ", ".join(all_sites[:10])
    )


def test_sub4_no_str_e_in_error_chip():
    """Arm 4 (DA must-fix) — STRICT-0: never `error_chip(str(e), ...)` or
    `error_article(str(e), ...)`. Callers must pass the Exception so the
    SSOT owns chain-context flattening."""
    reports = _walk_routers(_sub4_check)
    all_sites = [f"{rel}:{ln}" for rel, ln in reports]
    assert not all_sites, (
        "N-179 sub-4 STRICT-0: error_chip/error_article called with str(<exc>) — "
        "pass the Exception object directly: " + ", ".join(all_sites)
    )


def test_pin_has_teeth():
    """Verify each arm fires on a bad shape."""
    bad_sub1 = """
def h():
    e = ValueError("bad")
    return RedirectResponse(f"/x?err={str(e)}", status_code=303)
"""
    assert _sub1_check(ast.parse(bad_sub1)), "sub1 teeth: bad shape must fire"

    bad_sub2 = """
def h():
    e = ValueError("bad")
    return HTMLResponse(f"<small>Error: {e}</small>")
"""
    assert _sub2_check(ast.parse(bad_sub2)), "sub2 teeth: bad shape must fire"

    bad_sub3 = """
def h():
    e = ValueError("bad")
    ctx = {"err_msg": str(e)}
    return ctx
"""
    assert _sub3_check(ast.parse(bad_sub3)), "sub3 teeth: bad shape must fire"

    # SSOT-wrapped is NOT flagged.
    good = """
def h():
    e = ValueError("bad")
    return HTMLResponse(error_chip(e, prefix='X: ', purpose='form'))
"""
    assert not _sub2_check(ast.parse(good)), "sub2 teeth: SSOT-wrapped must NOT fire"

    # sub4 teeth: forbid error_chip(str(e), ...) pattern.
    bad_sub4 = """
def h():
    try:
        x = 1
    except Exception as e:
        return HTMLResponse(error_chip(str(e), prefix='X: '))
"""
    assert _sub4_check(ast.parse(bad_sub4)), "sub4 teeth: str(<exc>) shape must fire"

    # db-sme widened bindings: `except X as parse_e` is caught.
    bad_bind = """
def h():
    try:
        x = 1
    except Exception as parse_e:
        return HTMLResponse(f"<small>{parse_e}</small>")
"""
    assert _sub2_check(ast.parse(bad_bind)), "widened binding: except-as name must fire"
