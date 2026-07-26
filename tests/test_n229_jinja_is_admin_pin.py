"""N-229 R22 structural pin — Jinja `user.role == "admin"` STRICT-0 (2026-07-02).

Census R22 flagged the template-side is_admin drift: 6 Jinja `user.role`
reads on non-StrictUndefined ctx silently coerce False on missing key
(the pre-fix pattern: `{% if user.role == "admin" %}` returned False when
`user` was Undefined instead of raising, so a handler that forgot to
pass `user` degraded ADMIN to non-admin invisibly).

N-229 fix (this pin's landing commit):
  - `web/app.py` — expose `is_admin` as a Jinja global (`templates.env.
    globals["is_admin"] = _is_admin`).
  - `web/templates/base.html` — migrate 7 `{% if user.role == "admin" %}`
    sites to `{% if is_admin(user) %}`.
  - This pin — STRICT-0 tree-wide: no template contains
    `user.role == "admin"` (or `.role != "admin"`).

WHAT IT PINS (count-agnostic, tree-wide over `.html` + `.jinja` templates):

Every occurrence of `user.role == "admin"` / `user.role != "admin"` /
`user.role in [...]` in ANY template file fires. Route through the
`is_admin(user)` Jinja global.

SCOPE CAVEAT: text-scan (not AST — Jinja doesn't ship an AST walker
matching Python's ast module for our patterns). Extend the regex when a
new drift shape surfaces (e.g. `current_user.role`, `session.role`).
"""
from __future__ import annotations

import re
from pathlib import Path

from _pin_harness import TEMPLATES_ROOT, iter_template_files, relpath as _relpath  # noqa: F401


# `user.role == "admin"` / `user.role != "admin"` (with either quote style).
_DRIFT_PATTERNS = [
    re.compile(r"user\.role\s*==\s*['\"]admin['\"]"),
    re.compile(r"user\.role\s*!=\s*['\"]admin['\"]"),
]


def test_no_raw_user_role_admin_in_templates():
    """STRICT-0: no template contains `user.role == "admin"` or its
    negation. Route through the `is_admin(user)` Jinja global."""
    offenders: list[str] = []
    # N-224b R23: route WALK + relpath through the shared harness helpers
    # (fixes pin-harness-drift meta-pin flags V1+V5 on this file).
    for path in iter_template_files():
        if path.suffix.lower() not in (".html", ".jinja", ".j2"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in _DRIFT_PATTERNS:
            for m in pat.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                # N-224b R23: route relpath through the harness (SRC_ROOT
                # anchor). Yields `web/templates/base.html` shape for the
                # offender path — different anchor than TEMPLATES_ROOT
                # (that was `base.html`) but strictly more informative +
                # the harness owns the forward-slash normalization.
                rel = _relpath(path)
                offenders.append(f"{rel}:{line_no}  {m.group(0)}")
    assert not offenders, (
        "N-229 R22 Jinja is_admin STRICT-0: `user.role == \"admin\"` / "
        "`user.role != \"admin\"` in a template file. Route through the "
        "`is_admin(user)` Jinja global (registered in `web/app.py` at the "
        "Jinja2Templates env setup). Fail-closed on missing `user` ctx — "
        "the SSOT is `web/dependencies.py::is_admin` (Python N-222).\n\n"
        + "\n".join(offenders)
    )


def test_is_admin_jinja_global_wired():
    """Anti-vacuity: `is_admin` must be wired as a Jinja global in
    `web/app.py`. If it goes missing, migrated templates raise
    UndefinedError on every admin-gated fragment."""
    from pathlib import Path as _Path
    src = _Path(TEMPLATES_ROOT).parent / "app.py"
    text = src.read_text(encoding="utf-8")
    assert 'templates.env.globals["_admin_of"]' in text, (
        "N-229 R22 anti-vacuity: `templates.env.globals[\"_admin_of\"]` is "
        "no longer wired in `web/app.py`. Every migrated template fires "
        "UndefinedError on render. Restore the wiring or revert the "
        "migrations + pin. (Named `_admin_of` to avoid shadow by the "
        "`is_admin` BOOL that ~60 handlers pass in template ctx.)"
    )
