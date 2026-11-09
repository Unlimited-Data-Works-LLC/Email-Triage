"""N-197 R21_3 structural pin — cookie `secure=` MUST NOT be a literal.

Census run21 R21_3 discovered class: `web/routers/auth_keys.py:395` (the
dev-keypair challenge cookie) hardcoded `secure=False` — un-Secure on prod
HTTPS. A same-site downgrade could read the challenge cookie. The other 3
`set_cookie` sites in web/ (csrf.py, auth.py, auth_keys.py:896) all source
`secure=` from a config/https derivation.

Fix landed 2026-07-02: auth_keys.py:395 now derives `https = bool(getattr(
getattr(config, "tls", None), "enabled", False))` and passes `secure=https`.

Pin: every `set_cookie(...)` call anywhere in `src/email_triage/web/**`
MUST pass `secure=` as a NAME reference (not a bare bool literal). A
literal `secure=True` is banned as strongly as `secure=False` — the value
MUST come from a live-config derivation so a config change flips it.

N-197b follow-up (per census): factor a `web/_cookies.py::secure_flag(
config)` SSOT + `set_short_lived_challenge_cookie` helper so callers don't
even inline the `getattr(getattr(...))` chain.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


WEB_DIR = SRC_ROOT / "web"


def _find_literal_secure_cookies(tree: ast.AST) -> list[int]:
    """Every `<obj>.set_cookie(...)` call whose `secure=` kwarg is a bare
    True/False Constant."""
    hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "set_cookie":
            continue
        for kw in node.keywords:
            if kw.arg != "secure":
                continue
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
                hits.append(node.lineno)
    return hits


def test_no_literal_secure_flag_in_set_cookie():
    """Every `set_cookie` call in web/ MUST source `secure=` from a live-
    config-derived var, not a bare True/False literal. A literal defeats
    the point of the flag — the value can't reflect a runtime config
    change."""
    offenders: list[str] = []
    for path in iter_files(WEB_DIR):
        tree = parse_module(path)
        if tree is None:
            continue
        for ln in _find_literal_secure_cookies(tree):
            offenders.append(f"{relpath(path)}:{ln}")
    assert not offenders, (
        f"N-197 R21_3: set_cookie() with literal secure=True/False: "
        f"{offenders}. Source secure= from a config-derived var like "
        "`https = bool(getattr(getattr(config, 'tls', None), 'enabled', False))`."
    )


def test_pin_has_teeth():
    bad = ast.parse("""
def h(resp):
    resp.set_cookie("k", "v", secure=False)
""")
    assert _find_literal_secure_cookies(bad), "teeth: bad shape must fire"

    bad_true = ast.parse("""
def h(resp):
    resp.set_cookie("k", "v", secure=True)
""")
    assert _find_literal_secure_cookies(bad_true), "teeth: literal True also fires (rigidity is the bug)"

    good = ast.parse("""
def h(resp, https):
    resp.set_cookie("k", "v", secure=https)
""")
    assert not _find_literal_secure_cookies(good), "teeth: var ref must not fire"
