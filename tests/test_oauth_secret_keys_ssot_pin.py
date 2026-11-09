"""OAuth secret-store key-name SSOT pin (divergence census run13 #9).

The Google/O365 OAuth client-credential secret-store KEYS are referenced on two
sides — the SAVE path (``web/routers/integrations.py``) and the HYDRATE path
(``web/app.py`` boot). Duplicated string literals desync on a rename/typo (save
writes key X, hydrate reads key Y → install-wide OAuth death, the 2026-06-08
clobber class). ``web/oauth_secret_keys.py`` is the SSOT.

Count-agnostic property: a string literal equal to one of the OAuth secret-store
keys must NOT appear anywhere outside the SSOT module — every consumer imports
the named constant. A new ``read_secret(secrets, "GOOGLE_OAUTH_…")`` raw literal
turns this RED.
"""

from __future__ import annotations

import ast

from email_triage.web.oauth_secret_keys import OAUTH_SECRET_KEYS

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

_SSOT_REL = "web/oauth_secret_keys.py"


def _literal_oauth_keys(tree: ast.AST) -> list:
    out = []
    for n in ast.walk(tree):
        if (isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value in OAUTH_SECRET_KEYS):
            out.append(f"{n.value}@{getattr(n, 'lineno', '?')}")
    return out


def test_no_raw_oauth_secret_key_literal_outside_ssot():
    offenders = []
    for p in iter_src_files():
        rel = relpath(p)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        hits = _literal_oauth_keys(tree)
        if hits:
            offenders.append(f"{rel}: {hits}")
    assert not offenders, (
        "A raw OAuth secret-store key literal appears outside the SSOT "
        f"web/oauth_secret_keys.py: {offenders}. The SAVE (integrations.py) and "
        "HYDRATE (app.py) paths must import the SAME named constant — a "
        "duplicated literal desyncs on a rename/typo (install-wide OAuth death, "
        "the 2026-06-08 clobber class). Import the constant from "
        "email_triage.web.oauth_secret_keys instead of writing the string."
    )


def test_ssot_defines_all_keys():
    tree = parse_module(SRC_ROOT / "web" / "oauth_secret_keys.py")
    names = {
        n.targets[0].id for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
    }
    # The 7 client-credential keys + the aggregate set.
    for expected in (
        "GOOGLE_OAUTH_WEB_CLIENT_ID", "O365_OAUTH_CLIENT_SECRET",
        "OAUTH_SECRET_KEYS",
    ):
        assert expected in names, f"oauth_secret_keys.py lost {expected!r}"
    # Count-AGNOSTIC (was `len(...) == 7` — a magic number that silently drifts
    # when a provider key is added/removed): the aggregate set must equal EXACTLY
    # the per-key string constants, DERIVED from the module, so the set and the
    # named constants cannot diverge (a new key must land in BOTH; a constant
    # missing from the set, or an extra in the set, is RED).
    import email_triage.web.oauth_secret_keys as _oauth_mod
    key_constant_values = {
        getattr(_oauth_mod, n) for n in names
        if n != "OAUTH_SECRET_KEYS" and isinstance(getattr(_oauth_mod, n, None), str)
    }
    assert set(OAUTH_SECRET_KEYS) == key_constant_values, (
        "OAUTH_SECRET_KEYS must equal the set of the per-key named string "
        f"constants — drift: set={set(OAUTH_SECRET_KEYS)} vs "
        f"constants={key_constant_values}. Add a new provider key to BOTH the "
        "named constant AND the aggregate set."
    )


def test_pin_has_teeth():
    bad = ast.parse('x = read_secret(s, "GOOGLE_OAUTH_WEB_CLIENT_ID")\n')
    assert _literal_oauth_keys(bad), "missed a raw OAuth-key literal"
    ok = ast.parse('x = read_secret(s, GOOGLE_OAUTH_WEB_CLIENT_ID)\n')  # the constant
    assert not _literal_oauth_keys(ok), "flagged the named constant"
    unrelated = ast.parse('x = read_secret(s, "SESSION_SECRET")\n')
    assert not _literal_oauth_keys(unrelated), "flagged a non-OAuth key"
