"""URL-query secret-scrub SSOT pin (census run23 #3, HIGH sev).

Gemini's auth IS ``?key=<PLAINTEXT>`` — so scrubbing that shape from any URL
rendered into an exception message / log line is the ONE guard on a real
plaintext-API-key leak. Before this SSOT the URL-query scrub function was
byte-forked into 3 identical ``_strip_sensitive_query_params`` defs across
``ai_backends/azure_openai.py``, ``ai_backends/gemini_adapter.py``,
``ai_backends/openai_direct.py`` — each with its own ``sensitive = {...}``
set literal + its own ``urlsplit`` iteration body. Adding a new key type
required editing all three; fixing only two silently left a leak path.

Now they all import ``strip_url_query_secrets`` and ``URL_QUERY_SECRET_KEYS``
from ``email_triage._secret_scrub``.

Invariant 1 (count-agnostic — matches the sibling pin's shape): a re-inlined
URL_QUERY_SECRET_KEYS collection (list/tuple/set literal holding >=3 of the
five keys) outside the SSOT is drift.

Invariant 2 (function-shape): no ``def _strip_sensitive_query_params`` /
``def strip_url_query_secrets`` outside the SSOT — a copy-pasted re-def is
the exact CIDI shape this pin guards.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath as _relpath, walk_src

SSOT = SRC_ROOT / "_secret_scrub.py"

from email_triage._secret_scrub import URL_QUERY_SECRET_KEYS  # noqa: E402


# Threshold for "this is a re-inlined URL_QUERY_SECRET_KEYS copy". The real
# set is 5 keys ({"api-key","key","token","access_token","code"}); a re-inline
# copies most of them. Set to 3 so a coincidental 2-overlap set (the
# SECRET_TOKEN_KEYS sibling shares only {"access_token","code"} with this one)
# is NOT flagged.
_REINLINE_THRESHOLD = 3


def _url_secret_key_collection_lines(tree: ast.AST) -> list[int]:
    """List/tuple/set literals holding >= _REINLINE_THRESHOLD URL_QUERY_SECRET_KEYS."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            cnt = sum(
                1 for e in n.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
                and e.value in URL_QUERY_SECRET_KEYS
            )
            if cnt >= _REINLINE_THRESHOLD:
                out.append(n.lineno)
    return out


_FORBIDDEN_FUNC_NAMES = frozenset({
    "_strip_sensitive_query_params",
    "strip_url_query_secrets",
})


def _forbidden_def_lines(tree: ast.AST) -> list[int]:
    """Function defs whose name matches the SSOT function or the historical
    ``_strip_sensitive_query_params`` local name — a re-def outside the SSOT is
    a copy-pasted fork."""
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name in _FORBIDDEN_FUNC_NAMES
    ]


def test_url_secret_key_collection_only_in_ssot():
    offenders = []
    for p, _rel, tree in walk_src():
        if p == SSOT:
            continue
        locs = _url_secret_key_collection_lines(tree)
        if locs:
            offenders.append(f"{_relpath(p)}:{locs}")
    assert not offenders, (
        "a URL-query-secret-key collection was re-inlined outside "
        f"_secret_scrub.py (census run23 #3, HIGH sev): {offenders}. Import "
        "URL_QUERY_SECRET_KEYS / strip_url_query_secrets from "
        "email_triage._secret_scrub instead of copying the set."
    )


def test_no_reforked_url_scrub_def_outside_ssot():
    offenders = []
    for p, _rel, tree in walk_src():
        if p == SSOT:
            continue
        locs = _forbidden_def_lines(tree)
        if locs:
            offenders.append(f"{_relpath(p)}:{locs}")
    assert not offenders, (
        "a URL-query-secret-scrub function was RE-DEFINED outside "
        f"_secret_scrub.py (census run23 #3, HIGH sev — plaintext-API-key "
        f"leak surface on Gemini's ?key= auth): {offenders}. Import "
        "strip_url_query_secrets from email_triage._secret_scrub."
    )


def test_ssot_holds_the_keys_and_func():
    tree = parse_module(SSOT)
    assert tree is not None and _url_secret_key_collection_lines(tree), (
        "the URL_QUERY_SECRET_KEYS collection vanished from the SSOT"
    )
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "strip_url_query_secrets" in names


# --------------------------------------------------------------------------
# Invariant 3 — the 3 ai_backends adapters are wired to the SSOT (regression
# guard: a wired module can't silently lose it).
# --------------------------------------------------------------------------
_WIRED = (
    "ai_backends/azure_openai.py",
    "ai_backends/gemini_adapter.py",
    "ai_backends/openai_direct.py",
)
_SSOT_REFERENCES = ("_secret_scrub",)


def test_backends_reference_the_ssot():
    missing = []
    for m in _WIRED:
        src = (SRC_ROOT / m).read_text(encoding="utf-8")
        if not any(ref in src for ref in _SSOT_REFERENCES):
            missing.append(m)
    assert not missing, (
        f"an ai_backends URL-secret-scrub adapter lost its _secret_scrub "
        f"wiring: {missing}. Every adapter that renders a URL into an "
        "exception message must import strip_url_query_secrets."
    )


# --------------------------------------------------------------------------
# Behavioural teeth — the SSOT actually redacts the shape.
# --------------------------------------------------------------------------
def test_ssot_redacts_gemini_shape():
    from email_triage._secret_scrub import strip_url_query_secrets as S
    out = S("https://generativelanguage.googleapis.com/v1beta/models/x:generateContent?key=SECRETPLAINTEXT")
    assert out is not None and "SECRETPLAINTEXT" not in out
    assert "key=REDACTED" in out


def test_ssot_redacts_azure_shape():
    from email_triage._secret_scrub import strip_url_query_secrets as S
    out = S("https://foo.openai.azure.com/openai/deployments/x/chat/completions?api-key=SECRET&api-version=2024-02")
    assert out is not None and "SECRET" not in out
    assert "api-key=REDACTED" in out
    # non-secret param is preserved
    assert "api-version=2024-02" in out


def test_ssot_handles_none_and_query_less():
    from email_triage._secret_scrub import strip_url_query_secrets as S
    assert S(None) is None
    assert S("") == ""
    # No query → passthrough.
    assert S("https://x/y/z") == "https://x/y/z"


def test_pin_has_teeth_key_collection(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "SENS = {'key', 'api-key', 'token'}\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _url_secret_key_collection_lines(tree)


def test_pin_has_teeth_def_shape(tmp_path):
    bad = tmp_path / "n.py"
    bad.write_text(
        "def _strip_sensitive_query_params(url): return url\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _forbidden_def_lines(tree)


def test_pin_ignores_small_overlap_set(tmp_path):
    # The SECRET_TOKEN_KEYS shape (2-overlap) — must NOT flag.
    ok = tmp_path / "p.py"
    ok.write_text(
        "TOKS = frozenset({'access_token', 'code'})\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _url_secret_key_collection_lines(tree)
