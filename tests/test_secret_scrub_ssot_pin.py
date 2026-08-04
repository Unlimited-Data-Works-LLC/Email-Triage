"""Secret-scrub SSOT pin (divergence census 2026-06-09, finding #6).

Provider/client exception text can carry a token-shaped secret; when persisted to
an error column (``triage_jobs.error_text``, ``office365_subscriptions.error_last``,
embedding ``last_error_msg``) or surfaced in the admin UI it leaks. Before this
fix the redaction key list was **byte-duplicated** (``web/db.py`` watcher-retry +
``triage_logging``) and several writers scrubbed nothing (``finish_triage_job``,
``record_o365_subscription_error``, the embedding ``_scrub_error`` which only
TRIMMED). All converge on the leaf SSOT ``email_triage._secret_scrub``.

Invariant 1 (count-agnostic): the token-key COLLECTION lives only in the SSOT — a
re-inlined list/tuple/set of two-or-more known keys elsewhere is the drift this
guards (mirrors the auth_stale needle pin).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath as _relpath, walk_src

SSOT = SRC_ROOT / "_secret_scrub.py"

from email_triage._secret_scrub import SECRET_TOKEN_KEYS  # noqa: E402


def _iter_src():
    for p, _rel, tree in walk_src():
        yield p, tree


# Threshold for "this is a re-inlined SECRET_TOKEN_KEYS copy". The real scrub
# list is 13 distinctive keys; a re-inline copies most of them. Set to 3 so the
# pin does NOT false-positive on the URL-query-param scrub set
# ({"api-key","key","token","access_token","code"}) that lives in the SAME
# module (URL_QUERY_SECRET_KEYS) — a DIFFERENT redaction concern that shares
# only 2 keys (access_token, code) with this set. That URL-param scrub is
# now converged via ``strip_url_query_secrets`` here (census run23 #3, HIGH
# sev — was previously forked across 3 ai_backends adapters) and is guarded
# by its sibling pin ``test_url_query_secret_scrub_ssot_pin.py``.
_REINLINE_THRESHOLD = 3


def _token_key_collection_lines(tree: ast.AST) -> list[int]:
    """List/tuple/set literals holding >= _REINLINE_THRESHOLD SECRET_TOKEN_KEYS."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            cnt = sum(
                1 for e in n.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
                and e.value in SECRET_TOKEN_KEYS
            )
            if cnt >= _REINLINE_THRESHOLD:
                out.append(n.lineno)
    return out


def test_token_key_list_only_in_ssot():
    offenders = []
    for p, tree in _iter_src():
        if p == SSOT:
            continue
        locs = _token_key_collection_lines(tree)
        if locs:
            offenders.append(f"{_relpath(p)}:{locs}")
    assert not offenders, (
        "a secret-token-key collection was re-inlined outside _secret_scrub.py "
        f"(census #6 byte-dup): {offenders}. Import SECRET_TOKEN_KEYS / "
        "scrub_secrets_from_text from email_triage._secret_scrub instead of "
        "copying the key list."
    )


def test_ssot_holds_the_keys_and_func():
    tree = parse_module(SSOT)
    assert tree is not None and _token_key_collection_lines(tree), (
        "the key set vanished from the SSOT"
    )
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "scrub_secrets_from_text" in names


# --------------------------------------------------------------------------
# Invariant 2 — the persisted-error-text writers + the log redactor are wired
# to the SSOT (regression guard: a wired module can't silently lose it).
# --------------------------------------------------------------------------
_WIRED = (
    "web/db.py",                # finish_triage_job, record_o365_subscription_error, watcher-retry
    "embedding_bits/__init__.py",  # _scrub_error -> scrub_error_for_persist (census run13 #2)
    "triage_logging.py",        # _TOKEN_KEYS log redaction
    "web/acme_job_state.py",    # acme_jobs.last_error (TSIG/EAB creds, admin-UI rendered)
)
# Funnels that satisfy the wiring: the secret-scrub SSOT directly, OR the
# combined persisted-error funnel ``scrub_error_for_persist`` (census run13 #2),
# which composes both redact_exc (PHI) AND scrub_secrets_from_text (secret) —
# a module routed through it is transitively secret-scrubbed.
_SSOT_REFERENCES = ("_secret_scrub", "scrub_error_for_persist")


def test_writers_reference_the_ssot():
    missing = []
    for m in _WIRED:
        src = (SRC_ROOT / m).read_text(encoding="utf-8")
        if not any(ref in src for ref in _SSOT_REFERENCES):
            missing.append(m)
    assert not missing, (
        f"a persisted-error-text / log-redaction module lost its secret-scrub "
        f"wiring (neither _secret_scrub nor scrub_error_for_persist): {missing}."
    )


# --------------------------------------------------------------------------
# Behavioural teeth.
# --------------------------------------------------------------------------
def test_scrub_redacts_token_shapes():
    from email_triage._secret_scrub import scrub_secrets_from_text as S
    # dict-repr / JSON
    assert "sk-secret" not in S('OAuthError: {"access_token": "sk-secret"}')
    # kwargs quoted
    assert "abc123" not in S("refresh_token='abc123' failed")
    # bareword
    assert "deadbeef" not in S("client_secret=deadbeef&grant_type=x")
    # ACME TSIG/EAB bare-secret shape (the acme_jobs.last_error leak surface)
    assert "aGVsbG8=" not in S("TSIG update refused: secret='aGVsbG8='")
    # non-secret text is preserved
    out = S("ConnectionError: timed out after 30s")
    assert "timed out" in out


def test_scrub_truncates_and_handles_none():
    from email_triage._secret_scrub import scrub_secrets_from_text as S
    assert S(None) is None
    assert S("") is None
    big = S("x" * 9000)
    assert big is not None and len(big) <= 500


def test_pin_has_teeth(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "KEYS = ('access_token', 'refresh_token', 'client_secret')\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _token_key_collection_lines(tree)


def test_pin_ignores_single_key(tmp_path):
    ok = tmp_path / "p.py"
    ok.write_text(
        "if k == 'password':\n    redact()\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _token_key_collection_lines(tree)
