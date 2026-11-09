""" v0.2.0 — JS-side base64url SSOT pin (`window.ETBase64`).

Mirror-of-Python-#123: the Python side (`email_triage._base64url`) has
`tests/test_base64url_ssot_pin.py` (AST). The JS side ships the same
SSOT convergence pattern in `src/email_triage/web/static/base64url.js`
(the `window.ETBase64.*` namespace). This test is the JS-side structural
pin — regex over `.js` + `.html` under `src/email_triage/web/**`
banning independent implementations of the base64url encode/decode
class:

    function b64urlToBytes(s) { ... .replace(/-/g, "+")... atob(s) ... }
    function bytesToB64url(bytes) { ... btoa(s)... .replace(/=+$/, "") }

Prime Directive #1: SSOT ships its count-agnostic structural pin same-
commit. Prime Directive #6: no hand-rolled harness — this uses
:func:`_pin_harness.iter_files` for the JS walk +
:func:`_pin_harness.iter_template_files` for the HTML walk +
:func:`_pin_harness.relpath` for the canonical forward-slash path
(N-224 R22 meta-pin contract #5).

Allow-list: the SSOT file itself.

Grounding: 2026-07-11 census-live  tail. The Python SSOT
(`_base64url.py`) shipped in 1508d3d0; this JS pin lands with
the `web/static/base64url.js` extraction.  tail closed. First push
(`7ed370d7`) tripped the meta-pin harness by hand-rolling Path.rglob
+ path-separator normalisation; this revision routes both through
the harness SSOT (feedback_meta_pins_gate_new_pin_pushes).
"""
from __future__ import annotations

import re

from _pin_harness import (
    REPO_ROOT, SRC_ROOT, iter_files, iter_template_files, relpath,
)

_STATIC_ROOT = SRC_ROOT / "web" / "static"

_SSOT_HOME_JS = "base64url.js"

# URL-safe decode canary — `+ / URL-safe-normalise + atob` shape. Both
# replaces AND `atob(` must appear in the same file to filter out
# innocent uses of `.replace(/-/g, ...)` elsewhere.
_URL_SAFE_REPLACE_A = re.compile(r'\.replace\(/-/g,\s*"\+"\)')
_URL_SAFE_REPLACE_B = re.compile(r'\.replace\(/_/g,\s*"/"\)')
_ATOB_CALL = re.compile(r'\batob\(')

# URL-safe encode canary — `btoa(...)` chained with `+ / → -_`
# normalisation.
_BTOA_CALL = re.compile(r'\bbtoa\(')


def _iter_js_and_html_files():
    """Yield every `.js` file in ``web/static/**`` + every `.html` in
    ``web/templates/**``, sorted, both through the harness SSOT so
    the ``__pycache__`` skip + walker shape are one place. Skips
    the SSOT home itself."""
    for path in iter_files(_STATIC_ROOT, "*.js"):
        if path.name == _SSOT_HOME_JS:
            continue
        yield path
    yield from iter_template_files(pattern="*.html")


def test_no_hand_rolled_urlsafe_base64_decoder_outside_ssot():
    """ Arm A — URL-safe base64 decode shape only in the SSOT.

    Any `.js` / `.html` file under `src/email_triage/web/**` whose body
    contains BOTH the `-/+` and `_//` URL-safe replaces AND an `atob(`
    call is re-implementing `window.ETBase64.b64urlToBytes`. The only
    file allowed to do so is the SSOT itself.
    """
    offenders: list[str] = []
    for path in _iter_js_and_html_files():
        rel = relpath(path, REPO_ROOT)
        text = path.read_text(encoding="utf-8")
        if not _ATOB_CALL.search(text):
            continue
        if _URL_SAFE_REPLACE_A.search(text) and _URL_SAFE_REPLACE_B.search(text):
            offenders.append(rel)
    assert not offenders, (
        "#130 JS SSOT Arm A: a `.js` / `.html` file under "
        "`src/email_triage/web/**` contains a hand-rolled URL-safe base64 "
        "decoder shape (`.replace(/-/g, \"+\").replace(/_/g, \"/\")` + "
        "`atob(...)`). Route through the `window.ETBase64.b64urlToBytes` "
        "SSOT (loaded unconditionally from `base.html` at "
        "`/static/base64url.js`). If a new site needs the shape, alias "
        "it: `const b64urlToBytes = window.ETBase64.b64urlToBytes;` — "
        "same as `webauthn.js` / `login.html` / `login_dev_keypair.html` "
        "post-#130.\n\n" + "\n".join(offenders)
    )


def test_no_hand_rolled_urlsafe_base64_encoder_outside_ssot():
    """ Arm B — URL-safe base64 encode shape only in the SSOT.

    Any `.js` / `.html` file under `src/email_triage/web/**` whose body
    contains BOTH the `+→-` and `/→_` URL-safe replaces on a `btoa(...)`
    result is re-implementing `window.ETBase64.bytesToB64url`. Only the
    SSOT is allowed.
    """
    _plus_re = re.compile(r'\.replace\(/\\?\+/g,\s*"-"\)')
    _slash_re = re.compile(r'\.replace\(/\//g,\s*"_"\)')
    offenders: list[str] = []
    for path in _iter_js_and_html_files():
        rel = relpath(path, REPO_ROOT)
        text = path.read_text(encoding="utf-8")
        if not _BTOA_CALL.search(text):
            continue
        if _plus_re.search(text) and _slash_re.search(text):
            offenders.append(rel)
    assert not offenders, (
        "#130 JS SSOT Arm B: a `.js` / `.html` file under "
        "`src/email_triage/web/**` contains a hand-rolled URL-safe base64 "
        "encoder shape (`btoa(...).replace(/\\+/g, \"-\").replace(/\\//g, "
        "\"_\")`). Route through the `window.ETBase64.bytesToB64url` SSOT.\n\n"
        + "\n".join(offenders)
    )
