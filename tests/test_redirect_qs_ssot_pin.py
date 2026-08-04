"""Redirect query-string SSOT pin (divergence census run12 #5 — flash-redirect;
widened run17  to the SUCCESS family + the mid-message shape).

A handler signalling to the next page via a flash query param on a
``RedirectResponse`` must URL-ENCODE the value, or an exception/notice text with
``&`` / ``=`` / ``#`` / a space splits the redirect URL (and an unescaped ``<``
only survives by the target template's autoescape). Several sites hand-rolled the
value raw (``f"/x?err={save_error}"`` / ``f"/x?save_msg=Backend+{row['name']}+added."``)
— `web/routers/_redirect.py` (`err_qs`/`msg_qs`/`qs`) is the SSOT; `tls_csr._qstr`
is the pre-existing (URL-integrity-only) encoder.

Count-agnostic property (over every f-string in ``web/routers/``): a value
interpolated as (part of) a FLASH-FAMILY redirect query param — the ERROR family
(``err`` / ``flush_err`` / ``reset_err`` / …) AND the SUCCESS family (``save_msg``
``save_error`` ``saved`` ``reset_ok`` ``ok``) — must be a sanctioned ENCODER call
(or an ``int(...)`` / ``len(...)`` digit coercion). A new raw
``save_msg={raw_value}`` (or a mid-message ``…?err=… {raw} …``) turns this RED.

run17  widened the family from ERR-only to ERR+SUCCESS: a success-flash carries
a user-controlled value too (a backend ``name``, a reset ``namespace``, a cert
path), so the same split/truncate/redirect-injection risk applies. Two detectors,
both count-agnostic:

* ``_raw_param_interpolations`` — the value sits IMMEDIATELY after the
  ``?<family>=`` literal (``?save_msg={msg}``). ``_PARAM_TAIL`` defines the family.
* ``_raw_family_param_values`` — a param-context scanner that also catches the
  MID-MESSAGE shape (``?save_msg=Backend+{name}+added.`` / ``?err=…{crt_path} first.``),
  which the tail-anchored detector cannot see because the raw value is not glued to
  the ``=``. It tracks the open query-param key left-to-right (resetting at each
  ``&``/``#``) so a raw value under a NON-family key (``&id={account_id}``) is NOT
  a false positive.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

_ROUTERS_SUBDIR = "web/routers"
_SSOT_REL = "web/routers/_redirect.py"
# Sanctioned encoders: the _redirect SSOT funnels + the pre-existing _qstr
# (URL-integrity) + stdlib quote/quote_plus.
_ENCODERS = {"err_qs", "msg_qs", "qs", "_qstr", "quote", "quote_plus"}
# A value coerced to digits is URL-safe without an encoder.
_SAFE_CALLS = _ENCODERS | {"int", "len"}
# The SUCCESS flash params (run17 ). The ERROR family is matched by suffix
# (``…err`` — err / flush_err / reset_err) since those names self-describe; the
# success names do not share a suffix, so they are enumerated. ``save_error``
# ends in ``error`` (not ``err``) so it is listed explicitly, not suffix-matched.
_SUCCESS_PARAMS = {"save_msg", "save_error", "saved", "reset_ok", "ok"}
# A literal f-string segment ending in a FLASH redirect query-param assignment
# (``?err=`` / ``&flush_err=`` / ``?save_msg=`` / ``&reset_ok=`` / …) — the
# immediately-glued shape. Widened run17  from err-only to err+success.
_PARAM_TAIL = re.compile(
    r"[?&](?:[A-Za-z_]*err|save_msg|save_error|saved|reset_ok|ok)=$"
)
# Any query-param key assignment inside a constant segment — for the mid-message
# param-context scanner (NOT anchored to the end).
_KEY_LITERAL_RE = re.compile(r"[?&]([A-Za-z0-9_]+)=")


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _is_safe_value(fv_value: ast.AST) -> bool:
    """A FormattedValue's expression is URL-safe iff it is a sanctioned encoder
    call or an int/len digit coercion."""
    return isinstance(fv_value, ast.Call) and _call_name(fv_value) in _SAFE_CALLS


def _is_family_key(key: str) -> bool:
    """True if ``key`` is a flash-family redirect param (err-suffix OR a success
    name) — the keys whose interpolated VALUE must be encoded."""
    return key.endswith("err") or key in _SUCCESS_PARAMS


def _raw_param_interpolations(tree: ast.AST) -> list[str]:
    """``?<family>=`` literal IMMEDIATELY followed by a ``{value}`` that is NOT a
    sanctioned encoder/int call — the un-encoded glued-value shape."""
    out: list[str] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.JoinedStr):
            continue
        parts = n.values
        for i, part in enumerate(parts):
            if not (isinstance(part, ast.Constant) and isinstance(part.value, str)):
                continue
            if not _PARAM_TAIL.search(part.value):
                continue
            if i + 1 >= len(parts) or not isinstance(parts[i + 1], ast.FormattedValue):
                continue
            if _is_safe_value(parts[i + 1].value):
                continue  # encoded / digit-coerced — OK
            out.append(part.value.strip())
    return out


def _raw_family_param_values(tree: ast.AST) -> list[str]:
    """Param-context scan: a raw (non-encoder) value interpolated ANYWHERE inside
    a FLASH-FAMILY param's value — including the MID-MESSAGE shape
    (``?save_msg=Backend+{name}+added.``) the tail detector misses.

    Tracks the currently-open query-param key left-to-right: a constant segment's
    last ``[?&]key=`` opens that key; a ``&``/``#`` after it (or in a key-less
    segment) closes the value (so ``&id={account_id}`` after a family value is NOT
    flagged). A FormattedValue whose open key is a family key and whose expression
    is not encoder/int-safe is an offender."""
    out: list[str] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.JoinedStr):
            continue
        current_key: str | None = None
        for part in n.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                s = part.value
                matches = list(_KEY_LITERAL_RE.finditer(s))
                if matches:
                    last = matches[-1]
                    # a separator AFTER the last `key=` closes that value.
                    if any(c in s[last.end():] for c in "&#"):
                        current_key = None
                    else:
                        current_key = last.group(1)
                elif any(c in s for c in "&#"):
                    current_key = None  # value closed, no new key here
                # else: mid-value text (e.g. "Backend ") — key unchanged
            elif isinstance(part, ast.FormattedValue):
                if (current_key is not None and _is_family_key(current_key)
                        and not _is_safe_value(part.value)):
                    out.append(f"{current_key}={{...}}")
    return out


def _offenders_for_tree(tree: ast.AST) -> list[str]:
    """Union of both detectors' hits (deduped).

    SCOPE (honest caveat, DA run17 ): catches a flash-family value glued or
    mid-message under a LITERAL ``?key=`` / ``&key=`` in the f-string only. A
    family value assembled into a VARIABLE and interpolated as ``?{qs}`` (e.g.
    admin.py:837, auth_keys.py:1778) is a structural blind spot — those sites
    are protected by routing through ``err_qs``/``qs``/``urlencode``, NOT by this
    scanner. The full-word ``error=`` key (vs the ``*err`` suffix) is likewise
    not in the family. No live offender at HEAD; documented so a future
    variable-assembled raw flash param is a KNOWN gap, not a false "complete net"."""
    return sorted(set(_raw_param_interpolations(tree)) | set(_raw_family_param_values(tree)))


def test_no_raw_redirect_param_interpolation():
    offenders = []
    for p in iter_src_files(_ROUTERS_SUBDIR):
        rel = relpath(p)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        hits = _offenders_for_tree(tree)
        if hits:
            offenders.append(f"{rel}: {hits}")
    assert not offenders, (
        "Raw value interpolated into a flash redirect param (err/save_msg/saved/"
        "reset_ok/save_error/ok) — URL-injection / split / unencoded into the next "
        f"page: {offenders}. Wrap it in web.routers._redirect.err_qs(...) / "
        "msg_qs(...) / qs(...) (or the URL-integrity _qstr) so an exception/notice "
        "with `&`/`=`/`#`/space can't split the redirect URL."
    )


def test_redirect_ssot_exists():
    tree = parse_module(SRC_ROOT / "web" / "routers" / "_redirect.py")
    names = {n.name for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for fn in ("err_qs", "msg_qs", "qs"):
        assert fn in names, f"web/routers/_redirect.py lost its {fn!r} funnel"


def test_pin_has_teeth():
    # --- glued shape (tail detector) ---
    bad = 'x = f"/admin/security?err={save_error}"\n'
    assert _raw_param_interpolations(ast.parse(bad)), "missed a raw err= interpolation"
    bad_amp = 'x = f"/x?tab=1&err={e}"\n'
    assert _raw_param_interpolations(ast.parse(bad_amp))
    # SUCCESS family is now in scope (run17 ):
    bad_save = 'x = f"/x?save_msg={msg}"\n'
    assert _raw_param_interpolations(ast.parse(bad_save)), "missed a raw save_msg="
    bad_reset = 'x = f"/x?reset_ok={namespace}"\n'
    assert _raw_param_interpolations(ast.parse(bad_reset)), "missed a raw reset_ok="
    bad_serr = 'x = f"/x?save_error={e}"\n'
    assert _raw_param_interpolations(ast.parse(bad_serr)), "missed a raw save_error="
    ok = 'x = f"/admin/security?{err_qs(save_error)}"\n'   # whole param in encoder
    assert not _raw_param_interpolations(ast.parse(ok))
    ok_enc = 'x = f"/x?err={_qstr(e)}"\n'                   # encoder call → allowed
    assert not _raw_param_interpolations(ast.parse(ok_enc))
    ok_int = 'x = f"/x?flushed={int(deleted)}"\n'           # not family + int-safe
    assert not _raw_param_interpolations(ast.parse(ok_int))

    # --- mid-message shape (param-context scanner) ---
    mid_save = 'x = f"/config/ai-backends?save_msg=Backend+{name}+added."\n'
    assert _raw_family_param_values(ast.parse(mid_save)), "missed a mid-message save_msg"
    mid_err = (
        'x = f"/admin/acme-status?err=Cannot enable HTTPS. Place one at '
        '{crt_path} first."\n'
    )
    assert _raw_family_param_values(ast.parse(mid_err)), "missed a mid-message err"
    # An encoded mid value is fine.
    mid_ok = 'x = f"/config/ai-backends?save_msg=Backend+{quote(name)}+added."\n'
    assert not _raw_family_param_values(ast.parse(mid_ok))
    # The whole-param-in-encoder idiom is fine (no glued literal key).
    enc_ok = 'x = f"/config/ai-backends?{qs(save_msg=notice)}"\n'
    assert not _raw_family_param_values(ast.parse(enc_ok))
    assert not _raw_param_interpolations(ast.parse(enc_ok))
    # FALSE-POSITIVE GUARD: a raw value under a NON-family key AFTER a (safely
    # encoded) family value must NOT be flagged — the `&id={account_id}` case.
    fp = 'x = f"/x?err={err_qs(e)}&id={account_id}"\n'
    assert not _raw_family_param_values(ast.parse(fp)), "false-flagged a non-family value"
    # A pure navigation param (no family key) is never flagged.
    nav = 'x = f"/accounts?account_id={account_id}&tab={active_tab}"\n'
    assert not _raw_family_param_values(ast.parse(nav))
    assert not _raw_param_interpolations(ast.parse(nav))
