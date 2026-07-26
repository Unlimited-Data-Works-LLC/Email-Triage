"""Template-side companion to ``test_no_unguarded_secret_write.py``
(2026-06-08 OAuth-clobber incident).

The server SSOT stops a blank/autofilled value from clobbering a stored
secret; this guard stops the *field* from being autofillable in the first
place. The original bug shipped a bare ``<input type="password">`` with no
autofill defense (form-level ``autocomplete="off"`` is deliberately ignored
by password managers — MDN). This pin asserts every raw password input in
the template tree carries a field-level ``autocomplete=`` attribute (the
hardened credential inputs render via the ``m.secret_input`` macro, which
adds ``autocomplete="new-password"`` + readonly-until-focus, so they are not
raw ``type="password"`` at the call site and don't need a hand-rolled attr).

Count-agnostic (``pattern_count_agnostic_structural_drift_catch``): a NEW
bare password field anywhere under ``web/templates`` trips CI with its
file:line — route it through ``m.secret_input`` (preferred) or add a
field-level ``autocomplete=``.
"""

from __future__ import annotations

import re

from _pin_harness import TEMPLATES_ROOT, iter_template_files, relpath

_TEMPLATES = TEMPLATES_ROOT

# Match a whole <input ...> tag (attributes may span lines; an input tag has
# no '>' inside it). Then keep the password-typed ones.
_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_IS_PASSWORD = re.compile(r"""type\s*=\s*['"]password['"]""", re.IGNORECASE)
_HAS_AUTOCOMPLETE = re.compile(r"""autocomplete\s*=""", re.IGNORECASE)


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _bare_password_inputs() -> list[tuple[str, int]]:
    offenders: list[tuple[str, int]] = []
    for p in iter_template_files():
        text = p.read_text(encoding="utf-8")
        rel = relpath(p, base=TEMPLATES_ROOT)
        for m in _INPUT_TAG.finditer(text):
            tag = m.group(0)
            if not _IS_PASSWORD.search(tag):
                continue
            if not _HAS_AUTOCOMPLETE.search(tag):
                offenders.append((rel, _line_of(text, m.start())))
    return offenders


def test_no_bare_password_input_in_templates():
    """Every raw <input type="password"> carries a field-level autocomplete=
    attribute (or is rendered via m.secret_input). A bare password field is
    the 2026-06-08 autofill-clobber surface."""
    offenders = _bare_password_inputs()
    assert not offenders, (
        "Bare <input type=\"password\"> with no field-level autocomplete= "
        "(an autofill-clobber surface — form-level autocomplete=off is "
        "ignored by password managers):\n"
        + "\n".join(f"  {rel} (line {ln})" for rel, ln in offenders)
        + "\n\nFix: render it via {{ m.secret_input(name, has_stored, "
        "new_hint) }} (readonly-until-focus + autocomplete=new-password), or "
        "add a field-level autocomplete= attribute if it is genuinely not a "
        "stored-credential field."
    )


_CRED_MACRO_RE = re.compile(r"\bmacro\s+(\w*(?:secret|cred)\w*)\s*\(",
                            re.IGNORECASE)


def _credential_macros() -> dict[str, str]:
    """{macro_name: body} for every macro whose name marks it a credential
    input (contains 'secret' or 'cred')."""
    text = (_TEMPLATES / "_macros.html").read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for m in _CRED_MACRO_RE.finditer(text):
        start = m.start()
        out[m.group(1)] = text[start:text.index("endmacro", start)]
    return out


def test_every_credential_macro_is_hardened():
    """Count-agnostic (census N-66) — EVERY credential-input macro (name
    contains 'secret'/'cred') must keep the anti-autofill defenses, not just
    ``secret_input``. ``cred_text_input`` (the OAuth client-id field from the
    2026-06-08 clobber incident) was hardened but UNPINNED, so a
    defense-stripping refactor of it passed green. A NEW credential macro now
    inherits the requirement.
    """
    macros = _credential_macros()
    assert macros, "no credential macros found in _macros.html — scanner blind"
    assert "secret_input" in macros, "the known secret_input macro vanished"
    # The common anti-autofill needles (the autocomplete VALUE varies:
    # secret_input uses new-password, cred_text_input uses off — so assert the
    # attribute is present, not a specific value).
    needles = (
        "readonly",
        "removeAttribute('readonly')",
        "data-1p-ignore",
        'data-lpignore="true"',
    )
    offenders: list[str] = []
    for name, body in macros.items():
        for needle in needles:
            if needle not in body:
                offenders.append(f"{name}: missing {needle!r}")
        if "autocomplete=" not in body:
            offenders.append(f"{name}: missing autocomplete=")
    assert not offenders, (
        "a credential-input macro lost its anti-autofill defense (the "
        "2026-06-08 OAuth-clobber surface): " + "; ".join(offenders)
        + ". Every macro whose name contains 'secret'/'cred' must keep "
        "readonly-until-focus + an autocomplete= attr + data-*-ignore."
    )


def test_credential_macro_pin_has_teeth():
    """A credential macro missing a defense needle must be caught."""
    needles = ("readonly", "removeAttribute('readonly')",
               "data-1p-ignore", 'data-lpignore="true"')
    weak = "macro cred_weak(name)\n  <input type='text'>\nendmacro"
    assert not all(n in weak for n in needles)
