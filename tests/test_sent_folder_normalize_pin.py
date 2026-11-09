"""run18  — sent-folder-override normalization SSOT pin.

WHY: ``providers/sent_folder.py:normalize_sent_folder_override`` is the SSOT for
coercing a stored ``sent_folder_override`` value into a clean ``list[str]`` —
strip each entry, drop blanks/None, and tolerate BOTH the legacy scalar-string
shape (``"Sent"``) and the post-v19 list shape (``["Sent", "Sent Items"]``).

Three constructors that take a ``sent_folders`` parameter —
``SentMailIndex`` / ``SentMailCaptureLoop`` / ``HIPAASentCounter`` (all in
``actions/``) — each hand-rolled the SAME inline strip loop instead of calling
the SSOT (census run18 ). NO LIVE DRIFT at HEAD: every caller that passes a
non-empty ``sent_folders`` (``web/background_sweepers.py``,
``web/triage_runner_bulk.py``, ``web/routers/ui/profile.py``) pre-normalizes via
the SSOT before constructing — so the inline copies received already-clean
lists. But the inline loop is strictly NARROWER than the SSOT: handed a bare
scalar string it iterates the string into its CHARACTERS (``"Sent"`` →
``("S", "e", "n", "t")``), whereas the SSOT returns ``["Sent"]``. A future
caller that constructs one of these directly with a raw config value — without
the pre-normalize hop — would silently fan the scan across phantom
single-character "folders".

PD#5 (collapse duplicated predicate/parse copies into one funnel re-exported by
callers — two mirrored copies WILL drift) + PD#2 (make the pin interprocedural
where the value hops through a helper). This pin asserts the structural PROPERTY,
count-agnostic (``pattern_count_agnostic_structural_drift_catch``): EVERY src
function whose signature carries a ``sent_folders`` parameter routes that param
through ``normalize_sent_folder_override`` in its body — never ``len(X) == 3``.
A fourth such constructor added tomorrow is covered automatically.

SCOPE CAVEAT (honest residual): the detector requires the SSOT CALL to appear in
the same function body that declares the ``sent_folders`` param — it does not
prove the call's ARGUMENT is that exact param (a constructor could call the SSOT
on an unrelated value and still inline-strip the param). That weaker shape is not
present at HEAD and would be a deliberate evasion; the convention to keep is:
the constructor normalizes ITS ``sent_folders`` param through the SSOT.
"""

from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, relpath, walk_src

# The SSOT funnel every ``sent_folders``-param constructor must route through.
_SSOT_FUNC = "normalize_sent_folder_override"
_SENT_FOLDERS_PARAM = "sent_folders"

# Function-keyed allow-list (``(relpath, funcname)``) — a site that legitimately
# takes a ``sent_folders`` param WITHOUT normalizing (e.g. it forwards an
# already-normalized value to a callee that normalizes). EMPTY at HEAD: all three
# constructors route through the SSOT. Keyed on (relpath, enclosing_fn) — never a
# bare lineno (R38), so an unrelated edit above the constructor doesn't break it.
_ALLOW: frozenset[tuple[str, str]] = frozenset()


def _fn_has_sent_folders_param(fn: ast.AST) -> bool:
    """True when ``fn`` declares a parameter literally named ``sent_folders``
    (positional, positional-only, keyword-only, ``*args`` / ``**kwargs``)."""
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    a = fn.args
    allargs = (
        list(getattr(a, "posonlyargs", []))
        + list(a.args)
        + list(a.kwonlyargs)
    )
    if a.vararg is not None:
        allargs.append(a.vararg)
    if a.kwarg is not None:
        allargs.append(a.kwarg)
    return any(arg.arg == _SENT_FOLDERS_PARAM for arg in allargs)


def _body_calls_ssot(fn: ast.AST) -> bool:
    """True when ``fn``'s body contains a call to :data:`_SSOT_FUNC` — matched as
    a bare ``normalize_sent_folder_override(...)`` (``ast.Name``) OR a dotted
    ``mod.normalize_sent_folder_override(...)`` (``ast.Attribute``)."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = (
            f.id if isinstance(f, ast.Name)
            else f.attr if isinstance(f, ast.Attribute) else None
        )
        if name == _SSOT_FUNC:
            return True
    return False


def _sent_folders_param_offenders() -> list[tuple[str, str]]:
    """``(relpath, funcname)`` for every src function that takes a
    ``sent_folders`` param but does NOT route it through the SSOT."""
    offenders: list[tuple[str, str]] = []
    for _path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if not _fn_has_sent_folders_param(node):
                continue
            if _body_calls_ssot(node):
                continue
            key = (rel, node.name)
            if key in _ALLOW:
                continue
            offenders.append(key)
    return offenders


def test_every_sent_folders_param_routes_through_the_ssot():
    """Count-agnostic interprocedural pin: EVERY src function carrying a
    ``sent_folders`` parameter coerces it through ``normalize_sent_folder_override``
    (PD#5 SSOT + PD#2 interprocedural). A new constructor that hand-rolls the
    inline strip — narrower than the SSOT (it shreds a bare str into characters) —
    fails here."""
    offenders = _sent_folders_param_offenders()
    assert offenders == [], (
        "function(s) take a `sent_folders` parameter but do NOT route it through "
        f"the normalize_sent_folder_override SSOT: {sorted(offenders)}. Coerce via "
        "`from email_triage.providers.sent_folder import normalize_sent_folder_override` "
        "so the strip/drop-blank/legacy-scalar contract lives in ONE place "
        "(PD#5) — an inline strip iterates a bare scalar string into its "
        "characters."
    )


# --- Teeth ------------------------------------------------------------------

def _detect(src: str) -> list[str]:
    """Run the detector over a planted source STRING; return offender funcnames."""
    tree = ast.parse(src)
    out: list[str] = []
    for node in ast.walk(tree):
        if _fn_has_sent_folders_param(node) and not _body_calls_ssot(node):
            out.append(node.name)
    return out


def test_pin_has_teeth():
    # BAD — a constructor that inline-strips a sent_folders param (no SSOT call).
    bad = (
        "class C:\n"
        "    def __init__(self, sent_folders=None):\n"
        "        cleaned = []\n"
        "        if sent_folders:\n"
        "            for f in sent_folders:\n"
        "                if f.strip():\n"
        "                    cleaned.append(f.strip())\n"
        "        self._sf = tuple(cleaned)\n"
    )
    assert _detect(bad) == ["__init__"]

    # GOOD — routes the param through the SSOT (bare-name call shape).
    good_bare = (
        "class C:\n"
        "    def __init__(self, sent_folders=None):\n"
        "        self._sf = tuple(normalize_sent_folder_override(sent_folders))\n"
    )
    assert _detect(good_bare) == []

    # GOOD — dotted call shape (mod.normalize_sent_folder_override(...)).
    good_dotted = (
        "class C:\n"
        "    def __init__(self, sent_folders=None):\n"
        "        self._sf = tuple(sf.normalize_sent_folder_override(sent_folders))\n"
    )
    assert _detect(good_dotted) == []

    # NOT APPLICABLE — a function without a sent_folders param is never flagged.
    unrelated = (
        "def f(folders=None):\n"
        "    return [x.strip() for x in (folders or [])]\n"
    )
    assert _detect(unrelated) == []


def test_allow_list_keys_are_function_keyed():
    """Allow-list entries are ``(relpath, funcname)`` 2-tuples — never a bare
    lineno (R38: a line key breaks fail-closed on an unrelated edit)."""
    for entry in _ALLOW:
        assert isinstance(entry, tuple) and len(entry) == 2, entry
        assert all(isinstance(part, str) for part in entry), entry


def test_the_three_known_constructors_are_covered():
    """Anchor: the three run18  constructors carry a ``sent_folders`` param
    AND route through the SSOT at HEAD (a clean negative — proves the pin sees
    real sites, not a vacuous pass)."""
    seen: set[tuple[str, str]] = set()
    for _path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if _fn_has_sent_folders_param(node):
                seen.add((rel, node.name))
    assert ("actions/sent_mail_index.py", "__init__") in seen
    assert ("actions/sent_mail_capture.py", "__init__") in seen
    assert ("actions/hipaa_sent_counter.py", "__init__") in seen
    # And none of them is an offender.
    assert _sent_folders_param_offenders() == []


# ``enclosing_fn`` / ``relpath`` imported for parity with the harness API the
# other structural pins use; ``walk_src`` is the source of truth here.
_ = (enclosing_fn, relpath)
