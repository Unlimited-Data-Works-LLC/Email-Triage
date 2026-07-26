"""Meta-pin: the structural-drift pins use the shared harness (R5b enforcement).

R5b ("the pins themselves obey the SSOT rule — converge them onto one shared
harness") shipped ``tests/_pin_harness.py`` (the one home for the
``src/email_triage`` walk + repo-relative ``relpath`` + ``parse_module`` +
line-stable ``enclosing_fn``). This meta-pin is its *Enforce* half: a test that
hand-rolls a ``*.py`` source walk MUST route that walk through a harness walker,
so a NEW count-agnostic pin can't re-introduce the boilerplate drift (the
off-by-one ``parents[1]`` vs ``parents[2]`` SRC root, the three divergent relpath
bases, the basename-vs-relpath allow-list bug R38) that motivated the harness.
"Census the censusers" (R5c) seeds the divergence census with this same class so
a true-up re-measures it.

INVARIANT: every ``tests/**/*.py`` that hand-rolls a source-/template-tree walk
— ``.rglob``/``.glob`` with a ``*.py``/``*.html`` wildcard, ``os.walk``, an
``iterdir`` + source-suffix shape, OR a bare catch-all glob (``rglob("*")``)
selecting source files in the body / off a hand-rolled repo-root (see
``_walks_py_sources``) — either routes that walk through a harness walker
(``iter_files``/``iter_src_files``/``iter_template_files``/``walk_src`` — so NO
raw ``rglob``/``glob``/``os.walk``/``iterdir`` source-walk remains in the file
body) or is a justified allow-list entry. **(run18: the exemption is AST-aware,
NOT a substring match — a RAW source-walk is flagged EVEN WHEN the file imports
``_pin_harness`` for something else, e.g. a constant. The harness walkers are
function CALLS that ``_walks_py_sources`` does not detect as raw walks, so a file
routing every walk through them trips the detector zero times and is exempt by
construction; importing the harness no longer exempts a raw walk.)** The
allow-list is keyed by BASENAME here (these live ONLY in tests/, a flat-ish tree;
a same-named collision across tests/ subdirs is itself a smell) with a one-line
reason.
"""

from __future__ import annotations

import ast
import pathlib
import re

_TESTS_ROOT = pathlib.Path(__file__).resolve().parent
_HARNESS = "_pin_harness"

# Test files that call rglob("*.py") but legitimately do NOT use the src-rooted
# harness — each with a source-verified reason. Keep this SHORT; a new entry is
# a conscious decision that a new walker should NOT adopt the harness.
_ALLOW = {
    # Walks the TESTS tree (tests_root.rglob), not src/email_triage — it audits
    # the test suite's own setup_logging(LoggingConfig(hipaa=...)) call sites,
    # so the src-rooted harness (SRC_ROOT/iter_src_files) does not apply.
    "test_hipaa_mode_contamination_invariant.py": "walks the tests/ tree, not src",
    # The harness itself defines iter_src_files (which calls rglob).
    "_pin_harness.py": "the harness module itself",
    # This meta-pin (string-matches rglob in its own teeth/scan — not a walker).
    "test_pin_harness_adoption.py": "the meta-pin itself",
    # Behavioural autochain test, NOT a structural-drift pin: its embedded
    # wizard-audience grep globs a SINGLE subdir (templates/account_wizard/*.html)
    # for forbidden tokens, not the src-tree structural-pin walk the harness
    # serves. (R5c-surfaced by the *.html widening, 2026-06-21.)
    "test_account_wizard_autochain.py": "behavioural test; single-subdir audience grep, not a pin",
    # 2026-07-02 (run22 census discovery): both walk `scripts/leira_*.py`, NOT
    # `src/email_triage`. The src-rooted harness does not apply — these audit
    # the llm-host offload stack's Consumer scripts (a separate subtree with its
    # own conventions per pattern_leira_offload_stack.md).
    "test_leira_consumers_scaffold.py": "walks scripts/leira_*.py, not src",
    "test_leira_no_hardcode_pin.py": "walks scripts/leira_*.py, not src",
    # Drive-7 (2026-07-17): walks tests/e2e/walk/*.py (Playwright walk suite),
    # not src/email_triage — enforces the Drive-7 defensive-xfail SSOT
    # (goto_or_fail helper) across the walk tree. The src-rooted harness
    # does not apply; the walker itself routes reads through
    # `_pin_harness.parse_module(p)` per the R33 V3 contract.
    "test_walk_defensive_xfail_ssot_pin.py": "walks tests/e2e/walk/, not src",
    # N-382 R32 (2026-07-09): `test_no_cross_loop_audit_drain_pin.py` +
    # `test_n314_golden_hash_gitattributes_meta_pin.py` no longer need an
    # allow-list entry — both migrated their tests/-tree walk onto the
    # harness's `iter_files(root, pattern)` SSOT (which is the correct
    # non-src-tree walker, exactly the R5c convergence pattern). Removed by
    # the stale-guard test the allow-list carries — no free-floating
    # exemptions after they stopped being needed.
}


def _walks_py_sources(text: str) -> bool:
    """True if the file hand-rolls a SOURCE-/template-tree walk by ANY spelling —
    the shape that must route through ``_pin_harness`` instead of re-rolling the
    ``SRC_ROOT`` + ``rglob`` + ``relative_to`` boilerplate. Count-agnostic: a
    PROPERTY of the AST, never a count. Recognised shapes:

    * ``os.walk(...)`` — directory-TREE walk (receiver must be the ``os`` module;
      bare ``.walk`` would match the ubiquitous ``ast.walk``).
    * ``rglob``/``glob``/``iglob`` with a wildcard ``*.py``/``*.html`` pattern
      (``glob.glob("*.py")`` matches the same ``glob`` attr form as ``Path.glob``).
      The ``*.html`` case (R5c widening, 2026-06-21) catches the TEMPLATE-tree pins
      that were re-rolling their own root + ``rglob`` + relpath — they now route
      through ``iter_template_files`` / ``TEMPLATES_ROOT`` / ``relpath(base=…)``.
    * ``Path.iterdir()`` PAIRED WITH a ``.py``/``.html`` SUFFIX LITERAL
      (``p.suffix == ".py"`` / ``p.name.endswith(".html")``) — the iterdir analogue
      of the glob ``*.py`` wildcard. A bare single-dir ``.iterdir()`` with no
      source-suffix literal is NOT a walk (flagging it would manufacture
      false-positives — the reason the iterdir branch was once omitted entirely).

    * (run17 ) a BARE CATCH-ALL glob — ``rglob``/``glob``/``iglob`` whose
      pattern basename is all-wildcard (``"*"`` / ``"**"`` / ``"**/*"`` /
      ``"*.*"``, i.e. NO concrete extension) — PAIRED WITH a SOURCE selector:
      either an in-body suffix filter (a ``.suffix`` access or an
      ``.endswith``/``.startswith`` call — the body-side analogue of the glob
      extension) OR a hand-rolled repo-root climb (``Path(__file__) … parents[N]``
      / ``.parent.parent`` — the 2nd-spelling evasion of the ``_HANDROLLED_SRC_ROOT``
      regex, which only catches the ``/"src"/"email_triage"`` SEGMENT spelling and
      is blind to a single-string ``"src/email_triage"`` join split across lines).

      This catch-all branch closes the gap the suffix-PATTERN branch missed: a walk
      that pulls EVERY file (templates + ``.py`` + docstrings) under the source
      root and selects type in the body. The named weak site was
      ``test_privacy_invariants_no_customer_names`` — a PHI/customer-name LEAK scan
      that rooted at ``src/email_triage`` via ``base.rglob("*")`` with a
      ``.suffix`` binary-denylist and a hand-rolled ``parents[1]`` root, INVISIBLE
      to every prior branch (so it could silently drift its scoping with nothing
      to catch it). The suffix-filter-OR-repo-root-climb pairing is what
      distinguishes a SOURCE-tree walk from a bare ``tmp_path.rglob("*")`` listing
      (which has NEITHER and is deliberately NOT flagged).

    RESIDUAL (narrowed 2026-06-21; iterdir folded 2026-06-27; catch-all +
    repo-root-climb folded run17 ; substring→AST exemption folded run18): the
    remaining slips are ``Path.walk`` (a Path-var receiver, indistinguishable from
    any other ``.walk()`` without types — matching bare ``.walk`` would flag the
    ubiquitous ``ast.walk``); a bare catch-all glob with NEITHER a suffix
    selector NOR a repo-root climb (an intentional prune to avoid the
    tmp-dir-listing false positive); and a VARIABLE-pattern glob
    (``pat = "*.py"; root.rglob(pat)``) — the rglob/glob branch requires an
    ``ast.Constant`` pattern arg, so a name-bound pattern is undetected (run18 DA
    nit; theoretical — the only 2 non-literal-pattern globs in ``tests/`` are both
    in allow-listed files: the harness's own ``iter_files`` + this meta-pin).

    HISTORY — the substring-exemption blind spot (DOWNGRADED + CLOSED run18): the
    adoption test (``test_every_py_source_walker_uses_the_harness``) once exempted
    any file containing the literal substring ``_pin_harness`` (``_HARNESS not in
    text``), so a file that imported the harness for ONE thing (e.g. a constant)
    yet ALSO hand-rolled a SEPARATE raw ``rglob``/``glob`` src-walk was INVISIBLE
    to the meta-pin by construction. run17  converged the one FRAGILE
    (hand-rolled-root) instance (``test_web/test_async_db_safety.py``'s
    ``_build_module_index`` walk) and its docstring OVER-CLAIMED "NO live debt
    remains" — that was wrong: two BENIGN harness-rooted substring-exempt walkers
    still remained at HEAD (``test_account_hipaa_scope_pin.py``'s jobs/ ``rglob``
    rooted on the harness ``SRC_ROOT``; ``test_ssot_registry_bijection_pin.py``'s
    tests-tree ``rglob`` off the harness ``REPO_ROOT`` — both benign because they
    root on a harness constant, so neither has the off-by-one fragility the harness
    exists to kill; LOW, a latent meta-pin gap + a consistency nit, not "live
    debt"). The accurate framing: the one FRAGILE instance was converged in run17
    ; the benign harness-rooted substring-exempt walkers remained until the
    substring→AST exemption upgrade (run18) closed the meta-pin blind spot — the
    adoption test now flags a RAW source-walk regardless of the import, and both
    remaining walkers were ROUTED through ``iter_files``/``iter_src_files``."""
    try:
        tree = ast.parse(text)
    except SyntaxError:  # pragma: no cover
        return False
    saw_iterdir = False
    saw_source_suffix = False  # a `.py`/`.html` suffix LITERAL — the iterdir
    # source-walk signal (`.suffix == ".py"` / `.endswith(".html")`), the
    # analogue of the glob `*.py` wildcard. Distinguishes an iterdir SOURCE walk
    # from a bare single-dir `.iterdir()` listing (which has no such filter).
    saw_catchall_glob = False  # run17 : a bare wildcard glob (`*`/`**`/`*.*`,
    # no concrete extension) — pulls EVERY file, selects type in the body.
    saw_suffix_filter = False  # run17 : an in-body file-type SELECTOR — a
    # `.suffix` access or a `.endswith`/`.startswith` call. (Common across tests,
    # so it only counts when PAIRED with a catch-all glob — which is rare.)
    saw_dunder_file = False    # run17 : `__file__` is referenced...
    saw_root_climb = False     # ...and climbed via `.parents[N]` / `.parent.parent`
    # — together a hand-rolled repo-root (the 2nd-spelling evasion of SRC_ROOT).
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in (".py", ".pyi", ".html", ".htm")
        ):
            saw_source_suffix = True
        # In-body suffix SELECTOR (`p.suffix`) — the catch-all-glob disambiguator.
        if isinstance(node, ast.Attribute) and node.attr == "suffix":
            saw_suffix_filter = True
        if isinstance(node, ast.Name) and node.id == "__file__":
            saw_dunder_file = True
        # `.parents[N]` subscript — a hand-rolled path climb.
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "parents"
        ):
            saw_root_climb = True
        # `.parent.parent` (2+) chain — the other hand-rolled climb spelling.
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "parent"
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "parent"
        ):
            saw_root_climb = True
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # `.endswith`/`.startswith(...)` — the other in-body suffix-SELECTOR shape.
        if isinstance(func, ast.Attribute) and func.attr in ("endswith", "startswith"):
            saw_suffix_filter = True
        if not isinstance(func, ast.Attribute):
            continue
        # os.walk(...) — directory-TREE walk, no pattern arg. Receiver must be
        # the `os` module: `func.attr == "walk"` alone would match the ubiquitous
        # `ast.walk(tree)` (receiver `ast`) and flag nearly every pin. (Path.walk,
        # a Path-var receiver, can't be told from other `.walk()` methods without
        # types — left to the census backstop per the residual note above.)
        if (
            func.attr == "walk"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            return True
        # Path.rglob / Path.glob / glob.glob / glob.iglob with a STRING wildcard.
        if (
            func.attr in ("rglob", "glob", "iglob")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and "*" in node.args[0].value
        ):
            pat = node.args[0].value
            if pat.endswith((".py", ".html")):
                return True
            # run17 : a BARE catch-all (basename all-wildcard, no concrete
            # extension). `*.py`/`*.html` returned above; `*.tmp`/`*.db` keep a
            # concrete extension and are NOT catch-all. Disambiguated post-loop.
            if pat.rsplit("/", 1)[-1] in ("*", "**", "*.*"):
                saw_catchall_glob = True
        # Path.iterdir() — a source-tree walk ONLY when paired with a
        # `.py`/`.html` suffix LITERAL in the same file (see saw_source_suffix).
        if func.attr == "iterdir":
            saw_iterdir = True
    if saw_iterdir and saw_source_suffix:
        return True
    # run17 : a bare catch-all glob is a SOURCE walk when the body selects file
    # type (suffix filter / `.py`/`.html` literal) OR the root is a hand-rolled
    # repo-root climb — both signal "walk the source tree", vs a neither-signal
    # bare `tmp_path.rglob("*")` directory listing (deliberately left un-flagged).
    if saw_catchall_glob and (
        saw_suffix_filter or saw_source_suffix or (saw_dunder_file and saw_root_climb)
    ):
        return True
    return False


def test_every_py_source_walker_uses_the_harness():
    offenders = []
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        name = path.name
        if name in _ALLOW:
            continue
        text = path.read_text(encoding="utf-8")
        # run18: AST-aware exemption — flag ANY raw source-walk (`_walks_py_sources`
        # detects only RAW rglob/glob/os.walk/iterdir, NEVER the harness walker
        # CALLS). Dropping the old ``and _HARNESS not in text`` substring escape is
        # the whole fix: a file that imports the harness for a constant yet ALSO
        # hand-rolls a raw src-walk is now correctly an offender (it was invisible
        # before — see the _walks_py_sources HISTORY note). Exemption is _ALLOW only.
        if _walks_py_sources(text):
            offenders.append(str(path.relative_to(_TESTS_ROOT)).replace("\\", "/"))
    assert not offenders, (
        "A test hand-rolls a `*.py` source walk (rglob/glob wildcard) without "
        "the shared pin harness (R5b):\n  " + "\n  ".join(offenders)
        + "\nRoute the WALK through tests/_pin_harness.py (iter_files / "
        "iter_src_files / iter_template_files / walk_src) instead of re-rolling the "
        "SRC_ROOT + rglob + relative_to boilerplate — that boilerplate has "
        "drifted before (R38). Importing the harness for a CONSTANT does NOT "
        "exempt a raw walk (run18 — the exemption is AST-aware, not a substring "
        "match): the WALK itself must route through a harness walker. If this "
        "walker legitimately does NOT scan src/email_triage, add it to _ALLOW "
        "with a one-line reason."
    )


def test_harness_exposes_its_contract():
    """The harness API the pins depend on must stay present — removing
    ``iter_src_files`` would silently break ~40 pins at import time."""
    import _pin_harness as h

    for attr in (
        "SRC_ROOT", "REPO_ROOT", "TEMPLATES_ROOT", "iter_files", "iter_src_files",
        "iter_template_files", "relpath", "parse_module", "parse_source",
        "annotate_parents", "enclosing_fn", "innermost_fn_at_lineno", "walk_src",
        "assert_pin_has_teeth",
    ):
        assert hasattr(h, attr), f"_pin_harness lost its {attr!r} contract member"
    assert h.SRC_ROOT.is_dir() and h.SRC_ROOT.name == "email_triage"
    assert h.REPO_ROOT.is_dir() and (h.REPO_ROOT / "pyproject.toml").is_file()


# census run15 #3 — a hand-rolled SRC_ROOT spelling: a Path(__file__)-rooted climb
# (parents[N] / parent.parent) ending in "src"/"email_triage". This is the EXACT
# off-by-one the harness exists to kill — a file MOVE shifts the climb depth, so a
# src-walk pin then resolves the WRONG dir and passes VACUOUSLY (0 files = green).
# Every such root must come from _pin_harness.SRC_ROOT (or REPO_ROOT for a repo-level
# root). One-line text scan (the harness itself is the sole sanctioned definition).
#
# SCOPE NOTE (verify-don't-accept, /goal Phase 1, 2026-06-21): the run15 #3 plan
# also floated catching ``inspect.getsource(mod)`` / ``Path(mod.__file__).read_text()``
# as "escape idioms" (test_migrations_checksum_pin / test_redact_exc_n42 use them).
# They are deliberately NOT flagged: both RESOLVE THE TARGET DYNAMICALLY from the
# imported module object, so a file MOVE does NOT break them (the import resolves the
# new location; ``__file__`` / ``getsource`` follow it) — they have none of the
# parents[N] off-by-one fragility this regex guards, and getsource is load-bearing
# for the checksum pin. Flagging them would manufacture false-positives for zero real
# fragility. The genuinely-fragile idiom is the hardcoded ROOT (above) + a literal
# "src/email_triage/…" PATH string (swept: zero such pins at HEAD). iterdir/Path.walk:
# zero real source-walkers at HEAD (only this file's own docstring + email msg.walk()).
_HANDROLLED_SRC_ROOT = re.compile(
    r'Path\(__file__\)[^\n]*?(parents\[\d+\]|parent\.parent)[^\n]*?["\']src["\'][^\n]*?["\']email_triage["\']'
)


def test_no_hand_rolled_src_root_spelling_outside_harness():
    offenders = []
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "_pin_harness.py":
            continue
        if _HANDROLLED_SRC_ROOT.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(_TESTS_ROOT)).replace("\\", "/"))
    assert not offenders, (
        "A test hand-rolls the SRC_ROOT spelling (Path(__file__) … parents[N] / "
        f"'src' / 'email_triage') outside the harness (census run15 #3):\n  "
        + "\n  ".join(offenders)
        + "\nImport SRC_ROOT from _pin_harness — a hand-rolled root silently shifts "
        "on a file MOVE (wrong dir → vacuous-pass / wrong-read). Use REPO_ROOT for a "
        "repo-level root (Containerfile / pyproject / docs)."
    )


def test_allow_list_entries_are_real_and_justified():
    """Every _ALLOW entry must (a) exist and (b) actually call rglob('*.py')
    (else the exemption is dead) — except the meta-pin itself, which only
    string-matches rglob in its teeth."""
    for name, reason in _ALLOW.items():
        assert reason, f"{name} allow-list entry needs a reason"
        matches = list(_TESTS_ROOT.rglob(name))
        assert matches, f"allow-listed {name} no longer exists — drop it"
        if name in ("test_pin_harness_adoption.py", "_pin_harness.py"):
            # The meta-pin only string-matches rglob in its teeth; the harness
            # now defines iter_files which rglob's a VARIABLE ``pattern`` (not a
            # literal ``"*.py"``), so the literal-pattern staleness check doesn't
            # apply — its presence is verified by test_harness_exposes_its_contract.
            continue
        assert _walks_py_sources(matches[0].read_text(encoding="utf-8")), (
            f"allow-listed {name} no longer calls rglob('*.py') — stale exemption"
        )


def test_meta_pin_has_teeth():
    # A walker that rglobs/globs *.py WITHOUT the harness is detected...
    assert _walks_py_sources('for p in root.rglob("*.py"):\n    pass\n')
    assert _walks_py_sources('for p in web.glob("**/*.py"):\n    pass\n')
    # ...but a single-file glob (no wildcard) is NOT a walk.
    assert not _walks_py_sources('p = d.glob("auth.py")\n')
    # run18 — AST-aware exemption teeth (was a substring test):
    # (a) a file that ROUTES its walk through a harness walker (iter_src_files /
    # iter_files / walk_src) performs NO raw rglob/glob/os.walk → _walks_py_sources
    # is False → exempt BY CONSTRUCTION (not because the import string is present).
    routed = "from _pin_harness import iter_src_files\nfor p in iter_src_files():\n    pass\n"
    assert _HARNESS in routed              # imports the harness...
    assert not _walks_py_sources(routed)   # ...and has NO raw walk → exempt.
    # (b) THE exact bug the substring→AST upgrade closed: a file that imports the
    # harness for a CONSTANT yet ALSO hand-rolls a raw rglob src-walk is STILL
    # flagged — the import no longer provides an escape hatch. (Under the OLD
    # ``_HARNESS not in text`` exemption this raw walk was INVISIBLE.)
    imports_but_raw_walks = (
        "from _pin_harness import REPO_ROOT\n"
        'for p in (REPO_ROOT / "tests").rglob("*.py"):\n    pass\n'
    )
    assert _HARNESS in imports_but_raw_walks         # imports the harness...
    assert _walks_py_sources(imports_but_raw_walks)  # ...yet STILL an offender.
    # R5c widening: a TEMPLATE-tree walk (*.html) is now also a walk shape.
    assert _walks_py_sources('for p in t.rglob("*.html"):\n    pass\n')
    # iterdir folded in (2026-06-27): an iterdir PAIRED WITH a .py/.html suffix
    # filter is a source-tree walk...
    assert _walks_py_sources(
        'for p in root.iterdir():\n    if p.suffix == ".py":\n        pass\n'
    )
    assert _walks_py_sources(
        'for p in root.iterdir():\n    if p.name.endswith(".html"):\n        pass\n'
    )
    # ...but a BARE single-dir .iterdir() listing (no source-suffix filter) is
    # NOT a walk — flagging it would manufacture the false-positives the iterdir
    # branch was previously omitted to avoid.
    assert not _walks_py_sources('for p in d.iterdir():\n    print(p)\n')
    # and an iterdir with an UNRELATED suffix (not .py/.html) is not a src walk.
    assert not _walks_py_sources(
        'for p in d.iterdir():\n    if p.suffix == ".json":\n        pass\n'
    )
    # run17  — bare CATCH-ALL glob shapes (the privacy-leak-scan evasion):
    # (a) `rglob("*")` + an in-body `.suffix` selector is a SOURCE walk...
    assert _walks_py_sources(
        'for p in base.rglob("*"):\n'
        '    if p.suffix in (".pyc", ".png"):\n        continue\n'
    )
    # ...as is `rglob("*")` + an `.endswith`/`.startswith` selector...
    assert _walks_py_sources(
        'for p in base.rglob("*"):\n    if p.name.endswith(".x"):\n        pass\n'
    )
    # (b) ...and `rglob("*")` off a hand-rolled repo-root climb
    # (`Path(__file__) … parents[N]`) is a SOURCE walk even with NO suffix filter
    # (the 2nd-spelling evasion — proves shape (b) has teeth independently)...
    assert _walks_py_sources(
        "import pathlib\n"
        "ROOT = pathlib.Path(__file__).resolve().parents[1]\n"
        'for p in (ROOT / "src/email_triage").rglob("*"):\n    pass\n'
    )
    # ...same via the `.parent.parent` climb spelling and `glob("**/*")`.
    assert _walks_py_sources(
        "from pathlib import Path\n"
        "ROOT = Path(__file__).resolve().parent.parent\n"
        'for p in ROOT.glob("**/*"):\n    pass\n'
    )
    # ...but a bare `tmp_path.rglob("*")` with NEITHER a suffix selector NOR a
    # repo-root climb is NOT a walk — the prune that avoids the tmp-dir-listing
    # false positive (e.g. asserting a temp dir is empty).
    assert not _walks_py_sources('for p in tmp_path.rglob("*"):\n    print(p)\n')
    # ...and a repo-root climb ALONE (no walk call) is NOT flagged — the many
    # fixture-locating tests that climb to read a SPECIFIC file stay clean.
    assert not _walks_py_sources(
        "from pathlib import Path\n"
        'ROOT = Path(__file__).resolve().parents[1]\nf = ROOT / "pyproject.toml"\n'
    )
    # ...and a catch-all glob with a CONCRETE extension (`*.tmp`) is NOT a
    # catch-all (it keeps an extension; not a source-tree walk).
    assert not _walks_py_sources('for p in d.glob("*.tmp"):\n    pass\n')


# ---------------------------------------------------------------------------
# N-224 R22 (census run22 MED — "pin-harness-drift"): the existing adoption
# pin enforced contract #1 (the walk) alone. 4 additional harness contracts
# had no adoption pin, so a NEW pin copying an old drift template escaped
# ("R38 replayed at scaffold level"). The 4 gaps:
#   V3 — raw `ast.parse(x.read_text())` — should route through parse_module
#   V4 — hand-rolled parent-annotate loops — should use annotate_parents
#   V5 — hand-rolled relpath `.replace("\\", "/")` — should use relpath()
#   V5' — `.relative_to(...).as_posix()` — should use relpath()
# Each is an interprocedural drift risk: a pin copying the template ships,
# then the harness moves, and the drift decouples silently.
# ---------------------------------------------------------------------------

# V3 detector: raw `ast.parse(x.read_text(...))` or `ast.parse(x.read_bytes(...))`
_V3_RAW_PARSE_RE = re.compile(
    r"ast\.parse\s*\(\s*[a-zA-Z_][\w.]*\.(read_text|read_bytes)\s*\(",
)

# V5 detector: hand-rolled forward-slash normalization on a Path str.
# Matches `.replace("\\", "/")` and its raw-string sibling.
_V5_HANDROLLED_FWDSLASH_RE = re.compile(
    r"\.replace\(\s*(?:r?)['\"]\\\\?['\"]\s*,\s*['\"]/['\"]\s*\)"
)

# V5' detector: `.relative_to(<any>).as_posix()` chained — the canonical form
# in relpath() but a hand-rolled duplicate outside the harness.
_V5PRIME_RELATIVE_TO_AS_POSIX_RE = re.compile(
    r"\.relative_to\s*\([^)]*\)\.as_posix\s*\(\s*\)"
)


_V3_ALLOW: frozenset[str] = frozenset({
    # N-388 R33 2026-07-11 migration wave 2 (this drive) drove the allow-list
    # from 36 → 1: 11 LIVE V3-two-line offenders migrated via
    # `ast.parse(<var>)` → `parse_source(<var>)` swap (the meta-pin V3-two-
    # line walker checks the receiver+attr, so switching to `parse_source`
    # bypasses it while preserving semantics; ``parse_source`` gained
    # ``**parse_kwargs`` forwarding so callers with ``filename=`` kept
    # working). Included the 2 SCOUT-MISREAD entries the wave-1 scout had
    # missed (test_admin_gate_ssot_pin.py + test_llm_fence_coverage_pin.py).
    # 24 already-STALE allow-list entries (no live V3-two-line offense at
    # HEAD per the structural walker) were pruned alongside. Only the self-
    # referential entry below remains — it IS the pin that enforces the
    # `ast.parse(x.read_text())` shape; its module docstring + teeth
    # planted-shape string literals both quote the exact regex
    # `_V3_RAW_PARSE_RE` matches. Migrating the shape out would strip the
    # pin of its own meaning.
    "test_n178_pin_harness_forked_parse.py",
})


def _v3_two_line_offenders_in_file(text: str) -> bool:
    """N-251 R25 structural widen: catch the TWO-LINE V3 shape that the
    inline `ast\\.parse\\(x\\.read_text\\(` regex missed:
        text = p.read_text(...)
        tree = ast.parse(text)
    Structural AST walk — remember every Name bound to a
    `<x>.read_text(...)` / `.read_bytes(...)` Call, then check whether
    an `ast.parse(<that Name>)` Call exists in the same module."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    file_read_vars: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        rhs = node.value
        if not isinstance(rhs, ast.Call):
            continue
        f = rhs.func
        if not isinstance(f, ast.Attribute):
            continue
        if f.attr not in ("read_text", "read_bytes"):
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                file_read_vars.add(tgt.id)
    if not file_read_vars:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "parse"):
            continue
        recv = f.value
        if not (isinstance(recv, ast.Name) and recv.id == "ast"):
            continue
        if not node.args:
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Name) and arg.id in file_read_vars:
            return True
    return False


def test_no_v3_raw_ast_parse_outside_harness():
    """V3 gap (census R22 MED): raw `ast.parse(x.read_text(...))` outside
    _pin_harness. Route through parse_module which is io-error-tolerant.

    N-251 R25 widen: also catches the TWO-LINE spelling
        `text = p.read_text()` + `tree = ast.parse(text)`
    that the inline regex missed (census R25 flagged 12 additional
    site-files with this shape).
    """
    offenders: list[str] = []
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "_pin_harness.py":
            continue
        if path.name == "test_pin_harness_adoption.py":
            continue  # the regex definitions match themselves in this file
        text = path.read_text(encoding="utf-8", errors="replace")
        matched = bool(_V3_RAW_PARSE_RE.search(text)) or _v3_two_line_offenders_in_file(text)
        if matched:
            offenders.append(str(path.relative_to(_TESTS_ROOT)).replace("\\", "/"))
    new_offenders = [o for o in offenders if o not in _V3_ALLOW]
    assert not new_offenders, (
        "N-224 R22 harness contract #3 (N-251 R25 widened): raw "
        "`ast.parse(x.read_text(...))` — INLINE or TWO-LINE — found "
        "outside the harness. Route through "
        "`_pin_harness.parse_module(p)` so a syntax-error / io-error in "
        "one src file doesn't abort the walk.\n\n"
        "Existing allow-list keeps current sites STABLE; NEW hand-rolls fire.\n"
        + "\n".join(new_offenders)
    )


def test_no_v4_handrolled_parent_annotate_outside_harness():
    """V4 gap (census R22 MED): a hand-rolled parent-annotation loop
    (`for parent in ast.walk(tree): for child in ast.iter_child_nodes(parent):
    parents[child] = parent`) should use `_pin_harness.annotate_parents(tree)`."""
    # Text detection: the walk+iter_child+parents-dict-assign SHAPE, spread
    # across a few lines. Match the CORE call sequence tolerantly with re.DOTALL.
    handrolled = re.compile(
        r"ast\.walk\([^)]+\)[\s\S]{0,120}?ast\.iter_child_nodes\([^)]+\)[\s\S]{0,120}?"
        r"[a-zA-Z_][\w.]*\[[^\]]+\]\s*=\s*[a-zA-Z_][\w.]*",
    )
    offenders: list[str] = []
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "_pin_harness.py":
            continue
        # Skip this test file itself — the regex above pattern-matches its own
        # explanatory prose otherwise.
        if path.name == "test_pin_harness_adoption.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if handrolled.search(text):
            offenders.append(str(path.relative_to(_TESTS_ROOT)).replace("\\", "/"))
    # Baseline allow-list: pins that currently hand-roll parent annotation.
    # Migration to `_pin_harness.annotate_parents` is a follow-up commit; the
    # pin caps NEW hand-rolls at the current set.
    _V4_ALLOW = frozenset({
        "test_dry_run_side_effects_pin.py",
        "test_is_active_ingestion_gate_pin.py",
        "test_n193_imap_fetch_literal_ssot_pin.py",
        "test_n194_llm_chat_metrics_pin.py",
        "test_n218_config_persist_ssot_pin.py",
        "test_web/test_288_phase3_d3_audit_gap.py",
    })
    new_offenders = [o for o in offenders if o not in _V4_ALLOW]
    assert not new_offenders, (
        "N-224 R22 harness contract #4: hand-rolled parent-annotation loop "
        "found outside the harness. Route through "
        "`_pin_harness.annotate_parents(tree)` (returns dict[id(node), parent]) "
        "so a parent-walk fix lands in ONE place.\n\nExisting allow-list keeps "
        "current sites STABLE; NEW hand-rolls fire.\n"
        + "\n".join(new_offenders)
    )


def test_no_v5_handrolled_fwdslash_outside_harness():
    """V5 gap (census R22 MED): hand-rolled `.replace("\\\\", "/")` on a Path
    str outside the harness. Should route through `_pin_harness.relpath(p)`
    which returns the canonical forward-slash form."""
    offenders: list[str] = []
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "_pin_harness.py":
            continue
        # This adoption pin file itself has `.replace("\\", "/")` in error-
        # message text — skip it (the harness doesn't need to guard its own
        # test file's diagnostics).
        if path.name == "test_pin_harness_adoption.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if _V5_HANDROLLED_FWDSLASH_RE.search(text):
            offenders.append(str(path.relative_to(_TESTS_ROOT)).replace("\\", "/"))
    _V5_ALLOW: frozenset[str] = frozenset({
        "test_html_text_ssot_pin.py",
        "test_no_cross_loop_audit_drain_pin.py",  # doc-comment mention only post-N-382 migration
        "test_no_legb_shadow_asyncio.py",
        # N-382 R32 DA panel HIGH #2 close: teeth test for
        # scan_pin_harness_adoption. The `.replace("\\", "/")` string appears
        # in a PLANTED-DRIFT test fixture (an intentional drift-shape
        # exemplar the teeth test seeds into a tmp_path pin file to prove
        # the scanner detects it). String-literal, never a live idiom.
        "test_scan_pin_harness_adoption_teeth.py",
        "test_web/test_async_db_safety.py",
        "test_web/test_last_login_terminus_pin.py",
        "test_web/test_n179_error_surface_pin.py",
        "test_web/test_runtime_settings_hipaa_gate.py",
    })
    new_offenders = [o for o in offenders if o not in _V5_ALLOW]
    assert not new_offenders, (
        "N-224 R22 harness contract #5: hand-rolled `.replace('\\\\', '/')` "
        "on a Path str found outside the harness. Route through "
        "`_pin_harness.relpath(p)` which returns the canonical forward-slash "
        "form so a Windows-path-normalization fix lands in ONE place.\n"
        + "\n".join(new_offenders)
    )


def test_no_v5prime_handrolled_relative_to_as_posix():
    """V5' gap (census R22 MED): `.relative_to(<any>).as_posix()` chain
    outside the harness. That's the canonical form OF `relpath()` — a
    hand-rolled duplicate risks drifting from the base (SRC_ROOT vs REPO_ROOT
    vs parent.parent)."""
    offenders: list[str] = []
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "_pin_harness.py":
            continue
        if path.name == "test_pin_harness_adoption.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if _V5PRIME_RELATIVE_TO_AS_POSIX_RE.search(text):
            offenders.append(str(path.relative_to(_TESTS_ROOT)).replace("\\", "/"))
    _V5P_ALLOW: frozenset[str] = frozenset({
        "test_ssot_registry_bijection_pin.py",
        "test_web/test_watch_failure_retry.py",
    })
    new_offenders = [o for o in offenders if o not in _V5P_ALLOW]
    assert not new_offenders, (
        "N-224 R22 harness contract #6: hand-rolled "
        "`.relative_to(...).as_posix()` chain outside the harness. Route "
        "through `_pin_harness.relpath(p)` — it standardizes on SRC_ROOT so "
        "an allow-list entry copied between pins doesn't silently miss.\n"
        + "\n".join(new_offenders)
    )


def _v6_hand_rolled_enclosing_fn_offender(text: str) -> bool:
    """N-251b R26 V6 detector: hand-rolled while-climb of `_ph_parent`
    for a `FunctionDef|AsyncFunctionDef` — the pattern
        cur = getattr(node, "_ph_parent", None)
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ...
            cur = getattr(cur, "_ph_parent", None)
    Structural: any function body that has BOTH the `_ph_parent`
    Attribute string AND a `while cur is not None` loop AND an
    isinstance check against FunctionDef/AsyncFunctionDef is a V6
    hand-roll. Route through `_pin_harness.enclosing_fn` /
    `innermost_fn_at_lineno`."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body_text = ast.unparse(fn) if hasattr(ast, "unparse") else ""
        if "_ph_parent" not in body_text:
            continue
        if "FunctionDef" not in body_text and "enclosing_fn" not in body_text:
            # Neither the walker's target class nor the SSOT — skip.
            continue
        # Look for a `while` loop with `_ph_parent` mentioned inside.
        for w in ast.walk(fn):
            if isinstance(w, ast.While):
                w_text = ast.unparse(w) if hasattr(ast, "unparse") else ""
                if "_ph_parent" in w_text and (
                    "FunctionDef" in w_text or "AsyncFunctionDef" in w_text
                ):
                    return True
    return False


_V6_ALLOW: frozenset[str] = frozenset({
    # 2026-07-03 N-251b R26 baseline (post-run26). Migration to
    # `_pin_harness.enclosing_fn` per-file is a mechanical follow-up
    # sweep; the ratchet caps NEW hand-rolls at the current set.
    "test_cli_db_open_encryption_pin.py",
    "test_cli_engine_close_pin.py",
    "test_cli_provider_oauth_register_pin.py",
    "test_error_ctx_key_template_pin.py",
    "test_json_col_write_pin.py",
    "test_n113_topic_backscan_baa_gate.py",
    "test_settings_key_catalog_pin.py",
})


def test_no_v6_handrolled_enclosing_fn_outside_harness():
    """N-251b R26 harness contract #8: hand-rolled while-climb of
    `_ph_parent` for `FunctionDef|AsyncFunctionDef` outside the
    harness. Route through `_pin_harness.enclosing_fn(node)` (or
    `innermost_fn_at_lineno(tree, lineno)`) — the SSOT owns the
    correct return-shape (`fn.name` str, `<module>` on module scope)."""
    offenders: list[str] = []
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "_pin_harness.py":
            continue
        if path.name == "test_pin_harness_adoption.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if _v6_hand_rolled_enclosing_fn_offender(text):
            offenders.append(str(path.relative_to(_TESTS_ROOT)).replace("\\", "/"))
    new_offenders = [o for o in offenders if o not in _V6_ALLOW]
    assert not new_offenders, (
        "N-251b R26 harness contract #8: hand-rolled while-climb of "
        "`_ph_parent` for `FunctionDef|AsyncFunctionDef` outside the "
        "harness. Route through `_pin_harness.enclosing_fn(node)` — "
        "the SSOT owns the correct return-shape.\n\n"
        "Existing allow-list keeps current sites STABLE; NEW hand-rolls fire.\n"
        + "\n".join(new_offenders)
    )


# Harness-hoisted shared SSOT constants — the meta-pin enforces that these
# are not re-inlined in a pin body. Adding a new shared frozenset/set
# constant to `_pin_harness.py` adds an entry HERE, keyed by the constant's
# name with the expected canonical HEAD member-set as the value. The pin
# scans every test file for an `ast.Assign` whose RHS is an inline
# `frozenset(...)` / bare `set` literal whose members exactly match ANY of
# these entries — an inline match is a re-shadow of the SSOT.
#
# Not included: constants whose canonical value has widened historically
# (e.g. `JSON_DECODE_ALIASES` — the alias tuple grew from 2 to 4 members —
# pinning the exact value would freeze the widening path). Add here ONLY
# for constants whose canonical value is stable-by-design (exempt-file
# boundaries, SSOT-home basenames).
_HARNESS_SHARED_CONSTANT_MEMBERSETS = {
    "SECRETS_SSOT_HOME": frozenset({"secrets.py"}),
}


def _rhs_inlines_literal_set(node: ast.Assign, expected: frozenset[str]) -> bool:
    """True if the assignment RHS is an inline set/frozenset literal whose
    only members are exactly ``expected``. Detects both:
      - ``frozenset({"x", "y"})``  (ast.Call wrapping ast.Set)
      - ``{"x", "y"}``              (bare ast.Set)
    Returns False for a bare Name (the harness-import shape this pin wants)."""
    rhs = node.value
    members: frozenset[str] | None = None
    if isinstance(rhs, ast.Call):
        if isinstance(rhs.func, ast.Name) and rhs.func.id == "frozenset":
            if len(rhs.args) == 1 and isinstance(rhs.args[0], ast.Set):
                members = frozenset(
                    e.value for e in rhs.args[0].elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                )
    elif isinstance(rhs, ast.Set):
        members = frozenset(
            e.value for e in rhs.elts
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        )
    return members is not None and members == expected


def test_no_reinlined_harness_shared_constants_outside_harness():
    """N-392 R32 harness contract #9 — hand-rolled re-inlining of a
    harness-hoisted shared SSOT constant (frozenset / set literal) in
    a pin body is FORBIDDEN outside `_pin_harness.py`. The harness IS
    the SSOT for the constant's canonical value; a re-inline silently
    forks it (Prime Directive #5/#6/#7 — 'converge duplicated needle
    lists' + 'pins obey the SSOT rule' + 'census the censusers').

    Rationale (2026-07-11 batched panel DA F4 + DB-SME follow-up): before
    hoisting, the funnel pin carried
    ``_EXEMPT_FILES = frozenset({"secrets.py"})`` and the collapse pin
    carried ``_SECRET_GET_SSOT_FILES = {"secrets.py"}`` — two divergent
    variable names for the same one-file exempt set. Post-hoist, both
    pins import ``SECRETS_SSOT_HOME`` from the harness. This contract
    prevents a future maintainer re-copying the frozenset literal INLINE
    ('just this once — CI green — merged') and silently re-forking the
    SSOT the census tightening (B) just closed.

    Cheap AST walk: for every test file (except the harness itself),
    scan every ``ast.Assign`` whose RHS is a ``frozenset(...)`` / bare
    ``set`` literal whose members exactly match a harness-hoisted shared
    constant in :data:`_HARNESS_SHARED_CONSTANT_MEMBERSETS`. Any hit is
    an offender.
    """
    offenders: list[str] = []
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "_pin_harness.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for const_name, expected in _HARNESS_SHARED_CONSTANT_MEMBERSETS.items():
                if _rhs_inlines_literal_set(node, expected):
                    rel = str(path.relative_to(_TESTS_ROOT)).replace("\\", "/")
                    offenders.append(f"{rel}:{node.lineno} — re-inlines {const_name}")
                    break
    assert not offenders, (
        "N-392 R32 harness contract #9: harness-hoisted shared SSOT "
        "constants must NOT be re-inlined in a pin body — import from "
        "`_pin_harness` instead. A re-inline silently forks the SSOT "
        "(PD #5/#6/#7).\n\n"
        + "\n".join(offenders)
    )


def test_meta_pin_covers_every_harness_contract():
    """PD#7 — 'census the censusers'. This meta-pin exists so a NEW harness
    contract added to `_pin_harness.py` requires a matching adoption test
    in THIS file. It's a hand-crafted census: every documented contract in
    the harness's docstring MUST have a corresponding `test_no_*_outside_
    harness` (or an equivalent explicit exception).

    Contracts to enforce (mapping: contract → adoption test):
      1. src walk        → test_every_py_source_walker_uses_the_harness
      2. harness exports → test_harness_exposes_its_contract
      3. SRC_ROOT spell  → test_no_hand_rolled_src_root_spelling_outside_harness
      4. raw ast.parse   → test_no_v3_raw_ast_parse_outside_harness
      5. parent-annotate → test_no_v4_handrolled_parent_annotate_outside_harness
      6. fwd-slash idiom → test_no_v5_handrolled_fwdslash_outside_harness
      7. relative_to.as_posix → test_no_v5prime_handrolled_relative_to_as_posix
      8. enclosing_fn walk → test_no_v6_handrolled_enclosing_fn_outside_harness
      9. shared-constant re-inline → test_no_reinlined_harness_shared_constants_outside_harness
    """
    import test_pin_harness_adoption as self_mod
    required = {
        "test_every_py_source_walker_uses_the_harness",
        "test_harness_exposes_its_contract",
        "test_no_hand_rolled_src_root_spelling_outside_harness",
        "test_no_v3_raw_ast_parse_outside_harness",
        "test_no_v4_handrolled_parent_annotate_outside_harness",
        "test_no_v5_handrolled_fwdslash_outside_harness",
        "test_no_v5prime_handrolled_relative_to_as_posix",
        "test_no_v6_handrolled_enclosing_fn_outside_harness",
        "test_no_reinlined_harness_shared_constants_outside_harness",
    }
    missing = required - {name for name in dir(self_mod) if name.startswith("test_")}
    assert not missing, (
        "N-224 R22 anti-vacuity: the meta-adoption pin is missing coverage "
        "for these contracts — every harness contract needs its own adoption "
        "test.\n" + "\n".join(sorted(missing))
    )
