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

# In the curated PUBLIC tree, operator-only files named in _ALLOW (e.g. the
# *llm-host* suite) are publish-stripped, so an _ALLOW entry can legitimately have
# no match there. Detect the FULL DEV TREE by a publish-config file that is
# itself stripped from the public mirror; enforce "drop dead _ALLOW entries"
# ONLY there, so this shipping meta-pin stays green in the curated tree.
from _pin_harness import _FULL_DEV_TREE  # noqa: E402  (the one dev-tree detector, PD-5)

# Test files that call rglob("*.py") but legitimately do NOT use the src-rooted
# harness — each with a source-verified reason. Keep this SHORT; a new entry is
# a conscious decision that a new walker should NOT adopt the harness.
_ALLOW = {
    # Walks the TESTS tree (tests_root.rglob), not src/email_triage — it audits
    # the test suite's own setup_logging(LoggingConfig(hipaa=...)) call sites,
    # so the src-rooted harness (SRC_ROOT/iter_src_files) does not apply.
    "test_hipaa_mode_contamination_invariant.py": "walks the tests/ tree, not src",
    # This meta-pin (string-matches rglob in its own teeth/scan — not a walker).
    "test_pin_harness_adoption.py": "the meta-pin itself",
    # Behavioural autochain test, NOT a structural-drift pin: its embedded
    # wizard-audience grep globs a SINGLE subdir (templates/account_wizard/*.html)
    # for forbidden tokens, not the src-tree structural-pin walk the harness
    # serves. (R5c-surfaced by the *.html widening, 2026-06-21.)
    "test_account_wizard_autochain.py": "behavioural test; single-subdir audience grep, not a pin",
    # (punch 647) The vendored-carrier census walks THIS interpreter's stdlib /
    # purelib / platlib (os.walk, pruning nested roots), never src/email_triage or
    # the repo, so no repo-rooted harness walker applies.
    "test_image_inventory.py": "walks the interpreter's install roots, not src",
    # (2026-07-26) test_publish_no_operator_tooling.py no longer needs an entry:
    # rewritten to the DEFAULT-DENY model it delegates the ship-set walk to the
    # scripts/publish_shipset.py funnel (git ls-files, not a raw rglob('*.py')),
    # so _walks_py_sources is False and no exemption is needed. Removed by the
    # stale-guard the allow-list carries — no free-floating exemptions.
    # (punch 617) the two offload-stack consumer pins no longer need entries: their
    # scripts/ walk routes through the harness's iter_files, and their names would
    # otherwise ship an operator host name in this shipped meta-pin's literals.
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
        if not matches:
            # Publish-stripped in the curated tree -> the entry is a no-op there.
            # Enforce "drop dead entries" ONLY in the full dev tree.
            assert not _FULL_DEV_TREE, f"allow-listed {name} no longer exists — drop it"
            continue
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


_V3_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _v3_split_scope(scope):
    """Split one scope into (its OWN statements, its NESTED scopes).

    ``ast.walk`` flattens the whole module, which is what made this detector
    scope-blind. This descends only within a single scope and hands nested
    defs back so the caller can recurse with the right inherited bindings.
    """
    body = [scope.body] if isinstance(scope, ast.Lambda) else list(scope.body)
    own, nested = [], []
    stack = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, _V3_SCOPE_NODES):
            nested.append(node)
            continue
        own.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return own, nested


def _v3_file_read_vars(nodes) -> set[str]:
    """Names bound to a ``<x>.read_text(...)`` / ``.read_bytes(...)`` call."""
    found: set[str] = set()
    for node in nodes:
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
                found.add(tgt.id)
    return found


def _v3_parses_one_of(nodes, names: set[str]) -> bool:
    """Is there an ``ast.parse(<name>)`` for a name in ``names``?"""
    for node in nodes:
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
        if isinstance(arg, ast.Name) and arg.id in names:
            return True
    return False


def _v3_two_line_offenders_in_file(text: str) -> bool:
    """N-251 R25 structural widen: catch the TWO-LINE V3 shape that the
    inline `ast\\.parse\\(x\\.read_text\\(` regex missed:
        text = p.read_text(...)
        tree = ast.parse(text)

    SCOPE-AWARE since 2026-08-25. The original walked the WHOLE module with
    ``ast.walk`` and pooled every ``.read_text()`` binding into one set, so a
    file where function A does ``text = p.read_text(...)`` and an unrelated
    function B takes a PARAMETER named ``text`` and does ``ast.parse(text)``
    was flagged on a name collision alone. Measured: that false positive was
    live and RED at HEAD ``a95274d3`` in
    ``test_privacy_invariants_no_customer_names.py``, where the two sites are
    in different functions and neither is a raw parse of a file read.

    A name is now only credited to an ``ast.parse`` in the scope that bound it
    or in a scope nested inside that one — which is exactly Python's own
    resolution for the shape this pin is about. Teeth in
    ``test_v3_two_line_detector_is_scope_aware_and_has_teeth``: the same-scope
    and the module-level-into-function spellings both still return True.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False

    def _visit(scope, inherited: set[str]) -> bool:
        own, nested = _v3_split_scope(scope)
        visible = inherited | _v3_file_read_vars(own)
        if _v3_parses_one_of(own, visible):
            return True
        return any(_visit(inner, visible) for inner in nested)

    return _visit(tree, set())


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
    _V4_ALLOW = frozenset()
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
        "test_no_cross_loop_audit_drain_pin.py",  # doc-comment mention only post-N-382 migration
        "test_no_legb_shadow_asyncio.py",
        # N-382 R32 DA panel HIGH #2 close: teeth test for
        # scan_pin_harness_adoption. The `.replace("\\", "/")` string appears
        # in a PLANTED-DRIFT test fixture (an intentional drift-shape
        # exemplar the teeth test seeds into a tmp_path pin file to prove
        # the scanner detects it). String-literal, never a live idiom.
        "test_scan_pin_harness_adoption_teeth.py",
        "test_web/test_async_db_safety.py",
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
    # Dead-entry check (panel DA F1, 2026-11-07): an entry the regex no longer
    # flags would silently excuse a future regression in that file. A missing
    # file fails only in the full dev tree (publish strips some tests).
    for name in sorted(_V5_ALLOW):
        if not (_TESTS_ROOT / name).exists():
            assert not _FULL_DEV_TREE, f"_V5_ALLOW entry {name} no longer exists — drop it"
            continue
        assert name in offenders, (
            f"_V5_ALLOW entry {name} has no hand-rolled `.replace('\\\\', '/')` "
            "left — stale exemption, drop it"
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
     10. dev-tree detector → test_the_dev_tree_detector_has_one_definition
     11. call-graph fixpoint → test_no_handrolled_call_graph_fixpoint_outside_harness
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
        "test_the_dev_tree_detector_has_one_definition",
        "test_no_handrolled_call_graph_fixpoint_outside_harness",
        "test_the_call_graph_fixpoint_detector_has_teeth",
    }
    missing = required - {name for name in dir(self_mod) if name.startswith("test_")}
    assert not missing, (
        "N-224 R22 anti-vacuity: the meta-adoption pin is missing coverage "
        "for these contracts — every harness contract needs its own adoption "
        "test.\n" + "\n".join(sorted(missing))
    )


# --- contract  (census-r2 B fold, sme-da SHOULD-2 / PD-6): ONE call-graph fixpoint -----------
# `_pin_harness` owns the reach and taint fixpoints over calls (`reachers_of`, `reach_closure`,
# `param_taint_fixpoint`, all on `CallGraph` / `CrossModuleResolver`). Before class B each pin
# that needed "which defs reach X" wrote its own `while changed:` loop over callee names, and no
# two agreed on lambdas, hops or same-named defs. This contract names that idiom.
# SCOPE: the `changed`-flag fixpoint (a `while <flag>:` loop that resets the flag to False and
# sets it True, or `|=`, inside) in a def that also reads callees. A worklist walker (`while
# stack:` / `while frontier:`) is a different idiom and is NOT caught: test_582's
# `pd14_emitter_sites` and test_live_db_ro_mount_overlay's `_cli_db_walk` are such walkers today,
# named here so the gap is on record rather than assumed closed.

#: Names whose call reads a callee: the harness readers, and the private one the old `reachers_of` used.
_CALLEE_READERS = frozenset({
    "call_name", "_call_name", "callee_ref", "call_callee_names", "call_site", "call_args_of",
    "hop_target", "unwrap_callable", "_own_call_names", "dispatched_slot",
})


def _handrolled_fixpoint_lines(source: str) -> list[int]:
    """Lines of the defs in ``source`` that run a ``changed``-flag fixpoint AND read callees."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    out: set[int] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        reads_callees = any(
            (isinstance(n, ast.Attribute) and n.attr == "func")
            or (isinstance(n, ast.Call) and (getattr(n.func, "id", None) or getattr(n.func, "attr", None))
                in _CALLEE_READERS)
            for n in ast.walk(fn))
        if not reads_callees:
            continue
        for loop in ast.walk(fn):
            if not (isinstance(loop, ast.While) and isinstance(loop.test, ast.Name)):
                continue
            flag = loop.test.id

            def sets(value: bool) -> bool:
                return any(isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
                           and n.value.value is value
                           and any(isinstance(t, ast.Name) and t.id == flag for t in n.targets)
                           for n in ast.walk(loop))

            raised = sets(True) or any(isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name)
                                       and n.target.id == flag for n in ast.walk(loop))
            if sets(False) and raised:
                out.add(fn.lineno)
                break
    return sorted(out)


def test_no_handrolled_call_graph_fixpoint_outside_harness():
    """PD#6 / harness contract : a pin that needs a reach or taint over calls asks
    ``reachers_of`` / ``reach_closure`` / ``param_taint_fixpoint``; it does not loop to a fixpoint
    over callee names itself."""
    sources = _test_sources()
    assert "_pin_harness.py" in sources, "the walk did not reach the harness: its root is wrong"
    offenders = [f"{rel}:{line}" for rel, text in sources.items() if rel != "_pin_harness.py"
                 for line in _handrolled_fixpoint_lines(text)]
    assert not offenders, (
        "a test file runs its own `changed`-flag fixpoint over callee names. Use "
        "`_pin_harness.reachers_of` / `reach_closure` (reach) or `param_taint_fixpoint` (taint): a "
        "second fixpoint drifts on lambdas, hops and same-named defs (PD#6, contract #11):\n  "
        + "\n  ".join(offenders))


def test_the_call_graph_fixpoint_detector_has_teeth():
    # the retired shape: d6adcce0's `reachers_of`, a flag fixpoint over `_own_call_names`
    old_reachers = (
        "def reachers_of(tree, target):\n"
        "    calls = {fn.name: _own_call_names(fn) for fn in ast.walk(tree)}\n"
        "    reach = {n for n, c in calls.items() if target in c}\n"
        "    changed = True\n"
        "    while changed:\n"
        "        changed = False\n"
        "        for name, c in calls.items():\n"
        "            if name not in reach and c & reach:\n"
        "                reach.add(name)\n"
        "                changed = True\n"
        "    return reach\n")
    assert _handrolled_fixpoint_lines(old_reachers) == [1]
    # the same loop with the flag raised by `|=`, reading `.func` directly
    augmented = (
        "def taint(fns):\n"
        "    again = True\n"
        "    while again:\n"
        "        again = False\n"
        "        for f in fns:\n"
        "            again |= mark(f.func)\n")
    assert _handrolled_fixpoint_lines(augmented) == [1]
    # not the idiom: a fixpoint that reads no callee, a callee read with no fixpoint, a worklist
    no_callee = old_reachers.replace("_own_call_names(fn)", "set()")
    assert _handrolled_fixpoint_lines(no_callee) == []
    no_loop = "def names(tree):\n    return [call_name(n) for n in ast.walk(tree)]\n"
    assert _handrolled_fixpoint_lines(no_loop) == []
    worklist = ("def walk(start):\n    stack = [start]\n    while stack:\n        n = stack.pop()\n"
                "        stack += callee_ref(n.func)\n")
    assert _handrolled_fixpoint_lines(worklist) == []
    # a flag loop whose flag is never raised is not a fixpoint
    never_raised = old_reachers.replace("                changed = True\n", "                pass\n")
    never_raised = never_raised.replace("    changed = True\n    while", "    changed = False\n    while")
    assert _handrolled_fixpoint_lines(never_raised) == []


def test_v3_two_line_detector_is_scope_aware_and_has_teeth():
    """The 2026-08-25 scope-awareness fix must NARROW the detector, not blunt it.

    The original pooled every ``.read_text()`` binding in the module into one
    set, so two unrelated functions sharing a variable name were flagged. The
    fix credits a binding only to the scope that made it and to scopes nested
    inside it. Every real spelling below must still return True; only the
    cross-scope name collision may return False.
    """
    # --- MUST STILL FIRE (the shapes this pin exists for) ------------------
    same_scope = (
        "import ast\n"
        "def f(p):\n"
        "    text = p.read_text(encoding='utf-8')\n"
        "    return ast.parse(text)\n"
    )
    module_level = (
        "import ast\n"
        "text = P.read_text()\n"
        "def f():\n"
        "    return ast.parse(text)\n"
    )
    nested_closure = (
        "import ast\n"
        "def outer(p):\n"
        "    blob = p.read_bytes()\n"
        "    def inner():\n"
        "        return ast.parse(blob)\n"
        "    return inner\n"
    )
    for label, src in (
        ("same scope", same_scope),
        ("module-level read, parsed in a function", module_level),
        ("outer read, parsed in a nested closure", nested_closure),
    ):
        assert _v3_two_line_offenders_in_file(src), (
            f"the two-line V3 detector no longer catches: {label}. The "
            "scope-awareness fix was meant to remove a false POSITIVE; if it "
            "also removed a true positive the pin is now blunter than before "
            "the fix and the fix must be reverted, not adjusted."
        )

    # --- MUST NOT FIRE (the false positive that made this fix necessary) ---
    cross_scope = (
        "import ast\n"
        "def reader(p):\n"
        "    text = p.read_text()\n"
        "    return text\n"
        "def parser(path, text):\n"
        "    return ast.parse(text)\n"
    )
    assert not _v3_two_line_offenders_in_file(cross_scope), (
        "the detector still flags two unrelated functions that merely share a "
        "variable name. `parser`'s `text` is a PARAMETER, not a file read; "
        "crediting `reader`'s binding to it is a name collision, not a raw "
        "parse. This is the shape that was RED at HEAD a95274d3."
    )

    # --- and the real module that was falsely flagged ----------------------
    victim = _TESTS_ROOT / "test_privacy_invariants_no_customer_names.py"
    if victim.exists():
        assert not _v3_two_line_offenders_in_file(
            victim.read_text(encoding="utf-8", errors="replace")
        ), (
            "test_privacy_invariants_no_customer_names.py is flagged again. "
            "Either a genuine raw two-line parse was added to it, or the "
            "scope-awareness fix regressed — check which before allow-listing."
        )


# The strip list's file name, split so this file's own needle is not a hit: the
# detector below flags any string constant ENDING with it, and this file is in the
# net like every other test file.
_STRIP_LIST_NAME = "publish-strip-paths" + ".txt"

# Files allowed to carry a string constant naming the strip list, each with its
# reason. Punch 629 fold (DA F5): an explicit allow-list, not a list of call shapes.
_STRIP_LIST_NAME_ALLOW = {
    "_pin_harness.py": "the ONE _FULL_DEV_TREE definition (contract #10)",
    "test_punch509_go_trailer_verified_outside_the_net_pin.py": (
        "stages the strip list's path as a file in a planted git repo to test the SME "
        "evidence gate; it never probes the real tree"),
}


def _dev_tree_detector_sites(sources: dict[str, str]) -> list[str]:
    """``rel:line`` of every assignment to ``_FULL_DEV_TREE`` (any target shape) and of
    every string constant that ENDS with the strip list's file name, in any file
    outside ``_STRIP_LIST_NAME_ALLOW`` (PD#5).

    Punch 629 fold (DA F5, db F2a fix 5): the old net matched one call shape
    (``.exists()``/``.is_file()`` on a path built with the bare name) and missed
    ``os.path.exists(os.path.join(...))``, a full-path ``Path("scripts/...")`` and a
    probe through a variable. Any probe of the strip list has to name it, so the
    constant is the net: no call shapes, no dataflow, and a new shape is caught
    by construction. A false hit is loud (fails CLOSED): allow-list it with a reason."""
    out: set[str] = set()
    for rel, text in sources.items():
        allowed = rel.rsplit("/", 1)[-1] in _STRIP_LIST_NAME_ALLOW
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            targets = (node.targets if isinstance(node, ast.Assign)
                       else [node.target] if isinstance(node, (ast.AnnAssign, ast.AugAssign))
                       else [])
            if rel != "_pin_harness.py" and any(
                    isinstance(n, ast.Name) and n.id == "_FULL_DEV_TREE"
                    for t in targets for n in ast.walk(t)):
                out.add(f"{rel}:{node.lineno}")
            elif (not allowed and isinstance(node, ast.Constant) and isinstance(node.value, str)
                  and node.value.endswith(_STRIP_LIST_NAME)):
                out.add(f"{rel}:{node.lineno}")
    return sorted(out)


def _test_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for path in sorted(_TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = str(path.relative_to(_TESTS_ROOT)).replace("\\", "/")
        sources[rel] = path.read_text(encoding="utf-8", errors="replace")
    return sources


def test_the_dev_tree_detector_has_one_definition():
    """PD#5 / harness contract : ``_FULL_DEV_TREE`` is defined ONCE, in
    ``_pin_harness.py``, and every caller imports it. Five test files each re-rolled it
    before punch 629; a sixth copy would drift on the next detector change."""
    sources = _test_sources()
    assert "_pin_harness.py" in sources, "the walk did not reach the harness: its root is wrong"
    assert "_FULL_DEV_TREE" in sources["_pin_harness.py"], "the harness lost the definition"
    offenders = _dev_tree_detector_sites(sources)
    assert not offenders, (
        "a test file names the strip list outside the allow-list, or defines its own "
        "full-dev-tree detector. Import it instead: `from _pin_harness import "
        "_FULL_DEV_TREE` (PD#5), or allow-list a non-probe use with its reason.\n  "
        + "\n  ".join(offenders))


def test_the_strip_list_name_allow_list_is_live():
    """Each allow-listed file still exists and still names the strip list; a dead
    entry would exempt the next file to take that name. A publish-stripped entry is
    absent on the public tree, so absence fails only on the full dev tree."""
    sources = _test_sources()
    by_name = {rel.rsplit("/", 1)[-1]: text for rel, text in sources.items()}
    for name, reason in _STRIP_LIST_NAME_ALLOW.items():
        assert reason, f"{name} needs a reason"
        if name not in by_name:
            assert not _FULL_DEV_TREE, f"allow-listed {name} no longer exists: drop it"
            continue
        assert _STRIP_LIST_NAME in by_name[name], f"{name} no longer names the strip list: drop it"


def test_the_dev_tree_detector_pin_has_teeth():
    name = _STRIP_LIST_NAME
    harness = f"_FULL_DEV_TREE: bool = (REPO_ROOT / 'scripts' / '{name}').exists()\n"
    assert not _dev_tree_detector_sites({"_pin_harness.py": harness})
    assert _dev_tree_detector_sites({"test_x.py": "_FULL_DEV_TREE = True\n"}) == ["test_x.py:1"]
    assert _dev_tree_detector_sites({"test_x.py": harness}) == ["test_x.py:1"]
    assert _dev_tree_detector_sites({"test_x.py": "a, _FULL_DEV_TREE = 1, 2\n"})
    assert _dev_tree_detector_sites(
        {"test_x.py": f"DEV = (ROOT / 'scripts' / '{name}').is_file()\n"}), (
        "the same predicate under another name must be caught")
    # The three shapes the old call-shape net missed (db F2a fix 5), plus a fourth
    # that is no call at all: an f-string path (its constant part is a JoinedStr value).
    for shape in (
        f"import os\nDEV = os.path.exists(os.path.join(R, 'scripts', '{name}'))\n",
        f"from pathlib import Path\nDEV = Path('scripts/{name}').exists()\n",
        f"P = ROOT / 'scripts' / '{name}'\nDEV = P.exists()\n",
        f"import os\nDEV = os.path.isfile(f\"{{ROOT}}/scripts/{name}\")\n",
    ):
        assert _dev_tree_detector_sites({"test_x.py": shape}), shape
        # the allow-list exempts the constant, never a _FULL_DEV_TREE assignment
        allowed = "test_punch509_go_trailer_verified_outside_the_net_pin.py"
        assert not _dev_tree_detector_sites({allowed: shape}), shape
        assert _dev_tree_detector_sites({allowed: shape.replace("DEV =", "_FULL_DEV_TREE =")})
    assert not _dev_tree_detector_sites(
        {"test_x.py": "from _pin_harness import _FULL_DEV_TREE\nif _FULL_DEV_TREE:\n    pass\n"})
    # a mention inside longer text is not a path: the constant must END with the name
    assert not _dev_tree_detector_sites({"test_x.py": f"MSG = 'see scripts/{name}, line 3'\n"})


# --- the detector's canary (punch 629 fold: hipaa F2a fix 1 = db fix 2) -------------
# Nine files' dev-only arms (the punch-511 F1 fence among them) ride the ONE probe in
# the harness. If the strip list is renamed or moved, every arm turns into a skip or a
# no-op on the DEV tree, and the one-definition pin above stays green. Two other
# dev-only paths, each stripped from the public tree by its own strip-list entry
# (`scripts/hooks/*`, `scripts/publish-*`), are probed under THIS file's root rather
# than the harness's REPO_ROOT, so a wrong harness root disagrees too.

def _dev_tree_signals(root: pathlib.Path) -> tuple[bool, bool]:
    hooks_gate = (root / "scripts" / "hooks" / "sme_review_gate.py").is_file()
    curate = (root / "scripts" / "publish-curate.py").is_file()
    return hooks_gate, curate


def _dev_tree_canary(full_dev_tree: bool, root: pathlib.Path) -> list[str]:
    hooks_gate, curate = _dev_tree_signals(root)
    if full_dev_tree == hooks_gate == curate:
        return []
    return [f"_FULL_DEV_TREE={full_dev_tree}, but scripts/hooks/sme_review_gate.py "
            f"present={hooks_gate} and scripts/publish-curate.py present={curate}"]


def test_the_dev_tree_detector_agrees_with_two_independent_dev_only_paths():
    """True on the dev tree, False on the public tree: equal on both. A disagreement
    means the harness's probe no longer marks the dev tree."""
    assert not _dev_tree_canary(_FULL_DEV_TREE, _TESTS_ROOT.parent), (
        "the full-dev-tree detector disagrees with two independent dev-only paths; "
        "every dev-only arm that rides it would skip or no-op silently:\n  "
        + "\n  ".join(_dev_tree_canary(_FULL_DEV_TREE, _TESTS_ROOT.parent)))


def test_the_dev_tree_canary_has_teeth(tmp_path):
    def plant(*parts: str) -> None:
        p = tmp_path.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")

    assert not _dev_tree_canary(False, tmp_path), "the public shape: nothing present"
    assert _dev_tree_canary(True, tmp_path), "detector True with neither path present"
    plant("scripts", "hooks", "sme_review_gate.py")
    assert _dev_tree_canary(True, tmp_path), "one path present, one absent"
    plant("scripts", "publish-curate.py")
    assert not _dev_tree_canary(True, tmp_path), "the dev shape: all present"
    # the failure this canary exists for: the strip list renamed on the dev tree
    assert _dev_tree_canary(False, tmp_path), "detector False on a full dev tree"
