"""Pin (punch 771; PD-1 count-agnostic, PD-5/PD-6 one funnel): a test that starts a child python
which imports the product gets THIS tree's ``src`` from the harness, never from a hand-built
``PYTHONPATH``.

Why. ``email_triage`` is installed editable from the MAIN checkout. A test run in a git worktree
whose child process does not put its own ``src`` first imports the main checkout's code, so the
test measures a tree other than the one under test and can pass or fail for the wrong reason (class
AH: the alembic baseline test compared this tree's migration with the main checkout's ``init_db``).
Four tests each hand-rolled the three lines that fix it; ``_pin_harness.tree_src_env`` is now the one
copy, and a fifth hand-rolled copy is the drift this pin refuses.

Two properties, each over every test file under ``tests/``, no count:

* A. No test file other than the harness WRITES a ``PYTHONPATH`` whose value names a ``src``
  directory (a name with a ``src`` token such as ``src`` / ``repo_src`` / ``SRC_ROOT``, a ``"src"``
  string segment, or ``email_triage.__file__``). A ``PYTHONPATH`` for another purpose (a hooks
  directory, a plugin directory, a hostile ``sitecustomize`` under test) is legal BY PREDICATE:
  nothing here is allow-listed. Shapes read: a dict literal key, ``env["PYTHONPATH"] = ..``,
  ``setenv/putenv/setdefault("PYTHONPATH", ..)`` and ``dict(.., PYTHONPATH=..)``.
* B. A test file that both starts a child python (``subprocess.run/Popen/check_*/call``) and writes
  child source that imports the product (``import email_triage`` / ``from email_triage ..`` inside a
  string, or ``-m email_triage..`` in an argv list) must call ``tree_src_env``. B is the stronger net:
  it also catches a test that forgot the path entirely.

Honest scope: a ``PYTHONPATH`` value routed through an intermediate name that has no ``src`` token
(``pp = str(x); env["PYTHONPATH"] = pp``) is invisible to A, and B reads one file at a time (a child
started by a helper in another module is not followed). ``scripts/verified-test.py`` ``_pin_src`` is
the same idiom in a SCRIPT; a script cannot import the test harness and is a deliberate twin.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    REPO_ROOT,
    assert_pin_has_teeth,
    docstring_constant_ids,
    iter_files,
    parse_module,
    relpath,
)

_HARNESS_FILE = "_pin_harness.py"
_HELPER = "tree_src_env"
_TEST_ROOTS = ("tests",)  # the operator-only openclaw skill tests do not ship; none imports the product
_CHILD_STARTERS = frozenset({"run", "Popen", "check_output", "check_call", "call"})
_IMPORTS_PRODUCT = re.compile(r"(?:^|[\n;(])\s*(?:import|from)\s+email_triage\b")


def _is_pythonpath(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value == "PYTHONPATH"


def _pythonpath_values(tree: ast.AST):
    """``(lineno, value expression)`` for every write of a ``PYTHONPATH`` key in ``tree``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if _is_pythonpath(key):
                    yield node.lineno, value
        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Subscript) and _is_pythonpath(t.slice):
                    yield node.lineno, node.value
        elif isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if name in {"setenv", "putenv", "setdefault"} and len(node.args) >= 2 and _is_pythonpath(node.args[0]):
                yield node.lineno, node.args[1]
            for kw in node.keywords:
                if kw.arg == "PYTHONPATH":
                    yield node.lineno, kw.value


def _names_a_src_dir(value: ast.AST) -> bool:
    """The value expression names a ``src`` directory: an identifier with a ``src`` token, a
    ``"src"`` string segment, or ``email_triage.__file__``."""
    for sub in ast.walk(value):
        ident = sub.id if isinstance(sub, ast.Name) else sub.attr if isinstance(sub, ast.Attribute) else None
        if ident is not None and "src" in ident.lower().split("_"):
            return True
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value in {"src", "src/"}:
            return True
        if isinstance(sub, ast.Attribute) and sub.attr == "__file__" \
                and isinstance(sub.value, ast.Name) and sub.value.id == "email_triage":
            return True
    return False


def hand_built_src_paths(tree: ast.AST) -> list[int]:
    """Line numbers where a test writes a ``PYTHONPATH`` naming a ``src`` directory by hand (A)."""
    return sorted({ln for ln, value in _pythonpath_values(tree) if _names_a_src_dir(value)})


def _child_calls(tree: ast.AST):
    return [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _CHILD_STARTERS
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"
    ]


def _starts_a_child_python(tree: ast.AST) -> bool:
    return bool(_child_calls(tree))


def _program_texts(tree: ast.AST, call: ast.Call):
    """The strings a child-starting call can run: the string literals inside the call and the
    literals assigned to any Name the call mentions (``code = (..)`` then ``["-c", code]``). A
    string that merely sits in the same file (a planted source file, a detector input) is not."""
    skip = docstring_constant_ids(tree)
    names = {n.id for n in ast.walk(call) if isinstance(n, ast.Name)}
    roots: list[ast.AST] = [call]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in names for t in targets):
                roots.append(node.value)
    for root in roots:
        for n in ast.walk(root):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip:
                yield n.value
            elif isinstance(n, ast.JoinedStr):
                yield "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in n.values)
        for n in ast.walk(root):
            if isinstance(n, (ast.List, ast.Tuple)):
                for a, b in zip(n.elts, n.elts[1:]):
                    if (isinstance(a, ast.Constant) and a.value == "-m" and isinstance(b, ast.Constant)
                            and isinstance(b.value, str)):
                        yield "-m " + b.value


def _child_imports_the_product(tree: ast.AST) -> bool:
    for call in _child_calls(tree):
        for text in _program_texts(tree, call):
            if _IMPORTS_PRODUCT.search(text) or re.match(r"-m email_triage\b", text):
                return True
    return False


def _calls_the_helper(tree: ast.AST) -> bool:
    return any(
        (isinstance(n, ast.Name) and n.id == _HELPER) or (isinstance(n, ast.Attribute) and n.attr == _HELPER)
        for n in ast.walk(tree)
    )


def child_without_tree_src(tree: ast.AST) -> bool:
    """B: starts a child python that imports the product and never calls ``tree_src_env``."""
    return (_starts_a_child_python(tree) and _child_imports_the_product(tree)
            and not _calls_the_helper(tree))


def _test_trees():
    for root in _TEST_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for path in iter_files(base):
            if path.name == _HARNESS_FILE:
                continue  # the one home of the idiom
            tree = parse_module(path)
            if tree is not None:
                yield path, tree


def test_no_test_hand_builds_a_src_pythonpath():
    offenders = [f"{relpath(p, REPO_ROOT)}:{ln}" for p, t in _test_trees() for ln in hand_built_src_paths(t)]
    assert not offenders, (
        "a test hand-builds a PYTHONPATH naming a src directory; use _pin_harness.tree_src_env() "
        "(the one copy: this tree's src first, ahead of an inherited PYTHONPATH):\n  "
        + "\n  ".join(offenders)
    )


def test_a_child_python_that_imports_the_product_gets_this_trees_src():
    offenders = [relpath(p, REPO_ROOT) for p, t in _test_trees() if child_without_tree_src(t)]
    assert not offenders, (
        "a test starts a child python that imports email_triage without _pin_harness.tree_src_env(): "
        "in a git worktree the child imports the MAIN checkout's code and tests another tree:\n  "
        + "\n  ".join(offenders)
    )


def test_the_live_population_is_seen():
    """B measures something: some test starts a child that imports the product, and each such
    file calls the helper (so the detector cannot pass by finding no child at all)."""
    seen = [p for p, t in _test_trees() if _starts_a_child_python(t) and _child_imports_the_product(t)]
    assert seen, "no test starts a child python that imports the product -- pin B measures nothing"
    uncovered = [relpath(p, REPO_ROOT) for p in seen
                 if not _calls_the_helper(parse_module(p))]
    assert not uncovered, uncovered


def test_the_helper_puts_this_trees_src_first_and_keeps_the_rest(monkeypatch):
    import os

    from _pin_harness import SRC_ROOT, tree_src_env

    monkeypatch.setenv("PYTHONPATH", "elsewhere")
    env = tree_src_env({"TZ": "UTC"})
    assert env["PYTHONPATH"].split(os.pathsep) == [str(SRC_ROOT.parent), "elsewhere"]
    assert env["TZ"] == "UTC" and "PATH" in {k.upper() for k in env}
    monkeypatch.delenv("PYTHONPATH")
    assert tree_src_env()["PYTHONPATH"] == str(SRC_ROOT.parent)


def test_the_src_pythonpath_pin_has_teeth():
    """Each hand-built shape is refused; each PYTHONPATH for another purpose is legal by predicate."""
    for bad in (
        'import os\nenv = {**os.environ, "PYTHONPATH": repo_src}\n',
        'import os\nenv = dict(os.environ)\nenv["PYTHONPATH"] = str(_REPO_ROOT / "src")\n',
        'def t(monkeypatch):\n    monkeypatch.setenv("PYTHONPATH", str(SRC_ROOT.parent))\n',
        'import os\nenv = dict(os.environ, PYTHONPATH=src)\n',
        'import email_triage\nenv = {"PYTHONPATH": str(Path(email_triage.__file__).parents[1])}\n',
        'env.setdefault("PYTHONPATH", src_dir)\n',
    ):
        assert_pin_has_teeth(hand_built_src_paths, bad)
    good = (
        'env = {"PYTHONPATH": str(HOOKS)}\n'
        'env["PYTHONPATH"] = str(_TESTS_DIR)\n'
        'env["PYTHONPATH"] = os.pathsep.join(p for p in (plugin_dir, env.get("PYTHONPATH")) if p)\n'
        'env = {"PYTHONPATH": "elsewhere"}\n'
        'monkeypatch.setenv("PYTHONPATH", str(tmp_path))\n'
    )
    assert_pin_has_teeth(lambda t: not hand_built_src_paths(t), good)


def test_the_child_import_pin_has_teeth():
    spawn = "import subprocess, sys\n"
    bad_sources = (
        spawn + 'subprocess.run([sys.executable, "-c", "import email_triage; print(1)"])\n',
        spawn + 'subprocess.run([sys.executable, "-c", "x = 1\\nfrom email_triage.web import db"])\n',
        spawn + 'subprocess.Popen([sys.executable, "-m", "email_triage.cli", "--help"])\n',
        spawn + 'code = f"import email_triage as e; {body}"\nsubprocess.check_output([sys.executable, "-c", code])\n',
    )
    for bad in bad_sources:
        assert_pin_has_teeth(child_without_tree_src, bad)
    good = (
        spawn + "from _pin_harness import tree_src_env\n"
        'subprocess.run([sys.executable, "-c", "import email_triage"], env=tree_src_env())\n'
    )
    other = (
        spawn + 'subprocess.run([sys.executable, str(HOOKS / "gate.py")])  # src/email_triage/x.py is a path\n'
        'DOC = "this child must not import email_triage"\n'
        'FIXTURE = "from email_triage.web import x\\n"  # a planted source file, never run as a child\n'
        'subprocess.run(["git", "add", "x.py"])\n'
    )
    prose = '"""import email_triage in a child"""\nimport subprocess\nsubprocess.run(["true"])\n'
    for fine in (good, other, prose):
        assert_pin_has_teeth(lambda t: not child_without_tree_src(t), fine)
