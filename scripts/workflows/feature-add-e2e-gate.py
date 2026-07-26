"""feature-add-e2e-gate — fail-close when a new route/template ships without a walk.

Layer-3 of the v0.2.0 CIDI-drift defense (per project_style_guide + the
feedback drawer feedback_ui_fixes_reviewed_with_playwright —  cache-flush
regression cited). Scans the git diff BASE..HEAD for:

  * NEW FastAPI routes under ``src/email_triage/**/*.py`` — matches
    ``@router.<get|post|patch|delete|put>('...')`` decorators at any nesting.
  * EDITED router files — the set of decorators in HEAD minus the set in
    BASE names the added routes.
  * NEW Jinja templates under ``src/email_triage/**/templates/**/*.html``.

For each new route / template, the gate demands a matching walk file at
``tests/e2e/walk/test_<slug>.py``. Missing => exit 1 (MISSING-WALK) with
a paste-ready skeleton. Ambient escape hatches:

  --skip=<reason> CLI flag, OR
  a git commit trailer ``OPERATOR-APPROVED-SKIP: <reason>`` on any commit
  in BASE..HEAD

... fail-open with the skip reason echoed.

Exit codes: 0 GREEN, 1 MISSING-WALK, 2 SETUP-error (git/diff failure).
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src" / "email_triage"
WALK_ROOT = REPO_ROOT / "tests" / "e2e" / "walk"
ROUTER_VERBS = frozenset({"get", "post", "patch", "delete", "put"})


class GateError(Exception):
    """Setup-time error (git failure, missing tree). Exit 2."""


# ---------------------------------------------------------------------------
# git glue
# ---------------------------------------------------------------------------

def _git(*args: str, cwd: Path | None = None) -> str:
    """Run a git command relative to ``cwd`` (default REPO_ROOT) and return
    its trimmed stdout. Raises GateError on non-zero exit."""
    cp = subprocess.run(
        ["git", *args],
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if cp.returncode != 0:
        raise GateError(
            f"git {' '.join(args)!r} failed (rc={cp.returncode}): "
            f"{cp.stderr.strip()[:400]}"
        )
    return cp.stdout


def _diff_name_status(base: str, cwd: Path | None = None) -> list[tuple[str, str]]:
    """Return [(status, path), ...] from ``git diff --name-status BASE..HEAD``.

    Status letters: A (added), M (modified), D (deleted), R... (renamed —
    the destination path is what we care about).
    """
    out = _git("diff", "--name-status", f"{base}..HEAD", cwd=cwd)
    rows: list[tuple[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        # Rename lines look like "R100\told\tnew" — take the destination.
        path = parts[-1]
        rows.append((status, path))
    return rows


def _file_at_rev(rev: str, path: str, cwd: Path | None = None) -> str | None:
    """Return the contents of ``path`` at ``rev``, or None if the file does
    not exist there. A missing file is NOT an error at the git level."""
    cp = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if cp.returncode != 0:
        return None
    return cp.stdout


def _commit_range_has_skip_trailer(base: str, cwd: Path | None = None) -> str | None:
    """Return the skip reason if any commit in BASE..HEAD carries the
    trailer ``OPERATOR-APPROVED-SKIP: <reason>``. Trailer parsing is a
    simple substring match on the raw commit body."""
    try:
        body = _git("log", "--format=%B", f"{base}..HEAD", cwd=cwd)
    except GateError:
        return None
    m = re.search(r"OPERATOR-APPROVED-SKIP:\s*(.+)", body)
    if m:
        return m.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# route + template extraction
# ---------------------------------------------------------------------------

_ROUTE_KEY = tuple[str, str]  # (verb, pattern) e.g. ("post", "/ops/db-backup")


def _extract_routes(source: str) -> set[_ROUTE_KEY]:
    """Extract the set of ``(verb, url_pattern)`` from a Python source string.

    Recognises decorator shapes ``@router.<verb>('/x')``,
    ``@<something>.<verb>('/x')`` — any Attribute whose ``attr`` is one of
    ROUTER_VERBS with a string-literal first arg. Missing string-literal =
    skipped (dynamic pattern; the walk cannot be named from it anyway)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    out: set[_ROUTE_KEY] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            verb: str | None = None
            if isinstance(func, ast.Attribute) and func.attr in ROUTER_VERBS:
                verb = func.attr
            if verb is None:
                continue
            if not dec.args:
                continue
            first = dec.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                out.add((verb, first.value))
    return out


def _slug_from_pattern(pattern: str) -> str:
    """Derive a walk-file slug from a URL pattern.

    Last non-empty URL segment, stripped of ``{path_params}``, lowered,
    non-word chars -> ``_``. Empty pattern => 'root'. A pattern ending in
    a param-only segment (``/a/{id}``) falls back to the preceding segment
    (``a``) — otherwise the slug reduces to ``id`` which is not meaningful.
    """
    p = pattern.strip("/")
    if not p:
        return "root"
    segs = [s for s in p.split("/") if s]
    # Strip fully-parameterized trailing segments so /a/{id} -> a.
    while segs and segs[-1].startswith("{") and segs[-1].endswith("}"):
        segs.pop()
    if not segs:
        return "root"
    last = segs[-1]
    last = re.sub(r"\{[^}]*\}", "", last)
    slug = re.sub(r"\W+", "_", last).strip("_").lower()
    return slug or "root"


def _slug_from_template(path: str) -> str:
    """Derive a slug from a template file path — the basename without .html,
    lowered, non-word -> ``_``."""
    base = Path(path).stem
    return re.sub(r"\W+", "_", base).strip("_").lower()


# ---------------------------------------------------------------------------
# gate — the walk
# ---------------------------------------------------------------------------

def _is_src_py(path: str) -> bool:
    return path.startswith("src/email_triage/") and path.endswith(".py")


def _is_src_template(path: str) -> bool:
    return path.startswith("src/email_triage/") and path.endswith(".html") and "/templates/" in path


def _walk_file_exists(slug: str, walk_root: Path | None = None) -> bool:
    root = walk_root or WALK_ROOT
    return (root / f"test_{slug}.py").exists()


def _walk_skeleton(slug: str, kind: str, ident: str) -> str:
    # Best-effort URL for the skeleton goto: for a route ident the last
    # token is the URL pattern; for a template we don't know the URL.
    goto_url = "/"
    if kind == "route":
        # ident looks like "POST /ops/db-backup".
        parts = ident.split(None, 1)
        if len(parts) == 2:
            goto_url = parts[1]
    return (
        "# tests/e2e/walk/test_{slug}.py\n"
        "\"\"\"Walk — {ident} ({kind}).\"\"\"\n"
        "from __future__ import annotations\n"
        "import pytest\n"
        "from playwright.sync_api import expect\n"
        "pytestmark = pytest.mark.e2e\n\n"
        "def test_golden(authed_page, base_url):\n"
        "    # GOLDEN: exercise the feature end-to-end.\n"
        "    authed_page.goto(base_url + '{goto_url}')\n"
        "    # TODO: assert rendered DOM (button text, form action, status)\n"
        "\n"
        "def test_server_refuses_remedy(page, base_url):\n"
        "    # BRANCH: server refuses -> user-remedy path exists.\n"
        "    pass\n"
    ).format(slug=slug, ident=ident, kind=kind, goto_url=goto_url)


def _collect_missing_walks(
    base: str,
    *,
    repo_root: Path | None = None,
    walk_root: Path | None = None,
) -> tuple[list[tuple[str, str, str]], int, int]:
    """Return (missing_walks, new_routes_count, new_templates_count).

    ``missing_walks`` is a list of (slug, kind, ident) triples where
    ``kind`` is 'route' | 'template' and ``ident`` is the URL pattern or
    template path.
    """
    cwd = repo_root or REPO_ROOT
    rows = _diff_name_status(base, cwd=cwd)
    src_py = [(status, p) for status, p in rows if _is_src_py(p)]
    templates = [(status, p) for status, p in rows if _is_src_template(p)]

    new_routes: list[tuple[str, str]] = []  # (verb, pattern)
    for status, path in src_py:
        head_source = _file_at_rev("HEAD", path, cwd=cwd)
        # A deleted file has no HEAD source; skip.
        if head_source is None:
            continue
        head_routes = _extract_routes(head_source)
        if status.startswith("A"):
            new_routes.extend(sorted(head_routes))
        else:  # M or R
            base_source = _file_at_rev(base, path, cwd=cwd) or ""
            base_routes = _extract_routes(base_source)
            added = head_routes - base_routes
            new_routes.extend(sorted(added))

    new_templates: list[str] = []
    for status, path in templates:
        if status.startswith("A"):
            new_templates.append(path)

    missing: list[tuple[str, str, str]] = []
    walk_dir = walk_root or WALK_ROOT
    seen_slugs: set[str] = set()
    for verb, pattern in new_routes:
        slug = _slug_from_pattern(pattern)
        if slug in seen_slugs:
            continue
        seen_slugs.add(slug)
        if not _walk_file_exists(slug, walk_dir):
            missing.append((slug, "route", f"{verb.upper()} {pattern}"))
    for tpath in new_templates:
        slug = _slug_from_template(tpath)
        if slug in seen_slugs:
            continue
        seen_slugs.add(slug)
        if not _walk_file_exists(slug, walk_dir):
            missing.append((slug, "template", tpath))

    return missing, len(new_routes), len(new_templates)


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------

def _self_test() -> int:
    """Seed a tmpdir with 3 scenarios and assert the gate behaves.

    1. router-add without walk => missing_walks non-empty.
    2. router-add + matching walk => missing_walks empty.
    3. trailer-skip => wrapper reports skip (exit 0).
    """
    import tempfile

    def _init_repo(tmp: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp, check=True)
        # Initial commit — empty src tree + walk root.
        (tmp / "src" / "email_triage").mkdir(parents=True)
        (tmp / "tests" / "e2e" / "walk").mkdir(parents=True)
        (tmp / "src" / "email_triage" / "__init__.py").write_text("")
        (tmp / "tests" / "e2e" / "walk" / "__init__.py").write_text("")
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "init"], cwd=tmp, check=True,
        )

    def _add_router(tmp: Path) -> None:
        router_src = (
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/self-test/widget')\n"
            "def widget():\n"
            "    return {'ok': True}\n"
        )
        (tmp / "src" / "email_triage" / "widget_router.py").write_text(router_src)

    # Scenario 1: router without walk => missing.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _init_repo(tmp)
        _add_router(tmp)
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "add widget"], cwd=tmp, check=True)
        missing, n_r, n_t = _collect_missing_walks(
            "HEAD~1",
            repo_root=tmp,
            walk_root=tmp / "tests" / "e2e" / "walk",
        )
        assert missing, f"scenario 1: expected missing walks, got {missing}"
        assert any(s == "widget" for s, _, _ in missing), (
            f"scenario 1: expected 'widget' slug in {missing}"
        )
        print(f"[self-test] scenario 1 OK: missing={[s for s, *_ in missing]}")

    # Scenario 2: router + matching walk => empty.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _init_repo(tmp)
        _add_router(tmp)
        (tmp / "tests" / "e2e" / "walk" / "test_widget.py").write_text(
            "def test_x(): pass\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add widget + walk"], cwd=tmp, check=True,
        )
        missing, _, _ = _collect_missing_walks(
            "HEAD~1",
            repo_root=tmp,
            walk_root=tmp / "tests" / "e2e" / "walk",
        )
        assert not missing, f"scenario 2: expected no missing, got {missing}"
        print("[self-test] scenario 2 OK: matched walk => no missing")

    # Scenario 3: trailer-skip => gate wrapper exits 0.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _init_repo(tmp)
        _add_router(tmp)
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        subprocess.run(
            [
                "git", "commit", "-q", "-m",
                "add widget\n\nOPERATOR-APPROVED-SKIP: dev-tools scratchpad demo",
            ],
            cwd=tmp,
            check=True,
        )
        skip = _commit_range_has_skip_trailer("HEAD~1", cwd=tmp)
        assert skip and "scratchpad" in skip, (
            f"scenario 3: expected trailer skip, got {skip!r}"
        )
        print(f"[self-test] scenario 3 OK: trailer-skip detected: {skip!r}")

    # Scenario 4 (MF2 — DA Batch-2 High + db-batch3 MEDIUM tighten): EDITED
    # router (status 'M') that ADDS a decorator. Earlier scenarios only prove
    # NEW files (status 'A'); the `M` path (``head_routes - base_routes`` in
    # ``_collect_missing_walks``) was untested.
    #
    # Assert three properties over the diff delta (count-agnostic, Directive 1
    # — NOT ``len(missing) == N``: the gate must scan head-minus-base, never
    # re-census the whole edited file):
    #
    #   (1) the ADDED decorator IS flagged,
    #   (2) the PRE-EXISTING route WITH a walk is NOT re-flagged, AND
    #   (3) the PRE-EXISTING route WITHOUT a walk (``legacy_no_walk``) is also
    #       NOT re-flagged — this is the db-batch3 tighten: without (3), a
    #       whole-file re-scan regression that returned ``head_routes`` instead
    #       of ``head_routes - base_routes`` would still pass (2) because
    #       ``existing`` has a walk, and pass ``n_r >= 1`` at n_r == 3.
    #       Adding a walk-less pre-existing route means a whole-file re-scan
    #       regression puts ``legacy_no_walk`` in missing_slugs, and (3) fires.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _init_repo(tmp)
        router_path = tmp / "src" / "email_triage" / "edited_router.py"
        # BASE commit — TWO pre-existing routes: one with a walk, one without.
        router_path.write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/self-test/existing')\n"
            "def existing():\n"
            "    return {'ok': True}\n"
            "@router.get('/self-test/legacy-no-walk')\n"
            "def legacy_no_walk():\n"
            "    return {'ok': True}\n"
        )
        (tmp / "tests" / "e2e" / "walk" / "test_existing.py").write_text(
            "def test_x(): pass\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "base router"], cwd=tmp, check=True,
        )
        # EDIT (status 'M') — add a THIRD decorator, no walk for it.
        router_path.write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/self-test/existing')\n"
            "def existing():\n"
            "    return {'ok': True}\n"
            "@router.get('/self-test/legacy-no-walk')\n"
            "def legacy_no_walk():\n"
            "    return {'ok': True}\n"
            "@router.post('/self-test/added')\n"
            "def added():\n"
            "    return {'ok': True}\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "edit router: add a route"],
            cwd=tmp, check=True,
        )
        missing, n_r, _n_t = _collect_missing_walks(
            "HEAD~1",
            repo_root=tmp,
            walk_root=tmp / "tests" / "e2e" / "walk",
        )
        missing_slugs = {s for s, _, _ in missing}
        # (1) The ADDED decorator on the edited (M) file demands a walk...
        assert "added" in missing_slugs, (
            f"scenario 4: edited-router (M) added decorator not detected: {missing}"
        )
        # (2) The PRE-EXISTING route WITH a walk is NOT re-flagged.
        assert "existing" not in missing_slugs, (
            f"scenario 4: pre-existing (walk-ful) route wrongly re-flagged on an "
            f"M edit: {missing}"
        )
        # (3) db-batch3 tighten — the PRE-EXISTING route WITHOUT a walk is ALSO
        # NOT re-flagged. Under a whole-file re-scan regression, this WOULD
        # appear in missing_slugs (because it has no walk), so this assertion
        # is what catches the "head_routes returned instead of head_routes -
        # base_routes" regression class the count-agnostic property was meant
        # to guard.
        assert "legacy_no_walk" not in missing_slugs, (
            f"scenario 4: pre-existing walk-less route wrongly re-flagged on an "
            f"M edit — head_routes returned instead of head-minus-base delta "
            f"(whole-file re-scan regression): {missing}"
        )
        # The delta counted the added route (not the whole file's route set).
        assert n_r >= 1, f"scenario 4: expected >=1 delta route counted, got {n_r}"
        print(
            "[self-test] scenario 4 OK: M-path detected added decorator; "
            f"delta_missing={sorted(missing_slugs)}"
        )

    print("[self-test] ALL SCENARIOS PASSED")
    return 0


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _default_base() -> str:
    """Base rev for the diff. env override E2E_GATE_BASE > origin/main > main."""
    env = os.environ.get("E2E_GATE_BASE")
    if env:
        return env
    for cand in ("origin/main", "main"):
        cp = subprocess.run(
            ["git", "rev-parse", "--verify", cand],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        if cp.returncode == 0:
            return cand
    return "HEAD~1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        default=None,
        help="git rev to diff against; default: E2E_GATE_BASE env, then origin/main.",
    )
    parser.add_argument(
        "--skip",
        default=None,
        help="Fail-open with this reason (equivalent to the OPERATOR-APPROVED-SKIP trailer).",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run the 3 self-test scenarios in a tmpdir and exit.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    base = args.base or _default_base()

    try:
        skip_trailer = _commit_range_has_skip_trailer(base)
    except GateError as exc:
        print(f"feature-add-e2e-gate: SETUP ERROR ({exc}) — exit 2", file=sys.stderr)
        return 2

    skip = args.skip or skip_trailer
    try:
        missing, n_r, n_t = _collect_missing_walks(base)
    except GateError as exc:
        print(f"feature-add-e2e-gate: SETUP ERROR ({exc}) — exit 2", file=sys.stderr)
        return 2

    summary = (
        f"feature-add-e2e-gate: {n_r} new routes / {n_t} new templates "
        f"checked; {len(missing)} walks missing."
    )
    print(summary)

    if skip:
        print(
            f"feature-add-e2e-gate: SKIP ({skip}) — fail-open, "
            f"{len(missing)} missing walks NOT enforced this run."
        )
        for slug, kind, ident in missing:
            print(f"  would-fail: {kind} {ident} -> tests/e2e/walk/test_{slug}.py")
        return 0

    if not missing:
        print("feature-add-e2e-gate: OK — every new route/template has a walk.")
        return 0

    print("feature-add-e2e-gate: FAIL — the following need walks:", file=sys.stderr)
    for slug, kind, ident in missing:
        expected = f"tests/e2e/walk/test_{slug}.py"
        print(f"  MISSING WALK: {kind} {ident}", file=sys.stderr)
        print(f"    expected file: {expected}", file=sys.stderr)
        print(f"    paste-ready skeleton:", file=sys.stderr)
        for line in _walk_skeleton(slug, kind, ident).splitlines():
            print(f"      {line}", file=sys.stderr)
    print(
        "\nEscape hatches (use rarely, per feedback_dont_gate_operator_design_choices):",
        file=sys.stderr,
    )
    print(
        "  * add `OPERATOR-APPROVED-SKIP: <reason>` to a commit trailer, OR",
        file=sys.stderr,
    )
    print("  * re-run with `--skip=<reason>` for a one-shot local bypass.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
