"""Tests for scripts/publish-public-mirror.sh.

Drives the bash script via subprocess against a fixture git repo
that mirrors the operator's real publish topology in miniature:

  fixture/
    private/           # role of the live email-triage repo
      scripts/publish-public-mirror.sh    (copied from real repo)
      scripts/publish-scrub-patterns.txt  (custom test catalogue)
      docs/PUBLISH-LOG.md                 (created by first publish)
    public/            # role of the public mirror; bare repo
                       # registered as remote `public-mirror` from
                       # `private/`.

Each test boots a fresh fixture so state from one test cannot leak
into the next. The script lives in this worktree and is exercised
"as-is" — no copy/paste of the implementation into the test.

Tests cover the five invariants the operator prompt called out:

  1. Dirty tree     -> abort, exit code != 0
  2. Not on main    -> abort
  3. No remote      -> instruction message + abort
  4. Scrub match    -> findings printed, interactive prompt path
                       (--auto-proceed exercises the proceed path;
                       a no-input run on stdin exercises the abort
                       path)
  5. Happy path     -> last-published ref advances + audit log
                       entry appended.

Bash is required. On Windows the test discovers a usable bash via
git-bash (which ships with git for Windows). If no bash is found
the entire module is skipped — Linux/Mac CI hits the script
directly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "publish-public-mirror.sh"
PATTERNS_PATH = REPO_ROOT / "scripts" / "publish-scrub-patterns.txt"


# ─── bash discovery ─────────────────────────────────────────────────


def _find_bash() -> str | None:
    """Return a usable bash executable path, or None."""
    candidates = ["bash"]
    if sys.platform == "win32":
        # git-bash ships with git for windows; check common install paths.
        candidates += [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
        ]
    for cand in candidates:
        found = shutil.which(cand) if "/" not in cand and "\\" not in cand else cand
        if found and Path(found).exists():
            return found
    return None


BASH = _find_bash()
pytestmark = pytest.mark.skipif(
    BASH is None,
    reason="bash not available on this platform; publish-mirror is a bash script",
)


# ─── fixture helpers ────────────────────────────────────────────────


def _git(cwd: Path, *args: str, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run `git <args>` in cwd. Returns the CompletedProcess."""
    full_env = os.environ.copy()
    # Pin a deterministic identity so commits succeed in CI.
    full_env.setdefault("GIT_AUTHOR_NAME", "Test")
    full_env.setdefault("GIT_AUTHOR_EMAIL", "test@example.com")
    full_env.setdefault("GIT_COMMITTER_NAME", "Test")
    full_env.setdefault("GIT_COMMITTER_EMAIL", "test@example.com")
    if env:
        full_env.update(env)
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=full_env,
        check=check,
        capture_output=True,
        text=True,
    )


def _run_script(cwd: Path, *args: str, stdin: str = "") -> subprocess.CompletedProcess:
    """Run publish-public-mirror.sh in cwd with the given args + stdin."""
    cmd = [BASH, str(SCRIPT_PATH), *args]
    return subprocess.run(
        cmd,
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        # The script reads $0 to print --help — passing absolute path is fine.
    )


def _make_fixture(tmp_path: Path, *, clean: bool = True, on_main: bool = True,
                  with_remote: bool = True, with_patterns: bool = True,
                  bundle_content: str = "hello world\n") -> tuple[Path, Path]:
    """Build a fresh fixture and return (private_repo, public_bare_repo).

    Steps:
      1. Init `private/` as a non-bare repo; first commit on main.
      2. Init `public/` as a bare repo.
      3. Register `public-mirror` remote on private repo (unless
         `with_remote=False`).
      4. Copy the real scrub patterns file (or a stub) into the
         fixture so the script's `[ -f $patterns ]` check passes.
      5. Add a second commit containing `bundle_content` (which the
         test may use to seed scrub findings).
      6. Optionally introduce a dirty file (`clean=False`) or
         switch off main (`on_main=False`).
    """
    private = tmp_path / "private"
    public = tmp_path / "public"
    private.mkdir()
    public.mkdir()

    # Bare public repo first.
    _git(public, "init", "--bare", "-b", "main")

    # Non-bare private repo.
    _git(private, "init", "-b", "main")
    (private / "README.md").write_text("Test project\n", encoding="utf-8")
    _git(private, "add", "README.md")
    _git(private, "commit", "-m", "initial commit")

    # Copy script + patterns from real repo. The script is read via
    # absolute path (SCRIPT_PATH) — but it reads PATTERNS_FILE
    # relative to `git rev-parse --show-toplevel`, so the patterns
    # file MUST live inside the fixture's private repo.
    (private / "scripts").mkdir()
    (private / "docs").mkdir()
    if with_patterns:
        # Use a tailored catalogue so we control what matches.
        # Includes a SHAPE-only pattern that the bundle commit will
        # match — synthetic content "SECRET_TOKEN_SHAPE_xxx".
        (private / "scripts" / "publish-scrub-patterns.txt").write_text(
            "# test catalogue\n"
            "# Synthetic pattern used by the scrub-match test:\n"
            "SECRET_TOKEN_SHAPE_[A-Z0-9]+\n",
            encoding="utf-8",
        )

    # Add a second commit so there's something to publish.
    (private / "feature.txt").write_text(bundle_content, encoding="utf-8")
    _git(private, "add", "feature.txt")
    _git(private, "commit", "-m", "add feature")

    # Wire the remote.
    if with_remote:
        _git(private, "remote", "add", "public-mirror", str(public))

    # Switch off main if requested.
    if not on_main:
        _git(private, "checkout", "-b", "feature-branch")

    # Introduce dirty content if requested.
    if not clean:
        (private / "dirty.txt").write_text("uncommitted\n", encoding="utf-8")
        _git(private, "add", "dirty.txt")
        # Don't commit — leave staged so the diff --cached check fires.

    return private, public


# ─── tests ─────────────────────────────────────────────────────────


def test_dirty_tree_aborts(tmp_path: Path) -> None:
    private, _ = _make_fixture(tmp_path, clean=False)
    result = _run_script(private)
    assert result.returncode == 64, (
        f"expected exit 64 for dirty tree, got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "dirty" in result.stderr.lower() or "dirty" in result.stdout.lower()


def test_not_on_main_aborts(tmp_path: Path) -> None:
    private, _ = _make_fixture(tmp_path, on_main=False)
    result = _run_script(private)
    assert result.returncode == 64
    combined = result.stdout + result.stderr
    assert "main" in combined.lower()
    assert "feature-branch" in combined


def test_no_public_mirror_remote_aborts_with_instructions(tmp_path: Path) -> None:
    private, _ = _make_fixture(tmp_path, with_remote=False)
    result = _run_script(private)
    assert result.returncode == 65
    combined = result.stdout + result.stderr
    assert "public-mirror" in combined
    # The error message should include the operator's setup hint.
    assert "git remote add" in combined


def test_missing_patterns_file_aborts(tmp_path: Path) -> None:
    private, _ = _make_fixture(tmp_path, with_patterns=False)
    result = _run_script(private)
    assert result.returncode == 66
    combined = result.stdout + result.stderr
    assert "publish-scrub-patterns.txt" in combined


def test_scrub_match_aborts_when_operator_does_not_proceed(tmp_path: Path) -> None:
    # Commit content that matches the synthetic pattern in the
    # fixture catalogue.
    private, _ = _make_fixture(
        tmp_path,
        bundle_content="api_key=SECRET_TOKEN_SHAPE_ABC123\n",
    )
    # Operator types anything other than 'proceed' -> abort (exit 68).
    result = _run_script(private, stdin="abort\n")
    assert result.returncode == 68, (
        f"expected exit 68 for operator abort, got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    combined = result.stdout + result.stderr
    assert "SECRET_TOKEN_SHAPE_ABC123" in combined
    # The pattern itself should appear in the findings printout.
    assert "SECRET_TOKEN_SHAPE_[A-Z0-9]+" in combined


def test_scrub_match_proceeds_under_auto_proceed_dry_run(tmp_path: Path) -> None:
    # Same fixture but with --auto-proceed + --dry-run: scrub finds
    # the pattern, the script reports it, then exits 0 without
    # advancing state.
    private, _ = _make_fixture(
        tmp_path,
        bundle_content="api_key=SECRET_TOKEN_SHAPE_DEADBEEF\n",
    )
    result = _run_script(private, "--auto-proceed", "--dry-run")
    assert result.returncode == 0, (
        f"expected exit 0, got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "SECRET_TOKEN_SHAPE_DEADBEEF" in result.stdout + result.stderr
    # Dry-run skips the audit log + ref advance.
    assert not (private / "docs" / "PUBLISH-LOG.md").exists()
    last_ref = _git(private, "rev-parse", "--verify", "--quiet",
                    "refs/publish/last-published", check=False)
    assert last_ref.returncode != 0, "dry-run must not advance the last-published ref"


def test_happy_path_advances_ref_and_appends_log(tmp_path: Path) -> None:
    # Bundle has no scrub matches. Use --auto-proceed --squash for
    # a fully non-interactive run; the script should publish to the
    # bare public remote, advance the ref, and write the audit log.
    private, public = _make_fixture(
        tmp_path,
        bundle_content="boring feature content\n",
    )
    result = _run_script(private, "--auto-proceed", "--squash")
    assert result.returncode == 0, (
        f"expected exit 0, got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    # 1. last-published ref advanced to current HEAD.
    head = _git(private, "rev-parse", "HEAD").stdout.strip()
    last = _git(private, "rev-parse", "refs/publish/last-published").stdout.strip()
    assert head == last, "last-published ref should equal HEAD after successful publish"

    # 2. Public bare repo has commits on main.
    public_log = _git(public, "log", "--oneline", "main").stdout
    assert "publish:" in public_log, (
        f"expected squashed commit on public/main; got:\n{public_log}"
    )

    # 3. PUBLISH-LOG.md created with one entry.
    log_path = private / "docs" / "PUBLISH-LOG.md"
    assert log_path.exists()
    log_text = log_path.read_text(encoding="utf-8")
    assert "# Publish log" in log_text
    assert "squash" in log_text
    # The audit row should record the bundle commit count (1 commit:
    # the "add feature" commit; the initial commit is the parent on
    # private/main and was published as the squash base when no
    # public/main existed yet, so the bundle range is HEAD..HEAD-1
    # = 1 row in the table that is NOT the header).
    rows = [ln for ln in log_text.splitlines() if ln.startswith("| ") and "Date" not in ln and "----" not in ln]
    assert len(rows) == 1, f"expected exactly one audit row; got {len(rows)}:\n{log_text}"


def test_second_publish_only_diffs_forward(tmp_path: Path) -> None:
    # First publish: succeeds. Then add a second commit and publish
    # again — the second run's bundle should be exactly 1 commit
    # (the new one), not the full history.
    private, _ = _make_fixture(tmp_path, bundle_content="first feature\n")

    r1 = _run_script(private, "--auto-proceed", "--squash")
    assert r1.returncode == 0, r1.stderr

    # Add a second commit.
    (private / "feature2.txt").write_text("second feature\n", encoding="utf-8")
    _git(private, "add", "feature2.txt")
    _git(private, "commit", "-m", "add second feature")

    r2 = _run_script(private, "--auto-proceed", "--keep")
    assert r2.returncode == 0, r2.stderr
    # The bundle report should mention "1 commit(s)" (the new one).
    assert "1 commit" in r2.stdout, (
        f"expected bundle of 1 commit on second publish; got:\n{r2.stdout}"
    )


def test_up_to_date_publish_exits_nonzero(tmp_path: Path) -> None:
    # First publish succeeds; immediate re-publish with no new
    # commits should exit 67.
    private, _ = _make_fixture(tmp_path, bundle_content="payload\n")
    r1 = _run_script(private, "--auto-proceed", "--squash")
    assert r1.returncode == 0, r1.stderr

    r2 = _run_script(private, "--auto-proceed", "--squash")
    assert r2.returncode == 67, (
        f"expected exit 67 for up-to-date, got {r2.returncode}\n"
        f"stdout: {r2.stdout}\nstderr: {r2.stderr}"
    )
