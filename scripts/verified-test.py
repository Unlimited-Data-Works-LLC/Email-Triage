#!/usr/bin/env python3
"""C2 companion — verified-test wrapper.

Runs pytest and writes `.evidence/<id>.json` recording:
  * command (verbatim pytest args)
  * exit code
  * passed / failed / skipped counts (scraped from pytest summary)
  * staged diff sha256 at time of run
  * timestamp (ISO8601 UTC)

The `evidence_bound_claim_gate.py` PreToolUse hook reads `.evidence/`
on `git commit` and DENIES messages that assert success tokens
(`verified`, `N/N`, `green`, `passes`, `imports clean`, `all pass`)
without a matching evidence file whose diff-sha matches the staged
diff.

Usage
-----
Instead of `pytest tests/foo -q`, run:
    python scripts/verified-test.py tests/foo -q

The script forwards all args to pytest, prints its output live, and
writes the evidence artifact regardless of pass/fail. Use it just as
you'd use pytest.

The evidence artifact id is `<staged-diff-sha[:12]>-<utc-timestamp>`,
so multiple runs against the same staged diff DO produce distinct
artifacts (a re-run after a fix is a separate evidence event).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_RATCHET_GLOBS = ("test_n*_*_ratchet_pin.py", "test_n*_*_ssot_pin.py")


def _staged_touches_src(cwd: str) -> bool:
    try:
        r = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=cwd, capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return False
        for line in r.stdout.splitlines():
            if line.startswith("src/"):
                return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _cross_cutting_pin_files(cwd: str) -> list[str]:
    tests_dir = Path(cwd) / "tests"
    if not tests_dir.is_dir():
        return []
    out: set[str] = set()
    for pattern in _RATCHET_GLOBS:
        for p in tests_dir.glob(pattern):
            out.add(p.as_posix())
    return sorted(out)


def _augment_args_with_ratchet_sweep(pytest_args: list[str], cwd: str) -> tuple[list[str], list[str]]:
    """Return (augmented_args, added_paths). Adds cross-cutting ratchet+SSOT
    pin files to pytest_args when the staged diff touches src/ (per
    feedback_pre_push_ratchet_pin_sweep). Bypass with VERIFIED_TEST_NO_AUTO=1.
    De-duplicates against paths already present in pytest_args."""
    if os.environ.get("VERIFIED_TEST_NO_AUTO") == "1":
        return list(pytest_args), []
    if not _staged_touches_src(cwd):
        return list(pytest_args), []
    already = {a for a in pytest_args if a.endswith(".py")}
    to_add = [p for p in _cross_cutting_pin_files(cwd) if p not in already]
    return list(pytest_args) + to_add, to_add


def _staged_diff_sha(cwd: str) -> str:
    try:
        r = subprocess.run(
            ["git", "diff", "--cached"],
            cwd=cwd, capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return ""
        return hashlib.sha256(r.stdout.encode("utf-8")).hexdigest()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _scrape_pytest_counts(output: str) -> dict[str, int]:
    """Scrape pytest summary line. Matches BOTH forms:
    - verbose:  `======= 3 failed, 45 passed, 2 skipped in 1.5s =======`
    - quiet:    `3 failed, 45 passed, 2 skipped in 1.5s`
    `-q` mode strips the `====` decoration, so the anchors are optional.
    """
    counts: dict[str, int] = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
    # Scan every candidate line for `<n> <kind>[, <n> <kind>…] in <secs>s`.
    # Take the LAST match (pytest summary is always the last such line).
    matches = re.findall(
        r"((?:\d+\s+\w+(?:,\s+)?)+)\s+in\s+[\d.]+s",
        output,
    )
    if not matches:
        return counts
    for chunk in matches[-1].split(","):
        chunk = chunk.strip()
        m2 = re.match(r"(\d+)\s+(\w+)", chunk)
        if not m2:
            continue
        n, kind = int(m2.group(1)), m2.group(2).lower()
        if kind in counts:
            counts[kind] = n
    return counts


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit("usage: python scripts/verified-test.py <pytest args…>")

    cwd = os.getcwd()
    diff_sha = _staged_diff_sha(cwd)

    pytest_args = sys.argv[1:]
    pytest_args, ratchet_added = _augment_args_with_ratchet_sweep(pytest_args, cwd)
    if ratchet_added:
        sys.stderr.write(
            f"[verified-test] staged diff touches src/ — auto-including "
            f"{len(ratchet_added)} cross-cutting ratchet/SSOT pin(s) "
            f"(bypass: VERIFIED_TEST_NO_AUTO=1)\n"
        )
    env = dict(os.environ)
    env.setdefault("PYTHONUTF8", "1")

    proc = subprocess.Popen(
        [sys.executable, "-m", "pytest", *pytest_args],
        cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    lines: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line)
    rc = proc.wait()
    output = "".join(lines)

    counts = _scrape_pytest_counts(output)
    now = datetime.datetime.now(datetime.timezone.utc)
    eid = f"{diff_sha[:12]}-{int(now.timestamp())}"

    evidence = {
        "id": eid,
        "command": ["pytest", *pytest_args],
        "exit_code": rc,
        "counts": counts,
        "diff_sha": diff_sha,
        "timestamp": now.isoformat(),
        "ratchet_auto_included": ratchet_added,
    }

    dst = Path(cwd) / ".evidence" / f"{eid}.json"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    sys.stderr.write(
        f"\n[verified-test] evidence written: {dst.relative_to(cwd)}\n"
        f"  exit_code = {rc}\n"
        f"  counts    = {counts}\n"
        f"  diff_sha  = {diff_sha[:16]}…\n"
    )
    return rc


if __name__ == "__main__":
    sys.exit(main())
