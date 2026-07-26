"""Tests for scripts/hooks/_defer_shape_router.py (drive-5 shape router).

Design anchor: ``project_defer_sweep_feeds_defer_gate`` + the drive-5 spec.
Sits between ``_defer_phrase_weights`` (aggregator) and ``defer_gate.py``
(consumer). Pins:

  * Shape -> action mapping for all 8 documented shapes.
  * Backwards-compat fallback when phrase_weights.json is missing
    (BLOCK-all, pre-drive-5 posture).
  * Insufficient-hits fallback (< 5 hits -> BLOCK).
  * Canonicalization via SWEEP_PATTERNS (single-funnel per Prime Directive #5).
  * ``resolve_hits`` severity reduction (any BLOCK > any WARN > all ALLOW).
  * Dominant-shape tie-break is deterministic.
  * defer_gate integration: event-log is still written on WARN / ALLOW so
    the learner corpus keeps growing on non-BLOCK outcomes.

Self-referential note: this file carries defer-language phrases as string
literals. It sits under ``tests/`` matching the ``test_defer_*.py`` prefix,
which is exempt from the defer_gate prose scan.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "scripts" / "hooks"
sys.path.insert(0, str(HOOKS))

import _defer_shape_router as router  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _weights(phrases, verdicts_sha256="0" * 64):
    return {
        "schema_version": 1,
        "computed_at": "2026-07-16T00:00:00",
        "verdicts_file": "defer_sweep/verdicts.jsonl",
        "verdicts_file_sha256": verdicts_sha256,
        "verdicts_row_count": sum(p.get("total_hits", 0) for p in phrases.values()),
        "verdicts_rows_skipped": 0,
        "min_hits": 10,
        "high_rate_threshold": 0.85,
        "low_rate_threshold": 0.15,
        "buckets": {"HIGH_CONF_DEFER": [], "LOW_CONF_NOISE": [], "MIXED": []},
        "phrases": phrases,
    }


def _phrase_entry(shape_distribution, *, is_defer_rate=1.0):
    total = sum(shape_distribution.values())
    return {
        "total_hits": total,
        "is_defer_true": int(total * is_defer_rate),
        "is_defer_rate": is_defer_rate,
        "shape_distribution": shape_distribution,
        "example_snippets": {},
        "classification": "HIGH_CONF_DEFER" if is_defer_rate >= 0.85 else "MIXED",
    }


def _write_weights(tmp_path, phrases):
    """Write phrase_weights.json + a sibling verdicts.jsonl whose sha256 is
    recorded in the weights' provenance field. Necessary since the router's
    _load_weights_cached rejects weights whose verdicts_file_sha256 does not
    match the actual verdicts.jsonl content (DA-F1+F2 poisoning defense,
    46b4f107 batch panel)."""
    import hashlib
    verdicts = tmp_path / "verdicts.jsonl"
    # Any stable non-empty content is fine — the test only needs the hash to match.
    body = b'{"test": "fixture"}\n'
    verdicts.write_bytes(body)
    sha = hashlib.sha256(body).hexdigest()
    p = tmp_path / "phrase_weights.json"
    p.write_text(json.dumps(_weights(phrases, verdicts_sha256=sha)), encoding="utf-8")
    router.clear_cache()
    return p


# ---------------------------------------------------------------------------
# Shape -> action mapping (per drive-5 spec — one test per shape)
# ---------------------------------------------------------------------------

def test_shape_hard_defer_blocks():
    assert router.SHAPE_ACTIONS["hard-defer"] == router.BLOCK


def test_shape_waiting_op_blocks():
    assert router.SHAPE_ACTIONS["waiting-op"] == router.BLOCK


def test_shape_tracked_work_warns():
    assert router.SHAPE_ACTIONS["tracked-work"] == router.WARN


def test_shape_todo_marker_warns():
    assert router.SHAPE_ACTIONS["todo-marker"] == router.WARN


def test_shape_blocked_on_warns():
    assert router.SHAPE_ACTIONS["blocked-on"] == router.WARN


def test_shape_wip_allows():
    assert router.SHAPE_ACTIONS["wip"] == router.ALLOW


def test_shape_meta_doc_allows():
    assert router.SHAPE_ACTIONS["meta-doc"] == router.ALLOW


def test_shape_false_positive_allows():
    assert router.SHAPE_ACTIONS["false-positive"] == router.ALLOW


def test_all_eight_shapes_have_an_action():
    """Structural pin (Prime Directive #1 count-agnostic form): every shape
    documented in the drive-5 spec has a mapped action, and every mapped
    action is one of the three valid values."""
    required = {
        "hard-defer", "waiting-op", "tracked-work", "todo-marker",
        "blocked-on", "wip", "meta-doc", "false-positive",
    }
    assert required.issubset(router.SHAPE_ACTIONS.keys())
    for shape, action in router.SHAPE_ACTIONS.items():
        assert action in (router.BLOCK, router.WARN, router.ALLOW), (
            f"shape {shape!r} maps to unknown action {action!r}"
        )


# ---------------------------------------------------------------------------
# dominant_shape
# ---------------------------------------------------------------------------

def test_dominant_shape_picks_plurality():
    d = {"hard-defer": 10, "meta-doc": 3, "wip": 1}
    assert router.dominant_shape(d) == "hard-defer"


def test_dominant_shape_empty_returns_none():
    assert router.dominant_shape({}) is None


def test_dominant_shape_tie_breaks_alphabetically():
    d = {"wip": 5, "meta-doc": 5}
    # Alphabetical: 'meta-doc' < 'wip'
    assert router.dominant_shape(d) == "meta-doc"


def test_dominant_shape_single_entry():
    assert router.dominant_shape({"tracked-work": 1}) == "tracked-work"


# ---------------------------------------------------------------------------
# canonicalize
# ---------------------------------------------------------------------------

def test_canonicalize_maps_next_drive():
    # SWEEP has next[- ]drive -> canonical "next-drive".
    assert router.canonicalize("next drive") == "next-drive"
    assert router.canonicalize("next-drive") == "next-drive"


def test_canonicalize_maps_todo():
    assert router.canonicalize("TODO") == "TODO"
    assert router.canonicalize("todo") == "TODO"


def test_canonicalize_maps_defer_family():
    assert router.canonicalize("deferred") == "defer"
    assert router.canonicalize("deferring") == "defer"


def test_canonicalize_maps_parked():
    assert router.canonicalize("parked") == "park"


def test_canonicalize_returns_none_on_unknown_phrase():
    # A tight-pattern hit with no SWEEP canonical.
    assert router.canonicalize("xyz-nonexistent-phrase-abc") is None


def test_canonicalize_returns_none_on_empty():
    assert router.canonicalize("") is None


# ---------------------------------------------------------------------------
# resolve_action — fallback ladder
# ---------------------------------------------------------------------------

def test_resolve_action_no_weights_blocks():
    """Fallback #1: weights None -> BLOCK (backwards-compat with pre-drive-5)."""
    action, reason = router.resolve_action("deferred", weights=None)
    assert action == router.BLOCK
    assert "no phrase_weights.json" in reason


def test_resolve_action_uncanonicalizable_blocks():
    """Fallback #2: phrase has no SWEEP canonical -> BLOCK."""
    w = _weights({})
    action, reason = router.resolve_action("xyz-unmatched", weights=w)
    assert action == router.BLOCK
    assert "not in SWEEP taxonomy" in reason


def test_resolve_action_canonical_not_in_weights_blocks():
    """Fallback #3: canonical missing from weights -> BLOCK."""
    w = _weights({})
    action, reason = router.resolve_action("deferred", weights=w)
    assert action == router.BLOCK
    assert "not in phrase_weights.json" in reason


def test_resolve_action_insufficient_hits_blocks():
    """Fallback #4: total_hits < MIN_HITS_FOR_ROUTING -> BLOCK."""
    w = _weights({
        "defer": _phrase_entry({"wip": 3}),   # only 3 hits, threshold is 20 (DA-F5)
    })
    action, reason = router.resolve_action("deferred", weights=w)
    assert action == router.BLOCK
    assert "3 hits" in reason


def test_resolve_action_empty_shape_distribution_blocks():
    """Fallback #5: shape_distribution empty -> BLOCK."""
    w = _weights({
        "defer": {"total_hits": 20, "is_defer_true": 20, "is_defer_rate": 1.0,
                  "shape_distribution": {}, "example_snippets": {},
                  "classification": "HIGH_CONF_DEFER"},
    })
    action, reason = router.resolve_action("deferred", weights=w)
    assert action == router.BLOCK
    assert "empty shape_distribution" in reason


def test_resolve_action_unknown_dominant_shape_blocks():
    """Fallback #6: dominant shape not in SHAPE_ACTIONS -> BLOCK."""
    w = _weights({
        "defer": _phrase_entry({"brand-new-shape": 20}),
    })
    action, reason = router.resolve_action("deferred", weights=w)
    assert action == router.BLOCK
    assert "not in SHAPE_ACTIONS" in reason


# ---------------------------------------------------------------------------
# resolve_action — happy paths (one per shape, sufficient hits)
# ---------------------------------------------------------------------------

def _happy_weights(shape, n=20):
    return _weights({"defer": _phrase_entry({shape: n})})


def test_resolve_action_hard_defer_blocks():
    action, reason = router.resolve_action("deferred", weights=_happy_weights("hard-defer"))
    assert action == router.BLOCK
    assert "hard-defer" in reason


def test_resolve_action_waiting_op_blocks():
    action, reason = router.resolve_action("deferred", weights=_happy_weights("waiting-op"))
    assert action == router.BLOCK
    assert "waiting-op" in reason


def test_resolve_action_tracked_work_warns_with_hint():
    action, reason = router.resolve_action("deferred", weights=_happy_weights("tracked-work"))
    assert action == router.WARN
    assert "tracked-work" in reason
    assert "the backlog" in reason  # hint text


def test_resolve_action_todo_marker_warns():
    action, reason = router.resolve_action("deferred", weights=_happy_weights("todo-marker"))
    assert action == router.WARN
    assert "todo-marker" in reason


def test_resolve_action_blocked_on_warns():
    action, reason = router.resolve_action("deferred", weights=_happy_weights("blocked-on"))
    assert action == router.WARN
    assert "blocked-on" in reason


def test_resolve_action_wip_allows_silently():
    action, reason = router.resolve_action("deferred", weights=_happy_weights("wip"))
    assert action == router.ALLOW
    assert "wip" in reason


def test_resolve_action_meta_doc_allows():
    action, reason = router.resolve_action("deferred", weights=_happy_weights("meta-doc"))
    assert action == router.ALLOW
    assert "meta-doc" in reason


def test_resolve_action_false_positive_allows():
    action, reason = router.resolve_action("deferred", weights=_happy_weights("false-positive"))
    assert action == router.ALLOW
    assert "false-positive" in reason


# ---------------------------------------------------------------------------
# resolve_action — plurality wins on mixed distribution
# ---------------------------------------------------------------------------

def test_resolve_action_plurality_wins_meta_doc():
    """A phrase with mostly meta-doc verdicts but a few hard-defer routes
    to ALLOW (meta-doc dominates)."""
    w = _weights({
        "defer": _phrase_entry({"meta-doc": 24, "hard-defer": 3, "wip": 2}),
    })
    action, reason = router.resolve_action("deferred", weights=w)
    assert action == router.ALLOW
    assert "meta-doc" in reason


def test_resolve_action_plurality_hard_defer_blocks():
    """Inverse: mostly hard-defer with some meta-doc still BLOCKs."""
    w = _weights({
        "defer": _phrase_entry({"hard-defer": 20, "meta-doc": 4}),
    })
    action, reason = router.resolve_action("deferred", weights=w)
    assert action == router.BLOCK
    assert "hard-defer" in reason


# ---------------------------------------------------------------------------
# resolve_hits — severity reduction
# ---------------------------------------------------------------------------

def test_resolve_hits_empty_list_allows(tmp_path):
    _write_weights(tmp_path, {})
    action, details = router.resolve_hits([], weights_path=tmp_path / "phrase_weights.json")
    assert action == router.ALLOW
    assert details == []


def test_resolve_hits_all_allow_returns_allow(tmp_path):
    p = _write_weights(tmp_path, {
        "defer": _phrase_entry({"wip": 20}),
        "TODO": _phrase_entry({"meta-doc": 20}),
    })
    action, details = router.resolve_hits(["deferred", "TODO"], weights_path=p)
    assert action == router.ALLOW
    assert len(details) == 2
    for _, act, _ in details:
        assert act == router.ALLOW


def test_resolve_hits_any_warn_returns_warn(tmp_path):
    p = _write_weights(tmp_path, {
        "defer": _phrase_entry({"wip": 20}),
        "TODO":  _phrase_entry({"tracked-work": 20}),
    })
    action, _ = router.resolve_hits(["deferred", "TODO"], weights_path=p)
    assert action == router.WARN


def test_resolve_hits_any_block_returns_block(tmp_path):
    p = _write_weights(tmp_path, {
        "defer": _phrase_entry({"wip": 20}),
        "TODO":  _phrase_entry({"tracked-work": 20}),
        "park":  _phrase_entry({"hard-defer": 20}),
    })
    action, _ = router.resolve_hits(["deferred", "TODO", "parked"], weights_path=p)
    assert action == router.BLOCK


def test_resolve_hits_missing_weights_file_blocks_all(tmp_path):
    """Backwards-compat: no phrase_weights.json -> BLOCK matches pre-drive-5 posture."""
    router.clear_cache()
    action, details = router.resolve_hits(
        ["deferred", "TODO"], weights_path=tmp_path / "does_not_exist.json"
    )
    assert action == router.BLOCK
    assert all(a == router.BLOCK for _, a, _ in details)


def test_resolve_hits_unparseable_weights_file_blocks_all(tmp_path):
    """A corrupt weights file loads as None -> same BLOCK fallback as missing."""
    bad = tmp_path / "phrase_weights.json"
    bad.write_text("not{valid-json", encoding="utf-8")
    router.clear_cache()
    action, _ = router.resolve_hits(["deferred"], weights_path=bad)
    assert action == router.BLOCK


# ---------------------------------------------------------------------------
# warn_message formatting
# ---------------------------------------------------------------------------

def test_warn_message_names_each_phrase():
    details = [
        ("deferred", router.WARN, "defer:tracked-work — add to the backlog as tracked"),
        ("TODO", router.WARN, "TODO:todo-marker — prefer a the backlog row over an inline TODO"),
    ]
    msg = router.warn_message("prose defer-language", details)
    assert "deferred" in msg
    assert "TODO" in msg
    assert "WARN" in msg
    assert "prose defer-language" in msg


# ---------------------------------------------------------------------------
# load_weights caching
# ---------------------------------------------------------------------------

def test_load_weights_cached(tmp_path):
    p = _write_weights(tmp_path, {"defer": _phrase_entry({"wip": 20})})
    first = router.load_weights(p)
    second = router.load_weights(p)
    assert first is second  # same object -> cache hit


def test_clear_cache_reloads(tmp_path):
    p = _write_weights(tmp_path, {"defer": _phrase_entry({"wip": 20})})
    first = router.load_weights(p)
    router.clear_cache()
    second = router.load_weights(p)
    assert first is not second  # cache cleared -> fresh load
    assert first == second       # contents identical


# ---------------------------------------------------------------------------
# Integration with defer_gate.py — event log still written on WARN / ALLOW
# ---------------------------------------------------------------------------

def _run_gate(payload, cwd):
    """Run defer_gate.main() with a synthetic PreToolUse payload and capture
    (exit_code, stdout, stderr). Uses subprocess so exit(0) / exit(2) are
    observable, matches the real hook invocation shape."""
    import os
    import subprocess
    r = subprocess.run(
        [sys.executable, str(HOOKS / "defer_gate.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env={**os.environ, "PYTHONPATH": str(HOOKS)},
        timeout=20,
    )
    return r.returncode, r.stdout, r.stderr


def _init_git_repo(cwd):
    """Init a throwaway git repo with a commit. defer_gate's
    _is_baseline_or_earlier check will fail against GATE_BASELINE (which
    doesn't exist in this fresh repo) — so HEAD is treated as post-baseline
    and the gate is live."""
    import subprocess

    def run(*args):
        subprocess.run(args, cwd=cwd, check=True, capture_output=True)

    run("git", "init", "-q", "-b", "main")
    run("git", "config", "user.email", "test@example.com")
    run("git", "config", "user.name", "test")
    (cwd / "seed.txt").write_text("seed\n", encoding="utf-8")
    run("git", "add", "seed.txt")
    run("git", "commit", "-q", "-m", "seed")


def test_event_log_written_on_warn(tmp_path, monkeypatch):
    """A WARN outcome MUST still write to the event log — the learner needs
    the corpus to keep growing on non-BLOCK routing outcomes."""
    cwd = tmp_path / "repo"
    cwd.mkdir()
    _init_git_repo(cwd)

    import hashlib
    weights_dir = cwd / "defer_sweep"
    weights_dir.mkdir()
    verdicts_body = b'{"stub": "fixture"}\n'
    (weights_dir / "verdicts.jsonl").write_bytes(verdicts_body)
    sha = hashlib.sha256(verdicts_body).hexdigest()
    (weights_dir / "phrase_weights.json").write_text(
        json.dumps(_weights({
            "defer": _phrase_entry({"tracked-work": 20}),
            "TODO": _phrase_entry({"tracked-work": 20}),
        }, verdicts_sha256=sha)),
        encoding="utf-8",
    )

    # Route event log to a scratch dir so we don't clobber the user's real log.
    log_home = tmp_path / "fake_home"
    log_home.mkdir()
    monkeypatch.setenv("HOME", str(log_home))
    monkeypatch.setenv("USERPROFILE", str(log_home))

    target = cwd / "notes.md"
    # "TODO defer" hits the tight _PATTERNS (regex \bTODO:?\s*defer\b) so
    # new_defer_phrases returns a hit. That hit canonicalizes via SWEEP
    # \bTODO\b to canonical "TODO", which the mock weights map to
    # tracked-work -> WARN.
    payload = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": str(target),
            "content": "TODO defer this cleanup for now.\n",
        },
        "cwd": str(cwd),
    }
    rc, out, err = _run_gate(payload, cwd)

    assert rc == 0, f"expected WARN=allow (exit 0), got {rc}\nstdout={out}\nstderr={err}"
    assert "WARN" in err, f"expected WARN in stderr, got: {err}"

    log = log_home / ".the AI assistant" / "defer_gate_events.jsonl"
    assert log.exists(), f"event log NOT written on WARN: {log}"
    lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines, "event log empty on WARN"
    entry = json.loads(lines[0])
    assert entry["surface"] == "prose"


def test_event_log_written_on_allow(tmp_path, monkeypatch):
    """An ALLOW outcome (silent) still writes to the event log."""
    cwd = tmp_path / "repo"
    cwd.mkdir()
    _init_git_repo(cwd)

    import hashlib
    weights_dir = cwd / "defer_sweep"
    weights_dir.mkdir()
    verdicts_body = b'{"stub": "fixture"}\n'
    (weights_dir / "verdicts.jsonl").write_bytes(verdicts_body)
    sha = hashlib.sha256(verdicts_body).hexdigest()
    (weights_dir / "phrase_weights.json").write_text(
        json.dumps(_weights({
            "defer": _phrase_entry({"wip": 20}),
            "TODO": _phrase_entry({"wip": 20}),
        }, verdicts_sha256=sha)),
        encoding="utf-8",
    )

    log_home = tmp_path / "fake_home"
    log_home.mkdir()
    monkeypatch.setenv("HOME", str(log_home))
    monkeypatch.setenv("USERPROFILE", str(log_home))

    target = cwd / "notes.md"
    # Same "TODO defer" hit as the WARN test — mock weights this time map
    # TODO to shape=wip which routes to ALLOW.
    payload = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": str(target),
            "content": "TODO defer this cleanup for now.\n",
        },
        "cwd": str(cwd),
    }
    rc, out, err = _run_gate(payload, cwd)
    assert rc == 0
    # ALLOW is silent — no WARN banner.
    assert "WARN" not in err

    log = log_home / ".the AI assistant" / "defer_gate_events.jsonl"
    assert log.exists(), "event log NOT written on ALLOW"
    lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines


def test_backwards_compat_no_weights_file_still_blocks(tmp_path, monkeypatch):
    """Without any phrase_weights.json, the gate behaves identically to
    pre-drive-5: a NEW prose defer phrase demands YubiKey approval (which
    isn't present in this test) -> DENY (exit 2)."""
    cwd = tmp_path / "repo"
    cwd.mkdir()
    _init_git_repo(cwd)
    # NO defer_sweep/phrase_weights.json created.

    log_home = tmp_path / "fake_home"
    log_home.mkdir()
    monkeypatch.setenv("HOME", str(log_home))
    monkeypatch.setenv("USERPROFILE", str(log_home))

    target = cwd / "notes.md"
    # Phrase chosen so tight _PATTERNS in _defer_phrases fires: this exact
    # sentence has the "TODO defer" idiom that is on the gate-tight list.
    payload = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": str(target),
            "content": "TODO defer this to a later drive.\n",
        },
        "cwd": str(cwd),
    }
    rc, _out, err = _run_gate(payload, cwd)
    assert rc == 2, f"expected DENY (exit 2), got {rc}\nstderr={err}"
    assert "defer-gate" in err.lower()


def test_default_weights_path_respects_cwd_git_boundary(tmp_path, monkeypatch):
    """Regression pin for the cwd-git-boundary escape bug (2026-07-23).

    Before the fix, ``_default_weights_path()`` first tried
    ``$CWD/defer_sweep/phrase_weights.json`` (absent), then fell back to
    ``_repo_root()`` which walks up from ``__file__`` — escaping any
    tmp-git-repo cwd used by tests and returning the REAL repo's weights
    file. Result: the "no phrase_weights.json present -> BLOCK" contract
    was untestable in isolation; ``test_backwards_compat_no_weights_file_still_blocks``
    would fail locally when the real repo shipped a phrase_weights.json
    classifying the test's target phrase as WARN / ALLOW.

    Fix: if cwd itself contains a ``.git``, treat it as the repo boundary
    and return a NON-EXISTENT weights path (so the caller's None check
    fires the fail-CLOSED BLOCK branch), rather than walking past cwd to
    ``__file__``'s real repo root.
    """
    fake_repo = tmp_path / "fake-repo"
    fake_repo.mkdir()
    (fake_repo / ".git").mkdir()  # sentinel — mimic a git repo

    monkeypatch.chdir(fake_repo)
    resolved = router._default_weights_path()
    # Must NOT escape to the real repo's phrase_weights.json.
    assert not resolved.exists(), (
        f"cwd-git-boundary escape: _default_weights_path resolved to "
        f"{resolved!r} which exists — must return a non-existent path so "
        f"the caller's None check fires fail-CLOSED BLOCK"
    )
    # Must point at the cwd's would-be weights path, not the real repo's.
    assert resolved == fake_repo / "defer_sweep" / "phrase_weights.json"
