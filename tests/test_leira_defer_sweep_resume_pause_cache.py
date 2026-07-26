"""Unit tests for scripts/leira_defer_sweep.py — resume-skip, pause-sentinel,
extract-cache (per-file + commit-log delta), verdict-shape guard, cooldown gate,
and append-mode verdicts SSOT.

Pins the resumability + cache behavior introduced in the 2026-07-15 commits
(5d5ba8f4 refactor(llm-host): apply pattern_leira_offload_stack, d57d1b65 chore
save llm-host defer-sweep script, 3180ae3c task  bundle) so a future edit that
breaks any of the eight documented properties (append-mode SSOT, malformed-line
fail-open, pause-file break at batch boundary, cooldown short-circuit, extract
manifest stat-key match, commit-log delta on head-advance, force-env bypass,
per-element verdict coercion) fails a targeted test rather than a full sweep.

Follows tests/test_leira_prepass_resilience.py — fresh module import per test
with TEMP + LEIRA_CONTEXT_TOKENS + LEIRA_MODEL env scoped BEFORE import so no
HTTP probe fires and the leira_prepass cooldown sidecar stays under tmp_path.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import time
from pathlib import Path

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


def _fresh_import(tmp_path, monkeypatch, *, extract_force_env: str = ""):
    """Delete + reimport BOTH leira_defer_sweep and leira_prepass with env set,
    so import-time HTTP is skipped and the cooldown sidecar lives under tmp_path.
    Returns the freshly-imported leira_defer_sweep module."""
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("LEIRA_CONTEXT_TOKENS", "8192")
    monkeypatch.setenv("LEIRA_MODEL", "qwen3.6:35b")
    monkeypatch.setenv("LEIRA_URL", "http://127.0.0.1:1/api/chat")
    monkeypatch.setenv("LEIRA_MAX_BATCHES", "0")
    monkeypatch.setenv("LEIRA_SWEEP_LIMIT", "0")
    monkeypatch.setenv("LEIRA_EXTRACT_FORCE", extract_force_env)
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    for name in ("leira_defer_sweep", "leira_prepass"):
        if name in sys.modules:
            del sys.modules[name]
    return importlib.import_module("leira_defer_sweep")


@pytest.fixture
def lds(tmp_path, monkeypatch):
    """Fresh leira_defer_sweep with data-dir + REPO + SESSION_DIR redirected
    under tmp_path. Path constants monkeypatched AFTER import so the real
    defer_sweep/ at repo root is never touched by test writes."""
    mod = _fresh_import(tmp_path, monkeypatch)

    data_dir = tmp_path / "defer_sweep"
    data_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(mod, "_DATA_DIR", data_dir)
    monkeypatch.setattr(mod, "_VERDICTS_PATH", data_dir / "verdicts.jsonl")
    monkeypatch.setattr(mod, "_PAUSE_PATH", data_dir / ".pause")
    monkeypatch.setattr(mod, "_EXTRACT_MANIFEST_PATH", data_dir / "extract-manifest.json")
    monkeypatch.setattr(mod, "_EXTRACT_CACHE_PATH", data_dir / "extract-cache.jsonl")
    monkeypatch.setattr(mod, "_PUNCH_ROWS", None)

    session_dir = tmp_path / "sessions"
    session_dir.mkdir(exist_ok=True)
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(mod, "SESSION_DIR", session_dir)
    monkeypatch.setattr(mod, "REPO", repo_dir)

    return mod


@pytest.fixture
def lds_with_scaffold(lds, monkeypatch):
    """lds + main()-safe stubs: cooldown clear, git head sha stubbed, the backlog
    empty, extract_from_commits a no-op, judge_batch a recorder returning valid
    dict verdicts. Individual tests override any of these before calling main()."""
    monkeypatch.setattr(lds, "leira_in_cooldown", lambda: (False, 0.0))
    monkeypatch.setattr(lds, "_git_head_sha", lambda: "testsha00")
    monkeypatch.setattr(lds, "_load_punch_rows", lambda: [])
    monkeypatch.setattr(lds, "extract_from_commits", lambda: [])
    monkeypatch.setattr(lds, "resolve_current_status", lambda item: "unknown")

    seen_batches: list[list[dict]] = []

    def _default_judge(batch):
        seen_batches.append(list(batch))
        return [
            {"is_defer": True, "item": (c.get("phrase_canon") or "x"),
             "shape": "hard-defer"}
            for c in batch
        ]

    monkeypatch.setattr(lds, "judge_batch", _default_judge)
    lds._test_seen_batches = seen_batches
    return lds


# ---------------------------------------------------------------------------
# _verdict_key
# ---------------------------------------------------------------------------

def test_verdict_key_stable_for_same_candidate(lds):
    a = {"phrase_canon": "hold-off", "file": "a.md", "offset": 5,
         "snippet": "one", "source_type": "memory", "phrase": "hold-off"}
    b = {"phrase_canon": "hold-off", "file": "a.md", "offset": 5,
         "snippet": "TOTALLY DIFFERENT", "source_type": "audit",
         "phrase": "hold off"}
    ka = lds._verdict_key(a)
    kb = lds._verdict_key(b)
    assert ka == kb
    assert len(ka) == 40
    assert all(ch in "0123456789abcdef" for ch in ka)


def test_verdict_key_differs_when_file_changes(lds):
    a = {"phrase_canon": "hold-off", "file": "a.md", "offset": 5}
    b = {"phrase_canon": "hold-off", "file": "b.md", "offset": 5}
    assert lds._verdict_key(a) != lds._verdict_key(b)


def test_verdict_key_differs_when_offset_changes(lds):
    a = {"phrase_canon": "hold-off", "file": "a.md", "offset": 0}
    b = {"phrase_canon": "hold-off", "file": "a.md", "offset": 42}
    assert lds._verdict_key(a) != lds._verdict_key(b)


def test_verdict_key_differs_when_phrase_canon_changes(lds):
    a = {"phrase_canon": "hold-off", "file": "a.md", "offset": 5}
    b = {"phrase_canon": "TODO", "file": "a.md", "offset": 5}
    assert lds._verdict_key(a) != lds._verdict_key(b)


def test_verdict_key_defaults_when_keys_missing(lds):
    import hashlib
    key = lds._verdict_key({})
    expected = hashlib.sha1(b"||0").hexdigest()
    assert key == expected


# ---------------------------------------------------------------------------
# _load_prior_verdicts
# ---------------------------------------------------------------------------

def test_load_prior_verdicts_missing_file_returns_empty_tuple(lds, tmp_path):
    p = tmp_path / "nope.jsonl"
    keys, rows = lds._load_prior_verdicts(p)
    assert keys == set()
    assert rows == []
    assert not p.exists()


def test_load_prior_verdicts_empty_file_returns_empty(lds, tmp_path):
    p = tmp_path / "verdicts.jsonl"
    p.write_text("", encoding="utf-8")
    keys, rows = lds._load_prior_verdicts(p)
    assert keys == set()
    assert rows == []


def test_load_prior_verdicts_reads_valid_lines_and_derives_keys(lds, tmp_path):
    p = tmp_path / "verdicts.jsonl"
    row_a = {"phrase_canon": "hold-off", "file": "a.md", "offset": 1, "is_defer": True}
    row_b = {"phrase_canon": "TODO", "file": "b.md", "offset": 2, "is_defer": False}
    row_c = {"phrase_canon": "park", "file": "c.md", "offset": 3, "is_defer": True}
    p.write_text(
        "\n".join(json.dumps(r) for r in (row_a, row_b, row_c)),
        encoding="utf-8",
    )
    keys, rows = lds._load_prior_verdicts(p)
    assert len(rows) == 3
    assert [r["file"] for r in rows] == ["a.md", "b.md", "c.md"]
    assert set(keys) == {lds._verdict_key(row_a),
                         lds._verdict_key(row_b),
                         lds._verdict_key(row_c)}


def test_load_prior_verdicts_skips_malformed_line_between_valid(lds, tmp_path, capsys):
    p = tmp_path / "verdicts.jsonl"
    lines = [
        json.dumps({"phrase_canon": "hold-off", "file": "a.md", "offset": 1}),
        "{not-json-at-all",
        json.dumps({"phrase_canon": "TODO", "file": "b.md", "offset": 2}),
    ]
    p.write_text("\n".join(lines), encoding="utf-8")
    keys, rows = lds._load_prior_verdicts(p)
    assert len(rows) == 2
    assert len(keys) == 2
    assert [r["file"] for r in rows] == ["a.md", "b.md"]
    err = capsys.readouterr().err
    assert "[resume]" in err
    assert "malformed" in err


def test_load_prior_verdicts_tolerates_truncated_last_line(lds, tmp_path):
    p = tmp_path / "verdicts.jsonl"
    p.write_text(
        json.dumps({"phrase_canon": "hold-off", "file": "a.md", "offset": 1})
        + "\n{\"phrase_canon\": \"TODO\", \"file\": \"b.md\", \"offset\":",
        encoding="utf-8",
    )
    keys, rows = lds._load_prior_verdicts(p)
    assert len(rows) == 1
    assert rows[0]["file"] == "a.md"
    assert len(keys) == 1


def test_load_prior_verdicts_skips_blank_lines(lds, tmp_path):
    p = tmp_path / "verdicts.jsonl"
    p.write_text(
        json.dumps({"phrase_canon": "hold-off", "file": "a.md", "offset": 1})
        + "\n\n"
        + json.dumps({"phrase_canon": "TODO", "file": "b.md", "offset": 2}),
        encoding="utf-8",
    )
    keys, rows = lds._load_prior_verdicts(p)
    assert len(rows) == 2
    assert len(keys) == 2


# ---------------------------------------------------------------------------
# _pause_requested
# ---------------------------------------------------------------------------

def test_pause_requested_returns_false_when_absent(lds, tmp_path):
    assert lds._pause_requested(tmp_path / ".pause") is False


def test_pause_requested_returns_true_when_empty_file_present(lds, tmp_path):
    p = tmp_path / ".pause"
    p.write_text("", encoding="utf-8")
    assert lds._pause_requested(p) is True


# ---------------------------------------------------------------------------
# main() — resume-skip / pause / cooldown-gate integration
# ---------------------------------------------------------------------------

def _seed_session_file(session_dir: Path, name: str, texts: list[str]) -> Path:
    """Write a .jsonl file whose text contains defer phrases so extract_from_file
    finds candidates deterministically. Each line is a text snippet with a
    known defer word."""
    p = session_dir / name
    p.write_text("\n".join(texts), encoding="utf-8")
    return p


def test_main_resume_skips_candidates_with_prior_verdicts(lds_with_scaffold, tmp_path, monkeypatch):
    mod = lds_with_scaffold
    session_file = _seed_session_file(
        mod.SESSION_DIR,
        "s.jsonl",
        ["TODO the first thing", "FIXME the second thing"],
    )

    candidates = mod.extract_from_file(session_file, "session")
    assert len(candidates) >= 2
    first_key_target = candidates[0]

    prior = {
        "phrase": first_key_target["phrase"],
        "phrase_canon": first_key_target["phrase_canon"],
        "snippet": first_key_target["snippet"],
        "file": first_key_target["file"],
        "offset": first_key_target["offset"],
        "source_type": "session",
        "is_defer": True,
        "item": "already-judged",
        "shape": "hard-defer",
    }
    mod._VERDICTS_PATH.write_text(json.dumps(prior) + "\n", encoding="utf-8")

    rc = mod.main([])
    assert rc == 0

    seen_offsets = {c["offset"] for batch in mod._test_seen_batches for c in batch}
    assert first_key_target["offset"] not in seen_offsets
    assert len(seen_offsets) >= 1


def test_main_pause_file_stops_at_batch_boundary_with_partial_verdicts(
    lds_with_scaffold, tmp_path, monkeypatch, capsys
):
    mod = lds_with_scaffold
    _seed_session_file(
        mod.SESSION_DIR, "s.jsonl",
        ["TODO one", "FIXME two", "XXX three"],
    )
    mod._PAUSE_PATH.write_text("", encoding="utf-8")

    rc = mod.main([])
    assert rc == 0
    assert mod._VERDICTS_PATH.exists()
    lines = [
        ln for ln in mod._VERDICTS_PATH.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    assert lines == []
    err = capsys.readouterr().err
    assert "pause file detected" in err


def test_main_short_circuits_when_leira_in_cooldown(lds, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(lds, "leira_in_cooldown", lambda: (True, 60.0))

    def _boom(*a, **k):
        raise AssertionError("judge_batch called during cooldown")

    monkeypatch.setattr(lds, "judge_batch", _boom)
    monkeypatch.setattr(lds, "_load_punch_rows", lambda: [])

    rc = lds.main([])
    assert rc == 0
    assert not lds._VERDICTS_PATH.exists()
    assert not (lds._DATA_DIR / "tables.md").exists()
    err = capsys.readouterr().err
    assert "cooldown" in err.lower()
    assert "rm " in err


def test_main_proceeds_past_cooldown_gate_when_not_in_cooldown(
    lds_with_scaffold, tmp_path, monkeypatch
):
    mod = lds_with_scaffold
    _seed_session_file(mod.SESSION_DIR, "s.jsonl", ["TODO one thing"])

    rc = mod.main([])
    assert rc == 0
    assert mod._VERDICTS_PATH.exists()
    verdict_lines = [
        ln for ln in mod._VERDICTS_PATH.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    assert len(verdict_lines) >= 1
    assert (mod._DATA_DIR / "tables.md").exists()


# ---------------------------------------------------------------------------
# _file_stat_key
# ---------------------------------------------------------------------------

def test_file_stat_key_returns_mtime_and_size_tuple(lds, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("hello", encoding="utf-8")
    result = lds._file_stat_key(p)
    st = p.stat()
    assert result == (st.st_mtime_ns, st.st_size)
    assert isinstance(result[0], int)
    assert isinstance(result[1], int)


def test_file_stat_key_missing_file_returns_none(lds, tmp_path):
    assert lds._file_stat_key(tmp_path / "does-not-exist") is None


def test_file_stat_key_size_change_reflected(lds, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("abcde", encoding="utf-8")
    a = lds._file_stat_key(p)
    past = time.time() - 3600
    os.utime(p, (past, past))
    p.write_text("x" * 50, encoding="utf-8")
    b = lds._file_stat_key(p)
    assert a is not None and b is not None
    assert a[1] == 5
    assert b[1] == 50
    assert a[1] != b[1]


# ---------------------------------------------------------------------------
# _git_head_sha
# ---------------------------------------------------------------------------

class _Completed:
    def __init__(self, returncode: int, stdout: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def test_git_head_sha_returns_stripped_stdout_when_git_succeeds(lds, monkeypatch):
    monkeypatch.setattr(
        lds.subprocess, "run",
        lambda *a, **k: _Completed(0, "deadbeefcafe1234\n"),
    )
    assert lds._git_head_sha() == "deadbeefcafe1234"


def test_git_head_sha_nonzero_returncode_returns_none(lds, monkeypatch):
    monkeypatch.setattr(
        lds.subprocess, "run",
        lambda *a, **k: _Completed(128, ""),
    )
    assert lds._git_head_sha() is None


def test_git_head_sha_oserror_returns_none(lds, monkeypatch):
    def _raise(*a, **k):
        raise OSError("git: command not found")

    monkeypatch.setattr(lds.subprocess, "run", _raise)
    assert lds._git_head_sha() is None


def test_git_head_sha_empty_stdout_returns_none(lds, monkeypatch):
    monkeypatch.setattr(
        lds.subprocess, "run",
        lambda *a, **k: _Completed(0, ""),
    )
    assert lds._git_head_sha() is None


# ---------------------------------------------------------------------------
# extract-manifest
# ---------------------------------------------------------------------------

def test_load_extract_manifest_missing_returns_empty_dict(lds):
    assert lds._load_extract_manifest() == {}


def test_manifest_save_load_roundtrip_preserves_structure(lds):
    original = {"a.md": {"mtime_ns": 1, "size_bytes": 2}}
    lds._save_extract_manifest(original)
    loaded = lds._load_extract_manifest()
    assert loaded == original
    assert not lds._EXTRACT_MANIFEST_PATH.with_suffix(".json.tmp").exists()
    on_disk = lds._EXTRACT_MANIFEST_PATH.read_text(encoding="utf-8")
    assert "\n  " in on_disk


def test_load_extract_manifest_malformed_json_returns_empty(lds, capsys):
    lds._EXTRACT_MANIFEST_PATH.write_text("{not-json", encoding="utf-8")
    result = lds._load_extract_manifest()
    assert result == {}
    err = capsys.readouterr().err
    assert "[extract-cache] manifest unreadable" in err


def test_load_extract_manifest_force_env_returns_empty_even_when_file_valid(
    lds, capsys, monkeypatch
):
    lds._EXTRACT_MANIFEST_PATH.write_text(
        json.dumps({"x.md": {"mtime_ns": 1, "size_bytes": 2}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(lds, "_EXTRACT_FORCE", True)
    result = lds._load_extract_manifest()
    assert result == {}
    err = capsys.readouterr().err
    assert "LEIRA_EXTRACT_FORCE=1" in err
    assert "ignoring manifest" in err


@pytest.mark.parametrize(
    "env_value,expected",
    [
        ("1", True),
        ("true", True),
        ("True", True),
        ("yes", True),
        ("arbitrary", True),
        ("", False),
        ("0", False),
        ("false", False),
        ("False", False),
    ],
)
def test_extract_force_env_parses_truthy_and_falsy_values(
    tmp_path, monkeypatch, env_value, expected
):
    mod = _fresh_import(tmp_path, monkeypatch, extract_force_env=env_value)
    assert mod._EXTRACT_FORCE is expected


def test_save_extract_manifest_atomic_no_tmp_leak_on_success(lds):
    lds._save_extract_manifest({"k": "v"})
    assert lds._EXTRACT_MANIFEST_PATH.exists()
    assert json.loads(
        lds._EXTRACT_MANIFEST_PATH.read_text(encoding="utf-8")
    ) == {"k": "v"}
    assert not lds._EXTRACT_MANIFEST_PATH.with_suffix(".json.tmp").exists()


# ---------------------------------------------------------------------------
# extract-cache (per-source rows JSONL)
# ---------------------------------------------------------------------------

def test_load_extract_cache_missing_returns_empty(lds):
    assert lds._load_extract_cache() == {}
    assert not lds._EXTRACT_CACHE_PATH.exists()


def test_load_extract_cache_buckets_rows_by_file_field(lds, capsys):
    rows = [
        {"file": "a.md", "phrase": "TODO", "phrase_canon": "TODO", "snippet": "x",
         "offset": 0, "source_type": "memory"},
        {"file": "a.md", "phrase": "FIXME", "phrase_canon": "FIXME", "snippet": "y",
         "offset": 10, "source_type": "memory"},
        {"file": "b.md", "phrase": "FIXME", "phrase_canon": "FIXME", "snippet": "z",
         "offset": 5, "source_type": "audit"},
    ]
    lds._EXTRACT_CACHE_PATH.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )
    buckets = lds._load_extract_cache()
    assert set(buckets.keys()) == {"a.md", "b.md"}
    assert len(buckets["a.md"]) == 2
    assert [r["offset"] for r in buckets["a.md"]] == [0, 10]
    assert len(buckets["b.md"]) == 1
    err = capsys.readouterr().err
    assert "loaded 3 rows" in err


def test_load_extract_cache_commit_rows_collapse_to_commit_log_bucket(lds):
    rows = [
        {"file": "commit:abc123", "phrase_canon": "TODO", "snippet": "x",
         "offset": 0, "source_type": "commit"},
        {"file": "commit:def456", "phrase_canon": "TODO", "snippet": "y",
         "offset": 5, "source_type": "commit"},
    ]
    lds._EXTRACT_CACHE_PATH.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )
    buckets = lds._load_extract_cache()
    assert list(buckets.keys()) == ["__commit_log__"]
    assert len(buckets["__commit_log__"]) == 2
    assert "commit:abc123" not in buckets
    assert "commit:def456" not in buckets


def test_load_extract_cache_skips_malformed_lines_fail_open(lds, capsys):
    lds._EXTRACT_CACHE_PATH.write_text(
        json.dumps({"file": "a.md", "phrase_canon": "TODO", "offset": 0}) + "\n"
        + "not-json-at-all\n"
        + json.dumps({"file": "b.md", "phrase_canon": "FIXME", "offset": 1}) + "\n",
        encoding="utf-8",
    )
    buckets = lds._load_extract_cache()
    total = sum(len(v) for v in buckets.values())
    assert total == 2
    err = capsys.readouterr().err
    assert "[extract-cache] cache line 2 malformed" in err


def test_load_extract_cache_force_env_returns_empty(lds, capsys, monkeypatch):
    lds._EXTRACT_CACHE_PATH.write_text(
        json.dumps({"file": "a.md", "phrase_canon": "TODO", "offset": 0}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(lds, "_EXTRACT_FORCE", True)
    assert lds._load_extract_cache() == {}
    err = capsys.readouterr().err
    assert "LEIRA_EXTRACT_FORCE=1" in err
    assert "ignoring cache" in err


def test_extract_cache_save_load_roundtrip(lds):
    key = "a.md"
    row = {"file": key, "phrase": "FIXME", "phrase_canon": "FIXME",
           "snippet": "x", "offset": 0, "source_type": "memory"}
    lds._save_extract_cache({key: [row]})
    text = lds._EXTRACT_CACHE_PATH.read_text(encoding="utf-8")
    non_empty = [ln for ln in text.splitlines() if ln.strip()]
    assert len(non_empty) == 1
    reloaded = lds._load_extract_cache()
    assert reloaded == {key: [row]}


# ---------------------------------------------------------------------------
# _cached_extract_file
# ---------------------------------------------------------------------------

def test_cached_extract_file_miss_extracts_populates_manifest_and_bucket(lds, tmp_path):
    src = tmp_path / "note.md"
    src.write_text("TODO fix the retry logic", encoding="utf-8")
    manifest: dict = {}
    buckets: dict = {}
    rows, hit = lds._cached_extract_file(src, "memory", manifest, buckets)
    assert hit is False
    assert len(rows) >= 1
    key = str(src)
    assert key in manifest
    st = src.stat()
    assert manifest[key]["mtime_ns"] == st.st_mtime_ns
    assert manifest[key]["size_bytes"] == st.st_size
    assert manifest[key]["rows"] == len(rows)
    assert manifest[key]["extracted_at_iso"].endswith("Z")
    assert buckets[key] == rows


def test_cached_extract_file_hit_when_stat_unchanged(
    lds, tmp_path, monkeypatch
):
    src = tmp_path / "note.md"
    src.write_text("TODO fix later", encoding="utf-8")
    manifest: dict = {}
    buckets: dict = {}
    rows_first, _ = lds._cached_extract_file(src, "memory", manifest, buckets)

    def _boom(*a, **k):
        raise AssertionError("extract_from_file must not be called on a cache hit")

    monkeypatch.setattr(lds, "extract_from_file", _boom)
    rows_second, hit = lds._cached_extract_file(src, "memory", manifest, buckets)
    assert hit is True
    assert rows_second is buckets[str(src)]
    assert rows_second == rows_first


def test_cached_extract_file_stat_mismatch_purges_and_reextracts(lds, tmp_path):
    src = tmp_path / "note.md"
    src.write_text("TODO fix", encoding="utf-8")
    manifest: dict = {}
    buckets: dict = {}
    lds._cached_extract_file(src, "memory", manifest, buckets)
    first_bucket = list(buckets[str(src)])

    past = time.time() - 3600
    os.utime(src, (past, past))
    src.write_text("TODO alpha and FIXME beta and XXX gamma", encoding="utf-8")

    rows_second, hit = lds._cached_extract_file(src, "memory", manifest, buckets)
    assert hit is False
    assert buckets[str(src)] == rows_second
    assert rows_second != first_bucket
    st = src.stat()
    assert manifest[str(src)]["mtime_ns"] == st.st_mtime_ns
    assert manifest[str(src)]["size_bytes"] == st.st_size


def test_cached_extract_file_manifest_hit_but_missing_bucket_forces_reextract(
    lds, tmp_path
):
    src = tmp_path / "note.md"
    src.write_text("TODO fix later", encoding="utf-8")
    manifest: dict = {}
    buckets: dict = {}
    lds._cached_extract_file(src, "memory", manifest, buckets)
    buckets.pop(str(src))

    rows, hit = lds._cached_extract_file(src, "memory", manifest, buckets)
    assert hit is False
    assert str(src) in buckets
    assert buckets[str(src)] == rows
    assert len(rows) >= 1


def test_cached_extract_file_returns_hit_false_when_stat_none(lds, tmp_path):
    src = tmp_path / "does-not-exist.md"
    manifest: dict = {}
    buckets: dict = {}
    rows, hit = lds._cached_extract_file(src, "memory", manifest, buckets)
    assert hit is False
    assert rows == []
    assert str(src) not in manifest


# ---------------------------------------------------------------------------
# _cached_extract_commits
# ---------------------------------------------------------------------------

def test_cached_extract_commits_hit_when_head_matches_prior_sha(lds, monkeypatch):
    monkeypatch.setattr(lds, "_git_head_sha", lambda: "abc123")

    def _boom():
        raise AssertionError("extract_from_commits must not be called on head-hit")

    monkeypatch.setattr(lds, "extract_from_commits", _boom)

    prior_row = {"file": "commit:abc123deadbe", "phrase_canon": "TODO",
                 "snippet": "hit1", "offset": 0, "source_type": "commit"}
    prior_row2 = {"file": "commit:abc123deadbf", "phrase_canon": "FIXME",
                  "snippet": "hit2", "offset": 0, "source_type": "commit"}
    manifest = {"__commit_log__": {"head_sha": "abc123", "rows": 2}}
    buckets = {"__commit_log__": [prior_row, prior_row2]}

    combined = lds._cached_extract_commits(manifest, buckets)
    assert combined == [prior_row, prior_row2]


def test_cached_extract_commits_invalidates_on_head_change(lds, monkeypatch):
    monkeypatch.setattr(lds, "_git_head_sha", lambda: "bbb")

    delta_stdout = (
        "beef11111111\x00feat: add TODO fix later hook\x00body text here\x1e"
    )

    def _fake_run(cmd, **kwargs):
        assert any("aaa..HEAD" in str(x) for x in cmd)
        return _Completed(0, delta_stdout)

    monkeypatch.setattr(lds.subprocess, "run", _fake_run)

    existing = {"file": "commit:aaa0000000ff", "phrase_canon": "FIXME",
                "snippet": "prior", "offset": 0, "source_type": "commit"}
    manifest = {"__commit_log__": {"head_sha": "aaa", "rows": 1}}
    buckets = {"__commit_log__": [existing]}

    combined = lds._cached_extract_commits(manifest, buckets)
    assert existing in combined
    assert any(r.get("source_type") == "commit" and r is not existing for r in combined)
    assert len(combined) >= 2
    assert manifest["__commit_log__"]["head_sha"] == "bbb"


def test_cached_extract_commits_delta_git_rc_nonzero_falls_back_to_full_reextract(
    lds, monkeypatch, capsys
):
    monkeypatch.setattr(lds, "_git_head_sha", lambda: "bbb")
    monkeypatch.setattr(
        lds.subprocess, "run",
        lambda *a, **k: _Completed(128, ""),
    )
    full_row = {"file": "commit:zzzz00000000", "phrase_canon": "TODO",
                "snippet": "full", "offset": 0, "source_type": "commit"}
    monkeypatch.setattr(lds, "extract_from_commits", lambda: [full_row])

    manifest = {"__commit_log__": {"head_sha": "aaa", "rows": 5}}
    buckets = {"__commit_log__": [
        {"file": "commit:oldrow000000", "phrase_canon": "FIXME",
         "snippet": "stale", "offset": 0, "source_type": "commit"}
    ]}
    combined = lds._cached_extract_commits(manifest, buckets)
    assert combined == [full_row]
    assert buckets["__commit_log__"] == [full_row]
    assert manifest["__commit_log__"]["head_sha"] == "bbb"
    err = capsys.readouterr().err
    assert "unknown?" in err
    assert "miss" in err


def test_cached_extract_commits_no_prior_manifest_calls_full_extract(lds, monkeypatch, capsys):
    monkeypatch.setattr(lds, "_git_head_sha", lambda: "ccc")
    row = {"file": "commit:aaa000000000", "phrase_canon": "TODO",
           "snippet": "x", "offset": 0, "source_type": "commit"}
    monkeypatch.setattr(lds, "extract_from_commits", lambda: [row])

    manifest: dict = {}
    buckets: dict = {}
    combined = lds._cached_extract_commits(manifest, buckets)
    assert combined == [row]
    assert buckets["__commit_log__"] == [row]
    assert manifest["__commit_log__"]["head_sha"] == "ccc"
    err = capsys.readouterr().err
    assert "miss __commit_log__" in err


def test_cached_extract_commits_updates_manifest_iso_and_row_count(lds, monkeypatch):
    monkeypatch.setattr(lds, "_git_head_sha", lambda: "ccc")
    rows = [
        {"file": "commit:x1", "phrase_canon": "TODO", "snippet": "a",
         "offset": 0, "source_type": "commit"},
        {"file": "commit:x2", "phrase_canon": "FIXME", "snippet": "b",
         "offset": 0, "source_type": "commit"},
        {"file": "commit:x3", "phrase_canon": "park", "snippet": "c",
         "offset": 0, "source_type": "commit"},
    ]
    monkeypatch.setattr(lds, "extract_from_commits", lambda: list(rows))

    manifest: dict = {}
    buckets: dict = {}
    lds._cached_extract_commits(manifest, buckets)
    entry = manifest["__commit_log__"]
    assert entry["rows"] == 3
    assert entry["extracted_at_iso"].endswith("Z")
    assert "T" in entry["extracted_at_iso"]


def test_cached_extract_commits_head_none_full_reextract(lds, monkeypatch):
    monkeypatch.setattr(lds, "_git_head_sha", lambda: None)
    row = {"file": "commit:zzz", "phrase_canon": "TODO", "snippet": "x",
           "offset": 0, "source_type": "commit"}
    monkeypatch.setattr(lds, "extract_from_commits", lambda: [row])

    manifest: dict = {}
    buckets: dict = {}
    combined = lds._cached_extract_commits(manifest, buckets)
    assert combined == [row]
    assert manifest["__commit_log__"]["head_sha"] == ""


# ---------------------------------------------------------------------------
# Verdicts append-mode preservation (SSOT)
# ---------------------------------------------------------------------------

def test_main_verdicts_jsonl_opened_append_mode_preserves_prior_rows(
    lds_with_scaffold, tmp_path, monkeypatch
):
    mod = lds_with_scaffold
    _seed_session_file(mod.SESSION_DIR, "s.jsonl", ["TODO current thing"])

    prior = {"phrase": "hold-off", "phrase_canon": "hold-off",
             "snippet": "old-row snippet", "file": "unrelated-legacy.md",
             "offset": 999999, "source_type": "memory",
             "is_defer": True, "item": "old-row", "shape": "hard-defer"}
    mod._VERDICTS_PATH.write_text(json.dumps(prior) + "\n", encoding="utf-8")

    rc = mod.main([])
    assert rc == 0
    lines = [
        json.loads(ln) for ln in
        mod._VERDICTS_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    assert any(row.get("file") == "unrelated-legacy.md" for row in lines)
    assert len(lines) >= 2


# ---------------------------------------------------------------------------
# judge_batch — per-element shape guard + padding + error paths
# ---------------------------------------------------------------------------

def _patch_call_leira(lds, monkeypatch, result):
    """Install a call_leira stub returning `result` (dict / str / raises)."""
    if isinstance(result, BaseException):
        exc = result

        def _raise(*a, **k):
            raise exc

        monkeypatch.setattr(lds, "call_leira", _raise)
    else:
        monkeypatch.setattr(lds, "call_leira", lambda *a, **k: result)


def test_judge_batch_coerces_bare_true_bool_to_malformed_verdict_bool(lds, monkeypatch):
    _patch_call_leira(lds, monkeypatch, {"verdicts": [True]})
    out = lds.judge_batch([{"phrase": "x", "snippet": "y"}])
    assert out == [{"is_defer": True, "item": "", "shape": "malformed-verdict-bool"}]


def test_judge_batch_coerces_bare_false_bool_to_malformed_verdict_bool(lds, monkeypatch):
    _patch_call_leira(lds, monkeypatch, {"verdicts": [False]})
    out = lds.judge_batch([{"phrase": "x", "snippet": "y"}])
    assert out == [{"is_defer": False, "item": "", "shape": "malformed-verdict-bool"}]


def test_judge_batch_coerces_string_element_to_malformed_verdict_other(lds, monkeypatch):
    _patch_call_leira(lds, monkeypatch, {"verdicts": ["maybe"]})
    out = lds.judge_batch([{"phrase": "x", "snippet": "y"}])
    assert out == [{"is_defer": False, "item": "", "shape": "malformed-verdict-other"}]


def test_judge_batch_coerces_none_element_to_malformed_verdict_other(lds, monkeypatch):
    _patch_call_leira(lds, monkeypatch, {"verdicts": [None]})
    out = lds.judge_batch([{"phrase": "x", "snippet": "y"}])
    assert out == [{"is_defer": False, "item": "", "shape": "malformed-verdict-other"}]


def test_judge_batch_preserves_valid_dict_verdicts_untouched(lds, monkeypatch):
    good = {"is_defer": True, "item": "ship X", "shape": "hard-defer"}
    _patch_call_leira(lds, monkeypatch, {"verdicts": [good]})
    out = lds.judge_batch([{"phrase": "x", "snippet": "y"}])
    assert out == [good]


def test_judge_batch_mixed_shapes_each_coerced_independently(lds, monkeypatch):
    good = {"is_defer": True, "item": "a", "shape": "hard-defer"}
    _patch_call_leira(lds, monkeypatch, {"verdicts": [good, True, "x"]})
    batch = [
        {"phrase": "p1", "snippet": "s1"},
        {"phrase": "p2", "snippet": "s2"},
        {"phrase": "p3", "snippet": "s3"},
    ]
    out = lds.judge_batch(batch)
    assert out[0] == good
    assert out[1] == {"is_defer": True, "item": "", "shape": "malformed-verdict-bool"}
    assert out[2] == {"is_defer": False, "item": "", "shape": "malformed-verdict-other"}


def test_judge_batch_pads_when_verdicts_shorter_than_batch(lds, monkeypatch):
    good = {"is_defer": True, "item": "a", "shape": "hard-defer"}
    _patch_call_leira(lds, monkeypatch, {"verdicts": [good]})
    batch = [
        {"phrase": "p1", "snippet": "s1"},
        {"phrase": "p2", "snippet": "s2"},
        {"phrase": "p3", "snippet": "s3"},
    ]
    out = lds.judge_batch(batch)
    assert len(out) == 3
    assert out[0] == good
    pad = {"is_defer": False, "item": "", "shape": "false-positive"}
    assert out[1] == pad
    assert out[2] == pad


def test_judge_batch_truncates_when_verdicts_longer_than_batch(lds, monkeypatch):
    verdicts = [
        {"is_defer": True, "item": f"i{k}", "shape": "hard-defer"}
        for k in range(5)
    ]
    _patch_call_leira(lds, monkeypatch, {"verdicts": verdicts})
    batch = [
        {"phrase": "p1", "snippet": "s1"},
        {"phrase": "p2", "snippet": "s2"},
    ]
    out = lds.judge_batch(batch)
    assert len(out) == 2
    assert out == verdicts[:2]


def test_judge_batch_non_list_verdicts_returns_all_error_batch(lds, monkeypatch, capsys):
    _patch_call_leira(lds, monkeypatch, {"verdicts": 42})
    batch = [
        {"phrase": "p1", "snippet": "s1"},
        {"phrase": "p2", "snippet": "s2"},
    ]
    out = lds.judge_batch(batch)
    err_row = {"is_defer": False, "item": "", "shape": "error"}
    assert out == [err_row, err_row]
    err = capsys.readouterr().err
    assert "[judge] batch failed" in err


def test_judge_batch_string_result_parsed_as_json(lds, monkeypatch):
    _patch_call_leira(
        lds, monkeypatch,
        json.dumps({"verdicts": [
            {"is_defer": True, "item": "a", "shape": "hard-defer"}
        ]}),
    )
    out = lds.judge_batch([{"phrase": "x", "snippet": "y"}])
    assert out == [{"is_defer": True, "item": "a", "shape": "hard-defer"}]


def test_judge_batch_ollama_call_error_returns_error_batch(lds, monkeypatch, capsys):
    _patch_call_leira(lds, monkeypatch, lds.OllamaCallError("boom"))
    batch = [
        {"phrase": "p1", "snippet": "s1"},
        {"phrase": "p2", "snippet": "s2"},
        {"phrase": "p3", "snippet": "s3"},
    ]
    out = lds.judge_batch(batch)
    err_row = {"is_defer": False, "item": "", "shape": "error"}
    assert out == [err_row, err_row, err_row]
    err = capsys.readouterr().err
    assert "[judge] batch failed" in err
    assert "boom" in err


def test_judge_batch_leira_unavailable_propagates(lds, monkeypatch):
    _patch_call_leira(lds, monkeypatch, lds.LeiraUnavailable("down"))
    with pytest.raises(lds.LeiraUnavailable):
        lds.judge_batch([{"phrase": "x", "snippet": "y"}])
