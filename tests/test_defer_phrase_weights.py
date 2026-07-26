"""Tests for scripts/hooks/_defer_phrase_weights.py.

Pins:
  * aggregate correctness on a synthetic mini-verdicts fixture (per phrase:
    total_hits, is_defer_true, is_defer_rate, shape_distribution, snippets).
  * Threshold classification (HIGH_CONF_DEFER / LOW_CONF_NOISE / MIXED),
    including the "undersampled → always MIXED" guardrail.
  * Snippet dedup (first-120-char key) and per-shape cap.
  * CLI invocation via ``main([...])`` produces a valid output file.
  * Deterministic output: two runs on the same input agree bit-for-bit
    (except computed_at). Prime-Directive-#1 count-agnostic pin.

Self-referential note: this file carries defer-language phrases as string
literals (fixture rows). It sits under ``tests/`` which is exempt from the
defer_gate prose scan.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "scripts" / "hooks"
sys.path.insert(0, str(HOOKS))

from _defer_phrase_weights import (  # noqa: E402
    HIGH_RATE_DEFAULT,
    LOW_RATE_DEFAULT,
    MAX_SNIPPETS_PER_SHAPE,
    SCHEMA_VERSION,
    aggregate_verdicts,
    classify_phrase,
    main,
    write_weights,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _row(phrase_canon, shape, is_defer, snippet="ctx", phrase=None):
    return {
        "phrase": phrase or phrase_canon,
        "phrase_canon": phrase_canon,
        "snippet": snippet,
        "file": "fake.md",
        "offset": 0,
        "source_type": "test",
        "is_defer": is_defer,
        "item": "",
        "shape": shape,
    }


def _write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Aggregate correctness
# ---------------------------------------------------------------------------

def test_aggregate_counts_totals_and_defer_rate(tmp_path):
    verdicts = tmp_path / "verdicts.jsonl"
    rows = (
        [_row("WAITING-ON-OP", "waiting-op", True, f"snip-op-{i}") for i in range(9)]
        + [_row("WAITING-ON-OP", "hard-defer", True, "hard-snip")]
        + [_row("await", "meta-doc", False, f"await-{i}") for i in range(20)]
    )
    _write_jsonl(verdicts, rows)

    result = aggregate_verdicts(verdicts, min_hits=5)
    p = result["phrases"]

    assert p["WAITING-ON-OP"]["total_hits"] == 10
    assert p["WAITING-ON-OP"]["is_defer_true"] == 10
    assert p["WAITING-ON-OP"]["is_defer_rate"] == 1.0
    assert p["WAITING-ON-OP"]["shape_distribution"] == {
        "waiting-op": 9,
        "hard-defer": 1,
    }

    assert p["await"]["total_hits"] == 20
    assert p["await"]["is_defer_true"] == 0
    assert p["await"]["is_defer_rate"] == 0.0

    assert result["verdicts_row_count"] == 30
    assert result["verdicts_rows_skipped"] == 0


def test_shape_distribution_uses_actual_shape_keys(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    rows = [
        _row("defer", "hard-defer", True),
        _row("defer", "tracked-work", True),
        _row("defer", "meta-doc", False),
        _row("defer", "hard-defer", True),
    ]
    _write_jsonl(verdicts, rows)
    result = aggregate_verdicts(verdicts, min_hits=1)
    assert result["phrases"]["defer"]["shape_distribution"] == {
        "hard-defer": 2,
        "meta-doc": 1,
        "tracked-work": 1,
    }


def test_unknown_shape_still_tallied_fail_open(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    _write_jsonl(verdicts, [_row("x", "brand-new-shape", True)])
    result = aggregate_verdicts(verdicts, min_hits=1)
    assert result["phrases"]["x"]["shape_distribution"] == {"brand-new-shape": 1}


def test_missing_phrase_canon_skipped(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    good = _row("defer", "hard-defer", True)
    bad = _row("", "hard-defer", True)   # empty phrase_canon
    _write_jsonl(verdicts, [good, bad])
    result = aggregate_verdicts(verdicts, min_hits=1)
    assert "defer" in result["phrases"]
    assert result["verdicts_row_count"] == 2
    assert result["verdicts_rows_skipped"] == 1


def test_malformed_json_line_skipped(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    verdicts.write_text(
        json.dumps(_row("defer", "hard-defer", True)) + "\n"
        + "{not-valid-json\n"
        + json.dumps(_row("defer", "meta-doc", False)) + "\n",
        encoding="utf-8",
    )
    result = aggregate_verdicts(verdicts, min_hits=1)
    # Malformed line silently skipped; both valid rows aggregated.
    assert result["phrases"]["defer"]["total_hits"] == 2


# ---------------------------------------------------------------------------
# Snippet dedup + per-shape cap
# ---------------------------------------------------------------------------

def test_snippet_dedup_by_120char_prefix(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    # Same 120-char prefix, different suffix → still deduped.
    prefix = "A" * 120
    rows = [
        _row("q", "wip", True, prefix + "different-1"),
        _row("q", "wip", True, prefix + "different-2"),
        _row("q", "wip", True, prefix + "different-3"),
    ]
    _write_jsonl(verdicts, rows)
    result = aggregate_verdicts(verdicts, min_hits=1)
    snips = result["phrases"]["q"]["example_snippets"]["wip"]
    assert len(snips) == 1


def test_snippet_per_shape_capped(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    rows = [_row("q", "wip", True, f"unique-snippet-{i}") for i in range(10)]
    _write_jsonl(verdicts, rows)
    result = aggregate_verdicts(verdicts, min_hits=1)
    assert len(result["phrases"]["q"]["example_snippets"]["wip"]) == MAX_SNIPPETS_PER_SHAPE


def test_snippet_truncation(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    long_snip = "x" * 500
    _write_jsonl(verdicts, [_row("q", "wip", True, long_snip)])
    result = aggregate_verdicts(verdicts, min_hits=1)
    s = result["phrases"]["q"]["example_snippets"]["wip"][0]
    assert len(s) <= 200
    assert s.endswith("…")


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def test_classify_high_conf_defer():
    assert classify_phrase(total_hits=100, is_defer_rate=0.95) == "HIGH_CONF_DEFER"
    assert classify_phrase(total_hits=10, is_defer_rate=HIGH_RATE_DEFAULT) == "HIGH_CONF_DEFER"


def test_classify_low_conf_noise():
    assert classify_phrase(total_hits=100, is_defer_rate=0.05) == "LOW_CONF_NOISE"
    assert classify_phrase(total_hits=10, is_defer_rate=LOW_RATE_DEFAULT) == "LOW_CONF_NOISE"


def test_classify_mixed_when_undersampled():
    # Even at rate 1.0, if total_hits < min_hits → MIXED
    assert classify_phrase(total_hits=3, is_defer_rate=1.0, min_hits=10) == "MIXED"
    assert classify_phrase(total_hits=3, is_defer_rate=0.0, min_hits=10) == "MIXED"


def test_classify_mixed_middle_band():
    assert classify_phrase(total_hits=100, is_defer_rate=0.5) == "MIXED"
    assert classify_phrase(total_hits=100, is_defer_rate=0.16) == "MIXED"


def test_buckets_populated(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    rows = (
        # HIGH_CONF: 95% defer rate on 20 rows
        [_row("high", "hard-defer", True) for _ in range(19)]
        + [_row("high", "meta-doc", False)]
        # LOW_CONF: 5% defer rate on 20 rows
        + [_row("low", "meta-doc", False) for _ in range(19)]
        + [_row("low", "hard-defer", True)]
        # MIXED: 50% on 20 rows
        + [_row("mid", "hard-defer", True) for _ in range(10)]
        + [_row("mid", "meta-doc", False) for _ in range(10)]
        # Undersampled: 100% but only 3 rows → MIXED
        + [_row("under", "hard-defer", True) for _ in range(3)]
    )
    _write_jsonl(verdicts, rows)
    result = aggregate_verdicts(verdicts, min_hits=10)
    b = result["buckets"]
    assert "high" in b["HIGH_CONF_DEFER"]
    assert "low" in b["LOW_CONF_NOISE"]
    assert "mid" in b["MIXED"]
    assert "under" in b["MIXED"]


# ---------------------------------------------------------------------------
# Output schema + reproducibility
# ---------------------------------------------------------------------------

def test_output_schema_shape(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    _write_jsonl(verdicts, [_row("defer", "hard-defer", True)])
    result = aggregate_verdicts(verdicts, min_hits=1)
    for k in (
        "schema_version",
        "computed_at",
        "verdicts_file",
        "verdicts_file_sha256",
        "verdicts_row_count",
        "min_hits",
        "high_rate_threshold",
        "low_rate_threshold",
        "buckets",
        "phrases",
    ):
        assert k in result, f"missing top-level key: {k}"
    assert result["schema_version"] == SCHEMA_VERSION
    # sha256 is deterministic on content
    assert len(result["verdicts_file_sha256"]) == 64


def test_reproducibility_ignoring_computed_at(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    rows = [_row("defer", "hard-defer", True, f"s{i}") for i in range(15)]
    _write_jsonl(verdicts, rows)
    a = aggregate_verdicts(verdicts, min_hits=5)
    b = aggregate_verdicts(verdicts, min_hits=5)
    a.pop("computed_at")
    b.pop("computed_at")
    assert a == b


def test_phrases_sorted_by_key(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    rows = [
        _row("zebra", "hard-defer", True),
        _row("alpha", "hard-defer", True),
        _row("mango", "hard-defer", True),
    ]
    _write_jsonl(verdicts, rows)
    result = aggregate_verdicts(verdicts, min_hits=1)
    assert list(result["phrases"].keys()) == ["alpha", "mango", "zebra"]


# ---------------------------------------------------------------------------
# CLI invocation
# ---------------------------------------------------------------------------

def test_cli_end_to_end(tmp_path, capsys):
    verdicts = tmp_path / "v.jsonl"
    out = tmp_path / "phrase_weights.json"
    rows = [_row("defer", "hard-defer", True) for _ in range(12)] + [
        _row("await", "meta-doc", False) for _ in range(12)
    ]
    _write_jsonl(verdicts, rows)

    rc = main(["--verdicts", str(verdicts), "--out", str(out), "--min-hits", "10"])
    assert rc == 0
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["phrases"]["defer"]["classification"] == "HIGH_CONF_DEFER"
    assert data["phrases"]["await"]["classification"] == "LOW_CONF_NOISE"

    captured = capsys.readouterr()
    assert "phrase-weights" in captured.out
    assert "HIGH=" in captured.out


def test_cli_missing_verdicts_file_returns_2(tmp_path):
    out = tmp_path / "phrase_weights.json"
    rc = main(["--verdicts", str(tmp_path / "nope.jsonl"), "--out", str(out)])
    assert rc == 2
    assert not out.exists()


def test_cli_quiet_flag_suppresses_summary(tmp_path, capsys):
    verdicts = tmp_path / "v.jsonl"
    _write_jsonl(verdicts, [_row("defer", "hard-defer", True)])
    out = tmp_path / "pw.json"
    rc = main(["--verdicts", str(verdicts), "--out", str(out), "--quiet"])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == ""


# ---------------------------------------------------------------------------
# Structural pin (Prime Directive #1 — count-agnostic)
# ---------------------------------------------------------------------------

def test_every_phrase_row_carries_all_required_fields(tmp_path):
    """Count-agnostic pin — every phrase in output has all documented fields,
    regardless of how many phrases are in the corpus."""
    verdicts = tmp_path / "v.jsonl"
    rows = []
    for phrase in ("a", "b", "c", "d", "e"):
        for _ in range(3):
            rows.append(_row(phrase, "hard-defer", True))
    _write_jsonl(verdicts, rows)
    result = aggregate_verdicts(verdicts, min_hits=1)
    required = (
        "total_hits",
        "is_defer_true",
        "is_defer_rate",
        "shape_distribution",
        "example_snippets",
        "classification",
    )
    for name, entry in result["phrases"].items():
        for k in required:
            assert k in entry, f"phrase {name!r} missing field {k!r}"


def test_write_weights_roundtrip(tmp_path):
    verdicts = tmp_path / "v.jsonl"
    _write_jsonl(verdicts, [_row("defer", "hard-defer", True)])
    result = aggregate_verdicts(verdicts, min_hits=1)
    out = tmp_path / "sub" / "phrase_weights.json"
    write_weights(result, out)
    assert out.exists()
    reloaded = json.loads(out.read_text(encoding="utf-8"))
    # Restrict comparison to phrases/buckets — computed_at will vary if we
    # re-aggregate, but write/roundtrip preserves everything as-is.
    assert reloaded == result


# ---------------------------------------------------------------------------
# Real-corpus smoke (soft — only if it exists)
# ---------------------------------------------------------------------------

def test_real_corpus_smoke_if_present():
    """If defer_sweep/verdicts.jsonl exists in the repo, run against it —
    corpus is 50k+ rows and this must complete in a few seconds."""
    real = Path(__file__).resolve().parents[1] / "defer_sweep" / "verdicts.jsonl"
    if not real.exists():
        return
    result = aggregate_verdicts(real, min_hits=10)
    assert result["verdicts_row_count"] > 0
    # At least SOME phrases must be present; distribution is real-world.
    assert result["phrases"]
    # Buckets are always emitted as lists (possibly empty).
    for b in ("HIGH_CONF_DEFER", "LOW_CONF_NOISE", "MIXED"):
        assert isinstance(result["buckets"][b], list)
