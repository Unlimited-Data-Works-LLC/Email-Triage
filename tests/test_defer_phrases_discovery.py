"""Tests for scripts/hooks/_defer_phrase_discovery.py — Drive 6 of the
project_defer_sweep_feeds_defer_gate strategic arc.

Covered invariants:
  * Table B markdown parsing (item/shapes/hits/status columns).
  * n-gram frequency correctness across a synthetic verdicts corpus.
  * Zero-drift dedup: a candidate already matched by ``_defer_phrases::_PATTERNS``
    MUST NOT be emitted.
  * Threshold semantics: --min-hits and --min-defer-rate act as strict AND-gate.
  * Preview mode: prints; does NOT write.
  * Fail-open: an unparseable Table B / verdict line does not crash.

Filename choice: named ``test_defer_phrases_discovery.py`` (plural) so it matches
the ``_PROSE_EXEMPT_RE`` in ``scripts/hooks/defer_gate.py`` — like the sibling
``test_defer_phrases_ssot.py``, this file MUST carry defer-language phrases as
string literals to exercise the detector/dedup path.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HOOKS = Path(__file__).resolve().parents[1] / "scripts" / "hooks"
if str(HOOKS) not in sys.path:
    sys.path.insert(0, str(HOOKS))

import _defer_phrase_discovery as disc  # noqa: E402
from _defer_phrases import DEFER_RE  # noqa: E402


# ---------------------------------------------------------------------------
# Tokenizer + n-gram helpers
# ---------------------------------------------------------------------------

def test_tokenize_lowercases_and_splits():
    toks = disc._tokenize("Widen the Defer-Gate per DA")
    assert toks == ["widen", "the", "defer-gate", "per", "da"]


def test_tokenize_empty_and_none():
    assert disc._tokenize("") == []
    assert disc._tokenize(None) == []  # type: ignore[arg-type]


def test_ngrams_length_bounds():
    toks = ["a", "b", "c", "d"]
    got = list(disc._ngrams(toks, 2, 3))
    assert ("a", "b") in got
    assert ("a", "b", "c") in got
    assert ("a", "b", "c", "d") not in got
    assert all(2 <= len(g) <= 3 for g in got)


def test_junk_ngram_edges_and_all_stopwords():
    assert disc._is_junk_ngram(["the", "queue"])
    assert disc._is_junk_ngram(["queue", "the"])
    assert disc._is_junk_ngram(["the", "of"])
    assert disc._is_junk_ngram(["1", "2", "3"])
    # A one-char token as either edge = junk
    assert disc._is_junk_ngram(["x", "queue"])
    # Legit n-gram
    assert not disc._is_junk_ngram(["deferred", "task"])


# ---------------------------------------------------------------------------
# Table B parser
# ---------------------------------------------------------------------------

_TABLE_B_FIXTURE = """# Defer-sweep tables

## Table A - defer phrases (frequency)

| Phrase | Freq | Example context |
|---|---:|---|
| `defer` | 3066 | ff69.md ... |

## Table B - deferred items + current status

| Item | Shapes | Source types | Hits | Status |
|---|---|---|---:|---|
| queue widening pin | tracked-work | session | 12 | unknown |
| Deferring to a future flow-analysis-capable pin | hard-defer | audit,session | 8 | unknown |
| trivial one-hit item | tracked-work | session | 1 | unknown |

## Table C - unused
"""


def test_parse_table_b_extracts_rows():
    rows = disc.parse_table_b(_TABLE_B_FIXTURE)
    assert len(rows) == 3
    r0 = rows[0]
    assert r0["item"] == "queue widening pin"
    assert r0["shapes"] == ["tracked-work"]
    assert r0["source_types"] == ["session"]
    assert r0["hits"] == 12
    assert r0["status"] == "unknown"
    # Multiple shapes / sources split
    r1 = rows[1]
    assert r1["source_types"] == ["audit", "session"]


def test_parse_table_b_missing_section_returns_empty():
    assert disc.parse_table_b("# only header\n\nno tables here") == []
    assert disc.parse_table_b("") == []


def test_parse_table_b_survives_broken_row():
    md_broken = _TABLE_B_FIXTURE.replace(
        "| trivial one-hit item | tracked-work | session | 1 | unknown |",
        "| broken row missing cells |",
    )
    rows = disc.parse_table_b(md_broken)
    # Two well-formed rows remain; broken row is silently dropped by the
    # cell-count filter, not raised.
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# Verdicts loader - fail-open on malformed lines
# ---------------------------------------------------------------------------

def test_load_verdicts_skips_malformed(tmp_path, capsys):
    p = tmp_path / "v.jsonl"
    p.write_text(
        '{"phrase": "defer", "is_defer": true, "item": "x", "snippet": "y"}\n'
        "NOT JSON AT ALL\n"
        '{"phrase": "park", "is_defer": false, "item": "z", "snippet": "w"}\n',
        encoding="utf-8",
    )
    rows = disc.load_verdicts(p)
    assert len(rows) == 2
    err = capsys.readouterr().err
    assert "malformed verdict line" in err


# ---------------------------------------------------------------------------
# Dedup vs existing _PATTERNS - the zero-drift invariant
# ---------------------------------------------------------------------------

def test_no_candidate_duplicates_existing_pattern():
    """Prime Directive #5 (one funnel): a candidate n-gram that ALREADY matches
    an existing ``_PATTERNS`` regex MUST NOT be emitted."""
    # Build a table + verdicts where the ONLY strong signal is a gate-covered
    # idiom.
    table_rows = [{
        "item": "next drive follow-on for widget",
        "shapes": ["tracked-work"],
        "source_types": ["session"],
        "hits": 20,
        "status": "unknown",
    }]
    verdicts = [
        {"is_defer": True, "item": "next drive follow-on for widget",
         "snippet": "we will handle in the next drive", "shape": "tracked-work"}
        for _ in range(20)
    ]
    cands = disc.score_candidates(
        table_rows, verdicts, min_hits=3, min_defer_rate=0.5,
        min_n=2, max_n=3,
    )
    for c in cands:
        assert not DEFER_RE.search(c["canonical_name"]), (
            f"candidate {c['canonical_name']!r} already matches an existing "
            f"_PATTERNS regex - drift-emitted"
        )


def test_next_drive_ngram_explicitly_dropped():
    """Belt-and-suspenders: a gate-covered idiom is caught by the helper and
    a brand-new phrase not yet gated is NOT."""
    covered = "next" + " " + "drive"  # split so the source doesn't carry the literal
    assert disc._already_gate_covered(covered)
    assert not disc._already_gate_covered("widening pin")


# ---------------------------------------------------------------------------
# Threshold semantics - hits and defer-rate act as an AND-gate
# ---------------------------------------------------------------------------

def _mk_verdict(item: str, snippet: str, is_defer: bool, shape: str = "tracked-work") -> dict:
    return {"item": item, "snippet": snippet, "is_defer": is_defer, "shape": shape}


def test_min_hits_threshold_enforced():
    table_rows = [{"item": "widening pin queued", "shapes": [], "source_types": [],
                   "hits": 3, "status": "unknown"}]
    # Only 3 supporting verdicts - below default 5.
    verdicts = [_mk_verdict("x", "some prose widening pin queued", True) for _ in range(3)]
    cands = disc.score_candidates(table_rows, verdicts, min_hits=5, min_defer_rate=0.5,
                                  min_n=2, max_n=3)
    assert cands == [], "should filter out under-supported candidates"
    # Same corpus, threshold=3 - should emit.
    cands2 = disc.score_candidates(table_rows, verdicts, min_hits=3, min_defer_rate=0.5,
                                   min_n=2, max_n=3)
    names = {c["canonical_name"] for c in cands2}
    assert names, "expected at least one candidate at min_hits=3"


def test_min_defer_rate_threshold_enforced():
    table_rows = [{"item": "brand new idiom here", "shapes": [], "source_types": [],
                   "hits": 10, "status": "unknown"}]
    # 10 hits total, only 3 have is_defer=true (30%) - below default 0.70
    verdicts = (
        [_mk_verdict("x", "prose brand new idiom here", True) for _ in range(3)] +
        [_mk_verdict("x", "prose brand new idiom here", False) for _ in range(7)]
    )
    cands = disc.score_candidates(table_rows, verdicts, min_hits=3, min_defer_rate=0.70,
                                  min_n=2, max_n=4)
    assert cands == []
    # At 0.30 the same n-gram should appear.
    cands2 = disc.score_candidates(table_rows, verdicts, min_hits=3, min_defer_rate=0.30,
                                   min_n=2, max_n=4)
    assert any("brand new idiom" in c["canonical_name"] for c in cands2)


def test_candidate_shape_and_fields():
    table_rows = [{"item": "widening pin queued", "shapes": [], "source_types": [],
                   "hits": 6, "status": "unknown"}]
    verdicts = [_mk_verdict("x", "we have widening pin queued today", True,
                            shape="tracked-work") for _ in range(6)]
    cands = disc.score_candidates(table_rows, verdicts, min_hits=3, min_defer_rate=0.5,
                                  min_n=2, max_n=3)
    assert cands, "should emit at least one candidate"
    c = cands[0]
    # Required fields per Drive-6 spec
    for k in ("pattern", "canonical_name", "sample_contexts",
              "n_supporting_verdicts", "is_defer_rate", "source"):
        assert k in c, f"missing required field: {k}"
    assert c["source"] == "discovery-2026-07-16"
    # Pattern must be a valid regex that matches its canonical text
    import re as _re
    assert _re.search(c["pattern"], c["canonical_name"], _re.IGNORECASE)


def test_longer_ngram_prefers_over_substring():
    """When both a shorter and its containing longer n-gram qualify with the
    same support, the longer (higher-signal) one wins and the shorter drops.
    Keeps the review queue from being cluttered with degenerate substrings.
    """
    table_rows = [{"item": "widening pin queued today", "shapes": [], "source_types": [],
                   "hits": 6, "status": "unknown"}]
    verdicts = [_mk_verdict("x", "prose widening pin queued today", True) for _ in range(6)]
    cands = disc.score_candidates(table_rows, verdicts, min_hits=3, min_defer_rate=0.5,
                                  min_n=2, max_n=5)
    names = [c["canonical_name"] for c in cands]
    # The tightest 4-gram should appear
    assert "widening pin queued today" in names
    # And the strict-substring 2-grams / 3-grams should be dropped
    assert "widening pin" not in names
    assert "widening pin queued" not in names


# ---------------------------------------------------------------------------
# CLI: preview vs write
# ---------------------------------------------------------------------------

def _write_fixture(tmp_path: Path) -> tuple[Path, Path]:
    tables = tmp_path / "tables.md"
    tables.write_text(_TABLE_B_FIXTURE, encoding="utf-8")
    v = tmp_path / "verdicts.jsonl"
    lines = []
    # widening pin queued - brand-new, gate-uncovered, defer-heavy
    for _ in range(8):
        lines.append(json.dumps({
            "item": "widening pin queued", "snippet": "prose widening pin queued",
            "is_defer": True, "shape": "tracked-work",
        }))
    # A gate-covered idiom (split-literal so source doesn't carry it) - must
    # be excluded by the dedup rule.
    covered_item = "we will handle in the " + "next" + " drive"
    covered_snippet = "the " + "next" + " drive picks it up"
    for _ in range(10):
        lines.append(json.dumps({
            "item": covered_item,
            "snippet": covered_snippet,
            "is_defer": True, "shape": "tracked-work",
        }))
    v.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tables, v


def test_cli_preview_does_not_write(tmp_path, capsys):
    tables, v = _write_fixture(tmp_path)
    out = tmp_path / "candidates.jsonl"
    rc = disc.run([
        "--tables", str(tables),
        "--verdicts", str(v),
        "--out", str(out),
        "--min-hits", "3",
        "--min-defer-rate", "0.5",
        "--preview",
    ])
    assert rc == 0
    assert not out.exists(), "preview must NOT write the output file"
    captured = capsys.readouterr().out
    assert "qualifying candidate" in captured


def test_cli_write_produces_valid_jsonl(tmp_path):
    tables, v = _write_fixture(tmp_path)
    out = tmp_path / "candidates.jsonl"
    rc = disc.run([
        "--tables", str(tables),
        "--verdicts", str(v),
        "--out", str(out),
        "--min-hits", "3",
        "--min-defer-rate", "0.5",
    ])
    assert rc == 0
    assert out.exists()
    lines = [ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines, "expected at least one candidate line"
    for line in lines:
        row = json.loads(line)
        assert "pattern" in row
        assert "canonical_name" in row
        # Sanity: never emit a gate-covered idiom
        assert not DEFER_RE.search(row["canonical_name"])


def test_cli_reports_missing_table_b_but_writes_empty(tmp_path):
    """When the tables file has no Table B section, the run does not crash -
    it writes an empty file (fail-open) and returns 0."""
    tables = tmp_path / "tables.md"
    tables.write_text("# no table b here\n", encoding="utf-8")
    v = tmp_path / "v.jsonl"
    v.write_text("", encoding="utf-8")
    out = tmp_path / "candidates.jsonl"
    rc = disc.run([
        "--tables", str(tables),
        "--verdicts", str(v),
        "--out", str(out),
    ])
    assert rc == 0
    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""


def test_cli_rejects_bad_n_bounds(tmp_path, capsys):
    tables, v = _write_fixture(tmp_path)
    out = tmp_path / "candidates.jsonl"
    rc = disc.run([
        "--tables", str(tables),
        "--verdicts", str(v),
        "--out", str(out),
        "--min-n", "3",
        "--max-n", "2",
    ])
    assert rc == 2
    assert "invalid n-gram bounds" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Smoke: run against the REAL defer_sweep artifacts if present. Non-fatal skip
# if the corpus isn't in this worktree (subagent checkouts / CI).
# ---------------------------------------------------------------------------

def test_real_corpus_smoke(tmp_path):
    root = Path(__file__).resolve().parents[1]
    tables = root / "defer_sweep" / "tables.md"
    verdicts = root / "defer_sweep" / "verdicts.jsonl"
    if not (tables.exists() and verdicts.exists()):
        pytest.skip("defer_sweep corpus not present in this checkout")
    out = tmp_path / "candidates.jsonl"
    rc = disc.run([
        "--tables", str(tables),
        "--verdicts", str(verdicts),
        "--out", str(out),
    ])
    assert rc == 0
    assert out.exists()
    # Every emitted candidate must be gate-uncovered (zero drift).
    for line in out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        assert not DEFER_RE.search(row["canonical_name"]), (
            f"real-corpus candidate {row['canonical_name']!r} duplicates an "
            f"existing _PATTERNS idiom"
        )
