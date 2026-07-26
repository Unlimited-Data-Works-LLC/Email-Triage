"""Tests for _defer_safe_context - cluster detection, dry-run vs commit,
threshold behavior, preview shape, and the count-agnostic SSOT pin."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HOOKS_DIR = REPO / "scripts" / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from _defer_safe_context import (  # noqa: E402
    CLUSTER_TEMPLATES,
    _CLUSTER_ORDER,
    _detect_cluster,
    apply_entries,
    format_preview,
    main,
    mine_verdicts,
)
from _pin_harness import iter_files  # noqa: E402


# ---------- cluster detection ---------------------------------------------

class TestDetectCluster:
    def test_code_fence_triple_backtick(self):
        assert _detect_cluster("here is code\n```\nsome text\n```", "queue") == "code-fence"

    def test_code_fence_single_backtick_wrap(self):
        assert _detect_cluster("use `queue` in the API", "queue") == "code-fence"

    def test_blockquote_leading_raw_newline(self):
        assert _detect_cluster("intro\n> we should queue this", "queue") == "blockquote"

    def test_blockquote_escaped_newline(self):
        # Verdict snippets often carry literal backslash-n from JSON round-trip.
        raw = "intro text" + "\\n" + "> queue discussion here"
        assert _detect_cluster(raw, "queue") == "blockquote"

    def test_negation_apostrophe_dont(self):
        assert _detect_cluster("we don't queue these anymore", "queue") == "negation"

    def test_negation_never_word(self):
        assert _detect_cluster("never queue the security fix", "queue") == "negation"

    def test_negation_out_of_proximity_returns_none(self):
        # negation word 200 chars away from phrase, no other indicator.
        snippet = "never" + ("x" * 200) + "queue"
        assert _detect_cluster(snippet, "queue") is None

    def test_rule_citation_drawer_name(self):
        assert _detect_cluster(
            "per feedback_root_cause_scope we act now", "queue"
        ) == "rule-citation"

    def test_rule_citation_prime_directive(self):
        assert _detect_cluster(
            "Prime Directive #5 says one SSOT", "queue"
        ) == "rule-citation"

    def test_rule_citation_hipaa_marker(self):
        assert _detect_cluster(
            "per section 164.312(b) audit event required".replace("section ", "§ "),
            "queue",
        ) == "rule-citation"

    def test_definition_means(self):
        assert _detect_cluster(
            "queue means to line up for processing", "queue"
        ) == "definition"

    def test_definition_is_called(self):
        assert _detect_cluster(
            "the practice queue is called batching", "queue"
        ) == "definition"

    def test_none_on_neutral_text(self):
        assert _detect_cluster("the meeting is scheduled for Friday", "queue") is None

    def test_none_on_empty_snippet(self):
        assert _detect_cluster("", "queue") is None

    def test_precedence_code_fence_beats_blockquote(self):
        s = "```\n> queue this\n```"
        assert _detect_cluster(s, "queue") == "code-fence"


# ---------- mine_verdicts + apply_entries ----------------------------------

def _write_verdicts(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "verdicts.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return p


def _fp_row(snippet: str, canon: str = "queue", phrase: str | None = None) -> dict:
    return {
        "phrase": phrase or canon,
        "phrase_canon": canon,
        "snippet": snippet,
        "file": "fake.md",
        "offset": 0,
        "source_type": "test",
        "is_defer": False,
        "item": "",
        "shape": "false-positive",
    }


class TestMineVerdicts:
    def test_filters_ineligible_shapes(self, tmp_path):
        ineligible = _fp_row("> queue this")
        ineligible["shape"] = "hard-defer"
        eligible = _fp_row("> queue this")  # shape=false-positive
        rows = [ineligible] * 10 + [eligible] * 3
        vp = _write_verdicts(tmp_path, rows)
        entries = mine_verdicts(vp, min_cluster_hits=3)
        assert entries, "expected the eligible rows to produce entries"
        # source_shape carries the eligible row's shape only
        assert all(e["source_shape"] == "false-positive" for e in entries)

    def test_meta_doc_is_wider_net(self, tmp_path):
        row = _fp_row("> queue this")
        row["shape"] = "meta-doc"
        vp = _write_verdicts(tmp_path, [row] * 3)
        entries = mine_verdicts(vp, min_cluster_hits=3)
        assert entries, "meta-doc must be eligible per _ELIGIBLE_SHAPES"
        assert any(e["source_shape"] == "meta-doc" for e in entries)

    def test_skips_is_defer_true_mixed_signal(self, tmp_path):
        row = _fp_row("> queue this")
        row["is_defer"] = True  # contradicts shape=false-positive
        vp = _write_verdicts(tmp_path, [row] * 5)
        entries = mine_verdicts(vp, min_cluster_hits=1)
        assert entries == []

    def test_below_threshold_excluded(self, tmp_path):
        vp = _write_verdicts(tmp_path, [_fp_row("> queue this")] * 2)
        entries = mine_verdicts(vp, min_cluster_hits=3)
        assert entries == []

    def test_at_threshold_included(self, tmp_path):
        vp = _write_verdicts(tmp_path, [_fp_row("> queue this")] * 3)
        entries = mine_verdicts(vp, min_cluster_hits=3)
        assert entries, "boundary hit-count == threshold must emit"

    def test_templates_are_substituted(self, tmp_path):
        vp = _write_verdicts(tmp_path, [_fp_row("> queue this later")] * 5)
        entries = mine_verdicts(vp, min_cluster_hits=3)
        # blockquote template is "> {phrase}"
        assert any(
            e["pattern"] == "> queue" and e["cluster"] == "blockquote"
            for e in entries
        )
        assert any("x5 hits" in e["provenance"] for e in entries)

    def test_negation_produces_all_templates(self, tmp_path):
        vp = _write_verdicts(tmp_path, [_fp_row("we don't queue that")] * 5)
        entries = mine_verdicts(vp, min_cluster_hits=3)
        pats = {e["pattern"] for e in entries if e["cluster"] == "negation"}
        assert pats == {"don't queue", "never queue", "no queue", "not queue"}

    def test_snake_form_for_rule_citation(self, tmp_path):
        # phrase_canon with hyphens should be snake-cased in rule-citation templates
        row = _fp_row("per feedback_root_cause_scope this is fine", canon="follow-up")
        vp = _write_verdicts(tmp_path, [row] * 5)
        entries = mine_verdicts(vp, min_cluster_hits=3)
        rc = [e for e in entries if e["cluster"] == "rule-citation"]
        assert any(e["pattern"] == "feedback_follow_up" for e in rc)
        assert any(e["pattern"] == "feedback_dont_follow_up" for e in rc)

    def test_malformed_jsonl_skipped_fail_open(self, tmp_path):
        p = tmp_path / "verdicts.jsonl"
        with p.open("w", encoding="utf-8") as f:
            f.write("not valid json at all\n")
            f.write(json.dumps(_fp_row("> queue this")) + "\n")
            f.write("{broken\n")
            f.write(json.dumps(_fp_row("> queue this")) + "\n")
            f.write("\n")
            f.write("# comment\n")
            f.write(json.dumps(_fp_row("> queue this")) + "\n")
        entries = mine_verdicts(p, min_cluster_hits=3)
        assert any(e["cluster"] == "blockquote" for e in entries)

    def test_missing_file_returns_empty(self, tmp_path):
        assert mine_verdicts(tmp_path / "nope.jsonl", min_cluster_hits=1) == []

    def test_missing_phrase_canon_skipped(self, tmp_path):
        row = _fp_row("> queue this")
        row["phrase_canon"] = ""
        vp = _write_verdicts(tmp_path, [row] * 5)
        assert mine_verdicts(vp, min_cluster_hits=1) == []

    def test_deterministic_sort(self, tmp_path):
        rows = (
            [_fp_row("> queue this", canon="queue")] * 5
            + [_fp_row("never batch that", canon="batch")] * 5
            + [_fp_row("`queue`", canon="queue")] * 5
        )
        vp = _write_verdicts(tmp_path, rows)
        e1 = mine_verdicts(vp, min_cluster_hits=3)
        e2 = mine_verdicts(vp, min_cluster_hits=3)
        assert e1 == e2


class TestApplyEntries:
    def test_dry_run_writes_nothing(self, tmp_path):
        out = tmp_path / "wl.jsonl"
        entries = [
            {"pattern": "> queue", "source_shape": "false-positive",
             "provenance": "queue x5 hits", "cluster": "blockquote"},
        ]
        would_add, dupes = apply_entries(entries, out, dry_run=True)
        assert would_add == entries
        assert dupes == []
        assert not out.exists()

    def test_commit_writes_file_and_creates_parent(self, tmp_path):
        out = tmp_path / "sub" / "nested" / "wl.jsonl"
        entries = [
            {"pattern": "> queue", "source_shape": "false-positive",
             "provenance": "queue x5 hits", "cluster": "blockquote"},
        ]
        would_add, dupes = apply_entries(entries, out, dry_run=False)
        assert would_add == entries
        assert dupes == []
        assert out.exists()
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["pattern"] == "> queue"
        assert obj["cluster"] == "blockquote"

    def test_commit_dedupes_against_existing(self, tmp_path):
        out = tmp_path / "wl.jsonl"
        out.write_text(
            json.dumps({
                "pattern": "> queue",
                "source_shape": "false-positive",
                "provenance": "seeded",
                "cluster": "blockquote",
            }) + "\n",
            encoding="utf-8",
        )
        entries = [
            {"pattern": "> queue", "source_shape": "false-positive",
             "provenance": "queue x5 hits", "cluster": "blockquote"},
            {"pattern": "> new-pat", "source_shape": "false-positive",
             "provenance": "new x5 hits", "cluster": "blockquote"},
        ]
        would_add, dupes = apply_entries(entries, out, dry_run=False)
        assert [e["pattern"] for e in would_add] == ["> new-pat"]
        assert [e["pattern"] for e in dupes] == ["> queue"]
        assert len(out.read_text(encoding="utf-8").strip().splitlines()) == 2

    def test_dry_run_still_reports_duplicates(self, tmp_path):
        out = tmp_path / "wl.jsonl"
        out.write_text(
            json.dumps({"pattern": "> queue",
                        "source_shape": "false-positive",
                        "provenance": "seeded",
                        "cluster": "blockquote"}) + "\n",
            encoding="utf-8",
        )
        entries = [
            {"pattern": "> queue", "source_shape": "false-positive",
             "provenance": "p", "cluster": "blockquote"},
        ]
        would_add, dupes = apply_entries(entries, out, dry_run=True)
        assert would_add == []
        assert [e["pattern"] for e in dupes] == ["> queue"]


class TestFormatPreview:
    def test_dry_run_header(self):
        entries = [{
            "pattern": "> queue", "source_shape": "false-positive",
            "provenance": "queue x5 hits", "cluster": "blockquote",
        }]
        s = format_preview(entries, entries, [], dry_run=True)
        assert "[dry-run]" in s
        assert "candidates: 1" in s
        assert "new: 1" in s
        assert "cluster=blockquote: 1" in s
        assert "> queue" in s

    def test_commit_header(self):
        s = format_preview([], [], [], dry_run=False)
        assert "[COMMIT]" in s

    def test_truncation_note_on_large_batch(self):
        entries = [{
            "pattern": f"pat-{i}", "source_shape": "false-positive",
            "provenance": "p", "cluster": "blockquote",
        } for i in range(25)]
        s = format_preview(entries, entries, [], dry_run=True)
        assert "+5 more" in s


# ---------- CLI -----------------------------------------------------------

class TestCLI:
    def test_dry_run_by_default(self, tmp_path, capsys):
        vp = _write_verdicts(tmp_path, [_fp_row("> queue this")] * 5)
        out = tmp_path / "wl.jsonl"
        rc = main([
            "--verdicts", str(vp),
            "--out", str(out),
            "--min-cluster-hits", "3",
        ])
        assert rc == 0
        cap = capsys.readouterr()
        assert "[dry-run]" in cap.out
        assert not out.exists(), "dry-run must not write the whitelist file"

    def test_commit_flag_writes(self, tmp_path, capsys):
        vp = _write_verdicts(tmp_path, [_fp_row("> queue this")] * 5)
        out = tmp_path / "wl.jsonl"
        rc = main([
            "--verdicts", str(vp),
            "--out", str(out),
            "--min-cluster-hits", "3",
            "--commit",
        ])
        assert rc == 0
        cap = capsys.readouterr()
        assert "[COMMIT]" in cap.out
        assert out.exists()

    def test_explicit_dry_run_overrides_commit(self, tmp_path, capsys):
        # --dry-run wins over --commit (belt-and-braces safety).
        vp = _write_verdicts(tmp_path, [_fp_row("> queue this")] * 5)
        out = tmp_path / "wl.jsonl"
        rc = main([
            "--verdicts", str(vp),
            "--out", str(out),
            "--min-cluster-hits", "3",
            "--commit",
            "--dry-run",
        ])
        assert rc == 0
        cap = capsys.readouterr()
        assert "[dry-run]" in cap.out
        assert not out.exists()

    def test_min_cluster_hits_threshold_honored(self, tmp_path, capsys):
        vp = _write_verdicts(tmp_path, [_fp_row("> queue this")] * 5)
        out = tmp_path / "wl.jsonl"
        rc = main([
            "--verdicts", str(vp),
            "--out", str(out),
            "--min-cluster-hits", "10",   # above what fixture provides
            "--commit",
        ])
        assert rc == 0
        cap = capsys.readouterr()
        assert "candidates: 0" in cap.out
        assert not out.exists()


# ---------- SSOT + structural pin -----------------------------------------

class TestSSOTPin:
    """Prime Directive #1 + #5 count-agnostic pin - CLUSTER_TEMPLATES lives
    only in _defer_safe_context.py. Any hand-rolled duplicate in a sibling
    hook fails the pin regardless of hook count."""

    def test_cluster_templates_are_single_ssot(self):
        ssot_file = HOOKS_DIR / "_defer_safe_context.py"
        offenders: list[str] = []
        for p in iter_files(HOOKS_DIR, "*.py"):
            if p.resolve() == ssot_file.resolve():
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            for probe in ("CLUSTER_TEMPLATES = {", "CLUSTER_TEMPLATES: dict"):
                if probe in text:
                    offenders.append(f"{p.relative_to(REPO)}: {probe!r}")
        assert not offenders, (
            "hand-rolled CLUSTER_TEMPLATES found - import from "
            "_defer_safe_context instead (Prime Directive #5):\n  "
            + "\n  ".join(offenders)
        )

    def test_every_cluster_has_template_family(self):
        for c in _CLUSTER_ORDER:
            assert c in CLUSTER_TEMPLATES and CLUSTER_TEMPLATES[c], (
                f"cluster {c!r} has no template family - detector would "
                "surface hits with nothing to substitute (Prime Directive #1)"
            )

    def test_module_avoids_sibling_pin_probes(self):
        """The safe-context module lives in scripts/hooks/ and is scanned by
        test_defer_phrases_ssot_pin. Load that pin's probe list at runtime
        and verify none appear in this module - inlining the literals here
        would itself trip both pins."""
        pin_path = REPO / "tests" / "test_defer_phrases_ssot_pin.py"
        spec = importlib.util.spec_from_file_location("_ssot_pin", pin_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        probes = mod._PROBES
        text = (HOOKS_DIR / "_defer_safe_context.py").read_text(
            encoding="utf-8"
        ).lower()
        offenders = [p for p in probes if p in text]
        assert not offenders, (
            "safe-context module contains sibling-pin probe phrase(s): "
            f"{offenders} - will trip test_defer_phrases_ssot_pin"
        )
