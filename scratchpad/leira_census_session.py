#!/usr/bin/env python3
"""leira_census_session.py — Feed diff 98fddb33..HEAD to llm-host for structural-drift classification.

Post-hoc override: known llm-host verdict-schema hallucination where the model returns
empty findings but a non-CONVERGED verdict → forced to CONVERGED.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from leira_prepass import call_leira, OllamaCallError, DEFAULT_MODEL, context_bytes  # noqa: E402

BASE_SHA = "98fddb33"

CATEGORIES = [
    "BROAD_EXCEPT_SWALLOW",
    "HAND_ROLLED_SSOT_DUP",
    "MISSING_PIN_COVERAGE",
    "UNTESTED_NEW_MODULE",
    "REGISTER_ROW_MISSING",
    "STALE_ALLOW_LIST",
    "MIRROR_WITH_CHECK_INSTEAD_OF_DIRECT_IMPORT",
    "OWNER_ATTRIBUTED_DEFER",
    # 2026-07-11 session-retrofit — categories baked from same-drive
    # class-closures. Each entry has a shipped pin (or fold) as its
    # closure evidence:
    "LINE_ANCHORED_ALLOW_LIST_LITERAL",         #  meta-pin: `frozenset({(str, int)})` in tests/
    "SILENT_SWALLOW_ACCRETION",                 #  ratchet: `except X: pass` / `except X: return None` outside baseline
    "SELECT_STAR_OVERFETCH",                    #  ratchet: `SELECT * FROM <table>` outside baseline (sec.164.502(b))
    "SYNC_SQLITE_IN_ASYNC",                     #  ratchet: `.execute`/`.fetchall` inside `async def` outside baseline
    "EXCEPTION_CHAIN_MISSING_FROM",             #  fold: `except X as e: raise Y(...)` without `from e`
    "NONE",
]

SCHEMA = {
    "type": "object",
    "required": ["verdict", "findings", "notes"],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["CONVERGED", "NON_CONVERGED"],
            "description": "CONVERGED if no drift categories present; NON_CONVERGED otherwise.",
        },
        "findings": {
            "type": "array",
            "description": "One entry per genuine structural-drift site. Empty when CONVERGED.",
            "items": {
                "type": "object",
                "required": ["category", "file", "line", "note"],
                "properties": {
                    "category": {"type": "string", "enum": CATEGORIES},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "note": {"type": "string"},
                },
            },
        },
        "notes": {"type": "string", "description": "One-paragraph rationale."},
    },
}


def _git_diff(base: str) -> str:
    """Return unified diff of BASE..HEAD (name-status + patches, capped by model context)."""
    proc = subprocess.run(
        ["git", "diff", "--unified=3", f"{base}..HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        raise SystemExit(f"git diff failed: {proc.stderr[:300]}")
    return proc.stdout


def _cap_diff(diff: str) -> tuple[str, dict]:
    """Cap diff to ~40% of llm-host context (leave room for prompt + response)."""
    budget = context_bytes(0.40)
    if len(diff) <= budget:
        return diff, {"raw_bytes": len(diff), "capped_bytes": len(diff), "truncated": False}
    return diff[:budget] + "\n... [diff truncated]", {
        "raw_bytes": len(diff), "capped_bytes": budget, "truncated": True,
    }


def _apply_override(result: dict) -> dict:
    """Post-hoc override for the known verdict-schema hallucination: empty findings
    but a NON_CONVERGED verdict → force CONVERGED. Recorded in _override."""
    findings = result.get("findings") or []
    verdict = result.get("verdict")
    if not findings and verdict != "CONVERGED":
        result["_override"] = {
            "applied": True,
            "reason": "empty findings but verdict was " + str(verdict) + " — hallucination override → CONVERGED",
            "original_verdict": verdict,
        }
        result["verdict"] = "CONVERGED"
    else:
        result["_override"] = {"applied": False}
    return result


def main() -> None:
    diff = _git_diff(BASE_SHA)
    if not diff.strip():
        out = {
            "verdict": "CONVERGED",
            "findings": [],
            "notes": f"No diff between {BASE_SHA} and HEAD.",
            "_override": {"applied": False},
            "_meta": {"base_sha": BASE_SHA, "raw_bytes": 0, "model": DEFAULT_MODEL},
        }
        Path(REPO_ROOT / "scratchpad" / "leira_census_session.json").write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    capped, stats = _cap_diff(diff)

    prompt = (
        "You are a STRUCTURAL-DRIFT classifier for the email-triage HIPAA-class codebase "
        "(FastAPI/Jinja/SQLite). Read the git diff below (base "
        f"{BASE_SHA}..HEAD) and identify each site that introduces one of these drift categories.\n\n"
        "CATEGORIES (choose ONE per finding; NONE means no drift):\n"
        "- BROAD_EXCEPT_SWALLOW — a bare `except:` or `except Exception:` that swallows without re-raise/log/typed-error\n"
        "- HAND_ROLLED_SSOT_DUP — a hand-rolled duplicate of an existing SSOT helper (secret write, base64, audit emit, etc.)\n"
        "- MISSING_PIN_COVERAGE — new SSOT / seam without a same-change count-agnostic structural pin\n"
        "- UNTESTED_NEW_MODULE — new module / file / route with no test coverage in the same diff\n"
        "- REGISTER_ROW_MISSING — HIPAA/medical-risk change without §164.316 register row in `audit-reports/hipaa-findings-register.md`\n"
        "- STALE_ALLOW_LIST — allow-list entry that is now unused / outdated / drifted\n"
        "- MIRROR_WITH_CHECK_INSTEAD_OF_DIRECT_IMPORT — mirrored constant / list checked against instead of importing the SSOT\n"
        "- OWNER_ATTRIBUTED_DEFER — comment / doc labels a deferral as owner-decided when it is AI-deferred\n"
        "- NONE — a change that shows NO drift (only surface if you have nothing else to say)\n\n"
        f"Prior distinct commits (context, not full source): shown in the diff below.\n"
        f"Diff bytes: {stats['raw_bytes']} (capped_to={stats['capped_bytes']}, truncated={stats['truncated']}).\n\n"
        f"----DIFF----\n{capped}\n----END----\n\n"
        "Return the JSON schema exactly. `verdict` is CONVERGED iff `findings` is empty. "
        "Do NOT invent findings just to fill the array — an empty `findings` list with CONVERGED "
        "verdict is the RIGHT answer for a clean diff. Cite `file:line` from diff hunks."
    )

    try:
        result = call_leira(prompt, schema=SCHEMA)
    except OllamaCallError as e:
        out = {
            "verdict": "UNCERTAIN",
            "findings": [],
            "notes": f"llm-host call failed: {e}",
            "_override": {"applied": False},
            "_error": str(e),
            "_meta": {"base_sha": BASE_SHA, "model": DEFAULT_MODEL, "raw_bytes": stats["raw_bytes"]},
        }
        Path(REPO_ROOT / "scratchpad" / "leira_census_session.json").write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(out, ensure_ascii=False, indent=2), file=sys.stderr)
        sys.exit(1)

    result = _apply_override(result)
    result["_meta"] = {
        "base_sha": BASE_SHA,
        "model": DEFAULT_MODEL,
        "diff_stats": stats,
        "categories": CATEGORIES,
    }

    Path(REPO_ROOT / "scratchpad" / "leira_census_session.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
