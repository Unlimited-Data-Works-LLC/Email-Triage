#!/usr/bin/env python3
"""verify_leira_prepass_vs_run19.py — MVP verify harness for Consumer #1.

WHAT THIS CHECKS (Option C, what MVP verify should honestly cover):
  1. Schema validity — the llm-host output parsed and has the required keys.
  2. Sites-exist — every candidate file:line points at a real file with >= that many lines.
  3. Spot-sample semantic hit-rate — for each of the class's signature keywords, does at
     least ONE candidate site's raw source line contain the keyword? (Cheap way to catch
     "llm-host flagged sites that aren't of this class at all".)

WHAT THIS DOES NOT DO YET (call it out honestly — follow-up work):
  - Recall vs run19: the run19 backlog is a synthesis (only 14 file:line refs across ALL
    classes) — wrong known-good source. Real recall verification needs to parse the per-
    agent transcripts in the workflow subagent dir (each agent-<id>.jsonl carries its raw
    site enumeration). That's a bigger harness, deferred to the next window.
  - The 200-hit CAP in leira_census_prepass.py drops raw grep hits past the cap. On
    permission-check we saw 437 hits capped to 200 (46% dropped); on audit-emit 690 capped
    to 200 (71% dropped). This is a known enumeration-completeness limitation of Consumer
    #1 — the census subagent MUST still AST-widen (which the fork prompt requires). Fix
    options: batch (multi-llm-host-call merge) or a smarter pre-filter (dedup by file, drop
    imports-only, etc.). Also follow-up.
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

REPO = Path(__file__).resolve().parents[1]

CLASS_KEYWORDS = {
    "audit-emit": [
        "record_hipaa_access_event", "record_access_event", "record_auth_event",
        "safe_audit_write", "safe_audit_write_async", "hipaa_access_events",
        "audit_emitter", "log_entries",
    ],
    "permission-check": [
        "can_manage_account", "_manageable_account_ids", "_require_admin",
        "_gate_account_ids", "get_email_account", "may_manage_global_lists",
        "OwnedAccount",
    ],
    "secret-read": [
        "secrets.get", "_secret_key_for_account", "INSTALL_OAUTH_FIELDS",
        "oauth_secret_keys", "DbSecrets",
    ],
}


def _normalize_path(p: str) -> Path:
    # llm-host sometimes returns "src\\email_triage\\..." or "src/email_triage/..." or bare.
    p = p.replace("\\", "/").lstrip("/")
    if not p.startswith("src/email_triage/"):
        p = "src/email_triage/" + p.lstrip("./")
    return REPO / p


def verify(class_key: str, leira_out_path: Path) -> int:
    d = json.loads(leira_out_path.read_text(encoding="utf-8"))
    sites = d["candidate_sites"]
    keywords = CLASS_KEYWORDS.get(class_key, [])

    print(f"class: {class_key}")
    print(f"llm-host sites: {len(sites)}  unique files: {len({s['file'] for s in sites})}")

    # 1. Sites-exist check
    missing = []
    bad_line = []
    for s in sites:
        p = _normalize_path(s["file"])
        if not p.is_file():
            missing.append(f"{s['file']}:{s['line']}")
            continue
        try:
            n = sum(1 for _ in p.open("rb"))
        except OSError:
            missing.append(f"{s['file']}:{s['line']} (unreadable)")
            continue
        if s["line"] > n:
            bad_line.append(f"{s['file']}:{s['line']} (file has {n} lines)")
    ok_sites = len(sites) - len(missing) - len(bad_line)
    exist_pct = ok_sites / len(sites) * 100 if sites else 0
    print(f"  sites-exist: {ok_sites}/{len(sites)} = {exist_pct:.0f}%")
    for m in missing[:3]:
        print(f"    MISSING: {m}")
    for b in bad_line[:3]:
        print(f"    BAD LINE: {b}")

    # 2. Semantic hit-rate (per-keyword coverage in the flagged sites' raw source)
    keyword_hits = {}
    for kw in keywords:
        matched = 0
        for s in sites:
            p = _normalize_path(s["file"])
            if not p.is_file():
                continue
            try:
                line = p.read_text(encoding="utf-8", errors="replace").splitlines()[s["line"] - 1]
            except (OSError, IndexError):
                continue
            if kw in line:
                matched += 1
                break
        keyword_hits[kw] = matched
    covered = sum(1 for v in keyword_hits.values() if v > 0)
    kw_pct = covered / len(keywords) * 100 if keywords else 0
    print(f"  keyword-coverage: {covered}/{len(keywords)} keywords hit at least one site = {kw_pct:.0f}%")
    for kw, v in keyword_hits.items():
        mark = "OK" if v else "MISS"
        print(f"    {mark}: {kw}")

    # Cap-loss signal (distinguish FILTER-drop from CAP-drop — filter is a feature, cap is a limit).
    pm = d.get("_prepass_meta", {})
    fs = pm.get("filter_stats") or {}
    if fs:
        raw = fs.get("raw_total", 0)
        filt = fs.get("filtered_total", 0)
        cap = pm.get("capped_to", filt)
        print(f"  filter: raw {raw} -> filtered {filt} (dropped imports={fs.get('dropped_imports',0)}+comments={fs.get('dropped_comments',0)}+cluster={fs.get('dropped_cluster',0)})")
        if filt > cap:
            print(f"  CAP LOSS: filtered {filt} -> llm-host only saw {cap} ({100*(filt-cap)/filt:.0f}% dropped AT the cap). AST-widen required.")
        else:
            print(f"  no cap loss (filtered {filt} <= cap; all sent to llm-host)")
    elif pm:  # old format (pre-fix)
        raw = pm.get("raw_hits", 0)
        cap = pm.get("capped_to", 0)
        if raw > cap:
            print(f"  CAP LOSS (old format): raw {raw} -> capped {cap} ({100*(raw-cap)/raw:.0f}%). AST-widen required.")

    # Verdict
    if exist_pct >= 95 and kw_pct >= 50:
        verdict = "PASS-MVP — schema ok, sites real, semantically on-class"
        rc = 0
    elif exist_pct >= 80 and kw_pct >= 30:
        verdict = "PARTIAL — mostly real sites but semantic hit-rate mixed (llm-host may be flagging peripheral sites)"
        rc = 0
    else:
        verdict = "FAIL — either sites don't exist or don't match the class semantically"
        rc = 1
    print(f"VERDICT: {verdict}")
    return rc


def main():
    if len(sys.argv) != 3:
        print("usage: verify_leira_prepass_vs_run19.py <class-key> <llm-host-prepass-output.json>")
        sys.exit(2)
    sys.exit(verify(sys.argv[1], Path(sys.argv[2])))


if __name__ == "__main__":
    main()
