"""CI guard: PHI field renders in templates must be wrapped in a HIPAA guard.

Audit finding NEW-4 (HIPAA §164.312(b), CIP-011-R1): templates were
rendering ``msg.subject`` / ``msg.sender`` / ``classification.reason``
/ ``raw_description`` directly, leaking PHI to any admin viewing a
HIPAA-enabled account.

Backend redaction (items #15b + #16a + #16b) covers persistence, but
the render layer is a separate surface. This test greps every
``*.html`` in the templates tree for unwrapped PHI field renders
and fails if any surface without an effective-HIPAA guard.

Heuristic (grep, not AST):
  - Detect ``{{ <phi_field> ... }}`` on a line.
  - Pass if the same line contains a guard token
    (``hipaa_mode``, ``effective_hipaa``, ``msg.hipaa``,
    ``[redacted]``).
  - Else pass if a 10-line backward window contains one of the
    guard tokens (block form: ``{% if effective_hipaa %}``).
  - Otherwise the site is an offender.

If the heuristic flags a false positive, add the specific
``path:line`` key to ``ALLOWLIST`` with a justification comment.
"""

from __future__ import annotations

from pathlib import Path


TEMPLATES = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "email_triage"
    / "web"
    / "templates"
)

# Fields that require an effective-HIPAA wrap at render time.
#
# Covers both the audit's canonical variables (``msg.sender``) and
# the variants actually used in templates (``parsed.sender`` in the
# classify flow, ``r.sender`` / ``r.get('sender')`` in triage rows,
# ``cat.description`` / ``cat.merged_from`` in discover consolidated
# output — the latter two derive from LLM output over scanned mail).
PHI_FIELDS = [
    "msg.sender",
    "msg.subject",
    "msg.recipients",
    "msg.body_text",
    "parsed.sender",
    "parsed.subject",
    "parsed.recipients",
    "parsed.body_text",
    "classification.reason",
    "raw_description",
    "r.sender",
    "r.subject",
    "r.reason",
    "r.get('sender'",
    "r.get('subject'",
    "r.get('reason'",
    "r.get('body_text'",
    "r.get('recipients'",
    "cat.description",
    "cat.merged_from",
]

# Files under ``templates/`` whose ``cat.description`` fields refer
# to admin-configured category metadata (bucket names like
# "invoices"), NOT LLM-generated descriptions from scanned mail.
# These are category-management surfaces, not discover output, so
# they're non-PHI.
NON_PHI_CAT_DESCRIPTION_FILES = {
    "categories/_row.html",
    "categories/manage.html",
    "categories/_edit.html",
    "profile.html",
    "profile/_personal_categories.html",
    # #95 sub-A — wizard step 5 renders the same per-user
    # escalation-categories table that profile.html does.
    # cat.description here is admin-config text describing the
    # category itself (e.g. "Bills/finance"), not PHI extracted
    # from any message.
    "account_wizard/step5.html",
}

# Specific ``path:line`` sites that are audited and guarded by
# surrounding markup the grep heuristic misses. Keep small.
ALLOWLIST: set[str] = {
    # triage/_results.html:181 -- inside the ``r.status == 'skipped'``
    # branch where ``r.get('reason')`` is the SKIP reason
    # (server-internal code: "self_origin", "x_email_triage_header",
    # "in_flight"), NOT the LLM classification reason text. Server
    # codes are non-PHI; rendered into a tooltip so the operator can
    # tell which loop-prevention gate fired. See punch-list #119 +
    # #117 + #114.
    # 2026-05-11: line shifted from 140 → 181 when #129 multi-label
    # added bulk-tag toolbar + per-row checkboxes above this block.
    # 2026-05-12: line shifted from 181 → 185 when the slug-jargon
    # cleanup commit added a 4-line Jinja comment inside the bulk-
    # tag selector explaining why the option text dropped the slug
    # parenthetical (df6287c). Line-numbered allowlist is brittle —
    # if this drifts again, consider switching to a marker comment.
    "triage/_results.html:185",
}


def _line_has_guard(line: str) -> bool:
    tokens = ("hipaa_mode", "effective_hipaa", "msg.hipaa", "[redacted]")
    return any(t in line for t in tokens)


def _window_has_guard(lines: list[str], idx: int, size: int = 10) -> bool:
    context = "\n".join(lines[max(0, idx - size): idx])
    return (
        "hipaa_mode" in context
        or "effective_hipaa" in context
        or "msg.hipaa" in context
    )


def test_templates_guard_phi_fields():
    offenders: list[tuple[str, str, str]] = []
    for path in TEMPLATES.rglob("*.html"):
        rel = path.relative_to(TEMPLATES).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for field in PHI_FIELDS:
                # Look for ``{{ field`` or ``{{field`` (Jinja print).
                if f"{{{{ {field}" not in line and f"{{{{{field}" not in line:
                    continue
                # cat.description is PHI only in discover output;
                # in category-management pages it's admin config.
                if field in ("cat.description", "cat.merged_from") and rel in NON_PHI_CAT_DESCRIPTION_FILES:
                    continue
                if _line_has_guard(line):
                    continue
                if _window_has_guard(lines, i):
                    continue
                key = f"{rel}:{i}"
                if key in ALLOWLIST:
                    continue
                offenders.append((key, field, line.strip()))
    assert not offenders, (
        "Unguarded PHI field renders found in templates:\n"
        + "\n".join(
            f"  {k}  ({field})  {line}"
            for k, field, line in offenders
        )
    )
