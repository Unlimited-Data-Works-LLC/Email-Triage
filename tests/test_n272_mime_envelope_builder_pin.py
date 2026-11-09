"""N-272 R28 structural pin — MIME envelope builder SSOT (2026-07-03).

Census R28 discovered MED #5 (Outbound MIME envelope builder, 7 forks):
`MIMEMultipart("alternative")` construction is spread across 4+ sites
each differing on Date/Message-Id/X-Email-Triage stamp. N-272 lands
`web/_mime_builder.build_alternative_message` SSOT + 1 migration
(`recipient_digest.py`).

WHAT IT PINS (growth-cap ratchet):

Total `MIMEMultipart("alternative")` calls tree-wide outside
`_mime_builder.py` must be <= baseline. Migrations decrement.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_MAX_MIMEMULTIPART_CALLS = 0  # 2026-07-03 N-272c R28 STRICT-0 (all 4 sites migrated: recipient_digest + auth.py + 2 imap.py).
_SSOT_FILE = "_mime_builder.py"


def _count_mimemultipart_in_tree(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = None
        if isinstance(f, ast.Name):
            name = f.id
        elif isinstance(f, ast.Attribute):
            name = f.attr
        if name != "MIMEMultipart":
            continue
        # Must be called with "alternative" as first positional arg —
        # a `MIMEMultipart("mixed")` or `MIMEMultipart("related")` is
        # a distinct concern and not part of the alternative-envelope
        # class the SSOT covers.
        if not node.args:
            continue
        arg0 = node.args[0]
        if isinstance(arg0, ast.Constant) and arg0.value == "alternative":
            n += 1
    return n


def test_mime_envelope_ssot_growth_cap():
    """Tree-wide `MIMEMultipart("alternative")` outside `_mime_builder.
    py` must be <= baseline. NEW hand-rolls fire — route through
    `_mime_builder.build_alternative_message`."""
    total = 0
    per_file: list[tuple[str, int]] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] == _SSOT_FILE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        n = _count_mimemultipart_in_tree(tree)
        if n > 0:
            total += n
            per_file.append((rel, n))
    assert total <= _MAX_MIMEMULTIPART_CALLS, (
        f"N-272 R28 MIME envelope SSOT growth-cap: total "
        f"MIMEMultipart('alternative') calls {total} > baseline "
        f"{_MAX_MIMEMULTIPART_CALLS}. NEW hand-rolls must route "
        "through `web._mime_builder.build_alternative_message` — the "
        "SSOT owns Date/Message-Id/X-Email-Triage/RFC-2046-order in "
        "ONE place.\n\n"
        + "\n".join(f"{p}: {n}" for p, n in per_file)
    )


def test_build_alternative_message_ssot_shape():
    """Anti-vacuity: SSOT imports + returns a multipart with the
    documented headers (Message-Id, X-Email-Triage) + correct part
    count."""
    from email_triage.web._mime_builder import build_alternative_message
    msg = build_alternative_message(
        subject="Test",
        from_addr="sender@ex.com",
        to="recipient@ex.com",
        plain_body="plain",
        html_body="<p>html</p>",
        source_tag="test",
    )
    assert msg["Message-Id"], "Message-Id missing — MUA threading breaks"
    assert msg["X-Email-Triage"], "X-Email-Triage stamp missing — loop-prevention broken"
    assert len(msg.get_payload()) == 2, "alternative multipart must have 2 parts"
