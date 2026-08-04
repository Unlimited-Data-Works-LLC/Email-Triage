"""SMTP transport SSOT pin (divergence census 2026-06-09, egress class #2 —
SMTP-send sub-finding).

The actual ``smtplib`` send dance — ``with smtplib.SMTP(host, port) as s:
s.starttls(); s.login(...); s.send_message(msg)`` — was re-rolled in four
senders (recipient-digest [high-PHI], escalate-digest, daily-health ×2) outside
the ``web/smtp_send.send_smtp_message`` SSOT. Each re-roll is a place a future
edit could drop STARTTLS, skip login, or diverge error handling on a PHI-egress
path. They now all route through the one transport function.

Count-agnostic: assert ``smtplib.SMTP(...)`` / ``smtplib.SMTP_SSL(...)`` is
constructed nowhere outside the SSOT module (never ``len()==N``).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath  # N-350 R31

SSOT_REL = "web/smtp_send.py"


def _smtp_constructions(tree: ast.AST) -> list[int]:
    """Line numbers of ``smtplib.SMTP(...)`` / ``smtplib.SMTP_SSL(...)`` /
    a bare ``SMTP(...)`` / ``SMTP_SSL(...)`` call (covers `from smtplib import SMTP`)."""
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = ""
        if isinstance(f, ast.Attribute):      # smtplib.SMTP(...)
            name = f.attr
        elif isinstance(f, ast.Name):         # SMTP(...) after a direct import
            name = f.id
        if name in ("SMTP", "SMTP_SSL"):
            out.append(n.lineno)
    return out


def test_smtplib_constructed_only_in_ssot():
    offenders = []
    for p in iter_src_files():
        if relpath(p) == SSOT_REL:
            continue
        try:
            tree = parse_module(p); assert tree is not None  # N-350 R31
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        locs = _smtp_constructions(tree)
        if locs:
            offenders.append(f"{relpath(p)}:{locs}")
    assert not offenders, (
        "smtplib.SMTP(...) constructed outside web/smtp_send.py (the transport "
        f"SSOT): {offenders}. Build the message and call "
        "web.smtp_send.send_smtp_message(msg, smtp_host=..., ...) instead — one "
        "place owns STARTTLS/login/send on the PHI-egress path."
    )


def test_ssot_actually_constructs_smtp():
    """Guard the pin: the SSOT must still hold the one construction."""
    tree = parse_module(SRC_ROOT / "web" / "smtp_send.py"); assert tree is not None  # N-350 R31
    assert _smtp_constructions(tree), "web/smtp_send.py no longer constructs smtplib.SMTP"


def test_pin_has_teeth(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "import smtplib\n"
        "def send(msg, h, p):\n"
        "    with smtplib.SMTP(h, p) as s:\n"
        "        s.send_message(msg)\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _smtp_constructions(tree)


def test_pin_has_teeth_direct_import(tmp_path):
    ok_shape = tmp_path / "n.py"
    ok_shape.write_text(
        "from smtplib import SMTP\n"
        "def send(msg, h, p):\n"
        "    with SMTP(h, p) as s:\n"
        "        s.send_message(msg)\n",
        encoding="utf-8",
    )
    tree = parse_module(ok_shape); assert tree is not None
    assert _smtp_constructions(tree)
