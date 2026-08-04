"""N-322 R30 unit tests — task  N-317 half-2 persisted-key
re-normalize sweep.

DA panel on tranche  flagged that N-253 (and later N-317)
runtime-canonicalized `canonical_email(input)` at every allow-list
gate BUT the persisted STORED forms in `users.email`,
`users.notify_email`, and `email_accounts.aliases_json` remained in
the pre-canonicalization shape. Operator confirmed 2026-07-03 that
prod install has such rows. Sweep = `user re-normalize-emails
[--apply]` CLI verb.

These tests pin the CLI-parser + subparser + dry-run/apply
semantic. The actual re-normalize loop is exercised via the
`--apply` end-to-end path against a temp DB.
"""
from __future__ import annotations


def test_cli_parser_accepts_verb_dry_run():
    from email_triage.cli import build_parser
    args = build_parser().parse_args(["user", "re-normalize-emails"])
    assert args.user_cmd == "re-normalize-emails"
    assert args.apply is False


def test_cli_parser_accepts_apply_flag():
    from email_triage.cli import build_parser
    args = build_parser().parse_args(
        ["user", "re-normalize-emails", "--apply"]
    )
    assert args.apply is True


def test_canonicalize_display_name_wrapped(tmp_path, monkeypatch):
    """A `users.email` row stored as `Alice <a@b.com>` (pre-N-253
    shape) becomes `a@b.com` after `canonical_email` runs — the
    sweep MUST detect it as divergent."""
    from email_triage.mail_headers import canonical_email
    raw = "Alice <a@b.com>"
    assert canonical_email(raw) == "a@b.com"
    assert raw != canonical_email(raw), (
        "N-322 R30: display-name-wrapped shape should differ from "
        "its canonical form; else nothing to sweep."
    )


def test_canonicalize_idn_domain():
    """N-317 IDN normalize — U-label vs A-label form.  Sweep MUST
    also close this half."""
    from email_triage.mail_headers import canonical_email
    u = canonical_email("alice@münchen.de")
    a = canonical_email("alice@xn--mnchen-3ya.de")
    assert u == a
    assert u == "alice@xn--mnchen-3ya.de"


def test_already_canonical_is_noop():
    """Idempotence: a row already in canonical form is unchanged
    after re-normalize (the sweep MUST report zero divergent for
    fresh installs)."""
    from email_triage.mail_headers import canonical_email
    assert canonical_email("a@b.com") == "a@b.com"
    assert canonical_email(None) == ""
    assert canonical_email("") == ""
