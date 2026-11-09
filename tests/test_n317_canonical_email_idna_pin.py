"""N-317 R30 unit tests — `canonical_email` IDNA collision-resistance.

Task  tranche  DA follow-up. Pre-fix N-253 (`b87b65bd`)
compared bare-address forms case-insensitively but did NOT
IDNA-normalize the domain, so two envelopes carrying the SAME
recipient in different encodings (U-label / A-label) collided in the
allow-list gate at §164.312(a)(1). Result: an authorized
recipient's IDN-encoded envelope variant BYPASSED the allow-list.

N-317 folds a `str.encode("idna").decode("ascii")` step over the
domain part inside `canonical_email`. This test pins the invariant:
Unicode and punycode forms of the same address MUST canonicalize to
the same key, and malformed domains fail CLOSED (return the raw
bare form, which the allow-list rejects).
"""
from __future__ import annotations


def test_idn_unicode_and_punycode_forms_collide():
    """§164.312(a)(1): two envelope encodings of the same real
    recipient MUST canonicalize to the same allow-list key."""
    from email_triage.mail_headers import canonical_email

    u = canonical_email("alice@münchen.de")
    a = canonical_email("alice@xn--mnchen-3ya.de")
    assert u == a, (
        f"N-317 R30 REGRESSION: unicode form {u!r} and punycode "
        f"form {a!r} must canonicalize to the same key; else IDN "
        f"encoding bypasses the §164.312(a)(1) allow-list gate."
    )
    assert u == "alice@xn--mnchen-3ya.de"


def test_ascii_addresses_preserved():
    from email_triage.mail_headers import canonical_email
    assert canonical_email("a@b.com") == "a@b.com"
    assert canonical_email("Alice <a@b.com>") == "a@b.com"
    assert canonical_email("A@B.COM") == "a@b.com"


def test_none_and_empty_stay_empty():
    from email_triage.mail_headers import canonical_email
    assert canonical_email(None) == ""
    assert canonical_email("") == ""


def test_malformed_domain_fails_closed():
    """A domain the idna codec rejects returns the bare-form
    unchanged so any allow-list gate rejects (no authorized entry
    matches a malformed domain)."""
    from email_triage.mail_headers import canonical_email
    # `---.com` fails idna (invalid label start); should return bare
    # form unchanged rather than raising.
    result = canonical_email("alice@---.com")
    assert result == "alice@---.com"


def test_idn_deterministic_across_encodings():
    """A U-label and its A-label form canonicalize to the same key
    (round-trip through the idna codec both ways)."""
    from email_triage.mail_headers import canonical_email

    # Compute the A-label form dynamically so the test doesn't depend
    # on a hand-written punycode string (stdlib `idna` normalizes some
    # non-ASCII via NAMEPREP e.g. ß→ss, so hard-coded expected forms
    # are fragile).
    u_label_domain = "тест.рф"
    a_label_domain = u_label_domain.encode("idna").decode("ascii")
    assert a_label_domain != u_label_domain, (
        "sanity check: cyrillic label should transform to punycode"
    )

    u = canonical_email(f"user@{u_label_domain}")
    a = canonical_email(f"user@{a_label_domain}")
    assert u == a, (
        f"N-317 R30: U-label {u!r} vs A-label {a!r} must "
        f"canonicalize identically."
    )
