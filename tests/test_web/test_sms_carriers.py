"""Unit tests for the email-to-SMS gateway helper module (#73)."""

from __future__ import annotations

import pytest

from email_triage.web.sms_carriers import (
    US_CELL_CARRIERS,
    build_sms_address,
    carrier_display_name,
    carrier_gateway,
    normalize_us_cell_number,
)


# ---------------------------------------------------------------------------
# Carrier table sanity
# ---------------------------------------------------------------------------

def test_carrier_table_shape():
    """Every entry is (slug, name, gateway-with-leading-@)."""
    assert len(US_CELL_CARRIERS) >= 8
    seen_slugs = set()
    for slug, name, domain in US_CELL_CARRIERS:
        assert slug and slug.isalnum(), f"bad slug: {slug!r}"
        assert name, f"empty name for {slug}"
        assert domain.startswith("@"), f"gateway must start with @: {domain!r}"
        assert "." in domain[1:], f"gateway must be a domain: {domain!r}"
        assert slug not in seen_slugs, f"duplicate slug: {slug}"
        seen_slugs.add(slug)


def test_expected_us_carriers_present():
    """Spot-check the well-known major-carrier slugs survive."""
    slugs = {s for s, _, _ in US_CELL_CARRIERS}
    for must_have in ("verizon", "att", "tmobile", "uscellular", "googlefi"):
        assert must_have in slugs, f"missing carrier: {must_have}"


def test_carrier_gateway_lookup():
    assert carrier_gateway("verizon") == "@vtext.com"
    assert carrier_gateway("att") == "@txt.att.net"
    assert carrier_gateway("tmobile") == "@tmomail.net"


def test_carrier_gateway_unknown_returns_none():
    assert carrier_gateway("orange-france") is None
    assert carrier_gateway("") is None


def test_carrier_display_name_lookup():
    assert carrier_display_name("verizon") == "Verizon"
    assert carrier_display_name("att") == "AT&T"
    assert carrier_display_name("googlefi") == "Google Fi"
    assert carrier_display_name("nope") is None


# ---------------------------------------------------------------------------
# normalize_us_cell_number
# ---------------------------------------------------------------------------

class TestNormalize:
    def test_clean_10_digits(self):
        assert normalize_us_cell_number("5551234567") == "5551234567"

    def test_with_dashes(self):
        assert normalize_us_cell_number("555-123-4567") == "5551234567"

    def test_with_parens_and_dots(self):
        assert normalize_us_cell_number("(555) 123.4567") == "5551234567"

    def test_with_country_code_1(self):
        assert normalize_us_cell_number("1-555-123-4567") == "5551234567"

    def test_with_plus_country_code(self):
        assert normalize_us_cell_number("+1 555.123.4567") == "5551234567"

    def test_too_short_rejected(self):
        assert normalize_us_cell_number("12345") is None

    def test_too_long_rejected(self):
        # 12 digits — not a valid US number.
        assert normalize_us_cell_number("123456789012") is None

    def test_11_digits_not_starting_with_1_rejected(self):
        # 11 digits but country code != 1 (defensive — we only support US).
        assert normalize_us_cell_number("25551234567") is None

    def test_letters_rejected(self):
        # 555-123-456A digit-counts to 9; should fail length check.
        assert normalize_us_cell_number("555-123-456A") is None

    def test_empty_rejected(self):
        assert normalize_us_cell_number("") is None
        assert normalize_us_cell_number(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# build_sms_address
# ---------------------------------------------------------------------------

class TestBuildAddress:
    def test_round_trip_each_carrier(self):
        """Every shipping carrier slug produces a valid address."""
        number = "5551234567"
        for slug, _name, gateway in US_CELL_CARRIERS:
            addr = build_sms_address(number, slug)
            assert addr == f"{number}{gateway}"

    def test_unknown_carrier_returns_none(self):
        assert build_sms_address("5551234567", "fake-co") is None

    def test_non_canonical_number_returns_none(self):
        # The function is strict: caller must normalize first.
        assert build_sms_address("555-123-4567", "verizon") is None
        assert build_sms_address("555123456", "verizon") is None  # 9 digits
        assert build_sms_address("", "verizon") is None
