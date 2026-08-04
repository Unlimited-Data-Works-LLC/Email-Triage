"""N-71 — sender-domain extraction SSOT pin.

Before N-71, four code paths extracted the sender domain:

  1. ``classify/hints.py::_extract_domain``     — ``rsplit("@",1)[-1]``
  2. ``web/email_watches.py::_domain_of``        — ``split("@",1)[1]``
  3. ``actions/digest.py::_extract_sender_name`` — ``split("@")[1].split(".")[0]``
  4. ``db/accounts.py::looks_like_email_address``— ``split("@")[-1]``

Cases 1 and 2 gate **watch-fire / classification** with the sender domain;
they disagree on double-@ spoof addresses:

  * ``split("@",1)[1]``   on ``"a@b@evil.com"`` → ``"b"``   (wrong domain)
  * ``rsplit("@",1)[-1]`` on ``"a@b@evil.com"`` → ``"evil.com"`` (correct)

Per RFC 5321 §4.1.2 the domain is the LAST ``@``-separated token.

The fix introduces ``mail_headers.extract_domain(sender)`` as the SSOT:
composed on the frozen ``extract_bare_address`` SSOT (display-name stripping)
followed by ``rsplit("@",1)[-1]`` (rightmost = real domain).

Cases 3 (display-name extraction for digest sender labels) and 4 (email
address format validation) are NOT domain-security gates and are explicitly
excluded from the pin — they act on already-extracted parts of the address,
not on the raw From header.

Pin structure (mirrors A7 ``test_bare_address_ssot_pin_a7.py``):
  * Invariant 1: ``mail_headers.extract_domain`` exists and is the SSOT.
  * Invariant 2: the two domain-gate callers (hints._extract_domain,
    email_watches._domain_of) delegate to it.
  * Invariant 3 (count-agnostic structural): no module outside
    ``mail_headers.py`` has a bare ``addr.split("@", 1)[1]`` or
    ``addr.rsplit("@", 1)[-1]`` on a value that came from a sender/From
    header — detected by heuristic: a rsplit/split("@",...) whose result
    is immediately returned or used in a domain context, outside the SSOT.
  * Behavioural: double-@ spoof resolves consistently to the LAST domain
    across both caller sites.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

# Package root + per-file targets come from the shared harness (R5b) so this
# pin cannot drift in its src-locate / relpath / parse scaffolding. ``SRC_ROOT``
# is ``src/email_triage`` and ``relpath`` yields the canonical ``web/db.py``
# form — the same base this pin already keyed its allow-list on.
_SSOT = SRC_ROOT / "mail_headers.py"
_ALLOWED = {"mail_headers.py"}

# Allowlisted modules with justification — they split("@") on an email
# string but are NOT domain-security gates (classification / watch-fire):
#
# actions/digest.py: ``sender.split("@")[1].split(".")[0]`` in
#   ``_extract_sender_name`` extracts the FIRST domain LABEL as a short
#   display name for the digest ("news@techpresso.com" → "Techpresso").
#   It is a presentation helper, not a rule-match gate.
#
# db/accounts.py: ``s.split("@")[-1]`` in ``looks_like_email_address``
#   validates that the host part of a candidate address contains a dot.
#   It is a format-check predicate, not a rule-match gate.
#
# Any NEW allowlist entry requires a justification comment here explaining
# why the split is not a classification / watch-fire domain gate.
_ALLOWED_MODULES = {
    "actions/digest.py",   # display-name extraction (not a security gate)
    "db/accounts.py",      # email format validation (not a security gate)
}


# ---------------------------------------------------------------------------
# Invariant 1 — the SSOT exists and lives in mail_headers.py
# ---------------------------------------------------------------------------

def test_extract_domain_ssot_exists():
    """mail_headers.extract_domain must be importable."""
    from email_triage.mail_headers import extract_domain
    assert callable(extract_domain)


def test_extract_domain_ssot_defined_in_mail_headers():
    """extract_domain is defined in mail_headers.py (not imported from
    elsewhere — it IS the SSOT)."""
    tree = parse_module(_SSOT); assert tree is not None  # N-350 R31
    defined = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "extract_domain" in defined, (
        "extract_domain is not defined in mail_headers.py — "
        "the N-71 SSOT must live there."
    )


# ---------------------------------------------------------------------------
# Invariant 2 — the two domain-gate callers delegate to the SSOT
# ---------------------------------------------------------------------------

_GATE_CALLERS = {
    "classify/hints.py": "_extract_domain",
    "web/email_watches.py": "_domain_of",
}


def test_domain_gate_callers_delegate_to_ssot():
    """hints._extract_domain and email_watches._domain_of must reference
    mail_headers.extract_domain (the N-71 SSOT)."""
    offenders = []
    for caller_rel, fn_name in _GATE_CALLERS.items():
        text = (SRC_ROOT / caller_rel).read_text(encoding="utf-8")
        # The function must reference the SSOT name.
        if "extract_domain" not in text:
            offenders.append(
                f"{caller_rel}::{fn_name} does not reference extract_domain "
                "(from mail_headers)"
            )
    assert not offenders, (
        "A domain-gate caller does not delegate to mail_headers.extract_domain: "
        f"{offenders}. Route it through extract_domain(sender) so double-@ "
        "spoof addresses resolve to the correct (last) domain."
    )


# ---------------------------------------------------------------------------
# Invariant 3 — count-agnostic structural pin: no module outside
# mail_headers.py performs a raw split("@") on a value named
# ``sender`` / ``addr`` / ``address`` / ``from_`` that is returned as a
# domain string (or used in a domain match context).
#
# Scope: we pin the KNOWN-UNSAFE pattern — a bare split/rsplit on "@" whose
# RESULT is used directly as a domain (not for extracting the local part).
# The digest.py and accounts.py usages are explicitly excluded (they operate
# on already-normalised parts; they are display-name and validation paths
# respectively, NOT domain-gate paths). The pin catches NEW code that
# re-rolls the domain gate outside the SSOT.
#
# The heuristic: an ast.Attribute call with attr ``split`` or ``rsplit``
# whose first arg is the constant ``"@"`` and whose result is subscripted
# with a numeric index ([-1], [1], [0]) — the classic domain-extraction
# shape.
# ---------------------------------------------------------------------------

_AT_SPLIT_METHODS = {"split", "rsplit"}


def _is_at_split_call(node: ast.AST) -> bool:
    """Detects foo.split("@") or foo.rsplit("@", ...) call shapes."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr not in _AT_SPLIT_METHODS:
        return False
    if not node.args:
        return False
    return (
        isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "@"
    )


def _is_domain_subscript(node: ast.AST) -> bool:
    """Detects <split_call>[-1] or <split_call>[1] — the domain-extraction
    index pattern.  Index [0] = the local part (not a domain gate)."""
    if not isinstance(node, ast.Subscript):
        return False
    # Index value: -1 or positive integer > 0.
    sl = node.slice
    if isinstance(sl, ast.Constant):
        if isinstance(sl.value, int) and sl.value not in (0,):
            return _is_at_split_call(node.value)
    if isinstance(sl, ast.UnaryOp) and isinstance(sl.op, ast.USub):
        if isinstance(sl.operand, ast.Constant) and sl.operand.value == 1:
            return _is_at_split_call(node.value)
    return False


def _find_domain_split_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        if path.name in _ALLOWED:
            continue
        rel_str = relpath(path)  # canonical "actions/digest.py" form — the allow-list key base
        if rel_str in _ALLOWED_MODULES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        # Violation message keeps the repo-root-relative form ("src/email_triage/...");
        # message-only, never an allow-list/equality key.
        rel = relpath(path, SRC_ROOT.parents[1])
        for n in ast.walk(tree):
            if _is_domain_subscript(n):
                # Only flag when the split receiver is named like a sender/addr
                # variable — avoids false positives on domain-unrelated @-splits
                # (e.g. email address validation, alias generation).
                recv = n.value
                if isinstance(recv, ast.Call):
                    # The split's receiver is the call's own receiver.
                    obj = recv.func.value if isinstance(recv.func, ast.Attribute) else None
                    if isinstance(obj, ast.Name):
                        if obj.id.lower() in {
                            "sender", "addr", "address", "from_", "from",
                            "s", "a",  # common loop vars for sender strings
                        }:
                            violations.append(f"{rel}:{getattr(n, 'lineno', '?')}")
    return violations


def test_no_raw_at_split_domain_extraction():
    """No module outside mail_headers.py performs a raw split(@)[±1] on a
    sender/addr variable to extract the domain portion (N-71 structural guard).
    New domain-gate code must use mail_headers.extract_domain(sender)."""
    violations = _find_domain_split_violations()
    assert violations == [], (
        "A raw split('@')[±1] domain-extraction on a sender/addr variable was "
        "found outside mail_headers.py (N-71 divergence guard):\n  "
        + "\n  ".join(violations)
        + "\nUse mail_headers.extract_domain(sender) instead — it composes "
        "extract_bare_address + rsplit correctly and handles double-@ spoofs."
    )


def test_pin_has_teeth_rsplit_domain(tmp_path):
    """The pin catches a planted raw rsplit('@')[-1] on 'sender'."""
    planted = ast.parse(
        "def f(sender):\n"
        "    domain = sender.rsplit('@', 1)[-1]\n"
        "    return domain\n"
    )
    hits = [n for n in ast.walk(planted) if _is_domain_subscript(n)]
    assert hits, "pin missed a planted rsplit('@')[-1]"


def test_pin_has_teeth_split_domain(tmp_path):
    """The pin catches a planted raw split('@')[1] on 'addr'."""
    planted = ast.parse(
        "def f(addr):\n"
        "    return addr.split('@', 1)[1]\n"
    )
    hits = [n for n in ast.walk(planted) if _is_domain_subscript(n)]
    assert hits, "pin missed a planted split('@')[1]"


def test_pin_does_not_flag_local_part_extraction(tmp_path):
    """split('@')[0] is the local-part, NOT a domain gate — must not be flagged."""
    ok = ast.parse(
        "def f(sender):\n"
        "    return sender.split('@')[0]\n"  # [0] = local part
    )
    hits = [n for n in ast.walk(ok) if _is_domain_subscript(n)]
    assert not hits, "pin incorrectly flagged split('@')[0] (local-part extraction)"


# ---------------------------------------------------------------------------
# Behavioural tests — the SSOT must resolve double-@ spoofs correctly and
# behave identically to the callers' previous implementations on clean inputs.
# ---------------------------------------------------------------------------

class TestExtractDomainSSOT:
    def test_bare_address(self):
        from email_triage.mail_headers import extract_domain
        assert extract_domain("user@example.com") == "example.com"

    def test_display_name_form(self):
        from email_triage.mail_headers import extract_domain
        assert extract_domain('"CTOx" <news@email.ctox.com>') == "email.ctox.com"

    def test_no_at_returns_empty(self):
        from email_triage.mail_headers import extract_domain
        assert extract_domain("notanemail") == ""
        assert extract_domain("") == ""
        assert extract_domain(None) == ""  # type: ignore[arg-type]

    def test_double_at_spoof_resolves_to_last_domain(self):
        """Security-critical: a double-@ spoof must resolve to the LAST (real)
        domain, not the first.  split("@",1)[1] would give 'b' here (wrong),
        rsplit("@",1)[-1] gives 'evil.com' which is what the SSOT returns.

        In practice, extract_bare_address first strips display names; the
        resulting bare addr-spec is what gets split.  If the addr-spec itself
        contains two @ signs (malformed per RFC but occasionally seen on the
        wire), the LAST segment is the domain.
        """
        from email_triage.mail_headers import extract_domain, extract_bare_address
        # Simulate a malformed bare addr-spec with two @ signs.
        # extract_bare_address on "a@b@evil.com" (no angle brackets) → "a@b@evil.com"
        # extract_domain should then give "evil.com".
        assert extract_domain("a@b@evil.com") == "evil.com"

    def test_subdomain_preserved(self):
        from email_triage.mail_headers import extract_domain
        assert extract_domain("noreply@mail.example.co.uk") == "mail.example.co.uk"

    def test_case_folded(self):
        from email_triage.mail_headers import extract_domain
        assert extract_domain("User@EXAMPLE.COM") == "example.com"

    def test_callers_agree_on_double_at_spoof(self):
        """hints._extract_domain and email_watches._domain_of must return
        the same value as the SSOT for a double-@ spoof address — the
        consistency guarantee the SSOT provides."""
        from email_triage.mail_headers import extract_domain
        from email_triage.classify.hints import _extract_domain as hints_ed
        from email_triage.web.email_watches import _domain_of

        spoof = "a@b@evil.com"
        expected = extract_domain(spoof)   # "evil.com"

        assert hints_ed(spoof) == expected, (
            f"hints._extract_domain({spoof!r}) = {hints_ed(spoof)!r}, "
            f"expected {expected!r} (SSOT result)"
        )
        # _domain_of takes a From header; wrap in a display-name for realism.
        # The bare-address layer extracts "a@b@evil.com" first.
        assert _domain_of(spoof) == expected, (
            f"email_watches._domain_of({spoof!r}) = {_domain_of(spoof)!r}, "
            f"expected {expected!r} (SSOT result)"
        )
