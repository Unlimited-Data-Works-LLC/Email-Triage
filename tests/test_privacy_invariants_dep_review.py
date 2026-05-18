"""Dependency-list privacy guard (M-9).

Walks ``pyproject.toml`` ``dependencies`` + ``optional-dependencies``
and fails if anything outside the known-safe set lands without an
explicit operator-reviewed exception in
``docs/privacy-dep-allowlist.md``.

The two surfaces this enforces:

1. **Hard denylist** -- packages that may NEVER appear, regardless of
   override. Currently ``anthropic``, ``groq`` (and any name matching
   the regex pattern ``r"^anthropic[-_]"`` to catch future SDK
   renames). The denylist exists because the project's standing rule
   ``feedback_no_anthropic.md`` excludes Anthropic full stop. The
   override file CANNOT lift the denylist.

2. **Known-safe allowlist** -- the curated set of packages whose data
   flow has been audited. Anything outside this set must appear in
   ``docs/privacy-dep-allowlist.md`` as a bullet under
   ``## Approved exceptions`` with the documented format.

When this test fails, the failure message names the offending package,
the section of ``pyproject.toml`` it appeared in, and the file the
operator should edit to record the exception.

See ``docs/privacy-audit-runbook.md`` for the full operator contract.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
ALLOWLIST_FILE = REPO_ROOT / "docs" / "privacy-dep-allowlist.md"


# ---------------------------------------------------------------------------
# Hard denylist -- never overrideable
# ---------------------------------------------------------------------------

# Exact-match denylist of dep names. Lowercase comparison; PEP-503
# normalisation handled by the parser below (s/[-_.]+/-/g).
_DENYLIST_EXACT: frozenset[str] = frozenset({
    "anthropic",
    "groq",
})

# Regex denylist for SDK family renames. Matches a normalised dep
# name (lowercase, PEP-503).
_DENYLIST_REGEX: tuple[re.Pattern[str], ...] = (
    re.compile(r"^anthropic[-]"),  # anthropic-sdk, anthropic-tools, ...
    re.compile(r"^claude[-]"),     # claude-sdk, claude-tools, ...
)


# ---------------------------------------------------------------------------
# Known-safe allowlist
# ---------------------------------------------------------------------------

# Concrete enumeration of every dep currently in pyproject.toml. New
# additions either land here (after a privacy review) or in
# docs/privacy-dep-allowlist.md (per-dep operator override).
#
# Names are normalised: lowercased, with [-_.] runs collapsed to "-".
_KNOWN_SAFE: frozenset[str] = frozenset({
    # Required deps -- core protocol / web / mail libraries.
    "pyyaml",
    "httpx",
    "mcp",
    "fastapi",
    "uvicorn",
    "jinja2",
    "python-multipart",
    "itsdangerous",
    "pyjwt",
    "icalendar",
    "cryptography",
    "webauthn",
    "acme",
    "josepy",
    "dnspython",
    "numpy",            # local-only vector math for sent-mail RAG cosine (#136)
    # Optional extras -- local-only or operator-opt-in surfaces.
    "keyring",          # OS-keyring backend for master-key storage
    "aioimaplib",       # IMAP fetch (with the recursion patch)
    "msal",             # O365 OAuth (Microsoft library)
    "openai",           # opt-in classifier backend (operator-chosen)
    "google-generativeai",  # opt-in Gemini classifier backend
    "redis",            # opt-in classification cache (#151) — LAN-only by policy
    "pytest",
    "pytest-asyncio",
    "pytest-xdist",     # parallel test runner — dev-only, no network/PHI exposure
})


# ---------------------------------------------------------------------------
# Parser -- pure Python, tolerates the limited TOML subset pyproject uses
# ---------------------------------------------------------------------------

def _normalise(name: str) -> str:
    """PEP-503 + lowercase. ``Foo_Bar.baz`` -> ``foo-bar-baz``."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _strip_version_spec(spec: str) -> str:
    """Pull the package name out of a requirement string.

    ``"foo>=1.0"`` -> ``"foo"``;
    ``"foo[extra]>=1.0"`` -> ``"foo"`` (extras dropped);
    ``"uvicorn[standard]>=0.30"`` -> ``"uvicorn"``;
    ``"pyjwt[crypto]>=2.8.0"`` -> ``"pyjwt"``.
    """
    s = spec.strip()
    # Strip leading whitespace + comments.
    s = re.split(r"[<>=!~;\[]", s, maxsplit=1)[0]
    return _normalise(s)


def _parse_pyproject() -> dict[str, list[str]]:
    """Return a dict mapping section name -> list of normalised package
    names. Sections covered:

    - ``dependencies`` (required)
    - ``optional-dependencies.<name>`` (one section per extra)
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    out: dict[str, list[str]] = {}

    # Pull the [project] dependencies = [...] block.
    deps = _extract_list(text, key="dependencies")
    if deps is not None:
        out["dependencies"] = [_strip_version_spec(d) for d in deps if d.strip()]

    # Pull each entry under [project.optional-dependencies].
    extras = _extract_optional_extras(text)
    for extra_name, items in extras.items():
        section = f"optional-dependencies.{extra_name}"
        out[section] = [_strip_version_spec(d) for d in items if d.strip()]

    return out


def _scan_balanced_list(text: str, start: int) -> tuple[int, str] | None:
    """From position ``start`` (must point AT or BEFORE the opening
    ``[``), scan forward and return ``(end_idx, body)`` covering the
    matched bracket pair.

    Skips over quoted strings (so ``"uvicorn[standard]"`` doesn't
    confuse the bracket counter). Returns ``None`` if no opening
    bracket is found or the list never closes.
    """
    n = len(text)
    i = start
    # Find the opening bracket.
    while i < n and text[i] != "[":
        i += 1
    if i >= n:
        return None
    open_idx = i
    depth = 1
    j = open_idx + 1
    while j < n and depth > 0:
        ch = text[j]
        if ch == '"' or ch == "'":
            # Skip over the quoted string body. TOML basic strings
            # don't support escaped close-quotes via backslash inside
            # this project's pyproject (no need to handle them), but
            # we tolerate ``\"`` defensively.
            quote = ch
            j += 1
            while j < n and text[j] != quote:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            j += 1  # skip closing quote
            continue
        if ch == "#":
            # Inline comment to end-of-line.
            while j < n and text[j] != "\n":
                j += 1
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return j, text[open_idx + 1 : j]
        j += 1
    return None


def _strip_toml_comments(text: str) -> str:
    """Remove ``# ...`` comment runs while preserving quoted strings.

    TOML comments are full-line or trailing-after-content. Apostrophes
    inside comments (``Duo's library``) confuse a naive
    ``"..."``-vs-``'...'`` regex, so we drop comments before that
    regex runs.
    """
    out: list[str] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if ch == '"' or ch == "'":
            quote = ch
            out.append(ch)
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i])
                    out.append(text[i + 1])
                    i += 2
                    continue
                out.append(text[i])
                i += 1
            if i < n:
                out.append(text[i])
                i += 1
            continue
        if ch == "#":
            # Skip to end of line (do not append).
            while i < n and text[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _extract_list(text: str, *, key: str) -> list[str] | None:
    """Find ``<key> = [...]`` inside the [project] block. Tolerant of
    multi-line lists AND of bracket characters inside quoted items
    (e.g. ``"uvicorn[standard]>=0.30"``)."""
    # Strip TOML comments first so apostrophes inside comments
    # ("Duo's library") don't break the quoted-string regex below.
    text = _strip_toml_comments(text)

    # Scope to the [project] section.
    project_pat = re.compile(r"^\[project\]\s*$", re.MULTILINE)
    pm = project_pat.search(text)
    if not pm:
        project_block_start = 0
    else:
        project_block_start = pm.end()
    # End at the next top-level section header.
    after_pat = re.compile(r"^\[[^\]]+\]\s*$", re.MULTILINE)
    am = after_pat.search(text, pos=project_block_start)
    project_block_end = am.start() if am else len(text)
    project_block = text[project_block_start:project_block_end]

    key_pat = re.compile(
        rf"^\s*{re.escape(key)}\s*=\s*",
        re.MULTILINE,
    )
    km = key_pat.search(project_block)
    if not km:
        return None
    scanned = _scan_balanced_list(project_block, km.end())
    if scanned is None:
        return None
    _, body = scanned
    items: list[str] = []
    for raw in re.findall(r'"([^"]*)"|\'([^\']*)\'', body):
        item = raw[0] or raw[1]
        if item:
            items.append(item)
    return items


def _extract_optional_extras(text: str) -> dict[str, list[str]]:
    """Find every ``<name> = [...]`` under
    ``[project.optional-dependencies]``. Same balanced-bracket
    scanner as ``_extract_list``."""
    text = _strip_toml_comments(text)
    header_pat = re.compile(
        r"^\[project\.optional-dependencies\]\s*$", re.MULTILINE,
    )
    hm = header_pat.search(text)
    if not hm:
        return {}
    section_start = hm.end()
    # End at the next [...] section header.
    after_pat = re.compile(r"^\[[^\]]+\]\s*$", re.MULTILINE)
    am = after_pat.search(text, pos=section_start)
    section_end = am.start() if am else len(text)
    body = text[section_start:section_end]

    extras: dict[str, list[str]] = {}
    name_pat = re.compile(r"^(\w[\w\-]*)\s*=\s*", re.MULTILINE)
    for m in name_pat.finditer(body):
        name = m.group(1).strip()
        scanned = _scan_balanced_list(body, m.end())
        if scanned is None:
            continue
        _, items_body = scanned
        items: list[str] = []
        for raw in re.findall(r'"([^"]*)"|\'([^\']*)\'', items_body):
            item = raw[0] or raw[1]
            if item:
                items.append(item)
        extras[name] = items
    return extras


# ---------------------------------------------------------------------------
# Override file parser -- bullets under "## Approved exceptions"
# ---------------------------------------------------------------------------

def _parse_allowlist_overrides() -> set[str]:
    """Return the set of normalised package names listed under
    ``## Approved exceptions`` in the allowlist file. Empty set when
    the file is missing or the section is empty."""
    if not ALLOWLIST_FILE.exists():
        return set()
    text = ALLOWLIST_FILE.read_text(encoding="utf-8")

    # Find the "## Approved exceptions" section, scope to the next
    # ## heading or EOF.
    section_match = re.search(
        r"^##\s+Approved exceptions\s*$(.*?)(?=^##\s|\Z)",
        text, re.MULTILINE | re.DOTALL,
    )
    if not section_match:
        return set()
    body = section_match.group(1)

    overrides: set[str] = set()
    # Each entry is a bullet starting with "- **Package**: <name>...".
    # The PyPI name lives between **Package**: and a comma / version
    # specifier / newline. Tolerant of backticks around the name.
    pattern = re.compile(
        r"-\s+\*\*Package\*\*\s*:\s*`?([A-Za-z0-9_.\-\[\]]+?)`?(?:[<>=!~,\s])",
    )
    for m in pattern.finditer(body):
        raw = m.group(1)
        # Drop extras "[foo]" before normalising.
        raw = re.split(r"[\[]", raw, maxsplit=1)[0]
        if raw:
            overrides.add(_normalise(raw))
    return overrides


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPyprojectDenylist:
    """The denylist is an immovable contract: no override, no
    exception. Any future commit that adds an Anthropic / Groq /
    Claude-family SDK to ``pyproject.toml`` MUST fail this test."""

    def test_no_anthropic_in_required_deps(self):
        sections = _parse_pyproject()
        deps = sections.get("dependencies", [])
        offenders = [d for d in deps if _is_denied(d)]
        assert not offenders, (
            f"Hard denylist hit in [project] dependencies: {offenders}. "
            f"feedback_no_anthropic.md excludes Anthropic full stop; "
            f"this cannot be overridden via the allowlist file."
        )

    def test_no_anthropic_in_optional_deps(self):
        sections = _parse_pyproject()
        offenders: list[str] = []
        for section_name, deps in sections.items():
            if not section_name.startswith("optional-dependencies."):
                continue
            for d in deps:
                if _is_denied(d):
                    offenders.append(f"{section_name}::{d}")
        assert not offenders, (
            f"Hard denylist hit in optional-dependencies: {offenders}. "
            f"feedback_no_anthropic.md excludes Anthropic full stop."
        )


class TestPyprojectAllowlist:
    """Every dep must be either in the known-safe set OR appear in
    ``docs/privacy-dep-allowlist.md`` with a documented exception."""

    def test_required_deps_are_known_safe_or_allowlisted(self):
        sections = _parse_pyproject()
        overrides = _parse_allowlist_overrides()
        deps = sections.get("dependencies", [])
        unknown = [
            d for d in deps
            if d not in _KNOWN_SAFE and d not in overrides
        ]
        assert not unknown, (
            f"Unknown deps in [project] dependencies: {unknown}. "
            f"Either add a privacy review entry to "
            f"{ALLOWLIST_FILE.relative_to(REPO_ROOT)} or move the dep "
            f"out of pyproject.toml."
        )

    def test_optional_extras_are_known_safe_or_allowlisted(self):
        sections = _parse_pyproject()
        overrides = _parse_allowlist_overrides()
        unknown: list[str] = []
        for section_name, deps in sections.items():
            if not section_name.startswith("optional-dependencies."):
                continue
            for d in deps:
                if d not in _KNOWN_SAFE and d not in overrides:
                    unknown.append(f"{section_name}::{d}")
        assert not unknown, (
            f"Unknown deps in optional-dependencies: {unknown}. "
            f"Either add a privacy review entry to "
            f"{ALLOWLIST_FILE.relative_to(REPO_ROOT)} or move the dep "
            f"out of pyproject.toml."
        )


class TestDenylistMatcher:
    """Pin the matcher behaviour so a future contributor adding a new
    Anthropic-shaped name (anthropic-sdk, claude-tools, etc.) hits the
    denylist as expected."""

    @pytest.mark.parametrize("name", [
        "anthropic", "Anthropic", "ANTHROPIC",
        "anthropic-sdk", "anthropic_python", "Anthropic.SDK",
        "claude-sdk", "claude-tools",
        "groq",
    ])
    def test_denied_names_are_denied(self, name):
        assert _is_denied(_normalise(name)), (
            f"{name!r} should be denied by the privacy denylist"
        )

    @pytest.mark.parametrize("name", [
        "openai", "google-generativeai", "httpx", "fastapi",
        "anth",       # not a denied prefix
        "opus",       # could be a different package
    ])
    def test_non_denied_names_pass(self, name):
        assert not _is_denied(_normalise(name)), (
            f"{name!r} should NOT be on the denylist"
        )


class TestParserIntegrity:
    """Make sure the parser actually pulls every dep section out of
    pyproject.toml. Drift here would silently green-light additions."""

    def test_parser_finds_required_deps(self):
        sections = _parse_pyproject()
        assert "dependencies" in sections
        deps = sections["dependencies"]
        # Cross-check against known-stable entries (these are pinned
        # at the pyproject.toml level for years -- if any is missing,
        # the parser regressed).
        assert "fastapi" in deps
        assert "httpx" in deps
        assert "jinja2" in deps

    def test_parser_finds_optional_extras(self):
        sections = _parse_pyproject()
        section_names = [s for s in sections if s.startswith("optional-")]
        # We expect at least one optional-dependencies section.
        assert section_names, (
            "Parser did not find any optional-dependencies sections; "
            "pyproject.toml has [project.optional-dependencies] today"
        )

    def test_allowlist_file_is_present(self):
        """The allowlist file is part of the privacy-audit contract --
        if it goes missing, the override mechanism breaks silently."""
        assert ALLOWLIST_FILE.exists(), (
            f"Privacy dep-allowlist file missing: "
            f"{ALLOWLIST_FILE.relative_to(REPO_ROOT)}. Required by "
            f"M-9 -- recreate from docs/privacy-audit-runbook.md."
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_denied(name: str) -> bool:
    """True when ``name`` (already normalised) is on the hard denylist.

    Exposed at module scope so the parametrized matcher tests can
    exercise the same predicate the section tests rely on.
    """
    norm = _normalise(name)
    if norm in _DENYLIST_EXACT:
        return True
    for pat in _DENYLIST_REGEX:
        if pat.search(norm):
            return True
    return False
