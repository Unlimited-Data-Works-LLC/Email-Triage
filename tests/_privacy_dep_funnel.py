"""The ONE admission predicate for every privacy dependency walk (punch 513).

Two surfaces install third-party packages into an install that handles ePHI:

* ``pyproject.toml`` — the app's own declared dependencies, walked by
  ``tests/test_privacy_invariants_dep_review.py`` (M-9).
* ``scripts/embedding-bits-manifest.json`` — the wheels the embedding
  lazy-install puts into ``/app/data/runtime-deps/site-packages``
  INSIDE the PHI-bearing container, walked by
  ``tests/test_privacy_invariants_no_embedding_telemetry.py``.

Until 2026-09-25 only the first surface had an identity gate: the manifest
test reviewed download HOSTS and nothing reviewed the package IDENTITIES
(hipaa-sme N4 / CAL-3; register §3 row "Runtime embedding package set —
identity review"). Closing that by copying the denylist into the manifest
test would have produced exactly the two-mirrored-copies drift Prime
Directive #5 forbids, so the predicate lives HERE and both walks import it.

WHAT THE PREDICATE IS (one funnel, two reviewed sets)
-----------------------------------------------------
``admission_failure(name, reviewed=…)`` returns ``None`` when a package is
admitted and a reason string when it is not. Two gates, in order:

1. the HARD denylist — ``AI provider`` / ``groq`` / the ``AI provider-*`` and
   ``the AI assistant-*`` families. Never overrideable, on EITHER surface, because
   ``feedback_no_anthropic`` excludes AI provider full stop.
2. the reviewed sets — a package must appear in the reviewed set for the
   surface it lands on, or in ``internal documentation`` as an
   operator-recorded exception.

The reviewed sets stay SEPARATE per surface on purpose: ``_KNOWN_SAFE``
(pyproject) holds dev-only names like ``pytest-xdist``, and unioning the
two would admit them into the runtime container, while
``RUNTIME_KNOWN_SAFE`` holds names like ``torch`` that have no business
being admitted into ``pyproject.toml`` unreviewed. Three packages are on
both lists (``jinja2``, ``packaging``, ``markdown-it-py``) — genuinely
both declared AND installed at runtime, reviewed once per surface.

PUBLISH NOTE (deliberate, not an oversight)
-------------------------------------------
This module SHIPS to the public mirror (the ``tests/*`` allow glob), and so
does the manifest walk that imports it.
``tests/test_privacy_invariants_dep_review.py`` and
``internal documentation`` do NOT ship. That is why the override
parser returns an EMPTY set when the doc is absent rather than asserting it
exists: on the mirror the override door simply does not exist, so
admission rests on the in-gate reviewed set alone — strictly more
conservative (fail closed), never more permissive.
"""

from __future__ import annotations

import re
from typing import Iterable

from _pin_harness import REPO_ROOT  # the harness owns the repo root (PD#6)

ALLOWLIST_FILE = REPO_ROOT / "docs" / "privacy-dep-allowlist.md"  # publish: absent-tolerant: a missing doc parses to no overrides, so it can only REFUSE more, never admit more; the claim binds every SHIPPED consumer of this constant, not just parse_allowlist_overrides() -- the one consumer that hard-asserts .exists() (test_allowlist_file_is_present) is dev-only and stripped from the mirror; pinned by test_the_override_door_degrades_closed_when_its_doc_is_absent
MANIFEST_FILE = REPO_ROOT / "scripts" / "embedding-bits-manifest.json"
MANIFEST_BUILDER = REPO_ROOT / "scripts" / "build-embedding-bits-manifest.py"

# The ``required_by`` value for a manifest wheel nothing else in the
# manifest requires — a DIRECT install target of the app. One literal on
# each side; ``build-embedding-bits-manifest.py::ROOT_REQUIRER`` is the
# other, and ``test_root_requirer_literal_agrees_with_the_generator``
# pins them equal.
ROOT_REQUIRER = "email-triage"


# ---------------------------------------------------------------------------
# Hard denylist -- never overrideable, on either surface
# ---------------------------------------------------------------------------

# Exact-match denylist of normalised dep names.
DENYLIST_EXACT: frozenset[str] = frozenset({
    "anthropic",
    "groq",
})

# Regex denylist for SDK family renames, matched against a normalised name.
DENYLIST_REGEX: tuple[re.Pattern[str], ...] = (
    re.compile(r"^anthropic[-]"),  # AI provider-sdk, AI provider-tools, ...
    re.compile(r"^claude[-]"),     # the AI assistant-sdk, the AI assistant-tools, ...
)


# ---------------------------------------------------------------------------
# Reviewed set -- the embedding lazy-install runtime surface
# ---------------------------------------------------------------------------

# Every package the embedding manifest installs into the PHI-bearing
# container, with the package that REQUIRES it (the manifest's own
# ``required_by`` field is the machine-derived record; these comments are
# the human-readable half). A manifest regeneration that adds a name not
# in this set fails the identity walk until an operator reviews it and
# adds it here — the same posture ``_KNOWN_SAFE`` gives ``pyproject.toml``.
#
# Derived 2026-09-25 from the pinned wheels' own ``METADATA``
# ``Requires-Dist`` (extras-gated requirements excluded), NOT from memory:
# the seven "Added in the v0.1.1 HF stack bump" entries turned out to hang
# off ``typer`` (which transformers 5.x and huggingface-hub 1.x both
# require for their CLIs), not off transformers directly.
RUNTIME_KNOWN_SAFE: frozenset[str] = frozenset({
    # --- the direct install target ---
    "sentence-transformers",   # required_by: email-triage (embedding extra)
    # --- the HF/torch stack ---
    "transformers",            # <- sentence-transformers
    "huggingface-hub",         # <- sentence-transformers, tokenizers, transformers
    "tokenizers",              # <- transformers          (binary, per-arch)
    "safetensors",             # <- transformers          (binary, per-arch)
    "regex",                   # <- transformers          (binary, per-arch)
    "hf-xet",                  # <- huggingface-hub       (binary, per-arch)
    "torch",                   # <- sentence-transformers (binary, per-arch, CPU-only)
    "filelock",                # <- huggingface-hub, torch
    "fsspec",                  # <- huggingface-hub, torch
    "packaging",               # <- huggingface-hub, transformers
    "jinja2",                  # <- torch (also a declared app dep)
    "networkx",                # <- torch
    "sympy",                   # <- torch
    "mpmath",                  # <- sympy
    "setuptools",              # <- torch
    # Added 2026-09-30 (punch 555): an unconditional requirement nobody had
    # pinned — in neither requirements.lock nor the image (probe of the running
    # container), so the --no-deps install left the stack unimportable. Its
    # only network hits are tqdm/contrib/{discord,telegram}.py (``requests``,
    # optional extras); tqdm/__init__ does not import contrib. Accepted via
    # --accept-network-import tqdm, recorded in the manifest's audit block.
    "tqdm",                    # <- huggingface-hub, sentence-transformers, transformers
    # --- the sklearn leg (cosine / nearest-neighbour helpers) ---
    "scikit-learn",            # <- sentence-transformers (binary, per-arch)
    "scipy",                   # <- scikit-learn, sentence-transformers (binary, per-arch)
    "joblib",                  # <- scikit-learn
    "threadpoolctl",           # <- scikit-learn
    "pillow",                  # <- sentence-transformers (binary, per-arch; unused image path)
    # --- the typer CLI leg the v0.1.1 HF bump pulled in ---
    "typer",                   # <- huggingface-hub, transformers
    "rich",                    # <- typer
    "shellingham",             # <- typer
    "markdown-it-py",          # <- rich (also a declared dev dep)
    "pygments",                # <- rich
    "mdurl",                   # <- markdown-it-py
})


# ---------------------------------------------------------------------------
# Reviewed set -- production-lock transitives (punch 457 / 773)
# ---------------------------------------------------------------------------

# The 27 distributions that sat in `requirements.lock` in NO reviewed set when the class AI ratchet was
# frozen (2026-10-30). A THIRD set, not a widening of `_KNOWN_SAFE` (pyproject-direct, includes dev-only
# names) or `RUNTIME_KNOWN_SAFE` (the embedding lazy-install manifest): they are lock transitives, and
# unioning them into either surface would admit them where nobody reviewed them. Consumed by
# `unreviewed_closure_names()` in tests/test_privacy_invariants_dep_review.py only.
#
# Reviewed 2026-11-02 on the LOCKED BYTES: each wheel was fetched for linux/cp314 with `--require-hashes`
# against the hashes in requirements.lock (so the bytes read are the bytes the image installs), unzipped, and
# scanned for network-capable imports and call sites, telemetry/analytics words, and hard-coded hosts
# (Python text and compiled-extension strings). Docs/spec URLs are not hosts. Raw output:
# ~/.internal-config/work/email-triage/class-p3/review27.json (review27.py). No name phones home: none carries a
# telemetry client, and none hard-codes a host it connects to. The four telemetry-word hits are false
# positives (a "google analytics" comment in h11/_abnf.py; `searchResEntry` in pyasn1_modules/rfc2251.py; a
# Rust `MapsEntry` symbol in cbor2 and watchfiles). Each line: the lock `# via` requirer, then the finding.
LOCK_KNOWN_SAFE: frozenset[str] = frozenset({
    "annotated-doc",           # <- fastapi.        Type-annotation helper. No network import.
    "annotated-types",         # <- pydantic.       Constraint metadata for typing. No network import.
    "cbor2",                   # <- webauthn.       CBOR codec (native ext). Decodes WebAuthn attestation bytes; no network.
    "cffi",                    # <- cryptography.   C FFI loader (native ext). No network import or host.
    "charset-normalizer",      # <- requests.       Guesses a text encoding from BYTES it is handed. No network.
    "click",                   # <- uvicorn.        CLI toolkit. Its only urllib use is urllib.parse.unquote.
    "greenlet",                # <- sqlalchemy.     Coroutine switching (native ext). No network call site.
    "h11",                     # <- httpcore, uvicorn. HTTP/1.1 sans-I/O parser: it never opens a socket.
    "httpcore",                # <- httpx.          HTTP client transport. Connects ONLY to the address its caller passes; no host, no telemetry.
    "httptools",               # <- uvicorn.        HTTP parser (native ext). Parses bytes; opens nothing.
    "idna",                    # <- anyio, httpx, requests. IDNA codec. No network.
    "pyasn1-modules",          # <- webauthn.       ASN.1 module definitions (RFC schemas). No network import.
    "pycparser",               # <- cffi.           C parser, build-time use. No network.
    "pydantic-core",           # <- pydantic, msal. Validation core (Rust ext). No host string, no network import.
    "pyopenssl",               # <- acme, webauthn. TLS wrapper over a socket the CALLER supplies; no host.
    "pyrfc3339",               # <- acme.           RFC 3339 timestamp parser. No network.
    "python-dateutil",         # <- dateparser, icalendar. Date parsing. No network (doc URLs only).
    "python-dotenv",           # <- uvicorn.        Reads a .env file when asked. No network.
    "pytz",                    # <- dateparser.     Zone data. No network.
    "six",                     # <- python-dateutil. Py2/3 shims. No network.
    "typing-extensions",       # <- fastapi, pydantic, sqlalchemy. Typing backports; imports asyncio for type shims only.
    "typing-inspection",       # <- fastapi, pydantic. Typing introspection. No network.
    "tzdata",                  # <- icalendar.      Zone data files only.
    "tzlocal",                 # <- dateparser.     Reads the local zone name. No network.
    "uvloop",                  # <- uvicorn.        Event loop (native ext). Sockets are opened for the app's own listeners and the addresses callers give; no host string.
    "watchfiles",              # <- uvicorn.        File-change watcher (native ext). No network call site, no host string.
    "websockets",              # <- uvicorn.        WebSocket client/server. Connects only to a URI its caller passes; urllib use is parse and getproxies (env read).
})


# ---------------------------------------------------------------------------
# Predicate + parsers
# ---------------------------------------------------------------------------

def normalise(name: str) -> str:
    """PEP-503 + lowercase. ``Foo_Bar.baz`` -> ``foo-bar-baz``."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def strip_version_spec(spec: str) -> str:
    """Pull the package name out of a requirement string.

    ``"foo>=1.0"`` -> ``"foo"``;
    ``"foo[extra]>=1.0"`` -> ``"foo"`` (extras dropped);
    ``"uvicorn[standard]>=0.30"`` -> ``"uvicorn"``;
    ``"pyjwt[crypto]>=2.8.0"`` -> ``"pyjwt"``.
    """
    s = spec.strip()
    s = re.split(r"[<>=!~;\[]", s, maxsplit=1)[0]
    return normalise(s)


def is_denied(name: str) -> bool:
    """True when ``name`` is on the hard denylist. Not overrideable."""
    norm = normalise(name)
    if norm in DENYLIST_EXACT:
        return True
    return any(pat.search(norm) for pat in DENYLIST_REGEX)


def parse_allowlist_section(heading: str = "Approved exceptions") -> set[str]:
    """Normalised package names bulleted under ``## <heading>``.

    Returns an EMPTY set when the file or the section is missing — the
    operator override door is simply closed then (see the PUBLISH NOTE in
    the module docstring). Never raises: a missing override file must not
    turn into an admission.
    """
    if not ALLOWLIST_FILE.exists():
        return set()
    text = ALLOWLIST_FILE.read_text(encoding="utf-8")
    section = re.search(
        rf"^##\s+{re.escape(heading)}\s*$(.*?)(?=^##\s|\Z)",
        text, re.MULTILINE | re.DOTALL,
    )
    if not section:
        return set()
    names: set[str] = set()
    pattern = re.compile(
        r"-\s+\*\*Package\*\*\s*:\s*`?([A-Za-z0-9_.\-\[\]]+?)`?(?:[<>=!~,\s])",
    )
    for m in pattern.finditer(section.group(1)):
        raw = re.split(r"[\[]", m.group(1), maxsplit=1)[0]
        if raw:
            names.add(normalise(raw))
    return names


def parse_allowlist_overrides() -> set[str]:
    """The operator override set (``## Approved exceptions``)."""
    return parse_allowlist_section()


def admission_failure(
    name: str,
    *,
    reviewed: Iterable[Iterable[str]],
    surface: str = "",
) -> str | None:
    """``None`` when ``name`` is admitted, else why it is not.

    ``reviewed`` is the surface's reviewed name sets (e.g. the in-gate
    known-safe set plus the operator override set). The denylist is
    checked FIRST and cannot be lifted by any of them, so an override
    entry for a denied package still fails — deliberately.
    """
    norm = normalise(name)
    where = f" on {surface}" if surface else ""
    if is_denied(norm):
        return (
            f"{norm!r}{where} is on the HARD privacy denylist "
            f"(feedback_no_anthropic excludes Anthropic full stop); no "
            f"allowlist entry can lift it."
        )
    if any(norm in {normalise(n) for n in names} for names in reviewed):
        return None
    return (
        f"{norm!r}{where} is not in the reviewed set and has no operator "
        f"exception in {ALLOWLIST_FILE.name}. Review the package, then "
        f"record it (the reviewed set for this surface in "
        f"tests/_privacy_dep_funnel.py, or an '## Approved exceptions' "
        f"bullet in {ALLOWLIST_FILE.name})."
    )


# ---------------------------------------------------------------------------
# Lock walk (punch 457) -- the TRANSITIVE closure the image actually installs
# ---------------------------------------------------------------------------

LOCK_FILE = REPO_ROOT / "requirements.lock"  # the production closure (pip-compile --generate-hashes)
DEV_LOCK_FILE = REPO_ROOT / "requirements-dev.lock"  # the CI closure; the denylist binds it too

def lock_files() -> list:
    """EVERY ``requirements*.lock`` at the repo root, by glob (punch 457, DA M1 / DB N3).

    A hand-enumerated pair (production + dev) missed ``requirements-ci-tools.lock``;
    a glob picks up the next lock without anyone remembering to list it."""
    return sorted(REPO_ROOT.glob("requirements*.lock"))


# ``name==version \`` at column 0 (pip-compile also emits ``name[extra]==...`` and
# `` ; marker`` suffixes, both tolerated); `` --hash=`` and `` # via`` lines are indented.
# ``name @ url`` is a PEP 508 direct reference (no ``==``): it installs a package from
# a URL, so its NAME meets the denylist too (DB N3: ``==`` alone let it escape).
_LOCK_PIN_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:==|@)", re.MULTILINE
)


def parse_lock_names(text: str) -> list[str]:
    """Sorted, normalised distribution names pinned in a pip-compile lock.

    The pyproject walk sees only the hand-written surface; this sees the
    transitive closure that reaches the image, which is where a new package
    arrives without a review row (punch 457)."""
    return sorted({normalise(m.group(1)) for m in _LOCK_PIN_RE.finditer(text)})
