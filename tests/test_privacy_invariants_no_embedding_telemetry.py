"""Privacy invariant — embedding-bits installer makes NO telemetry calls.

The lazy-install path (#180) downloads wheels + model files over
HTTPS. The only URLs the installer is permitted to contact are the
ones listed in scripts/embedding-bits-manifest.json (resolved via
PyPI JSON API for placeholder PyPI URLs at build time, baked into
the manifest at release-cut time).

This is a STATIC SOURCE SCAN — not a runtime test. We grep the
embedding_bits package source for any literal URL that isn't an
allowlisted host. Adding a new HTTP call to the installer requires
adding the host to the allowlist here (which is a security review
gate, not a refactor).

Why static-source:
* A runtime test would require running the installer to confirm.
  Some telemetry endpoints fire only on rare paths (model auto-
  download retry, upgrade ping). Static scan catches them all.
* Tests grep the SOURCE, not the BUILT module — Python bytecode
  could in principle hide a literal URL behind base64 / format
  ops; the source check is the truth.

Allowlisted hosts (download endpoints in the production manifest):
  download.pytorch.org    PyTorch CPU index (torch wheel)
  files.pythonhosted.org  PyPI hosted-file CDN (all other wheels)
  pypi.org                PyPI JSON metadata API (URL resolution
                          step in the builder script)
  huggingface.co          HuggingFace model file CDN

Banned hosts (HF / pip / Python telemetry):
  hf.co                                 abbreviated HF (telemetry sometimes)
  huggingface.co/api/telemetry         explicit HF telemetry endpoint
  pypi.org/simple                       not used; we only hit JSON
  api.github.com                        not used in installer path
  api.pypistats.org                     not used
  warehouse.python.org                  not used
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# --- which files this invariant covers ---
PKG_ROOT = Path(__file__).resolve().parent.parent / "src" / "email_triage"

EMBEDDING_BITS_SOURCES = [
    PKG_ROOT / "embedding_bits" / "__init__.py",
    # The manifest builder is in scripts/; same allowlist applies.
    PKG_ROOT.parent.parent / "scripts" / "build-embedding-bits-manifest.py",
]


# --- allowlist: literal substrings permitted in URLs ---
ALLOWLISTED_HOSTS = (
    "download.pytorch.org",
    "files.pythonhosted.org",
    "pypi.org",          # used only for JSON metadata in the builder
    "huggingface.co",    # model file CDN
    "example.test",      # test fixtures
    "github.com",        # commit message / user-agent strings
)

# Hosts that should NEVER appear in the installer module.
BANNED_HOSTS = (
    "hf.co",
    "api.github.com",
    "api.pypistats.org",
    "warehouse.python.org",
    "googleapis.com",     # GCS / Drive — out of scope
    "amazonaws.com",      # S3 — out of scope
)


URL_REGEX = re.compile(r'https?://([a-zA-Z0-9_.\-]+)/?[^\s\'"]*')


@pytest.mark.parametrize("path", EMBEDDING_BITS_SOURCES, ids=lambda p: p.name)
def test_no_banned_urls(path: Path):
    """No banned host appears in the embedding-bits installer source."""
    if not path.exists():
        pytest.skip(f"{path} not present in this checkout")
    text = path.read_text(encoding="utf-8")
    for host in BANNED_HOSTS:
        assert host not in text, (
            f"Banned host {host!r} found in {path}; this is a privacy "
            f"regression — embedding-bits installer must NOT call "
            f"telemetry / out-of-scope endpoints. Either remove the "
            f"call or update the privacy review."
        )


@pytest.mark.parametrize("path", EMBEDDING_BITS_SOURCES, ids=lambda p: p.name)
def test_every_url_is_allowlisted(path: Path):
    """Every literal URL in the installer module points at an allowlisted host."""
    if not path.exists():
        pytest.skip(f"{path} not present in this checkout")
    text = path.read_text(encoding="utf-8")
    for match in URL_REGEX.finditer(text):
        host = match.group(1)
        if any(host == h or host.endswith("." + h) for h in ALLOWLISTED_HOSTS):
            continue
        pytest.fail(
            f"URL host {host!r} found in {path} is NOT in the privacy "
            f"allowlist. Either add the host to ALLOWLISTED_HOSTS in "
            f"tests/test_privacy_invariants_no_embedding_telemetry.py "
            f"(after security review) or remove the URL from the "
            f"installer."
        )


def test_pip_telemetry_disabled_in_env():
    """The installer module unconditionally sets PIP_DISABLE_PIP_VERSION_CHECK
    and HF_HUB_DISABLE_TELEMETRY at module import time."""
    src_text = (PKG_ROOT / "embedding_bits" / "__init__.py").read_text(
        encoding="utf-8",
    )
    # These setdefault() calls run at import time
    assert 'os.environ.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")' in src_text
    assert 'os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")' in src_text
    assert 'os.environ.setdefault("DO_NOT_TRACK", "1")' in src_text
