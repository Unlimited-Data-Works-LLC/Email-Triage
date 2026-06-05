"""Portable email triage system with LLM classification and configurable routing."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("email-triage")
except PackageNotFoundError:
    # Raw source tree with no install (pip never ran) — no .dist-info to read.
    __version__ = "0.0.0+unknown"
