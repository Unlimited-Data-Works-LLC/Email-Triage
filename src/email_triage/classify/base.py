"""Abstract classifier interface for email triage.

All LLM backends implement this interface so the flow engine can classify
emails without knowing which backend is in use.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from email_triage.engine.models import Classification, EmailMessage, ListHint


def _is_local_host(
    url: str, *, extra_suffixes: list[str] | tuple[str, ...] = (),
) -> bool:
    """Return True if ``url`` points to a local-only destination.

    Used by the HIPAA safety gate: external LLM endpoints must not
    receive PHI unless a Business Associate Agreement is in place
    (enforced elsewhere).

    Always-on signals (no config needed):
      * localhost / 127.0.0.1 / ::1
      * RFC1918 private IPv4 (10/8, 172.16/12, 192.168/16)
      * .local mDNS suffix

    Operator-extensible: ``extra_suffixes`` adds operator-defined
    "treat-as-local" hostname suffixes (e.g. ``.home.lan``,
    ``.internal.example``). Sourced from
    ``config.tls.local_url_suffixes``; the source tree carries no
    operator-specific suffix.
    """
    if not url:
        return False
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.endswith(".local"):
        return True
    for suffix in extra_suffixes:
        s = (suffix or "").lower().strip()
        if s and host.endswith(s):
            return True
    # RFC1918 private IPv4.
    if host.startswith("10.") or host.startswith("192.168."):
        return True
    if host.startswith("172."):
        try:
            second = int(host.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


class Classifier(ABC):
    """Classify an email message into a triage category."""

    # Subclasses set this to True when their endpoint is local-only.
    # Used by actions that must fail-closed on HIPAA content when the
    # configured classifier is external (pre-BAA-gate).
    is_local: bool = False

    @abstractmethod
    async def classify(
        self,
        message: EmailMessage,
        categories: dict[str, str],
        list_hints: list[ListHint] | None = None,
    ) -> Classification:
        """Classify a single email.

        Parameters
        ----------
        message:
            The normalised email to classify.
        categories:
            Mapping of category slug to human description.  The LLM prompt
            is built dynamically from this dict.
        list_hints:
            Optional hints from user/global classification lists.  These are
            injected into the prompt as context, **not** hard overrides
            (unless the hint has ``skip_ai=True``).

        Returns
        -------
        Classification with category, confidence, reason, and source.
        """

    async def complete(self, prompt: str) -> str:
        """Raw text completion for non-classification tasks.

        Used by the digest generator to extract articles from newsletters,
        and by any other feature needing free-form LLM output.

        The default raises ``NotImplementedError``.  Backends that support
        raw completion (Ollama, OpenAI, Gemini) override this.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support raw completion")
