"""ProviderTraits registry — collapses ``if ptype ==`` switches across
the codebase into table-driven dispatch (#138.2).

Many call sites need to know per-provider data:

- the secrets-store key shape ("ACCOUNT_<id>_IMAP_PASSWORD" vs.
  "..._O365_SECRET" vs. "..._GMAIL_REFRESH_TOKEN");
- whether an account is "authenticated" (do we have a usable
  password / refresh token persisted yet?);
- whether the wizard step-3 push/poll page can safely default-skip
  for this provider (push semantics differ; IMAP needs the
  push-vs-poll cadence picker, Gmail/O365 don't);
- whether the account is currently at the default OAuth scope set
  (no calendar, no extras opted in) so we can skip the scope
  re-auth dance.

The registry is keyed on ``provider_type`` (the same string the DB
column holds: ``imap`` / ``gmail_api`` / ``office365``). Each entry
is a ``ProviderTraits`` dataclass; helper functions below resolve the
trait without leaking the lookup-or-default boilerplate.

Migration is incremental: 8-10 of the 19 ``if ptype ==`` switch sites
across the codebase are migrated in this commit (#138 first pass).
The remainder are flagged with ``# TODO #138 traits-migration`` and
will move in a follow-up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ProviderTraits:
    """Per-provider behavioral metadata, resolved by ptype string.

    Most of these are short callables / strings rather than full
    objects so the registry stays cheap to construct at import time
    (the heavy provider modules ``imap.py``, ``gmail_api.py``,
    ``office365.py`` are NOT imported here — that would defeat the
    lazy-import discipline the rest of the codebase relies on for
    optional-dep tolerance).

    Fields:
        ptype: Canonical provider-type string (matches the DB column).
        secret_key_template: ``str.format``-style template for the
            secrets-store key, with ``{account_id}`` placeholder. Used
            by ``secret_key_for_account()``. ``None`` for providers
            without a secret (no current example, but reserved).
        inbox_only: True when the account's only meaningful watch
            target is INBOX — the wizard step-3 page can auto-skip
            because there's nothing to choose. False when the operator
            should consciously pick folders / cadence (IMAP).
        push_kind: Short string describing the push delivery mechanism
            (``"imap_idle"`` / ``"gmail_pubsub"`` / ``"graph_subscription"``)
            or ``"none"`` for providers without push. Used by the
            WatcherManager dispatch + UI chip rendering — replaces
            three of the longest ``if ptype ==`` switches.
        default_search_query: Default query for the
            ``sent-mail-index build`` CLI subcommand. Gmail uses
            its native ``in:sent`` syntax; IMAP uses ``ALL`` and
            relies on the operator pointing the account at a Sent
            mailbox; O365 has no Sent-only default yet.
        secret_form_field: HTML form field name carrying this
            provider's password/secret on the account-edit form.
            Used by ``_save_provider_secret`` to consolidate the
            "if ptype == 'imap': read 'password' else read
            'client_secret'" branch.
    """

    ptype: str
    secret_key_template: str | None
    inbox_only: bool
    push_kind: str
    default_search_query: str
    secret_form_field: str | None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TRAITS: dict[str, ProviderTraits] = {
    "imap": ProviderTraits(
        ptype="imap",
        secret_key_template="ACCOUNT_{account_id}_IMAP_PASSWORD",
        inbox_only=False,  # operator picks folders + cadence
        push_kind="imap_idle",
        default_search_query="ALL",
        secret_form_field="password",
    ),
    "gmail_api": ProviderTraits(
        ptype="gmail_api",
        secret_key_template="ACCOUNT_{account_id}_GMAIL_REFRESH_TOKEN",
        inbox_only=True,  # push paths don't expose folder selection
        push_kind="gmail_pubsub",
        default_search_query="in:sent",
        secret_form_field=None,  # OAuth refresh token, not a form field
    ),
    "office365": ProviderTraits(
        ptype="office365",
        secret_key_template="ACCOUNT_{account_id}_O365_SECRET",
        inbox_only=True,  # Graph push not yet wired; defaults are good
        push_kind="graph_subscription",
        default_search_query="",
        secret_form_field="client_secret",
    ),
}


# ---------------------------------------------------------------------------
# Resolver helpers
# ---------------------------------------------------------------------------

def get_traits(ptype: str) -> ProviderTraits | None:
    """Look up traits by provider type. ``None`` for unknown types."""
    return TRAITS.get(ptype)


def secret_key_for_account(account_id: int, ptype: str) -> str | None:
    """Render the secrets-store key for ``(account_id, ptype)``.

    Equivalent to ``factory.secret_key_for_account`` but driven from
    the traits registry. Both call sites resolve to the same string;
    the factory keeps its own copy because the factory module must
    stay importable without the traits registry being present.
    """
    t = get_traits(ptype)
    if t is None or t.secret_key_template is None:
        return None
    return t.secret_key_template.format(account_id=account_id)


def is_authenticated(secrets, acct: dict) -> bool:
    """True when the account has a usable secret / refresh token saved.

    * IMAP — password persisted in secrets backend.
    * Gmail — refresh token (the OAuth callback writes it).
    * O365 — refresh token / client secret persisted.

    Mirrors the wizard-step-2 polling helper that previously lived in
    ``web/routers/ui.py:_account_authenticated``.
    """
    ptype = acct.get("provider_type", "")
    sk = secret_key_for_account(acct["id"], ptype)
    if not sk:
        return False
    try:
        return bool(secrets.get(sk))
    except Exception:
        return False


def has_default_scopes(acct: dict) -> bool:
    """True when the account is at the default OAuth scope set.

    For IMAP this is always True (no OAuth scopes apply).

    For Gmail / O365 we treat the calendar opt-in as the only
    operator-flippable extra scope today (the wizard step-3 form
    only exposes that knob). Defaulting to ``False`` on missing
    keys matches the form's unchecked default.
    """
    if acct.get("provider_type") == "imap":
        return True
    cfg = acct.get("config") or {}
    if cfg.get("calendar_opted_in", False):
        return False
    return True


def inbox_only(acct: dict) -> bool:
    """Wizard step-3 skip helper: True when the account's folder
    set is so trivial there's nothing to configure beyond INBOX.

    Routes through the registry so adding a new provider only
    requires updating the traits table — not three sibling helpers
    (``_account_only_inbox_selectable`` was the canonical site).
    """
    t = get_traits(acct.get("provider_type", ""))
    if t is None:
        return False
    return t.inbox_only


def default_search_query(ptype: str) -> str:
    """Default-Sent-folder query for the ``sent-mail-index build`` CLI.

    Empty string for providers without a known default — the caller
    should fail-fast or surface the omission to the operator.
    """
    t = get_traits(ptype)
    return t.default_search_query if t else ""
