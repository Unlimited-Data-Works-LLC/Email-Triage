"""the backlog  (Census v3 finding #2 wider-tree follow-up).

Sibling of ``test_canonical_email_ssot_pin.py`` (which scopes to
``web/routers/**``). This pin widens the same predicate to the
``providers/`` + ``style_learning/`` + ``actions/`` subtrees — the
docstring hole #3 the routers-scope pin explicitly disclaims:

    "Out-of-scope siblings. The pin scopes to web/routers/** (the
    HTTP surface). .strip().lower() chains inside ... providers/ /
    actions/ / style_learning/ are NOT audited by this pin."

Motivating incidents this drive:

* ``providers/gmail_calendar.py::respond_to_invite`` compared
  ``self._account`` and Google Calendar ``attendee.email`` via raw
  ``.lower()`` — RSVP duplicate-attendee bug (the backlog  landed
  at ``f314abe1``).
* ``style_learning/per_contact_hipaa.py:1326`` composed cache-key
  via ``str(addr).strip().lower()`` — per-contact HIPAA overlay
  cache miss on IDN divergence (same drive fold).

Peer ``providers/office365.py:172/356`` was already convention per
N-346 partial 3 — this pin holds every future provider / distiller
site to the same rule.

Same predicate as the routers pin:
* ``.strip().lower()`` chain on a receiver whose identifier
  substrings hit ``_EMAIL_SHAPE_MARKERS``.
* Exempt if the enclosing fn also references ``canonical_email``
  (author knows the class; belt-and-braces defensive lower is OK).
* Allow-list ``_ALLOWED_PROVIDERS_BYPASSES`` for provably-not-email
  ``.strip().lower()`` uses (subject slugs, header-name folds, etc.).

Prime Directive #6: routes through shared ``_pin_harness``.
"""
from __future__ import annotations

import ast

from _canonical_email_pin_predicates import (
    fn_calls_canonical_email,
    is_email_shape,
    is_strip_lower_chain,
)
from _pin_harness import (
    innermost_fn_at_lineno,
    iter_src_files,
    parse_module,
    relpath,
)


_SCOPES = ("providers", "style_learning", "actions", "web")

# ``web/routers/`` has its own dedicated sibling pin
# (``test_canonical_email_ssot_pin.py``); this pin exempts that
# subtree to avoid double-coverage + double-drift risk. DA F2 fold:
# the widened ``web`` scope catches ``web/db.py:2750`` +
# ``web/email_watches.py:846`` which fell BETWEEN the two prior pins.
_EXEMPT_SUBPATHS = ("web/routers",)


# Legit ``.strip().lower()`` sites in-scope subtrees that are provably
# NOT email compares. Add with a one-line justification comment.
_ALLOWED_PROVIDERS_BYPASSES: set[tuple[str, str]] = {
    # web/db.py::upsert_gmail_watch — the ``.strip().lower()`` at
    # :2750 persists ``email_address`` into ``gmail_watches``. The
    # source docstring at :2744-2749 documents the deliberate bypass:
    # "Migrating to canonical_email(email_address) would break
    # existing-row lookups by adding IDNA + local-part quoting-strip
    # semantics that current persisted rows don't carry. Safe
    # migration requires a backfill or dual-shape lookup." Same
    # persisted-shape-vs-canonical-needle class as sent_mail_index.
    ("web/db.py", "upsert_gmail_watch"),
    # actions/sent_mail_index.py::retrieve_similar — the ``.strip()
    # .lower()`` on ``contact_address`` feeds a SQL ``LIKE
    # LOWER(to_addresses) LIKE '%' || ? || '%'`` filter that matches
    # against the RAW display form of the persisted ``to_addresses``
    # column. Canonicalizing the filter (which IDNA-normalizes +
    # strips display-wrap) would collapse EVERY LIKE match to zero
    # rows — the raw column never contains the A-label form. Proper
    # fix is a column migration + write-path canonical-normalize
    # (out-of-scope for this drive). Bypass is RATIONALIZED here +
    # documented in-source at the call site.
    ("actions/sent_mail_index.py", "retrieve_similar"),
}


# All email-shape / .lower() / .strip().lower() / canonical_email
# predicates now live in tests/_canonical_email_pin_predicates.py so the
# routers-pin + this pin share ONE source of truth (PD#6 SSOT).


def _scan() -> list[tuple[str, int, str]]:
    offenders: list[tuple[str, int, str]] = []
    for scope in _SCOPES:
        for path in iter_src_files(scope):
            tree = parse_module(path)
            if tree is None:
                continue
            rp = relpath(path)
            if any(rp.startswith(ex + "/") for ex in _EXEMPT_SUBPATHS):
                continue
            for node in ast.walk(tree):
                if not is_strip_lower_chain(node):
                    continue
                receiver = node.func.value.func.value  # type: ignore[union-attr]
                if not is_email_shape(receiver):
                    continue
                fn = innermost_fn_at_lineno(tree, node.lineno)
                if fn is None:
                    continue
                if fn_calls_canonical_email(fn):
                    continue
                fname = fn.name
                if (rp, fname) in _ALLOWED_PROVIDERS_BYPASSES:
                    continue
                offenders.append((rp, node.lineno, fname))
    return offenders


def test_no_strip_lower_on_email_shape_in_providers_or_style_learning():
    offenders = _scan()
    assert not offenders, (
        "``.strip().lower()`` on an email-shape receiver inside "
        "``providers/`` / ``style_learning/`` / ``actions/`` without "
        "``canonical_email`` in the enclosing fn — §164.312(a)(1) / "
        "§164.312(c)(1) canonical-email SSOT bypass. Under IDN "
        "(U-label / A-label) or display-wrap (``Name <a@b>`` vs "
        "``a@b``) divergence, ``.strip().lower()`` preserves the "
        "mismatch. Route through ``email_triage.mail_headers."
        "canonical_email`` (peer ``providers/office365.py`` "
        "convention per N-346 partial 3):\n"
        + "\n".join(f"  {rp}:{ln}  in {fname}(...)" for rp, ln, fname in offenders)
        + "\nIf the site is provably not an email compare (subject "
        "slug, header-name fold, etc.), add ``(relpath, funcname)`` "
        "to ``_ALLOWED_PROVIDERS_BYPASSES`` with a one-line "
        "justification."
    )
