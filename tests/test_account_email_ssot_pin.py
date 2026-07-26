"""census run17  — ``account_email()`` SSOT-bypass pin.

``db.accounts.account_email(acct)`` is the single source of truth for reading
an account's operator-facing address out of an account dict. It encapsulates
the per-provider field dance (Gmail/O365 store it under ``config["account"]``;
IMAP under ``config["email_address"]`` with a ``config["username"]`` fallback)
and is the value the loaders (``get_email_account`` / ``list_email_accounts``)
*materialize* onto the dict as the top-level ``"email_address"`` key.

The bypass class: a caller open-codes ``acct.get("email_address")`` /
``acct["email_address"]`` instead of calling the SSOT. That read is fragile —
it returns ``""`` for any account dict that was NOT built through a loader
(any hand-built dict that skips the loader; note the wizard route's own
``acct`` IS loader-built at HEAD — so its census "→ ''" framing was
DOWNGRADED, N-147), and it forks the resolution
logic so a future provider-field change is silently missed at the bypass
site (the 2026-05-05 "Send digest now" IMAP bug, where the handler read only
``config["account"]`` and rejected every IMAP account).

This **count-agnostic** pin asserts the STRUCTURAL invariant: no module under
``src/email_triage`` *reads* the literal ``"email_address"`` key off a dict —
via ``.get("email_address")`` or an ``["email_address"]`` subscript-load —
outside the SSOT home (``db/accounts.py``), EXCEPT the curated set of genuine
non-account reads (config dicts, gmail-watch rows, raw form data — dicts that
are not account dicts and legitimately carry their own ``email_address``).
A new ``acct.get("email_address")`` bypass in any non-allow-listed function
fails here regardless of how many sites already exist.

SCOPE CAVEAT (honest): there is no sound static way to prove a given dict IS
an account dict, so this pin uses a curated allow-list keyed on
``(relpath, enclosing_function)`` for the known non-account reads. Two
consequences follow and are accepted deliberately:
  * a NEW genuine non-account read (a new gmail-watch / config consumer) must
    be ADDED to ``_ALLOWED_NON_ACCOUNT_READS`` with a one-line rationale — a
    small, visible friction that keeps the bypass surface auditable;
  * a NEW account-dict read added *inside* an already-allow-listed function
    would be masked. The allow-listed functions are specifically the
    watch/config/form handlers, which do not deal in account dicts, so this
    residual is narrow — but it is the heuristic's known blind spot.

Writes are intentionally NOT flagged: the materializer
(``d["email_address"] = account_email(d)``) and the config/watch back-fills
(``config["email_address"] = form.get(...)``) are stores, not SSOT-read
bypasses; flagging them would only add noise.
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath, enclosing_fn

# The SSOT home — ``account_email`` itself, plus the loaders that materialize
# the key, legitimately read ``config["email_address"]``. Whole-file allowed.
_ALLOWED_FILES = {"db/accounts.py"}

# Curated genuine NON-account reads keyed on (relpath, enclosing_function).
# Each is a config dict / gmail-watch row / raw form payload — NOT an account
# dict — that carries its own ``email_address`` field. (See module docstring's
# SCOPE CAVEAT before adding: only a non-account dict belongs here.)
_ALLOWED_NON_ACCOUNT_READS = {
    # Provider CONFIG dict (not an account dict) — read to seed the From:
    # header / provider construction.
    ("cli.py", "_create_provider"),
    ("providers/factory.py", "build_provider"),
    # Raw multipart FORM payload on the IMAP account-edit save path.
    ("web/routers/ui/_shared.py", "_extract_provider_config"),
    # gmail_watches ROWS (the watch table's own email_address column), not the
    # account dict — the unified-poll loop + watch-renew sweep + admin list.
    ("web/ingestion_push.py", "_run_watch_renewal_sweep"),
    ("web/poll_ingestion.py", "_poll_once_gmail"),
    ("web/routers/integrations.py", "_gmail_watches_with_account_metadata"),
    ("web/routers/integrations.py", "admin_integrations_renew_watch"),
}


def _reads_email_address_key(node: ast.AST) -> bool:
    """True if ``node`` READS the literal ``"email_address"`` key off a dict —
    either ``<expr>.get("email_address"[, default])`` or an
    ``<expr>["email_address"]`` subscript in Load (read) context."""
    # ``.get("email_address")`` — first positional arg is the key.
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "email_address"
    ):
        return True
    # ``x["email_address"]`` subscript-LOAD (a read; stores/dels are excluded).
    if (
        isinstance(node, ast.Subscript)
        and isinstance(getattr(node, "ctx", None), ast.Load)
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == "email_address"
    ):
        return True
    return False


def _find_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel in _ALLOWED_FILES:
            continue
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not _reads_email_address_key(node):
                continue
            fn = enclosing_fn(node)
            if (rel, fn) in _ALLOWED_NON_ACCOUNT_READS:
                continue
            violations.append(f"{rel}:{node.lineno} (in {fn}())")
    return violations


def test_no_account_email_ssot_bypass():
    """Every account-dict address read goes through ``account_email(acct)``.
    A hit open-coded ``acct.get('email_address')`` / ``acct['email_address']``
    — replace it with ``account_email(acct)`` (rename any shadowing local), or,
    if the dict is genuinely a config/watch/form (NOT an account dict), add its
    ``(relpath, function)`` to ``_ALLOWED_NON_ACCOUNT_READS`` with a rationale.
    """
    violations = _find_violations()
    assert violations == [], (
        "account_email() SSOT bypass (census run17 ) — open-coded "
        "'email_address' read on a dict at:\n  "
        + "\n  ".join(violations)
        + "\nUse db.accounts.account_email(acct) for account dicts; allow-list "
        "a genuine non-account (config/watch/form) read in "
        "_ALLOWED_NON_ACCOUNT_READS."
    )


def test_pin_has_teeth():
    """The detector FLAGS both bypass shapes and does NOT flag the SSOT call
    nor an unrelated ``.get`` / subscript."""
    from _pin_harness import parse_source

    bad = parse_source(
        "def f(acct):\n"
        "    a = acct.get('email_address')\n"
        "    b = acct['email_address']\n"
        "    return a, b\n"
    )
    hits = [n for n in ast.walk(bad) if _reads_email_address_key(n)]
    assert len(hits) == 2, "pin missed a planted bypass shape (no teeth)"

    good = parse_source(
        "def g(acct):\n"
        "    from email_triage.db.accounts import account_email\n"
        "    a = account_email(acct)\n"
        "    b = acct.get('name')\n"
        "    acct['email_address'] = a\n"  # a STORE — must not be flagged
        "    return a, b\n"
    )
    assert not any(_reads_email_address_key(n) for n in ast.walk(good)), (
        "pin false-flagged the SSOT call, an unrelated key, or a store"
    )


if __name__ == "__main__":  # pragma: no cover — allow-list dump helper
    for v in _find_violations():
        print(v)
