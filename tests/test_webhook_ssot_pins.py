"""Structural pins for the per-target webhook body-templating SSOT.

Per Prime Directive #1 (every SSOT ships its count-agnostic structural
pin in the same change) + Prime Directive #6 (pins reuse one shared
harness), these three pins guard the seams introduced by
`web/_webhook_template.py`:

* **P1** — Every outbound webhook POST goes through the reshaper.
  ``EventDispatcher._deliver`` in ``web/events.py`` MUST call
  ``render_for_target(...)`` and pass the result to
  ``client.post(target.url, content=<render_result>, ...)``. A future
  edit that constructs a payload inline and posts it would silently
  reintroduce the pre-drive envelope-verbatim assumption for typed
  targets. AST-scan pins the seam.

* **P2** — Every ``.fire(...)`` call on an ``EventDispatcher`` in
  ``src/`` explicitly passes ``is_hipaa=``. The HIPAA lock is caller-
  discipline (Prime Directive #9 says gate at the actuator — here the
  actuator is ``_deliver``, but the input signal is caller-supplied),
  so a future call site that forgets the kwarg silently downgrades a
  HIPAA account to full-envelope emission. SME-panel 2026-07-15 finding.

* **P3** — ``render_for_target`` still calls ``_hipaa_locked_bytes`` on
  the ``is_hipaa=True`` branch (defense against a future refactor that
  removes the branch or inlines a "safe-enough" shape).

All three walk ``ast.parse`` over the target module(s); none count
matches. Reuses the shared ``_pin_harness`` per Prime Directive #6.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

# Reuse the shared harness — Prime Directive #6.
import sys
sys.path.insert(0, str(Path(__file__).parent))
from _pin_harness import iter_src_files, parse_module, relpath  # noqa: E402


REPO_SRC = Path(__file__).parent.parent / "src"
EVENTS_PATH = REPO_SRC / "email_triage" / "web" / "events.py"
TEMPLATE_PATH = REPO_SRC / "email_triage" / "web" / "_webhook_template.py"


# ---------------------------------------------------------------------------
# P1 — every outbound webhook POST in EventDispatcher._deliver routes through
#      render_for_target(...)
# ---------------------------------------------------------------------------

def _iter_dispatcher_deliver() -> ast.AsyncFunctionDef | None:
    """Locate the ``EventDispatcher._deliver`` method AST node."""
    tree = parse_module(EVENTS_PATH)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "EventDispatcher":
            for member in node.body:
                if (
                    isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and member.name == "_deliver"
                ):
                    return member
    return None


def test_deliver_calls_render_for_target():
    """P1: ``_deliver`` MUST call ``render_for_target(...)`` — a
    future refactor cannot bypass the reshaper."""
    deliver = _iter_dispatcher_deliver()
    assert deliver is not None, "EventDispatcher._deliver not found"
    calls = [
        n for n in ast.walk(deliver)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "render_for_target"
    ]
    assert calls, (
        "EventDispatcher._deliver MUST call render_for_target(...) — "
        "a webhook POST that skips the reshaper reintroduces the pre-"
        "drive envelope-verbatim assumption for typed targets "
        "(SME-panel 2026-07-15 D1/DA2 finding, Prime Directive #1)."
    )


def test_deliver_client_post_sources_from_render():
    """P1 (companion): ``client.post(target.url, content=<name>, ...)``
    in ``_deliver`` MUST source ``content`` from a name bound to the
    ``render_for_target`` return value. The current binding name is
    ``payload``; this test lets it change but pins the source."""
    deliver = _iter_dispatcher_deliver()
    assert deliver is not None
    render_names: set[str] = set()
    for n in ast.walk(deliver):
        if (
            isinstance(n, ast.Assign)
            and isinstance(n.value, ast.Call)
            and isinstance(n.value.func, ast.Name)
            and n.value.func.id == "render_for_target"
        ):
            for tgt in n.targets:
                if isinstance(tgt, ast.Name):
                    render_names.add(tgt.id)
    assert render_names, (
        "render_for_target(...) result MUST be bound to a Name in "
        "_deliver so client.post(content=<name>) can reference it"
    )
    posts = [
        n for n in ast.walk(deliver)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "post"
    ]
    assert posts, "expected client.post(...) call in _deliver"
    for post in posts:
        content_kw = next(
            (k for k in post.keywords if k.arg == "content"), None
        )
        assert content_kw is not None, (
            "client.post(...) MUST pass `content=` — Prime Directive #1"
        )
        assert (
            isinstance(content_kw.value, ast.Name)
            and content_kw.value.id in render_names
        ), (
            f"client.post(content=<X>) X must be one of {render_names}; "
            f"got {ast.dump(content_kw.value)}"
        )


# ---------------------------------------------------------------------------
# P2 — every .fire() call on an EventDispatcher in src/ passes is_hipaa=
# ---------------------------------------------------------------------------

def _iter_fire_calls_in_src() -> list[tuple[str, ast.Call]]:
    """Walk every .py in src/ for `.fire(event, payload, ...)` calls
    that look like an EventDispatcher fire. We conservatively match on
    ``dispatcher.fire(...)`` and the surface-name-agnostic
    ``EventDispatcher.fire(...)`` — but NOT on any other ``.fire``
    (e.g., a UI button — none exists in this repo)."""
    hits: list[tuple[str, ast.Call]] = []
    for path in iter_src_files(REPO_SRC):
        try:
            tree = parse_module(path)
        except SyntaxError:
            continue
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if not isinstance(f, ast.Attribute) or f.attr != "fire":
                continue
            # Match `<something_that_looks_like_a_dispatcher>.fire(...)`.
            # Conservative: match any `.fire(...)` where the FIRST
            # positional arg is a string-literal event name — the shape
            # of every EventDispatcher call. This avoids false positives
            # on hypothetical other ``.fire`` surfaces.
            if not n.args:
                continue
            first = n.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue
            hits.append((relpath(path, REPO_SRC), n))
    return hits


def test_every_fire_call_passes_is_hipaa_kwarg():
    """P2: every ``dispatcher.fire(<event_str>, ...)`` in src/ MUST
    explicitly pass ``is_hipaa=<expr>``. Caller-discipline is the gate;
    the pin catches a future call site that forgets and silently
    downgrades a HIPAA account to full-envelope emission (SME-panel
    2026-07-15 HIPAA F2 / DA F3).

    The dispatcher method's default is ``is_hipaa=False``, so a
    forgotten kwarg is a silent regression, NOT a syntax error.
    """
    hits = _iter_fire_calls_in_src()
    assert hits, (
        "expected at least one .fire('<event>', ...) call in src/; "
        "if the dispatcher API just changed, update this pin"
    )
    offenders: list[str] = []
    for rel, call in hits:
        kwarg_names = {k.arg for k in call.keywords}
        if "is_hipaa" not in kwarg_names:
            offenders.append(f"{rel}:{call.lineno}")
    assert not offenders, (
        "the following .fire() call sites must pass is_hipaa= "
        "explicitly (SME-panel 2026-07-15 HIPAA F2 / DA F3):\n  "
        + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# P3 — render_for_target still calls _hipaa_locked_bytes on the HIPAA branch
# ---------------------------------------------------------------------------

def test_render_for_target_calls_hipaa_locked_bytes():
    """P3: the HIPAA lock must remain wired — a refactor that removes
    the ``_hipaa_locked_bytes`` call from ``render_for_target`` would
    silently emit operator-templatable bytes on a HIPAA-flagged
    target."""
    tree = parse_module(TEMPLATE_PATH)
    render_fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "render_for_target":
            render_fn = node
            break
    assert render_fn is not None, (
        "render_for_target function not found in _webhook_template.py"
    )
    lock_calls = [
        n for n in ast.walk(render_fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "_hipaa_locked_bytes"
    ]
    assert lock_calls, (
        "render_for_target MUST call _hipaa_locked_bytes on the "
        "is_hipaa=True branch — defense-in-depth atop the "
        "_FORBIDDEN_KEYS guard (SME-panel 2026-07-15 HIPAA finding)"
    )


# ---------------------------------------------------------------------------
# P5 — DA-F1 (SME-panel 2026-07-15 Layer-F verify): every fire_notification
#      caller stuffs account_id into the payload dict, OR is on the explicit
#      allow-list. Prevents a forgetful caller from silently fanning across
#      accounts via the wildcard-match fallback in _matching_targets.
# ---------------------------------------------------------------------------

# The one legitimate caller today. Any new caller MUST update this set +
# ensure its payload dict-literal includes ``"account_id"`` OR the payload
# is constructed by a helper that guarantees the key. If your new caller
# genuinely CANNOT surface an account_id (a global broadcast — kill-
# switch, system-wide health), add it to _BROADCAST_CALLERS instead so
# DA-F2's dropped-scoped-target semantic gives you correct behavior.
_FIRE_NOTIFICATION_KNOWN_CALLERS = {
    ("email_triage/actions/notify.py", "execute"),
    # Punch 608: the standard-mode door hands any payload it cannot verify
    # as standard to the strict door unchanged; that payload is the one
    # `NotifyAction._build_notification` built, which always carries
    # `account_id`.
    ("email_triage/web/events.py", "fire_standard_notification"),
}
_FIRE_NOTIFICATION_BROADCAST_CALLERS: set[tuple[str, str]] = set()


def _innermost_fn_name_at(tree: ast.AST, lineno: int) -> str:
    """Return the innermost def / async def name containing ``lineno``."""
    best_name = ""
    best_span = -1
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            if start <= lineno <= end:
                span = end - start
                if best_span < 0 or span < best_span:
                    best_name = node.name
                    best_span = span
    return best_name


def test_fire_notification_callers_pass_account_id_or_are_allow_listed():
    """P5 (DA-F1): every ``fire_notification(payload, ...)`` call site
    in src/ MUST either (a) build a payload dict-literal that includes
    an ``"account_id"`` key, OR (b) be listed in
    ``_FIRE_NOTIFICATION_KNOWN_CALLERS`` (the payload is assembled
    externally + guaranteed to carry the key), OR (c) be listed in
    ``_FIRE_NOTIFICATION_BROADCAST_CALLERS`` (deliberate cross-account
    broadcast — kill-switch, system-wide health). A caller that omits
    account_id silently downgrades to the wildcard-target-fan path
    (SME-panel 2026-07-15 DA-F1 finding)."""
    offenders: list[str] = []
    for path in iter_src_files(REPO_SRC):
        try:
            tree = parse_module(path)
        except SyntaxError:
            continue
        for n in ast.walk(tree):
            if not (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "fire_notification"
            ):
                continue
            rel_slash = relpath(path, REPO_SRC)
            fn_name = _innermost_fn_name_at(tree, n.lineno)
            key = (rel_slash, fn_name)
            if (
                key in _FIRE_NOTIFICATION_KNOWN_CALLERS
                or key in _FIRE_NOTIFICATION_BROADCAST_CALLERS
            ):
                continue
            # Fall-through: enforce inline `"account_id"` dict key.
            payload_arg = n.args[0] if n.args else None
            has_key = (
                isinstance(payload_arg, ast.Dict)
                and any(
                    isinstance(k, ast.Constant) and k.value == "account_id"
                    for k in payload_arg.keys
                )
            )
            if not has_key:
                offenders.append(f"{rel_slash}:{n.lineno} in {fn_name}()")
    assert not offenders, (
        "the following fire_notification(...) call sites must either "
        "pass a payload dict-literal containing `\"account_id\"` OR be "
        "added to _FIRE_NOTIFICATION_KNOWN_CALLERS in this pin file "
        "(SME-panel 2026-07-15 DA-F1):\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# P5b — DA-F1 COMPANION PIN (2026-07-16 D1 close). The P5 test above allow-
# lists `email_triage/actions/notify.py::execute` under the textual promise
# that its payload is "assembled externally + guaranteed to carry the key".
# The promise was VACUOUS at HEAD 68e2aee6: `NotifyAction._build_notification`
# omitted `account_id` in both branches (HIPAA + non-HIPAA), so every
# notification silently dispatched with acct_id=None and every account-
# scoped WebhookTarget was filtered out at web/events.py:230-232. Prod bug
# D1 (2026-07-16) — scoped-webhook per-account routing shipped DOA.
#
# THIS COMPANION PIN turns the allow-list's textual promise into AST-enforced
# fact — walks the sole allow-listed helper (`_build_notification`) and asserts
# every `ast.Return` whose value is a Dict literal has an `"account_id"` key.
# Prime Directive #1: allow-list ships with count-agnostic structural pin.
# Prime Directive #2: pin is interprocedural — P5 guards the callsite,
# P5b guards the helper.
# Prime Directive #6/#7: pin uses shared harness; census the censusers.
# ---------------------------------------------------------------------------

_NOTIFY_BUILD_MODULE = "email_triage/actions/notify.py"
_NOTIFY_BUILD_HELPER_NAME_RE = re.compile(r"^_build_.*notification$")


def test_notify_build_notification_returns_account_id_key_in_every_branch():
    """P5b (D1 close-out, DA-F1 promise verification): every
    ``_build_*notification`` helper in ``actions/notify.py`` that assembles
    the payload the P5 allow-list excuses MUST return a dict containing
    ``"account_id"`` in every branch. Structural — walks every helper
    whose name matches ``_build_.*notification``, collects every
    ``ast.Return`` whose value is an inline Dict, and asserts each has
    the key. Asserts >= 2 return-dict branches exist across the helpers
    so a collapse to one branch fires the pin; a future split into
    per-branch helpers (``_build_hipaa_notification`` +
    ``_build_normal_notification``) is naturally included by the regex
    (DA panel-1 MF-3 fold, 2026-07-16: the wider scan prevents a helper-
    split refactor from silently narrowing the coverage while emitting a
    misleading `single-branch collapse` message)."""
    path = REPO_SRC / _NOTIFY_BUILD_MODULE
    assert path.exists(), (
        f"{_NOTIFY_BUILD_MODULE} not found — P5b allow-list promise now "
        "references a missing file. Either restore the file OR remove "
        "notify.py from _FIRE_NOTIFICATION_KNOWN_CALLERS (and re-derive "
        "the caller's promise chain)."
    )
    tree = parse_module(path)
    assert tree is not None, f"{_NOTIFY_BUILD_MODULE} did not parse"
    helpers: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _NOTIFY_BUILD_HELPER_NAME_RE.match(node.name)
        ):
            helpers.append(node)
    assert helpers, (
        f"{_NOTIFY_BUILD_MODULE} has no `_build_*notification` helper — "
        "the P5 allow-list's promise names a payload-assembly helper that "
        "does not exist. Either restore it OR remove notify.py from "
        "_FIRE_NOTIFICATION_KNOWN_CALLERS."
    )
    return_dicts: list[tuple[str, int, ast.Dict]] = []
    for helper in helpers:
        for n in ast.walk(helper):
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict):
                return_dicts.append((helper.name, n.lineno, n.value))
    assert len(return_dicts) >= 2, (
        f"{_NOTIFY_BUILD_MODULE}: found {len(return_dicts)} inline-Dict "
        f"returns across `_build_*notification` helpers "
        f"({[h.name for h in helpers]}); expected >= 2 (HIPAA + non-HIPAA "
        "branches). Cases: (a) a helper collapsed its 2 branches to 1 — "
        "re-scope this pin explicitly if intentional. (b) the helper(s) now "
        "return via a nested helper Call (not an inline Dict) — extend this "
        "pin to walk the new helper's returns, OR bring the Dict "
        "construction back to a _build_*notification def."
    )
    missing: list[str] = []
    for helper_name, lineno, dict_node in return_dicts:
        has_account_id = any(
            isinstance(k, ast.Constant) and k.value == "account_id"
            for k in dict_node.keys
        )
        if not has_account_id:
            missing.append(
                f"{_NOTIFY_BUILD_MODULE}:{lineno} in {helper_name}() — "
                "return-dict missing 'account_id'"
            )
    assert not missing, (
        "P5b (D1 fix, 2026-07-16): `_build_*notification` return dict(s) "
        "missing 'account_id' key — the P5 allow-list's promise is "
        "vacuous.\n  " + "\n  ".join(missing)
    )


# ---------------------------------------------------------------------------
# P4 — no built-in default_template references {{secret}} (registry hygiene)
# ---------------------------------------------------------------------------

def test_no_registry_template_references_secret_placeholder():
    """DA1 finding: registry hygiene — no built-in default_template
    may reference ``{{secret}}``. Combined with the parse-time refusal
    in ``config._parse_webhooks``, this closes the exfil-via-body-
    template attack surface."""
    from email_triage.web._webhook_target_types import TARGET_TYPES
    offenders: list[str] = []
    for name, entry in TARGET_TYPES.items():
        tmpl = entry.get("default_template")
        if tmpl and "{{secret}}" in tmpl:
            offenders.append(name)
    assert not offenders, (
        f"target-type default_template MUST NOT reference "
        f"{{secret}} — offenders: {offenders}"
    )
