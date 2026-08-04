"""A8 (divergence census 2026-06-09) — escaped error-surface pin.

The HTMX handlers return small HTML fragments to report failures. The
census found 22+ of them interpolating an exception message (``{e}`` /
``fmt_exc(e)`` / a provider error string / the Google OAuth ``error`` query
param) straight into an ``<small>`` / ``<article>`` / ``<span>`` with NO
``html.escape`` — a reflected-XSS surface into the operator's authenticated,
PHI-bearing admin session (the error text echoes attacker-influenceable
values: folder names, server banners, OAuth error params, pasted content).

The escaped surface is ``email_triage.web.error_html`` (``error_chip`` /
``error_article``), or an inline ``html.escape`` where the markup is bespoke.

This **count-agnostic** pin asserts the STRUCTURAL invariant: no module
under ``src/email_triage`` interpolates an UNESCAPED exception / error
value into an HTML-tag-bearing f-string. New code that re-rolls an
unescaped error fragment fails here regardless of site count.

SCOPE CAVEAT (SME db-sme F3 / DA-#2): this pin guards the EXCEPTION class
only — a FormattedValue that is a bare ``e``/``exc``/``err``/``error``/``ex``
name, or ``fmt_exc/str(e)/repr(e)``. It is structurally BLIND to other
attacker-influenceable dynamic values in HTML f-strings — an IMAP folder
name (``f'<option>{f}</option>'``), a reverse-DNS suggestion, a provider
host. Those are a SEPARATE, broader XSS class ("any unescaped
attacker-derived value in HTML"); the ones the A8 SME pass surfaced were
fixed inline (accounts folder-option, dispatcher hostname-mismatch), but a
general structural pin for them is NOT this file. Do not read a green run
here as "no unescaped attacker value remains" — only "no unescaped
exception string remains."
"""

from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import (
    SRC_ROOT,
    annotate_parents,
    enclosing_fn,
    iter_src_files,
    parse_module,
    relpath,
    walk_src,
)

# The SSOT module legitimately builds the (escaped) fragments.
_ALLOWED = {"error_html.py"}
_EXC_NAMES = {"e", "exc", "err", "ex", "error", "exception"}


def _is_escape_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Attribute) and node.func.attr == "escape")
        or (isinstance(node.func, ast.Name) and node.func.id == "escape")
    )


def _is_risky_value(v: ast.AST) -> bool:
    """A FormattedValue payload that carries an unescaped exception/error
    string: a bare exc name, or ``str(e)`` / ``repr(e)`` / ``fmt_exc(...)``."""
    if isinstance(v, ast.Name) and v.id in _EXC_NAMES:
        return True
    if isinstance(v, ast.Call):
        fn = v.func
        nm = fn.id if isinstance(fn, ast.Name) else (
            fn.attr if isinstance(fn, ast.Attribute) else ""
        )
        if nm == "fmt_exc":
            return True
        if nm in {"str", "repr"} and v.args and isinstance(v.args[0], ast.Name) \
                and v.args[0].id in _EXC_NAMES:
            return True
    return False


def _joinedstr_has_html_tag(node: ast.JoinedStr) -> bool:
    return any(
        isinstance(v, ast.Constant) and isinstance(v.value, str) and "<" in v.value
        for v in node.values
    )


def _find_violations() -> list[str]:
    violations: list[str] = []
    for path, rel, tree in walk_src():
        if path.name in _ALLOWED:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            if not _joinedstr_has_html_tag(node):
                continue
            for v in node.values:
                if (
                    isinstance(v, ast.FormattedValue)
                    and not _is_escape_call(v.value)
                    and _is_risky_value(v.value)
                ):
                    violations.append(f"{rel}:{node.lineno}")
                    break
    return violations


def test_no_unescaped_error_in_html():
    """Every exception/error value rendered into HTML is escaped — via
    ``web.error_html`` (error_chip / error_article) or inline html.escape.
    A hit is a reflected-XSS-adjacent unescaped error fragment."""
    violations = _find_violations()
    assert violations == [], (
        "Unescaped error interpolated into HTML (A8 / XSS-adjacent) at:\n  "
        + "\n  ".join(violations)
        + "\nUse web.error_html.error_chip(msg, prefix=...) / "
        "error_article(msg, heading=...), or wrap the value in html.escape()."
    )


def test_pin_has_teeth(tmp_path):
    bad = ast.parse(
        "def f(e):\n"
        "    return HTMLResponse(f'<small>oops: {e}</small>')\n"
    )
    hits = [
        n for n in ast.walk(bad)
        if isinstance(n, ast.JoinedStr) and _joinedstr_has_html_tag(n)
        and any(
            isinstance(v, ast.FormattedValue) and not _is_escape_call(v.value)
            and _is_risky_value(v.value) for v in n.values
        )
    ]
    assert hits, "pin missed a planted unescaped error-in-HTML"

    # An ESCAPED one must NOT be flagged.
    good = ast.parse(
        "def f(e):\n"
        "    return HTMLResponse(f'<small>oops: {html.escape(str(e))}</small>')\n"
    )
    ghits = [
        n for n in ast.walk(good)
        if isinstance(n, ast.JoinedStr) and _joinedstr_has_html_tag(n)
        and any(
            isinstance(v, ast.FormattedValue) and not _is_escape_call(v.value)
            and _is_risky_value(v.value) for v in n.values
        )
    ]
    assert not ghits, "escaped error must not be flagged"


def test_error_html_helpers_escape():
    from email_triage.web.error_html import error_article, error_chip

    chip = error_chip("</small><script>alert(1)</script>", prefix="Save failed: ")
    assert "<script>" not in chip
    assert "&lt;script&gt;" in chip
    assert chip.startswith('<small style="color:var(--pico-del-color);">Save failed: ')

    art = error_article('x" onload="evil()', heading="Provider error")
    assert "onload=" in art  # text preserved...
    assert '"' not in art.split("Provider error:</strong> ")[1].split("</p>")[0]  # ...but escaped
    assert "&quot;" in art


# --------------------------------------------------------------------------
# N-68 — form-input values in HTMLResponse f-strings (extended A8 scope).
#
# The original A8 pin guards only EXCEPTION variables (e/err/error/exc/ex
# and fmt_exc). It is structurally BLIND to a different XSS class: an
# attacker-controlled form value (form.get(...) / request.form[...])
# interpolated into an HTML f-string without html.escape(). The N-68
# finding (routes.py cat!r in unknown-category error) is exactly this
# class. This pin closes the gap for routes.py — it must be extended for
# any new routers that follow the same pattern.
#
# Invariant: in routes.py (the fixed file) no JoinedStr that contains an
# HTML tag and a FormattedValue whose payload is a bare form.get()/form[...]
# call WITHOUT an html.escape() wrapper.
# --------------------------------------------------------------------------
# Scope WIDENED (Loop-7 DA must-fix): scan EVERY router module, not just
# routes.py — the XSS class spans labels.py / profile.py too. Taint is
# tracked ONE HOP: a name assigned from form.get()/form[...] that then reaches
# an HTML f-string unescaped is flagged (catches `cat = form.get(...);
# f'<tag>{cat}</tag>'`). KNOWN LIMITATION (documented residual): a TWO-hop
# taint (form -> derived var -> HTML, e.g. routes.py will_create echoed from a
# label-probe) is NOT caught — manual root-cause-scope review is load-bearing
# for that shape until the pin grows real taint tracking.
_ROUTERS_DIR = SRC_ROOT / "web" / "routers"


def _is_form_get_call(node: ast.AST) -> bool:
    """An attacker-controlled REQUEST value: ``form.get/getlist(...)``,
    ``request.form.get(...)``, ``*.query_params.get(...)``, or ``form[...]``.

    Tightened (Loop-7) to the canonical request-form receivers only — a bare
    ``.get()`` on any dict (``contact.get('name')``, ``cfg.get(...)``) is NOT
    attacker-controlled and must not be treated as form taint, else the pin
    drowns in false positives on every dict read interpolated into HTML.
    """
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr in ("get", "getlist"):
            recv = fn.value
            if isinstance(recv, ast.Name) and recv.id == "form":
                return True
            if isinstance(recv, ast.Attribute) and recv.attr in (
                "form", "query_params",
            ):
                return True
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Name) and val.id == "form":
            return True
    return False


def _form_tainted_names(func: ast.AST) -> set[str]:
    """Names assigned (one hop) from a form.get()/form[...] anywhere on the
    RHS — incl. ``x = (form.get('k') or '').strip().lower()`` chains."""
    tainted: set[str] = set()
    for n in ast.walk(func):
        if isinstance(n, ast.Assign) and any(
            _is_form_get_call(x) for x in ast.walk(n.value)
        ):
            for tgt in n.targets:
                if isinstance(tgt, ast.Name):
                    tainted.add(tgt.id)
        if isinstance(n, ast.AnnAssign) and n.value is not None and any(
            _is_form_get_call(x) for x in ast.walk(n.value)
        ) and isinstance(n.target, ast.Name):
            tainted.add(n.target.id)
    return tainted


def _func_html_form_violations(func: ast.AST, rel: str) -> list[str]:
    tainted = _form_tainted_names(func)
    out: list[str] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.JoinedStr) or not _joinedstr_has_html_tag(node):
            continue
        for v in node.values:
            if not isinstance(v, ast.FormattedValue) or _is_escape_call(v.value):
                continue
            risky = _is_form_get_call(v.value) or any(
                _is_form_get_call(x) for x in ast.walk(v.value)
            )
            if not risky:
                risky = any(
                    isinstance(x, ast.Name) and x.id in tainted
                    for x in ast.walk(v.value)
                )
            if risky:
                out.append(f"{rel}:{node.lineno}")
                break
    return out


def _find_form_input_violations(path: Path) -> list[str]:
    tree = parse_module(path)
    if tree is None:  # pragma: no cover
        return []
    rel = relpath(path)
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.extend(_func_html_form_violations(node, rel))
    return out


def test_no_unescaped_form_input_in_html_routers():
    """No form-derived value (direct form.get OR a one-hop-tainted name) is
    interpolated into an HTML f-string WITHOUT html.escape() in ANY router
    module — the N-68 reflected-XSS class (routes.py + labels.py + profile.py)."""
    violations: list[str] = []
    for path in iter_src_files("web/routers"):
        violations.extend(_find_form_input_violations(path))
    assert violations == [], (
        "Unescaped form-input value interpolated into HTML (N-68 / XSS) at:\n  "
        + "\n  ".join(violations)
        + "\nWrap the form value in html.escape(...) or route the error "
        "through web.error_html.error_chip()."
    )


def test_n68_pin_has_teeth(tmp_path):
    """The pin catches a planted unescaped form.get() directly in an HTML
    f-string (the form.get call is the payload of the FormattedValue)."""
    # The pin looks for form.get(...) as the *direct* payload of a
    # FormattedValue inside an HTML-tag-bearing f-string.  This is the
    # shape the pin was designed to catch: f'<small>{form.get("x")}</small>'
    # rather than a two-step assignment (cat = form.get; f'<small>{cat}</small>').
    bad = ast.parse(
        "def f(form):\n"
        "    return HTMLResponse(f'<small>unknown: {form.get(\"row_0\")}</small>')\n"
    )
    hits = _find_form_input_violations_from_tree(bad, "<planted>")
    assert hits, (
        "pin missed a planted direct form.get() in HTML f-string. "
        "Expected: f'<tag>{form.get(...)}</tag>' to be flagged."
    )


def _find_form_input_violations_from_tree(
    tree: ast.AST, label: str
) -> list[str]:
    """Same logic as _find_form_input_violations but operates on an
    already-parsed tree (for teeth tests that can't write to SRC_ROOT)."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        if not _joinedstr_has_html_tag(node):
            continue
        for v in node.values:
            if not isinstance(v, ast.FormattedValue):
                continue
            if _is_escape_call(v.value):
                continue
            if _is_form_get_call(v.value) or any(
                _is_form_get_call(n) for n in ast.walk(v.value)
            ):
                violations.append(label)
                break
    return violations


def test_n68_escaped_form_input_passes(tmp_path):
    """html.escape(form.get(...)) must NOT be flagged."""
    ok = ast.parse(
        "import html\n"
        "def f(form):\n"
        "    cat = form.get('row_0_category')\n"
        "    return HTMLResponse(f'<small>unknown: {html.escape(repr(cat))}</small>')\n"
    )
    hits = _find_form_input_violations_from_tree(ok, "<planted>")
    assert not hits, "escaped form input must not be flagged by N-68 pin"


def test_n68_pin_catches_one_hop_taint():
    """The widened pin catches a ONE-HOP form taint: a name assigned from
    form.get(...) then interpolated into an HTML f-string unescaped (the class
    that spans labels.py/profile.py, not just the direct form.get() shape)."""
    tree = ast.parse(
        "async def f(form):\n"
        "    slug = (form.get('x') or '').strip().lower()\n"
        "    return HTMLResponse(f'<span>tagged with {slug}</span>')\n"
    )
    assert _func_html_form_violations(tree.body[0], "<planted>"), (
        "pin missed a one-hop form-taint: slug = form.get(...); f'<span>{slug}</span>'"
    )


def test_n68_pin_one_hop_escaped_passes():
    tree = ast.parse(
        "import html\n"
        "async def f(form):\n"
        "    slug = (form.get('x') or '').strip()\n"
        "    return HTMLResponse(f'<span>{html.escape(slug)}</span>')\n"
    )
    assert not _func_html_form_violations(tree.body[1], "<planted>")


def test_n68_pin_ignores_plain_dict_get():
    """A bare dict .get() (contact.get('name')) is NOT form taint — the
    tightened detector must not flag it (else 23 false positives)."""
    tree = ast.parse(
        "async def f(contact):\n"
        "    name = contact.get('name')\n"
        "    return HTMLResponse(f'<span>{name}</span>')\n"
    )
    assert not _func_html_form_violations(tree.body[0], "<planted>")


# ---------------------------------------------------------------------------
# N-83 — error-string → HTMLResponse shape the A8 exception-name pin misses.
#
# A8 guards bare exception variable names (e/exc/err/ex/error/exception +
# fmt_exc). N-83 is the next class: an attacker-reachable dynamic string
# (provider/classifier error, DB-stored email address, config-stored backend
# name, a form-submitted allowlist email) is read into an HTML interpolation
# slot and lands UNESCAPED in a styled ``<article|<small|<span``
# del/ins/amber/red/green error/status fragment.  The A8 pin misses it because
# the read at the interpolation site is not a bare exception name.
#
# COUNT-AGNOSTIC by construction (PD#1 / PD#6 — NOT a name denylist):
# ``_n83_find_violations`` flags ANY string-carrying dynamic read — a bare
# ``ast.Name`` (``msg``/``err``/``detail``/``payload`` — any identifier), an
# ``ast.Attribute`` (``e.args[0]``), or an ``ast.Subscript`` (``run["e"][0]``,
# ``s["start_utc"]``) — interpolated into a styled error/status fragment
# without an ``html.escape`` / ``error_chip`` / ``error_article`` wrap.  A new
# unescaped site named ``{anything}`` cannot evade it.  ``ast.Call`` (int()/
# len()/escape()/error_*), ``ast.BinOp`` (int arithmetic) and ``ast.Constant``
# are excluded as non-string-or-already-handled.
#
# The verified-live N-83 fixes (escaped, so absent from the flag set below):
#   - triage_classify.py — provider_error / classifier_error ``msg`` from
#     run["errors"][0] (provider/LLM content) → error_article
#   - triage_classify.py — ``backend`` from config.classifier.backend → escape
#   - accounts.py — ``to_addr`` (DB email_address) in <code> + success msg → escape
#   - oauth.py — ``auto_watch_error`` (fmt_exc(exc)) → escape
#   - auth_keys.py — ``payload`` (form allowlist email, {!r}) → escape(repr())
#   - _shared.py — O365 ``sub_id`` + Webhook ``start_utc/end_utc`` → escape
#   - webhook.py — Webhook ``start_utc/end_utc`` in value="" attr → escape
#
# A SAFE site (int path-param, pre-escaped value, literal-derived string, a
# server-generated token, a urlencoded url where <> can't appear) is exempted
# ONLY by (rel_path, fn, payload) in _N83_ALLOW_LIST after a source read —
# never by variable name alone (N-77 lesson). The key is LINE-STABLE (R38);
# see the allow-list header below for the full provenance.
#
# Scope: web/routers only (same as the N-68 pin).
# ---------------------------------------------------------------------------
_N83_ALLOW_LIST: set[tuple[str, str, str]] = {
    # (rel_path, enclosing_fn, payload) — LINE-STABLE (R38). RE-KEYED 2026-06-11
    # from (rel, lineno) after the line-keyed form broke fail-closed TWICE on
    # UNRELATED edits (batch-1 auth_keys, batch-4 accounts — a shifted line
    # staled the entry → a safe site re-flagged → a green pin went red on an
    # innocent commit). fn+payload survives a line shift.
    #
    # This is the COMPLETE per-read set machine-enumerated from the fragments
    # the N-83 audit (2026-06-11) verified SAFE — every read here is an int id
    # / a pre-escaped value (the *_esc / safe_* / *_help / escape()'d names) /
    # a server-set attribute marker (*_attr / *_marker) / a urlencoded url /
    # a base64url token / a literal-derived string. The old form keyed the
    # whole f-string by its line, so ONE entry covered all its reads; this
    # finer key needs one entry PER read but is STRONGER — a NEW unsafe read
    # (new payload) added to an exempted fragment now flags. Coarsening
    # tradeoff: a same-fn same-payload NEW unsafe read would be exempted, but
    # these payload names carry a function-level safety invariant. Do NOT add
    # a row without reading the source — escape attacker-reachable strings.
    # --- ui/_shared.py ---
    ('ui/_shared.py', '_help_span', 'safe'),
    ('ui/_shared.py', '_render_cadence_status_label', 'iv'),
    ('ui/_shared.py', '_render_calendar_surrogate_picker', 'account_id'),
    ('ui/_shared.py', '_render_calendar_surrogate_picker', 'label_help'),
    ('ui/_shared.py', '_render_calendar_surrogate_picker', 'options_html'),
    ('ui/_shared.py', '_render_calendars_table', 'account_id'),
    ('ui/_shared.py', '_render_calendars_table', 'api_help'),
    ('ui/_shared.py', '_render_calendars_table', 'cid_esc'),
    ('ui/_shared.py', '_render_calendars_table', 'disabled_attr'),
    ('ui/_shared.py', '_render_calendars_table', 'discovered_ids_esc'),
    ('ui/_shared.py', '_render_calendars_table', 'display_esc'),
    ('ui/_shared.py', '_render_calendars_table', 'display_help'),
    ('ui/_shared.py', '_render_calendars_table', 'listings_help'),
    ('ui/_shared.py', '_render_calendars_table', 'meetings_help'),
    ('ui/_shared.py', '_render_calendars_table', 'ro_marker'),
    ('ui/_shared.py', '_render_calendars_table', 'self_disabled_attr'),
    ('ui/_shared.py', '_render_calendars_table', 'self_help'),
    ('ui/_shared.py', '_render_calendars_table', 'star'),
    ('ui/_shared.py', '_render_calendars_table', 'summary_esc'),
    ('ui/_shared.py', '_render_calendars_table', 'use_help'),
    ('ui/_shared.py', '_render_gmail_push_status_label', 'days'),
    ('ui/_shared.py', '_render_gmail_push_status_label', 'sub'),
    ('ui/_shared.py', '_render_gmail_watch_chip', 'account_id'),
    ('ui/_shared.py', '_render_gmail_watch_chip', 'sub'),
    ('ui/_shared.py', '_render_gmail_watch_start_button', 'btn_base_style'),
    ('ui/_shared.py', '_render_gmail_watch_start_button', 'label'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'aid_kv'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'code_attr'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'code_chip'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'explain_block'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'result_id'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'safe_msg'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'spinner_id'),
    ('ui/_shared.py', '_render_o365_probe_chip_success', 'safe_addr'),
    ('ui/_shared.py', '_render_o365_push_chip', 'account_id'),
    ('ui/_shared.py', '_render_o365_push_chip', 'btn_base_style'),
    ('ui/_shared.py', '_render_o365_push_chip', 'safe_sub'),
    ('ui/_shared.py', '_render_o365_push_chip', 'sub_text'),
    # --- ui/accounts.py ---
    ('ui/accounts.py', 'accounts_auth_status', 'poll_attrs'),
    ('ui/accounts.py', 'accounts_folder_create', 'safe_name'),
    ('ui/accounts.py', 'digest_test_send', 'msg'),
    # --- ui/admin.py ---
    ('ui/admin.py', 'explain_error_endpoint', 'safe'),
    # --- ui/calendars.py ---
    ('ui/calendars.py', 'calendars_save', 'n_enabled'),
    # --- ui/labels.py ---
    ('ui/labels.py', 'messages_bulk_label_add', 'total'),
    # --- ui/oauth.py ---
    ('ui/oauth.py', 'gmail_api_auth_complete_manual', 'account_id'),
    ('ui/oauth.py', 'gmail_api_auth_start', 'url'),
    ('ui/oauth.py', 'gmail_api_auth_start_manual', 'account_id'),
    ('ui/oauth.py', 'gmail_api_auth_start_manual', 'url'),
    ('ui/oauth.py', 'oauth_google_callback', 'auto_banner'),
    ('ui/oauth.py', 'oauth_google_callback', 'auto_watch_msg'),
    # --- ui/profile.py ---
    ('ui/profile.py', '_format_alias_descriptors_for_preview', 'samples'),
    ('ui/profile.py', '_mine_result_fragment', 'STYLE_LEARNING_INLINE_LIMIT_CEILING'),
    ('ui/profile.py', 'api_keys_create', 'agent_sentence'),
    ('ui/profile.py', 'api_keys_create', 'alias'),
    ('ui/profile.py', 'api_keys_create', 'raw_key'),
    # --- ui/push.py ---
    ('ui/push.py', 'gmail_api_watch_start', 'msg'),
    # --- ui/routes.py ---
    ('ui/routes.py', 'accounts_routes_save_all', 'chips'),
    # --- ui/triage_classify.py ---
    ('ui/triage_classify.py', 'triage_preview', 'wait'),
}

# Pico CSS color variables that mark an error/status styled fragment.
_N83_COLOR_MARKERS = (
    "var(--pico-del-color)",
    "var(--pico-ins-color)",
    "var(--pico-color-amber",
    "var(--pico-color-red",
    "var(--pico-color-green",
    "var(--pico-muted-color)",
)


def _n83_annotate_parents(tree: ast.AST) -> None:
    """Annotate every node with its parent so a violation site can resolve its
    enclosing function (the line-stable key, R38). Delegates to the shared
    harness (R5b) — the parent-annotation boilerplate is converged there."""
    annotate_parents(tree)


def _n83_enclosing_fn(node: ast.AST) -> str:
    """Nearest enclosing function name (or ``<module>``). The allow-list keys
    on (rel, fn, payload), NEVER (rel, lineno): a line-keyed exemption goes
    stale (fail-closed → re-flags a safe site) the moment an UNRELATED edit
    shifts the file — it broke twice (batch-1 auth_keys, batch-4 accounts) before
    this re-key. fn+payload survives a line shift; only a rename/refactor of the
    site itself (which re-verifies anyway) changes it. (R38.) Delegates to the
    shared harness ``enclosing_fn`` (R5b) — same line-stable semantics."""
    return enclosing_fn(node)


def _n83_payload(value: ast.AST) -> str:
    """Stable source text of the interpolated read — the key's 3rd component
    and the human-facing payload. ``ast.unparse`` normalises quoting so the
    allow-list entry matches regardless of the original spelling."""
    try:
        return ast.unparse(value)
    except Exception:  # pragma: no cover
        return ast.dump(value)[:60]


def _joinedstr_has_styled_error_fragment(node: ast.JoinedStr) -> bool:
    """True when the f-string contains BOTH an HTML tag AND a pico color var
    — the signature of a styled error/status chip or article."""
    has_tag = False
    has_color_var = False
    for v in node.values:
        if not isinstance(v, ast.Constant) or not isinstance(v.value, str):
            continue
        if "<" in v.value:
            has_tag = True
        if any(m in v.value for m in _N83_COLOR_MARKERS):
            has_color_var = True
    return has_tag and has_color_var


def _n83_tree_violations(
    tree: ast.AST, rel: str, allow_list: set[tuple[str, int]],
) -> list[str]:
    """Count-agnostic core (PD#1/#6, NOT a name denylist): on one parsed
    tree, flag every styled error/status f-string that interpolates a
    string-carrying dynamic read WITHOUT an html.escape / error_chip /
    error_article wrap.

    A "dynamic read" is a bare ``ast.Name`` (``msg``/``err``/``detail`` — ANY
    identifier), an ``ast.Attribute`` (``e.args[0]``), or an ``ast.Subscript``
    (``run["errors"][0]``, ``s["start_utc"]``).  ``ast.Call`` (int()/len()/
    escape()/error_*), ``ast.BinOp`` (int arithmetic) and ``ast.Constant`` are
    excluded as non-string-or-already-handled.  A VERIFIED-SAFE site is
    exempted by ``(rel, fn, payload)`` in ``allow_list`` — NEVER by variable name.
    """
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        if not _joinedstr_has_styled_error_fragment(node):
            continue
        for v in node.values:
            if not isinstance(v, ast.FormattedValue):
                continue
            if _is_escape_call(v.value):
                continue
            # Exempt error_chip / error_article calls (the SSOT helpers).
            if isinstance(v.value, ast.Call):
                fn = v.value.func
                nm = (
                    fn.attr if isinstance(fn, ast.Attribute)
                    else fn.id if isinstance(fn, ast.Name)
                    else ""
                )
                if nm in ("error_chip", "error_article"):
                    continue
            if isinstance(v.value, (ast.Name, ast.Attribute, ast.Subscript)):
                payload = _n83_payload(v.value)
                key = (rel, _n83_enclosing_fn(node), payload)
                if key not in allow_list:
                    violations.append(
                        f"{rel}:{node.lineno} [{key[1]}] ({payload})"
                    )
                    break
    return violations


def _n83_find_violations(routers_dir: Path) -> list[str]:
    """Walk every router module and apply the count-agnostic N-83 core."""
    violations: list[str] = []
    for path in iter_src_files("web/routers"):
        tree = parse_module(path)  # parses + annotates parents (harness)
        if tree is None:  # pragma: no cover
            continue
        # ``rel`` is the ALLOW-LIST KEY (``ui/_shared.py`` form) — keyed on the
        # routers subtree, NOT SRC_ROOT — so it must stay relative to
        # ``routers_dir``, NOT the harness ``relpath`` (which is SRC_ROOT-relative
        # → ``web/routers/ui/_shared.py`` and would silently miss every entry).
        rel = relpath(path, base=routers_dir)
        violations.extend(_n83_tree_violations(tree, rel, _N83_ALLOW_LIST))
    return violations


# ---------------------------------------------------------------------------
# N-83 ATTRIBUTE-CONTEXT detector (hipaa-sme PD#1/#2 must-fix).
#
# The styled-fragment detector above keys on a pico-COLOR marker, so it does
# NOT cover the most-exploitable N-83 site: a dynamic read in an HTML
# ATTRIBUTE value (`value="{x}"`, `title="{x}"`, …) of a fragment that has no
# color var. The webhook quiet-hours editor (webhook.py — value="{start_utc}"
# from a form with NO HH:MM validation, confirmed _shared.py
# _webhook_quiet_save_snapshot) is stored-XSS via a crafted POST; without
# this pin, reverting that escape would NOT turn the suite red.
#
# COUNT-AGNOSTIC, independent of the color marker: in any web/routers JoinedStr
# that contains an HTML tag, flag a FormattedValue that is a string-carrying
# read (Name | Attribute | Subscript — NOT a Call/BinOp/Constant, NOT
# escape/error_html-wrapped) whose IMMEDIATELY-PRECEDING constant part ends
# with `="` or `='` (i.e. the value sits inside a quoted HTML attribute),
# unless its (rel, fn, payload) is a source-verified entry in _N83_ATTR_ALLOW_LIST.
#
# The HTML-tag guard (`<` present in some constant part) excludes non-HTML
# `="`-bearing f-strings — e.g. Content-Disposition HTTP headers
# (`f'attachment; filename="{fname}"'`) — which are a SEPARATE header-injection
# class, out of scope here.
# ---------------------------------------------------------------------------

# Ground-truth allow-list for the attribute-context detector — every entry a
# source read (N-83 audit 2026-06-11). The webhook value="" sites are
# deliberately ABSENT: they escape INLINE at the interpolation site, so a
# reverted bare `{start_v}` re-flags here.
_N83_ATTR_ALLOW_LIST: set[tuple[str, str, str]] = {
    # (rel_path, enclosing_fn, payload) — LINE-STABLE (R38; see _N83_ALLOW_LIST).
    # Complete per-read set for attribute-context SAFE reads (int id /
    # pre-escaped / urlencoded / CSS literal / token). The webhook value=""
    # sites are deliberately ABSENT — they escape INLINE, so a reverted bare
    # read re-flags.
    # --- ui/_shared.py ---
    ('ui/_shared.py', '_help_span', 'safe'),
    ('ui/_shared.py', '_render_calendar_surrogate_picker', 'cid'),
    ('ui/_shared.py', '_render_calendars_table', 'cid_esc'),
    ('ui/_shared.py', '_render_calendars_table', 'discovered_ids_esc'),
    ('ui/_shared.py', '_render_calendars_table', 'display_esc'),
    ('ui/_shared.py', '_render_calendars_table', 'summary_esc'),
    ('ui/_shared.py', '_render_gmail_watch_start_button', 'btn_base_style'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'result_id'),
    ('ui/_shared.py', '_render_o365_probe_chip_failure', 'spinner_id'),
    ('ui/_shared.py', '_render_o365_push_chip', 'btn_base_style'),
    # --- ui/accounts.py ---
    ('ui/accounts.py', 'accounts_folder_create', 'safe_name'),
    ('ui/accounts.py', 'digest_preview', 'iframe_src'),
    # --- ui/oauth.py ---
    ('ui/oauth.py', 'gmail_api_auth_start', 'url'),
    ('ui/oauth.py', 'gmail_api_auth_start_manual', 'url'),
    # --- ui/profile.py ---
    ('ui/profile.py', 'api_keys_create', 'raw_key'),
}


def _is_html_attr_preceding(prev: ast.AST) -> bool:
    """True if the constant immediately before a FormattedValue ends a quoted
    HTML attribute opener — ``…="`` or ``…='`` (after rstrip)."""
    if not (isinstance(prev, ast.Constant) and isinstance(prev.value, str)):
        return False
    pv = prev.value.rstrip()
    return pv.endswith('="') or pv.endswith("='")


def _n83_attr_tree_violations(
    tree: ast.AST, rel: str, allow_list: set[tuple[str, int]],
) -> list[str]:
    """Count-agnostic attribute-context core (PD#1/#6). On one parsed tree,
    flag every string-carrying dynamic read interpolated inside an HTML
    attribute value (immediately-preceding constant ends ``="``/``='``) of an
    HTML-tag-bearing f-string, without an escape/error_html wrap, unless
    (rel, fn, payload) is in ``allow_list``."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        # HTML-tag guard — excludes HTTP-header f-strings (Content-Disposition).
        if not _joinedstr_has_html_tag(node):
            continue
        vals = node.values
        for i, v in enumerate(vals):
            if not isinstance(v, ast.FormattedValue) or i == 0:
                continue
            if _is_escape_call(v.value):
                continue
            if isinstance(v.value, ast.Call):
                fn = v.value.func
                nm = (
                    fn.attr if isinstance(fn, ast.Attribute)
                    else fn.id if isinstance(fn, ast.Name)
                    else ""
                )
                if nm in ("error_chip", "error_article"):
                    continue
            if not isinstance(v.value, (ast.Name, ast.Attribute, ast.Subscript)):
                continue
            if not _is_html_attr_preceding(vals[i - 1]):
                continue
            payload = _n83_payload(v.value)
            key = (rel, _n83_enclosing_fn(node), payload)
            if key not in allow_list:
                violations.append(f"{rel}:{node.lineno} [{key[1]}] ({payload})")
                break
    return violations


def _n83_attr_find_violations(routers_dir: Path) -> list[str]:
    """Walk every router module and apply the attribute-context core."""
    violations: list[str] = []
    for path in iter_src_files("web/routers"):
        tree = parse_module(path)  # parses + annotates parents (harness)
        if tree is None:  # pragma: no cover
            continue
        # ``rel`` is the ALLOW-LIST KEY (``ui/_shared.py`` form) — see the note in
        # ``_n83_find_violations``; keep it routers_dir-relative, NOT the
        # SRC_ROOT-relative harness ``relpath``.
        rel = relpath(path, base=routers_dir)
        violations.extend(
            _n83_attr_tree_violations(tree, rel, _N83_ATTR_ALLOW_LIST)
        )
    return violations


def test_n83_no_unescaped_read_in_html_attribute():
    """N-83 attribute-context (count-agnostic): no dynamic string read lands
    unescaped inside an HTML attribute value (value="{x}", title="{x}", …) in
    any router module, unless its (rel, fn, payload) is a source-verified entry in
    _N83_ATTR_ALLOW_LIST. Covers the webhook stored-XSS site the
    styled-fragment pin (color-marker-keyed) misses."""
    violations = _n83_attr_find_violations(_ROUTERS_DIR)
    assert violations == [], (
        "N-83: unescaped dynamic read in an HTML attribute value at:\n  "
        + "\n  ".join(violations)
        + "\nEscape INLINE at the attribute site: value=\"{html.escape(x, "
        "quote=True)}\".  If the value is provably safe (int / literal / "
        "pre-escaped / server-token / urlencoded url), add a VERIFIED "
        "(rel_path, fn, payload) entry to _N83_ATTR_ALLOW_LIST with a source read."
    )


def test_n83_attr_pin_has_teeth():
    """The attribute detector flags a raw read in value="{x}" and a Subscript
    read, and is count-agnostic (any name) — empty allow-list."""
    bad_name = ast.parse(
        "def f(x):\n"
        "    return HTMLResponse(\n"
        "        f'<input type=\"time\" value=\"{x}\">'\n"
        "    )\n"
    )
    assert _n83_attr_tree_violations(bad_name, "<planted>", set()), (
        "attr pin missed a raw {x} inside value=\"...\"."
    )

    # A Subscript read in single-quoted attribute, arbitrary name.
    bad_sub = ast.parse(
        "def f(s):\n"
        "    return HTMLResponse(\n"
        "        f\"<input value='{s['start_utc']}'>\"\n"
        "    )\n"
    )
    assert _n83_attr_tree_violations(bad_sub, "<planted>", set()), (
        "attr pin missed a raw {s['start_utc']} inside value='...'."
    )


def test_n83_attr_pin_passes_inline_escape():
    """value=\"{html.escape(x)}\" must NOT be flagged (inline-escaped)."""
    ok = ast.parse(
        "import html\n"
        "def f(x):\n"
        "    return HTMLResponse(\n"
        "        f'<input value=\"{html.escape(x, quote=True)}\">'\n"
        "    )\n"
    )
    assert _n83_attr_tree_violations(ok, "<planted>", set()) == [], (
        "inline-escaped attribute value must not be flagged."
    )


def test_n83_attr_pin_ignores_non_html_header():
    """A `="`-bearing f-string with NO HTML tag (Content-Disposition header)
    must NOT be flagged — the HTML-tag guard excludes the header-injection
    class (separate scope)."""
    header = ast.parse(
        "def f(fname):\n"
        "    return Response(headers={\n"
        "        'Content-Disposition': f'attachment; filename=\"{fname}\"',\n"
        "    })\n"
    )
    assert _n83_attr_tree_violations(header, "<planted>", set()) == [], (
        "non-HTML Content-Disposition header must not be flagged by the "
        "HTML attribute-context pin."
    )


def test_n83_attr_pin_covers_webhook_value_sites():
    """Regression guard for the must-fix: the webhook editor's value=\"\"
    sites are COVERED — an UNESCAPED variant of that handler flags. (If the
    real handler ever drops the inline escape, the suite goes red.)"""
    # Simulate the reverted (vulnerable) shape of the webhook handler.
    reverted = ast.parse(
        "def f(s, account_id):\n"
        "    start_v = s['start_utc'] or ''\n"
        "    return HTMLResponse(\n"
        "        f'<input type=\"time\" name=\"start_utc\" value=\"{start_v}\">'\n"
        "    )\n"
    )
    assert _n83_attr_tree_violations(reverted, "<planted>", set()), (
        "attr pin must flag a reverted (raw) webhook value=\"{start_v}\"."
    )
    # And the real module currently passes (escaped inline + nothing to allow).
    import email_triage  # noqa: F401  (ensure src importable)
    oc = (
        _ROUTERS_DIR / "ui" / "webhook.py"
    )
    tree = parse_module(oc); assert tree is not None  # N-350 R31
    flags = _n83_attr_tree_violations(tree, "ui/webhook.py", _N83_ATTR_ALLOW_LIST)
    assert flags == [], (
        f"webhook.py must be clean under the attr pin (inline-escaped); got {flags}"
    )


def test_n83_no_unescaped_error_string_in_styled_html():
    """N-83 (count-agnostic): no dynamic string read (ANY Name/Attribute/
    Subscript — not a fixed name set) is interpolated unescaped into a styled
    <article|<small|<span> error/status fragment in any router module, unless
    its (rel, fn, payload) is a source-verified entry in _N83_ALLOW_LIST.

    Catches the shape the A8 exception-name pin misses (a provider error
    string, a DB-stored value, a form value reaching an HTML slot under any
    variable name).  Fix: route through error_article(x) / error_chip(x) or
    wrap in html.escape()."""
    violations = _n83_find_violations(_ROUTERS_DIR)
    assert violations == [], (
        "N-83: unescaped dynamic read in a styled HTML fragment at:\n  "
        + "\n  ".join(violations)
        + "\nRoute through error_article(x)/error_chip(x) or wrap in "
        "html.escape().  If the value is provably safe (int / literal / "
        "pre-escaped / server-token / urlencoded url), add a VERIFIED "
        "(rel_path, fn, payload) entry to _N83_ALLOW_LIST with a source-read comment."
    )


def test_n83_pin_has_teeth():
    """The inverted (count-agnostic) pin catches a planted unescaped read in a
    styled fragment — drives the REAL _n83_tree_violations core, empty
    allow-list. Also proves it is NOT a name denylist: an arbitrary name the
    old denylist never knew (``detail``) is still flagged."""
    # Bare Name (msg).
    bad_name = ast.parse(
        "def f(run):\n"
        "    msg = (run['errors'] or ['err'])[0]\n"
        "    return HTMLResponse(\n"
        "        f'<article style=\"border-left:3px solid var(--pico-del-color);\">"
        "<p>{msg}</p></article>'\n"
        "    )\n"
    )
    assert _n83_tree_violations(bad_name, "<planted>", set()), (
        "N-83 pin missed a planted unescaped {msg} in a styled error fragment."
    )

    # An arbitrary name the old _N83_RISKY_NAMES denylist never contained —
    # the inverted pin MUST still flag it (count-agnostic proof).
    bad_novel = ast.parse(
        "def f(x):\n"
        "    detail = x.boom\n"
        "    return HTMLResponse(\n"
        "        f'<small style=\"color:var(--pico-del-color);\">{detail}</small>'\n"
        "    )\n"
    )
    assert _n83_tree_violations(bad_novel, "<planted>", set()), (
        "N-83 pin missed {detail} — the inverted detector must flag ANY "
        "dynamic read, not a fixed name set (PD#1/#6)."
    )

    # A Subscript read (s["start_utc"]) must be flagged too.
    bad_sub = ast.parse(
        "def f(s):\n"
        "    return HTMLResponse(\n"
        "        f'<small style=\"color:var(--pico-muted-color);\">"
        "{s[\"start_utc\"]}</small>'\n"
        "    )\n"
    )
    assert _n83_tree_violations(bad_sub, "<planted>", set()), (
        "N-83 pin missed a Subscript read s['start_utc'] in a styled fragment."
    )


def test_n83_pin_passes_escaped_forms():
    """error_article(x) / error_chip(x) / html.escape(x) must NOT be flagged
    — they route the dynamic value through an escaped surface."""
    for src in (
        "from email_triage.web.error_html import error_article\n"
        "def f(run):\n"
        "    msg = (run['errors'] or ['err'])[0]\n"
        "    return HTMLResponse(error_article(msg, heading='Provider error'))\n",

        "import html\n"
        "def f(x):\n"
        "    return HTMLResponse(\n"
        "        f'<small style=\"color:var(--pico-del-color);\">{html.escape(x)}</small>'\n"
        "    )\n",

        "from email_triage.web.error_html import error_chip\n"
        "def f(e):\n"
        "    return HTMLResponse(\n"
        "        f'<small style=\"color:var(--pico-del-color);\">{error_chip(e)}</small>'\n"
        "    )\n",
    ):
        tree = ast.parse(src)
        assert _n83_tree_violations(tree, "<planted>", set()) == [], (
            f"escaped/SSOT-wrapped read must not be flagged; src:\n{src}"
        )


def test_n83_pin_int_and_constant_not_flagged():
    """An int-arithmetic (BinOp) read, a Call (int()/len()), and a Constant
    are NOT string-carrying dynamic reads and must not be flagged."""
    tree = ast.parse(
        "def f(n, items):\n"
        "    return HTMLResponse(\n"
        "        f'<small style=\"color:var(--pico-ins-color);\">"
        "{n * 30 // 60} / {len(items)} / {42}</small>'\n"
        "    )\n"
    )
    assert _n83_tree_violations(tree, "<planted>", set()) == [], (
        "int BinOp / len() Call / Constant must not be flagged by N-83 pin."
    )


def test_n83_allow_list_exempts_by_fn_payload_not_lineno():
    """A flagged site is exempted by (rel, fn, payload) — and that key is
    LINE-STABLE: shifting the site down (blank lines above) must NOT break the
    exemption (the whole point of the R38 re-key; the old (rel, lineno) key
    re-flagged here)."""
    body = (
        "def f(msg):\n"
        "    return HTMLResponse(\n"
        "        f'<small style=\"color:var(--pico-del-color);\">{msg}</small>'\n"
        "    )\n"
    )
    tree = ast.parse(body)
    _n83_annotate_parents(tree)
    flagged = _n83_tree_violations(tree, "x.py", set())
    assert flagged, "precondition: the bare {msg} must flag with empty allow-list"
    key = ("x.py", "f", "msg")
    assert _n83_tree_violations(tree, "x.py", {key}) == [], (
        "an allow-listed (rel, fn, payload) must suppress the flag"
    )
    # Line-stability: the SAME key must still suppress after a line shift.
    shifted = ast.parse("\n\n\n\n\n" + body)
    _n83_annotate_parents(shifted)
    assert _n83_tree_violations(shifted, "x.py", {key}) == [], (
        "the (rel, fn, payload) key must survive a line shift — a (rel, lineno) "
        "key would NOT (this is the R38 regression the re-key fixes)"
    )
