"""Flash-redirect write↔read COUPLING pin (divergence census run14 #7).

A handler signals the next page via a flash query param on a 303 redirect
(``?err=…`` / ``?msg=…`` / ``?saved=1`` / ``?save_msg=…`` …). The TARGET route's
GET handler must READ that param (``request.query_params.get("…")`` or the
``_redirect.read_flash`` SSOT) and render it — otherwise the notice is silently
SWALLOWED. That was census run14 #7's live bug: the watch-save wrote ``?saved=1``
to ``/profile/watches/{}/edit`` whose GET hard-coded ``save_msg=None`` and never
read it, so every save (and its HIPAA-skip count) showed nothing.

The existing ``test_redirect_qs_ssot_pin`` pins the WRITE side (values route
through the err_qs/msg_qs encoder). THIS pin is the interprocedural other half:
the value HOPS handler-POST → RedirectResponse URL → the sibling GET handler, so
the pin matches the written param to the route's GET reader (PD#2 — pin the seam,
not the source).

COUNT-AGNOSTIC PROPERTY (over web/routers): for every FLASH-notice param written
on a RedirectResponse to a route R, the @router.get handler FOR THAT EXACT route
R renders it — read in the handler body, in a helper THAT HANDLER calls
(interprocedural, same file), or in a Jinja TEMPLATE that handler renders
(``{% if request.query_params.get("err") %}`` — the admin-page idiom). Navigation
params (``step`` / ``wizard`` / ``tab`` / ``account_id`` / ``offset`` / ``page`` …)
are not flash notices and are excluded.

SOUNDNESS (the pin keyed on the right granularity — PD#2, "a pin keyed on the
wrong granularity is blind by construction"):
  * reads are resolved PER-GET-HANDLER, not per-file — a sibling route in the
    same file reading the param does NOT credit a route that swallows it (the
    db-sme MF-1 fix: ``read_flash`` credits msg+err, so a file-scoped union let
    one profile.py read mask a swallow on any of its 10 routes);
  * the route match is EXACT on the normalized path — UI routers declare FULL
    paths (no mount prefix; only ``/api`` is prefix-mounted, and flash redirects
    are all UI), so a bidirectional ``endswith`` would mis-credit ``/backup`` for
    ``/admin/backup`` (the db-sme MF-2 fix);
  * the WRITE detector follows the hoisted-``qs`` idiom
    (``qs = "saved=1" if … else err_qs(…)`` then ``f"/x?{qs}"``) — the dominant
    admin-page write form (the DA OBJ-1 fix; PD#4 enumeration net);
  * the route→template seam handles BOTH ``_render`` signatures —
    ``_render(request, name, ctx)`` AND ``_shared._render(templates, request,
    name, ctx)`` — by scanning args for the ``.html`` literal (the DA OBJ-2 fix);
  * reads at the ``/config`` AGGREGATOR are attributed PER-TAB (db-sme NH-4): a
    builder reached inside an ``if tab == "X":`` guard credits only tab X, and a
    ``?tab=X`` write (or a shim forwarding to ``/config?tab=X``) is matched against
    that tab's reads — so a swallow on one tab is NOT masked by a sibling tab
    reading the same param name (MF-1's defect class, displaced up to the
    aggregator). The cross-file bare-name registry is guarded by
    ``test_no_cross_file_dupname_reads_flash`` (NH-1/NH-3): no two router files may
    define a same-named flash-reading function (would let the first-def-wins
    resolver mis-credit) — fails LOUD if a future collision appears.

The ONE residual hop it can't resolve statically — a context builder in a
DIFFERENT module than the ``@router.get`` — is an explicit VERIFIED exception
(``_CROSS_FILE_READS``), guarded by ``test_cross_file_reads_are_real`` so the read
must still exist (removing it re-arms the pin; it is not a blind skip).

NET BOUNDARY (honest scope — ``feedback_just_be_honest``; not a completeness
over-claim). The WRITE detector sees every flash idiom CURRENTLY live in the repo:
a ``RedirectResponse(...)`` with the URL positional OR ``url=`` keyword, the URL a
literal / f-string / hoisted ``{qs}`` fragment / hoisted whole-URL local. OUT of
the net (none carry a flash today; documented so a future reader doesn't trust a
coverage the pin lacks): a raw ``Response(headers={"Location": …})`` hand-rolled
303, and a redirect URL built entirely inside a called helper. The READ resolver's
dispatcher hop (``_DISPATCHERS = {"db_call"}``) and forwarding-shim detector
(``request.url.query``) key on the exact two shapes live today — a NEW dispatcher
(``run_in_threadpool`` / ``asyncio.to_thread``) or forward idiom would
FALSE-POSITIVE (loud — a flagged non-swallow), never silently mask a real swallow.
The failure direction is fail-LOUD by construction.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    SRC_ROOT,
    TEMPLATES_ROOT,
    innermost_fn_at_lineno,
    iter_src_files,
    parse_module,
    relpath,
)

# Flash-NOTICE param names a redirect writes to signal success/error to the next
# page (vs navigation params, excluded). A written param NOT in this set is
# ignored (it is navigation/state, not a flash notice).
_FLASH_PARAMS = {
    "err", "saved", "msg", "save_msg", "save_error", "success",
    "flush_err", "flushed", "reset_err", "reset_ok", "folder_msg",
}
# Encoder call → the param name it writes (msg_qs → ?msg=, err_qs → ?err=).
_ENCODER_PARAM = {"msg_qs": "msg", "err_qs": "err"}
# read_flash() reads BOTH of these (the SSOT reader).
_READ_FLASH_PARAMS = {"msg", "err"}

# Dispatchers that INVOKE a function passed as their first positional arg — the
# value hops through the dispatcher (PD#2: "make the pin interprocedural wherever
# the value hops through a helper/dispatcher, db_call(helper, …)"). The /config
# aggregator runs a tab builder off the event loop via ``db_call(build_…, request)``,
# so the BFS must follow the function REFERENCE, not just direct ``.func`` calls.
_DISPATCHERS = {"db_call"}

# VERIFIED cross-file reads: a context-builder HELPER in a DIFFERENT module than
# the ``@router.get`` reads the flash (so neither the handler's interprocedural
# in-file reads nor the rendered template resolve it). {(route, param):
# (helper_relpath, fn_name)}. NOT a blind skip — ``test_cross_file_reads_are_real``
# asserts the helper fn still reads the param, so deleting the read RE-ARMS the
# pin (no silent false-negative).
_CROSS_FILE_READS = {
    # /accounts page context is built by _shared._build_accounts_page_snapshot,
    # which routes through `read_flash` (msg+err) into `flash_success` /
    # `flash_error`. The accounts template renders those context vars, not
    # query_params. Backwards-compat legacy `?success=` / `?error=` keys
    # remain honored (post-N-253b).
    ("/accounts", "success"): ("web/routers/ui/_shared.py", "_build_accounts_page_snapshot"),
    ("/accounts", "msg"): ("web/routers/ui/_shared.py", "_build_accounts_page_snapshot"),
    ("/accounts", "err"): ("web/routers/ui/_shared.py", "_build_accounts_page_snapshot"),
}


def _norm_path(p: str) -> str:
    """``/accounts/{account_id}/routes`` → ``/accounts/{}/routes`` (route-param
    names differ between the f-string redirect and the @router.get template)."""
    p = p.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    p = re.sub(r"\{[^}]*\}", "{}", p)
    return p or "/"


def _str_const(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _call_name(node: ast.AST) -> str | None:
    """The simple name of a Call's target — ``f.id`` for a Name, ``f.attr`` for an
    Attribute (``self._build(…)`` → ``_build``), else None."""
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _params_from_querystring(qs: str) -> set[str]:
    """``saved=1&err=x`` → {saved, err}. Only literal ``k=v`` pairs."""
    out: set[str] = set()
    for part in qs.split("&"):
        if "=" in part:
            out.add(part.split("=", 1)[0])
    return out


def _params_from_rhs(node: ast.AST) -> set[str]:
    """Flash params an expression ASSIGNED to a ``qs``-style local produces — so the
    hoisted-variable redirect idiom (``qs = "saved=1" if … else err_qs(…)``;
    ``f"/x?{qs}"``) is followed (DA OBJ-1). Handles a literal querystring, an
    ``err_qs``/``msg_qs``/``qs(**kw)`` encoder call, a ternary (both branches), a
    boolean ``or`` chain, and a hoisted f-string."""
    params: set[str] = set()
    s = _str_const(node)
    if s is not None:
        return _params_from_querystring(s)
    if isinstance(node, ast.Call):
        nm = _call_name(node)
        if nm in _ENCODER_PARAM:
            params.add(_ENCODER_PARAM[nm])
        elif nm == "qs":
            for kw in node.keywords:
                if kw.arg:
                    params.add(kw.arg)
    elif isinstance(node, ast.IfExp):
        params |= _params_from_rhs(node.body) | _params_from_rhs(node.orelse)
    elif isinstance(node, ast.BoolOp):
        for v in node.values:
            params |= _params_from_rhs(v)
    elif isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                params |= _params_from_querystring(v.value)
            elif isinstance(v, ast.FormattedValue):
                params |= _params_from_rhs(v.value)
    return params


def _local_qs_map(scope: ast.AST | None) -> dict[str, set[str]]:
    """Within a function (or module) scope, map each ``name`` assigned a
    querystring-bearing RHS to the flash params it carries — so a redirect that
    interpolates ``{name}`` can resolve the params (DA OBJ-1)."""
    out: dict[str, set[str]] = {}
    if scope is None:
        return out
    for stmt in ast.walk(scope):
        if isinstance(stmt, ast.Assign):
            params = _params_from_rhs(stmt.value)
            if not params:
                continue
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, set()).update(params)
    return out


def _url_path_and_params(node: ast.AST, local_qs: dict[str, set[str]]) -> tuple[str, set[str]] | None:
    """Parse a redirect URL (a str Constant or an f-string JoinedStr) into
    ``(norm_path, written_params)``. ``local_qs`` resolves a hoisted ``{qs}``
    interpolation. Returns None if not a URL-with-query."""
    # plain string: "/admin/tls/csr?saved=1"
    s = _str_const(node)
    if s is not None:
        if "?" not in s or not s.startswith("/"):
            return None
        path, qs = s.split("?", 1)
        return _norm_path(path), _params_from_querystring(qs)
    if not isinstance(node, ast.JoinedStr):
        return None
    # f-string: accumulate the literal path until "?", then collect params from
    # literal `k=` segments, {msg_qs(..)}/{err_qs(..)}/{qs(k=..)} encoders, AND a
    # hoisted {qs} local resolved via local_qs.
    path_chars: list[str] = []
    seen_q = False
    params: set[str] = set()
    for v in node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            text = v.value
            if not seen_q and "?" in text:
                before, after = text.split("?", 1)
                path_chars.append(before)
                seen_q = True
                params |= _params_from_querystring(after)
            elif not seen_q:
                path_chars.append(text)
            else:
                params |= _params_from_querystring(text)
        elif isinstance(v, ast.FormattedValue):
            if not seen_q:
                path_chars.append("{}")  # a path-segment interpolation
            else:
                inner = v.value
                if isinstance(inner, ast.Call):
                    nm = _call_name(inner)
                    if nm in _ENCODER_PARAM:
                        params.add(_ENCODER_PARAM[nm])
                    elif nm == "qs":
                        for kw in inner.keywords:
                            if kw.arg:
                                params.add(kw.arg)
                elif isinstance(inner, ast.Name):
                    params |= local_qs.get(inner.id, set())  # hoisted {qs} local
    if not seen_q:
        return None
    full = "".join(path_chars)
    if not full.startswith("/"):
        return None
    return _norm_path(full), params


def _is_redirect(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node) == "RedirectResponse"


def _redirect_url_arg(node: ast.Call) -> ast.AST | None:
    """The URL node of a RedirectResponse — positional ``args[0]`` OR the ``url=``
    KEYWORD form (DA Gap-1: ``RedirectResponse(url=f"/x?{qs}", status_code=303)``
    is a live in-repo idiom)."""
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg == "url":
            return kw.value
    return None


def _local_assign_map(scope: ast.AST | None) -> dict[str, ast.AST]:
    """Within a scope, map each assigned ``name`` to its RHS expression node — so a
    redirect to a HOISTED whole-URL local (``target = f"/x?{qs}"; RedirectResponse(
    target)`` — DA Gap-1) can resolve ``target`` back to the f-string. First
    assignment wins (a flash redirect's URL is not reassigned mid-handler)."""
    out: dict[str, ast.AST] = {}
    if scope is None:
        return out
    for stmt in ast.walk(scope):
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, stmt.value)
    return out


# A tab-aggregator page (``/config``) renders the written flash on ONE active tab;
# the ``tab=<X>`` value in the redirect URL says WHICH. Captured so the read match
# is per-tab, not pooled across every tab builder (db-sme NH-4).
_TAB_RE = re.compile(r"[?&]tab=([a-z0-9_]+)")


def _extract_tab(url_node: ast.AST) -> str | None:
    """The literal ``tab=<value>`` in a redirect URL (``/config?tab=integrations``),
    or None. Reads the constant string parts (the tab value is never interpolated)."""
    texts: list[str] = []
    s = _str_const(url_node)
    if s is not None:
        texts.append(s)
    elif isinstance(url_node, ast.JoinedStr):
        for v in url_node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                texts.append(v.value)
    for t in texts:
        m = _TAB_RE.search(t)
        if m:
            return m.group(1)
    return None


def _collect_writes(tree: ast.AST) -> set[tuple[str, str | None, str]]:
    """(norm_route, tab, flash_param) written on a RedirectResponse — positional or
    ``url=`` keyword (DA Gap-1). A hoisted ``{qs}`` fragment OR a hoisted whole-URL
    local is resolved against the assignments in the redirect's ENCLOSING function
    (DA OBJ-1 + Gap-1). ``tab`` is the aggregator tab the flash targets, else None
    (db-sme NH-4)."""
    out: set[tuple[str, str | None, str]] = set()
    for node in ast.walk(tree):
        if not _is_redirect(node):
            continue
        url_node = _redirect_url_arg(node)
        if url_node is None:
            continue
        fn = innermost_fn_at_lineno(tree, node.lineno)
        scope = fn if fn is not None else tree
        local_assigns = _local_assign_map(scope)
        local_qs = {
            n: ps for n, rhs in local_assigns.items() if (ps := _params_from_rhs(rhs))
        }
        if isinstance(url_node, ast.Name):  # hoisted whole-URL local
            url_node = local_assigns.get(url_node.id, url_node)
        parsed = _url_path_and_params(url_node, local_qs)
        if parsed is None:
            continue
        route, params = parsed
        tab = _extract_tab(url_node)
        for p in params:
            if p in _FLASH_PARAMS:
                out.add((route, tab, p))
    return out


def _flash_reads(node: ast.AST) -> set[str]:
    """Every flash param READ within ``node`` (a function body or a file tree) —
    ``query_params.get("<p>")`` (a param NAME, distinguished from a
    ``router.get("/path")`` route by the leading ``/``) + ``read_flash`` (msg+err)."""
    out: set[str] = set()
    for n in ast.walk(node):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Attribute) and f.attr == "get" and n.args:
            p = _str_const(n.args[0])
            if p and not p.startswith("/"):  # a param name, not a route path
                out.add(p)
        elif isinstance(f, ast.Name) and f.id == "read_flash":
            out |= _READ_FLASH_PARAMS
    return out


def _rendered_templates(node: ast.AST) -> set[str]:
    """Template names rendered within ``node`` — ``_render(request, "<tpl>", …)``
    (3-arg) AND ``_shared._render(templates, request, "<tpl>", …)`` (4-arg) AND
    ``TemplateResponse(...)``. Scans each such call's args for the FIRST ``.html``
    string literal rather than a fixed index (DA OBJ-2 — the 4-arg form puts the
    template at a different position)."""
    out: set[str] = set()
    for n in ast.walk(node):
        if not isinstance(n, ast.Call):
            continue
        if _call_name(n) in ("_render", "TemplateResponse"):
            for a in n.args:
                s = _str_const(a)
                if s and s.endswith(".html"):
                    out.add(s)
                    break
    return out


# Cache: template name → the flash params it reads via ``query_params.get('<p>')``.
_TPL_READ_RE = re.compile(r'query_params\.get\(["\']([a-z_]+)["\']')


def _template_param_reads(tpl_name: str) -> set[str]:
    """Flash params a Jinja template reads via ``request.query_params.get('<p>')``
    — the admin-page idiom (``{% if request.query_params.get("err") %}``). Returns
    ∅ for a missing template (the render call may be dynamic / a partial). Does NOT
    follow ``{% include %}``/``{% extends %}`` — a flash read factored into a shared
    partial would FALSE-POSITIVE (loud), never false-negative; acceptable."""
    path = TEMPLATES_ROOT / tpl_name
    if not path.is_file():
        return set()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):  # pragma: no cover
        return set()
    return set(_TPL_READ_RE.findall(text))


def _get_handlers(tree: ast.AST) -> list[tuple[ast.AST, str]]:
    """Every ``@router.get('<path>')`` handler in a file as ``(fn_node, norm_path)``."""
    out: list[tuple[ast.AST, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "get"
                and dec.args
            ):
                p = _str_const(dec.args[0])
                if p and p.startswith("/"):
                    out.append((node, _norm_path(p)))
    return out


def _get_routes(tree: ast.AST) -> set[str]:
    """The route paths a file serves via ``@router.get`` (for teeth/diagnostics)."""
    return {route for _, route in _get_handlers(tree)}


def _redirect_path(node: ast.AST) -> str | None:
    """The normalized PATH a RedirectResponse points at (query optional) — for
    resolving a forwarding shim's target route. Handles a Constant and an f-string
    (path segment up to the first ``?``)."""
    s = _str_const(node)
    if s is not None:
        return _norm_path(s) if s.startswith("/") else None
    if isinstance(node, ast.JoinedStr):
        chars: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                if "?" in v.value:
                    chars.append(v.value.split("?", 1)[0])
                    break
                chars.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                chars.append("{}")  # a path-segment interpolation before any "?"
        full = "".join(chars)
        return _norm_path(full) if full.startswith("/") else None
    return None


def _forward_targets(handler: ast.AST) -> set[tuple[str, str | None]]:
    """(target_route, target_tab) pairs a GET ``handler`` is a FORWARDING SHIM for —
    it forwards the inbound query (``qs = request.url.query``) onto a
    RedirectResponse to another route, so the flash survives the bounce and is read
    at the FINAL destination. The consolidated admin pages do this: ``/admin/backup``
    → ``/config?tab=backup`` (the target TAB rides the forward, so the inherited
    reads are the right tab's — db-sme NH-4). Returns ∅ for a non-forwarding handler
    (a fresh redirect that drops the inbound query is NOT a forward).

    NH-2 caveat: a shim that branches to two targets is satisfied if EITHER reads the
    param. Low risk — both branches forward the inbound query, so a flash is read
    wherever it lands; accepted, not unsound (fail-loud, never silent-mask)."""
    forwards_query = any(
        isinstance(n, ast.Attribute) and n.attr == "query"
        and isinstance(n.value, ast.Attribute) and n.value.attr == "url"
        for n in ast.walk(handler)
    )
    if not forwards_query:
        return set()
    local_assigns = _local_assign_map(handler)
    targets: set[tuple[str, str | None]] = set()
    for n in ast.walk(handler):
        if not _is_redirect(n):
            continue
        url_node = _redirect_url_arg(n)
        if url_node is None:
            continue
        if isinstance(url_node, ast.Name):  # hoisted whole-URL local
            url_node = local_assigns.get(url_node.id, url_node)
        t = _redirect_path(url_node)
        if t:
            targets.add((t, _extract_tab(url_node)))
    return targets


def _tab_eq_test(test: ast.AST) -> str | None:
    """``tab == "X"`` (or ``"X" == tab``) → ``"X"``, else None. The aggregator
    dispatches each tab's builder under such a guard (``elif tab == "integrations":
    …``)."""
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
        for a, b in ((test.left, test.comparators[0]), (test.comparators[0], test.left)):
            if isinstance(a, ast.Name) and a.id == "tab":
                s = _str_const(b)
                if s:
                    return s
    return None


def _tab_branches(handler: ast.AST) -> list[tuple[str, set[int]]]:
    """For an aggregator handler, ``(tabname, {id(node) in that branch's body})`` per
    ``if/elif tab == "<X>":`` guard — so a builder call inside it is attributed to
    tab X (db-sme NH-4)."""
    out: list[tuple[str, set[int]]] = []
    for n in ast.walk(handler):
        if isinstance(n, ast.If):
            tab = _tab_eq_test(n.test)
            if tab:
                ids: set[int] = set()
                for stmt in n.body:
                    for d in ast.walk(stmt):
                        ids.add(id(d))
                out.append((tab, ids))
    return out


def _direct_read_params(call: ast.Call) -> set[str]:
    """Flash params read DIRECTLY by this one call — ``query_params.get("p")`` → {p},
    ``read_flash(...)`` → {msg, err}, else ∅."""
    f = call.func
    if isinstance(f, ast.Attribute) and f.attr == "get" and call.args:
        p = _str_const(call.args[0])
        if p and not p.startswith("/"):
            return {p}
    elif isinstance(f, ast.Name) and f.id == "read_flash":
        return set(_READ_FLASH_PARAMS)
    return set()


def _callees(call: ast.Call, file_fns: dict[str, ast.AST], global_fns: dict[str, ast.AST]) -> list[ast.AST]:
    """The fn nodes a Call invokes — its direct callee (IN-FILE first, then the
    GLOBAL registry for a cross-file builder it imports) PLUS, for a dispatcher
    (``db_call(builder, …)``), the function REFERENCE passed as an arg (PD#2)."""
    nm = _call_name(call)
    names = {nm} if nm else set()
    if nm in _DISPATCHERS:
        for a in call.args:
            if isinstance(a, ast.Name):
                names.add(a.id)
            elif isinstance(a, ast.Attribute):
                names.add(a.attr)
    out: list[ast.AST] = []
    for name in names:
        target = file_fns.get(name) or global_fns.get(name)
        if target is not None:
            out.append(target)
    return out


def _reads_closure(seeds: list[ast.AST], file_fns: dict[str, ast.AST], global_fns: dict[str, ast.AST]) -> set[str]:
    """The transitive flash-read set reachable FROM ``seeds`` (a builder + everything
    it calls) — body reads ∪ rendered-template reads. Per-call-graph, so a route is
    credited only with reads it actually reaches (db-sme MF-1)."""
    seen: set[int] = set()
    stack = list(seeds)
    reads: set[str] = set()
    while stack:
        fn = stack.pop()
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        reads |= _flash_reads(fn)
        for tpl in _rendered_templates(fn):
            reads |= _template_param_reads(tpl)
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                for callee in _callees(n, file_fns, global_fns):
                    if id(callee) not in seen:
                        stack.append(callee)
    return reads


def _handler_reads_by_tab(
    handler: ast.AST, file_fns: dict[str, ast.AST], global_fns: dict[str, ast.AST]
) -> tuple[set[str], dict[str, set[str]]]:
    """``(always_reads, {tab: reads})`` for a GET handler — interprocedural (PD#2),
    per-handler (MF-1), and per-TAB for an aggregator (NH-4): a read reached from
    inside an ``if tab == "X":`` guard is attributed to tab X; everything else is
    ``always`` (rendered on every tab). A non-aggregator handler has no tab guards →
    all reads land in ``always`` (identical to the prior per-handler behaviour)."""
    branches = _tab_branches(handler)

    def tab_for(node: ast.AST) -> str | None:
        for tab, ids in branches:
            if id(node) in ids:
                return tab
        return None

    always: set[str] = set()
    by_tab: dict[str, set[str]] = {}
    for n in ast.walk(handler):
        if not isinstance(n, ast.Call):
            continue
        bucket = by_tab.setdefault(t, set()) if (t := tab_for(n)) else always
        bucket |= _direct_read_params(n)
        if _call_name(n) in ("_render", "TemplateResponse"):
            for a in n.args:
                s = _str_const(a)
                if s and s.endswith(".html"):
                    bucket |= _template_param_reads(s)
                    break
        callees = _callees(n, file_fns, global_fns)
        if callees:
            bucket |= _reads_closure(callees, file_fns, global_fns)
    return always, by_tab


def _scan(trees: list[ast.AST], labels: list[str] | None = None) -> list[str]:
    """Core property: every written flash param is read by its EXACT target route's
    GET handler (interprocedural, following cross-file builders and forwarding-shim
    hops). Returns the offender messages."""
    # GLOBAL fn registry (name → first def across all files) so a handler's BFS can
    # follow a call to a cross-file builder it imports (in-file lookup overrides).
    global_fns: dict[str, ast.AST] = {}
    for tree in trees:
        for f in ast.walk(tree):
            if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
                global_fns.setdefault(f.name, f)

    route_always: dict[str, set[str]] = {}            # route → reads on every tab
    route_tab: dict[str, dict[str, set[str]]] = {}    # route → {tab: reads}
    forward: dict[str, set[tuple[str, str | None]]] = {}  # route → {(target, tab)}
    writes: dict[tuple[str, str | None, str], str] = {}
    for i, tree in enumerate(trees):
        label = labels[i] if labels else f"<tree{i}>"
        file_fns = {
            f.name: f for f in ast.walk(tree)
            if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for w in _collect_writes(tree):
            writes.setdefault(w, label)
        for handler, route in _get_handlers(tree):
            always, by_tab = _handler_reads_by_tab(handler, file_fns, global_fns)
            route_always.setdefault(route, set()).update(always)
            for tab, rds in by_tab.items():
                route_tab.setdefault(route, {}).setdefault(tab, set()).update(rds)
            tgts = _forward_targets(handler)
            if tgts:
                forward.setdefault(route, set()).update(tgts)

    def eff_reads(route: str, tab: str | None,
                  seen: frozenset[tuple[str, str | None]] = frozenset()) -> set[str]:
        if (route, tab) in seen:
            return set()
        seen = seen | {(route, tab)}
        out = set(route_always.get(route, set()))
        tabs = route_tab.get(route, {})
        if tab is not None:
            out |= tabs.get(tab, set())          # ONLY the targeted tab (NH-4)
        else:
            for rds in tabs.values():
                out |= rds                       # tab unknown → any tab (pooled, correct)
        for (troute, ttab) in forward.get(route, ()):
            # a forwarding shim inherits its target's reads, carrying the forward's
            # tab (so /admin/integrations → /config?tab=integrations reads the
            # INTEGRATIONS tab, not the pooled union).
            out |= eff_reads(troute, ttab if ttab is not None else tab, seen)
        return out

    offenders = []
    for (route, tab, param), wfile in sorted(
        writes.items(), key=lambda kv: (kv[0][0], kv[0][1] or "", kv[0][2])
    ):
        if (route, param) in _CROSS_FILE_READS:
            continue  # verified cross-file helper read (guarded below)
        if param not in eff_reads(route, tab):
            where = f"{route!r}" + (f"?tab={tab}" if tab else "")
            offenders.append(
                f"{wfile}: writes ?{param}= to {where} but its GET handler "
                "(body / called helper / rendered template / forwarded route) never reads it"
            )
    return offenders


def test_flash_param_written_is_read_by_target_route():
    trees: list[ast.AST] = []
    labels: list[str] = []
    for p in iter_src_files("web/routers"):
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        trees.append(tree)
        labels.append(relpath(p))

    offenders = _scan(trees, labels)
    assert not offenders, (
        "A flash-notice param is written on a redirect but its EXACT target route's "
        f"GET never reads it — the notice is silently SWALLOWED (census run14 #7):\n  "
        + "\n  ".join(offenders)
        + "\nRead it in the route's GET (request.query_params.get / the "
        "_redirect.read_flash SSOT) or in the template it renders "
        '({% if request.query_params.get("…") %}) and render it. If a context '
        "builder in ANOTHER module reads it, add a guarded _CROSS_FILE_READS entry."
    )


def test_pin_has_teeth():
    # A planted write with no matching reader IS flagged.
    write_only = parse_source_module(
        'def post():\n'
        '    return RedirectResponse("/x/page?saved=1")\n'
    )
    assert ("/x/page", None, "saved") in _collect_writes(write_only)
    # An f-string write through msg_qs resolves to the `msg` param + path.
    fstr = parse_source_module(
        'def post():\n'
        '    return RedirectResponse(f"/profile/watches/{gid}/edit?{msg_qs(m)}")\n'
    )
    assert ("/profile/watches/{}/edit", None, "msg") in _collect_writes(fstr)
    # DA OBJ-1: a HOISTED qs local (ternary of a literal + an err_qs call) is
    # followed — the dominant admin-page write idiom.
    hoisted = parse_source_module(
        'def post(save_error):\n'
        '    qs = "saved=1" if not save_error else err_qs(save_error)\n'
        '    return RedirectResponse(f"/admin/security?{qs}", status_code=303)\n'
    )
    w = _collect_writes(hoisted)
    assert ("/admin/security", None, "saved") in w and ("/admin/security", None, "err") in w
    # DA Gap-1: the url= KEYWORD form is seen (positional args[0] is empty).
    kw_url = parse_source_module(
        'def post():\n'
        '    return RedirectResponse(url=f"/admin/security?{msg_qs(m)}", status_code=303)\n'
    )
    assert ("/admin/security", None, "msg") in _collect_writes(kw_url)
    # DA Gap-1: a HOISTED whole-URL local is resolved back to its f-string.
    hoisted_url = parse_source_module(
        'def post():\n'
        '    target = f"/x/page?{err_qs(e)}"\n'
        '    return RedirectResponse(target, status_code=303)\n'
    )
    assert ("/x/page", None, "err") in _collect_writes(hoisted_url)
    # db-sme NH-4: the tab discriminator is parsed off the write URL.
    assert ("/config", "integrations", "err") in _collect_writes(parse_source_module(
        'def post():\n'
        '    return RedirectResponse(f"/config?tab=integrations&{err_qs(e)}")\n'
    ))
    # A GET handler reading via read_flash is credited with msg+err; the decorator's
    # own router.get is NOT mistaken for a read (it starts with "/").
    getter = parse_source_module(
        '@router.get("/x/page")\n'
        'def page(request):\n'
        '    msg, err = read_flash(request)\n'
        '    return msg\n'
    )
    assert _get_routes(getter) == {"/x/page"}
    assert _flash_reads(getter) == {"msg", "err"}
    # DA OBJ-2: the 4-arg _shared._render(templates, request, "<tpl>", ctx) form is
    # resolved (template found by the .html literal, not a fixed arg index).
    rend4 = parse_source_module(
        '@router.get("/admin/acme-status")\n'
        'async def page(request):\n'
        '    return await _render(templates, request, "admin/acme_status.html", {})\n'
    )
    assert _rendered_templates(rend4) == {"admin/acme_status.html"}
    rend3 = parse_source_module(
        'def page(request):\n'
        '    return templates.TemplateResponse(request, "x/y.html", {})\n'
    )
    assert "x/y.html" in _rendered_templates(rend3)
    # A navigation param (step) is NOT treated as a flash notice.
    nav = parse_source_module('def p():\n    return RedirectResponse("/accounts/new?step=1")\n')
    assert _collect_writes(nav) == set()
    # db-sme MF-1: a swallow on route /a/page is NOT masked by a SIBLING route
    # /b/page (same file) reading the same param — per-handler granularity catches
    # it. (The old file-scoped union missed exactly this.)
    swallow = parse_source_module(
        '@router.post("/a/save")\n'
        'def save():\n'
        '    return RedirectResponse("/a/page?err=boom")\n'
        '@router.get("/a/page")\n'
        'def a_page(request):\n'
        '    return None\n'  # never reads err — SWALLOWED
        '@router.get("/b/page")\n'
        'def b_page(request):\n'
        '    return request.query_params.get("err")\n'  # sibling reads it
    )
    offenders = _scan([swallow])
    assert any("/a/page" in o and "err" in o for o in offenders), (
        "MF-1: per-handler granularity must flag the /a/page swallow even though "
        "the sibling /b/page reads err"
    )
    # And the inverse: a handler that DOES read it (directly) is not flagged.
    ok = parse_source_module(
        '@router.post("/c/save")\n'
        'def save():\n'
        '    return RedirectResponse("/c/page?err=boom")\n'
        '@router.get("/c/page")\n'
        'def c_page(request):\n'
        '    return request.query_params.get("err")\n'
    )
    assert not _scan([ok])
    # Interprocedural: the read lives in a HELPER the handler calls (same file).
    via_helper = parse_source_module(
        '@router.post("/d/save")\n'
        'def save():\n'
        '    return RedirectResponse("/d/page?err=boom")\n'
        '@router.get("/d/page")\n'
        'def d_page(request):\n'
        '    return _ctx(request)\n'
        'def _ctx(request):\n'
        '    return {"error": request.query_params.get("err")}\n'
    )
    assert not _scan([via_helper])
    # Forwarding shim: the write target /admin/e is a legacy shim that forwards the
    # inbound query to /e-tab, whose handler reads err → satisfied via the hop.
    forwarding = parse_source_module(
        '@router.post("/admin/e/save")\n'
        'def save():\n'
        '    return RedirectResponse("/admin/e?err=boom")\n'
        '@router.get("/admin/e")\n'
        'def e_legacy(request):\n'
        '    qs = request.url.query\n'
        '    tail = ("&" + qs) if qs else ""\n'
        '    return RedirectResponse(f"/e-tab?{tail}", status_code=303)\n'
        '@router.get("/e-tab")\n'
        'def e_tab(request):\n'
        '    return request.query_params.get("err")\n'
    )
    assert not _scan([forwarding])
    # ...but a shim forwarding to a target that ALSO never reads it is still caught.
    forwarding_swallow = parse_source_module(
        '@router.post("/admin/f/save")\n'
        'def save():\n'
        '    return RedirectResponse("/admin/f?err=boom")\n'
        '@router.get("/admin/f")\n'
        'def f_legacy(request):\n'
        '    qs = request.url.query\n'
        '    return RedirectResponse(f"/f-tab?{qs}", status_code=303)\n'
        '@router.get("/f-tab")\n'
        'def f_tab(request):\n'
        '    return None\n'
    )
    assert any("/admin/f" in o for o in _scan([forwarding_swallow]))
    # Dispatcher hop (PD#2): the builder is invoked via db_call(builder, request),
    # passed as a first-class arg — the BFS must follow the reference, not just
    # direct .func calls. (Cross-file too: builder defined in a second "file".)
    aggregator = parse_source_module(
        '@router.get("/agg")\n'
        'async def agg(request):\n'
        '    ctx = {}\n'
        '    ctx.update(await db_call(build_tab, request))\n'
        '    return ctx\n'
    )
    builder_file = parse_source_module(
        'def build_tab(request):\n'
        '    return {"error": request.query_params.get("err")}\n'
    )
    writer = parse_source_module(
        'def save():\n'
        '    return RedirectResponse("/agg?err=boom")\n'
    )
    assert not _scan([aggregator, builder_file, writer])
    # db-sme NH-4: the /config aggregator pools tab builders. A swallow on the BETA
    # tab must NOT be masked by the ALPHA tab reading the same param — reads are
    # attributed per `if tab == "X":` branch and matched against the write's tab.
    cfg = parse_source_module(
        '@router.get("/cfg")\n'
        'async def cfg(request):\n'
        '    tab = request.query_params.get("tab")\n'
        '    ctx = {}\n'
        '    if tab == "alpha":\n'
        '        ctx.update(await db_call(build_alpha, request))\n'
        '    elif tab == "beta":\n'
        '        ctx.update(await db_call(build_beta, request))\n'
        '    return ctx\n'
        'def build_alpha(request):\n'
        '    return {"error": request.query_params.get("err")}\n'
        'def build_beta(request):\n'
        '    return {}\n'  # beta does NOT read err — a swallow on tab=beta
    )
    w_alpha = parse_source_module('def p():\n    return RedirectResponse("/cfg?tab=alpha&err=x")\n')
    w_beta = parse_source_module('def p():\n    return RedirectResponse("/cfg?tab=beta&err=x")\n')
    assert not _scan([cfg, w_alpha]), "the alpha tab reads err — not a swallow"
    assert any("/cfg" in o and "err" in o for o in _scan([cfg, w_beta])), (
        "NH-4: a swallow on tab=beta must be flagged even though the alpha tab "
        "(pooled at the same /cfg route) reads err"
    )


def test_no_cross_file_dupname_reads_flash():
    """db-sme NH-1/NH-3 guard: the global fn registry resolves a cross-file call by
    BARE NAME (first-def-wins). If two web/routers files defined a same-named
    function AND one read a flash param, the resolver could mis-credit a route and
    mask a swallow. Today there is NO such collision (db-sme verified: 13 dup names,
    none read a flash param) — this ARMS the guard so a future one fails LOUD."""
    from collections import defaultdict
    name_files: dict[str, set[str]] = defaultdict(set)
    name_reads_flash: set[str] = set()
    for p in iter_src_files("web/routers"):
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        rp = relpath(p)
        for f in ast.walk(tree):
            if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name_files[f.name].add(rp)
                if _flash_reads(f) & _FLASH_PARAMS:
                    name_reads_flash.add(f.name)
    offenders = sorted(
        n for n, files in name_files.items() if len(files) > 1 and n in name_reads_flash
    )
    assert not offenders, (
        "NH-1/NH-3: these function names are defined in >1 web/routers file AND read "
        f"a flash param — the global-registry bare-name resolver could mis-credit a "
        f"route, masking a swallow: {offenders}. Rename to disambiguate (or resolve "
        "cross-file calls through actual imports)."
    )


def test_template_param_reads_resolve_acme_status_err():
    """The live false-positive this fix closes: auth_keys writes ?err= to
    /admin/acme-status, whose GET reads it ONLY in the Jinja template
    (admin/acme_status.html). The template scanner must surface that read."""
    assert "err" in _template_param_reads("admin/acme_status.html"), (
        "acme_status.html reads ?err= via query_params.get — the template scanner "
        "regressed; the acme-status flash would false-positive as swallowed."
    )


def test_cross_file_reads_are_real():
    """Every _CROSS_FILE_READS exception is VERIFIED, not a blind skip: the named
    helper fn must still read the param via query_params.get. If the read is
    deleted (re-introducing the swallow) this FAILS — re-arming the pin."""
    for (route, param), (helper_rel, fn_name) in _CROSS_FILE_READS.items():
        tree = parse_module(SRC_ROOT / helper_rel)
        assert tree is not None, f"cross-file helper file not found: {helper_rel}"
        fn = next(
            (n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn_name),
            None,
        )
        assert fn is not None, f"{helper_rel}: fn {fn_name}() (reads ?{param}= for {route}) not found"
        reads = _flash_reads(fn)
        assert param in reads, (
            f"{helper_rel}:{fn_name}() no longer reads ?{param}= — the {route} flash "
            f"is now SWALLOWED. Restore the read or remove the _CROSS_FILE_READS entry."
        )


def parse_source_module(src: str) -> ast.AST:
    return ast.parse(src)
