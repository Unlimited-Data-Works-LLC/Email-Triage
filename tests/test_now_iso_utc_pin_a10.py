"""A10 (divergence census 2026-06-09) — ``_now_iso`` is UTC, always.

Stored/compared timestamps (DB columns, dedup keys, audit rows) are UTC
across the whole codebase. The helper for "now, as an ISO string" was
copy-pasted ~8 times under the name ``_now_iso`` — and ONE copy (in
``mail_headers``) returned LOCAL time (``datetime.now().astimezone()``) for
a human-facing header stamp, under the SAME name. Two functions named
``_now_iso`` with different tz semantics is a collision waiting to flip a
comparison the moment they're crossed.

The SSOT is ``email_triage._isotime`` — ``now_utc_iso`` (stored/compared)
and the DISTINCTLY-named ``now_local_iso`` (display only).

This **count-agnostic** pin asserts the STRUCTURAL invariant: any function
named ``_now_iso`` / ``now_iso`` under ``src/email_triage`` returns UTC —
its body must not use a naive ``datetime.now()`` or ``.astimezone()``
(local) — so a LOCAL timestamp can never again hide under the ``_now_iso``
name. (Local display timestamps must use a clearly different name, e.g.
``now_local_iso`` / ``*_local_iso``.)
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath, parse_source  # N-350 R31

_NOW_ISO_NAMES = {"_now_iso", "now_iso"}


def _body_src(fn: ast.FunctionDef, source: str) -> str:
    try:
        return ast.get_source_segment(source, fn) or ""
    except Exception:  # pragma: no cover
        return ""


def _returns_local_now(fn: ast.FunctionDef) -> bool:
    """True if the function body computes a LOCAL/naive now — a bare
    ``datetime.now()`` (no ``timezone.utc`` arg) or any ``.astimezone()``."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # .astimezone(...) → local
            if node.func.attr == "astimezone":
                return True
            # datetime.now() with NO args → naive local
            if node.func.attr == "now" and not node.args and not node.keywords:
                return True
    return False


def _find_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        source = path.read_text(encoding="utf-8")
        try:
            tree = parse_source(source)
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        rel = relpath(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in _NOW_ISO_NAMES:
                if _returns_local_now(node):
                    violations.append(
                        f"{rel}:{node.lineno} (`{node.name}` returns LOCAL time "
                        f"— must be UTC; use now_utc_iso / rename to *_local_iso)"
                    )
    return violations


def test_now_iso_is_always_utc():
    violations = _find_violations()
    assert violations == [], (
        "A `_now_iso`-named helper returns LOCAL time (A10 tz collision):\n  "
        + "\n  ".join(violations)
        + "\nStored/compared timestamps must be UTC (email_triage._isotime."
        "now_utc_iso). A local display timestamp must use a DISTINCT name "
        "(now_local_iso / *_local_iso)."
    )


def test_pin_has_teeth():
    bad = ast.parse(
        "from datetime import datetime\n"
        "def _now_iso():\n"
        "    return datetime.now().astimezone().isoformat()\n"
    )
    fns = [n for n in ast.walk(bad) if isinstance(n, ast.FunctionDef)]
    assert any(_returns_local_now(f) for f in fns), "pin missed a local _now_iso"

    good = ast.parse(
        "from datetime import datetime, timezone\n"
        "def _now_iso():\n"
        "    return datetime.now(timezone.utc).isoformat()\n"
    )
    gfns = [n for n in ast.walk(good) if isinstance(n, ast.FunctionDef)]
    assert not any(_returns_local_now(f) for f in gfns), "UTC _now_iso must pass"


def test_isotime_ssot_semantics():
    from email_triage._isotime import now_local_iso, now_utc_iso

    utc = now_utc_iso()
    assert utc.endswith("+00:00") or utc.endswith("Z"), utc
    # local carries an explicit offset (aware), and the two are the same
    # instant — only the rendered offset differs.
    loc = now_local_iso()
    assert ("+" in loc[10:]) or ("-" in loc[10:]), loc  # has a tz offset


# ---------------------------------------------------------------------------
# A10 ADOPTION pin (drift-prevention batch 3, 2026-06-11)
# ---------------------------------------------------------------------------
# The pin above guards CORRECTNESS (a `_now_iso`-named helper must be UTC).
# This one guards ADOPTION: an inline ``datetime.now(timezone.utc).isoformat()``
# (or any aware ``<x>.now(<tz>).isoformat()``) re-decides timestamp formatting
# at the call site, forking the SSOT. 120 such copies existed across 35 files
# before this batch; each is a place a future format change (Z-suffix,
# ``timespec=``, microsecond truncation) would silently MISS. The single home
# for THIS shape is ``email_triage._isotime.now_utc_iso``. The allow-list is
# FILE-level (only ``_isotime.py``, the definition) — robust against
# line-shifts, unlike a ``(path, lineno)`` allow-list.
#
# SCOPE/KNOWN GAPS (per the 2026-06-11 devils-advocate review):
#   * This pin keys on the CALL SHAPE (``.now(arg).isoformat()``), not on the
#     receiver being a ``datetime``. The repo has zero non-datetime ``.now()``
#     objects today, so no false-positive — but a future arrow/pendulum/pandas
#     ``obj.now(x).isoformat()`` would trip it. If that ever lands, narrow the
#     detector (e.g. require the receiver name to resolve to ``datetime``)
#     rather than widening the file allow-list.
#   * ``now_utc_iso`` is the home for the ``.now().isoformat()`` shape. The
#     DIFFERENT stored-timestamp format — ``Z``-suffix, second precision, no
#     microseconds (``schema_migrations.applied_at``) — now has its OWN SSOT
#     ``_isotime.now_utc_iso_z`` (2026-06-11; the lone ``web/migrations.py``
#     ``time.strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())`` was routed through it),
#     PINNED below by ``test_no_raw_time_strftime_outside_ssot``. (Closed the
#     gap the 2026-06-11 DA review flagged.) A datetime's ``dt.strftime(...)``
#     METHOD used to format a GIVEN datetime for an external API wire format
#     (O365 OData ``receivedDateTime``, Graph ``expirationDateTime``) is a
#     distinct concern — NOT a stored "now" — and is intentionally out of scope.


def _is_aware_now_call(node: ast.AST) -> bool:
    """``<x>.now(<≥1 arg>)`` — an AWARE ``now`` (has a tz arg). The naive
    ``.now()`` (no args, local) is the correctness pin's concern, not this one."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "now"
        and bool(node.args or node.keywords)
    )


def _rooted_in_aware_now(node: ast.AST, now_vars: set[str]) -> bool:
    """True if ``node`` is (recursively) rooted in an aware ``.now(arg)`` Call OR
    a local var bound to one. A10 WIDENED (2026-06-14): the original detector saw
    only the INLINE ``datetime.now(tz).isoformat()`` shape — blind to the
    var-bound (``now = datetime.now(tz); now.isoformat()``), the arith
    (``(datetime.now(tz) ± delta).isoformat()``), and the var-arith
    (``(now ± delta).isoformat()``) shapes that re-decide the stored format just
    the same. This roots through Name (var), BinOp (arith), Call-chain, and
    UnaryOp so all four shapes are caught."""
    if isinstance(node, ast.Name) and node.id in now_vars:
        return True
    if _is_aware_now_call(node):
        return True
    if isinstance(node, ast.BinOp):
        return (
            _rooted_in_aware_now(node.left, now_vars)
            or _rooted_in_aware_now(node.right, now_vars)
        )
    if isinstance(node, ast.BoolOp):
        # N-203 R22 (2026-07-02): widen coverage to `(a or b).isoformat()` and
        # `(a and b).isoformat()` shapes. Census run22 R22_5 discovery: the
        # style-DELETE-cutoff site used `(now or datetime.now(tz)).isoformat()`
        # to fall back to a fresh now when the caller didn't supply one — the
        # pre-widened pin's Name/BinOp/Call/UnaryOp coverage was blind to the
        # BoolOp shape, letting the site fork the A10 SSOT. Any operand rooted
        # in an aware-now = the whole expression is aware-now-rooted.
        return any(_rooted_in_aware_now(v, now_vars) for v in node.values)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _rooted_in_aware_now(node.func.value, now_vars)
    if isinstance(node, ast.UnaryOp):
        return _rooted_in_aware_now(node.operand, now_vars)
    return False


def _now_vars_in_fn(fn: ast.AST) -> set[str]:
    """Names bound (anywhere in this function scope) to an aware-now-rooted value
    — fixpoint, so ``a = now(); b = a + d; c = b`` all count as now-rooted."""
    now_vars: set[str] = set()
    for _ in range(5):
        before = len(now_vars)
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and _rooted_in_aware_now(n.value, now_vars):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        now_vars.add(t.id)
        if len(now_vars) == before:
            break
    return now_vars


def _aware_now_isoformat_lines(fn: ast.AST) -> list[int]:
    """Line numbers, within ONE function body, of every ``<aware-now>.isoformat()``
    that bypasses the ``_isotime`` SSOT — inline, var-bound, arith AND var-arith.
    A ``.isoformat()`` on a NON-now datetime (a parsed / passed-in / fromtimestamp
    value) is NOT rooted in ``.now(arg)`` and is correctly NOT flagged."""
    now_vars = _now_vars_in_fn(fn)
    hits: list[int] = []
    for n in ast.walk(fn):
        if not (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "isoformat"
        ):
            continue
        if _rooted_in_aware_now(n.func.value, now_vars):
            hits.append(n.lineno)
    return hits


# Frozen migration bodies (``web/migrations.py`` functions registered with
# ``@register(N, ...)``) are the ONE place an inline aware-now ISO string is
# REQUIRED, not forbidden: an already-applied migration's source is immutable
# (its AST-normalized checksum is recorded in every deployed DB and re-verified
# on boot — see ``tests/test_migrations_applied_body_immutable.py``). Routing
# such a body through the mutable ``_isotime`` SSOT changes its executable tokens
# → changes its checksum → the boot-time tamper-guard refuses to start. That is
# exactly what downed the deploy host deploy on 2026-06-11 (A10 swept ``_v5`` onto
# now_utc_iso()). So an inline ``.now(tz).isoformat()`` INSIDE a registered
# migration body is allowed; the runner (``run_migrations``) and any other live
# code in the file stay covered.
#
# Keyed on the ``@register(...)`` decorator — the SAME authoritative "this is a
# frozen migration" signal the freeze pin keys on (``migrations.MIGRATIONS``) —
# NOT a ``_vNN_`` name regex: a future migration registered under any other
# function name must get the same carve-out, and a nested helper that happens to
# match a name pattern must NOT (DA 2026-06-11).


def _is_register_decorated(node: ast.AST) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Name) and target.id == "register":
            return True
        if isinstance(target, ast.Attribute) and target.attr == "register":
            return True
    return False


def _migration_body_line_ranges(tree: ast.AST) -> list[tuple[int, int]]:
    """(start, end) line ranges of every ``@register(...)``-decorated migration
    body — the registry is the single source of truth for "this is frozen"."""
    ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if _is_register_decorated(node):
            ranges.append((node.lineno, node.end_lineno or node.lineno))
    return ranges


def _find_inline_violations() -> list[str]:
    violations: set[str] = set()
    for path in iter_src_files():
        source = path.read_text(encoding="utf-8")
        try:
            tree = parse_source(source)
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        rel = relpath(path)
        frozen = (
            _migration_body_line_ranges(tree) if rel == "web/migrations.py" else []
        )

        def _add(ln: int) -> None:
            if not any(lo <= ln <= hi for lo, hi in frozen):
                violations.add(f"{rel}:{ln}")  # noqa: B023 — frozen per-file

        # (a) per-function WIDENED scan (var / arith / var-arith / inline) —
        #     var-tracking is function-scoped so a `now` in one fn can't bleed
        #     into another.
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for ln in _aware_now_isoformat_lines(fn):
                    _add(ln)
        # (b) module-scope inline aware-now (no enclosing function) — the
        #     original whole-tree inline guard, kept so an import-time stamp
        #     can't slip past the per-function pass.
        for n in ast.walk(tree):
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "isoformat"
                and _is_aware_now_call(n.func.value)
            ):
                _add(n.lineno)
    return sorted(violations)


def test_no_inline_aware_now_isoformat_outside_ssot():
    violations = _find_inline_violations()
    assert violations == [], (
        "Inline aware-now ISO string(s) bypass the _isotime SSOT (A10 "
        "adoption):\n  " + "\n  ".join(violations)
        + "\nUse email_triage._isotime.now_utc_iso() (stored/compared, UTC) "
        "or now_local_iso() (human display). The only file allowed to compute "
        "the timestamp inline is _isotime.py itself."
    )


def _teeth_hits(src: str) -> list[int]:
    """Run the WIDENED detector over a planted source's functions."""
    tree = ast.parse(src)
    out: list[int] = []
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out += _aware_now_isoformat_lines(fn)
    return out


def test_adoption_pin_has_teeth():
    # inline
    assert _teeth_hits(
        "from datetime import datetime, timezone\n"
        "def f():\n"
        "    return datetime.now(timezone.utc).isoformat()\n"
    ), "pin missed an inline utc isoformat"
    # aliased inline
    assert _teeth_hits(
        "import datetime as dt\n"
        "def f(tz):\n"
        "    return dt.datetime.now(tz).isoformat()\n"
    ), "pin missed an aliased inline now"
    # var-bound (A10 WIDENED — was a blind spot)
    assert _teeth_hits(
        "from datetime import datetime, timezone\n"
        "def f():\n"
        "    now = datetime.now(timezone.utc)\n"
        "    return now.isoformat()\n"
    ), "pin missed the var-bound now.isoformat() shape"
    # arith inline (A10 WIDENED)
    assert _teeth_hits(
        "from datetime import datetime, timezone, timedelta\n"
        "def f():\n"
        "    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()\n"
    ), "pin missed the inline arith shape"
    # var-arith (A10 WIDENED — the subtlest, both my + the subagent's first scan missed it)
    assert _teeth_hits(
        "from datetime import datetime, timezone, timedelta\n"
        "def f():\n"
        "    now = datetime.now(timezone.utc)\n"
        "    return (now - timedelta(hours=1)).isoformat()\n"
    ), "pin missed the var-arith shape"

    # the SSOT call sites are clean (now_utc_iso / to_utc_iso, no raw .isoformat())
    assert not _teeth_hits(
        "from email_triage._isotime import now_utc_iso, to_utc_iso\n"
        "def f(dt):\n"
        "    return now_utc_iso() + to_utc_iso(dt)\n"
    ), "SSOT calls must pass"
    # a NON-now datetime (parsed / passed-in / fromtimestamp) is NOT flagged
    assert not _teeth_hits(
        "def f(parsed):\n"
        "    return parsed.isoformat()\n"
    ), "a non-now .isoformat() must NOT be flagged"
    assert not _teeth_hits(
        "from datetime import datetime, timezone\n"
        "def f(ms):\n"
        "    return datetime.fromtimestamp(ms, tz=timezone.utc).isoformat()\n"
    ), "fromtimestamp(...).isoformat() (not now-rooted) must NOT be flagged"
    # the local-display SSOT body is owned by the correctness pin, not this one
    assert not _teeth_hits(
        "from datetime import datetime\n"
        "def now_local_iso():\n"
        "    return datetime.now().astimezone().isoformat()\n"
    ), "local .now().astimezone() form is not this pin's concern"


# ---------------------------------------------------------------------------
# A10 strftime/gmtime stored-ts pin (2026-06-11) — the now_utc_iso_z SSOT's pin
# ---------------------------------------------------------------------------
# A stored "now" built via the time MODULE — ``time.strftime(fmt, time.gmtime())``
# — bypasses the _isotime SSOT just as an inline ``.now().isoformat()`` does, but
# the adoption pin above (keyed on ``.now(...).isoformat()``) can't see it. The
# lone such site (migrations.py:416) was routed through ``_isotime.now_utc_iso_z``;
# this bans a NEW one. Keyed on the MODULE function ``time.strftime`` — a
# datetime's ``dt.strftime(...)`` METHOD (O365 OData / Graph API wire formatting
# of a GIVEN datetime) has a different receiver and is intentionally NOT matched.


def _raw_time_strftime_sites(tree: ast.AST) -> list[int]:
    """Line numbers of ``time.strftime(...)`` MODULE calls (Name 'time' .
    'strftime') — the raw stored-now construction. NOT ``<dt>.strftime(...)``."""
    hits: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "strftime"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "time"
        ):
            hits.append(node.lineno)
    return hits


def _find_raw_strftime_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        try:
            tree = parse_module(path); assert tree is not None  # N-350 R31
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        rel = relpath(path)
        for ln in _raw_time_strftime_sites(tree):
            violations.append(f"{rel}:{ln}")
    return violations


def test_no_raw_time_strftime_outside_ssot():
    violations = _find_raw_strftime_violations()
    assert violations == [], (
        "Raw time.strftime(...) stored-timestamp construction bypasses the "
        "_isotime SSOT:\n  " + "\n  ".join(violations)
        + "\nUse email_triage._isotime.now_utc_iso_z() (Z-suffix, second "
        "precision) or now_utc_iso() (+00:00, microsecond). A dt.strftime(...) "
        "method call for an external API wire format is out of scope; if that's "
        "what this is, it won't match (different receiver) — re-check."
    )


def test_strftime_pin_has_teeth():
    bad = ast.parse(
        "import time\n"
        "def f():\n"
        "    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())\n"
    )
    assert _raw_time_strftime_sites(bad), "pin missed a raw time.strftime stored-ts"

    # a datetime METHOD strftime (API wire format of a given dt) is NOT flagged
    ok = ast.parse(
        "def f(dt):\n"
        "    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')\n"
    )
    assert not _raw_time_strftime_sites(ok), (
        "dt.strftime() method (API wire format) must NOT be flagged"
    )
