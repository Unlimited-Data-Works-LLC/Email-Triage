"""N-193 R20_8 structural pin — IMAP fetch body-content SSOT.

Census run20 R20_8 finding: 5 metadata-only `.fetch(seq, "(UID ...)")` sites
in `providers/imap.py` are SAFE by string content only. A single edit that
adds `BODY[HEADER]` / `RFC822` / `BODY.PEEK[]` to the fetch spec would
silently pull actual mail content into memory OUTSIDE the body-aware
SSOT `providers/imap_blocking.py`. The tuple-return + parens bug that
returns `(None, [])` on error would then silently drop PHI without a
signal.

The body-aware SSOT (`imap_blocking._blocking_fetch` /
`fetch_message_blocking` / `fetch_messages_batch_blocking`) is the ONLY
place body-content fetches may originate. This pin: any `.fetch()` call
in `src/email_triage/providers/**` EXCEPT `imap_blocking.py` whose spec
argument mentions a body/header/content section MUST fail.

Detects both:
(a) STRING LITERAL spec — `"(BODY[HEADER] ...)"` / `"(RFC822 ...)"`.
(b) NAME-TAINT — spec is a Name bound in the same function to a string
    literal that mentions a body/header section.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import iter_files, parse_module, relpath, SRC_ROOT


PROVIDERS_DIR = SRC_ROOT / "providers"
_SSOT_FILE = "imap_blocking.py"

# Body-content markers — anything that pulls actual mail content (headers OR
# body OR full message). BODY.PEEK[HEADER] and BODY.PEEK[] are ALLOWED
# because those are what the SSOT itself uses (peek doesn't mark as read),
# but they must originate from the SSOT.
_BODY_CONTENT_MARKERS = re.compile(
    r"BODY\s*\[|BODY\.PEEK\s*\[|\bRFC822\b|\bHEADER\b(?!\s*])",
    re.IGNORECASE,
)


def _has_body_content(spec: str) -> bool:
    return bool(_BODY_CONTENT_MARKERS.search(spec))


def _binds_to_content_spec(fn: ast.AST, name: str) -> bool:
    """1-hop taint: True if `name` is bound anywhere in `fn` to a string
    constant that contains a body-content marker."""
    for sub in ast.walk(fn):
        if not (isinstance(sub, ast.Assign)):
            continue
        if not (isinstance(sub.value, ast.Constant) and isinstance(sub.value.value, str)):
            continue
        for tgt in sub.targets:
            if isinstance(tgt, ast.Name) and tgt.id == name:
                if _has_body_content(sub.value.value):
                    return True
    return False


def _enclosing_fn(tree: ast.AST, node: ast.AST) -> ast.AST | None:
    """Nearest enclosing FunctionDef of `node` in `tree`."""
    # ast doesn't give parent pointers by default; build a simple parent map.
    parent = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parent[id(c)] = p
    cur = node
    while cur is not None:
        cur = parent.get(id(cur))
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
    return None


def _find_content_fetches(tree: ast.AST) -> list[int]:
    """Every `.fetch(<seq>, <spec>)` call whose spec references body/header
    content — literal OR 1-hop taint."""
    hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "fetch":
            continue
        if len(node.args) < 2:
            continue
        spec = node.args[1]
        # Case (a): string literal
        if isinstance(spec, ast.Constant) and isinstance(spec.value, str):
            if _has_body_content(spec.value):
                hits.append(node.lineno)
                continue
        # Case (b): name-taint
        if isinstance(spec, ast.Name):
            fn = _enclosing_fn(tree, node)
            if fn is not None and _binds_to_content_spec(fn, spec.id):
                hits.append(node.lineno)
    return hits


def test_no_body_content_fetch_outside_ssot():
    """Only `providers/imap_blocking.py` may originate a body-content
    IMAP fetch. Any other `providers/*.py` doing `client.fetch(seq,
    "(BODY[HEADER] ...)")` bypasses the body-aware SSOT."""
    offenders: list[str] = []
    for path in iter_files(PROVIDERS_DIR):
        if path.name == _SSOT_FILE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for ln in _find_content_fetches(tree):
            offenders.append(f"{relpath(path)}:{ln}")
    assert not offenders, (
        "N-193 R20_8: IMAP `.fetch()` call with body-content spec "
        f"(BODY[.../HEADER/RFC822) outside `providers/imap_blocking.py` "
        f"SSOT: {offenders}. Route through `fetch_message_blocking` / "
        "`fetch_messages_batch_blocking`."
    )


def test_pin_has_teeth():
    bad_literal = ast.parse("""
async def h(client, seq):
    return await client.fetch(seq, "(BODY[HEADER] FLAGS)")
""")
    assert _find_content_fetches(bad_literal)

    bad_taint = ast.parse("""
async def h(client, seq):
    spec = "(RFC822 FLAGS)"
    return await client.fetch(seq, spec)
""")
    assert _find_content_fetches(bad_taint)

    good_literal = ast.parse("""
async def h(client, seq):
    return await client.fetch(seq, "(UID)")
""")
    assert not _find_content_fetches(good_literal)

    good_taint = ast.parse("""
async def h(client, seq):
    spec = "(UID INTERNALDATE)"
    return await client.fetch(seq, spec)
""")
    assert not _find_content_fetches(good_taint)
