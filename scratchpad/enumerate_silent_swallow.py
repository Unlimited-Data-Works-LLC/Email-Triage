"""Enumerate silent-swallow except handlers by enclosing_fn."""
import ast
import pathlib

sites = {}


def find_fn(tree, line):
    best_name = "<module>"
    best_start = -1
    for c in ast.walk(tree):
        if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(c, "end_lineno", c.lineno) or c.lineno
            if c.lineno <= line <= end and c.lineno > best_start:
                best_name, best_start = c.name, c.lineno
    return best_name


base = pathlib.Path("src/email_triage")
for p in base.rglob("*.py"):
    if "__pycache__" in p.parts:
        continue
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if len(node.body) != 1:
            continue
        s = node.body[0]
        if isinstance(s, ast.Pass) or (
            isinstance(s, ast.Return) and s.value is None
        ):
            rel = p.relative_to(base).as_posix()
            fn = find_fn(tree, node.lineno)
            sites.setdefault((rel, fn), 0)
            sites[(rel, fn)] += 1

print(f"total sites: {sum(sites.values())}")
print(f"unique (rel, fn) pairs: {len(sites)}")
top = sorted(sites.items(), key=lambda x: -x[1])[:15]
print("top functions by site count:")
for (rel, fn), n in top:
    print(f"  {n:3d}  {rel}::{fn}")
