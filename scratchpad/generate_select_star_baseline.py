"""Generate baseline of SELECT * sites by (rel, enclosing_fn)."""
import ast
import pathlib
import re

sites = set()


def find_fn(tree, line):
    best_name = "<module>"
    best_start = -1
    for c in ast.walk(tree):
        if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(c, "end_lineno", c.lineno) or c.lineno
            if c.lineno <= line <= end and c.lineno > best_start:
                best_name, best_start = c.name, c.lineno
    return best_name


pat = re.compile(r"SELECT\s+\*\s+FROM", re.IGNORECASE)
base = pathlib.Path("src/email_triage")
for p in base.rglob("*.py"):
    if "__pycache__" in p.parts:
        continue
    text = p.read_text(encoding="utf-8")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if pat.search(node.value):
                rel = p.relative_to(base).as_posix()
                fn = find_fn(tree, node.lineno)
                sites.add((rel, fn))

for rel, fn in sorted(sites):
    print(f'    ("{rel}", "{fn}"),')
print(f"# total {len(sites)} entries")
