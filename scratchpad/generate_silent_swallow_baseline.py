"""Generate the _BASELINE_SWALLOW frozenset literal for the pin."""
import ast
import pathlib

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
            sites.add((rel, fn))

for rel, fn in sorted(sites):
    print(f'    ("{rel}", "{fn}"),')
print(f"# total {len(sites)} entries")
