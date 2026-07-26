"""Generate baseline of sync sqlite calls inside async def by (rel, fn)."""
import ast
import pathlib

sites = set()


def find_enclosing_async_fn(tree, target_line):
    best_name = "<module>"
    best_start = -1
    for c in ast.walk(tree):
        if not isinstance(c, ast.AsyncFunctionDef):
            continue
        end = getattr(c, "end_lineno", c.lineno) or c.lineno
        if c.lineno <= target_line <= end and c.lineno > best_start:
            best_name, best_start = c.name, c.lineno
    return best_name


DB_ATTRS = {"execute", "fetchall", "fetchone", "executemany"}

base = pathlib.Path("src/email_triage")
for p in base.rglob("*.py"):
    if "__pycache__" in p.parts:
        continue
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if child.func.attr in DB_ATTRS:
                    rel = p.relative_to(base).as_posix()
                    sites.add((rel, node.name))
                    break  # one per fn

for rel, fn in sorted(sites):
    print(f'    ("{rel}", "{fn}"),')
print(f"# total {len(sites)} entries")
