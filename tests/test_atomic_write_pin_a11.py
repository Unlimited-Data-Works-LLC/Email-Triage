"""A11 (divergence census 2026-06-09) — atomic config/state write pin.

A bare ``open(path, "w")`` truncates before writing; a crash mid-write
leaves a half-written file. For the config YAML that meant a corrupt file
the next boot couldn't parse. The fix routes the config writer through the
``email_triage._atomicio`` SSOT (sibling temp + ``os.replace``).

This **count-agnostic** pin asserts the STRUCTURAL invariant: no module
under ``src/email_triage`` dumps YAML straight to an open file handle
(``yaml.dump(data, f, ...)`` / ``yaml.safe_dump(data, f, ...)``) — that is
the non-atomic, truncate-then-write shape. Dump to a STRING and write it
with ``atomic_write_text`` instead. (Dumping to ``sys.stdout`` / a
``StringIO`` buffer is exempt — those aren't a target file.)
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath

_EXEMPT_STREAMS = {"stdout"}  # sys.stdout attr name (stderr cut 2026-11-05: no site used it)


def _is_yaml_dump(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"dump", "safe_dump"}
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "yaml"
    )


def _second_arg_is_exempt_stream(node: ast.Call) -> bool:
    if len(node.args) < 2:
        return True  # dump-to-string (1 arg) is fine
    stream = node.args[1]
    # sys.stdout / sys.stderr
    if isinstance(stream, ast.Attribute) and stream.attr in _EXEMPT_STREAMS:
        return True
    # a StringIO()/BytesIO() buffer
    if isinstance(stream, ast.Call):
        f = stream.func
        nm = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
        if nm in {"StringIO", "BytesIO"}:
            return True
    return False


def _find_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        rel = relpath(path)
        for node in ast.walk(tree):
            if _is_yaml_dump(node) and not _second_arg_is_exempt_stream(node):
                violations.append(
                    f"{rel}:{node.lineno} (yaml.dump to an open file — non-atomic; "
                    f"dump to a string + atomic_write_text)"
                )
    return violations


def test_no_non_atomic_yaml_file_dump():
    violations = _find_violations()
    assert violations == [], (
        "Non-atomic yaml.dump-to-file (A11) at:\n  "
        + "\n  ".join(violations)
        + "\nUse: atomic_write_text(path, yaml.dump(data, ...))."
    )


def test_pin_has_teeth():
    bad = ast.parse("import yaml\nwith open(p,'w') as f:\n    yaml.dump(d, f)\n")
    hits = [n for n in ast.walk(bad)
            if _is_yaml_dump(n) and not _second_arg_is_exempt_stream(n)]
    assert hits, "pin missed a planted yaml.dump-to-file"
    # dump-to-string + dump-to-stdout are exempt.
    ok = ast.parse("import yaml, sys\nyaml.dump(d)\nyaml.dump(d, sys.stdout)\n")
    okhits = [n for n in ast.walk(ok)
              if _is_yaml_dump(n) and not _second_arg_is_exempt_stream(n)]
    assert not okhits, "dump-to-string / stdout must be exempt"


# --------------------------------------------------------------------------
# census  — sensitive/state file writes must go through the _atomicio SSOT
# (a power-loss can't corrupt the secrets store / OAuth token cache / TLS
# key+cert, and the perms-aware ``mode`` lands credentials owner-only).
#
# STRUCTURAL + count-agnostic (NOT a hardcoded writer list — db-sme R1/R2):
# scan every ``<target>.write_bytes(...)`` / ``<target>.write_text(...)`` call
# whose target NAME looks like a key/secret/token/cert/store/cache/pending file
# and flag it unless it is the atomic SSOT itself. After this census the only
# sensitive writes left are ``atomic_write_bytes/_text`` calls (a different AST
# shape — a bare ``Name`` func, not an ``Attribute.write_*``), so a re-divergent
# bare write on a NEW sensitive path is what trips.
# --------------------------------------------------------------------------
import re as _re

_SENSITIVE_NAME = _re.compile(
    r"(?i)(key|secret|token|cred|pending|cert|store|cache)"
)


def _sensitive_bare_write_lines(tree: ast.AST) -> list[int]:
    out: list[int] = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("write_bytes", "write_text")):
            continue
        recv = n.func.value
        name = None
        if isinstance(recv, ast.Name):
            name = recv.id
        elif isinstance(recv, ast.Attribute):
            name = recv.attr
        elif isinstance(recv, ast.Call) and recv.args:
            # Path(<x>).write_*  — inspect the Path() argument.
            a = recv.args[0]
            if isinstance(a, ast.Name):
                name = a.id
            elif isinstance(a, ast.Attribute):
                name = a.attr
        if name and _SENSITIVE_NAME.search(name):
            out.append(n.lineno)
    return out


def test_no_bare_sensitive_file_write_outside_atomicio():
    offenders = []
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        locs = _sensitive_bare_write_lines(tree)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "a bare write_bytes/write_text on a key/secret/token/cert/store target "
        f"outside the _atomicio SSOT: {offenders}. A power-loss mid-write can "
        "corrupt it (and a credential file is left world-readable in the pre-"
        "chmod window). Use atomic_write_bytes/atomic_write_text(..., mode=0o600)."
    )


def test_sensitive_write_pin_has_teeth():
    bad = ast.parse(
        "pending_key.write_bytes(pem)\n"
        "self._token_cache_path.write_text(s)\n"
        "Path(args.save_old_key_to).write_text(k)\n"
    )
    assert len(_sensitive_bare_write_lines(bad)) == 3
    ok = ast.parse("report_path.write_text(md)\nout.write_bytes(b)\n")
    assert not _sensitive_bare_write_lines(ok)


# --------------------------------------------------------------------------
# N-189 R20_14 — `.partial + os.replace` idiom MUST chmod before replace.
# `open(tmp, "wb")` respects umask (typically 0644/0664 → world-readable
# window on POSIX for a credential-bearing artifact). os.replace preserves
# the file's mode across the atomic swap, so a chmod AFTER replace still
# leaves an observable world-readable window during writer runtime.
# The fix: `os.chmod(tmp, 0o600)` BEFORE `os.replace(tmp, out_path)`.
# --------------------------------------------------------------------------

def _find_partial_replace_fns(tree: ast.AST) -> list[tuple[str, int, bool]]:
    """Return (funcname, lineno, has_chmod_before_replace) for every
    function containing an `os.replace(tmp, ...)` call whose `tmp` receiver
    is derived from a `.partial` name."""
    results = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Collect this fn's os.replace calls + os.chmod calls in order.
        replaces = []
        chmods = []
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                base = sub.func.value
                if not (isinstance(base, ast.Name) and base.id == "os"):
                    continue
                if sub.func.attr == "replace" and sub.args:
                    replaces.append((sub.lineno, sub))
                elif sub.func.attr == "chmod":
                    chmods.append(sub.lineno)
        if not replaces:
            continue
        # For each os.replace, check if there's an os.chmod on an earlier line
        # in the same function AND the fn body contains a `".partial"` literal
        # (the shape we care about — sibling temp + rename).
        has_partial = any(
            isinstance(sub, ast.Constant) and isinstance(sub.value, str) and ".partial" in sub.value
            for sub in ast.walk(fn)
        )
        if not has_partial:
            continue
        for rlineno, _rcall in replaces:
            has_chmod_before = any(cl < rlineno for cl in chmods)
            results.append((fn.name, rlineno, has_chmod_before))
    return results


def test_partial_atomic_write_chmods_before_replace():
    """N-189 R20_14: every function with a `.partial + os.replace` sibling-
    swap pattern MUST chmod the temp before os.replace — else the landed
    artifact inherits the umask default (world-readable window on POSIX)."""
    offenders = []
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for fn, ln, has_chmod in _find_partial_replace_fns(tree):
            if not has_chmod:
                offenders.append(f"{rel}::{fn}:{ln}")
    assert not offenders, (
        "N-189 R20_14: `.partial + os.replace` atomic-write pattern with NO "
        "`os.chmod` before the replace — the landed artifact inherits the "
        f"umask (world-readable on POSIX for a credential-bearing file): {offenders}. "
        "Add `os.chmod(tmp, 0o600)` (or a wider mode as appropriate) BEFORE "
        "os.replace(tmp, out_path). N-189 R20_14 close 2026-07-01."
    )


def test_partial_replace_teeth():
    bad = ast.parse(
        "import os\n"
        "def h(out_path):\n"
        "    tmp = out_path.with_name(out_path.name + '.partial')\n"
        "    tmp.write_bytes(b'x')\n"
        "    os.replace(tmp, out_path)\n"
    )
    hits = _find_partial_replace_fns(bad)
    assert hits and not hits[0][2], f"teeth: bad shape must be missing chmod-before, got {hits}"

    good = ast.parse(
        "import os\n"
        "def h(out_path):\n"
        "    tmp = out_path.with_name(out_path.name + '.partial')\n"
        "    tmp.write_bytes(b'x')\n"
        "    os.chmod(tmp, 0o600)\n"
        "    os.replace(tmp, out_path)\n"
    )
    hits = _find_partial_replace_fns(good)
    assert hits and hits[0][2], f"teeth: good shape must have chmod-before, got {hits}"


def test_atomic_write_mode_sets_owner_only_perms(tmp_path):
    import os
    import sys
    from email_triage._atomicio import atomic_write_bytes
    target = tmp_path / "secret.bin"
    atomic_write_bytes(target, b"ciphertext", mode=0o600)
    assert target.read_bytes() == b"ciphertext"
    assert not list(tmp_path.glob("*.tmp"))
    if sys.platform != "win32":  # POSIX perms only meaningful off Windows
        assert (target.stat().st_mode & 0o777) == 0o600


# --------------------------------------------------------------------------
# census run21 D1 (2026-07-18) — the hand-rolled tmp+rename idiom must go
# through the _atomicio SSOT.
#
# Concrete driver: the HTTP-01 webroot solver (``web/acme_http01.py``)
# shipped a hand-rolled ``tmp = root / f".{token}.tmp"; tmp.write_text(...);
# os.chmod(tmp, 0o644); tmp.replace(path)`` — same crash-safety shape as
# ``_atomicio`` but forked, so a corner (missing fsync, missing except-arm
# tmp cleanup, umask window before chmod on POSIX) will drift out of
# ``_atomicio`` and this call site will never catch up. Route through the
# SSOT.
#
# STRUCTURAL, count-agnostic, interprocedural. Within every function body,
# find a ``<tmp>.write_text(...)`` / ``<tmp>.write_bytes(...)`` call where
# ``<tmp>`` is an ``ast.Name`` — then look for a downstream
# ``<tmp>.replace(...)`` or ``os.replace(<tmp>, ...)`` on the SAME name in
# the same function body. That is the sibling-tmp-swap shape. Flag it
# unless the same function body ALSO calls ``atomic_write_bytes`` /
# ``atomic_write_text`` (the SSOT itself is the only exemption; no
# file-name allow-list — every module under src/email_triage is covered by
# construction of the shared ``iter_src_files``).
# --------------------------------------------------------------------------


def _find_bare_tmp_replace_fns(tree: ast.AST) -> list[tuple[str, int]]:
    """(funcname, lineno) for every fn body that shows the sibling-tmp
    swap shape: some `<name>.write_text/_bytes(...)` AND some
    `<name>.replace(...)` or `os.replace(<name>, ...)` on the SAME name.

    Structural — the same ``ast.Name.id`` is the receiver of the write and
    the target of the replace. No receiver-name pattern match. No fn-body
    blanket exemption: a fn that routes an unrelated write through
    ``atomic_write_text`` while still hand-rolling a second tmp+rename is
    ALSO a divergence (DA MF-1 fold, 2026-07-18). The SSOT's own file is
    exempted at the outer walk (file-name allow-list in
    ``test_no_bare_tmp_replace_outside_atomicio``), not per-fn here."""
    hits: list[tuple[str, int]] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Collect (name, lineno) for each <name>.write_text/_bytes(...) call.
        write_names: dict[str, int] = {}
        for sub in ast.walk(fn):
            if not (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)):
                continue
            if sub.func.attr not in ("write_text", "write_bytes"):
                continue
            recv = sub.func.value
            if isinstance(recv, ast.Name):
                write_names.setdefault(recv.id, sub.lineno)
        if not write_names:
            continue
        # Look for a matching-name .replace() or os.replace(<name>, ...).
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Call):
                continue
            f = sub.func
            # Case A: <name>.replace(...)
            if isinstance(f, ast.Attribute) and f.attr == "replace" \
                    and isinstance(f.value, ast.Name) \
                    and f.value.id in write_names:
                hits.append((fn.name, write_names[f.value.id]))
                break
            # Case B: os.replace(<name>, ...)
            if isinstance(f, ast.Attribute) and f.attr == "replace" \
                    and isinstance(f.value, ast.Name) and f.value.id == "os" \
                    and sub.args and isinstance(sub.args[0], ast.Name) \
                    and sub.args[0].id in write_names:
                hits.append((fn.name, write_names[sub.args[0].id]))
                break
    return hits


def test_no_bare_tmp_replace_outside_atomicio():
    """census run21 D1: hand-rolled tmp+rename must route through _atomicio."""
    offenders: list[str] = []
    for path in iter_src_files():
        # The SSOT's own file legitimately implements this shape — every
        # OTHER module is a divergence.
        if path.name == "_atomicio.py":
            continue
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        rel = relpath(path)
        for fn, ln in _find_bare_tmp_replace_fns(tree):
            offenders.append(f"{rel}::{fn}:{ln}")
    assert not offenders, (
        "hand-rolled tmp-write + rename shape (write_text/_bytes on a Name "
        "followed by <name>.replace(...) / os.replace(<name>, ...) in the "
        f"same fn) outside the _atomicio SSOT: {offenders}. Route through "
        "atomic_write_text / atomic_write_bytes — the SSOT owns fsync, "
        "chmod-before-swap, and except-arm tmp cleanup; a forked copy "
        "silently drifts out of those guarantees. census run21 D1."
    )


def test_bare_tmp_replace_pin_has_teeth():
    # BAD 1: the exact acme_http01 webroot idiom pre-fix.
    bad = ast.parse(
        "import os\n"
        "def publish(root, token, key_auth):\n"
        "    path = root / token\n"
        "    tmp = root / f'.{token}.tmp'\n"
        "    tmp.write_text(key_auth, encoding='utf-8')\n"
        "    os.chmod(tmp, 0o644)\n"
        "    tmp.replace(path)\n"
    )
    hits = _find_bare_tmp_replace_fns(bad)
    assert hits, f"teeth: bad shape must trip, got {hits}"

    # BAD 2: os.replace(tmp, final) — the other spelling.
    bad2 = ast.parse(
        "import os\n"
        "def h(target, data):\n"
        "    tmp = target.with_suffix('.tmp')\n"
        "    tmp.write_bytes(data)\n"
        "    os.replace(tmp, target)\n"
    )
    hits2 = _find_bare_tmp_replace_fns(bad2)
    assert hits2, f"teeth: os.replace(tmp, ...) shape must trip, got {hits2}"

    # GOOD 1: same shape, but the fn routes through the SSOT — exempt.
    ok = ast.parse(
        "from email_triage._atomicio import atomic_write_text\n"
        "def publish(root, token, key_auth):\n"
        "    path = root / token\n"
        "    atomic_write_text(path, key_auth, mode=0o644)\n"
    )
    okhits = _find_bare_tmp_replace_fns(ok)
    assert not okhits, f"teeth: SSOT route must be exempt, got {okhits}"

    # GOOD 2: a plain write with no rename shape — not our concern.
    ok2 = ast.parse(
        "def h(out, s):\n"
        "    out.write_text(s)\n"
    )
    assert not _find_bare_tmp_replace_fns(ok2)


def test_atomic_write_is_crash_safe(tmp_path):
    from email_triage._atomicio import atomic_write_text

    target = tmp_path / "config.yaml"
    target.write_text("original: true\n", encoding="utf-8")

    # A normal write replaces atomically.
    atomic_write_text(target, "updated: true\n")
    assert target.read_text(encoding="utf-8") == "updated: true\n"
    # No .tmp litter left behind.
    assert not list(tmp_path.glob("*.tmp"))

    # A failure mid-write leaves the ORIGINAL intact (never truncated).
    # Passing a non-str raises TypeError inside the temp-file write (the
    # io.write type-check) — AFTER the temp is opened but BEFORE os.replace
    # — which is exactly the raise-before-replace timing that matters: the
    # target file is never touched, and the except-arm unlinks the temp.
    import pytest

    with pytest.raises(Exception):
        atomic_write_text(target, object())  # type: ignore[arg-type]
    # Original survived; no torn write.
    assert target.read_text(encoding="utf-8") == "updated: true\n"
    assert not list(tmp_path.glob("*.tmp"))
