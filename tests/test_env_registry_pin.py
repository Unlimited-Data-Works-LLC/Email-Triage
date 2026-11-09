"""Punch 547 — every environment touch in src is in the ONE registry (PD-1/PD-2).

Operator directive 2026-09-29: remove, do not document, any env read that can
override a security control, an audit or identity value, or a fail-closed
decision. The reads that remain live in ``email_triage._env_registry.ENV_READS``
with a class and a justification; the removed keys live in ``RETIRED`` and a
process that still carries one is refused at start.

The property (count-agnostic, over every site the shared scanner finds):

1. every env touch in ``src/email_triage`` matches a registry row
   ``(path, function, key)`` — or a documented ``"*"`` row for a dynamic key;
2. no touch has an ``unrecognised`` shape (``e = os.environ``,
   ``getattr(os, "environ")``, a bare ``getenv`` passed as a value): the
   scanner could not classify it, so it cannot be registered;
3. no registry row is stale (every row matches a real site);
4. every row's class is legal, and CONTROL-OVERRIDE is not a legal class;
5. no site reads a RETIRED key.

Interprocedural (PD-2): ``_pin_harness.scan_env_reads`` follows a key through
any module-level helper whose key is its own parameter (``_envbool.env_bool``),
to a fixpoint, so a read through a helper is keyed at the caller.

SCOPE (what a green run does NOT prove): methods are not propagated (the one
param-keyed method, ``EnvSecrets.get``, is the secret-read class and is pinned by
``test_secret_read_funnel_pin``); a key smuggled through a dict/list/``**kwargs``
is reported unresolved, not followed (and then fails arm 1 unless a ``"*"`` row
exists); env read inside third-party libraries and at the interpreter level is
outside our AST — the httpx half is pinned in ``test_egress_funnel_pin``, and
SSL_CERT_FILE/DIR are refused at start via RETIRED.
"""
from __future__ import annotations

import ast
import re

import pytest

from _pin_harness import (
    SRC_ROOT,
    parse_module,
    assert_pin_has_teeth,
    env_read_sites,
    parse_source,
    scan_env_reads,
)
from email_triage import _env_registry as reg


def _row_for(site, rows):
    for r in rows:
        if r.path != site.path or r.function != site.qualname:
            continue
        if r.key == "*" or r.key == site.key:
            return r
    return None


def _violations(sites, rows) -> list[str]:
    out: list[str] = []
    for s in sites:
        where = f"{s.path}:{s.lineno} {s.qualname} [{s.shape}]"
        if s.shape == "unrecognised":
            out.append(f"{where}: env reference in a shape the scanner cannot classify")
            continue
        if s.key in reg.RETIRED:
            out.append(f"{where}: reads RETIRED key {s.key!r} ({reg.RETIRED[s.key]})")
            continue
        row = _row_for(s, rows)
        if row is None:
            out.append(f"{where}: key={s.key!r} has no registry row")
        elif s.key is None and row.key != "*":
            out.append(f"{where}: unresolved key needs a documented '*' row")
    return out


def _detector(tree: ast.AST):
    return _violations(scan_env_reads([("planted.py", tree)]), rows=())


def test_every_src_env_touch_is_registered():
    bad = _violations(env_read_sites(), reg.ENV_READS)
    assert not bad, (
        "Environment touches without a registry row (punch 547). An env var that "
        "can override a control, an audit/identity value or a fail-closed "
        "decision is REMOVED, not registered; anything else gets a row in "
        "src/email_triage/_env_registry.py with its class + justification:\n  "
        + "\n  ".join(bad)
    )


def test_the_scanner_can_see_the_known_shapes():
    """Prove the rig can see before trusting its clean result: the helper
    itself, a helper-resolved caller, a direct read and a write must all be in
    the scan — a mis-wired walker returning [] would make the arm above vacuous."""
    sites = env_read_sites()
    shapes = {(s.path, s.shape) for s in sites}
    assert ("_envbool.py", "get") in shapes
    assert ("web/access_audit.py", "helper:env_bool") in shapes
    assert ("web/routers/health.py", "get") in shapes
    assert ("embedding_bits/__init__.py", "write") in shapes


def test_no_registry_row_is_stale():
    sites = env_read_sites()
    stale = [
        r for r in reg.ENV_READS
        if not any(
            s.path == r.path and s.qualname == r.function
            and (r.key == "*" or s.key == r.key)
            for s in sites
        )
    ]
    assert not stale, (
        "Registry rows with no matching site — delete them (an OWED-REMOVAL row "
        "goes stale by design when its owning change lands):\n  "
        + "\n  ".join(f"{r.path} {r.function} {r.key}" for r in stale)
    )


def test_registry_classes_are_legal():
    assert "CONTROL-OVERRIDE" not in reg.LEGAL_CLASSES
    for r in reg.ENV_READS:
        assert r.cls in reg.LEGAL_CLASSES, r
        assert r.justification.strip(), r
        if r.cls == reg.OWED_REMOVAL:
            assert re.search(r"punch \d+", r.justification), (
                f"{r}: an OWED-REMOVAL row must name the punch that removes it"
            )
    keys = [(r.path, r.function, r.key) for r in reg.ENV_READS]
    assert len(keys) == len(set(keys)), "duplicate registry rows"


@pytest.mark.parametrize("bad", [
    'import os\ndef f():\n    return os.environ.get("X")\n',
    'import os as _os\ndef f():\n    return _os.environ["X"]\n',
    'from os import environ as E\ndef f():\n    return E.get("X")\n',
    'from os import getenv\ndef f():\n    return getenv("X")\n',
    'import os\ndef f():\n    return "X" in os.environ\n',
    'import os\ndef f():\n    e = os.environ\n    return e.get("X")\n',
    'import os\ndef f():\n    return getattr(os, "environ").get("X")\n',
    'import os\ndef f():\n    return os.environ.get("EMAIL_TRIAGE_DB_ENCRYPTION")\n',
    # docstring-less function with a later triple-quoted literal — the exact
    # shape that blinded the old substring detector (538 fold-check DA-FC4 ii)
    'import os\ndef f():\n    v = os.environ.get("GIT_SHA")\n    q = """sql"""\n    return v\n',
])
def test_pin_has_teeth_direct_shapes(bad):
    assert_pin_has_teeth(
        _detector, bad,
        good_source='def f():\n    return "X"\n',
    )


def test_pin_has_teeth_through_helpers_across_modules():
    """PD-2: a read through a helper, and through a helper-of-helper in a
    different module, is keyed at the final caller."""
    helper = parse_source(
        'import os\n'
        'def env_flag(key):\n    return os.environ.get(key)\n'
        'def env_flag2(name):\n    return env_flag(name)\n'
    )
    caller = parse_source(
        'from email_triage.h import env_flag2\n'
        'def g():\n    return env_flag2("SECRET_SWITCH")\n'
    )
    sites = scan_env_reads([("h.py", helper), ("c.py", caller)])
    resolved = {(s.path, s.qualname, s.key) for s in sites if s.key}
    assert ("c.py", "g", "SECRET_SWITCH") in resolved, sites
    # And with only the helper rows registered, the caller is still a violation.
    rows = (
        reg.EnvRead("h.py", "env_flag", "*", reg.HELPER, "t"),
        reg.EnvRead("h.py", "env_flag2", "*", reg.HELPER, "t"),
    )
    bad = _violations(sites, rows)
    assert any("c.py" in b and "SECRET_SWITCH" in b for b in bad), bad


def test_a_registered_read_is_not_flagged():
    tree = parse_source('import os\ndef f():\n    return os.environ.get("X")\n')
    sites = scan_env_reads([("p.py", tree)])
    rows = (reg.EnvRead("p.py", "f", "X", reg.TUNABLE, "test"),)
    assert _violations(sites, rows) == []


def test_web_app_imports_no_os():
    """538 fold-check residue (DB-538FC-1 / DA-FC4): the build-identity module
    imports no ``os`` at all, so no helper-mediated env read can hide there."""
    def offenders(tree):
        return [
            n for n in ast.walk(tree)
            if (isinstance(n, ast.Import) and any(a.name.split(".")[0] == "os" for a in n.names))
            or (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "os")
        ]
    tree = parse_module(SRC_ROOT / "web" / "app.py")
    assert tree is not None and not offenders(tree)
    assert_pin_has_teeth(offenders, "import os.path\n", "import osmosis\n")
    assert_pin_has_teeth(offenders, "from os import environ\n")


def test_retired_env_is_refused(monkeypatch):
    for k in reg.RETIRED:
        monkeypatch.delenv(k, raising=False)
    reg.refuse_retired_env()  # clean env: no raise
    monkeypatch.setenv("EMAIL_TRIAGE_DB_ENCRYPTION", "false")
    with pytest.raises(reg.RetiredEnvError) as ei:
        reg.refuse_retired_env()
    assert "persistence.encryption_enabled" in str(ei.value)


def test_cli_refuses_a_retired_env_before_any_command(monkeypatch, capsys):
    from email_triage.cli import main

    for k in reg.RETIRED:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ET_BACKUP_TRIGGER_URL", "https://evil.example")
    rc = main(["version-check", "--print-target-schema-only"])
    assert rc == reg.RETIRED_ENV_EXIT_CODE
    assert "ET_BACKUP_TRIGGER_URL" in capsys.readouterr().err
