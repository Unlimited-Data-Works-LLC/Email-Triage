"""N-465 — a security knob has exactly ONE authoritative store.

Why this pin exists
===================
``EMAIL_TRIAGE_CSRF_ENFORCE`` was a second store for ``tls.csrf_enforce``. It
was read ONCE, in lifespan, so using it already cost a process restart — the
same cost as editing YAML — while creating a fork no surface reconciled:
``/admin/security`` renders the CONFIG value, so an install with the env var
set to 0 displayed enforcement as ON while the middleware let every violation
through. Removed 2026-09-12 (config-surface audit finding #1).

Deleting the branch is the down-payment; this pin is the prevention (PD-1).

The property, stated as a class rather than as a name
=====================================================
1. **No env var may shadow a security-section config field.** The predicate is
   built FROM ``config.py`` at run time — every field of ``TLSConfig`` and
   ``AuthConfig`` — so a knob added tomorrow is covered without editing this
   file. An env literal read anywhere in ``src/`` whose name, lowercased and
   stripped of the ``EMAIL_TRIAGE_`` / ``ET_`` prefix, matches one of those
   fields is an offender.

2. **Every write to an app-state ``csrf_enforce`` derives from the config
   object or the security form** — never from an environment read, and never
   from a bare literal. Count-agnostic over however many writers exist.

Deliberate scope limit, stated rather than papered over: a knob whose env name
does not mechanically match its field name (``EMAIL_TRIAGE_STRICT_TLS`` for
``tls.enabled``, say) is invisible to net 1. Net 1 catches the shape that
actually recurred — the env var named after its field.

No carve-out (punch 547)
========================
This pin used to exempt ``EMAIL_TRIAGE_DB_ENCRYPTION`` on the claim that YAML
could not decide encryption before the DB opens. That claim was false —
``resolve_db_encryption(config)`` takes the already-loaded config — and the
operator removed the override on 2026-09-29. Every remaining env read in src is
registered in ``email_triage._env_registry`` (``test_env_registry_pin.py``);
this pin keeps its narrower job: no env name shadows a security config field.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT, env_read_sites, iter_files, parse_module, parse_source, relpath,
    scan_env_reads,
)

_ENV_READERS = {"getenv"}
_ENV_PREFIXES = ("EMAIL_TRIAGE_", "ET_")
# ``LoggingConfig`` added 2026-09-12 on hipaa-sme review: it owns ``hipaa``
# (config.py) — the single most safeguard-critical knob in the codebase — and
# the first draft of this pin excluded it while shipping in the same batch as
# an N-464 HIPAA clobber. Widened and re-run: zero offenders, so it is free.
_SECURITY_SECTIONS = ("TLSConfig", "AuthConfig", "LoggingConfig")


def _security_field_names() -> set[str]:
    """Every field of the security config sections, read from config.py.

    Built at run time so the pin's net widens with the config surface. A
    hardcoded list here would be the "membership predicate narrower than the
    class" failure this project keeps re-finding.
    """
    tree = parse_module(SRC_ROOT / "config.py")
    assert tree is not None, "config.py did not parse"
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name in _SECURITY_SECTIONS:
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    names.add(stmt.target.id.lower())
    assert names, "no security config fields found — the predicate is dead"
    return names


def _env_literals():
    """Yield (relpath, lineno, NAME) for every env read whose key resolves.

    Punch 547 (PD-6): the SHARED scanner ``_pin_harness.env_read_sites`` — any
    receiver, ``from os import environ`` aliases, module-constant keys (the house
    idiom), and keys resolved through helpers — instead of a walker of its own.
    """
    for s in env_read_sites():
        if s.key:
            yield s.path, s.lineno, s.key


def _strip_prefix(env_name: str) -> str:
    for pref in _ENV_PREFIXES:
        if env_name.startswith(pref):
            return env_name[len(pref):].lower()
    return env_name.lower()


def test_no_env_var_shadows_a_security_config_field():
    fields = _security_field_names()
    seen = [n for _, _, n in _env_literals()]
    # FLOOR + positive control. `assert not offenders` over an empty net passes,
    # and the DA measured both this pin and its teeth going green with the
    # generator stubbed to yield nothing. A registered env read must be seen,
    # and the module-constant indirection must resolve (planted: no src read
    # uses the constant form since punch 547 removed the two that did).
    assert "ET_HEALTH_OPS_TOKEN" in seen, (
        f"the env-read net went dead; {len(seen)} literal(s) found"
    )
    planted = parse_source(
        'import os\n_VAR = "EMAIL_TRIAGE_CSRF_ENFORCE"\n'
        'def f():\n    return os.environ.get(_VAR)\n'
    )
    assert [s.key for s in scan_env_reads([("p.py", planted)])] == [
        "EMAIL_TRIAGE_CSRF_ENFORCE"
    ], "the constant-indirection resolver went dead"
    offenders = []
    for rel, lineno, env_name in _env_literals():
        stem = _strip_prefix(env_name)
        if stem in fields:
            offenders.append(f"{rel}:{lineno} {env_name} shadows a security knob ({stem})")
    assert not offenders, (
        "a security knob must have ONE authoritative store; these env reads "
        "fork it:\n  " + "\n  ".join(offenders)
    )


def test_app_state_csrf_enforce_is_written_only_from_config_or_the_form():
    """Every writer of the effective flag sources it from the single store."""
    allowed_sources = ("config", "csrf_enforce", "form")
    offenders = []
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not (isinstance(target, ast.Attribute) and target.attr == "csrf_enforce"):
                    continue
                # Only app-state writes; `config.tls.csrf_enforce = x` is the
                # store itself being written by the admin form, which is fine.
                recv = ast.unparse(target.value)
                if "state" not in recv:
                    continue
                rhs = ast.unparse(node.value)
                if "environ" in rhs or "getenv" in rhs:
                    offenders.append(f"{relpath(path)}:{node.lineno} env-derived: {rhs}")
                elif not any(src in rhs for src in allowed_sources):
                    offenders.append(f"{relpath(path)}:{node.lineno} unrecognised source: {rhs}")
    assert not offenders, (
        "app.state.csrf_enforce must derive from config.tls.csrf_enforce or the "
        "/admin/security form:\n  " + "\n  ".join(offenders)
    )


def test_both_nets_have_teeth():
    """Mutation proof — a pin never shown red is indistinguishable from a dead one."""
    fields = _security_field_names()
    assert "csrf_enforce" in fields, "the security-field predicate lost its exemplar"
    # Net 1 against the exact shape that was removed.
    assert _strip_prefix("EMAIL_TRIAGE_CSRF_ENFORCE") in fields
    assert _strip_prefix("EMAIL_TRIAGE_SESSION_TTL_SECS") in fields
    # ... and a non-security tunable must NOT trip it (no false positive).
    assert _strip_prefix("EMAIL_TRIAGE_WRITER_QUEUE_MAXSIZE") not in fields

    # Net 2 against an env-derived app-state write.
    bad = ast.parse('app.state.csrf_enforce = os.environ.get("X") == "1"\n')
    hits = []
    for node in ast.walk(bad):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and t.attr == "csrf_enforce":
                    rhs = ast.unparse(node.value)
                    if "environ" in rhs or "getenv" in rhs:
                        hits.append(rhs)
    assert hits, "net 2 would not have flagged an env-derived write"
