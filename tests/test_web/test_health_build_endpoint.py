"""`GET /health/build` — the SHA, authenticated, and nothing else.

cve-arc needs one datum to answer "is this deployment current": the commit the
running build came from. This route exists so it can ask over HTTP instead of
`ssh <host> "sudo podman exec ..."`.

The whole safety argument is PAYLOAD NARROWNESS, so that is what these tests
pin. A 2026-06-13 devils-advocate review (`30b503ad`) rejected "a token alone on
the published port" unlocking **/health/detail**, and a later review of a
LAN-reachable read-only token for that same body returned NO-GO for re-creating
exactly that artifact. The detail body is the sensitive object: its `status`
field alone is a one-bit oracle over sixteen OR-terms (audit_failures,
cert_degraded, version_incompatible, baa_expired, ...). A 40-char commit hash is
not that object.

So the load-bearing test here is not "does it return the SHA" — it is
**test_response_carries_nothing_but_the_sha**. If a future field creeps into
this payload, the narrowness argument silently stops being true while every
other test still passes.
"""

from __future__ import annotations

import sqlite3

import pytest
from _pin_harness import docstring_constant_ids, parse_source

from email_triage.web.auth import generate_api_key, hash_api_key


def _issue_api_key(db, user_id: int, name: str = "cve-arc") -> str:
    """Mint a real API key for `user_id` and return the plaintext."""
    key = generate_api_key()
    db.execute(
        "INSERT INTO api_keys (user_id, name, key_hash, created_at) "
        "VALUES (?, ?, ?, datetime('now'))",
        (user_id, name, hash_api_key(key)),
    )
    db.commit()
    return key


def test_unauthenticated_bearer_client_gets_401_not_a_login_redirect(client):
    """A monitor is an API client. A 303 to /login would be parsed as success-ish
    HTML by a naive client and hide a broken credential."""
    resp = client.get(
        "/health/build",
        headers={"Authorization": "Bearer not-a-real-key"},
        follow_redirects=False,
    )
    assert resp.status_code == 401, resp.text
    assert "build_sha" not in resp.text


def test_unauthenticated_browser_client_is_never_served_the_sha(client):
    resp = client.get("/health/build", follow_redirects=False)
    assert resp.status_code in (303, 401), resp.status_code
    assert "build_sha" not in resp.text


def test_a_non_admin_api_key_is_sufficient(client, db, regular_user):
    """Least privilege: a monitor must not need an ADMIN key to read a build
    number. If this ever starts requiring admin, the deployment's monitoring
    credential gets over-privileged to work around it."""
    key = _issue_api_key(db, regular_user["id"])
    resp = client.get("/health/build", headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 200, resp.text
    # Asserts AUTHORIZATION, not the value. The fixture app has no baked
    # /app/VERSION, so `app.state.build_sha` is absent and the route answers ""
    # — the value round-trip is covered by
    # test_a_real_sha_passes_through_unchanged.
    assert "build_sha" in resp.json()


def test_response_carries_nothing_but_the_sha(client, db, regular_user):
    """THE load-bearing pin — the narrowness IS the security argument.

    /health/detail's body is the object the 2026-06-13 review protected. If any
    of it leaks in here, this route becomes the thing that was rejected.
    """
    key = _issue_api_key(db, regular_user["id"])
    body = client.get("/health/build", headers={"Authorization": f"Bearer {key}"}).json()

    assert set(body) == {"build_sha", "version"}, (
        f"/health/build must return EXACTLY this closed set; got {sorted(body)}. "
        "Both keys are build IDENTIFIERS (which commit / which release line) of "
        "the same sensitivity class — neither is an oracle over anything. The "
        "payload is safe because the set is enumerated and closed, so any new "
        "key must be argued for here rather than arriving by drift."
    )
    forbidden = {
        "status", "degraded", "audit_failures", "csrf_rejects", "tasks",
        "watchers_failing", "ingestion", "schema_version", "uptime_secs",
        "last_triage", "baa_expired", "retry_dead", "office365_push", "db",
    }
    assert not (forbidden & set(body)), f"detail-body field leaked: {forbidden & set(body)}"


@pytest.mark.parametrize(
    "resolved",
    [
        "unknown",          # placeholder sentinel
        "dev",              # placeholder sentinel
        "v0.2.0",           # a release TAG, not a commit
        "a1b2c3d",          # 7-char sha (the .git/HEAD walk's shape)
        "$Format:%H$",      # unsubstituted export-subst literal
        "",                 # nothing baked at all
        "A" * 40,           # right length, wrong alphabet (uppercase / non-hex)
    ],
)
def test_anything_that_is_not_a_full_sha_answers_empty(client, db, regular_user, app, resolved):
    """REGRESSION (DA must-fix MF-1, 2026-08-05). Absent beats wrong.

    A consumer equality-compares this against a 40-char HEAD, so any of these
    would be permanent FALSE DRIFT — a security fix that looks eternally
    un-deployed. Enumerating sentinels loses that race by construction; the
    endpoint asserts the SHAPE instead, so this is parametrized over the shapes
    rather than over a deny-list.
    """
    key = _issue_api_key(db, regular_user["id"])
    original = getattr(app.state, "build_sha", "")
    try:
        app.state.build_sha = resolved
        body = client.get("/health/build", headers={"Authorization": f"Bearer {key}"}).json()
        assert body["build_sha"] == "", f"{resolved!r} leaked through as a build_sha"
    finally:
        app.state.build_sha = original


def test_a_real_sha_passes_through_unchanged(client, db, regular_user, app):
    key = _issue_api_key(db, regular_user["id"])
    original = getattr(app.state, "build_sha", "")
    try:
        app.state.build_sha = "809b9e3e2aa25fb5c02a98a858dcb3560f7223a1"
        body = client.get("/health/build", headers={"Authorization": f"Bearer {key}"}).json()
        assert body["build_sha"] == "809b9e3e2aa25fb5c02a98a858dcb3560f7223a1"
    finally:
        app.state.build_sha = original


# ---------------------------------------------------------------------------
# punch 538 / register row N-523 — build_sha is BUILD-BOUND, never env-resolved.
#
# `build_sha` used to be `app.state.version` = `_resolve_version()`, which
# returns `EMAIL_TRIAGE_VERSION` / `GIT_SHA` VERBATIM ahead of the baked
# /app/VERSION file. A scanner reads the manifests AT the sha this route reports
# and treats an advisory as fixed if that commit carries the fix, so a stale
# 40-hex env var on an older image silenced advisories whose fixes were not
# running: a field named `build_sha` reporting a non-build value, and a security
# control failing OPEN. The route now reads `app.state.build_sha` =
# `_build_sha.baked_build_sha()`, which reads the baked file and nothing else.
#
# The load-bearing arm is test_the_route_no_longer_reads_the_resolved_version:
# a monkeypatched env var proves nothing on its own, because the app fixture may
# have resolved its state before the test ran. Making the two state fields
# DISAGREE and asserting which one the route reports is the direct measurement.
# ---------------------------------------------------------------------------


def test_the_route_no_longer_reads_the_resolved_version(client, db, regular_user, app):
    """`version` is a 40-hex sha and `build_sha` is empty. The route must report
    the EMPTY one — the only way `version` can be answering is if the route is
    still reading it."""
    key = _issue_api_key(db, regular_user["id"])
    original_version = app.state.version
    original_build = getattr(app.state, "build_sha", "")
    try:
        app.state.version = "f" * 40
        app.state.build_sha = ""
        body = client.get("/health/build", headers={"Authorization": f"Bearer {key}"}).json()
        assert body["build_sha"] == "", (
            "/health/build reported app.state.version. That value can come from "
            "EMAIL_TRIAGE_VERSION / GIT_SHA at RUNTIME, so an older image could "
            "name any commit it liked and a scanner would read that commit's "
            "manifests — silencing advisories whose fixes are not running."
        )
    finally:
        app.state.version = original_version
        app.state.build_sha = original_build


def test_baked_build_sha_ignores_the_environment(tmp_path, monkeypatch):
    """The resolver itself: the baked file wins over BOTH env vars, which are
    each set to a DIFFERENT valid-looking 40-hex sha."""
    from email_triage._build_sha import baked_build_sha

    baked = "0" * 39 + "1"
    path = tmp_path / "VERSION"
    path.write_text(baked + "\n", encoding="utf-8")
    monkeypatch.setenv("EMAIL_TRIAGE_VERSION", "a" * 40)
    monkeypatch.setenv("GIT_SHA", "b" * 40)
    assert baked_build_sha(str(path)) == baked


@pytest.mark.parametrize(
    "baked,expected",
    [
        ("809b9e3e2aa25fb5c02a98a858dcb3560f7223a1", "809b9e3e2aa25fb5c02a98a858dcb3560f7223a1"),
        ("$Format:%H$", ""),
        ("dev", ""),
        ("unknown", ""),
        ("", ""),
    ],
)
def test_baked_build_sha_reads_only_the_baked_file(tmp_path, monkeypatch, baked, expected):
    from email_triage._build_sha import baked_build_sha

    monkeypatch.setenv("EMAIL_TRIAGE_VERSION", "c" * 40)
    path = tmp_path / "VERSION"
    path.write_text(baked, encoding="utf-8")
    assert baked_build_sha(str(path)) == expected


def test_baked_build_sha_is_empty_when_nothing_was_baked(tmp_path, monkeypatch):
    """No file at all — an env var must NOT fill the gap. This is the rollback
    shape: a container started from an older image with a quadlet that still
    carries last deploy's GIT_SHA."""
    from email_triage._build_sha import baked_build_sha

    monkeypatch.setenv("GIT_SHA", "d" * 40)
    assert baked_build_sha(str(tmp_path / "absent" / "VERSION")) == ""


@pytest.mark.parametrize(
    "baked",
    [
        "809b9e3e2aa25fb5c02a98a858dcb3560f7223a1x",       # one junk char
        "809b9e3e2aa25fb5c02a98a858dcb3560f7223a1 dirty",  # sha + a word
        "0" * 41,                                          # 41 hex digits
        "809b9e3e2aa25fb5c02a98a858dcb3560f7223a1﻿",  # a non-space invisible
    ],
)
def test_a_sha_followed_by_junk_is_not_a_build_sha(tmp_path, monkeypatch, baked):
    """N-539-X1(b) (db-sme, panel 4, 2026-09-29). Absent beats wrong — and a
    TRUNCATION is the one construction that breaks it.

    The resolver used to `return baked[:40]`, so the route's shape gate
    `fullmatch`ed a value the resolver had already cut down to 40 characters.
    A `/app/VERSION` holding a real sha followed by anything non-whitespace was
    therefore ACCEPTED, and the first 40 characters were reported as the build
    commit. cve-arc silences advisories against the sha this field reports, so a
    sha-shaped value derived from a malformed bake is exactly the fail-open the
    route's "by construction" claim rules out. The WHOLE stripped file must be
    the sha or there is no answer.
    """
    from email_triage._build_sha import baked_build_sha

    monkeypatch.setenv("EMAIL_TRIAGE_VERSION", "c" * 40)
    path = tmp_path / "VERSION"
    path.write_text(baked, encoding="utf-8")
    assert baked_build_sha(str(path)) == "", (
        f"{baked!r} was accepted as a build sha. A truncated read of a malformed "
        f"bake is a plausible-but-wrong commit, which is worse than no answer."
    )


def _env_reads_in_code(src: str) -> list[str]:
    """Env touches in ``src`` (one function's source), via the SHARED AST
    scanner ``_pin_harness.scan_env_reads`` (punch 547, PD-6). A docstring or a
    comment naming a variable is not a read; a later triple-quoted literal can
    no longer blind it, and ``from os import environ as E`` is seen (538
    fold-check DA-FC4 ii/iii — the old substring scan missed both)."""
    import textwrap

    from _pin_harness import parse_source, scan_env_reads

    tree = parse_source(textwrap.dedent(src))
    return [s.key or s.shape for s in scan_env_reads([("fn.py", tree)])]


def test_the_environment_detector_has_teeth():
    """Prove the scan can FAIL before trusting it to pass. A prose-only mention
    is allowed; a real read is not."""
    prose_only = '''
    """Docstring naming GIT_SHA."""
    # a comment naming os.environ and EMAIL_TRIAGE_VERSION
    return open(path).read().strip()
'''
    assert _env_reads_in_code(prose_only) == []
    real_read = '''
    """Docstring."""
    return os.environ.get("GIT_SHA", "")
'''
    assert _env_reads_in_code(real_read) == ["GIT_SHA"]
    # DA-FC4 (ii): docstring-less, with a LATER triple-quoted literal.
    later_literal = (
        'def f():\n    v = os.environ.get("GIT_SHA")\n'
        '    q = """sql"""\n    return v\n'
    )
    assert _env_reads_in_code(later_literal) == ["GIT_SHA"]
    # DA-FC4 (iii): an aliased import.
    aliased = 'from os import environ as E\ndef f():\n    return E.get("BUILD_ID")\n'
    assert _env_reads_in_code(aliased) == ["BUILD_ID"]


def test_neither_the_resolver_nor_the_route_can_reach_the_environment():
    """Structural arm. A behavioural test proves the value at ONE call; this
    proves the env is not reachable from EITHER function at all, so a later
    "just fall back to GIT_SHA when the file is missing" edit fails here rather
    than silently re-opening N-523.

    SCOPE, stated because the name reads wider than a per-function scan: each
    listed function's OWN source is scanned; a callee is covered only when it is
    listed too. So ``/health/runtime-deps``'s inventory callees are listed where
    they read no environment (punch 539 fold-check, da DA-FC539-1(c)):
    ``runtime_install_record``, ``runtime_marker_status`` and
    ``resolve_manifest_path``, whose manifest env read the fold-check removed
    (hipaa H539FC-8), plus the CLI's ``_embedding_bits_paths``, which kept a
    hand-rolled copy of it. ``get_runtime_deps_path`` is not listed: it chooses
    the runtime prefix, not ``build_sha``, and since punch 547 it reads no
    environment at all (it returns the fixed ``DEFAULT_RUNTIME_DEPS``;
    ``test_env_registry_pin`` holds that tree-wide)."""
    import inspect

    from email_triage import _build_sha as build_sha_mod
    from email_triage import cli as cli_mod
    from email_triage import embedding_bits as eb_mod
    from email_triage.web.routers import health as health_mod

    # `read_baked_version` and `is_placeholder_build_value` are in this set
    # because they are SHARED with `_resolve_version`. Until 2026-09-29 that caller read the environment by
    # design, which made the shared funnel the likeliest place for an env read
    # to land; neither may read it now (operator directive, N-523).
    for fn in (
        build_sha_mod.read_baked_version,
        build_sha_mod.baked_build_sha,
        build_sha_mod.is_placeholder_build_value,
        health_mod._served_build_sha,
        health_mod.health_build,
        health_mod.health_runtime_deps,
        eb_mod.runtime_install_record,
        eb_mod.runtime_marker_status,
        eb_mod.resolve_manifest_path,
        cli_mod._embedding_bits_paths,
    ):
        found = _env_reads_in_code(inspect.getsource(fn))
        assert not found, (
            f"{fn.__qualname__} references {found}. build_sha must be bounded by "
            f"what was true at BUILD time — a runtime env var cannot be allowed "
            f"to answer the question a scanner acts on."
        )


def _funcs_with_literal(src: str, needle: str) -> set[str]:
    """Every function in ``src`` whose CODE carries a string literal containing
    ``needle``. The docstring is excluded: prose MUST be able to name what the
    code may not repeat, which is the same rule `_env_reads_in_code` follows."""
    import ast

    tree = parse_source(src)
    docs = docstring_constant_ids(tree)
    found: set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(fn):
            if (
                isinstance(sub, ast.Constant)
                and isinstance(sub.value, str)
                and id(sub) not in docs
                and needle in sub.value
            ):
                found.add(fn.name)
    return found


#: A function whose NAME says it answers "which build is this" is a
#: build-identity resolver, and none of them may read the environment. Matching
#: on the name rather than on a hand-kept list makes the pin below
#: count-agnostic WITHIN web/app.py: a resolver added there tomorrow is measured
#: without editing this. LIMITS (538 fold-check DA-FC3/DA-FC4/DB-538FC-1): this
#: arm is per-function and covers the web/app.py and _build_sha.py resolvers
#: whose NAME matches. The tree-wide, interprocedural property — no env read
#: anywhere in src outside the registry, which has NO row for either module and
#: only the ops-token row for routers/health.py — is
#: ``tests/test_env_registry_pin.py`` (punch 547); a differently-named resolver
#: reading env fails THERE.
_BUILD_IDENTITY_NAME_NEEDLES = ("version", "build_sha")


def _build_identity_functions(module) -> list[str]:
    """Every module-level function in ``module`` whose name matches a
    build-identity needle. Discovered by walking the module, never listed."""
    import ast
    import inspect

    return [
        node.name
        for node in ast.parse(inspect.getsource(module)).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(n in node.name for n in _BUILD_IDENTITY_NAME_NEEDLES)
    ]


def test_no_build_identity_resolver_reads_the_environment():
    """OPERATOR DIRECTIVE 2026-09-29: *"Absolutely not. Gut that code path
    now."* — the `EMAIL_TRIAGE_VERSION` / `GIT_SHA` override of the build
    identifier is removed outright, from BOTH surfaces, not just from the one a
    scanner reads.

    The narrower arm above names the `_build_sha` readers and both routes
    explicitly. That was right while `_resolve_version` was ALLOWED to read the
    environment; now nothing is, so the correct scope is a property over every
    build-identity resolver in the module. This reuses `_env_reads_in_code` —
    the same detector, with its own teeth arm — rather than hand-rolling a
    second walker (PD-6: the pins obey the SSOT rule too).

    First entry of punch 547, the pre-publish environment-override census. This
    pin covers `web/app.py`'s resolvers; it does not claim to cover the census.
    """
    import inspect

    from email_triage import _build_sha as build_sha_mod
    from email_triage.web import app as app_mod

    found_fns = [
        (m, n) for m in (app_mod, build_sha_mod) for n in _build_identity_functions(m)
    ]
    names = [n for _, n in found_fns]
    # Prove the DISCOVERY half can see, before trusting what it reports. A
    # mis-wired walker returning [] would make the loop below vacuous — the
    # silently-partial-rig failure mode.
    assert {"_resolve_version", "baked_build_sha", "read_baked_version"} <= set(names), (
        f"the build-identity walker found {sorted(names)}, which does not "
        f"include both known resolvers — it is mis-wired, so its clean result "
        f"below would mean nothing."
    )
    offenders = {
        f"{m.__name__}.{name}": found
        for m, name in found_fns
        if (found := _env_reads_in_code(inspect.getsource(getattr(m, name))))
    }
    assert not offenders, (
        f"{offenders} — a build identifier that a runtime environment variable "
        f"can set is not a build identifier. A scanner reads the manifests AT "
        f"the commit these fields report, so an older image naming a newer "
        f"commit silences advisories whose fixes are not running. Removed at "
        f"the operator's direction 2026-09-29; do not re-introduce it as a "
        f"'fallback when the file is missing'."
    )


def _funcs_using_name(src: str, name: str) -> set[str]:
    """Every function in ``src`` that references the identifier ``name`` —
    including in a parameter DEFAULT, which is where `BAKED_VERSION_PATH`
    reached the pre-convergence `_resolve_build_sha`."""
    import ast

    found: set[str] = set()
    for fn in ast.walk(ast.parse(src)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Name) and sub.id == name:
                found.add(fn.name)
    return found


def test_the_re_inlined_literal_detector_has_teeth():
    """Prove both scans can FAIL, and that the literal scan exempts prose,
    before either is trusted to pass. A rig that cannot fail manufactures a
    clean bill of health."""
    src = (
        'def prose_only():\n'
        '    """A docstring naming $Format and /app/VERSION."""\n'
        '    return 1\n'
        'def real_inline(p=BAKED_VERSION_PATH):\n'
        '    return x.startswith("$Format")\n'
    )
    assert _funcs_with_literal(src, "$Format") == {"real_inline"}
    assert _funcs_with_literal(src, "/app/VERSION") == set()
    assert _funcs_using_name(src, "BAKED_VERSION_PATH") == {"real_inline"}
    assert _funcs_using_name(src, "_is_placeholder_build_value") == set()


def _placeholder_membership_tests(src: str) -> set[str]:
    """Functions that test membership against the ``{"dev","unknown"}``
    sentinels — by the funnel's name or by a re-inlined literal collection."""
    import ast

    found: set[str] = set()
    for fn in ast.walk(ast.parse(src)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Compare)
                    and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)):
                continue
            for comp in node.comparators:
                if isinstance(comp, ast.Name) and comp.id.lstrip("_") == "PLACEHOLDER_BAKED_VALUES":
                    found.add(fn.name)
                elif isinstance(comp, (ast.Set, ast.Tuple, ast.List)) and {
                    e.value for e in comp.elts if isinstance(e, ast.Constant)
                } & {"dev", "unknown"}:
                    found.add(fn.name)
    return found


def test_placeholder_sentinels_are_tested_only_in_the_funnel():
    """538 fold-check DA-FC6 (punch 547 residue). The one-funnel arm below
    pins the ``$Format`` and ``/app/VERSION`` needles; the ``{"dev","unknown"}``
    sentinels — the exact drift H538-5/DA-A2 named (a sentinel added to one
    resolver, missed in the other) — were unpinned. A literal pin is wrong
    (``_resolve_version`` legitimately RETURNS "unknown"), so the property is:
    no function but the funnel performs a MEMBERSHIP TEST against them."""
    import inspect

    from email_triage import _build_sha as build_sha_mod
    from email_triage.web import app as app_mod

    # The funnel moved to ``_build_sha`` (punch 539/538 follow-up); both the
    # funnel module and the app module are measured.
    found = set()
    for mod in (build_sha_mod, app_mod):
        found |= _placeholder_membership_tests(inspect.getsource(mod))
    assert found == {"is_placeholder_build_value"}, found
    # Teeth: both re-inline shapes are caught; a plain return is not.
    assert _placeholder_membership_tests(
        'def g(v):\n    return v in {"dev", "unknown"}\n') == {"g"}
    assert _placeholder_membership_tests(
        'def g(v):\n    return v not in _PLACEHOLDER_BAKED_VALUES\n') == {"g"}
    assert _placeholder_membership_tests('def g():\n    return "unknown"\n') == set()


def test_the_baked_value_predicates_are_each_one_funnel():
    """PD-5 / R5 — hipaa `H538-5` and da `DA-A2` (panel 4, 2026-09-29).

    538 added `BAKED_VERSION_PATH` and a second placeholder test in the same
    change that cites PD-5 as its reason for existing: `_resolve_build_sha` and
    `_resolve_version` each carried their own `{"dev","unknown"}` +
    `$Format` predicate character-for-character, and `_resolve_version` still
    opened the literal path the new constant names. Two mirrored copies WILL
    drift — a sentinel added to one resolver and missed in the other makes the
    two readers disagree about which image is running with nothing saying so.

    Count-agnostic by construction: this asserts a PROPERTY over every function
    in the module (which ones carry the literal), not that some list has length
    N, so a resolver added tomorrow is measured the same way.
    """
    import inspect

    from email_triage import _build_sha as build_sha_mod
    from email_triage.web import app as app_mod

    # Both modules: the reader lives in `_build_sha` since the punch-539
    # convergence, and `_resolve_version` stays in `web/app.py`. Scanned per
    # module (a concatenated source would not parse: `from __future__` must lead).
    srcs = [inspect.getsource(m) for m in (app_mod, build_sha_mod)]

    def _lit(needle: str) -> set[str]:
        return set().union(*(_funcs_with_literal(s, needle) for s in srcs))

    def _uses(name: str) -> set[str]:
        return set().union(*(_funcs_using_name(s, name) for s in srcs))

    # NEGATIVE arm: nothing re-inlines either needle in CODE. Both live at
    # module level — `_EXPORT_SUBST_PREFIX` and `BAKED_VERSION_PATH` — so the
    # correct measurement is that NO function carries the literal.
    assert _lit("$Format") == set(), (
        "the export-subst placeholder is inlined in a function body instead of "
        "read from EXPORT_SUBST_PREFIX — R5: a collection of re-inlined "
        "needles is the violation."
    )
    assert _lit("/app/VERSION") == set(), (
        "a resolver opens the baked path as a literal instead of reading "
        "BAKED_VERSION_PATH — the constant exists precisely so there is one."
    )

    # POSITIVE arm, and the anti-deletion one: a negative-only pin is satisfied
    # by deleting the predicate outright. Every function that reads the baked
    # path must ROUTE its placeholder test through the funnel — so a third
    # resolver added tomorrow that opens the file and rolls its own sentinel
    # check fails here rather than drifting quietly.
    openers = _uses("BAKED_VERSION_PATH")
    funnel_callers = _uses("is_placeholder_build_value")
    assert openers, "no function reads BAKED_VERSION_PATH — the constant is dead"
    assert openers <= funnel_callers, (
        f"{sorted(openers - funnel_callers)} read the baked build identifier "
        f"without going through is_placeholder_build_value. Two copies of the "
        f"placeholder test WILL drift, and the two readers would then disagree "
        f"about which image is running with nothing saying so."
    )


def test_route_has_no_degraded_branch_and_never_touches_the_detail_snapshot():
    """REGRESSION (DA must-fix MF-4). The ABSENCE is the security argument.

    `health_build` not calling `_compute_health_detail` is the entire reason it
    is not the artifact `30b503ad` rejected. Nothing pinned that, so a later
    "improve the monitor" change adding `503 when degraded` would re-create the
    one-bit oracle for the same any-authenticated-principal audience — and every
    other test here would still pass, because the one-key assertion still holds
    and the 200 case runs against a healthy fixture app.
    """
    import inspect

    from email_triage.web.routers import health as health_mod

    src = inspect.getsource(health_mod.health_build)
    body = src.split('"""', 2)[-1]  # strip the docstring; prose may discuss them
    for forbidden in ("_compute_health_detail", "503", "degraded"):
        assert forbidden not in body, (
            f"health_build must not reference {forbidden!r} — the absence of the "
            "degraded/detail path is what keeps this route off the rejected design."
        )


def test_db_outage_is_a_non_200_not_a_false_sha(client, db, regular_user, monkeypatch):
    """db-sme MF5 — pin the monitor-visible behaviour when the DB is down.

    Authentication needs the DB, so a DB outage makes this route non-200 even
    though build currency has zero DB dependency. The contract that matters to a
    consumer is: it must NOT return 200 with a wrong-or-empty sha, because that
    would read as real drift and could trigger a remediation deploy during a
    database incident. Any non-200 means UNKNOWN.
    """
    key = _issue_api_key(db, regular_user["id"])

    class _BrokenDB:
        def execute(self, *a, **kw):
            raise sqlite3.OperationalError("database is locked")

        def __getattr__(self, name):
            raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(client.app.state, "db", _BrokenDB(), raising=False)
    resp = client.get("/health/build", headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code != 200, (
        "a DB outage must never present as a successful build-sha read — a "
        f"consumer would score it as drift. Got {resp.status_code}: {resp.text[:200]}"
    )


def test_the_ops_token_does_not_unlock_this_route(client, db, monkeypatch):
    """The ops token is the LOOPBACK CLI path (`30b503ad`). It has no business
    widening a route built for remote callers, and honouring it here would start
    re-entangling the two credentials the reviews insisted stay separate."""
    monkeypatch.setenv("ET_HEALTH_OPS_TOKEN", "x" * 32)
    resp = client.get(
        "/health/build",
        headers={"X-Ops-Token": "x" * 32},
        follow_redirects=False,
    )
    assert resp.status_code in (303, 401), resp.status_code
    assert "build_sha" not in resp.text
