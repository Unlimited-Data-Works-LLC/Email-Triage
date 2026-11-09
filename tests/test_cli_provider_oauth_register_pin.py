"""Count-agnostic structural pin (N-130): a cli.py handler that builds an ACCOUNT
provider must register the install-level OAuth first.

THE BUG THIS CATCHES
====================
``providers.factory.build_provider`` / ``web.routers.ui._create_provider_from_account``
read the install Google / Office365 OAuth client creds from factory MODULE-LEVEL
SINGLETONS — set by ``factory.hydrate_and_register_install_oauth(config, secrets)``.
The server boot calls that in its lifespan; the CLI runs OUTSIDE the boot, so a CLI
command that builds an account provider WITHOUT first calling
``hydrate_and_register_install_oauth`` gets an EMPTY ``client_id`` ->
``GmailAuthError(400, "client_id not configured")`` (and the O365 sibling).

N-130: ``cmd_style_profile`` + ``cmd_sent_mail_index`` hit this LIVE — mining a Gmail
account on prod right after N-129 cleared the encrypted-DB-open crash. It is the
sibling of N-129's CLI-vs-boot divergence: the CLI must replicate a boot-time setup
step the provider factory depends on. No unit test caught it because the CLI mine
path for Gmail was never exercised end-to-end.

This pin: every cli.py call to a provider builder (``_create_provider_from_account``
or ``build_provider``) must sit in a function that ALSO references
``hydrate_and_register_install_oauth`` — a property over every site, not ``len==N``.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, innermost_fn_at_lineno, parse_module, parse_source

CLI_PATH = SRC_ROOT / "cli.py"
_PROVIDER_BUILDERS = {"_create_provider_from_account", "build_provider"}
_REGISTER = "hydrate_and_register_install_oauth"


def _references(fn: ast.AST, names: set[str]) -> bool:
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and n.id in names:
            return True
        if isinstance(n, ast.Attribute) and n.attr in names:
            return True
    return False


def _call_name(call: ast.Call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _find_offenders(tree: ast.AST) -> list[tuple[int, str]]:
    """Provider-builder calls whose enclosing function does NOT reference the
    install-OAuth register. Returns [(lineno, fn_name), ...]."""
    # Resolve the enclosing function NODE by line span, never by name: cli.py
    # defines several nested `_run` functions, so a name lookup would check the
    # wrong body.
    offenders: list[tuple[int, str]] = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        if _call_name(call) not in _PROVIDER_BUILDERS:
            continue
        fn = innermost_fn_at_lineno(tree, call.lineno)
        if fn is None:
            continue
        if not _references(fn, {_REGISTER}):
            offenders.append((getattr(call, "lineno", -1), fn.name))
    return offenders


def test_cli_provider_build_registers_install_oauth():
    """No cli.py provider build runs without registering the install OAuth first."""
    tree = parse_module(CLI_PATH)
    assert tree is not None, f"could not parse {CLI_PATH}"
    offenders = _find_offenders(tree)
    assert not offenders, (
        "cli.py function(s) build an account provider (_create_provider_from_account / "
        "build_provider) WITHOUT calling hydrate_and_register_install_oauth -> the "
        "install OAuth creds stay unregistered -> 'client_id not configured'. "
        f"Offenders (lineno, fn): {offenders}"
    )


def test_pin_has_teeth():
    """RED on a build-without-register; GREEN on build-with-register + a non-builder."""
    bad = (
        "def cmd_x(config, secrets):\n"
        "    provider = _create_provider_from_account(acct, secrets)\n"
    )
    bad_build = (
        "def cmd_w(acct, secrets):\n"
        "    return build_provider(acct, secrets)\n"
    )
    good = (
        "def cmd_y(config, secrets):\n"
        "    hydrate_and_register_install_oauth(config, secrets)\n"
        "    provider = _create_provider_from_account(acct, secrets)\n"
    )
    no_provider = (  # a function that builds no provider is out of scope
        "def cmd_z(config):\n"
        "    db = _cli_open_config_db(config)\n"
    )
    for src in (bad, bad_build):
        assert _find_offenders(parse_source(src)), f"pin missed a bad shape:\n{src}"
    for src in (good, no_provider):
        assert not _find_offenders(parse_source(src)), (
            f"pin false-positive on a good shape:\n{src}"
        )


def _find_register_calls_without_conn(tree: ast.AST) -> list[int]:
    """hydrate_and_register_install_oauth(...) calls that DON'T pass a 3rd arg (the
    db conn). A 2-arg call takes conn=None -> the one-shot per-account->install
    OAuth migration is SKIPPED -> a fresh/un-migrated install re-opens N-130 gap #3
    (the register passes but the migration never runs). (hipaa-sme N-130.)"""
    offenders: list[int] = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or _call_name(call) != _REGISTER:
            continue
        has_conn = len(call.args) >= 3 or any(kw.arg == "conn" for kw in call.keywords)
        if not has_conn:
            offenders.append(getattr(call, "lineno", -1))
    return offenders


def test_cli_register_passes_conn():
    """Every cli.py call to hydrate_and_register_install_oauth passes the db conn
    (3rd arg / conn=) so the one-shot migration actually runs on a fresh install —
    a 2-arg call silently skips it and re-opens N-130 gap #3."""
    tree = parse_module(CLI_PATH)
    assert tree is not None, f"could not parse {CLI_PATH}"
    offenders = _find_register_calls_without_conn(tree)
    assert not offenders, (
        "cli.py calls hydrate_and_register_install_oauth WITHOUT the db conn "
        "(3rd positional arg or conn=) -> conn=None skips the one-shot "
        "per-account->install OAuth migration -> a fresh/un-migrated install "
        f"re-opens N-130 gap #3. Pass the open config-db handle. Lines: {offenders}"
    )


def test_conn_check_has_teeth():
    """RED on a 2-arg register call; GREEN on the 3rd positional arg or conn=."""
    bad = (
        "def cmd_x(config, secrets):\n"
        "    hydrate_and_register_install_oauth(config, secrets)\n"
    )
    good_pos = (
        "def cmd_y(config, secrets, db):\n"
        "    hydrate_and_register_install_oauth(config, secrets, db)\n"
    )
    good_kw = (
        "def cmd_z(config, secrets, db):\n"
        "    hydrate_and_register_install_oauth(config, secrets, conn=db)\n"
    )
    assert _find_register_calls_without_conn(parse_source(bad)), "missed a 2-arg call"
    for src in (good_pos, good_kw):
        assert not _find_register_calls_without_conn(parse_source(src)), (
            f"conn-check false-positive:\n{src}"
        )
