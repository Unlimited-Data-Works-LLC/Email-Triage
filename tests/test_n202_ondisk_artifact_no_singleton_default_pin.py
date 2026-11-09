"""N-202 R22 structural pin — Office365Provider + Office365CalendarProvider
`token_cache_path` MUST NOT default to a shared-singleton string literal.
(2026-07-02)

Census run22 R22_3 (HIGH — §164.310(d)(2)(i) + §164.312(a)(1)):
`token_cache_path: str = "./data/msal_cache.json"` in the two provider
ctors was a shared-singleton pool. Any caller that forgot the kwarg
silently POOLED every account's OAuth refresh token in one file — a
cross-account credential-leak back-door.

Fix landed 2026-07-02: both ctors default `token_cache_path=""`  and the
body raises `ValueError` on empty, forcing callers to route through
`providers.factory.msal_cache_path_for_account(account_id)`.

This pin bans re-introducing a string-literal default OR any default
matching the singleton path.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


PROVIDERS_DIR = SRC_ROOT / "providers"
_TARGET_CLASSES = {"Office365Provider", "Office365CalendarProvider"}
_BANNED_LITERAL_SUFFIXES = ("msal_cache.json", "/msal_cache.json")


def _find_provider_classes(tree: ast.AST) -> list[ast.ClassDef]:
    return [
        n for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name in _TARGET_CLASSES
    ]


def _find_init_default(cls: ast.ClassDef, arg_name: str) -> ast.AST | None:
    """Return the default value node for `arg_name` in `cls.__init__`,
    or None if the arg has no default (positional/required)."""
    for node in cls.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != "__init__":
            continue
        args = node.args
        # kwonly + regular args together, with defaults tail-aligned per PEP.
        regular_args = args.args
        defaults = args.defaults
        # defaults align with the TAIL of regular_args.
        offset = len(regular_args) - len(defaults)
        for i, a in enumerate(regular_args):
            if a.arg != arg_name:
                continue
            if i < offset:
                return None  # no default
            return defaults[i - offset]
    return None


def test_no_shared_singleton_default_for_token_cache_path():
    """Every `Office365(Calendar)?Provider.__init__(...)` MUST NOT default
    `token_cache_path` to a string containing `msal_cache.json`. The
    approved default is `""` + body-level fail-closed check."""
    offenders: list[str] = []
    for path in iter_files(PROVIDERS_DIR):
        tree = parse_module(path)
        if tree is None:
            continue
        for cls in _find_provider_classes(tree):
            dflt = _find_init_default(cls, "token_cache_path")
            if dflt is None:
                continue  # required (positional) — fine
            if isinstance(dflt, ast.Constant) and isinstance(dflt.value, str):
                v = dflt.value
                if v == "":
                    continue  # approved default (paired with fail-closed body check)
                if v.endswith(_BANNED_LITERAL_SUFFIXES):
                    offenders.append(
                        f"{relpath(path)}:{dflt.lineno}  "
                        f"{cls.name}.__init__ token_cache_path default = {v!r}"
                    )
            # Any non-empty literal is suspicious — flag anything ending
            # in .json as at least a bell:
            elif isinstance(dflt, ast.Constant) and isinstance(dflt.value, str) and dflt.value.endswith(".json"):
                offenders.append(
                    f"{relpath(path)}:{dflt.lineno}  "
                    f"{cls.name}.__init__ token_cache_path default = "
                    f"{dflt.value!r} (json literal — suspicious)"
                )
    assert not offenders, (
        "N-202 R22: shared-singleton token_cache_path default in an O365 "
        "provider ctor — pre-N-202 this was `'./data/msal_cache.json'`, a "
        "cross-account credential-pool back-door (§164.310(d)(2)(i) + "
        "§164.312(a)(1)). The approved default is `''` (empty string) "
        "with a body-level `if not token_cache_path: raise ValueError(...)` "
        "so callers MUST pass a per-account path from "
        "`providers.factory.msal_cache_path_for_account(account_id)`.\n\n"
        + "\n".join(offenders)
    )


def test_fail_closed_body_check_present():
    """Both O365 provider ctors must contain a body-level fail-closed check
    on `token_cache_path` — a caller passing an empty string (or omitting
    the kwarg → default '') MUST raise, not silently use the singleton."""
    missing: list[str] = []
    for path in iter_files(PROVIDERS_DIR):
        tree = parse_module(path)
        if tree is None:
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        for cls in _find_provider_classes(tree):
            if "token_cache_path is REQUIRED" in src or "N-202" in src:
                continue  # marker present in comment or error msg
            missing.append(f"{relpath(path)}  {cls.name}")
    assert not missing, (
        "N-202 R22: O365 provider ctor missing the body-level fail-closed "
        "check on `token_cache_path`. Add:\n"
        "    if not token_cache_path:\n"
        "        raise ValueError(\"...token_cache_path is REQUIRED...\")\n"
        "so a caller that omits the kwarg (defaulting to '') fails fast.\n\n"
        + "\n".join(missing)
    )


# ---------------------------------------------------------------------------
# N-209 R23 — CALLER-SIDE ban: singleton literal at construction time
# ---------------------------------------------------------------------------

_BANNED_LITERALS = {"./data/msal_cache.json", "data/msal_cache.json"}


def _walk_all_python():
    """Iterate every `.py` file in the project src tree (not just providers/) —
    the caller-side pin needs coverage where callers LIVE, which is web/, cli.py,
    and any future entrypoint."""
    for path in iter_files(SRC_ROOT):
        yield path


def _find_singleton_kwarg_offenders(tree: ast.AST) -> list[tuple[int, str]]:
    """Every `<any>.token_cache_path=<literal-singleton>` kwarg OR a `.get(...,
    '<singleton>')` fallback inside a call to `Office365(Calendar)?Provider(
    ...)`. The census R23_2 form: `o365_cfg.get("token_cache_path",
    "./data/msal_cache.json")`."""
    offenders = []
    for node in ast.walk(tree):
        # `<obj>.get("token_cache_path", "<singleton>")` — the fallback shape.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "get" and len(node.args) >= 2:
                arg1 = node.args[0]
                arg2 = node.args[1]
                if (isinstance(arg1, ast.Constant) and arg1.value == "token_cache_path"
                        and isinstance(arg2, ast.Constant) and isinstance(arg2.value, str)
                        and arg2.value in _BANNED_LITERALS):
                    offenders.append((node.lineno, f".get('token_cache_path', {arg2.value!r})"))
        # `token_cache_path=<singleton-literal>` direct kwarg.
        if isinstance(node, ast.keyword) and node.arg == "token_cache_path":
            v = node.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value in _BANNED_LITERALS:
                offenders.append((v.lineno, f"token_cache_path={v.value!r}"))
    return offenders


def test_no_singleton_literal_at_o365_construction_callsite():
    """N-209 R23: caller-side ban on the pre-N-209 singleton literal
    `"./data/msal_cache.json"`. Even after N-202 killed the ctor default,
    census R23_2 discovered `cli.py:483` still passed the singleton via
    `.get("token_cache_path", "./data/msal_cache.json")` — a §164.310(d)(2)(i)
    live cross-account credential-pool defect on the CLI leg.

    Bans:
    (a) The literal as a direct kwarg value:
        `token_cache_path="./data/msal_cache.json"`
    (b) The literal as a `.get()` fallback:
        `<cfg>.get("token_cache_path", "./data/msal_cache.json")`
    Anywhere in `src/email_triage/**`."""
    offenders: list[str] = []
    for path in _walk_all_python():
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno, form in _find_singleton_kwarg_offenders(tree):
            offenders.append(f"{relpath(path)}:{lineno}  {form}")
    assert not offenders, (
        "N-209 R23: shared-singleton `./data/msal_cache.json` literal "
        "reappeared at a caller — the ctor default was killed by N-202 but "
        "a caller passing the literal EXPLICITLY (via `.get()` fallback or "
        "direct kwarg) re-opens the cross-account credential-pool defect. "
        "For per-account paths use `providers.factory.msal_cache_path_for_"
        "account(account_id)`. For the CLI (single-account, no account_id "
        "at bootstrap), derive a per-USERNAME path like:\n"
        "    _safe_stem = ''.join(c if c.isalnum() else '_' for c in username)[:40]\n"
        "    default = f'./data/msal_cache_cli_{_safe_stem}.json'\n"
        "so a second CLI invocation on a different account gets its own file.\n\n"
        + "\n".join(offenders)
    )
