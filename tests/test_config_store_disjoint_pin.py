"""run17 #6 — config-store disjointness pin (PD#1).

email-triage persists configuration across THREE stores with fuzzy boundaries
(census run17 #6): the YAML config file, the ``settings`` DB table
(``set_setting`` / ``set_bool_setting``), and the encrypted ``secrets_store``
(``<provider>.set``). A value written to TWO of them drifts silently — and the
HIPAA-load-bearing failure is a CREDENTIAL/secret key that lands in BOTH the
encrypted secrets store AND the plaintext ``settings`` table (a secret at rest
outside its encrypted home — defeats §164.312(a)(2)(iv) encryption).

This pin enforces the **settings ∩ secrets disjointness** invariant: no key is
written to BOTH the settings table and the secrets store. Verified DISJOINT at
HEAD, so this is a count-agnostic DRIFT-PREVENTION pin, not a live-bug fix.

KEY RESOLUTION (run17 #6 3-SME must-fix): the load-bearing credential keys —
``HIPAA_RECIPIENT_SALT_SECRET_KEY``, ``GOOGLE_OAUTH_WEB_CLIENT_SECRET``,
``O365_OAUTH_CLIENT_SECRET``, … — are passed as MODULE CONSTANTS (``ast.Name``),
not string literals. A literal-only scan would be BLIND to exactly the keys this
pin exists to protect (PD#4 completeness). So the scan first builds a repo-wide
symbol table of module-level ``NAME = "literal"`` string constants and resolves
``ast.Name`` key args through it. Full-KEY comparison (not namespace) is used so
``style_learning:master`` and ``style_learning:hipaa_recipient_salt_v1`` are
correctly DISTINCT keys under the shared ``style_learning:`` namespace.

SCOPE CAVEAT (honest, narrowed per the 3-SME): (1) a key built from a genuinely
RUNTIME value (a param / computed string, not a module constant) is not compared
— only literals, f-string leading-prefixes, and module-constant-resolved names
are. (2) The secrets store is detected by a receiver-TYPE predicate (run18 #5,
§7d): a ``.set`` receiver whose STATIC type resolves to the ``SecretsProvider``
family (annotation / family-constructor / family-return-annotated factory — see
``_pin_harness.secret_receiver_type_table``), with the legacy receiver-NAME
substring (``secret``/``provider``) retained ONLY as a fallback for the
runtime-typed receivers the static resolver can't type (``self.secrets``, an
unannotated param). The union widens the net to a renamed handle (``bootstrap =
create_secrets_provider(...)``) without regressing — the previous name-only
heuristic was the §7-recurring "membership predicate narrower than the class".
The residual: a secrets write through a receiver that is NEITHER type-resolvable
NOR name-matching is still not compared. (3) The YAML store is a separate dotted
``TriageConfig`` field-path namespace (structurally non-colliding with these flat
runtime keys); extending to the YAML key-set is the documented follow-on tracked
under finding #8 (secret-not-in-plaintext-YAML). NB ``email_accounts.config_json``
is deliberately NOT folded into this key-collision net — it is the accounts SSOT,
whose migration writers scrub secrets out (a different invariant).
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    innermost_fn_at_lineno,
    is_secrets_provider_typed_receiver,
    iter_src_files,
    parse_module,  # N-178a
    parse_source,
    relpath,
    secret_receiver_type_table,
)

_SETTINGS_WRITERS = frozenset({"set_setting", "set_bool_setting"})
# Receiver-NAME fallback (run18 #5, §7d): retained ONLY for the runtime-typed
# receivers the static type table can't resolve (``self.secrets`` / an
# unannotated param). The PRIMARY classifier is the resolved receiver TYPE.
_SECRET_RECEIVERS = ("secret", "provider")
_ALLOW: frozenset[str] = frozenset()  # by-design shared keys (none; stay disjoint)


def _collect_str_constants() -> dict[str, str]:
    """Repo-wide module-level ``NAME = "literal"`` / ``NAME: str = "literal"``
    string constants (first definition wins) — so a constant-named key arg
    resolves to its value (the credential keys are all constant-named)."""
    consts: dict[str, str] = {}
    for f in iter_src_files():
        try:
            tree = parse_module(f)
            if tree is None: continue
        except SyntaxError:
            continue
        for node in tree.body:  # module-level only
            target = val = None
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)):
                target, val = node.targets[0].id, node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target, val = node.target.id, node.value
            if target and isinstance(val, ast.Constant) and isinstance(val.value, str):
                consts.setdefault(target, val.value)
    return consts


def _key_prefix(node: ast.AST, symbols: dict[str, str]) -> str | None:
    """A literal str key, the leading literal of an f-string, or a module-constant
    ``ast.Name`` resolved through ``symbols``. Split at the first f-string
    interpolation so dynamic-suffix keys cluster by their literal prefix."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.split("{")[0]
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                break
        return ("".join(parts) or None)
    if isinstance(node, ast.Name) and node.id in symbols:
        return symbols[node.id].split("{")[0]
    return None


def _is_secret_receiver(func: ast.Attribute, type_table) -> bool:
    """Receiver of ``<recv>.set`` is a secrets store — by resolved static TYPE
    (§7d, PRIMARY: ``is_secrets_provider_typed_receiver``) OR, as the documented
    residual, the legacy receiver-NAME substring (``secret``/``provider``) for the
    runtime-typed receivers the static resolver can't type (``self.secrets`` / an
    unannotated param). Strict union → the net only ever widens."""
    if is_secrets_provider_typed_receiver(func, type_table):
        return True
    recv = (func.value.id if isinstance(func.value, ast.Name)
            else func.value.attr if isinstance(func.value, ast.Attribute) else "")
    return any(s in (recv or "").lower() for s in _SECRET_RECEIVERS)


def _scan_tree(tree: ast.AST, symbols: dict[str, str],
               rel: str = "<mem>",
               type_table=frozenset()) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """(settings_key -> sites, secrets_key -> sites) for ONE tree. The single
    extraction path BOTH the live scan and the teeth test exercise. ``type_table``
    is the §7d resolved-receiver-TYPE set (empty for the in-memory teeth, which
    fall back to the receiver-NAME heuristic)."""
    settings: dict[str, set[str]] = {}
    secrets: dict[str, set[str]] = {}
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        func = n.func
        name = (func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute) else None)
        if name in _SETTINGS_WRITERS and len(n.args) >= 2:
            k = _key_prefix(n.args[1], symbols)
            if k:
                settings.setdefault(k, set()).add(f"{rel}:{n.lineno}")
        # N-223 R22: widen to .delete for symmetry with .set (census
        # config-persist MED — 5 unguarded raw `<recv>.delete` on secrets
        # outside `_secret_write` were LATENT because the pin scoped
        # only `.set`).
        if isinstance(func, ast.Attribute) and func.attr in ("set", "delete") and n.args:
            if _is_secret_receiver(func, type_table):
                k = _key_prefix(n.args[0], symbols)
                if k:
                    secrets.setdefault(k, set()).add(f"{rel}:{n.lineno}")
    return settings, secrets


def _store_key_sites() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    symbols = _collect_str_constants()
    settings: dict[str, set[str]] = {}
    secrets: dict[str, set[str]] = {}
    for f in iter_src_files():
        rel = relpath(f)
        try:
            tree = parse_module(f)
            if tree is None: continue
        except SyntaxError:
            continue
        type_table = secret_receiver_type_table(tree)
        s, k = _scan_tree(tree, symbols, rel, type_table)
        for d, src in ((settings, s), (secrets, k)):
            for key, sites in src.items():
                d.setdefault(key, set()).update(sites)
    return settings, secrets


def test_settings_and_secrets_key_sets_are_disjoint():
    settings, secrets = _store_key_sites()
    overlap = (set(settings) & set(secrets)) - _ALLOW
    detail = {k: {"settings": sorted(settings[k]), "secrets": sorted(secrets[k])} for k in overlap}
    assert not overlap, (
        "A config key is written to BOTH the settings table AND the secrets store "
        f"— a secret may sit in plaintext settings, or config drifts: {detail}. "
        "Pick ONE store (secret/credential → secrets_store; operational flag → settings) "
        "or add the key to _ALLOW with a by-design reason."
    )


def test_pin_has_teeth():
    # Feed synthetic source through the REAL extraction path (NOT a hand-built set
    # intersection) so a regression in the scanner/resolver is caught (3-SME must-fix).
    # (a) literal collision:
    src = (
        "def h(db, secrets, v):\n"
        "    set_setting(db, 'dup_key', v)\n"
        "    secrets.set('dup_key', v)\n"
    )
    s, k = _scan_tree(ast.parse(src), {})
    assert "dup_key" in s and "dup_key" in k
    # (b) CONSTANT-named collision is resolved (the credential-key shape):
    src2 = (
        "SECRET_K = 'style_learning:foo'\n"
        "def h(db, secrets, v):\n"
        "    set_setting(db, SECRET_K, v)\n"
        "    secrets.set(SECRET_K, v)\n"
    )
    tree2 = ast.parse(src2)
    syms = _collect_constants_in(tree2)
    s2, k2 = _scan_tree(tree2, syms)
    assert "style_learning:foo" in s2 and "style_learning:foo" in k2, "constant key not resolved"
    # (c) disjoint → no overlap:
    src3 = (
        "def h(db, secrets, v):\n"
        "    set_setting(db, 'only_settings', v)\n"
        "    secrets.set('only_secret', v)\n"
    )
    s3, k3 = _scan_tree(ast.parse(src3), {})
    assert set(s3) & set(k3) == set()


def _collect_constants_in(tree: ast.AST) -> dict[str, str]:
    """The _collect_str_constants logic for a single in-memory tree (teeth)."""
    out: dict[str, str] = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            out.setdefault(node.targets[0].id, node.value.value)
    return out


def test_real_tree_is_actually_scanned():
    # non-vacuity: the live tree yields SOME settings + secrets keys (else the
    # disjointness test would pass trivially on empty sets) AND a credential key
    # constant is resolved into the secrets set (the must-fix payoff).
    settings, secrets = _store_key_sites()
    assert settings, "no set_setting keys found — the scanner is mis-wired"
    assert secrets, "no secrets-store .set keys found — the scanner is mis-wired"


# ---------------------------------------------------------------------------
# run18 #5 — settings-table WRITE-COVERAGE pin (PD#1, count-agnostic).
#
# The disjointness pin (above) proves a key isn't written to TWO stores. This
# companion proves the COMPLEMENT: every raw value-write to the ``settings``
# table (``INSERT`` / ``REPLACE INTO settings`` / ``UPDATE settings SET``) routes
# through the settings SSOT (``set_setting`` / ``set_bool_setting``) — the single
# place that owns the single-writer commit + ``invalidate_setting_cache``
# contract — UNLESS it is a frozen ``@register`` migration body (an applied
# migration is immutable and legitimately touches the table during a schema/data
# cutover) or an explicitly-``_ALLOW``-ed transactional exception. A raw write
# that bypasses the SSOT is the structural seam a future
# secret-into-plaintext-settings drift would enter through, so it must be
# *visible* even though HEAD is converged. Count-agnostic: a PROPERTY over every
# settings-write site (``ast.walk`` of every string literal), never ``len==N``.
#
# RESIDUAL (honest): SQL is matched as a string-literal shape (Python concatenates
# adjacent literals into one ``Constant`` at parse time, so a multi-line SSOT
# statement is one node). A write assembled at runtime via ``%``/``.format``/an
# f-string interpolating the table name, or executed from a non-literal string,
# is not seen — none exist at HEAD (the three writers are all literal SQL).
# ---------------------------------------------------------------------------

# ``INTO settings`` covers INSERT / INSERT OR REPLACE / REPLACE INTO; the UPDATE
# arm requires ``settings SET`` so prose like "dynamic-DNS-update settings for …"
# (a docstring) is NOT a match; ``... FROM settings`` (a READ) never is. The
# DELETE arm (N-183 R20_11) catches ``DELETE FROM settings ...`` — a value-only
# WRITE regex missed the DELETE class, letting a new DELETE bypass slip under it.
_SETTINGS_WRITE_RE = re.compile(
    r"(?is)(\binto\s+settings\b|\bupdate\s+settings\s+set\b|\bdelete\s+from\s+settings\b)"
)

# Functions that ARE the settings-write SSOT — the raw INSERT/UPDATE/DELETE here
# IS the funnel, so it is exempt by construction. N-183 R20_11 promotes
# `delete_setting` + `delete_account_settings` to the SSOT set (they're the
# canonical DELETE funnels; the WRITE_RE previously missed them entirely).
_SETTINGS_WRITE_SSOT = frozenset({
    "set_setting", "set_bool_setting",
    "delete_setting",           # web/db.py — single-key DELETE SSOT (N-183)
    "delete_account_settings",  # web/settings_keys.py — batch account DELETE (N-183)
})

# (relpath::funcname) raw settings-writes sanctioned OUTSIDE the SSOT and OUTSIDE
# a ``@register`` migration body — keyed by enclosing-FUNCTION name (line-stable:
# survives an unrelated line shift, R38). Each a reviewed exception with a reason.
_SETTINGS_WRITE_ALLOW = {
    "db/audit.py::_capture_chain_anchor": (
        "transactional audit-chain anchor UPSERT — it must share the prune "
        "transaction so anchor + DELETE are atomic; set_setting() auto-commits, "
        "which would split that transaction (see the inline comment at the site)."
    ),
    "web/routers/ui/profile.py::_delete_all_db_work": (
        "N-183 R20_11: bulk-delete under a SAVEPOINT (nested inside "
        "profile_style_data_delete_all) — the M8 route deletes BOTH the "
        "settings-table profile row AND the sent_mail_index rows atomically "
        "in one SAVEPOINT-guarded transaction; delete_setting() would "
        "auto-commit + split the atomicity guarantee across the tables."
    ),
}


def _has_register_decorator(fn: ast.AST) -> bool:
    """True if ``fn`` carries a ``@register(...)`` (or bare ``@register``)
    decorator — i.e. it is a frozen migration body."""
    for d in getattr(fn, "decorator_list", []):
        target = d.func if isinstance(d, ast.Call) else d
        nm = (target.id if isinstance(target, ast.Name)
              else target.attr if isinstance(target, ast.Attribute) else None)
        if nm == "register":
            return True
    return False


def _settings_write_sites(tree: ast.AST) -> list[str]:
    """Enclosing-function names (``<module>`` at module scope) of every raw
    ``settings``-table write in ``tree``. The single extraction path the live
    scan, the staleness check, AND the teeth all share."""
    out: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if not _SETTINGS_WRITE_RE.search(node.value):
            continue
        fn = innermost_fn_at_lineno(tree, node.lineno)
        out.append(fn.name if fn is not None else "<module>")
    return out


def _settings_write_violations_in_tree(tree: ast.AST, rel: str) -> list[str]:
    """``relpath::funcname`` for raw settings-writes in ``tree`` that are NEITHER
    the SSOT NOR a ``@register`` migration body NOR ``_ALLOW``-ed."""
    out: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if not _SETTINGS_WRITE_RE.search(node.value):
            continue
        fn = innermost_fn_at_lineno(tree, node.lineno)
        fname = fn.name if fn is not None else "<module>"
        if fname in _SETTINGS_WRITE_SSOT:
            continue
        if fn is not None and _has_register_decorator(fn):
            continue
        key = f"{rel}::{fname}"
        if key in _SETTINGS_WRITE_ALLOW:
            continue
        out.append(key)
    return out


def test_raw_settings_writes_route_through_the_ssot():
    """No module writes the ``settings`` table with raw INSERT/UPDATE outside the
    ``set_setting`` / ``set_bool_setting`` SSOT (a frozen ``@register`` migration
    body or an explicit ``_SETTINGS_WRITE_ALLOW`` entry excepted)."""
    offenders: list[str] = []
    for f in iter_src_files():
        rel = relpath(f)
        try:
            tree = parse_module(f)
            if tree is None: continue
        except SyntaxError:  # pragma: no cover
            continue
        offenders.extend(_settings_write_violations_in_tree(tree, rel))
    assert not offenders, (
        "Raw settings-table write bypassing the set_setting/set_bool_setting "
        f"SSOT (run18 #5):\n  " + "\n  ".join(sorted(offenders))
        + "\nRoute the write through set_setting() / set_bool_setting() (it owns "
        "the single-writer commit + cache invalidation). A frozen @register "
        "migration body is exempt; a genuinely-transactional exception goes in "
        "_SETTINGS_WRITE_ALLOW with a one-line reason."
    )


def test_settings_write_allow_list_is_not_stale():
    """Every ``_SETTINGS_WRITE_ALLOW`` entry still matches a real off-SSOT raw
    settings-write — a stale exception must be pruned so the allow-list can't rot
    into a silent hole."""
    seen: set[str] = set()
    for f in iter_src_files():
        rel = relpath(f)
        try:
            tree = parse_module(f)
            if tree is None: continue
        except SyntaxError:  # pragma: no cover
            continue
        for fname in _settings_write_sites(tree):
            seen.add(f"{rel}::{fname}")
    stale = set(_SETTINGS_WRITE_ALLOW) - seen
    assert not stale, (
        "Stale _SETTINGS_WRITE_ALLOW entries (no longer match a raw settings "
        "write) — remove them:\n  " + "\n  ".join(sorted(stale))
    )


def test_settings_write_coverage_pin_has_teeth():
    # (a) a raw INSERT in a NON-@register, NON-SSOT helper → flagged:
    bad = parse_source(
        "def helper(conn, k):\n"
        "    conn.execute('INSERT INTO settings (key) VALUES (?)', (k,))\n"
    )
    assert _settings_write_violations_in_tree(bad, "x/y.py") == ["x/y.py::helper"]
    # (b) a frozen @register migration body → NOT flagged (immutable; legitimate):
    mig = parse_source(
        "@register(7, 'm')\n"
        "def _v7(conn):\n"
        "    conn.execute('UPDATE settings SET value_json = ? WHERE key = ?', (v, k))\n"
    )
    assert _settings_write_violations_in_tree(mig, "web/migrations.py") == []
    # (c) the SSOT itself → NOT flagged:
    ssot = parse_source(
        "def set_setting(conn, key, value):\n"
        "    conn.execute('INSERT INTO settings (key, value_json) VALUES (?, ?)', (key, v))\n"
    )
    assert _settings_write_violations_in_tree(ssot, "web/db.py") == []
    # (d) a settings READ (SELECT … FROM settings) is NOT a write → NOT flagged:
    rd = parse_source(
        "def reader(conn, k):\n"
        "    conn.execute('SELECT value_json FROM settings WHERE key = ?', (k,))\n"
    )
    assert _settings_write_violations_in_tree(rd, "x/y.py") == []
