"""Punch 418: the master key is read through ONE normalising funnel.

``EnvSecrets.get`` returned ``ET_MASTER_KEY`` verbatim while ``ContainerSecrets`` stripped it,
so a trailing newline (``podman secret create < file``, ``echo``, an editor) produced a
different HKDF-derived SQLCipher key, audit HMAC key and DR-bundle passphrase depending on
which reader a caller used. ``secrets.read_master_key`` / ``secrets.normalize_master_key``
are now the only way to read it.

What this holds:
  1. BEHAVIOUR: trailing CR/LF is stripped and nothing else (leading characters and trailing
     spaces survive); a secret that is only a newline is a missing key; the env and the
     container backend agree on one value.
  2. STRUCTURE (count-agnostic, every ``src/email_triage`` file via the shared harness): any
     ``.get``/``.require``/``read_secret``/``read_secret_required`` call whose argument names
     ``master_key_name`` sits under ``normalize_master_key(...)``. Scope caveat: the scan sees the
     name ``master_key_name`` only, not an alias variable (``cli.py`` ``secrets init-master-key``
     reads it into ``key_name`` for an existence check and never derives a key from it).
  3. TEETH: the detector flags a planted raw read and passes both funnel shapes.
"""

from __future__ import annotations

import ast
from types import SimpleNamespace

import pytest
from _pin_harness import assert_pin_has_teeth, enclosing_fn, walk_src

import email_triage.secrets as _sec  # new names are read at call time, so the pin FAILS (not errors) on the old tree
from email_triage.secrets import ContainerSecrets, SecretNotFound, read_bootstrap_master_key

_READER_ATTRS = frozenset({"get", "require"})
_READER_NAMES = frozenset({"read_secret", "read_secret_required"})


def _cfg(backend: str = "env") -> SimpleNamespace:
    return SimpleNamespace(secrets=SimpleNamespace(
        backend=backend, keyfile_path="", external={}, master_key_name="ET_MASTER_KEY",
    ))


def test_normalize_strips_trailing_cr_lf_only():
    assert _sec.normalize_master_key("abc\n") == "abc"
    assert _sec.normalize_master_key("abc\r\n") == "abc"
    assert _sec.normalize_master_key("abc\n\n\r\n") == "abc"
    assert _sec.normalize_master_key(" abc ") == " abc "  # spaces are the key's own
    assert _sec.normalize_master_key("\nabc") == "\nabc"  # leading characters are the key's own
    assert _sec.normalize_master_key("abc") == "abc"


def test_env_backend_master_key_read_is_normalised(monkeypatch):
    monkeypatch.setenv("ET_MASTER_KEY", "generated-key-for-test\n")
    assert read_bootstrap_master_key(_cfg("env")) == "generated-key-for-test"


def test_env_backend_keeps_the_keys_own_spaces(monkeypatch):
    monkeypatch.setenv("ET_MASTER_KEY", " generated key \n")
    assert read_bootstrap_master_key(_cfg("env")) == " generated key "


def test_a_secret_that_is_only_a_newline_is_a_missing_key(monkeypatch):
    monkeypatch.setenv("ET_MASTER_KEY", "\n")
    with pytest.raises(SecretNotFound):
        read_bootstrap_master_key(_cfg("env"))


def test_env_and_container_backends_agree_on_one_value(monkeypatch, tmp_path):
    (tmp_path / "ET_MASTER_KEY").write_text("generated-key-for-test\n", encoding="utf-8")
    monkeypatch.setenv("ET_MASTER_KEY", "generated-key-for-test\n")
    from email_triage.secrets import EnvSecrets

    from_container = _sec.read_master_key(ContainerSecrets(tmp_path), "ET_MASTER_KEY")
    from_env = _sec.read_master_key(EnvSecrets(), "ET_MASTER_KEY")
    assert from_container == from_env == "generated-key-for-test"


# ── structure ────────────────────────────────────────────────────────────────


def _mentions_master_key_name(call: ast.Call) -> bool:
    for sub in [*call.args, *(k.value for k in call.keywords)]:
        for node in ast.walk(sub):
            if isinstance(node, ast.Name) and node.id == "master_key_name":
                return True
            if isinstance(node, ast.Attribute) and node.attr == "master_key_name":
                return True
    return False


def _is_reader(call: ast.Call) -> bool:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr in _READER_ATTRS or f.attr in _READER_NAMES
    return isinstance(f, ast.Name) and f.id in _READER_NAMES


def _under_normalize(node: ast.AST) -> bool:
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, ast.Call):
            f = cur.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name == "normalize_master_key":
                return True
        cur = getattr(cur, "_ph_parent", None)
    return False


def _raw_master_key_reads(tree: ast.AST) -> list[ast.Call]:
    return [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _is_reader(n) and _mentions_master_key_name(n)
        and not _under_normalize(n)
    ]


def test_every_master_key_read_goes_through_the_normalising_funnel():
    violations = [
        (rel, enclosing_fn(n), n.lineno)
        for _path, rel, tree in walk_src()
        for n in _raw_master_key_reads(tree)
    ]
    assert not violations, (
        "a master-key read that skips secrets.read_master_key / normalize_master_key "
        f"derives different keys from a stripped reader (punch 418): {violations}"
    )


def test_the_raw_master_key_read_detector_has_teeth():
    bad = "def f(cfg, p):\n    return p.get(cfg.secrets.master_key_name)\n"
    good = (
        "def f(cfg, p):\n"
        "    a = normalize_master_key(p.get(cfg.secrets.master_key_name) or '')\n"
        "    return read_master_key(p, cfg.secrets.master_key_name)\n"
    )
    assert_pin_has_teeth(_raw_master_key_reads, bad, good)
    bad_required = "def g(p, master_key_name):\n    return read_secret_required(p, master_key_name)\n"
    assert_pin_has_teeth(_raw_master_key_reads, bad_required)
