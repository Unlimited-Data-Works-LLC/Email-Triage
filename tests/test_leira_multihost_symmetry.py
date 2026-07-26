"""Symmetry pin — Python twin.

Consumes the SHARED vectors at ``tests/leira_multihost_vectors.json`` (also
consumed by ``tests/leira_multihost_symmetry.Tests.ps1`` — the PS twin). If
either twin's behavior diverges from the JSON expectation, the vector fails in
that twin only, pinpointing the drift. Both twins iterate the vectors
COUNT-AGNOSTICALLY (``ast.walk`` / ``ForEach`` — no ``len(X) == N``) so adding
a new vector to the JSON auto-extends the pin without touching either twin.

Prime Directive #1 (project_style_guide): every SSOT ships its count-agnostic
structural pin in the same change. The JSON is the SSOT; this file + the PS
twin are the pin.

Landed 2026-07-17 in Drive-A of the llm-host multi-host completion arc; closes
the DA follow-on NTH from Drive-16 (state_2026-07-17_0900_edt).
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
VECTORS_PATH = Path(__file__).parent / "leira_multihost_vectors.json"


def _load_vectors() -> list[dict]:
    """Load the SSOT vector list. Missing / malformed = pin fail (loud)."""
    payload = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    vectors = payload.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise RuntimeError(
            f"leira_multihost_vectors.json has no 'vectors' list at {VECTORS_PATH}"
        )
    return vectors


_VECTORS = _load_vectors()


def _reimport_with_vector_env(tmp_path, monkeypatch, env: dict) -> object:
    """Fresh import of leira_prepass with the vector's env applied; clears
    all four multi-host env knobs first so a leaked value from the caller
    doesn't corrupt the resolution."""
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("PYTHONPATH", str(SCRIPTS_DIR))
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    for name in ("OLLAMA_HOST", "OLLAMA_URL", "LEIRA_URL", "LEIRA_OLLAMA_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    if "leira_prepass" in sys.modules:
        del sys.modules["leira_prepass"]
    return importlib.import_module("leira_prepass")


@pytest.mark.parametrize(
    "vector",
    _VECTORS,
    ids=[v["id"] for v in _VECTORS],
)
def test_multihost_vector(vector, tmp_path, monkeypatch):
    """Drive one shared vector through the Python twin.

    Success shape: import succeeds, ``active_host_name()`` matches
    ``expect_active_host_name``, and (optionally) module ``LEIRA_URL`` matches
    ``expect_active_host_url``.

    Raise shape: import raises the class named by ``expect_raises`` and the
    message contains every substring in ``expect_message_contains``.
    """
    env = vector.get("env", {}) or {}
    expect_raises = vector.get("expect_raises")

    if expect_raises:
        with pytest.raises(Exception) as exc_info:
            _reimport_with_vector_env(tmp_path, monkeypatch, env)
        got = exc_info.value.__class__.__name__
        assert got == expect_raises, (
            f"vector {vector['id']}: expected {expect_raises}, got {got} — "
            f"msg={exc_info.value!s}"
        )
        msg = str(exc_info.value)
        for needle in vector.get("expect_message_contains", []) or []:
            assert needle in msg, (
                f"vector {vector['id']}: message missing {needle!r} — got: {msg}"
            )
        return

    mod = _reimport_with_vector_env(tmp_path, monkeypatch, env)
    expected_name = vector["expect_active_host_name"]
    assert mod.active_host_name() == expected_name, (
        f"vector {vector['id']}: active_host_name() != {expected_name!r} — "
        f"got {mod.active_host_name()!r}, env={env}"
    )
    expected_url = vector.get("expect_active_host_url")
    if expected_url is not None:
        assert mod.LEIRA_URL == expected_url, (
            f"vector {vector['id']}: LEIRA_URL != {expected_url!r} — "
            f"got {mod.LEIRA_URL!r}"
        )


def test_symmetry_vectors_meta_pin():
    """Meta-pin: the vector file exists and every vector has the required keys.
    Count-agnostic — asserts a property over EVERY vector, not a hardcoded N."""
    payload = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    vectors = payload["vectors"]
    assert vectors, "vector list is empty — SSOT harness is inert"

    seen_ids: set[str] = set()
    for v in vectors:
        assert "id" in v, f"vector missing 'id': {v}"
        assert v["id"] not in seen_ids, f"duplicate vector id: {v['id']}"
        seen_ids.add(v["id"])
        assert "name" in v, f"vector {v['id']} missing 'name'"
        assert "env" in v and isinstance(v["env"], dict), (
            f"vector {v['id']} missing/invalid 'env' map"
        )
        if v.get("expect_raises"):
            assert "expect_active_host_name" not in v, (
                f"vector {v['id']} sets both expect_raises + expect_active_host_name"
            )
        else:
            assert "expect_active_host_name" in v, (
                f"vector {v['id']} needs expect_active_host_name (or expect_raises)"
            )
        for key in v["env"]:
            assert key in ("OLLAMA_HOST", "OLLAMA_URL", "LEIRA_URL"), (
                f"vector {v['id']} uses unsupported env knob {key!r}; only "
                f"OLLAMA_HOST / OLLAMA_URL / LEIRA_URL are wired today"
            )
        # db-sme NTH fold (Batch-1, 2026-07-17): the '<env-url>' sentinel is a
        # convention shared by JSON + both twins; without a pin, one twin
        # could quietly return the raw URL as the active_host_name and both
        # cases pass in isolation. Discriminator: any vector that pins
        # expect_active_host_url MUST have expect_active_host_name ==
        # '<env-url>' (drawer rule 1/2 shape).
        if "expect_active_host_url" in v:
            assert v.get("expect_active_host_name") == "<env-url>", (
                f"vector {v['id']}: expect_active_host_url implies "
                f"expect_active_host_name == '<env-url>' (drawer rule 1/2 "
                f"discriminator); got {v.get('expect_active_host_name')!r}"
            )
