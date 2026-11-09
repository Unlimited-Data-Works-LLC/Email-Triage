"""Punch 563 — no ``src`` call to sentence-transformers' deprecated dimension API.

sentence-transformers 6.1.0 (the floor since punch 557) renamed
``SentenceTransformer.get_sentence_embedding_dimension`` to
``get_embedding_dimension``; the old name is a ``@deprecated(FutureWarning)``
alias (6.1.0 ``sentence_transformer/model.py:1263-1268``) that warns on every
model load and goes away when upstream removes it.

Invariant (count-agnostic, every ``src/email_triage`` module): no attribute
access spelled ``get_sentence_embedding_dimension``. Plus a behavioural arm:
the backend reads the dimension through the 6.x name.

SCOPE CAVEAT: a name reached through ``getattr`` with a computed string is
not seen.
"""

from __future__ import annotations

import ast
import sys
import types

from tests._pin_harness import (
    assert_pin_has_teeth,
    iter_src_files,
    parse_module,
    relpath,
)

_DEPRECATED = "get_sentence_embedding_dimension"


def _violations(tree) -> list[int]:
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr == _DEPRECATED
    ]


def test_no_deprecated_dimension_call_in_src():
    bad = {
        relpath(p): lines
        for p in iter_src_files()
        if (tree := parse_module(p)) is not None and (lines := _violations(tree))
    }
    assert not bad, (
        f"{_DEPRECATED} is deprecated in sentence-transformers 6.x; call "
        f"get_embedding_dimension(): {bad}"
    )


def test_pin_has_teeth():
    assert_pin_has_teeth(
        _violations,
        "dim = model.get_sentence_embedding_dimension()\n",
        good_source="dim = model.get_embedding_dimension()\n",
    )


def test_backend_reads_the_6x_dimension_name(monkeypatch):
    """A model exposing ONLY the 6.x name reports its dimension. Before the
    fix the backend called the old name, the AttributeError was swallowed by
    the try-wrapper, and the dimension silently read None."""
    from email_triage.engine.embedding_backend import SentenceTransformersBackend

    class _Model:
        def __init__(self, *a, **k):
            pass

        def get_embedding_dimension(self):
            return 384

    stub = types.ModuleType("sentence_transformers")
    stub.SentenceTransformer = _Model
    monkeypatch.setitem(sys.modules, "sentence_transformers", stub)

    backend = SentenceTransformersBackend(model="punch563-stub")
    monkeypatch.setattr(backend, "_resolve_staged_model_path", lambda: None)
    backend._load_model()
    assert backend.metrics()["dimension"] == 384
