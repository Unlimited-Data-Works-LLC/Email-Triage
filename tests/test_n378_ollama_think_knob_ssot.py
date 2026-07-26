"""N-378 (2026-07-08) structural pin — Ollama ``think`` payload option is
a CONFIG KNOB, threaded uniformly through every /api/chat payload.

Story: N-372 (2026-07-05) removed ``think: False`` because Ollama bug
#15260 broke grammar-mask application when combined with
``format=<json-schema>``. That bug was CLOSED in Ollama 0.31.1
(2026-06-30). Production 2026-07-07/08 with thinking uncontrolled showed
recurring ``finish_reason=length, raw_len=0`` empty responses on the
topic-match path — silent quality-loss on the digest verdicts.

The fix re-introduces the option AS A CONFIG KNOB
(``classifier.ollama_think`` — None / False / True). The operator's
environment-specific decision must never be baked hardcoded again —
a separate deployment on older Ollama needs ``None`` until they upgrade.

WHAT IT PINS (count-agnostic structural):

1. Every ``payload = {...}`` dict literal in
   ``src/email_triage/classify/ollama.py`` that describes an Ollama
   /api/chat POST body (identified by top-level keys ``model`` +
   ``messages``) MUST include the SSOT unpack
   ``**self._payload_think_extras()``. A future ``_chat_foo`` method
   that hardcodes ``"think": False`` (or omits it entirely) fires this
   pin at import time.

2. The helper methods ``_payload_think_extras`` and
   ``_maybe_append_no_think`` exist on ``OllamaClassifier``. Renaming
   or deleting one without a coordinated migration fires the pin.

3. Every ``OllamaClassifier(...)`` construction in
   ``src/email_triage/**`` that reads ``config.classifier.*`` (i.e. the
   real factories — cli.py, web/routers/ui/_shared.py,
   web/routers/ui/triage_classify.py — not the bare model-listing
   probe) MUST pass BOTH ``ollama_think=config.classifier.ollama_think``
   AND ``ollama_no_think_marker=config.classifier.ollama_no_think_marker``
   kwargs. A future factory that forgets one silently drops the
   operator's config knob to the classifier's default (None / False) —
   catches that class of drift.

Applies count-agnostic + interprocedural per PD#1/#2 — new /api/chat
methods added later inherit the property; new factories can't skip the
kwargs. Reuses the shared pin harness (``_pin_harness``) per meta-pin
adoption rule.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


OLLAMA_MODULE = SRC_ROOT / "classify" / "ollama.py"


def _is_api_chat_payload_dict(node: ast.Dict) -> bool:
    """True if this dict literal describes an Ollama /api/chat payload.

    We identify it structurally: top-level string keys ``"model"`` AND
    ``"messages"`` — the two invariants of an Ollama /api/chat POST body.
    Both keys are ``Constant(str)`` in every current payload, so we don't
    have to chase compile-time f-string keys.
    """
    literal_keys = {
        k.value for k in node.keys
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }
    return "model" in literal_keys and "messages" in literal_keys


def _dict_has_think_extras_unpack(node: ast.Dict) -> bool:
    """True if the dict literal contains ``**self._payload_think_extras()``.

    In an ``ast.Dict``, a ``**mapping`` unpack is represented as
    ``keys[i] is None`` with the value being the mapping expression.
    """
    for key, value in zip(node.keys, node.values):
        if key is not None:
            continue
        # Look for the exact SSOT call shape:
        # ``self._payload_think_extras()`` — Call(Attribute(Name("self"),
        # "_payload_think_extras"), args=[], keywords=[]).
        if not isinstance(value, ast.Call):
            continue
        func = value.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr != "_payload_think_extras":
            continue
        if not (isinstance(func.value, ast.Name) and func.value.id == "self"):
            continue
        if value.args or value.keywords:
            continue
        return True
    return False


def test_every_api_chat_payload_spreads_think_extras():
    """Every /api/chat payload dict in classify/ollama.py includes
    ``**self._payload_think_extras()``."""
    tree = parse_module(OLLAMA_MODULE)
    assert tree is not None, (
        "N-378 pin blind: classify/ollama.py failed to parse — "
        "syntax error or decode error. Fix the source first."
    )
    missing: list[str] = []
    total = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        if not _is_api_chat_payload_dict(node):
            continue
        total += 1
        if not _dict_has_think_extras_unpack(node):
            missing.append(f"line {node.lineno}")
    assert total >= 4, (
        "N-378 pin blind: expected ≥4 /api/chat payload dicts in "
        f"classify/ollama.py (_chat + _chat_topics + _chat_safety + "
        f"_complete_once), found only {total}. Detection may have "
        "drifted — verify the identifier-key set."
    )
    assert not missing, (
        "N-378: /api/chat payload dict(s) missing "
        "`**self._payload_think_extras()` SSOT unpack: "
        f"{missing}. Every /api/chat payload MUST route the `think` "
        "payload option through the ClassifierConfig knob — never "
        "hardcode. Add `**self._payload_think_extras()` at the end of "
        "the payload dict."
    )


def test_ollama_classifier_has_think_helpers():
    """The two SSOT helper methods exist on OllamaClassifier.

    Deleting or renaming without a coordinated migration collapses every
    /api/chat payload to a hardcoded-off ``think`` (or a NameError at
    call time). Pin the presence of the exact method names the payload
    dicts reference.
    """
    tree = parse_module(OLLAMA_MODULE)
    assert tree is not None, (
        "N-378 pin blind: classify/ollama.py failed to parse."
    )
    class_node = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.ClassDef) and n.name == "OllamaClassifier"),
        None,
    )
    assert class_node is not None, (
        "N-378: OllamaClassifier class not found in "
        "src/email_triage/classify/ollama.py. Pin scope drifted."
    )
    method_names = {
        m.name for m in class_node.body
        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for required in ("_payload_think_extras", "_maybe_append_no_think"):
        assert required in method_names, (
            f"N-378: OllamaClassifier missing helper method "
            f"`{required}`. This is the SSOT the /api/chat payloads "
            "reference; removing it silently drops the operator's "
            "`ollama_think` / `ollama_no_think_marker` config knob."
        )


def _kwarg_names(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg is not None}


def _kwarg_target_is_config_classifier(kw: ast.keyword, attr: str) -> bool:
    """True if kw.value is ``config.classifier.<attr>`` (any Attribute chain
    ending in ``.classifier.<attr>``). Tolerates local aliases like
    ``self.config.classifier.X``."""
    v = kw.value
    if not isinstance(v, ast.Attribute) or v.attr != attr:
        return False
    parent = v.value
    return (
        isinstance(parent, ast.Attribute) and parent.attr == "classifier"
    )


def _construction_reads_config_classifier(call: ast.Call) -> bool:
    """True if the OllamaClassifier(...) call passes at least one kwarg
    whose value is ``config.classifier.<something>``. Distinguishes a real
    factory from a bare probe (ai_backends_crud.py) that hand-builds args."""
    for kw in call.keywords:
        if kw.arg is None:
            continue
        v = kw.value
        if (
            isinstance(v, ast.Attribute)
            and isinstance(v.value, ast.Attribute)
            and v.value.attr == "classifier"
        ):
            return True
    return False


def test_every_factory_threads_think_kwargs():
    """Every OllamaClassifier(...) construction that reads config.classifier
    threads BOTH `ollama_think` and `ollama_no_think_marker` from
    ClassifierConfig — no factory silently drops the knob."""
    missing: list[str] = []
    seen_factories = 0
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Bare-name only — the codebase always imports the class,
            # never uses `email_triage.classify.ollama.OllamaClassifier(...)`
            # attribute form for these factories.
            if not (isinstance(func, ast.Name) and func.id == "OllamaClassifier"):
                continue
            if not _construction_reads_config_classifier(node):
                continue  # bare probe / test double / not a real factory
            seen_factories += 1
            names = _kwarg_names(node)
            for required in ("ollama_think", "ollama_no_think_marker"):
                if required not in names:
                    missing.append(
                        f"{relpath(path)}:{node.lineno} missing kwarg "
                        f"`{required}=`",
                    )
                    continue
                kw = next(k for k in node.keywords if k.arg == required)
                # Best-effort: assert kwarg VALUE is `config.classifier.<same>`.
                # Tolerates alias chains (`self.config.classifier.X`) — the
                # attribute chain ending in `.classifier.<same>` is the shape.
                if not _kwarg_target_is_config_classifier(kw, required):
                    missing.append(
                        f"{relpath(path)}:{node.lineno} kwarg "
                        f"`{required}=` does not target "
                        f"`config.classifier.{required}` — factories must "
                        "read from the ClassifierConfig SSOT, not a "
                        "hardcoded value.",
                    )
    assert seen_factories >= 3, (
        "N-378 pin blind: expected ≥3 OllamaClassifier factory "
        "constructions from config.classifier (cli.py + "
        "web/routers/ui/_shared.py + web/routers/ui/triage_classify.py). "
        f"Found only {seen_factories}. Detection may have drifted."
    )
    assert not missing, (
        "N-378: OllamaClassifier factory sites missing think-knob kwargs — "
        "these factories will silently drop the operator's "
        "`classifier.ollama_think` / `classifier.ollama_no_think_marker` "
        f"config to the class default (None / False): {missing}. "
        "Add `ollama_think=config.classifier.ollama_think, "
        "ollama_no_think_marker=config.classifier.ollama_no_think_marker`."
    )
