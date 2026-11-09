"""N-431 (2026-07-19) count-agnostic structural pin — every direct call to
Ollama's ``/api/(chat|embeddings)`` HTTP endpoint from ``src/email_triage/``
MUST send a ``keep_alive`` payload field, routed through the shared SSOT
``email_triage._ollama_reuse.merge_reuse_options`` OR carrying an explicit
``keep_alive`` key in the payload dict literal.

Story: audit 2026-07-19 (recorded in
``STATE_2026-07-19_0730_edt_ollama_reuse_probe_planned_next_build.md``) found
3 of 5 direct ``.post(*/api/(chat|embeddings)...)`` sites missing the
``keep_alive`` payload field. Absent that field the Ollama daemon applies its
built-in default ``"5m"`` per call, silently overriding any operator TTL pin
(including a Forever ``keep_alive: -1``). Recurrence class of
``feedback_always_set_ollama_keep_alive_explicitly`` — the SSOT is the
wire field, NOT the operator's forever-pin cron.

WHAT IT PINS (count-agnostic, structural, interprocedural per PD#1 / PD#2):

1. Every ``client.post(f"{...}/api/(chat|embeddings)"...)`` call in
   ``src/email_triage/**`` (excluding ``_ollama_reuse.py`` itself — that IS
   the SSOT) MUST satisfy at least ONE of:

   a. Live in the same function-body as a preceding call to
      ``merge_reuse_options`` (the ``email_triage._ollama_reuse`` SSOT
      shim) — the async-mutator branch.
   b. Pass a ``json=`` argument whose dict literal carries an explicit
      ``keep_alive`` key — the direct-in-payload branch (safety valve for
      an already-compliant site that the SSOT would only preserve
      anyway).
   c. Pass a ``json=`` NAME whose local-binding dict literal in the same
      function-body carries an explicit ``keep_alive`` key — for
      payloads assembled into a variable BEFORE the ``.post``.

   A new /api/chat method or /api/embeddings site added later that
   picks neither shape fires this pin at import time.

2. The 3 target modules previously missing ``keep_alive`` — ``classify/
   ollama.py``, ``cli.py``, ``engine/embedding_backend.py`` — MUST import
   ``email_triage._ollama_reuse``. Deleting the import silently drops the
   SSOT wiring at every site that reads its ``merge_reuse_options``.

3. Every ``OllamaClassifier(...)`` construction in ``src/email_triage/**``
   that reads ``config.classifier.*`` (i.e. a real factory, NOT a bare
   admin-picker probe) MUST pass ``ollama_keep_alive=config.classifier.
   ollama_keep_alive``. Forgetting this kwarg silently drops the
   operator's config knob to the classifier's default (``"10m"``). Same
   pattern as N-378's ``ollama_think`` factory pin.

4. Behavioural teeth — the SSOT probe converts a Forever-pin
   ``expires_at`` (year > ``FOREVER_PIN_YEAR_THRESHOLD``) → ``-1``;
   normal TTL rows do NOT contribute a keep_alive override; a caller-set
   ``keep_alive`` in the payload is NEVER overwritten.

Reuses the shared pin harness (``_pin_harness``) per meta-pin adoption
rule (``feedback_meta_pins_gate_new_pin_pushes`` +
``test_pin_harness_adoption.py``).
"""
from __future__ import annotations

import ast
import asyncio
from typing import Any

from _pin_harness import (
    SRC_ROOT,
    iter_files,
    parse_module,
    relpath,
)

# The SSOT module itself is exempt (it IS the funnel). Same idiom as
# N-378's think-knob pin exempting the helper module.
_SSOT_RELPATH = relpath(SRC_ROOT / "_ollama_reuse.py")

# The 3 target modules that were previously missing keep_alive — they
# MUST now import the SSOT. A future audit-report class ("did the wiring
# get quietly reverted?") reads this list.
_MUST_IMPORT_SSOT = (
    "classify/ollama.py",
    "cli.py",
    "engine/embedding_backend.py",
)


def _is_api_endpoint_post(call: ast.Call, endpoint: str) -> bool:
    """True if ``call`` is a ``<x>.post(f"{...}/api/<endpoint>"...)`` shape.

    The literal ``/api/<endpoint>`` substring lives in ONE of:
      * the fully-literal ``ast.Constant`` first-arg (``"http://x/api/chat"``),
      * an ``ast.JoinedStr`` first-arg whose literal parts contain it
        (``f"{base_url}/api/chat"`` — the pattern every site actually uses).
    """
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "post":
        return False
    if not call.args:
        return False
    first = call.args[0]
    needle = f"/api/{endpoint}"
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return needle in first.value
    if isinstance(first, ast.JoinedStr):
        for v in first.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                if needle in v.value:
                    return True
    return False


def _find_enclosing_function(tree: ast.AST, target: ast.Call):
    """The nearest ``FunctionDef``/``AsyncFunctionDef`` whose source span
    contains ``target``. ``None`` at module scope (never expected here —
    every .post lives inside a function body)."""
    line = target.lineno
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            hi = getattr(node, "end_lineno", node.lineno) or node.lineno
            if node.lineno <= line <= hi:
                if best is None or node.lineno > best.lineno:
                    best = node
    return best


def _fn_body_calls_merge_reuse_options_before(
    fn: ast.AST, target_line: int,
) -> bool:
    """True if any call to ``merge_reuse_options`` appears in ``fn`` at a
    line ``<= target_line``. Ordering-safe: the wire dictates that the
    SSOT call SET the ``keep_alive`` key on the payload BEFORE the .post
    reads it. Bare-name (``merge_reuse_options(...)``) OR attribute
    (``_ollama_reuse.merge_reuse_options(...)``) both count.
    """
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and node.lineno <= target_line:
            f = node.func
            if isinstance(f, ast.Name) and f.id == "merge_reuse_options":
                return True
            if isinstance(f, ast.Attribute) and f.attr == "merge_reuse_options":
                return True
    return False


def _dict_has_key(node: ast.Dict, key_name: str) -> bool:
    for k in node.keys:
        if k is None:  # ** unpack
            continue
        if isinstance(k, ast.Constant) and k.value == key_name:
            return True
    return False


def _post_call_carries_keep_alive_key(
    fn: ast.AST, call: ast.Call,
) -> bool:
    """True if the .post's ``json=`` kwarg's dict literal carries an
    explicit ``"keep_alive"`` key. Two shapes accepted:

      * ``.post(url, json={"keep_alive": ..., ...})`` — inline dict.
      * ``.post(url, json=payload)`` — a Name that was bound to a dict
        literal earlier in the same function body via
        ``payload = {"keep_alive": ..., ...}``.
    """
    json_kw = None
    for kw in call.keywords:
        if kw.arg == "json":
            json_kw = kw
            break
    if json_kw is None:
        return False

    val = json_kw.value
    if isinstance(val, ast.Dict):
        return _dict_has_key(val, "keep_alive")

    if isinstance(val, ast.Name):
        # Walk fn body for the most-recent Assign to this name.
        name = val.id
        matching_assigns: list[ast.Dict] = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and node.lineno < call.lineno:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == name:
                        if isinstance(node.value, ast.Dict):
                            matching_assigns.append(node.value)
        if not matching_assigns:
            return False
        # ANY assignment prior to the .post that literally sets
        # keep_alive is compliant — the taken branch at runtime is
        # what pays for the wire field, and we don't have per-branch
        # data-flow. Being generous here matches the pin's intent
        # (safety valve, not enforcement teeth — the SSOT branch is
        # the primary path).
        return any(
            _dict_has_key(d, "keep_alive") for d in matching_assigns
        )
    return False


def _iter_post_sites():
    """Yield ``(relpath, path, tree, fn, call, endpoint)`` for every /api/chat
    OR /api/embeddings .post site in ``src/email_triage/**`` (SSOT module
    excluded).
    """
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel == _SSOT_RELPATH:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for endpoint in ("chat", "embeddings"):
                if _is_api_endpoint_post(node, endpoint):
                    fn = _find_enclosing_function(tree, node)
                    if fn is None:
                        continue
                    yield rel, path, tree, fn, node, endpoint


def test_every_ollama_api_post_routes_through_keep_alive_ssot():
    """Every /api/chat + /api/embeddings .post in src/email_triage/ MUST
    precede the .post with a ``merge_reuse_options(...)`` call in the
    same function body — DA panel NTH-1 (2026-07-19) tightening. The
    earlier draft accepted an explicit-``keep_alive``-key safety valve
    branch too; that widened the canonical form to two shapes, which is
    itself a drift surface. All 5 wire sites landed at commit go through
    the SSOT (Stage A + topic-match + safety + _complete_once + embed
    backend + CLI embed shim), so the safety valve carries no live site
    and the pin now enforces ONE canonical form."""
    missing: list[str] = []
    seen = 0
    for rel, _path, _tree, fn, call, endpoint in _iter_post_sites():
        seen += 1
        via_ssot = _fn_body_calls_merge_reuse_options_before(fn, call.lineno)
        if not via_ssot:
            missing.append(
                f"{rel}:{call.lineno} (/api/{endpoint}) missing keep_alive: "
                "no `merge_reuse_options(...)` call precedes it in the "
                "same function body.",
            )
    # The audit found 6 real sites (4 chat + 1 embed in classify/ollama.py
    # + 1 embed in engine/embedding_backend.py + 1 embed in cli.py). A
    # count-collapse below 5 signals the enumeration net drifted.
    assert seen >= 5, (
        "N-431 pin blind: expected >=5 Ollama /api/(chat|embeddings) "
        f".post sites in src/email_triage/, found only {seen}. Detection "
        "may have drifted — verify the .post detector against the target "
        "modules.",
    )
    assert not missing, (
        "N-431: /api/(chat|embeddings) .post site(s) missing `keep_alive` "
        "payload field: " + "; ".join(missing) + ". Every site MUST "
        "precede the .post with a `merge_reuse_options(payload, "
        "base_url, model, client, ...)` call in the same function body "
        "— the SSOT is the wire field. Absent the field, Ollama's "
        "daemon default `5m` silently overrides the operator's TTL pin."
    )


def test_target_modules_import_ollama_reuse_ssot():
    """The 3 modules the audit found missing keep_alive MUST import the SSOT
    (``email_triage._ollama_reuse`` or its ``merge_reuse_options`` shim).
    A silent revert of the wiring would drop the field again."""
    missing: list[str] = []
    for rel in _MUST_IMPORT_SSOT:
        tree = parse_module(SRC_ROOT / rel)
        assert tree is not None, (
            f"N-431 pin blind: {rel} failed to parse — syntax error. "
            "Fix the source first."
        )
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                src = node.module or ""
                if src.endswith("_ollama_reuse"):
                    found = True
                    break
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.endswith("_ollama_reuse"):
                        found = True
                        break
                if found:
                    break
        if not found:
            missing.append(rel)
    assert not missing, (
        "N-431: modules previously missing keep_alive DO NOT import the "
        f"SSOT `email_triage._ollama_reuse`: {missing}. A silent revert "
        "of the wiring would drop the field again — the import is the "
        "structural evidence the SSOT is reachable."
    )


def _kwarg_names(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg is not None}


def _kwarg_target_is_config_classifier(kw: ast.keyword, attr: str) -> bool:
    v = kw.value
    if not isinstance(v, ast.Attribute) or v.attr != attr:
        return False
    parent = v.value
    return (
        isinstance(parent, ast.Attribute) and parent.attr == "classifier"
    )


def _construction_reads_config_classifier(call: ast.Call) -> bool:
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


def test_every_factory_threads_ollama_keep_alive_kwarg():
    """Every ``OllamaClassifier(...)`` construction that reads
    ``config.classifier`` threads the ``ollama_keep_alive`` kwarg —
    factories that forget it silently drop the operator's config knob
    to the classifier's default. Same pattern as N-378's think-knob
    factory pin (:mod:`test_n378_ollama_think_knob_ssot`)."""
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
            if not (
                isinstance(func, ast.Name) and func.id == "OllamaClassifier"
            ):
                continue
            if not _construction_reads_config_classifier(node):
                continue
            seen_factories += 1
            names = _kwarg_names(node)
            if "ollama_keep_alive" not in names:
                missing.append(
                    f"{relpath(path)}:{node.lineno} missing kwarg "
                    f"`ollama_keep_alive=`",
                )
                continue
            kw = next(k for k in node.keywords if k.arg == "ollama_keep_alive")
            if not _kwarg_target_is_config_classifier(kw, "ollama_keep_alive"):
                missing.append(
                    f"{relpath(path)}:{node.lineno} kwarg "
                    "`ollama_keep_alive=` does not target "
                    "`config.classifier.ollama_keep_alive` — factories "
                    "must read from the ClassifierConfig SSOT."
                )
    assert seen_factories >= 3, (
        "N-431 pin blind: expected >=3 OllamaClassifier factory "
        "constructions from config.classifier (cli.py + "
        "web/routers/ui/_shared.py + web/routers/ui/triage_classify.py). "
        f"Found only {seen_factories}. Detection may have drifted."
    )
    assert not missing, (
        "N-431: OllamaClassifier factory sites missing "
        "`ollama_keep_alive` kwarg — these factories will silently drop "
        "the operator's `classifier.ollama_keep_alive` config to the "
        f"classifier's default (`'10m'`): {missing}."
    )


# ---------------------------------------------------------------------------
# Behavioural teeth — the SSOT probe's semantics.
# ---------------------------------------------------------------------------


def test_probe_forever_pin_sentinel_translation():
    """A Forever-pin ``expires_at`` (year > ``FOREVER_PIN_YEAR_THRESHOLD``)
    is converted to ``keep_alive: -1``. Normal TTL rows do not contribute."""
    from email_triage._ollama_reuse import (
        _expires_at_is_forever_pin,
        FOREVER_PIN_YEAR_THRESHOLD,
    )

    # Ollama's Forever-pin marker (year 9999).
    assert _expires_at_is_forever_pin("9999-12-31T23:59:59Z")
    # A distant-but-normal year is not Forever.
    assert not _expires_at_is_forever_pin("2027-01-01T00:00:00Z")
    # Boundary check — strictly greater-than.
    assert _expires_at_is_forever_pin(
        f"{FOREVER_PIN_YEAR_THRESHOLD + 1}-01-01T00:00:00Z",
    )
    assert not _expires_at_is_forever_pin(
        f"{FOREVER_PIN_YEAR_THRESHOLD}-12-31T23:59:59Z",
    )
    # Bad shapes fail-open to False (safe default — the merger falls
    # back to the caller's default_keep_alive).
    assert not _expires_at_is_forever_pin("")
    assert not _expires_at_is_forever_pin("not-a-date")


def test_merge_reuse_options_preserves_caller_keep_alive():
    """A caller that already set ``keep_alive`` in the payload is NEVER
    overwritten — even if the probe reports a Forever pin from the daemon.
    This is the ``feedback_always_set_ollama_keep_alive_explicitly``
    invariant: the WIRE FIELD is the SSOT; the caller wins."""
    from email_triage import _ollama_reuse

    _ollama_reuse._reset_for_tests()

    class _FakeResp:
        status_code = 200

        def json(self) -> Any:
            return {
                "models": [
                    {
                        "name": "qwen3.6:35b",
                        "expires_at": "9999-12-31T23:59:59Z",
                        "details": {"context_length": 8192},
                    },
                ],
            }

    class _FakeClient:
        async def get(self, url: str, **kwargs: Any) -> _FakeResp:
            return _FakeResp()

    payload = {
        "model": "qwen3.6:35b",
        "messages": [],
        "keep_alive": "5m",  # caller's explicit choice
    }
    asyncio.run(
        _ollama_reuse.merge_reuse_options(
            payload, "http://llm-host.example.invalid:11434", "qwen3.6:35b",
            _FakeClient(), default_keep_alive="10m",
        ),
    )
    assert payload["keep_alive"] == "5m", (
        "SSOT overwrote the caller's explicit keep_alive — "
        "byte-identical-options / caller-wins invariant broken."
    )


def test_merge_reuse_options_omits_finite_default_when_not_pinned():
    """A bare payload gets NO ``keep_alive`` when the model is not
    Forever-pinned.

    Operator policy 2026-08-18, verbatim: *"if the keep_alive is forever
    -> send back -1 to keep it. If it is not, don't send a keep_alive
    back at all and let ollama just reset the timeout on it's own."*

    The superseded shape injected the finite default (``"10m"``)
    unconditionally. Because a per-request ``keep_alive`` OVERRIDES the
    daemon's ``OLLAMA_KEEP_ALIVE``, that demoted the Forever pin on a
    host launched with ``-1`` — measured 2026-09-10.
    """
    from email_triage import _ollama_reuse

    _ollama_reuse._reset_for_tests()

    class _FakeResp:
        status_code = 200

        def json(self) -> Any:
            return {"models": []}  # nothing loaded → not pinned

    class _FakeClient:
        async def get(self, url: str, **kwargs: Any) -> _FakeResp:
            return _FakeResp()

    payload = {"model": "nomic-embed-text", "prompt": "hi"}
    asyncio.run(
        _ollama_reuse.merge_reuse_options(
            payload, "http://llm-host.example.invalid:11434", "nomic-embed-text",
            _FakeClient(), default_keep_alive="1h",
        ),
    )
    assert "keep_alive" not in payload, (
        "SSOT wrote a finite keep_alive for an unpinned model — that is "
        f"the clobber policy forbids (got {payload.get('keep_alive')!r})."
    )


def test_merge_reuse_options_sends_minus_one_when_forever_pinned():
    """A bare payload gets ``-1`` when ``/api/ps`` shows a Forever pin.

    This is the half the dead ``_expires_at_is_forever_pin`` guard was
    written for and never wired to: before 2026-09-10 the helper had ZERO
    production callers and was exercised only by unit tests, so the write
    path could not tell a pinned model from an unpinned one.
    """
    from email_triage import _ollama_reuse

    _ollama_reuse._reset_for_tests()

    class _FakeResp:
        status_code = 200

        def json(self) -> Any:
            # Year 2318 is the real sentinel this deployment emits for
            # ``keep_alive: -1`` — NOT 9999. Any check must be a
            # year-threshold, never equality on 9999.
            return {"models": [
                {"name": "qwen3.6:35b",
                 "expires_at": "2318-12-21T20:04:39.671688554Z"},
            ]}

    class _FakeClient:
        async def get(self, url: str, **kwargs: Any) -> _FakeResp:
            return _FakeResp()

    payload = {"model": "qwen3.6:35b", "messages": []}
    asyncio.run(
        _ollama_reuse.merge_reuse_options(
            payload, "http://llm-host.example.invalid:11434", "qwen3.6:35b",
            _FakeClient(), default_keep_alive="10m",
        ),
    )
    assert payload["keep_alive"] == -1, (
        "SSOT failed to reinforce an existing Forever pin — a classify "
        "call will let a 24GB model evict."
    )


def test_merge_reuse_options_omits_when_probe_cannot_tell():
    """Unknown pin state fails toward OMISSION, never a finite write.

    Omission can only decline to EXTEND a pin; a finite write DESTROYS
    one. So a dead ``/api/ps`` must not fall back to ``default_keep_alive``.
    """
    from email_triage import _ollama_reuse

    _ollama_reuse._reset_for_tests()

    class _DeadClient:
        async def get(self, url: str, **kwargs: Any) -> Any:
            raise RuntimeError("connection refused")

    payload = {"model": "qwen3.6:35b", "messages": []}
    asyncio.run(
        _ollama_reuse.merge_reuse_options(
            payload, "http://llm-host.example.invalid:11434", "qwen3.6:35b",
            _DeadClient(), default_keep_alive="10m",
        ),
    )
    assert "keep_alive" not in payload, (
        "SSOT fell back to a finite default when the probe failed — that "
        "clobbers a pin it could not see."
    )


def test_merge_reuse_options_explicit_forever_default_skips_probe():
    """``ollama_keep_alive: -1`` in YAML is honoured without a probe.

    An operator who configured the Forever sentinel is reinforcing a pin
    deliberately; that intent outranks any observed state, and spending
    an ``/api/ps`` hop to confirm it would be pure cost.
    """
    from email_triage import _ollama_reuse

    _ollama_reuse._reset_for_tests()

    class _StrictClient:
        async def get(self, url: str, **kwargs: Any) -> Any:
            raise AssertionError(
                f"probed .get({url}) despite an explicit Forever default",
            )

    for configured in (-1, "-1"):
        payload = {"model": "qwen3.6:35b", "messages": []}
        asyncio.run(
            _ollama_reuse.merge_reuse_options(
                payload, "http://llm-host.example.invalid:11434", "qwen3.6:35b",
                _StrictClient(), default_keep_alive=configured,
            ),
        )
        # NORMALISED to the int, never echoed verbatim. The config seam
        # types ``ollama_keep_alive`` as ``str`` and str()s it, so YAML
        # ``-1`` arrives as ``"-1"`` — which Ollama REJECTS at duration
        # parse (measured 2026-09-10: 400 ``time: missing unit in duration
        # "-1"``). Echoing the configured value put that on the wire and
        # made the ONE documented way to express Forever intent fail every
        # call, falling open to zero topic verdicts on a PHI path.
        assert payload["keep_alive"] == -1, (
            f"configured={configured!r} produced "
            f"{payload['keep_alive']!r}; the wire needs the int -1."
        )
        assert not isinstance(payload["keep_alive"], str), (
            "a string Forever value 400s at Ollama's duration parser."
        )


def test_is_valid_keep_alive_accepts_ollama_shapes_rejects_typos():
    """DA MF-3 (2026-07-19 panel) validator: accept Ollama's native
    ``keep_alive`` shapes; reject the typo class that would reach the
    daemon and 400 → silent 5m fallback (the very recurrence class
    N-431 closes)."""
    from email_triage._ollama_reuse import is_valid_keep_alive

    # Accepted shapes.
    for good in ("10m", "1h", "-1", "0", "30s", "180"):
        assert is_valid_keep_alive(good), (
            f"is_valid_keep_alive rejected legitimate shape {good!r}"
        )
    for good_int in (-1, 0, 10, 3600):
        assert is_valid_keep_alive(good_int), (
            f"is_valid_keep_alive rejected legitimate int {good_int!r}"
        )

    # Rejected shapes — the exact class DA MF-3 wanted caught.
    for bad in (
        "1o",       # letter O for minute (the DA MF-3 canonical typo)
        "+10m",     # leading + not Ollama-accepted
        " 10m",     # leading whitespace
        "10m ",     # trailing whitespace
        "10x",      # unknown unit
        "1.5m",     # fractional not supported by Ollama's parse
        "-2",       # negative other than -1 not accepted
        "abc",      # gibberish
        "",         # empty (caller falls back to default anyway, but reject explicitly)
        True,       # bool subclass of int; semantically wrong
        None,       # not a str/int
        [10],       # list
    ):
        assert not is_valid_keep_alive(bad), (
            f"is_valid_keep_alive accepted bad shape {bad!r} — the "
            "recurrence class this drive is closing would silently "
            "5m-default at the daemon."
        )


def test_merge_reuse_options_caller_set_value_skips_probe():
    """A caller-supplied ``keep_alive`` short-circuits before any probe.

    SUPERSEDES the former ``..._no_probe_on_hot_path`` pin (DA MF-2,
    2026-07-19), which asserted the merge path NEVER touches ``/api/ps``.
    That no-probe shape is exactly what made the clobber invisible: with
    no read of ``expires_at`` the write path could not distinguish a
    Forever-pinned model from an unpinned one, so it wrote ``"10m"`` over
    both. The probe is now REQUIRED on the caller-unset path — the
    30s-per-base_url cache keeps a batched sweep at one probe, not N.

    What survives from MF-2 is the narrower guarantee worth keeping: when
    the caller already decided, we spend nothing and change nothing.
    """
    from email_triage import _ollama_reuse

    _ollama_reuse._reset_for_tests()

    class _StrictClient:
        """Fails loud if the SSOT probes when it has no need to."""

        async def get(self, url: str, **kwargs: Any) -> Any:
            raise AssertionError(
                f"SSOT called .get({url}) despite a caller-set keep_alive.",
            )

    for caller_value in (-1, "30m", 0):
        payload = {"model": "qwen3.6:35b", "keep_alive": caller_value}
        asyncio.run(
            _ollama_reuse.merge_reuse_options(
                payload, "http://llm-host.example.invalid:11434", "qwen3.6:35b",
                _StrictClient(), default_keep_alive="10m",
            ),
        )
        assert payload["keep_alive"] == caller_value, (
            "SSOT overwrote a caller-set keep_alive."
        )


def test_no_wire_site_presets_keep_alive_in_a_payload_literal():
    """No module outside the SSOT may put ``keep_alive`` in a dict literal.

    This pins the CALLER, not the helper — the gap that made the
    2026-09-10 clobber survive its own fix.

    ``merge_reuse_options`` preserves a caller-set ``keep_alive`` (a
    deliberate ``-1`` must never be downgraded by a stale probe). Two wire
    sites in ``classify/ollama.py`` — the Topic-match and safety-detect
    payloads — pre-set ``"keep_alive": self._keep_alive`` from the config
    default. That made an ordinary payload look deliberately caller-set, so
    the SSOT handed the finite ``"10m"`` straight to the wire and demoted
    the daemon's Forever pin on every Topic-match call. Fixing
    ``merge_reuse_options`` alone did NOT fix those two sites, and a
    helper-level test stayed green throughout —
    ``pattern_teeth_test_on_a_helper_does_not_pin_the_caller``.

    Structural (``ast.walk`` over every module), not a count.

    COVERAGE, measured against planted mutants rather than asserted — the
    first version of this pin caught only the dict-literal shape, i.e. the
    one shape the bug happened to have, while ``payload["keep_alive"] = v``
    (what an author writes when the value is conditional) sailed past it.
    Now flagged: the string constant ``"keep_alive"`` ANYWHERE (dict
    literal, subscript assign, ``setdefault``, and the
    ``_KA = "keep_alive"`` indirection) AND the keyword form
    (``update(keep_alive=v)``, ``dict(keep_alive=v)``), which carries no
    string constant at all.

    NOT covered, and stated rather than papered over: a fully dynamic key
    (``payload[some_var] = v`` where the value is computed at runtime) is
    invisible to any static scan.
    """
    import ast

    offenders: list[str] = []
    scanned = 0
    for path in sorted(iter_files(SRC_ROOT)):
        # The SSOT itself is the ONE place allowed to set the field.
        if relpath(path) == _SSOT_RELPATH:
            continue
        scanned += 1
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            rel = relpath(path)
            # Shape 1 — the string "keep_alive" ANYWHERE as a constant.
            # Covers {"keep_alive": v}, payload["keep_alive"] = v,
            # payload.setdefault("keep_alive", v), and the indirection
            # _KA = "keep_alive"; {_KA: v}.
            if isinstance(node, ast.Constant) and node.value == "keep_alive":
                offenders.append(f"{rel}:{node.lineno}")
            # Shape 2 — keyword form, which carries no string constant:
            # payload.update(keep_alive=v) and dict(keep_alive=v).
            #
            # Scoped to DICT-BUILDING calls only. A bare "any keyword named
            # keep_alive" rule fires on ordinary Python kwargs — measured:
            # OllamaEmbeddingBackend(keep_alive=...) and
            # _build_single_backend(keep_alive=...) in engine/
            # embedding_backend.py are constructor arguments, not wire
            # payloads, and flagging them would have made this pin a nuisance
            # its next reader would weaken.
            elif isinstance(node, ast.Call):
                fn = node.func
                builds_a_dict = (
                    (isinstance(fn, ast.Name) and fn.id == "dict")
                    or (isinstance(fn, ast.Attribute)
                        and fn.attr in ("update", "setdefault"))
                )
                if builds_a_dict:
                    for kw in node.keywords:
                        if kw.arg == "keep_alive":
                            offenders.append(f"{rel}:{node.lineno}")

    assert scanned > 0, "pin scanned no files — it would pass vacuously."
    assert not offenders, (
        "keep_alive is pre-set in a payload literal outside the SSOT: "
        + ", ".join(offenders)
        + ". merge_reuse_options preserves caller-set values, so this "
        "smuggles a finite TTL past the Forever-pin check. Delete the key "
        "and let merge_reuse_options decide."
    )


def test_topic_match_and_safety_paths_send_minus_one_when_pinned():
    """Behavioural teeth on THE TWO CALL SITES THAT ACTUALLY CLOBBERED.

    ``_chat_topics`` (Topic-match) and ``_chat_safety`` are the payloads that
    pre-set ``"keep_alive": self._keep_alive`` and therefore smuggled a finite
    ``"10m"`` past ``merge_reuse_options`` — which preserves caller-set values
    by design. Fixing the SSOT did NOT fix them.

    A verification that exercised ``classify()`` instead showed the pin being
    reinforced and was reported as proof; live traffic refuted it 8 minutes
    later. So this test asserts on the wire payload of the FAILING sites
    specifically — ``violation_2026-09-10_called_it_proven_on_a_synthetic_path``
    ``_that_skipped_the_defect``.
    """
    import json

    from email_triage import _ollama_reuse
    from email_triage.classify.ollama import OllamaClassifier

    for method_name in ("_chat_topics", "_chat_safety"):
        _ollama_reuse._reset_for_tests()

        posted: dict[str, Any] = {}

        class _PsResp:
            status_code = 200

            def json(self) -> Any:
                # Forever pin, real sentinel shape for this deployment.
                return {"models": [
                    {"name": "qwen3.6:35b",
                     "expires_at": "2318-12-21T21:26:29.206511716Z"},
                ]}

        class _ChatResp:
            status_code = 200

            def raise_for_status(self) -> None:
                return None

            def json(self) -> Any:
                return {
                    "model": "qwen3.6:35b",
                    "message": {"role": "assistant", "content": json.dumps(
                        {"topic_verdicts": []},
                    )},
                }

        class _Client:
            async def get(self, url: str, **kw: Any) -> Any:
                return _PsResp()

            async def post(self, url: str, **kw: Any) -> Any:
                posted.update(kw.get("json") or {})
                return _ChatResp()

        cls = OllamaClassifier(
            model="qwen3.6:35b",
            base_url="http://llm-host.example.invalid:11434",
            ollama_keep_alive="10m",   # the finite default that clobbered
        )
        # The wire sites obtain their client via ``await self._http.get()``
        # — stub THAT, not a ``_client`` attribute that nothing reads.
        class _Holder:
            async def get(self) -> Any:
                return _Client()

        cls._http = _Holder()  # type: ignore[attr-defined]

        async def _drive() -> None:
            method = getattr(cls, method_name)
            try:
                await method("prompt text", "qwen3.6:35b")
            except Exception:
                # Response-shape handling is not what this test pins; the
                # payload was captured before any parse could fail.
                pass

        asyncio.run(_drive())

        assert posted, f"{method_name} never POSTed — test proves nothing."
        assert posted.get("keep_alive") == -1, (
            f"{method_name} sent keep_alive={posted.get('keep_alive')!r} while "
            "/api/ps showed a Forever pin. A finite value here DEMOTES the "
            "operator's pin on every call — the 2026-09-10 clobber."
        )
