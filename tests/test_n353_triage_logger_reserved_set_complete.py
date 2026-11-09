"""N-353 R31 — TriageLogger `_reserved` set mirrors stdlib LogRecord.

Trust-repair fix-forward per PHASE3 audit_hmac d8df4a24 finding + the backlog
row  (task ). The `_reserved` set at `triage_logging.py::TriageLogger._log`
previously held only `{"message", "asctime"}`. The `k in record.__dict__` clause
next to it catches init-set LogRecord attrs dynamically, so no live PHI leak
existed at HEAD. The defence-in-depth intent — an explicit named set that:
(a) documents which keys are LogRecord-reserved, (b) survives a future Python
release that adds a new init-attr the codebase hasn't yet imported — was NOT
met. This pin enforces the FULL set of 22 stdlib LogRecord attributes.

Ref: stdlib `logging.LogRecord.__init__` — enumerated attrs it sets on the
record instance, plus `message` (set by `LogRecord.getMessage`) and `asctime`
(set by the `Formatter`).
"""
from __future__ import annotations

import logging

from email_triage.triage_logging import TriageLogger


# The full stdlib LogRecord reserved-attr set. Every key here would clobber a
# LogRecord built-in if a caller's `extra={key: value}` were promoted onto
# `record.__dict__` unguarded. Sourced from CPython's Lib/logging/__init__.py
# (LogRecord.__init__ + LogRecord.getMessage + Formatter.format).
_EXPECTED_RESERVED = frozenset({
    "name", "msg", "args", "levelname", "levelno",
    "pathname", "filename", "module", "exc_info", "exc_text",
    "stack_info", "lineno", "funcName", "created", "msecs",
    "relativeCreated", "thread", "threadName", "processName",
    "process", "message", "asctime",
    # Python 3.12+ added taskName (asyncio task context).
    "taskName",
})


def _extract_reserved_from_source() -> frozenset[str]:
    """Read the literal `_reserved = {...}` set from `_log` via ast.

    Sourcing from the actual code (not a re-import of the value) proves the
    live set matches the pin's expectation — the pin cannot silently drift by
    re-importing a re-exported copy.
    """
    import ast
    import inspect
    import textwrap

    src = textwrap.dedent(inspect.getsource(TriageLogger._log))
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "_reserved"
            and isinstance(node.value, ast.Set)
        ):
            names: set[str] = set()
            for elt in node.value.elts:
                assert isinstance(elt, ast.Constant) and isinstance(elt.value, str), (
                    f"_reserved set must be all literal str constants; "
                    f"found {ast.dump(elt)}"
                )
                names.add(elt.value)
            return frozenset(names)
    raise AssertionError(
        "N-353: _reserved literal set not found in TriageLogger._log source"
    )


def test_reserved_set_mirrors_stdlib_logrecord_attrs():
    """The `_reserved` set literal in `_log` MUST list all 22 stdlib
    LogRecord attributes (init-set + message + asctime)."""
    live = _extract_reserved_from_source()
    missing = _EXPECTED_RESERVED - live
    extra = live - _EXPECTED_RESERVED
    assert not missing, (
        "N-353: TriageLogger._log `_reserved` set is missing stdlib LogRecord "
        f"attrs: {sorted(missing)}. Add each to the set literal at "
        "`triage_logging.py::TriageLogger._log`."
    )
    assert not extra, (
        "N-353: TriageLogger._log `_reserved` set contains keys NOT in the "
        f"stdlib LogRecord reserved-attr set: {sorted(extra)}. Either these "
        "are stale entries (remove) or the expected set here is out of date."
    )


def test_reserved_covers_every_logrecord_init_dict_key():
    """Behavioural teeth: build a real LogRecord via stdlib and prove every
    key it sets on `.__dict__` (minus message/asctime which are formatter-set)
    appears in the pin's expected set. Catches a future Python release adding
    a new init-attr the pin's expected set doesn't yet name."""
    rec = logging.LogRecord(
        name="teeth",
        level=logging.INFO,
        pathname="(pin)",
        lineno=0,
        msg="teeth-probe",
        args=(),
        exc_info=None,
    )
    init_attrs = set(rec.__dict__.keys())
    # message + asctime are formatter-set, so LogRecord.__init__ doesn't set
    # them — verify they're still in our expected set as documentation.
    assert "message" in _EXPECTED_RESERVED
    assert "asctime" in _EXPECTED_RESERVED
    missing = init_attrs - _EXPECTED_RESERVED
    assert not missing, (
        "N-353 teeth: stdlib LogRecord.__init__ sets an attr this pin's "
        f"expected set does NOT list: {sorted(missing)}. This means a future "
        "Python release added an attr; add it to `_EXPECTED_RESERVED` here + "
        "to `_reserved` in `triage_logging.py::TriageLogger._log`."
    )


def test_extra_reserved_key_does_not_clobber_logrecord_attr():
    """Behavioural teeth: for EVERY reserved key, calling a TriageLogger
    method with `extra={reserved_key: <different value>}` MUST NOT clobber
    the LogRecord's built-in attr value. Proves the guard works end-to-end
    (via _log promotion path)."""
    from email_triage.triage_logging import get_logger

    logger = get_logger("test_n353")

    # Attach a stashing handler that records the LogRecord we emit so we can
    # assert on each built-in attr's post-emit value. `get_logger("test_n353")`
    # returns a TriageLogger over the stdlib logger named
    # `email_triage.test_n353`, so attach the handler there.
    stashed: list[logging.LogRecord] = []

    class _Stash(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:  # noqa: D401
            stashed.append(record)

    stdlib_logger = logging.getLogger("email_triage.test_n353")
    handler = _Stash(level=logging.DEBUG)
    stdlib_logger.addHandler(handler)
    stdlib_logger.setLevel(logging.DEBUG)

    try:
        for key in _EXPECTED_RESERVED:
            stashed.clear()
            # Pass a would-be-clobbering extra. The guard MUST skip it.
            try:
                logger.info("N-353 teeth probe", extra={key: "WOULD_CLOBBER"})
            except Exception as e:
                raise AssertionError(
                    f"N-353: extra={{{key!r}: ...}} raised {type(e).__name__}: {e}"
                ) from e
            assert stashed, f"N-353: no record emitted for reserved key {key!r}"
            rec = stashed[-1]
            actual = getattr(rec, key, None)
            assert actual != "WOULD_CLOBBER", (
                f"N-353: extra={{{key!r}: 'WOULD_CLOBBER'}} clobbered LogRecord's "
                f"built-in `{key}` attr — the guard at `TriageLogger._log` failed."
            )
    finally:
        stdlib_logger.removeHandler(handler)
