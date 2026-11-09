"""N-475 residual: a free-text PHI value must never be baked into a message
string that reaches an un-expungeable sink.

BACKGROUND
==========
Three sinks persist operator-facing text into HMAC-chained, write-once tables.
None of them can scrub a PHI value that is ALREADY inside the string:

* ``log_entries.error`` — ``SQLiteLogHandler.emit`` stores
  ``redact_exc(record.exc_info[1])`` under the ``error`` key, and ``error`` /
  ``error_type`` are members of ``_PERSIST_SAFE_KEYS``, so the fail-closed
  allow-list in ``redact_persisted_extra`` passes their VALUES through.
  ``redact_exc`` substitutes exactly two shapes — an address and a filesystem
  path — and its own docstring records the residual: a free-form fragment
  embedded in arbitrary error prose "is not generically detectable".
* ``log_entries.message`` — ``record.getMessage()`` is persisted with NO
  redaction of any kind. The allow-list governs ``extra`` only, and the N-338
  gate covers positional ``args``; neither can see an f-string that was already
  interpolated before the call.
* ``audit_gap_events.exc_msg`` — written by a DIRECT INSERT through
  ``redact_exc`` alone, so no allow-list runs on that path at all.

WHY THIS PIN GUARDS THE SOURCE, NOT THE SINK
============================================
Guarding the three sinks would need three controls that each re-derive what
"PHI" means, and a fourth sink would arrive unguarded. The value can only enter
a persisted string at ONE kind of place — the interpolation — so that is the
seam to pin. One property, sink-agnostic: once the value is not in the string,
every downstream table is safe whatever its redaction posture.

Anchors: §164.502(b) minimum-necessary (how much PHI a log field may carry) is
primary; §164.312(b) Audit Controls is the mechanism context. The aggravating
factor is §164.526 — a PHI value inside an HMAC-chained write-once row has no
amendment path and no §164.310(d)(2)(i) disposal path, because expunging it
breaks the chain. The pin itself is a §164.308(a)(1)(ii)(B) risk-management
measure.

THE NAME SET, AND THE SSOT IT DELIBERATELY DOES *NOT* REUSE
===========================================================
``TriageLogger._PHI_KEYS`` is the SSOT for PHI **log-kwarg keys** — the
``reason=`` in ``log.info(..., reason=x)`` is the CLASSIFICATION reason. It is
NOT a set of variable names, and reusing it as one was measured to produce 11
false positives and zero true ones: a Gemini ``blockReason``, two IMAP server
responses, an enum-validated retry-dead reason, and seven FastAPI request
models named ``body`` (``body.role``, ``body.user_email``). ``triage_logging``'s
own comment warns about exactly this collision class for ``response``/
``content``. Two name-spaces, one name set, false positives by construction.

So this set is its own, and it is deliberately NARROW — values extracted FROM
message content, which have no shape a regex could scrub afterwards. Widening
it is cheap; widening it to ``_PHI_KEYS`` is not, and has been tried.

COUNT-AGNOSTIC + INTERPROCEDURAL (PD#1 / PD#2 / PD#6)
=====================================================
The walk is a PROPERTY over every ``*.py`` under ``src/email_triage`` via the
shared harness — never ``len(X) == N``, and never a hand-rolled source walk
that could drift in its own scoping. The check is at the INTERPOLATION, so it
holds no matter which helper the string is handed to afterwards; it does not
depend on recognising the sink.

MEASURED BEFORE SHIPPING: 0 violations at HEAD across 241 files, with a
positive control of 3/3 and a negative control of 0/2 on the same detector.
``ALLOW_LIST`` is therefore empty by measurement, not by assumption.

WIDENED (punch 595 retro, hipaa-sme): the detector was f-string-only, so
``"..." % subject``, ``"...".format(subject)`` and ``"..." + subject`` passed.
It now consumes the shared funnel ``_pin_harness.message_interpolation_offenders``
(f-string, ``%``, ``+``, ``.format``), the SAME detector the punch-595
secret-name pin uses with ``SECRET_TOKEN_KEYS`` (one funnel, two name sets,
PD-5). Census at HEAD before widening: one non-f-string interpolated log message
in src (``web/routers/ui/users.py:297``, the punch-595 OTP site; no PHI name,
so this pin stays at 0 by measurement).

KNOWN RESIDUAL, stated rather than implied: this pin sees the INTERPOLATION
SITE. A value rebound first (``ref = case_ref; raise X(f"{ref}")``) or passed
through a dict escapes it. That is a floor, not a proof — per the project's own
filed pattern, a name-keyed net over source is never complete. It closes the
direct and by far most likely shapes.
"""

from __future__ import annotations

import ast

import pytest

from _pin_harness import (
    annotate_parents,
    assert_pin_has_teeth,
    message_interpolation_offenders,
    walk_src,
)

# Free-text PHI carriers: values extracted FROM message content (N-97 / N-475).
# A regex cannot scrub these after the fact — `extracted_phrase` is free-form
# prose and has no shape to key on, which is why the control has to be here.
PHI_NAMES: frozenset[str] = frozenset({
    "case_ref",
    "explicit_case_ref",
    "extracted_phrase",
    "raw_deadline_phrase",
    "normalized_subject",
    "subject",
    "body_text",
    "body_html",
})

# Sites permitted to interpolate a PHI name into a message string, with the
# reason. EMPTY at N-475 close — measured, not assumed: zero violations at HEAD.
# An entry here is a claim that the value is NOT the PHI one the name suggests;
# it REQUIRES an inline justification naming what the value actually is.
ALLOW_LIST: dict[str, str] = {}


def _offenders(tree: ast.AST) -> list[tuple[int, str, str]]:
    """(lineno, kind, names) for every PHI interpolation reaching a sink: the
    shared funnel keyed on PHI_NAMES (f-string, ``%``, ``+``, ``.format``)."""
    return message_interpolation_offenders(tree, PHI_NAMES)


def test_no_phi_interpolated_into_a_persisted_message_string() -> None:
    """Every string built for a raise or a log message is PHI-free."""
    violations: list[str] = []

    for _path, rel, tree in walk_src():
        annotate_parents(tree)
        for lineno, kind, names in _offenders(tree):
            if f"{rel}:{lineno}" in ALLOW_LIST:
                continue
            violations.append(
                f"  {rel}:{lineno}  {kind}  interpolates {names}"
            )

    if violations:
        listed = "\n".join(violations)
        raise AssertionError(
            "A free-text PHI value is baked into a message string that reaches "
            "an un-expungeable sink (log_entries.error / log_entries.message / "
            "audit_gap_events.exc_msg). Once it is IN the string no redaction "
            "layer can remove it, and the row cannot be amended or disposed of "
            "without breaking the HMAC chain.\n"
            f"{listed}\n"
            "Fix: pass the value as a KWARG so the redaction layers can see it "
            "("
            "log.error('clock: lookup failed', case_ref=ref)"
            "), or omit it. Do NOT add an ALLOW_LIST entry unless the value is "
            "genuinely not the PHI one its name suggests, and say what it is."
        )


def test_pin_has_teeth() -> None:
    """The detector flags a planted violation and spares the benign shapes that
    round 1 of this pin got wrong.

    The good source is not decoration: those two lines are REAL shapes from
    src/ that an earlier, wider version of this detector flagged — a FastAPI
    request model named ``body`` and an IMAP protocol ``reason``. A negative
    control without a positive one proves nothing, so both run here.
    """
    assert_pin_has_teeth(
        _offenders,
        bad_source=(
            "def f(case_ref, m):\n"
            "    raise ValueError(f'duplicate case {case_ref}')\n"
            "    log.error(f'subject was {m.subject}')\n"
        ),
        good_source=(
            "def g(body, reason):\n"
            "    raise ValueError(f'Invalid role: {body.role}')\n"
            "    raise RuntimeError(f'server said {reason}')\n"
            "    log.error('clock: lookup failed', case_ref=body.case_ref)\n"
        ),
    )


def test_log_level_first_argument_is_not_mistaken_for_the_message() -> None:
    """``.log(level, msg)`` puts the message SECOND.

    A detector that always read ``args[0]`` would silently skip every
    ``.log()`` site — the one route the N-332 pin recommends for preserving
    severity, so precisely where a careful author is sent.
    """
    tree = ast.parse(
        "log.log(logging.WARNING, f'phrase {extracted_phrase}')\n"
    )
    assert _offenders(tree), ".log(level, msg) message argument not inspected"


@pytest.mark.parametrize("shape", [
    "log.warning('subject was %s' % subject)",
    "log.warning('subject was %s / %s' % (a, msg.subject))",
    "log.error('subject was {}'.format(subject))",
    "log.error('subject was {s}'.format(s=m.normalized_subject))",
    "log.info('case ' + case_ref)",
    "log.info('a ' + x + ' phrase ' + extracted_phrase)",
    "raise ValueError('bad case %s' % case_ref)",
    "raise ValueError('bad case {}'.format(case_ref))",
    "log.log(logging.WARNING, 'phrase ' + extracted_phrase)",
])
def test_widened_shapes_have_teeth(shape: str) -> None:
    """Punch 595 retro: each non-f-string interpolation form is caught."""
    assert_pin_has_teeth(_offenders, bad_source=shape)


@pytest.mark.parametrize("benign", [
    "log.info('%d rows' % count)",
    "x = 10 % subject_count",
    "log.info('static ' + 'text')",
    "log.error('failed', subject=subject)",
    "log.info('role {}'.format(body.role))",
])
def test_widened_shapes_spare_benign_code(benign: str) -> None:
    assert not _offenders(ast.parse(benign))
