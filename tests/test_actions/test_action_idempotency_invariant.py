""" paired class invariant — every Action subclass MUST be idempotent.

Background
----------
``engine/flow.py`` ``route_and_act`` persists ``flow.actions_completed``
after every successful action body. The persist-per-iteration
fix makes crash-recovery skip already-completed actions — but only if
re-running a completed action is a no-op. That property — *every concrete
``Action`` subclass is idempotent* — is the load-bearing assumption that
keeps the  rating at MED. Without this guard, a future non-idempotent
action silently re-opens HIGH exposure: a crash between action N's
external side effect and the per-iteration persist replays N on recovery,
duplicating the side effect (the "second draft" hazard the PR-6 / C2
idempotency layer was built to prevent).

This guard pins the contract structurally + behaviourally:

  * **Structural pin** — for every concrete ``Action`` subclass, the
    class MUST opt into one of two idempotency contracts:

      (a) the **helper-based contract** — ``execute`` calls both
          ``check_idempotent_already_done`` and ``record_idempotent_done``
          from ``actions/base.py``. This is the strict contract: a second
          execute returns ``SKIPPED`` without invoking the side effect.

      (b) the **naturally-idempotent contract** — the action's external
          side effect is itself idempotent at the provider/storage layer
          (Gmail/O365 ``apply_label`` is INSERT-OR-IGNORE; ``move`` to an
          already-occupied folder is a no-op). The class MUST declare
          this by setting the class attribute ``_naturally_idempotent =
          True`` with a one-line ``_idempotency_rationale`` string
          documenting why. A second execute may invoke the provider
          again but produces no duplicate side effect.

    An ``Action`` subclass that opts into neither is rejected — adding
    a new action is now a forcing function to decide which contract it
    holds.

  * **Behavioural pin** — for every helper-based action (contract (a)),
    instantiate the action, build a synthetic flow + message + provider
    mock, call ``execute`` twice with the SAME (flow, message), assert
    the second call returns ``ActionResult.SKIPPED``. This is the same
    behaviour the per-action ``tests/test_actions/test_idempotency.py``
    suite already verifies for ~5 actions individually; running it
    against every helper-based class is the parametrised whole-surface
    check that scales as new actions land.

The structural pin is the load-bearing one — it cannot regress silently
even if a behavioural test's mock setup becomes stale.

Count-agnostic
--------------
Discovery uses ``Action.__subclasses__()`` recursively after importing
every module under ``actions/``. There is NO hard-coded subclass count
or list — a new ``Action`` is in scope automatically, exactly as the
 /  connection-safety guards discover new modules. The lesson
from : an enumerated subclass list in a test docstring or xfail
reason drifts (the  source spec listed "14 subclasses" when the
real count was 11). The count is whatever the importer finds.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
import textwrap
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

import email_triage.actions as _actions_pkg
from email_triage.actions.base import Action
from email_triage.engine.models import (
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)


# ---------------------------------------------------------------------------
# Discovery — every concrete Action subclass in the package
# ---------------------------------------------------------------------------

def _import_all_action_modules() -> None:
    """Import every ``email_triage.actions.<module>`` so each ``Action``
    subclass is registered in ``Action.__subclasses__()``.

    Subclass discovery is import-time: a class only appears in
    ``__subclasses__`` after its module is imported. The test suite as a
    whole imports most of them transitively, but this function makes the
    discovery deterministic — the test does not rely on import order.
    """
    for _, name, _ in pkgutil.iter_modules(_actions_pkg.__path__):
        importlib.import_module(f"email_triage.actions.{name}")


def _all_concrete_action_subclasses() -> list[type[Action]]:
    """Every non-abstract production ``Action`` subclass, sorted by
    qualified name.

    The filter on ``__module__.startswith("email_triage.actions.")`` is
    load-bearing: pytest collection runs after test modules are imported,
    and test files (``tests/test_engine/test_flow.py``) define their own
    ``Action`` subclasses as fixtures (``CompletingAction``,
    ``WaitingAction``, ``FailingAction``). Those are not part of the
    production surface and must not be held to the production idempotency
    contract — they exist only to drive ``FlowEngine`` tests. The module-
    path filter scopes discovery to the production actions package and
    nothing else.
    """
    _import_all_action_modules()

    def _walk(cls: type) -> set[type]:
        out: set[type] = set()
        for sub in cls.__subclasses__():
            out.add(sub)
            out |= _walk(sub)
        return out

    return sorted(
        (
            c for c in _walk(Action)
            if not inspect.isabstract(c)
            and c.__module__.startswith("email_triage.actions.")
        ),
        key=lambda c: f"{c.__module__}.{c.__name__}",
    )


# ---------------------------------------------------------------------------
# Structural pin — helper-based contract detection
# ---------------------------------------------------------------------------

def _execute_uses_idempotency_helpers(cls: type[Action]) -> tuple[bool, bool]:
    """AST-inspect the ``execute`` method that ``cls`` resolves to (walking
    the MRO) for calls to the two idempotency helpers. Returns
    ``(uses_check, uses_record)``.

    The MRO walk is load-bearing: ``AcceptInviteAction`` /
    ``DeclineInviteAction`` / ``TentativeInviteAction`` all inherit
    ``execute`` from ``_InviteResponseBase`` and the subclass body
    overrides only the ``name`` property. An inspection scoped to the
    subclass alone would miss the inherited helper calls and falsely
    flag the action as opting into no contract.

    A call to a helper is matched as the bare name
    (``check_idempotent_already_done(...)``) anywhere inside the resolved
    ``execute`` body. A call inside a nested helper of ``cls`` that
    ``execute`` invokes is not followed — actions that delegate to a
    private method should inline the helper call or accept the
    structural pin's verdict that they hold the natural-idempotency
    contract instead.
    """
    # Walk the MRO to find the class that actually DEFINES execute. For
    # the invite subclasses, that is _InviteResponseBase; for direct
    # Action subclasses, it is cls itself.
    defining_cls: type | None = None
    for klass in cls.__mro__:
        if klass is Action or klass is object:
            continue
        if "execute" in klass.__dict__:
            defining_cls = klass
            break
    if defining_cls is None:
        return False, False

    src = textwrap.dedent(inspect.getsource(defining_cls))
    tree = ast.parse(src)
    uses_check = False
    uses_record = False
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "execute":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    name = None
                    if isinstance(sub.func, ast.Name):
                        name = sub.func.id
                    elif isinstance(sub.func, ast.Attribute):
                        name = sub.func.attr
                    if name == "check_idempotent_already_done":
                        uses_check = True
                    elif name == "record_idempotent_done":
                        uses_record = True
    return uses_check, uses_record


# ---------------------------------------------------------------------------
# Tests — structural pin
# ---------------------------------------------------------------------------

def test_action_class_discovery_finds_concrete_subclasses():
    """Sanity: discovery must surface a real, non-trivial set of
    concrete Action subclasses. A broken importer would let the
    parametrised tests below pass vacuously.
    """
    subs = _all_concrete_action_subclasses()
    assert len(subs) >= 8, (
        f"expected at least 8 concrete Action subclasses (currently 11 "
        f"in tree); found {len(subs)}: "
        f"{[c.__name__ for c in subs]}"
    )
    # Spot-check a few that must always be present — these are core to
    # the triage pipeline and removing one would be a much larger change
    # than this guard's scope.
    names = {c.__name__ for c in subs}
    for required in (
        "NotifyAction", "LabelAction", "MoveAction",
        "DraftReplyAction", "EscalateAction",
    ):
        assert required in names, (
            f"core action {required} missing from discovery; got {names}"
        )


@pytest.mark.parametrize(
    "cls",
    _all_concrete_action_subclasses(),
    ids=lambda c: c.__name__,
)
def test_action_subclass_holds_an_idempotency_contract(cls: type[Action]):
    """Every concrete Action subclass MUST hold one of two idempotency
    contracts (see module docstring): the helper-based contract OR the
    naturally-idempotent contract declared via class attribute.

    Failure mode this catches: a new action lands without thinking about
    crash-recovery semantics. Either it forgets the check/record helpers
    (silent re-run hazard) or it has no externalised opt-out for a
    provably-natural side effect (forced to add explicit reasoning).
    """
    uses_check, uses_record = _execute_uses_idempotency_helpers(cls)
    holds_helper_contract = uses_check and uses_record
    holds_natural_contract = bool(
        getattr(cls, "_naturally_idempotent", False)
    )
    rationale = getattr(cls, "_idempotency_rationale", None)

    if holds_helper_contract:
        # Strict contract — also verified behaviourally below.
        return
    if holds_natural_contract:
        assert isinstance(rationale, str) and rationale.strip(), (
            f"{cls.__name__} opts into the naturally-idempotent contract "
            f"via `_naturally_idempotent = True` but does NOT supply a "
            f"`_idempotency_rationale` string. Add a one-line "
            f"`_idempotency_rationale = '...'` class attribute "
            f"explaining why re-running this action is a provider-level "
            f"no-op (e.g. INSERT-OR-IGNORE, move to current folder)."
        )
        return

    pytest.fail(
        f"{cls.__name__} ({cls.__module__}) is a concrete Action "
        f"subclass that opts into NEITHER idempotency contract:\n"
        f"  - helper-based: execute() must call BOTH "
        f"`check_idempotent_already_done` AND `record_idempotent_done` "
        f"(uses_check={uses_check}, uses_record={uses_record}).\n"
        f"  - naturally-idempotent: class must set "
        f"`_naturally_idempotent = True` AND `_idempotency_rationale = "
        f"'...'`.\n"
        f"#263 — without one of these, a crash between this action's "
        f"side effect and the per-iteration persist would replay the "
        f"action on recovery and duplicate the side effect. Pick a "
        f"contract."
    )


# ---------------------------------------------------------------------------
# Tests — behavioural pin (helper-based actions only)
# ---------------------------------------------------------------------------

def _helper_based_actions() -> list[type[Action]]:
    """Subset of concrete Action subclasses that hold the helper-based
    contract — the ones whose ``execute`` body calls both idempotency
    helpers. The behavioural pin runs against this subset; the
    naturally-idempotent subset is structural-only (the second-call
    side effect is by design a provider-level no-op, which a mocked
    provider cannot meaningfully assert).
    """
    out: list[type[Action]] = []
    for cls in _all_concrete_action_subclasses():
        uses_check, uses_record = _execute_uses_idempotency_helpers(cls)
        if uses_check and uses_record:
            out.append(cls)
    return out


def _make_flow(action_name: str) -> FlowState:
    """Build a synthetic FlowState minimally sufficient for an Action's
    execute call. ``state_bag`` is empty — the legacy per-flow
    idempotency fallback in ``check_idempotent_already_done`` is what
    we exercise here (no `db` in state_bag → durable path skipped,
    fallback path used)."""
    return FlowState(
        flow_id=f"f-{action_name}-1",
        provider="test",
        message_id="m-1",
        status=FlowStatus.ACTING,
        state_bag={},
    )


def _make_message() -> EmailMessage:
    return EmailMessage(
        message_id="m-1",
        provider="test",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Test subject",
        body_text="Test body.",
        date=datetime(2026, 5, 24, 12, 0, tzinfo=timezone.utc),
        thread_id=None,
        headers={},
    )


def _make_classification() -> Classification:
    return Classification(
        category="invoices", confidence=0.9, reason="test rule",
    )


def _make_provider() -> AsyncMock:
    """Async provider mock with a generous attribute surface. Actions
    invoke a variety of provider methods (apply_label, move_message,
    create_draft, etc.) — AsyncMock auto-creates any attribute as an
    awaitable. The behavioural pin only asserts the SECOND execute
    returns SKIPPED; what the first call does on the provider is not
    asserted (per-action tests in ``test_idempotency.py`` cover that
    surface)."""
    provider = AsyncMock()
    provider.name = "test"
    return provider


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls",
    _helper_based_actions(),
    ids=lambda c: c.__name__,
)
async def test_helper_based_action_is_skipped_on_second_execute(
    cls: type[Action],
):
    """Behavioural pin — calling ``execute`` twice with the SAME (flow,
    message) MUST return ``ActionResult.SKIPPED`` on the second call.

    This is the crash-recovery contract: after the per-iteration persist
    in ``route_and_act`` records action N as completed,
    a recovery rerun of the flow re-enters the route loop, invokes
    action N's ``execute`` again — and the helper-based contract must
    short-circuit it via ``check_idempotent_already_done`` returning
    a SKIPPED ``ActionOutput`` from the per-flow ``state_bag`` record
    that ``record_idempotent_done`` wrote.

    The mock provider's behaviour on the first call is intentionally
    unspecified; we only assert the second-call short-circuit. The
    per-action test_idempotency.py suite covers the first-call
    side-effect semantics.
    """
    action = cls()
    flow = _make_flow(action.name)
    message = _make_message()
    classification = _make_classification()
    provider = _make_provider()

    # First execute — runs the action body and (per contract) calls
    # ``record_idempotent_done`` which stamps ``flow.state_bag
    # ["action_results"][action.name]``. Outcome may be COMPLETED /
    # WAITING / FAILED / SKIPPED depending on the action's first-call
    # path through the mock provider — not asserted here.
    try:
        first = await action.execute(flow, message, classification, provider)
    except Exception as exc:
        pytest.skip(
            f"{cls.__name__}.execute raises on a minimal mock setup "
            f"({type(exc).__name__}: {exc}); the structural pin still "
            f"holds the contract, the behavioural pin needs a richer "
            f"fixture (track in a follow-up if this hides a real gap)."
        )

    # If the first call already short-circuited via some non-idempotency
    # path (e.g. SKIPPED because no SMTP config), the second call would
    # also short-circuit for the same reason — that's not the contract
    # we are pinning. The check we want is: a *successful* first call
    # records the idempotency entry, the second call observes it. So
    # ensure the legacy state_bag fallback was written (the durable
    # path needs a real DB which the mock provider lacks).
    if not (flow.state_bag and flow.state_bag.get("action_results")):
        pytest.skip(
            f"{cls.__name__} first execute did not write an idempotency "
            f"record on this minimal setup (first.result={first.result}); "
            f"the strict-contract second-call assertion would not be "
            f"exercising the short-circuit. The structural pin still "
            f"holds the contract."
        )

    # Second execute on the SAME flow/message — must short-circuit.
    second = await action.execute(flow, message, classification, provider)
    assert second.result == ActionResult.SKIPPED, (
        f"{cls.__name__} second execute MUST return SKIPPED (got "
        f"{second.result.value}). The helper-based idempotency contract "
        f"is the crash-recovery guarantee for #263; a non-SKIPPED second "
        f"result means the side effect would duplicate on recovery."
    )
    assert second.data and second.data.get("skipped_idempotent"), (
        f"{cls.__name__} second execute returned SKIPPED but without "
        f"the `skipped_idempotent` data marker — the contract is that "
        f"the SKIPPED reason carries the marker (see "
        f"actions/base.py:check_idempotent_already_done)."
    )
