"""Tests for action registry and router."""

import pytest

from email_triage.actions.base import Action
from email_triage.actions.registry import ActionRegistry, Router
from email_triage.config import RouteConfig
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
)
from email_triage.providers.base import EmailProvider


class StubAction(Action):
    def __init__(self, action_name: str):
        self._name = action_name

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, flow, message, classification, provider, config=None):
        return ActionOutput(result=ActionResult.COMPLETED)


class TestActionRegistry:
    def test_register_and_get(self):
        reg = ActionRegistry()
        action = StubAction("notify")
        reg.register(action)
        assert reg.get("notify") is action

    def test_get_missing_returns_none(self):
        reg = ActionRegistry()
        assert reg.get("nonexistent") is None

    def test_get_or_raise_missing(self):
        reg = ActionRegistry()
        with pytest.raises(KeyError, match="Unknown action"):
            reg.get_or_raise("nonexistent")

    def test_names(self):
        reg = ActionRegistry()
        reg.register(StubAction("notify"))
        reg.register(StubAction("label"))
        assert sorted(reg.names) == ["label", "notify"]


class TestRouter:
    def test_resolve_known_category(self):
        reg = ActionRegistry()
        reg.register(StubAction("notify"))
        reg.register(StubAction("label"))
        routes = {"invoices": RouteConfig(actions=["label", "notify"])}
        router = Router(routes, reg)

        actions = router.resolve("invoices")
        assert [a.name for a in actions] == ["label", "notify"]

    def test_resolve_unknown_category_falls_back_to_default(self):
        reg = ActionRegistry()
        reg.register(StubAction("notify"))
        routes = {"_default": RouteConfig(actions=["notify"])}
        router = Router(routes, reg)

        actions = router.resolve("unknown-category")
        assert [a.name for a in actions] == ["notify"]

    def test_resolve_no_default_returns_empty(self):
        reg = ActionRegistry()
        routes = {"invoices": RouteConfig(actions=["label"])}
        router = Router(routes, reg)

        actions = router.resolve("unknown-category")
        assert actions == []

    def test_resolve_skips_unknown_actions(self):
        reg = ActionRegistry()
        reg.register(StubAction("notify"))
        routes = {"invoices": RouteConfig(actions=["notify", "nonexistent"])}
        router = Router(routes, reg)

        actions = router.resolve("invoices")
        assert [a.name for a in actions] == ["notify"]
