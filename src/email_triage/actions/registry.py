"""Action registry and router.

The registry maps action names to Action instances.  The router resolves
a classification category to an ordered list of actions using the route
configuration.
"""

from __future__ import annotations

import logging
from typing import Any

from email_triage.actions.base import Action
from email_triage.config import RouteConfig

logger = logging.getLogger("email_triage.actions.registry")


class ActionRegistry:
    """Registry of available actions, keyed by name."""

    def __init__(self) -> None:
        self._actions: dict[str, Action] = {}

    def register(self, action: Action) -> None:
        """Register an action instance."""
        self._actions[action.name] = action

    def get(self, name: str) -> Action | None:
        """Look up an action by name."""
        return self._actions.get(name)

    def get_or_raise(self, name: str) -> Action:
        """Look up an action by name, raising if not found."""
        action = self._actions.get(name)
        if action is None:
            raise KeyError(f"Unknown action: '{name}'")
        return action

    @property
    def names(self) -> list[str]:
        return list(self._actions.keys())


class Router:
    """Resolve a category to an ordered action list using route config."""

    def __init__(
        self,
        routes: dict[str, RouteConfig],
        registry: ActionRegistry,
    ):
        self._routes = routes
        self._registry = registry

    def resolve(self, category: str) -> list[Action]:
        """Return the actions for ``category``, falling back to _default."""
        route = self._routes.get(category) or self._routes.get("_default")
        if route is None:
            logger.warning("No route for category '%s' and no _default", category)
            return []

        actions = []
        for action_name in route.actions:
            action = self._registry.get(action_name)
            if action is None:
                logger.warning(
                    "Route for '%s' references unknown action '%s'",
                    category, action_name,
                )
                continue
            actions.append(action)
        return actions
