"""HTMX HTML endpoints for the web UI — split into per-concern files.

Single back-compat surface: `from email_triage.web.routers.ui import router`
returns one `APIRouter` that mounts every concern. Helpers + module
state live in `_shared`; per-concern handlers in the matching file.

The package-level `__getattr__` preserves PEP 562 fallbacks for legacy
names (`_install_google_oauth`, `_install_ingestion_config`) and proxies
any other attribute lookup to `_shared` (then to concern submodules) so
the dozens of `from email_triage.web.routers.ui import X` sites that
predate the split keep working unchanged.

Patchable-helper indirection (the trickiest part of the split):
  Tests do
      mock.patch("email_triage.web.routers.ui._test_account_connection", fake)
  and expect handlers to honour the override. Handlers live in concern
  files (e.g. accounts.py) and call patchable helpers as bare names
  resolved from their per-module globals snapshot of `_shared`. To make
  the package-level setattr propagate to every snapshot, this module
  replaces itself in `sys.modules` with a thin subclass of `ModuleType`
  whose `__setattr__` mirrors writes onto `_shared` AND every concern
  submodule that has the name in its globals. (PEP 562 / ModuleType
  subclass — the standard trick.)
"""
from __future__ import annotations

import sys
import types as _types

from fastapi import APIRouter

from . import _shared  # noqa: F401
# Re-export everything in `_shared` (helpers, prelude constants, the
# patchable factory shims). Tests reach for these via
#   from email_triage.web.routers.ui import X
# and monkeypatch them via the package alias. `from X import *` would
# skip underscore-prefixed names (most helpers!), so use globals()
# update which doesn't.
globals().update({
    _n: _v for _n, _v in vars(_shared).items() if not _n.startswith("__")
})

# Concern submodules — assemble into one router for back-compat.
from .accounts import router as _accounts_router
from .wizard import router as _wizard_router
from .routes import router as _routes_router
from .digests import router as _digests_router
from .categories import router as _categories_router
from .calendars import router as _calendars_router
from .oauth import router as _oauth_router
from .push import router as _push_router
from .profile import router as _profile_router
from .users import router as _users_router
from .admin import router as _admin_router
from .ai_backends_crud import router as _ai_backends_crud_router
from .embedding_install import router as _embedding_install_router
from .triage_classify import router as _triage_classify_router
from .openclaw import router as _openclaw_router
from .labels import router as _labels_router
from .retry_queue import router as _retry_queue_router

router = APIRouter()
# 2026-05-18: ``_embedding_install_router`` MUST register before
# ``_ai_backends_crud_router``. Both share the ``/config/ai-backends/*``
# prefix; ai_backends_crud has a ``/config/ai-backends/{backend_id}``
# parameterized route that FastAPI tries to match against literal
# paths like ``/config/ai-backends/embedding-install`` first, fails
# the int validation on the string ``embedding-install``, and returns
# 422 INSTEAD of falling through to the more-specific route. Putting
# the specific routes first means they get matched before the
# parameterized variant is even tried. Defense-in-depth: the
# ai_backends_crud parameterized routes also use the ``{backend_id:int}``
# Starlette converter so a future re-order doesn't reintroduce this.
for _r in (
    _accounts_router,
    _wizard_router,
    _routes_router,
    _digests_router,
    _categories_router,
    _calendars_router,
    _oauth_router,
    _push_router,
    _profile_router,
    _users_router,
    _admin_router,
    _embedding_install_router,
    _ai_backends_crud_router,
    _triage_classify_router,
    _openclaw_router,
    _labels_router,
    _retry_queue_router,
):
    router.include_router(_r)


# ---------------------------------------------------------------------------
# Patchable-helper mirror — see the module docstring above.
# ---------------------------------------------------------------------------
_CONCERN_MODULES = (
    ".accounts",
    ".wizard",
    ".routes",
    ".digests",
    ".categories",
    ".calendars",
    ".oauth",
    ".push",
    ".profile",
    ".users",
    ".admin",
    ".ai_backends_crud",
    ".embedding_install",
    ".triage_classify",
    ".openclaw",
    ".labels",
    ".retry_queue",
)


class _UiPackage(_types.ModuleType):
    """ModuleType subclass with a `__setattr__` that mirrors writes
    onto `_shared` AND every concern submodule that snapshotted the
    name into its own globals.

    Why the broad mirror: dozens of tests patch
    `email_triage.web.routers.ui.X` (via `unittest.mock.patch` or
    `monkeypatch.setattr`) for helpers that originally lived module-
    level in `web/routers/ui.py`. After the #144 split, those helpers
    moved to `_shared.py`; each concern file does
    `globals().update(vars(_shared))` at import to keep handler
    bare-name references working. The original-module patch path used
    to update one dict; we now have to update N dicts (one per concern
    file that snapshotted the name) so handlers still see the patched
    value at call time.
    """

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if hasattr(_shared, name):
            try:
                setattr(_shared, name, value)
            except Exception:
                pass
            import sys as _sys
            for _modname in _CONCERN_MODULES:
                full = self.__name__ + _modname
                _m = _sys.modules.get(full)
                if _m is not None and name in vars(_m):
                    try:
                        setattr(_m, name, value)
                    except Exception:
                        pass

    def __getattr__(self, name):
        # PEP 562 fallback. Order:
        #   1. legacy install-singleton names (factory.py, #138.1)
        #   2. anything in `_shared`
        #   3. concern submodules
        if name == "_install_google_oauth":
            from email_triage.providers import factory as _f
            return _f._install_google_oauth
        if name == "_install_office365_oauth":
            from email_triage.providers import factory as _f
            return _f._install_office365_oauth
        if name == "_install_ingestion_config":
            from email_triage.providers import factory as _f
            return _f._install_ingestion_config
        if hasattr(_shared, name):
            return getattr(_shared, name)
        from importlib import import_module
        for _modname in _CONCERN_MODULES:
            _m = import_module(_modname, package=self.__name__)
            if hasattr(_m, name):
                return getattr(_m, name)
        raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")


# Install the subclass in sys.modules so `__setattr__` interception fires
# on `setattr(ui_mod, ...)`. The current module's __dict__ is preserved by
# changing its __class__ — that's safe for top-level package modules and
# doesn't disturb already-bound names.
sys.modules[__name__].__class__ = _UiPackage
