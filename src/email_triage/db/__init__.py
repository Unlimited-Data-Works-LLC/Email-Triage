"""Per-domain SQLite helpers extracted from the legacy ``web.db`` god-module.

The historical home of every DB helper was ``email_triage.web.db`` (8819 LOC
before the  decomp). That single file mixed schema for the entire app
with helpers for every domain — auth, audit, accounts, style learning,
ai-backends, retries, watches. The size made cherry-picks painful, made
import-cycle hazards hard to reason about, and held every cluster's
back-compat shim hostage to a single file's churn.

This subpackage is the new home as the decomp lands cluster-by-cluster.
First module: ``db.audit`` (#277a — extracted 2026-05-23, sequenced ahead of
the H-02a HMAC migration to avoid cherry-pick pain in Cycle 7+).

Future modules per the backlog :
- ``db.accounts``
- ``db.style``
- ``db.retries``

Each extracted module gets a re-export shim in ``web/db.py`` so existing
callers (``from email_triage.web.db import <name>``) keep working
without change.
"""

from __future__ import annotations
