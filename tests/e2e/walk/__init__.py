"""Retrofit Playwright walks — one file per newly-landed feature.

Drive 3 of the v0.2.0 coordinated push (feat/v0.2.0). Every file in this
package is a real-browser walk that exercises the GOLDEN path AND the
server-refuses -> user-remedy shape catch (D2) for exactly one
feature-add. Companion to ``scripts/workflows/feature-add-e2e-gate.py``:
that gate refuses a PR that adds a route/template without adding the
matching ``test_<slug>.py`` file here.
"""
