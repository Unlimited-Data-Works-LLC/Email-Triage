"""SSOT for the OAuth secret-store key NAMES (census run13 #9).

The Google / Office365 OAuth *client* credentials live in the encrypted secret
store under these key names. TWO paths reference them:

  * the SAVE path — ``web/routers/integrations.py`` (``set_secret_if_changed`` /
    ``clear_secret`` from the admin Integrations form), and
  * the HYDRATE path — ``web/app.py`` boot (``read_secret`` into ``config``).

Before this SSOT both sides hand-wrote the same string literals. A rename on
ONE side (or a typo) silently desyncs them: the save writes key ``X`` while the
hydrate reads key ``Y`` → the OAuth config never loads → install-wide OAuth
death, the same shape as the 2026-06-08 credential-clobber incident. One
definition here; both sides import it, so a rename is a single-point edit and
``tests/test_oauth_secret_keys_ssot_pin.py`` keeps a raw literal from creeping
back.

NOTE: the VALUES are the on-disk secret-store keys an operator's existing
secrets are stored under — they are frozen (changing one orphans already-saved
credentials). Rename the CONSTANT name freely; never the string value.
"""

from __future__ import annotations

GOOGLE_OAUTH_WEB_CLIENT_ID = "GOOGLE_OAUTH_WEB_CLIENT_ID"
GOOGLE_OAUTH_WEB_CLIENT_SECRET = "GOOGLE_OAUTH_WEB_CLIENT_SECRET"
GOOGLE_OAUTH_DESKTOP_CLIENT_ID = "GOOGLE_OAUTH_DESKTOP_CLIENT_ID"
GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET = "GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET"
O365_OAUTH_TENANT_ID = "O365_OAUTH_TENANT_ID"
O365_OAUTH_CLIENT_ID = "O365_OAUTH_CLIENT_ID"
O365_OAUTH_CLIENT_SECRET = "O365_OAUTH_CLIENT_SECRET"

#: Every OAuth secret-store key — the set the pin proves no raw literal escapes.
OAUTH_SECRET_KEYS = frozenset({
    GOOGLE_OAUTH_WEB_CLIENT_ID,
    GOOGLE_OAUTH_WEB_CLIENT_SECRET,
    GOOGLE_OAUTH_DESKTOP_CLIENT_ID,
    GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET,
    O365_OAUTH_TENANT_ID,
    O365_OAUTH_CLIENT_ID,
    O365_OAUTH_CLIENT_SECRET,
})


#: N-181 R20_5: the paired hydrate+save SSOT tuple.
#:
#: Each entry = ``(key_const, config_section, config_attr, form_field, kind)``.
#: The HYDRATE side (``providers/factory.py::hydrate_and_register_install_oauth``)
#: iterates this tuple to populate the 7 install-OAuth config attributes from the
#: secrets store — no more parallel hand-list of ``read_secret(...)`` calls that
#: can drift from a new key. The SAVE side (``web/routers/integrations.py::
#: admin_integrations_save``) keeps its per-kind logic (id preserve-blank vs
#: secret validate-and-set vs the tenant ``common`` special case) but is pinned
#: to reference every ``key_const`` here — the exact-set equality pin catches
#: an 8th hydrate key that never landed a save writer (N-130 recurrence shape).
INSTALL_OAUTH_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    # (key_const, config_section, config_attr, form_field, kind)
    (GOOGLE_OAUTH_WEB_CLIENT_ID, "google_oauth", "web_client_id",
     "google_oauth_web_client_id", "id"),
    (GOOGLE_OAUTH_WEB_CLIENT_SECRET, "google_oauth", "web_client_secret",
     "google_oauth_web_client_secret", "google_secret"),
    (GOOGLE_OAUTH_DESKTOP_CLIENT_ID, "google_oauth", "desktop_client_id",
     "google_oauth_desktop_client_id", "id"),
    (GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET, "google_oauth", "desktop_client_secret",
     "google_oauth_desktop_client_secret", "google_secret"),
    (O365_OAUTH_TENANT_ID, "office365_oauth", "tenant_id",
     "office365_oauth_tenant_id", "tenant_id"),
    (O365_OAUTH_CLIENT_ID, "office365_oauth", "client_id",
     "office365_oauth_client_id", "id"),
    (O365_OAUTH_CLIENT_SECRET, "office365_oauth", "client_secret",
     "office365_oauth_client_secret", "secret"),
)
