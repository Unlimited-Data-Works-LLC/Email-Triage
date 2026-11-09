# External Secrets Providers (Option C)

The bootstrap layer supports plugin-registered backends via `backend: "external:<name>"` in YAML. This lets you source the **master encryption key** from KeePass, HashiCorp Vault, AWS Secrets Manager, or any other vault without baking a dependency on any one of them into the core.

## How it works

1. An optional module imports the core and registers a factory:
   ```python
   from email_triage.secrets import register_external_provider
   register_external_provider("keepass", KeepassSecrets)
   ```
2. The user enables it in YAML:
   ```yaml
   secrets:
     backend: "external:keepass"
     master_key_name: ET_MASTER_KEY
     external:
       database: /mnt/nas/vault.kdbx
       keyfile: /home/alice/.kp_keyfile
   ```
3. At startup, `bootstrap_secrets_from_config` calls `KeepassSecrets(**external)` to fetch the master key, then wraps the DB in `DbSecrets` as usual. User-managed secrets still live in the encrypted SQLite table.

Only `get()` is required — external providers typically supply the one master key and nothing else. `set()` and `list_keys()` may raise `NotImplementedError`.

## Skeleton: a KeePass provider

```python
# email_triage/secrets_keepass.py  (ship as email-triage[keepass] extra)

from email_triage.secrets import SecretsProvider, register_external_provider


class KeepassSecrets(SecretsProvider):
    """Reads secrets from a KeePass .kdbx database.

    Expects entries whose *title* matches the requested key name.
    The value is read from the entry's password field.
    """

    def __init__(self, database: str, password: str = "", keyfile: str = ""):
        try:
            from pykeepass import PyKeePass
        except ImportError:
            raise ImportError(
                "pykeepass required. Install with: pip install email-triage[keepass]"
            )
        self._kp = PyKeePass(database, password=password or None, keyfile=keyfile or None)

    def get(self, key: str) -> str | None:
        entry = self._kp.find_entries(title=key, first=True)
        return entry.password if entry else None

    def set(self, key: str, value: str) -> None:
        raise NotImplementedError(
            "KeePass writes are not supported by this provider. "
            "Edit the database in KeePassXC/Keeweb instead."
        )

    def list_keys(self) -> list[str]:
        return [e.title for e in self._kp.entries if e.title]


# Auto-register at import time.
register_external_provider("keepass", KeepassSecrets)
```

The user activates it by importing the module (e.g. in a site-local `email_triage_plugins.py` that the app imports at startup, or via a future `plugins:` config section).

## Why a registry instead of hard-coding?

- **Zero core dependency** on KeePass, Vault SDKs, cloud SDKs. Core stays portable.
- **Optional extras**: shippable as `email-triage[keepass]` / `email-triage[vault]` without bloating the default install.
- **Forward-compatible**: a medical researcher could add a custom backend for their compliance system without forking the project.

## Design constraints (why not a richer interface?)

The `SecretsProvider` ABC is deliberately minimal (`get`/`set`/`list_keys`). Anything more complex — rotation callbacks, audit logging, multi-tenancy — belongs at the `DbSecrets` layer, not the bootstrap layer. External providers have one job: hand us the master key.
