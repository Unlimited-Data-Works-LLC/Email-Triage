# Legacy master key: the database refuses to open (punch 418)

Admin-guide section for the `EncryptedDbKeyRefused` refusal. The re-key command that removes
the need for it is tracked as punch 831.

## How to recognise it

- The service does not start, or a CLI command exits, with `EncryptedDbKeyRefused` and the text
  "the storage key derived from the master key does not open 'triage.db': the master key is
  wrong, or the database was keyed with the un-normalised master key".
- It applies only to an install whose master-key secret ends with a newline (CR or LF) and whose
  database was created by a release before v0.2.0 while the secret carried that newline. In
  practice this is the deprecated `env` secrets backend with `ET_MASTER_KEY` set to a value
  that ends with a newline. The `container` and file backends already stripped the value, and
  a shell `$(cat file)` strips it too.
- Check the secret without printing it. This prints only `True` or `False`:

  ```
  python -c 'import os; print(os.environ["ET_MASTER_KEY"].endswith(("\n", "\r")))'
  ```

  `False` means the newline is not the cause: the master key is wrong. Restore the right key.

## Why the key no longer opens

From v0.2.0 the master key is read through one funnel, `secrets.read_master_key`, which strips
trailing CR/LF. The SQLCipher storage key, the audit HMAC key, the DbSecrets Fernet key and the
backup passphrase are all derived from that one string. A database keyed while the string
carried the newline needs a different storage key, so it no longer opens.

The release does not retry with the raw value. If it did, the storage key would come from one
string and the audit HMAC and Fernet keys from another, and the audit chain and the stored
secrets would no longer verify against the database.

The refusal fires when the database is first opened, before any migration runs (migrations open
it through the same keyed opener). The database file is unchanged.

## What to do today

1. Keep running the last release before v0.2.0 (v0.1.2). It reads the master key byte-for-byte,
   so it opens the database with the secret as it is.
2. Do not edit the secret. Removing the newline makes the old release fail to open the
   database too.
3. This is a stopgap: v0.1.2 does not have the v0.2.0 fixes. Upgrade once the re-key command
   below ships.

## The fix being built (punch 831)

A one-shot, operator-run `db rekey-legacy-master-key` command, tracked as punch 831:

- It derives every key from the raw value once.
- It re-keys the SQLCipher storage (`PRAGMA rekey`) to the normalised derivation.
- It re-wraps the DbSecrets/Fernet material.
- It keeps the old audit HMAC key as a prior version, so the existing chain still verifies.
- It records the operation as a chained admin-op row.

Once it has run, v0.2.0 and later will open the database with the secret as it is.
