# email-triage-api — OpenClaw skill

Thin Python wrapper around email-triage's `/api/v1/*` HTTP
surface. Lives in this repo (versioned with the API it wraps) and
deploys to the OpenClaw host at `~/.openclaw/skills/email-triage-api/` —
the OpenClaw **managed** skills directory, scanned automatically for
every agent on the gateway. One physical install, one `users.json`,
zero drift.

## Deploy to the OpenClaw host

From the email-triage repo root:

```bash
ssh <openclaw-host> "mkdir -p ~/.openclaw/skills"
tar -cC openclaw/skills email-triage-api | \
  ssh <openclaw-host> "tar -xC ~/.openclaw/skills/"
```

Then one edit in `~/.openclaw/openclaw.json` — the skill entry.
OpenClaw scans `~/.openclaw/skills/` as the managed source for **every**
agent automatically, so no path configuration is needed:

```jsonc
{
  "skills": {
    "entries": {
      "email-triage-api": {
        "enabled": true,
        "env": {
          "EMAIL_TRIAGE_URL": "https://triage.example.com:8080"
        }
      }
    }
  }
}
```

`EMAIL_TRIAGE_URL` must be the HTTPS endpoint the email-triage container
serves on (the cert hostname). Plain HTTP is rejected.

Restart: `systemctl --user restart openclaw-gateway`.

**Do NOT add `skills.load.extraDirs` pointing at the managed dir** —
it's redundant (the managed scan already covers it). An operator-
private handover doc captures the dead-end iterations that surfaced
this gotcha.

**No token in openclaw.json.** Tokens are per-user. The **secure** way to
supply them is a credential helper (no plaintext on disk); the legacy
`users.json` plaintext store still works but is deprecated. Full design +
recipes: [`internal documentation`](../../../internal documentation).

## Token layout — secure backend (recommended)

Point `EMAIL_TRIAGE_TOKEN_CMD` at a command that prints the `et_…` token;
the skill runs it on demand and reads stdout (the alias is passed as
`{alias}` and the `ET_ALIAS` env var). One line covers every user:

```jsonc
// ~/.openclaw/openclaw.json — skills.entries.email-triage-api.env
{
  "EMAIL_TRIAGE_URL": "https://triage.example.com:8080",
  "EMAIL_TRIAGE_TOKEN_CMD": "pass show email-triage/{alias}"
}
```

Bridges to OpenClaw's native exec-provider `SecretRef`, `pass`,
`secret-tool`, 1Password `op`, HashiCorp `vault`, the Windows Credential
Manager, etc. A configured helper is **fail-closed**: if it can't produce a
token the call fails (exit 4) — it never silently falls back to a stale
plaintext token. For OpenClaw, apply secret wiring via
`openclaw secrets configure --apply` (don't hand-edit a `SecretRef` and
restart blind — the gateway aborts boot on an unresolvable ref).

## Token layout — legacy plaintext (deprecated)

When no helper is configured, a single
`~/.openclaw/skills/email-triage-api/users.json` (mode `0600`, owned by
`openclaw`) maps short aliases to tokens:

```jsonc
{
  "default": "et_...",      // fallback when no --as is given
  "bob":   "et_...",
  "alice": "et_..."
}
```

Each agent passes `--as <alias>` on every call so the right token is
used. The skill falls back to `users.json["default"]`, then to the
legacy `EMAIL_TRIAGE_TOKEN` env var, only when `--as` isn't given. Using a
plaintext token emits a one-time security warning; migrate per
`internal documentation`.

### User self-serve workflow

1. Log into email-triage → **Accounts** → **🔑 Access Tokens** →
   **Create a token**.
2. The success panel shows the `et_...` value and a sentence to paste
   into their AI assistant's chat, like:
   > *Please save my new email-triage token. Run this command:
   > `email-triage-api register-me --as alice --token et_...`*
3. The assistant runs the command once. The skill writes the new
   alias to `users.json` (append-or-overwrite). Done.

### Manual token management

```bash
python3 ~/.openclaw/skills/email-triage-api/scripts/email-triage-api.py register-me \
    --as alice --token et_...
python3 ~/.openclaw/skills/email-triage-api/scripts/email-triage-api.py list-aliases
python3 ~/.openclaw/skills/email-triage-api/scripts/email-triage-api.py forget-me \
    --as alice
```

`register-me` / `forget-me` / `list-aliases` are pure local-file ops —
they don't hit the server and don't need a URL or token configured. When a
backend is configured, `register-me` is backend-aware: it pipes the token to
`EMAIL_TRIAGE_TOKEN_SET_CMD` on stdin (e.g. `pass insert -m -f email-triage/{alias}`)
instead of writing plaintext; if only the read helper (`EMAIL_TRIAGE_TOKEN_CMD`)
is set it refuses to write a plaintext token the read path would ignore.

## Smoke test after deploy

```bash
ssh <openclaw-host> "python3 ~/.openclaw/skills/email-triage-api/scripts/email-triage-api.py accounts-list"
```

Expect: JSON list of your non-HIPAA accounts. (Uses the `default`
alias from `users.json` or the env-var fallback.)

## Full command reference

See [SKILL.md](SKILL.md) — the canonical manifest + command table.
