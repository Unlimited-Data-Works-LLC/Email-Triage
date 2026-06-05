---
name: email-triage-api
description: >
  Read and act on a user's email and calendar (Gmail + Microsoft 365)
  through the email-triage install on the deploy host. Search or filter mail, label,
  move, archive, or draft replies; list/create/update/delete calendar
  events; RSVP to invites; find free time slots; run classification +
  routing triage on behalf of the user. The default and only tool for
  any mailbox or calendar task — replaces the older gmail-skill and
  gcal-skill.
---

# email-triage — mail + calendar + triage

Thin HTTP wrapper around the email-triage `/api/openclaw/*` surface
(27 subcommands: 24 server-facing + 3 local file-ops -- `register-me`,
`forget-me`, `list-aliases`). Every server-facing action goes through
email-triage which owns credentials, HIPAA gating, rate limits, and
scope checks.

## When to Use

- **Any mail task** for an email-triage-registered account — list,
  search, label, move, archive, draft replies, queue summaries,
  bulk operations by filter.
- **Any calendar task** — list events in a window, create / update /
  delete an event, RSVP (accept / decline / tentative), find free
  time slots respecting working hours and OOO, bulk RSVP.
- **Triage** — run the classifier + routing pipeline on a batch of
  messages on demand (`triage-run`). Review recent runs (`runs`).
- **Per-account webhook + quiet-hours** configuration.

## When NOT to Use

- `gmail-skill` / `gcal-skill` — **retired**. Do not call. Use this skill.
- `imap-smtp-email` — still exists but is SMTP-only now (outbound OTP
  mail for the web UI). Do not use for reading mail or calendar.
- HIPAA-flagged accounts — the server returns 403 through every
  endpoint here, by design. HIPAA mail doesn't flow through OpenClaw.
- Account setup (adding a Gmail account, minting an OAuth client,
  etc.) — those are one-time web-UI tasks the human does directly.

## Identity — always pass `--as <alias>`

Each user's agent has a dedicated alias registered in
`~/.openclaw/skills/email-triage-api/users.json`. Pass `--as <alias>`
on **every** call so the right user's token is used. If the agent's
system prompt has given you an alias (e.g. "alice", "bob"), use
that literally. Never guess or mix aliases — you'd act as the wrong
user.

If `--as` is omitted, the skill uses `users.json["default"]`. That's
safe for agents that serve a single operator.

## Response shapes — DO NOT guess field names

These are the actual field names returned by the server. They don't
always match the SMTP-header names a model might assume. **If a field
you expect is missing, check this table before rendering `?` or
fabricating a value** — the underlying data is always there, the key
is just named differently.

### ⚠ Rendering an inbox view — exact field reads

For every message dict in `messages[]`, render exactly these fields:

```
date    ← message["date"]      # ISO 8601, slice/format as you like
sender  ← message["sender"]    # "Display Name <addr@host>" — NEVER message["from"]
subject ← message["subject"]
```

**`message["from"]` does not exist. `message["sender"]` always does.**
If you ever produce `?` in the From column of a rendered table, you
read the wrong field. Re-read the dict. The eBay / Dalstrong / Neuron
newsletters that look like "anonymous promotional mail" all have
populated `sender` strings (e.g. `"eBay <ebay@reply.ebay.com>"`).

A correct render of the response above looks like:

| Date | From | Subject |
|---|---|---|
| Apr 19 | eBay <ebay@reply.ebay.com> | Alex, get $5 off the item you love in-app |
| Apr 19 | Dalstrong <info@dalstrong.com> | Before you fire up the grill, read this |

Use `m["sender"].split("<")[0].strip()` if you want the display name
only, or `m["sender"]` verbatim. Either is real data, never empty
"on promotional emails" or any other category — the field is always
populated by the provider.

### `mail-get` response

| Field | Contains |
|---|---|
| `message_id` | Stable id, same one `mail-search` returned. |
| `thread_id` | Thread id — use as `--thread-id` on `mail-draft`. |
| `sender` | **"Display Name <addr@example>"** — this is the From: line. Not `from`. |
| `recipients` | Array of To: strings. |
| `subject` | Subject line, unescaped. |
| `date` | ISO-8601. |
| `body_text` | Plain-text body. Can be very long. |
| `labels` | Array of label names (Gmail) or folder path (IMAP). |
| `headers` | Dict of raw SMTP headers. `headers.from` is a valid fallback if `sender` is ever empty, but `sender` should be preferred. |

There is **no top-level `from` field**. A model that reaches for
`from` will get `None` / `?`.

### `mail-search` response

```json
{ "message_ids": ["...", "..."], "used_filter": { ... } }
```

`mail-search` returns **only IDs**. For rendering a list with
sender / subject / date, **use `mail-list` instead** — it does the
search and fetches summaries in one round trip. See the bulk-read
section below for the full task → command map.

### `mail-bulk` response

```json
{
  "requested": 50, "succeeded": 48, "failed": 2,
  "items": [
    {"message_id": "...", "status": "ok", "data": {...}},
    {"message_id": "...", "status": "error", "error": "..."}
  ],
  "elapsed_secs": 3.4
}
```

### `calendar-list` / `calendar-get` response

Events carry these fields:

```
event_id, calendar_id, calendar_summary, summary, description,
location, start, end, all_day, organizer, attendees, status,
ical_uid
```

Times are ISO strings. `all_day` events return a date-only
start/end. The same event may appear once per opted-in source
calendar; the server dedupes by `ical_uid` (then `event_id`)
before returning.

### ⚠ Rendering a calendar view — MANDATORY source label

**STRICT REQUIREMENT.** When summarizing calendar events for the
user, you MUST surface which calendar each event came from. The
operator configured multiple opted-in calendars deliberately and
the source is part of the answer. A response that hides the
source is wrong even if the times + titles are right.

For every event dict in `events[]`, the canonical fields are:

```
when    ← event["start"]            # plus event["end"] for span
title   ← event["summary"]          # event title shown to humans
where   ← event["calendar_summary"] # which calendar it lives on
        ← event["calendar_id"]      # fallback if summary is empty
```

**Two correct rendering shapes** (pick one based on the data):

1. **Mixed sources** — events come from 2+ distinct
   `calendar_summary` values. Append the source as a
   parenthetical on every line:

   ```
   <day>
     • <start time> – <event["summary"]> (<event["calendar_summary"]>)
   ```

2. **Single source** — every event in the response carries the
   same `calendar_summary`. Render a header line ONCE for the
   whole listing, then plain rows:

   ```
   Calendar: <calendar_summary>
     <day>
       • <start time> – <event["summary"]>
   ```

Either shape is acceptable. **Omitting the source entirely is
NOT acceptable** — that's the bug this section exists to
prevent. Even if `calendar_summary == calendar_id` (single
opted-in calendar; the summary defaulted to the id), still
render it. Empty AND empty → only then can you omit; in
practice this never happens for opted-in calendars.

### `calendar-free-slots` response

```json
{ "account_id": 3, "length_minutes": 30, "timezone": "America/Toronto",
  "slots": [["2026-04-20T09:00:00-04:00", "2026-04-20T09:30:00-04:00"], ...] }
```

`slots` is an array of `[start_iso, end_iso]` pairs.

## PREFER bulk-read for lists (closes the N+1 hallucination)

"Show me my 5 most recent unread with sender + subject" is **one
`mail-list` call**, not one search + five gets.

```bash
# ✅ DO THIS:
email-triage-api --as bob mail-list 3 --unread --limit 5
# → {"messages": [{"message_id","sender","subject","date","labels",
#                  "snippet","unread","has_attachment"}, ...], ...}
```

```bash
# ❌ DO NOT DO THIS (N+1 round-trips, invites hallucination on any
#    per-id failure, can't be batched via shell loop — exec preflight
#    blocks pipes and multi-statement commands):
email-triage-api --as bob mail-search 3 --unread --limit 5
# then five separate mail-get calls
```

### When to use which bulk-read:

| Use | Command |
|---|---|
| "List mail matching X with metadata" (inbox-view rendering) | `mail-list` |
| "I already have message_ids, give me metadata" | `mail-fetch --message-ids ID,ID,ID` |
| "I need the full body of matching messages" (summarising newsletters, extracting totals) | `mail-list-full` — bigger payloads, tighter limit (10, max 50) |
| "Show details for these calendar events" | `calendar-fetch --event-ids ID,ID,ID` |

`mail-search` (IDs only) and `mail-get` (single full message) still
exist; use them when you genuinely need only IDs, or when you already
have exactly one ID and want the full body + headers. For rendering a
*list* of messages to the user, **always use a bulk-read**.

### Bulk-read response shape

```json
{
  "messages": [
    { "message_id": "...", "thread_id": "...",
      "sender": "Display Name <addr>", "recipients": [...],
      "subject": "...", "date": "ISO",
      "labels": ["INBOX", "UNREAD", "Newsletters"],
      "snippet": "first ~200 chars, whitespace-collapsed",
      "unread": true, "has_attachment": false }
  ],
  "errors": [
    { "message_id": "...", "error": "..." }
  ],
  "used_filter": { ... },   // present on list, not on fetch
  "limit": 20
}
```

Per-message errors (a single bad id in a fetch batch, provider hiccup
on one message during a list) **collect into `errors`** — the call
still returns 200 and the successful messages are in `messages`.
Always check `errors` before declaring the result complete.

The full-body variant (`mail-list-full`) replaces `snippet` with the
complete `body_text` and includes `headers`. Calendar fetch returns
`events` instead of `messages`.

## Command reference

Invocation shape:

```
email-triage-api --as <alias> <subcommand> [args]
```

The bare `email-triage-api` is the **OpenClaw skill name** — the
runtime resolves it to the underlying script when the agent invokes
the tool. It is **not** a shell command; running it from a manual
shell prompt fails with "command not found".

For manual debugging from a shell on the OpenClaw host (operator
workflow, not agent), invoke the script directly:

```
EMAIL_TRIAGE_URL=https://<host>:8080 \
  python3 ~/.openclaw/skills/email-triage-api/scripts/email-triage-api.py \
    --as <alias> <subcommand> [args]
```

Output is pretty-printed JSON by default (use `--compact` for
single-line). Status-only actions (label, move, archive, delete,
respond) print `ok: <what happened>`.

### Accounts

| Command | What it does |
|---|---|
| `accounts-list` | List non-HIPAA accounts the user owns. |
| `account-quiet-hours <id>` | Configure webhook quiet window / pause. |
| `health` | Install-wide health snapshot. **Admin-token only.** Returns the operator-facing detail body (tasks block, ingestion counts, watchers, audit_failures, csrf_rejects, schema_version, version). HTTP 503 + body on degraded. Useful for the monitoring system scrapes + agent self-checks. |

### Mail

| Command | What it does |
|---|---|
| `mail-list <account_id> [--unread --label L --folder F --from A --to A --subject S --after ISO --before ISO --q RAW --limit N]` | **Bulk-read**: filter → list of summaries. **Prefer this for rendering message lists.** |
| `mail-list-full <account_id> [same flags as mail-list, --limit 1–50]` | Bulk-read with full `body_text` (not just snippet). For when you need to read bodies. |
| `mail-fetch <account_id> --message-ids ID,ID,ID` | Bulk-read summaries for an explicit list of ids. |
| `mail-search <account_id> [filter flags]` | Structured search, IDs only. Use when you only need ids, not metadata. |
| `mail-get <account_id> <message_id>` | Fetch one full message. Use only when you have exactly one id. |
| `mail-label <account_id> <message_id> <label>` | Apply a label. |
| `mail-move <account_id> <message_id> <folder>` | Move to a folder. |
| `mail-archive <account_id> <message_id>` | Archive. |
| `mail-draft <account_id> <message_id> --to A[,A] --subject S --body B [--in-reply-to ID] [--thread-id ID]` | Create a reply draft. Never sent automatically. |
| `mail-queue-summary <account_id> <message_id> [--category CAT]` | Queue newsletter / summary action. |
| `mail-bulk <account_id> --operation {label\|move\|archive\|queue_summary} [--args-json '{...}'] (--message-ids ID,ID \| --filter-json '{...}') [--limit N]` | Apply one action to many messages. |

### Triage + runs

| Command | What it does |
|---|---|
| `triage-run <account_id> [--query Q --limit N]` | Run classification + routing on a batch. Emits a `triage.completed` event. |
| `runs [--account-id ID --limit N]` | List recent triage runs. |

### Calendar

| Command | What it does |
|---|---|
| `calendar-list <account_id> --time-min ISO --time-max ISO [--limit N]` | List events in a window. |
| `calendar-get <account_id> <event_id>` | Fetch one event. |
| `calendar-fetch <account_id> --event-ids ID,ID,ID` | Bulk-read: fetch many events in one call. |
| `calendar-create <account_id> --summary S --start ISO --end ISO [--description --location --all-day --attendees A[,A]]` | Create an event. |
| `calendar-update <account_id> <event_id> [any field above]` | Patch an event. |
| `calendar-delete <account_id> <event_id>` | Delete. |
| `calendar-respond <account_id> <event_id> <accepted\|declined\|tentative>` | RSVP. |
| `calendar-free-slots <account_id> [--length N --count N --time-min ISO --time-max ISO]` | Find N free windows of length L. Respects working hours + OOO. |
| `calendar-bulk-respond <account_id> --responses-json '[{"event_id":"...","response":"..."}, ...]'` | Bulk RSVP. |

### Token management (local file ops, no server call)

| Command | What it does |
|---|---|
| `register-me --as <alias> --token et_...` | Save the user's personal token under an alias (upsert). |
| `forget-me --as <alias>` | Remove an alias from users.json. |
| `list-aliases` | Show configured aliases (token values redacted). |

Use `register-me` only when the user explicitly hands you a fresh
`et_...` token from the email-triage web UI and asks you to save it.

## Defaults you should respect

- **`--limit` defaults to 5 on every list-shaped command**
  (`mail-list`, `mail-list-full`, `mail-search`). Only pass an
  explicit `--limit N` when the user asked for a specific quantity
  ("show me 20 unread", "all of today's newsletters", etc.). Don't
  default to "give me everything."
- **`--as <alias>` is required on every server-facing call.** The
  agent's system prompt has assigned an alias; use it literally.
- **Bodies come back with HTML stripped** on `mail-list-full`,
  `mail-list`, and `mail-fetch`. Snippets and `body_text` are clean
  text — no `<div>`, no `&nbsp;`. Single-message `mail-get` returns
  the raw body for cases where you want HTML.

## Templates — copy-paste recipes

Every recipe below assumes the agent has been told to act as
`<alias>` and that the user's account_id is `<acct>`. Substitute
those literally; everything else is verbatim.

### Render an inbox view (the most common ask)

> User: *"what's in my inbox?"* / *"any new mail?"* / *"check my email"*

```bash
email-triage-api --as <alias> mail-list <acct> --unread
```

Returns 5 summaries. Reads:

```json
{ "messages": [
    { "sender": "Display <addr>", "subject": "...", "date": "ISO",
      "snippet": "first ~200 chars, clean text",
      "labels": [...], "unread": true, "has_attachment": false }, ... ],
  "errors": [] }
```

Display them as a numbered list to the user; pull a specific one for
a follow-up with `mail-get` or `mail-list-full`.

### Render a calendar view (the next most common ask)

> User: *"what's on my calendar?"* / *"what do I have today?"* /
> *"any meetings this week?"* / *"what's coming up?"*

```bash
email-triage-api --as <alias> calendar-list <acct> \
    --time-min "$(date -u +%Y-%m-%dT00:00:00Z)" \
    --time-max "$(date -u -d '+5 days' +%Y-%m-%dT23:59:59Z)" \
    --limit 50
```

Returns events with calendar source attached:

```json
{ "events": [
    { "event_id": "...", "calendar_id": "...",
      "calendar_summary": "...",
      "summary": "...",
      "start": "ISO", "end": "ISO",
      "location": "...", "all_day": false,
      "organizer": "...", "attendees": [...] }, ... ] }
```

**MANDATORY**: every rendered event MUST surface its source
calendar via `calendar_summary` (or `calendar_id` if the summary
is empty). Two acceptable shapes — pick one based on the data:

- **Mixed sources** (events from 2+ distinct `calendar_summary`
  values) → per-row parenthetical:

  ```
  <day>
    • <start time> – <event["summary"]> (<event["calendar_summary"]>)
  ```

- **Single source** (every event shares one `calendar_summary`)
  → header line ONCE, then plain rows:

  ```
  Calendar: <calendar_summary>
    <day>
      • <start time> – <event["summary"]>
  ```

Omitting the source entirely is wrong and the user notices.
Even if every event came from one calendar, render the
`Calendar: <name>` header — that's the operator-facing answer
to "which calendar are you reading?"

**Do NOT invent placeholder text in the rendered output.** Replace
the bracketed slots above with literal field values from the
tool's JSON response. If the tool returned no events, say "No
events in the next N days" — never fabricate events.

### "Summarise today's <category>"

> User: *"summarise today's newsletters"* / *"what's in today's
> updates?"*

```bash
email-triage-api --as <alias> mail-list-full <acct> \
    --label Newsletters --after 2026-04-19T00:00:00Z
```

Default 5 messages with full clean-text bodies. Iterate `messages[]`,
extract subject + body_text, summarise back to user.

### "Show me X from <sender>"

```bash
email-triage-api --as <alias> mail-list <acct> --from "noreply@bank.com"
```

```bash
email-triage-api --as <alias> mail-list <acct> --subject "invoice"
```

Combine flags freely: `--unread --from "alice@" --after 2026-04-15T00:00:00Z`.

### "Did <person> send me anything today?"

```bash
email-triage-api --as <alias> mail-list <acct> \
    --from "alice@example.com" --after 2026-04-19T00:00:00Z
```

If `messages` is empty: "Nothing from Alice today." Plus `errors` if any.

### "Pull the full body of these specific messages"

You already have ids from a prior `mail-list` call:

```bash
email-triage-api --as <alias> mail-fetch <acct> \
    --message-ids 19da7b...d5,19da79...90
```

Returns summaries (no body) for each. For the **bodies**, switch to
`mail-list-full` with a filter, or call `mail-get` once per id (rare
case — usually a list-with-bodies is what's wanted).

### "Read this one message in detail"

```bash
email-triage-api --as <alias> mail-get <acct> <message_id>
```

Returns the **raw** body (HTML preserved). For an LLM-friendly clean-
text version, use `mail-list-full` with a filter that matches just
that message (e.g. `--subject "exact subject"`).

### Bulk write — archive matching mail

> User: *"archive everything from coupons@oldsite.com"*

```bash
email-triage-api --as <alias> mail-bulk <acct> \
    --operation archive \
    --filter-json '{"from":"coupons@oldsite.com"}' \
    --limit 100
```

`mail-bulk` defaults to limit 50; pass `--limit 100` when the user
says "all" / "everything" / a specific count. Capped server-side at
`push.bulk_max_batch_size` (default 100).

### Bulk write — label by filter

> User: *"label all unread bills as 'review'"*

```bash
email-triage-api --as <alias> mail-bulk <acct> \
    --operation label --args-json '{"label":"review"}' \
    --filter-json '{"unread":true,"subject":"bill"}' \
    --limit 50
```

### Bulk write — by explicit ids (after a list)

```bash
# Step 1: see what's there.
email-triage-api --as <alias> mail-list <acct> --unread --limit 10
# Step 2: act on the ones the user picked (say, items 1, 3, 5).
email-triage-api --as <alias> mail-bulk <acct> \
    --operation move --args-json '{"folder":"Receipts"}' \
    --message-ids 19da7b...d5,19da78...8e,19da76...1c
```

### Calendar — what's today / this week

```bash
# Today
email-triage-api --as <alias> calendar-list <acct> \
    --time-min 2026-04-19T00:00:00-04:00 \
    --time-max 2026-04-20T00:00:00-04:00

# Next 7 days
email-triage-api --as <alias> calendar-list <acct> \
    --time-min 2026-04-19T00:00:00-04:00 \
    --time-max 2026-04-26T00:00:00-04:00
```

Compute the ISO window in the user's local TZ (the
`calendar-free-slots` response includes the user's timezone — handy
reference).

### Calendar — find free time

> User: *"find me three 30-minute slots this week"*

```bash
email-triage-api --as <alias> calendar-free-slots <acct> --length 30 --count 3
```

Respects the user's working hours + OOO server-side — no client-side
math needed.

### Calendar — fetch many events by id

You have ids from a `calendar-list` call:

```bash
email-triage-api --as <alias> calendar-fetch <acct> \
    --event-ids ev-1,ev-2,ev-3
```

### Calendar — bulk RSVP

> User: *"accept all three of those meetings"*

```bash
email-triage-api --as <alias> calendar-bulk-respond <acct> \
    --responses-json '[
      {"event_id":"ev-1","response":"accepted"},
      {"event_id":"ev-2","response":"accepted"},
      {"event_id":"ev-3","response":"accepted"}
    ]'
```

### Triage — run the classifier on demand

> User: *"triage the last 5 unread"*

```bash
email-triage-api --as <alias> triage-run <acct> --query is:unread --limit 5
```

### Drafting (never sent)

> User: *"reply to that and tell them I'll get back to them tomorrow"*

```bash
email-triage-api --as <alias> mail-draft <acct> <message_id> \
    --to "alice@example.com" --subject "Re: Question" \
    --body "Thanks for the note — I'll get back to you in the morning."
```

The draft lands in the user's mail provider. Never sent automatically.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | HTTP 4xx/5xx (non-auth, non-rate) or client-side error |
| 2 | HTTP 429 — rate-limited. `Retry-After` printed to stderr. |
| 3 | HTTP 401 — token missing or rejected. Tell the user to mint a new one at `<url>/accounts/api-keys`. |
| 4 | config missing — URL or token not resolvable |

## Setup and deployment details

See [README.md](README.md) in this directory for install, token
layout, per-user setup, and migration notes. Operators use that; you
(the agent) just need the command reference above.
