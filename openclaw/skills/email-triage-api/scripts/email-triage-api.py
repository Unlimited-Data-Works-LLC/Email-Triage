#!/usr/bin/env python3
"""email-triage-api OpenClaw skill.

Thin HTTP wrapper around email-triage's /api/openclaw/* surface so
OpenClaw / the agent can operate mail, calendar, and triage actions the
same way it operates SSH. No business logic lives here; every
subcommand maps 1:1 to a server endpoint, passes the bearer token,
and prints the response.

Config:
  EMAIL_TRIAGE_URL     Base URL of the email-triage install. Required.
                       Usually set in ~/.openclaw/openclaw.json's
                       skills.entries.email-triage-api.env block.

Token resolution order (first hit wins):
  1. --token et_...              explicit CLI override
  2. --as <alias>                 users.json[<alias>] — per-user tokens
                                  live in ~/.openclaw/skills/
                                  email-triage-api/users.json
  3. users.json["default"]        installation-wide fallback
  4. EMAIL_TRIAGE_TOKEN env var   legacy path, also injected by
                                  OpenClaw SecretRef if configured

Multi-user: each human mints their own token in the email-triage web
UI, then runs (or has their agent run) the ``register-me`` subcommand
to store it under an alias. The agent's system prompt pins that
alias via ``--as <name>`` on every call.

Optional:
  EMAIL_TRIAGE_TIMEOUT Per-call timeout, seconds. Default 30.

Exit codes:
  0  success
  1  HTTP 4xx/5xx other than auth/rate-limit, or unexpected client error
  2  HTTP 429 (rate-limited; Retry-After printed to stderr)
  3  HTTP 401 (bad/missing token)
  4  missing required config (URL or token)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------

def _users_json_path() -> str:
    """Return the absolute path of the skill's users.json."""
    # The script lives at .../email-triage-api/scripts/email-triage-api.py;
    # users.json sits alongside at the skill root.
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "users.json")


def _read_users_json() -> dict[str, str]:
    """Return the alias→token map, or {} if the file is missing."""
    path = _users_json_path()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        print(f"warning: could not read {path}: {e}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        return {}
    # Only string values (tokens) survive; ignore stray types.
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def _write_users_json(data: dict[str, str]) -> None:
    """Write alias→token map with 0600 perms. Atomic replace via tmp."""
    path = _users_json_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    # umask 077 before create so the fresh tmp is 0600 from the start.
    prev_umask = os.umask(0o077)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # best-effort on non-POSIX filesystems
    finally:
        os.umask(prev_umask)


class _Ctx:
    """Per-invocation runtime context (base URL, token, timeout, verbosity)."""
    __slots__ = ("url", "token", "timeout", "verbose", "pretty", "alias")

    def __init__(self, args: argparse.Namespace):
        self.url = (args.url or os.environ.get("EMAIL_TRIAGE_URL") or "").rstrip("/")
        self.alias = args.as_alias  # may be None
        self.token = self._resolve_token(args)
        timeout_raw = os.environ.get("EMAIL_TRIAGE_TIMEOUT", "30")
        try:
            self.timeout = float(timeout_raw)
        except ValueError:
            self.timeout = 30.0
        self.verbose = bool(args.verbose)
        self.pretty = not args.compact

    @staticmethod
    def _resolve_token(args: argparse.Namespace) -> str:
        # 1. Explicit --token wins — useful for probes + register-me itself.
        if args.token:
            return args.token
        users = _read_users_json()
        # 2. --as <alias> → users.json[alias]
        if args.as_alias:
            tok = users.get(args.as_alias, "")
            if tok:
                return tok
            # If --as was requested but the alias isn't in the map,
            # DON'T silently fall through — that would act as a
            # different user than the caller asked for, which is the
            # opposite of safe. Let require() fail with a clear error.
            return ""
        # 3. users.json["default"]
        default = users.get("default", "")
        if default:
            return default
        # 4. Legacy env var (the SecretRef path).
        return os.environ.get("EMAIL_TRIAGE_TOKEN", "") or ""

    def require(self) -> None:
        missing: list[str] = []
        if not self.url:
            missing.append("EMAIL_TRIAGE_URL (or --url)")
        if not self.token:
            if self.alias:
                print(
                    f"error: no token registered for alias '{self.alias}'.\n"
                    f"  Mint one in the email-triage web UI under Access Tokens,\n"
                    f"  then run: email-triage-api register-me --as {self.alias} --token et_...",
                    file=sys.stderr,
                )
                sys.exit(4)
            missing.append("a token (--token / --as <alias> / EMAIL_TRIAGE_TOKEN)")
        if not missing:
            return
        print(
            "error: missing required config: " + ", ".join(missing),
            file=sys.stderr,
        )
        print(
            "  Mint a token: log into email-triage → Accounts → Access Tokens.\n"
            "  Register it:  email-triage-api register-me --as <you> --token et_...\n"
            "  Then call:    email-triage-api --as <you> <subcommand>",
            file=sys.stderr,
        )
        sys.exit(4)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _request(
    ctx: _Ctx,
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: Any | None = None,
) -> tuple[int, Any, dict[str, str]]:
    """Issue one HTTP request to /api/openclaw<path>. Returns
    (status, parsed_body, headers_dict)."""
    url = ctx.url + "/api/openclaw" + path
    if params:
        # Drop Nones + False-if-flag-style; keep 0/False for booleans
        # we want to send explicitly (callers decide by including them).
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url += "?" + urllib.parse.urlencode(clean, doseq=True)
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", "Bearer " + ctx.token)
    body: bytes | None = None
    if json_body is not None:
        req.add_header("Content-Type", "application/json")
        body = json.dumps(json_body).encode("utf-8")
    if ctx.verbose:
        print(f"→ {method} {url}", file=sys.stderr)
    try:
        with urllib.request.urlopen(req, data=body, timeout=ctx.timeout) as resp:
            raw = resp.read()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            if ctx.verbose:
                print(f"← {resp.status}", file=sys.stderr)
            return resp.status, _parse_json(raw), headers
    except urllib.error.HTTPError as e:
        raw = e.read() or b""
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        if ctx.verbose:
            print(f"← {e.code}", file=sys.stderr)
        return e.code, _parse_json(raw), headers
    except urllib.error.URLError as e:
        print(f"error: network failure contacting {url}: {e.reason}", file=sys.stderr)
        sys.exit(1)


def _parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"_raw": raw.decode("utf-8", errors="replace")}


# ---------------------------------------------------------------------------
# Output + error mapping
# ---------------------------------------------------------------------------

def _emit_and_exit(
    ctx: _Ctx,
    status: int,
    body: Any,
    headers: dict[str, str],
    *,
    ok_summary: str | None = None,
) -> None:
    """Print the response body + exit with the right code for the
    HTTP status. ``ok_summary`` is a plain-text confirmation for
    status-only endpoints (label, move, etc.); when set and the call
    succeeded, print that instead of the JSON body."""
    if 200 <= status < 300:
        if ok_summary:
            print(ok_summary)
        else:
            _print_body(ctx, body)
        sys.exit(0)
    # Error paths.
    if status == 401:
        print(
            "error: 401 unauthorized — token is missing or rejected.\n"
            "  Create a new key at <url>/accounts/api-keys and retry.",
            file=sys.stderr,
        )
        sys.exit(3)
    if status == 429:
        retry = headers.get("retry-after", "?")
        print(
            f"error: 429 rate-limited — retry after {retry} seconds.",
            file=sys.stderr,
        )
        # Still dump body for any extra context.
        _print_body(ctx, body, stream=sys.stderr)
        sys.exit(2)
    # Generic 4xx / 5xx.
    code = ""
    msg = ""
    if isinstance(body, dict):
        # FastAPI tends to wrap errors as {"detail": "..."} or
        # {"detail": {"code": "...", "message": "..."}}.
        detail = body.get("detail", body)
        if isinstance(detail, dict):
            code = str(detail.get("code", ""))
            msg = str(detail.get("message", ""))
        elif isinstance(detail, str):
            msg = detail
    print(
        f"error: {status} {code or ''} {msg}".rstrip(),
        file=sys.stderr,
    )
    if body is not None:
        _print_body(ctx, body, stream=sys.stderr)
    sys.exit(1)


def _print_body(ctx: _Ctx, body: Any, *, stream=sys.stdout) -> None:
    if body is None:
        return
    if ctx.pretty:
        print(json.dumps(body, indent=2, sort_keys=False), file=stream)
    else:
        print(json.dumps(body, separators=(",", ":")), file=stream)


# ---------------------------------------------------------------------------
# Subcommand handlers — one per endpoint. Each builds params/body and
# delegates to _request + _emit_and_exit.
# ---------------------------------------------------------------------------

def _cmd_register_me(ctx: _Ctx, args: argparse.Namespace) -> None:
    """Write/overwrite one alias → token entry in users.json."""
    alias = args.as_alias.strip()
    token = args.token.strip()
    if not alias or not token:
        print("error: --as and --token are both required.", file=sys.stderr)
        sys.exit(1)
    if not token.startswith("et_"):
        print(
            "warning: token does not start with 'et_' — double-check you copied\n"
            "         the whole value from the email-triage Access Tokens page.",
            file=sys.stderr,
        )
    users = _read_users_json()
    existed = alias in users
    users[alias] = token
    _write_users_json(users)
    verb = "Updated" if existed else "Registered"
    print(f"{verb} alias '{alias}' in {_users_json_path()}.")
    sys.exit(0)


def _cmd_forget_me(ctx: _Ctx, args: argparse.Namespace) -> None:
    """Remove an alias from users.json."""
    alias = args.as_alias.strip()
    users = _read_users_json()
    if alias not in users:
        print(f"No alias '{alias}' in {_users_json_path()}.")
        sys.exit(0)
    del users[alias]
    _write_users_json(users)
    print(f"Removed alias '{alias}'.")
    sys.exit(0)


def _cmd_list_aliases(ctx: _Ctx, args: argparse.Namespace) -> None:
    """Show the aliases configured, WITHOUT printing any token values."""
    users = _read_users_json()
    if not users:
        print("No aliases configured.")
        sys.exit(0)
    for alias, tok in sorted(users.items()):
        # Show just enough of the suffix to distinguish tokens without
        # leaking them to screen/logs.
        tail = tok[-4:] if len(tok) >= 6 else "***"
        print(f"  {alias}  (ends in …{tail})")
    sys.exit(0)


def _cmd_accounts_list(ctx: _Ctx, args: argparse.Namespace) -> None:
    status, body, headers = _request(ctx, "GET", "/accounts")
    _emit_and_exit(ctx, status, body, headers)


def _cmd_health(ctx: _Ctx, args: argparse.Namespace) -> None:
    """Install-wide health snapshot. Admin token required.

    Returns the operator-facing detail body the web UI's
    /health/detail serves: tasks block, ingestion counts, watchers,
    audit_failures, csrf_rejects, schema_version, version. Useful
    for unattended monitors (the monitoring system) + agent self-checks (the agent).

    HTTP 503 status code on degraded carries the same body so the
    operator can read what's degraded without an extra round-trip.
    """
    status, body, headers = _request(ctx, "GET", "/health")
    _emit_and_exit(ctx, status, body, headers)


def _cmd_account_quiet_hours(ctx: _Ctx, args: argparse.Namespace) -> None:
    payload: dict[str, Any] = {}
    if args.enabled is not None:
        payload["enabled"] = args.enabled
    if args.paused is not None:
        payload["paused"] = args.paused
    if args.start_utc is not None:
        payload["start_utc"] = args.start_utc
    if args.end_utc is not None:
        payload["end_utc"] = args.end_utc
    status, body, headers = _request(
        ctx, "PUT", f"/accounts/{args.account_id}/quiet-hours", json_body=payload,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_mail_search(ctx: _Ctx, args: argparse.Namespace) -> None:
    params: dict[str, Any] = {"limit": args.limit}
    if args.unread:
        params["unread"] = "true"
    if args.label:
        params["label"] = args.label
    if args.folder:
        params["folder"] = args.folder
    if args.from_:
        params["from"] = args.from_
    if args.to:
        params["to"] = args.to
    if args.subject:
        params["subject"] = args.subject
    if args.after:
        params["after"] = args.after
    if args.before:
        params["before"] = args.before
    if args.q:
        params["q"] = args.q
    status, body, headers = _request(
        ctx, "GET", f"/accounts/{args.account_id}/mail/search", params=params,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_mail_get(ctx: _Ctx, args: argparse.Namespace) -> None:
    status, body, headers = _request(
        ctx, "GET", f"/accounts/{args.account_id}/messages/{args.message_id}",
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_mail_list(ctx: _Ctx, args: argparse.Namespace) -> None:
    """Bulk-read summaries by filter — the N+1 killer."""
    params: dict[str, Any] = {"limit": args.limit}
    if args.unread:
        params["unread"] = "true"
    for k_in, k_out in (
        ("label", "label"), ("folder", "folder"), ("from_", "from"),
        ("to", "to"), ("subject", "subject"),
        ("after", "after"), ("before", "before"), ("q", "q"),
    ):
        v = getattr(args, k_in, None)
        if v:
            params[k_out] = v
    status, body, headers = _request(
        ctx, "GET", f"/accounts/{args.account_id}/bulk/mail", params=params,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_mail_fetch(ctx: _Ctx, args: argparse.Namespace) -> None:
    """Bulk-read summaries for an explicit list of message_ids."""
    ids = _split_csv(args.message_ids)
    if not ids:
        print("error: --message-ids is required", file=sys.stderr)
        sys.exit(1)
    status, body, headers = _request(
        ctx, "POST",
        f"/accounts/{args.account_id}/bulk/mail/fetch",
        json_body={"message_ids": ids},
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_mail_list_full(ctx: _Ctx, args: argparse.Namespace) -> None:
    """Bulk-read FULL body_text by filter. Big payloads — default
    limit 10, max 50."""
    params: dict[str, Any] = {"limit": args.limit}
    if args.unread:
        params["unread"] = "true"
    for k_in, k_out in (
        ("label", "label"), ("folder", "folder"), ("from_", "from"),
        ("to", "to"), ("subject", "subject"),
        ("after", "after"), ("before", "before"), ("q", "q"),
    ):
        v = getattr(args, k_in, None)
        if v:
            params[k_out] = v
    status, body, headers = _request(
        ctx, "GET", f"/accounts/{args.account_id}/bulk/mail/full",
        params=params,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_calendar_fetch(ctx: _Ctx, args: argparse.Namespace) -> None:
    """Bulk-read calendar events by explicit list of event_ids."""
    ids = _split_csv(args.event_ids)
    if not ids:
        print("error: --event-ids is required", file=sys.stderr)
        sys.exit(1)
    status, body, headers = _request(
        ctx, "POST",
        f"/accounts/{args.account_id}/bulk/calendar/fetch",
        json_body={"event_ids": ids},
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_mail_label(ctx: _Ctx, args: argparse.Namespace) -> None:
    status, body, headers = _request(
        ctx, "POST",
        f"/accounts/{args.account_id}/messages/{args.message_id}/label",
        json_body={"label": args.label},
    )
    _emit_and_exit(
        ctx, status, body, headers,
        ok_summary=f"ok: labelled {args.message_id} '{args.label}'",
    )


def _cmd_mail_move(ctx: _Ctx, args: argparse.Namespace) -> None:
    status, body, headers = _request(
        ctx, "POST",
        f"/accounts/{args.account_id}/messages/{args.message_id}/move",
        json_body={"folder": args.folder},
    )
    _emit_and_exit(
        ctx, status, body, headers,
        ok_summary=f"ok: moved {args.message_id} → {args.folder}",
    )


def _cmd_mail_archive(ctx: _Ctx, args: argparse.Namespace) -> None:
    status, body, headers = _request(
        ctx, "POST",
        f"/accounts/{args.account_id}/messages/{args.message_id}/archive",
        json_body={},
    )
    _emit_and_exit(
        ctx, status, body, headers,
        ok_summary=f"ok: archived {args.message_id}",
    )


def _cmd_mail_draft(ctx: _Ctx, args: argparse.Namespace) -> None:
    payload: dict[str, Any] = {
        "to": _split_csv(args.to),
        "subject": args.subject,
        "body": args.body,
    }
    if args.in_reply_to:
        payload["in_reply_to"] = args.in_reply_to
    if args.thread_id:
        payload["thread_id"] = args.thread_id
    status, body, headers = _request(
        ctx, "POST",
        f"/accounts/{args.account_id}/messages/{args.message_id}/draft",
        json_body=payload,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_mail_queue_summary(ctx: _Ctx, args: argparse.Namespace) -> None:
    payload: dict[str, Any] = {}
    if args.category:
        payload["category"] = args.category
    status, body, headers = _request(
        ctx, "POST",
        f"/accounts/{args.account_id}/messages/{args.message_id}/queue-summary",
        json_body=payload,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_mail_bulk(ctx: _Ctx, args: argparse.Namespace) -> None:
    payload: dict[str, Any] = {"operation": args.operation, "limit": args.limit}
    if args.args_json:
        payload["args"] = _parse_inline_json(args.args_json, "--args-json")
    if args.message_ids and args.filter_json:
        print(
            "error: --message-ids and --filter-json are mutually exclusive",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.message_ids:
        payload["message_ids"] = _split_csv(args.message_ids)
    elif args.filter_json:
        payload["filter"] = _parse_inline_json(args.filter_json, "--filter-json")
    status, body, headers = _request(
        ctx, "POST", f"/accounts/{args.account_id}/bulk/mail/write", json_body=payload,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_triage_run(ctx: _Ctx, args: argparse.Namespace) -> None:
    payload: dict[str, Any] = {"query": args.query, "limit": args.limit}
    status, body, headers = _request(
        ctx, "POST", f"/accounts/{args.account_id}/triage", json_body=payload,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_runs(ctx: _Ctx, args: argparse.Namespace) -> None:
    params: dict[str, Any] = {"limit": args.limit}
    if args.account_id is not None:
        params["account_id"] = args.account_id
    status, body, headers = _request(ctx, "GET", "/runs", params=params)
    _emit_and_exit(ctx, status, body, headers)


# --- Calendar ---------------------------------------------------------------

def _cmd_calendar_list(ctx: _Ctx, args: argparse.Namespace) -> None:
    params = {"time_min": args.time_min, "time_max": args.time_max, "limit": args.limit}
    status, body, headers = _request(
        ctx, "GET", f"/accounts/{args.account_id}/calendar/events", params=params,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_calendar_get(ctx: _Ctx, args: argparse.Namespace) -> None:
    status, body, headers = _request(
        ctx, "GET",
        f"/accounts/{args.account_id}/calendar/events/{args.event_id}",
    )
    _emit_and_exit(ctx, status, body, headers)


def _calendar_event_payload(args: argparse.Namespace) -> dict[str, Any]:
    """Shared between create + update. Only includes fields the caller
    actually passed, so update truly patches and create gets just the
    set the user intended."""
    payload: dict[str, Any] = {}
    if getattr(args, "summary", None) is not None:
        payload["summary"] = args.summary
    if getattr(args, "description", None) is not None:
        payload["description"] = args.description
    if getattr(args, "location", None) is not None:
        payload["location"] = args.location
    if getattr(args, "start", None) is not None:
        payload["start"] = args.start
    if getattr(args, "end", None) is not None:
        payload["end"] = args.end
    if getattr(args, "all_day", False):
        payload["all_day"] = True
    if getattr(args, "attendees", None):
        payload["attendees"] = _split_csv(args.attendees)
    return payload


def _cmd_calendar_create(ctx: _Ctx, args: argparse.Namespace) -> None:
    payload = _calendar_event_payload(args)
    status, body, headers = _request(
        ctx, "POST", f"/accounts/{args.account_id}/calendar/events",
        json_body=payload,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_calendar_update(ctx: _Ctx, args: argparse.Namespace) -> None:
    payload = _calendar_event_payload(args)
    if not payload:
        print(
            "error: calendar-update needs at least one field to change",
            file=sys.stderr,
        )
        sys.exit(1)
    status, body, headers = _request(
        ctx, "PATCH",
        f"/accounts/{args.account_id}/calendar/events/{args.event_id}",
        json_body=payload,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_calendar_delete(ctx: _Ctx, args: argparse.Namespace) -> None:
    status, body, headers = _request(
        ctx, "DELETE",
        f"/accounts/{args.account_id}/calendar/events/{args.event_id}",
    )
    _emit_and_exit(
        ctx, status, body, headers,
        ok_summary=f"ok: deleted event {args.event_id}",
    )


def _cmd_calendar_respond(ctx: _Ctx, args: argparse.Namespace) -> None:
    status, body, headers = _request(
        ctx, "POST",
        f"/accounts/{args.account_id}/calendar/events/{args.event_id}/respond",
        json_body={"response": args.response},
    )
    _emit_and_exit(
        ctx, status, body, headers,
        ok_summary=f"ok: {args.response} {args.event_id}",
    )


def _cmd_calendar_free_slots(ctx: _Ctx, args: argparse.Namespace) -> None:
    params: dict[str, Any] = {"length": args.length, "count": args.count}
    if args.time_min:
        params["time_min"] = args.time_min
    if args.time_max:
        params["time_max"] = args.time_max
    status, body, headers = _request(
        ctx, "GET", f"/accounts/{args.account_id}/calendar/free-slots",
        params=params,
    )
    _emit_and_exit(ctx, status, body, headers)


def _cmd_calendar_bulk_respond(ctx: _Ctx, args: argparse.Namespace) -> None:
    responses = _parse_inline_json(args.responses_json, "--responses-json")
    status, body, headers = _request(
        ctx, "POST", f"/accounts/{args.account_id}/bulk/calendar/respond",
        json_body={"responses": responses},
    )
    _emit_and_exit(ctx, status, body, headers)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _split_csv(s: str | None) -> list[str]:
    if not s:
        return []
    return [part.strip() for part in s.split(",") if part.strip()]


def _parse_inline_json(s: str, field: str) -> Any:
    try:
        return json.loads(s)
    except ValueError as e:
        print(f"error: {field} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------

def _bool_flag_or_none(v: str | None) -> bool | None:
    """--enabled / --enabled=false / --enabled=true parsing for tri-state
    PUT payloads where 'field absent' and 'field=false' are distinct."""
    if v is None:
        return None
    return v.strip().lower() in ("1", "true", "yes", "on")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-triage-api",
        description="OpenClaw skill wrapping the email-triage /api/openclaw HTTP API.",
    )
    parser.add_argument("--url", default=None,
                        help="Override EMAIL_TRIAGE_URL (no trailing /api/openclaw).")
    parser.add_argument("--token", default=None,
                        help="Explicit bearer token (overrides --as and users.json).")
    parser.add_argument("--as", dest="as_alias", default=None, metavar="ALIAS",
                        help="Use the token stored under <alias> in users.json. "
                             "Run 'register-me --as <alias> --token et_...' first.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print method/URL/status to stderr before body.")
    parser.add_argument("--compact", action="store_true",
                        help="Compact JSON output (default is pretty-printed).")
    sub = parser.add_subparsers(dest="cmd", metavar="<subcommand>", required=True)

    # -- token-management (local file, no server call) --
    p = sub.add_parser(
        "register-me",
        help="Save a token under an alias in users.json (write-only, no server call).",
    )
    p.add_argument("--as", dest="as_alias", required=True, metavar="ALIAS",
                   help="The alias this agent/user will be known by.")
    p.add_argument("--token", required=True, metavar="TOKEN",
                   help="The et_... token minted in the email-triage UI.")
    p.set_defaults(handler=_cmd_register_me, _no_server=True)

    p = sub.add_parser(
        "forget-me",
        help="Remove a token alias from users.json (local file only).",
    )
    p.add_argument("--as", dest="as_alias", required=True, metavar="ALIAS")
    p.set_defaults(handler=_cmd_forget_me, _no_server=True)

    p = sub.add_parser(
        "list-aliases",
        help="Show which aliases are configured in users.json (values redacted).",
    )
    p.set_defaults(handler=_cmd_list_aliases, _no_server=True)

    # -- accounts --
    p = sub.add_parser("accounts-list", help="List non-HIPAA accounts the token owns.")
    p.set_defaults(handler=_cmd_accounts_list)

    p = sub.add_parser(
        "health",
        help="Install-wide health snapshot (admin-token required).",
    )
    p.set_defaults(handler=_cmd_health)

    p = sub.add_parser("account-quiet-hours",
                       help="Update OpenClaw quiet-hours / pause settings for one account.")
    p.add_argument("account_id", type=int)
    p.add_argument("--enabled", type=_bool_flag_or_none, metavar="true|false")
    p.add_argument("--paused", type=_bool_flag_or_none, metavar="true|false")
    p.add_argument("--start-utc", default=None, help="HH:MM (UTC) — start of quiet window")
    p.add_argument("--end-utc", default=None, help="HH:MM (UTC) — end of quiet window")
    p.set_defaults(handler=_cmd_account_quiet_hours)

    # -- mail --
    p = sub.add_parser("mail-search",
                       help="Structured message search (returns message_ids).")
    p.add_argument("account_id", type=int)
    p.add_argument("--unread", action="store_true")
    p.add_argument("--label", default=None)
    p.add_argument("--folder", default=None)
    p.add_argument("--from", dest="from_", default=None, metavar="ADDR")
    p.add_argument("--to", default=None, metavar="ADDR")
    p.add_argument("--subject", default=None)
    p.add_argument("--after", default=None, metavar="ISO8601")
    p.add_argument("--before", default=None, metavar="ISO8601")
    p.add_argument("--q", default=None, help="Raw provider query syntax (appended).")
    p.add_argument(
        "--limit", type=int, default=5,
        help="Number of message_ids to return. Default 5 — only raise "
             "when the user explicitly asks for a specific quantity.",
    )
    p.set_defaults(handler=_cmd_mail_search)

    p = sub.add_parser("mail-get", help="Fetch one full message.")
    p.add_argument("account_id", type=int)
    p.add_argument("message_id")
    p.set_defaults(handler=_cmd_mail_get)

    # --- Bulk-read (closes the N+1 agent-hallucination gap) ---
    p = sub.add_parser(
        "mail-list",
        help="Bulk-read: filter in, list of summaries out. PREFER this over "
             "mail-search + mail-get in a loop.",
    )
    p.add_argument("account_id", type=int)
    p.add_argument("--unread", action="store_true")
    p.add_argument("--label", default=None)
    p.add_argument("--folder", default=None)
    p.add_argument("--from", dest="from_", default=None, metavar="ADDR")
    p.add_argument("--to", default=None, metavar="ADDR")
    p.add_argument("--subject", default=None)
    p.add_argument("--after", default=None, metavar="ISO8601")
    p.add_argument("--before", default=None, metavar="ISO8601")
    p.add_argument("--q", default=None, help="Raw provider query (appended).")
    p.add_argument(
        "--limit", type=int, default=5,
        help="Number of summaries to return. Default 5 — only raise "
             "when the user explicitly asks for a specific quantity.",
    )
    p.set_defaults(handler=_cmd_mail_list)

    p = sub.add_parser(
        "mail-fetch",
        help="Bulk-read: summaries for an explicit list of message_ids.",
    )
    p.add_argument("account_id", type=int)
    p.add_argument("--message-ids", required=True, dest="message_ids",
                   metavar="ID[,ID]",
                   help="Comma-separated message_ids (usually from a prior "
                        "mail-search call).")
    p.set_defaults(handler=_cmd_mail_fetch)

    p = sub.add_parser(
        "mail-list-full",
        help="Bulk-read: filter in, FULL body_text out. Larger payloads.",
    )
    p.add_argument("account_id", type=int)
    p.add_argument("--unread", action="store_true")
    p.add_argument("--label", default=None)
    p.add_argument("--folder", default=None)
    p.add_argument("--from", dest="from_", default=None, metavar="ADDR")
    p.add_argument("--to", default=None, metavar="ADDR")
    p.add_argument("--subject", default=None)
    p.add_argument("--after", default=None, metavar="ISO8601")
    p.add_argument("--before", default=None, metavar="ISO8601")
    p.add_argument("--q", default=None)
    p.add_argument(
        "--limit", type=int, default=5,
        help="Number of full messages to return. Default 5 (cap 50). "
             "Only raise when the user explicitly asks for more.",
    )
    p.set_defaults(handler=_cmd_mail_list_full)

    p = sub.add_parser("mail-label", help="Apply a label to one message.")
    p.add_argument("account_id", type=int)
    p.add_argument("message_id")
    p.add_argument("label")
    p.set_defaults(handler=_cmd_mail_label)

    p = sub.add_parser("mail-move", help="Move one message to a folder.")
    p.add_argument("account_id", type=int)
    p.add_argument("message_id")
    p.add_argument("folder")
    p.set_defaults(handler=_cmd_mail_move)

    p = sub.add_parser("mail-archive", help="Archive one message.")
    p.add_argument("account_id", type=int)
    p.add_argument("message_id")
    p.set_defaults(handler=_cmd_mail_archive)

    p = sub.add_parser("mail-draft", help="Create a reply draft (never sent).")
    p.add_argument("account_id", type=int)
    p.add_argument("message_id")
    p.add_argument("--to", required=True, metavar="ADDR[,ADDR]")
    p.add_argument("--subject", required=True)
    p.add_argument("--body", required=True)
    p.add_argument("--in-reply-to", default=None, dest="in_reply_to")
    p.add_argument("--thread-id", default=None, dest="thread_id")
    p.set_defaults(handler=_cmd_mail_draft)

    p = sub.add_parser("mail-queue-summary",
                       help="Queue a newsletter/etc. summary for a message.")
    p.add_argument("account_id", type=int)
    p.add_argument("message_id")
    p.add_argument("--category", default=None)
    p.set_defaults(handler=_cmd_mail_queue_summary)

    p = sub.add_parser("mail-bulk",
                       help="Apply one operation to many messages (by ids or filter).")
    p.add_argument("account_id", type=int)
    p.add_argument("--operation", required=True,
                   choices=["label", "move", "archive", "queue_summary"])
    p.add_argument("--args-json", default=None, dest="args_json",
                   help='e.g. \'{"label":"Read"}\' or \'{"folder":"Archive"}\'.')
    p.add_argument("--message-ids", default=None, dest="message_ids",
                   metavar="ID[,ID]")
    p.add_argument("--filter-json", default=None, dest="filter_json",
                   help='MailFilter JSON, e.g. \'{"unread":true,"label":"Inbox"}\'.')
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(handler=_cmd_mail_bulk)

    # -- triage / runs --
    p = sub.add_parser("triage-run",
                       help="Run triage on messages matching a query.")
    p.add_argument("account_id", type=int)
    p.add_argument("--query", default="is:unread")
    p.add_argument("--limit", type=int, default=5)
    p.set_defaults(handler=_cmd_triage_run)

    p = sub.add_parser("runs", help="List recent triage runs (optionally per account).")
    p.add_argument("--account-id", type=int, default=None, dest="account_id")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(handler=_cmd_runs)

    # -- calendar --
    p = sub.add_parser("calendar-list", help="List calendar events in a time window.")
    p.add_argument("account_id", type=int)
    p.add_argument("--time-min", required=True, dest="time_min", metavar="ISO8601")
    p.add_argument("--time-max", required=True, dest="time_max", metavar="ISO8601")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(handler=_cmd_calendar_list)

    p = sub.add_parser("calendar-get", help="Fetch one calendar event.")
    p.add_argument("account_id", type=int)
    p.add_argument("event_id")
    p.set_defaults(handler=_cmd_calendar_get)

    p = sub.add_parser(
        "calendar-fetch",
        help="Bulk-read: fetch many events by event_ids in one call.",
    )
    p.add_argument("account_id", type=int)
    p.add_argument("--event-ids", required=True, dest="event_ids",
                   metavar="ID[,ID]",
                   help="Comma-separated event_ids (usually from a prior "
                        "calendar-list).")
    p.set_defaults(handler=_cmd_calendar_fetch)

    p = sub.add_parser("calendar-create", help="Create a new calendar event.")
    p.add_argument("account_id", type=int)
    p.add_argument("--summary", required=True)
    p.add_argument("--start", required=True, metavar="ISO8601")
    p.add_argument("--end", required=True, metavar="ISO8601")
    p.add_argument("--description", default=None)
    p.add_argument("--location", default=None)
    p.add_argument("--all-day", action="store_true", dest="all_day")
    p.add_argument("--attendees", default=None, metavar="EMAIL[,EMAIL]")
    p.set_defaults(handler=_cmd_calendar_create)

    p = sub.add_parser("calendar-update",
                       help="Patch an existing event; pass only fields to change.")
    p.add_argument("account_id", type=int)
    p.add_argument("event_id")
    p.add_argument("--summary", default=None)
    p.add_argument("--start", default=None, metavar="ISO8601")
    p.add_argument("--end", default=None, metavar="ISO8601")
    p.add_argument("--description", default=None)
    p.add_argument("--location", default=None)
    p.add_argument("--all-day", action="store_true", dest="all_day")
    p.add_argument("--attendees", default=None, metavar="EMAIL[,EMAIL]")
    p.set_defaults(handler=_cmd_calendar_update)

    p = sub.add_parser("calendar-delete", help="Delete a calendar event.")
    p.add_argument("account_id", type=int)
    p.add_argument("event_id")
    p.set_defaults(handler=_cmd_calendar_delete)

    p = sub.add_parser("calendar-respond",
                       help="RSVP to an event (accepted / declined / tentative).")
    p.add_argument("account_id", type=int)
    p.add_argument("event_id")
    p.add_argument("response", choices=["accepted", "declined", "tentative"])
    p.set_defaults(handler=_cmd_calendar_respond)

    p = sub.add_parser("calendar-free-slots",
                       help="Find N free windows of length L respecting working hours + OOO.")
    p.add_argument("account_id", type=int)
    p.add_argument("--length", type=int, default=30,
                   help="Slot length in minutes (5–480).")
    p.add_argument("--count", type=int, default=5,
                   help="Number of slots to return (1–50).")
    p.add_argument("--time-min", default=None, dest="time_min", metavar="ISO8601")
    p.add_argument("--time-max", default=None, dest="time_max", metavar="ISO8601")
    p.set_defaults(handler=_cmd_calendar_free_slots)

    p = sub.add_parser("calendar-bulk-respond",
                       help="RSVP to many events in one call.")
    p.add_argument("account_id", type=int)
    p.add_argument("--responses-json", required=True, dest="responses_json",
                   help='e.g. \'[{"event_id":"abc","response":"accepted"}]\'.')
    p.set_defaults(handler=_cmd_calendar_bulk_respond)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    ctx = _Ctx(args)
    # register-me / forget-me / list-aliases don't call the server, so
    # they skip the URL+token requirement. Handlers mark themselves
    # with _no_server=True via set_defaults.
    if not getattr(args, "_no_server", False):
        ctx.require()
    args.handler(ctx, args)


if __name__ == "__main__":
    main()
