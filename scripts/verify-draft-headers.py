"""Fetch the most recent draft from INBOX.Drafts and print its
From / In-Reply-To / To / Subject headers so a deploy cycle's
draft-creation behaviour can be verified end-to-end.

Run inside the email-triage container.
"""

import asyncio
import sys
from pathlib import Path

from email_triage.config import load_config
from email_triage.web.db import init_db, get_email_account


async def main() -> int:
    account_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    folder = sys.argv[2] if len(sys.argv) > 2 else "INBOX.Drafts"

    config = load_config()
    db_path = Path(config.persistence.db_path)
    conn = init_db(str(db_path))

    from email_triage.secrets import bootstrap_secrets_from_config
    secrets = bootstrap_secrets_from_config(conn, config)
    config.google_oauth.web_client_id = secrets.get("GOOGLE_OAUTH_WEB_CLIENT_ID") or ""
    config.google_oauth.web_client_secret = secrets.get("GOOGLE_OAUTH_WEB_CLIENT_SECRET") or ""

    acct = get_email_account(conn, account_id=account_id)
    print(f"Account: {acct['name']}, drafts folder: {folder}")
    cfg = acct.get("config") or {}
    print(f"  email_address field: {cfg.get('email_address')!r}")
    print(f"  drafts_folder field: {cfg.get('drafts_folder')!r}")
    print(f"  username (LOGIN):    {cfg.get('username')!r}")

    from email_triage.providers.factory import build_provider
    provider = build_provider(acct, secrets)

    # Fetch the most recent draft from the Drafts folder.
    # Use the IMAP search path.
    client = await provider._connect()
    await client.select(provider._quote_mailbox(folder))
    result, data = await client.search("ALL")
    if result != "OK":
        print(f"SEARCH failed: {result}")
        return 1
    uid_str = data[0].decode() if isinstance(data[0], bytes) else data[0]
    uids = uid_str.split()
    if not uids:
        print(f"No drafts in {folder}")
        return 1
    latest_uid = uids[-1]
    print(f"\nLatest draft UID: {latest_uid}")

    # Fetch the raw RFC822 body
    result, data = await client.fetch(latest_uid, "(RFC822)")
    if result != "OK":
        print(f"FETCH failed: {result}")
        return 1

    # data is a list with format like
    #   [b'10 FETCH (RFC822 {1481}', bytearray(b'<body>'), b')']
    # Bytes / bytearray detection across the list — pick the
    # longest entry that contains "From:" — that's the message.
    raw_body = None
    for item in data:
        if isinstance(item, (bytes, bytearray)):
            b = bytes(item)
            if len(b) > 100 and b"From:" in b:
                raw_body = b
                break
    if not raw_body:
        print("Could not extract draft body — printing raw response:")
        for item in data:
            print(type(item).__name__, repr(item)[:200])
        return 1

    import email
    msg = email.message_from_bytes(raw_body)
    print(f"\nFrom: {msg['From']}")
    print(f"To: {msg['To']}")
    print(f"Subject: {msg['Subject']}")
    print(f"Date: {msg['Date']}")
    print(f"In-Reply-To: {msg['In-Reply-To']}")
    print(f"Message-ID: {msg['Message-ID']}")
    print(f"\n--- Plain text body ---")
    import base64
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                print(payload.decode("utf-8", errors="replace"))
            break

    await provider.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
