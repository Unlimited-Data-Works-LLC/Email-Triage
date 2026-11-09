"""N-258 R26 — canonical JSON SSOT for HMAC signing (2026-07-03).

Census R26 discovered MED (canonical-JSON signing recipes, 7+ distinct
recipes): non-frozen HMAC-signed surfaces (webhook fire + watch_runner
+ audit-detail Recipe-C sites) used
`json.dumps(payload, separators=(",", ":"))` with NO `sort_keys=True`.
Consequence: dict-order variance means bytes fed to `hmac.new(...)`
differ across Python versions / dict-insertion orders → receivers
re-computing the signature can NEVER reliably match.

The frozen audit-chain forms in `db/audit.py` deliberately use their
own recipes (checksummed migration bodies, backwards-compat) and are
EXCLUDED from the SSOT — this module owns ONLY the non-frozen family.

Contract:
    canonical_json(payload) -> bytes

    * `sort_keys=True` — deterministic key order.
    * `separators=(",", ":")` — no ambient whitespace.
    * `ensure_ascii=False` — no `\\u` escaping of non-ASCII; matches
      the wire shape most HMAC-verifying receivers expect.
    * `.encode("utf-8")` — bytes for direct `hmac.new(...)` feeding.

Callers that feed bytes to `hmac.new(key, canonical, hashlib.sha256)`
outside `db/audit.py` chain-writers MUST route through this SSOT.
"""
from __future__ import annotations

import json
from typing import Any


def canonical_json(payload: Any) -> bytes:
    """Serialise ``payload`` into deterministic bytes for HMAC signing.

    Deterministic key order + tight separators + UTF-8 = a receiver that
    re-serialises the parsed payload with the same helper gets the
    EXACT same bytes. Non-deterministic key order or ambient whitespace
    breaks signature-verification handshakes across Python versions,
    receivers, and re-encoders.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
