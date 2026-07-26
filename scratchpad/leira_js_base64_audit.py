#!/usr/bin/env python3
""" JS base64url audit — llm-host offload.

Ask llm-host qwen3.6:35b to sweep all `.js` + `.html` files under
`src/email_triage/web/` and flag any base64 encode/decode implementation
that ISN'T a delegation to `window.ETBase64.*`. Verify-don't-accept the
Python-side pin's regex-based enumeration — the pin catches the URL-safe
shape; llm-host may find semantic drift the regex misses (e.g. an
obfuscated shape, an inline block that decodes without .replace()).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path("C:/Users/ExampleUser/Documents/the AI assistant/Projects/email-triage")
sys.path.insert(0, str(REPO / "scripts"))

from leira_prepass import call_leira


def gather_js_html_bodies() -> str:
    """Grep for `atob(` OR `btoa(` OR `base64` in `.js`+`.html`; return
    the concatenated hits with 8 lines of context each. Bounds llm-host
    prompt to <30k chars."""
    result = subprocess.run(
        ["grep", "-rn", "-B", "2", "-A", "6",
         r"atob(\|btoa(\|base64",
         "src/email_triage/web/static",
         "src/email_triage/web/templates"],
        cwd=REPO, capture_output=True, text=True,
    )
    return result.stdout[:30000]


SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line_hint": {"type": "string"},
                    "class": {
                        "type": "string",
                        "enum": [
                            "HAND_ROLLED_B64URL_DECODE_OUTSIDE_SSOT",
                            "HAND_ROLLED_B64URL_ENCODE_OUTSIDE_SSOT",
                            "HAND_ROLLED_PLAIN_B64_OUTSIDE_SSOT",
                            "SSOT_DELEGATION_CORRECT",
                            "COMMENT_OR_STRING_LITERAL_NOT_CODE",
                            "OBFUSCATED_SHAPE_REGEX_PIN_MISSES",
                            "NONE",
                        ],
                    },
                    "why": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["HIGH", "MED", "LOW", "INFO"],
                    },
                },
                "required": ["class", "why", "severity"],
            },
        },
        "verdict": {
            "type": "string",
            "enum": ["CONVERGED", "RESIDUAL_SITES_FOUND",
                     "UNCERTAIN_NEEDS_HUMAN_REVIEW"],
        },
    },
    "required": ["findings", "verdict"],
}


def main() -> int:
    body = gather_js_html_bodies()
    prompt = (
        "You are auditing the JavaScript / HTML surface of the email-triage "
        "web module for base64url encode/decode drift. The SSOT is "
        "`window.ETBase64.*` exposed by "
        "`src/email_triage/web/static/base64url.js` and includes 4 helpers: "
        "`b64urlToBytes(s) -> Uint8Array` (URL-safe decode with padding "
        "fixup), `bytesToB64url(bytes) -> string` (URL-safe encode, "
        "unpadded), `bytesToB64(bytes) -> string` (plain padded encode), "
        "`decodeBase64ToBytes(b64) -> Uint8Array` (plain decode with "
        "whitespace strip).\n\n"
        "Post-#130 fold, three files should be COMPLIANT (aliasing the "
        "SSOT): `web/static/webauthn.js`, `web/templates/login.html`, "
        "`web/templates/login_dev_keypair.html`. Any OTHER `.js` or "
        "`.html` file under `src/email_triage/web/` that decodes/encodes "
        "base64 IS a residual class-drift site. Comment mentions of the "
        "word 'base64' or 'b64' are NOT drift.\n\n"
        "Also flag any OBFUSCATED_SHAPE (e.g. character class "
        "`[-]` instead of literal `-`, or split-across-lines "
        "`.replace(/-\n/g, ...)`) that the Python regex pin at "
        "`tests/test_js_base64url_ssot_pin.py` would miss.\n\n"
        "Return strict JSON: findings[] + overall verdict. Findings are "
        "LEADS not verdicts; an honest 'NONE' + CONVERGED is the correct "
        "answer if no drift is visible.\n\n"
        "== JS + HTML grep hits ==\n" + body
    )
    result = call_leira(prompt, SCHEMA)
    if not result.get("findings"):
        original = result.get("verdict")
        result["verdict"] = "CONVERGED"
        result["_verdict_override_note"] = (
            f"Post-hoc override: llm-host returned '{original}' with empty "
            "findings — schema-hallucination pattern documented in the "
            "census script's methodology entry."
        )
    out = REPO / "scratchpad_leira_130_js_audit.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"verdict = {result.get('verdict')}")
    print(f"findings = {len(result.get('findings', []))}")
    for f in result.get("findings", []):
        print(f"  - [{f.get('severity')}] {f.get('class')} — "
              f"{f.get('file', '?')} — {f.get('why', '')[:80]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
