/* base64url helpers — SSOT.
 *
 * Extracted from the three hand-rolled copies at:
 *  - src/email_triage/web/static/webauthn.js:10 (b64urlToBytes/bytesToB64url)
 *  - src/email_triage/web/templates/login.html:81 (inline b64ToBuf/bufToB64)
 *  - src/email_triage/web/templates/login_dev_keypair.html:107 (four helpers)
 *
 * Purpose: one canonical URL-safe base64 (RFC 4648 §5) encode/decode pair
 * used by WebAuthn (challenge/allowCredentials.id + assertion response
 * fields) plus a plain-base64 pair used by the dev-keypair signature +
 * PEM handling. Namespaced as `window.ETBase64` so pages can include one
 * <script> and get consistent behavior — no more drift where webauthn.js
 * pads-then-decodes while a template variant .padEnd()-then-decodes with
 * a subtly different modulo.
 *
 * Mirror-of Python SSOT: `email_triage._base64url`.
 * The Python side lands the pin at tests/test_base64url_ssot_pin.py; the
 * JS side needs a separate harness (grep-based test in Python — see the
 * companion structural pin for the JS class).
 *
 * No external deps. Uses the browser's `atob`/`btoa` primitives.
 */
(function () {
    "use strict";

    // ------------------------------------------------------------------
    // URL-safe base64 (RFC 4648 §5) — the WebAuthn wire format.
    // ------------------------------------------------------------------

    /* Decode a URL-safe base64 string (unpadded OR padded) to a Uint8Array.
     * Input may contain `-` / `_` in place of `+` / `/`, and may omit the
     * trailing `=` padding per RFC 4648 §5. Whitespace is NOT stripped
     * (WebAuthn payloads never contain whitespace; use `decodeBase64ToBytes`
     * for the dev-keypair PEM path which does need whitespace stripping).
     */
    function b64urlToBytes(s) {
        s = s.replace(/-/g, "+").replace(/_/g, "/");
        while (s.length % 4) s += "=";
        var raw = atob(s);
        var out = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    }

    /* Encode a Uint8Array (or ArrayBuffer) to a URL-safe base64 string
     * WITHOUT padding — the WebAuthn wire shape.
     */
    function bytesToB64url(bytes) {
        var s = "";
        var a = new Uint8Array(bytes);
        for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
        return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    // ------------------------------------------------------------------
    // Plain base64 — used by the dev-keypair signature + PEM path.
    // ------------------------------------------------------------------

    /* Encode a Uint8Array (or ArrayBuffer) to a plain (padded, +/-neutral)
     * base64 string. NOT URL-safe. Used by login_dev_keypair.html for the
     * signature field that ships back to the server.
     */
    function bytesToB64(bytes) {
        var s = "";
        var a = new Uint8Array(bytes);
        for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
        return btoa(s);
    }

    /* Decode a plain (padded) base64 string with whitespace tolerated —
     * used by the dev-keypair PEM path to strip line breaks between
     * `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----`.
     */
    function decodeBase64ToBytes(b64) {
        var raw = atob(b64.replace(/\s+/g, ""));
        var out = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    }

    window.ETBase64 = {
        b64urlToBytes: b64urlToBytes,
        bytesToB64url: bytesToB64url,
        bytesToB64: bytesToB64,
        decodeBase64ToBytes: decodeBase64ToBytes,
    };
})();
