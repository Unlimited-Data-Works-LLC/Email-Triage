/* WebAuthn helper: thin wrapper around navigator.credentials for the
 * /profile/hardware-keys self-service registration UI and the login
 * page's "touch your security key" step.
 *
 * No external deps. Uses the WebAuthn JSON encoding (the
 * native PublicKeyCredential parsing in modern browsers; fallback
 * b64url encoding for older browsers handled inline).
 */
window.ETWebAuthn = (function () {
    function b64urlToBytes(s) {
        s = s.replace(/-/g, "+").replace(/_/g, "/");
        while (s.length % 4) s += "=";
        const raw = atob(s);
        const out = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    }
    function bytesToB64url(bytes) {
        let s = "";
        const a = new Uint8Array(bytes);
        for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
        return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function decodeOptions(opts, idFields) {
        // Decode b64url fields server emits as JSON.
        opts.challenge = b64urlToBytes(opts.challenge);
        if (opts.user && opts.user.id) {
            opts.user.id = b64urlToBytes(opts.user.id);
        }
        for (const list of [opts.allowCredentials, opts.excludeCredentials]) {
            if (Array.isArray(list)) {
                for (const c of list) {
                    if (typeof c.id === "string") c.id = b64urlToBytes(c.id);
                }
            }
        }
        return opts;
    }

    function encodeAttestation(cred) {
        return {
            id: cred.id,
            rawId: bytesToB64url(cred.rawId),
            type: cred.type,
            response: {
                attestationObject: bytesToB64url(cred.response.attestationObject),
                clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
                transports: cred.response.getTransports ? cred.response.getTransports() : [],
            },
            clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
        };
    }
    function encodeAssertion(cred) {
        return {
            id: cred.id,
            rawId: bytesToB64url(cred.rawId),
            type: cred.type,
            response: {
                authenticatorData: bytesToB64url(cred.response.authenticatorData),
                clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
                signature: bytesToB64url(cred.response.signature),
                userHandle: cred.response.userHandle ? bytesToB64url(cred.response.userHandle) : null,
            },
            clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
        };
    }

    async function registerHardwareKey(nickname) {
        const beginResp = await fetch("/profile/hardware-keys/register/begin", {
            method: "POST",
        });
        if (!beginResp.ok) {
            const err = await beginResp.json().catch(() => ({}));
            throw new Error(err.error || ("Begin failed: HTTP " + beginResp.status));
        }
        const opts = decodeOptions(await beginResp.json());
        const cred = await navigator.credentials.create({publicKey: opts});
        const attestation = encodeAttestation(cred);
        const finishResp = await fetch("/profile/hardware-keys/register/finish", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({nickname: nickname, response: attestation}),
        });
        if (!finishResp.ok) {
            const err = await finishResp.json().catch(() => ({}));
            throw new Error(err.error || ("Finish failed: HTTP " + finishResp.status));
        }
        return await finishResp.json();
    }

    async function loginWithHardwareKey(email) {
        const fd = new FormData();
        fd.append("email", email);
        const beginResp = await fetch("/login/webauthn/begin", {
            method: "POST", body: fd,
        });
        if (!beginResp.ok) {
            const err = await beginResp.json().catch(() => ({}));
            throw new Error(err.error || "no_credential");
        }
        const opts = decodeOptions(await beginResp.json());
        const cred = await navigator.credentials.get({publicKey: opts});
        const assertion = encodeAssertion(cred);
        const finishResp = await fetch("/login/webauthn/finish", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({email: email, response: assertion}),
        });
        if (!finishResp.ok) {
            const err = await finishResp.json().catch(() => ({}));
            throw new Error(err.error || "verify_failed");
        }
        return await finishResp.json();
    }

    return {
        registerHardwareKey: registerHardwareKey,
        loginWithHardwareKey: loginWithHardwareKey,
    };
})();
