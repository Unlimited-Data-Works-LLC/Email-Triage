// Auto-attach X-CSRF-Token header on every state-changing fetch().
//
// PR 8 / D1 follow-up: the CsrfMiddleware validates an X-CSRF-Token
// header on POST/PUT/PATCH/DELETE. This shim:
//
// 1. Pre-fetches a token from /api/csrf-token on page load (cached
//    for the lifetime of the page).
// 2. Patches window.fetch so any state-changing call automatically
//    carries the header without each call site having to plumb it.
// 3. Listens for `htmx:configRequest` so HTMX-driven calls (which
//    use XHR, not window.fetch, and would otherwise bypass the shim
//    entirely) also carry the header. (#83.1)
// 4. Exposes ``window.ETCsrfToken`` (always-current cached value)
//    and ``window.ETCsrfReady`` (a Promise that resolves to the
//    token) so legacy inline JS that already mints its own
//    request can synchronise on the shim instead of building a
//    parallel cookie-reading fallback. (#83.4)
//
// Form-body POSTs (plain HTML form, no JS) are covered by the
// server-side receive-buffering enhancement landed alongside this
// file -- the middleware reads the body once, peeks at the
// `csrf_token` form field, and replays the body to the downstream
// handler unchanged. Templates that submit via form (not fetch)
// still need to render a hidden `csrf_token` field for that path
// to work; the renderer-side helper is `web/csrf.py:csrf_input`.
//
// Soft-launch: this file's failure modes (token fetch fails, network
// error, etc.) are silent. The middleware has its own enforce flag
// (default False); a missing header in soft-launch logs + counts but
// the request proceeds. Operator monitors the counter via /health.
//
// Cardinality discipline: one token per session. Re-fetched only if
// the current one becomes invalid (server bumped session_secret, key
// rotation, etc.). The token is a base64-ish opaque blob; never log
// it on the client side.

(function() {
  "use strict";

  let cachedToken = null;
  let inflight = null;

  async function fetchTokenOnce() {
    if (cachedToken) return cachedToken;
    if (inflight) return inflight;
    inflight = (async function() {
      try {
        const resp = await origFetch.call(window, "/api/csrf-token", {
          credentials: "same-origin",
        });
        if (resp && resp.ok) {
          const body = await resp.json();
          if (body && body.token) {
            cachedToken = body.token;
            // Also expose synchronously for inline JS that prefers a
            // direct read over awaiting a promise. Refreshed every
            // time we resolve a fresh token, so the global stays
            // current across stale-token retries.
            window.ETCsrfToken = cachedToken;
          }
        }
      } catch (e) {
        // Soft-launch: silent. The /health csrf_rejects counter
        // is the operator's signal.
      }
      inflight = null;
      return cachedToken;
    })();
    return inflight;
  }

  // Reset the cache if the server signals an expired token (HTTP
  // 403 with the documented body shape). One retry per response.
  function isStaleTokenSignal(resp) {
    return resp && resp.status === 403;
  }

  const STATE_CHANGING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
  const origFetch = window.fetch.bind(window);

  window.fetch = async function patchedFetch(input, init) {
    init = init || {};
    let method = init.method;
    if (!method && typeof input === "object" && input && input.method) {
      method = input.method;
    }
    method = (method || "GET").toUpperCase();

    if (!STATE_CHANGING.has(method)) {
      return origFetch(input, init);
    }

    const token = await fetchTokenOnce();
    if (!token) {
      // Couldn't fetch a token — let the request go through; the
      // middleware will handle it per its enforce flag (soft-launch
      // counts the rejection and proceeds; enforce returns 403).
      return origFetch(input, init);
    }

    const headers = new Headers(
      init.headers || (typeof input === "object" && input && input.headers) || {}
    );
    if (!headers.has("X-CSRF-Token")) {
      headers.set("X-CSRF-Token", token);
    }
    init.headers = headers;

    const resp = await origFetch(input, init);
    if (isStaleTokenSignal(resp)) {
      // Refresh once and retry — covers session_secret rotation
      // mid-tab without the user having to reload the page.
      cachedToken = null;
      window.ETCsrfToken = null;
      const fresh = await fetchTokenOnce();
      if (fresh && fresh !== token) {
        headers.set("X-CSRF-Token", fresh);
        init.headers = headers;
        return origFetch(input, init);
      }
    }
    return resp;
  };

  // Bridge for plain HTML form submits. <form method="post"> doesn't
  // go through window.fetch, so the patched fetch above doesn't see
  // it. We listen for `submit` at document level (capture phase) and
  // inject a hidden csrf_token field with the cached token before the
  // browser serializes the form. The server-side middleware reads the
  // field from the body. (#83.2)
  //
  // Skips:
  //   * non-POST forms (GET / dialog) -- safe methods don't need it.
  //   * forms with action paths in the exempt set (best-effort -- the
  //     server-side middleware enforces the real exempt list, this
  //     just avoids inserting a useless field).
  //   * forms that already have a csrf_token field (template-rendered
  //     server-side -- preserve operator's value).
  function isExemptAction(action) {
    if (!action) return false;
    return /\/(health|webhooks\/|api\/oauth\/|login)/.test(action);
  }
  document.addEventListener("submit", function(evt) {
    try {
      const form = evt.target;
      if (!form || form.tagName !== "FORM") return;
      const method = (form.method || "GET").toUpperCase();
      if (method !== "POST") return;
      if (isExemptAction(form.getAttribute("action") || "")) return;
      if (form.querySelector('input[name="csrf_token"]')) return;
      const token = cachedToken;
      if (!token) return;
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "csrf_token";
      input.value = token;
      form.appendChild(input);
    } catch (e) {
      // Soft-launch: silent. Server-side counter is the signal.
    }
  }, true);  // capture so we run BEFORE the form serializes

  // Bridge for HTMX. HTMX uses XMLHttpRequest, not window.fetch, so
  // the patched fetch above doesn't intercept it. The shim listens
  // for `htmx:configRequest` -- HTMX's documented hook for adding
  // headers to outgoing requests -- and injects the token there.
  // No-op for safe methods because HTMX dispatches the event for
  // every request type; we filter on the verb the same way the
  // fetch path does.
  document.addEventListener("htmx:configRequest", function(evt) {
    try {
      const verb = (evt.detail.verb || "").toUpperCase();
      if (!STATE_CHANGING.has(verb)) return;
      const token = cachedToken;
      if (!token) return;
      if (!evt.detail.headers) evt.detail.headers = {};
      if (!evt.detail.headers["X-CSRF-Token"]) {
        evt.detail.headers["X-CSRF-Token"] = token;
      }
    } catch (e) {
      // Soft-launch: any failure is silent. Middleware counter
      // surfaces the rejection.
    }
  });

  // Pre-fetch on script load so the token is ready by the time the
  // user's first state-changing action fires. Expose the in-flight
  // promise so callers can ``await window.ETCsrfReady`` instead of
  // racing the page-load fetch.
  window.ETCsrfReady = fetchTokenOnce();
})();
