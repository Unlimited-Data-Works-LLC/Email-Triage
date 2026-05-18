// SW is intentionally minimal — install heuristic only, no caching.
// Caching is forbidden because the browser SW cache is persistent
// and visible to other tabs in scope. Allowlist for any future cache
// MUST exclude /dashboard, /accounts, /runs, /triage, and any other
// PHI-touching path.
//
// The browser's PWA-install prompt requires a registered service
// worker at root scope plus a manifest plus 192/512 icons. This file
// satisfies the registration requirement and nothing else: install +
// activate immediately, then pass every fetch through to the network
// untouched.

self.addEventListener("install", function (event) {
  // skipWaiting() makes the new SW take over right away on first
  // install; otherwise the page would have to be reloaded once before
  // the SW activates. No cached data exists yet, so there's nothing
  // to migrate.
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  // clients.claim() makes the SW control already-open tabs without
  // requiring a reload. Same rationale as skipWaiting().
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", function (event) {
  // Pass-through. No respondWith() = the browser handles the request
  // exactly as if no SW were registered. Required for the install
  // heuristic on Chrome/Edge — the SW must register a fetch handler,
  // even if it does nothing. Do NOT add caching here without
  // re-reading the comment block at the top of this file.
});
