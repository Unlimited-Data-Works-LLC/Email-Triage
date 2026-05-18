/*
 * #124 — PWA install-prompt surface.
 *
 * Browsers that implement the install heuristic (Chrome / Edge /
 * Brave on desktop + Android) fire a `beforeinstallprompt` event on
 * window when the page is installable. The event has a `prompt()`
 * method that surfaces the OS-native install dialog — but only if
 * called inside a user gesture (click). So the protocol is:
 *
 *   1. Stash the event when it fires.
 *   2. Reveal a UI button.
 *   3. On click, call event.prompt(), wait for the user's choice,
 *      then drop the stashed event (browsers fire beforeinstallprompt
 *      again only after a hard refresh + cache invalidation).
 *
 * iOS Safari does NOT implement beforeinstallprompt (Apple ships
 * Add-to-Home-Screen via the Share sheet only). For iOS we render
 * an instruction line instead of a button. UA-sniff is good-enough
 * for an install-prompt surface — false positives just see slightly
 * different copy.
 *
 * Dismissal is sticky via localStorage (key 'pwaInstallChoice') so
 * the button doesn't re-prompt after the user has either installed
 * the app or said "no thanks". Cleared by clearing browser storage
 * — same as any other per-site preference.
 *
 * Markup contract — the host page provides:
 *
 *   <div data-pwa-install hidden>
 *     <button data-pwa-install-trigger>Install</button>
 *     <div data-pwa-install-ios hidden>iOS instructions ...</div>
 *     <div data-pwa-install-installed hidden>Already installed ...</div>
 *   </div>
 *
 * The script reveals the host wrapper + the right child for the
 * platform. It never renders new DOM, so the host page keeps full
 * control of layout + tooltips.
 */

(function () {
  "use strict";

  var STORAGE_KEY = "pwaInstallChoice";

  function getRoot() {
    return document.querySelector("[data-pwa-install]");
  }

  function isIOS() {
    // iPhone / iPad / iPod. iPadOS 13+ identifies as Mac in UA — so
    // also catch macOS-with-touch (the current iPad signature).
    var ua = navigator.userAgent || "";
    if (/iPhone|iPad|iPod/.test(ua)) return true;
    if (/Mac/.test(ua) && navigator.maxTouchPoints && navigator.maxTouchPoints > 1) return true;
    return false;
  }

  function isStandalone() {
    // The display-mode media query is the modern signal for "running
    // as an installed PWA". navigator.standalone is the iOS-Safari
    // legacy property — also worth checking.
    if (window.matchMedia && window.matchMedia("(display-mode: standalone)").matches) {
      return true;
    }
    if (window.navigator && window.navigator.standalone) {
      return true;
    }
    return false;
  }

  function getStoredChoice() {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      return null;
    }
  }

  function setStoredChoice(value) {
    try {
      localStorage.setItem(STORAGE_KEY, value);
    } catch (e) { /* private mode; non-fatal */ }
  }

  function show(el) { if (el) el.hidden = false; }
  function hide(el) { if (el) el.hidden = true; }

  function setup() {
    var root = getRoot();
    if (!root) return;  // host page didn't include the install card

    var trigger = root.querySelector("[data-pwa-install-trigger]");
    var iosBlock = root.querySelector("[data-pwa-install-ios]");
    var installedBlock = root.querySelector("[data-pwa-install-installed]");

    // Already running as an installed PWA — surface a friendly
    // "you're using the installed app" note, not a duplicate prompt.
    if (isStandalone()) {
      hide(trigger);
      hide(iosBlock);
      show(installedBlock);
      show(root);
      return;
    }

    // User already accepted or dismissed in a prior visit — keep
    // the surface hidden so we don't nag.
    var prior = getStoredChoice();
    if (prior === "accepted" || prior === "dismissed") {
      hide(root);
      return;
    }

    // iOS: no programmatic install API. Show the Share-sheet hint
    // straight away (no event to wait for).
    if (isIOS()) {
      hide(trigger);
      show(iosBlock);
      show(root);
      // Allow the user to dismiss the iOS hint persistently.
      var iosDismiss = root.querySelector("[data-pwa-install-ios-dismiss]");
      if (iosDismiss) {
        iosDismiss.addEventListener("click", function () {
          setStoredChoice("dismissed");
          hide(root);
        });
      }
      return;
    }

    // Desktop / Android Chrome path: wait for the browser to tell us
    // the page is installable, then reveal the button.
    var deferred = null;

    window.addEventListener("beforeinstallprompt", function (ev) {
      // Stop the browser's mini-infobar — we render our own UI.
      ev.preventDefault();
      deferred = ev;
      if (trigger) {
        trigger.disabled = false;
        show(trigger);
      }
      show(root);
    });

    if (trigger) {
      trigger.addEventListener("click", function () {
        if (!deferred) return;  // event hasn't fired yet — nothing to prompt
        // Disable to prevent double-clicks while the OS dialog is up.
        trigger.disabled = true;
        deferred.prompt();
        deferred.userChoice.then(function (choice) {
          var outcome = (choice && choice.outcome) || "dismissed";
          setStoredChoice(outcome);  // 'accepted' or 'dismissed'
          deferred = null;
          // Either way, hide the surface — we don't re-prompt this session.
          hide(root);
        }).catch(function () {
          // Some browsers reject userChoice if the dialog is cancelled
          // by the OS. Treat as dismissed.
          setStoredChoice("dismissed");
          deferred = null;
          hide(root);
        });
      });
    }

    // Listen for `appinstalled` so we update state if the user
    // installs through some other entry point (URL-bar icon, OS menu)
    // while the page is open.
    window.addEventListener("appinstalled", function () {
      setStoredChoice("accepted");
      deferred = null;
      hide(trigger);
      hide(iosBlock);
      show(installedBlock);
      show(root);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setup);
  } else {
    setup();
  }
})();
