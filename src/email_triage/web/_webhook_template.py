"""Per-target webhook body reshaper (SSOT).

The Outbound event webhooks system emits our envelope
``{"event", "timestamp", "data": {...}}`` (canonical-JSON + HMAC-signed)
by default — that is the ``custom`` target-type. For **typed** targets
(Slack / PagerDuty / Opsgenie / Discord / Teams and future additions)
the receiver expects its own top-level shape; this module owns the
one-way reshape from our envelope to the receiver's wire bytes.

Design:

* ``render_for_target(envelope, target, is_hipaa, resolved_secret)`` is
  the ONE call site every fire path uses. ``web/events.py::_deliver``
  routes through it; the count-agnostic structural pin
  ``tests/test_webhook_reshaper_ssot_pin.py`` pins that seam so a
  future POST can't quietly bypass the reshaper (Prime Directive #1).
* Templating is **substitution-only** — ``{{path.to.field}}`` walks the
  render context (``event``, ``timestamp``, ``data.*``) with
  ``.``-separated keys; a missing key resolves to the empty string
  (Mustache convention). No iteration, no partials, no logic — the
  smallest surface that satisfies the five built-in target shapes.
* All substitutions are JSON-string escaped by default — every built-in
  target body is JSON, so an unescaped ``"`` or newline in a subject
  would corrupt the payload.
* **The ``{{secret}}`` binding is HEADER-CONTEXT-ONLY.** SME-panel
  2026-07-15 DA finding: an operator body_template
  ``'{"x":"{{secret}}"}'`` would exfiltrate the HMAC signing key over
  the wire on every fire. Body render context is now envelope-only.
  Parse-time refusal in ``config._parse_webhooks`` is the belt; this
  is the suspenders.
* **HIPAA lock** — when the target's account is HIPAA-flagged, the
  operator template is IGNORED and a minimal
  ``{event, category, timestamp, flow_id}`` shape is emitted. This is
  defense-in-depth atop the existing ``_FORBIDDEN_KEYS`` guard at
  ``web/events.py:509``; a HIPAA target cannot leak PHI through a
  hand-edited template. Enforcement emits an INFO log carrying
  ``flow_id``, ``target_type``, and ``url_host`` (netloc, no path) so
  §164.312(b) audit controls are observable — no silent enforcement.
* **Fail-closed required fields** — each typed target-type declares a
  ``required_fields`` list in the registry; a missing field refuses
  the send (``RequiredFieldMissing`` raised, caller drops the
  delivery + logs at WARNING). Prime Directive #8: security controls
  fail CLOSED, never silently ship an empty ``routing_key``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from email_triage._signing import canonical_json
from email_triage.triage_logging import get_logger


logger = get_logger("email_triage.web._webhook_template")

_MISSING = ""


# ---------------------------------------------------------------------------
# `{{secret}}` refusal SSOT
# ---------------------------------------------------------------------------
#
# Prime Directive #5 (no mirrored predicate lists) + SME-panel 2026-07-15
# DA-F1 fold from task  drive: the ``{{secret}}`` refusal used to live
# hand-rolled at three sites (``config._parse_webhooks`` parse-time,
# ``web/routers/integrations.py`` wizard-save, ``web/routers/integrations.py``
# live-preview). A future tightening (case-insensitive ``{{SECRET}}``,
# ``{{secret.subkey}}`` future-proof, template-comment tolerance) would
# inevitably drift one site behind the other two — the exact CIDI drift the
# playbook forbids. This module is the ONE public surface; callers import
# :func:`refuses_secret_binding` and get the same verdict + the same operator-
# facing message.
_SECRET_BINDING_RE = re.compile(r"\{\{\s*secret\s*\}\}")

SECRET_BINDING_REFUSAL_MESSAGE = (
    "webhook body_template must NOT reference {{secret}} — the target's "
    "signing/auth secret is header-context-only. If your target-type needs "
    "the secret in the body, register it in _webhook_target_types.py."
)


def refuses_secret_binding(body_template: str | None) -> str | None:
    """Return the canonical refusal message when ``body_template`` references
    ``{{secret}}`` (whitespace-tolerant), else ``None``.

    SSOT for the three refusal call-sites (parse-time YAML load, wizard
    save, wizard live-preview). Callers do::

        err = refuses_secret_binding(body_template)
        if err:
            raise ConfigError(err)            # parse-time
            # OR set save_error = err          # wizard save
            # OR set template_error = err      # wizard preview

    so a future tightening (case-insensitive, nested path, comment-tolerant)
    lands in this function and every site inherits.
    """
    if body_template is None:
        return None
    if _SECRET_BINDING_RE.search(body_template):
        return SECRET_BINDING_REFUSAL_MESSAGE
    return None


class RequiredFieldMissing(Exception):
    """Raised when a target-type declares a required field that is not
    present (non-empty) in the envelope's ``data`` at render time. The
    caller (``web/events.py::_deliver``) catches this and drops the
    delivery with a WARNING — never ships a body missing a mandatory
    field (Prime Directive #8, fail-closed)."""


def _lookup(context: dict[str, Any], path: str) -> str:
    """Walk a dot-separated path through ``context``.

    ``data.subject`` → ``context["data"]["subject"]``. Missing key at
    any level → the empty string (Mustache convention). Non-str leaves
    are ``str()``-coerced.
    """
    node: Any = context
    for part in path.strip().split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return _MISSING
    if node is None:
        return _MISSING
    return str(node)


def _json_escape(s: str) -> str:
    """Return ``s`` escaped for inclusion inside a JSON string literal.

    ``json.dumps(s, ensure_ascii=True)`` renders U+2028 / U+2029 / all
    control chars as ``\\uXXXX`` — required for downstream JavaScript
    parsers that historically treat U+2028 / U+2029 as literal line
    terminators. The ``ensure_ascii=True`` literal is pinned by
    ``tests/test_webhook_render_for_target.py::
    test_json_escape_forces_ensure_ascii`` so a future perf micro-optim
    can't silently regress this.
    """
    return json.dumps(s, ensure_ascii=True)[1:-1]


def _substitute(template: str, context: dict[str, Any]) -> str:
    """Replace every ``{{path.to.field}}`` placeholder in ``template``.

    Every substitution is JSON-string escaped so the rendered output
    remains valid JSON when the template writes placeholders inside
    JSON string values (the case for every built-in target).
    """
    out: list[str] = []
    i = 0
    n = len(template)
    while i < n:
        j = template.find("{{", i)
        if j < 0:
            out.append(template[i:])
            break
        out.append(template[i:j])
        k = template.find("}}", j + 2)
        if k < 0:
            out.append(template[j:])
            break
        path = template[j + 2:k]
        out.append(_json_escape(_lookup(context, path)))
        i = k + 2
    return "".join(out)


def _hipaa_locked_bytes(envelope: dict[str, Any]) -> bytes:
    """Minimal HIPAA-safe wire shape.

    Regardless of the operator's template, a HIPAA-flagged target
    receives ONLY ``{event, category, timestamp, flow_id}``. Defense-
    in-depth atop the ``_FORBIDDEN_KEYS`` guard in ``web/events.py``.

    ``event`` is a fixed enum (``notification`` / ``triage.completed``)
    with no PHI risk — included so receivers can discriminate. The
    timestamp is dispatcher-authoritative (envelope top-level) — the
    ``data.timestamp`` field is NOT read (a future caller could
    populate it from PHI-time e.g. encounter/appointment time).
    """
    data = envelope.get("data") or {}
    minimal = {
        "event": envelope.get("event", ""),
        "category": data.get("category", ""),
        "timestamp": envelope.get("timestamp", ""),
        "flow_id": data.get("flow_id", ""),
    }
    return canonical_json(minimal)


def _url_host(url: str) -> str:
    """Return the netloc of ``url`` (no scheme, no path, no query).

    Used for HIPAA-lock audit log lines — the full URL could carry
    path-encoded secrets (Slack webhook URLs bake the token into the
    path), the netloc alone is safe to log.
    """
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc or "<no-netloc>"
    except Exception:
        return "<parse-error>"


def _validate_required_fields(target_type: str, envelope: dict[str, Any]) -> None:
    """Fail-closed check that every field a target-type declares
    ``required`` is present + non-empty in ``envelope.data`` at render
    time. Raises :class:`RequiredFieldMissing` on the first missing
    field — the caller drops the delivery + logs.
    """
    from email_triage.web._webhook_target_types import TARGET_TYPES
    entry = TARGET_TYPES.get(target_type)
    if entry is None:
        return
    required = entry.get("required_fields") or ()
    data = envelope.get("data") or {}
    for field in required:
        if not data.get(field):
            raise RequiredFieldMissing(
                f"target_type={target_type!r} requires data.{field}; "
                f"got empty/missing"
            )


def render_for_target(
    envelope: dict[str, Any],
    target: Any,
    *,
    is_hipaa: bool = False,
    resolved_secret: str = "",
    _suppress_audit_log: bool = False,
) -> bytes:
    """Reshape our envelope into the bytes the target's receiver expects.

    Parameters
    ----------
    envelope:
        Our canonical outbound shape:
        ``{"event": str, "timestamp": str, "data": {...}}``.
    target:
        A ``WebhookTarget`` (or duck-typed object) carrying
        ``target_type`` (str) + ``body_template`` (str | None).
    is_hipaa:
        HIPAA lock — when True the operator template is IGNORED and a
        minimal metadata shape is emitted; an INFO log line
        (``event_class="hipaa_webhook_lock_enforced"``) records the
        enforcement for §164.312(b) audit purposes.
    resolved_secret:
        The plaintext value of the target's ``secret_key`` (already
        resolved by the caller). Passed through to
        :func:`render_headers_for_target` — NEVER bound into the body
        render context (SME-panel 2026-07-15 DA finding: an operator
        template ``{{secret}}`` in the body would ship the HMAC key
        over the wire; parse-time refusal in
        ``config._parse_webhooks`` is the belt, this scoping is the
        suspenders).
    _suppress_audit_log:
        Opt-in for RENDER-ONLY paths that must reuse the same SSOT
        without polluting the audit log with non-enforcement events.
        Consumed by the admin-only wizard live-preview
        (``admin_integrations_webhook_preview``) which fires this
        function per keystroke — logging every preview would drown the
        genuine emit-time enforcement signal in wizard-interaction
        noise. Callers MUST NOT set this on a real fire path
        (SME-panel 2026-07-15 DA-1 fold: the argument is a leading
        underscore to make the "opt in only if you're sure" contract
        explicit at call sites).

    Return value: the exact bytes to POST — no envelope, no wrapping.

    Raises :class:`RequiredFieldMissing` when a typed target's
    ``required_fields`` are not all present + non-empty in
    ``envelope.data`` — the caller drops the delivery.
    """
    if is_hipaa:
        if not _suppress_audit_log:
            logger.info(
                "HIPAA-webhook-lock enforced — operator template ignored, "
                "minimal metadata shape emitted",
                extra={
                    "event_class": "hipaa_webhook_lock_enforced",
                    "flow_id": (envelope.get("data") or {}).get("flow_id", ""),
                    "target_type": getattr(target, "target_type", "custom") or "custom",
                    "url_host": _url_host(getattr(target, "url", "") or ""),
                    "template_present": bool(getattr(target, "body_template", None)),
                },
            )
        return _hipaa_locked_bytes(envelope)

    target_type = getattr(target, "target_type", "custom") or "custom"
    body_template = getattr(target, "body_template", None)

    # Fail-closed: every typed target-type declares required_fields.
    # (Custom has none; skipping the check preserves the pre-drive
    # envelope-verbatim path.)
    if target_type != "custom":
        _validate_required_fields(target_type, envelope)

    # Custom + no override → the historical envelope-verbatim wire
    # (byte-identical to canonical_json(envelope)) — preserves the
    # existing HMAC-verification contract for custom-relay integrations.
    if target_type == "custom" and not body_template:
        return canonical_json(envelope)

    # Resolve the effective template — operator override first, else
    # the target-type's built-in default. Registry lookup is lazy to
    # avoid an import cycle (registry lists target types by short name).
    if not body_template:
        from email_triage.web._webhook_target_types import TARGET_TYPES
        entry = TARGET_TYPES.get(target_type)
        if entry is None:
            # Unknown target-type at fire time — fall back to envelope
            # verbatim (parse-time validation should have caught this;
            # fail-safe here so a config edit can't crash delivery).
            return canonical_json(envelope)
        body_template = entry.get("default_template")
        if not body_template:
            return canonical_json(envelope)

    # ⚠️ Body render context is ENVELOPE-ONLY. ``resolved_secret`` is
    # NOT bound here — see the ``resolved_secret`` docstring above +
    # ``config._parse_webhooks`` parse-time refusal of ``{{secret}}``
    # in operator body_template.
    context: dict[str, Any] = dict(envelope)
    return _substitute(body_template, context).encode("utf-8")


def render_headers_for_target(
    target: Any,
    *,
    resolved_secret: str = "",
) -> dict[str, str]:
    """Return per-target-type required headers (Opsgenie ``GenieKey``, …).

    Values may carry ``{{secret}}`` placeholders — substituted against
    the resolved target secret. Values are NOT JSON-escaped here (they
    are header values, not JSON string literals).

    Header context is intentionally SEPARATE from body context — the
    ``{{secret}}`` binding lives here and here only (see
    :func:`render_for_target`).
    """
    target_type = getattr(target, "target_type", "custom") or "custom"
    if target_type == "custom":
        return {}
    from email_triage.web._webhook_target_types import TARGET_TYPES
    entry = TARGET_TYPES.get(target_type)
    if entry is None:
        return {}
    raw = entry.get("required_headers") or {}
    out: dict[str, str] = {}
    for name, value in raw.items():
        if "{{" in value:
            # Raw (non-JSON-escaped) substitute for header values.
            rendered: list[str] = []
            i = 0
            while i < len(value):
                j = value.find("{{", i)
                if j < 0:
                    rendered.append(value[i:])
                    break
                rendered.append(value[i:j])
                k = value.find("}}", j + 2)
                if k < 0:
                    rendered.append(value[j:])
                    break
                path = value[j + 2:k]
                node: Any = {"secret": resolved_secret}
                for part in path.strip().split("."):
                    if isinstance(node, dict) and part in node:
                        node = node[part]
                    else:
                        node = ""
                        break
                rendered.append("" if node is None else str(node))
                i = k + 2
            out[name] = "".join(rendered)
        else:
            out[name] = value
    return out
