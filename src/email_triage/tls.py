"""Self-signed TLS cert generation for the internal HTTPS listener.

Produces an RSA-2048 cert + key pair for the FastAPI/uvicorn listener
so the `/` UI runs over HTTPS even on a homelab Tailnet. Defense-in-
depth alongside the WireGuard transport — strict reading of HIPAA
§164.312(e)(1) wants TLS at the app listener regardless of what the
LAN does for transport.

Browser sees a self-signed warning the first time. Operator either
imports the cert as a trusted root (one-click on Tailnet peers) or
clicks through. Upgrade path: replace the cert files with a
real LE / Tailscale-issued cert; uvicorn doesn't care which CA
issued them.
"""

from __future__ import annotations

import asyncio
import functools
import importlib
import os
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    hostname: str,
    valid_days: int = 365,
    extra_sans: list[str] | None = None,
) -> tuple[bytes, bytes]:
    """Generate a fresh RSA-2048 self-signed cert + key.

    Returns ``(cert_pem, key_pem)`` byte strings the caller writes
    to disk. SAN list defaults to the hostname plus ``localhost`` +
    ``127.0.0.1`` so loopback health checks work without an alias.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "email-triage"),
    ])

    san_entries: list[x509.GeneralName] = [
        x509.DNSName(hostname),
        x509.DNSName("localhost"),
    ]
    # Add 127.0.0.1 / ::1 as IP SANs so curl --insecure against
    # loopback validates the SAN list rather than tripping on
    # hostname mismatch.
    import ipaddress as _ip
    san_entries.append(x509.IPAddress(_ip.ip_address("127.0.0.1")))
    san_entries.append(x509.IPAddress(_ip.ip_address("::1")))
    for extra in extra_sans or []:
        try:
            san_entries.append(x509.IPAddress(_ip.ip_address(extra)))
        except (ValueError, TypeError):
            san_entries.append(x509.DNSName(extra))

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))  # clock skew slack
        .not_valid_after(now + timedelta(days=int(valid_days)))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def write_cert_files(
    cert_dir: str | Path,
    cert_pem: bytes,
    key_pem: bytes,
) -> tuple[Path, Path]:
    """Write cert + key to ``<cert_dir>/server.crt`` + ``server.key``
    with restrictive perms on the key. Returns the two paths.

    Atomic temp-then-replace per file. Order: key first, cert second --
    the hot-reload watcher (cli.py:_watch_cert) polls cert mtime and
    triggers SSLContext.load_cert_chain on change. Writing key first
    closes the race where a watcher fires with new-cert + old-key.
    """
    cert_dir_path = Path(cert_dir)
    cert_dir_path.mkdir(parents=True, exist_ok=True)
    crt = cert_dir_path / "server.crt"
    key = cert_dir_path / "server.key"
    # census  — route through the _atomicio SSOT (was a hand-rolled
    # temp+replace+chmod copy). Key first, cert second (the hot-reload order
    # the loop preserves — see the docstring); the key lands 0o600 via the
    # mode param, the cert gets default perms (correct — it's public).
    from email_triage._atomicio import atomic_write_bytes
    for path, data, mode in ((key, key_pem, 0o600), (crt, cert_pem, None)):
        atomic_write_bytes(path, data, mode=mode)
    return crt, key


def load_existing_cert_paths(
    cert_dir: str | Path,
) -> tuple[Path | None, Path | None]:
    """Return the cert + key paths if both exist, else ``(None, None)``."""
    cert_dir_path = Path(cert_dir)
    crt = cert_dir_path / "server.crt"
    key = cert_dir_path / "server.key"
    if crt.is_file() and key.is_file():
        return crt, key
    return None, None


def fetch_tailscale_cert(
    hostname: str,
    cert_dir: str | Path,
    tailscale_bin: str = "tailscale",
    timeout: int = 60,
) -> tuple[Path, Path]:
    """Fetch a real Let's Encrypt cert for ``hostname`` via the
    Tailscale daemon's HTTPS feature.

    Tailscale issues LE certs for ``<host>.<tailnet>.ts.net`` names
    when HTTPS is enabled in the Tailnet admin console (free for
    personal use). The daemon handles ACME negotiation, DNS-01
    challenge, and renewal cadence; the operator just needs to
    invoke ``tailscale cert <hostname>`` periodically (monthly cron
    is more than enough — LE certs are valid 90 days, Tailscale
    refreshes proactively).

    Shells out to the Tailscale CLI rather than implementing ACME
    in-process — keeps this path zero-dependency and matches the
    standard ops pattern (operator can run the same command by hand
    to verify).

    Returns ``(cert_path, key_path)`` after writing PEMs into
    ``cert_dir/server.crt`` + ``server.key``. Raises RuntimeError on
    any CLI failure with the captured stderr in the message.
    """
    import subprocess
    cert_dir_path = Path(cert_dir)
    cert_dir_path.mkdir(parents=True, exist_ok=True)
    crt = cert_dir_path / "server.crt"
    key = cert_dir_path / "server.key"

    # Tailscale's `cert` subcommand writes two files at the given
    # paths. The CLI requires the hostname argument and refuses
    # alt names that don't resolve via MagicDNS.
    cmd = [
        tailscale_bin, "cert",
        "--cert-file", str(crt),
        "--key-file", str(key),
        hostname,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            f"tailscale binary not found ({e}). Install Tailscale on "
            f"the host and enable HTTPS in the admin console."
        ) from e
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"tailscale cert timed out after {timeout}s. The Tailnet "
            f"may not have HTTPS enabled, or the hostname is unknown."
        )

    if result.returncode != 0:
        raise RuntimeError(
            f"tailscale cert failed (exit {result.returncode}): "
            f"{(result.stderr or result.stdout).strip()[:500]}"
        )

    if not crt.is_file() or not key.is_file():
        raise RuntimeError(
            f"tailscale cert reported success but cert files missing "
            f"at {cert_dir_path}"
        )

    try:
        os.chmod(key, 0o600)
    except OSError as _swallow_exc:
        # Fail CLOSED (PD#8): a chmod failure is tolerated only when the key
        # is already private. A group/world-readable key is refused, never
        # used. (os.stat raising here also propagates: closed.)
        from email_triage.triage_logging import get_logger as _gl
        _gl("tls").error(
            "could not chmod 0600 on the Tailscale private key",
            key_path=str(key), exc_info=_swallow_exc,
        )
        if os.stat(key).st_mode & 0o077:
            raise RuntimeError(
                f"Tailscale private key {key} is group/world-accessible and "
                f"chmod 0600 failed ({type(_swallow_exc).__name__}); "
                f"refusing to use it."
            ) from _swallow_exc
    return crt, key


def cert_mtime(cert_path: Path | str) -> float | None:
    """Return the cert file's mtime, or None if absent.

    Cheap probe used by the hot-reload watcher: poll this on a timer,
    rebuild the SSLContext when the value changes. The ACME renewer's
    atomic-replace write changes the mtime atomically with the new
    bytes appearing on disk, so observing a change is a sufficient
    signal that a fresh cert is ready to load.
    """
    p = Path(cert_path)
    try:
        return p.stat().st_mtime
    except FileNotFoundError:
        return None


def build_ssl_context(cert_path: Path | str, key_path: Path | str):
    """Build an ``ssl.SSLContext`` from the cert + key on disk.

    Used by the hot-reload watcher: the watcher detects an mtime
    change, calls this, swaps it into the running uvicorn server.
    Caller is responsible for the swap mechanism (uvicorn-version-
    dependent).
    """
    import ssl as _ssl
    ctx = _ssl.create_default_context(_ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


# ---------------------------------------------------------------------------
# Outbound certificate-check modes (operator 2026-10-21). The one source for
# client-side TLS on IMAP, SMTP and HTTPS egress (§164.312(e)(1)).
#
# Two operator switches, global in ``outbound_tls`` with a per-account
# (IMAP) and per-section (``smtp``) override:
#
# * ``cert_check: off`` connects without validating: the setup and
#   troubleshooting mode, and the behaviour before punch 645/651.
# * ``cert_check: on`` + ``cert_enforce: off`` (validate-only) validates the
#   certificate and hostname; a failure logs ONE structured WARNING
#   (``tls_cert_check_failed``: host, port, protocol, error class, the setting
#   that decided) and the connection goes ahead unverified.
# * ``cert_check: on`` + ``cert_enforce: on`` (the default, panel M H6) validates
#   and refuses the connection on failure (:class:`CertCheckRefused`, naming the
#   host). An install turns ``cert_enforce`` off for setup or troubleshooting.
#
# Python's ``ssl`` has no verify callback that reports a verdict and carries
# on, so a real verdict comes from a verifying handshake: on
# ``ssl.SSLCertVerificationError`` in non-enforce mode the caller's connect is
# run again with an unverified context (Postfix's ``may``/``encrypt`` versus
# ``verify``/``secure`` levels are the same split: log "Untrusted TLS
# connection" and deliver, or refuse). These settings never refuse a boot, a
# save or a deploy and never touch ``/health``; the log event is the signal.
# Pin: ``tests/test_punch645_client_tls_context_pin.py``.
# ---------------------------------------------------------------------------

#: The live ``TriageConfig``, bound once at start (:func:`bind_tls_config`).
#: The admin save edits that object in place, so a saved switch applies to the
#: next connection without a restart.
_bound_config: Any = None

#: One log event per (host, port, protocol, error class, action) per hour, so
#: a per-message fetch against a bad certificate does not write one
#: ``log_entries`` row per message.
_CERT_LOG_TTL_SECS = 3600.0
_cert_log_last: dict[tuple, float] = {}

_TRUE = frozenset({"1", "true", "yes", "on", "enabled", "enforce"})
_FALSE = frozenset({"0", "false", "no", "off", "disabled"})


@dataclass(frozen=True)
class CertPolicy:
    """What an outbound TLS connection does with the server certificate.
    ``source`` names the setting that decided it, for the log event."""

    check: bool = True
    enforce: bool = True
    source: str = "default"

    @property
    def mode(self) -> str:
        if not self.check:
            return "off"
        return "enforce" if self.enforce else "validate"


#: Default (panel M H6, 2026-10-22; the operator may change it): check on,
#: enforce on. The validate-only and off modes stay as setup / troubleshooting modes.
DEFAULT_CERT_POLICY = CertPolicy(check=True, enforce=True)


class CertCheckRefused(ssl.SSLCertVerificationError):
    """``cert_enforce`` is on and the server certificate did not verify. A
    subclass of ``ssl.SSLCertVerificationError`` so existing handlers keep
    working; the message names the protocol, host and port and keeps the
    original verification text."""


def bind_tls_config(config: Any) -> None:
    """Bind the live config (app start and CLI start). Safe to call again."""
    global _bound_config
    _bound_config = config


def bound_config() -> Any:
    return _bound_config


def coerce_tristate(value: Any) -> bool | None:
    """An override value as True / False / None (inherit). Never raises: an
    unrecognised value inherits rather than refusing a load or a save."""
    if value is None or isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


def _policy_from(block: Any, base: CertPolicy, source: str) -> CertPolicy:
    if block is None:
        return base
    if isinstance(block, dict):
        check = coerce_tristate(block.get("cert_check"))
        enforce = coerce_tristate(block.get("cert_enforce"))
    else:
        check = coerce_tristate(getattr(block, "cert_check", None))
        enforce = coerce_tristate(getattr(block, "cert_enforce", None))
    if check is None and enforce is None:
        return base
    return CertPolicy(
        check=base.check if check is None else check,
        enforce=base.enforce if enforce is None else enforce,
        source=source,
    )


def current_cert_policy(scope: str = "global") -> CertPolicy:
    """The policy for ``scope``: ``"global"`` (``outbound_tls``, used by HTTPS
    egress and as the IMAP default) or ``"smtp"`` (``smtp.cert_check`` /
    ``smtp.cert_enforce`` over the global)."""
    cfg = _bound_config
    base = _policy_from(getattr(cfg, "outbound_tls", None), DEFAULT_CERT_POLICY,
                        "outbound_tls")
    if scope == "smtp":
        return _policy_from(getattr(cfg, "smtp", None), base, "smtp")
    return base


def resolve_cert_policy(account_config: Any = None, *,
                        source: str = "account") -> CertPolicy:
    """An account's policy: its ``cert_check`` / ``cert_enforce`` keys (each
    ``inherit`` / on / off) over the global :func:`current_cert_policy`."""
    return _policy_from(account_config, current_cert_policy(), source)


class DistrustedChainRefused(ssl.SSLError):
    """The server presented a chain that contains a key on ``DENIED_SPKI_SHA256`` (or a chain
    this check could not read). Raised from the TLS handshake, so the connection never carries
    a request. An ``ssl.SSLError``, so every egress client already treats it as a refused
    connection; the message names the host and the distrusted key's label, never a secret."""


_SPKI_MODULE = "email_triage._distrusted_spki"


@functools.lru_cache(maxsize=1)
def _spki_denylist():
    """The deny list and the SPKI hasher (``email_triage/_distrusted_spki.py``), defined once
    and read here and by the build-time scanner ``scripts/check_distrusted_spki.py`` (punch
    776 (a)). A module of the package, so a wheel or portable install carries it (cycle P DA
    P4-5: the earlier lookup of ``<repo>/scripts`` or ``/app/scripts`` refused every verified
    connection on an install without either). A module that cannot be imported is a
    refusal, never a skipped check (PD-8)."""
    try:
        return importlib.import_module(_SPKI_MODULE)
    except ImportError as exc:
        raise DistrustedChainRefused(
            f"punch 776: the distrusted-key list ({_SPKI_MODULE}) was not found, so the "
            "server chain cannot be checked and the connection is refused"
        ) from exc


@functools.lru_cache(maxsize=512)
def _denied_label(der: bytes) -> str | None:
    module = _spki_denylist()
    try:
        return module.DENIED_SPKI_SHA256.get(module.spki_sha256(der))
    except module.DerError as exc:
        raise DistrustedChainRefused(
            f"punch 776: a certificate in the server chain could not be read ({exc}); "
            "the connection is refused"
        ) from exc


def _verified_chain_der(tls_obj) -> list[bytes]:
    getter = getattr(tls_obj, "get_verified_chain", None)  # public since Python 3.13
    if getter is not None:
        return list(getter())
    import _ssl  # Python 3.11 / 3.12: the same chain through the private handle
    return [c.public_bytes(_ssl.ENCODING_DER) for c in (tls_obj._sslobj.get_verified_chain() or [])]


def enforce_chain_not_distrusted(tls_obj) -> None:
    """Refuse a completed handshake whose VERIFIED chain holds a distrusted key. Scoped to
    verifying contexts: a ``CERT_NONE`` context (``cert_check: off``, the non-enforce leg)
    verified nothing, so there is no verified chain to judge. Called from the guarded
    socket classes, and directly on a socket a library handshook in a context it built
    itself (redis-py, ``cache/_redis.py``); the caller closes the socket on a refusal."""
    host = getattr(tls_obj, "server_hostname", None) or "?"
    try:
        # Read inside the try (punch 656 NOTE): an object with no readable ``context`` raises the
        # same typed refusal as an unreadable chain, not a raw AttributeError (PD-8).
        if tls_obj.context.verify_mode == ssl.CERT_NONE:
            return
        chain = _verified_chain_der(tls_obj)
        if not chain:
            raise DistrustedChainRefused(
                f"punch 776: no verified chain was available to check for {host}; refused"
            )
        for der in chain:
            label = _denied_label(der)
            if label:
                raise DistrustedChainRefused(
                    f"punch 776: {host} presented a chain containing a distrusted key "
                    f"({label}); refused"
                )
    except DistrustedChainRefused as exc:
        _logger().error(
            "outbound TLS chain refused by the distrusted-key list",
            event="tls_distrusted_chain_refused", host=host, reason=str(exc),
        )
        raise
    except Exception as exc:  # noqa: BLE001 - PD-8: ANY failure to read the chain refuses
        # An unreadable chain is a refusal (PD-8): the check does not degrade to skipped.
        # Every Exception converts, not a named few (punch 656): a chain getter that returns
        # None or a non-bytes element raises TypeError, and one that fails inside the TLS
        # library raises RuntimeError. Left raw, those escaped as an untyped error and left
        # the handshaken socket open, because only DistrustedChainRefused closes it above.
        _logger().error(
            "outbound TLS chain could not be read for the distrusted-key check",
            event="tls_distrusted_chain_unreadable", host=host, error_class=type(exc).__name__,
        )
        raise DistrustedChainRefused(
            f"punch 776: the chain for {host} could not be read ({type(exc).__name__}); refused"
        ) from exc


class _GuardedSSLSocket(ssl.SSLSocket):
    """``SSLSocket`` whose completed handshake is judged against the distrusted-key list."""

    def do_handshake(self, *args, **kwargs):
        super().do_handshake(*args, **kwargs)
        try:
            enforce_chain_not_distrusted(self)
        except DistrustedChainRefused:
            self.close()
            raise


class _GuardedSSLObject(ssl.SSLObject):
    """The memory-BIO twin (asyncio / anyio ``start_tls``)."""

    def do_handshake(self, *args, **kwargs):
        super().do_handshake(*args, **kwargs)
        enforce_chain_not_distrusted(self)


def guard_verifying_context(ctx):
    """Make ``ctx`` (a VERIFYING context) judge the verified chain after every handshake it
    performs, for sockets and memory BIOs alike. Every verifying outbound context is built
    through this (``client_tls_context``); a pin walks the egress modules to keep it so."""
    ctx.sslsocket_class = _GuardedSSLSocket
    ctx.sslobject_class = _GuardedSSLObject
    return ctx


def guard_caller_tls(verify):
    """A caller's OWN TLS setting (an httpx ``verify=``, an IMAP ``ssl_context=``), made to
    judge the verified chain like every context this module builds (cycle P DA P4-1/-4):

    * an ``ssl.SSLContext`` is guarded in place (a ``CERT_NONE`` one verified nothing, and
      the guard stands down on it at handshake time);
    * a CA bundle path (file, or directory as a CApath, the httpx reading) becomes a
      verifying context over it, built here and guarded, never by the library. An
      unreadable path raises, as the library would have: a caller's own bundle is never
      silently swapped for the default store (``client_tls_context`` falls back; this
      does not);
    * anything else (``False``: nothing verified; ``None``: not set) is returned as given."""
    if isinstance(verify, ssl.SSLContext):
        return guard_verifying_context(verify)
    if isinstance(verify, (str, os.PathLike)):
        path = os.fspath(verify)
        if os.path.isdir(path):
            return guard_verifying_context(ssl.create_default_context(capath=path))
        return guard_verifying_context(ssl.create_default_context(cafile=path))
    return verify


def client_tls_context(*, cafile: str | None = None, capath: str | None = None):
    """A VERIFYING ``ssl.SSLContext`` for an outbound connection (we are the
    client): ``CERT_REQUIRED``, hostname check on, the system/default trust
    store, or ``cafile`` / ``capath`` instead when given (the HTTPS-egress CA
    bundle setting). An unreadable bundle is logged and the default store is
    used: a CA-bundle setting never refuses a connection by itself. The context is
    guarded (punch 776 (a)): a chain holding a distrusted key is refused after the handshake."""
    if cafile or capath:
        try:
            return guard_verifying_context(
                ssl.create_default_context(cafile=cafile or None, capath=capath or None))
        except (OSError, ssl.SSLError) as exc:
            _logger().warning(
                "outbound TLS CA bundle unreadable; using the default trust store",
                event="tls_ca_bundle_unreadable", cafile=cafile or "",
                capath=capath or "", error_class=type(exc).__name__,
            )
    return guard_verifying_context(ssl.create_default_context())


def _unverified_tls_context():
    """The NON-verifying context for ``cert_check: off`` and for the
    non-enforce fallback. Private: reached only through the mode helpers
    below, never built at a call site (pinned)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def mode_context(policy: CertPolicy, *, verified: bool, cafile: str | None = None,
                 capath: str | None = None):
    """The context for one leg of a mode-aware connection: the verifying one
    when ``verified`` and the policy checks, else the unverified one. For a
    transport that builds its own legs (HTTPS egress)."""
    if verified and policy.check:
        return client_tls_context(cafile=cafile, capath=capath)
    return _unverified_tls_context()


def cert_verify_error(exc: BaseException | None) -> ssl.SSLCertVerificationError | None:
    """The ``ssl.SSLCertVerificationError`` inside ``exc`` (itself, its
    cause/context chain, or an exception held in ``args`` / ``reason`` as
    urllib3 and requests wrap it), or None."""
    seen: set[int] = set()
    stack = [exc]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen or not isinstance(e, BaseException):
            continue
        seen.add(id(e))
        if isinstance(e, ssl.SSLCertVerificationError):
            return e
        stack.extend([e.__cause__, e.__context__, getattr(e, "reason", None)])
        stack.extend(a for a in getattr(e, "args", ()) if isinstance(a, BaseException))
    return None


#: The ``tls_cert_check_failed`` event's logger name and message: written by
#: :func:`log_cert_check_failure`, read back for the admin warning banner
#: (``db.audit.recent_cert_check_failures``, panel M M-DA-10).
CERT_FAIL_LOGGER = "email_triage.tls"
CERT_FAIL_MESSAGE = "outbound TLS certificate check failed"


def _logger():
    from email_triage.triage_logging import get_logger
    return get_logger(CERT_FAIL_LOGGER)


def log_cert_check_failure(*, host: str, port: int | None, protocol: str,
                           exc: BaseException, policy: CertPolicy,
                           action: str | None = None) -> None:
    """ONE structured WARNING per (host, port, protocol, error class, action)
    per hour. Carries no PHI and no secret: the server's host and port, the
    protocol, the error class and the library's verification reason (which
    names the certificate problem, e.g. ``self-signed certificate``)."""
    root = cert_verify_error(exc) or exc
    if action is None:
        action = "refused" if policy.enforce else "connected_unverified"
    key = (str(host).lower(), port, protocol, type(root).__name__, action)
    now = time.monotonic()
    last = _cert_log_last.get(key)
    if last is not None and now - last < _CERT_LOG_TTL_SECS:
        return
    _cert_log_last[key] = now
    _logger().warning(
        CERT_FAIL_MESSAGE,
        event="tls_cert_check_failed", host=str(host), port=port,
        protocol=protocol, error_class=type(root).__name__,
        reason=str(getattr(root, "verify_message", "") or ""),
        setting=policy.source, cert_check=policy.check,
        cert_enforce=policy.enforce, action=action,
    )


def refused_error(exc: BaseException, *, host: str, port: int | None,
                  protocol: str, policy: CertPolicy) -> CertCheckRefused:
    root = cert_verify_error(exc) or exc
    err = CertCheckRefused(
        f"{protocol} certificate check failed for {host}:{port} and certificate "
        f"enforcement is on ({policy.source}.cert_enforce), so the connection was "
        f"refused: {root}"
    )
    err.verify_code = getattr(root, "verify_code", None)
    err.verify_message = getattr(root, "verify_message", None)
    return err


def _stamp(conn: Any, verdict: str) -> Any:
    """Record the verdict on the connection (``_et_cert_verdict``) so a caller
    such as the connection-test probe can show it. Only on an object that takes
    attributes (imaplib / smtplib clients do)."""
    if hasattr(conn, "__dict__"):
        conn._et_cert_verdict = verdict
    return conn


def tls_connect(connect: Callable[[Any], Any], *, host: str, port: int | None,
                protocol: str, policy: CertPolicy | None = None) -> Any:
    """Run ``connect(ctx)`` (which must open the connection AND complete the
    TLS handshake, e.g. ``IMAP4_SSL(..., ssl_context=ctx)`` or SMTP connect +
    STARTTLS) under ``policy`` (default: the global one). Returns what
    ``connect`` returned, stamped with ``_et_cert_verdict`` = ``verified`` /
    ``unchecked`` / ``failed``. ``connect`` must clean up its own socket when
    it raises."""
    policy = current_cert_policy() if policy is None else policy
    if not policy.check:
        return _stamp(connect(_unverified_tls_context()), "unchecked")
    try:
        return _stamp(connect(client_tls_context()), "verified")
    except Exception as exc:
        if cert_verify_error(exc) is None:
            raise
        log_cert_check_failure(host=host, port=port, protocol=protocol,
                               exc=exc, policy=policy)
        if policy.enforce:
            raise refused_error(exc, host=host, port=port, protocol=protocol,
                                policy=policy) from exc
    return _stamp(connect(_unverified_tls_context()), "failed")


def _log_late_cert_failure(fut: Any, *, host: str, port: int | None,
                            protocol: str, policy: CertPolicy) -> None:
    """Done-callback for a handshake that outlived the wait in
    :func:`tls_connect_async`: log it if it ended in a certificate error. Not an
    audit write (``ALLOW_LOSS_CHECK`` in ``tests/test_582_audit_loss_trace_pin.py``);
    a cancelled handshake has no result to lose."""
    if fut.cancelled():
        return
    exc = fut.exception()
    if exc is not None and cert_verify_error(exc) is not None:
        # The connection was NOT continued unverified: the client's own
        # hello fails. Its own action label keeps it off the M-DA-10 banner.
        log_cert_check_failure(host=host, port=port, protocol=protocol,
                               exc=exc, policy=policy,
                               action="failed_after_handshake_wait")


async def tls_connect_async(connect: Callable[[Any], Any], *, host: str,
                            port: int | None, protocol: str,
                            policy: CertPolicy | None = None,
                            handshake: Callable[[Any], Any] | None = None,
                            timeout: float = 10.0,
                            discard: Callable[[Any], None] | None = None) -> Any:
    """Async counterpart of :func:`tls_connect` for a client that runs its TLS
    handshake LATER, in a background task (aioimaplib schedules
    ``create_connection`` as a task, so a failed verification would surface only
    as a hello timeout). ``connect(ctx)`` builds the client; ``handshake(client)``
    returns an awaitable that completes when its handshake has (aioimaplib: the
    connection task). Under check: build with the verifying context and await the
    handshake; a certificate failure is logged, then refused under enforce or the
    client is rebuilt with the unverified context. Any other failure, or no
    handshake to await, returns the verifying client and its own connect
    reports the problem. No extra connection on the success path. If the CALLER
    is cancelled during the wait (a render-probe bound), the late certificate
    failure is still logged and the client, which the caller never receives, goes
    to ``discard`` (panel X db SHOULD-1/-2)."""
    policy = current_cert_policy() if policy is None else policy
    if not policy.check:
        return connect(_unverified_tls_context())
    client = connect(client_tls_context())
    pending = handshake(client) if handshake is not None else None
    if not isinstance(pending, asyncio.Future):
        return client
    try:
        await asyncio.wait_for(asyncio.shield(pending), timeout)
        return client
    except asyncio.CancelledError:
        # Panel X db SHOULD-1: a cancel from outside is not a timeout, but the
        # shielded handshake runs on all the same; keep its late failure visible.
        pending.add_done_callback(functools.partial(
            _log_late_cert_failure, host=host, port=port, protocol=protocol,
            policy=policy,
        ))
        if discard is not None:
            discard(client)
        raise
    except (asyncio.TimeoutError, TimeoutError):
        # Panel M M-DA-7: the handshake is still running (shielded). If it
        # later ends in a certificate failure, log it then, so a slow server
        # under validate mode is not silent; the client's own hello reports
        # the failure to the caller.
        pending.add_done_callback(functools.partial(
            _log_late_cert_failure, host=host, port=port, protocol=protocol,
            policy=policy,
        ))
        return client
    except Exception as exc:
        if cert_verify_error(exc) is None:
            return client
        log_cert_check_failure(host=host, port=port, protocol=protocol,
                               exc=exc, policy=policy)
        if policy.enforce:
            raise refused_error(exc, host=host, port=port, protocol=protocol,
                                policy=policy) from exc
    return connect(_unverified_tls_context())
