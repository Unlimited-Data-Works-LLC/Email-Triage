"""The ONE reader of ``requirements.lock`` (PD-5): pins, markers, extras, hashes and header.

Split out of ``scripts/check_deps_drift.py`` (punch 549) so the product tree can
ship it: the monitoring system drift check is operator monitoring and is publish-stripped,
while the lock pins that read the lock through this module are product tests.
``check_deps_drift`` re-exports every name here, so its callers are unchanged.

Parsing rules:

* Strip ``[extras]`` from the name (extras never change the resolved version),
  but keep them per entry in ``LockedSet.extras``.
* ``--hash=`` values, inline or as continuation lines, are counted per entry in
  ``LockedSet.hash_counts``.
* The ``# via`` annotation under each entry (one line, or a ``# via`` line
  followed by ``#   name`` lines) is read per entry into ``LockedSet.via``: the
  packages the lock says pull the entry in. A requirement SOURCE in it
  (``email-triage (pyproject.toml)``, ``-c requirements.lock.pins``) is not a
  package and is dropped.
* Evaluate PEP-508 environment markers against the TARGET environment (the
  container), not this interpreter. A marker that cannot be evaluated is UNKNOWN,
  never evidence of drift.

Stdlib only, plus ``packaging`` when markers are evaluated.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field

# ``name[extra1,extra2]==version`` optionally followed by `` ; <marker>`` and/or
# a trailing ``\`` hash continuation.  pip-compile never emits ranges in a lock,
# so a line that does not pin with ``==`` is not a requirement line.
_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)"
    r"\s*(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*==\s*(?P<version>[^\s;#\\]+)"
    r"(?:\s*;\s*(?P<marker>[^#\\]+?))?"
    r"\s*(?:#.*)?$"
)


class LockParseError(ValueError):
    """The lock file could not be parsed — an UNKNOWN state, never a RED."""


def canonical(name: str) -> str:
    """PEP-503 canonical distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class LockedSet:
    """Parse result: what the lock requires on a given target environment."""

    pins: dict[str, str]
    """canonical name -> locked version, for entries applicable to the target."""

    not_applicable: tuple[str, ...] = ()
    """Entries whose marker evaluated FALSE for the target (e.g. pywin32)."""

    unevaluated: tuple[str, ...] = ()
    """Entries whose marker could NOT be evaluated — force WARNING, never RED."""

    extras: dict[str, frozenset[str]] = field(default_factory=dict)
    """canonical name -> the ``[extras]`` the lock requests, for EVERY entry."""

    hash_counts: dict[str, int] = field(default_factory=dict)
    """canonical name -> number of ``--hash=`` values, for EVERY entry
    (applicable or not): a lock installs in pip's hash-checking mode only when
    every entry carries one (punch 549, N-545)."""

    via: dict[str, frozenset[str]] = field(default_factory=dict)
    """canonical name -> canonical names of the PACKAGES the lock's ``# via``
    annotation says require it, for EVERY entry (empty when only a requirement
    source, such as the project's pyproject.toml, asks for it). This is the lock's
    own claim about its edges. A reachability check takes its ROOTS from
    pyproject.toml and never from here: a stale lock still names the project as the
    requirer of a dependency pyproject dropped."""


# One ``# via`` annotation as pip-compile writes it under an entry: ``# via x`` on
# one line, or ``# via`` and then one ``#   x`` line per requirer. A requirer that
# is a requirement SOURCE rather than a package reads ``name (file)`` or ``-c file``.
_VIA_RE = re.compile(r"^#\s+via(?:\s+(?P<rest>\S.*?))?\s*$")
_VIA_ITEM_RE = re.compile(r"^#\s{2,}(?P<item>\S.*?)\s*$")
_VIA_SOURCE_RE = re.compile(r"^(?:-\S+\s+\S.*|[A-Za-z0-9._-]+\s+\(.*\))$")


def _read_via_comment(
    line: str, current: str | None, via: dict[str, set[str]], via_open: bool
) -> bool:
    """Fold one comment line into ``via``; returns whether a multi-line ``# via``
    block is still open. A comment above the first entry belongs to no entry."""
    if current is None:
        return False
    if via_open:
        item = _VIA_ITEM_RE.match(line)
        if item:
            _add_via(via, current, item.group("item"))
            return True
    head = _VIA_RE.match(line)
    if head is None:
        return False
    rest = head.group("rest")
    if rest is None:
        return True
    _add_via(via, current, rest)
    return False


def _add_via(via: dict[str, set[str]], entry: str, item: str) -> None:
    if not _VIA_SOURCE_RE.match(item):
        via[entry].add(canonical(item))


def parse_lock(text: str, environment: dict[str, str] | None = None) -> LockedSet:
    """Parse a pip-compile lock into the pins applicable to ``environment``.

    ``environment`` is a full PEP-508 marker environment describing the TARGET
    (the container), not this interpreter.  When it is None, markers are not
    evaluated and every marked entry lands in ``unevaluated`` (→ WARNING).
    """
    pins: dict[str, str] = {}
    not_applicable: list[str] = []
    unevaluated: list[str] = []
    extras: dict[str, frozenset[str]] = {}
    hash_counts: dict[str, int] = {}
    current: str | None = None  # the entry a ``--hash`` continuation belongs to
    via: dict[str, set[str]] = {}
    via_open = False  # inside a multi-line ``# via`` block of ``current``

    evaluate = _marker_evaluator(environment)

    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            via_open = _read_via_comment(line, current, via, via_open)
            continue
        if not line:
            continue
        # A hash continuation belongs to the preceding requirement.
        if line.startswith("--hash") or line.startswith("\\"):
            if current is not None:
                hash_counts[current] += line.count("--hash=")
            continue
        if line.startswith("--"):
            current = None  # a pip option line, not part of any entry
            continue
        inline_hashes = line.count("--hash=")
        line = line.split(" --hash=", 1)[0].rstrip(" \\").strip()
        if not line or line.startswith("#"):
            continue

        match = _REQ_RE.match(line)
        if match is None:
            # An unpinned / editable / URL requirement means this lock is not
            # the shape we can compare — UNKNOWN, not drift.
            raise LockParseError(f"unparseable lock line: {line!r}")

        name = canonical(match.group("name"))
        current = name
        via_open = False
        via[name] = set()
        hash_counts[name] = inline_hashes
        extras[name] = frozenset(
            e.strip().lower() for e in (match.group("extras") or "").split(",") if e.strip()
        )
        marker = (match.group("marker") or "").strip()
        if marker:
            applicable = evaluate(marker)
            if applicable is None:
                unevaluated.append(name)
                continue
            if not applicable:
                not_applicable.append(name)
                continue
        pins[name] = match.group("version").strip()

    if not pins and not unevaluated:
        raise LockParseError("lock contained no pinned requirements")

    return LockedSet(
        pins=pins,
        not_applicable=tuple(sorted(not_applicable)),
        unevaluated=tuple(sorted(unevaluated)),
        extras=extras,
        hash_counts=hash_counts,
        via={name: frozenset(parents) for name, parents in via.items()},
    )


# The lock's own header, as pip-compile writes it, plus the provenance line
# scripts/regen-lock.sh adds.  These are the ONE readers of that header; the
# pins and the pre-push hook import them (PD-5).
_HEADER_PY_RE = re.compile(r"^#.*\bautogenerated by pip-compile with Python (\d+\.\d+)\b")
_PROVENANCE_RE = re.compile(r"^#\s*resolved-for:\s*(?P<body>.+?)\s*$")


def _leading_comment_block(text: str) -> list[str]:
    block: list[str] = []
    for raw in text.splitlines():
        if not raw.startswith("#"):
            break
        block.append(raw)
    return block


def header_python(text: str) -> str | None:
    """``X.Y`` from the header's "autogenerated by pip-compile with Python X.Y"."""
    for raw in _leading_comment_block(text):
        m = _HEADER_PY_RE.match(raw)
        if m:
            return m.group(1)
    return None


def header_command(text: str) -> str:
    """The pip-compile command the header records, joined onto one line.

    It is the indented ``#    pip-compile ...`` run in the leading comment block;
    any flag pip-compile chooses to record (``--no-index`` included) is kept.
    """
    parts = [
        raw[1:].strip().rstrip("\\").strip()
        for raw in _leading_comment_block(text)
        if raw.startswith("#    ")
    ]
    return " ".join(p for p in parts if p)


def header_extras(text: str) -> frozenset[str]:
    """The ``--extra=<name>`` set the header's command compiled in."""
    return frozenset(re.findall(r"--extra[= ]([A-Za-z0-9_\-]+)", header_command(text)))


def lock_provenance(text: str) -> dict[str, str] | None:
    """``key=value`` pairs from the ``# resolved-for:`` line regen-lock.sh writes.

    It is a CLAIM the regen script makes about the environment it resolved in,
    a proxy; the object check is hash-mode pip installing the lock on the image.
    """
    for raw in _leading_comment_block(text):
        m = _PROVENANCE_RE.match(raw)
        if m:
            return dict(
                pair.split("=", 1) for pair in m.group("body").split() if "=" in pair
            )
    return None


def _marker_evaluator(environment: dict[str, str] | None):
    """Return ``marker -> bool | None`` (None = could not evaluate)."""
    if environment is None:
        return lambda _marker: None
    try:
        from packaging.markers import Marker
    except Exception:  # pragma: no cover - exercised via the None branch
        return lambda _marker: None

    def _evaluate(marker: str) -> bool | None:
        # An invalid/undecidable marker is UNKNOWN, never evidence of drift.
        try:
            return bool(Marker(marker).evaluate(environment=environment))
        except Exception:
            return None

    return _evaluate


_UPGRADE_FLAGS = ("--upgrade-package", "-P")
_SPEC_NAME_RE = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def route_regen_args(
    args: list[str], image_lock_text: str, dev_lock_text: str | None
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Split ``scripts/regen-lock.sh``'s extra args into ``(both, dev_only, shared, tools_only)``.

    ``both`` reaches the image resolve (``requirements.lock``) and the dev resolve;
    ``dev_only`` reaches the dev resolve alone; the CI tools resolve
    (``requirements-ci-tools.lock``) takes ``shared + tools_only``. ``shared`` is
    every arg that names no package; it is also in ``both``, so it reaches every
    resolve. Punch 629 fold (db F2a fix 6):
    every extra arg used to reach both, so ``--upgrade-package pytest==9.0.3`` added
    pytest and three of its dependencies to the image's lock. Panel O F4: the CI tools
    resolve then took every arg, so ``-P pip-audit==2.11.0`` (dev-only by the old
    routing) added pip-audit and its dependencies to the dev lock, and a dev-only
    ``-P pytest==...`` reached the tools lock.

    Only an upgrade request is routed (``--upgrade-package X``,
    ``--upgrade-package=X``, ``-P X``, ``-PX``). One naming a package the image lock
    already pins goes to BOTH: the dev resolve is constrained to the image pins, so
    alone it could not move that package. One naming a package the dev lock pins and
    the image lock does not goes to the dev resolve only. One naming a package in
    neither lock goes to the CI tools resolve only; the CI tools resolve is
    constrained to the dev lock's pins, so an upgrade of a package the dev lock pins
    reaches it through that constraint and needs no arg. Every other arg names no
    package (``--upgrade`` and any other bare pip-compile option) and reaches every
    resolve, the CI tools resolve included (panel O round 2: otherwise a full refresh,
    ``regen-lock.sh --upgrade``, would leave pip-audit and cyclonedx-bom stale).
    ``dev_lock_text`` None (no dev lock yet) reads as an empty dev lock.

    Raises ValueError on an upgrade request with no readable package name, and on
    any arg holding a line break (the script reads the routing one arg per line)."""
    for arg in args:
        if "\n" in arg or "\r" in arg:
            raise ValueError(f"an extra arg holds a line break: {arg!r}")
    image = set(parse_lock(image_lock_text).hash_counts)
    dev = set(parse_lock(dev_lock_text).hash_counts) if dev_lock_text is not None else set()
    both: list[str] = []
    dev_only: list[str] = []
    shared: list[str] = []
    tools_only: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _UPGRADE_FLAGS:
            if i + 1 >= len(args):
                raise ValueError(f"{arg} names no package")
            taken, spec = [arg, args[i + 1]], args[i + 1]
        elif arg.startswith("--upgrade-package="):
            taken, spec = [arg], arg.split("=", 1)[1]
        elif arg.startswith("-P"):
            taken, spec = [arg], arg[2:]
        else:
            both.append(arg)
            shared.append(arg)
            i += 1
            continue
        m = _SPEC_NAME_RE.match(spec)
        if not m:
            raise ValueError(f"cannot read a package name in {arg} {spec!r}")
        name = canonical(m.group(1))
        (both if name in image else dev_only if name in dev else tools_only).extend(taken)
        i += len(taken)
    return both, dev_only, shared, tools_only


def _main(argv: list[str]) -> int:
    """``lock_reader.py regen-args <image-lock> <dev-lock> [arg ...]``: prints how
    many args the image resolve takes (both), then how many the dev resolve takes
    (both plus dev-only), then the both, dev-only, shared and tools-only args, one
    per line: the shape ``scripts/regen-lock.sh`` hands its container, whose CI
    tools resolve takes every arg after the dev resolve's (shared plus tools-only).
    A dev-lock path that does not exist reads as an empty dev lock (a first regen)."""
    if len(argv) < 3 or argv[0] != "regen-args":
        print("usage: lock_reader.py regen-args <image-lock> <dev-lock> [arg ...]", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        text = fh.read()
    dev_text = None
    if os.path.exists(argv[2]):
        with open(argv[2], encoding="utf-8") as fh:
            dev_text = fh.read()
    try:
        both, dev_only, shared, tools_only = route_regen_args(argv[3:], text, dev_text)
    except ValueError as exc:
        print(f"lock_reader: {exc}", file=sys.stderr)
        return 2
    # db F2a r2 L1: a typo of an image package (`-P pyjwtt`) routes away from the
    # image resolve, so the image lock silently does not move. Say where each routed
    # upgrade goes before the container runs.
    if dev_only:
        print("regen-lock: dev resolve only: " + " ".join(dev_only), file=sys.stderr)
    if tools_only:
        print("regen-lock: CI tools resolve only: " + " ".join(tools_only), file=sys.stderr)
    print(len(both))
    print(len(both) + len(dev_only))
    for arg in both + dev_only + shared + tools_only:
        print(arg)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
