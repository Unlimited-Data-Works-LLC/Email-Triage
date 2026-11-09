"""Pin: ``requirements.lock`` satisfies every DIRECT-dependency floor ``pyproject.toml`` declares (punch 546, DA-546-2).

Why this exists. The image installs from ``requirements.lock`` (Containerfile) and
installs the project itself with ``--no-deps``, so the pyproject floors are never
enforced by pip at build time. Nothing else read both files: ``check_deps_drift``
compares the lock against the running container, never against pyproject. So a
security floor raised in pyproject (``pyjwt[crypto]>=2.15.1``) could ship with the
lock still pinning the vulnerable version, and every check stayed green.

INVARIANT (count-agnostic): for every requirement in ``[project].dependencies`` and
in each optional extra that the lock's own header says it was compiled with
(``--extra=<name>``), when the requirement's environment marker applies:
  * the lock pins that distribution (PEP 503 normalized name),
  * the pinned version satisfies the requirement's specifier, and
  * the lock entry carries every extra the requirement asks for.
The extra set is read from the lock header, not hardcoded, so adding an extra to
the pip-compile command widens the pin automatically. Lock lines carry their own
environment markers; a pin whose marker is false on Linux does not count as pinned.

SCOPE GUARD (db-546 DB-546-11): the lock header decides which extras are checked,
so a pyproject extra that is left out of the pip-compile command would go
unchecked in silence. Every pyproject extra must therefore be either compiled into
the lock or listed in ``_EXCLUDED_EXTRAS`` with the reason the image does not
install it from the lock. A new extra that is neither fails the pin.

REQUESTED EXTRAS (DA-546 LOW, punch 549): ``pyjwt[crypto]`` is satisfied only by a
lock entry that carries ``[crypto]``. A bare ``pyjwt`` pin at the right version
leaves ``cryptography`` out of the resolve.

ONE PARSER (PD-5, punch 549): the lock is read through
``scripts/lock_reader.parse_lock`` and its header readers, the SSOT the monitoring system
drift check re-exports. This file used to carry its own ``$``-anchored line regex, which
read nothing from a hashed lock (``name==ver`` followed by a continuation
backslash). The teeth below run on both the plain and the hashed lock formats.

Out of scope: whether the lock was resolved for the image's platform and
interpreter. That is the N-545 pin (punch 549).
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from _pin_harness import load_repo_script

_REPO = pathlib.Path(__file__).resolve().parents[1]

#: THE lock parser (PD-5), shipped; the monitoring system drift check re-exports it.
drift = load_repo_script("scripts/lock_reader.py", "_et_lock_reader")

# Extras the image does NOT install from requirements.lock, each with its reason.
# Verified against the Containerfile on 2026-09-29 (punch 546).
_EXCLUDED_EXTRAS: dict[str, str] = {
    "dev": "test tooling; the CI unit and e2e jobs and Containerfile.test install it from requirements-dev.lock (punch 511); the runtime image never does",
    "e2e": "browser test tooling (Playwright), compiled into requirements-dev.lock since punch 622; never in the image",
    "ci": "CI tooling (pip, setuptools, pip-audit, cyclonedx-bom) compiled into requirements-ci-tools.lock for the scan and SBOM jobs (punch 623); never in the image",
    "encryption": "sqlcipher3 is built from source in the Containerfile at a pinned tag, not from the lock",
    "embedding": "installed at runtime by the embedding_bits installer, hash-verified against its manifest",
    "keyring": "not installed in the image",
}


def _lock_pins(lock_text: str, env: dict[str, str]) -> dict[str, Version]:
    """Pins whose own marker (if any) applies in ``env``, read by the SSOT parser."""
    locked = drift.parse_lock(lock_text, {**env, "extra": ""})
    assert not locked.unevaluated, f"lock entries whose marker could not be evaluated: {locked.unevaluated}"
    return {name: Version(ver) for name, ver in locked.pins.items()}


def _lock_extras(lock_text: str) -> list[str]:
    return sorted(drift.header_extras(lock_text))


def _violations(pyproject: dict, lock_text: str, env: dict[str, str]) -> list[str]:
    """Every way the lock fails a pyproject requirement; empty means conforming."""
    project = pyproject["project"]
    pins = _lock_pins(lock_text, env)
    entry_extras = drift.parse_lock(lock_text, None).extras
    scoped: list[str] = list(project.get("dependencies", []))
    optional = project.get("optional-dependencies", {})
    for extra in _lock_extras(lock_text):
        scoped.extend(optional.get(extra, []))

    out: list[str] = []
    for raw in scoped:
        req = Requirement(raw)
        if req.marker is not None and not req.marker.evaluate({**env, "extra": ""}):
            continue
        name = canonicalize_name(req.name)
        if name == canonicalize_name(project["name"]):
            continue  # a self-referencing extra, e.g. "email-triage[cache]"
        pinned = pins.get(name)
        if pinned is None:
            out.append(f"{req.name}: required by pyproject ({raw!r}) but not pinned in the lock")
            continue
        if req.specifier and not req.specifier.contains(pinned, prereleases=True):
            out.append(f"{req.name}: lock pins {pinned}, pyproject requires {req.specifier}")
        missing = {e.lower() for e in req.extras} - entry_extras.get(name, frozenset())
        if missing:
            out.append(f"{req.name}: pyproject requests extras {sorted(missing)} the lock entry does not carry")
    return out


def _unscoped_extras(pyproject: dict, lock_text: str) -> list[str]:
    """pyproject extras that are neither compiled into the lock nor explicitly excluded."""
    declared = set(pyproject["project"].get("optional-dependencies", {}))
    return sorted(declared - set(_lock_extras(lock_text)) - set(_EXCLUDED_EXTRAS))


def _linux_env() -> dict[str, str]:
    # The lock describes the Linux image, whatever OS runs the suite.
    env = dict(default_environment())
    env.update(sys_platform="linux", platform_system="Linux", os_name="posix")
    return env


_NL = chr(10)
_H = chr(92)  # the continuation backslash pip-compile writes before each hash line
_SHA = "--hash=sha256:" + "a" * 64


def _plain(header: str, *entries: str) -> str:
    return "#    " + header + _NL + "".join(e + _NL for e in entries)


def _hashed(header: str, *entries: str) -> str:
    """The ``--generate-hashes`` shape: entry, continuation, hash line, via comment."""
    out = "#    " + header + _NL
    for entry in entries:
        out += f"{entry} {_H}{_NL}    {_SHA}{_NL}    # via x{_NL}"
    return out


_BOTH_FORMATS = (_plain, _hashed)


#: Every lock at the repo root (requirements.lock, and requirements-dev.lock since punch
#: 511): each must satisfy the floors of the extras its own header compiled.
_LOCKS = sorted(_REPO.glob("requirements*.lock"))


@pytest.mark.parametrize("lock_path", _LOCKS, ids=lambda p: p.name)
def test_lock_satisfies_every_pyproject_floor(lock_path) -> None:
    assert _REPO / "requirements.lock" in _LOCKS, "the lock glob missed requirements.lock; the scanner is blind"
    pyproject = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    lock_text = lock_path.read_text(encoding="utf-8")
    assert _lock_extras(lock_text), "lock header names no --extra; the scope read is broken"
    assert _violations(pyproject, lock_text, _linux_env()) == []


def test_teeth_a_lock_below_a_floor_is_caught() -> None:
    pyproject = {"project": {"name": "x", "dependencies": ["pyjwt[crypto]>=2.15.1"]}}
    for fmt in _BOTH_FORMATS:
        got = _violations(pyproject, fmt("pip-compile --extra=cache pyproject.toml", "pyjwt[crypto]==2.13.0"), _linux_env())
        assert len(got) == 1 and "2.13.0" in got[0], (fmt.__name__, got)
        ok = fmt("pip-compile --extra=cache pyproject.toml", "pyjwt[crypto]==2.15.1")
        assert _violations(pyproject, ok, _linux_env()) == [], fmt.__name__


def test_teeth_a_missing_pin_and_an_extra_from_the_header_are_caught() -> None:
    pyproject = {
        "project": {
            "name": "x",
            "dependencies": [],
            "optional-dependencies": {"cache": ["redis>=5.0"], "unused": ["nope>=1"]},
        }
    }
    # The SSOT parser refuses a lock with no requirement line at all (UNKNOWN to
    # the monitor), so each fixture carries one unrelated pin.
    for fmt in _BOTH_FORMATS:
        lock = fmt("pip-compile --extra=cache pyproject.toml", "unrelated==1.0")
        got = _violations(pyproject, lock, _linux_env())
        assert got == ["redis: required by pyproject ('redis>=5.0') but not pinned in the lock"], (fmt.__name__, got)


def test_teeth_a_windows_only_requirement_is_not_demanded_on_linux() -> None:
    pyproject = {"project": {"name": "x", "dependencies": ['pywin32>=300; sys_platform == "win32"']}}
    for fmt in _BOTH_FORMATS:
        assert _violations(pyproject, fmt("pip-compile pyproject.toml", "unrelated==1.0"), _linux_env()) == []


def test_every_pyproject_extra_is_compiled_or_explicitly_excluded() -> None:
    pyproject = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    lock_text = (_REPO / "requirements.lock").read_text(encoding="utf-8")
    assert _unscoped_extras(pyproject, lock_text) == []
    # An exclusion must not shadow an extra the lock does compile, and must name a real extra.
    declared = set(pyproject["project"].get("optional-dependencies", {}))
    assert not set(_EXCLUDED_EXTRAS) & set(_lock_extras(lock_text))
    assert set(_EXCLUDED_EXTRAS) <= declared
    assert all(reason.strip() for reason in _EXCLUDED_EXTRAS.values())


def test_teeth_a_new_extra_left_out_of_the_lock_is_caught() -> None:
    pyproject = {"project": {"name": "x", "optional-dependencies": {"cache": [], "brand_new": ["y>=1"]}}}
    for fmt in _BOTH_FORMATS:
        assert _unscoped_extras(pyproject, fmt("pip-compile --extra=cache pyproject.toml")) == ["brand_new"]


def test_teeth_a_windows_only_lock_pin_does_not_satisfy_a_linux_requirement() -> None:
    pyproject = {"project": {"name": "x", "dependencies": ["pyjwt>=2.0"]}}
    for fmt in _BOTH_FORMATS:
        lock = fmt("pip-compile pyproject.toml", 'pyjwt==2.15.1 ; sys_platform == "win32"', "unrelated==1.0")
        got = _violations(pyproject, lock, _linux_env())
        assert got == ["pyjwt: required by pyproject ('pyjwt>=2.0') but not pinned in the lock"], (fmt.__name__, got)


def test_teeth_a_requested_extra_the_lock_entry_lacks_is_caught() -> None:
    """``pyjwt[crypto]`` is not satisfied by a bare ``pyjwt`` pin (DA-546 LOW)."""
    pyproject = {"project": {"name": "x", "dependencies": ["pyjwt[crypto]>=2.15.1"]}}
    for fmt in _BOTH_FORMATS:
        got = _violations(pyproject, fmt("pip-compile pyproject.toml", "pyjwt==2.15.1"), _linux_env())
        assert got == ["pyjwt: pyproject requests extras ['crypto'] the lock entry does not carry"], (
            fmt.__name__,
            got,
        )
        assert _violations(pyproject, fmt("pip-compile pyproject.toml", "PyJWT[Crypto,other]==2.15.1"), _linux_env()) == []
