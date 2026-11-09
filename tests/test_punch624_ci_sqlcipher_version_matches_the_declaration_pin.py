"""Punch 624 pin: CI's SQLCipher version is an equality tied to source-built.pins.

CI installs the PyPI ``sqlcipher3`` manylinux wheel; the image source-builds the version
``source-built.pins`` declares. The workflow's Confirm step used to assert only
``startswith('4.')``, so a wheel on any 4.x passed while the image moved: a CI run could say
"encrypted-DB tests green" about a SQLCipher the image no longer ships (0.6.4's 4.19.0 against
the 4.20.0 punch 731 declares).

The wheel's SQLCipher is recorded in ``vendor/ci-sqlcipher3-wheel.record`` (a repo file, not a
comment). The workflow step asserts equality against that record; this pin ties the record to the
two things it must agree with.

PROPERTY (count-agnostic: every workflow that reads ``PRAGMA cipher_version``, not a named one):

  1. The assertion is an equality against the record's ``wheel-sqlcipher``, never a ``startswith``
     prefix and never a version literal in the workflow.
  2. ``wheel-version`` equals the ``sqlcipher3`` pin in requirements-dev.lock, so a lock bump has
     to re-record what the new wheel vendors.
  3. ``wheel-sqlcipher`` (W) against the ``c sqlcipher`` row of source-built.pins (P):
     W == P with no ``lag-*`` key; W < P only with a complete lag record (a date, both versions,
     the newest upstream release, and the upstream check text) whose versions match W, P and the
     locked wheel; W > P fails (CI would test a SQLCipher newer than the image ships).
  4. W is never below ``db/_engine.SQLCIPHER_MIN_MAJOR_MINOR`` (the walresetbug floor), lag record
     or not: encrypted-DB tests on a pre-fix SQLCipher are false evidence about the encryption path.
  5. The lag record names its re-check trigger (``lag-recheck-trigger``): what will tell a human
     that the wheel can move, since ``lag-upstream-latest`` is compared to the lock, never to upstream.

The lag record has no expiry date on purpose: a pin that goes red on a calendar day with no code
change is a time bomb. It is instead bound to the versions, so a lock bump or a pin bump
invalidates it and forces a fresh upstream check.
"""

from __future__ import annotations

import datetime
import re
import shlex
import sys
import types

import pytest
import yaml

from _pin_harness import REPO_ROOT, load_repo_script, workflow_texts
from email_triage.db._engine import SQLCIPHER_MIN_MAJOR_MINOR

source_built = load_repo_script("scripts/source_built.py")

RECORD_PATH = "vendor/ci-sqlcipher3-wheel.record"
_PRAGMA = "PRAGMA cipher_version"
_VERSION = re.compile(r"\d+\.\d+\.\d+")
_REQUIRED = ("wheel-package", "wheel-version", "wheel-sqlcipher")
_LAG_KEYS = (
    "lag-recorded",
    "lag-wheel",
    "lag-pin",
    "lag-upstream-latest",
    "lag-upstream-check",
    "lag-recheck-trigger",
)


def declared_sqlcipher() -> str:
    comps = source_built.load(REPO_ROOT / "source-built.pins")
    versions = [c.version for c in comps if c.kind == "c" and c.name == "sqlcipher"]
    assert len(versions) == 1, versions
    return versions[0]


def locked_wheel(lock_text: str) -> str:
    found = re.findall(r"^sqlcipher3==(\S+)", lock_text, re.M)
    assert len(found) == 1, found
    return found[0]


def parse_record(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        assert sep, f"record line without a colon: {line!r}"
        assert key.strip() not in out, f"duplicate record key {key.strip()!r}"
        out[key.strip()] = value.strip()
    return out


def _ver(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in text.split("."))


def workflow_problems(workflow: str) -> list[str]:
    """Why this workflow's assertion breaks the property; empty when it holds."""
    out: list[str] = []
    # EVERY occurrence, case-insensitively (DA N2): a second step, or a lowercase ``pragma``,
    # must not escape a pin that looked only at the first match.
    assertions = [
        workflow[m.start():].split("\n", 1)[0] for m in re.finditer(re.escape(_PRAGMA), workflow, re.I)
    ]
    if not assertions:
        return [f"the workflow does not read {_PRAGMA}"]
    for assertion in assertions:
        if "startswith(" in assertion:
            out.append("the cipher_version assertion is a startswith prefix, not an equality")
        if RECORD_PATH not in workflow or "rec['wheel-sqlcipher']" not in assertion:
            out.append(f"the assertion does not compare against wheel-sqlcipher in {RECORD_PATH}")
        if re.search(r"==\s*['\"]\d+\.\d+", assertion):
            out.append("the assertion compares against a version literal: use the record")
    return out


def record_problems(record: dict[str, str], declared: str, locked: str) -> list[str]:
    """Why this record breaks the property against the pin and the lock; empty when it holds."""
    out: list[str] = []
    for key in _REQUIRED:
        if not record.get(key):
            out.append(f"record key {key} is missing or empty")
    if out:
        return out
    known = set(_REQUIRED) | set(_LAG_KEYS)
    out += [f"unknown record key {k!r}" for k in record if k not in known]
    if record["wheel-package"] != "sqlcipher3":
        out.append(f"wheel-package is {record['wheel-package']!r}, expected 'sqlcipher3'")
    if record["wheel-version"] != locked:
        out.append(
            f"wheel-version {record['wheel-version']} is not the locked sqlcipher3 {locked}: "
            "re-record what the locked wheel vendors"
        )
    wheel = record["wheel-sqlcipher"]
    if not _VERSION.fullmatch(wheel):
        return out + [f"wheel-sqlcipher {wheel!r} is not x.y.z"]
    lag = {k: record[k] for k in _LAG_KEYS if k in record}
    if _ver(wheel)[:2] < SQLCIPHER_MIN_MAJOR_MINOR:
        out.append(
            f"wheel-sqlcipher {wheel} is below the walresetbug floor "
            f"{'.'.join(str(n) for n in SQLCIPHER_MIN_MAJOR_MINOR)}.0 (db/_engine.py): "
            "CI would run the encrypted-DB tests on a pre-fix SQLCipher"
        )
    if _ver(wheel) > _ver(declared):
        out.append(f"CI tests SQLCipher {wheel}, newer than the {declared} source-built.pins declares")
    elif wheel == declared:
        if lag:
            out.append(f"lag record {sorted(lag)} present while the wheel ({wheel}) equals the pin: delete it")
    else:
        missing = [k for k in _LAG_KEYS if not lag.get(k)]
        if missing:
            return out + [f"wheel {wheel} lags the pin {declared} without a lag record: missing {missing}"]
        try:
            datetime.date.fromisoformat(lag["lag-recorded"])
        except ValueError:
            out.append(f"lag-recorded {lag['lag-recorded']!r} is not an ISO date")
        if lag["lag-wheel"] != wheel:
            out.append(f"lag-wheel {lag['lag-wheel']} is not the wheel's {wheel}")
        if lag["lag-pin"] != declared:
            out.append(f"lag-pin {lag['lag-pin']} is not the pin {declared}: the pin moved, re-check upstream")
        if lag["lag-upstream-latest"] != locked:
            out.append(
                f"lag-upstream-latest {lag['lag-upstream-latest']} is not the locked wheel {locked}: "
                "re-check upstream"
            )
    return out


def test_every_workflow_that_reads_the_cipher_version_asserts_the_record():
    reading = {name: t for name, t in workflow_texts().items() if _PRAGMA.lower() in t.lower()}
    assert reading, "no workflow reads PRAGMA cipher_version: the pin has nothing to hold"
    for name, text in reading.items():
        assert workflow_problems(text) == [], (name, workflow_problems(text))


def test_the_record_agrees_with_the_pin_and_the_lock():
    lock = (REPO_ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
    record = parse_record((REPO_ROOT / RECORD_PATH).read_text(encoding="utf-8"))
    assert record_problems(record, declared_sqlcipher(), locked_wheel(lock)) == []


def _confirm_step_command() -> str:
    doc = yaml.safe_load(workflow_texts()[".github/workflows/tests.yml"])
    steps = [s for j in doc["jobs"].values() for s in j.get("steps", []) if _PRAGMA in s.get("run", "")]
    assert len(steps) == 1, steps
    return steps[0]["run"]


def _run_confirm_step(monkeypatch, cipher_version: str) -> None:
    """Execute the workflow's own python -c against a stub sqlcipher3 reporting cipher_version."""
    argv = shlex.split(_confirm_step_command())
    assert argv[:2] == ["python", "-c"], argv[:2]
    cursor = types.SimpleNamespace(fetchone=lambda: (cipher_version,))
    conn = types.SimpleNamespace(execute=lambda sql: cursor)
    stub = types.ModuleType("sqlcipher3")
    stub.dbapi2 = types.SimpleNamespace(connect=lambda target: conn)
    monkeypatch.setitem(sys.modules, "sqlcipher3", stub)
    monkeypatch.chdir(REPO_ROOT)
    exec(compile(argv[2], "<tests.yml confirm step>", "exec"), {})


def test_the_workflow_step_passes_only_on_the_recorded_version(monkeypatch):
    recorded = parse_record((REPO_ROOT / RECORD_PATH).read_text(encoding="utf-8"))["wheel-sqlcipher"]
    _run_confirm_step(monkeypatch, f"{recorded} community")
    higher = ".".join(str(n) for n in (_ver(recorded)[0], _ver(recorded)[1] + 1, 0))
    for wrong in (f"{higher} community", "4.0.0 community", f"{recorded}1 community"):
        with pytest.raises(AssertionError):
            _run_confirm_step(monkeypatch, wrong)


def _record(**overrides: str) -> dict[str, str]:
    base = {
        "wheel-package": "sqlcipher3",
        "wheel-version": "0.6.4",
        "wheel-sqlcipher": "4.19.0",
        "lag-recorded": "2026-10-30",
        "lag-wheel": "4.19.0",
        "lag-pin": "4.20.0",
        "lag-upstream-latest": "0.6.4",
        "lag-upstream-check": "read PyPI; newest release vendors 4.19.0",
        "lag-recheck-trigger": "cve-arc SQLCIPHER3-RELEASE alert for a new sqlcipher3 release",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def test_the_pin_has_teeth():
    ok = record_problems
    assert ok(_record(), "4.20.0", "0.6.4") == []  # declared lag
    equal = _record(**{"wheel-sqlcipher": "4.20.0"})
    for key in _LAG_KEYS:
        equal.pop(key)
    assert ok(equal, "4.20.0", "0.6.4") == []  # equal, no record
    assert ok({**equal, "lag-recorded": "2026-10-30"}, "4.20.0", "0.6.4")  # stale record
    for key in _LAG_KEYS:
        assert ok(_record(**{key: None}), "4.20.0", "0.6.4"), key  # incomplete record
    assert ok(_record(**{"lag-recorded": "30-10-2026"}), "4.20.0", "0.6.4")  # undated
    assert ok(_record(), "4.21.0", "0.6.4")  # the pin moved, the record did not
    assert ok(_record(**{"lag-wheel": "4.18.0"}), "4.20.0", "0.6.4")  # does not name the wheel
    assert ok(_record(), "4.20.0", "0.6.5")  # the lock moved, the record did not
    assert ok(_record(**{"wheel-sqlcipher": "4.21.0"}), "4.20.0", "0.6.4")  # CI newer than the image
    assert ok(_record(**{"extra-key": "x"}), "4.20.0", "0.6.4")  # unknown key
    assert ok(_record(**{"wheel-sqlcipher": None}), "4.20.0", "0.6.4")  # missing wheel version
    # F4 (DA S1): a lag of ANY size used to pass; the walresetbug floor is the lower bound.
    assert ok(_record(**{"wheel-sqlcipher": "4.12.0", "lag-wheel": "4.12.0"}), "4.20.0", "0.6.4")
    assert not [
        p for p in ok(_record(**{"wheel-sqlcipher": "4.14.0", "lag-wheel": "4.14.0"}), "4.20.0", "0.6.4")
        if "floor" in p
    ]  # the floor itself is allowed
    assert ok(_record(**{"lag-recheck-trigger": ""}), "4.20.0", "0.6.4")  # F5: a trigger is required

    good = (
        "run: python -c \"... PRAGMA cipher_version ...; assert v == rec['wheel-sqlcipher']\" "
        f"{RECORD_PATH}\n"
    )
    assert workflow_problems(good) == []
    assert workflow_problems(good.replace("v == rec['wheel-sqlcipher']", "str(v[0]).startswith('4.')"))
    assert workflow_problems(good.replace("rec['wheel-sqlcipher']", "'4.19.0'"))
    assert workflow_problems(good.replace(RECORD_PATH, "elsewhere.txt"))
    # F10 (DA N2): the pin reads EVERY occurrence, and case-insensitively.
    second = good + "run: python -c \"... PRAGMA cipher_version ...; print(v)\"\n"
    assert workflow_problems(second)
    assert workflow_problems(good + "run: python -c \"... pragma cipher_version ...; print(v)\"\n")
