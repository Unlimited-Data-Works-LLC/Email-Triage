#!/usr/bin/env bash
#
# scripts/run-pip-audit.sh — canonical pip-audit invocation.
#
# Used by:
#   - .github/workflows/security.yml (CI gate on every push to main)
#   - scripts/git-hooks/pre-push (local guard so CVEs don't ship to main)
#
# Both surfaces share this script so a single waiver list applies
# everywhere. Add new waivers ONLY after review and document the
# reason inline.
#
# Three legs, all always run; the script fails if any fails:
#   1. the ENVIRONMENT the caller built, as JSON, failing on any skipped
#      dependency but the project's own editable dist. In CI (security.yml)
#      that is requirements.lock plus every extra a CI workflow installs
#      (punch 516: dev, e2e and encryption ran in CI unaudited before).
#   2. the embedding runtime-deps MANIFEST (punch 555) — the second
#      dependency set the image ships: scripts/embedding-bits-manifest.json
#      is COPYed into the image and the admin Install button pip-installs it
#      into the PHI container. Leg 1 never sees it. The view is DERIVED here
#      from the manifest by its own builder (--requirements-view), never a
#      hand-kept list.
#   3. TEETH: the same leg-2 code over tests/fixtures/manifest_audit_teeth.json,
#      a manifest pinning a version with long-published advisories. It MUST
#      report them; a rig that has stopped detecting fails here instead of
#      reading green.
#
# `--locks` (the pre-push hook) replaces leg 1 with one audit per lock; see audit_lock.
#
# Every leg runs once per vulnerability service in SERVICES (punch 573,
# register N-562). The default `pypi` service can be blind to an advisory the
# `osv` service already carries: on 2026-10-06T15:04Z, with mako==1.4.1,
# `-s pypi` reported nothing, `-s osv` reported CVE-2026-102991, and PyPI's
# JSON listed no vulnerabilities for that release, 15 h after the GHSA review.
# The teeth run under each service too, so a service that stops detecting
# fails here.
#
# Leg 2 runs with --strict on purpose: pip-audit's PyPI service reports a
# requirement it cannot resolve as "Dependency not found on PyPI and could not
# be audited" and still exits 0 (measured 2026-09-30 on torch==2.12.0+cpu, which
# carried PYSEC-2025-194). The view drops the +cpu local segment for that
# reason, and --strict turns any future unresolvable pair into a failure.
set -euo pipefail

#
# Waiver list — CVE id, why, expected resolution. EMPTY.
#
# CVE-2026-3219 (GHSA-58qw-9mgm-455v, pip) was waived here on the ground that
# pip is a build-time tool. N-553 refutes that: the admin Install runs
# `sys.executable -m pip install` inside the PHI container. pip 26.2 fixes it
# (OSV lists no advisory for 26.2), CI's pip comes hashed from
# requirements-ci-tools.lock at the image's version (punch 623; the punch-511 pin
# C1 holds the two equal), and the image pins pip by hash (requirements-pip.txt, 26.2.2 since N-621), so the waiver was removed (punch 555,
# 2026-09-30) rather than re-justified.
WAIVERS=()

# The vulnerability services every leg runs under (see the header).
SERVICES=(pypi osv)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="${REPO_ROOT}/scripts/build-embedding-bits-manifest.py"
# The manifest the Containerfile COPYs into the image (pinned by
# tests/test_embedding_manifest_audit_pin.py).
EMBEDDING_MANIFEST="${REPO_ROOT}/scripts/embedding-bits-manifest.json"
TEETH_MANIFEST="${REPO_ROOT}/tests/fixtures/manifest_audit_teeth.json"

# Windows Git Bash (the pre-push hook) often has no python3 on PATH.
PYTHON="$(command -v python3 || command -v python || true)"
if [ -z "${PYTHON}" ]; then
    echo "run-pip-audit: no python3/python on PATH; cannot derive the embedding manifest view." >&2
    exit 2
fi

# audit_manifest <manifest> <captured-stdout-file> <service>
# Derive the requirements view and audit it. Returns pip-audit's status, or
# 2 when the view cannot be derived or is empty (nothing audited != clean).
audit_manifest() {
    local manifest="$1" out="$2" service="$3" view
    view="$(mktemp)"
    if ! "${PYTHON}" "${BUILDER}" --output "${manifest}" --requirements-view > "${view}"; then
        echo "run-pip-audit: could not derive the requirements view of ${manifest}" >&2
        rm -f "${view}"
        return 2
    fi
    if [ ! -s "${view}" ]; then
        echo "run-pip-audit: the requirements view of ${manifest} is empty" >&2
        rm -f "${view}"
        return 2
    fi
    local rc=0
    pip-audit "${WAIVERS[@]}" -r "${view}" -s "${service}" --no-deps --disable-pip --strict > "${out}" || rc=$?
    cat "${out}"
    rm -f "${view}"
    return "${rc}"
}

# --installed-set <freeze-file> (N-553): audit an INSTALLED set instead of the
# three legs — `python -m pip list --format=freeze` captured inside a BUILT
# image, the only view that includes what the base image ships (its pip).
# Same flags as the manifest leg (--strict: an unresolvable pin fails), the
# pyproject-named project line dropped (it is not on PyPI), local version
# segments dropped, and a teeth run over a fixture pinning pip 25.0.1 that
# must report pip.
INSTALLED_TEETH="${REPO_ROOT}/tests/fixtures/installed_set_teeth.txt"
audit_installed_set() {
    local freeze="$1" out="$2" service="$3" view rc=0
    view="$(mktemp)"
    if ! "${PYTHON}" - "${freeze}" "${REPO_ROOT}/pyproject.toml" > "${view}" <<'PYEOF'
import re, sys, tomllib
norm = lambda n: re.sub(r"[-_.]+", "-", n).lower()
with open(sys.argv[2], "rb") as fh:
    project = norm(tomllib.load(fh)["project"]["name"])
kept = 0
for raw in open(sys.argv[1], encoding="utf-8"):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)", line)
    if not m:
        sys.exit(f"run-pip-audit: unparseable installed-set line {line!r}; refusing a partial audit")
    if norm(m[1]) == project:
        continue
    print(f"{norm(m[1])}=={m[2].split('+', 1)[0]}")
    kept += 1
if not kept:
    sys.exit("run-pip-audit: the installed set is empty; nothing to audit")
PYEOF
    then
        rm -f "${view}"
        return 2
    fi
    pip-audit "${WAIVERS[@]}" -r "${view}" -s "${service}" --no-deps --disable-pip --strict > "${out}" || rc=$?
    cat "${out}"
    rm -f "${view}"
    return "${rc}"
}
if [ "${1:-}" = "--installed-set" ]; then
    if [ -z "${2:-}" ] || [ ! -f "${2}" ]; then
        echo "usage: run-pip-audit.sh --installed-set <pip-freeze-file>" >&2
        exit 2
    fi
    status=0
    out="$(mktemp)"
    trap 'rm -f "${out}"' EXIT
    for service in "${SERVICES[@]}"; do
        echo "== pip-audit [${service}]: installed set (${2})"
        : > "${out}"
        audit_installed_set "${2}" "${out}" "${service}" || status=1
        echo "== pip-audit [${service}]: installed-set teeth (${INSTALLED_TEETH#"${REPO_ROOT}/"} must report pip)"
        : > "${out}"
        teeth_rc=0
        audit_installed_set "${INSTALLED_TEETH}" "${out}" "${service}" || teeth_rc=$?
        if [ "${teeth_rc}" -eq 0 ] || ! grep -Eq "^pip[[:space:]]" "${out}"; then
            echo "run-pip-audit: TEETH FAILED [${service}]: the installed-set fixture's pip 25.0.1 was not reported (rc=${teeth_rc})." >&2
            status=1
        fi
    done
    exit "${status}"
fi

# --locks [<lock> ...] (the pre-push hook): audit the LOCKS instead of the ambient
# environment. Leg 1 audits whatever Python the caller has, which in CI is the
# environment the job built from requirements-dev.lock, but on a workstation is the
# global interpreter (measured 2026-10-17: 72 s, rc=1, 52 findings in pillow, pypdf,
# pyjwt and others that no lock pins). That is the wrong object, so the hook never
# ran a valid control. With --locks, leg 1 is replaced by one audit per lock (every
# requirements*.lock at the repo root when none is named, plus requirements-pip.txt, the
# image's own hash-pinned pip, N-621, and requirements-build.txt, the builder stage's
# hash-pinned build toolchain, punch 775 / cycle P db P3 MUST-1) over a name==version view
# derived by scripts/lock_reader.py (the ONE reader of the lock, PD-5), plus a teeth
# run of the same code over the installed-set fixture (pip 25.0.1 must be reported).
# The manifest leg and its teeth still run, under every service. CI keeps calling
# the script bare.
#
# --locks --ref <rev> (the pre-push hook, 2026-10-26, backlog row 2): audit the locks,
# pyproject.toml and the embedding manifest AS COMMITTED AT <rev>, never the working
# tree. The hook used to audit whatever the checkout held: on 2026-10-25 a shepherd
# launched from a checkout at old main audited filelock 4.1.1 while the pushed branch
# pinned 4.2.1 (a false RED), and the same defect passes a vulnerable branch pushed
# from a clean checkout. Each file is read with `git cat-file blob <rev>:<path>` into a
# temp dir; a missing file, or a rev that is not a commit, exits 2 (nothing audited is
# not clean). The reader, builder and teeth fixtures stay the working tree's: they
# are the rig, not the audited object.
#
# audit_lock <lock> <captured-stdout-file> <service>
# Returns pip-audit's status, or 2 when the view cannot be derived, is empty, or
# the lock holds an entry the view cannot decide (a marker it cannot evaluate would
# be dropped, and a partial audit must not read as clean).
audit_lock() {
    local lock="$1" out="$2" service="$3" view rc=0
    view="$(mktemp)"
    if ! "${PYTHON}" - "${REPO_ROOT}/scripts" "${lock}" "${PYPROJECT}" > "${view}" <<'PYEOF'
import sys, tomllib
sys.path.insert(0, sys.argv[1])
from lock_reader import LockParseError, canonical, parse_lock
try:
    with open(sys.argv[2], encoding="utf-8") as fh:
        locked = parse_lock(fh.read(), None)
    with open(sys.argv[3], "rb") as fh:
        project = canonical(tomllib.load(fh)["project"]["name"])
except (OSError, ValueError, KeyError) as e:
    sys.exit(f"run-pip-audit: cannot read the lock {sys.argv[2]} or pyproject.toml: {e}")
if locked.unevaluated:
    sys.exit(f"run-pip-audit: {sys.argv[2]} has entries with a marker the view cannot decide ({', '.join(locked.unevaluated)}); refusing a partial audit")
for name, version in sorted(locked.pins.items()):
    if name != project:  # the project itself is private, not on PyPI (as in --installed-set)
        print(f"{name}=={version}")
PYEOF
    then
        rm -f "${view}"
        return 2
    fi
    if [ ! -s "${view}" ]; then
        echo "run-pip-audit: the requirements view of ${lock} is empty" >&2
        rm -f "${view}"
        return 2
    fi
    local pins
    pins="$(wc -l < "${view}" | tr -d '[:space:]')"
    pip-audit "${WAIVERS[@]}" -r "${view}" -s "${service}" --no-deps --disable-pip --strict > "${out}" || rc=$?
    cat "${out}"
    echo "lock $(label "${lock}") [${service}]: ${pins} pins audited, rc=${rc}"
    rm -f "${view}"
    return "${rc}"
}

# label <path>: how a log line names an audited file: `<rev>:<path>` for a file read
# from --ref, else the path relative to the repo root.
label() {
    if [ -n "${REF_DIR}" ] && [ "${1#"${REF_DIR}/"}" != "$1" ]; then
        echo "${REF_SHA}:${1#"${REF_DIR}/"}"
    else
        echo "${1#"${REPO_ROOT}/"}"
    fi
}

# ref_file <path>: write <path> as committed at REF_SHA to REF_DIR/<path>, or exit 2.
ref_file() {
    mkdir -p "$(dirname "${REF_DIR}/$1")"
    if ! git -C "${REPO_ROOT}" cat-file blob "${REF_SHA}:$1" > "${REF_DIR}/$1" 2>/dev/null; then
        echo "run-pip-audit: --ref ${REF_SHA} has no $1; nothing was audited." >&2
        exit 2
    fi
}

PYPROJECT="${REPO_ROOT}/pyproject.toml"
REF_DIR=""
REF_SHA=""
LOCK_MODE=0
LOCKS=()
if [ "${1:-}" = "--locks" ]; then
    LOCK_MODE=1
    shift
    if [ "${1:-}" = "--ref" ]; then
        if [ "$#" -ne 2 ] || [ -z "$2" ]; then
            echo "usage: run-pip-audit.sh --locks --ref <rev>" >&2
            exit 2
        fi
        if ! REF_SHA="$(git -C "${REPO_ROOT}" rev-parse --verify --quiet "$2^{commit}")"; then
            echo "run-pip-audit: --ref $2 is not a commit; nothing was audited." >&2
            exit 2
        fi
        REF_DIR="$(mktemp -d)"
        trap 'rm -rf "${REF_DIR}"' EXIT
        # The default set, enumerated from the commit's tree in byte order (the
        # working-tree glob's order): every requirements*.lock, then the pip pin.
        ref_locks="$(git -C "${REPO_ROOT}" ls-tree --name-only "${REF_SHA}" | grep -E '^requirements.*\.lock$' || true)"
        if [ -z "${ref_locks}" ]; then
            echo "run-pip-audit: --ref ${REF_SHA} has no requirements*.lock; nothing was audited." >&2
            exit 2
        fi
        for name in ${ref_locks} requirements-pip.txt; do
            ref_file "${name}"
            LOCKS+=("${REF_DIR}/${name}")
        done
        # The build toolchain pin (punch 775) is audited when the commit has it. A commit
        # from before 775 has neither the file nor a Containerfile that installs it, and is
        # audited without it, said in the log; a commit whose Containerfile installs it but
        # lacks the file exits 2 like any other unreadable pin.
        if [ -n "$(git -C "${REPO_ROOT}" ls-tree --name-only "${REF_SHA}" -- requirements-build.txt)" ]; then
            ref_file requirements-build.txt
            LOCKS+=("${REF_DIR}/requirements-build.txt")
        elif git -C "${REPO_ROOT}" grep -q -F 'requirements-build.txt' "${REF_SHA}" -- Containerfile; then
            echo "run-pip-audit: --ref ${REF_SHA} installs requirements-build.txt (Containerfile) but has no such file; nothing was audited." >&2
            exit 2
        else
            echo "run-pip-audit: --ref ${REF_SHA} predates the build toolchain pin (no requirements-build.txt, none installed); not audited at this ref"
        fi
        ref_file pyproject.toml
        PYPROJECT="${REF_DIR}/pyproject.toml"
        ref_file "${EMBEDDING_MANIFEST#"${REPO_ROOT}/"}"
        EMBEDDING_MANIFEST="${REF_DIR}/${EMBEDDING_MANIFEST#"${REPO_ROOT}/"}"
    elif [ "$#" -gt 0 ]; then
        LOCKS=("$@")
    else
        LOCKS=("${REPO_ROOT}"/requirements*.lock "${REPO_ROOT}/requirements-pip.txt" "${REPO_ROOT}/requirements-build.txt")
    fi
    for lock in "${LOCKS[@]}"; do
        if [ ! -f "${lock}" ]; then
            echo "run-pip-audit: --locks names ${lock}, which is not a file; nothing was audited." >&2
            exit 2
        fi
    done
fi

status=0
out="$(mktemp)"
env_json="$(mktemp)"
trap 'rm -f "${out}" "${env_json}"; [ -z "${REF_DIR}" ] || rm -rf "${REF_DIR}"' EXIT

# Leg 1 — the environment. --skip-editable: the project is private, not on
# PyPI. It CANNOT take --strict: pip-audit 2.10.0 (_cli.py:557) makes ANY
# skipped dependency fatal under --strict, the project's own editable dist
# included (CI run 36780522491), and a non-editable install is "not found on
# PyPI", also a skip. Without --strict every OTHER skip passes silently (the
# workstation's torch 2.12.0+cpu did). So the leg writes JSON and fails on
# every skip except exactly one: the dist named by pyproject's [project].name
# with the reason "distribution marked as editable" — keyed on the pyproject
# SSOT, never on a name written here.
for service in "${SERVICES[@]}"; do
  if [ "${LOCK_MODE}" -eq 1 ]; then
    for lock in "${LOCKS[@]}"; do
        echo "== pip-audit [${service}]: lock $(label "${lock}")"
        : > "${out}"
        audit_lock "${lock}" "${out}" "${service}" || status=1
    done
    echo "== pip-audit [${service}]: lock-audit teeth (${INSTALLED_TEETH#"${REPO_ROOT}/"}: pip must be reported)"
    : > "${out}"
    lock_teeth_rc=0
    audit_lock "${INSTALLED_TEETH}" "${out}" "${service}" || lock_teeth_rc=$?
    if [ "${lock_teeth_rc}" -eq 0 ] || ! grep -Eq "^pip[[:space:]]" "${out}"; then
        echo "run-pip-audit: TEETH FAILED [${service}]: the lock audit did not report the fixture's pip 25.0.1 (rc=${lock_teeth_rc}); the lock audit cannot be trusted." >&2
        status=1
    fi
  else
    echo "== pip-audit [${service}]: environment"
    : > "${env_json}"
    env_rc=0
    pip-audit --skip-editable "${WAIVERS[@]}" -s "${service}" -f json -o "${env_json}" "$@" || env_rc=$?
    if [ "${env_rc}" -ne 0 ]; then
        status=1
    fi
    if ! "${PYTHON}" - "${env_json}" "${REPO_ROOT}/pyproject.toml" "${service}" <<'PYEOF'
import json, re, sys, tomllib
norm = lambda n: re.sub(r"[-_.]+", "-", n).lower()
try:
    deps = json.load(open(sys.argv[1], encoding="utf-8"))["dependencies"]
    with open(sys.argv[2], "rb") as fh:
        project = norm(tomllib.load(fh)["project"]["name"])
except (OSError, ValueError, KeyError) as e:
    print(f"run-pip-audit: environment audit result unreadable ({e}); nothing was audited.", file=sys.stderr)
    sys.exit(2)
bad = 0
for d in deps:
    if "skip_reason" in d:
        if norm(d["name"]) == project and d["skip_reason"] == "distribution marked as editable":
            continue
        print(f"run-pip-audit: SKIPPED, NOT AUDITED: {d['name']}: {d['skip_reason']}", file=sys.stderr)
        bad += 1
    for v in d.get("vulns", []):
        print(f"{d['name']} {d.get('version')} {v.get('id')} {','.join(v.get('fix_versions', []))}")
        bad += 1
print(f"environment [{sys.argv[3]}]: {len(deps)} dependencies, {bad} finding(s) or unaudited skip(s)")
sys.exit(1 if bad else 0)
PYEOF
    then
        status=1
    fi
  fi

    echo "== pip-audit [${service}]: embedding runtime-deps manifest ($(label "${EMBEDDING_MANIFEST}"))"
    : > "${out}"
    audit_manifest "${EMBEDDING_MANIFEST}" "${out}" "${service}" || status=1

    echo "== pip-audit [${service}]: teeth (${TEETH_MANIFEST#"${REPO_ROOT}/"}: every package must be reported)"
    : > "${out}"
    teeth_rc=0
    audit_manifest "${TEETH_MANIFEST}" "${out}" "${service}" || teeth_rc=$?
    # A vulnerability exit alone is not enough: --strict also exits 1 when a pin
    # cannot be resolved. Require an advisory row for EVERY package in the
    # fixture's view — including its per-arch +cpu torch pin, so a view that
    # stopped walking wheels_by_arch or stopped dropping the local segment fails.
    teeth_missing=""
    if [ "${teeth_rc}" -eq 0 ]; then
        teeth_missing="(exit 0)"
    fi
    teeth_names="$("${PYTHON}" "${BUILDER}" --output "${TEETH_MANIFEST}" --requirements-view | cut -d= -f1)" || teeth_missing="(no view)"
    for name in ${teeth_names}; do
        grep -Eq "^${name}[[:space:]]" "${out}" || teeth_missing="${teeth_missing} ${name}"
    done
    if [ -n "${teeth_missing}" ] || [ -z "${teeth_names}" ]; then
        echo "run-pip-audit: TEETH FAILED [${service}]: the known-vulnerable fixture was not fully reported:${teeth_missing:- (empty view)}; the manifest audit cannot be trusted." >&2
        status=1
    fi
done

exit "${status}"
