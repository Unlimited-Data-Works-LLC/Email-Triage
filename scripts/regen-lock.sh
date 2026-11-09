#!/usr/bin/env bash
#
# scripts/regen-lock.sh — regenerate requirements.lock FOR THE IMAGE
# (punch 549, register N-545).
#
# The lock describes what ships: the Containerfile's Linux base image, its
# Python, and a --hash for every entry. With hashes in the file, every
# `pip install -r requirements.lock` (the image build, CI, Containerfile.test)
# runs in pip's hash-checking mode, so a substituted artifact or a transitive
# dependency the lock does not pin fails the install instead of slipping in.
#
# Run it on a Linux host with podman (a git checkout is not required, so a
# copied tree works):
#     scripts/regen-lock.sh                            # minimal update, seeded from the committed lock
#     scripts/regen-lock.sh --upgrade-package pyjwt    # a deliberate bump; extra args go to pip-compile
#                                                      # (routed per resolve, see ROUTED below)
#     PODMAN="sudo podman" scripts/regen-lock.sh       # rootful podman
# A Windows/WSL podman has been unable to finish a full lock resolve, which is
# why the resolve runs here and not on a workstation.
#
# The lock is not a Windows or macOS install recipe. A developer checkout
# installs from pyproject: `pip install -e '.[dev]'`.
#
# Punch 511: the same run also writes requirements-dev.lock, the hashed lock the
# CI unit job installs (`pip install --require-hashes -r requirements-dev.lock`)
# instead of resolving the dev and encryption extras from PyPI unpinned on the
# self-hosted runner that shares a host with production. It compiles the image's
# extras PLUS --extra=dev --extra=encryption, constrained (-c) to the pins of the
# requirements.lock this run just wrote, so every package the image ships is
# tested at the version it ships. tests/test_punch511_ci_installs_are_hash_locked_pin.py
# fails a dev lock whose shared pins drift from requirements.lock, an unhashed
# entry, or a CI install that resolves from PyPI without hashes.
#
# Punch 622/623 (register N-607 residuals a and b): the dev lock also compiles the
# e2e extra (Playwright), so the e2e job and the CVE scan install it hashed, and
# the same run writes requirements-ci-tools.lock: the pyproject `ci` extra (pip,
# setuptools, pip-audit, cyclonedx-bom) with hashes, constrained to the dev lock's
# pins and to the image's pip (requirements-pip.txt), so the scan and SBOM jobs
# bootstrap their tools from it instead of from PyPI unhashed. It is the one lock
# compiled with --allow-unsafe: pip and setuptools are what it exists to pin.
#
# The resolve is SEEDED from the committed lock and never passes --upgrade, so
# every version the lock already pins stays put unless you name the package.
# tests/test_n545_lock_describes_the_image_ssot_pin.py fails a lock this script
# did not write (it checks the `# resolved-for:` line added below) and a lock
# whose interpreter or base image disagrees with the Containerfile.
set -euo pipefail

cd "$(dirname "$0")/.."

PODMAN="${PODMAN:-podman}"
# The regen toolchain is pinned, not just pip-tools: the header bytes are a
# function of it. pip-tools 7.6.1's get_compile_command skips a flag only when
# the option's default equals its value, and click 8.5.0 gives `--no-index`
# (declared with no default) the Sentinel.UNSET default, so the header records
# a `--no-index` that was never passed. Measured in python:3.12-slim on
# 2026-10-01: click 8.5.0 (what pip-tools 7.6.1 resolves unpinned) records it;
# click 8.4.1 and 8.2.1 do not. Raise both pins together, and check the header.
PIP_TOOLS="pip-tools==7.6.1 click==8.4.1"
LOCK="requirements.lock"
DEV_LOCK="requirements-dev.lock"
CI_LOCK="requirements-ci-tools.lock"
# The extras the image needs from the lock. The header pip-compile writes
# records them, and the pins read them back from there.
EXTRAS="--extra=cache --extra=imap --extra=keyfile --extra=office365"
# The extras the CI unit and e2e jobs add on top of the image's (punch 511, 622).
# The dev lock compiles EXTRAS plus these.
DEV_EXTRAS="--extra=dev --extra=encryption --extra=e2e"
# The extra the CI tools lock compiles (punch 623), on top of the base dependencies.
CI_EXTRAS="--extra=ci"
# Separate the locks on the container's stdout. No lock line starts with either.
SEP="=== $DEV_LOCK ==="
CI_SEP="=== $CI_LOCK ==="

# The base image is the first `FROM python:` in the Containerfile, the one place
# the image's interpreter is declared.
BASE="$(awk '$1 == "FROM" && $2 ~ /^python:/ { print $2; exit }' Containerfile)"
if [ -z "$BASE" ]; then
    echo "regen-lock: no 'FROM python:' line in Containerfile" >&2
    exit 1
fi

OUT="$(mktemp)"
trap 'rm -f "$OUT" "$OUT.lock" "$OUT.dev" "$OUT.ci" "$OUT.final"' EXIT

# The committed dev and CI tools locks seed their resolves when they exist, as
# the prod lock seeds the prod one.
SEEDS="$LOCK"
[ -f "$DEV_LOCK" ] && SEEDS="$SEEDS $DEV_LOCK"
[ -f "$CI_LOCK" ] && SEEDS="$SEEDS $CI_LOCK"

# Punch 629 fold (db F2a fix 6): the extra args used to reach BOTH resolves, so a
# dev-only `--upgrade-package pytest==9.0.3` added pytest and three dependencies to
# requirements.lock, the image's lock. scripts/lock_reader.py (the one lock reader)
# routes them: an upgrade of a package the image lock pins goes to the image and
# dev resolves (the dev resolve is constrained to the image pins and cannot move it
# alone), an upgrade of a package only the dev lock pins to the dev resolve only,
# and every other arg to the image and dev resolves. Panel O F4: an upgrade of a
# package in neither lock (a CI tool such as pip-audit) goes to the CI tools
# resolve only; it used to reach the dev resolve, which added it to
# requirements-dev.lock, and the CI tools resolve took every arg. Only an upgrade
# that names a package is routed. The CI tools resolve is constrained to the dev
# lock's pins, so an upgrade of a package the dev lock pins reaches it with no arg.
# Every arg that names no package (`--upgrade` and any other bare pip-compile
# option) reaches all three resolves, so a full refresh (`--upgrade`) moves the CI
# security tools (pip-audit, cyclonedx-bom) too. The router prints how many args
# the image resolve takes, then how many the dev resolve takes, then the routed
# args, one per line (the args that name no package once more, after the dev
# resolve's, for the CI tools resolve); the container gets that list as is. With
# no extra args it prints `0` twice, and every pip-compile command is the one a
# no-arg run has always run. Routed upgrades that skip the image resolve
# are named on stderr first (`regen-lock: dev resolve only: ...`, `regen-lock: CI
# tools resolve only: ...`), so a typo of an image package, which leaves
# requirements.lock unmoved, is visible.
PYTHON="$(command -v python3 || command -v python || true)"
if [ -z "$PYTHON" ]; then
    echo "regen-lock: no python3 on this host to route the extra args; neither lock was written" >&2
    exit 1
fi
ROUTED_TEXT="$("$PYTHON" scripts/lock_reader.py regen-args "$LOCK" "$DEV_LOCK" "$@")"
mapfile -t ROUTED <<< "$ROUTED_TEXT"

# The tree goes in over stdin: no bind mount, no SELinux relabel, no root-owned
# file written back into the checkout. The output path inside the container is
# the seed path, so pip-compile keeps the committed pins.
#
# The dev resolve is constrained to the prod lock just written. pip refuses
# [extras] in a constraints file and the lock keeps them (--no-strip-extras), so
# the constraint is a derived `name==version` list (comments, hash lines,
# continuations and extras removed), requirements.lock.pins, which the dev lock's
# header records. It exists only inside the container.
#
# The dev resolve runs with PIP_ONLY_BINARY=:all: (and pip-tools installs from
# wheels): no sdist build code runs during the resolve, pip-compile writes
# `--only-binary :all:` into the dev lock so the CI install is wheel-only too,
# and the dev lock carries wheel hashes only. A dev dependency with no wheel
# stops the resolve; that is a decision to make, not one to build around. The
# prod compile is unchanged (its output is the image's lock).
#
# The CI tools resolve runs the same way, constrained to the dev lock just
# written (requirements-dev.lock.pins: the scan installs both locks into one
# environment, so a shared package must sit at one version) and to the image's
# pip (requirements-pip.txt.pins).
# shellcheck disable=SC2086
tar -cf - pyproject.toml README.md LICENSE requirements-pip.txt $SEEDS src \
    | $PODMAN run --rm -i "$BASE" sh -euc '
        pip_tools="$1"; extras="$2"; dev_extras="$3"; ci_extras="$4"; ci_sep="$5"; sep="$6"; nboth="$7"; ndev="$8"; shift 8
        mkdir /w && cd /w && tar -xf -
        pip install --quiet --disable-pip-version-check --only-binary=:all: $pip_tools >&2
        # Each resolve takes its slice of the routed args (ROUTED): the image
        # resolve the first $nboth, the dev resolve the first $ndev, the CI tools
        # resolve the ones after $ndev (the args that name no package, then the
        # CI-tools-only upgrades).
        (
            n=$#; i=0
            for a in "$@"; do
                i=$((i + 1))
                [ "$i" -gt "$nboth" ] || set -- "$@" "$a"
            done
            shift "$n"
            pip-compile --quiet --generate-hashes $extras --no-strip-extras \
                --output-file=requirements.lock "$@" pyproject.toml >&2
        )
        # name==version only: comments, hash lines, option lines, continuations
        # and extras removed.
        pins() {
            sed -e "s/\r\$//" -e "/^[[:space:]]*#/d" -e "/^[[:space:]]*-/d" -e "/^[[:space:]]*\$/d" \
                -e "s/[[:space:]]*[\]\$//" -e "s/\[[^]]*\]//" "$1" > "$1.pins"
        }
        pins requirements.lock
        (
            n=$#; i=0
            for a in "$@"; do
                i=$((i + 1))
                [ "$i" -gt "$ndev" ] || set -- "$@" "$a"
            done
            shift "$n"
            PIP_ONLY_BINARY=:all: pip-compile --quiet --generate-hashes $extras $dev_extras --no-strip-extras \
                --constraint=requirements.lock.pins \
                --output-file=requirements-dev.lock "$@" pyproject.toml >&2
        )
        pins requirements-dev.lock
        pins requirements-pip.txt
        (
            n=$#; i=0
            for a in "$@"; do
                i=$((i + 1))
                [ "$i" -le "$ndev" ] || set -- "$@" "$a"
            done
            shift "$n"
            PIP_ONLY_BINARY=:all: pip-compile --quiet --generate-hashes --allow-unsafe $ci_extras --no-strip-extras \
                --constraint=requirements-dev.lock.pins --constraint=requirements-pip.txt.pins \
                --output-file=requirements-ci-tools.lock "$@" pyproject.toml >&2
        )
        python -c "import sys; print(\"PROVENANCE sys_platform=%s python_version=%d.%d\" % (sys.platform, *sys.version_info[:2]))"
        cat requirements.lock
        echo "$sep"
        cat requirements-dev.lock
        echo "$ci_sep"
        cat requirements-ci-tools.lock
    ' sh "$PIP_TOOLS" "$EXTRAS" "$DEV_EXTRAS" "$CI_EXTRAS" "$CI_SEP" "$SEP" "${ROUTED[@]}" > "$OUT"

PROV="$(head -n 1 "$OUT")"
case "$PROV" in
    "PROVENANCE "*) ;;
    *) echo "regen-lock: the container did not report its platform: $PROV" >&2; exit 1 ;;
esac
for sep in "$SEP" "$CI_SEP"; do
    if ! grep -qxF "$sep" "$OUT"; then
        echo "regen-lock: the container did not emit the section after '$sep'; no lock was written" >&2
        exit 1
    fi
done
# Section n of the container's output after the provenance line (0 the image
# lock, 1 the dev lock, 2 the CI tools lock). No early `exit` in awk: under
# pipefail it would SIGPIPE tail and abort the run.
section() {
    awk -v n="$1" -v a="$SEP" -v b="$CI_SEP" 'NR == 1 { next } $0 == a || $0 == b { s++; next } s == n { print }' "$OUT"
}
section 0 > "$OUT.lock"
section 1 > "$OUT.dev"
section 2 > "$OUT.ci"

# pip-compile leaves setuptools/pip out unless --allow-unsafe, and a hashed
# install then refuses the lock if anything in it needs them. Stop rather than
# write a lock the image (or the CI unit job) cannot install. The CI tools lock
# is compiled with --allow-unsafe on purpose and is not checked here.
for f in "$OUT.lock" "$OUT.dev"; do
    if grep -q "considered to be unsafe" "$f"; then
        echo "regen-lock: pip-compile left packages out as 'unsafe':" >&2
        sed -n '/considered to be unsafe/,$p' "$f" >&2
        echo "regen-lock: decide --allow-unsafe deliberately; no lock was written" >&2
        exit 1
    fi
done

# The provenance line goes at the end of the header, where the readers in
# scripts/lock_reader.py look for it (the leading comment block only).
for pair in "$OUT.lock:$LOCK" "$OUT.dev:$DEV_LOCK" "$OUT.ci:$CI_LOCK"; do
    awk -v prov="# resolved-for: ${PROV#PROVENANCE } base=$BASE" \
        '!done && !/^#/ { print prov; done = 1 } { print }' "${pair%%:*}" > "$OUT.final"
    mv "$OUT.final" "${pair#*:}"
done
echo "regen-lock: wrote $LOCK, $DEV_LOCK and $CI_LOCK for $BASE (${PROV#PROVENANCE })" >&2
