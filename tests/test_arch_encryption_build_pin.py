"""N-432 walresetbug Path-3 hybrid (2026-07-20) — structural pin over the UNIFIED
SQLCipher install path (Containerfile + pyproject).

Prime-directive pin: post-Path-3 both arches source-build the coleifer sqlcipher3
0.6.2 sdist against a freshly-generated SQLCipher v4.17.0 amalgamation (SQLite
3.53.3, the first walresetbug-clean SQLCipher — fix landed at SQLCipher v4.14.0
/ SQLite 3.51.3, 2026-03-17). This pin asserts the WIRING of that unified path
in both the Containerfile build layer AND the pyproject ``encryption`` extra;
a future edit that reintroduces the per-arch split (or drops the SHA pins, the
amalgamation-output sha256 pin, or the build-time floor asserts) fails this
suite BEFORE reaching a build.

HISTORICAL (pre-Path-3): x86_64 pulled prebuilt ``sqlcipher3-binary>=0.5.4,<0.6``
(vendored SQLCipher 4.6.0 = SQLite 3.45.3 = UNPATCHED walresetbug on prod arch);
arm64 source-built coleifer 0.6.2 sdist via ``--require-hashes -r requirements-
sqlcipher-arm64.txt`` (also vendored 3.51.1 — still affected). Both legs now
converge on 3.53.3. Decision + panel record:
internal documentation +
STATE_2026-07-20_0030_edt_walresetbug_path3_containerfile_drafted.md +
mempalace workflow ``wqpqvcbj6`` (3× SME GO-WITH-FIXES).

Count-agnostic: asserts the PRESENCE of the Path-3 shape + cross-surface
consistency of the coleifer distribution — never a magic line count.

PUNCH 538 (2026-09-29) — WHERE THE VALUES NOW LIVE. This pin used to assert the
two commit SHAs as LITERALS (``ENV SQLCIPHER_SHA=810db22f…``) and the SQLite
line as a ``30530[0-9]{2}`` range grep. Both were copies: the Containerfile said
a sha, this pin said the same sha, and ``source-built.pins`` now says it too —
three places to disagree. The declaration is the SSOT, so the asserts here moved
to the WIRING (the build reads the declaration, and each clone checks its
declared sha and tag) while the VALUES come from
``scripts/source_built.py``. What this file still owns is the Path-3 SHAPE: the
unified source build, no per-arch split, no wheel, the amalgamation-generation
mechanics, and the walresetbug floor — which is deliberately NOT folded into the
declaration check, because a floor and an equality answer different questions
(``tests/test_source_built_declaration_pin.py`` owns the equality).
"""

from __future__ import annotations

import re

import pytest

from _pin_harness import CONTAINERFILE as _CF_PATH
from _pin_harness import REPO_ROOT as _REPO  # census run15 #3 — robust repo root
from _pin_harness import dockerfile_code, load_repo_script

_CONTAINERFILE = _CF_PATH.read_text(encoding="utf-8")
_PYPROJECT = (_REPO / "pyproject.toml").read_text(encoding="utf-8")

# Non-comment Containerfile lines only — so a comment that NAMES a forbidden
# path (e.g. "sqlcipher3-binary was the pre-Path-3 amd64 wheel") doesn't trip
# the structural pins, which care about what the build actually RUNS. The filter
# lives in the harness (PD#6): the declaration pin needs the same one, and two
# copies would drift, leaving the weaker of the two as the real coverage.
_CF_CODE = dockerfile_code(_CONTAINERFILE)

# The source-built declaration — the SSOT for every sha, version and tag this
# build uses. Read through the SAME parser the build runs (PD#5).
_SB = load_repo_script("scripts/source_built.py", "_et_source_built")
_DECLARED = {c.name: c for c in _SB.load(_REPO / _SB.PINS_FILENAME)}


# ---------------------------------------------------------------------------
# Containerfile — Path-3 unified rebuild: SHA-pinned upstream sources
# ---------------------------------------------------------------------------


def test_containerfile_pins_sqlcipher_upstream_sha():
    """The SQLCipher checkout is sha-pinned, and the sha comes from the
    DECLARATION rather than an ``ENV`` line in this file.

    A clone by tag name alone is drift-prone (an annotated tag can be re-signed
    onto a different commit), so the ``rev-parse HEAD`` equality is what
    fail-closes. Punch 538 moved the value itself out of the Containerfile: the
    ``ENV SQLCIPHER_SHA=`` line is GONE, and its return is a defect
    (``tests/test_source_built_declaration_pin.py`` forbids any second copy).
    Bumping SQLCipher means editing ``source-built.pins`` and the amalgamation
    output sha256 — nothing else."""
    assert not re.search(r"^\s*ENV\s+SQLCIPHER_SHA=", _CONTAINERFILE, re.M), (
        "ENV SQLCIPHER_SHA is back. The sha must come from source-built.pins "
        "via `source_built.py shell`; an ENV line is a second copy the "
        "declaration can disagree with, and cve-arc silences advisories on the "
        "declaration's word."
    )
    assert 'git -C sqlcipher-src rev-parse HEAD)" = "${SB_SQLCIPHER_SHA}"' in _CF_CODE, (
        "Containerfile must assert git rev-parse HEAD == ${SB_SQLCIPHER_SHA}, "
        "sourced from source-built.pins"
    )
    assert _DECLARED["sqlcipher"].kind == "c"


def test_containerfile_pins_coleifer_sqlcipher3_sha():
    """Same for coleifer/sqlcipher3: sha-pinned, value from the declaration."""
    assert not re.search(r"^\s*ENV\s+SQLCIPHER3_SHA=", _CONTAINERFILE, re.M), (
        "ENV SQLCIPHER3_SHA is back — see test_containerfile_pins_sqlcipher_"
        "upstream_sha for why a second copy is the defect."
    )
    assert 'git -C sqlcipher3-src rev-parse HEAD)" = "${SB_SQLCIPHER3_SHA}"' in _CF_CODE, (
        "Containerfile must assert git rev-parse HEAD == ${SB_SQLCIPHER3_SHA}"
    )
    assert _DECLARED["sqlcipher3"].kind == "pypi"


def test_containerfile_source_builds_sqlcipher3_unified():
    """Path-3: both arches SOURCE-build the coleifer sqlcipher3 sdist against the
    freshly-generated SQLCipher v4.17.0 amalgamation. --no-binary sqlcipher3
    forces the source build; --no-build-isolation skips the sdist's conan build-
    require (whose OpenSSL 3.6.0 rebuild aborts under QEMU); setup.py then links
    Debian's -lcrypto from libssl-dev."""
    assert re.search(r"--no-binary\s+sqlcipher3", _CF_CODE), (
        "Path-3 requires --no-binary sqlcipher3 (source build) on both arches"
    )
    assert "--no-build-isolation" in _CF_CODE, (
        "Path-3 requires --no-build-isolation so setup.py skips conan"
    )


def test_containerfile_source_builds_amalgamation_from_upstream():
    """The amalgamation is generated by shelling coleifer's vendor/update
    mechanics against our SHA-pinned sqlcipher checkout (NOT vendor/update's
    shipped form, which bare-clones master — a supply-chain hole)."""
    assert re.search(
        r"cd\s+sqlcipher-src.*\./configure\s+--disable-tcl",
        _CF_CODE, re.S,
    ), (
        "Path-3 must run ./configure --disable-tcl in the SHA-pinned "
        "sqlcipher checkout to prepare the amalgamation-gen"
    )
    assert re.search(r"make\s+sqlite3\.c\s+sqlite3\.h", _CF_CODE), (
        "Path-3 must run `make sqlite3.c sqlite3.h` to generate the "
        "codec-enabled amalgamation via tclsh"
    )


def test_containerfile_asserts_sqlite_version_in_generated_header():
    """The generated ``sqlite3.h`` must carry EXACTLY the declared SQLite
    version — not a ``3.53.x`` range.

    Punch 538 replaced ``grep -qE '^#define SQLITE_VERSION_NUMBER
    30530[0-9]{2}$'`` with an extract-and-compare against
    ``${SB_SQLITE_VERSION}``. The range was the right shape for a floor and the
    wrong shape for a declared version: cve-arc silences advisories against the
    exact string in ``source-built.pins``, so a 3.53.x point release that is not
    running must not satisfy the check. The range grep returning is a
    regression, so its absence is asserted too."""
    assert "SQLITE_VERSION_NUMBER 30530" not in _CF_CODE, (
        "the 3.53.x RANGE grep is back. A range cannot be the binding behind a "
        "declared version — it accepts point releases the declaration does not "
        "name, which is exactly what a silencing consumer must not be told."
    )
    assert 'SQLITE_VERSION" { v=$3' in _CF_CODE and "${SB_SQLITE_VERSION}" in _CF_CODE, (
        "Path-3 build-time gate: the amalgamation's `#define SQLITE_VERSION` "
        "must be extracted and compared for EQUALITY against the declared "
        "${SB_SQLITE_VERSION} from source-built.pins"
    )


def test_containerfile_amalgamation_sha256_pin_wired():
    """db-sme MF-5: the generated amalgamation is sha256-pinned against
    vendor/sqlite3.expected.sha256 (closes the mksqlite3c.tcl / jimsh0
    non-determinism hole that git-sha input pinning doesn't cover)."""
    assert (
        "vendor/sqlite3.expected.sha256" in _CF_CODE
    ), (
        "Path-3 must COPY vendor/sqlite3.expected.sha256 into the build "
        "context for the amalgamation output sha256 pin"
    )
    assert (
        "sha256sum" in _CF_CODE and "sqlite3.c sqlite3.h" in _CF_CODE
    ), (
        "Path-3 must sha256sum the generated amalgamation and compare vs "
        "the checked-in expected file"
    )


def test_containerfile_build_time_asserts_walresetbug_floor():
    """The builder-stage smoke asserts ``sqlite_version_info >= (3, 51, 3)`` —
    the walresetbug FIX FLOOR, and nothing else about the version.

    This stays a floor on purpose and is NOT merged into the declaration's
    equality check. The two answer different questions and have different
    lifetimes: the floor is the WAL-reset race's lower bound and must survive
    every future version bump without being re-derived, whereas the equality is
    "is the running build the one we declared". Punch 538 removed the
    ``[:2] == (3, 53)`` and ``startswith('4.17.')`` RANGE asserts from both
    smokes, because those were neither — too loose to be the declaration's
    binding, and redundant with the floor.

    Any regression to a pre-fix vendored SQLite fails the BUILD, not runtime."""
    assert re.search(
        r"sqlite_version_info\s*>=\s*\(\s*3\s*,\s*51\s*,\s*3\s*\)", _CF_CODE,
    ), "build-time smoke missing walresetbug floor assertion (>= 3.51.3)"
    assert not re.search(
        r"sqlite_version_info\[:2\]\s*==\s*\(", _CF_CODE,
    ), (
        "a `sqlite_version_info[:2] == (...)` RANGE assert is back. Exact "
        "equality against source-built.pins is `source_built.py verify`'s job; "
        "a two-component range would silently accept a point release the "
        "declaration does not name."
    )
    assert _CF_CODE.count("source_built.py verify") >= 2, (
        "the exact-version check must run in the builder AND in the runtime "
        "stage — a builder-only check is green while a later COPY path diverges"
    )


def test_containerfile_no_pre_path3_wheel_pin():
    """The pre-Path-3 x86_64 branch pulled `sqlcipher3-binary>=0.5.4,<0.6`
    (SQLCipher 4.6.0 = SQLite 3.45.3 = UNPATCHED walresetbug). That form must
    not reappear on any code line; a comment naming the history is fine."""
    assert "sqlcipher3-binary" not in _CF_CODE, (
        "sqlcipher3-binary was the pre-Path-3 amd64 wheel (SQLCipher 4.6.0 = "
        "SQLite 3.45.3, UNPATCHED for walresetbug). Path-3 SOURCE-builds "
        "sqlcipher3 on both arches; if this reappears, walresetbug is back on prod"
    )


def test_containerfile_no_pre_path3_targetarch_branch():
    """Pre-Path-3 branched on ARG TARGETARCH to split per-arch install; Path-3
    is unified. A reintroduced TARGETARCH branch = design regression."""
    assert not re.search(r"^\s*ARG\s+TARGETARCH\b", _CONTAINERFILE, re.M), (
        "Path-3 unified both arches — ARG TARGETARCH branch must not reappear"
    )


def test_containerfile_no_dangling_arm64_requirements_ref():
    """The removed requirements-sqlcipher-arm64.txt must not be referenced."""
    assert "requirements-sqlcipher-arm64.txt" not in _CF_CODE, (
        "requirements-sqlcipher-arm64.txt was deleted with Path-3; no reference "
        "should remain in the Containerfile"
    )


def test_containerfile_no_libsqlcipher_dev():
    """apt libsqlcipher-dev remains the dead path (Debian ships format-
    incompatible SQLCipher 3.x; SQLCipher 4.7+ removed the system lib)."""
    assert "libsqlcipher-dev" not in _CF_CODE, (
        "apt libsqlcipher-dev is the dead/format-incompatible path"
    )


def test_containerfile_runtime_smoke_widened_for_path3():
    """The runtime stage smoke (unchanged bones from the pre-Path-3 posture)
    now also asserts the Path-3 floor + expected SQLCipher line so a future
    base-image bump that regresses vendored SQLite would fail the build."""
    assert "libssl3" in _CF_CODE, "runtime stage must install libssl3 explicitly"
    assert re.search(r"import sqlcipher3", _CF_CODE), (
        "runtime stage must carry a build-time `import sqlcipher3` smoke"
    )
    assert "cipher_version" in _CF_CODE, (
        "runtime smoke must assert SQLCipher cipher_version"
    )
    # Punch 538: the runtime cipher_version check is `source_built.py verify`
    # against the declaration, on the image that SHIPS. It replaced a
    # `startswith('4.17.')` prefix assert — which could not tell 4.17.0 from
    # 4.17.9 and so could not be the binding behind a declared version.
    assert "/app/scripts/source_built.py verify /app/source-built.pins" in _CF_CODE, (
        "the runtime stage must run `source_built.py verify` against the "
        "declaration it ships — this is the run cve-arc's silencing rule rests "
        "on, and the builder's copy does not prove the final image"
    )


# ---------------------------------------------------------------------------
# pyproject — [encryption] extra collapsed to unconditional sqlcipher3==0.6.2
# ---------------------------------------------------------------------------


def _encryption_extra() -> str:
    m = re.search(r"^encryption\s*=\s*\[(.*?)\]", _PYPROJECT, re.S | re.M)
    assert m, "encryption extra not found in pyproject.toml"
    return m.group(1)


def test_pyproject_encryption_unconditional_sqlcipher3():
    """[encryption] extra collapses to a single unconditional pin (Path-3
    unified: both arches source-build against the same amalgamation).

    The VERSION comes from ``source-built.pins`` rather than a literal here, so
    a bump touches the declaration and pyproject only. That the two AGREE is
    ``tests/test_source_built_declaration_pin.py``'s check; this one is about
    the extra's SHAPE (unconditional, no marker)."""
    body = _encryption_extra()
    declared = _DECLARED["sqlcipher3"].version
    assert f'"sqlcipher3=={declared}"' in body, (
        f"[encryption] extra must pin sqlcipher3=={declared} unconditionally — "
        f"the version source-built.pins declares. Got: {body.strip()}"
    )


def test_pyproject_encryption_no_per_arch_split():
    """The pre-Path-3 per-arch platform_machine split is gone."""
    body = _encryption_extra()
    assert "platform_machine" not in body, (
        "Path-3 unified — [encryption] extra must not carry platform_machine "
        "markers anymore"
    )
    assert "sqlcipher3-binary" not in body, (
        "sqlcipher3-binary was the pre-Path-3 x86_64 pin — must not appear "
        "in the collapsed extra"
    )


def test_no_third_party_sqlcipher_forks():
    """No third-party fork / apsw on ANY install surface. sqlcipher3-wheels
    is the disfavored laggykiller-cobuilt pipeline; apsw is not on the
    HIPAA encryption path."""
    for surface in (_CF_CODE, _PYPROJECT):
        assert "sqlcipher3-wheels" not in surface, (
            "third-party sqlcipher3-wheels fork forbidden on encryption path"
        )
        assert "apsw" not in surface, "apsw not on the encryption path"


# ---------------------------------------------------------------------------
# N-616 (punch 634): every archived file reaches its reader in a form that
# reader parses, and the amalgamation sha256 check fails CLOSED with a marker
# ---------------------------------------------------------------------------
# deploy.sh ships ``git archive HEAD``. Under ``core.autocrlf=true`` every text
# file WITHOUT an eol attribute arrived CRLF, and a line-anchored reader then
# matched nothing: that silently turned the amalgamation sha256 check off on
# prod builds from 2026-07-20 (measured on the batch-F deploy context).
#
# The net is keyed on FILES, not on reader shapes (DA, round 2): every
# Containerfile COPY source, and every archived path a sh step reads, is either
# pinned ``eol=lf`` or read ONLY by an explicitly allow-listed CR-tolerant
# reader. A COPY source no RUN reads must name its runtime consumer below.
# Derivation follows absolute paths, ``name=/abs`` assignments in the same RUN,
# relative paths against WORKDIR and any preceding ``cd``, and ``<`` redirects.

_CR_TOLERANT_READERS = frozenset({"pip", "pip3", "python", "python3"})
_NON_READING = frozenset({"test", "[", "ls", "stat", "mkdir", "rm", "mv", "cp", "chmod",
                          "chown", "touch", "echo", "true", ":", "printf"})
_SHELL_WORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while",
                          "until", "for", "!", "{", "}", "set", "export", "exec"})
#: COPY sources that no RUN step reads, with the runtime consumer that does.
#: A new unreferenced COPY source must be listed here (with a CR-tolerant
#: consumer) or pinned ``eol=lf``; otherwise the net fails closed.
_RUNTIME_CONSUMERS: dict[str, str] = {
    "pyproject.toml": "pip",  # `pip install .` / `-e .` name the directory, not the file
    "src/": "python",  # the application package
}
_ABS_PATH_RE = re.compile(r"(/[A-Za-z0-9._-][A-Za-z0-9._/-]*)")  # punch 662: any root; _resolve keeps only COPY destinations
_ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=(/[A-Za-z0-9._/-]+)")
_REL_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]*")
_AMALGAMATION_PIN = "vendor/sqlite3.expected.sha256"
_MARKER = ".amalg-sha256-verified"


def _instructions(text: str) -> list[str]:
    """Dockerfile/shell text as logical lines: continuations joined, comment
    lines dropped."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        if raw.lstrip().startswith("#"):
            continue
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        out.append(buf + raw)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _join(base: str, rel: str) -> str:
    return rel if rel.startswith("/") else base.rstrip("/") + "/" + rel


def _archive_copy_map(cf_text: str) -> dict[str, str]:
    """In-image destination -> repo path, for every COPY from the build context
    (``--from=`` copies carry no archived file). A directory COPY maps a prefix."""
    out: dict[str, str] = {}
    workdir = "/"
    for line in _instructions(cf_text):
        parts = line.split()
        if not parts:
            continue
        op = parts[0].upper()
        if op == "FROM":
            workdir = "/"
        elif op == "WORKDIR" and len(parts) > 1:
            workdir = _join(workdir, parts[1])
        elif op == "COPY" and not any(p.startswith("--from") for p in parts[1:]):
            args = [p for p in parts[1:] if not p.startswith("--")]
            if len(args) != 2:
                continue
            src, dest = args
            dest = _join(workdir, "" if dest == "." else dest)
            if src.endswith("/"):
                out[dest.rstrip("/") + "/"] = src
            elif dest.endswith("/"):
                out[dest + src.rsplit("/", 1)[-1]] = src
            else:
                out[dest] = src
    return out


def _resolve(path: str, copy_map: dict[str, str]) -> str | None:
    if path.startswith("/tmp/et-deploy/"):
        return path[len("/tmp/et-deploy/"):]
    if path in copy_map:
        return copy_map[path]
    for dest, src in copy_map.items():
        if dest.endswith("/") and path.startswith(dest):
            return src + path[len(dest):]
    return None


def archive_file_readers(cf_text: str, deploy_texts: list[str]) -> dict[str, set[str]]:
    """Repo path of every COPY source -> the set of commands that read it."""
    copy_map = _archive_copy_map(cf_text)
    readers: dict[str, set[str]] = {src: set() for src in copy_map.values()}
    for text, is_cf in [(cf_text, True), *((t, False) for t in deploy_texts)]:
        workdir = "/"
        for line in _instructions(text):
            parts = line.split()
            if not parts:
                continue
            if is_cf:
                op = parts[0].upper()
                if op == "FROM":
                    workdir = "/"
                if op == "WORKDIR" and len(parts) > 1:
                    workdir = _join(workdir, parts[1])
                if op != "RUN":
                    continue
                body = line.split(None, 1)[1] if len(parts) > 1 else ""
            else:
                body = line
            names = dict(_ASSIGN_RE.findall(body))
            cwd = workdir
            for segment in re.split(r";|&&|\|\||\|", body):
                for name, value in names.items():
                    segment = re.sub(r"\$\{?" + name + r"\b\}?", value, segment)
                tokens = [t.strip("'\"") for t in segment.split()]
                words = [t for t in tokens if t and not _ASSIGN_RE.fullmatch(t)]
                while words and words[0] in _SHELL_WORDS:
                    words = words[1:]
                cmd = words[0].rsplit("/", 1)[-1] if words else ""
                if cmd == "cd" and len(words) > 1 and not words[1].startswith("$"):
                    cwd = _join(cwd, words[1])
                    continue
                found: list[tuple[str, bool]] = []
                for i, tok in enumerate(tokens):
                    redirected = i > 0 and tokens[i - 1] == "<"
                    for path in _ABS_PATH_RE.findall(tok):
                        found.append((path, redirected))
                    for piece in tok.split("="):
                        if _REL_TOKEN_RE.fullmatch(piece) and "/" not in piece[:1] and i > 0:
                            found.append((_join(cwd, piece), redirected))
                for path, redirected in found:
                    src = _resolve(path, copy_map)
                    if src is not None:
                        readers.setdefault(src, set()).add("read" if redirected or not cmd else cmd)
    return readers


def _gitattributes_eol(text: str, path: str) -> str | None:
    """The eol a .gitattributes text gives ``path`` (last matching rule wins)."""
    import fnmatch

    eol = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern, *attrs = line.split()
        if pattern != path and not fnmatch.fnmatchcase(path, pattern):
            continue
        for attr in attrs:
            if attr.startswith("eol="):
                eol = attr.split("=", 1)[1]
            elif attr in ("-text", "binary", "!eol"):
                eol = None
    return eol


def archive_cr_violations(cf_text: str, deploy_texts: list[str], gitattributes: str) -> list[str]:
    import fnmatch

    out: list[str] = []
    for src, rd in sorted(archive_file_readers(cf_text, deploy_texts).items()):
        if _gitattributes_eol(gitattributes, src) == "lf":
            continue
        strict = sorted(r for r in rd if r not in _CR_TOLERANT_READERS and r not in _NON_READING)
        if strict:
            out.append(f"{src}: read by {strict}, not pinned eol=lf")
        elif not (rd - _NON_READING):
            consumer = next((v for k, v in _RUNTIME_CONSUMERS.items()
                             if src == k or (k.endswith("/") and src.startswith(k))
                             or fnmatch.fnmatchcase(src, k)), None)
            if consumer not in _CR_TOLERANT_READERS:
                out.append(f"{src}: COPYed, no known CR-tolerant reader, not pinned eol=lf")
    return out


def test_every_archived_file_is_lf_or_read_cr_tolerantly():
    gitattributes = (_REPO / ".gitattributes").read_text(encoding="utf-8")
    readers = archive_file_readers(_CONTAINERFILE, [])
    # Non-vacuity: the net must see the readers that motivated it.
    assert {"grep", "sha256sum"} <= readers.get(_AMALGAMATION_PIN, set()), readers
    assert "pip" in readers.get("requirements.lock", set()), readers
    # Punch 662: a /tmp COPY destination must yield a reader (panel N db-sme M2).
    assert "python" in readers.get("requirements-pip.txt", set()), readers
    # The deploy scripts' arm runs in tests/test_deploy_script.py: they do not
    # ship, and a shipped test must not read them (punch 519).
    bad = archive_cr_violations(_CONTAINERFILE, [], gitattributes)
    assert not bad, "CRLF-unsafe archived files:\n  " + "\n  ".join(bad)


@pytest.mark.parametrize("planted, culprit", [
    ("RUN while read -r l; do :; done < /build/requirements.lock\n", "requirements.lock"),
    ("RUN head -1 /build/pyproject.toml\n", "pyproject.toml"),
    ("RUN cd /build && grep -c x requirements.lock\n", "requirements.lock"),
    ("COPY notes.txt /app/notes.txt\n", "notes.txt"),
    ("RUN wc -l /app/source-built.pins\n", "source-built.pins"),
    # Punch 662: a COPY destination outside /build, /app and /tmp/et-deploy.
    ("COPY pyproject.toml /tmp/pp.toml\nRUN head -1 /tmp/pp.toml\n", "pyproject.toml"),
])
def test_cr_net_has_teeth(planted, culprit):
    bad = archive_cr_violations(_CONTAINERFILE + "\n" + planted, [], "")
    assert any(v.startswith(culprit + ":") for v in bad), (planted, bad)


def test_cr_net_accepts_a_tolerant_reader():
    planted = "RUN python3 -c \"open('/build/requirements.lock').read()\"\n"
    readers = archive_file_readers(_CONTAINERFILE + "\n" + planted, [])
    assert "python3" in readers["requirements.lock"]
    bad = archive_cr_violations(_CONTAINERFILE + "\n" + planted, [], "")
    assert not any(v.startswith("requirements.lock:") for v in bad), bad


def test_gitattributes_eol_resolution():
    assert _gitattributes_eol("*.sh text eol=lf\n", _AMALGAMATION_PIN) is None
    assert _gitattributes_eol(f"{_AMALGAMATION_PIN} text eol=lf\nvendor/* -text\n",
                              _AMALGAMATION_PIN) is None
    assert _gitattributes_eol("vendor/*.sha256 text eol=lf\n", _AMALGAMATION_PIN) == "lf"


def test_committed_amalgamation_pin_holds_exactly_two_strict_lf_lines():
    """hipaa r2 fix 1: an emptied, truncated or CRLF pin fails here, in CI,
    before any build could meet it."""
    raw = (_REPO / _AMALGAMATION_PIN).read_bytes()
    assert b"\r" not in raw, f"{_AMALGAMATION_PIN} carries CR bytes"
    assert raw.endswith(b"\n"), f"{_AMALGAMATION_PIN} must end with a newline"
    lines = raw.decode("ascii").split("\n")[:-1]
    names = sorted(m.group(1) for ln in lines
                   if (m := re.fullmatch(r"[0-9a-f]{64}  (sqlite3\.[ch])", ln)))
    assert names == ["sqlite3.c", "sqlite3.h"] and len(lines) == 2, lines


def _amalgamation_check_body(cf_text: str) -> str:
    """The exact shell body of the amalgamation sha256 RUN (continuations kept)."""
    lines = cf_text.splitlines()
    i = next(k for k, ln in enumerate(lines)
             if ln.strip().startswith("pin=/build/vendor/sqlite3.expected.sha256;"))
    start = i
    while not lines[start].lstrip().startswith("RUN "):
        start -= 1
    end = i
    while lines[end].rstrip().endswith("\\"):
        end += 1
    return "\n".join(lines[start:end + 1]).split("RUN ", 1)[1]


def test_amalgamation_check_shape_is_fail_closed():
    body = _amalgamation_check_body(_CONTAINERFILE)
    absent = body[body.index('if [ ! -s "$pin" ]; then'):]
    absent = absent[:absent.index("fi;")]
    assert "exit 1" in absent, "an absent or empty pin must stop the build"
    assert "strict lines (CRLF?)" in body
    check = body.index('if ! sha256sum -c "$pin" > "$marker.tmp"; then')
    assert check > body.index('if [ "$strict" -lt 2 ]; then'), "marker before the strict count"
    assert body.rstrip().endswith('mv "$marker.tmp" "$marker"'), "the marker must be the last write"
    # CR-stripping would mask the .gitattributes fix (lead decision, punch 634).
    for masking in ("tr -d", "\\r", "dos2unix", "sed -i", "ARG"):
        assert masking not in body, masking


_MARKER_WRITE_RE = re.compile(
    r"(?:>>?|\btee\b|\bmv\b|\bcp\b|\btouch\b|\binstall\b)[^;&|]*?"
    r"(?:\$marker\b|\$\{marker\}|/build/\.amalg-sha256-verified|/app/\.amalg-sha256-verified)"
)


def marker_shape_violations(cf_text: str) -> list[str]:
    out: list[str] = []
    instr = _instructions(cf_text)
    writers = [ln for ln in instr if ln.split()[:1] == ["RUN"] and _MARKER_WRITE_RE.search(ln)]
    if len(writers) != 1 or "pin=/build/vendor/sqlite3.expected.sha256;" not in writers[0]:
        out.append(f"the marker must be written by exactly the amalgamation RUN, found {len(writers)} writer(s)")
    copies = [ln for ln in instr if ln.split()[:1] == ["COPY"] and _MARKER in ln]
    if copies != ["COPY --from=builder /build/.amalg-sha256-verified /app/.amalg-sha256-verified"]:
        out.append(f"the marker must arrive only via COPY --from=builder, found {copies}")
    asserts = [ln for ln in instr if ln.split()[:1] == ["RUN"]
               and "m=/app/.amalg-sha256-verified;" in ln
               and "p=/app/vendor/sqlite3.expected.sha256;" in ln
               and 'grep -qxF "$want" "$m"' in ln and 'sha256sum < "$p"' in ln]
    if len(asserts) != 1:
        out.append("no final-stage assert compares the marker's pin sha with the shipped pin file")
    elif copies and instr.index(asserts[0]) < instr.index(copies[0]):
        out.append("the final-stage assert runs before the marker is copied in")
    return out


def test_amalgamation_marker_shape():
    bad = marker_shape_violations(_CONTAINERFILE)
    assert not bad, bad


@pytest.mark.parametrize("mutate", [
    lambda t: t + "\nRUN touch /build/.amalg-sha256-verified\n",
    lambda t: t + "\nCOPY .amalg-sha256-verified /app/.amalg-sha256-verified\n",
    lambda t: t.replace('grep -qxF "$want" "$m"', "true"),
])
def test_amalgamation_marker_shape_has_teeth(mutate):
    assert marker_shape_violations(mutate(_CONTAINERFILE))


def test_amalgamation_check_fails_closed_under_sh(tmp_path):
    """Runs the Containerfile's own step body under dash (the image's /bin/sh)
    against planted pin files, and checks the marker only the strict pass writes."""
    import hashlib
    import shutil
    import subprocess
    import sys

    import pytest

    if sys.platform == "win32":
        pytest.skip("MSYS grep reads CRLF as a line end, unlike the image's GNU grep; "
                    "CI (Linux) and the in-image pass run this arm under dash")
    sh = shutil.which("dash") or shutil.which("sh")
    if sh is None:
        pytest.skip("no POSIX sh here; CI and the in-image pass run this")
    amalg = tmp_path / "amalg"
    amalg.mkdir()
    (amalg / "sqlite3.c").write_bytes(b"int c;\n")
    (amalg / "sqlite3.h").write_bytes(b"int h;\n")
    digest = {n: hashlib.sha256((amalg / n).read_bytes()).hexdigest()
              for n in ("sqlite3.c", "sqlite3.h")}
    good = [f"{digest['sqlite3.c']}  sqlite3.c", f"{digest['sqlite3.h']}  sqlite3.h"]
    cases = {
        "absent": (None, 1, "is absent or empty"),
        "empty": ("", 1, "is absent or empty"),
        "crlf": ("\r\n".join(good) + "\r\n", 1, "0 strict lines (CRLF?)"),
        "one-line": (good[0] + "\n", 1, "1 strict lines (CRLF?)"),
        "drift": ("0" * 64 + "  sqlite3.c\n" + good[1] + "\n", 1, "AMALGAMATION SHA DRIFT"),
        "good": ("\n".join(good) + "\n", 0, "STRICT MODE"),
    }
    body = _amalgamation_check_body(_CONTAINERFILE)
    for case, (content, want_fail, needle) in cases.items():
        pin = tmp_path / f"{case}.sha256"
        marker = tmp_path / f"{case}.marker"
        if content is not None:
            pin.write_bytes(content.encode("ascii"))
        script = body
        for old, new in (
            ("pin=/build/vendor/sqlite3.expected.sha256;", f"pin='{pin.as_posix()}';"),
            ("amalg=/build/vendor-build/sqlcipher3-src/vendor;", f"amalg='{amalg.as_posix()}';"),
            ("marker=/build/.amalg-sha256-verified;", f"marker='{marker.as_posix()}';"),
        ):
            assert script.count(old) == 1, ("input not found", old)
            script = script.replace(old, new)
        r = subprocess.run([sh, "-c", script], capture_output=True, text=True, timeout=60)
        out = r.stdout + r.stderr
        assert (r.returncode != 0) == bool(want_fail), (case, sh, r.returncode, out[-1200:])
        assert needle in out, (case, needle, out[-1200:])
        if want_fail:
            assert not marker.exists(), (case, "a failed check must leave no marker")
            if case != "drift":
                assert digest["sqlite3.c"] in out and digest["sqlite3.h"] in out, (
                    case, "the failure must print the computed lines ready to pin")
        else:
            lines = marker.read_text(encoding="ascii").splitlines()
            pin_sha = hashlib.sha256(pin.read_bytes()).hexdigest()
            assert lines == ["sqlite3.c: OK", "sqlite3.h: OK", f"pin-sha256 {pin_sha}"], lines
