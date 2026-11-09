#!/usr/bin/env python3
"""The ONE reader of ``source-built.pins`` — shared by the build and the CI pin.

Punch 538 / cve-arc task  (2026-09-29). ``source-built.pins`` declares the
components this image builds from upstream source (they are in neither
``pyproject.toml`` nor ``requirements.lock``, so a manifest-reading scanner is
blind to them). The declaration is only worth something if the BUILD reads it,
and only stays worth something if exactly one parser exists: two parsers drift,
and a line this build ignores could still be read by a consumer as truth
(Prime Directive #5 — one funnel, re-exported by callers).

So this module is that funnel. The Containerfile sources ``shell`` for every
sha/version/tag it uses, and runs ``verify`` twice (builder + runtime).
``tests/test_source_built_declaration_pin.py`` imports THIS file rather than
re-deriving the grammar.

Subcommands
-----------
``parse``   Validate the file. Exit 0 and echo each component normalised, or
            exit non-zero on ANY malformed shape.
``shell``   Print ``SB_<NAME>_{KIND,VERSION,REPO,SHA,TAG}=`` assignments for a
            POSIX shell to ``eval``. Under ``set -eu`` an unset ``SB_*`` is a
            fatal error at use, so a component silently dropped from the file
            breaks the build rather than falling back to a default.
``verify``  In a BUILT environment, compare the declaration against what is
            actually installed and loaded. Prints every observed value and
            exits non-zero on any mismatch — or on a declared component it has
            no observation for, which is the fail-closed case that matters:
            a new ``c`` line must teach this function how to observe it, or
            the build stops.

Stdlib only, on purpose: it runs in the builder stage before anything but pip's
own dependencies exist, and in the runtime stage where the toolchain is gone.

Exit codes: 0 ok; 2 the declaration is malformed; 3 the built environment
disagrees with the declaration.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

#: The declaration's filename, relative to the repo (or image) root.
PINS_FILENAME = "source-built.pins"

#: ``pypi`` = a Python distribution ``importlib.metadata`` can report;
#: ``c`` = a C library compiled into the extension. The column exists so a
#: consumer never queries the PyPI namespace for a C library name.
KINDS = ("pypi", "c")

#: Exactly six columns. Anything else — including a trailing ``#`` comment,
#: which tokenises as a seventh column — is rejected.
COLUMNS = 6

_SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_REPO_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_VERSION_RE = re.compile(r"\A[0-9][A-Za-z0-9.+_-]*\Z")
_TAG_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9./+_-]*\Z")
#: ``SB_`` variable-name sanitiser — the declared name uppercased, with every
#: character a POSIX shell name cannot carry folded to ``_``.
_SHELL_UNSAFE_RE = re.compile(r"[^A-Z0-9_]")


class DeclarationError(ValueError):
    """The declaration file is malformed. Always fatal — never a warning."""


class VerificationError(RuntimeError):
    """The built environment disagrees with the declaration."""


class Component(NamedTuple):
    """One declared source-built component."""

    kind: str
    name: str
    version: str
    repo: str
    sha: str
    tag: str
    lineno: int

    @property
    def repo_name(self) -> str:
        """The repository's own name — the part after ``owner/``."""
        return self.repo.split("/", 1)[1]

    @property
    def embedded(self) -> bool:
        """True when this component has NO clone of its own.

        ``sqlite`` is declared against ``sqlcipher/sqlcipher`` because the
        SQLCipher amalgamation IS SQLite: one checkout, one binary, two
        identities a CVE feed files under. The test is structural rather than
        a hand-kept list — a name that is not its repository's name cannot
        have been cloned from a repository of that name — so a fourth
        component added tomorrow classifies itself.
        """
        return self.name != self.repo_name

    @property
    def shell_prefix(self) -> str:
        """``SB_SQLCIPHER3`` for ``sqlcipher3`` — the shell variable stem."""
        return "SB_" + _SHELL_UNSAFE_RE.sub("_", self.name.upper())


def parse_text(text: str, *, source: str = PINS_FILENAME) -> list[Component]:
    """Parse the declaration, or raise :class:`DeclarationError`.

    Fails closed on every shape: a wrong column count, an unknown kind, a
    duplicate name, two names that collapse to one ``SB_*`` shell stem, a sha
    that is not 40 lowercase hex, a malformed version/repo/tag, an embedded
    line whose ``repo@sha`` matches no non-embedded line, two rows disagreeing
    about one repository's sha, and an empty file (which would otherwise make
    ``verify`` vacuously green).
    """
    components: list[Component] = []
    seen: dict[str, int] = {}
    stems: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != COLUMNS:
            raise DeclarationError(
                f"{source}:{lineno}: expected {COLUMNS} whitespace-separated "
                f"columns <kind> <name> <version> <owner>/<repo> <40-hex sha> "
                f"<tag>, got {len(fields)}. There are no trailing comments: a "
                f"'#' after the sixth column is a seventh column."
            )
        kind, name, version, repo, sha, tag = fields
        if kind not in KINDS:
            raise DeclarationError(
                f"{source}:{lineno}: unknown kind {kind!r}; expected one of "
                f"{', '.join(KINDS)}"
            )
        if not _NAME_RE.match(name):
            raise DeclarationError(f"{source}:{lineno}: malformed name {name!r}")
        if name in seen:
            raise DeclarationError(
                f"{source}:{lineno}: duplicate name {name!r} (first declared on "
                f"line {seen[name]}). One component, one row — two rows for one "
                f"name is exactly the divergence this file exists to remove."
            )
        if not _VERSION_RE.match(version):
            raise DeclarationError(
                f"{source}:{lineno}: malformed version {version!r} (no leading 'v')"
            )
        if not _REPO_RE.match(repo):
            raise DeclarationError(
                f"{source}:{lineno}: malformed repository {repo!r}; expected "
                f"<owner>/<repo>"
            )
        if not _SHA_RE.match(sha):
            raise DeclarationError(
                f"{source}:{lineno}: {sha!r} is not a 40-character lowercase-hex "
                f"commit sha. It must be the PEELED COMMIT sha, never an "
                f"annotated-tag object sha."
            )
        if not _TAG_RE.match(tag):
            raise DeclarationError(f"{source}:{lineno}: malformed tag {tag!r}")
        comp = Component(kind, name, version, repo, sha, tag, lineno)
        # db-sme N-538-D1 (panel 4, 2026-09-29). The duplicate guard above is
        # keyed on the declared NAME, but `_SHELL_UNSAFE_RE` folds '-', '_' and
        # '.' all to '_', and `_NAME_RE` admits all three — so `my-lib` and
        # `my_lib` are two LEGAL distinct names sharing one `SB_*` stem. The
        # build sources what `shell` emits, so the later row's assignments
        # would silently overwrite the earlier row's and the parser would exit
        # 0. Read the stem off the Component's own property rather than
        # recomputing it here: this guard and the emitter must not be able to
        # disagree about what a stem is.
        prior = stems.get(comp.shell_prefix)
        if prior is not None:
            raise DeclarationError(
                f"{source}:{lineno}: {name!r} and {prior!r} (line "
                f"{seen[prior]}) both reduce to the shell variable stem "
                f"{comp.shell_prefix} — '-', '_' and '.' all fold to '_'. The "
                f"build sources these assignments, so one component's values "
                f"would silently replace the other's. Rename one."
            )
        stems[comp.shell_prefix] = name
        seen[name] = lineno
        components.append(comp)

    if not components:
        raise DeclarationError(
            f"{source}: no data lines. An empty declaration would make every "
            f"downstream check vacuously true; a build with nothing source-built "
            f"should not carry this file at all."
        )

    by_repo: dict[str, Component] = {}
    for comp in components:
        prior = by_repo.setdefault(comp.repo, comp)
        if prior.sha != comp.sha:
            raise DeclarationError(
                f"{source}:{comp.lineno}: {comp.repo} is declared at {comp.sha} "
                f"here and at {prior.sha} on line {prior.lineno}. One checkout "
                f"has one sha."
            )

    clone_sources = {(c.repo, c.sha) for c in components if not c.embedded}
    for comp in components:
        if comp.embedded and (comp.repo, comp.sha) not in clone_sources:
            raise DeclarationError(
                f"{source}:{comp.lineno}: {comp.name!r} is embedded (its name is "
                f"not its repository's name, so it has no clone of its own), but "
                f"nothing non-embedded declares {comp.repo}@{comp.sha}. An "
                f"embedded component must ride on a checkout the build actually "
                f"makes."
            )
    return components


def load(path: Path | str) -> list[Component]:
    """Read and parse the declaration at ``path``."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise DeclarationError(f"cannot read {p}: {exc}") from exc
    return parse_text(text, source=str(p))


def default_pins_path(start: Path | str | None = None) -> Path:
    """``source-built.pins`` beside this script's parent directory.

    ``scripts/source_built.py`` -> ``<root>/source-built.pins``, which holds in
    the repo, in the builder stage (``/build``) and in the runtime stage
    (``/app``). Callers that know the path should pass it explicitly.
    """
    here = Path(start) if start is not None else Path(__file__).resolve()
    return here.parent.parent / PINS_FILENAME


def shell_assignments(components: list[Component]) -> list[str]:
    """``SB_<NAME>_<FIELD>='<value>'`` assignments for a POSIX shell to ``eval``.

    Every value has already been validated against a character class with no
    quote, backslash or whitespace in it, so single-quoting is sufficient and
    the eval cannot be turned into an injection by editing the declaration.

    Deliberately no ``export`` and no ``:-`` default anywhere: under ``set -u``
    a component dropped from the declaration becomes an unbound-variable error
    at the point of use, which fails the build. A default would silence it.
    """
    out: list[str] = []
    for comp in components:
        stem = comp.shell_prefix
        for field, value in (
            ("KIND", comp.kind),
            ("VERSION", comp.version),
            ("REPO", comp.repo),
            ("SHA", comp.sha),
            ("TAG", comp.tag),
        ):
            out.append(f"{stem}_{field}='{value}'")
    return out


def observe(components: list[Component], *,
            site_dir: str | None = None) -> list[tuple[Component, str]]:
    """Observe each declared component in the CURRENT environment.

    ``site_dir`` is passed through ``site.addsitedir`` first — the builder
    installs under ``--prefix=/install``, which is not on ``sys.path`` and
    whose ``.pth`` files matter; the runtime stage needs nothing.

    Raises :class:`VerificationError` for a declared component this function
    has no way to observe. That is the fail-closed arm: a future ``c`` entry
    (say a separately declared libcrypto) must be taught here, and until it is
    the build stops rather than reporting a green it did not measure.
    """
    if site_dir:
        import site

        site.addsitedir(site_dir)

    from importlib.metadata import version as _dist_version

    import sqlcipher3.dbapi2 as dbapi2

    conn = dbapi2.connect(":memory:")
    try:
        row = conn.execute("PRAGMA cipher_version").fetchone()
    finally:
        conn.close()
    if not row or not str(row[0]).strip():
        raise VerificationError(
            "PRAGMA cipher_version returned nothing — the loaded extension is "
            "not SQLCipher, so encryption at rest would be a silent no-op."
        )
    # "4.19.0 community" -> "4.19.0". The build string carries an edition
    # suffix; the version is its first token.
    cipher_version = str(row[0]).split()[0]

    observed: list[tuple[Component, str]] = []
    for comp in components:
        if comp.kind == "pypi":
            got = _dist_version(comp.name)
        elif comp.name == "sqlcipher":
            got = cipher_version
        elif comp.name == "sqlite":
            got = dbapi2.sqlite_version
        else:
            raise VerificationError(
                f"{comp.name!r} is declared (kind {comp.kind!r}) but this "
                f"verifier has no observation for it. Teach observe() how to "
                f"read its version — never skip it: an unobserved declaration "
                f"is a version a consumer would trust on our word alone."
            )
        observed.append((comp, str(got)))
    return observed


def verify(components: list[Component], *, site_dir: str | None = None,
           out=None) -> None:
    """Print every observed value, then raise on ANY mismatch."""
    stream = sys.stdout if out is None else out
    observed = observe(components, site_dir=site_dir)
    mismatches = []
    for comp, got in observed:
        ok = got == comp.version
        print(
            f"source-built {comp.kind:4} {comp.name:12} declared={comp.version:8} "
            f"observed={got:8} {'OK' if ok else 'MISMATCH'}",
            file=stream,
        )
        if not ok:
            mismatches.append(f"{comp.name}: declared {comp.version}, observed {got}")
    if mismatches:
        raise VerificationError(
            "the built environment disagrees with source-built.pins: "
            + "; ".join(mismatches)
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="source_built.py",
        description="Read source-built.pins — the one parser the build and the "
                    "CI pin share.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, help_text in (
        ("parse", "validate the declaration and echo it normalised"),
        ("shell", "print SB_* shell assignments for the build to eval"),
        ("verify", "compare the declaration against the built environment"),
    ):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument(
            "path", nargs="?", default=None,
            help=f"path to {PINS_FILENAME} (default: beside the repo/image root)",
        )
        if name == "verify":
            sp.add_argument(
                "--site-dir", default=None,
                help="site-packages directory to addsitedir before importing "
                     "(the builder's --prefix install is not on sys.path)",
            )
    args = ap.parse_args(argv)

    path = Path(args.path) if args.path else default_pins_path()
    try:
        components = load(path)
    except DeclarationError as exc:
        print(f"source-built.pins: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "parse":
        for comp in components:
            print(
                f"{comp.kind} {comp.name} {comp.version} {comp.repo} {comp.sha} "
                f"{comp.tag}" + ("  # embedded" if comp.embedded else "")
            )
        return 0

    if args.cmd == "shell":
        for assignment in shell_assignments(components):
            print(assignment)
        return 0

    try:
        verify(components, site_dir=args.site_dir)
    except VerificationError as exc:
        print(f"source-built.pins: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # pragma: no cover - import/runtime failure
        # Fail CLOSED: an import error here means the encryption binding did
        # not load, which must break the build, not be reported as unverified.
        print(f"source-built.pins: verification could not run: {exc!r}",
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
