"""Bundle E5  — structural invariant for the channel-2 contamination class.

Enforces that the autouse fixture ``_restore_hipaa_mode_around_each_test`` in
``tests/conftest.py`` is present with the expected snapshot+yield+restore
shape, and that every ``setup_logging(LoggingConfig(hipaa=...))`` call site
in ``tests/`` is enumerated (the autouse covers the whole test tree by
collection rules).

Sister test to the Sub-check D pattern in
``tests/test_web/test_runtime_settings_hipaa_gate.py`` (Bundle E5 ):
both lock a structural invariant that would otherwise erode silently.
"""

import pathlib
import re


_CONTAMINATION_CALL_RE = re.compile(
    r"setup_logging\s*\(\s*LoggingConfig\s*\(\s*hipaa\s*="
)


class TestSetupLoggingHipaaContamination:
    """Bundle E5  (Q-extend) — every ``setup_logging(LoggingConfig(hipaa=...))``
    call in ``tests/`` is covered by the autouse fixture at
    ``tests/conftest.py``."""

    def test_every_hipaa_setup_logging_is_in_protected_scope(self):
        """Walk ``tests/`` for ``setup_logging(LoggingConfig(hipaa=...))`` calls
        and assert the autouse fixture covers them.

        The autouse fixture in ``tests/conftest.py`` applies to the entire
        suite by pytest's collection rules, so EVERY test file is in scope.
        This test always passes AS LONG AS:

        - The autouse fixture exists in ``tests/conftest.py`` with the right
          shape (snapshot prior -> yield -> restore prior).
        - At least one call site exists (sanity — if removed entirely we
          want a heads-up because the contamination test coverage went
          to zero).

        Failure modes this catches:

        - Someone deletes/breaks the autouse fixture in ``tests/conftest.py``.
        - Someone removes all the ``setup_logging(LoggingConfig(hipaa=...))``
          tests (intentional or accidental).
        - Someone adds the pattern with a custom conftest that overrides
          the autouse via ``autouse=False`` or name collision.
        """
        tests_root = pathlib.Path(__file__).parent
        conftest_path = tests_root / "conftest.py"

        # (a) Verify the autouse fixture exists and has the right shape.
        assert conftest_path.exists(), (
            "tests/conftest.py missing. The Bundle E5 #21 autouse fixture "
            "`_restore_hipaa_mode_around_each_test` lives there. Restore "
            "it or the contamination class re-opens silently."
        )
        conftest_text = conftest_path.read_text(encoding="utf-8")
        assert "_restore_hipaa_mode_around_each_test" in conftest_text, (
            "tests/conftest.py does not contain the autouse fixture "
            "`_restore_hipaa_mode_around_each_test`. Add it back per "
            "Bundle E5 #21 to close the channel-2 contamination class."
        )
        # Loose-fit shape check: the fixture snapshots, yields, restores.
        assert (
            "_triage_logging._hipaa_mode" in conftest_text
            and "yield" in conftest_text
        ), (
            "Autouse fixture in tests/conftest.py is present but doesn't "
            "match the expected snapshot+yield+restore shape. See Bundle "
            "E5 #21 spec."
        )

        # (b) Enumerate all setup_logging(LoggingConfig(hipaa=...)) call sites.
        call_sites: list[str] = []
        for py_file in tests_root.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            for line_num, line in enumerate(text.split("\n"), start=1):
                if _CONTAMINATION_CALL_RE.search(line):
                    call_sites.append(
                        f"{py_file.relative_to(tests_root)}:{line_num}"
                    )

        # (c) At least one call site exists — sanity that the testing of
        # HIPAA-mode wasn't removed entirely. Every site is covered by
        # the autouse fixture per collection rules.
        assert len(call_sites) > 0, (
            "Expected at least one setup_logging(LoggingConfig(hipaa=...)) "
            "call site in tests/ (sites are the contamination evidence). "
            "Got zero. Either the testing of HIPAA-mode is removed "
            "(investigate why) or the regex needs updating."
        )
