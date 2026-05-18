"""Smoke tests for ``scripts/deploy.sh`` integration with the
``version-check`` pre-flight gate (#125 partial follow-up).

These are bash-level shape checks — we ``grep`` the script for the
required call patterns rather than executing it. The script SSHes into
a real deploy host + manages a systemd quadlet; the integration test
proper is "operator runs it next time."

Run alongside :mod:`tests.test_cli_version_check` to cover both ends
of the contract.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_SH = REPO_ROOT / "scripts" / "deploy.sh"


# ---------------------------------------------------------------------------
# Sanity: the script exists + parses.
# ---------------------------------------------------------------------------

class TestSyntax:
    def test_deploy_sh_exists(self):
        assert DEPLOY_SH.is_file(), (
            f"scripts/deploy.sh missing at {DEPLOY_SH}"
        )

    def _find_real_bash(self) -> str | None:
        """Locate a real GNU bash (skipping the Windows WSL stub).

        On Windows, ``shutil.which("bash")`` typically resolves to
        ``C:\\Windows\\System32\\bash.exe`` — the WSL launcher. When
        WSL has no installed distribution the stub exits non-zero on
        every invocation, which would make this test falsely fail.
        Prefer Git Bash / MSYS2 when available.
        """
        candidates = [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
            "/usr/bin/bash",
            "/bin/bash",
        ]
        for c in candidates:
            if Path(c).is_file():
                return c
        # Fall through to PATH lookup, but reject the WSL stub.
        path_bash = shutil.which("bash")
        if path_bash and "System32" not in path_bash:
            return path_bash
        return None

    def test_deploy_sh_parses(self):
        """``bash -n`` is a syntax check that does not execute the
        script. Catches unterminated strings, missing fi/done, etc."""
        bash = self._find_real_bash()
        if bash is None:
            pytest.skip("No real bash on PATH (WSL stub doesn't count)")
        result = subprocess.run(
            [bash, "-n", str(DEPLOY_SH)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"bash -n scripts/deploy.sh failed:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )


# ---------------------------------------------------------------------------
# The version-check integration must be wired into deploy.sh.
# Each test pins one specific pattern; if any of them break, the
# integration regressed.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def deploy_script_text() -> str:
    return DEPLOY_SH.read_text(encoding="utf-8")


class TestForceFlag:
    def test_force_flag_is_parsed(self, deploy_script_text):
        """``--force`` must be a recognised CLI flag (else the script
        rejects it with exit 64 — unhelpful for an operator who needs
        to bypass the gate after taking a snapshot)."""
        assert "--force) FORCE=1" in deploy_script_text or re.search(
            r"--force\)\s*FORCE=1", deploy_script_text,
        ), "deploy.sh must recognise --force"

    def test_force_default_is_zero(self, deploy_script_text):
        assert re.search(r"^FORCE=0\b", deploy_script_text, re.MULTILINE), (
            "deploy.sh must default FORCE=0"
        )


class TestPreviousSchemaExtraction:
    """Step 4b: extract the :previous image's schema cap via the
    new --print-target-schema-only CLI flag."""

    def test_calls_print_target_schema_only(self, deploy_script_text):
        assert "--print-target-schema-only" in deploy_script_text, (
            "deploy.sh must call `version-check --print-target-schema-only`"
            " to extract the :previous image's schema cap"
        )

    def test_runs_against_previous_image(self, deploy_script_text):
        """The extraction must use the :previous image (otherwise we'd
        be reading the cap of the running image, which is what we're
        ABOUT to replace — wrong direction)."""
        # The relevant block runs `podman run ... :previous version-check`.
        assert re.search(
            r"localhost/email-triage:previous\s+version-check"
            r"\s+--print-target-schema-only",
            deploy_script_text,
        ), "deploy.sh must run version-check --print-target-schema-only "\
            "inside a :previous container"

    def test_stores_into_previous_schema_caps_var(self, deploy_script_text):
        """The captured cap must land in a variable named
        PREVIOUS_SCHEMA_CAPS so the pre-flight call (and the quadlet
        drop-in) can reference it."""
        assert "PREVIOUS_SCHEMA_CAPS=" in deploy_script_text

    def test_sanitises_extracted_value(self, deploy_script_text):
        """The captured value must be sanity-checked as a positive
        integer — older :previous images that predate the flag will
        produce garbage, and we must NOT inject that into the env
        var (would corrupt the banner)."""
        assert re.search(
            r"\[\[ \"\$PREVIOUS_SCHEMA_CAPS\" =~ \^\[1-9\]\[0-9\]\*\$ \]\]",
            deploy_script_text,
        ), "deploy.sh must regex-validate the cap as a positive integer"


class TestPreFlightGate:
    """Step 5b: run version-check against the freshly-built :latest
    image with the live DB read-only + the previous cap injected."""

    def test_runs_version_check_with_json(self, deploy_script_text):
        """The gate uses --json so the script can disambiguate the
        two status-2 cases (incompatible_rollback vs.
        downgrade_not_supported)."""
        assert "version-check --db /data/triage.db --json" in deploy_script_text

    def test_injects_previous_schema_caps_env(self, deploy_script_text):
        """The pre-flight container must receive
        EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS via -e — otherwise the
        helper has no way to spot the rollback-incompat case."""
        # The shape we wrote: `-e EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS=$PREVIOUS_SCHEMA_CAPS`
        assert "-e EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS=" in deploy_script_text

    def test_mounts_live_db_readonly(self, deploy_script_text):
        """The gate must read the LIVE DB (mounted read-only) — running
        version-check against an empty DB would always say up_to_date
        and silently skip the gate."""
        assert "/srv/email-triage/data:/data:ro" in deploy_script_text

    def test_exit_code_2_with_incompatible_status_halts_without_force(
        self, deploy_script_text,
    ):
        """Status incompatible_rollback + no --force ⇒ exit 4."""
        # Look for a branch that mentions "incompatible_rollback" and
        # then exits with code 4 nearby.
        m = re.search(
            r"incompatible_rollback[\s\S]{0,1500}?\bexit 4\b",
            deploy_script_text,
        )
        assert m is not None, (
            "deploy.sh must exit 4 when version-check reports "
            "incompatible_rollback without --force"
        )

    def test_force_override_is_respected(self, deploy_script_text):
        """--force lets incompatible_rollback proceed (operator
        accepted the risk)."""
        # The relevant branch checks $FORCE and logs a warn.
        assert re.search(
            r'FORCE.*=.*1.*[\s\S]{0,500}--force passed',
            deploy_script_text,
        ) or '"$FORCE" = 1' in deploy_script_text, (
            "deploy.sh must check $FORCE in the incompatible_rollback branch"
        )

    def test_downgrade_aborts_regardless_of_force(self, deploy_script_text):
        """status downgrade_not_supported must abort even with
        --force — overriding it would corrupt data."""
        # The downgrade branch must NOT check $FORCE — it exits 4
        # unconditionally. Verify the branch exists + exits 4.
        m = re.search(
            r"downgrade_not_supported[\s\S]{0,800}?\bexit 4\b",
            deploy_script_text,
        )
        assert m is not None, (
            "deploy.sh must exit 4 on downgrade_not_supported "
            "regardless of --force"
        )

    def test_gate_is_skippable_via_skip_validate(self, deploy_script_text):
        """For emergency / known-good deploys, --skip-validate must
        bypass the gate (same boundary as the init_db pre-flight)."""
        # The gate must be inside an `if [ "$SKIP_VALIDATE" = 0 ]; then ... fi`
        # block that mentions version-check.
        assert re.search(
            r'SKIP_VALIDATE.*=.*0[\s\S]{0,2500}version-check',
            deploy_script_text,
        ), "version-check gate must be inside the SKIP_VALIDATE block"


class TestFromRegistryFlag:
    """CR-2a: --from-registry <tag> opt-in flag for the GHCR-pull
    code path. When present, source-staging + build are skipped and
    cosign verification + pull run instead."""

    def test_from_registry_flag_is_parsed(self, deploy_script_text):
        assert "--from-registry) FROM_REGISTRY=" in deploy_script_text or re.search(
            r"--from-registry\)\s*FROM_REGISTRY=", deploy_script_text,
        ), "deploy.sh must recognise --from-registry"

    def test_from_registry_default_is_empty(self, deploy_script_text):
        """Default empty string means the existing --from-source
        behaviour is unchanged."""
        assert re.search(r'^FROM_REGISTRY=""', deploy_script_text, re.MULTILINE), (
            "deploy.sh must default FROM_REGISTRY to empty"
        )

    def test_registry_image_flag_is_parsed(self, deploy_script_text):
        """The image-base override is necessary so the namespace
        isn't baked into the script (publish-scrub compliance)."""
        assert "--registry-image) REGISTRY_IMAGE=" in deploy_script_text

    def test_source_staging_gated_on_from_registry(self, deploy_script_text):
        """The ``git archive HEAD`` line that ships source to the
        deploy host must be inside an ``if [ -z $FROM_REGISTRY ]``
        branch -- registry mode has no source to stage."""
        # Look for the pattern: the source-staging block is gated.
        m = re.search(
            r'if\s+\[\s+-z\s+"\$FROM_REGISTRY"\s+\][\s\S]{0,800}?'
            r'git archive HEAD',
            deploy_script_text,
        )
        assert m is not None, (
            "deploy.sh must gate 'git archive HEAD' on -z $FROM_REGISTRY"
        )

    def test_build_gated_on_from_registry(self, deploy_script_text):
        """``podman build`` must be inside the same source-mode
        guard -- registry mode tags the verified pull as :latest
        directly, no local build."""
        m = re.search(
            r'if\s+\[\s+-z\s+"\$FROM_REGISTRY"\s+\][\s\S]{0,400}?'
            r'sudo podman build',
            deploy_script_text,
        )
        assert m is not None, (
            "deploy.sh must gate 'sudo podman build' on -z $FROM_REGISTRY"
        )

    def test_podman_pull_uses_registry_ref(self, deploy_script_text):
        """The pull step must reference ``$REGISTRY_REF`` (composed
        from $REGISTRY_IMAGE:$FROM_REGISTRY) rather than a bare
        ``:latest`` tag."""
        assert re.search(
            r'sudo podman pull \$REGISTRY_REF',
            deploy_script_text,
        ), "deploy.sh must pull via $REGISTRY_REF in registry-pull mode"


class TestCosignVerification:
    """CR-2a: two-OIDC-subject cosign verification before any tag
    swap. CI build provenance (release.yml) + operator attestation
    (operator-attest.yml). HIPAA additionally asserts the
    hipaa_safe predicate."""

    def test_cosign_presence_check_before_verify(self, deploy_script_text):
        """The script must fail fast (exit 6) if cosign isn't on the
        deploy host -- otherwise verify falls through as an opaque
        exit-127."""
        assert "command -v cosign" in deploy_script_text
        assert "exit 6" in deploy_script_text

    def test_verify_ci_release_workflow_subject(self, deploy_script_text):
        """First verify call pins the release.yml OIDC subject."""
        assert re.search(
            r'cosign verify\b[\s\S]{0,500}?release\\?\.yml',
            deploy_script_text,
        ), "deploy.sh must verify release.yml OIDC subject"

    def test_verify_attestation_operator_workflow_subject(self, deploy_script_text):
        """Second verify call uses verify-attestation with the
        operator-attest.yml OIDC subject + predicate type custom."""
        assert "cosign verify-attestation" in deploy_script_text
        assert "operator-attest" in deploy_script_text
        assert "--type custom" in deploy_script_text

    def test_oidc_issuer_pinned_to_github_actions(self, deploy_script_text):
        """Both verifies pin the issuer to GitHub Actions tokens.
        Without this, an attacker with any sigstore OIDC token could
        forge an identity."""
        assert deploy_script_text.count(
            "https://token.actions.githubusercontent.com"
        ) >= 2, (
            "Both verify calls must pin --certificate-oidc-issuer to "
            "token.actions.githubusercontent.com"
        )

    def test_cosign_failure_exits_with_code_5(self, deploy_script_text):
        """A failed cosign verify must abort with exit 5 -- distinct
        from the version-check exit 4 so operators can disambiguate
        verification failure from migration-compat failure."""
        assert "exit 5" in deploy_script_text

    def test_cosign_failure_restarts_old_image(self, deploy_script_text):
        """On verification failure, the service we stopped in step 3
        must be restarted -- otherwise the install is dead and the
        operator has no clue why."""
        # Look for a `systemctl start email-triage.service` near an
        # `exit 5` in the cosign block.
        m = re.search(
            r'cosign verify[\s\S]{0,2000}?'
            r'systemctl start email-triage\.service[\s\S]{0,200}?'
            r'exit 5',
            deploy_script_text,
        )
        assert m is not None, (
            "Cosign-failure path must restart the old image before exit 5"
        )


class TestHipaaAttestationGate:
    """CR-2a: HIPAA installs additionally require the operator-
    attestation predicate to carry ``hipaa_safe: true``."""

    def test_hipaa_mode_env_var_is_checked(self, deploy_script_text):
        """EMAIL_TRIAGE_HIPAA_MODE=true forces HIPAA mode (for fresh
        installs that have no email_accounts rows yet)."""
        assert "EMAIL_TRIAGE_HIPAA_MODE" in deploy_script_text

    def test_hipaa_mode_detected_from_email_accounts_table(self, deploy_script_text):
        """If any row in email_accounts has hipaa=1, the install is
        HIPAA-flagged. Detection runs against the live DB."""
        assert re.search(
            r'SELECT COUNT\(\*\) FROM email_accounts WHERE hipaa=1',
            deploy_script_text,
        ), "deploy.sh must auto-detect HIPAA mode from email_accounts"

    def test_hipaa_predicate_check_requires_true(self, deploy_script_text):
        """The HIPAA gate must look for ``hipaa_safe`` set to ``true``
        in the attestation predicate. A missing-or-false predicate
        must abort."""
        assert re.search(
            r'"hipaa_safe"[\s\S]{0,40}?true',
            deploy_script_text,
        ), "deploy.sh must require hipaa_safe=true in HIPAA mode"

    def test_hipaa_failure_uses_exit_5(self, deploy_script_text):
        """HIPAA predicate failure is a verification failure -- same
        exit code as other cosign-chain failures."""
        # Already covered by TestCosignVerification but pin
        # explicitly that the HIPAA branch references exit 5.
        m = re.search(
            r'hipaa_safe[\s\S]{0,800}?\bexit 5\b',
            deploy_script_text,
        )
        assert m is not None, (
            "HIPAA gate must exit 5 on missing hipaa_safe=true"
        )


class TestPreApplySnapshot:
    """CR-2b: step-0 raw DB snapshot before any image swap. Created
    in both source mode and registry mode. Restored automatically
    if the post-apply health check fails."""

    def test_snapshot_path_encodes_commit_sha(self, deploy_script_text):
        """``triage.db.preupgrade-${commit_sha}`` -- the sha suffix
        is how the rollback hook + the cleanup module discover the
        right file."""
        assert re.search(
            r'triage\.db\.preupgrade-\$\{commit_sha\}',
            deploy_script_text,
        ), "snapshot filename must encode the commit_sha"

    def test_snapshot_uses_sqlite3_backup_command(self, deploy_script_text):
        """``sqlite3 .backup`` over a quiesced DB is byte-equivalent
        to ``cp`` but uses the SQLite-aware page copier so we don't
        snapshot an in-progress WAL checkpoint."""
        assert re.search(
            r'sqlite3\s+\S+/triage\.db\s+\\?"\.backup',
            deploy_script_text,
        ), "snapshot must use sqlite3 .backup"

    def test_snapshot_taken_after_systemctl_stop(self, deploy_script_text):
        """The snapshot must follow ``systemctl stop`` (no open
        writers) AND precede the build / pull step (we're snapshotting
        the OLD state)."""
        stop_idx = deploy_script_text.find("sudo systemctl stop email-triage.service")
        snap_idx = deploy_script_text.find("triage.db.preupgrade-${commit_sha}")
        assert stop_idx > 0 and snap_idx > 0
        assert snap_idx > stop_idx, (
            "snapshot must be taken after systemctl stop"
        )

    def test_snapshot_taken_flag_set(self, deploy_script_text):
        """SNAPSHOT_TAKEN flag drives the health-check rollback
        branch. Set to 1 immediately after the .backup command."""
        assert "SNAPSHOT_TAKEN=1" in deploy_script_text

    def test_health_failure_restores_snapshot(self, deploy_script_text):
        """When /health never comes up, the snapshot must be copied
        back over triage.db BEFORE the :previous image is retagged.
        Without this, the old image lands on a forward-migrated DB
        and refuses to start."""
        m = re.search(
            r'SNAPSHOT_TAKEN[\s\S]{0,500}?'
            r"cp '\$SNAPSHOT_PATH'[\s\S]{0,300}?triage\.db",
            deploy_script_text,
        )
        assert m is not None, (
            "Health-failure path must restore the snapshot via cp"
        )

    def test_health_failure_still_rolls_back_image(self, deploy_script_text):
        """The snapshot-restore branch must ALSO re-tag :previous
        -> :latest. Restoring just the DB without rolling back the
        image leaves the install running the broken new image."""
        m = re.search(
            r"cp '\$SNAPSHOT_PATH'[\s\S]{0,500}?"
            r'podman tag localhost/email-triage:previous localhost/email-triage:latest',
            deploy_script_text,
        )
        assert m is not None, (
            "Snapshot-restore must be followed by image rollback"
        )


class TestQuadletDropIn:
    """Step 6b: persist EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS into a
    quadlet drop-in so the running container has it (for the
    /config banner)."""

    def test_writes_quadlet_drop_in_path(self, deploy_script_text):
        assert "/etc/containers/systemd/email-triage.container.d" in deploy_script_text

    def test_drop_in_file_named_predictably(self, deploy_script_text):
        """A predictable filename (10-version-caps.conf) makes the
        override easy to find + audit by hand."""
        assert "10-version-caps.conf" in deploy_script_text

    def test_drop_in_sets_environment(self, deploy_script_text):
        """The drop-in must declare
        Environment=EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS=... in a
        [Container] section so quadlet forwards it as a podman --env."""
        assert "[Container]" in deploy_script_text
        assert "Environment=EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS=" in deploy_script_text

    def test_daemon_reload_after_drop_in(self, deploy_script_text):
        """systemd must reload after the drop-in is rewritten,
        otherwise the next start picks up the old value."""
        assert "systemctl daemon-reload" in deploy_script_text

    def test_drop_in_cleared_when_no_previous(self, deploy_script_text):
        """If no :previous image exists, the drop-in must be REMOVED
        (else a stale value survives across deploys)."""
        assert re.search(
            r"rm -f /etc/containers/systemd/email-triage\.container\.d/10-version-caps\.conf",
            deploy_script_text,
        ), "deploy.sh must remove the drop-in when no :previous cap is available"
