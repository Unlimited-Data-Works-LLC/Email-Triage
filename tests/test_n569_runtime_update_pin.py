"""Punch 569 / N-570 — keep the old embedding runtime unless the change is a
security fix (operator decision 2026-10-02).

Before 569 the N-524 gate refused on ANY difference between the installed set
and the image's manifest. Now a difference serves (``stale_ok``) only when the
install can show it is a known older set and no change since is a security fix;
every other difference still refuses. These tests are the matrix the decision
hangs on, plus the structural pins that keep ``stale_ok`` the ONLY new serving
state.

Each behavioural arm builds its prefix through ``tests/_embedding_runtime_fixture``
with the REAL ``write_installed_marker``, so an arm cannot pass on a half-built
rig (``pattern_a_silently_partial_verification_rig_manufactures_findings``).
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

from _pin_harness import parse_module, parse_source
from _pin_harness import _FULL_DEV_TREE  # the one dev-tree detector (PD-5)

from email_triage import embedding_bits as eb
from tests._embedding_runtime_fixture import (
    history_entry,
    make_verified_prefix,
    make_versioned_prefix,
)

SRC = Path(eb.__file__)


def _status():
    return eb.runtime_status()


# ---------------------------------------------------------------------------
# The stale_ok vs refuse matrix
# ---------------------------------------------------------------------------

def test_non_security_change_from_a_known_set_is_stale_ok(tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    st = _status()
    assert st.state == eb.STATE_STALE_OK, st.reason
    assert st.serving and not st.verified and st.update_required
    assert (st.installed_set_version, st.image_set_version) == (1, 2)
    assert st.security == eb.SECURITY_NONE
    ok, reason = eb.runtime_marker_status()
    assert ok is True and reason.startswith("stale_ok:")


def test_a_security_change_refuses(tmp_path, monkeypatch):
    make_versioned_prefix(
        tmp_path, monkeypatch, steps=(True,), advisories=("CVE-2099-0001",),
    )
    st = _status()
    assert st.state == eb.STATE_REFUSED
    assert st.reason_token == "security_drift"
    assert st.security == eb.SECURITY_FIX
    assert st.advisories == ("CVE-2099-0001",)
    assert not st.serving
    assert eb.runtime_marker_status()[0] is False


def test_any_security_step_in_the_gap_refuses(tmp_path, monkeypatch):
    """v1 -> v3 with v2 a security fix and v3 not: the old set missed v2."""
    make_versioned_prefix(tmp_path, monkeypatch, steps=(True, False))
    st = _status()
    assert st.reason_token == "security_drift"
    assert (st.installed_set_version, st.image_set_version) == (1, 3)


def test_several_non_security_steps_stay_stale_ok(tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False, False, False))
    st = _status()
    assert st.state == eb.STATE_STALE_OK, st.reason
    assert st.image_set_version == 4


@pytest.mark.parametrize("flag", ["false", 0, None, "no"])
def test_a_security_flag_that_is_not_a_boolean_refuses(tmp_path, monkeypatch, flag):
    """D1: absent or unparseable = security. ``"false"`` is not ``false``."""
    make_versioned_prefix(tmp_path, monkeypatch, steps=(flag,))
    st = _status()
    assert st.state == eb.STATE_REFUSED
    assert st.reason_token == "security_drift"
    assert st.security == eb.SECURITY_UNKNOWN


def test_an_image_manifest_without_history_refuses(tmp_path, monkeypatch):
    _prefix, _site, mpath = make_versioned_prefix(tmp_path, monkeypatch)
    m = json.loads(mpath.read_text(encoding="utf-8"))
    del m[eb.SET_CHANGES_KEY]
    mpath.write_text(json.dumps(m), encoding="utf-8")
    st = _status()
    assert st.reason_token == "security_drift" and st.security == eb.SECURITY_UNKNOWN


def test_a_package_change_without_a_new_history_entry_refuses(tmp_path, monkeypatch):
    """The newest entry must describe the manifest it sits in."""
    _prefix, _site, mpath = make_versioned_prefix(tmp_path, monkeypatch)
    m = json.loads(mpath.read_text(encoding="utf-8"))
    m["wheels"][0]["version"] = "7.7"
    mpath.write_text(json.dumps(m), encoding="utf-8")
    st = _status()
    assert st.reason_token == "security_drift" and st.security == eb.SECURITY_UNKNOWN


def test_an_old_schema_marker_cannot_be_stale_ok(tmp_path, monkeypatch):
    prefix, _site, _m = make_versioned_prefix(tmp_path, monkeypatch)
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    for key in ("set_version", "set_digest", "record_digests", "models_digest"):
        marker.pop(key)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    st = _status()
    assert st.state == eb.STATE_REFUSED
    assert st.reason_token == "set_mismatch"


def _unplace(prefix):
    """Strip the install record to a pre-569 one: it no longer names its set."""
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    for key in ("set_version", "set_digest", "record_digests", "models_digest"):
        marker.pop(key)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")


def test_an_unplaced_record_under_a_security_manifest_reports_security_drift(
    tmp_path, monkeypatch,
):
    """Punch 664, edge 1: the record names no set, the manifest bump is a
    security fix. It used to read ``set_mismatch`` / unknown, so the admin prompt
    did not say 'security fix'."""
    prefix, _site, _m = make_versioned_prefix(
        tmp_path, monkeypatch, steps=(True,), advisories=("CVE-2099-0001",),
    )
    _unplace(prefix)
    st = _status()
    assert st.state == eb.STATE_REFUSED and not st.serving
    assert st.reason_token == "security_drift"
    assert st.security == eb.SECURITY_FIX
    assert st.advisories == ("CVE-2099-0001",)
    assert eb.runtime_marker_status()[1].startswith("security_drift")
    notice = eb.update_notice(st, restart=False, auto=False)
    assert "security fix" in notice["headline"]
    assert notice["security"] == eb.SECURITY_FIX


def test_an_unplaced_record_under_a_non_security_manifest_stays_set_mismatch(
    tmp_path, monkeypatch,
):
    """Punch 664, edge 2 (Prime Directive 18): the flag is set only where the
    history says security. A non-security bump must not read as one."""
    prefix, _site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(False, False))
    _unplace(prefix)
    st = _status()
    assert st.state == eb.STATE_REFUSED
    assert st.reason_token == "set_mismatch"
    assert st.security == eb.SECURITY_UNKNOWN
    assert "security fix" not in eb.update_notice(st, restart=False, auto=False)["headline"]


def test_an_unplaced_record_prices_the_worst_case_in_a_mixed_history(tmp_path, monkeypatch):
    """The record cannot place the install, so a security step anywhere after
    the first set counts, even when the newest step is not one."""
    prefix, _site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(True, False))
    _unplace(prefix)
    st = _status()
    assert st.reason_token == "security_drift" and st.security == eb.SECURITY_FIX


def test_an_unplaced_record_with_an_unreadable_history_stays_set_mismatch(tmp_path, monkeypatch):
    """No history to derive from: the old fail-closed reading, unchanged."""
    prefix, _site, mpath = make_versioned_prefix(tmp_path, monkeypatch, steps=(True,))
    _unplace(prefix)
    m = json.loads(mpath.read_text(encoding="utf-8"))
    del m[eb.SET_CHANGES_KEY]
    mpath.write_text(json.dumps(m), encoding="utf-8")
    st = _status()
    assert st.reason_token == "set_mismatch" and st.security == eb.SECURITY_UNKNOWN


def test_an_old_schema_marker_still_passes_an_exact_match(tmp_path, monkeypatch):
    """Back-compat: every pre-569 install is schema 1, and an exact match must
    not start refusing the day 569 deploys."""
    prefix, _site, _m = make_verified_prefix(tmp_path, monkeypatch)
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    for key in ("set_version", "set_digest", "record_digests", "models_digest"):
        marker.pop(key)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    assert _status().state == eb.STATE_OK


def _model_only_change(tmp_path, monkeypatch, *, security):
    """Same packages; the image's set v2 differs from v1 ONLY by a model file."""
    from tests._embedding_runtime_fixture import DEFAULT_PACKAGES

    prefix, _site, mpath = make_versioned_prefix(
        tmp_path, monkeypatch, declared=DEFAULT_PACKAGES, steps=(security,),
    )
    m = json.loads(mpath.read_text(encoding="utf-8"))
    m["models"] = [{"name": "m", "files": [{"name": "w.bin", "sha256": "b" * 64}]}]
    m[eb.SET_CHANGES_KEY][-1]["set_digest"] = eb.manifest_set_digest(m)
    mpath.write_text(json.dumps(m), encoding="utf-8")
    eb.invalidate_runtime_ready_cache()
    return prefix


def test_a_model_only_change_is_drift_not_ok(tmp_path, monkeypatch):
    """Before the fold a model-only release read ``ok`` and no notice fired."""
    _model_only_change(tmp_path, monkeypatch, security=False)
    st = _status()
    assert st.state == eb.STATE_STALE_OK, st.reason
    assert "model files changed" in st.reason
    assert st.update_required and not st.verified


def test_a_security_model_change_refuses(tmp_path, monkeypatch):
    _model_only_change(tmp_path, monkeypatch, security=True)
    st = _status()
    assert st.state == eb.STATE_REFUSED and st.reason_token == "security_drift"


def test_a_schema_1_marker_cannot_see_a_model_change(tmp_path, monkeypatch):
    """Back-compat, stated: a pre-569 marker records no models, so an exact
    package match stays ``ok`` for it (prod's marker until its next update)."""
    prefix = _model_only_change(tmp_path, monkeypatch, security=True)
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    for key in ("set_version", "set_digest", "record_digests", "models_digest"):
        marker.pop(key)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    assert _status().state == eb.STATE_OK


def test_a_tampered_installed_dist_refuses(tmp_path, monkeypatch):
    _prefix, site, _m = make_versioned_prefix(tmp_path, monkeypatch)
    dist_info = next(site.glob("fake_a-*.dist-info"))
    (dist_info / "RECORD").write_text("fake_a/__init__.py,sha256=x,1\n", encoding="utf-8")
    st = _status()
    assert st.state == eb.STATE_REFUSED
    assert st.reason_token == "disk_marker_mismatch"


def test_a_tampered_dist_refuses_even_on_an_exact_match(tmp_path, monkeypatch):
    _prefix, site, _m = make_verified_prefix(tmp_path, monkeypatch)
    dist_info = next(site.glob("fake_b-*.dist-info"))
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: fake-b\nVersion: 2.0\nX: y\n", encoding="utf-8",
    )
    st = _status()
    assert st.reason_token == "disk_marker_mismatch"


def test_an_install_newer_than_the_image_refuses(tmp_path, monkeypatch):
    prefix, _site, _m = make_versioned_prefix(tmp_path, monkeypatch)
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["set_version"] = 5
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    st = _status()
    assert st.reason_token == "set_mismatch"


def test_an_install_the_history_does_not_know_refuses(tmp_path, monkeypatch):
    prefix, _site, _m = make_versioned_prefix(tmp_path, monkeypatch)
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["set_digest"] = "f" * 64
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    assert _status().reason_token == "set_mismatch"


def test_a_name_the_image_no_longer_provides_refuses(tmp_path, monkeypatch):
    prefix, _site, _m = make_versioned_prefix(tmp_path, monkeypatch)
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["provided_by_image"] = {"fake-provided": "1.0"}
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    st = _status()
    assert st.reason_token == "set_mismatch"
    assert "fake-provided" in st.reason


def test_the_record_reports_stale_ok_as_serving_but_not_verified(tmp_path, monkeypatch):
    """D5: health ``runtime_verified`` and the monitoring system plugin read ``verified``,
    which stays EXACT, so both WARN on stale_ok."""
    make_versioned_prefix(tmp_path, monkeypatch)
    rec = eb.runtime_install_record()
    assert rec["verified"] is False
    assert rec["serving"] is True
    assert rec["state"] == eb.STATE_STALE_OK
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    try:
        import check_runtime_deps_verified as plugin
    except ModuleNotFoundError as exc:
        if exc.name != "check_runtime_deps_verified":
            raise
        plugin = None
    finally:
        sys.path.pop(0)
    if plugin is None:
        # The plugin is operator-internal: scripts/** is default-deny in the publish
        # ship-set, so the public tree has no plugin to drive. The record half above
        # still runs there; on the full dev tree a missing plugin fails.
        assert not _FULL_DEV_TREE, "the monitoring plugin is missing from the full dev tree"
        pytest.skip("the monitoring plugin is operator-internal and not in the public tree")
    code, out = plugin.classify({
        "present": rec["present"], "verified": rec["verified"],
        "reason_token": rec["reason"].split(":", 1)[0],
    })
    assert code == plugin.WARNING
    assert "(stale_ok)" in out


def test_stale_ok_serves_through_every_serve_gate(tmp_path, monkeypatch):
    _prefix, site, _m = make_versioned_prefix(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.add_runtime_to_sys_path()
    assert str(site) in sys.path


def test_restart_pending_closes_every_serve_gate(tmp_path, monkeypatch):
    """Two arms, so the probe is shown able to PASS: with every import lookup
    succeeding, the gates open without the flag and close with it (mutation
    M6 survived a one-armed version, because the fake prefix holds no
    ``sentence_transformers`` and the gates read False regardless)."""
    import importlib.machinery
    import importlib.util

    _prefix, site, _m = make_verified_prefix(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a: object())
    monkeypatch.setattr(
        importlib.machinery.PathFinder, "find_spec",
        classmethod(lambda cls, name, path=None, target=None: object()),
    )
    eb.invalidate_runtime_ready_cache()
    assert eb.is_runtime_ready() is True, "control arm: the gate can open"
    assert eb.runtime_importable_probe() is True, "control arm"
    sys.path.remove(str(site))
    eb.invalidate_runtime_ready_cache()

    monkeypatch.setattr(eb, "_restart_pending", True)
    eb.add_runtime_to_sys_path()
    assert str(site) not in sys.path
    assert eb.is_runtime_ready() is False
    assert eb.runtime_importable_probe() is False
    assert eb.runtime_install_record()["restart_pending"] is True


# ---------------------------------------------------------------------------
# The set history parser
# ---------------------------------------------------------------------------

def _manifest_with(history_fn):
    m = {"manifest_version": 3, "wheels": [
        {"name": "a", "version": "1", "filename": "a.whl", "sha256": "1" * 64},
    ], "models": []}
    m[eb.SET_CHANGES_KEY] = history_fn(m)
    return m


def test_the_digest_ignores_order_and_covers_every_arch():
    base = {
        "wheels": [
            {"name": "a", "version": "1", "filename": "a", "sha256": "1" * 64},
            {"name": "b", "version": "1", "filename": "b", "sha256": "2" * 64},
        ],
        "wheels_by_arch": {"x86_64": [
            {"name": "t", "version": "1", "filename": "t", "sha256": "3" * 64},
        ], "aarch64": [
            {"name": "t", "version": "1", "filename": "t2", "sha256": "4" * 64},
        ]},
        "models": [{"name": "m", "files": [{"name": "w", "sha256": "5" * 64}]}],
    }
    swapped = json.loads(json.dumps(base))
    swapped["wheels"].reverse()
    assert eb.manifest_set_digest(base) == eb.manifest_set_digest(swapped)
    for mutate in (
        lambda m: m["wheels_by_arch"]["aarch64"][0].update(version="2"),
        lambda m: m["models"][0]["files"][0].update(sha256="6" * 64),
        lambda m: m["wheels"][1].update(sha256="7" * 64),
    ):
        changed = json.loads(json.dumps(base))
        mutate(changed)
        assert eb.manifest_set_digest(changed) != eb.manifest_set_digest(base)


@pytest.mark.parametrize("bad", [
    lambda m: [],
    lambda m: [history_entry(m, 2, security=False)],
    lambda m: [history_entry(m, 1, security=False), history_entry(m, 1, security=False)],
    lambda m: [history_entry(m, 1, security="false")],
    lambda m: [{**history_entry(m, 1, security=False), "advisories": ["bad id\n"]}],
    lambda m: [{**history_entry(m, 1, security=False), "release": "latest"}],
    lambda m: [{**history_entry(m, 1, security=False), "set_digest": "XYZ"}],
    lambda m: [{**history_entry(m, 1, security=False), "set_version": True}],
])
def test_the_history_parser_refuses_what_it_cannot_vouch_for(bad):
    with pytest.raises(eb.ManifestHistoryError):
        eb.parse_set_changes(_manifest_with(bad))


def test_the_history_parser_accepts_a_well_formed_history():
    m = _manifest_with(lambda m: [
        {**history_entry(m, 1, security=True, advisories=("CVE-2026-1",)),
         "set_digest": "a" * 64, "release": "v0.2.0"},
        history_entry(m, 2, security=False, release="v0.2.1"),
    ])
    hist = eb.parse_set_changes(m)
    assert [h.set_version for h in hist] == [1, 2]
    assert hist[0].advisories == ("CVE-2026-1",)


def test_the_shipped_manifest_has_a_current_history():
    """The image's own manifest must parse with a current newest entry, or every
    future non-security change would refuse (fail closed, but by accident)."""
    raw = eb._load_raw_manifest(Path(__file__).resolve().parents[1]
                                / "scripts" / "embedding-bits-manifest.json")
    hist = eb.parse_set_changes(raw)
    assert hist[-1].set_digest == eb.manifest_set_digest(raw)


# ---------------------------------------------------------------------------
# The SHIPPED manifest against prod-shaped installs (the deploy-day transition)
#
# Prod (the deploy host, 2026-10-06 22:59) runs the newest set with a SCHEMA-1 marker
# written before 569. The newest step of the shipped history is a security fix
# (fsspec, punch 570). The 569 deploy must not refuse that install, and an
# install still on the older set must refuse with the advisories named.
# ---------------------------------------------------------------------------

_SHIPPED = Path(__file__).resolve().parents[1] / "scripts" / "embedding-bits-manifest.json"


def _install_shipped_set(tmp_path, monkeypatch):
    """Every name the shipped manifest expects for this arch, on disk at the
    manifest's version, recorded by the REAL marker writer."""
    from tests._embedding_runtime_fixture import _write_tree, point_defaults_at

    raw = eb._load_raw_manifest(_SHIPPED)
    manifest = eb._resolve_manifest_arch(raw, label=_SHIPPED.name)
    packages = sorted(eb.manifest_expected_versions(manifest).items())
    prefix = tmp_path / "rdeps"
    site = _write_tree(prefix, packages)
    point_defaults_at(monkeypatch, prefix, _SHIPPED)
    eb.write_installed_marker(
        target_dir=prefix, manifest=manifest,
        manifest_sha256=eb._manifest_sha256(_SHIPPED), raw_manifest=raw,
    )
    eb.invalidate_runtime_ready_cache()
    return prefix, site, raw


def test_the_newest_shipped_set_reads_ok_with_a_schema_2_marker(tmp_path, monkeypatch):
    _install_shipped_set(tmp_path, monkeypatch)
    assert _status().state == eb.STATE_OK


def test_a_prod_schema_1_marker_on_the_newest_shipped_set_reads_ok(tmp_path, monkeypatch):
    """The deploy-day invariant: an exact match never consults the history, so
    the newest step being a SECURITY fix does not refuse an up-to-date install."""
    prefix, _site, raw = _install_shipped_set(tmp_path, monkeypatch)
    assert eb.parse_set_changes(raw)[-1].security_change is True, (
        "this arm is about a security-newest history; re-read it if that changed"
    )
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    for key in ("set_version", "set_digest", "record_digests", "models_digest"):
        marker.pop(key)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    st = _status()
    assert st.state == eb.STATE_OK, st.reason
    assert st.verified and not st.update_required
    assert st.security != eb.SECURITY_FIX, "the security flag must not outlive the drift that set it"


def test_an_install_on_the_previous_shipped_set_refuses_with_its_advisories(
    tmp_path, monkeypatch,
):
    """A schema-2 install of the set before the newest step, under the shipped
    image: the newest step is a security fix, so it refuses and names it."""
    prefix, site, raw = _install_shipped_set(tmp_path, monkeypatch)
    hist = eb.parse_set_changes(raw)
    assert len(hist) >= 2 and hist[-1].security_change is True
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    # Move one package back a version on disk and in the record, and record
    # the install as the previous set (the shape a 569 install of v1 leaves).
    name = sorted(marker["distributions"])[0]
    old_version = marker["distributions"][name] + ".post0"
    for d in site.glob(f"{name.replace('-', '_')}-*.dist-info"):
        (d / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {old_version}\n",
            encoding="utf-8",
        )
        d.rename(d.with_name(f"{name.replace('-', '_')}-{old_version}.dist-info"))
    marker["distributions"][name] = old_version
    marker["set_version"] = hist[-2].set_version
    marker["set_digest"] = hist[-2].set_digest
    marker["record_digests"] = eb.dist_info_digests(prefix)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    st = _status()
    assert st.state == eb.STATE_REFUSED, st.reason
    assert st.reason_token == "security_drift"
    assert st.security == eb.SECURITY_FIX
    assert set(hist[-1].advisories) <= set(st.advisories)


# ---------------------------------------------------------------------------
# Structural pins: stale_ok is the ONLY new serving state, and only one arm
# of one function produces it, after the security check.
# ---------------------------------------------------------------------------

def _stale_ok_constructions(tree: ast.AST) -> list[str]:
    """The enclosing function name of every ``RuntimeStatus(state=STATE_STALE_OK)``
    or ``RuntimeStatus(STATE_STALE_OK, …)`` construction, and of every bare
    ``"stale_ok"`` string literal used as a state."""
    hits: list[str] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            callee = node.func
            name = getattr(callee, "id", None) or getattr(callee, "attr", None)
            if name != "RuntimeStatus":
                continue
            args = list(node.args[:1]) + [
                kw.value for kw in node.keywords if kw.arg == "state"
            ]
            for a in args:
                if (isinstance(a, ast.Name) and a.id == "STATE_STALE_OK") or (
                    isinstance(a, ast.Constant) and a.value == "stale_ok"
                ):
                    hits.append(fn.name)
    return hits


def test_stale_ok_is_built_in_exactly_one_place():
    tree = parse_module(SRC)
    assert _stale_ok_constructions(tree) == ["_drift_status"]


def test_the_stale_ok_pin_has_teeth():
    planted = parse_source(
        "def shortcut(m):\n"
        "    return RuntimeStatus(state=STATE_STALE_OK, reason='x')\n"
        "def other():\n"
        "    return RuntimeStatus('stale_ok', 'y')\n"
    )
    assert _stale_ok_constructions(planted) == ["shortcut", "other"]


def test_the_security_check_precedes_the_stale_ok_return():
    tree = parse_module(SRC)
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_drift_status"
    )
    src = ast.get_source_segment(SRC.read_text(encoding="utf-8"), fn) or ""
    sec = src.index("s.security_change for s in steps")
    stale = src.index("state=STATE_STALE_OK")
    hist = src.index("parse_set_changes(raw_manifest)")
    assert hist < sec < stale


def test_serving_states_are_exactly_ok_and_stale_ok():
    assert eb.SERVING_STATES == frozenset({"ok", "stale_ok"})
    for state in (eb.STATE_REFUSED, eb.STATE_NO_PREFIX):
        assert not eb.RuntimeStatus(state=state, reason="x").serving


# ---------------------------------------------------------------------------
# D4 at the consumer, and the image-provided accounting during an update
# ---------------------------------------------------------------------------

async def test_the_st_backend_refuses_and_counts_while_a_restart_is_pending(monkeypatch):
    """The serve gates close on restart-pending, but a backend that loaded its
    model BEFORE the update would keep calling into the old in-memory package,
    whose lazy submodule imports now resolve into the NEW tree. The backend
    itself must refuse, typed and counted."""
    from email_triage.engine.embedding_backend import SentenceTransformersBackend

    backend = SentenceTransformersBackend()
    loads: list[int] = []
    monkeypatch.setattr(backend, "_load_model", lambda: loads.append(1))
    monkeypatch.setattr(eb, "_restart_pending", True)
    with pytest.raises(eb.RuntimeRestartRequired, match=eb.RESTART_MESSAGE):
        await backend.embed_text("hello")
    assert loads == [], "the model must not be touched"
    assert backend.metrics()["errors"] == 1
    assert backend.metrics()["last_error"]


def test_a_live_prefix_on_sys_path_is_not_image_provided(tmp_path, monkeypatch):
    """An update records a STAGING prefix while the live one may be on sys.path
    (stale_ok serves). A name found in the live prefix is the old runtime, not
    the image, and must not be recorded as ``provided_by_image``."""
    import importlib

    _prefix, site, _m = make_verified_prefix(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "path", list(sys.path) + [str(site)])
    importlib.invalidate_caches()
    provided = eb.environment_provided_versions(
        ["fake-a", "fake-b"], target_dir=tmp_path / "staging",
    )
    assert provided == {}, provided
