""" / N-15 seam 6 — the /compliance audit-chain verify SURFACE.

Tests the VIEW (rule ), not just the verifier machinery: the rendered
/compliance page must surface each audit-event chain's tamper-evidence status,
and must flip to a visible break warning the moment a hashed field is mutated
out from under the chain.
"""
from email_triage.db.audit import (
    record_hipaa_boundary,
    verify_all_audit_chains,
    verify_audit_chain,
)
from email_triage.web.routers.ui._shared import _compliance_page_snapshot


class TestSnapshotExposesAuditChains:
    def test_snapshot_carries_every_chained_table_intact_on_fresh_db(self, db, app):
        snap = _compliance_page_snapshot(db, app.state)
        assert "audit_chains" in snap
        chains = snap["audit_chains"]
        # Count-agnostic: every chained table the registry knows about is present.
        from email_triage.db.audit import _AUDIT_CHAIN_CANONICAL_FIELDS
        assert set(chains) == set(_AUDIT_CHAIN_CANONICAL_FIELDS)
        assert all(c["intact"] for c in chains.values())

    def test_tampering_a_hashed_field_breaks_the_chain(self, db, app):
        # Seed three chained boundary rows, then mutate a HASHED field (reason)
        # on the middle one directly — bypassing the writer.
        for i in range(3):
            record_hipaa_boundary(
                db, scope=f"account:{i}", direction="on",
                actor_id=None, reason=f"seed {i}",
            )
        assert verify_audit_chain(db, "hipaa_boundary_events")["intact"] is True
        mid = db.execute(
            "SELECT id FROM hipaa_boundary_events ORDER BY id LIMIT 1 OFFSET 1"
        ).fetchone()[0]
        db.execute(
            "UPDATE hipaa_boundary_events SET reason = ? WHERE id = ?",
            ("TAMPERED", mid),
        )
        db.commit()
        result = verify_audit_chain(db, "hipaa_boundary_events")
        assert result["intact"] is False
        assert result["first_break_id"] == mid
        # The convenience aggregate reflects it too.
        assert verify_all_audit_chains(db)["hipaa_boundary_events"]["intact"] is False


class TestRenderedAuditChainSurface:
    def test_compliance_page_shows_intact_chains(self, client, admin_cookies, db):
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        assert "Audit-event chains" in body
        assert "audit chains intact" in body
        assert "Chain break detected" not in body  # log_entries section, intact

    def test_compliance_page_surfaces_a_tampered_audit_chain(
        self, client, admin_cookies, db,
    ):
        """Mutate a hashed field directly, then the rendered page must SHOW the
        break (operator-visible tamper-evidence, not just an API verdict)."""
        record_hipaa_boundary(
            db, scope="account:1", direction="on", actor_id=None, reason="real",
        )
        row_id = db.execute(
            "SELECT id FROM hipaa_boundary_events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        db.execute(
            "UPDATE hipaa_boundary_events SET direction = ? WHERE id = ?",
            ("off", row_id),
        )
        db.commit()
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        assert "audit chain(s) show a break" in body
        assert "hipaa_boundary_events" in body
