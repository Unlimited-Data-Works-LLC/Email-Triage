# Divergence census — 2026-11-04 (public stub)

The divergence census is the project's structural-drift audit: SSOT convergence,
count-agnostic pin coverage, and review of the HIPAA control surface. Its latest
round ran on **2026-11-04**, ahead of the v0.2.0 release.

That round did **not** converge. It found one high-severity issue. That issue was
fixed, reviewed and deployed before this release: a notice that mail may have gone
un-triaged after a capped sync recovery could be cleared by the next routine sync.
The round also left 13 medium-severity and 7 low-severity structural findings open.
They are tracked for the v0.2.1 patch release. The census runs again in rounds
until a round finds nothing at medium severity or above.

The earlier census, of 2026-07-24, converged: two consecutive rounds produced zero
surviving actionable findings.

The full dated census reports are part of the private HIPAA audit trail
(45 CFR §164.316 documentation) and are intentionally not published. This stub
carries the census date so the `census-freshness` release gate in
`.github/workflows/release.yml` can enforce the same freshness window on this
public mirror as on the development repository. That gate refuses to cut a `v*`
release when the latest census is older than 90 days.

Maintainers: refresh this file from the publish staging tree
(`publish/audit-reports/` in the development repo) at each release pre-flight.
Its filename date must track the latest completed census round.
