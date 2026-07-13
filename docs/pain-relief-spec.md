# PAIN Relief: Capture (plugin) and Evaluation (downstream)

> **SCOPE SPLIT (authoritative).** The PAIN Relief work is divided across a
> hard boundary:
>
> - **The k8s plugin CAPTURES only.** It emits, per finding, the CWE IDs (§1) and,
>   per workload, a neutral `WorkloadPosture` block of raw Kubernetes-observed
>   facts (§CAPTURE below) — securityContext booleans, NetworkPolicy CIDRs,
>   replicas/PDB/topology, serviceaccount, volumes. It contains NO taxonomy, NO
>   join, NO PAIN/EPSS modification, and NO cloud-semantic interpretation (no
>   "IMDS", no control names). The plugin's base PAIN/LEV/reachability scoring is
>   unchanged.
> - **A DOWNSTREAM evaluator EVALUATES.** It loads the vdr-pain-relief
>   taxonomy, matches CWE × observed-facts → credits, and applies the
>   Modified-metric and adjustedEPSS moves. Everything below §CAPTURE (the loader,
>   join engine, exploitability model, credit-posture report) describes THAT
>   downstream consumer, not the plugin. Retained here as the downstream design of
>   record; the Go implementations live on the closed branches
>   feat/cc1-taxonomy-loader, feat/cc-join-scoring, feat/cc4-report-html.
>
> Implemented in the plugin today: §1 (CWE surfacing) and §CAPTURE
> (WorkloadPosture), on PR #11.

Status: **Design spec.** Companion to
[`reachability-v2-spec.md`](reachability-v2-spec.md). The private
[vdr-pain-relief](https://github.com/stackArmor/vdr-pain-relief) taxonomy
maps (machine-verified control × CWE class) → deterministic Modified-metric
credit. The taxonomy holds the causal stories and governance; the downstream
evaluator applies them to the plugin's captured facts.

## CAPTURE — what the plugin emits (implemented)

Per finding: `cwes` (§1). Per workload, `resources[].posture` (`model.WorkloadPosture`),
all fields raw Kubernetes observations, `omitempty`, read-only, fail-open:

- `securityContext`: readOnlyRootFilesystem, runAsNonRoot, privileged,
  allowPrivilegeEscalation, droppedCapabilities[], seccompProfileType
- `workload`: replicas, hasPodDisruptionBudget, zoneSpread, livenessProbe,
  readinessProbe
- `identity`: serviceAccountName, automountServiceAccountToken, envFromSecretRef
- `volumes`: writableVolumeMounts[]
- `networkPolicy`: selectedByEgressPolicy, egressDefaultDeny, egressAllowedCidrs[],
  egressDeniedByExcept[], selectedByIngressPolicy

The downstream evaluator maps these raw facts onto taxonomy control predicates
(e.g. an `egressDeniedByExcept` containing `169.254.169.254/32` satisfies the
taxonomy's imds-protection control). The plugin never makes that mapping.

---

## DOWNSTREAM EVALUATION (design of record — NOT in the plugin)

Status: **Design spec — not implemented in the plugin.** Consumes the private
[vdr-pain-relief](https://github.com/stackArmor/vdr-pain-relief) taxonomy:
(machine-verified control × CWE class) → deterministic Modified-metric credit.
Describes how a downstream consumer surfaces CWEs, verifies controls, joins, and
scores.

## 1. Phase CC0 — CWE surfacing (prerequisite for everything)

The plugin does not currently expose CWE IDs per finding. Add:

- **Enrichment record:** `cwes []string` on the cached per-CVE enrichment record.
  Source precedence (same order the v2 spec §5.3 uses for the mechanism filter):
  1. CISA Vulnrichment ADP CWE assignments;
  2. NVD CVE record CWE (`weaknesses[].description`), skipping
     `NVD-CWE-noinfo`/`NVD-CWE-Other`;
  3. none → empty list (fail-open: no CWE, no credit, no guessing).
- **Output surfaces:** `cwes` on the finding in JSON; a `CWE` column in the table
  view (first CWE + count); CycloneDX property `vdr:cwes` (comma-joined).
- **Data-quality metric:** report header counts
  `findingsWithSpecificCwe / findings` — the number that gates real-world credit
  coverage. Track it; do not loosen keying to inflate it.

## 2. Taxonomy artifact

The plugin is public; the full taxonomy is private. Vendoring the full table
into the public binary would publish it (embedded YAML is trivially
extractable). Two tiers:

- **Vendored default: the PUBLIC SNIPPET only.** The taxonomy repo marks a
  small set of rows `visibility: public` (the same illustrative rows the white
  paper shows) and exports them as a snippet bundle; the public plugin embeds
  that. Public users get a working credit engine, the full method, and sample
  rows — the same "example, not a standard" posture as the archetype catalog.
- **`--taxonomy <ref>`: the full private table**, pulled as a pinned, signed
  OCI artifact from the private registry (authenticated), for stackArmor
  deployments and customers. Never `latest`; a failed load/parse/verify
  **disables the credit engine loudly** — no silent fallback to the snippet,
  because "which table scored this" must never be ambiguous. The report header
  names the tier (`taxonomy: snippet-v0.6.0` vs `taxonomy: full-v0.6.0`).
- **Never a ConfigMap.** Same governed-configuration line as the PAIN cut
  points: in-band cluster config is an ungoverned scoring knob, and taxonomy
  rows are editable discounts. Changes flow only through the private repo's
  review and signed releases.
- `taxonomyVersion` is recorded in the report header and in **every** credit
  evidence line. A score is reproducible only against a named release.
- Files consumed: `taxonomy/impact-*.yaml`, `taxonomy/attested-class.yaml`,
  `taxonomy/likelihood.yaml`, `taxonomy/classes.yaml`,
  `profiles/verification-sources.yaml`, `profiles/stig-adapters/*.yaml`.
  `reachability-pointers.yaml` is documentation; the credit engine ignores it.

### Outcome-class resolution

- `class:ACE` expands to its member list at load time.
- `class:CRASH` expands to unconditional members plus
  `membersWhenAvailabilityOnly`, the latter matching a finding only when its own
  CVSS vector is availability-only (C:N/I:N, A:L|H). The vector is read from the
  same source the scorer already uses; no new data needed.

## 3. Verification collectors

A row applies only when `verification-sources.yaml` has a predicate for the
asset's platform AND the collector proves it. Sources, cheapest first:

1. **Already collected (k8s):** pod specs (securityContext, env, volumes,
   serviceaccounts, replicas, anti-affinity/topologySpread, probes), Services,
   Ingress/Gateway annotations, PDBs. NetworkPolicies arrive with reachability
   milestone B1 (shared dependency).
2. **Image facts:** no-shell detection is a per-digest layer query (the scanner
   already unpacks layers; record presence of `/bin/sh`, `/bin/bash`, busybox,
   interpreters).
3. **STIG/SCAP results:** `--stig-results-file <path>` (repeatable) ingests
   pass/fail per rule ID; `profiles/stig-adapters/*.yaml` resolves rules →
   control predicates (`satisfies` requires all listed rules passing plus any
   `supplement` collector check; `supports` corroborates but never fires a row
   alone). Results carry a scan timestamp; a governed freshness window
   (`--stig-max-age`, default 30d) fails closed for credit purposes.
4. **Cloud reads (optional, off critical path):** RDS `MultiAZ`/`rds.force_ssl`,
   Cloud SQL `availabilityType`/`requireSsl`, ALB desync attributes, EC2
   metadata options. Same posture as edge-auth optional signals: enrich and
   verify, never required for the k8s-native rows.
5. **Attested artifacts:** signed, dated, reusable (surface-attestation style)
   for the `attested-class.yaml` rows and grants dumps; verified when
   `--require-signed-evidence` is set; expired renewal window = no credit.

## 4. Join engine

Per (finding, asset), after the reachability decision:

```text
creditJoin(finding, asset):
    cwes = finding.cwes;  if empty: return []        # fail-open
    credits = []
    for row in taxonomy.rows:                        # impact lane only
        if not matches(cwes, expand(row.cweClasses, finding.vector)): continue
        if not controlVerified(row.control, asset):  record near-miss; continue
        if conditionFails(row, finding, asset):      record near-miss; continue
        if disqualified(row, finding, asset):        record near-miss; continue
        credits.append(row)
    return credits
```

- **Cross-references** conditions/disqualifiers already use: the HA rows'
  reachability condition reads `ReachabilityDecision.IRV` (v2). Under v1
  (no per-finding IRV), fall back conservatively: treat the finding as IRV, so
  HA credit requires the rate-limit conjunction or the per-finding citation.
  The poison-pill disqualifier reads the vdr-dataflow ConfigMap's tainted
  inbound edges (source archetype = broker/persistent).
- **No stacking (governance 4a):** collapse per metric — any number of firing
  rows on MC still yields one High→Low. Evidence lists every row that fired.
- **Impact application:** substitute Modified C/I/A into the existing PAIN
  arithmetic (the memo's Eq. 1 path already implemented in `internal/scoring`);
  word, N-level, deadline follow. Never touches reachability or KEV/BOD 26-04.

### 4a. Exploitability (likelihood lane) — graduated adjustedEPSS

Exploitability stays binary (LEV/NLEV). Controls never edit the published EPSS;
they lower a local estimate, the mirror of how impact credits move Modified
C/I/A without touching the base vector.

```text
adjustedEPSS = max( EPSS * PRODUCT(residualFactor of applicable rows),
                    EPSS * STACKING_FLOOR )              # multiplicative, floored
LEV = KEV OR (adjustedEPSS >= EPSS_THRESHOLD) OR (floor AND NOT floorDefeated)
  # floorDefeated: a CC-LIKE-EDGEAUTH-FLOOR row verified for the asset
  # KEV: frozen -- residualFactor never applies; LEV stays true; clock untouched
  # STACKING_FLOOR: governed constant (~0.5), caps total stacked reduction
```

- `epss-residual` rows carry `residualFactor` (0,1); apply only to non-KEV
  findings whose CWE the row counters (`*` = all). Factors **stack
  multiplicatively** (defense-in-depth), bounded below by `EPSS * STACKING_FLOOR`.
- `floor-defeated` rows (edge-auth) remove only the floor OR-term; they do not
  touch adjustedEPSS.
- Both **EPSS (published) and adjustedEPSS (local, with the row cited)** appear in
  output; the published value is never mutated.
- **No taxonomy → adjustedEPSS = EPSS, floor as-is → stock LEV/NLEV.**

Evidence line format:

```text
"PAIN Relief: CC-RUN-SELINUX-CONFINE v0.7.0 counters CWE-787 via class:ACE (enforcing; process domain httpd_t, policy query 2026-07-02); MC,MI High->Low"
"PAIN Relief: CC-LIKE-EDR-BLOCK v0.7.0 residualFactor 0.85; EPSS 0.74 -> adjustedEPSS 0.63 -> LEV (blocking EDR enforcing, policy export 2026-07-02)"
"PAIN Relief near-miss: CC-HA-RECOVERABLE-CRASH blocked -- missing PodDisruptionBudget (replicas=4, zone spread ok, liveness ok)"
```

### 4b. Reachability guidelines are NOT implemented (current decision)

The credit engine consumes whatever reachability verdict the plugin already
produces — it does **not** implement the reachability paper's hard-line Phase B
changes (pruning requires enforcement-or-attestation; telemetry silence never
prunes) or the Gate 3 role/two-login tightening. Rationale: FedRAMP is not
expected to take that hard a line on internet-reachability. The HA carve-out
reads the `IRV` bit regardless of how strictly it was computed, so the credit
engine is agnostic to the reachability model version. Revisit only if FedRAMP
direction changes.

## 5. Credit-posture report (the near-miss surface)

Per workload, emitted in JSON and summarized in the table view:

- **firing:** rows applied, with affected finding counts;
- **blocked:** rows where the control or a condition failed, with the exact
  failed predicate and the finding count that would benefit ("one
  PodDisruptionBudget away from MA credit on 14 findings");
- **inapplicable:** no keyed findings on the workload (not shown by default).

This is deterministic output of facts already computed by the join; it is the
operator-facing incentive surface and costs no extra collection.

## 6. New model fields

```go
// on the enrichment record
CWEs []string `json:"cwes,omitempty"`

// per (finding, asset), alongside ReachabilityDecision
type ControlCredit struct {
    RowID           string   `json:"rowId"`
    TaxonomyVersion string   `json:"taxonomyVersion"`
    Metrics         []string `json:"metrics"`          // MC|MI|MA
    ViaClass        string   `json:"viaClass,omitempty"` // "class:ACE" when matched through a class
    Evidence        []string `json:"evidence"`
}
// scoring.Input gains ModifiedOverrides (per-dimension High->Low flags) fed by
// the collapsed credit set; recompute path unchanged.

// exploitability: scoring.Input gains AdjustedEPSS + the row that set it;
// LEV recompute uses adjustedEPSS, KEV frozen.
type ExploitabilityAdjustment struct {
    EPSS         float64 `json:"epss"`          // published, untouched
    AdjustedEPSS float64 `json:"adjustedEpss"`  // local estimate
    RowID        string  `json:"rowId,omitempty"`
    FloorDefeated bool   `json:"floorDefeated,omitempty"`
}
```

CycloneDX: `vdr:controlCredit:<metric>` = comma-joined row ids;
`vdr:adjustedEpss`, `vdr:taxonomyVersion`.

## 7. Milestones

| # | Milestone | Size | Acceptance |
|---|---|---|---|
| CC0 | CWE surfacing | S | `cwes` populated (Vulnrichment→NVD), JSON/table/VEX surfaces, data-quality counter in header; golden tests incl. noinfo skip |
| CC1 | Taxonomy loader | S | pinned-release load, schema check, class expansion (incl. vector-conditioned CRASH), version in header |
| CC2 | K8s verification collectors | M | podspec/image/ingress predicates for the runtime, web, availability rows; per-control verification records in the evidence bundle |
| CC3 | Join engine + scoring hook (impact) | M | credits computed per (finding, asset); no-stacking collapse; ModifiedOverrides recompute; v1 IRV-fallback conservatism test (HA row requires citation/rate-limit when reachability model is v1) |
| CC3b | Exploitability adjustment | S | adjustedEPSS = EPSS * PRODUCT(residualFactors) floored at STACKING_FLOOR; LEV recompute; KEV frozen test; floor-defeat term; both EPSS values in output; no-taxonomy = stock LEV |
| CC4 | Credit-posture report | S | firing/blocked lists with exact failed predicates and benefiting-finding counts; PAIN and LEV downgrades each shown with row key |
| CC5 | STIG results ingestion | M | `--stig-results-file` + adapter resolution (requires_all + supplement semantics; supports never fires alone); freshness window fails closed |
| CC6 | Cloud-managed flags | M | RDS/Cloud SQL/ALB reads behind optional credentials; managed-db-ha and db-tls rows verifiable |

Order: CC0 → CC1 → CC2 → CC3 → CC3b → CC4, with CC5/CC6 parallel after CC1. CC0
is independently valuable (CWE visibility in reports) and should land first
regardless of the rest.

## 8. Non-goals

- No credit without a specific CWE (or class member) match — generic CWE-20 and
  noinfo never key.
- No mutation of published EPSS or the CVSS base vector; adjustedEPSS is a
  separate local field. No KEV interaction (frozen). No reachability
  determination changes — the reachability hard-line guidelines are not
  implemented (§4b).
- No runtime LLM anywhere in the decision path; attested artifacts enter as
  signed inputs like all other evidence.
- No taxonomy editing from the plugin; rows change only via the private repo's
  governed review.
