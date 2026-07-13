# Handoff: PAIN Relief + Reachability integration for trivy-plugin-vdr

Written 2026-07-02. Consolidates the design decisions from the PAIN/reachability
session so the build can proceed (subagent per task). Read this, the
[pain-relief-spec](pain-relief-spec.md), and
[reachability-v2-spec](reachability-v2-spec.md) before starting.

## Locked decisions

1. **Exploitability downgrade = graduated adjustedEPSS** (implemented in the
   taxonomy, vdr-pain-relief 0.7.0). LEV stays binary. Controls never edit
   published EPSS; an `epss-residual` likelihood row lowers a local estimate
   `adjustedEPSS = EPSS * strongest-residualFactor`, thresholded at 0.50.
   **KEV frozen** (no factor, clock untouched). **Floor** defeated only binary
   via edge-auth. **No stacking** in v1 (lowest factor wins). **No taxonomy →
   adjustedEPSS = EPSS**, stock LEV. Only CC-LIKE-EDR-BLOCK carries a factor
   today (0.85, back-test pending).
2. **Reachability hard-line guidelines are NOT implemented.** Do not build the
   Phase B enforcement-or-attestation rule (telemetry silence never prunes) or
   the Gate 3 role/two-login tightening into the plugin. FedRAMP is not expected
   to take that hard a line. The credit engine reads the `IRV` bit from whatever
   reachability model runs (v1 today) and is agnostic to its strictness. The
   reachability paper PRs (#5 Gate 3) stay open/unmerged pending FedRAMP
   direction; do not revert already-merged paper text without explicit
   instruction.
3. **Taxonomy is opt-in.** No taxonomy loads by default. `--taxonomy <ref>`
   enables it. Public plugin embeds only the public snippet (0 rows public
   today, so default is genuinely "no credit engine").
4. **Taxonomy fetch uses gh CLI auth** (below).

## Repo/PR state

- **vdr-pain-relief** (private): PR #1 open, at 0.7.0 — 31 rows, 9 STIG/CIS
  adapters, classes.yaml (ACE/CRASH), exploitability model, snippet export tool.
  Merge when reviewed.
- **trivy-plugin-vdr** (public): on branch `codex/route-protocol-alpn-metadata`
  with UNCOMMITTED README + reachability-v2-spec edits (codex session's, leave
  them). Committed here this session (unpushed): pain-relief-spec.md,
  HANDOFF (this file). Route-protocol/ALPN metadata work is in-flight.
- **rfc-fedramp-vdr** (public): reachability companion blog PR #4, Gate 3 PR #5
  open. PAIN paper needs the credit-modifier section (HOLD — do not edit the
  local paper until Matthew confirms).

## Build tasks (one subagent each)

Branch strategy decision needed first: the plugin repo is mid-flight on the
codex branch. Recommended: cut `feat/PAIN Relief` from the codex branch base
(or main once codex merges), implement there, rebase before merge. Do NOT build
on the dirty codex branch directly.

- **T0 — codex pull & deploy.** Merge/deploy the in-flight codex branches
  (route-protocol-alpn-metadata and siblings) per Matthew's intent
  ("code from codex pulled in and deployed"). Resolve the uncommitted spec/README
  edits. Gate for everything else that touches the same repo.
- **T1 — CC0 CWE surfacing.** `cwes []string` on the enrichment record
  (Vulnrichment ADP → NVD `weaknesses[]`, skip noinfo/Other); JSON + table +
  `vdr:cwes`; data-quality counter in header. Independently valuable; land first.
- **T2 — CC1 taxonomy loader + gh-cli fetch.** `--taxonomy <ref>` accepts a
  local path or `owner/repo@tag`. For a private repo, fetch via the **gh CLI as a
  child process** using its existing auth: shell out to
  `gh api repos/<owner>/<repo>/tarball/<tag>` (or `gh release download`) so no
  token handling lives in the plugin — it inherits the operator's `gh auth`.
  Pin to a tag/digest, never `latest`. Verify signature when
  `--require-signed-evidence`. On any load/parse/verify failure: **disable the
  credit engine loudly, do not fall back.** Load rows + classes.yaml + profiles;
  expand ACE, and CRASH with the per-finding availability-only vector test.
  Record `taxonomyVersion` + tier (snippet/full) in the header.
- **T3 — CC2 verification collectors.** podspec/image/ingress predicates per
  verification-sources.yaml; per-control records into the evidence bundle.
- **T4 — CC3 impact join + scoring.** finding-CWE × verified control × row →
  Modified C/I/A; no-stacking collapse; recompute PAIN via existing Eq.1 path;
  v1 IRV-fallback conservatism (HA rows need rate-limit/citation under v1).
- **T5 — CC3b exploitability.** adjustedEPSS = EPSS × strongest residualFactor;
  LEV recompute; KEV frozen; floor-defeat term; both EPSS values in output;
  no-taxonomy = stock.
- **T6 — CC4 + HTML template.** Credit-posture report (firing/blocked with exact
  failed predicate + benefiting-finding counts). **HTML template** must show, per
  finding: PAIN row and whether it was downgraded and by which row key; LEV and
  whether exploitability was downgraded (EPSS → adjustedEPSS) and by which row
  key; and a legend/key mapping row ids → titles (short reference, not full
  rationale — full rationale stays in evidence lines / the private table). Show
  reachability status as computed (v1), no hard-line semantics.
- **T7 — CC5/CC6 STIG + cloud flags.** `--stig-results-file` + adapter
  resolution; optional RDS/Cloud SQL/ALB reads.

## Guardrails for every task

- Fail-open: no CWE/class match → no credit. No taxonomy → stock behavior
  everywhere (PAIN and LEV unchanged).
- Every applied credit records row id + taxonomyVersion in its evidence line;
  the HTML key references row ids only.
- Never mutate published EPSS or CVSS base; never touch KEV clocks; never change
  the reachability determination.
- Do not implement the reachability hard-line (decision 2).
