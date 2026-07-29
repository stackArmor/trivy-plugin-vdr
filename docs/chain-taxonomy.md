# CAPEC and ATT&CK Chain-Taxonomy Enrichment

CAPEC/ATT&CK projection is disabled by default. Enable it for a scan with:

```bash
trivy vdr k8s --include-chain-taxonomy --output vdr-capec.json
```

When enabled, `vdr` projects each finding's specific CWE assignments through
the official CAPEC and Enterprise ATT&CK corpora. Without the flag, normal
scans do not load the embedded catalog, calculate transition candidates, or
emit `chainCatalog`, `chainTaxonomy`, or `capecTransitions`. The projection is
informational: it preserves taxonomy evidence for review and future capability
modeling, but it does not change PAIN, IRV, remediation deadlines, or another
finding.

## What the result means

CAPEC `CanPrecede` and `CanFollow` relationships connect attack patterns, not
CVEs. A CVE inherits only a candidate taxonomy role through:

```text
CVE -> CWE -> active Standard/Detailed CAPEC pattern
                  -> ATT&CK technique -> ATT&CK tactic
                  -> explicit CAPEC predecessor/successor
```

When chain taxonomy is enabled, every finding receives `chainTaxonomy`:

- `status: mapped` means at least one active Standard/Detailed CAPEC pattern
  references one of the finding's CWEs.
- `status: unknown` means a specific CWE or eligible CAPEC mapping was absent.
  Unknown is not evidence that the CVE cannot participate in a chain.
- `predecessorStatus` and `successorStatus` are independently `present`,
  `not_declared`, or `unknown`. `not_declared` means the CVE mapped to an
  eligible CAPEC pattern but the sparse CAPEC graph declares no edge in that
  direction; `unknown` means there was no eligible path to assess.
- `producer_candidate` means a mapped CAPEC has an explicit successor.
- `consumer_candidate` means a mapped CAPEC has an explicit predecessor.
- `bridge_candidate` means the union of mapped patterns has both.
- `isolated_in_capec` means CAPEC declares no explicit edge for the mapped
  patterns. CAPEC's sparse edge coverage makes this an absence of evidence, not
  a negative classification.

`paths[]` retains each CWE-to-CAPEC path independently, including its resolved
ATT&CK techniques/tactics, predecessor and successor CAPEC IDs, and structured
CAPEC consequence impacts. The top-level lists on `chainTaxonomy` are sorted
convenience unions; `paths[]` is the reviewable provenance.

The report's `summary.chainTaxonomy` records post-filter active-finding
coverage. `chainCatalog` records the source corpus versions and SHA-256 hashes.
`reportSchemaVersion` identifies the public JSON contract independently of the
plugin release.

## Exact same-resource transition candidates

The report-level `capecTransitions[]` list is narrower than the per-finding
taxonomy role. It intentionally models one reviewable **external-to-follow-on**
shape rather than classifying every mapped CVE as an entrypoint. A transition
is emitted only when:

1. Two distinct active CVEs affect the same exact resource/container.
2. The resource is internet-accessible.
3. The upstream CVE is network-triggerable without prior privileges
   (`AV:N/PR:N`) and has a path `CWE A -> CAPEC P`.
4. CAPEC declares the explicit edge `P CanPrecede Q`.
5. The downstream CVE has a path `CWE B -> CAPEC Q`. Its CVSS attack vector
   can be network, adjacent, local, physical, or unavailable; AV/PR is retained
   only as review context.

Candidates are aggregated by exact resource, CVE pair, and CAPEC edge so the
same relationship is not repeated for every package occurrence or alternate
CWE mapping. Each endpoint retains the full package-occurrence and CWE lists,
the exact resource, CVSS AV/PR context, resource internet exposure, source
consequence impacts, and target CAPEC prerequisite prose. Policy
`capec-transition-v1` labels this `external_to_follow_on`,
`pattern_level_candidate` evidence. Every candidate is deliberately
`confidence: low` and `reviewRequired: true`: broad CWE assignments can project
into CAPEC patterns that do not match the concrete vulnerable code path.

The relationship endpoints are explicitly pair-scoped:

- `upstream.role: candidate_entrypoint` means the exposed `AV:N/PR:N` CVE maps
  to the CAPEC pattern on the source side of this particular `CanPrecede` edge.
- `downstream.role: candidate_follower` means the other CVE maps to the target
  CAPEC pattern in this transition.

These roles are never copied onto a CVE as a standalone classification. One
upstream CVE can feed multiple transition pairs, so
`summary.chainTaxonomy.entrypointCandidates` counts distinct
`(exact resource, upstream CVE)` combinations and
`uniqueEntrypointCves` counts distinct upstream CVE IDs.

CAPEC does not supply a structured `provides -> requires` capability contract.
Consequences and prerequisites are useful review evidence, but an explicit
CAPEC edge remains a relationship between attack-pattern classes rather than
proof that the concrete upstream exploit satisfies the downstream
precondition. Transition candidates never change IRV, PAIN, or remediation.
They are absent from standalone image scans because those scans have no
resource-level internet-exposure evidence.

Existing VDR JSON can be enriched without rescanning:

```bash
trivy vdr enrich-report \
  --input vdr.json \
  --output vdr-enriched.json \
  --html-output vdr-enriched.html
```

The command accepts legacy reports without `reportSchemaVersion` and the
current schema. Unknown future schemas fail closed. Resource-view reports are
also annotated; if their resource-local findings cannot reproduce the original
top-level finding count exactly, a warning records the coverage denominator
used.

## Offline catalog generation

The runtime never downloads CAPEC or ATT&CK and never performs a live per-CVE
taxonomy traversal. A release-time generator parses the official machine-
readable corpora directly:

- CAPEC XML: `Related_Weakness`, `Taxonomy_Mapping`, `CanPrecede`,
  `CanFollow`, `Consequences`, `Prerequisites`, and `Execution_Flow`
- Enterprise ATT&CK STIX JSON: active technique external IDs and
  `kill_chain_phases`

The generator filters CAPEC to Standard/Detailed patterns and excludes
Deprecated/Obsolete entries. It canonicalizes both relationship directions:

```text
A CanPrecede B -> A -> B
A CanFollow B  -> B -> A
```

Regenerate the checked-in catalog with:

```bash
curl -L https://capec.mitre.org/data/archive/capec_latest.zip \
  -o /tmp/capec_latest.zip
curl -L https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
  -o /tmp/enterprise-attack.json

make chain-catalog \
  CAPEC=/tmp/capec_latest.zip \
  ATTACK=/tmp/enterprise-attack.json

go test ./...
```

The generated JSON is deterministic for identical inputs. Changes to source
versions, hashes, pattern counts, CWE coverage, ATT&CK mappings, or chain edges
must be reviewed like a policy-data change.

## Current embedded snapshot

The initial snapshot contains:

- CAPEC 3.9, dated 2023-01-24
- Enterprise ATT&CK 19.1, modified 2026-05-12
- 497 active Standard/Detailed CAPEC patterns
- 307 distinct CWE keys
- 247 CAPEC-to-ATT&CK mappings
- 111 unique eligible CAPEC chain edges

CAPEC coverage is incomplete, especially for newer and memory-safety CWEs.
ATT&CK tactics describe adversary goals and must not be treated as a mandatory
attack sequence. Later chain construction should match an exploit's concrete
`provides` capability to a deployed successor's `requires` capability and use
CAPEC edges only as corroboration.
