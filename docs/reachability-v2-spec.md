# Reachability v2: Finding-Level Internet-Reachable Vulnerability (IRV) Decision

Status: **Design spec — not implemented.** This document supersedes and incorporates
[`protocol-reachability-handoff.md`](protocol-reachability-handoff.md): the CVE
required-surface classifier designed there becomes filter **C2** of this model, and its
non-goals, evidence tiers, and VEX property scheme carry forward unchanged unless
explicitly amended below. The current production behavior is documented in
[`internet-reachability.md`](internet-reachability.md) and is referred to here as **v1**.

## 1. Motivation

FedRAMP Consolidated Rules 2026 (launched 2026-06-24) define an Internet-Reachable
Vulnerability (**FRD-IRV**) as:

> "A vulnerability in a machine-based information resource that might be exploited or
> otherwise triggered by a payload originating from a source on the public internet."

The definition explicitly includes resources with **no direct route to/from the
internet** that receive payloads indirectly, and scopes the determination to "the
specific vulnerable machine-based information resources processing the payload." Rule
**VER-EVA-EIR** gives the canonical examples: SQL injection on a private database
reached through an exposed application, and Log4Shell triggered by a logged string that
transited several tiers.

The plugin's v1 model computes a single asset-level boolean (`Exposure.InternetAccessible`,
consumed as `irv := in.InternetReachable` in `internal/scoring/scoring.go:308`). That
model has a **critical false negative**: a private PostgreSQL StatefulSet behind an
internet-facing web app is marked NIRV today, yet under FRD-IRV a SQL-injection or
protocol-parser CVE on that database is IRV — the payload originates on the public
internet and is processed by the vulnerable resource. v1 also has a class of false
positives the new rules let us remove: a TLS-handshake CVE on a listener that only
internal peers can open a connection to is not triggerable by an internet payload even
if the asset is "reachable" in a data-flow sense.

v2 therefore moves the IRV decision from the asset to the **(vulnerability, asset)
pair**:

```text
IRV(v, a) = [ E(a) OR T(a) ]                 -- a payload can arrive at a
            AND execution(v, a)              -- the vulnerable code can run on a
            AND surface_match(v, a)          -- the arriving payload format can hit v
            AND mechanism_applies(v, a)      -- v's trigger mechanism works at a's position
```

- `E(a)`: **direct exposure** — asset accepts connections originated from the internet
  (v1's engine, Phase A).
- `T(a)`: **transitive payload exposure** — asset receives data that originated from the
  internet through one or more intermediary workloads (Phase B).
- `execution(v, a)`, `surface_match(v, a)`, `mechanism_applies(v, a)`: per-vulnerability
  filters (Phase C). Each is a predicate that **defaults to true** absent evidence.

### Design principles (normative)

1. **Minimal false negatives.** Every filter defaults to "applies" (IRV-preserving)
   when evidence is missing, ambiguous, stale, or conflicting. An operator earns NIRV
   exclusions only by supplying data; the plugin never infers safety from absence of
   data. This generalizes the handoff doc's "unknown = wildcard" rule to all four terms.
2. **Evidence on every decision.** Every IRV/NIRV determination — and every filter
   that fired or declined to fire — emits human-readable evidence lines (the existing
   `Exposure.Evidence []string` pattern) plus machine-checkable references into an
   evidence bundle (section 8).
3. **Determinism.** Same input snapshot → same output. All external inputs (flow logs,
   IAM policies, enrichment records) are snapshotted into the evidence bundle; there is
   no runtime LLM/agentic step in the decision path. Optional agentic *enrichment*
   produces signed evidence records consumed like any other input (section 7.3).
4. **No CVSS mutation, no port-only downgrades, no probabilistic scoring** (section 11).

---

## 2. Decision pipeline overview

```text
                         ┌────────────────────────────────────────────┐
 cluster + cloud +       │ Phase A: direct exposure          E(a)     │
 operator inputs ───────►│ Phase B: taint graph              T(a)     │──► per-asset
                         └────────────────────────────────────────────┘    PayloadExposure
                                            │
 per (finding, asset):                      ▼
                         ┌────────────────────────────────────────────┐
 CVE + enrichment +      │ Phase C filters (evaluated only when       │
 runtime evidence ──────►│ E(a) OR T(a) is true):                     │──► per-finding
                         │   C3 execution(v,a)                        │    ReachabilityDecision
                         │   C2 surface_match(v,a)                    │
                         │   C1 mechanism_applies(v,a)                │
                         └────────────────────────────────────────────┘
```

Top-level decision algorithm (replaces `irv := in.InternetReachable` at
`internal/scoring/scoring.go:308`):

```text
func decideIRV(v Finding, a Asset) ReachabilityDecision:
    if not (E(a) or T(a)):
        return NIRV(phase="exposure",
                    evidence="no direct route and no tainted data-flow path to asset")

    # Filters run in cheapest-first order; each returns (passes bool, FilterResult).
    # "passes" means "this filter does NOT exclude IRV".
    for f in [executionFilter, surfaceFilter, mechanismFilter]:
        passes, result = f(v, a)
        decision.filtersApplied += result          # recorded even when it passes
        if not passes:
            return NIRV(phase=f.name, filters=decision.filtersApplied,
                        evidence=result.evidence)

    return IRV(phase="exposure:"+ (E(a) ? "direct" : "transitive"),
               filters=decision.filtersApplied)
```

Every filter is fail-open: an error, a missing data source, or an "unknown"
classification makes `passes = true` with an evidence line explaining why the filter
declined to exclude.

---

## 3. Phase A — Direct exposure E(a)

The v1 engine (`internal/exposure/exposure.go`: Ingress, Gateway API, Service
LoadBalancer classification for GKE and AWS; operator override labels/ConfigMap;
NodePort advisory handling; init-container inheritance) is kept as-is. Three deltas:

### A.1 hostNetwork / hostPort pods

A pod with `spec.hostNetwork: true`, or a container with `ports[].hostPort` set, binds
directly to node network interfaces. As with NodePort, whether the node itself is
internet-facing is not determinable from cluster state, but unlike NodePort there is no
Service object to label — so the signal must live on the workload.

- **Detection:** during inventory collection (pod spec already read), record
  `hostNetwork` and the set of `hostPort` values per container.
- **Classification:** advisory by default (`InternetAccessible=false`), same posture as
  NodePort. Honor a workload/pod label `vdr.fedramp.io/internet-reachable-hostPort:
  "true"|"false"` (parallel to `vdr.fedramp.io/internet-reachable-nodePort`). The
  existing `vdr.fedramp.io/internet-reachable` label on the workload wins when both
  are present.
- **Evidence (advisory):**
  `"Pod ns/name binds hostPort 8443 (container app); node-IP reachability is unverified and NOT counted as internet-reachable. Set label vdr.fedramp.io/internet-reachable-hostPort to classify."`
- **Phase B interaction:** a hostNetwork pod is still a taint-graph node; its edges are
  keyed by node IPs when flow data is used (section 5.3.1).

### A.2 DaemonSet exposure

DaemonSets are already inventoried but their exposure is only derived through Services
that select them. Two DaemonSet-specific paths are added:

1. DaemonSets whose pod template sets `hostNetwork`/`hostPort` (the common pattern for
   node-level ingress daemons, e.g. ingress-nginx in DaemonSet+hostPort mode) — handled
   by A.1.
2. DaemonSets selected by a public Service/Ingress/Gateway route — already handled by
   the v1 selector mapping; no change, but add a test fixture to prove it.

### A.3 Edge-auth exclusion: pre-auth boundary semantics

**Default posture:** a detected edge-auth boundary that rejects unauthenticated traffic
before backend processing **excludes direct IRV for that route by default**. The plugin
must not require cloud-account discovery, region/account lookups, or per-resource tags
to recognize the common IAP/OIDC/Cognito use case: a private workload exposed through a
pre-auth boundary. Optional signals and annotations exist to **refute or refine** the
exclusion, not to earn it in the normal case.

This unifies current behavior across providers. GKE IAP already behaves this way in
v1. Under v2, AWS ALB OIDC/Cognito and AWS Verified Access follow the same rule when
their Kubernetes-visible configuration proves pre-auth rejection. The model asks a
local, deterministic question first: "can anonymous internet request bytes reach the
backend parser?" If the answer is no, the route is not a direct internet payload path.

A route qualifies for edge-auth exclusion when all required local facts hold:

- **(a) Pre-processing rejection:** the boundary rejects unauthenticated traffic
  *before* any backend processing occurs. Examples: GKE IAP enabled; ALB
  `auth-type: oidc|cognito` with `auth-on-unauthenticated-request` unset,
  `authenticate`, or `deny`; Verified Access endpoint policy present.
- **(b) No explicit customer-auth refutation:** the operator has not marked the route
  as public/customer enrollment. The default is private-access semantics because the
  plugin's target use is CSP workload exposure, not customer identity-product
  modeling.
- **(c) No known bypass:** the backend is not also reachable through another public
  path that skips the boundary. Other public Kubernetes routes are evaluated
  independently by Phase A. The residual surface — a public path outside plugin
  visibility, or an application that intentionally accepts unsigned/spoofed boundary
  assertion headers — is handled by explicit refutation annotations below.

When the boundary qualifies, `E(a)=false` for **that route only**. The asset may still
be directly exposed through another unauthenticated route, or transitively payload
exposed through Phase B. The `AccessProtection` record is kept as evidence in all
cases.

**Refutation and refinement metadata.** Operators may explicitly mark a boundary as
customer-auth/public, or force-disqualify the exclusion when a bypass exists. This is
the metadata path; there is no requirement to tag every protected resource.

- Annotation on the backend Service (or on the BackendConfig / Ingress):
  `vdr.fedramp.io/edge-auth-role: remote-access|customer-auth`.
  - `remote-access` restates the default and is useful only as documentation.
  - `customer-auth` refutes the default exclusion and keeps the route direct-IRV.
  Legacy alias:
  `vdr.fedramp.io/edge-auth-population: closed|open` maps `closed`→`remote-access`,
  `open`→`customer-auth`; when both are present, `edge-auth-role` wins.
- Central ConfigMap key in `fedramp-vdr-trivy/vdr-fedramp`:
  `edgeAuthRoles` (legacy alias `edgeAuthPopulations` accepted):
  ```yaml
  data:
    edgeAuthRoles: |
      - service: prod/customer-portal
        role: customer-auth
        note: "Public customer login; internet-originated payloads are allowed"
  ```
- Bypass/refutation annotation:
  `vdr.fedramp.io/edge-auth-assertion-validated: "false"` force-disqualifies the
  exclusion for that backend when the operator knows direct backend access is possible
  or the application does not validate required boundary assertions.

**Optional cloud signals.** Credentialed cloud reads are allowed only as optional
refutation or audit enrichment. They are not required for the default exclusion and
must not be on the critical path.

| Product | Local pre-auth signal | Default | Optional refuting/enriching signal |
|---|---|---|---|
| GCP IAP | BackendConfig / GCPBackendPolicy IAP enabled | exclude direct IRV | IAP IAM policy can be archived as evidence; broad `allUsers`/`allAuthenticatedUsers` may refute if intentionally customer-auth |
| AWS ALB OIDC | ALB auth annotations, unauthenticated action not `allow` | exclude direct IRV | none required; operator may mark `customer-auth` |
| AWS ALB Cognito | ALB auth annotations, unauthenticated action not `allow` | exclude direct IRV | none required; operator may mark `customer-auth` |
| AWS Verified Access | Verified Access association/policy visible from cluster/cloud metadata | exclude direct IRV | optional policy/trust-provider snapshot for audit |
| Other pre-auth proxy / client VPN | recognized config or operator declaration of pre-auth boundary | exclude direct IRV | operator may mark `customer-auth` or assertion-invalid |

Decision table:

| Boundary detected | Pre-rejects before backend | Refutation | Result |
|---|---|---|---|
| none | — | — | E(a) per v1 route rules |
| IAP / OIDC / Cognito / Verified Access / client VPN | yes | none, or `remote-access` documentation | `E(a)=false` for this route; evidence records pre-auth boundary |
| same | yes | `edge-auth-role: customer-auth` / `edge-auth-population: open` / assertion-invalid override | `E(a)=true`; `AccessProtection` recorded as advisory evidence |
| same | no (e.g. ALB `auth-on-unauthenticated-request: allow`) | any | `E(a)=true`; boundary recorded as advisory only |

Evidence line formats:

```text
"edge-auth exclusion: GKE IAP (BackendConfig prod/web-bc) rejects unauthenticated traffic before backend processing; no customer-auth refutation found; route excluded from direct IRV"
"edge-auth exclusion: AWS ALB OIDC on Ingress prod/ops uses auth-on-unauthenticated-request=authenticate; no customer-auth refutation found; route excluded from direct IRV"
"edge-auth NOT excluded: AWS ALB Cognito on Ingress prod/customer is annotated vdr.fedramp.io/edge-auth-role=customer-auth; route remains direct IRV and AccessProtection is recorded as advisory evidence"
"edge-auth NOT excluded: AWS ALB OIDC on Ingress prod/app has auth-on-unauthenticated-request=allow; unauthenticated payload bytes may reach backend"
```

---

## 4. Phase B — Transitive payload exposure T(a)

The core new capability: a directed data-flow graph over workloads, tainted from
Phase-A entry points.

### 4.1 Graph model

```text
Node  := workload identity
         k8s:   {cluster, namespace, workloadKind, workloadName}   -- the same
                model.ResourceRef granularity used by exposure today
         ext:   {provider, kind, id}                               -- external service
                (cloud LB, VPC peer, SaaS endpoint), used for path evidence only
Edge  := {src Node, dst Node, dstPorts []PortRef, direction: src→dst,
          source: observed|permitted|declared,
          formats []DeliveredFormat,        -- section 6.2, may be empty=unknown
          firstSeen, lastSeen time,         -- observed edges only
          evidenceRef string}               -- pointer into evidence bundle
PortRef := {port int32, name string, appProtocol string}
```

Direction is **payload direction**: an edge `frontend → api` means data that entered
`frontend` can be forwarded to `api`. For request/response protocols the connection
initiator is the payload sender; response-channel taint (server→client) is
deliberately **not** modeled in v2 (open question Q5).

Edges are produced by three signal tiers, best-available-wins per edge attribute but
**union** for edge existence (an edge exists if *any* tier asserts it — adding signal
sources can only add edges, never remove them, preserving minimal false negatives):

### 4.2 Kubernetes signal sources

#### Tier 1 — Observed flows (preferred)

1. **Cilium Hubble.** Input: either a live query (`hubble observe --output jsonpb
   --since <window>` against the Hubble Relay, flag `--hubble-server`) or an exported
   flow file (`--flows-file <path>`, newline-delimited JSON `flow.Flow` records; this
   is the format `hubble observe -o jsonpb` emits). Mapping:
   - node identity: `flow.source.workloads[0]` / `flow.destination.workloads[0]`
     (kind+name), falling back to pod owner resolution against the inventory when the
     workload field is absent;
   - keep only `verdict: FORWARDED` L4/L7 flows; drop reply packets
     (`is_reply: true`) so direction = payload direction;
   - `flow.l7` populates `formats` (HTTP, Kafka, DNS, gRPC per Hubble L7 visibility);
     L4-only flows leave `formats` empty (= unknown = wildcard);
   - `flow.time` populates `firstSeen`/`lastSeen` aggregation.
2. **Service mesh telemetry.**
   - Istio/Envoy: scrape or accept a Prometheus export of `istio_requests_total` and
     `istio_tcp_connections_opened_total` (labels `source_workload`,
     `source_workload_namespace`, `destination_workload`,
     `destination_workload_namespace`, `request_protocol`). Input flag
     `--mesh-metrics-file <path>` (Prometheus text or OpenMetrics exposition snapshot)
     — live scraping is out of scope for the first milestone.
   - Linkerd: `linkerd viz edges -o json` output accepted via the same flag.
3. **Staleness window.** Observed edges older than `--flow-max-age` (default `168h` =
   7 days) are dropped *as observed edges* — but note the tier-combination rule in
   4.4: dropping an observed edge never removes an edge that a lower tier asserts.

#### Tier 2 — Permitted flows: NetworkPolicies

NetworkPolicies are **not collected today** — this is milestone B1:

- Add to `internal/k8s/exposure_objects.go` collection: typed list of
  `networking.k8s.io/v1 NetworkPolicy` (namespaced) via
  `c.Client.NetworkingV1().NetworkPolicies(namespace).List(...)`, plus RBAC
  `networkpolicies: [list]` in both README ClusterRole examples.
- Optionally (same milestone, dynamic/unstructured like the other CRDs):
  `cilium.io/v2 CiliumNetworkPolicy`, `cilium.io/v2 CiliumClusterwideNetworkPolicy`,
  and `projectcalico.org/v3 NetworkPolicy` / `GlobalNetworkPolicy`. First milestone
  evaluates only vanilla `networking.k8s.io/v1`; when Cilium/Calico CRDs are *present
  but not evaluated*, the graph builder must treat policy data as **incomplete** and
  fall back to declared topology for the affected namespaces (evidence:
  `"CiliumNetworkPolicy present in namespace X but not evaluated; permitted-flow tier disabled for X"`).

Allow-graph evaluation (standard Kubernetes semantics — remember **default-allow when
no policy selects a pod**):

```text
buildPermittedEdges(policies, workloads):
    for each dst workload d, each ingress port p of d:
        selecting = policies P where P.namespace == d.namespace
                    and P.podSelector matches d.podTemplate.labels
                    and "Ingress" in P.policyTypes
        if selecting is empty:
            # default-allow: any workload (and any external peer) may connect
            for each workload s in cluster: addEdge(s → d, port p, source=permitted,
                evidence="no NetworkPolicy selects dst; Kubernetes default-allow")
            continue
        for each rule in union(selecting[].ingress):
            if rule.ports set and p not in rule.ports: continue
            if rule.from empty:      # allow-all rule
                for each s: addEdge(s → d, p, permitted, evidence=policyRef)
            for each peer in rule.from:
                for each s matching (podSelector, namespaceSelector) combination:
                    addEdge(s → d, p, permitted, evidence=policyRef)
                # ipBlock peers: emit ext node edge; 0.0.0.0/0 (minus private
                # excepts) additionally marks d as a Phase-A-equivalent entry
                # point candidate ONLY if d also has a public route (never by itself)
```

Egress policies are evaluated symmetrically and intersected: an edge `s → d` is
permitted only if `d`'s ingress allows it **and** `s`'s egress allows it (each side
defaulting to allow when unselected).

#### Tier 3 — Declared topology (always available)

- **Service selector → endpoints:** every Service that selects workload `d` makes `d`
  a *connectable target*; the conservative closure is: any workload in the cluster may
  connect to any Service (this is exactly Kubernetes default networking). Tier 3 alone
  therefore yields the complete graph — which is the correct minimal-false-negative
  degenerate case (see 4.5).
- **Operator-declared edges** (to *refine*, i.e. document, not to remove): annotation
  on the source workload
  `vdr.fedramp.io/sends-to: "ns1/svc-a, ns2/svc-b"` and/or ConfigMap key
  `declaredEdges` with `{from, to, formats}` entries. Declared edges may carry
  `formats` for C2 (e.g. `postgres`, `http`). Declared edges add edges and metadata;
  they never subtract.
- **Operator-declared isolation** is expressed only through NetworkPolicies (tier 2) —
  we deliberately do not offer a "trust me, these don't talk" annotation, because an
  unenforced claim is not evidence. (Open question Q4 records the pressure to add one.)

### 4.3 Non-Kubernetes extensions

Same graph model, different collectors. All are milestone B4+ (post-GA of the k8s
path) but the interfaces are fixed now:

- **VPC Flow Logs (GCP/AWS):** offline ingestion (`--vpc-flows-file`) of exported flow
  log records (GCP: BigQuery/GCS JSON export schema with
  `src_instance`/`dest_instance`/`src_gke_details`; AWS: v5 flow log fields incl.
  `pkt-src-aws-service`, ENI→instance/SG resolution supplied as a sidecar mapping
  file). Aggregate to security-group- or instance-level nodes; GKE-annotated GCP
  flows map back to workload nodes.
- **Host telemetry (VM fleets):** accepted as a normalized peer-map file
  (`--host-flows-file`): JSON lines `{host, pid?, process?, laddr, raddr, direction,
  observedAt}` as produced by `ss -tnp`/netstat scrapes or eBPF socket telemetry
  agents. Hosts become `ext` nodes unless a mapping file ties them to inventory
  assets.
- **Cloud Run:** the `cloudrun` source builds edges from (1) service-to-service
  invocation grants — service A's runtime service account holding `roles/run.invoker`
  on service B ⇒ edge A→B (permitted tier); (2) VPC connectors / direct VPC egress ⇒
  edges from the service node into the connected VPC's node set (bridging to VPC flow
  logs when supplied). Phase-A entry points are the existing Cloud Run public
  services.

### 4.4 Tier combination rule

Per (src,dst,port) edge:

1. Edge **existence** = union of all tiers.
2. Edge **formats** metadata = highest tier that supplies it (observed L7 > declared >
   inferred from `appProtocol`/port-name per the handoff doc's evidence tiers).
3. **Pruning** (deciding an edge does NOT exist) is only possible when tier-2 policy
   data is complete for both endpoints AND tier-1 observation (if configured) shows no
   flow within the window: an edge absent from the permitted graph is absent, period —
   NetworkPolicy is enforcement, not observation, so policy-only pruning is sound.
   Observed-flow *absence* alone never prunes (a monthly batch job may simply not have
   run in the window); it is recorded as advisory
   (`"edge permitted by policy but not observed in last 7d"`).

### 4.5 Taint algorithm

```text
computeTaint(graph, entryPoints):        # entryPoints = { a : E(a) == true }
    # plus NetworkPolicy ingress rules with public ipBlock hits per 4.2 tier-2 note
    tainted = {}
    queue = [(e, path=[entry-evidence(e)]) for e in entryPoints]
    while queue not empty:
        (n, path) = queue.pop()
        if n in tainted: continue                  # keep first (shortest) path; also
        tainted[n] = path                          # collect up to K=3 distinct paths
        for edge in graph.outEdges(n):             # deterministic order: sorted by
            queue.push((edge.dst, path + [edge]))  # (namespace, kind, name, port)
    return tainted

T(a)     = a in tainted
paths(a) = tainted[a]     # recorded as TaintPath evidence
```

BFS with sorted adjacency gives deterministic shortest paths. Up to `K=3` distinct
paths are retained per asset for evidence (configurable `--taint-max-paths`); the
count of additional paths is recorded (`"+ 4 more paths"`).

Assets not reached by taint **and** not directly exposed are **NIRV wholesale** — no
Phase C evaluation needed:

```text
"NIRV: no direct route (Phase A) and no data-flow path from any internet entry point (Phase B graph: 3 entry points, 41 nodes, 187 edges, sources=[networkpolicy, hubble]); asset postgres/db-analytics is unreached"
```

Path evidence line format:

```text
"tainted via frontend(Ingress web-public) -> api(edge: permitted, NetworkPolicy prod/allow-frontend, port 8080/http) -> postgres(edge: observed, Hubble flows 2026-06-21..2026-06-28, port 5432, l7=unknown)"
```

### 4.6 Conservative defaults by data availability

| Available data | T(a) behavior |
|---|---|
| Observed flows + policies | Full graph; policy prunes, flows enrich formats/recency |
| Policies only | Permitted graph; pruning sound; formats mostly unknown |
| Observed flows only | Union of observed edges **and** tier-3 declared topology — observed flows alone must not prune (absence ≠ impossibility), so the graph degrades to "declared topology, with some edges enriched" |
| **Neither** | **T(a) = true for every asset in the cluster.** Tier-3 declared topology under default-allow is the complete graph, so every asset connected to the cluster network is transitively payload-exposed. This is deliberate: with no flow/policy data the plugin must not manufacture NIRV. The operator earns exclusions by providing data. Evidence: `"T=true (default): no NetworkPolicy or flow data available; Kubernetes default-allow networking makes every workload transitively payload-exposed from 3 internet entry points"` |

Note the practical consequence: **turning on v2 with zero Phase-B data never reduces
IRV counts below v1 at the exposure stage — it strictly raises them** (private assets
become IRV-eligible). Reductions come only from supplying policies/flows (Phase B
pruning) or from Phase C filters. This is the intended compliance posture under
FRD-IRV.

### 4.7 Snapshot determinism & staleness

- All Phase-B inputs are read once at collection time and archived verbatim into the
  evidence bundle (section 8). The graph builder consumes only the archived snapshot;
  re-running against the bundle reproduces the identical graph and decisions
  (`vdr replay --evidence-bundle <dir>` is a stretch goal, milestone B5).
- Observed-flow validity window: `--flow-max-age` (default 168h). Flow files whose
  newest record is older than the window fail closed for pruning-related uses and emit
  a warning; they are still archived.
- The graph, tainted set, and per-asset paths carry a `snapshotAt` timestamp and a
  content hash of the input set, both emitted in the report header.

---

## 5. Phase C — Per-vulnerability filters

Evaluated per (finding, asset) only when `E(a) OR T(a)`. Order: C3 execution (cheap
lookup), C2 surface, C1 mechanism — but they are logically independent ANDs; all
results are recorded even after the first exclusion short-circuits the IRV outcome
(the remaining filters are skipped and recorded as `skipped`).

### 5.1 C3 — Execution evidence: `execution(v, a)`

Does the vulnerable code actually execute (or is it loadable) in the asset's
containers?

- **Default: passes** (stays IRV). No runtime evidence supplied → no exclusion.
- **Evidence inputs** (flag `--execution-evidence <path>`, repeatable; directory or
  file):
  - eBPF loaded-library / process telemetry exports: normalized JSON lines
    `{asset: ResourceRef-ish selector, image, observedAt, kind: "library-loaded"|
    "process-executed"|"symbol-resolved", subject: {package?, path?, soName?,
    symbol?}, window: {from, to}}`. Producers: any agent that can enumerate
    `/proc/<pid>/maps` or hook `dlopen`/`execve` (e.g. Tetragon, Falco with the right
    ruleset, custom eBPF). The plugin defines the exchange format, not the agent.
  - External VEX-style evidence files asserting `vulnerable_code_not_present` /
    `vulnerable_code_not_in_execute_path` for (CVE, image) pairs, with a `source` and
    optional signature (verified when `--require-signed-evidence` is set).
- **Exclusion rules** (both require evidence *coverage*, i.e. the telemetry window
  spans ≥ `--execution-min-window` (default 72h) of the asset actually running):
  1. **package-not-executed:** telemetry enumerates all executed processes/loaded
     libraries for the container over the window and the vulnerable package's
     binaries/libraries are provably absent from that enumeration **and** the agent
     asserts complete coverage (`"coverage": "complete"` in the export). Maps to VEX
     justification `vulnerable_code_not_in_execute_path`.
  2. **symbol-not-loaded:** the vulnerable shared object is never mapped (finer:
     never `dlopen`ed / never present in any `proc/maps`). Maps to
     `vulnerable_code_not_present` when the file is absent from the image layer
     actually mounted, else `vulnerable_code_not_in_execute_path`.
- **Interaction with Trivy:** none required — this operates on Trivy findings
  post-scan; no `--skip-*` coupling. (Trivy's own experimental reachability is not
  consumed in v2.)
- Evidence line:
  `"execution excluded: package libxml2 never loaded in prod/api (Tetragon export tetragon-2026-06-28.jsonl, coverage=complete, window 2026-06-21..2026-06-28); VEX justification vulnerable_code_not_in_execute_path"`
  or on pass:
  `"execution filter passed (default): no runtime execution evidence supplied"`.

### 5.2 C2 — Trigger-surface matching: `surface_match(v, a)`

This is the handoff doc's CVE required-surface classifier, generalized from "the
exposed backend surface" to "the set of formats delivered to `a` over the edges that
carry taint to it."

- **Required surface X(v):** deterministic classifier per the handoff doc — CPE
  product→protocol table, CWE hints, curated title/description token rules, CVSS
  `AV:N` gate; output `{requiredProtocols, requiredAlpn, confidence, evidence,
  classifierVersion}`. High confidence is required for any exclusion; medium/unknown
  are advisory/wildcard exactly as specified there.
- **Delivered surface D(a):** union over
  - Phase-A route metadata for directly exposed assets (`RouteMetadata`
    backendProtocol / backendProtocolVersion / ALPN — already implemented), filtered
    through the handoff doc's evidence tiers (Tier 1/2 and corroborated 3a usable for
    exclusions; 3b/4 advisory);
  - Phase-B **inbound tainted-edge formats** for transitively exposed assets: per-edge
    `formats` from Hubble L7, mesh `request_protocol`, `ServicePort.appProtocol`,
    corroborated port-name convention, declared-edge formats. Only the edges on taint
    paths into `a` count — a non-tainted side channel doesn't widen D(a)... but see
    the conservative rule: if *any* tainted inbound edge has unknown format,
    `D(a) = {*}` (wildcard).
- **Decision:**

```text
surfaceFilter(v, a):
    X = classify(v)                       # required surface
    if X.confidence != high or X.requiredProtocols empty:
        return pass, "surface filter passed: required surface unknown/low-confidence (wildcard)"
    D = deliveredFormats(a)               # from tainted edges / routes
    if D contains wildcard:
        return pass, "surface filter passed: at least one delivering edge has unknown format (wildcard)"
    if X.requiredProtocols ∩ D == ∅ (and ALPN likewise when specified):
        return exclude, "surface mismatch: CVE requires ssh; tainted edges deliver only {http/1.1 (Hubble L7), postgres (declared)}"
    return pass, "surface match: CVE requires http; edge frontend->api delivers http/1.1"
```

- **Kept non-goal:** no port-only downgrades — port-number heuristics (handoff Tier 4)
  never populate D(a) for exclusion purposes.
- Note an important asymmetry vs. the naive reading: for a transitively exposed
  database, "delivered format" is what the *intermediary* sends it (e.g. the postgres
  wire protocol carrying attacker-influenced query text) — so SQL-injection CVEs on
  the DB match (required surface: sql/postgres, delivered: postgres), while an
  OpenSSH CVE on the same DB host is excludable. This is exactly VER-EVA-EIR's
  intended discrimination.

### 5.3 C1 — Trigger-mechanism class: `mechanism_applies(v, a)`

Distinguishes vulnerabilities triggered by **payload content** (which survives
forwarding through tiers) from those triggered by **connection/peer properties**
(which do not — only the directly connecting peer can trigger them).

```text
mechanismFilter(v, a):
    class = mechanismClass(v)             # PAYLOAD_CARRIED | PEER_BOUND | UNKNOWN
    if class in {PAYLOAD_CARRIED, UNKNOWN}:
        return pass
    # PEER_BOUND:
    if E(a): return pass                  # internet peers connect directly
    # E(a)=false, T(a)=true: only internal intermediaries open connections to a
    return exclude, "mechanism excluded: CWE-295 (TLS handshake) is PEER_BOUND; asset has no direct internet route — only internal peers (frontend, api) open connections to it (taint is payload-only)"
```

**CWE-keyed partition** (curated table shipped with the plugin, versioned like the C2
classifier; a CVE with multiple CWEs takes the *most IRV-preserving* class, i.e.
PAYLOAD_CARRIED beats PEER_BOUND beats nothing):

| Class | CWEs (initial table) | Rationale |
|---|---|---|
| **PAYLOAD_CARRIED** — never class-excluded | CWE-89 (SQLi), CWE-78 (OS cmd inj), CWE-917 (EL inj / Log4Shell), CWE-94 (code inj), CWE-502 (deserialization), CWE-119/CWE-787/CWE-125 (parser memory corruption), CWE-611 (XXE), CWE-918 (SSRF), CWE-22 (path traversal), CWE-79 (XSS — see warning), CWE-434 (unrestricted upload), CWE-1333/CWE-400-via-input (ReDoS, decompression/zip bombs — see warning) | Trigger travels *inside* the data; intermediaries forward it |
| **PEER_BOUND** — excludable when E(a)=false | CWE-287/CWE-306 *when the flaw is at the network listener* (socket-level auth bypass), CWE-295 and TLS/protocol **handshake & state-machine** flaws, CWE-400 *connection-flood* DoS (SYN floods, connection-slot exhaustion) | Trigger requires the attacker to be the connecting peer; a benign internal client re-originates its own handshake/connection |
| **UNKNOWN** → treated as PAYLOAD_CARRIED | everything else | Minimal false negatives |

**Explicit warnings (normative, restated from the table):**

- **Stored XSS (CWE-79) is PAYLOAD_CARRIED.** The script payload originates from an
  internet source even though it detonates later in a victim browser; the vulnerable
  resource processing the payload is IRV. Do not be tempted to treat XSS on an
  internal rendering tier as peer-bound.
- **ReDoS and zip-bomb/decompression DoS are PAYLOAD_CARRIED.** They are DoS by
  *content*, not by connection volume. Only connection-flood-style DoS is PEER_BOUND.
- **CWE-287/306 are PEER_BOUND only at the listener.** An auth bypass in
  application-level logic that evaluates forwarded credentials/tokens (e.g. a JWT
  validation flaw) is PAYLOAD_CARRIED — the curated table keys on (CWE, CPE/product
  heuristic) pairs for these two CWEs, and when the position can't be determined the
  entry resolves to UNKNOWN → PAYLOAD_CARRIED.

**Enrichment sources** for the CWE(s) of a CVE, in precedence order:
1. CISA Vulnrichment ADP CWE assignments (the plugin already consumes Vulnrichment for
   the automatability fallback; extend the cached record with `cwes []string`). Note:
   this CWE use is **unaffected** by the companion vdr-pain-cvss v1.4 removal of
   Vulnrichment, which excluded only the technical-impact/exploitation inputs — see
   the LEV alignment note in section 6.1;
2. NVD CVE record CWE (`weaknesses[].description`);
3. none found → UNKNOWN → PAYLOAD_CARRIED.

**Optional agentic enrichment hook:** an external process may supply per-CVE mechanism
classifications as signed evidence records
(`{cve, class, rationale, source, signedBy, producedAt}` accepted via
`--mechanism-evidence <path>`). Deterministic rule: a signed record may move a CVE
from UNKNOWN to PEER_BOUND (enabling exclusion) or from PEER_BOUND to PAYLOAD_CARRIED
(revoking one); it may **never** move PAYLOAD_CARRIED to PEER_BOUND — the curated
table's payload classifications are a floor. No LLM runs inside the CLI (handoff
non-goal preserved).

---

## 6. Wiring and output

### 6.1 Scoring integration

`internal/scoring/scoring.go` `Score()` currently receives `in.InternetReachable
bool`. Change:

```go
// scoring.Input gains:
Reachability *model.ReachabilityDecision // nil => v1 semantics via InternetReachable

// scoring.go:307-309 becomes:
irv := in.InternetReachable                       // v1 path (default)
if in.Reachability != nil {                       // v2 path
    irv = in.Reachability.IRV
}
column := remediationColumn(lev, irv)
```

The VDR-TFR-PVR matrix, PAIN computation, and LEV computation are untouched — v2 only
changes which findings land in the `LEV+IRV` vs `LEV+NIRV` column.

> **LEV alignment note.** The companion PAIN methodology (vdr-pain-cvss **v1.4**)
> removed CISA Vulnrichment from its model: LEV there is
> `EPSS >= threshold OR KEV membership OR the FRD-LEV unauthenticated-automation
> floor` (direct-exposure IRV combined with `AV:N/PR:N/UI:N`). This spec does not
> compute LEV; when the plugin aligns its LEV inputs to v1.4 (replacing the
> Vulnrichment `exploitation=active` input with KEV membership), that change is
> orthogonal to this spec, with one touchpoint: the FRD-LEV floor's
> "direct exposure" input is exactly Phase A's `E(a)` — not the broader `IRV(v,a)`.
> Separately, this spec's use of Vulnrichment for **CWE enrichment** in the C1
> mechanism partition (section 5.3) is **unaffected** by the v1.4 removal: what v1.4
> excluded are the technical-impact/exploitation inputs, not CWE sourcing. A future
> implementer must not remove the Vulnrichment CWE source as part of that alignment.

**Compatibility flag:** `--reachability-model=v1|v2` (default **v1** until GA).
- `v1`: exact current behavior; none of the new collectors run (except NetworkPolicy
  collection, which is harmless and useful for warm-up).
- `v2`: full pipeline. Reports carry `"reachabilityModel": "v2"` in the header.
- A transitional `--reachability-model=v2-report-only` runs v2 and emits
  `ReachabilityDecision` on every finding but keeps v1's boolean for the deadline
  column, so operators can diff the models before switching deadlines. (Sizing: small;
  strongly recommended for rollout.)

New CLI flags (all `k8s`-source unless noted):

| Flag | Default | Purpose |
|---|---|---|
| `--reachability-model` | `v1` | `v1` / `v2` / `v2-report-only` |
| `--flows-file` | — | Hubble jsonpb flow export (repeatable) |
| `--hubble-server` | — | live Hubble Relay address (later milestone) |
| `--mesh-metrics-file` | — | Istio/Linkerd telemetry snapshot |
| `--flow-max-age` | `168h` | observed-flow validity window |
| `--taint-max-paths` | `3` | evidence paths retained per asset |
| `--execution-evidence` | — | runtime execution evidence files/dirs |
| `--mechanism-evidence` | — | signed per-CVE mechanism records |
| `--require-signed-evidence` | `false` | reject unsigned external evidence |
| `--edge-auth-signals` | `off` | optional edge-auth audit/refutation signals; not required for default IAP/OIDC/Cognito exclusion |
| `--vpc-flows-file`, `--host-flows-file` | — | non-k8s collectors (B4) |
| `--evidence-bundle` | — | directory to write the audit bundle (section 8) |

### 6.2 New model fields (`internal/model/model.go`)

```go
// PayloadExposure is the Phase-B result for an asset. Attached alongside Exposure
// (which remains the Phase-A direct-exposure record, unchanged for compatibility).
type PayloadExposure struct {
    Tainted   bool        `json:"tainted"`
    Paths     []TaintPath `json:"paths,omitempty"`
    ExtraPaths int        `json:"extraPaths,omitempty"` // paths beyond --taint-max-paths
    Sources   []string    `json:"sources,omitempty"`    // "networkpolicy","hubble","mesh","declared","default-allow"
    SnapshotAt time.Time  `json:"snapshotAt,omitempty"`
    Evidence  []string    `json:"evidence,omitempty"`
}

type TaintPath struct {
    Entry string          `json:"entry"`           // e.g. "frontend (Ingress web-public)"
    Hops  []TaintHop      `json:"hops"`
}

type TaintHop struct {
    To          string   `json:"to"`               // "prod/Deployment/api"
    EdgeSource  string   `json:"edgeSource"`       // observed|permitted|declared
    Port        int32    `json:"port,omitempty"`
    Formats     []string `json:"formats,omitempty"`
    EvidenceRef string   `json:"evidenceRef,omitempty"` // path within evidence bundle
    FirstSeen   string   `json:"firstSeen,omitempty"`
    LastSeen    string   `json:"lastSeen,omitempty"`
}

// ReachabilityDecision is the per-(finding, asset) v2 verdict. Attached to
// Affected (findings view) and to per-resource findings (resources view).
type ReachabilityDecision struct {
    IRV            bool           `json:"irv"`
    Model          string         `json:"model"`           // "v2"
    Phase          string         `json:"phase"`           // "exposure:direct"|"exposure:transitive"|"exposure"(NIRV)|"execution"|"surface"|"mechanism"
    FiltersApplied []FilterResult `json:"filtersApplied,omitempty"`
    Evidence       []string       `json:"evidence,omitempty"`
}

type FilterResult struct {
    Name          string   `json:"name"`            // "execution"|"surface"|"mechanism"
    Outcome       string   `json:"outcome"`         // "passed-default"|"passed-evidence"|"excluded"|"skipped"
    Version       string   `json:"version,omitempty"` // classifier/table version
    VEXJustification string `json:"vexJustification,omitempty"`
    Evidence      []string `json:"evidence,omitempty"`
}
```

`Exposure` (Phase A) is unchanged. `Affected` gains `PayloadExposure *PayloadExposure`
and `Reachability *ReachabilityDecision`. `Summary` gains
`PayloadExposed int` beside `InternetAccessible`.

### 6.3 VEX / CycloneDX export

Extends the handoff doc's `vdr:*` property scheme (all handoff properties retained):

| Property | Values |
|---|---|
| `vdr:reachabilityModel` | `v1` / `v2` |
| `vdr:assetDirectlyExposed` | `true/false` (= E(a)) |
| `vdr:assetPayloadExposed` | `true/false` (= T(a)) |
| `vdr:taintPath` | first path, rendered as the evidence-line string |
| `vdr:findingInternetReachable` | final IRV(v,a) |
| `vdr:reachabilityPhase` | `ReachabilityDecision.Phase` |
| `vdr:filter:execution` / `:surface` / `:mechanism` | filter outcome strings |
| `vdr:mechanismClass` | `payload_carried` / `peer_bound` / `unknown` |
| `vdr:classifierVersion` / `vdr:mechanismTableVersion` | versions |
| `vdr:evidenceBundleHash` | sha256 of the bundle manifest |

VEX `analysis` mapping rules (conservative, per handoff guidance):
- C3 exclusions with complete-coverage evidence → `analysis.state: not_affected`,
  `justification: vulnerable_code_not_in_execute_path` (or
  `vulnerable_code_not_present`). These are the **only** decisions strong enough for
  `not_affected`.
- C1/C2 exclusions and Phase-B NIRV → keep `analysis.state: exploitable` (the
  component *is* affected; it just isn't internet-reachable), detail explains the NIRV
  determination; deadline column moves to `LEV+NIRV`. Never emit `not_affected` from a
  reachability-only argument.

### 6.4 Report surfaces

- JSON first (all fields above). Table adds one column: `Reach` with values
  `direct` / `transitive` / `nirv` / `nirv(filtered:mechanism)` etc.
- HTML: reuse the exposure filter control; add taint-path rendering to the finding
  detail hover. Keep scope small (handoff doc's caution stands).

---

## 7. Evidence and audit (`--evidence-bundle <dir>`)

Every exclusion must carry machine-checkable evidence refs. Bundle layout:

```text
bundle/
  manifest.json            # {generatedAt, pluginVersion, model:"v2", inputHashes{}, snapshotAt}
  inputs/
    k8s/                   # verbatim JSON of every collected object, one file per GVR
      networkpolicies.json
      services.json ...
    flows/hubble-*.jsonl   # archived copies of --flows-file inputs
    mesh/metrics-*.txt
    edge-auth/*.json       # optional --edge-auth-signals snapshots, when supplied
    evidence/              # archived execution/mechanism evidence files (+signatures)
  graph/
    nodes.json  edges.json tainted.json     # deterministic serialization, sorted keys
  decisions/
    findings.jsonl         # one ReachabilityDecision per (finding, asset), with
                           # evidenceRef paths resolving into inputs/ and graph/
```

`manifest.json.inputHashes` is a map of every file to its sha256; the manifest hash is
emitted in the report (`vdr:evidenceBundleHash`) so a report can be tied to its bundle.
An auditor (or the future `vdr replay`) can re-derive every decision from the bundle
alone. Bundles contain no secrets by construction (collectors never write Secret
objects into the bundle).

---

## 8. Implementation backlog

Ordered milestones. Sizing: S ≈ ≤2 days, M ≈ ≤1 week, L ≈ 2–3 weeks.

| # | Milestone | Size | Acceptance criteria |
|---|---|---|---|
| **B1** | NetworkPolicy collection | **S** | `networking.k8s.io/v1` NetworkPolicies listed per namespace in `exposure_objects.go`; RBAC docs updated; objects archived to evidence bundle; presence of Cilium/Calico policy CRDs detected and flagged (not yet evaluated); no behavior change to v1 output |
| **B2** | Taint graph + wholesale NIRV pruning | **L** | Graph built from tier-2 (NetworkPolicy allow-graph, default-allow correct) + tier-3 (Service topology, declared edges); BFS taint from Phase-A entry points; `PayloadExposure` emitted per asset; `--reachability-model=v2\|v2-report-only` flag; with no policy data, T=true for all assets (golden test); unreached assets NIRV with graph-stats evidence line; deterministic output verified by repeat-run hash test |
| **C1** | CWE mechanism partition | **M** | Curated CWE table shipped + versioned; Vulnrichment/NVD CWE ingestion; PEER_BOUND exclusion only when E(a)=false; XSS/ReDoS/zip-bomb regression tests pinned PAYLOAD_CARRIED; signed mechanism-evidence override honored with floor rule; `FilterResult` in JSON |
| **C2** | Surface matching | **M** | Handoff-doc classifier implemented (curated token/CPE rules, versioned); D(a) from route metadata + tainted-edge formats; wildcard-on-any-unknown-edge rule; high-confidence-only exclusions; no port-only downgrades (test: Tier-4 evidence never excludes) |
| **B3** | Hubble/flow ingestion | **M** | `--flows-file` jsonpb parsing; reply-drop, staleness window, workload attribution incl. hostNetwork node-IP mapping; edges enrich formats (feeds C2) and recency evidence; observed-absence never prunes (test); mesh metrics file ingestion |
| **C3** | Execution evidence | **M** | Evidence-file format published; coverage + window checks; VEX `not_affected` emitted only for complete-coverage exclusions; signature verification behind `--require-signed-evidence` |
| **A1** | Edge-auth pre-auth boundary model | **M** | GKE IAP v1 behavior preserved; ALB OIDC/Cognito and Verified Access with pre-auth rejection exclude direct IRV by default; no cloud discovery required; customer-auth/refutation path (`vdr.fedramp.io/edge-auth-role: customer-auth`, `edge-auth-population: open`, `edge-auth-assertion-validated: "false"`) honored; optional signal snapshots are audit/refutation only; unified IAP/OIDC/Cognito/Verified Access decision table |
| **A2** | hostNetwork/hostPort + DaemonSet | **S** | Advisory detection + label; DaemonSet fixture; Phase-B node integration |
| **B4** | Non-k8s collectors (VPC flows, host telemetry, Cloud Run edges) | **L** | File-based ingestion for each; Cloud Run invoker-IAM edges; bridging into one graph |
| **B5** | Evidence bundle `vdr replay` | **M** | Decisions reproducible from bundle alone; manifest-hash in report |

Suggested delivery order: B1 → B2 → C1 → C2 → B3 → C3 → A1 → A2 → B4 → B5. B1+B2
alone already fix the FRD-IRV false negative (transitive IRV) and deliver sound
policy-based NIRV pruning; C1 is the highest-value exclusion filter per unit effort.

## 9. Migration notes

1. Default stays `v1`; nothing changes for existing users until they opt in.
2. `v2-report-only` is the recommended first step: deadlines unchanged, decisions
   visible for diffing.
3. **Expect IRV counts to rise** when switching to v2 in clusters without
   NetworkPolicies or flow data (section 4.6). That is the correct FRD-IRV reading,
   not a regression. Communicate this prominently in release notes.
4. **Edge-auth behavior change** (A1): GKE IAP remains an exclusion as in v1. AWS ALB
   OIDC/Cognito and Verified Access now follow the same pre-auth-boundary rule under
   v2: when they reject unauthenticated traffic before backend processing, the route is
   excluded from direct IRV by default. Operators only need metadata when they want to
   refute that default for customer-auth/public-enrollment routes or known bypasses.

## 10. Non-goals

Carried over from the handoff doc and reaffirmed:

- No mutation of vendor/scanner base CVSS vectors (an *additional* environmental
  rating with `MAV` remains allowed per the handoff VEX guidance).
- No remediation-timeline downgrades from port-number heuristics alone.
- No runtime LLM/agentic analysis inside the CLI; agentic output enters only as
  signed, archived evidence records under the deterministic override rules of 5.3.
- No probabilistic scoring: every term in IRV(v,a) is a boolean backed by evidence;
  there are no confidence-weighted scores in the decision path (classifier
  "confidence" tiers gate whether evidence is *usable*, never scale an output).
- No operator flag to lower evidence thresholds.
- No modeling of response-channel (server→client) taint in v2 (Q5).

## 11. Open questions

- **Q1 — Namespace-scoped scans vs. cluster-wide graph.** `--namespace` runs see only
  part of the graph; a tainted path may enter through a namespace not scanned. Current
  position: in v2, a namespaced scan computes T(a) with tier-3 default-allow unless
  policies prove isolation of the scanned namespaces from the rest of the cluster
  (i.e. partial visibility degrades conservatively). Needs validation against real
  RBAC-restricted deployments.
- **Q2 — Entry points from NetworkPolicy ipBlock 0.0.0.0/0.** Section 4.2 treats a
  public-CIDR ingress rule as an entry-point *candidate* only when a public route also
  exists, to avoid marking every default-allow pod as directly exposed. Is there a
  cluster topology (e.g. nodes with public IPs and no NAT) where policy-only public
  ingress should count as E(a)? Leaning: keep as candidate + advisory evidence.
- **Q3 — Edge-auth customer-auth refutation signals.** AWS Cognito and ALB OIDC
  boundaries do not require user-pool or IdP inspection to exclude direct IRV: the
  local ALB auth configuration is enough when unauthenticated requests are rejected
  before the backend. A possible future question — noted here, not a commitment — is
  whether any provider-side signal is worth adding later to automatically refute the
  default for known customer-auth/public-enrollment routes. Any such signal
  would have to be one that cannot mistake an open enrollment population for a
  restricted one.
- **Q4 — Operator-declared negative edges.** Teams without NetworkPolicies will ask
  for a "these workloads don't talk" annotation. Current position: refused (unenforced
  claims aren't evidence; the NetworkPolicy *is* the attestation and is enforced).
  Revisit only with strong field pressure, and if ever added it must be a distinct,
  loudly-labeled evidence class.
- **Q5 — Response-channel taint.** A vulnerable HTTP *client* library in an internal
  worker that fetches attacker-influenced URLs (via SSRF or by processing
  internet-sourced job data) receives internet payloads over connections it
  originates. v2's payload-direction edges catch the common case (job data flowed in
  through tainted edges) but not egress-to-internet-origin responses. Candidate for
  v3; noting so PEER_BOUND exclusions are worded to not overclaim (they already only
  fire on listener-position flaws).
- **Q6 — Finding-level PAIN interplay.** In the findings view, PAIN/deadline is the
  worst across affected assets; with per-(v,a) IRV the "worst" now varies by asset in
  two dimensions (PAIN and column). Current `Score()` is already per-asset, and the
  findings view already takes the most urgent result, so no change should be needed —
  flagged for explicit test coverage in B2.
