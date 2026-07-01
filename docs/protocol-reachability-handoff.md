# Protocol-Aware Reachability Handoff

This handoff captures the current design direction for using route protocol metadata and CVE protocol classification to decide finding-level internet reachability. It is intentionally conservative: the default is internet-known-reachable (IKR/IRV) when the asset is internet-reachable and the vulnerability is `AV:N`; protocol evidence is used only to downgrade to not-internet-known-reachable (NIKR/NIRV) when there is positive evidence of a mismatch.

## Current State

PR #6, `[codex] add route protocol metadata`, adds machine-readable `exposure.routes` metadata in JSON output. It does not yet classify CVE protocols and does not yet change remediation timeline selection.

Added route metadata fields:

- `frontendProtocol`
- `backendProtocol`
- `backendProtocolVersion`
- `backendTls`
- `alpn`
- `alpnPolicy`

Current route protocol sources:

- AWS ALB Ingress: `alb.ingress.kubernetes.io/backend-protocol`, `alb.ingress.kubernetes.io/backend-protocol-version`, `listen-ports`, and certificate hints.
- AWS Gateway: `gateway.k8s.aws` `TargetGroupConfiguration.spec.protocol` and `spec.protocolVersion`.
- AWS NLB Service: `service.beta.kubernetes.io/aws-load-balancer-alpn-policy`.
- GKE Ingress: `cloud.google.com/app-protocols` when the referenced Service port is resolvable.
- Gateway route kind: `GRPCRoute` contributes `GRPC` / `h2` route semantics.

RBAC was updated to collect `gateway.k8s.aws/targetgroupconfigurations`.

## Correct Reachability Policy

The partner paper frames internet reachability as a finding-level intersection:

```text
IRV(v, a) = E(a) intersects X(v)
```

Where:

- `E(a)` is the exposed surface delivered to the vulnerable component.
- `X(v)` is the exploit-required surface for the vulnerability.

Unknown required fields are wildcards, not blockers. That means missing protocol evidence must not make a finding look safer.

Operational policy:

```text
If asset is not internet-reachable:
  finding is NIRV

If asset is internet-reachable and CVSS AV is not N:
  finding is NIRV

If asset is internet-reachable and CVSS AV:N:
  default finding is IRV

Downgrade AV:N finding to NIRV only when there is positive evidence that:
  the vulnerability requires protocol/version X
  AND the exposed backend surface does not deliver X to the vulnerable component
```

This corrects an earlier framing. The rule is not "only high-confidence protocol matches get IRV." The rule is "IRV is the fail-safe default for internet-reachable AV:N findings; only high-confidence mismatches earn NIRV."

## Backend Protocol Evidence

The next implementation step is to improve backend protocol determination, because NIRV downgrades depend on proving what protocol/version reaches the vulnerable component.

Recommended evidence tiers:

### Tier 1: Explicit Provider Config

Use for NIRV downgrades.

Examples:

- AWS ALB `backend-protocol=HTTP|HTTPS`
- AWS ALB `backend-protocol-version=HTTP1|HTTP2|GRPC`
- AWS Gateway `TargetGroupConfiguration.protocol`
- AWS Gateway `TargetGroupConfiguration.protocolVersion`
- GKE Ingress `cloud.google.com/app-protocols`

### Tier 2: Explicit Kubernetes Protocol Fields

Use for NIRV downgrades when route-to-Service mapping is clear.

Examples:

- `ServicePort.appProtocol`
- `GRPCRoute` to a backend Service
- `HTTPRoute` to a backend Service, for HTTP semantics

### Tier 3a: Strong Kubernetes Convention

Can be high confidence when multiple independent signals agree.

Examples:

- Service port name `ssh` and port `22` behind a `TCPRoute`.
- Service port name `postgres` and port `5432` behind a `TCPRoute` or LoadBalancer Service.
- Service port name `grpc` and a `GRPCRoute`.
- Service port name `http` and port `80` behind an `HTTPRoute`.
- Service port name `https` and port `443` with explicit backend TLS or HTTPS provider config.

Tier 3a can support NIRV downgrades only when at least two independent signals agree, such as route kind plus Service port name, or Service port name plus standard port.

### Tier 3b: Weak Kubernetes Convention

Metadata/advisory only. Do not use alone for NIRV downgrades.

Examples:

- Service port name `web` on port `8080`.
- Service port name `api` on port `443`.
- App label hints without matching port or route evidence.

### Tier 4: Port-Only Heuristics

Never use alone for NIRV downgrades.

Examples:

- `22` -> likely SSH
- `5432` -> likely PostgreSQL
- `6379` -> likely Redis
- `3306` -> likely MySQL
- `3389` -> likely RDP

These are useful for metadata and investigation, but not strong enough alone to relax a remediation timeline.

## CVE Protocol Classification

This is not implemented yet. The proposed classifier should be deterministic and evidence-driven, using title, description, and CVSS vector fields.

Classifier input:

- CVE ID
- title
- description
- CVSS vector

Classifier output:

```json
{
  "attackVector": "network",
  "requiredProtocols": ["ssh"],
  "requiredAlpn": [],
  "confidence": "high",
  "evidence": ["matched explicit token: OpenSSH server"],
  "classifierVersion": "YYYY-MM-DD"
}
```

Recommended confidence model:

- High: explicit protocol or ALPN token in CVE text, or a strong product/protocol phrase such as `OpenSSH server`, `HTTP/2`, `gRPC`, `Redis RESP`, `PostgreSQL server`.
- Medium: product-to-protocol inference without explicit wire protocol wording, such as `Apache ZooKeeper` with generic remote attacker language.
- Unknown: generic remote wording such as `crafted packet`, `network request`, or `remote attacker` with no protocol/product evidence.

Important policy:

- Medium and unknown do not downgrade to NIRV.
- Medium can be surfaced as advisory evidence.
- Unknown means wildcard, which preserves IRV when the asset is internet-reachable and the CVE is `AV:N`.

## Timeline Selection

The report should eventually show both the base/scanner timeline and the VDR finding-level reachability timeline. The selected timeline should follow the fail-safe rule.

Example IRV default:

```json
{
  "assetInternetReachable": true,
  "findingInternetReachable": true,
  "reachabilityDecision": "insufficient_evidence_to_downgrade",
  "remediationTrack": "LEV+IRV",
  "reason": "Asset is internet-reachable and CVSS is AV:N; required protocol is unknown and treated as wildcard."
}
```

Example proven downgrade:

```json
{
  "assetInternetReachable": true,
  "findingInternetReachable": false,
  "reachabilityDecision": "proven_protocol_mismatch",
  "remediationTrack": "LEV+NIRV",
  "reason": "CVE requires SSH, but the exposed backend surface delivers HTTP/2 only."
}
```

## VEX / CycloneDX Guidance

CycloneDX is the best fit if VDR metadata needs to be machine-readable in VEX-like output.

Recommended CycloneDX approach:

- Keep the original scanner vulnerability and base CVSS vector.
- Add VDR-specific custom properties on the vulnerability record.
- Optionally add a separate VDR-owned environmental CVSS rating using modified metrics such as `MAV`.
- Avoid `analysis.state: not_affected` unless the intent is to tell VEX consumers to suppress the vulnerability as not affecting the component.

Suggested properties:

- `vdr:assetInternetReachable`
- `vdr:findingInternetReachable`
- `vdr:requiredProtocol`
- `vdr:requiredAlpn`
- `vdr:exposedBackendProtocol`
- `vdr:exposedBackendProtocolVersion`
- `vdr:exposedBackendAlpn`
- `vdr:reachabilityDecision`
- `vdr:remediationTrack`
- `vdr:evidence`

Example:

```json
{
  "id": "CVE-2026-12345",
  "ratings": [
    {
      "method": "CVSSv31",
      "source": { "name": "NVD" },
      "vector": "CVSS:3.1/AV:N/AC:L/..."
    },
    {
      "method": "CVSSv31",
      "source": { "name": "trivy-plugin-vdr" },
      "vector": "CVSS:3.1/AV:N/AC:L/.../MAV:A",
      "justification": "Environmental context: asset is internet-reachable, but the exposed backend protocol does not match the CVE-required protocol."
    }
  ],
  "analysis": {
    "state": "exploitable",
    "detail": "The vulnerable component is present. VDR downgraded this finding to NIRV because the exposed backend protocol does not match the protocol required by the vulnerability."
  },
  "properties": [
    { "name": "vdr:assetInternetReachable", "value": "true" },
    { "name": "vdr:findingInternetReachable", "value": "false" },
    { "name": "vdr:requiredProtocol", "value": "ssh" },
    { "name": "vdr:exposedBackendProtocol", "value": "http" },
    { "name": "vdr:reachabilityDecision", "value": "proven_protocol_mismatch" },
    { "name": "vdr:remediationTrack", "value": "LEV+NIRV" }
  ]
}
```

Other VEX formats:

- CSAF is less friendly for custom machine-readable properties. Use notes, threats, scores, or remediations, or link to the VDR JSON report.
- OpenVEX has free-text fields such as status notes and impact statements, but no CycloneDX-like property bag for this metadata.

## Implementation Backlog

1. Expand backend protocol evidence extraction.
   - Add `ServicePort.appProtocol`.
   - Add Service port name plus standard-port agreement.
   - Add explicit confidence/source/evidence fields to route metadata or a nested backend protocol evidence model.

2. Add deterministic CVE required-surface classifier.
   - Require CVSS parsing for `AV:N`.
   - Match title and description against curated protocol/ALPN rules.
   - Emit evidence and classifier version.
   - Treat unknown protocol/version as wildcard.

3. Add finding-level reachability decision.
   - Default internet-reachable `AV:N` findings to IRV.
   - Downgrade only on high-confidence required-surface mismatch and high-confidence exposed-surface evidence.
   - Preserve evidence explaining why downgrade was or was not allowed.

4. Update reports.
   - JSON first.
   - Table output can show selected track plus short state.
   - HTML output is currently not part of the reachability-only workflow; keep scope controlled.

5. Consider CycloneDX export later.
   - Keep scanner CVSS intact.
   - Add VDR custom properties and optional environmental rating.
   - Avoid overclaiming `not_affected`.

## Non-Goals

- Do not use runtime LLM or agentic CVE analysis in the CLI.
- Do not downgrade remediation timelines based only on port-number heuristics.
- Do not mutate vendor/scanner base CVSS vectors.
- Do not treat unknown protocol as NIRV.
- Do not add an operator flag to lower the evidence threshold.
