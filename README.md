# vdr

`vdr` is a Trivy plugin for vulnerability detection and response workflows. It can inventory Kubernetes workloads from the current Kubernetes context or Google Cloud Run services and jobs from a Google Cloud project, scan each unique full image reference once, and report findings back against the resources and containers that use each image.

The Kubernetes source collects workload image inventory, scans each unique image with Trivy, enriches CVEs with EPSS and CISA Vulnrichment data, analyzes public ingress/gateway exposure, and emits JSON, table, and optional standalone HTML reports. The Cloud Run source collects every container image used by Cloud Run services and jobs in the selected regions, analyzes service reachability through Cloud Run IAM/ingress and external load balancers/IAP, and emits the same report shapes.

## Features

- Trivy plugin entrypoint named `vdr`.
- Kubernetes source subcommand named `k8s`.
- Google Cloud Run source subcommand named `cloudrun`.
- Workload inventory from Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs, plus standalone Pods. Pods managed by a collected controller are skipped to avoid double-counting; pods owned by other controllers (e.g. operators/CRDs) are still inventoried.
- Reserved future source subcommands named `ecs` and `image`.
- JSON and table output mode flags.
- Finding-centric and resource-centric view flags.
- Per-finding FedRAMP Rev5 VDR **PAIN** (Potential Agency Impact, N1–N5) and **VDR-TFR-PVR** remediation deadline, driven by an asset-archetype classification (see [PAIN scoring and remediation](#pain-scoring-and-remediation)).
- Optional standalone HTML report with per-finding PAIN and FedRAMP remediation deadlines, plus filter controls for severity (multi-select), PAIN, namespace, internet exposure, automatable, exploitation status, EPSS score, technical impact, and remediation deadline (multi-select).
- Namespace selection, all-namespace scanning, image source, parallel scanning, cache cleanup, timeout, severity, EPSS, enrichment, exposure, and debug flags.
- Automatic private-registry authentication from Kubernetes `imagePullSecrets`, Google Artifact Registry/GCR (via `gcloud`), and AWS ECR (via the `aws` CLI).
- Resilient scanning: a single image that fails to pull or scan is reported as a warning and the run continues, producing a partial (still enriched) report.
- INFO-level progress logging to stderr by default.
- Shared JSON model for inventory, findings, EPSS, CISA Vulnrichment, exposure, access protection, reports, and summaries.

## Usage

```sh
trivy vdr --help
trivy vdr k8s --help
trivy vdr k8s --namespace default --format json
trivy vdr k8s --all-namespaces --min-severity HIGH --min-epss 0.5
trivy vdr k8s --view resources --output vdr-k8s.json
trivy vdr k8s --image-src remote --parallel-scans 5
trivy vdr k8s --skip-enrichment --skip-exposure --debug
trivy vdr k8s --refresh-enrichment
trivy vdr k8s --skip-registry-auth
trivy vdr k8s --no-gcloud-auth --no-ecr-auth
trivy vdr k8s --vex-oci-registries registry.example.com,ghcr.io/acme
trivy vdr k8s --quiet
trivy vdr k8s --namespace default --output vdr-k8s.json --html-output vdr-k8s.html
trivy vdr k8s --html-output vdr-k8s.html --html-template custom-template.html
trivy vdr k8s --all-namespaces --scoring-config vdr-scoring.yaml
trivy vdr cloudrun --project my-gcp-project --region us-east4 --region us-central1 --output vdr-cloudrun.json
trivy vdr cloudrun --project my-gcp-project --region us-east4 --view resources --html-output vdr-cloudrun.html
```

Future source commands are reserved but not implemented yet: `trivy vdr ecs` and `trivy vdr image`.

## Required permissions

`vdr` uses read-only access. Registry authentication and exposure analysis add optional reads; when those optional reads are denied, the run records warnings and continues where possible.

### Kubernetes native RBAC

For Kubernetes inventory in selected namespaces:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vdr-read
rules:
  - apiGroups: [""]
    resources: ["namespaces", "pods", "services", "configmaps"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets"]
    verbs: ["list"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "ingressclasses"]
    verbs: ["list"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways", "httproutes", "grpcroutes", "referencegrants"]
    verbs: ["list"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["tcproutes", "tlsroutes"]
    verbs: ["list"]
  - apiGroups: ["networking.gke.io"]
    resources: ["gcpbackendpolicies"]
    verbs: ["list"]
  - apiGroups: ["cloud.google.com"]
    resources: ["backendconfigs"]
    verbs: ["list"]
  - apiGroups: ["elbv2.k8s.aws"]
    resources: ["ingressclassparams"]
    verbs: ["list"]
  - apiGroups: ["gateway.k8s.aws"]
    resources: ["loadbalancerconfigurations"]
    verbs: ["list"]
```

Notes:

- `secrets/get` is only needed when registry auth from Kubernetes `imagePullSecrets` is enabled. Use `--skip-registry-auth` to avoid reading Secrets.
- `configmaps/get` is used for the optional `kube-system/vdr-fedramp` scoring ConfigMap.
- Exposure resources are optional. If `--skip-exposure` is set, `services`, `ingresses`, `ingressclasses`, Gateway API resources, GKE BackendConfig/GCPBackendPolicy, and AWS ALB/Gateway custom resources are not needed for exposure analysis.
- If you never use AWS ALB/Gateway resources, the `elbv2.k8s.aws` and `gateway.k8s.aws` rules can be omitted. If you never use GKE ingress/gateway IAP metadata, the `cloud.google.com/backendconfigs` and `networking.gke.io/gcpbackendpolicies` rules can be omitted.

### GKE IAM alternative

When accessing GKE through Google IAM instead of a Kubernetes service account, the caller still needs Kubernetes API authorization after authentication. The broad managed role `roles/container.developer` is usually enough to read Kubernetes API objects through GKE credentials, but a narrower setup is preferred:

- Google IAM: `roles/container.clusterViewer` on the project or cluster, so the caller can discover and authenticate to the cluster.
- Kubernetes RBAC: bind the native `ClusterRole` above to the Google principal or Google group.

### Cloud Run IAM

For Cloud Run inventory and exposure analysis, grant a custom Google Cloud IAM role with these permissions on the scanned project:

```text
run.services.list
run.services.getIamPolicy
run.jobs.list
resourcemanager.projects.get
compute.regions.list
compute.globalForwardingRules.list
compute.forwardingRules.list
compute.targetHttpProxies.get
compute.targetHttpsProxies.get
compute.regionTargetHttpProxies.get
compute.regionTargetHttpsProxies.get
compute.urlMaps.get
compute.regionUrlMaps.get
compute.backendServices.get
compute.regionBackendServices.get
compute.regionNetworkEndpointGroups.get
```

Notes:

- `run.services.getIamPolicy` is required to detect `allUsers` with `roles/run.invoker` on services whose ingress is `all`.
- `resourcemanager.projects.get` is required to read project labels used as Cloud Run PAIN scoring defaults. Resource-level Cloud Run labels override project labels.
- The Compute permissions are required only for services whose ingress is `internal-and-cloud-load-balancing`; they let `vdr` resolve public forwarding rules to URL maps, backend services, serverless NEGs, and backend IAP state.
- Cloud Run jobs are always treated as not internet reachable, but `run.jobs.list` is required to inventory and scan their images.
- For private Google Artifact Registry/GCR images, the local `gcloud` identity used for `gcloud auth print-access-token` must also be able to read those images, for example with `roles/artifactregistry.reader` on the relevant repositories or project.

## Enrichment cache

EPSS and CISA Vulnrichment data are cached under `--cache-dir`. EPSS cache files are refreshed after 24 hours. Vulnrichment cache files are refreshed after 7 days.

Use `--refresh-enrichment` to force EPSS and Vulnrichment refresh attempts even when cached files are still fresh. If a forced refresh fails and an existing cache file is still readable and valid, `vdr` keeps and uses the cached data.

## Private registry authentication

Before scanning, `vdr` assembles Docker credentials so Trivy can pull private images, and hands them to Trivy through a temporary `DOCKER_CONFIG` directory (written owner-only and removed when the run ends). Credentials come from three sources:

- **Kubernetes `imagePullSecrets`** — the `kubernetes.io/dockerconfigjson` (and legacy `kubernetes.io/dockercfg`) Secrets referenced by the scanned workloads' pod specs.
- **Google Artifact Registry / GCR** — for `*.pkg.dev`, `gcr.io`, and `*.gcr.io` images, `vdr` runs `gcloud auth print-access-token` once.
- **AWS ECR** — for `*.dkr.ecr.<region>.amazonaws.com` images, `vdr` runs `aws ecr get-login-password --region <region>` once per registry.

A cluster secret always wins over a cloud-CLI token for the same registry host. Tokens are never logged. Each source degrades gracefully: a missing/unauthenticated `gcloud` or `aws` CLI, an unreadable Secret, or an RBAC denial produces a warning, not a failure (affected images then surface as per-image scan warnings).

Flags:

- `--skip-registry-auth` disables all automatic authentication.
- `--no-gcloud-auth` skips the `gcloud` token for GAR/GCR.
- `--no-ecr-auth` skips the `aws` token for ECR.

This adds one Kubernetes RBAC requirement beyond inventory collection: `get` on `secrets` in the scanned namespaces. For Cloud Run, no Kubernetes Secrets are read. The optional `gcloud` and `aws` CLIs must be installed and authenticated on the machine running the plugin.

## VEX attestations

`vdr` can opt into Trivy's experimental OCI VEX attestation discovery for trusted registries:

```sh
trivy vdr k8s --vex-oci-registries registry.example.com,ghcr.io/acme
```

The allowlist accepts registry hosts (`registry.example.com`) or repository prefixes (`ghcr.io/acme`). Matching images are scanned with `trivy image --vex oci --show-suppressed`; other images are scanned without OCI VEX. Suppressed VEX findings are not silently dropped: reports keep them in `suppressedFindings` with the VEX status, justification, source, and informational `wouldHaveBeenPain` / `wouldHaveBeenRemediation` values. They are excluded from the active finding count and remediation queue.

## Logging

Progress is logged to stderr (the report is written to stdout or `--output`, so logs never contaminate it). The default level is INFO and announces each phase: inventory collection, registry auth, scanning, EPSS/vulnrichment fetch-vs-cache, and report output. Use `--quiet` for warnings and errors only, or `--debug` for verbose diagnostics.

## Image scanning and Trivy cache cleanup

`vdr` scans each unique full image reference once and fans findings back out to every Kubernetes resource that uses that image. Scan results are returned in deterministic image-reference order, independent of the order in which concurrent scans finish.

Scan defaults:

- `--image-src remote`
- `--parallel-scans 5`
- `--cache-cleanup auto`
- `--cache-min-free-gb 10`
- `--cache-min-free-percent 10`

`vdr` downloads the Trivy vulnerability and Java databases once up front (`trivy image --download-db-only` / `--download-java-db-only`) and then scans each image with `trivy image --image-src <value> --skip-db-update --skip-java-db-update --skip-version-check --format json --scanners vuln --timeout <timeout> <image>`. The default `--image-src remote` pulls each image from its registry.

**Safe parallel scanning.** Trivy's scan cache (fanal) is a BoltDB that takes an exclusive lock per scan, so multiple `trivy image` processes cannot share one cache directory — doing so causes lock timeouts, and downloading a database mid-scan corrupts a shared cache (SIGSEGV). `vdr` avoids both: it pre-downloads the databases, then for parallel runs gives each worker its own cache directory with the databases **hardlinked** from the shared cache (no extra disk) and a private scan cache. This makes `--parallel-scans` > 1 safe and fast. If a database is ever found corrupted, `vdr` clears and re-downloads it once automatically (self-heal).

A single image that cannot be pulled or scanned does not abort the run: the failure is logged inline and recorded as a warning in the report, the remaining images are still scanned and enriched, and a summary of failed images is printed at the end. If any image fails, `vdr` exits with a non-zero status after writing the report.

Cache cleanup runs once after the image scan phase completes:

- `--cache-cleanup never` skips cleanup.
- `--cache-cleanup always` runs `trivy clean --scan-cache`.
- `--cache-cleanup auto` checks free disk space for the configured Trivy cache directory, or the nearest existing parent directory, and runs `trivy clean --scan-cache` when free space is below either `--cache-min-free-gb` or `--cache-min-free-percent`.

If cleanup fails after an image scan succeeds, the scan result is kept and a warning is recorded for later reporting.

## Reporting

JSON output defaults to a finding-centric report. Each finding includes `affected` — a list of `{resource, exposure}` entries — so a deduplicated image scan can still be traced back to every Kubernetes resource and container using that image, along with that resource's internet exposure.

Use `--view resources` for resource-centric JSON or table output. Resource reports include the matching container image inventory, container security metadata, resource labels, exposure state, and findings scoped to that resource/container.

Use `--html-output <path>` to write a standalone HTML report. The default HTML template is embedded in the plugin and requires no remote CDN assets. It supports light/dark mode (following the OS preference, with a toggle that is remembered), a multi-select severity filter, a Trivy fix-status filter (including `will_not_fix`), a PAIN filter, a multi-select remediation-deadline filter, and click-to-sort on every column (severity sorts by rank, EPSS numerically).

Each finding shows its **PAIN** tier and a FedRAMP **Remediation** deadline (see [PAIN scoring and remediation](#pain-scoring-and-remediation)). Automatable, Exploitation, and Technical impact from CISA Vulnrichment are also shown for context; CVSS-derived Automatable and Technical impact values are rendered in italics with a `†` marker so they are distinguishable from authoritative Vulnrichment values. Hover any value or column header for an in-report explanation. Use `--html-template <path>` to override the template with a local Go `html/template`; the template receives `.Report` and `.ReportJSON`.

## PAIN scoring and remediation

Every finding is scored against the FedRAMP Rev5 VDR model: a **PAIN** rating (Potential Agency Impact, N1–N5) and a **VDR-TFR-PVR** remediation deadline. PAIN and the deadline appear in the JSON (`pain`, `remediation`), the table, and the HTML report.

### PAIN = f(severity, scope)

- **Severity** is the CVE's CVSS impact vector (which of Confidentiality/Integrity/Availability it touches) re-weighted by the asset's `CR/IR/AR` requirements, which come from its **asset archetype**. CISA Vulnrichment **technical impact** refines this as a *floor*: when `total`, each in-scope CVSS dimension is raised to High before weighting; it never invents impact on a dimension the CVE does not touch, and `partial`/absent leaves the CVSS vector unchanged. The weighted impact maps to a word — Minimal → N1, Narrow → N2, Disruptive, Debilitating. The scalar cut points for those words are calibratable via `wordThresholds` in a governed `--scoring-config` file (defaults: Narrow 0.25, Disruptive 0.55, Debilitating 0.80). They are deliberately **not** read from the in-cluster ConfigMap, so the calibration can't be changed by ad-hoc cluster edits.
- **Scope** is whether the asset serves one agency or more than one. Disruptive → N3 (single) / N4 (multi); Debilitating → N4 (single) / N5 (multi).

### Asset archetypes

An archetype assigns the `CR/IR/AR` requirements (e.g. `identity-secrets` and `data-backbone` are H/H/H, `app-tier` is M/M/H, `platform-foundation` — DNS/NTP/discovery, metadata-only — is L/H/H, `internal-tooling` is L/L/L). It is resolved most-specific-first:

```
workload label vdr.fedramp.io/asset-archetype
  → namespace label
  → name rule   (cluster ConfigMap; first match wins)
  → namespace rule (cluster ConfigMap; first match wins)
  → built-in "unclassified" cluster-default (H/H/H — noisy N4, surfaces for classification)
```

Tag workloads you control with `vdr.fedramp.io/asset-archetype: <archetype>`. Cloud-managed, shared-responsibility components (`kube-system`, `gke-managed-*`, `amazon-cloudwatch`, `azure-*`, …) that cannot carry the label are classified by name/namespace rules in the ConfigMap instead.

### Remediation deadline

```
deadline = matrix[ Certification Class ][ PAIN ][ column ]
  column = LEV+IRV | LEV+NIRV | NLEV
  LEV (likely exploitable) = EPSS >= 0.70  OR  exploitation = active
  IRV (internet reachable) = the affected resource is internet-reachable
```

So the same CVE remediates faster on a higher-PAIN, internet-reachable, actively exploited asset. The EPSS LEV cutoff (0.70) is built into the plugin. PAIN-1 findings have no FedRAMP deadline. In the findings view the finding-level PAIN/deadline is the most urgent across all affected resources.

### Cluster configuration

The provider **Certification Class** (A/B/C/D), the **agency scope**, and the archetype **rules** are read from an in-cluster ConfigMap named **`vdr-fedramp`** in **`kube-system`** — no flag required. It carries the scalar keys `class` and `multiAgency`, plus an embedded `scoring.yaml` that is deep-merged over the plugin's built-in rubric (catalog, algorithm, EPSS threshold, and the `unclassified` default). Namespace labels (`vdr.fedramp.io/class`, `vdr.fedramp.io/multi-agency`) and workload labels override the ConfigMap (most specific wins). When the ConfigMap is missing or unreadable the plugin **warns** and falls back to built-in defaults (Class B, single-agency, no tenant rules).

See [`examples/configmaps/`](examples/configmaps/) for starter GKE, EKS, and AKS ConfigMaps. The optional `--scoring-config <file>` flag layers a local YAML/JSON config under the ConfigMap for testing or non-cluster use.

## Exposure rules

Exposure analysis is intentionally conservative:

- Cloud Run jobs are never marked internet reachable.
- Cloud Run services are public when ingress is `all` and the service IAM policy grants `allUsers` `roles/run.invoker`.
- Cloud Run services with `internal-and-cloud-load-balancing` ingress are public only when an external global or regional load balancer routes to the service's serverless NEG and the backend service does not have IAP enabled.
- GKE Gateway is public only for known external GKE Gateway classes.
- GKE Gateway backends protected by `GCPBackendPolicy.spec.default.iap.enabled=true` are not marked internet accessible.
- GKE Ingress is public for `gce` and not public for `gce-internal`.
- GKE Ingress BackendConfig IAP is resolved through the Service port selected by the Ingress backend. Per-port BackendConfig mappings override `default`.
- AWS ALB Ingress and Gateway are public only when the ALB scheme/load balancer configuration is internet-facing.
- AWS ALB `oidc` and `cognito` auth are recorded as AWS access protection. They are not reported as GCP IAP.
- Gateway cross-namespace backend references require a matching `ReferenceGrant`.
- An Ingress with no load balancer provisioned in its status is treated as not serving traffic and is excluded. When a Gateway and an unprovisioned Ingress both target the same Service, the Gateway's exposure applies.
- A `Service` of type `LoadBalancer` with a provisioned external address (and no internal-scheme annotation — GKE `networking.gke.io/load-balancer-type: Internal`, AWS `aws-load-balancer-scheme: internal`, Azure `azure-load-balancer-internal: "true"`) marks the pods it selects internet-reachable. This is how **ingress/gateway controller pods** (Traefik, ingress-nginx, Envoy) — which the load balancer forwards to directly — are detected, structurally, without naming the controller. The AWS ALB controller has no in-cluster data-path pod, so it is correctly not flagged.
- A `Service` of type `NodePort` is **not** counted as internet-reachable by default, because node-IP reachability depends on the nodes having public IPs and permissive firewall rules — which the cluster can't determine. Set the label `vdr.fedramp.io/internet-reachable-nodePort: "true"` (or `"false"`) on the Service to classify it; when the label is absent the finding shows `nodeport` and its tooltip points to the label. (`true` makes it count toward IRV and the remediation deadline.)

Normal init containers do not inherit internet exposure. Sidecar-style init containers inherit exposure only when their container restart policy is `Always`.

## Known limits

The Kubernetes source currently supports Kubernetes workload image inventory, Trivy image vulnerability scans, EPSS/Vulnrichment enrichment, GKE exposure metadata, and AWS ALB exposure metadata. The Cloud Run source supports Cloud Run services and jobs, Cloud Run IAM ingress checks, and external Google Cloud load balancer/IAP checks for serverless NEG backends. The `ecs` and `image` sources are reserved for future implementation.

Run the standalone binary during development:

```sh
go run ./cmd/vdr --help
go run ./cmd/vdr k8s --help
go run ./cmd/vdr cloudrun --help
go build -o vdr ./cmd/vdr
```

## Development

```sh
make test
make build
make install-local
```

To build and run against your current Kubernetes context in one step (writes `output.json` and `output.html`):

```sh
scripts/local-test.sh                     # all namespaces
scripts/local-test.sh --namespace default # single namespace
scripts/local-test.sh --debug             # verbose progress logs
```

The script runs the freshly built binary directly, so it picks up local changes on every run. Trivy must be installed; `gcloud`/`aws` are optional for registry auth.
