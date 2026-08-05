# vdr

`vdr` is a Trivy plugin for vulnerability detection and response workflows. It can inventory Kubernetes workloads from the current Kubernetes context or rendered Helm charts, Google Cloud Run services and jobs from a Google Cloud project, or AWS ECS task definitions from selected regions, scan each unique full image reference once, and report findings back against the resources and containers that use each image. It can also scan standalone image references directly. A separate `k8s-compliance` source runs Trivy's built-in Kubernetes misconfiguration and RBAC rules without changing the vulnerability-report schema.

The Kubernetes source collects workload image inventory, scans each unique image with Trivy, enriches CVEs with EPSS and CISA Vulnrichment data, analyzes public ingress/gateway exposure, and emits JSON, table, and optional standalone HTML reports. The Helm source applies the same pipeline to rendered deployment intent. The Cloud Run source collects every container image used by Cloud Run services and jobs in the selected regions, analyzes service reachability through Cloud Run IAM/ingress and external load balancers/IAP, and emits the same report shapes. The ECS source inventories active task-definition revisions, records runtime and ECS security metadata, resolves ECR and repository credential auth for scans, and conservatively reports reachability only from collected runtime/exposure evidence. Use `--reachability-only` with Kubernetes, Helm, Cloud Run, or ECS to collect internet-reachability metadata without registry auth, Trivy scans, EPSS, or Vulnrichment enrichment. Use `--scan-reachability-only` to run vulnerability scans with internet reachability and asset classification, while omitting EPSS, Vulnrichment, PAIN, and remediation scoring from the final JSON or table output.

## Features

- Trivy plugin entrypoint named `vdr`.
- Kubernetes source subcommand named `k8s`.
- Separate Kubernetes compliance source named `k8s-compliance`, with a dedicated versioned JSON contract and Trivy-style table output by default.
- Google Cloud Run source subcommand named `cloudrun`.
- AWS ECS source subcommand named `ecs`.
- Standalone image source subcommand named `image`.
- Helm source subcommand named `helm`, supporting local charts, configured repository references, direct repository URLs, and OCI charts.
- Ordered Helm values files with Helm-compatible rightmost-file precedence, plus an optional independently rendered Ingress, ingress-controller, or Gateway API chart.
- Workload inventory from Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs, plus standalone Pods. Pods managed by a collected controller are skipped to avoid double-counting; pods owned by other controllers (e.g. operators/CRDs) are still inventoried.
- JSON and table output mode flags.
- Finding-centric and resource-centric view flags.
- Per-finding FedRAMP Rev5 VDR **PAIN** (Potential Agency Impact, N1–N5) and **VDR-TFR-PVR** remediation deadline, driven by an independently dimensional asset security-impact profile (see [PAIN scoring and remediation](#pain-scoring-and-remediation)).
- Optional standalone HTML report with per-finding PAIN and FedRAMP remediation deadlines, plus filter controls for severity (multi-select), PAIN, namespace, internet exposure, automatable, exploitation status, EPSS score, technical impact, and remediation deadline (multi-select).
- Optional CAPEC/ATT&CK chain-taxonomy evidence and same-resource transition candidates, enabled with `--include-chain-taxonomy`.
- Namespace selection, all-namespace scanning, image source, parallel scanning, cache cleanup, timeout, severity, EPSS, enrichment, exposure, and debug flags.
- Automatic private-registry authentication from the local Docker config, Kubernetes `imagePullSecrets`, ECS task `repositoryCredentials`, Google Artifact Registry/GCR (via `gcloud`), and AWS ECR (via the `aws` CLI).
- Resilient scanning: a single image that fails to pull or scan is reported as a warning and the run continues, producing a partial (still enriched) report.
- INFO-level progress logging to stderr by default.
- Shared JSON model for inventory, findings, EPSS, CISA Vulnrichment, exposure, access protection, reports, and summaries.

## Usage

```sh
trivy vdr --help
trivy vdr k8s --help
trivy vdr k8s --namespace default --format json
trivy vdr k8s -n default --format table
trivy vdr k8s --all-namespaces --min-severity HIGH --min-epss 0.5
trivy vdr k8s --view resources --output vdr-k8s.json
trivy vdr k8s --image-src remote --parallel-scans 5
trivy vdr k8s --skip-enrichment --skip-exposure --debug
trivy vdr k8s --reachability-only --output vdr-k8s-reachability.json
trivy vdr k8s --scan-reachability-only --output vdr-k8s-scan-reachability.json
trivy vdr k8s --refresh-enrichment
trivy vdr k8s --include-chain-taxonomy --output vdr-k8s-capec.json
trivy vdr k8s --skip-registry-auth
trivy vdr k8s --no-gcloud-auth --no-ecr-auth
trivy vdr k8s --oci-vex-included
trivy vdr k8s -O
trivy vdr k8s --vex-oci-registries registry.example.com,ghcr.io/acme
trivy vdr k8s --quiet
trivy vdr k8s --namespace default --output vdr-k8s.json --html-output vdr-k8s.html
trivy vdr k8s --html-output vdr-k8s.html --html-template custom-template.html
trivy vdr k8s --all-namespaces --scoring-config vdr-scoring.yaml
trivy vdr k8s-compliance --namespace default
trivy vdr k8s-compliance --all-namespaces --min-severity HIGH
trivy vdr k8s-compliance --all-namespaces --format json --output vdr-k8s-compliance.json
trivy vdr cloudrun --project my-gcp-project --region us-east4 --region us-central1 --output vdr-cloudrun.json
trivy vdr cloudrun --project my-gcp-project --region us-east4 --view resources --html-output vdr-cloudrun.html
trivy vdr cloudrun --project my-gcp-project --region us-east4 --reachability-only --output vdr-cloudrun-reachability.json
trivy vdr cloudrun --project my-gcp-project --region us-east4 --scan-reachability-only --output vdr-cloudrun-scan-reachability.json
trivy vdr ecs --region us-east-1 --region us-gov-west-1 --output vdr-ecs.json
trivy vdr ecs --region us-east-1 --view resources --reachability-only --output vdr-ecs-reachability.json
trivy vdr image gcr.io/my-gcp-project/app:v1
trivy vdr image --parallel-scans 2 gcr.io/my-gcp-project/app:v1 nginx:1.25
trivy vdr helm ./charts/app -f values/base.yaml -f values/prod.yaml --format json
trivy vdr helm bitnami/nginx --chart-version 19.0.0 --namespace prod
trivy vdr helm nginx --repo https://charts.example.com --chart-version 1.2.3
trivy vdr helm oci://registry.example.com/charts/app --chart-version 1.2.3
trivy vdr helm ./charts/app --ingress-chart ./charts/edge --ingress-values values/edge.yaml
trivy vdr helm ./charts/app --config-map examples/configmaps/vdr-fedramp-configmap.gke.yaml
trivy vdr enrich-report --input vdr.json --output vdr-enriched.json --html-output vdr-enriched.html
```

`enrich-report` adds the embedded CAPEC/ATT&CK taxonomy projection to an
existing VDR JSON report without rescanning images. Legacy reports without
`reportSchemaVersion` are accepted; unknown future schemas fail closed. Existing
vulnerability, exposure, PAIN, and remediation fields are preserved. Retired
legacy `chainableEntrypoint` fields are not copied into the current schema.

## Kubernetes compliance scanning

`trivy vdr k8s-compliance` is intentionally separate from `trivy vdr k8s`. It runs Trivy's built-in Kubernetes misconfiguration and RBAC scanners with image scanning disabled, so compliance findings cannot be mixed into the existing VDR vulnerability, PAIN, or CAPEC calculations. It uses the default built-in check bundle rather than selecting a named `--compliance` profile.

Table is the default format for this source. It follows Trivy's resource-oriented Kubernetes presentation: each failing resource has a namespace/kind/name heading, test success/failure counts, and an ID/severity/status/title/message table. When a resource is controller-owned, the heading also shows its resolved top-level parent, such as `Pod/api-abc (parent: Deployment/api)` or `Job/nightly-123 (parent: CronJob/nightly)`.

Use `--format json` for the separate `k8s-compliance/v1` contract:

```json
{
  "reportSchemaVersion": "k8s-compliance/v1",
  "clusterName": "my-context",
  "summary": {
    "resources": 10,
    "failedResources": 3,
    "failedChecks": 7,
    "bySeverity": {
      "HIGH": 2,
      "MEDIUM": 5
    }
  },
  "resources": [
    {
      "resource": {
        "apiVersion": "v1",
        "kind": "Pod",
        "namespace": "default",
        "name": "api-abc"
      },
      "parentController": {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "namespace": "default",
        "name": "api"
      },
      "results": []
    }
  ]
}
```

The individual scanned resource is always retained. Parent mapping is enriched read-only from Kubernetes owner references and resolves common controller chains including Pod → ReplicaSet → Deployment and Job → CronJob. A denied mapping read becomes a warning and does not discard Trivy's finding.

The command passes `--disable-node-collector` so it remains read-only and does not create Trivy's temporary node-collector Job. As a result, node-infrastructure checks that require that collector are not included; workload-definition and RBAC checks still use Trivy's built-in rules. See Trivy's [Kubernetes scanning guide](https://trivy.dev/docs/dev/guide/target/kubernetes/) and [built-in checks documentation](https://trivy.dev/docs/latest/scanner/misconfiguration/check/builtin/).

## Helm chart scanning

The `helm` source runs the installed `helm template` client, inventories the rendered Kubernetes workloads, and sends their unique image references through the same registry-authentication, Trivy, enrichment, scoring, and reporting pipeline used by the live Kubernetes source. Helm must be installed and available on `PATH`.

The chart argument may be:

- a local chart directory or packaged `.tgz` archive;
- a reference from the user's configured Helm repositories, such as `bitnami/nginx`;
- an unqualified chart paired with `--repo <url>`; or
- an `oci://` chart reference.

`--chart-version` selects a remote chart version. Repository and OCI authentication use the existing Helm configuration and `helm registry login` state; VDR does not accept repository passwords on its command line.

Application values files are passed to Helm exactly in the order supplied. `-f` is an alias for `--values` only for the `helm` source; use the long `--format` flag to select the VDR report format. Helm's normal precedence applies: chart defaults are lowest, then each values file is merged from left to right, and the rightmost file wins.

```sh
trivy vdr helm ./charts/payments \
  -f values/base.yaml \
  -f values/us-east.yaml \
  -f values/prod.yaml \
  --namespace payments \
  --release-name payments \
  --format json
```

Use `--ingress-chart` to render a second release containing shared Ingress, ingress-controller, or **Gateway API** infrastructure. Its values and namespace are independent from the application chart:

```sh
trivy vdr helm ./charts/payments \
  -f values/prod.yaml \
  --ingress-chart oci://registry.example.com/platform/edge \
  --ingress-chart-version 2.1.0 \
  --ingress-values values/edge-base.yaml \
  --ingress-values values/edge-prod.yaml \
  --ingress-namespace edge-system
```

The two rendered streams are merged before topology analysis. This allows VDR to resolve Ingress and Gateway routes through Services to application workloads, including HTTPRoute, GRPCRoute, TCPRoute, TLSRoute, and cross-namespace ReferenceGrant relationships. A duplicate API version/kind/namespace/name across the two releases is rejected because the same collision would not be independently installable in Kubernetes.

Helm exposure has `assessmentBasis: "declared"`. It represents deployment intent derived from rendered classes, schemes, annotations, Services, routes, and policies; it does **not** claim that a load balancer was provisioned or that the resources are currently serving traffic. Live `k8s` scans retain their observed-status behavior. For custom Ingress or Gateway classes whose external edge cannot be inferred from the manifests, provide `internetAccessibleIngressClasses` or `internetAccessibleGatewayClasses` in the VDR ConfigMap.

If the rendered chart contains `fedramp-vdr-trivy/vdr-fedramp`, it is consumed automatically. `--config-map <file>` can supply a separate `v1/ConfigMap` and takes precedence over a rendered ConfigMap. This is useful when the scoring and custom class configuration is managed outside the application chart.

Useful rendering flags include `--kube-version`, repeatable `--api-versions`, and `--include-crds`. The Helm source does not contact a Kubernetes API and requires no Kubernetes RBAC. Remote chart downloads and image scans still require their respective network access and credentials.

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
    resources: ["namespaces", "pods", "replicationcontrollers", "services", "configmaps"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
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
    resources: ["loadbalancerconfigurations", "targetgroupconfigurations"]
    verbs: ["list"]
```

Notes:

- Choose one of these Secret-access options when registry authentication from Kubernetes `imagePullSecrets` is enabled:
  - **Any referenced Secret:** keep the `secrets/get` ClusterRole rule above. VDR can get any Secret by name, but it still cannot list or watch Secrets.
  - **Only approved Secret names:** omit the `secrets/get` rule above and apply the namespace-scoped [`vdr-image-pull-secret-reader` example](examples/rbac/vdr-image-pull-secret-reader.yaml), customized with the exact `imagePullSecret` names. Repeat it in each scanned namespace.
- Use `--skip-registry-auth` or `--reachability-only` to avoid reading Secrets entirely.
- `configmaps/get` is used for the optional `fedramp-vdr-trivy/vdr-fedramp` scoring ConfigMap.
- Exposure resources are optional for vulnerability scan reports. If `--skip-exposure` is set, `services`, `ingresses`, `ingressclasses`, Gateway API resources, GKE BackendConfig/GCPBackendPolicy, and AWS ALB/Gateway custom resources are not needed for exposure analysis. `--reachability-only` requires exposure resources and cannot be combined with `--skip-exposure`.
- If you never use AWS ALB/Gateway resources, the `elbv2.k8s.aws` and `gateway.k8s.aws` rules can be omitted. If you never use GKE ingress/gateway IAP metadata, the `cloud.google.com/backendconfigs` and `networking.gke.io/gcpbackendpolicies` rules can be omitted.
- `k8s-compliance` also requires read access to every resource type Trivy evaluates. The Pod, ReplicationController, Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, and CronJob list permissions above provide VDR's parent-controller enrichment; other resource permissions depend on the built-in Trivy checks and APIs installed in the cluster.

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
- `--reachability-only` uses the same Cloud Run and Compute read permissions, but skips registry authentication, Trivy image scans, EPSS, and Vulnrichment.
- For private Google Artifact Registry/GCR images, the local `gcloud` identity used for `gcloud auth print-access-token` must also be able to read those images, for example with `roles/artifactregistry.reader` on the relevant repositories or project.

## Enrichment cache

EPSS and CISA Vulnrichment data are cached under `--cache-dir`. EPSS cache files are refreshed after 24 hours. Vulnrichment cache files are refreshed after 7 days.

Use `--refresh-enrichment` to force EPSS and Vulnrichment refresh attempts even when cached files are still fresh. If a forced refresh fails and an existing cache file is still readable and valid, `vdr` keeps and uses the cached data.

## Private registry authentication

Before scanning, `vdr` assembles Docker credentials so Trivy can pull private images. It writes an owner-only temporary `DOCKER_CONFIG` directory that is removed when the run ends. For each image scan, it also passes only the credential matching that image's registry through Trivy's explicit credential environment, which supports registries that do not consume the generated Docker config consistently. Credentials come from four sources:

- **Local Docker config** — credentials in `$DOCKER_CONFIG/config.json`, or `~/.docker/config.json` when `DOCKER_CONFIG` is unset.
- **Deployment credentials** — Kubernetes `kubernetes.io/dockerconfigjson` (and legacy `kubernetes.io/dockercfg`) `imagePullSecrets` referenced by scanned pod specs, plus AWS Secrets Manager credentials referenced by ECS task `repositoryCredentials`.
- **Google Artifact Registry / GCR** — for `*.pkg.dev`, `gcr.io`, and `*.gcr.io` images, `vdr` runs `gcloud auth print-access-token` once.
- **AWS ECR** — for `*.dkr.ecr.<region>.amazonaws.com` images, `vdr` runs `aws ecr get-login-password --region <region>` once per registry.

A cluster secret always wins over a cloud-CLI token for the same registry host. Tokens are never logged. Each source degrades gracefully: a missing/unauthenticated `gcloud` or `aws` CLI, an unreadable Secret, or an RBAC denial produces a warning, not a failure (affected images then surface as per-image scan warnings).

Customers can choose broad or limited Secret access. The broad ClusterRole rule
allows VDR to `get` any referenced Secret by name without allowing `list` or
`watch`. For tighter access, omit that broad rule and restrict `get` to exact
`imagePullSecret` names with `Role.rules[].resourceNames`; see the
[`vdr-image-pull-secret-reader` RBAC example](examples/rbac/vdr-image-pull-secret-reader.yaml).

Flags:

- `--skip-registry-auth` disables all automatic authentication.
- `--no-gcloud-auth` skips the `gcloud` token for GAR/GCR.
- `--no-ecr-auth` skips the `aws` token for ECR.
- `--gcp-impersonate-service-account <email>` uses an impersonated Google service account for Cloud Run metadata clients and adds `--impersonate-service-account` to GAR/GCR `gcloud` token fetches.
- `--aws-role-arn <arn>` assumes the AWS role ARN with `aws sts assume-role` before fetching ECR tokens.

This adds one Kubernetes RBAC requirement beyond inventory collection: `get` on `secrets` in the scanned namespaces. For Cloud Run and standalone image scans, no Kubernetes Secrets are read. The optional `gcloud` and `aws` CLIs must be installed and authenticated on the machine running the plugin.

## Required permissions

`vdr` is read-only against orchestrator and cloud APIs. It needs enough access to list workloads and routing objects, read the optional FedRAMP ConfigMap, read image-pull credentials when registry auth is enabled, and inspect exposure controls.

### Kubernetes RBAC

For Kubernetes clusters, grant the identity running `trivy vdr k8s` a read-only ClusterRole like this:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vdr-reader
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "namespaces", "configmaps"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets"]
    verbs: ["get", "list"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "ingressclasses"]
    verbs: ["get", "list"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways", "httproutes", "grpcroutes", "tcproutes", "tlsroutes", "referencegrants"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.gke.io"]
    resources: ["gcpbackendpolicies"]
    verbs: ["get", "list"]
  - apiGroups: ["cloud.google.com"]
    resources: ["backendconfigs"]
    verbs: ["get", "list"]
  - apiGroups: ["elbv2.k8s.aws"]
    resources: ["ingressclassparams"]
    verbs: ["get", "list"]
  - apiGroups: ["gateway.k8s.aws"]
    resources: ["loadbalancerconfigurations", "targetgroupconfigurations"]
    verbs: ["get", "list"]
```

Bind it with a `ClusterRoleBinding` for all namespaces, or a `RoleBinding` per namespace when using `--namespace` and when you do not need cluster-scoped resources such as `namespaces` and `ingressclasses`. The displayed `secrets/get` rule is the broad option: it permits getting any Secret by name but not listing or watching Secrets. For exact-name access, omit that rule and apply the namespace-scoped [`vdr-image-pull-secret-reader` example](examples/rbac/vdr-image-pull-secret-reader.yaml). If `--skip-registry-auth` is set, Secret access can be omitted entirely; otherwise unreadable pull Secrets are reported as warnings and affected private images may fail to scan.

For GKE IAM-based Kubernetes API access, `roles/container.viewer` is enough for workload, namespace, Service, Ingress, Gateway, ConfigMap, and GKE exposure metadata reads, but it does not include Secret reads. Reading image-pull Secrets through GKE IAM requires a role containing `container.secrets.get` such as `roles/container.developer`, or a narrower custom role. Prefer Kubernetes RBAC when possible because it can grant `get` on Secrets without broad write access.

### Cloud Run IAM

The planned Cloud Run source uses Google Cloud APIs rather than Kubernetes RBAC. The identity running `trivy vdr cloudrun` should have these project-level predefined roles, or a custom role with the listed permissions:

- `roles/run.viewer` for Cloud Run inventory and IAM policy checks. Required permissions include `run.services.list`, `run.services.get`, `run.services.getIamPolicy`, `run.jobs.list`, `run.jobs.get`, and `run.locations.list`.
- `roles/compute.networkViewer` for load balancer exposure analysis when a service uses `internal-and-cloud-load-balancing` ingress. Required permissions include reads for global and regional forwarding rules, target HTTP(S) proxies, URL maps, backend services, and network endpoint groups, plus backend service IAP settings.

Cloud Run jobs are treated as not internet reachable and do not need load balancer analysis. Cloud Run services are considered internet reachable only when `allUsers` has `roles/run.invoker` and ingress is `all`, or when `internal-and-cloud-load-balancing` ingress is fronted by a public HTTP(S) load balancer whose Cloud Run backend is not IAP-protected.

### AWS ECS IAM

The ECS source uses AWS APIs rather than Kubernetes RBAC. The identity running `trivy vdr ecs` should have read-only permissions in each scanned region:

- `ecs:ListTaskDefinitions`
- `ecs:DescribeTaskDefinition`
- `ecs:ListClusters`
- `ecs:ListServices`
- `ecs:DescribeServices`
- `ecs:ListTasks`
- `ecs:DescribeTasks`
- `elasticloadbalancing:DescribeTargetGroups`
- `elasticloadbalancing:DescribeLoadBalancers`
- `ec2:DescribeNetworkInterfaces`
- `ec2:DescribeSecurityGroups`
- `secretsmanager:GetSecretValue` when task definitions use `repositoryCredentials`
- ECR token access through the existing AWS CLI auth path (`aws ecr get-login-password`)

Task-definition `repositoryCredentials` secret values are used only to build scan-time Docker auth and are not written to inventory, reports, logs, or evidence. ECR auth can be disabled with `--no-ecr-auth`; all automatic registry auth can be disabled with `--skip-registry-auth`.

ECS resources include a `runtime` object in resource-view JSON. Runtime status is based on ECS service desired/running counts and currently observed running tasks. `defined_only` task definitions are not treated as internet-reachable by default.

## VEX attestations

`vdr` can opt into Trivy's experimental OCI VEX attestation discovery:

```sh
trivy vdr k8s --oci-vex-included
trivy vdr k8s -O
trivy vdr k8s --vex-oci-registries registry.example.com,ghcr.io/acme
```

By default, OCI VEX attestation lookup is off. `--oci-vex-included` / `-O` enables registry VEX lookup for every scanned image. `--vex-oci-registries` is the narrower form: it accepts registry hosts (`registry.example.com`) or repository prefixes (`ghcr.io/acme`), and only matching images are scanned with `trivy image --vex oci --show-suppressed`. Other images are scanned without OCI VEX. Suppressed VEX findings are not silently dropped: reports keep them in `suppressedFindings` with the VEX status, justification, source, and informational `wouldHaveBeenPain` / `wouldHaveBeenRemediation` values. They are excluded from the active finding count and remediation queue.

> **Important — sign attestations with cosign v2.** Trivy discovers the classic cosign
> attestation (`.att` tag) layout. cosign **v3** publishes attestations as OCI 1.1
> referrers, which Trivy does **not** read yet — a v3 attestation is silently ignored by
> `--vex oci` (the scan logs `No VEX attestations found`). Create attestations with cosign
> **v2** so they land as the `.att` tag Trivy can find:
>
> ```sh
> cosign attest --predicate vex.json --type openvex --key <gcpkms-or-key> --tlog-upload=false --yes <image>@<digest>
> ```
>
> Revisit once a referrer-aware Trivy ships.

## Logging

Progress is logged to stderr (the report is written to stdout or `--output`, so logs never contaminate it). The default level is INFO and announces each phase: inventory collection, registry auth, scanning, EPSS/vulnrichment fetch-vs-cache, and report output. Use `--quiet` for warnings and errors only, or `--debug` for verbose diagnostics.

## Image scanning and Trivy cache cleanup

`vdr` scans each unique full image reference once and fans findings back out to every Kubernetes, Cloud Run, or standalone image resource that uses that image. Scan results are returned in deterministic image-reference order, independent of the order in which concurrent scans finish.

Scan defaults:

- `--image-src remote`
- `--parallel-scans 5`
- `--cache-cleanup auto`
- `--cache-min-free-gb 10`
- `--cache-min-free-percent 10`

`vdr` downloads the Trivy vulnerability and Java databases once up front (`trivy image --download-db-only` / `--download-java-db-only`) and then scans each image with `trivy image --image-src <value> --skip-db-update --skip-java-db-update --skip-version-check --format json --scanners vuln --timeout <timeout> <image>`. The default `--image-src remote` pulls each image from its registry.

**Safe parallel scanning.** Trivy's scan cache (fanal) is a BoltDB that takes an exclusive lock per scan, so multiple `trivy image` processes cannot share one cache directory — doing so causes lock timeouts, and downloading a database mid-scan corrupts a shared cache (SIGSEGV). `vdr` avoids both: it pre-downloads the databases, then for parallel runs gives each worker its own cache directory with the databases **hardlinked** from the shared cache (no extra disk) and a private scan cache. This makes `--parallel-scans` > 1 safe and fast. If a database is ever found corrupted, `vdr` clears and re-downloads it once automatically (self-heal).

A transient image pull or scan failure is retried twice before it is treated as failed. A single image that still cannot be pulled or scanned does not abort the run: the failure is logged inline and recorded as a warning in the report, the remaining images are still scanned and enriched, and a summary of failed images is printed at the end. If any image fails, `vdr` exits with a non-zero status after writing the report.

Standalone image scans (`trivy vdr image IMAGE...`) never run internet reachability analysis and do not include exposure metadata. They do include EPSS and CISA Vulnrichment enrichment by default, unless `--skip-enrichment` is set.

Cache cleanup runs once after the image scan phase completes:

- `--cache-cleanup never` skips cleanup.
- `--cache-cleanup always` runs `trivy clean --scan-cache`.
- `--cache-cleanup auto` checks free disk space for the configured Trivy cache directory, or the nearest existing parent directory, and runs `trivy clean --scan-cache` when free space is below either `--cache-min-free-gb` or `--cache-min-free-percent`.

If cleanup fails after an image scan succeeds, the scan result is kept and a warning is recorded for later reporting.

## Reporting

JSON output defaults to a finding-centric report. Each finding includes `affected` — a list of `{resource, exposure}` entries — so a deduplicated image scan can still be traced back to every Kubernetes, Cloud Run, or ECS resource and container using that image, along with that resource's internet exposure when available.

The top-level JSON metadata includes `scannerVersion` for the Trivy binary used by the plugin and `pluginVersion` for the VDR plugin build.

CAPEC/ATT&CK chain-taxonomy enrichment is disabled by default. Use `--include-chain-taxonomy` to opt a scan into loading the release-pinned embedded catalog, calculating transition candidates, and emitting the related report fields. When enabled, every finding includes informational `chainTaxonomy` evidence projected through the catalog. The projection preserves each `CWE -> CAPEC -> ATT&CK` path, structured CAPEC consequence impacts, and explicit CAPEC predecessor/successor IDs. `taxonomyRole` is `producer_candidate`, `consumer_candidate`, `bridge_candidate`, `isolated_in_capec`, or `unknown`; these are pattern-level evidence labels, not proof of a CVE-specific exploit chain.

With that option enabled, the report also emits top-level `capecTransitions` for a deliberately narrow external-to-follow-on review case: two distinct active CVEs affect the same exact internet-accessible resource, the upstream is `AV:N/PR:N`, and their path-specific CAPEC patterns match an explicit `CanPrecede` edge. The downstream may have any CVSS attack vector; its AV/PR values are retained only as context. Inside each concrete pair, the upstream endpoint is labeled `candidate_entrypoint` and the downstream endpoint `candidate_follower`; neither role is copied onto a CVE as a standalone classification. Candidates are aggregated by resource, CVE pair, and CAPEC edge while retaining all package occurrences and CWE paths. Each transition also retains source consequence impacts, target prerequisite prose, exposure, and exact resource identity. Because broad CWEs can over-project into CAPEC, every candidate is explicitly low-confidence and review-required. These are review candidates only: they do not infer a capability match or change IRV, PAIN, or remediation. The top-level `chainCatalog` records corpus versions and SHA-256 hashes, while `summary.chainTaxonomy` reports coverage, transition pairs, distinct resource-specific entrypoint candidates, and unique upstream CVEs. `reportSchemaVersion` versions the JSON contract. CycloneDX carries the taxonomy projection and transition set as `vdr:*` properties. See [CAPEC and ATT&CK chain-taxonomy enrichment](docs/chain-taxonomy.md).

Use `--view resources` for resource-centric JSON or table output. Resource reports include the matching container image inventory, container security metadata, resource labels, exposure state, and findings scoped to that resource/container.

Container security metadata (`images[].security`) is collected from every source (since v2.3.0): Kubernetes and Helm report the pod/container securityContext (privileged, capability add/drop, read-only root filesystem, seccomp/AppArmor profiles); ECS reports `privileged`, `readonlyRootFilesystem`, capability add/drop, and seccomp/AppArmor profiles from `dockerSecurityOptions` (EC2 launch type); Cloud Run reports the platform-enforced posture — never privileged, writable in-memory root filesystem — plus `sandbox` (`gVisor` for gen1, `microVM` for gen2) when the execution environment is explicit.

Duplicate findings are merged by default (since v2.0.0): findings that share the same vulnerability ID, package name, and installed version become a single entry. In the findings view duplicates are merged across images and scan targets: the surviving finding keeps the worst-case `pain` and `remediation`, `affected` lists every resource from all merged duplicates, and `imageRefs` lists every image the duplicates came from when they span more than one. In the resources view, duplicate findings are collapsed within each resource. Summary counts reflect the deduplicated totals, and deduplication applies to every output format. Use `--no-dedupe` to keep the previous one-entry-per-image-and-target behavior.

Use `--reachability-only` with `k8s`, `cloudrun`, or `ecs` for an internet-reachability metadata report without vulnerability findings. This mode emits the resources view, skips registry authentication and Trivy scanning, and does not fetch EPSS or Vulnrichment data.

Use `--scan-reachability-only` with `k8s`, `cloudrun`, or `ecs` to run Trivy vulnerability scans and exposure analysis without EPSS, Vulnrichment, PAIN, or remediation scoring output. JSON findings keep scanner vulnerability data plus `affected[].resource`, `affected[].exposure`, and `affected[].classification` with the effective Certification Class and security-impact profile. Resource-view reports also include each resource's `classification`. Table output replaces PAIN/remediation/enrichment columns with Class and Security-Impact Profile columns. This mode does not support `--html-output`, `--html-template`, `--skip-exposure`, `--min-epss`, `--include-chain-taxonomy`, or the standalone `image` source.

Use `--html-output <path>` to write a standalone HTML report. The default HTML template is embedded in the plugin and requires no remote CDN assets. It supports light/dark mode (following the OS preference, with a toggle that is remembered), a multi-select severity filter, a Trivy fix-status filter (including `will_not_fix`), a PAIN filter, a multi-select remediation-deadline filter, and click-to-sort on every column (severity sorts by rank, EPSS numerically).

Each finding shows its **PAIN** tier and a FedRAMP **Remediation** deadline (see [PAIN scoring and remediation](#pain-scoring-and-remediation)). Automatable, Exploitation, and Technical impact from CISA Vulnrichment are also shown for context; CVSS-derived Automatable and Technical impact values are rendered in italics with a `†` marker so they are distinguishable from authoritative Vulnrichment values. Hover any value or column header for an in-report explanation. Use `--html-template <path>` to override the template with a local Go `html/template`; the template receives `.Report` and `.ReportJSON`.

When `--include-chain-taxonomy` is enabled, the HTML report provides a **CAPEC chain role** filter and CAPEC evidence badges beside mapped CVEs. When external-to-follow-on candidates exist, a separate **CAPEC transition candidates** table displays the aggregated upstream CWE/CAPEC → `CanPrecede` → downstream CAPEC/CWE path and observed AV/PR/exposure context.

## PAIN scoring and remediation

Every finding is scored against the FedRAMP Rev5 VDR model: a **PAIN** rating (Potential Agency Impact, N1–N5) and a **VDR-TFR-PVR** remediation deadline. PAIN and the deadline appear in the JSON (`pain`, `remediation`), the table, and the HTML report.

### PAIN = f(severity, scope)

- **Severity** is the CVE's CVSS impact vector (which of Confidentiality/Integrity/Availability it touches) re-weighted by the asset's independent `CR/IR/AR` **security-impact profile**, which may be capped by an optional system-and-agency security-requirements ceiling. CISA Vulnrichment **technical impact** refines this as a *floor*: when `total`, each in-scope CVSS dimension is raised to High before weighting; it never invents impact on a dimension the CVE does not touch, and `partial`/absent leaves the CVSS vector unchanged. The weighted dimensions form the pre-cap complement-product aggregate `U`; PAIN normalizes it by the all-High-impact/all-High-requirement maximum `D_H = 0.995904`, not by the CVSS MISS cap of `0.915`. The scalar maps to Minimal, Narrow, Disruptive, or Debilitating using governed defaults `0.28115159694107 / 0.56230319388214 / 0.933`. These anchors make one High impact at Low requirement Narrow, one High impact at Medium requirement Disruptive, and reserve Debilitating for compound High-impact alignment. The thresholds are calibratable via `wordThresholds` in a governed `--scoring-config` file and are deliberately **not** read from the in-cluster ConfigMap, so calibration cannot be changed by ad-hoc cluster edits.
- **Scope** is whether the asset serves one agency or more than one. Disruptive → N3 (single) / N4 (multi); Debilitating → N4 (single) / N5 (multi).

### Asset security-impact profile

The required input is a three-dimensional CR/IR/AR profile. A ConfigMap rule or `vdr.fedramp.io/security-impact-profile` label may express it in any of three supported forms:

- a direct independent vector such as `cr-h_ir-m_ar-l`;
- a governed decision trace, `<disclosure>.<trusted-change>.<dependency>`, whose segments independently derive CR, IR, and AR; or
- a named entry from the optional archetype catalog in [`policy/vdr-policy.yaml`](policy/vdr-policy.yaml).

For example, `regulated-data.authoritative-record.shared-critical-path` derives H/H/H and `public-content.bounded-processing.bounded-service` derives L/M/M. Decision traces resolve natively and do not need duplicate catalog entries. Archetypes are one useful assignment system, not the required model.

A CSP may use an archetype system, an asset-value system, or another governed method to choose the profile, but the runtime transport is always SIP. A scalar asset-value method must translate High/Medium/Low to `cr-h_ir-h_ar-h`, `cr-m_ir-m_ar-m`, or `cr-l_ir-l_ar-l` before assignment. That method erases independent CR/IR/AR reasoning and should not be the CSP's only classification interface.

For cloud compliance findings, use the same three independent decisions rather than classifying from resource type alone. Broad IAM mutation, deployment, impersonation, or cross-service administration supports `privileged-access` for disclosure and a High trusted-change reason such as `identity-control` or `config-control`; constrained workload authority supports `scoped-access`. Regulated objects support `regulated-data`, intentionally public objects support `public-content`, and payload-free telemetry supports `ops-metadata`. Select dependency/outage separately from the affected population and consequence.

```
workload label vdr.fedramp.io/security-impact-profile
  → namespace label vdr.fedramp.io/security-impact-profile
  → securityImpactProfile name rule   (cluster ConfigMap; first match wins)
  → securityImpactProfile kind rule   (cluster ConfigMap; first match wins)
  → securityImpactProfile namespace rule (cluster ConfigMap; first match wins)
  → built-in "unclassified" cluster-default (H/H/H — noisy N4, surfaces for classification)
```

Tag workloads you control with `vdr.fedramp.io/security-impact-profile: <profile>`, where `<profile>` is a direct vector, governed decision trace, or named archetype. Cloud-managed, shared-responsibility components (`kube-system`, `gke-managed-*`, `amazon-cloudwatch`, `azure-*`, …) that cannot carry the label are classified by name/namespace rules in the ConfigMap instead. For Cloud Run, service/job labels override project labels. For ECS, task definition tags are used as labels.

`kindRules` (since v2.1.0) match on workload kind with optional namespace and name globs — e.g. `{kind: Job, securityImpactProfile: security-evidence.record-keeping.operations-support}` classifies standalone Jobs (Helm hooks, one-shot migrations) whose generated names defeat name globs and which cannot carry labels. Kind rules sit between name rules and namespace rules, so a specific name rule or label still wins. CronJob-spawned Jobs are not inventoried separately (since v2.1.0); they are covered by their CronJob's template, so a `Job` kind rule only affects standalone Jobs.

Every scored finding records where each classification input came from, so defaults are auditable: `pain.securityImpactProfileSource` (`label | namespaceLabel | nameRule | kindRule | namespaceRule | default | failsafe`), `remediation.classSource` (`label | namespaceLabel | configMap | scoringConfig | builtin`), and `pain.multiAgencySource` (`label | namespaceLabel | multiAgencyNamespaces | configMap | scoringConfig | builtin | failsafe`). A `configMap` source means the in-cluster `vdr-fedramp` ConfigMap value applied because the workload and namespace carried no label; `scoringConfig` means a `--scoring-config` file set it; `builtin` means nothing was configured anywhere; `failsafe` means no signal existed anywhere and the conservative fail-safe was used.

### Optional security-requirements ceiling

The asset security-impact profile supplies the uncapped CR/IR/AR vector. An optional deployment-wide ceiling can be derived from the system and deploying agency security objectives:

```text
ceiling(objective) = min(system objective, agency objective)
effective asset requirement = min(profile requirement, ceiling)
```

Pass it for one invocation with `--security-requirements-ceiling cr-m_ir-m_ar-l`, or place `securityRequirementsCeiling: cr-m_ir-m_ar-l` in the `vdr-fedramp` ConfigMap data. The runtime flag has highest precedence. The display form `CR:M/IR:M/AR:L` is also accepted.

The ceiling is entirely optional: when omitted, no warning is emitted and profile scoring is unchanged. When declared, reports retain the resolved profile and uncapped requirements, show `securityRequirementsCeiling` and its source, expose the effective `cr`/`ir`/`ar`, and set `recalculated: true` only when the ceiling actually lowers a dimension.

### Remediation deadline

```
deadline = matrix[ Certification Class ][ PAIN ][ column ]
  column = LEV+IRV | LEV+NIRV | NLEV
  LEV (likely exploitable) = EPSS >= 0.50  OR  exploitation = active
  IRV (internet reachable) = a public route reaches the affected resource AND the CVE is CVSS AV:N
```

So the same CVE remediates faster on a higher-PAIN, publicly routed asset when that CVE has a network attack vector, and when it is actively exploited. The EPSS LEV cutoff (0.50) is built into the plugin. Internet reachability and CVSS exploitability metrics do not independently establish LEV; public-route evidence plus CVSS AV:N are evaluated separately as IRV when the remediation column is selected. PAIN-1 findings have no FedRAMP deadline. In the findings view the finding-level PAIN/deadline is the most urgent across all affected resources.

### Cluster configuration

The provider **Certification Class** (A/B/C/D), the **agency scope**, and the security-impact-profile **rules** are read from an in-cluster ConfigMap named **`vdr-fedramp`** in the **`fedramp-vdr-trivy`** namespace — no flag required. It carries the scalar keys `class`, `multiAgency`, and optionally `securityRequirementsCeiling`, plus an embedded `scoring.yaml` that is deep-merged over the plugin's built-in rubric (optional named-archetype catalog entries, profile rules, algorithm settings, and the `unclassified` default). Compositional reason mappings remain governed by the embedded canonical policy and are not cluster-overridable. It can also carry `internetAccessibleIngressClasses` / `internetAccessibleGatewayClasses` — lists of Ingress/Gateway class names to treat as internet-reachable when their edge load balancer is built outside Kubernetes, a cleaner alternative to labeling each resource (see [exposure rules](#exposure-rules)). Namespace labels (`vdr.fedramp.io/class`, `vdr.fedramp.io/multi-agency`, `vdr.fedramp.io/security-impact-profile`) and workload labels override the ConfigMap (most specific wins). When the ConfigMap is missing or unreadable the plugin **warns** and falls back to built-in defaults (Class B, single-agency, no tenant rules). A missing ceiling is normal and produces no warning. Retired `archetype` and `assetValue` fields are rejected so the estate has one transport contract. If a present ConfigMap is invalid, incompatible, or uses an unsupported format, the plugin logs an **error** directing the operator to regenerate it with the current profile schema and links to [`trivy-plugin-vdr-skills`](https://github.com/stackArmor/trivy-plugin-vdr-skills) for AI-assisted migration.

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
- Some reachability can't be inferred from the cluster at all — e.g. an app behind ingress-nginx whose external L7 load balancer is provisioned outside Kubernetes (standalone NEG / Terraform), where the controller Service stays `ClusterIP`/`NodePort` and the app `Ingress` objects use an unrecognized class such as `nginx`. The label `vdr.fedramp.io/internet-reachable: "true"` (or `"false"`) lets an operator declare it, on either object kind:
  - On an **`IngressClass`**: every Ingress using that class is treated as public (`"true"`) or forced not-public (`"false"`, which wins even over a built-in public class like `gce`). One label surfaces all backends behind that class.
  - On a **`Service`** of any type: its selected workloads are forced reachable (`"true"`) or not-reachable (`"false"`, which suppresses even a `type=LoadBalancer` external address). Use this for the ingress controller pods themselves or a standalone-NEG app with no Ingress.

	  On a Service this label takes precedence over `vdr.fedramp.io/internet-reachable-nodePort`.

	  > **Use this label only when the load balancer is managed outside Kubernetes** (e.g. a standalone NEG wired to a GCP load balancer provisioned in Terraform). It is a manual, operator-asserted override: the cluster has no way to verify it, so it can drift out of sync with the real edge — if the external LB is added, removed, or re-scoped (internal ↔ external) the label won't follow, and the assessment will be silently wrong. This is inherently brittle. The recommended alternative is to let Kubernetes own the load balancer — a native GKE `Ingress` (`gce`), a GKE `Gateway`, or a `type=LoadBalancer` Service — so reachability (and IAP/BackendConfig protection) is inferred directly from cluster state and stays correct automatically, with no label to maintain.

JSON output also includes optional `exposure.routes` metadata when route details are available. For Kubernetes this can include Ingress/Gateway hostnames, path matches, header matches, rewrite filters, backend Service references, and provider-derived protocol hints such as frontend protocol, backend protocol, backend protocol version, backend TLS, ALPN, and ALPN policy. AWS ALB Ingress protocol hints come from `alb.ingress.kubernetes.io/backend-protocol` / `backend-protocol-version`; AWS Gateway hints come from `gateway.k8s.aws` `TargetGroupConfiguration`; AWS NLB Service ALPN hints come from `service.beta.kubernetes.io/aws-load-balancer-alpn-policy`; GKE Ingress backend hints come from `cloud.google.com/app-protocols` when present. For Cloud Run load-balancer paths this can include forwarding-rule, URL-map, target-proxy, hostname, path, rewrite, and backend-service metadata. These details are informational; the current table and HTML reports keep the existing high-level internet exposure column.

Normal init containers do not inherit internet exposure. Sidecar-style init containers inherit exposure only when their container restart policy is `Always`.

## Known limits

The Kubernetes source currently supports Kubernetes workload image inventory, Trivy image vulnerability scans, EPSS/Vulnrichment enrichment, GKE exposure metadata, and AWS ALB exposure metadata. The Cloud Run source supports Cloud Run services and jobs, Cloud Run IAM ingress checks, and external Google Cloud load balancer/IAP checks for serverless NEG backends. The ECS source currently inventories active task definitions, scans container images, records task/container security metadata, supports ECR and task `repositoryCredentials` auth, classifies service/running-task runtime evidence, and maps internet-facing ELB target groups plus public task ENIs with open security-group ingress. EventBridge schedule discovery is not yet collected from AWS APIs, although the report model has a `scheduled` runtime status for that evidence. The image source supports direct image vulnerability scans without internet reachability analysis.

Run the standalone binary during development:

```sh
go run ./cmd/vdr --help
go run ./cmd/vdr k8s --help
go run ./cmd/vdr cloudrun --help
go run ./cmd/vdr ecs --help
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
