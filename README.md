# vdr

`vdr` is a Trivy plugin for vulnerability detection and response workflows. The first source is Kubernetes: `trivy vdr k8s` will inventory workload images from the current Kubernetes context, scan each unique full image reference once, and report findings back against the resources and containers that use each image.

The Kubernetes source collects workload image inventory, scans each unique image with Trivy, enriches CVEs with EPSS and CISA Vulnrichment data, analyzes public ingress/gateway exposure, and emits JSON, table, and optional standalone HTML reports.

## Features

- Trivy plugin entrypoint named `vdr`.
- Kubernetes source subcommand named `k8s`.
- Reserved future source subcommands named `ecs` and `image`.
- JSON and table output mode flags.
- Finding-centric and resource-centric view flags.
- Optional standalone HTML report with filter controls for namespace, internet exposure, automatable, exploitation status, EPSS score, and technical impact.
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
trivy vdr k8s --quiet
trivy vdr k8s --namespace default --output vdr-k8s.json --html-output vdr-k8s.html
trivy vdr k8s --html-output vdr-k8s.html --html-template custom-template.html
```

Future source commands are reserved but not implemented yet: `trivy vdr ecs` and `trivy vdr image`.

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

This adds one RBAC requirement beyond inventory collection: `get` on `secrets` in the scanned namespaces. The optional `gcloud` and `aws` CLIs must be installed and authenticated on the machine running the plugin.

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

JSON output defaults to a finding-centric report. Each finding includes `affectedResources` so a deduplicated image scan can still be traced back to every Kubernetes resource and container using that image.

Use `--view resources` for resource-centric JSON or table output. Resource reports include the matching container image inventory, container security metadata, resource labels, exposure state, and findings scoped to that resource/container.

Use `--html-output <path>` to write a standalone HTML report. The default HTML template is embedded in the plugin and requires no remote CDN assets. It supports light/dark mode (following the OS preference, with a toggle that is remembered) and click-to-sort on every column (severity sorts by rank, EPSS numerically). Use `--html-template <path>` to override it with a local Go `html/template`; the template receives `.Report` and `.ReportJSON`.

## Exposure rules

Exposure analysis is intentionally conservative:

- GKE Gateway is public only for known external GKE Gateway classes.
- GKE Gateway backends protected by `GCPBackendPolicy.spec.default.iap.enabled=true` are not marked internet accessible.
- GKE Ingress is public for `gce` and not public for `gce-internal`.
- GKE Ingress BackendConfig IAP is resolved through the Service port selected by the Ingress backend. Per-port BackendConfig mappings override `default`.
- AWS ALB Ingress and Gateway are public only when the ALB scheme/load balancer configuration is internet-facing.
- AWS ALB `oidc` and `cognito` auth are recorded as AWS access protection. They are not reported as GCP IAP.
- Gateway cross-namespace backend references require a matching `ReferenceGrant`.

Normal init containers do not inherit internet exposure. Sidecar-style init containers inherit exposure only when their container restart policy is `Always`.

## Known limits

The Kubernetes source currently supports Kubernetes workload image inventory, Trivy image vulnerability scans, EPSS/Vulnrichment enrichment, GKE exposure metadata, and AWS ALB exposure metadata. The `ecs` and `image` sources are reserved for future implementation.

Run the standalone binary during development:

```sh
go run ./cmd/vdr --help
go run ./cmd/vdr k8s --help
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
