# Kubernetes VDR Trivy Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Trivy plugin named `vdr` with a `k8s` subcommand that inventories images from the current Kubernetes context, scans each unique image once, and reports resource-level vulnerability findings enriched with EPSS, CISA Vulnrichment, and internet exposure metadata.

**Architecture:** The plugin is a standalone Go executable invoked by Trivy as `trivy vdr`. It dispatches source subcommands such as `trivy vdr k8s`; future sources will include `trivy vdr ecs` and `trivy vdr image`. The `k8s` source uses client-go to collect workload image inventory, invokes `trivy image --format json --scanners vuln` per unique image, enriches CVE findings from local EPSS and Vulnrichment caches, analyzes Ingress/Gateway exposure, and emits normalized JSON or table output. The implementation intentionally does not call `trivy k8s`, because Trivy Kubernetes summary output is not optimized for exact image-to-workload fanout.

**Tech Stack:** Go 1.23+, Trivy CLI subprocesses, Kubernetes client-go/dynamic client, JSON/YAML fixtures, Go unit tests, Trivy plugin manifest.

---

## File Structure

Create this structure:

```text
plugin.yaml
Makefile
go.mod
go.sum
cmd/vdr/main.go
internal/config/config.go
internal/config/config_test.go
internal/k8s/inventory.go
internal/k8s/inventory_test.go
internal/scanner/trivy.go
internal/scanner/trivy_test.go
internal/enrich/epss/epss.go
internal/enrich/epss/epss_test.go
internal/enrich/vulnrichment/vulnrichment.go
internal/enrich/vulnrichment/vulnrichment_test.go
internal/exposure/exposure.go
internal/exposure/exposure_test.go
internal/report/report.go
internal/report/report_test.go
internal/report/html.go
internal/report/html_test.go
internal/report/templates/default.html
internal/model/model.go
README.md
testdata/
```

---

### Task 1: Initial Plugin Scaffold, Shared Model, CLI Config

**Files:**
- Create: `plugin.yaml`
- Create: `Makefile`
- Create: `go.mod`
- Create: `cmd/vdr/main.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `internal/model/model.go`
- Create: `README.md`

- [ ] Initialize the Go module with `go mod init github.com/matthewvenne/trivy-plugin-vdr`.
- [ ] Create `plugin.yaml` for a Trivy plugin named `vdr`.
- [ ] Create shared model structs for inventory, resource refs, findings, EPSS, Vulnrichment, exposure, and reports.
- [ ] Write config tests for defaults, namespace parsing, invalid formats, invalid views, invalid severity, and timeout parsing.
- [ ] Implement CLI flags: `--namespace`, `--all-namespaces`, `--include-zero-daemonsets`, `--format`, `--view`, `--output`, `--cache-dir`, `--timeout`, `--min-severity`, `--min-epss`, `--skip-enrichment`, `--skip-exposure`, `--debug`.
- [ ] Create `cmd/vdr/main.go` that parses config and prints help.
- [ ] Add `Makefile` targets `build`, `test`, and `install-local`.
- [ ] Add README usage examples.
- [ ] Verify with `go test ./...`, `go run ./cmd/vdr --help`, and `go build -o vdr ./cmd/vdr`.
- [ ] Commit with `git commit -m "feat: scaffold vdr plugin"`.

---

### Task 1A: Pivot Scaffold to `trivy vdr k8s`

**Files:**
- Modify: `plugin.yaml`
- Modify: `Makefile`
- Modify: `README.md`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Rename: `cmd/k8s-vdr/main.go` to `cmd/vdr/main.go`
- Modify: `docs/superpowers/plans/2026-06-25-vdr-plugin.md`

- [ ] Rename the executable package path from `cmd/k8s-vdr` to `cmd/vdr`.
- [ ] Change the plugin manifest name from `k8s-vdr` to `vdr`.
- [ ] Change the plugin usage to `trivy vdr <source> [flags]`.
- [ ] Change the binary name and Makefile build target from `k8s-vdr` to `vdr`.
- [ ] Change the default cache directory from `$HOME/.cache/trivy/k8s-vdr` to `$HOME/.cache/trivy/vdr`.
- [ ] Refactor config parsing so root/global flags are shared and `k8s` is the first source subcommand.
- [ ] Keep current Kubernetes flags under `trivy vdr k8s`: `--namespace`, `--all-namespaces`, `--include-zero-daemonsets`, `--skip-exposure`.
- [ ] Keep global flags available to `trivy vdr k8s`: `--format`, `--view`, `--output`, `--cache-dir`, `--timeout`, `--min-severity`, `--min-epss`, `--skip-enrichment`, `--debug`.
- [ ] Reserve but do not implement future source subcommands `ecs` and `image`; they should return clear errors like `source "ecs" is not implemented yet` if invoked.
- [ ] Update README examples to use `trivy vdr k8s`.
- [ ] Update this implementation plan so future tasks refer to `cmd/vdr`, binary `vdr`, and `trivy vdr k8s`.
- [ ] Verify with `go test ./...`, `go run ./cmd/vdr --help`, `go run ./cmd/vdr k8s --help`, and `go build -o vdr ./cmd/vdr`.
- [ ] Commit with `git commit -m "feat: pivot plugin to vdr subcommands"`.

---

### Task 2: Kubernetes Inventory Collector

**Files:**
- Modify: `go.mod`
- Modify: `internal/model/model.go`
- Create: `internal/k8s/inventory.go`
- Create: `internal/k8s/inventory_test.go`

- [ ] Add Kubernetes dependencies: `k8s.io/client-go`, `k8s.io/api`, and `k8s.io/apimachinery`.
- [ ] Write tests using fake clients for Pods, Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs.
- [ ] Collect regular containers and init containers.
- [ ] Collect container security metadata for every regular and init container: privileged, Linux capabilities add/drop, seccomp profile, AppArmor profile, and readOnlyRootFilesystem.
- [ ] Store `containerType` as `container` or `initContainer`.
- [ ] Store init-container `restartPolicy` when present. Kubernetes sidecar-style init containers use `restartPolicy: Always`.
- [ ] Exclude DaemonSets with `status.desiredNumberScheduled == 0` by default.
- [ ] Include zero-desired DaemonSets when `--include-zero-daemonsets` is set.
- [ ] Deduplicate by exact full image reference, not stripped image name.
- [ ] Implement `NewForCurrentContext()` to load the default kubeconfig and return the current context name.
- [ ] Verify with `go test ./internal/k8s/...` and `go test ./...`.
- [ ] Commit with `git commit -m "feat: collect kubernetes image inventory"`.

---

### Task 2A: Workload Container Security Metadata

**Files:**
- Modify: `internal/model/model.go`
- Modify: `internal/k8s/inventory.go`
- Modify: `internal/k8s/inventory_test.go`

- [ ] Add a `ContainerSecurity` model attached to `ContainerImage` and/or `ResourceRef`.
- [ ] Capture `securityContext.privileged`.
- [ ] Capture `securityContext.capabilities.add` and `securityContext.capabilities.drop`.
- [ ] Capture `securityContext.readOnlyRootFilesystem`.
- [ ] Capture seccomp profile from container `securityContext.seccompProfile`, falling back to pod `securityContext.seccompProfile` when container value is unset.
- [ ] Capture AppArmor profile from container-level AppArmor fields when available in the Kubernetes API version, and from pod annotations such as `container.apparmor.security.beta.kubernetes.io/<container-name>`.
- [ ] Keep this metadata available to exposure/reporting so internet-exposed vulnerable resources can show container hardening context.
- [ ] Add tests for privileged containers, capabilities, readOnlyRootFilesystem, container seccomp, pod-level seccomp fallback, and AppArmor annotation lookup.
- [ ] Verify with `go test ./internal/k8s/...` and `go test ./...`.
- [ ] Commit with `git commit -m "feat: collect container security metadata"`.

---

### Task 3: Trivy Image Scanner and Result Normalization

**Files:**
- Modify: `internal/model/model.go`
- Create: `internal/scanner/trivy.go`
- Create: `internal/scanner/trivy_test.go`

- [ ] Write tests with a fake command runner.
- [ ] Verify command arguments include `image --image-src registry --format json --scanners vuln --timeout <timeout> <image>` by default.
- [ ] Parse Trivy JSON vulnerabilities into internal findings.
- [ ] Preserve image ref, package name, installed version, fixed version, severity, title, description, references, and status.
- [ ] Return useful errors on non-zero Trivy exits.
- [ ] Implement scan fanout over the deduped inventory image keys.
- [ ] Verify with `go test ./internal/scanner/...` and `go test ./...`.
- [ ] Commit with `git commit -m "feat: scan unique inventory images with trivy"`.

---

### Task 3A: Parallel Scanning and Disk-Pressure Cache Cleanup

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/scanner/trivy.go`
- Modify: `internal/scanner/trivy_test.go`
- Create: `internal/scanner/cache.go`
- Create: `internal/scanner/cache_test.go`
- Modify: `README.md`

- [ ] Add flags: `--image-src`, `--parallel-scans`, `--cache-cleanup`, `--cache-min-free-gb`, and `--cache-min-free-percent`.
- [ ] Defaults: `--image-src registry`, `--parallel-scans 5`, `--cache-cleanup auto`, `--cache-min-free-gb 10`, `--cache-min-free-percent 10`.
- [ ] Validate `parallel-scans > 0`, `cache-cleanup` in `auto|always|never`, `cache-min-free-gb >= 0`, and `cache-min-free-percent` between 0 and 100.
- [ ] Pass `--image-src <value>` to `trivy image`; default must force registry scanning.
- [ ] Update `ScanInventory` or add an options-based scanner to scan up to `parallel-scans` unique images concurrently while preserving deterministic final finding order by image ref.
- [ ] After each image scan completes, run cache cleanup only when policy says so:
  - `never`: do nothing.
  - `always`: run `trivy clean --scan-cache`.
  - `auto`: inspect free disk space for the configured Trivy cache directory or nearest existing parent; run `trivy clean --scan-cache` only when free space is below either configured threshold.
- [ ] Cache cleanup must be tested with fake disk-space and fake command runners; tests must not invoke real `trivy clean`.
- [ ] If cleanup fails after a successful image scan, surface a warning/diagnostic in a testable way without discarding the scan result. A later report task may expose warnings.
- [ ] Verify with `go test ./internal/scanner/...`, `go test ./internal/config/...`, and `go test ./...`.
- [ ] Commit with `git commit -m "feat: scan images concurrently with cache cleanup"`.

---

### Task 4: EPSS and CISA Vulnrichment Enrichment

**Files:**
- Modify: `internal/model/model.go`
- Create: `internal/enrich/epss/epss.go`
- Create: `internal/enrich/epss/epss_test.go`
- Create: `internal/enrich/vulnrichment/vulnrichment.go`
- Create: `internal/enrich/vulnrichment/vulnrichment_test.go`

- [ ] Implement EPSS cache at `<cache-dir>/epss/epss.csv`.
- [ ] Fetch `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` when cache is missing or older than 24 hours.
- [ ] Parse CVE score, percentile, model version, and score date.
- [ ] Implement Vulnrichment cache at `<cache-dir>/vulnrichment/<year>/<bucket>/CVE-YYYY-NNNN.json`.
- [ ] Fetch raw files from `https://raw.githubusercontent.com/cisagov/vulnrichment/develop/<year>/<bucket>/CVE-YYYY-NNNN.json` on cache miss.
- [ ] Extract CISA ADP SSVC options: `Exploitation`, `Automatable`, and `Technical Impact`.
- [ ] Treat missing Vulnrichment files as non-fatal.
- [ ] Add a 7-day TTL for cached Vulnrichment CVE JSON files; refresh files older than 7 days.
- [ ] Add a global `--refresh-enrichment` flag that forces both EPSS and Vulnrichment to refetch regardless of TTL.
- [ ] Forced refresh must still use safe temp-file validation and atomic rename, and must keep usable existing cache data when a refresh fails.
- [ ] Verify with `go test ./internal/enrich/...` and `go test ./...`.
- [ ] Commit with `git commit -m "feat: enrich findings with epss and vulnrichment"`.

---

### Task 4A: Enrichment TTL and Forced Refresh

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/enrich/epss/epss.go`
- Modify: `internal/enrich/epss/epss_test.go`
- Modify: `internal/enrich/vulnrichment/vulnrichment.go`
- Modify: `internal/enrich/vulnrichment/vulnrichment_test.go`
- Modify: `README.md`

- [ ] Add config flag `--refresh-enrichment`.
- [ ] EPSS keeps 24-hour TTL unless `--refresh-enrichment` is set.
- [ ] Vulnrichment gets 7-day TTL unless `--refresh-enrichment` is set.
- [ ] Existing Vulnrichment cache files younger than 7 days are used without network fetch.
- [ ] Existing Vulnrichment cache files older than 7 days are refreshed.
- [ ] `--refresh-enrichment` forces EPSS and Vulnrichment refresh attempts even when cache files are fresh.
- [ ] Failed forced refresh keeps and uses existing valid cache where possible.
- [ ] Tests must use local/httptest servers and must not hit real network.
- [ ] Verify with `go test ./internal/enrich/...`, `go test ./internal/config/...`, and `go test ./...`.
- [ ] Commit with `git commit -m "feat: add enrichment refresh controls"`.

---

### Task 5: Exposure Analyzer for GKE and AWS Ingress/Gateway

**Files:**
- Modify: `internal/model/model.go`
- Create: `internal/exposure/exposure.go`
- Create: `internal/exposure/exposure_test.go`

- [ ] Write tests for GKE Gateway external/internal classes.
- [ ] Write tests for GKE `GCPBackendPolicy.spec.default.iap.enabled=true`.
- [ ] Write tests for GKE Ingress `gce` and `gce-internal`.
- [ ] Write tests for GKE Ingress `BackendConfig.spec.iap.enabled=true`.
- [ ] Write tests for AWS ALB Ingress annotation `alb.ingress.kubernetes.io/scheme=internet-facing`.
- [ ] Write tests for AWS `IngressClassParams.spec.scheme=internet-facing`.
- [ ] Write tests for AWS ALB auth annotations `oidc` and `cognito`.
- [ ] Write tests for AWS Gateway `LoadBalancerConfiguration.spec.scheme=internet-facing`.
- [ ] Resolve Gateway `HTTPRoute`, `GRPCRoute`, `TCPRoute`, and `TLSRoute` backendRefs to Services.
- [ ] Resolve Ingress backend Services to selected workloads through Service selectors.
- [ ] Mark normal init containers as `internetAccessible=false` even when their parent workload is exposed.
- [ ] Mark sidecar-style init containers as eligible to inherit parent workload exposure only when their container `restartPolicy` is `Always`.
- [ ] Include evidence strings explaining why exposure was or was not inherited for init containers.
- [ ] For GKE Gateway, mark internet accessible only when route is public and no target `GCPBackendPolicy` enables IAP.
- [ ] For AWS ALB, mark protected when ALB auth is `oidc` or `cognito`; do not call it IAP.
- [ ] Verify with `go test ./internal/exposure/...` and `go test ./...`.
- [ ] Commit with `git commit -m "feat: analyze ingress and gateway exposure"`.

---

### Task 6: Report Output, Orchestration, Integration Docs

**Files:**
- Modify: `cmd/vdr/main.go`
- Modify: `README.md`
- Create: `internal/report/report.go`
- Create: `internal/report/report_test.go`
- Create: `internal/report/html.go`
- Create: `internal/report/html_test.go`
- Create: `internal/report/templates/default.html`

- [ ] Write report tests for finding-centric JSON.
- [ ] Write report tests for resource-centric JSON.
- [ ] Write report tests for severity and EPSS filters.
- [ ] Write table output tests.
- [ ] Write HTML report tests.
- [ ] Implement default finding-centric output with `affectedResources`.
- [ ] Implement `--view resources`.
- [ ] Add optional HTML output flags: `--html-output` and `--html-template`.
- [ ] Embed a default HTML template in the Go package.
- [ ] Custom template path overrides the embedded template when `--html-template` is supplied.
- [ ] The HTML report should summarize the entire scan and include filter controls for namespace, internet exposed, automatable, exploitation status, EPSS score, and technical impact.
- [ ] Use `/Users/matthewvenne/Downloads/rally-security-dashboard.html` only as a visual/functionality guide; do not require that file at runtime.
- [ ] HTML generation must be standalone with embedded JSON data and no required remote CDN dependency.
- [ ] Wire main orchestration: config, inventory, scan, enrichment, exposure, report.
- [ ] Document cache behavior, exposure rules, init-container exposure rules, and known limits.
- [ ] Verify with `go test ./...`, `go build -o vdr ./cmd/vdr`, `./vdr --help`, and `./vdr k8s --help`.
- [ ] Commit with `git commit -m "feat: emit enriched k8s vdr reports"`.

---

## Final Verification

Run:

```bash
go test ./...
go build -o vdr ./cmd/vdr
trivy plugin install .
trivy vdr --help
trivy vdr k8s --help
trivy vdr k8s --namespace default --skip-enrichment --skip-exposure --format json --output /tmp/vdr-k8s.json --html-output /tmp/vdr-k8s.html
```

Expected:

- Each unique image is scanned once.
- Images are scanned with `--image-src registry` by default and up to 5 image scans run concurrently by default.
- Trivy scan cache is cleaned only under configured disk-pressure policy unless cleanup is disabled or forced.
- Findings list every Kubernetes workload/container using that image.
- Workload metadata includes privileged status, Linux capabilities, seccomp/AppArmor profile, and readOnlyRootFilesystem when configured.
- EPSS fields are present when available.
- EPSS cache uses a 24-hour TTL, Vulnrichment cache uses a 7-day TTL, and `--refresh-enrichment` forces both refresh paths.
- Vulnrichment fields are present when available.
- HTML report generation works with the embedded default template and optional custom template.
- Public exposure is set only for public route paths without provider-specific access protection.
- Normal init containers are not internet accessible.
- Init containers with `restartPolicy: Always` can inherit parent workload exposure as Kubernetes sidecars.
- Zero-desired DaemonSets are excluded by default and included with `--include-zero-daemonsets`.
