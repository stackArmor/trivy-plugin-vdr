# Kubernetes VDR Trivy Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Trivy plugin named `k8s-vdr` that inventories images from the current Kubernetes context, scans each unique image once, and reports resource-level vulnerability findings enriched with EPSS, CISA Vulnrichment, and internet exposure metadata.

**Architecture:** The plugin is a standalone Go executable invoked by Trivy as `trivy k8s-vdr`. It uses client-go to collect workload image inventory, invokes `trivy image --format json --scanners vuln` per unique image, enriches CVE findings from local EPSS and Vulnrichment caches, analyzes Ingress/Gateway exposure, and emits normalized JSON or table output. The implementation intentionally does not call `trivy k8s`, because Trivy Kubernetes summary output is not optimized for exact image-to-workload fanout.

**Tech Stack:** Go 1.23+, Trivy CLI subprocesses, Kubernetes client-go/dynamic client, JSON/YAML fixtures, Go unit tests, Trivy plugin manifest.

---

## File Structure

Create this structure:

```text
plugin.yaml
Makefile
go.mod
go.sum
cmd/k8s-vdr/main.go
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
internal/model/model.go
README.md
testdata/
```

---

### Task 1: Plugin Scaffold, Shared Model, CLI Config

**Files:**
- Create: `plugin.yaml`
- Create: `Makefile`
- Create: `go.mod`
- Create: `cmd/k8s-vdr/main.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `internal/model/model.go`
- Create: `README.md`

- [ ] Initialize the Go module with `go mod init github.com/matthewvenne/trivy-plugin-k8s-vdr`.
- [ ] Create `plugin.yaml` for a Trivy plugin named `k8s-vdr`.
- [ ] Create shared model structs for inventory, resource refs, findings, EPSS, Vulnrichment, exposure, and reports.
- [ ] Write config tests for defaults, namespace parsing, invalid formats, invalid views, invalid severity, and timeout parsing.
- [ ] Implement CLI flags: `--namespace`, `--all-namespaces`, `--include-zero-daemonsets`, `--format`, `--view`, `--output`, `--cache-dir`, `--timeout`, `--min-severity`, `--min-epss`, `--skip-enrichment`, `--skip-exposure`, `--debug`.
- [ ] Create `cmd/k8s-vdr/main.go` that parses config and prints help.
- [ ] Add `Makefile` targets `build`, `test`, and `install-local`.
- [ ] Add README usage examples.
- [ ] Verify with `go test ./...`, `go run ./cmd/k8s-vdr --help`, and `go build -o k8s-vdr ./cmd/k8s-vdr`.
- [ ] Commit with `git commit -m "feat: scaffold k8s-vdr plugin"`.

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
- [ ] Store `containerType` as `container` or `initContainer`.
- [ ] Store init-container `restartPolicy` when present. Kubernetes sidecar-style init containers use `restartPolicy: Always`.
- [ ] Exclude DaemonSets with `status.desiredNumberScheduled == 0` by default.
- [ ] Include zero-desired DaemonSets when `--include-zero-daemonsets` is set.
- [ ] Deduplicate by exact full image reference, not stripped image name.
- [ ] Implement `NewForCurrentContext()` to load the default kubeconfig and return the current context name.
- [ ] Verify with `go test ./internal/k8s/...` and `go test ./...`.
- [ ] Commit with `git commit -m "feat: collect kubernetes image inventory"`.

---

### Task 3: Trivy Image Scanner and Result Normalization

**Files:**
- Modify: `internal/model/model.go`
- Create: `internal/scanner/trivy.go`
- Create: `internal/scanner/trivy_test.go`

- [ ] Write tests with a fake command runner.
- [ ] Verify command arguments include `image --format json --scanners vuln --timeout <timeout> <image>`.
- [ ] Parse Trivy JSON vulnerabilities into internal findings.
- [ ] Preserve image ref, package name, installed version, fixed version, severity, title, description, references, and status.
- [ ] Return useful errors on non-zero Trivy exits.
- [ ] Implement scan fanout over the deduped inventory image keys.
- [ ] Verify with `go test ./internal/scanner/...` and `go test ./...`.
- [ ] Commit with `git commit -m "feat: scan unique inventory images with trivy"`.

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
- [ ] Verify with `go test ./internal/enrich/...` and `go test ./...`.
- [ ] Commit with `git commit -m "feat: enrich findings with epss and vulnrichment"`.

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
- Modify: `cmd/k8s-vdr/main.go`
- Modify: `README.md`
- Create: `internal/report/report.go`
- Create: `internal/report/report_test.go`

- [ ] Write report tests for finding-centric JSON.
- [ ] Write report tests for resource-centric JSON.
- [ ] Write report tests for severity and EPSS filters.
- [ ] Write table output tests.
- [ ] Implement default finding-centric output with `affectedResources`.
- [ ] Implement `--view resources`.
- [ ] Wire main orchestration: config, inventory, scan, enrichment, exposure, report.
- [ ] Document cache behavior, exposure rules, init-container exposure rules, and known limits.
- [ ] Verify with `go test ./...`, `go build -o k8s-vdr ./cmd/k8s-vdr`, and `./k8s-vdr --help`.
- [ ] Commit with `git commit -m "feat: emit enriched k8s vdr reports"`.

---

## Final Verification

Run:

```bash
go test ./...
go build -o k8s-vdr ./cmd/k8s-vdr
trivy plugin install .
trivy k8s-vdr --help
trivy k8s-vdr --namespace default --skip-enrichment --skip-exposure --format json --output /tmp/k8s-vdr.json
```

Expected:

- Each unique image is scanned once.
- Findings list every Kubernetes workload/container using that image.
- EPSS fields are present when available.
- Vulnrichment fields are present when available.
- Public exposure is set only for public route paths without provider-specific access protection.
- Normal init containers are not internet accessible.
- Init containers with `restartPolicy: Always` can inherit parent workload exposure as Kubernetes sidecars.
- Zero-desired DaemonSets are excluded by default and included with `--include-zero-daemonsets`.
