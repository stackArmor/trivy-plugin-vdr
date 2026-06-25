# k8s-vdr

`k8s-vdr` is a Trivy plugin for Kubernetes vulnerability detection and response workflows. It will inventory workload images from the current Kubernetes context, scan each unique full image reference once, and report findings back against the resources and containers that use each image.

This scaffold includes the plugin manifest, CLI configuration, shared report models, and local build targets. Kubernetes collection, Trivy scan orchestration, enrichment, exposure analysis, and report rendering are implemented in later tasks.

## Features

- Trivy plugin entrypoint named `k8s-vdr`.
- JSON and table output mode flags.
- Finding-centric and resource-centric view flags.
- Namespace selection, all-namespace scanning, cache, timeout, severity, EPSS, enrichment, exposure, and debug flags.
- Shared JSON model for inventory, findings, EPSS, CISA Vulnrichment, exposure, access protection, reports, and summaries.

## Usage

```sh
trivy k8s-vdr --help
trivy k8s-vdr --namespace default --format json
trivy k8s-vdr --all-namespaces --min-severity HIGH --min-epss 0.5
trivy k8s-vdr --view resources --output k8s-vdr.json
trivy k8s-vdr --skip-enrichment --skip-exposure --debug
```

Run the standalone binary during development:

```sh
go run ./cmd/k8s-vdr --help
go build -o k8s-vdr ./cmd/k8s-vdr
```

## Development

```sh
make test
make build
make install-local
```
