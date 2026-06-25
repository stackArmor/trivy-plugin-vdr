# vdr

`vdr` is a Trivy plugin for vulnerability detection and response workflows. The first source is Kubernetes: `trivy vdr k8s` will inventory workload images from the current Kubernetes context, scan each unique full image reference once, and report findings back against the resources and containers that use each image.

This scaffold includes the plugin manifest, CLI configuration, shared report models, and local build targets. Kubernetes collection, Trivy scan orchestration, enrichment, exposure analysis, and report rendering are implemented in later tasks.

## Features

- Trivy plugin entrypoint named `vdr`.
- Kubernetes source subcommand named `k8s`.
- Reserved future source subcommands named `ecs` and `image`.
- JSON and table output mode flags.
- Finding-centric and resource-centric view flags.
- Namespace selection, all-namespace scanning, cache, timeout, severity, EPSS, enrichment, exposure, and debug flags.
- Shared JSON model for inventory, findings, EPSS, CISA Vulnrichment, exposure, access protection, reports, and summaries.

## Usage

```sh
trivy vdr --help
trivy vdr k8s --help
trivy vdr k8s --namespace default --format json
trivy vdr k8s --all-namespaces --min-severity HIGH --min-epss 0.5
trivy vdr k8s --view resources --output vdr-k8s.json
trivy vdr k8s --skip-enrichment --skip-exposure --debug
```

Future source commands are reserved but not implemented yet: `trivy vdr ecs` and `trivy vdr image`.

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
