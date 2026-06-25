# vdr

`vdr` is a Trivy plugin for vulnerability detection and response workflows. The first source is Kubernetes: `trivy vdr k8s` will inventory workload images from the current Kubernetes context, scan each unique full image reference once, and report findings back against the resources and containers that use each image.

This scaffold includes the plugin manifest, CLI configuration, shared report models, and local build targets. Kubernetes collection, Trivy scan orchestration, enrichment, exposure analysis, and report rendering are implemented in later tasks.

## Features

- Trivy plugin entrypoint named `vdr`.
- Kubernetes source subcommand named `k8s`.
- Reserved future source subcommands named `ecs` and `image`.
- JSON and table output mode flags.
- Finding-centric and resource-centric view flags.
- Namespace selection, all-namespace scanning, image source, parallel scanning, cache cleanup, timeout, severity, EPSS, enrichment, exposure, and debug flags.
- Shared JSON model for inventory, findings, EPSS, CISA Vulnrichment, exposure, access protection, reports, and summaries.

## Usage

```sh
trivy vdr --help
trivy vdr k8s --help
trivy vdr k8s --namespace default --format json
trivy vdr k8s --all-namespaces --min-severity HIGH --min-epss 0.5
trivy vdr k8s --view resources --output vdr-k8s.json
trivy vdr k8s --image-src registry --parallel-scans 5
trivy vdr k8s --skip-enrichment --skip-exposure --debug
trivy vdr k8s --refresh-enrichment
```

Future source commands are reserved but not implemented yet: `trivy vdr ecs` and `trivy vdr image`.

## Enrichment cache

EPSS and CISA Vulnrichment data are cached under `--cache-dir`. EPSS cache files are refreshed after 24 hours. Vulnrichment cache files are refreshed after 7 days.

Use `--refresh-enrichment` to force EPSS and Vulnrichment refresh attempts even when cached files are still fresh. If a forced refresh fails and an existing cache file is still readable and valid, `vdr` keeps and uses the cached data.

## Image scanning and Trivy cache cleanup

`vdr` scans each unique full image reference once and fans findings back out to every Kubernetes resource that uses that image. Scan results are returned in deterministic image-reference order, independent of the order in which concurrent scans finish.

Scan defaults:

- `--image-src registry`
- `--parallel-scans 5`
- `--cache-cleanup auto`
- `--cache-min-free-gb 10`
- `--cache-min-free-percent 10`

The Trivy image command uses `trivy image --image-src <value> --format json --scanners vuln --timeout <timeout> <image>`. The default `--image-src registry` forces registry scanning.

Cache cleanup runs after each successful image scan:

- `--cache-cleanup never` skips cleanup.
- `--cache-cleanup always` runs `trivy clean --scan-cache`.
- `--cache-cleanup auto` checks free disk space for the configured Trivy cache directory, or the nearest existing parent directory, and runs `trivy clean --scan-cache` when free space is below either `--cache-min-free-gb` or `--cache-min-free-percent`.

If cleanup fails after an image scan succeeds, the scan result is kept and a warning is recorded for later reporting.

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
