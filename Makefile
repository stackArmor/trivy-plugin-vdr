.PHONY: build test install-local chain-catalog

BINARY := vdr
PLUGIN_VERSION := $(shell awk '/^version:/ {print $$2; exit}' plugin.yaml)
VERSION_LDFLAG := -X github.com/stackArmor/trivy-plugin-vdr/internal/buildinfo.PluginVersion=$(PLUGIN_VERSION)

build:
	go build -ldflags "$(VERSION_LDFLAG)" -o $(BINARY) ./cmd/vdr

test:
	go test ./...

chain-catalog:
	@test -n "$(CAPEC)" || (echo "CAPEC=/path/to/capec_latest.zip is required" >&2; exit 2)
	@test -n "$(ATTACK)" || (echo "ATTACK=/path/to/enterprise-attack.json is required" >&2; exit 2)
	go run ./cmd/vdr-chain-catalog \
		--capec "$(CAPEC)" \
		--attack "$(ATTACK)" \
		--output internal/chaincatalog/data/catalog.json

install-local: build
	mkdir -p $(HOME)/.trivy/plugins/vdr
	cp plugin.yaml $(HOME)/.trivy/plugins/vdr/plugin.yaml
	cp $(BINARY) $(HOME)/.trivy/plugins/vdr/$(BINARY)
