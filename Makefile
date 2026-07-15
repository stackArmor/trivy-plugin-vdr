.PHONY: build test install-local

BINARY := vdr
PLUGIN_VERSION := $(shell awk '/^version:/ {print $$2; exit}' plugin.yaml)
VERSION_LDFLAG := -X github.com/stackArmor/trivy-plugin-vdr/internal/buildinfo.PluginVersion=$(PLUGIN_VERSION)

build:
	go build -ldflags "$(VERSION_LDFLAG)" -o $(BINARY) ./cmd/vdr

test:
	go test ./...

install-local: build
	mkdir -p $(HOME)/.trivy/plugins/vdr
	cp plugin.yaml $(HOME)/.trivy/plugins/vdr/plugin.yaml
	cp $(BINARY) $(HOME)/.trivy/plugins/vdr/$(BINARY)
