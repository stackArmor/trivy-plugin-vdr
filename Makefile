.PHONY: build test install-local

BINARY := k8s-vdr

build:
	go build -o $(BINARY) ./cmd/k8s-vdr

test:
	go test ./...

install-local: build
	mkdir -p $(HOME)/.trivy/plugins/k8s-vdr
	cp plugin.yaml $(HOME)/.trivy/plugins/k8s-vdr/plugin.yaml
	cp $(BINARY) $(HOME)/.trivy/plugins/k8s-vdr/$(BINARY)
