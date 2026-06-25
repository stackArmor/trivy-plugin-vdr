.PHONY: build test install-local

BINARY := vdr

build:
	go build -o $(BINARY) ./cmd/vdr

test:
	go test ./...

install-local: build
	mkdir -p $(HOME)/.trivy/plugins/vdr
	cp plugin.yaml $(HOME)/.trivy/plugins/vdr/plugin.yaml
	cp $(BINARY) $(HOME)/.trivy/plugins/vdr/$(BINARY)
