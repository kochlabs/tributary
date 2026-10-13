export PATH := /usr/local/go/bin:/usr/local/node/bin:$(PATH)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all web build test fuzz bench dev install clean

all: web build

web:
	cd web && npm ci --no-audit --no-fund && npx ng build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/ ./cmd/...

test:
	go vet ./...
	go test ./...

fuzz:
	go test ./internal/decode -run XXX -fuzz FuzzDecode -fuzztime 60s

bench:
	go test ./internal/decode -run XXX -bench . -benchtime 3s

# Backend on :8443 with a scratch data dir; run `cd web && npx ng serve` for UI hot reload (proxies /api).
dev: build
	NFA_ADMIN_PASSWORD=admin12345 ./bin/nfad -data ./.devdata -listen :8443

install: all
	sudo deploy/install.sh

clean:
	rm -rf bin .devdata
