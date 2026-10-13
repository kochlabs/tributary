export PATH := /usr/local/go/bin:/usr/local/node/bin:$(PATH)

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
DIST     := dist/tributary-$(VERSION)-linux-amd64
URL      ?= https://localhost

.DEFAULT_GOAL := help
.PHONY: help all web build test check fmt fuzz bench serve dev install deploy status logs dist demo-start demo-stop clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: web build ## Build the web UI and both binaries

# ---- build ----

web/node_modules/.stamp: web/package-lock.json
	cd web && npm ci --no-audit --no-fund
	@touch $@

web: web/node_modules/.stamp ## Build the web UI into the embedded dist directory
	cd web && npx ng build

build: ## Build nfad and flowgen into bin/ (embeds the last web build)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

# ---- quality ----

test: ## Run go vet and the Go tests
	go vet ./...
	go test ./...

fmt: ## Format Go sources
	gofmt -w cmd internal

check: web/node_modules/.stamp ## Pre-commit check: gofmt, vet, tests and a web build
	@unformatted=$$(gofmt -l cmd internal); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	$(MAKE) --no-print-directory test
	cd web && npx ng build

fuzz: ## Fuzz the flow decoders for 60s
	go test ./internal/decode -run XXX -fuzz FuzzDecode -fuzztime 60s

bench: ## Benchmark NetFlow v9 decoding
	go test ./internal/decode -run XXX -bench . -benchtime 3s

# ---- development ----

dev: build ## Run the backend on :8443 with a scratch data dir (admin / admin12345)
	NFA_ADMIN_PASSWORD=admin12345 ./bin/nfad -data ./.devdata -listen :8443

serve: web/node_modules/.stamp ## UI with hot reload on :4200, proxying /api to :8443
	cd web && npx ng serve

# ---- this appliance ----

install: all ## Full install or upgrade via deploy/install.sh (ClickHouse, units, helper)
	sudo deploy/install.sh

deploy: all ## Rebuild, replace the running binary and helper, restart, health-check
	sudo install -m 755 bin/nfad /usr/local/bin/nfad
	sudo install -m 755 deploy/admin/tributary-admin.sh /usr/local/lib/tributary/
	sudo install -m 644 deploy/admin/services.conf /usr/local/lib/tributary/
	sudo systemctl restart nfad
	@for i in $$(seq 30); do curl -sfk $(URL)/healthz >/dev/null && { echo "nfad $(VERSION) is up"; exit 0; }; sleep 1; done; \
	  echo "nfad did not become healthy; see 'make logs'"; exit 1

status: ## Show appliance services and health
	@systemctl --no-pager --lines=0 status nfad clickhouse-server tributary-admin.path tributary-update-check.timer || true
	@curl -sfk $(URL)/healthz && echo || echo "health check failed"

logs: ## Follow the nfad log
	sudo journalctl -fu nfad

demo-start: build ## Send simulated flows from four fake exporters (stop with demo-stop)
	sudo systemd-run --unit nfa-demo --description "Tributary demo traffic" $(CURDIR)/bin/flowgen -rate 120

demo-stop: ## Stop simulated flows
	sudo systemctl stop nfa-demo

# ---- release ----

dist: all ## Package binaries, deploy scripts and README into dist/*.tar.gz
	rm -rf $(DIST)
	mkdir -p $(DIST)/bin
	cp bin/nfad bin/flowgen $(DIST)/bin/
	cp -r deploy README.md $(DIST)/
	tar -C dist -czf $(DIST).tar.gz $(notdir $(DIST))
	rm -rf $(DIST)
	@echo "$(DIST).tar.gz  (install: tar xzf, then sudo deploy/install.sh)"

clean: ## Remove build outputs and the dev data dir
	rm -rf bin dist .devdata
