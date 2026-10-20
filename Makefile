# Use local toolchains when installed there (CI provides its own).
empty    :=
space    := $(empty) $(empty)
export PATH := $(subst $(space),:,$(strip $(wildcard /usr/local/go/bin /usr/local/node/bin) $(PATH)))

# Package versions must increase with every commit for apt to see upgrades.
# A clean checkout of a release tag (v1.2.3) builds as 1.2.3; anything else as
# <latest release>+git<commit count>.<sha>, with .dirty for uncommitted
# changes (0.1.0 before the first release). Release builds set VERSION.
SHA      := $(shell git rev-parse --short HEAD 2>/dev/null || echo 0)
COUNT    := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
DIRTY    := $(shell git diff --quiet HEAD 2>/dev/null || echo .dirty)
TAG      := $(shell git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null)
LASTTAG  := $(shell git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null)
BASE     := $(or $(patsubst v%,%,$(LASTTAG)),0.1.0)
VERSION  ?= $(if $(and $(TAG),$(if $(DIRTY),,clean)),$(patsubst v%,%,$(TAG)),$(BASE)+git$(COUNT).$(SHA)$(DIRTY))
SOURCE_URL ?= https://github.com/kochlabs/tributary
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.sourceURL=$(SOURCE_URL)
DEB      := dist/tributary_$(VERSION)_amd64.deb
URL      ?= https://localhost

.DEFAULT_GOAL := help
.PHONY: help all web build brand notices i18n deb test check fmt fuzz bench serve dev install deploy status logs demo-start demo-stop clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: web build ## Build the web UI and both binaries

# ---- build ----

web/node_modules/.stamp: web/package-lock.json
	cd web && npm ci --no-audit --no-fund
	@touch $@

web: web/node_modules/.stamp ## Build the web UI into the embedded dist directory
	install -m 644 LICENSE web/public/LICENSE.txt
	install -m 644 THIRD_PARTY_NOTICES.md web/public/THIRD_PARTY_NOTICES.txt
	cd web && npx ng build
	@touch internal/webui/dist/.gitkeep # the build empties the directory; Go needs it present

build: ## Build nfad and flowgen into bin/ (embeds the last web build)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

brand: ## Regenerate web logos, favicon and login background from assets/brand/
	python3 -I assets/brand/build.py

i18n: web/node_modules/.stamp ## Extract UI text into web/src/locale/messages.xlf (the source for translations)
	cd web && npx ng extract-i18n

notices: web/node_modules/.stamp ## Regenerate THIRD_PARTY_NOTICES.md from the Go modules and web packages in use
	python3 -I scripts/third_party_notices.py

deb: all ## Build the Debian package into dist/
	deploy/deb/build.sh $(VERSION)

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
	@touch internal/webui/dist/.gitkeep

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

install: deb ## Install or upgrade from the package (adds the ClickHouse repo if needed)
	sudo deploy/install.sh $(DEB)

deploy: deb ## Build the package and install it on this box, then health-check
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall $(CURDIR)/$(DEB)
	@for i in $$(seq 30); do curl -sfk $(URL)/healthz >/dev/null && { echo "tributary $(VERSION) is up"; exit 0; }; sleep 1; done; \
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

clean: ## Remove build outputs and the dev data dir
	rm -rf bin dist .devdata
