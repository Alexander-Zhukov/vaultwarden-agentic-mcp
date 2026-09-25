GO ?= go
BIN := vaultwarden-agentic-mcp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
PKG := ./...
BW_IMAGE := vaultwarden-agentic-mcp-bw:2026.6.0
VWTEST_DIR ?= $(CURDIR)/.vwtest

.PHONY: help build run token fmt fmt-check lint vet test test-race cover cover-gate vuln tidy-check check-all \
	test-integration vw-up vw-down bw-image clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Compile the binary into ./bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/$(BIN) ./cmd/$(BIN)

run: ## Run the service with the local .env file
	set -a && . ./.env && set +a && $(GO) run ./cmd/$(BIN)

token: ## Print a new client token and the hash to configure for it
	$(GO) run ./cmd/$(BIN) token

fmt: ## Format the tree
	golangci-lint fmt

fmt-check: ## Fail if the tree is not formatted
	golangci-lint fmt --diff

lint: ## Run the linters, integration tests included
	golangci-lint run
	golangci-lint run --build-tags integration

vet: ## Run go vet
	$(GO) vet $(PKG)
	$(GO) vet -tags integration $(PKG)

test: ## Run unit tests
	$(GO) test $(PKG) -count=1 -shuffle=on

test-race: ## Run unit tests with the race detector
	$(GO) test $(PKG) -race -count=1 -shuffle=on

cover: ## Report unit test coverage
	$(GO) test $(PKG) -covermode=atomic -coverprofile=coverage.out -count=1
	$(GO) tool cover -func=coverage.out | tail -1

vuln: ## Scan dependencies for reachable vulnerabilities
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.7.0 $(PKG)

tidy-check: ## Fail if go.mod/go.sum are out of sync
	$(GO) mod tidy -diff

COVERAGE_MIN ?= 80

cover-gate: ## Fail when unit coverage falls under COVERAGE_MIN
	$(GO) test $(PKG) -race -shuffle=on -count=1 -covermode=atomic -coverpkg=./internal/... -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | awk -v min=$(COVERAGE_MIN) \
		'/^total:/ { sub("%", "", $$3); print "coverage " $$3 "%"; if ($$3 + 0 < min + 0) exit 1 }'

check-all: build fmt-check vet lint tidy-check cover-gate vuln ## Everything CI runs

bw-image: ## Build the official Bitwarden CLI image the integration suite checks against
	docker build -q -t $(BW_IMAGE) test/bw

vw-up: ## Start a throwaway Vaultwarden with TLS
	VWTEST_DIR=$(VWTEST_DIR) sh test/vw-up.sh

vw-down: ## Remove the throwaway Vaultwarden
	docker rm -f vaultwarden-agentic-mcp-test

test-integration: bw-image ## Run the suite against a real Vaultwarden and the official CLI
	eval "$$(VWTEST_DIR=$(VWTEST_DIR) sh test/vw-up.sh)" && \
	SSL_CERT_FILE=$$VWTEST_CA VWTEST_BW_IMAGE=$(BW_IMAGE) \
	$(GO) test ./... -tags integration -race -count=1 -v -run Live
	docker rm -f vaultwarden-agentic-mcp-test

clean: ## Remove build artefacts
	rm -rf bin coverage.out $(VWTEST_DIR)
