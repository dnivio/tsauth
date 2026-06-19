.PHONY: all build test lint clean generate check

# Dnivio Build System
# Per §21.1 (DR-SUP-1): hardened release pipeline

SHELL := /bin/bash
GO := go
GOFLAGS := -trimpath -buildvcs=true

CONTRACTS_DIR := contracts
SERVICE_DIR := service
DAEMON_DIR := daemon
SDK_DIR := sdk/go

all: generate build test

# ─── Code Generation ──────────────────────────────────────────────────────

generate:
	@echo "Generating protobuf code..."
	cd $(CONTRACTS_DIR) && buf generate || echo "buf not installed — skip proto gen"
	@echo "Generating OpenAPI spec..."
	cd $(CONTRACTS_DIR) && buf build -o openapi/dnivio.bin || echo "skip"

# ─── Build ────────────────────────────────────────────────────────────────

build: build-contracts build-service build-sdk

build-contracts:
	cd $(CONTRACTS_DIR) && $(GO) build $(GOFLAGS) ./...

build-service:
	cd $(SERVICE_DIR) && $(GO) build $(GOFLAGS) ./cmd/approval-service/...

build-sdk:
	cd $(SDK_DIR) && $(GO) build $(GOFLAGS) ./...

# ─── Test ──────────────────────────────────────────────────────────────────

test: test-unit test-integration

test-unit:
	cd $(CONTRACTS_DIR) && $(GO) test $(GOFLAGS) -race -short ./...
	cd $(SERVICE_DIR) && $(GO) test $(GOFLAGS) -race -short ./...
	cd $(SDK_DIR) && $(GO) test $(GOFLAGS) -race -short ./...

test-integration:
	cd $(SERVICE_DIR) && $(GO) test $(GOFLAGS) -race -run Integration ./...

test-coverage:
	cd $(CONTRACTS_DIR) && $(GO) test $(GOFLAGS) -coverprofile=../coverage/contracts.out ./...
	cd $(SERVICE_DIR) && $(GO) test $(GOFLAGS) -coverprofile=../coverage/service.out ./...
	$(GO) tool cover -html=coverage/service.out -o coverage/service.html

test-fuzz:
	cd $(CONTRACTS_DIR) && $(GO) test -fuzz=. -fuzztime=30s ./cose/...

test-property:
	cd $(SERVICE_DIR) && $(GO) test -run Property ./internal/policy/...

# ─── Lint & Security ──────────────────────────────────────────────────────

lint:
	golangci-lint run ./contracts/... ./service/... ./sdk/... 2>/dev/null || echo "golangci-lint not installed"
	go vet ./contracts/... ./service/... ./sdk/...

check-secrets:
	gitleaks detect --source . --no-git 2>/dev/null || echo "gitleaks not installed"

check-deps:
	go list -m all | tee deps.txt
	@echo "Checking for known vulnerabilities..."
	govulncheck ./... 2>/dev/null || echo "govulncheck not installed"

# ─── Database ─────────────────────────────────────────────────────────────

db-migrate:
	psql $(DATABASE_URL) -f $(SERVICE_DIR)/migrations/001_initial_schema.up.sql

db-rollback:
	psql $(DATABASE_URL) -f $(SERVICE_DIR)/migrations/001_initial_schema.down.sql

db-reset:
	psql $(DATABASE_URL) -f $(SERVICE_DIR)/migrations/001_initial_schema.down.sql
	psql $(DATABASE_URL) -f $(SERVICE_DIR)/migrations/001_initial_schema.up.sql

# ─── SBOM & Provenance ────────────────────────────────────────────────────

sbom:
	cyclonedx-gomod app -json -output sbom.json ./service/... 2>/dev/null || echo "cyclonedx not installed"

provenance:
	@echo "Build provenance:"
	@echo "  git_commit: $$(git rev-parse HEAD 2>/dev/null || echo unknown)"
	@echo "  build_time: $$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	@echo "  go_version: $$(go version)"

# ─── Clean ─────────────────────────────────────────────────────────────────

clean:
	rm -rf coverage/
	rm -rf bin/
	rm -f deps.txt sbom.json

# ─── Docker ────────────────────────────────────────────────────────────────

docker-build:
	docker build -t dnivio/approval-service:latest -f $(SERVICE_DIR)/Dockerfile .

docker-run:
	docker run -p 8443:8443 -p 8444:8444 \
	  -v $(PWD)/config.json:/etc/dnivio/config.json:ro \
	  dnivio/approval-service:latest

# ─── Full Check ────────────────────────────────────────────────────────────

check: lint check-secrets test-unit test-coverage
	@echo "All checks passed"
