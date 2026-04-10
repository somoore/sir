.PHONY: build test test-go test-rust test-race coverage check public-contract replay bench bench-check contributor-check install clean lint verify verify-release sbom audit smoke-test

# Toolchain versions — keep in sync with .github/workflows/ci.yml
RUST_VERSION ?= 1.94.0
GO_VERSION   ?= 1.25.9
REPLAY_ARGS  ?=
BENCH_ARGS   ?= -run '^$$' -bench . -benchmem
RELEASE_TAG  ?=
RELEASE_DIR  ?= ./verify-release

# Build flags for reproducibility and security
CARGO_FLAGS  = --release --locked
CARGO_ENV    = CARGO_INCREMENTAL=0
GO_BUILD     = CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"

build:
	$(CARGO_ENV) cargo build $(CARGO_FLAGS)
	mkdir -p bin
	$(GO_BUILD) -o bin/sir ./cmd/sir

# Run only Go tests
test-go:
	go test ./... -v -count=1

# Run only Rust tests
test-rust:
	cargo test --locked

# Run all tests (Rust + Go)
test: test-rust test-go

# Run tests with race detector
test-race:
	go test -race ./... -count=1
	cargo test --locked

# Coverage report
coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run the full verification suite (lint + test + verify)
check: public-contract lint test verify

public-contract:
	go test ./cmd/sir -run TestPublicContractParity

replay:
	mkdir -p bin
	go build -o bin/sir ./cmd/sir
	bash testdata/run_fixtures.sh $(REPLAY_ARGS)

bench:
	go test ./cmd/sir ./pkg/core ./pkg/hooks ./pkg/ledger ./pkg/session ./pkg/runtime ./pkg/mcp ./pkg/telemetry $(BENCH_ARGS)

bench-check:
	python3 scripts/check_bench_budget.py

contributor-check:
	bash scripts/check_review_context.sh

install: build
	mkdir -p ~/.local/bin
	cp target/release/mister-core ~/.local/bin/
	cp bin/sir ~/.local/bin/
	chmod 750 ~/.local/bin/mister-core ~/.local/bin/sir

clean:
	cargo clean
	rm -rf bin/
	rm -f CHECKSUMS.sha256 CHECKSUMS.sha512 sbom-sir.cdx.json

lint:
	cargo clippy --locked -- -D warnings
	go vet ./...

# Supply chain verification
verify: lint
	@echo "=== Verifying zero external Rust dependencies ==="
	@PKG_COUNT=$$(grep -c '^\[\[package\]\]' Cargo.lock); \
	if [ "$$PKG_COUNT" -ne 2 ]; then \
		echo "FATAL: Expected 2 packages in Cargo.lock, found $$PKG_COUNT"; \
		exit 1; \
	fi
	@echo "OK: Cargo.lock contains exactly 2 packages"
	@echo ""
	@echo "=== Running cargo-deny ==="
	cargo deny check
	@echo ""
	@echo "=== Running Go supply chain checks ==="
	bash go-supply-chain.sh
	@echo ""
	@echo "=== Generating checksums ==="
	bash scripts/checksum.sh ./bin 2>/dev/null || bash scripts/checksum.sh target/release 2>/dev/null || echo "No artifacts to checksum (run 'make build' first)"

verify-release:
	bash scripts/verify-release.sh "$(RELEASE_TAG)" "$(RELEASE_DIR)"

# SBOM generation
sbom:
	@command -v syft >/dev/null 2>&1 || { echo "Install syft: https://github.com/anchore/syft"; exit 1; }
	syft dir:. -o cyclonedx-json > sbom-sir.cdx.json
	@echo "SBOM written to sbom-sir.cdx.json"

# Security audit
audit:
	@echo "=== Cargo audit ==="
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "cargo-audit not installed (cargo install cargo-audit)"; \
	fi
	@echo ""
	@echo "=== govulncheck ==="
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@v1.1.4)"; \
	fi
	@echo ""
	@echo "=== cargo-deny ==="
	cargo deny check

# Real smoke tests against Claude Code (requires claude CLI authenticated)
smoke-test: build install
	@command -v claude >/dev/null 2>&1 || { echo "Claude Code not installed. Install: npm install -g @anthropic-ai/claude-code"; exit 1; }
	bash scripts/smoke-test.sh
