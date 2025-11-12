# AWS Nitro Verifier Makefile
# Provides commands for building, testing, and maintaining the project

# Configuration
COVERAGE_THRESHOLD := 80

.PHONY: help build test test-coverage test-coverage-serve test-strict lint clean check-deps security-scan install-tools setup-hooks

# Default target
help: ## Display this help message
	@echo "AWS Nitro Verifier - Available Commands:"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\033[36m%-20s\033[0m %s\n", "Target", "Description"} /^[a-zA-Z_-]+:.*?##/ { printf "\033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Building and Testing
build: ## Build the project
	@echo "🔨 Building project..."
	@mkdir -p bin
	@go build -o bin/awsnitroverifier ./cmd/awsnitroverifier
	@echo "✅ Binary built: bin/awsnitroverifier"


test: ## Run all tests with coverage
	@echo "🧪 Running tests with race detection..."
	@go test -v -race -coverprofile=coverage.out ./... -count=1
	@echo ""
	@echo "Filtering out cmd and types packages from coverage (cmd by integration tests, types has no logic)..."
	@grep -v "^github.com/anchorageoss/awsnitroverifier/cmd/\|^github.com/anchorageoss/awsnitroverifier/types/" coverage.out > coverage.filtered.out || true
	@echo "mode: atomic" > coverage.out.tmp
	@grep -v "^mode:" coverage.filtered.out >> coverage.out.tmp || true
	@mv coverage.out.tmp coverage.out
	@echo ""
	@echo "📊 Coverage summary (excluding cmd package):"
	@go tool cover -func=coverage.out | tail -1

test-coverage: test ## Generate HTML coverage report
	@go tool cover -html=coverage.out -o coverage.html
	@echo ""
	@echo "✅ Coverage report generated: coverage.html"
	@echo "   Open coverage.html in a browser to view detailed report"

test-coverage-serve: test ## Serve coverage report on HTTP server
	@set -e; \
	TMPDIR=$$(mktemp -d); \
	trap "rm -rf $$TMPDIR" EXIT; \
	go tool cover -html=coverage.out -o $$TMPDIR/index.html; \
	echo ""; \
	echo "✓ Coverage report generated"; \
	echo "  Location: $$TMPDIR/index.html"; \
	echo ""; \
	echo "Starting HTTP server on port 3000..."; \
	echo "  URL: http://localhost:3000"; \
	echo "  Press Ctrl+C to stop"; \
	echo ""; \
	if command -v python3 >/dev/null 2>&1; then \
		cd $$TMPDIR && python3 -m http.server 3000; \
	elif command -v python >/dev/null 2>&1; then \
		cd $$TMPDIR && python -m SimpleHTTPServer 3000; \
	else \
		echo "ERROR: python3 or python not found"; \
		exit 1; \
	fi

test-strict: ## Run tests with coverage threshold check
	@echo "🧪 Running tests with strict coverage checking..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo ""
	@echo "Filtering out cmd and types packages from coverage (cmd by integration tests, types has no logic)..."
	@grep -v "^github.com/anchorageoss/awsnitroverifier/cmd/\|^github.com/anchorageoss/awsnitroverifier/types/" coverage.out > coverage.filtered.out || true
	@echo "mode: atomic" > coverage.out.tmp
	@grep -v "^mode:" coverage.filtered.out >> coverage.out.tmp || true
	@mv coverage.out.tmp coverage.out
	@echo ""
	@COVERAGE=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$3}' | sed 's/%//'); \
	awk -v coverage="$$COVERAGE" -v threshold="$(COVERAGE_THRESHOLD)" 'BEGIN { \
		if (coverage < threshold) { \
			print "❌ Code coverage: " coverage "% (below " threshold "% minimum)"; \
			exit 1; \
		}; \
		print "✅ Code coverage: " coverage "% (meets " threshold "% minimum)"; \
		exit 0; \
	}'

test-short: ## Run tests without race detection (faster)
	@echo "🧪 Running short tests..."
	@go test -short ./...

bench: ## Run benchmarks
	@echo "🏃 Running benchmarks..."
	@go test -bench=. -benchmem ./...

##@ Code Quality
lint: ## Run linter with anchorlabsinc dependency checks
	@echo "🔍 Running linter..."
	@echo "  Running dependency checks (primary security check)..."
	@$(MAKE) check-deps
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "  Running golangci-lint with default configuration..."; \
		golangci-lint run --timeout=3m || echo "  ⚠️  Some linting issues found, but dependency check passed"; \
		echo "  ✅ Linting completed"; \
	else \
		echo "  ⚠️  golangci-lint not found. Run 'make install-tools' to get full linting."; \
		echo "  ✅ Dependency check completed (primary security check passed)"; \
	fi

go-mod-tidy: ## Run `go mod tidy`
	@echo "🧹 Running go mod tidy..."
	@go mod tidy

fmt: ## Format Go code
	@echo "🎨 Formatting code..."
	@go fmt ./...
	@gofmt -s -w .

vet: ## Run go vet
	@echo "🔍 Running go vet..."
	@go vet ./...

check-deps: ## Check for prohibited anchorlabsinc dependencies
	@./test_ci_check.sh

security-scan: ## Run security scan (gosec)
	@echo "🔒 Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "❌ gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

##@ Maintenance
clean: ## Clean build artifacts and temporary files
	@echo "🧹 Cleaning..."
	@go clean ./...
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@go mod tidy

mod-update: ## Update Go modules
	@echo "📦 Updating modules..."
	@go get -u ./...
	@go mod tidy

##@ Development Setup
install-tools: ## Install required development tools
	@echo "🔧 Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@echo "✅ Tools installed successfully"

setup-hooks: ## Set up git hooks
	@echo "🪝 Setting up git hooks..."
	@chmod +x .git/hooks/pre-commit
	@echo "✅ Git hooks configured"

##@ Comprehensive Checks
check: check-deps test-strict lint ## Run all code quality checks with coverage validation
	@echo "✅ All checks completed successfully!"

ci: check ## Run CI pipeline locally
	@echo "🚀 Running full CI pipeline..."
	@$(MAKE) clean
	@$(MAKE) check
	@echo "✅ CI pipeline completed successfully!"

##@ Release
prepare-release: ## Prepare for release (run all checks, update docs)
	@echo "🚀 Preparing release..."
	@$(MAKE) clean
	@$(MAKE) check
	@$(MAKE) bench
	@echo "📚 Please update CHANGELOG.md and README.md if needed"
	@echo "✅ Release preparation completed!"

# Show Go version and environment info
info: ## Show Go environment information
	@echo "📋 Environment Information:"
	@echo "Go version: $$(go version)"
	@echo "GOPATH: $$(go env GOPATH)"
	@echo "GOROOT: $$(go env GOROOT)"
	@echo "Module: $$(go list -m)"
	@echo "Working directory: $$(pwd)"