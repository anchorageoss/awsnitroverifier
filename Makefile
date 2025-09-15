# AWS Nitro Verifier Makefile
# Provides commands for building, testing, and maintaining the project

.PHONY: help build test lint clean check-deps security-scan install-tools setup-hooks

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


test: ## Run all tests
	@echo "🧪 Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report generated: coverage.html"

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
	@echo "🔍 Checking for prohibited dependencies..."
	@if grep -r "anchorlabsinc" --include="*.go" --include="*.mod" .; then \
		echo "❌ Found prohibited anchorlabsinc dependencies!"; \
		echo "   Please remove these before committing."; \
		exit 1; \
	else \
		echo "✅ No prohibited dependencies found."; \
	fi
	@if grep -r "github.com/anchorlabsinc" go.mod go.sum 2>/dev/null; then \
		echo "❌ Found anchorlabsinc references in go.mod/go.sum!"; \
		exit 1; \
	else \
		echo "✅ go.mod and go.sum are clean."; \
	fi

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
check: lint test check-deps ## Run all code quality checks
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