# Contributing to AWS Nitro Verifier

Thank you for your interest in contributing to the AWS Nitro Verifier project! This document provides guidelines for maintaining the open-source nature of this library.

## 🚨 Important: Dependency Restrictions

This library **strictly prohibits** certain proprietary dependencies to maintain its open-source nature. We have implemented multiple safeguards to prevent accidental inclusion of these dependencies.

### Automated Safeguards

1. **Dependency Checker** (`make check-deps`)
   - Scans all Go files for prohibited imports
   - Checks `go.mod` and `go.sum` for prohibited dependencies
   - Primary security safeguard - runs first in all checks

2. **Pre-commit Git Hook** (`.git/hooks/pre-commit`)
   - Automatically runs before every commit
   - Scans for prohibited imports and references
   - Runs tests and linting
   - Prevents commits containing violations

3. **Makefile Commands**
   - `make check-deps` - Check for prohibited dependencies
   - `make lint` - Run full linting with dependency checks
   - `make check` - Run all quality checks

4. **GitHub Actions CI** (`.github/workflows/ci.yml`)
   - Dependency check runs first in CI pipeline
   - Fails the entire pipeline if violations are found
   - Testing and security scanning

## Development Setup

### 1. Install Required Tools

```bash
make install-tools
```

This installs:
- `golangci-lint` - For comprehensive linting
- `gosec` - For security scanning

### 2. Set Up Git Hooks

```bash
make setup-hooks
```

This ensures the pre-commit hook is executable.

### 3. Verify Setup

```bash
make check
```

This runs all quality checks including dependency verification.

## Before Making Changes

### Check for Prohibited Dependencies

```bash
make check-deps
```

This command will scan your code for any prohibited dependencies.

### Run Full Quality Checks

```bash
make ci
```

This runs the complete CI pipeline locally:
- Dependency checks
- Linting
- Tests
- Security scanning

## Error Handling Guidelines

This library uses standard Go error handling patterns:

### ✅ Recommended Patterns
```go
import (
    "errors"
    "fmt"
)

// Use standard error wrapping
return fmt.Errorf("failed to process: %w", err)
return errors.New("something went wrong")
```

## Making Commits

The pre-commit hook will automatically:

1. 🔍 Check for prohibited dependencies
2. 🧪 Run tests
3. 🔍 Run linting
4. ✅ Allow commit only if all checks pass

## Testing Your Changes

### Run Specific Checks
```bash
# Check dependencies only
make check-deps

# Run tests only  
make test

# Run linting only
make lint

# Run security scan
make security-scan
```

### Run Everything
```bash
make ci
```

## Continuous Integration

Our GitHub Actions workflow includes:

1. **Dependency Security Check** - Primary safeguard
   - Scans for prohibited imports
   - Checks dependency files
   - Fails fast if violations found

2. **Testing and Quality**
   - Full test suite with race detection
   - Linting with `golangci-lint`
   - Build verification

## Release Preparation

Before creating a release:

```bash
make prepare-release
```

This runs all checks and provides release readiness verification.

## Troubleshooting

### "golangci-lint not found"
```bash
make install-tools
```

### "Pre-commit hook failed"
The hook is working correctly! Fix the issues it found and ensure tests pass.

### "Dependency check failed"
This means prohibited dependencies were found. Remove them and run:
```bash
go mod tidy
make check-deps
```

## Questions?

If you have questions about these restrictions or need help with patterns, please open an issue describing your use case.

Remember: These safeguards exist to ensure this library remains truly open-source and free of proprietary dependencies. Thank you for helping maintain this standard!