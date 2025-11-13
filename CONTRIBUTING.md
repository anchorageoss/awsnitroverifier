# Contributing to AWS Nitro Verifier

Thank you for your interest in contributing to the AWS Nitro Verifier project! This document provides guidelines for contributors and information about the test fixtures.

## Test Fixtures

The project includes embedded test attestation documents for testing and validation. These fixtures allow developers to test the verifier without needing access to live AWS Nitro Enclaves.

### Embedded Test Data

The test fixtures are embedded in the project using Go's `//go:embed` directive and located in `testdata/`:

- **turnkey-prod.base64** - Production Turnkey attestation (for testing)
- **aws-nitro-example.base64** - Generic AWS Nitro example

### Test Attestation Characteristics

The embedded attestations are test fixtures with expired certificates. They should only be used for testing with `SkipTimestampCheck: true`.

**Production Test Attestation:**

- PCR[3]: `b798abfdbd591d5e1b7db6485a6de9e65100f5796d9e3a2bd7c179989cd663338b567162974974fbcc45d03847e70d8b`
- UserData: `8a5510ca253818acec5fb27b3ca114b4a260fb84f881838eb124aae9c968ad74` (32 bytes)
- PublicKey: 130 bytes (Dual P-256 ECDSA keys)

### Obtaining Your Own Attestations

#### For AWS Nitro Enclaves

To obtain fresh attestation documents from AWS Nitro Enclaves:

1. Create an enclave with your application
2. From within the enclave, call the Nitro Secure Module to get an attestation
3. The attestation document will contain your PCR values and optional user data

Example from within an enclave (Python):

```python
import subprocess
import base64

# Get attestation with optional user data and nonce
result = subprocess.run([
    '/usr/bin/nitro-cli', 'describe-eif',
    '--eif-path', '/app/enclave.eif'
], capture_output=True, text=True)

# Parse and encode the attestation document
attestation = base64.b64encode(attestation_bytes).decode('utf-8')
```

For more information, see:
- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html)
- [Verifying AWS Nitro Root Certificates](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)

## Running Tests

To run the test suite:

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run tests for specific package
go test -v ./internal
```

## Building

```bash
# Build CLI tool
go build ./cmd/awsnitroverifier

# Build all packages
go build ./...
```

## Code Style

- Follow standard Go conventions and [effective Go](https://golang.org/doc/effective_go)
- Use `gofmt` for formatting
- Use `golangci-lint` for linting

```bash
# Format code
gofmt -w .

# Run linter
golangci-lint run ./...
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes and add tests if applicable
4. Ensure all tests pass (`go test ./...`)
5. Run the linter (`golangci-lint run ./...`)
6. Commit with clear messages
7. Push to your fork
8. Open a pull request with a clear description

## Security Considerations

This library validates AWS Nitro attestations. When modifying validation logic:

- Ensure cryptographic operations use standard library implementations
- Maintain ECDSA-only key type validation (AWS Nitro exclusively uses ECDSA)
- Keep certificate chain validation logic secure
- Test with both valid and invalid attestations

## Questions?

Feel free to open an issue or discussion in the repository if you have questions about contributing or need clarification.
