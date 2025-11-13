# AWS Nitro Enclave Attestation Verifier

[![Go Report Card](https://goreportcard.com/badge/github.com/anchorageoss/awsnitroverifier)](https://goreportcard.com/report/github.com/anchorageoss/awsnitroverifier)
[![Go Reference](https://pkg.go.dev/badge/github.com/anchorageoss/awsnitroverifier.svg)](https://pkg.go.dev/github.com/anchorageoss/awsnitroverifier)

A Go library for validating AWS Nitro Enclave attestation documents with complete chain of trust verification against the official AWS Nitro root certificate.

## Features

- ✅ **AWS Chain of Trust Verification** - Validates against official AWS Nitro root certificate
- ✅ **Flexible Certificate Validation** - Skip timestamp checks for offline/test scenarios
- ✅ **PCR Validation** - Validate specific PCR values against expected values
- ✅ **Data Extraction** - Access UserData, PublicKey, and Nonce from attestation
- ✅ **Clear Error Handling** - Distinguish between malformed input and validation failures
- ✅ **Test Fixtures** - Embedded example attestations for testing

## Installation

```bash
go get github.com/anchorageoss/awsnitroverifier
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/anchorageoss/awsnitroverifier"
)

func main() {
    // attestationBytes from AWS Nitro Enclave
    verifier := awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
        SkipTimestampCheck: false,
    })

    result, err := verifier.Validate(attestationBytes)

    if err != nil {
        log.Fatalf("Malformed attestation: %v", err)
    }

    if !result.Valid {
        fmt.Printf("Validation failed: %v\n", result.Errors)
        return
    }

    fmt.Printf("✅ Attestation valid\n")
    fmt.Printf("Root fingerprint: %s\n", result.RootFingerprint)
}
```

## Usage

See [USAGE.md](USAGE.md) for:
- Basic validation
- PCR validation
- Data extraction
- Offline/test mode
- Error handling patterns
- Migration from nitrite

## Error Handling

The library distinguishes between two types of errors:

```go
result, err := verifier.Validate(attestationBytes)

// Malformed input - parsing error
if err != nil {
    log.Fatalf("Input error: %v", err)
}

// Validation failure - well-formed but invalid
if !result.Valid {
    log.Fatalf("Validation error: %v", result.Errors)
}
```

**Malformed Input** (`err != nil`):
- Cannot be parsed as CBOR
- Invalid COSE Sign1 structure
- Malformed attestation document

**Validation Failures** (`Valid=false`):
- Certificate chain validation fails
- Signature verification fails
- Certificate expired (unless SkipTimestampCheck=true)
- PCR values don't match expected values

## API Reference

- **NewVerifier()** - Create a verifier with options
- **Validate()** - Validate attestation bytes
- **ValidationResult** - Contains validation status and extracted data
- **AWSNitroVerifierOptions** - Configuration for validation

For complete API documentation: https://pkg.go.dev/github.com/anchorageoss/awsnitroverifier

## Testing

```bash
# Run tests
go test -v ./...

# Run with coverage
go test -cover ./...
```

Test fixtures are included in `testdata/`. See [CONTRIBUTING.md](CONTRIBUTING.md) for information about obtaining your own attestations.

## Security

This library validates AWS Nitro attestations using:
- ECDSA signature verification (only algorithm supported by AWS Nitro)
- X.509 certificate chain validation
- AWS Nitro root certificate fingerprint verification

## References

- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html)
- [AWS Nitro Root Certificate Verification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
- [COSE Sign1 Specification (RFC 8152)](https://tools.ietf.org/html/rfc8152)

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for details
