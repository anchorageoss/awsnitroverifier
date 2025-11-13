# AWS Nitro Enclave Attestation Verifier

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

## Usage

### Basic Validation

```go
package main

import (
    "encoding/base64"
    "fmt"
    "log"
    
    nitroverifier "github.com/anchorageoss/awsnitroverifier"
)

func main() {
    // Load attestation (usually from AWS Nitro Enclave)
    attestationBase64 := "..." // base64-encoded attestation
    attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
    if err != nil {
        log.Fatal(err)
    }

    // Create verifier
    verifier := nitroverifier.NewVerifier(nitroverifier.AWSNitroVerifierOptions{
        SkipTimestampCheck: false, // Validate certificate timestamps
    })

    // Validate attestation
    result, err := verifier.Validate(attestationBytes)
    
    // Handle malformed input
    if err != nil {
        log.Fatalf("Invalid attestation: %v", err)
    }

    // Handle validation failures
    if !result.Valid {
        fmt.Printf("Validation failed:\n")
        for _, errMsg := range result.Errors {
            fmt.Printf("  - %s\n", errMsg)
        }
        return
    }

    // Success!
    fmt.Println("✅ Attestation is valid")
    if result.ChainTrusted {
        fmt.Printf("AWS root: %s\n", result.RootFingerprint)
    }
    if result.UserData != nil {
        fmt.Printf("UserData: %x\n", result.UserData)
    }
}
```

### PCR Validation

```go
verifier := nitroverifier.NewVerifier(nitroverifier.AWSNitroVerifierOptions{
    SkipTimestampCheck: true,
    PCRRules: []nitroverifier.PCRRule{
        {
            Index: 3,
            Value: []byte{...}, // Expected PCR value
        },
    },
})

result, err := verifier.Validate(attestationBytes)
if err != nil {
    log.Fatal(err)
}

if !result.Valid {
    log.Fatal("Validation failed")
}

// Check specific PCR results
for _, pcr := range result.PCRResults {
    if !pcr.Valid {
        fmt.Printf("PCR[%d] mismatch\n", pcr.Index)
    }
}
```

### Offline/Test Validation

For scenarios where certificates have expired (e.g., test fixtures, offline validation):

```go
verifier := nitroverifier.NewVerifier(nitroverifier.AWSNitroVerifierOptions{
    SkipTimestampCheck: true, // Skip certificate date validation
})

result, err := verifier.Validate(attestationBytes)
```

## API

### Quick Reference

- **Verifier** - Interface with `Validate([]byte) (*ValidationResult, error)` method
- **ValidationResult** - Contains validation status, errors, and extracted data
- **AWSNitroVerifierOptions** - Configuration for timestamp and PCR validation

For complete API documentation, see [pkg.go.dev](https://pkg.go.dev/github.com/anchorageoss/awsnitroverifier).

### Error Handling

The `Validate()` function uses Go's error handling idiomatically:

**Malformed Input** (`err != nil`):
- Cannot be parsed as CBOR
- Invalid COSE Sign1 structure
- Malformed attestation document

**Validation Failures** (`Valid=false`):
- Certificate chain validation fails
- Signature verification fails
- Certificate expired (unless SkipTimestampCheck=true)
- PCR values don't match expected values

```go
result, err := verifier.Validate(attestationBytes)

// Fatal error - input is invalid
if err != nil {
    log.Fatalf("Malformed attestation: %v", err)
}

// Validation error - attestation is well-formed but doesn't meet requirements
if !result.Valid {
    fmt.Printf("Validation failed: %v\n", result.Errors)
    return
}
```

## Testing

The library includes test fixtures in `testdata/`:

```bash
# Run tests
go test -v ./...

# Run with coverage
go test -cover ./...
```

For information about test fixtures and obtaining your own attestations, see [CONTRIBUTING.md](CONTRIBUTING.md).

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
