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

### As a library

```bash
go get github.com/anchorageoss/awsnitroverifier
```

Pin to a tagged release (`v0.N.0`) for stable behavior; releases follow the versioning scheme described below.

### As a CLI

Download a prebuilt binary from the [Releases page](https://github.com/anchorageoss/awsnitroverifier/releases) — `awsnitroverifier_<version>_<os>_<arch>.tar.gz` for linux/darwin × amd64/arm64. Or build locally:

```bash
make build  # → bin/awsnitroverifier
```

See [`cmd/awsnitroverifier/README.md`](cmd/awsnitroverifier/README.md) for CLI usage.

## Releases

Releases are automated via [goreleaser](https://goreleaser.com/) and triggered on every push to `main`. Versions are computed from git commit history by [`scripts/auto-version.sh`](scripts/auto-version.sh) — no manual tagging required.

The script stacks new versions on top of the highest existing `vMAJOR.MINOR.PATCH` tag: each commit on `main` bumps the minor digit by one (e.g. starting from `v0.1.0`, the next release is `v0.2.0`, then `v0.3.0`). To start a new major series, manually push the appropriate tag (e.g. `git tag v1.0.0`) and subsequent commits stack on top of that.

The release workflow ([`.github/workflows/release.yml`](.github/workflows/release.yml)):

1. Computes the version (`MAJOR.<MINOR_BASE + commits_since_tag>.0`) and short commit hash
2. Runs the full test suite, enforces an 80% coverage floor, runs the linter, and smoke-tests `--version`
3. Creates and pushes the git tag if it does not already exist
4. Runs goreleaser to build and publish cross-platform binaries to GitHub Releases (skipped if a release already exists for the tag)

Releases can also be triggered manually via `workflow_dispatch`, with an optional `dry_run` input to stop before tagging.

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
