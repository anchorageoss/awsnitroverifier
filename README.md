# AWS Nitro Enclave Attestation Verifier

A comprehensive Go library for validating AWS Nitro Enclave attestation documents with embedded test fixtures and complete chain of trust verification. This library provides robust verification capabilities for any AWS Nitro Enclave deployment.

## Features

- **Complete AWS Chain of Trust**: Validates against official AWS Nitro root certificate
- **Configurable Timestamp Validation**: Skip or customize certificate timestamp validation
- **PCR Validation**: Validate specific PCR values with detailed debugging support
- **UserData Extraction**: Access UserData and optional fields for application-specific verification
- **Embedded Test Fixtures**: Built-in example attestations for testing
- **Partial Validation Support**: Continue validation even if some checks fail
- **Generic AWS Nitro Support**: Works with any AWS Nitro Enclave deployment

## Installation

```go
import "github.com/awsnitroverifier/awsnitroverifier"
```

## Quick Start

### Basic Validation with Chain of Trust

```go
verifier := nitroverifier.NewVerifier(nitroverifier.ValidatorOptions{
    SkipTimestampCheck: true, // For expired test certificates
})

result, err := verifier.Validate(attestationBase64)

if result.Valid && result.ChainValidated {
    fmt.Printf("✅ Valid attestation from AWS Nitro hardware\n")
    fmt.Printf("Root fingerprint: %s\n", result.RootFingerprint)

    // Access optional application data
    if result.UserData != nil {
        fmt.Printf("UserData: %x\n", result.UserData)
    }
    if result.PublicKey != nil {
        fmt.Printf("PublicKey: %d bytes\n", len(result.PublicKey))
    }
}
```

### PCR Validation

```go
// Define expected PCR values for your specific enclave
expectedPCR3 := "your_expected_pcr3_value_here"
pcr3Bytes, _ := hex.DecodeString(expectedPCR3)

verifier := nitroverifier.NewVerifier(nitroverifier.ValidatorOptions{
    SkipTimestampCheck: true,
    PCRRules: []nitroverifier.PCRRule{
        {Index: 3, Value: pcr3Bytes},
    },
})

result, _ := verifier.Validate(attestationBase64)
```

### Using Test Fixtures

The library includes embedded test fixtures for development and testing:

```go
// For generic AWS Nitro testing (placeholder)
attestation := getAWSExampleAttestation() // Returns placeholder

// For Turnkey-specific testing (real attestations)
attestation := getTurnkeyProductionAttestation() // Real Turnkey attestation
```

## Validation Options

```go
type ValidatorOptions struct {
    // Skip certificate timestamp validation
    SkipTimestampCheck bool

    // Override validation time
    CurrentTime *time.Time

    // Expected PCR values
    PCRRules []PCRRule

    // Skip signature verification
    SkipSignatureVerification bool

    // Skip certificate chain validation against AWS root
    SkipChainValidation bool
}
```

## Validation Results

```go
type ValidationResult struct {
    Valid              bool                    // Overall validation status
    Document           *AttestationDocument    // Parsed attestation
    CertificateInfo    *CertificateInfo       // Certificate details
    CertificateChain   []CertificateInfo      // Full certificate chain
    ChainValidated     bool                   // Chain of trust validated
    RootFingerprint    string                 // AWS root certificate fingerprint
    PCRValidations     []PCRValidationResult  // Individual PCR results
    Errors             []error                // Validation errors

    // Optional attestation fields
    UserData  []byte  // Application-specific data
    PublicKey []byte  // Public key from enclave
    Nonce     []byte  // Optional nonce
}
```

## AWS Nitro Root Certificate

The library validates against the official AWS Nitro root certificate from AWS documentation:
- **Fingerprint**: `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`
- **Subject**: `CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US`

## Obtaining Attestation Documents

### For Generic AWS Nitro Enclaves

To obtain attestation documents from your AWS Nitro Enclave:

1. From within your enclave, call the Nitro Secure Module
2. The attestation document will contain your specific PCR values and optional data

Example (Python):
```python
import subprocess
import base64

# Get attestation with optional user data and nonce
# This is application-specific - modify for your enclave setup
result = subprocess.run([
    '/usr/bin/nitro-cli', 'describe-eif',
    '--eif-path', '/app/enclave.eif'
], capture_output=True, text=True)

# Process and encode the attestation document
attestation = base64.b64encode(attestation_bytes).decode('utf-8')
```

For more information, see:
- [AWS Nitro Enclaves Concepts](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html)
- [Verify Root Certificate](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)

### Example: Turnkey Integration

This library works well with Turnkey's AWS Nitro Enclave integration. For Turnkey-specific attestations:

```bash
# Production attestation
turnkey request \
  --host api.turnkey.com \
  --path /public/v1/query/get_attestation \
  --body '{"organizationId": "<yourOrgId>","enclaveType": "signer"}' \
  --organization=<yourOrgId> | jq -r '.attestationDocument' > turnkey-attestation.base64

# Pre-production attestation  
turnkey request \
  --host api.preprod.turnkey.engineering \
  --path /public/v1/query/get_attestation \
  --body '{"organizationId": "<yourOrgId>","enclaveType": "signer"}' \
  --organization=<yourOrgId> | jq -r '.attestationDocument' > turnkey-preprod-attestation.base64
```

## Testing

The library includes comprehensive tests:

```bash
go test -v
```

Test coverage includes:
- AWS specification compliance
- Chain of trust validation  
- PCR validation with real fixtures
- UserData extraction and validation
- Multiple environment support

## Example: Complete Attestation Validation

```go
func validateAttestation(attestationBase64 string, expectedPCRs map[uint]string) error {
    // Convert expected PCR strings to bytes
    var pcrRules []nitroverifier.PCRRule
    for index, pcrHex := range expectedPCRs {
        pcrBytes, err := hex.DecodeString(pcrHex)
        if err != nil {
            return fmt.Errorf("invalid PCR[%d]: %w", index, err)
        }
        pcrRules = append(pcrRules, nitroverifier.PCRRule{
            Index: index,
            Value: pcrBytes,
        })
    }

    verifier := nitroverifier.NewVerifier(nitroverifier.ValidatorOptions{
        SkipTimestampCheck: true, // Adjust based on your needs
        PCRRules:          pcrRules,
    })

    result, err := verifier.Validate(attestationBase64)
    if err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }

    if !result.Valid {
        return fmt.Errorf("attestation invalid: %v", result.Errors)
    }

    if !result.ChainValidated {
        return fmt.Errorf("certificate chain not validated")
    }

    fmt.Printf("✅ Valid AWS Nitro attestation\n")
    if result.UserData != nil {
        fmt.Printf("   UserData: %x\n", result.UserData)
    }
    if result.PublicKey != nil {
        fmt.Printf("   PublicKey: %d bytes\n", len(result.PublicKey))
    }
    fmt.Printf("   Root: %s\n", result.RootFingerprint)

    return nil
}
```

## PCR Debugging

```go
result, _ := verifier.Validate(attestationBase64)

summary := nitroverifier.GetPCRValidationSummary(result.PCRValidations)
fmt.Printf("PCR Summary: %d valid, %d invalid, %d missing\n",
    summary.Valid, summary.Invalid, summary.Missing)

for _, pcr := range result.PCRValidations {
    if !pcr.Valid {
        fmt.Printf("❌ PCR[%d] mismatch:\n", pcr.Index)
        fmt.Printf("   Expected: %x\n", pcr.Expected)
        fmt.Printf("   Actual:   %x\n", pcr.Actual)
    }
}
```

---

**Note**: The embedded fixtures may contain expired certificates and should be used for testing with `SkipTimestampCheck: true` if needed.