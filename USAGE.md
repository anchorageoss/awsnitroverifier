# Usage Guide

## Basic Validation

```go
package main

import (
    "encoding/base64"
    "fmt"
    "log"

    "github.com/anchorageoss/awsnitroverifier"
)

func main() {
    // Load attestation (usually from AWS Nitro Enclave)
    attestationBase64 := "..." // base64-encoded attestation
    attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
    if err != nil {
        log.Fatal(err)
    }

    // Create verifier
    verifier := awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
        SkipTimestampCheck: false,
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
        for _, validationErr := range result.Errors {
            fmt.Printf("  - %v\n", validationErr)
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

## PCR Validation

Validate Platform Configuration Registers against expected values:

```go
verifier := awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
    SkipTimestampCheck: false,
    PCRRules: []awsnitroverifier.PCRRule{
        {
            Index: 0,
            Value: expectedPCR0,
        },
        {
            Index: 1,
            Value: expectedPCR1,
        },
    },
})

result, err := verifier.Validate(attestationBytes)
if err != nil {
    log.Fatal(err)
}

if !result.Valid {
    log.Fatalf("Validation failed: %v", result.Errors)
}

// Check specific PCR results
for _, pcr := range result.PCRResults {
    if !pcr.Valid {
        fmt.Printf("PCR[%d] mismatch: expected %x, got %x\n",
            pcr.Index, pcr.Expected, pcr.Actual)
    }
}
```

## Extracting Data

Access data from the attestation:

```go
result, err := verifier.Validate(attestationBytes)
if err != nil || !result.Valid {
    return err
}

// Extract various fields
userData := result.UserData         // Application-specific data
publicKey := result.PublicKey       // Public key from attestation
nonce := result.Nonce               // Nonce included in attestation
fingerprint := result.RootFingerprint // SHA256 fingerprint of root cert
trusted := result.ChainTrusted      // Whether chain verified to AWS root

fmt.Printf("UserData: %x\n", userData)
fmt.Printf("PublicKey: %x\n", publicKey)
fmt.Printf("Root: %s\n", fingerprint)
```

## Offline/Test Mode

Skip certificate timestamp validation for expired test certificates:

```go
verifier := awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
    SkipTimestampCheck: true, // Allow expired certificates
})

result, err := verifier.Validate(testAttestationBytes)
if err != nil {
    log.Fatal(err)
}

if !result.Valid {
    log.Fatalf("Validation failed: %v", result.Errors)
}
```

## Error Handling

The library distinguishes between two types of errors:

```go
result, err := verifier.Validate(attestationBytes)

// Malformed input - parsing error
if err != nil {
    log.Fatalf("Input error: cannot parse attestation: %v", err)
}

// Validation failure - well-formed but invalid
if !result.Valid {
    log.Fatalf("Validation error: attestation doesn't meet requirements: %v", result.Errors)
}

// Success
log.Print("✅ Attestation verified")
```

For production, handle errors appropriately:

```go
result, err := verifier.Validate(attestationBytes)

if err != nil {
    // Parsing error - malformed input, probably attack or corruption
    metrics.Inc("attestation_malformed")
    return nil, fmt.Errorf("malformed attestation: %w", err)
}

if !result.Valid {
    // Validation error - well-formed but invalid
    metrics.Inc("attestation_invalid")
    for _, validationErr := range result.Errors {
        log.Warnf("Validation failure: %v", validationErr)
    }
    return nil, fmt.Errorf("attestation validation failed")
}

// Success
metrics.Inc("attestation_valid")
return &result, nil
```

---

## Migration from nitrite

If you're currently using nitrite, here's how to migrate to awsnitroverifier.

### Overview

Both libraries verify AWS Nitro Enclave attestations with different approaches:

| Feature | awsnitroverifier | nitrite |
|---------|---|---|
| API Style | Object-oriented (Verifier interface) | Functional (single Verify function) |
| PCR Validation | ✅ Built-in with rules | ❌ Not available |
| Data Extraction | ✅ UserData, PublicKey, Nonce | ⚠️ Limited |
| Error Handling | ✅ Malformed vs invalid distinction | ⚠️ Mixed errors |
| Input | `[]byte` | `io.Reader` |

### Migration Steps

#### Step 1: Update Import

```go
// Old
import "github.com/hf/nitrite"

// New
import "github.com/anchorageoss/awsnitroverifier"
```

#### Step 2: Convert Reader to Bytes

```go
// Old
result, err := nitrite.Verify(reader, &nitrite.VerifyOptions{
    CurrentTime: time.Now(),
})

// New
attestationBytes, err := io.ReadAll(reader)
if err != nil {
    return err
}
```

#### Step 3: Create Verifier

```go
verifier := awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
    SkipTimestampCheck: false,
})
```

#### Step 4: Validate

```go
result, err := verifier.Validate(attestationBytes)

// Handle malformed input
if err != nil {
    return fmt.Errorf("invalid attestation: %w", err)
}

// Handle validation failures
if !result.Valid {
    return fmt.Errorf("validation failed: %v", result.Errors)
}
```

### Complete Migration Example

**Before (nitrite):**
```go
func verifyAttestation(reader io.Reader) error {
    result, err := nitrite.Verify(reader, &nitrite.VerifyOptions{
        CurrentTime: time.Now(),
    })
    if err != nil {
        return err
    }

    // Use result...
    return nil
}
```

**After (awsnitroverifier):**
```go
func verifyAttestation(reader io.Reader) error {
    attestationBytes, err := io.ReadAll(reader)
    if err != nil {
        return err
    }

    verifier := awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
        SkipTimestampCheck: false,
    })

    result, err := verifier.Validate(attestationBytes)
    if err != nil {
        return fmt.Errorf("invalid attestation: %w", err)
    }

    if !result.Valid {
        return fmt.Errorf("validation failed: %v", result.Errors)
    }

    // Use result...
    return nil
}
```

### New Capabilities Available

Once migrated, you can use new features:

**PCR Validation:**
```go
verifier := awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
    PCRRules: []awsnitroverifier.PCRRule{
        {Index: 0, Value: expectedPCR0},
    },
})
```

**Data Extraction:**
```go
result, err := verifier.Validate(attestationBytes)
// ... error handling ...

userData := result.UserData
publicKey := result.PublicKey
nonce := result.Nonce
```

**Offline Mode:**
```go
verifier := awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
    SkipTimestampCheck: true,
})
```
