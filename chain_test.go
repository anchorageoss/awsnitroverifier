//go:build !selectTest || isolatedTest

package nitroverifier

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// TestChainOfTrustValidation tests AWS Nitro root certificate chain validation
func TestChainOfTrustValidation(t *testing.T) {
	attestationData := getTurnkeyProductionAttestation()
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationData)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	// Test with chain validation enabled but timestamp check disabled
	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	result, err := validator.Validate(attestationBytes)
	if err != nil {
		t.Fatalf("Fatal error: %v", err)
	}

	// Check chain validation was performed
	if !result.ChainValidated {
		t.Error("Certificate chain was not validated")
	}

	// Verify root fingerprint matches AWS Nitro root
	expectedFingerprint := "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
	if result.RootFingerprint != expectedFingerprint {
		t.Errorf("Root fingerprint mismatch: expected %s, got %s",
			expectedFingerprint, result.RootFingerprint)
	} else {
		t.Logf("✓ Root fingerprint verified: %s", result.RootFingerprint)
	}

	// Test that validation is successful overall
	if !result.Valid {
		t.Error("Validation was not successful")
	}

	// Successfully validated with expected root fingerprint
	t.Logf("✓ AWS Nitro attestation validated successfully")
}

// TestUserDataExtraction tests that UserData is properly extracted
func TestUserDataExtraction(t *testing.T) {
	attestationData := getTurnkeyProductionAttestation()
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationData)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}
	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	result, err := validator.Validate(attestationBytes)
	if err != nil {
		t.Fatalf("Fatal error: %v", err)
	}

	// Check UserData was extracted
	if result.UserData == nil {
		t.Error("UserData was not extracted")
	} else {
		t.Logf("✓ UserData extracted: %d bytes", len(result.UserData))
		t.Logf("  Hex: %s", hex.EncodeToString(result.UserData))

		// For Turnkey attestations, UserData should be 32 bytes
		if len(result.UserData) == 32 {
			t.Log("✓ UserData is 32 bytes (typical for Turnkey)")
		}
	}

	// Check PublicKey was extracted
	if result.PublicKey == nil {
		t.Log("PublicKey not present (optional)")
	} else {
		t.Logf("✓ PublicKey extracted: %d bytes", len(result.PublicKey))

		// For Turnkey attestations, PublicKey is usually 130 bytes
		if len(result.PublicKey) == 130 {
			t.Log("✓ PublicKey is 130 bytes (typical for Turnkey ECDSA key)")
		}
	}

	// Check Nonce
	if result.Nonce == nil {
		t.Log("Nonce not present (optional)")
	} else {
		t.Logf("✓ Nonce extracted: %d bytes", len(result.Nonce))
	}
}

// TestTurnkeyUserDataValidation tests UserData in Turnkey attestations
func TestTurnkeyUserDataValidation(t *testing.T) {
	fixtures := []struct {
		name            string
		attestationData string
		expected        string // Expected UserData in hex
	}{
		{
			name:            "Production",
			attestationData: getTurnkeyProductionAttestation(),
			expected:        "8a5510ca253818acec5fb27b3ca114b4a260fb84f881838eb124aae9c968ad74",
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			attestationData := fixture.attestationData
			attestationBytes, err := base64.StdEncoding.DecodeString(attestationData)
			if err != nil {
				t.Fatalf("Failed to decode test data: %v", err)
			}

			validator := NewVerifier(AWSNitroVerifierOptions{
				SkipTimestampCheck: true,
			})

			result, err := validator.Validate(attestationBytes)
			if err != nil {
				t.Fatalf("Fatal error: %v", err)
			}

			if result.UserData == nil {
				t.Errorf("%s: UserData not found", fixture.name)
				return
			}

			actualHex := hex.EncodeToString(result.UserData)
			t.Logf("%s UserData: %s (%d bytes)", fixture.name, actualHex, len(result.UserData))

			// Verify expected value if known
			if fixture.expected != "" && actualHex != fixture.expected {
				t.Errorf("%s: UserData mismatch", fixture.name)
				t.Logf("  Expected: %s", fixture.expected)
				t.Logf("  Actual:   %s", actualHex)
			}

			// Check PublicKey
			if result.PublicKey != nil {
				t.Logf("%s PublicKey: %d bytes", fixture.name, len(result.PublicKey))
				if testing.Verbose() {
					t.Logf("  Hex: %s", hex.EncodeToString(result.PublicKey))
				}
			}

			// Check if UserData appears to be a hash (32 bytes)
			if len(result.UserData) == 32 {
				t.Logf("✓ %s: UserData appears to be a 256-bit hash", fixture.name)
			}
		})
	}
}

// TestAWSRootCertificateVerification - this test has been moved to internal package
// since it tests internal implementation details
