//go:build !selectTest || isolatedTest

package nitroverifier

import (
	"encoding/base64"
	"testing"
)

// TestPublicAPIBasic tests the basic public API functionality
func TestPublicAPIBasic(t *testing.T) {
	// Get test attestation data
	attestationBase64 := getTurnkeyProductionAttestation()
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	// Test with default options
	t.Run("DefaultOptions", func(t *testing.T) {
		verifier := NewVerifier(AWSNitroVerifierOptions{})
		result, err := verifier.Validate(attestationBytes)
		if err != nil {
			t.Fatalf("Fatal error: %v", err)
		}

		// Should fail due to expired certificate
		if result.Valid {
			t.Error("Expected validation to fail due to expired certificate")
		}
	})

	// Test with timestamp check disabled
	t.Run("SkipTimestampCheck", func(t *testing.T) {
		verifier := NewVerifier(AWSNitroVerifierOptions{
			SkipTimestampCheck: true,
		})
		result, err := verifier.Validate(attestationBytes)
		if err != nil {
			t.Fatalf("Fatal error: %v", err)
		}

		// Should pass with timestamp check disabled
		if !result.Valid {
			t.Error("Expected validation to pass with timestamp check disabled")
		}

		// Check chain validation
		if !result.ChainValidated {
			t.Error("Expected certificate chain to be validated")
		}

		// Check root fingerprint is present
		if result.RootFingerprint == "" {
			t.Error("Expected root fingerprint to be present")
		}

		// Check optional fields are extracted
		if result.UserData == nil {
			t.Error("Expected UserData to be present")
		}
		if result.PublicKey == nil {
			t.Error("Expected PublicKey to be present")
		}
		if result.Nonce != nil {
			t.Log("Nonce is present (optional)")
		}
	})
}

// TestInvalidAttestationData tests error handling for invalid input
func TestInvalidAttestationData(t *testing.T) {
	testCases := []struct {
		name             string
		attestationBytes []byte
		expectError      bool
		expectValid      bool
	}{
		{
			name:             "Empty bytes",
			attestationBytes: []byte{},
			expectError:      false,
			expectValid:      false,
		},
		{
			name:             "Invalid CBOR data",
			attestationBytes: []byte("not-valid-cbor!@#$"),
			expectError:      false,
			expectValid:      false,
		},
		{
			name:             "Valid bytes but not CBOR",
			attestationBytes: []byte("hello world"),
			expectError:      false,
			expectValid:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := NewVerifier(AWSNitroVerifierOptions{
				SkipTimestampCheck: true,
			})
			result, err := verifier.Validate(tc.attestationBytes)

			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != nil && result.Valid != tc.expectValid {
				t.Errorf("Expected Valid=%v, got %v", tc.expectValid, result.Valid)
			}
		})
	}
}

// TestValidationResultFields tests that the ValidationResult contains expected fields
func TestValidationResultFields(t *testing.T) {
	attestationBase64 := getTurnkeyProductionAttestation()
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	verifier := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	result, err := verifier.Validate(attestationBytes)
	if err != nil {
		t.Fatalf("Fatal error: %v", err)
	}

	// Test all public fields are accessible
	t.Run("FieldAccess", func(t *testing.T) {
		// Core fields
		_ = result.Valid
		_ = result.ChainValidated
		_ = result.RootFingerprint

		// Optional fields
		_ = result.UserData
		_ = result.PublicKey
		_ = result.Nonce

		t.Log("✓ All public fields are accessible")
	})

	// Verify field values make sense
	t.Run("FieldValues", func(t *testing.T) {
		if result.ChainValidated && result.RootFingerprint == "" {
			t.Error("Chain validated but no root fingerprint")
		}

		if result.UserData != nil && len(result.UserData) == 0 {
			t.Error("UserData is non-nil but empty")
		}

		if result.PublicKey != nil && len(result.PublicKey) == 0 {
			t.Error("PublicKey is non-nil but empty")
		}
	})
}