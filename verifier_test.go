//go:build !selectTest || isolatedTest

package awsnitroverifier

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
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
		require.NoError(t, err)
		require.False(t, result.Valid, "Expected validation to fail due to expired certificate")
	})

	// Test with timestamp check disabled
	t.Run("SkipTimestampCheck", func(t *testing.T) {
		verifier := NewVerifier(AWSNitroVerifierOptions{
			SkipTimestampCheck: true,
		})
		result, err := verifier.Validate(attestationBytes)
		require.NoError(t, err)
		require.True(t, result.Valid, "Expected validation to pass, got errors: %v", result.Errors)
		require.True(t, result.ChainTrusted, "Expected certificate chain to be validated")
		require.NotEmpty(t, result.RootFingerprint, "Expected root fingerprint to be present")
		require.NotNil(t, result.UserData, "Expected UserData to be present")
		require.NotNil(t, result.PublicKey, "Expected PublicKey to be present")
	})
}

// TestInvalidAttestationData tests error handling for invalid input
func TestInvalidAttestationData(t *testing.T) {
	verifier := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	testCases := []struct {
		name             string
		attestationBytes []byte
		expectError      bool
	}{
		{
			name:             "Empty bytes",
			attestationBytes: []byte{},
			expectError:      true,
		},
		{
			name:             "Invalid CBOR data",
			attestationBytes: []byte("not-valid-cbor!@#$"),
			expectError:      true,
		},
		{
			name:             "Valid bytes but not CBOR",
			attestationBytes: []byte("hello world"),
			expectError:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := verifier.Validate(tc.attestationBytes)

			if tc.expectError {
				require.Error(t, err, "Expected error for malformed input")
			} else {
				require.NoError(t, err)
			}
			if err != nil {
				require.Nil(t, result, "Should not return result when error is non-nil")
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
	require.NoError(t, err)

	// Test all public fields are accessible
	t.Run("PublicAPIContract", func(t *testing.T) {
		// Verify that VerificationResult maintains its public API contract
		// This test will fail to compile if any of these fields become private
		// or are removed, helping prevent accidental breaking changes.

		var apiFields = struct {
			Valid           bool
			Errors          []error
			ChainTrusted    bool
			RootFingerprint string
			UserData        []byte
			PublicKey       []byte
			Nonce           []byte
			PCRResults      []PCRValidationResult
		}{
			Valid:           result.Valid,
			Errors:          result.Errors,
			ChainTrusted:    result.ChainTrusted,
			RootFingerprint: result.RootFingerprint,
			UserData:        result.UserData,
			PublicKey:       result.PublicKey,
			Nonce:           result.Nonce,
			PCRResults:      result.PCRResults,
		}

		_ = apiFields // Suppress unused variable warning
		t.Log("✓ All public API fields are accessible")
	})

	// Verify field values make sense
	t.Run("FieldValues", func(t *testing.T) {
		if result.ChainTrusted {
			require.NotEmpty(t, result.RootFingerprint, "Chain trusted but no root fingerprint")
		}

		if result.UserData != nil {
			require.NotEmpty(t, result.UserData, "UserData is non-nil but empty")
		}

		if result.PublicKey != nil {
			require.NotEmpty(t, result.PublicKey, "PublicKey is non-nil but empty")
		}

		if !result.Valid {
			require.NotEmpty(t, result.Errors, "Valid is false but Errors is empty")
		}
	})
}

// TestSignatureVerification tests signature verification with various scenarios
func TestSignatureVerification(t *testing.T) {
	attestationBase64 := getTurnkeyProductionAttestation()
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	verifier := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	// Test that valid attestation passes signature verification
	t.Run("ValidSignature", func(t *testing.T) {
		result, err := verifier.Validate(attestationBytes)
		require.NoError(t, err)

		// Valid attestation should have no certificate chain errors
		for _, errMsg := range result.Errors {
			errStr := errMsg.Error()
			require.NotContains(t, errStr, "certificate", "Valid attestation had certificate error")
			require.NotContains(t, errStr, "signature", "Valid attestation had signature error")
		}
	})

	// Test with corrupted signature bytes
	t.Run("CorruptedSignature", func(t *testing.T) {
		corruptedBytes := make([]byte, len(attestationBytes))
		copy(corruptedBytes, attestationBytes)
		// Corrupt the last byte (part of signature in COSE structure)
		if len(corruptedBytes) > 0 {
			corruptedBytes[len(corruptedBytes)-1] ^= 0xFF
		}

		result, err := verifier.Validate(corruptedBytes)
		require.NoError(t, err)
		require.False(t, result.Valid, "Expected validation to fail with corrupted signature")

		// Should have signature-related error
		found := false
		for _, errMsg := range result.Errors {
			if errMsg != nil && len(errMsg.Error()) > 0 {
				found = true
				break
			}
		}
		require.True(t, found, "Expected signature error, got: %v", result.Errors)
	})

	// Test validation result consistency
	t.Run("ValidUntilErrors", func(t *testing.T) {
		result, err := verifier.Validate(attestationBytes)
		require.NoError(t, err)

		// Valid should match whether Errors is empty
		if result.Valid {
			require.Empty(t, result.Errors, "Valid is true but Errors is not empty")
		} else {
			require.NotEmpty(t, result.Errors, "Valid is false but Errors is empty")
		}
	})
}

// TestValidationWithPCRRules tests PCR validation functionality
func TestValidationWithPCRRules(t *testing.T) {
	attestationBase64 := getTurnkeyProductionAttestation()
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	t.Run("ValidPCRRule", func(t *testing.T) {
		// This test attestation has PCRs, so we should be able to validate them
		verifier := NewVerifier(AWSNitroVerifierOptions{
			SkipTimestampCheck: true,
			PCRRules: []PCRRule{
				{Index: 0, Value: []byte("dummy-value")},
			},
		})

		result, err := verifier.Validate(attestationBytes)
		require.NoError(t, err)
		require.NotEmpty(t, result.PCRResults, "Expected PCR results but got none")

		// Check that PCR results are properly structured
		for _, pcr := range result.PCRResults {
			if pcr.Index == 0 {
				// We provided a dummy value, so it should not match
				require.False(t, pcr.Valid, "PCR[0] should not match dummy value")
			}
		}
	})

	t.Run("MultiplePCRRules", func(t *testing.T) {
		verifier := NewVerifier(AWSNitroVerifierOptions{
			SkipTimestampCheck: true,
			PCRRules: []PCRRule{
				{Index: 0, Value: []byte("value0")},
				{Index: 1, Value: []byte("value1")},
				{Index: 8, Value: []byte("value8")},
			},
		})

		result, err := verifier.Validate(attestationBytes)
		require.NoError(t, err)
		require.Len(t, result.PCRResults, 3, "Expected 3 PCR results")
	})
}

// TestValidationErrorHandling tests error handling in various scenarios
func TestValidationErrorHandling(t *testing.T) {
	verifier := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	testCases := []struct {
		name          string
		input         []byte
		shouldError   bool
		errorContains string
	}{
		{
			name:          "ValidAttestation",
			input:         decodeBase64(getTurnkeyProductionAttestation()),
			shouldError:   false,
			errorContains: "",
		},
		{
			name:          "EmptyInput",
			input:         []byte{},
			shouldError:   true,
			errorContains: "malformed",
		},
		{
			name:          "InvalidCBOR",
			input:         []byte{0xFF, 0xFF, 0xFF},
			shouldError:   true,
			errorContains: "malformed",
		},
		{
			name:          "RandomBytes",
			input:         []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			shouldError:   true,
			errorContains: "malformed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := verifier.Validate(tc.input)

			if tc.shouldError {
				require.Error(t, err, "Expected error for %s", tc.name)
				if tc.errorContains != "" {
					require.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err, "Unexpected error for %s", tc.name)
			}

			if err != nil {
				require.Nil(t, result, "Result should be nil when error is returned")
			}
		})
	}
}

// Helper function to decode base64 strings
func decodeBase64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
