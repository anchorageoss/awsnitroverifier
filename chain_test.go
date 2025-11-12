//go:build !selectTest || isolatedTest

package awsnitroverifier

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/anchorageoss/awsnitroverifier/internal"
)

// AWS Nitro attestation documents from Veracruz project
// Source: https://github.com/veracruz-project/go-nitro-enclave-attestation-document/blob/main/test/aws_nitro_document.cbor

//go:embed testdata/aws_nitro_document.base64
var awsNitroDocumentBase64 string

//go:embed testdata/aws_nitro_document.cbor
var awsNitroDocumentCbor []byte

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
	if !result.ChainTrusted {
		t.Errorf("Certificate chain was not validated, errors: %v", result.Errors)
	}

	// Verify root fingerprint matches AWS Nitro root using built-in constant
	if result.RootFingerprint != internal.AWSNitroRootFingerprint {
		t.Errorf("Root fingerprint mismatch: expected %s, got %s",
			internal.AWSNitroRootFingerprint, result.RootFingerprint)
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

// TestAWSNitroFixtures tests AWS Nitro attestation documents from Veracruz project
// These documents are sourced from: https://github.com/veracruz-project/go-nitro-enclave-attestation-document/blob/main/test/aws_nitro_document.cbor
func TestAWSNitroFixtures(t *testing.T) {
	testCases := []struct {
		name            string
		attestationData []byte
		description     string
	}{
		{
			name: "AWS Nitro Document (Base64)",
			attestationData: func() []byte {
				data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(awsNitroDocumentBase64))
				if err != nil {
					panic("Failed to decode embedded base64 data: " + err.Error())
				}
				return data
			}(),
			description: "Base64 encoded version",
		},
		{
			name:            "AWS Nitro Document (CBOR)",
			attestationData: awsNitroDocumentCbor,
			description:     "Raw CBOR bytes",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with chain validation enabled but timestamp check disabled
			// (These are older certificates that may have expired)
			validator := NewVerifier(AWSNitroVerifierOptions{
				SkipTimestampCheck: true,
			})

			result, err := validator.Validate(tc.attestationData)
			if err != nil {
				t.Fatalf("Fatal error validating %s: %v", tc.description, err)
			}

			// Check chain validation was performed
			if !result.ChainTrusted {
				t.Errorf("Certificate chain was not validated for %s, errors: %v", tc.description, result.Errors)
			}

			// Verify root fingerprint matches AWS Nitro root using built-in constant
			if result.RootFingerprint != internal.AWSNitroRootFingerprint {
				t.Errorf("Root fingerprint mismatch for %s: expected %s, got %s",
					tc.description, internal.AWSNitroRootFingerprint, result.RootFingerprint)
			} else {
				t.Logf("✓ Root fingerprint verified for %s: %s", tc.description, result.RootFingerprint)
			}

			// Test that validation is successful overall
			if !result.Valid {
				t.Errorf("Validation was not successful for %s, errors: %v", tc.description, result.Errors)
			} else {
				t.Logf("✓ AWS Nitro attestation (%s) validated successfully", tc.description)
			}

			// Log some details about the attestation
			if len(result.UserData) > 0 {
				t.Logf("  UserData: %d bytes (%s)", len(result.UserData), hex.EncodeToString(result.UserData))
			}
			if len(result.PublicKey) > 0 {
				t.Logf("  PublicKey: %d bytes", len(result.PublicKey))
			}
			if len(result.Nonce) > 0 {
				t.Logf("  Nonce: %d bytes", len(result.Nonce))
			}
		})
	}
}
