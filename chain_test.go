//go:build !selectTest || isolatedTest

package nitroverifier

import (
	"encoding/hex"
	"testing"
)

// TestChainOfTrustValidation tests AWS Nitro root certificate chain validation
func TestChainOfTrustValidation(t *testing.T) {
	attestationData := getTurnkeyProductionAttestation()

	// Test with chain validation enabled but timestamp check disabled
	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck:  true,
	})

	result, err := validator.Validate(attestationData)
	if err != nil {
		t.Fatalf("Fatal error: %v", err)
	}

	// Check chain validation was performed
	if !result.ChainValidated {
		t.Error("Certificate chain was not validated")
		for _, err := range result.Errors {
			t.Logf("  Error: %v", err)
		}
	}

	// Verify root fingerprint matches AWS Nitro root
	expectedFingerprint := AWSNitroRootFingerprint
	if result.RootFingerprint != expectedFingerprint {
		t.Errorf("Root fingerprint mismatch: expected %s, got %s",
			expectedFingerprint, result.RootFingerprint)
	} else {
		t.Logf("✓ Root fingerprint verified: %s", result.RootFingerprint)
	}

	// Check certificate chain was extracted
	if len(result.CertificateChain) == 0 {
		t.Error("Certificate chain was not extracted")
	} else {
		t.Logf("Certificate chain contains %d certificates:", len(result.CertificateChain))
		for i, cert := range result.CertificateChain {
			t.Logf("  [%d] %s", i, cert.Subject)

			// First certificate should be AWS Nitro root
			if i == 0 {
				expectedSubject := "CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US"
				if cert.Subject != expectedSubject {
					t.Errorf("Root certificate subject mismatch: expected %s, got %s",
						expectedSubject, cert.Subject)
				}
			}
		}
	}
}

// TestUserDataExtraction tests that UserData is properly extracted
func TestUserDataExtraction(t *testing.T) {
	attestationData := getTurnkeyProductionAttestation()

	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck:        true,
	})

	result, err := validator.Validate(attestationData)
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
		{
			name:            "PreProd",
			attestationData: getTurnkeyPreProductionAttestation(),
			expected:        "37ef96370730962341148a03754955137884516def11439b5d841809f6f9caac",
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			attestationData := fixture.attestationData

			validator := NewVerifier(AWSNitroVerifierOptions{
				SkipTimestampCheck:        true,
			})

			result, err := validator.Validate(attestationData)
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

// TestAWSRootCertificateVerification tests the AWS root certificate verification
func TestAWSRootCertificateVerification(t *testing.T) {
	// Load the AWS Nitro root certificate
	rootCert := EmbeddedAWSNitroRootCertificate()

	// Verify it's the correct certificate
	if err := VerifyAWSNitroRootCertificate(rootCert); err != nil {
		t.Errorf("AWS root certificate verification failed: %v", err)
	} else {
		t.Log("✓ AWS Nitro root certificate verified")
	}

	// Check fingerprint
	fingerprint := CalculateCertificateFingerprint(rootCert)
	if fingerprint != AWSNitroRootFingerprint {
		t.Errorf("Fingerprint mismatch: expected %s, got %s",
			AWSNitroRootFingerprint, fingerprint)
	} else {
		t.Logf("✓ Root certificate fingerprint: %s", fingerprint)
	}

	// Check subject
	expectedSubject := "CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US"
	if rootCert.Subject.String() != expectedSubject {
		t.Errorf("Subject mismatch: expected %s, got %s",
			expectedSubject, rootCert.Subject.String())
	} else {
		t.Logf("✓ Root certificate subject: %s", rootCert.Subject.String())
	}
}
