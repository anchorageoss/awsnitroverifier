package awsnitroverifier

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Note: Attestation fixtures are embedded and managed in the root package test_helpers.go
// using //go:embed. This allows the root package tests and the internal package tests
// to share the same test data files.

// Commands to obtain attestation documents:
//
// ## For Generic AWS Nitro Enclaves:
// To obtain your own attestation documents from AWS Nitro Enclaves:
// 1. Create an enclave with your application
// 2. From within the enclave, call the Nitro Secure Module to get an attestation
// 3. The attestation document will contain your PCR values and optional user data
//
// Example from within an enclave (Python):
// ```python
// import subprocess
// import base64
//
// # Get attestation with optional user data and nonce
// result = subprocess.run([
//     '/usr/bin/nitro-cli', 'describe-eif',
//     '--eif-path', '/app/enclave.eif'
// ], capture_output=True, text=True)
//
// # Parse and encode the attestation document
// attestation = base64.b64encode(attestation_bytes).decode('utf-8')
// ```
//
// For more information, see:
// - https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
// - https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
//
// ## For Turnkey-specific attestations:
// The Turnkey attestation documents embedded in this library were obtained using the Turnkey CLI:
//
// ### Production Attestation:
// ```bash
// turnkey request \
//   --host api.turnkey.com \
//   --path /public/v1/query/get_attestation \
//   --body '{"organizationId": "<yourOrgId>","enclaveType": "signer"}' \
//   --organization=<yourOrgId> | jq -r '.attestationDocument' > turnkey-attestation.base64
// ```
//
// ### Pre-production Attestation:
// ```bash
// turnkey request \
//   --host api.preprod.turnkey.engineering \
//   --path /public/v1/query/get_attestation \
//   --body '{"organizationId": "<yourOrgId>","enclaveType": "signer"}' \
//   --organization=<yourOrgId> | jq -r '.attestationDocument' > turnkey-preprod-attestation.base64
// ```
//
// Replace <yourOrgId> with your actual Turnkey organization ID.
// Requires the Turnkey CLI and appropriate permissions.
//
// ## Key differences between Turnkey fixtures:
//
// Production fixture (`turnkey-prod.base64`):
// - PCR[3]: b798abfdbd591d5e1b7db6485a6de9e65100f5796d9e3a2bd7c179989cd663338b567162974974fbcc45d03847e70d8b
// - UserData: 8a5510ca253818acec5fb27b3ca114b4a260fb84f881838eb124aae9c968ad74 (32 bytes)
// - PublicKey: 130 bytes (ECDSA)
//
// Pre-production fixture (`turnkey-preprod.base64`):
// - PCR[3]: 864e9095a9947ab14698122370c13baf23183f4e9911953cf5b909a49db00f43f446707314674d9309974f3cc4b24728
// - UserData: 37ef96370730962341148a03754955137884516def11439b5d841809f6f9caac (32 bytes)
// - PublicKey: 130 bytes (ECDSA)
//
// Note: These attestation documents contain expired certificates and should only be used for testing
// with SkipTimestampCheck: true

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
			if result.RootFingerprint != AWSNitroRootFingerprint {
				t.Errorf("Root fingerprint mismatch for %s: expected %s, got %s",
					tc.description, AWSNitroRootFingerprint, result.RootFingerprint)
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
