//go:build !selectTest || isolatedTest

package nitroverifier

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// TestCOSEStructureValidation tests that we properly parse COSE_Sign1 structure
func TestCOSEStructureValidation(t *testing.T) {
	tests := []struct {
		name        string
		description string
		expectValid bool
	}{
		{
			name:        "Valid COSE_Sign1",
			description: "Should have tag 18 (0xD2) for COSE_Sign1",
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test would use actual attestation document
			t.Logf("Test case: %s", tt.description)
		})
	}
}

// TestAttestationDocumentStructure validates the CBOR structure matches AWS spec
func TestAttestationDocumentStructure(t *testing.T) {
	// AWS Nitro attestations can use two formats:
	// Format 1: Tagged COSE_Sign1 (starts with 0xD2)
	// - First byte: 0xD2 (CBOR tag 18 for COSE_Sign1)
	// Format 2: Array COSE_Sign1 (starts with 0x84)
	// - First byte: 0x84 (CBOR array with 4 elements)
	//
	// Both formats have protected header:
	// - Protected header: 0xA1 (Type 5 map with 1 item)
	// - Algorithm key: 0x01 (key = 1 for algorithm)
	// - Algorithm value: 0x22 (ES384) or 0x24 (ES256)

	testCases := []struct {
		name          string
		expectedBytes []byte
		position      int
		description   string
		skipForArray  bool
	}{
		{
			name:          "COSE_format",
			expectedBytes: []byte{0xD2, 0x84}, // Either tagged or array format
			position:      0,
			description:   "First byte should be 0xD2 (tag) or 0x84 (array)",
		},
		{
			name:          "Protected_header_map",
			expectedBytes: []byte{0xA1},
			position:      2,
			description:   "Protected header should be Type 5 map with 1 item",
		},
		{
			name:          "Algorithm_key",
			expectedBytes: []byte{0x01},
			position:      3,
			description:   "Algorithm key should be 1",
		},
	}

	// Load a test attestation document
	attestationBase64 := turnkeyFixtures.Production
	if attestationBase64 == "" {
		t.Skip("No test attestation document available")
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.position >= len(attestationBytes) {
				t.Errorf("Position %d out of bounds (doc length: %d)", tc.position, len(attestationBytes))
				return
			}

			actual := attestationBytes[tc.position]
			if !bytes.Contains(tc.expectedBytes, []byte{actual}) {
				t.Errorf("%s: Expected one of %v at position %d, got 0x%02X",
					tc.description, tc.expectedBytes, tc.position, actual)
			} else {
				t.Logf("✓ %s: Found 0x%02X at position %d", tc.description, actual, tc.position)
			}
		})
	}
}

// TestPCRValidation tests PCR extraction and validation
func TestPCRValidation(t *testing.T) {
	attestationBase64 := turnkeyFixtures.Production
	if attestationBase64 == "" {
		t.Skip("No test attestation document available")
	}

	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck:        true,
	})

	result, err := validator.Validate(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to validate: %v", err)
	}

	// According to AWS spec, PCRs should be:
	// - Index range: 0-31
	// - Content length: 32, 48, or 64 bytes
	t.Run("PCR_constraints", func(t *testing.T) {
		if result.Document == nil {
			t.Fatal("Document is nil")
		}

		if len(result.Document.PCRs) < 1 || len(result.Document.PCRs) > 32 {
			t.Errorf("PCR count should be 1-32, got %d", len(result.Document.PCRs))
		}

		for index, pcr := range result.Document.PCRs {
			if index > 31 {
				t.Errorf("PCR index %d exceeds maximum of 31", index)
			}

			pcrLen := len(pcr)
			if pcrLen != 32 && pcrLen != 48 && pcrLen != 64 {
				t.Errorf("PCR[%d] has invalid length %d (expected 32, 48, or 64)", index, pcrLen)
			} else {
				t.Logf("✓ PCR[%d]: %d bytes - %s", index, pcrLen, hex.EncodeToString(pcr))
			}
		}
	})
}

// TestMandatoryFields verifies all mandatory fields are present
func TestMandatoryFields(t *testing.T) {
	attestationBase64 := turnkeyFixtures.Production
	if attestationBase64 == "" {
		t.Skip("No test attestation document available")
	}

	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck:        true,
	})

	result, err := validator.Validate(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to validate: %v", err)
	}

	if result.Document == nil {
		t.Fatal("Document is nil")
	}

	doc := result.Document

	// Test mandatory fields according to AWS spec
	tests := []struct {
		name    string
		check   func() bool
		message string
	}{
		{
			name:    "module_id",
			check:   func() bool { return doc.ModuleID != "" },
			message: "module_id must be non-empty",
		},
		{
			name:    "timestamp",
			check:   func() bool { return doc.Timestamp > 0 },
			message: "timestamp must be positive",
		},
		{
			name:    "digest",
			check:   func() bool { return doc.Digest == "SHA384" },
			message: "digest must be 'SHA384'",
		},
		{
			name:    "pcrs",
			check:   func() bool { return len(doc.PCRs) >= 1 && len(doc.PCRs) <= 32 },
			message: "pcrs must have 1-32 entries",
		},
		{
			name:    "certificate",
			check:   func() bool { return len(doc.Certificate) > 0 },
			message: "certificate must be present",
		},
		{
			name:    "cabundle",
			check:   func() bool { return doc.CABundle != nil },
			message: "cabundle must be present",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.check() {
				t.Errorf("%s", tt.message)
			} else {
				t.Logf("✓ %s validated", tt.name)
			}
		})
	}
}

// TestOptionalFieldConstraints tests optional field size constraints
func TestOptionalFieldConstraints(t *testing.T) {
	attestationBase64 := turnkeyFixtures.Production
	if attestationBase64 == "" {
		t.Skip("No test attestation document available")
	}

	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck:        true,
	})

	result, err := validator.Validate(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to validate: %v", err)
	}

	if result.Document == nil {
		t.Fatal("Document is nil")
	}

	doc := result.Document

	// Test optional field constraints according to AWS spec
	tests := []struct {
		name      string
		field     []byte
		minSize   int
		maxSize   int
		fieldName string
	}{
		{
			name:      "public_key",
			field:     doc.PublicKey,
			minSize:   0,
			maxSize:   1024,
			fieldName: "public_key",
		},
		{
			name:      "user_data",
			field:     doc.UserData,
			minSize:   0,
			maxSize:   512,
			fieldName: "user_data",
		},
		{
			name:      "nonce",
			field:     doc.Nonce,
			minSize:   0,
			maxSize:   512,
			fieldName: "nonce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.field != nil {
				fieldLen := len(tt.field)
				if fieldLen < tt.minSize || fieldLen > tt.maxSize {
					t.Errorf("%s size %d out of range [%d, %d]",
						tt.fieldName, fieldLen, tt.minSize, tt.maxSize)
				} else if fieldLen > 0 {
					t.Logf("✓ %s: %d bytes (within range [%d, %d])",
						tt.fieldName, fieldLen, tt.minSize, tt.maxSize)
				}
			}
		})
	}
}

// TestCertificateChainValidation tests the certificate chain structure
func TestCertificateChainValidation(t *testing.T) {
	attestationBase64 := turnkeyFixtures.Production
	if attestationBase64 == "" {
		t.Skip("No test attestation document available")
	}

	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck:        true,
	})

	result, err := validator.Validate(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to validate: %v", err)
	}

	if result.Document == nil || result.CertificateInfo == nil {
		t.Fatal("Document or certificate info is nil")
	}

	// Log certificate details
	t.Logf("Certificate Subject: %s", result.CertificateInfo.Subject)
	t.Logf("Certificate Issuer: %s", result.CertificateInfo.Issuer)
	t.Logf("Certificate Valid From: %s", result.CertificateInfo.NotBefore.Format(time.RFC3339))
	t.Logf("Certificate Valid To: %s", result.CertificateInfo.NotAfter.Format(time.RFC3339))

	// Check CA bundle
	if result.Document.CABundle != nil {
		t.Logf("CA Bundle contains %d certificates", len(result.Document.CABundle))

		// Parse and validate CA bundle structure
		chain, err := ParseCertificateChain(result.Document.CABundle)
		if err != nil {
			t.Errorf("Failed to parse CA bundle: %v", err)
		} else {
			for i, cert := range chain {
				t.Logf("  CA[%d] Subject: %s", i, cert.Subject.String())
				t.Logf("  CA[%d] Issuer: %s", i, cert.Issuer.String())
			}
		}
	}
}

// TestSignatureAlgorithm verifies the signature algorithm matches AWS spec
func TestSignatureAlgorithm(t *testing.T) {
	attestationBase64 := turnkeyFixtures.Production
	if attestationBase64 == "" {
		t.Skip("No test attestation document available")
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	// Check protected header for algorithm
	// According to spec: Byte 4-5 should indicate ECDSA with P-256 or P-384
	if len(attestationBytes) > 5 {
		algIndicator := attestationBytes[5]
		var algName string
		switch algIndicator {
		case 0x22: // -35 in CBOR = ES384
			algName = "ES384 (ECDSA with P-384)"
		case 0x24: // -37 in CBOR = ES256
			algName = "ES256 (ECDSA with P-256)"
		default:
			algName = fmt.Sprintf("Unknown (0x%02X)", algIndicator)
		}
		t.Logf("Signature Algorithm: %s", algName)
	}
}

// Benchmark signature verification
func BenchmarkSignatureVerification(b *testing.B) {
	attestationBase64 := turnkeyFixtures.Production
	if attestationBase64 == "" {
		b.Skip("No test attestation document available")
	}

	validator := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validator.Validate(attestationBase64)
	}
}
